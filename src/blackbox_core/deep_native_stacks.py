"""Live x64 stacks from PSS contexts and a copy-on-write VA clone.

The inspector never increments a target thread's suspension count. Windows
owns transient snapshot capture; all unwinding reads the resulting VA clone.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import ctypes as C
import os
import time

from . import deep_native_win as W


class PSS_THREAD_ENTRY(C.Structure):
    _fields_ = [("exit_status", W.U32), ("teb", W.PTR), ("pid", W.U32),
                ("tid", W.U32), ("affinity", W.SIZE), ("priority", W.I32),
                ("base_priority", W.I32), ("syscall_argument", W.PTR),
                ("syscall_number", W.U16), ("created", W.FILETIME),
                ("exited", W.FILETIME), ("kernel_time", W.FILETIME),
                ("user_time", W.FILETIME), ("start_address", W.PTR),
                ("captured", W.FILETIME), ("flags", W.U32),
                ("suspend_count", W.U16), ("context_size", W.U16), ("context", W.PTR)]


def _same_unwind_image(captured, disk):
    return bool(captured.get("guid") and all(captured.get(key) == disk.get(key) for key in
                ("guid", "age", "machine", "image_size", "image_timestamp")))


def _snapshot_module_identity(module):
    """Keep frame navigation bound to this capture, never a later module list."""
    binding = "PSS_CLONE_PE_IDENTITY_AND_LAYOUT_MATCH"
    if (module is None or module.get("snapshot_binding") != binding or
            not isinstance(module.get("snapshot_pe"), dict)):
        return None
    return {key: module[key] for key in ("base", "size", "name", "path")} | {
        "snapshot_pe": dict(module["snapshot_pe"]),
        "snapshot_binding": binding, "source": "SAME_PSS_CAPTURE"}


def _stack_positions(initial, advance, limit):
    """Keep the captured PC and allow StackWalk64's first initialization step.

    The first successful native call can return the input PC/SP unchanged;
    only subsequent repetition proves lack of progress. Permit that one
    initialization result without duplicating a displayed frame.
    """
    if not initial[0]:
        return
    seen = {initial}
    yield initial
    first = True
    while len(seen) < limit:
        position = advance()
        if position is None or not position[0]:
            return
        if first and position == initial:
            first = False
            continue
        first = False
        if position in seen:
            return
        seen.add(position)
        yield position


@contextmanager
def _unwind_image(kernel, module):
    """Pin the verified disk image while DbgHelp borrows its unwind metadata.

    Do not let SymLoadModuleEx reopen a pathname which could have been replaced
    after Toolhelp/PSS capture. Denying write/delete sharing also prevents a
    later writer from mutating this metadata during the stack walk.
    """
    import msvcrt
    from .deep_native import _os_error
    from .decoder_pdb import _local_file, _stable_file
    from .decoder_native_symbols import _pe_layout
    path, initial = _local_file(module["path"])
    create = W.bind(kernel.dll, "CreateFileW", W.HANDLE, C.c_wchar_p, W.U32,
                    W.U32, W.PTR, W.U32, W.U32, W.HANDLE)
    handle = create(str(path), 0x80000000, 1, None, 3, 0x00200080, None)
    if not handle or handle == W.INVALID_HANDLE:
        raise _os_error("UNWIND_IMAGE_OPEN_FAILED")
    try:
        descriptor = msvcrt.open_osfhandle(int(handle), os.O_RDONLY | os.O_BINARY)
    except BaseException:
        kernel.close(handle)
        raise
    with os.fdopen(descriptor, "rb") as stream:
        _stable_file(path, initial, os.fstat(stream.fileno()))
        disk = _pe_layout(stream, initial.st_size)
        _stable_file(path, initial, os.fstat(stream.fileno()))
        if not _same_unwind_image(module["snapshot_pe"], disk):
            raise ValueError("UNWIND_IMAGE_DIFFERS_FROM_PSS_CLONE")
        stream.seek(0)
        yield handle


def collect_stacks(inspector, params, deadline, cancel):
    from .deep_native import NativeError, _check, _integer, _os_error, _DBGHELP_LOCK
    limit = _integer(params.get("limit", 16), "limit", 1, 64)
    frame_limit = _integer(params.get("max_frames", 64), "max_frames", 1, 128)
    requested_tid = params.get("tid")
    if requested_tid is not None:
        _integer(requested_tid, "tid", 1, 0xFFFFFFFF)
    requested_created = params.get("thread_created_100ns", params.get("created_100ns"))
    if requested_created is not None:
        _integer(requested_created, "created_100ns", 1)
    modules = inspector._modules({"limit": 1024}, deadline, cancel)["rows"]
    symbols, symbol_module = None, None
    if params.get("pdb_path"):
        from .decoder_native_symbols import load_native_symbols
        module_base = _integer(params.get("module_base"), "module_base", 1)
        symbol_module = next((m for m in modules if m["base"] == module_base), None)
        if symbol_module is None:
            raise ValueError("SYMBOL_MODULE_NOT_LOADED")
        symbols = load_native_symbols(symbol_module["path"], params["pdb_path"], cancel=cancel)
        loaded = symbol_module.get("loaded_pe") or {}
        if not loaded.get("guid") or any(loaded.get(key) != symbols.pe.get(key)
                                         for key in ("guid", "age", "image_size", "image_timestamp")):
            raise ValueError("LOADED_MODULE_PE_PDB_IDENTITY_MISMATCH")
    rows, omitted, cleanup_error, unwind_withheld = [], 0, None, 0
    with inspector._open(0x4D0) as (kernel, process):
        process_machine, native_machine = W.U16(), W.U16()
        if not kernel.wow64(process, C.byref(process_machine), C.byref(native_machine)):
            raise _os_error("IS_WOW64_PROCESS2_FAILED")
        if process_machine.value or native_machine.value != 0x8664:
            raise NativeError("INCOMPLETE_EVIDENCE", "LIVE_STACK_REQUIRES_NATIVE_WINDOWS_X64_TARGET")
        capture = W.bind(kernel.dll, "PssCaptureSnapshot", W.U32, W.HANDLE, W.U32, W.U32, C.POINTER(W.HANDLE))
        free = W.bind(kernel.dll, "PssFreeSnapshot", W.U32, W.HANDLE, W.HANDLE)
        query = W.bind(kernel.dll, "PssQuerySnapshot", W.U32, W.HANDLE, W.U32, W.PTR, W.U32)
        marker_create = W.bind(kernel.dll, "PssWalkMarkerCreate", W.U32, W.PTR, C.POINTER(W.HANDLE))
        marker_free = W.bind(kernel.dll, "PssWalkMarkerFree", W.U32, W.HANDLE)
        walk_snapshot = W.bind(kernel.dll, "PssWalkSnapshot", W.U32, W.HANDLE, W.U32, W.HANDLE, W.PTR, W.U32)
        snapshot, marker, clone = W.HANDLE(), W.HANDLE(), W.HANDLE()
        error = capture(process, 0x1 | 0x80 | 0x100, 0x00100003, C.byref(snapshot))
        if error:
            raise _os_error("PSS_CAPTURE_SNAPSHOT_FAILED", error)
        try:
            _check(deadline, cancel)
            error = query(snapshot, 1, C.byref(clone), C.sizeof(clone))
            if error or not clone:
                raise _os_error("PSS_QUERY_VA_CLONE_FAILED", error)
            # Toolhelp enumerated live modules before capture. A DLL may have
            # been replaced at the same address in that interval. Bind a frame
            # only after reading the captured clone's own PE identity/layout.
            coherent_modules = []
            module_mismatches = 0
            for module in modules:
                _check(deadline, cancel)
                captured_pe = inspector._loaded_pe(kernel, clone, module["base"])
                if (captured_pe and captured_pe == module.get("loaded_pe") and
                        captured_pe.get("image_size") == module["size"]):
                    coherent_modules.append({**module, "snapshot_pe": captured_pe,
                                             "snapshot_binding": "PSS_CLONE_PE_IDENTITY_AND_LAYOUT_MATCH"})
                else:
                    module_mismatches += 1
            modules = coherent_modules
            if symbols is not None and not any(m["base"] == symbol_module["base"] for m in modules):
                raise NativeError("INCOMPLETE_EVIDENCE", "SYMBOL_MODULE_CHANGED_BEFORE_PSS_CAPTURE")
            error = marker_create(None, C.byref(marker))
            if error:
                raise _os_error("PSS_WALK_MARKER_CREATE_FAILED", error)
            remaining = max(.001, deadline - time.monotonic()) if deadline else 15
            if not _DBGHELP_LOCK.acquire(timeout=remaining):
                raise NativeError("TIMED_OUT", "DBGHELP_BUSY")
            try:
                dbg = W.library("dbghelp")
                initialize = W.bind(dbg, "SymInitializeW", W.BOOL, W.HANDLE, C.c_wchar_p, W.BOOL)
                cleanup = W.bind(dbg, "SymCleanup", W.BOOL, W.HANDLE)
                set_options = W.bind(dbg, "SymSetOptions", W.U32, W.U32)
                get_options = W.bind(dbg, "SymGetOptions", W.U32)
                load_module = W.bind(dbg, "SymLoadModuleExW", W.U64, W.HANDLE, W.HANDLE,
                                     C.c_wchar_p, C.c_wchar_p, W.U64, W.U32, W.PTR, W.U32)
                stack_walk = W.bind(dbg, "StackWalk64", W.BOOL, W.U32, W.HANDLE, W.HANDLE,
                                    C.POINTER(W.STACKFRAME64), W.PTR, W.PTR, W.PTR, W.PTR, W.PTR)
                read_type = C.WINFUNCTYPE(W.BOOL, W.HANDLE, W.U64, W.PTR, W.U32, C.POINTER(W.U32))
                read_failure = {"error": None}

                @read_type
                def read_clone(_, address, output, requested, received):
                    try:
                        if received:
                            received[0] = 0
                        _check(deadline, cancel)
                        if (not received or not output or not address or not 0 < requested <= 65536 or
                                address + requested > 2**64):
                            return False
                        count = W.SIZE()
                        ok = kernel.read_memory(clone, address, output, requested, C.byref(count))
                        if count.value > requested:
                            return False
                        received[0] = count.value
                        return bool(ok)
                    except NativeError as error:
                        read_failure["error"] = error
                        return False
                    except BaseException:
                        read_failure["error"] = NativeError("INCOMPLETE_EVIDENCE", "PSS_STACK_MEMORY_CALLBACK_FAILED")
                        return False
                function_table = W.bind(dbg, "SymFunctionTableAccess64", W.PTR, W.HANDLE, W.U64)
                module_base_api = W.bind(dbg, "SymGetModuleBase64", W.U64, W.HANDLE, W.U64)
                previous_options = get_options()
                # StackWalk needs PE unwind metadata, not DbgHelp's PDB loader.
                # Ignore embedded CodeView paths (which can be UNC), environment
                # symbol paths and automatic symbol-server discovery. Explicit
                # local PDB names/lines are parsed independently above.
                set_options(0x4 | 0x80 | 0x100 | 0x200 | 0x400 | 0x1000 |
                            0x20000 | 0x40000 | 0x80000 | 0x200000 | 0x2000000)
                initialized = False
                image_owners = ExitStack()
                try:
                    if not initialize(clone, "", False):
                        raise _os_error("SYM_INITIALIZE_FAILED")
                    initialized = True
                    for module in modules:
                        _check(deadline, cancel)
                        try:
                            image_handle = image_owners.enter_context(_unwind_image(kernel, module))
                            loaded_base = load_module(clone, image_handle, None, module["name"],
                                                      module["base"], module["size"], None, 0)
                            if loaded_base != module["base"]:
                                raise ValueError("DBGHELP_UNWIND_IMAGE_NOT_LOADED")
                            module["unwind_metadata_status"] = "PINNED_LOCAL_IMAGE_MATCHES_PSS_CODEVIEW_AND_LAYOUT"
                        except (OSError, ValueError, NativeError):
                            unwind_withheld += 1
                            module["unwind_metadata_status"] = "INCOMPLETE_EVIDENCE"
                    while True:
                        _check(deadline, cancel)
                        entry = PSS_THREAD_ENTRY()
                        error = walk_snapshot(snapshot, 3, marker, C.byref(entry), C.sizeof(entry))
                        if error == 259:
                            break
                        if error:
                            raise _os_error("PSS_WALK_THREAD_FAILED", error)
                        if entry.pid != inspector.identity.pid:
                            raise NativeError("PROCESS_CHANGED", "SNAPSHOT_THREAD_PROCESS_MISMATCH")
                        if requested_tid is not None and entry.tid != requested_tid:
                            continue
                        if len(rows) >= limit:
                            omitted += 1
                            continue
                        if requested_created is not None and entry.created.value != requested_created:
                            raise NativeError("PROCESS_CHANGED", "SNAPSHOT_THREAD_INSTANCE_MISMATCH")
                        row = {"tid": int(entry.tid), "created_100ns": entry.created.value,
                               "captured_100ns": entry.captured.value, "kind": "LIVE_PSS_THREAD_CONTEXT",
                               "frames": [], "historical_etw_stack": False,
                               "observed_suspend_count": int(entry.suspend_count), "owned_suspension_count": 0}
                        if not entry.context or entry.context_size < C.sizeof(W.CONTEXT64):
                            row.update(status="INCOMPLETE_EVIDENCE", reason="PSS_CONTEXT_NOT_CAPTURED")
                            rows.append(row)
                            continue
                        storage, context = W.aligned_context()
                        C.memmove(C.byref(context), entry.context, C.sizeof(context))
                        row["context"] = {n: int(getattr(context, n)) for n in
                                          ("rip", "rsp", "rbp", "rax", "rcx", "rdx", "rbx", "rsi", "rdi", "eflags")}
                        frame = W.STACKFRAME64()
                        frame.pc.offset, frame.frame.offset, frame.stack.offset = context.rip, context.rbp, context.rsp
                        frame.pc.mode = frame.frame.mode = frame.stack.mode = 3

                        def advance():
                            _check(deadline, cancel)
                            C.set_last_error(0)
                            walked = stack_walk(0x8664, clone, int(entry.tid), C.byref(frame), C.byref(context),
                                                C.cast(read_clone, W.PTR), C.cast(function_table, W.PTR),
                                                C.cast(module_base_api, W.PTR), None)
                            if read_failure["error"] is not None:
                                raise read_failure["error"]
                            if not walked:
                                row["unwind_winerror"] = C.get_last_error()
                                return None
                            return int(frame.pc.offset), int(frame.stack.offset)

                        initial = int(context.rip), int(context.rsp)
                        for pc, sp in _stack_positions(initial, advance, frame_limit):
                            _check(deadline, cancel)
                            found = next((m for m in modules if m["base"] <= pc < m["base"] + m["size"]), None)
                            record = {"address": pc, "stack_pointer": sp,
                                      "module": found["name"] if found else None,
                                      "module_base": found["base"] if found else None,
                                      "module_identity": _snapshot_module_identity(found),
                                      "rva": pc - found["base"] if found else None,
                                      "unwind_metadata_status": found.get("unwind_metadata_status") if found else None}
                            if symbols is not None and found and found["base"] == symbol_module["base"]:
                                record["symbol"] = symbols.lookup(pc - found["base"])
                                record["symbol_binding"] = "PSS_CLONE_CODEVIEW_AND_LOCAL_PE_PDB_MATCH"
                            row["frames"].append(record)
                        del storage
                        row.update(status="COMPLETED" if len(row["frames"]) > 1 else "INCOMPLETE_EVIDENCE",
                                   truncated=len(row["frames"]) >= frame_limit, unwind_completeness="NOT_PROVEN")
                        if len(row["frames"]) == 1:
                            row["reason"] = "ONLY_CAPTURED_CONTEXT_NO_UNWOUND_CALLER"
                        rows.append(row)
                finally:
                    if initialized:
                        cleanup(clone)
                    image_owners.close()
                    set_options(previous_options)
            finally:
                _DBGHELP_LOCK.release()
        finally:
            if marker:
                marker_free(marker)
            cleanup_error = free(kernel.current_process(), snapshot)
            if cleanup_error:
                raise NativeError("RECOVERY_UNCONFIRMED", "PSS_FREE_SNAPSHOT_FAILED", cleanup_error)
    if requested_tid is not None and not rows:
        raise NativeError("PROCESS_CHANGED", "REQUESTED_THREAD_NOT_CAPTURED")
    incomplete = not rows or omitted or module_mismatches or unwind_withheld or any(
        r["status"] != "COMPLETED" or r.get("truncated") for r in rows)
    return {"rows": rows, "omitted": omitted, "owned_suspension_count": 0,
            "snapshot_cleanup_winerror": cleanup_error,
            "module_bindings_withheld": module_mismatches,
            "unwind_module_metadata_withheld": unwind_withheld,
            "local_pdb": symbols.summary() if symbols is not None else None,
            "_source": "LIVE_PSS_THREAD_CONTEXT_AND_DBGHELP_STACKWALK64",
            "_status": "RECOVERY_UNCONFIRMED" if cleanup_error else "INCOMPLETE_EVIDENCE" if incomplete else "COMPLETED",
            "_limitations": ["PSS_CAPTURE_MAY_BRIEFLY_PAUSE_TARGET", "COPY_ON_WRITE_VA_CLONE_NOT_HISTORICAL_ETW",
                              "STACK_UNWIND_COMPLETENESS_NOT_PROVEN", "NO_SYMBOL_SERVER_OR_SOURCE_NETWORK_ACCESS"]}

