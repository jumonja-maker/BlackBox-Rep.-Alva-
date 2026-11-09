"""Live x64 stacks from PSS contexts and a copy-on-write VA clone.

The inspector never increments a target thread's suspension count. Windows
owns transient snapshot capture; all unwinding reads the resulting VA clone.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import ctypes as C
import os
import re
import time

from . import deep_native_win as W

_SAVED_UNWIND_OWNER = None


class _IMAGEHLP_CBA_READ_MEMORY(C.Structure):
    _fields_ = [("addr", W.U64), ("buf", W.PTR), ("bytes", W.U32),
                ("bytesread", C.POINTER(W.U32))]


def _saved_base_context(raw):
    """Use only the real captured AMD64 base; never advertise absent XSTATE.

    Windows SDK winnt.h: CONTEXT_XSTATE = CONTEXT_AMD64 | 0x40. That bit
    describes extension storage which this bounded reader does not consume.
    """
    if C.sizeof(W.CONTEXT64) != 1232:
        raise ValueError("UNSUPPORTED_AMD64_BASE_CONTEXT_ABI")
    if len(raw) < 1232:
        raise ValueError("FULL_AMD64_CONTEXT_NOT_CAPTURED")
    storage, context = W.aligned_context()
    C.memmove(C.byref(context), raw, 1232)
    recorded_flags = int(context.flags)
    context.flags &= ~0x40
    return storage, context, recorded_flags


class _SavedMemoryAdapter:
    """One bounded captured-memory reader shared by DbgHelp's two callbacks."""
    def __init__(self, owner, read_memory, check):
        self.owner, self.read_memory, self.check = owner, read_memory, check
        self.enabled = True
        self.error = self.reason = None
        self.metadata_provider = None
        self.failed_read_classes = {}
        self.counters = {"stackwalk_requests": 0, "symbol_handler_requests": 0,
                         "successful_reads": 0, "failed_reads": 0, "copied_bytes": 0,
                         "captured_memory_reads": 0, "local_image_metadata_reads": 0,
                         "local_image_metadata_bytes": 0}

    def refuse(self, reason):
        self.counters["failed_reads"] = min(16385, self.counters["failed_reads"] + 1)
        self.reason = self.reason or reason
        return False

    def copy(self, owner, address, destination, requested, received, channel):
        try:
            self.counters[channel] = min(16385, self.counters[channel] + 1)
            if received:
                received[0] = 0
            if not self.enabled or owner != self.owner:
                return self.refuse("DUMP_CALLBACK_READ_SCOPE_CLOSED_OR_WRONG_OWNER")
            if (not received or not destination or not address or not 0 < requested <= 65536 or
                    address + requested > 2**64):
                return self.refuse("DUMP_MEMORY_CALLBACK_INVALID_READ")
            if (self.counters["stackwalk_requests"] + self.counters["symbol_handler_requests"] > 16384 or
                    self.counters["copied_bytes"] + requested > 8 * 1024**2):
                return self.refuse("DUMP_MEMORY_CALLBACK_READ_BUDGET")
            self.check()
            file_backed = False
            try:
                value = self.read_memory(int(address), int(requested))
            except ValueError as missing:
                # A conflicting/partial captured mapping is never replaced.
                if str(missing) != "DUMP_UNWIND_MEMORY_NOT_CAPTURED" or self.metadata_provider is None:
                    raise
                role = self.metadata_provider.classify(int(address), int(requested))
                if role not in ("PE_HEADERS", "RUNTIME_FUNCTION_TABLE", "UNWIND_INFO"):
                    self.failed_read_classes[role] = min(16385, self.failed_read_classes.get(role, 0) + 1)
                value, _role = self.metadata_provider.read(int(address), int(requested))
                file_backed = True
            if len(value) != requested:
                return self.refuse("DUMP_MEMORY_CALLBACK_SHORT_READ")
            C.memmove(destination, value, len(value))
            received[0] = len(value)
            self.counters["successful_reads"] += 1
            self.counters["copied_bytes"] += len(value)
            self.counters["local_image_metadata_reads" if file_backed else "captured_memory_reads"] += 1
            if file_backed:
                self.counters["local_image_metadata_bytes"] += len(value)
            return True
        except BaseException as error:
            if isinstance(error, (InterruptedError, TimeoutError)) or getattr(error, "status", None) in ("CANCELLED", "TIMED_OUT"):
                self.error = self.error or error
            elif not isinstance(error, (ValueError, OSError)):
                self.error = self.error or ValueError("DUMP_MEMORY_CALLBACK_FAILED")
            reason = str(error)
            return self.refuse(reason if re.fullmatch(r"[A-Z0-9_]{1,160}", reason) else
                               "DUMP_MEMORY_CALLBACK_READ_REFUSED")


def _saved_memory_callbacks(adapter, callback_type):
    @callback_type(W.BOOL, W.HANDLE, W.U64, W.PTR, W.U32, C.POINTER(W.U32))
    def read_saved(owner, address, destination, requested, received):
        return adapter.copy(owner, address, destination, requested, received, "stackwalk_requests")

    @callback_type(W.BOOL, W.HANDLE, W.U32, W.U64, W.U64)
    def symbol_callback(owner, action, data, user):
        # CBA_READ_MEMORY only. Never enable symbol servers or arbitrary actions.
        if action != 0x6:
            return False
        if not adapter.enabled or owner != adapter.owner or not data or user != 0:
            return adapter.refuse("DUMP_SYMBOL_CALLBACK_INVALID_OWNER_OR_DATA")
        try:
            request = C.cast(data, C.POINTER(_IMAGEHLP_CBA_READ_MEMORY)).contents
            return adapter.copy(owner, request.addr, request.buf, request.bytes, request.bytesread,
                                "symbol_handler_requests")
        except BaseException:
            adapter.error = adapter.error or ValueError("DUMP_SYMBOL_CALLBACK_FAILED")
            return adapter.refuse("DUMP_SYMBOL_CALLBACK_FAILED")

    return read_saved, symbol_callback


def _require_saved_unwind_owner_clear():
    if _SAVED_UNWIND_OWNER is not None:
        from .deep_native import NativeError
        error = NativeError("RECOVERY_UNCONFIRMED", "PREVIOUS_OFFLINE_UNWIND_OWNER_REQUIRES_EXPLICIT_CLEANUP")
        error.offline_owner_retained = True
        error.resource_owner = "SAVED_DBGHELP_SESSION"
        raise error


def _release_saved_unwind_owner(owner):
    """Release only this retained capability, in borrowed-image lifetime order."""
    adapter = owner.get("memory_adapter")
    if adapter is not None:
        # Retained native callback objects stay alive, but cleanup may never
        # reuse a reader whose enclosing dump scope has already been closed.
        adapter.enabled = False
    if owner.get("release_unconfirmed"):
        return owner["release_unconfirmed"]
    if owner["initialized"]:
        try:
            confirmed = owner["cleanup"](owner["handle"])
        except BaseException:
            return "SYM_CLEANUP_EXCEPTION_OWNER_RETAINED"
        if not confirmed:
            return "SYM_CLEANUP_NOT_CONFIRMED_OWNER_RETAINED"
        owner["initialized"] = False
    owner.pop("callbacks", None)  # Only after SymCleanup has confirmed release.
    owner.pop("memory_adapter", None)
    try:
        owner["images"].close()
    except BaseException:
        owner["release_unconfirmed"] = "PINNED_IMAGE_RELEASE_UNCONFIRMED_RESTART_REQUIRED"
        return owner["release_unconfirmed"]
    try:
        closed = owner["kernel"].close(owner["handle"])
    except BaseException:
        closed = False
    if not closed:
        # An unverified CloseHandle outcome cannot be retried by numeric value:
        # it might already have been recycled by Windows for another owner.
        owner["release_unconfirmed"] = "SESSION_HANDLE_RELEASE_UNCONFIRMED_RESTART_REQUIRED"
        return owner["release_unconfirmed"]
    return None


def retry_saved_unwind_cleanup(*, deadline=None, cancel_event=None):
    """Explicit resource cleanup retry; never repeats a dump/native action."""
    from .deep_native import _DBGHELP_LOCK, _check
    global _SAVED_UNWIND_OWNER
    if deadline is not None and (type(deadline) not in (int, float) or not 0 < deadline < float("inf")):
        raise ValueError("INVALID_OFFLINE_CLEANUP_DEADLINE")
    deadline = min(time.monotonic() + 5, deadline) if deadline is not None else time.monotonic() + 5
    _check(deadline, cancel_event)
    if not _DBGHELP_LOCK.acquire(timeout=max(.001, deadline - time.monotonic())):
        raise TimeoutError("DBGHELP_CLEANUP_BUSY")
    try:
        _check(deadline, cancel_event)
        owner = _SAVED_UNWIND_OWNER
        if owner is None:
            return {"status": "COMPLETED", "data": {"offline_owner_retained": False,
                    "had_retained_owner": False, "cleanup_confirmed": True,
                    "source": "OWNED_OFFLINE_DBGHELP_SESSION", "resource_owner": "SAVED_DBGHELP_SESSION", "memory_contents_included": False},
                    "limitations": ["NO_DUMP_OR_NATIVE_ACTION_WAS_REPEATED"], "error": None}
        reason = _release_saved_unwind_owner(owner)
        if reason is not None:
            return {"status": "RECOVERY_UNCONFIRMED", "data": {"offline_owner_retained": True,
                    "had_retained_owner": True, "cleanup_confirmed": False,
                    "source": "OWNED_OFFLINE_DBGHELP_SESSION", "resource_owner": "SAVED_DBGHELP_SESSION", "memory_contents_included": False},
                    "error": reason, "limitations": ["NO_DUMP_OR_NATIVE_ACTION_WAS_REPEATED"]}
        _SAVED_UNWIND_OWNER = None
        return {"status": "COMPLETED", "data": {"offline_owner_retained": False,
                "had_retained_owner": True, "cleanup_confirmed": True,
                "source": "OWNED_OFFLINE_DBGHELP_SESSION", "resource_owner": "SAVED_DBGHELP_SESSION", "memory_contents_included": False},
                "limitations": ["NO_DUMP_OR_NATIVE_ACTION_WAS_REPEATED"], "error": None}
    finally:
        _DBGHELP_LOCK.release()


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


def _release_live_stack_owner(owner):
    """Keep DbgHelp's borrowed clone/images alive until exact release ACKs."""
    from .deep_native import _DBGHELP_LOCK
    if owner.get("release_unconfirmed"):
        return owner["release_unconfirmed"]
    owner["winerror"] = None
    if owner.get("initialized"):
        if not _DBGHELP_LOCK.acquire(timeout=5):
            return "LIVE_STACK_DBGHELP_CLEANUP_BUSY"
        try:
            try:
                confirmed = owner["cleanup"](owner["clone"])
            except BaseException:
                owner["release_unconfirmed"] = "LIVE_STACK_SYM_CLEANUP_EXCEPTION_RESTART_REQUIRED"
                return owner["release_unconfirmed"]
            if not confirmed:
                owner["winerror"] = getattr(C, "get_last_error", lambda: None)()
                return "LIVE_STACK_SYM_CLEANUP_NOT_ACKNOWLEDGED"
            owner["initialized"] = False
            owner.pop("callbacks", None)
        finally:
            _DBGHELP_LOCK.release()
    try:
        owner["images"].close()
    except BaseException:
        # ExitStack consumes attempted closers. Repeating a numeric close after
        # an ambiguous outcome could release an unrelated reused handle.
        owner["release_unconfirmed"] = "LIVE_STACK_PINNED_IMAGE_RELEASE_UNCONFIRMED_RESTART_REQUIRED"
        return owner["release_unconfirmed"]
    for key, api, arguments in (("marker", "marker_free", lambda value: (value,)),
                                ("snapshot", "free", lambda value: (owner["kernel"].current_process(), value))):
        value = owner.get(key)
        if not value:
            continue
        try:
            error = owner[api](*arguments(value))
        except BaseException:
            owner["release_unconfirmed"] = "LIVE_STACK_" + key.upper() + "_RELEASE_EXCEPTION_RESTART_REQUIRED"
            return owner["release_unconfirmed"]
        if error:
            owner["winerror"] = int(error)
            if error == 6:
                owner["release_unconfirmed"] = "LIVE_STACK_" + key.upper() + "_OWNERSHIP_LOST_RESTART_REQUIRED"
                return owner["release_unconfirmed"]
            return "LIVE_STACK_" + key.upper() + "_RELEASE_NOT_ACKNOWLEDGED"
        owner[key] = None
    return None


def _track_live_stack_owner(inspector, owner):
    from .deep_native import _QUERY_CLEANUP
    resource = {"kind": "LIVE_PSS_DBGHELP_CONTEXT", "closed": False}
    def release():
        reason = _release_live_stack_owner(owner)
        resource.update(reason=reason, release_winerror=owner.get("winerror"))
        if owner.get("release_unconfirmed"):
            resource["retry_close_allowed"] = False
        return reason is None
    resource["release"] = release
    inspector._owned_native_handles.append(resource)
    scope = getattr(_QUERY_CLEANUP, "current", None)
    if scope is not None and scope.inspector is inspector:
        scope.register(resource)
    return resource


def collect_stacks(inspector, params, deadline, cancel):
    from .deep_native import NativeError, _check, _integer, _os_error, _DBGHELP_LOCK, _close_native_resource
    if any(row["kind"] == "LIVE_PSS_DBGHELP_CONTEXT" and not row["closed"]
           for row in inspector._owned_native_handles):
        raise NativeError("RECOVERY_UNCONFIRMED", "PREVIOUS_LIVE_STACK_OWNER_REQUIRES_EXPLICIT_CLEANUP")
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
        class _SymbolCancellation:
            def is_set(self):
                # Keep the action's shorter deadline and typed cancellation
                # status during bounded local PE/PDB preparation as well.
                _check(deadline, cancel)
                return False
        symbols = load_native_symbols(symbol_module["path"], params["pdb_path"], cancel=_SymbolCancellation())
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
        # Module/symbol preparation may consume the deadline. Never begin a
        # new process snapshot (which may briefly pause threads) after that.
        _check(deadline, cancel)
        owner = {"kernel": kernel, "snapshot": snapshot, "clone": clone,
                 "marker": marker, "free": free, "marker_free": marker_free,
                 "images": ExitStack(), "initialized": False}
        resource = _track_live_stack_owner(inspector, owner)
        try:
            error = capture(process, 0x1 | 0x80 | 0x100, 0x00100003, C.byref(snapshot))
            if error:
                raise _os_error("PSS_CAPTURE_SNAPSHOT_FAILED", error)
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
                owner.update(cleanup=cleanup, library=dbg, callbacks=(read_clone,))
                image_owners = owner["images"]
                try:
                    if not initialize(clone, "", False):
                        raise _os_error("SYM_INITIALIZE_FAILED")
                    owner["initialized"] = True
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
                    set_options(previous_options)
            finally:
                _DBGHELP_LOCK.release()
        finally:
            if _close_native_resource(resource):
                inspector._owned_native_handles.remove(resource)
                cleanup_error = 0
            else:
                raise NativeError("RECOVERY_UNCONFIRMED", resource.get("reason") or
                                  "LIVE_STACK_CLEANUP_NOT_ACKNOWLEDGED", resource.get("winerror"))
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


def unwind_saved_contexts(contexts, read_memory, modules, image_path, *, pdb_path=None,
                          max_frames=64, deadline=None, cancel=None, metadata_result=None):
    """Reuse DbgHelp for an explicit saved AMD64 image, never a live process.

    Captured memory has priority. Truly absent typed unwind metadata may come
    from the explicit pinned PE; target stack/data never do. No dump-embedded
    path, automatic symbol discovery, code or zero-filled image mapping is used.
    """
    from .deep_native import _DBGHELP_LOCK, _check, _os_error
    global _SAVED_UNWIND_OWNER
    _require_saved_unwind_owner_clear()
    if C.sizeof(W.CONTEXT64) != 1232:
        raise ValueError("UNSUPPORTED_AMD64_BASE_CONTEXT_ABI")
    from .decoder_pdb import _local_file, _stable_file
    from .decoder_native_symbols import _pe_layout, load_native_symbols
    path, initial = _local_file(image_path)
    with path.open("rb") as binary:
        _stable_file(path, initial, os.fstat(binary.fileno()))
        pe = _pe_layout(binary, initial.st_size)
        _stable_file(path, initial, os.fstat(binary.fileno()))
    matches = [m for m in modules if isinstance(m.get("pdb_identity"), dict) and
               m["pdb_identity"].get("guid") == pe.get("guid") and
               m["pdb_identity"].get("age") == pe.get("age") and
               m.get("image_size") == pe.get("image_size") and
               m.get("image_timestamp") == pe.get("image_timestamp")]
    if pe.get("machine") != 0x8664 or len(matches) != 1:
        raise ValueError("SAVED_MODULE_AND_LOCAL_IMAGE_IDENTITY_MISMATCH_OR_AMBIGUOUS")
    saved = matches[0]
    module = {"base": saved["base_address"], "size": saved["image_size"],
              "name": saved["name"], "path": str(path), "snapshot_pe": pe}
    class SymbolCancellation:
        def is_set(self):
            _check(deadline, cancel)
            return False
    symbols = load_native_symbols(path, pdb_path, cancel=SymbolCancellation()) if pdb_path else None
    if symbols is not None and not _same_unwind_image(pe, symbols.pe):
        raise ValueError("SAVED_MODULE_LOCAL_PDB_IDENTITY_MISMATCH")
    kernel = W.Kernel()
    create = W.bind(kernel.dll, "CreateEventW", W.HANDLE, W.PTR, W.BOOL, W.BOOL, C.c_wchar_p)
    owner = state = None
    acquired = False
    cleanup_reason = None
    try:
        _check(deadline, cancel)
        remaining = max(.001, deadline - time.monotonic()) if deadline else 15
        acquired = _DBGHELP_LOCK.acquire(timeout=remaining)
        if not acquired:
            raise TimeoutError("DBGHELP_BUSY")
        _require_saved_unwind_owner_clear()
        owner = create(None, False, False, None)
        if not owner:
            raise _os_error("OFFLINE_UNWIND_SESSION_HANDLE_FAILED")
        state = {"kernel": kernel, "handle": owner, "images": ExitStack(), "initialized": False}
        dbg = W.library("dbghelp")
        initialize = W.bind(dbg, "SymInitializeW", W.BOOL, W.HANDLE, C.c_wchar_p, W.BOOL)
        cleanup = W.bind(dbg, "SymCleanup", W.BOOL, W.HANDLE)
        state["cleanup"] = cleanup
        state["library"] = dbg
        options = W.bind(dbg, "SymGetOptions", W.U32)
        set_options = W.bind(dbg, "SymSetOptions", W.U32, W.U32)
        load_module = W.bind(dbg, "SymLoadModuleExW", W.U64, W.HANDLE, W.HANDLE,
                             C.c_wchar_p, C.c_wchar_p, W.U64, W.U32, W.PTR, W.U32)
        register_callback = W.bind(dbg, "SymRegisterCallback64", W.BOOL, W.HANDLE, W.PTR, W.U64)
        walk = W.bind(dbg, "StackWalk64", W.BOOL, W.U32, W.HANDLE, W.HANDLE,
                      C.POINTER(W.STACKFRAME64), W.PTR, W.PTR, W.PTR, W.PTR, W.PTR)
        table = W.bind(dbg, "SymFunctionTableAccess64", W.PTR, W.HANDLE, W.U64)
        module_base = W.bind(dbg, "SymGetModuleBase64", W.U64, W.HANDLE, W.U64)
        previous_options = options()
        image_owners = state["images"]
        set_options(0x4 | 0x80 | 0x100 | 0x200 | 0x400 | 0x1000 |
                    0x20000 | 0x40000 | 0x80000 | 0x200000 | 0x2000000)
        try:
            if not initialize(owner, "", False):
                raise _os_error("OFFLINE_SYM_INITIALIZE_FAILED")
            state["initialized"] = True
            rows = []
            adapter = _SavedMemoryAdapter(owner, read_memory, lambda: _check(deadline, cancel))
            read_saved, symbol_callback = _saved_memory_callbacks(adapter, C.WINFUNCTYPE)
            # DbgHelp's symbol handler may read unwind metadata separately from
            # StackWalk64. Its callback must use the same captured-only reader.
            # Keep both native closures alive even if SymCleanup later fails.
            state["memory_adapter"] = adapter
            state["callbacks"] = (read_saved, symbol_callback)
            if not register_callback(owner, C.cast(symbol_callback, W.PTR), 0):
                raise _os_error("OFFLINE_SYMBOL_READ_CALLBACK_REGISTRATION_FAILED")
            image_handle = image_owners.enter_context(_unwind_image(kernel, module))
            from .deep_pe_unwind import PinnedPEUnwindMetadata
            # An independent open cursor must never move DbgHelp's borrowed
            # hFile pointer. The earlier pin denies writes and path replacement.
            metadata_stream = image_owners.enter_context(path.open("rb"))
            _stable_file(path, initial, os.fstat(metadata_stream.fileno()))
            provider = PinnedPEUnwindMetadata(metadata_stream, initial.st_size, pe, module["base"],
                                              lambda: _check(deadline, cancel))
            _stable_file(path, initial, os.fstat(metadata_stream.fileno()))
            if symbols is not None and provider.sha256 != symbols.summary()["pe_sha256"]:
                raise ValueError("PINNED_PE_METADATA_AND_PDB_SOURCE_HASH_MISMATCH")
            adapter.metadata_provider = provider
            if metadata_result is not None:
                metadata_result.update(provider.facts())
            loaded = load_module(owner, image_handle, None, module["name"],
                                 module["base"], module["size"], None, 0)
            if adapter.error is not None:
                raise adapter.error
            if loaded != module["base"]:
                raise ValueError("OFFLINE_MATCHED_UNWIND_IMAGE_NOT_LOADED")

            for saved_context in contexts:
                _check(deadline, cancel)
                row = {"tid": saved_context["tid"], "frames": [], "status": "INCOMPLETE_EVIDENCE",
                       "unwind_completeness": "NOT_PROVEN", "method": "SAVED_AMD64_DBGHELP_STACKWALK64",
                       "context_source": saved_context.get("context_source", "SAVED_THREAD_CONTEXT"),
                       "context_bytes_recorded": saved_context.get("context_bytes_recorded", len(saved_context["context"])),
                       "base_context_bytes_copied": min(len(saved_context["context"]), 1232),
                       "context_trailing_bytes_recorded": saved_context.get("context_trailing_bytes_recorded", max(0, len(saved_context["context"]) - 1232)),
                       "context_extension_status": "EXTENSIONS_NOT_ANALYZED",
                       "recorded_context_flags": saved_context.get("recorded_context_flags"),
                       "memory_contents_included": False}
                raw = saved_context["context"]
                if len(raw) < C.sizeof(W.CONTEXT64):
                    row["reason"] = "FULL_AMD64_CONTEXT_NOT_CAPTURED"
                    rows.append(row)
                    continue
                storage, context, recorded_flags = _saved_base_context(raw)
                row["recorded_context_flags"] = recorded_flags
                row["native_context_flags"] = int(context.flags)
                row["xstate_advertisement_cleared"] = bool(recorded_flags & 0x40)
                if context.flags & 0x100001 != 0x100001:
                    row["reason"] = "AMD64_CONTROL_CONTEXT_NOT_CAPTURED"
                    rows.append(row)
                    continue
                frame = W.STACKFRAME64()
                frame.pc.offset, frame.frame.offset, frame.stack.offset = context.rip, context.rbp, context.rsp
                frame.pc.mode = frame.frame.mode = frame.stack.mode = 3
                adapter.error = adapter.reason = None
                row["symbol_handler_callback_registered"] = True
                selected_context = module["base"] <= context.rip < module["base"] + module["size"]
                row["function_table_for_context_available"] = bool(table(owner, context.rip)) if selected_context else None
                row["dbghelp_module_base_matches_selected_image"] = (
                    module_base(owner, context.rip) == module["base"] if selected_context else None)
                if adapter.error is not None:
                    raise adapter.error

                def advance():
                    _check(deadline, cancel)
                    C.set_last_error(0)
                    ok = walk(0x8664, owner, saved_context["tid"], C.byref(frame), C.byref(context),
                              C.cast(read_saved, W.PTR), C.cast(table, W.PTR),
                              C.cast(module_base, W.PTR), None)
                    if adapter.error is not None:
                        raise adapter.error
                    if not ok:
                        row["unwind_winerror"] = C.get_last_error()
                        return None
                    return int(frame.pc.offset), int(frame.stack.offset)

                initial = int(context.rip), int(context.rsp)
                for index, (pc, sp) in enumerate(_stack_positions(initial, advance, max_frames)):
                    _check(deadline, cancel)
                    in_module = module["base"] <= pc < module["base"] + module["size"]
                    record = {"address": pc, "stack_pointer": sp,
                              "origin": "CAPTURED_CONTEXT_PC" if index == 0 else "DBGHELP_UNWOUND_CALLER",
                              "module": module["name"] if in_module else None,
                              "rva": pc - module["base"] if in_module else None,
                              "module_binding": "SAVED_RSDS_AND_PINNED_LOCAL_PE_MATCH" if in_module else "NOT_ESTABLISHED"}
                    if in_module and symbols is not None:
                        record["symbol"] = symbols.lookup(record["rva"])
                        record["symbol_binding"] = "SAVED_RSDS_LOCAL_PE_PDB_GUID_AGE_MATCH"
                    row["frames"].append(record)
                    # Do not use DbgHelp's leaf fallback in unverified modules.
                    if not in_module:
                        row["reason"] = "UNWIND_METADATA_FOR_NEXT_MODULE_NOT_VERIFIED"
                        break
                del storage
                row["truncated"] = len(row["frames"]) >= max_frames
                row["captured_memory_stop_reason"] = adapter.reason
                row["memory_read_contract"] = "CAPTURED_MEMORY_AND_TYPED_PINNED_PE_UNWIND_METADATA"
                row["unwind_read_counters"] = dict(adapter.counters)
                row["failed_read_classes"] = dict(adapter.failed_read_classes)
                row["local_image_metadata"] = provider.facts()
                if len(row["frames"]) > 1:
                    row["status"] = "UNWOUND_PARTIAL_STACK"
                if symbols is not None:
                    row["local_pdb"] = symbols.summary()
                rows.append(row)
            return rows
        finally:
            cleanup_reason = _release_saved_unwind_owner(state)
            state["cleanup_processed"] = True
            if cleanup_reason is not None:
                _SAVED_UNWIND_OWNER = state
            set_options(previous_options)
    finally:
        if state is not None and not state.get("cleanup_processed"):
            cleanup_reason = _release_saved_unwind_owner(state)
            if cleanup_reason is not None:
                _SAVED_UNWIND_OWNER = state
        if acquired:
            _DBGHELP_LOCK.release()
        if cleanup_reason is not None:
            from .deep_native import NativeError
            error = NativeError("RECOVERY_UNCONFIRMED", cleanup_reason)
            error.offline_owner_retained = True
            error.resource_owner = "SAVED_DBGHELP_SESSION"
            raise error

