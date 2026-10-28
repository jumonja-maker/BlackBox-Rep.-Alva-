"""MiniDumpWriteDump to an ordinary-user-created, explicitly duplicated handle.

No elevated path opening is allowed. IoWriteAll callbacks enforce the file
budget before each write, including sparse offsets, and cancel cooperatively.
"""
from __future__ import annotations

import ctypes as C
import time

from . import deep_native_win as W


class IO_CALLBACK(C.Structure):
    _pack_ = 4
    _fields_ = [("handle", W.HANDLE), ("offset", W.U64),
                ("buffer", W.PTR), ("size", W.U32)]


class CALLBACK_DATA(C.Union):
    _pack_ = 4
    _fields_ = [("io", IO_CALLBACK), ("status", W.I32)]


class CALLBACK_INPUT(C.Structure):
    _pack_ = 4
    _fields_ = [("pid", W.U32), ("process", W.HANDLE),
                ("type", W.U32), ("data", CALLBACK_DATA)]


def write_dump(inspector, params, deadline, cancel):
    from .deep_native import NativeError, _check, _integer, _os_error, _DBGHELP_LOCK, MAX_DUMP_BYTES
    output = _integer(params.get("file_handle"), "file_handle", 1)
    kernel = W.Kernel()
    try:
        full = params.get("full", False)
        if type(full) is not bool:
            raise ValueError("INVALID_DUMP_FULL_FLAG")
        maximum = _integer(params.get("max_bytes", MAX_DUMP_BYTES), "max_bytes", 65536, MAX_DUMP_BYTES)
        initial = W.I64()
        if kernel.file_type(output) != 1 or not kernel.file_size(output, C.byref(initial)) or initial.value:
            raise ValueError("DUMP_REQUIRES_EMPTY_REGULAR_FILE_HANDLE")
        callback_type = C.WINFUNCTYPE(W.BOOL, W.PTR, C.POINTER(CALLBACK_INPUT), W.PTR)

        class CALLBACK_INFORMATION(C.Structure):
            _pack_ = 4
            _fields_ = [("callback", callback_type), ("parameter", W.PTR)]

        state = {"reason": None, "maximum_written_offset": 0, "write_callbacks": 0}

        def stop_reason():
            if cancel is not None and cancel.is_set():
                return "CANCELLED"
            if deadline is not None and time.monotonic() >= deadline:
                return "TIMED_OUT"
            return state["reason"]

        @callback_type
        def callback(_, incoming, outgoing):
            try:
                kind = incoming.contents.type
                if kind == 6:  # CancelCallback: enable repeated checks.
                    out = C.cast(outgoing, C.POINTER(W.BOOL))
                    out[0], out[1] = 1, int(bool(stop_reason()))
                    return True
                if kind == 11:  # IoStartCallback: S_FALSE selects our writer.
                    C.cast(outgoing, C.POINTER(W.I32))[0] = 1
                    return True
                if kind == 13:  # IoFinishCallback
                    C.cast(outgoing, C.POINTER(W.I32))[0] = 0
                    return True
                if kind != 12:  # DbgHelp retains default module/thread flags.
                    return True
                io = incoming.contents.data.io
                status = C.cast(outgoing, C.POINTER(W.I32))
                reason = stop_reason()
                if reason or io.offset > maximum or io.size > maximum - io.offset:
                    state["reason"] = reason or "DUMP_SIZE_LIMIT_REACHED"
                    status[0] = -2147467260  # E_ABORT
                    return True
                if io.size and not io.buffer:
                    state["reason"] = "INVALID_MINIDUMP_IO_BUFFER"
                    status[0] = -2147467260
                    return True
                if not kernel.file_pointer(output, int(io.offset), None, 0):
                    state["reason"] = "DUMP_SEEK_FAILED"
                    status[0] = -2147467260
                    return True
                written = W.U32()
                if not kernel.write_file(output, io.buffer, io.size, C.byref(written), None) or written.value != io.size:
                    state["reason"] = "DUMP_WRITE_FAILED"
                    status[0] = -2147467260
                    return True
                state["maximum_written_offset"] = max(state["maximum_written_offset"], int(io.offset + io.size))
                state["write_callbacks"] += 1
                status[0] = 0
                return True
            except BaseException:
                state["reason"] = "DUMP_CALLBACK_FAILED"
                return False

        callback_info = CALLBACK_INFORMATION(callback, None)
        remaining = max(.001, deadline - time.monotonic()) if deadline else 120
        if not _DBGHELP_LOCK.acquire(timeout=remaining):
            raise NativeError("TIMED_OUT", "DBGHELP_BUSY")
        try:
            with inspector._open(0x450) as (_, process):
                _check(deadline, cancel)
                dbg = W.library("dbghelp")
                write = W.bind(dbg, "MiniDumpWriteDump", W.BOOL, W.HANDLE, W.U32, W.HANDLE,
                               W.U32, W.PTR, W.PTR, C.POINTER(CALLBACK_INFORMATION))
                flags = 0x1000 | 0x800 | (0x2 if full else 0)
                C.set_last_error(0)
                ok = write(process, inspector.identity.pid, output, flags, None, None, C.byref(callback_info))
                error = C.get_last_error()
                reason = stop_reason()
                if reason:
                    raise NativeError(reason if reason in ("CANCELLED", "TIMED_OUT") else "INCOMPLETE_EVIDENCE", reason, error)
                if not ok:
                    raise _os_error("MINIDUMP_WRITE_FAILED", error)
        finally:
            _DBGHELP_LOCK.release()
        size = W.I64()
        if (not kernel.flush_file(output) or not kernel.file_size(output, C.byref(size)) or
                not 32 <= size.value <= maximum or not state["write_callbacks"]):
            raise NativeError("INCOMPLETE_EVIDENCE", "MINIDUMP_BUDGET_OR_FLUSH_UNCONFIRMED")
        read = W.bind(kernel.dll, "ReadFile", W.BOOL, W.HANDLE, W.PTR, W.U32, C.POINTER(W.U32), W.PTR)
        header, count = C.create_string_buffer(32), W.U32()
        if (not kernel.file_pointer(output, 0, None, 0) or
                not read(output, header, 32, C.byref(count), None) or
                count.value != 32 or header.raw[:4] != b"MDMP"):
            raise NativeError("INCOMPLETE_EVIDENCE", "MINIDUMP_HEADER_UNCONFIRMED")
        return {"bytes": size.value, "full_memory": full, "flags": flags,
                "max_bytes": maximum, "io_write_callbacks": state["write_callbacks"],
                "signature": "MDMP", "sensitive": True, "automatic_share_allowed": False,
                "_source": "DBGHELP_MINIDUMP_TO_EXPLICIT_USER_HANDLE",
                "_limitations": ["SENSITIVE_MEMORY_NOT_AUTOMATICALLY_SHARED", "DYNAMIC_DUMP_MAY_CONTAIN_PARTIAL_MEMORY",
                                  "NO_FULL_ROLLBACK_OR_MEMORY_CONSISTENCY_GUARANTEE"]}
    finally:
        # The authenticated helper owns this duplicate and closes it exactly
        # once, including validation/cancellation before this function starts.
        # Native dump writing only borrows the handle.
        pass

