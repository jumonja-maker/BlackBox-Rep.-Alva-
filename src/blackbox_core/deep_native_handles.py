"""Handle inventory and killable object-name queries.

NtQueryObject(ObjectNameInformation) can block indefinitely for some objects.
It is therefore never called in the persistent inspector/debugger process.
"""
from __future__ import annotations

import ctypes as C
import json
import os
import subprocess
import sys
import tempfile
import time

from . import deep_native_win as W


def handle_rows(pid, limit, deadline=None, cancel_event=None):
    from .deep_native import NativeError, _check
    dll = W.library("ntdll")
    query = W.bind(dll, "NtQuerySystemInformation", W.I32, W.U32, W.PTR, W.U32, C.POINTER(W.U32))
    capacity, returned = 1024 * 1024, W.U32()
    while capacity <= 64 * 1024 * 1024:
        _check(deadline, cancel_event)
        buffer = C.create_string_buffer(capacity)
        status = query(64, buffer, capacity, C.byref(returned)) & 0xFFFFFFFF
        if status == 0:
            break
        if status not in (0xC0000004, 0xC0000023):
            raise NativeError("ACCESS_DENIED" if status == 0xC0000022 else "OPERATION_FAILED",
                              "SYSTEM_HANDLE_QUERY_NTSTATUS_%08X" % status)
        capacity = max(capacity * 2, returned.value + 4096)
    else:
        raise NativeError("INCOMPLETE_EVIDENCE", "SYSTEM_HANDLE_TABLE_MEMORY_BUDGET")
    header_size, item_size = C.sizeof(W.SIZE) * 2, C.sizeof(W.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
    count = W.SIZE.from_buffer(buffer).value
    available = min(capacity, returned.value or capacity)
    if count > 1_000_000 or header_size + count * item_size > available:
        raise NativeError("INCOMPLETE_EVIDENCE", "SYSTEM_HANDLE_TABLE_LAYOUT_BUDGET")
    rows, omitted = [], 0
    for index in range(count):
        if index % 1024 == 0:
            _check(deadline, cancel_event)
        item = W.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.from_buffer(buffer, header_size + index * item_size)
        if item.pid != pid:
            continue
        if len(rows) >= limit:
            omitted += 1
            continue
        rows.append({"handle": int(item.value), "type_index": int(item.type_index),
                     "granted_access": int(item.access), "attributes": int(item.attributes),
                     "pid": pid})
    return rows, omitted


def _unicode_query(query, handle, kind):
    capacity, required = 1024, W.U32()
    while capacity <= 64 * 1024:
        buffer = C.create_string_buffer(capacity)
        status = query(handle, kind, buffer, capacity, C.byref(required)) & 0xFFFFFFFF
        if status == 0:
            value = W.UNICODE_STRING.from_buffer(buffer)
            if not value.length:
                return ""
            offset = int(value.buffer or 0) - C.addressof(buffer)
            if (value.length % 2 or value.length > 32 * 1024 or
                    offset < C.sizeof(W.UNICODE_STRING) or offset + value.length > capacity):
                raise ValueError("OBJECT_UNICODE_STRING_OUTSIDE_BUFFER")
            return C.string_at(value.buffer, value.length).decode("utf-16-le", "replace")
        if status not in (0xC0000004, 0xC0000023, 0x80000005):
            raise OSError("OBJECT_QUERY_NTSTATUS_%08X" % status)
        capacity = max(capacity * 2, required.value)
    raise ValueError("OBJECT_NAME_MEMORY_BUDGET")


def _query_child(pid, created_100ns, value):
    from .deep_native import capture_identity, _times
    if capture_identity(pid).created_100ns != created_100ns:
        return {"name_status": "PROCESS_CHANGED", "name": None, "type_name": None}
    kernel = W.Kernel()
    process = kernel.open_process(0x1040, False, pid)
    if not process:
        return {"name_status": "ACCESS_DENIED", "winerror": C.get_last_error(), "name": None, "type_name": None}
    duplicate = W.HANDLE()
    try:
        if _times(kernel.process_times, process)[0] != created_100ns:
            return {"name_status": "PROCESS_CHANGED", "name": None, "type_name": None}
        if not kernel.duplicate(process, value, kernel.current_process(), C.byref(duplicate), 0, False, 2):
            return {"name_status": "INCOMPLETE_EVIDENCE", "winerror": C.get_last_error(), "name": None, "type_name": None}
        query = W.bind(W.library("ntdll"), "NtQueryObject", W.I32, W.HANDLE, W.U32, W.PTR, W.U32, C.POINTER(W.U32))
        type_name = _unicode_query(query, duplicate, 2)
        try:
            name = _unicode_query(query, duplicate, 1)
            status = "COMPLETED"
        except (OSError, ValueError):
            name, status = None, "INCOMPLETE_EVIDENCE"
        return {"name_status": status, "type_name": type_name, "name": name,
                "binding": "SAME_PROCESS_INSTANCE_HANDLE_VALUE_NOT_PERMANENT_OBJECT_IDENTITY"}
    finally:
        if duplicate:
            kernel.close(duplicate)
        kernel.close(process)


def query_bounded(identity, value, deadline=None, cancel_event=None):
    from .deep_native import _check
    from .optional_jobs import OwnedProcess
    _check(deadline, cancel_event)
    args = [str(identity.pid), str(identity.created_100ns), str(value)]
    command = ([sys.executable, "--deep-handle-query", *args] if getattr(sys, "frozen", False)
               else [sys.executable, "-m", "blackbox_core.deep_native_handles", *args])
    end = min(time.monotonic() + .75, deadline if deadline is not None else float("inf"))
    owner = None
    with tempfile.TemporaryFile() as output:
        try:
            owner = OwnedProcess(command, stdout=output, stderr=subprocess.DEVNULL, detach_console=True)
            while owner.process.poll() is None:
                _check(deadline, cancel_event)
                if time.monotonic() >= end:
                    return {"name_status": "TIMED_OUT", "name": None, "type_name": None}
                time.sleep(.01)
            if owner.process.returncode:
                return {"name_status": "INCOMPLETE_EVIDENCE", "name": None, "type_name": None}
            output.seek(0)
            data = output.read(65537)
            if len(data) > 65536:
                raise ValueError("HANDLE_QUERY_RESULT_BUDGET")
            result = json.loads(data)
            if (not isinstance(result, dict) or set(result) -
                    {"name_status", "name", "type_name", "binding", "winerror"}):
                raise ValueError("HANDLE_QUERY_RESULT_SCHEMA")
            return result
        except (OSError, ValueError):
            return {"name_status": "INCOMPLETE_EVIDENCE", "name": None, "type_name": None}
        finally:
            if owner is not None:
                owner.close(kill=owner.process.poll() is None)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 3 or os.name != "nt":
        return 2
    try:
        pid, created, handle = (int(x, 10) for x in args)
        if not (0 < pid < 2**32 and 0 < created < 2**64 and 0 < handle < 2**64):
            raise ValueError("INVALID_HANDLE_QUERY")
        result = _query_child(pid, created, handle)
        data = json.dumps(result, ensure_ascii=True, allow_nan=False)
        if len(data) > 65536:
            raise ValueError("HANDLE_QUERY_RESULT_BUDGET")
        # A frozen --windowed helper and pythonw may have sys.stdout=None,
        # although Popen supplied a real redirected Win32 standard handle.
        kernel = W.Kernel()
        get_stdout = W.bind(kernel.dll, "GetStdHandle", W.HANDLE, W.U32)
        output = get_stdout(0xFFFFFFF5)  # STD_OUTPUT_HANDLE
        if not output or output == W.INVALID_HANDLE:
            raise OSError("HANDLE_QUERY_STDOUT_UNAVAILABLE")
        raw = (data + "\n").encode("ascii")
        buffer, written = C.create_string_buffer(raw), W.U32()
        if not kernel.write_file(output, buffer, len(raw), C.byref(written), None) or written.value != len(raw):
            raise OSError("HANDLE_QUERY_STDOUT_FAILED")
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

