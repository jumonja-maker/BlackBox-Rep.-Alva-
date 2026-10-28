"""Explicit, bounded Windows process inspection for BB-DEEP-001.

Every native handle is bound to the requested process creation FILETIME.
Returned memory is sensitive and is never implicitly written into a journal.
Live snapshots are deliberately distinct from historical ETW evidence.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes as C
import hashlib
import os
from pathlib import Path
import struct
import threading
import time
from uuid import UUID

from .deep_contracts import ProcessIdentity, canonical_operation
from . import deep_native_win as W

MAX_MEMORY_READ = 64 * 1024
MAX_ROWS = 4096
MAX_DUMP_BYTES = 512 * 1024 * 1024
_DBGHELP_LOCK = threading.Lock()


class NativeError(Exception):
    def __init__(self, status, reason, winerror=None):
        super().__init__(reason)
        self.status, self.reason, self.winerror = status, reason, winerror


def _integer(value, name, minimum=0, maximum=2**64 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("INVALID_" + name.upper())
    return value


def _check(deadline=None, cancel_event=None):
    if cancel_event is not None and cancel_event.is_set():
        raise NativeError("CANCELLED", "OPERATION_CANCELLED")
    if deadline is not None and time.monotonic() >= deadline:
        raise NativeError("TIMED_OUT", "OPERATION_DEADLINE")


def _windows():
    if os.name != "nt":
        raise NativeError("UNSUPPORTED_PLATFORM", "WINDOWS_API_REQUIRED")


def _os_error(reason, error=None):
    code = C.get_last_error() if error is None else int(error)
    status = "ACCESS_DENIED" if code == 5 else "PROCESS_CHANGED" if code in (6, 87, 1168) else "OPERATION_FAILED"
    return NativeError(status, reason, code)


def _times(api, handle):
    created, exited, kernel, user = (W.FILETIME() for _ in range(4))
    if not api(handle, C.byref(created), C.byref(exited), C.byref(kernel), C.byref(user)):
        raise _os_error("GET_INSTANCE_TIMES_FAILED")
    return created.value, kernel.value, user.value


def _image(kernel, handle):
    length = W.U32(32768)
    value = C.create_unicode_buffer(length.value)
    if not kernel.image(handle, 0, value, C.byref(length)):
        raise _os_error("QUERY_PROCESS_IMAGE_FAILED")
    return value.value


def _identity(kernel, handle, pid):
    created, _, _ = _times(kernel.process_times, handle)
    return ProcessIdentity(pid, created, _image(kernel, handle))


def capture_identity(pid):
    """Capture actual Windows identity, never a PID-only or rounded timestamp."""
    _windows()
    _integer(pid, "pid", 1, 0xFFFFFFFF)
    kernel = W.Kernel()
    handle = kernel.open_process(0x1000 | 0x100000, False, pid)
    if not handle:
        raise _os_error("OPEN_PROCESS_IDENTITY_FAILED")
    try:
        if kernel.wait(handle, 0) != 258:
            raise NativeError("PROCESS_CHANGED", "PROCESS_ALREADY_EXITED")
        return _identity(kernel, handle, pid)
    finally:
        kernel.close(handle)


def verify_identity(identity):
    expected = ProcessIdentity.from_dict(identity)
    observed = capture_identity(expected.pid)
    if (observed.created_100ns != expected.created_100ns or
            expected.image_path and os.path.normcase(observed.image_path) != os.path.normcase(expected.image_path)):
        raise NativeError("PROCESS_CHANGED", "PROCESS_INSTANCE_CHANGED")
    return observed


def token_state():
    _windows()
    kernel = W.Kernel()
    adv = W.library("advapi32")
    open_token = W.bind(adv, "OpenProcessToken", W.BOOL, W.HANDLE, W.U32, C.POINTER(W.HANDLE))
    get_info = W.bind(adv, "GetTokenInformation", W.BOOL, W.HANDLE, W.U32, W.PTR, W.U32, C.POINTER(W.U32))
    token = W.HANDLE()
    if not open_token(kernel.current_process(), 8, C.byref(token)):
        raise _os_error("OPEN_CURRENT_TOKEN_FAILED")
    try:
        elevated, elevation_type, needed = W.U32(), W.U32(), W.U32()
        if not get_info(token, 20, C.byref(elevated), 4, C.byref(needed)):
            raise _os_error("QUERY_TOKEN_ELEVATION_FAILED")
        if not get_info(token, 18, C.byref(elevation_type), 4, C.byref(needed)):
            raise _os_error("QUERY_TOKEN_ELEVATION_TYPE_FAILED")
        return {"elevated": bool(elevated.value), "elevation_type": elevation_type.value,
                "source": "WIN32_TOKEN_ELEVATION"}
    finally:
        kernel.close(token)


_RIGHTS = {"processes": 0x1000, "modules": 0x410, "threads": 0x1000,
           "handles": 0x1040, "memory_map": 0x400, "memory_read": 0x410,
           "thread_stacks": 0x4D0, "wait_chains": 0x1000, "network": 0x1000,
           "disk": 0x1000, "snapshot": 0x1000, "dump": 0x450,
           "memory.write": 0x438, "memory.rollback": 0x438}


def probe_access(identity, operation):
    """Check actual operation rights; access denied never proves PPL."""
    try:
        operation = canonical_operation(operation)
        expected = ProcessIdentity.from_dict(identity)
        observed = verify_identity(expected)
        kernel = W.Kernel()
        query = kernel.open_process(0x1000, False, expected.pid)
        protection = None
        if query:
            try:
                level = W.U32()
                if kernel.process_information(query, 7, C.byref(level), C.sizeof(level)):
                    protection = level.value
            finally:
                kernel.close(query)
        rights = _RIGHTS.get(operation, 0x1000)
        handle = kernel.open_process(rights, False, expected.pid)
        if handle:
            try:
                if _times(kernel.process_times, handle)[0] != expected.created_100ns:
                    raise NativeError("PROCESS_CHANGED", "PROCESS_INSTANCE_CHANGED")
            finally:
                kernel.close(handle)
            return {"status": "AVAILABLE", "source": "WIN32_ACCESS_PROBE",
                    "identity": observed.to_dict(), "process_access_mask": rights,
                    "protection_level": protection,
                    "limitations": ["THREAD_AND_DEBUG_ACCESS_RECHECKED_WHEN_OPERATION_STARTS"]}
        error = C.get_last_error()
        if error == 5 and protection not in (None, 0xFFFFFFFE, 0xFFFFFFFF):
            status = "PROTECTED_PROCESS"
        elif error == 5:
            status = "ACCESS_DENIED" if token_state()["elevated"] else "ADMIN_REQUIRED"
        else:
            status = "PROCESS_CHANGED" if error in (87, 1168) else "OPERATION_FAILED"
        return {"status": status, "source": "WIN32_ACCESS_PROBE", "winerror": error,
                "protection_level": protection, "process_access_mask": rights,
                "next_action": "REQUEST_UAC" if status == "ADMIN_REQUIRED" else "SELECT_ACCESSIBLE_PROCESS"}
    except NativeError as error:
        return {"status": error.status, "reason": error.reason, "winerror": error.winerror,
                "source": "WIN32_ACCESS_PROBE"}


class ProcessInspector:
    def __init__(self, identity):
        self.identity = ProcessIdentity.from_dict(identity)
        self.closed = False

    @contextmanager
    def _open(self, rights):
        _windows()
        if self.closed:
            raise NativeError("OPERATION_FAILED", "INSPECTOR_CLOSED")
        kernel = W.Kernel()
        handle = kernel.open_process(rights | 0x1000 | 0x100000, False, self.identity.pid)
        if not handle:
            raise _os_error("OPEN_PROCESS_FOR_INSPECTION_FAILED")
        try:
            self._verify_handle(kernel, handle)
            yield kernel, handle
            self._verify_handle(kernel, handle)
        finally:
            kernel.close(handle)

    def _verify_handle(self, kernel, handle):
        if kernel.wait(handle, 0) != 258:
            raise NativeError("PROCESS_CHANGED", "PROCESS_EXITED_DURING_INSPECTION")
        observed = _identity(kernel, handle, self.identity.pid)
        if (observed.created_100ns != self.identity.created_100ns or
                self.identity.image_path and os.path.normcase(observed.image_path) != os.path.normcase(self.identity.image_path)):
            raise NativeError("PROCESS_CHANGED", "PROCESS_INSTANCE_CHANGED")

    def close(self):
        self.closed = True
        return {"status": "COMPLETED", "source": "INSPECTOR_CLEANUP", "owned_suspensions": 0}

    def execute(self, operation, parameters=None, *, deadline=None, cancel_event=None):
        started = time.monotonic_ns()
        parameters = dict(parameters or {})
        try:
            operation = canonical_operation(operation)
            _check(deadline, cancel_event)
            _windows()
            method = getattr(self, "_" + operation, None)
            if method is None:
                raise ValueError("NOT_AN_INSPECTION_OPERATION")
            data = method(parameters, deadline, cancel_event)
            if data.get("_status") != "RECOVERY_UNCONFIRMED":
                _check(deadline, cancel_event)
            status = data.pop("_status", "COMPLETED")
            limitations = data.pop("_limitations", [])
            source = data.pop("_source", "WINDOWS_LIVE_INSPECTION")
            return {"status": status, "source": source, "target": self.identity.to_dict(),
                    "data": data, "limitations": limitations,
                    "duration_ns": time.monotonic_ns() - started}
        except NativeError as error:
            return {"status": error.status, "source": "WINDOWS_LIVE_INSPECTION",
                    "target": self.identity.to_dict(), "reason": error.reason,
                    "winerror": error.winerror, "data": {}, "limitations": []}
        except (OSError, ValueError, OverflowError) as error:
            return {"status": "OPERATION_FAILED", "source": "WINDOWS_LIVE_INSPECTION",
                    "target": self.identity.to_dict(), "reason": str(error)[:400],
                    "winerror": getattr(error, "winerror", None), "data": {}, "limitations": []}

    def _processes(self, params, deadline, cancel):
        import psutil
        limit = _integer(params.get("limit", 512), "limit", 1, MAX_ROWS)
        verify_identity(self.identity)
        rows, omitted = [], 0
        for process in psutil.process_iter():
            _check(deadline, cancel)
            if len(rows) >= limit:
                omitted += 1
                continue
            row = {"pid": process.pid}
            try:
                row["identity"] = capture_identity(process.pid).to_dict()
                with process.oneshot():
                    row.update(ppid=process.ppid(), name=process.name(), owner=process.username(),
                               command_line=process.cmdline()[:128])
                if capture_identity(process.pid) != ProcessIdentity.from_dict(row["identity"]):
                    raise NativeError("PROCESS_CHANGED", "PROCESS_CHANGED_DURING_INVENTORY")
                row["status"] = "COMPLETED"
            except (psutil.Error, NativeError, OSError) as error:
                row.update(status=getattr(error, "status", "INCOMPLETE_EVIDENCE"),
                           reason=type(error).__name__)
            rows.append(row)
        verify_identity(self.identity)
        return {"rows": rows, "omitted": omitted, "selected_pid": self.identity.pid,
                "_source": "WIN32_PROCESS_IDENTITIES_AND_PSUTIL_METADATA",
                "_status": "INCOMPLETE_EVIDENCE" if omitted else "COMPLETED",
                "_limitations": ["DYNAMIC_PROCESS_TREE_PARENT_PID_IS_NOT_PARENT_LIFETIME_IDENTITY"]}

    @staticmethod
    def _read(kernel, handle, address, length):
        address = _integer(address, "address", 1, 2**64 - 1)
        length = _integer(length, "length", 1, MAX_MEMORY_READ)
        if address + length > 2**64:
            raise ValueError("ADDRESS_RANGE_OVERFLOW")
        data, count = C.create_string_buffer(length), W.SIZE()
        ok = kernel.read_memory(handle, address, data, length, C.byref(count))
        if not ok and not count.value:
            raise _os_error("READ_PROCESS_MEMORY_FAILED")
        return data.raw[:min(count.value, length)], bool(ok and count.value == length)

    def _memory_read(self, params, deadline, cancel):
        _check(deadline, cancel)
        address = _integer(params.get("address"), "address", 1)
        length = _integer(params.get("length", params.get("size", 256)), "length", 1, MAX_MEMORY_READ)
        with self._open(0x410) as (kernel, handle):
            raw, complete = self._read(kernel, handle, address, length)
        return {"address": address, "requested_bytes": length, "bytes_read": len(raw),
                "hex": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest(),
                "sensitive": True, "automatic_share_allowed": False,
                "_status": "COMPLETED" if complete else "INCOMPLETE_EVIDENCE",
                "_source": "WIN32_READ_PROCESS_MEMORY",
                "_limitations": ["LIVE_BYTES_MAY_CHANGE_BETWEEN_READS", "SENSITIVE_EXPLICIT_RESULT_ONLY"]}

    def _memory_map(self, params, deadline, cancel):
        limit = _integer(params.get("limit", 2048), "limit", 1, MAX_ROWS)
        address = _integer(params.get("start_address", 0), "start_address")
        rows, complete = [], False
        with self._open(0x400) as (kernel, handle):
            while len(rows) < limit:
                _check(deadline, cancel)
                info = W.MEMORY_BASIC_INFORMATION()
                count = kernel.virtual_query(handle, address, C.byref(info), C.sizeof(info))
                if not count:
                    if C.get_last_error() == 87:
                        complete = True
                        break
                    raise _os_error("VIRTUAL_QUERY_EX_FAILED")
                base, size = int(info.base or 0), int(info.region_size)
                if size <= 0 or base + size <= address or base + size >= 2**64:
                    raise NativeError("INCOMPLETE_EVIDENCE", "INVALID_MEMORY_REGION_PROGRESS")
                rows.append({"base": base, "size": size,
                             "allocation_base": int(info.allocation_base or 0),
                             "allocation_protection": int(info.allocation_protect),
                             "protection": int(info.protect), "state": int(info.state), "type": int(info.type),
                             "state_name": {0x1000: "COMMIT", 0x2000: "RESERVE", 0x10000: "FREE"}.get(info.state, "UNKNOWN"),
                             "type_name": {0x20000: "PRIVATE", 0x40000: "MAPPED", 0x1000000: "IMAGE", 0: "NONE"}.get(info.type, "UNKNOWN")})
                address = base + size
        return {"rows": rows, "complete_address_space": complete,
                "next_address": None if complete else address, "_source": "WIN32_VIRTUAL_QUERY_EX",
                "_status": "COMPLETED" if complete else "INCOMPLETE_EVIDENCE",
                "_limitations": ["DYNAMIC_NON_ATOMIC_ADDRESS_SPACE_SNAPSHOT"]}

    def _loaded_pe(self, kernel, handle, base):
        try:
            head, complete = self._read(kernel, handle, base, 64)
            if not complete or head[:2] != b"MZ":
                raise ValueError("NO_LOADED_PE_HEADER")
            offset = struct.unpack_from("<I", head, 60)[0]
            if not 64 <= offset <= 1024 * 1024:
                raise ValueError("LOADED_PE_HEADER_BUDGET")
            pe, complete = self._read(kernel, handle, base + offset, 512)
            if not complete or pe[:4] != b"PE\0\0":
                raise ValueError("INVALID_LOADED_PE_HEADER")
            magic = struct.unpack_from("<H", pe, 24)[0]
            directories = 24 + (112 if magic == 0x20B else 96 if magic == 0x10B else 0)
            if directories == 24:
                raise ValueError("UNSUPPORTED_LOADED_PE")
            result = {"machine": struct.unpack_from("<H", pe, 4)[0],
                      "image_timestamp": struct.unpack_from("<I", pe, 8)[0],
                      "image_size": struct.unpack_from("<I", pe, 24 + 56)[0],
                      "guid": None, "age": None}
            debug_rva, debug_size = struct.unpack_from("<II", pe, directories + 6 * 8)
            if not debug_rva or not debug_size:
                return result
            if debug_size % 28 or debug_size > 28 * 256:
                raise ValueError("LOADED_DEBUG_DIRECTORY_BUDGET")
            entries, complete = self._read(kernel, handle, base + debug_rva, debug_size)
            if not complete:
                return result
            identities = set()
            for at in range(0, len(entries), 28):
                if struct.unpack_from("<I", entries, at + 12)[0] != 2:
                    continue
                size, rva = struct.unpack_from("<II", entries, at + 16)
                if not 24 <= size <= 4096 or not rva:
                    continue
                data, complete = self._read(kernel, handle, base + rva, size)
                if complete and data[:4] == b"RSDS":
                    identities.add((str(UUID(bytes_le=data[4:20])), struct.unpack_from("<I", data, 20)[0]))
            if len(identities) == 1:
                result["guid"], result["age"] = next(iter(identities))
            return result
        except (NativeError, ValueError, struct.error):
            return None

    def _modules(self, params, deadline, cancel):
        limit = _integer(params.get("limit", 512), "limit", 1, 1024)
        hashing = params.get("hash_files", False)
        if type(hashing) is not bool:
            raise ValueError("INVALID_HASH_POLICY")
        rows, more = [], False
        with self._open(0x410) as (kernel, handle):
            snapshot = kernel.snapshot(0x8 | 0x10, self.identity.pid)
            if snapshot == W.INVALID_HANDLE:
                raise _os_error("MODULE_SNAPSHOT_FAILED")
            try:
                entry = W.MODULEENTRY32W()
                entry.size = C.sizeof(entry)
                ok = kernel.module_first(snapshot, C.byref(entry))
                while ok:
                    _check(deadline, cancel)
                    if len(rows) == limit:
                        more = True
                        break
                    base = int(entry.base or 0)
                    row = {"name": entry.name, "path": entry.path, "base": base,
                           "size": int(entry.image_size), "pid": self.identity.pid,
                           "loaded_pe": self._loaded_pe(kernel, handle, base),
                           "sha256": None, "file_version": _file_version(entry.path),
                           "file_identity_status": "NOT_REQUESTED"}
                    if hashing:
                        try:
                            from .decoder_pdb import _local_file, _stable_file
                            from .decoder_native_symbols import _pe_layout
                            path, initial = _local_file(entry.path)
                            digest = hashlib.sha256()
                            with path.open("rb") as stream:
                                while chunk := stream.read(1024 * 1024):
                                    _check(deadline, cancel)
                                    digest.update(chunk)
                                layout = _pe_layout(stream, initial.st_size)
                                _stable_file(path, initial, os.fstat(stream.fileno()))
                            row["sha256"] = digest.hexdigest()
                            row["pe"] = {key: layout[key] for key in
                                         ("guid", "age", "pdb_basename", "machine", "image_size", "image_timestamp")}
                            loaded = row["loaded_pe"] or {}
                            row["file_identity_status"] = (
                                "LOADED_PE_CODEVIEW_AND_LAYOUT_MATCH" if loaded.get("guid") and
                                all(loaded.get(key) == row["pe"].get(key) for key in
                                    ("guid", "age", "image_size", "image_timestamp")) else
                                "LOADED_PE_IDENTITY_UNCONFIRMED")
                        except (OSError, ValueError) as error:
                            row["file_identity_status"] = "INCOMPLETE_EVIDENCE"
                            row["file_identity_reason"] = str(error)[:120]
                    rows.append(row)
                    ok = kernel.module_next(snapshot, C.byref(entry))
                if not ok and C.get_last_error() not in (0, 18):
                    more = True
            finally:
                kernel.close(snapshot)
        return {"rows": rows, "truncated": more, "_source": "WIN32_TOOLHELP_LOADED_MODULES",
                "_status": "INCOMPLETE_EVIDENCE" if more or hashing and any(
                    r["file_identity_status"] != "LOADED_PE_CODEVIEW_AND_LAYOUT_MATCH" for r in rows) else "COMPLETED",
                "_limitations": ["MODULE_LOADS_MAY_CHANGE_DURING_QUERY", "FILE_HASH_DESCRIBES_DISK_BYTES_NOT_ALL_LOADED_PAGES",
                                  "CODEVIEW_IDENTITY_IS_NOT_AUTHENTICATED_PROVENANCE"]}

    def _thread_rows(self, kernel, deadline, cancel, limit):
        snapshot = kernel.snapshot(0x4, 0)
        if snapshot == W.INVALID_HANDLE:
            raise _os_error("THREAD_SNAPSHOT_FAILED")
        rows, more = [], False
        try:
            entry = W.THREADENTRY32()
            entry.size = C.sizeof(entry)
            ok = kernel.thread_first(snapshot, C.byref(entry))
            while ok:
                _check(deadline, cancel)
                if entry.pid == self.identity.pid:
                    if len(rows) == limit:
                        more = True
                        break
                    row = {"tid": int(entry.tid), "pid": int(entry.pid),
                           "base_priority": int(entry.base_priority), "created_100ns": None}
                    thread = kernel.open_thread(0x800, False, entry.tid)
                    if thread:
                        try:
                            if kernel.thread_pid(thread) != self.identity.pid:
                                raise NativeError("PROCESS_CHANGED", "THREAD_OWNER_CHANGED")
                            created, cpu_kernel, cpu_user = _times(kernel.thread_times, thread)
                            row.update(created_100ns=created, kernel_time_100ns=cpu_kernel,
                                       user_time_100ns=cpu_user, status="COMPLETED")
                        except NativeError as error:
                            row.update(status=error.status, reason=error.reason)
                        finally:
                            kernel.close(thread)
                    else:
                        row.update(status="INCOMPLETE_EVIDENCE", winerror=C.get_last_error())
                    rows.append(row)
                ok = kernel.thread_next(snapshot, C.byref(entry))
        finally:
            kernel.close(snapshot)
        return rows, more

    def _threads(self, params, deadline, cancel):
        limit = _integer(params.get("limit", 512), "limit", 1, 2048)
        with self._open(0x1000) as (kernel, _):
            rows, more = self._thread_rows(kernel, deadline, cancel, limit)
        return {"rows": rows, "truncated": more, "_source": "WIN32_THREAD_SNAPSHOT",
                "_status": "INCOMPLETE_EVIDENCE" if more or any(r["status"] != "COMPLETED" for r in rows) else "COMPLETED",
                "_limitations": ["THREAD_STATE_IS_NOT_INFERRED_FROM_CPU_COUNTERS"]}

    def _handles(self, params, deadline, cancel):
        from .deep_native_handles import handle_rows, query_bounded
        limit = _integer(params.get("limit", 256), "limit", 1, 1024)
        name_limit = _integer(params.get("name_limit", 16), "name_limit", 0, 64)
        with self._open(0x1040):
            rows, omitted = handle_rows(self.identity.pid, limit, deadline, cancel)
            for index, row in enumerate(rows):
                _check(deadline, cancel)
                if index < name_limit:
                    row.update(query_bounded(self.identity, row["handle"], deadline, cancel))
                else:
                    row.update(name=None, type_name=None, name_status="NOT_COLLECTED_NAME_BUDGET")
        return {"rows": rows, "omitted": omitted, "_source": "WINDOWS_SYSTEM_EXTENDED_HANDLE_INFORMATION",
                "_status": "INCOMPLETE_EVIDENCE" if omitted or name_limit < len(rows) or any(
                    r.get("name_status") != "COMPLETED" for r in rows) else "COMPLETED",
                "_limitations": ["HANDLE_VALUE_CAN_BE_REUSED_WITHIN_PROCESS", "OBJECT_NAMES_ARE_BOUNDED_IN_SEPARATE_QUERY_PROCESSES"]}

    def _wait_chains(self, params, deadline, cancel):
        from .windows_research import wait_chain
        limit = _integer(params.get("limit", 16), "limit", 1, 64)
        selected = params.get("tid")
        selected_created = params.get("thread_created_100ns", params.get("created_100ns"))
        if selected_created is not None:
            _integer(selected_created, "thread_created_100ns", 1)
        threads = self._threads({"limit": 2048}, deadline, cancel)["rows"]
        if selected is not None:
            _integer(selected, "tid", 1, 0xFFFFFFFF)
            threads = [r for r in threads if r["tid"] == selected]
            if not threads:
                raise NativeError("PROCESS_CHANGED", "THREAD_NOT_OWNED_BY_TARGET")
            if selected_created is not None and threads[0]["created_100ns"] != selected_created:
                raise NativeError("PROCESS_CHANGED", "SELECTED_THREAD_INSTANCE_CHANGED")
        rows = []
        with self._open(0x1000) as (kernel, _):
            for thread in threads[:limit]:
                _check(deadline, cancel)
                h = kernel.open_thread(0x800 | 0x100000, False, thread["tid"])
                if not h:
                    rows.append({"tid": thread["tid"], "status": "INCOMPLETE_EVIDENCE", "winerror": C.get_last_error()})
                    continue
                try:
                    if (kernel.wait(h, 0) != 258 or kernel.thread_pid(h) != self.identity.pid or
                            _times(kernel.thread_times, h)[0] != thread["created_100ns"]):
                        raise NativeError("PROCESS_CHANGED", "THREAD_INSTANCE_CHANGED")
                    result = wait_chain(thread["tid"], timeout_s=min(.25, max(.01, (deadline or time.monotonic() + .25) - time.monotonic())))
                    if kernel.wait(h, 0) != 258:
                        raise NativeError("PROCESS_CHANGED", "THREAD_EXITED_DURING_WAIT_CHAIN")
                    result["created_100ns"] = thread["created_100ns"]
                    result["thread_owner_pid"] = self.identity.pid
                    rows.append(result)
                finally:
                    kernel.close(h)
        complete = len(threads) <= limit and all(r.get("status") == "OK" for r in rows)
        return {"rows": rows, "omitted": max(0, len(threads) - limit),
                "_source": "WIN32_WAIT_CHAIN_TRAVERSAL",
                "_status": "COMPLETED" if complete else "INCOMPLETE_EVIDENCE",
                "_limitations": ["SUPPORTED_WCT_SYNCHRONIZATION_ONLY", "CYCLE_REPORTED_IS_A_DYNAMIC_OS_OBSERVATION_NOT_UNIVERSAL_DEADLOCK_PROOF"]}

    def _network(self, params, deadline, cancel):
        import psutil
        limit = _integer(params.get("limit", 1024), "limit", 1, MAX_ROWS)
        with self._open(0x1000):
            _check(deadline, cancel)
            process = psutil.Process(self.identity.pid)
            try:
                connections = process.net_connections(kind="all")
            except psutil.AccessDenied as error:
                raise NativeError("ACCESS_DENIED", "NETWORK_TABLE_ACCESS_DENIED", 5) from error
            rows = []
            for connection in connections[:limit]:
                _check(deadline, cancel)
                family = "IPv6" if int(connection.family) == 23 else "IPv4" if int(connection.family) == 2 else str(connection.family)
                rows.append({"pid": self.identity.pid, "family": family,
                             "protocol": "TCP" if int(connection.type) == 1 else "UDP" if int(connection.type) == 2 else str(connection.type),
                             "local": {"address": connection.laddr.ip, "port": connection.laddr.port} if connection.laddr else None,
                             "remote": {"address": connection.raddr.ip, "port": connection.raddr.port} if connection.raddr else None,
                             "state": connection.status, "bytes_sent": None, "bytes_received": None,
                             "kind": "CURRENT_ENDPOINT_SNAPSHOT"})
        return {"rows": rows, "omitted": max(0, len(connections) - limit),
                "_source": "WINDOWS_OWNER_PID_TCP_UDP_TABLES_VIA_PSUTIL",
                "_status": "INCOMPLETE_EVIDENCE" if len(connections) > limit else "COMPLETED",
                "_limitations": ["NOT_ETW_HISTORY", "TRAFFIC_BYTES_AND_PACKET_CONTENT_NOT_COLLECTED", "DYNAMIC_ENDPOINT_SNAPSHOT"]}

    def _disk(self, params, deadline, cancel):
        import psutil
        limit = _integer(params.get("limit", 256), "limit", 1, 1024)
        with self._open(0x1000):
            _check(deadline, cancel)
            process = psutil.Process(self.identity.pid)
            try:
                counters = process.io_counters()._asdict()
                files = process.open_files()
            except psutil.AccessDenied as error:
                raise NativeError("ACCESS_DENIED", "PROCESS_IO_QUERY_DENIED", 5) from error
            rows = [{"path": f.path, "fd": f.fd, "kind": "CURRENT_OPEN_FILE"} for f in files[:limit]]
        return {"counters": counters, "open_files": rows, "rows": rows,
                "omitted": max(0, len(files) - limit), "operation_latencies": None,
                "_source": "WIN32_PROCESS_IO_COUNTERS_AND_OPEN_FILE_SNAPSHOT",
                "_status": "INCOMPLETE_EVIDENCE" if len(files) > limit else "COMPLETED",
                "_limitations": ["PROCESS_IO_INCLUDES_CACHED_AND_NON_DISK_IO", "NOT_PHYSICAL_DEVICE_ACTIVITY",
                                  "PER_OPERATION_LATENCIES_AND_THREAD_FILE_CAUSALITY_REQUIRE_RECORDED_ETW"]}

    def _snapshot(self, params, deadline, cancel):
        sections = {}
        for operation in ("modules", "threads", "memory_map", "network", "disk"):
            _check(deadline, cancel)
            sections[operation] = self.execute(operation, {"limit": 128}, deadline=deadline, cancel_event=cancel)
        complete = all(value["status"] == "COMPLETED" for value in sections.values())
        return {"sections": sections, "_source": "MULTI_SOURCE_LIVE_SNAPSHOT",
                "_status": "COMPLETED" if complete else "INCOMPLETE_EVIDENCE",
                "_limitations": ["SECTIONS_COLLECTED_SEQUENTIALLY_NOT_ATOMIC_SNAPSHOT", "NO_TARGET_MEMORY_CONTENT_INCLUDED"]}

    def _thread_stacks(self, params, deadline, cancel):
        from .deep_native_stacks import collect_stacks
        return collect_stacks(self, params, deadline, cancel)

    def _dump(self, params, deadline, cancel):
        from .deep_native_dump import write_dump
        return write_dump(self, params, deadline, cancel)


def _file_version(path):
    """Read local version resources as data, never execute the target image."""
    if not path or str(path).startswith(("\\\\", "//")):
        return None
    try:
        dll = W.library("version")
        get_size = W.bind(dll, "GetFileVersionInfoSizeW", W.U32, C.c_wchar_p, C.POINTER(W.U32))
        get_info = W.bind(dll, "GetFileVersionInfoW", W.BOOL, C.c_wchar_p, W.U32, W.U32, W.PTR)
        query = W.bind(dll, "VerQueryValueW", W.BOOL, W.PTR, C.c_wchar_p, C.POINTER(W.PTR), C.POINTER(W.U32))
        ignored = W.U32()
        size = get_size(path, C.byref(ignored))
        if not 52 <= size <= 1024 * 1024:
            return None
        buffer = C.create_string_buffer(size)
        if not get_info(path, 0, size, buffer):
            return None
        pointer, length = W.PTR(), W.U32()
        if not query(buffer, "\\", C.byref(pointer), C.byref(length)) or length.value < 52:
            return None
        values = struct.unpack("<13I", C.string_at(pointer, 52))
        if values[0] != 0xFEEF04BD:
            return None
        return ".".join(str(x) for x in (values[2] >> 16, values[2] & 0xFFFF, values[3] >> 16, values[3] & 0xFFFF))
    except (OSError, ValueError, AttributeError):
        return None

