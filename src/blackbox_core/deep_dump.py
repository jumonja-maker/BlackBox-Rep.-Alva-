"""Bounded, read-only Windows minidump metadata and explicit memory inspection.

This is an offline view, not an ETL/EventPipe adapter or a heap/root-cause
analyser. Memory bytes are returned only by the explicit read_dump_memory API.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import struct
import time
from uuid import UUID

from .session_v2 import safe_path

MAX_DUMP_BYTES = 2 * 1024**3
MAX_METADATA_BYTES = 8 * 1024**2
MAX_ENTRIES = 65_536
MAX_READ_BYTES = 4096


def _int(value, low=0, high=2**64 - 1):
    return type(value) is int and low <= value <= high


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _stamp(stat):
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


class _Reader:
    def __init__(self, stream, size, cancel_event, deadline):
        self.stream, self.size = stream, size
        self.cancel_event = cancel_event
        self.deadline = min(time.monotonic() + 15, deadline) if deadline is not None else time.monotonic() + 15
        self.consumed = 0

    def check(self):
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise InterruptedError("DUMP_INSPECTION_CANCELLED")
        if time.monotonic() >= self.deadline:
            raise TimeoutError("DUMP_INSPECTION_DEADLINE")

    def range(self, offset, length):
        _require(_int(offset) and _int(length) and offset <= self.size and
                 length <= self.size - offset, "DUMP_RANGE_OUTSIDE_FILE")

    def read(self, offset, length):
        self.check()
        self.range(offset, length)
        self.consumed += length
        _require(self.consumed <= MAX_METADATA_BYTES, "DUMP_METADATA_READ_BUDGET")
        self.stream.seek(offset)
        value = self.stream.read(length)
        _require(len(value) == length, "DUMP_CHANGED_OR_TRUNCATED")
        return value

    def text(self, rva):
        length, = struct.unpack("<I", self.read(rva, 4))
        _require(length <= 32_768 and length % 2 == 0, "DUMP_STRING_BUDGET_OR_ENCODING")
        value = self.read(rva + 4, length).decode("utf-16-le", errors="strict")
        # Never disclose a build-machine/source/user profile path by default.
        return value.replace("\\", "/").rsplit("/", 1)[-1][:512]


@contextmanager
def _open(path, max_bytes, cancel_event, deadline):
    _require(_int(max_bytes, 32, MAX_DUMP_BYTES), "INVALID_DUMP_SIZE_BUDGET")
    _require(deadline is None or type(deadline) in (int, float) and
             0 < deadline < float("inf"), "INVALID_DUMP_DEADLINE")
    path = safe_path(Path(path))
    before = path.stat()
    _require(path.is_file() and 32 <= before.st_size <= max_bytes, "DUMP_FILE_SIZE_BUDGET")
    with path.open("rb") as stream:
        _require(_stamp(os.fstat(stream.fileno())) == _stamp(before), "DUMP_CHANGED_DURING_OPEN")
        reader = _Reader(stream, before.st_size, cancel_event, deadline)
        reader.check()
        yield path, reader
        reader.check()
        _require(_stamp(os.fstat(stream.fileno())) == _stamp(before) and
                 _stamp(path.stat()) == _stamp(before), "DUMP_CHANGED_DURING_REVIEW")


def _directory(reader):
    signature, version, count, rva, checksum, timestamp, flags = struct.unpack("<6IQ", reader.read(0, 32))
    _require(signature == 0x504D444D and version & 0xFFFF == 0xA793, "UNSUPPORTED_MINIDUMP_HEADER")
    _require(1 <= count <= 128 and rva >= 32, "DUMP_DIRECTORY_BUDGET")
    directory = reader.read(rva, count * 12)
    entries = {}
    unused = 0
    for i in range(count):
        kind, size, offset = struct.unpack_from("<III", directory, i * 12)
        reader.range(offset, size)
        # DbgHelp leaves multiple UnusedStream slots in real normal/full dumps.
        # They are directory padding, not duplicate meaningful stream types.
        if kind == 0:
            _require(size == 0, "NONEMPTY_UNUSED_MINIDUMP_STREAM")
            unused += 1
            continue
        _require(kind not in entries, "DUPLICATE_MINIDUMP_STREAM")
        entries[kind] = (offset, size)
    return entries, {"version": version, "timestamp_unix_s": timestamp,
                     "flags": flags, "checksum_recorded": checksum,
                     "checksum_verified": False, "stream_count": count,
                     "unused_stream_slots": unused}


def _array(reader, entry, width):
    offset, size = entry
    _require(size >= 4, "TRUNCATED_MINIDUMP_LIST")
    count, = struct.unpack("<I", reader.read(offset, 4))
    _require(count <= MAX_ENTRIES and 4 + count * width <= size, "INVALID_MINIDUMP_LIST_LENGTH")
    return count, offset + 4


def _codeview(reader, size, rva):
    if not size:
        return None
    _require(24 <= size <= 4096, "DUMP_CODEVIEW_BUDGET")
    data = reader.read(rva, size)
    if data[:4] != b"RSDS":
        return {"status": "UNSUPPORTED_CODEVIEW_FORMAT"}
    age, = struct.unpack_from("<I", data, 20)
    _require(age > 0 and any(data[4:20]), "INVALID_DUMP_RSDS_IDENTITY")
    return {"status": "RECORDED_RSDS", "guid": str(UUID(bytes_le=data[4:20])), "age": age,
            "local_pdb_match": "NOT_CHECKED"}


def _modules(reader, entry, limit):
    count, start = _array(reader, entry, 108)
    modules = []
    for i in range(count):
        reader.check()
        row = reader.read(start + 108 * i, 108)
        base, size, checksum, timestamp, name_rva = struct.unpack_from("<QIIII", row)
        _require(size > 0 and base + size <= 2**64, "INVALID_DUMP_MODULE_RANGE")
        cv_size, cv_rva = struct.unpack_from("<II", row, 76)
        if len(modules) < limit:
            modules.append({"base_address": base, "image_size": size,
                "image_timestamp": timestamp, "checksum_recorded": checksum,
                "name": reader.text(name_rva), "pdb_identity": _codeview(reader, cv_size, cv_rva),
                "source": "MINIDUMP_MODULE_LIST_UNVERIFIED"})
        elif cv_size:
            reader.range(cv_rva, cv_size)
    return modules, count


def _threads(reader, entry, limit, architecture):
    count, start = _array(reader, entry, 48)
    threads = []
    for i in range(count):
        reader.check()
        row = reader.read(start + 48 * i, 48)
        tid, suspend, priority_class, priority, teb, stack, stack_size, stack_rva, context_size, context_rva = struct.unpack("<IIIIQQIIII", row)
        reader.range(stack_rva, stack_size)
        reader.range(context_rva, context_size)
        _require(stack + stack_size <= 2**64, "INVALID_DUMP_STACK_RANGE")
        if len(threads) >= limit:
            continue
        context = {"status": "CONTEXT_UNSUPPORTED_OR_NOT_CAPTURED"}
        if architecture == 9 and context_size >= 256:
            raw = reader.read(context_rva, 256)
            flags, = struct.unpack_from("<I", raw, 48)
            if flags & 0x100001 == 0x100001:
                context = {"status": "SAVED_AMD64_CONTROL_CONTEXT",
                    "rip": struct.unpack_from("<Q", raw, 248)[0],
                    "rsp": struct.unpack_from("<Q", raw, 152)[0],
                    "rbp": struct.unpack_from("<Q", raw, 160)[0],
                    "unwind_status": "STACK_NOT_UNWOUND"}
        threads.append({"tid": tid, "recorded_suspend_count": suspend,
            "priority_class": priority_class, "priority": priority,
            "stack_address": stack, "stack_bytes_recorded": stack_size,
            "context": context, "thread_creation_time": None,
            "source": "SAVED_MINIDUMP_THREAD_NOT_LIVE_THREAD"})
    return threads, count


def _memory_ranges(reader, entries):
    ranges = []
    if 5 in entries:
        count, start = _array(reader, entries[5], 16)
        for i in range(count):
            address, size, rva = struct.unpack("<QII", reader.read(start + i * 16, 16))
            reader.range(rva, size)
            _require(address + size <= 2**64, "INVALID_DUMP_MEMORY_RANGE")
            ranges.append((address, size, rva))
    if 9 in entries:
        offset, length = entries[9]
        _require(length >= 16, "TRUNCATED_MEMORY64_LIST")
        count, data_offset = struct.unpack("<QQ", reader.read(offset, 16))
        _require(count <= MAX_ENTRIES and 16 + count * 16 <= length, "INVALID_MEMORY64_LIST")
        for i in range(count):
            address, size = struct.unpack("<QQ", reader.read(offset + 16 + i * 16, 16))
            reader.range(data_offset, size)
            _require(address + size <= 2**64, "INVALID_DUMP_MEMORY_RANGE")
            ranges.append((address, size, data_offset))
            data_offset += size
    _require(len(ranges) <= MAX_ENTRIES, "DUMP_MEMORY_RANGE_BUDGET")
    return ranges


def inspect_dump(path, *, max_bytes=MAX_DUMP_BYTES, limit=200, cancel_event=None, deadline=None):
    """Inspect captured structure without including memory bytes in the result."""
    _require(_int(limit, 1, 200), "INVALID_DUMP_DISPLAY_LIMIT")
    with _open(path, max_bytes, cancel_event, deadline) as (path, reader):
        entries, header = _directory(reader)
        architecture = None
        if 7 in entries:
            rva, size = entries[7]
            _require(size >= 32, "TRUNCATED_SYSTEM_INFO")
            architecture, = struct.unpack("<H", reader.read(rva, 2))
        modules, module_count = _modules(reader, entries[4], limit) if 4 in entries else ([], 0)
        threads, thread_count = _threads(reader, entries[3], limit, architecture) if 3 in entries else ([], 0)
        ranges = _memory_ranges(reader, entries)
        process_id = process_created_seconds = None
        if 15 in entries:
            rva, length = entries[15]
            _require(length >= 8, "TRUNCATED_MISC_INFO")
            length_recorded, flags = struct.unpack("<II", reader.read(rva, 8))
            _require(8 <= length_recorded <= length, "INVALID_MISC_INFO_LENGTH")
            if flags & 1 and length_recorded >= 12:
                process_id, = struct.unpack("<I", reader.read(rva + 8, 4))
            if flags & 2 and length_recorded >= 24:
                process_created_seconds, = struct.unpack("<I", reader.read(rva + 12, 4))
        for thread in threads:
            ip = thread["context"].get("rip")
            if ip is not None:
                matches = [m for m in modules if m["base_address"] <= ip < m["base_address"] + m["image_size"]]
                thread["instruction_module"] = ({"name": matches[0]["name"],
                    "rva": ip - matches[0]["base_address"], "pdb_identity": matches[0]["pdb_identity"]}
                    if len(matches) == 1 else None)
        data = {"schema": "blackbox.deep-minidump/1", "file": path.name,
            "size_bytes": reader.size, "source": "SAVED_MINIDUMP_UNVERIFIED",
            "header": header, "architecture": "AMD64" if architecture == 9 else architecture,
            "stream_types": sorted(entries), "modules": modules, "threads": threads,
            "memory_ranges": [{"address": a, "size": n} for a, n, _ in ranges[:limit]],
            "coverage": {"module_count": module_count, "thread_count": thread_count,
                "memory_range_count": len(ranges), "modules_omitted": max(0, module_count - limit),
                "threads_omitted": max(0, thread_count - limit),
                "memory_ranges_omitted": max(0, len(ranges) - limit)},
            "recorded_pid": process_id, "recorded_creation_unix_seconds": process_created_seconds,
            "live_process_binding": "NOT_ESTABLISHED",
            "memory_contents_included": False, "source_path_policy": "BASENAME_ONLY"}
    return {"status": "INCOMPLETE_EVIDENCE", "data": data,
        "limitations": ["MINIDUMP_STREAMS_ARE_UNVERIFIED_IMPORTED_DATA",
            "SAVED_THREAD_CONTEXT_IS_NOT_CURRENT_EXECUTION_STATE",
            "SECOND_RESOLUTION_CREATION_TIME_CANNOT_PROVE_FILETIME_IDENTITY",
            "STACK_UNWIND_AND_MANAGED_HEAP_ANALYSIS_NOT_PERFORMED",
            "MEMORY_CONTENTS_EXCLUDED_FROM_METADATA_AND_NORMAL_SHARE"],
        "next_action": "SELECT_SAVED_MODULE_AND_MATCH_LOCAL_PDB", "error": None}


def read_dump_memory(path, address, size, *, max_bytes=MAX_DUMP_BYTES,
                     cancel_event=None, deadline=None):
    """Explicit private memory read, refusing overlapping or absent descriptors."""
    _require(_int(address) and _int(size, 1, MAX_READ_BYTES) and address + size <= 2**64,
             "INVALID_DUMP_MEMORY_READ")
    with _open(path, max_bytes, cancel_event, deadline) as (_, reader):
        entries, _ = _directory(reader)
        ranges = _memory_ranges(reader, entries)
        overlaps = [(a, n, rva) for a, n, rva in ranges if a < address + size and address < a + n]
        _require(len(overlaps) == 1, "DUMP_MEMORY_RANGE_MISSING_OR_AMBIGUOUS")
        a, n, rva = overlaps[0]
        _require(a <= address and address + size <= a + n, "DUMP_MEMORY_READ_CROSSES_RANGE")
        value = reader.read(rva + address - a, size)
    return {"status": "COMPLETED", "data": {"address": address, "size": size,
        "value_hex": value.hex(), "source": "SAVED_MINIDUMP_MEMORY",
        "privacy": "SENSITIVE_MEMORY_DO_NOT_INCLUDE_IN_NORMAL_SHARE"},
        "limitations": ["HISTORICAL_BYTES_NOT_LIVE_PROCESS_MEMORY"], "error": None}
