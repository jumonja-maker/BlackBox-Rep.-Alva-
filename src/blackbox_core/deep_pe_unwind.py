"""Typed file-backed AMD64 unwind metadata from an explicitly pinned PE.

This is a data reader for the existing DbgHelp path. It never maps target
stack/data, executes the PE, guesses bytes, or opens a dump-embedded path.
"""
from __future__ import annotations

import hashlib
import struct

from .decoder_pdb import _read, _require
from .decoder_native_symbols import _pe_layout


class PinnedPEUnwindMetadata:
    def __init__(self, stream, size, expected, base, check):
        self.stream, self.size, self.base, self.check = stream, size, base, check
        self.read_bytes = 0
        self.regions = []
        self.sections = []
        self.check()
        actual = _pe_layout(stream, size)
        _require(all(actual.get(k) == expected.get(k) for k in
            ("guid", "age", "machine", "image_size", "image_timestamp", "section_headers")),
            "PINNED_PE_UNWIND_IDENTITY_OR_LAYOUT_CHANGED")
        _require(actual["machine"] == 0x8664 and 0 < base < 2**64 and
                 actual["image_size"] <= 2**64 - base, "PINNED_PE_UNWIND_REQUIRES_AMD64")
        self.image_size = actual["image_size"]
        digest = hashlib.sha256()
        stream.seek(0)
        remaining = size
        while remaining:
            self.check()
            block = stream.read(min(1024**2, remaining))
            _require(bool(block), "PINNED_PE_CHANGED_DURING_HASH")
            remaining -= len(block)
            digest.update(block)
        self.sha256 = digest.hexdigest()
        nt = struct.unpack_from("<I", self._read(0, 64), 60)[0]
        header = self._read(nt, 24)
        opt_size = struct.unpack_from("<H", header, 20)[0]
        opt = self._read(nt + 24, opt_size)
        _require(len(opt) >= 144 and struct.unpack_from("<H", opt)[0] == 0x20B and
                 struct.unpack_from("<I", opt, 108)[0] >= 4, "PINNED_PE_OPTIONAL_HEADER_UNSUPPORTED")
        headers_size = struct.unpack_from("<I", opt, 60)[0]
        table_end = nt + 24 + opt_size + len(actual["section_headers"])
        _require(table_end <= headers_size <= min(size, self.image_size, 1024**2),
                 "PINNED_PE_HEADERS_RANGE_INVALID")
        self.regions.append((0, headers_size, 0, "PE_HEADERS"))
        for at in range(0, len(actual["section_headers"]), 40):
            raw = actual["section_headers"][at:at + 40]
            vs, va, count, offset = struct.unpack_from("<4I", raw, 8)
            flags = struct.unpack_from("<I", raw, 36)[0]
            extent = max(vs, count)
            _require(va >= headers_size and va + extent <= self.image_size and
                     offset + count <= size and (not count or offset >= headers_size),
                     "PINNED_PE_SECTION_RANGE_INVALID")
            for previous in self.sections:
                _require(not (extent and previous[1] and va < previous[0] + previous[1] and previous[0] < va + extent) and
                         not (count and previous[2] and offset < previous[3] + previous[2] and previous[3] < offset + count),
                         "PINNED_PE_SECTION_OVERLAP")
            self.sections.append((va, extent, count, offset, flags))
        exception_rva, exception_size = struct.unpack_from("<II", opt, 112 + 3 * 8)
        _require(bool(exception_rva) == bool(exception_size), "PINNED_PE_EXCEPTION_DIRECTORY_INVALID")
        self.parsed = set()
        if exception_size:
            _require(exception_size % 12 == 0 and exception_size <= 12 * 65536,
                     "PINNED_PE_FUNCTION_TABLE_BUDGET")
            file_offset = self._readonly_offset(exception_rva, exception_size)
            self.regions.append((exception_rva, exception_size, file_offset, "RUNTIME_FUNCTION_TABLE"))
            raw = self._read(file_offset, exception_size)
            previous_end = 0
            for at in range(0, len(raw), 12):
                self.check()
                begin, end, unwind = struct.unpack_from("<III", raw, at)
                self._function(begin, end, unwind)
                _require(begin >= previous_end, "PINNED_PE_FUNCTION_TABLE_UNSORTED_OR_OVERLAPPING")
                previous_end = end
                self._unwind(unwind, (), 0)
        self.regions.sort()
        for previous, current in zip(self.regions, self.regions[1:]):
            self.check()
            _require(previous[0] + previous[1] <= current[0], "PINNED_PE_TYPED_METADATA_OVERLAP")

    def _read(self, offset, size):
        self.check()
        self.read_bytes += size
        _require(self.read_bytes <= 8 * 1024**2, "PINNED_PE_METADATA_READ_BUDGET")
        return _read(self.stream, offset, size, self.size)

    def _readonly_offset(self, rva, size):
        _require(size > 0 and 0 <= rva < self.image_size and size <= self.image_size - rva,
                 "PINNED_PE_METADATA_RVA_INVALID")
        matches = [s for s in self.sections if s[0] <= rva and rva + size <= s[0] + s[2]]
        _require(len(matches) == 1, "PINNED_PE_METADATA_NOT_UNIQUE_FILE_BACKED_RANGE")
        va, _extent, _raw_size, offset, flags = matches[0]
        _require(flags & 0x40000000 and not flags & (0x80000000 | 0x20000000),
                 "PINNED_PE_METADATA_SECTION_NOT_READONLY_DATA")
        return offset + rva - va

    def _function(self, begin, end, unwind):
        _require(0 < begin < end <= self.image_size and unwind > 0 and unwind % 4 == 0 and
                 any(s[4] & 0x20000000 and s[0] <= begin and end <= s[0] + s[1] for s in self.sections),
                 "PINNED_PE_RUNTIME_FUNCTION_INVALID")

    def _unwind(self, rva, ancestors, depth):
        _require(depth <= 8 and rva not in ancestors, "PINNED_PE_UNWIND_CHAIN_INVALID_OR_TOO_DEEP")
        if rva in self.parsed:
            return
        _require(len(self.parsed) < 65536, "PINNED_PE_UNWIND_RECORD_BUDGET")
        offset = self._readonly_offset(rva, 4)
        header = self._read(offset, 4)
        version, flags, count = header[0] & 7, header[0] >> 3, header[2]
        _require(version in (1, 2) and not flags & ~7 and not (flags & 4 and flags & 3),
                 "PINNED_PE_UNWIND_VERSION_OR_FLAGS_UNSUPPORTED")
        length = 4 + ((count + 1) & ~1) * 2
        length += 12 if flags & 4 else 4 if flags & 3 else 0
        _require(self._readonly_offset(rva, length) == offset, "PINNED_PE_UNWIND_RANGE_INVALID")
        raw = self._read(offset, length)
        self.parsed.add(rva)
        self.regions.append((rva, length, offset, "UNWIND_INFO"))
        if flags & 4:
            begin, end, chained = struct.unpack_from("<III", raw, length - 12)
            self._function(begin, end, chained)
            self._unwind(chained, (*ancestors, rva), depth + 1)
        elif flags & 3:
            handler = struct.unpack_from("<I", raw, length - 4)[0]
            _require(any(s[4] & 0x20000000 and s[0] <= handler < s[0] + s[1] for s in self.sections),
                     "PINNED_PE_UNWIND_HANDLER_RVA_INVALID")

    def classify(self, address, size):
        if not (type(address) is int and type(size) is int and 0 < size <= 65536 and
                self.base <= address < self.base + self.image_size and size <= self.base + self.image_size - address):
            return "OUTSIDE_SELECTED_IMAGE_OR_INVALID_SIZE"
        rva = address - self.base
        matches = [r for r in self.regions if r[0] <= rva and rva + size <= r[0] + r[1]]
        if len(matches) == 1:
            return matches[0][3]
        if len(matches) > 1:
            return "AMBIGUOUS_METADATA_RANGE"
        sections = [s for s in self.sections if s[0] <= rva < s[0] + s[1]]
        if not sections:
            return "IMAGE_GAP_OR_METADATA_CROSSING"
        flags = sections[0][4]
        return ("WRITABLE_IMAGE_DATA" if flags & 0x80000000 else "EXECUTABLE_IMAGE_CODE" if flags & 0x20000000 else
                "READONLY_IMAGE_BYTES_OUTSIDE_TYPED_METADATA")

    def read(self, address, size):
        role = self.classify(address, size)
        _require(role in ("PE_HEADERS", "RUNTIME_FUNCTION_TABLE", "UNWIND_INFO"), "PINNED_PE_READ_OUTSIDE_TYPED_METADATA")
        rva = address - self.base
        region = next(r for r in self.regions if r[0] <= rva and rva + size <= r[0] + r[1])
        return self._read(region[2] + rva - region[0], size), role

    def facts(self):
        return {"source": "LOCAL_PINNED_PE_UNWIND_METADATA", "sha256": self.sha256,
                "scope": "FILE_BACKED_HEADERS_RUNTIME_FUNCTION_AND_UNWIND_INFO_ONLY",
                "runtime_function_count": sum(r[1] // 12 for r in self.regions if r[3] == "RUNTIME_FUNCTION_TABLE"),
                "unwind_info_count": len(self.parsed), "memory_contents_included": False}
