"""Bounded CodeView C13 lines, inline sites and OMAP address translation.

All locations describe bytes recorded in a local PDB, not authenticated source.
Paths are reduced to basenames. No source file or symbol server is opened.
"""
from __future__ import annotations

from bisect import bisect_right
import struct

from .decoder_pdb import _require, _u16, _u32

MAX_LINES = 100_000
MAX_INLINE_RANGES = 100_000
MAX_OMAP = 500_000
MAX_SOURCE_FILES = 16_384
MAX_SUBSECTIONS = 65_536


def _text(data, at, *, basename=False):
    _require(0 <= at < len(data), "INVALID_PDB_STRING_OFFSET")
    end = data.find(b"\0", at)
    _require(at <= end <= at+4096, "INVALID_PDB_STRING")
    value = data[at:end].decode("utf-8", "strict")
    _require(value and not any(ord(c) < 32 for c in value), "INVALID_PDB_STRING")
    return value.replace("\\", "/").rsplit("/", 1)[-1] if basename else value


def named_strings(msf):
    """Read /names through the PDB named-stream map; never scan guessed bytes."""
    data = msf.read(1)
    if len(data) == 28:
        return b""
    _require(len(data) >= 40, "INVALID_PDB_NAMED_STREAM_MAP")
    n = _u32(data, 28); at = 32+n
    _require(0 <= n <= len(data)-40, "INVALID_PDB_NAMED_STREAM_MAP")
    names = data[32:at]
    count, capacity = struct.unpack_from("<II", data, at); at += 8
    _require(count <= capacity <= 16384, "PDB_NAMED_STREAM_MAP_BUDGET")
    vectors = []
    for _ in range(2):
        _require(at+4 <= len(data), "INVALID_PDB_NAMED_STREAM_MAP")
        words = _u32(data, at); at += 4
        _require(words <= (capacity+31)//32 and at+words*4 <= len(data),
                 "INVALID_PDB_NAMED_STREAM_MAP")
        bits = struct.unpack_from("<"+"I"*words, data, at); at += words*4
        vectors.append({i*32+b for i, word in enumerate(bits) for b in range(32) if word & (1 << b)})
    present, deleted = vectors
    _require(len(present) == count and not present & deleted and
             all(i < capacity for i in present | deleted) and at+count*8 <= len(data),
             "INVALID_PDB_NAMED_STREAM_MAP")
    found = []
    for _ in sorted(present):
        off, index = struct.unpack_from("<II", data, at); at += 8
        if _text(names, off) == "/names":
            found.append(index)
    _require(len(found) <= 1, "AMBIGUOUS_PDB_NAMES_STREAM")
    if not found:
        return b""
    strings = msf.read(found[0])
    _require(len(strings) >= 12 and struct.unpack_from("<II", strings) == (0xeffeeffe, 1),
             "UNSUPPORTED_PDB_NAMES_STREAM")
    length = _u32(strings, 8)
    _require(1 <= length <= len(strings)-12 and strings[12] == 0, "INVALID_PDB_NAMES_STREAM")
    return strings[12:12+length]


def ipi_names(msf):
    """IPI LF_FUNC_ID/LF_MFUNC_ID names used by inlinee IDs (not guessed types)."""
    if len(msf.streams) <= 4 or msf.streams[4][0] in (0, 0xffffffff):
        return {}
    data = msf.read(4)
    _require(len(data) >= 56, "INVALID_PDB_IPI_HEADER")
    version, header, first, last, length = struct.unpack_from("<5I", data)
    _require(version == 20040203 and header == 56 and first >= 0x1000 and
             first <= last <= first+500_000 and header+length == len(data), "INVALID_PDB_IPI_HEADER")
    at, index, names = header, first, {}
    while at < len(data):
        msf.budget.check()
        _require(at+4 <= len(data), "TRUNCATED_PDB_IPI_RECORD")
        size, kind = struct.unpack_from("<HH", data, at)
        _require(size >= 2 and at+2+size <= len(data) and index < last, "INVALID_PDB_IPI_RECORD")
        body = data[at+4:at+2+size]
        if kind in (0x1601, 0x1602):
            _require(len(body) >= 9, "TRUNCATED_PDB_FUNC_ID")
            names[index] = _text(body, 8)
        at += size+2; index += 1
    _require(index == last, "INVALID_PDB_IPI_RECORD_COUNT")
    return names


class Omap:
    def __init__(self, data, image_size, original_size, budget):
        _require(len(data) % 8 == 0 and 0 < len(data)//8 <= MAX_OMAP, "INVALID_OMAP_SIZE")
        self.rows = []
        for at in range(0, len(data), 8):
            budget.check()
            source, target = struct.unpack_from("<II", data, at)
            _require(source < image_size and target < original_size and
                     (not self.rows or source > self.rows[-1][0]), "INVALID_OMAP_ENTRY")
            self.rows.append((source, target))
        self.starts = [x[0] for x in self.rows]
        self.image_size, self.original_size = image_size, original_size

    def translate(self, rva):
        i = bisect_right(self.starts, rva)-1
        if i < 0 or rva >= self.image_size or self.rows[i][1] == 0:
            return None
        source, target = self.rows[i]
        result = target+rva-source
        return result if result < self.original_size else None


def _subsections(data, budget):
    at = 0; out = {}; count = 0
    while at < len(data):
        budget.check()
        count += 1
        _require(count <= MAX_SUBSECTIONS, "C13_SUBSECTION_BUDGET")
        _require(at+8 <= len(data), "TRUNCATED_C13_SUBSECTION")
        kind, length = struct.unpack_from("<II", data, at); at += 8
        _require(at+length <= len(data), "TRUNCATED_C13_SUBSECTION")
        out.setdefault(kind, []).append(data[at:at+length]); at = (at+length+3) & ~3
    _require(at == len(data), "INVALID_C13_PADDING")
    return out


def c13_data(data, strings, budget, rva):
    sections = _subsections(data, budget)
    own_strings = sections.get(0xf3, [])
    _require(len(own_strings) <= 1, "AMBIGUOUS_C13_STRINGS")
    strings = own_strings[0] if own_strings else strings
    checks = sections.get(0xf4, [])
    _require(len(checks) <= 1, "AMBIGUOUS_C13_CHECKSUMS")
    files = {}; raw = checks[0] if checks else b""; at = 0
    while at < len(raw):
        budget.check(); _require(at+6 <= len(raw), "TRUNCATED_C13_CHECKSUM")
        _require(len(files) < MAX_SOURCE_FILES, "PDB_SOURCE_FILE_BUDGET")
        off, size, kind = struct.unpack_from("<IBB", raw, at)
        _require(at+6+size <= len(raw) and (kind, size) in ((0, 0), (1, 16), (2, 20), (3, 32)),
                 "UNSUPPORTED_C13_CHECKSUM")
        files[at] = {"file": _text(strings, off, basename=True),
                     "checksum_kind": {0:"NONE", 1:"MD5", 2:"SHA1", 3:"SHA256"}[kind],
                     "checksum": raw[at+6:at+6+size].hex() or None}
        at = (at+6+size+3) & ~3
    _require(at == len(raw), "INVALID_C13_CHECKSUM_PADDING")
    lines = []
    for raw in sections.get(0xf2, []):
        _require(len(raw) >= 12, "TRUNCATED_C13_LINES")
        offset, segment, flags, size = struct.unpack_from("<IHHI", raw)
        _require(flags in (0, 1) and size > 0, "UNSUPPORTED_C13_LINE_FLAGS")
        start = rva(segment, offset, size); at = 12
        while at < len(raw):
            budget.check(); _require(at+12 <= len(raw), "TRUNCATED_C13_FILE_BLOCK")
            file_id, count, block = struct.unpack_from("<III", raw, at)
            expected = 12+count*(12 if flags else 8)
            _require(count <= MAX_LINES-len(lines) and block == expected and at+block <= len(raw) and
                     file_id in files, "INVALID_C13_FILE_BLOCK")
            entries = []
            for i in range(count):
                rel, bits = struct.unpack_from("<II", raw, at+12+i*8)
                line = bits & 0xffffff
                _require(rel < size and (not entries or rel >= entries[-1][0]), "INVALID_C13_LINE_OFFSET")
                columns = struct.unpack_from("<HH", raw, at+12+count*8+i*4) if flags else (0,0)
                _require(not all(columns) or columns[1] >= columns[0], "INVALID_C13_COLUMNS")
                entries.append((rel, {**files[file_id], "line": line,
                    "end_line": line+((bits >> 24) & 0x7f), "column": columns[0] or None,
                    "end_column": columns[1] or None, "statement": bool(bits & 0x80000000)}))
            ends = {}; following = size
            for rel, _ in reversed(entries):
                if rel not in ends:
                    ends[rel] = following; following = rel
            for rel, location in entries:
                end = ends[rel]
                # Compiler sentinel line numbers represent hidden/non-source regions.
                if end > rel and 0 < location["line"] < 0xf00000:
                    lines.append((start+rel, start+end, location))
                    _require(len(lines) <= MAX_LINES, "PDB_LINE_BUDGET")
            at += block
    inlinees = {}
    for raw in sections.get(0xf6, []):
        _require(len(raw) >= 4 and _u32(raw,0) in (0,1), "UNSUPPORTED_C13_INLINE_SIGNATURE")
        signature = _u32(raw,0); at = 4
        while at < len(raw):
            budget.check(); _require(at+12 <= len(raw), "TRUNCATED_C13_INLINEE")
            _require(len(inlinees) < MAX_INLINE_RANGES, "PDB_INLINEE_BUDGET")
            inlinee, file_id, line = struct.unpack_from("<III",raw,at); at += 12
            _require(file_id in files and 0 < line < 0xf00000 and inlinee not in inlinees,
                     "INVALID_C13_INLINEE")
            inlinees[inlinee] = {**files[file_id], "line": line}
            if signature:
                _require(at+4 <= len(raw), "TRUNCATED_C13_INLINEE")
                count = _u32(raw,at); at += 4
                _require(count <= 4096 and at+count*4 <= len(raw), "INVALID_C13_INLINEE_FILES")
                for i in range(count):
                    _require(_u32(raw,at+i*4) in files, "INVALID_C13_INLINEE_FILES")
                at += count*4
    return lines, inlinees, files


def _compressed(data, at):
    _require(at < len(data), "TRUNCATED_INLINE_ANNOTATION")
    b = data[at]; at += 1
    if b < 0x80:
        return b, at
    size, value = (1, b & 0x3f) if b < 0xc0 else (3, b & 0x1f)
    _require(b < 0xe0 and at+size <= len(data), "INVALID_INLINE_ANNOTATION")
    for part in data[at:at+size]:
        value = (value << 8) | part
    return value, at+size


def inline_ranges(annotations, *, procedure_start, procedure_end, location, files, budget):
    """CodeView annotations: a next start closes the previous source range.

    CodeOffsetBase denotes a separated code chunk, not an arithmetic delta.
    Such chunks need additional S_SEPCODE evidence and are refused here.
    """
    at = 0; offset = 0; pending = None; current = dict(location); ranges = []
    pending_location = None
    line_seen = False
    current.update(end_line=location['line'], column=None, end_column=None, statement=True)
    def signed(value):
        return -(value >> 1) if value & 1 else value >> 1
    def emit(start, end, source):
        _require(0 <= start < end <= procedure_end-procedure_start and
                 0 < source['line'] < 0xf00000, "INLINE_RANGE_OUTSIDE_PROCEDURE")
        ranges.append((procedure_start+start, procedure_start+end, dict(source)))
        _require(len(ranges) <= MAX_INLINE_RANGES, "PDB_INLINE_BUDGET")
    while at < len(annotations):
        budget.check(); op, at = _compressed(annotations, at)
        if op == 0 and not any(annotations[at:]):
            break
        _require(op in (1,3,4,5,6,7,8,9,10,11,12,13), "INLINE_ANNOTATION_UNSUPPORTED")
        value, at = _compressed(annotations, at)
        if op in (1,3,11,12):
            length = None
            if op == 12:
                length = value; value, at = _compressed(annotations, at)
            new_offset = (value if op == 1 else offset+(value & 0xf if op == 11 else value))
            _require(offset <= new_offset <= procedure_end-procedure_start,
                     "INLINE_ANNOTATION_OUT_OF_RANGE")
            if pending is not None and new_offset > pending:
                emit(pending, new_offset, pending_location)
            offset = pending = new_offset
            if op == 11:
                current['line'] += signed(value >> 4)
                current['end_line'] = current['line']
                line_seen = True
            # Separate line/file annotations can precede the next code-offset
            # annotation. They describe the next range, so the open range
            # must retain its source location until its end is observed.
            pending_location = dict(current)
            if length is not None:
                emit(pending,pending+length,pending_location); pending = None
        elif op == 4:
            _require(pending is not None, "INLINE_LENGTH_WITHOUT_START")
            emit(pending,pending+value,pending_location); pending = None
        elif op == 5:
            _require(value in files, "INVALID_INLINE_FILE")
            current.update(files[value])
        elif op == 6:
            current['line'] += signed(value); current['end_line'] = current['line']
            # The first explicit line offset can initialize a range opened
            # by CodeOffset; later offsets are staged for its successor.
            if not line_seen and pending is not None:
                pending_location = dict(current)
            line_seen = True
        elif op == 7: current['end_line'] = current['line']+value
        elif op == 8:
            _require(value in (0,1), "INVALID_INLINE_RANGE_KIND")
            current['statement'] = bool(value)
        elif op == 9: current['column'] = value or None
        elif op == 10: current['end_column'] = (current.get('column') or 0)+signed(value)
        elif op == 13: current['end_column'] = value or None
        _require(0 < current['line'] < 0xf00000 and
                 0 <= (current.get('end_column') or 0) <= 2**32-1,
                 "INLINE_ANNOTATION_OUT_OF_RANGE")
    # Never extend a final unclosed range to the end of the procedure.
    _require(pending is None, "INCOMPLETE_INLINE_ANNOTATION_RANGE")
    return ranges
