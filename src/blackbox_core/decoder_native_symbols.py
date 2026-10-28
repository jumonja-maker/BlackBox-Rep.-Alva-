"""Offline native MSF7/CodeView procedure ranges; no DbgHelp or symbol server.

Only Windows PDB S_[GL]PROC32[/_ID] ranges and exact S_PUB32 entries are
supported. OMAP, portable PDB, inline frames and unknown formats are refused.
All names are derived from unauthenticated local bytes, never root causes.
"""
from __future__ import annotations

from bisect import bisect_right
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import struct
import tempfile
import time
from uuid import UUID

from .decoder_pdb import (IdentityUnavailable, MSF7_MAGIC, _local_file, _stable_file,
                          _read, _require, _pe_rsds, _u16, _u32)
from .decoder_modules import binding_verdict, integer

MAX_DIRECTORY = 4 * 1024**2
MAX_SYMBOL_BYTES = 64 * 1024**2
MAX_RECORDS = 500_000
MAX_FUNCTIONS = 100_000
MAX_MODULES = 8192


class Budget:
    def __init__(self, cancel=None, seconds=30):
        self.cancel = cancel
        self.deadline = time.monotonic() + seconds
        self.read_bytes = self.records = 0

    def check(self):
        if self.cancel is not None and self.cancel.is_set():
            raise InterruptedError("SYMBOL_REVIEW_CANCELLED")
        if time.monotonic() > self.deadline:
            raise TimeoutError("SYMBOL_REVIEW_DEADLINE")

    def charge(self, size):
        self.check(); self.read_bytes += size
        _require(self.read_bytes <= MAX_SYMBOL_BYTES, "PDB_SYMBOL_READ_BUDGET")


@contextmanager
def snapshot_pair(binary_path, pdb_path, budget):
    """Never parse a changing caller-owned stream or use a path from the PDB."""
    with tempfile.TemporaryDirectory(prefix="blackbox-local-symbols-") as tmp:
        snapshots, hashes = [], []
        for i, original in enumerate((binary_path, pdb_path)):
            path, before = _local_file(original)
            snapshot = Path(tmp) / ("module.exe" if i == 0 else "symbols.pdb")
            digest = hashlib.sha256()
            with path.open("rb") as source, snapshot.open("xb") as dest:
                _stable_file(path, before, os.fstat(source.fileno()))
                total = 0
                while block := source.read(1024**2):
                    budget.check(); total += len(block)
                    _require(total <= before.st_size, "LOCAL_FILE_CHANGED_DURING_REVIEW")
                    dest.write(block); digest.update(block)
                _require(total == before.st_size, "LOCAL_FILE_CHANGED_DURING_REVIEW")
                _stable_file(path, before, os.fstat(source.fileno()))
            snapshots.append(snapshot); hashes.append(digest.hexdigest())
        yield snapshots, hashes


def _pe_layout(stream, size):
    identity = _pe_rsds(stream, size)
    at = _u32(_read(stream, 0, 64, size), 60)
    header = _read(stream, at, 24, size)
    count, opt_size = _u16(header, 6), _u16(header, 20)
    opt = _read(stream, at+24, opt_size, size)
    raw = _read(stream, at+24+opt_size, count*40, size)
    image_size = _u32(opt, 56)
    _require(image_size > 0, "INVALID_PE_IMAGE_SIZE")
    sections = []
    for i in range(count):
        offset = i*40
        vs, va, rs, rp = struct.unpack_from("<4I", raw, offset+8)
        flags = _u32(raw, offset+36)
        _require(va+max(vs, rs) <= image_size and rp+rs <= size,
                 "INVALID_PE_SECTION_RANGE")
        sections.append((va, vs, flags))
    identity.update(machine=_u16(header, 4), image_timestamp=_u32(header, 8),
                    image_size=image_size, section_headers=raw, sections=sections)
    return identity


class MsfReader:
    def __init__(self, stream, size, budget):
        self.stream, self.size, self.budget = stream, size, budget
        head = _read(stream, 0, 56, size)
        _require(head[:32] == MSF7_MAGIC, "UNSUPPORTED_PDB_CONTAINER")
        bs, fm, count, dsize, unused, mapblock = struct.unpack_from("<6I", head, 32)
        _require(bs in (512, 1024, 2048, 4096) and fm in (1, 2) and count >= 6 and
                 bs*count == size and 12 <= dsize <= MAX_DIRECTORY and
                 3 <= mapblock < count, "INVALID_MSF_LAYOUT")
        pages = (dsize+bs-1)//bs
        _require(pages <= bs//4, "MSF_DIRECTORY_MAP_BUDGET")
        directory_blocks = struct.unpack("<"+"I"*pages,
                                        _read(stream, mapblock*bs, pages*4, size))
        used = {0, mapblock}
        # MSF reserves two free-page-map blocks per block_size block interval.
        used.update(i for i in range(count) if i % bs in (1, 2))
        for page in directory_blocks:
            _require(3 <= page < count and page not in used, "INVALID_MSF_BLOCK_ALIAS")
            used.add(page)
        directory = b"".join(_read(stream, page*bs, bs, size)
                             for page in directory_blocks)[:dsize]
        n = _u32(directory, 0)
        _require(4 <= n <= 16384 and 4+n*4 <= dsize, "INVALID_MSF_DIRECTORY")
        sizes = struct.unpack_from("<"+"I"*n, directory, 4)
        at = 4+4*n; self.streams = []
        for length in sizes:
            blocks = 0 if length == 0xffffffff else (length+bs-1)//bs
            _require(at+blocks*4 <= dsize, "INVALID_MSF_DIRECTORY")
            mapping = struct.unpack_from("<"+"I"*blocks, directory, at)
            for page in mapping:
                _require(3 <= page < count and page not in used, "INVALID_MSF_BLOCK_ALIAS")
                used.add(page)
            self.streams.append((length, mapping)); at += blocks*4
        _require(at == dsize, "INVALID_MSF_DIRECTORY")
        self.bs = bs

    def read(self, index, length=None):
        _require(integer(index, 0, len(self.streams)-1), "INVALID_PDB_STREAM_INDEX")
        size, mapping = self.streams[index]
        _require(size != 0xffffffff, "PDB_STREAM_ABSENT")
        amount = size if length is None else length
        _require(integer(amount, 0, size), "INVALID_PDB_STREAM_SIZE")
        self.budget.charge(amount)
        result = bytearray()
        for page in mapping[:(amount+self.bs-1)//self.bs]:
            self.budget.check()
            result.extend(_read(self.stream, page*self.bs, min(self.bs, amount-len(result)), self.size))
        return bytes(result)


def _name(data, at):
    end = data.find(b"\x00", at)
    _require(end >= at and 0 < end-at <= 2048, "INVALID_CODEVIEW_SYMBOL_NAME")
    value = data[at:end].decode("utf-8", errors="strict")
    _require(not any(ord(c) < 32 for c in value), "INVALID_CODEVIEW_SYMBOL_NAME")
    return value


def _records(data, budget, start=0):
    at = start
    while at < len(data):
        budget.check(); budget.records += 1
        _require(budget.records <= MAX_RECORDS and at+4 <= len(data), "PDB_RECORD_BUDGET_OR_TRUNCATION")
        size, kind = struct.unpack_from("<HH", data, at)
        _require(size >= 2 and at+2+size <= len(data), "INVALID_CODEVIEW_RECORD")
        yield kind, data[at+4:at+2+size]
        at += size+2


def _rva(pe, section, offset, length=1):
    _require(1 <= section <= len(pe["sections"]), "INVALID_SYMBOL_SECTION")
    va, size, flags = pe["sections"][section-1]
    _require(length > 0 and offset+length <= size and flags & 0x20000000,
             "SYMBOL_OUTSIDE_EXECUTABLE_SECTION")
    return va+offset


def _pdb_symbols(msf, pe):
    info = msf.read(1, 28)
    version, signature, age = struct.unpack_from("<III", info)
    guid = str(UUID(bytes_le=info[12:28]))
    _require(version == 20000404 and age > 0 and any(info[12:28]), "UNSUPPORTED_PDB_IDENTITY")
    _require((guid, age) == (pe["guid"], pe["age"]), "PE_PDB_GUID_AGE_MISMATCH")
    dbi = msf.read(3)
    _require(len(dbi) >= 64 and struct.unpack_from("<iII", dbi) == (-1, 19990903, age),
             "UNSUPPORTED_OR_MISMATCHED_DBI")
    _require(_u16(dbi, 58) == pe["machine"], "PE_PDB_MACHINE_MISMATCH")
    symstream = _u16(dbi, 20)
    lengths = list(struct.unpack_from("<5i", dbi, 24))
    debug_size, ec_size = struct.unpack_from("<2i", dbi, 48)
    _require(all(n >= 0 for n in lengths+[debug_size, ec_size]) and
             64+sum(lengths)+debug_size+ec_size == len(dbi) and debug_size % 2 == 0 and
             debug_size >= 12, "INVALID_DBI_SUBSTREAM_SIZES")
    debug = dbi[64+sum(lengths)+ec_size:]
    debug_streams = struct.unpack("<"+"H"*(debug_size//2), debug)
    _require(debug_streams[3] == 0xffff and debug_streams[4] == 0xffff and
             (len(debug_streams) <= 10 or debug_streams[10] == 0xffff),
             "OMAP_OR_ORIGINAL_SECTIONS_UNSUPPORTED")
    sections = msf.read(debug_streams[5])
    _require(sections == pe["section_headers"], "PE_PDB_SECTION_LAYOUT_MISMATCH")
    functions, publics = set(), set()
    at, limit, modules = 64, 64+lengths[0], 0
    while at < limit:
        modules += 1; msf.budget.check()
        _require(modules <= MAX_MODULES and at+64 <= limit, "PDB_MODULE_INFO_BUDGET")
        modstream, symbols_size = _u16(dbi, at+34), _u32(dbi, at+36)
        n1, n2 = dbi.find(b"\x00", at+64, limit), -1
        if n1 >= 0:
            n2 = dbi.find(b"\x00", n1+1, limit)
        _require(n1 >= 0 and n2 >= 0, "INVALID_PDB_MODULE_INFO")
        at = (n2+4) & ~3
        _require(at <= limit, "INVALID_PDB_MODULE_INFO")
        if modstream == 0xffff or symbols_size == 0:
            continue
        data = msf.read(modstream, symbols_size)
        _require(len(data) >= 4 and _u32(data, 0) == 4, "UNSUPPORTED_CODEVIEW_SIGNATURE")
        for kind, body in _records(data, msf.budget, 4):
            if kind not in (0x110f, 0x1110, 0x1146, 0x1147):
                continue
            _require(len(body) >= 36, "TRUNCATED_PROCEDURE_RECORD")
            size, offset, section = _u32(body, 12), _u32(body, 28), _u16(body, 32)
            if size == 0:
                continue
            rva = _rva(pe, section, offset, size)
            functions.add((rva, rva+size, _name(body, 35)))
            _require(len(functions) <= MAX_FUNCTIONS, "PDB_FUNCTION_BUDGET")
    if symstream != 0xffff:
        for kind, body in _records(msf.read(symstream), msf.budget):
            if kind != 0x110e:
                continue
            _require(len(body) >= 11, "TRUNCATED_PUBLIC_SYMBOL_RECORD")
            if not _u32(body, 0) & 2:  # PublicSymFlags.Function; ignore data labels.
                continue
            publics.add((_rva(pe, _u16(body, 8), _u32(body, 4)), _name(body, 10)))
            _require(len(publics) <= MAX_FUNCTIONS, "PDB_PUBLIC_SYMBOL_BUDGET")
    return {"guid": guid, "age": age}, sorted(functions), sorted(publics)


class NativeSymbolTable:
    def __init__(self, pe, pdb, functions, publics, hashes):
        self.pe, self.pdb, self.functions = pe, pdb, functions
        self.hashes = hashes
        self.starts = [x[0] for x in functions]
        self.ends = []; high = 0
        for _, end, _ in functions:
            high = max(high, end); self.ends.append(high)
        self.publics = {}
        for rva, name in publics:
            self.publics.setdefault(rva, set()).add(name)

    def lookup(self, rva):
        _require(integer(rva, 0, self.pe["image_size"]-1), "INVALID_SYMBOL_RVA")
        i = bisect_right(self.starts, rva)-1; matches = set(); scanned = 0
        while i >= 0 and self.ends[i] > rva:
            start, end, name = self.functions[i]
            if start <= rva < end:
                matches.add((start, end, name))
            i -= 1; scanned += 1
            _require(scanned <= 4096, "SYMBOL_OVERLAP_BUDGET")
        if len(matches) > 1:
            return {"status": "AMBIGUOUS_PROCEDURE_RANGES", "name": None, "rva": rva}
        if matches:
            start, end, name = next(iter(matches))
            return {"status": "LOCAL_PDB_PROCEDURE_RANGE", "name": name, "rva": rva,
                    "symbol_rva": start, "displacement": rva-start, "code_size": end-start}
        names = self.publics.get(rva, set())
        if len(names) == 1:
            return {"status": "LOCAL_PDB_EXACT_PUBLIC_ENTRY", "name": next(iter(names)),
                    "rva": rva, "symbol_rva": rva, "displacement": 0, "code_size": None}
        return {"status": "AMBIGUOUS_PUBLIC_ENTRY" if names else "NO_RECORDED_FUNCTION_RANGE",
                "name": None, "rva": rva}

    def summary(self):
        return {"pe_sha256": self.hashes[0], "pdb_sha256": self.hashes[1],
                "guid": self.pdb["guid"], "age": self.pdb["age"],
                "procedure_ranges": len(self.functions), "public_entries": len(self.publics),
                "verification_class": "UNAUTHENTICATED_LOCAL_FILES",
                "source_lines": "NOT_SUPPORTED", "inline_frames": "NOT_SUPPORTED",
                "symbol_server_contacted": False, "source_execution": False}


def load_native_symbols(binary_path, pdb_path, *, cancel=None):
    budget = Budget(cancel)
    with snapshot_pair(binary_path, pdb_path, budget) as (paths, hashes):
        with paths[0].open("rb") as binary, paths[1].open("rb") as symbols:
            pe = _pe_layout(binary, paths[0].stat().st_size)
            msf = MsfReader(symbols, paths[1].stat().st_size, budget)
            pdb, functions, publics = _pdb_symbols(msf, pe)
        budget.check()
        return NativeSymbolTable(pe, pdb, functions, publics, hashes)


def resolve_bound_frame(row, frame, table):
    """Shared derived overlay; never changes the raw frame or trusts its name."""
    verdict = binding_verdict(row, frame, table.pe, table.pdb)
    symbol = (table.lookup(frame["rva"]) if verdict == "TRACE_PE_PDB_CONSISTENT_UNVERIFIED"
              else {"status": verdict, "name": None})
    return {"binding": verdict, "symbol": symbol}


def resolve_event_stack(row, binary_path, pdb_path, *, source_trace_sha256=None, cancel=None):
    """New derived report; raw trace/index and the supplied row are unchanged."""
    _require(type(row) is dict and type(row.get("frames")) is list and
             len(row["frames"]) <= 128, "INVALID_STACK_INPUT")
    from .decoder_index import validate_event
    validate_event(row, row.get("ordinal"))
    _require(source_trace_sha256 is None or (type(source_trace_sha256) is str and
             len(source_trace_sha256) == 64 and all(c in "0123456789abcdef" for c in source_trace_sha256)),
             "INVALID_SOURCE_TRACE_HASH")
    table = load_native_symbols(binary_path, pdb_path, cancel=cancel)
    frames = []
    for i, frame in enumerate(row["frames"]):
        if cancel is not None and cancel.is_set():
            raise InterruptedError("SYMBOL_REVIEW_CANCELLED")
        overlay = resolve_bound_frame(row, frame, table)
        frames.append({"frame_index": i, "address": frame["address"],
                       "recorded_name": frame["name"], **overlay})
    return {"schema": "blackbox.native-symbol-report/1", "status": "REVIEWED",
            "source_trace_sha256": source_trace_sha256,
            "source_event_id": row.get("ordinal"), "process_instance": row.get("process_instance"),
            "pid": row.get("pid"), "frames": frames, "local_files": table.summary(),
            "resolved_frames": sum(bool(f["symbol"]["name"]) for f in frames),
            "verification_class": "DERIVED_FROM_UNVERIFIED_TRACE_AND_LOCAL_FILES",
            "root_cause": "UNKNOWN", "trace_to_session_alignment": "NOT_ESTABLISHED"}
