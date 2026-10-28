"""Read-only local PE / Windows PDB identity preflight for Trace Decoder.

This does NOT resolve stack symbols, prove a module belongs to an imported
trace, authenticate local files, contact symbol servers or run target code.
No DLL/PDB is loaded as executable; only bounded byte ranges are inspected.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import struct
from uuid import UUID

MAX_LOCAL_FILE_BYTES = 512 * 1024 * 1024
MAX_PE_LFANEW = 1 * 1024 * 1024
MAX_PE_SECTIONS = 96
MAX_PE_DEBUG_ENTRIES = 256
MAX_PDB_DIRECTORY = 4 * 1024 * 1024
MSF7_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
PDB_STREAM_VC70 = 20000404


class IdentityUnavailable(ValueError):
    """Bounded, non-path-bearing failure code for untrusted local bytes."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise IdentityUnavailable(reason)


def _u16(buf: bytes, position: int) -> int:
    return struct.unpack_from("<H", buf, position)[0]


def _u32(buf: bytes, position: int) -> int:
    return struct.unpack_from("<I", buf, position)[0]


def _read(stream, position: int, length: int, total: int) -> bytes:
    _require(0 <= position <= total and 0 <= length <= total - position,
             "TRUNCATED_OR_OUT_OF_RANGE_FILE_DATA")
    stream.seek(position)
    data = stream.read(length)
    _require(len(data) == length, "TRUNCATED_OR_OUT_OF_RANGE_FILE_DATA")
    return data


def _local_file(path):
    target = Path(path).absolute()
    value = str(target)
    _require(not value.startswith(("\\\\", "//")) and "\x00" not in value,
             "UNSAFE_LOCAL_PATH")
    for piece in target.parts[1:]:
        _require(":" not in piece and not piece.endswith((" ", ".")),
                 "UNSAFE_LOCAL_PATH")
    for part in (target, *target.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            raise IdentityUnavailable("LOCAL_FILE_UNAVAILABLE") from None
        _require(not stat.S_ISLNK(info.st_mode) and
                 not (getattr(info, "st_file_attributes", 0) & 0x400),
                 "UNSAFE_LOCAL_PATH")
    info = target.lstat()
    _require(stat.S_ISREG(info.st_mode) and
             64 <= info.st_size <= MAX_LOCAL_FILE_BYTES,
             "LOCAL_FILE_SIZE_OR_TYPE_UNSUPPORTED")
    return target, info


def _stable_file(path, initial, opened) -> None:
    latest = path.lstat()
    for observed in (opened, latest):
        _require(observed.st_size == initial.st_size and
                 observed.st_mtime_ns == initial.st_mtime_ns and
                 (observed.st_dev, observed.st_ino) ==
                 (initial.st_dev, initial.st_ino), "LOCAL_FILE_CHANGED_DURING_REVIEW")
    _require(not stat.S_ISLNK(latest.st_mode) and
             not (getattr(latest, "st_file_attributes", 0) & 0x400),
             "UNSAFE_LOCAL_PATH")


def _rva_to_offset(rva, size, sections, headers_size, file_size):
    if rva < headers_size:
        _require(rva + size <= headers_size and rva + size <= file_size,
                 "INVALID_PE_DEBUG_DIRECTORY")
        return rva
    matches = []
    for virtual_address, virtual_size, raw_size, raw_ptr in sections:
        if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
            displacement = rva - virtual_address
            if displacement + size <= raw_size and raw_ptr + displacement + size <= file_size:
                matches.append(raw_ptr + displacement)
    _require(len(matches) == 1, "INVALID_OR_AMBIGUOUS_PE_RVA")
    return matches[0]


def _pe_rsds(stream, size):
    mz = _read(stream, 0, 64, size)
    _require(mz[:2] == b"MZ", "INVALID_PE_IMAGE")
    pe_at = _u32(mz, 60)
    _require(64 <= pe_at <= MAX_PE_LFANEW, "INVALID_PE_IMAGE")
    coff = _read(stream, pe_at, 24, size)
    _require(coff[:4] == b"PE\x00\x00", "INVALID_PE_IMAGE")
    section_count, optional_len = _u16(coff, 6), _u16(coff, 20)
    _require(1 <= section_count <= MAX_PE_SECTIONS and
             112 <= optional_len <= 4096, "UNSUPPORTED_PE_IMAGE_LAYOUT")
    optional = _read(stream, pe_at + 24, optional_len, size)
    magic = _u16(optional, 0)
    _require(magic in (0x10B, 0x20B), "UNSUPPORTED_PE_IMAGE_LAYOUT")
    directory_at = 96 if magic == 0x10B else 112
    _require(optional_len >= directory_at + 7 * 8 and
             _u32(optional, directory_at - 4) >= 7,
             "NO_PE_DEBUG_DIRECTORY")
    debug_rva = _u32(optional, directory_at + 6 * 8)
    debug_size = _u32(optional, directory_at + 6 * 8 + 4)
    _require(debug_rva != 0 and debug_size > 0, "NO_PE_DEBUG_DIRECTORY")
    _require(debug_size % 28 == 0 and
             debug_size // 28 <= MAX_PE_DEBUG_ENTRIES,
             "INVALID_PE_DEBUG_DIRECTORY")
    headers_size = _u32(optional, 60)
    section_data = _read(stream, pe_at + 24 + optional_len,
                         section_count * 40, size)
    sections = []
    for index in range(section_count):
        start = index * 40
        sections.append((_u32(section_data, start + 12),
                         _u32(section_data, start + 8),
                         _u32(section_data, start + 16),
                         _u32(section_data, start + 20)))
    directory_offset = _rva_to_offset(debug_rva, debug_size, sections,
                                      headers_size, size)
    directory = _read(stream, directory_offset, debug_size, size)
    identities = set()
    portable = False
    for index in range(debug_size // 28):
        start = index * 28
        if _u32(directory, start + 12) != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        record_size, record_rva, record_ptr = struct.unpack_from(
            "<III", directory, start + 16)
        if record_size < 24 or record_size > 4096:
            continue
        if record_ptr:
            data = _read(stream, record_ptr, record_size, size)
        else:
            data = _read(stream, _rva_to_offset(record_rva, record_size,
                                               sections, headers_size, size),
                         record_size, size)
        if data[:4] != b"RSDS":
            continue
        if _u16(directory, start + 10) == 0x504D:
            portable = True
            continue
        guid = data[4:20]
        age = _u32(data, 20)
        _require(any(guid) and age > 0, "INVALID_PE_RSDS_IDENTITY")
        # Keep only the basename. The original build-machine path may be private.
        path_bytes = data[24:].split(b"\x00", 1)
        _require(len(path_bytes) == 2, "INVALID_PE_RSDS_IDENTITY")
        basename = path_bytes[0].replace(b"\\", b"/").rsplit(b"/", 1)[-1]
        _require(0 < len(basename) <= 255, "INVALID_PE_RSDS_IDENTITY")
        identities.add((guid, age, basename.decode("utf-8", errors="replace")))
    _require(not portable, "PORTABLE_PDB_UNSUPPORTED")
    _require(len(identities) != 0, "PE_RSDS_IDENTITY_NOT_RECORDED")
    # Distinct records must not be chosen by arbitrary first-match ordering.
    _require(len({(guid, age) for guid, age, _ in identities}) == 1,
             "AMBIGUOUS_PE_RSDS_IDENTITY")
    guid, age, name = sorted(identities, key=lambda row: row[2])[0]
    return {"guid": str(UUID(bytes_le=guid)), "age": age,
            "pdb_basename": name, "source": "PE_CODEVIEW_RSDS_RECORD"}


def _pdb_msf7_info(stream, size):
    header = _read(stream, 0, 56, size)
    _require(header[:32] == MSF7_MAGIC, "UNSUPPORTED_PDB_CONTAINER")
    block_size, free_map, block_count, directory_size, unused, map_block = (
        struct.unpack_from("<6I", header, 32))
    _require(block_size in (512, 1024, 2048, 4096) and
             free_map in (1, 2) and block_count >= 6 and
             block_size * block_count == size and
             12 <= directory_size <= MAX_PDB_DIRECTORY and
             3 <= map_block < block_count,
             "UNSUPPORTED_OR_INVALID_MSF_LAYOUT")
    needed = (directory_size + block_size - 1) // block_size
    _require(needed <= block_size // 4, "MSF_DIRECTORY_MAP_TOO_LARGE")
    indexes = _read(stream, map_block * block_size, needed * 4, size)
    blocks = struct.unpack("<" + "I" * needed, indexes)
    _require(all(3 <= page < block_count for page in blocks) and
             len(set(blocks)) == needed, "INVALID_MSF_DIRECTORY_BLOCKS")
    directory = b"".join(_read(stream, page * block_size, block_size, size)
                         for page in blocks)[:directory_size]
    streams = _u32(directory, 0)
    _require(2 <= streams <= 16384 and 4 + 4 * streams <= len(directory),
             "INVALID_MSF_STREAM_DIRECTORY")
    sizes = struct.unpack_from("<" + "I" * streams, directory, 4)
    offset = 4 + streams * 4
    first_info_block = None
    for i, stream_size in enumerate(sizes):
        count = 0 if stream_size == 0xFFFFFFFF else (
            (stream_size + block_size - 1) // block_size)
        _require(offset + 4 * count <= len(directory),
                 "INVALID_MSF_STREAM_DIRECTORY")
        if i == 1:
            _require(stream_size != 0xFFFFFFFF and stream_size >= 28 and count > 0,
                     "PDB_INFO_STREAM_UNAVAILABLE")
            first_info_block = _u32(directory, offset)
        offset += 4 * count
    _require(offset == len(directory), "INVALID_MSF_STREAM_DIRECTORY")
    _require(first_info_block is not None and 3 <= first_info_block < block_count,
             "INVALID_MSF_STREAM_DIRECTORY")
    info = _read(stream, first_info_block * block_size, 28, size)
    version, signature, age = struct.unpack_from("<III", info, 0)
    _require(version == PDB_STREAM_VC70, "UNSUPPORTED_PDB_INFO_VERSION")
    _require(age > 0 and any(info[12:28]), "INVALID_PDB_INFO_IDENTITY")
    return {"guid": str(UUID(bytes_le=info[12:28])), "age": age,
            "source": "WINDOWS_PDB_MSF7_INFO_STREAM"}


def inspect_local_identity(path, kind):
    """Bounded open; changes/reparse points reject the result rather than certify."""
    target, before = _local_file(path)
    with target.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        _require(opened.st_size == before.st_size and
                 opened.st_mtime_ns == before.st_mtime_ns and
                 (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                 "LOCAL_FILE_CHANGED_DURING_REVIEW")
        result = (_pe_rsds(stream, opened.st_size) if kind == "pe" else
                  _pdb_msf7_info(stream, opened.st_size))
        after = os.fstat(stream.fileno())
    _stable_file(target, before, after)
    return result


def review_local_pe_pdb(binary_path, pdb_path):
    """Compare recorded PE CodeView and local MSF7 PDB GUID/age, nothing more."""
    common = {"trace_module_identity": "NOT_ESTABLISHED",
              "stack_symbols_resolved": False,
              "symbol_server_contacted": False,
              "source_execution": False,
              "verification_class": "UNAUTHENTICATED_LOCAL_FILES",
              "limitations": ["GUID_AGE_IS_NOT_MODULE_LOAD_IDENTITY",
                              "NO_TRACE_MODULE_ASSOCIATION",
                              "NO_SYMBOL_NAMES_RESOLVED",
                              "NO_NETWORK_LOOKUP"]}
    try:
        binary = inspect_local_identity(binary_path, "pe")
        pdb = inspect_local_identity(pdb_path, "pdb")
    except IdentityUnavailable as exc:
        return {**common, "status": "LOCAL_IDENTITY_UNAVAILABLE",
                "reason": str(exc)}
    except (OSError, ValueError, TypeError, OverflowError, struct.error):
        return {**common, "status": "LOCAL_IDENTITY_UNAVAILABLE",
                "reason": "LOCAL_FILE_INSPECTION_FAILED"}
    matched = ((binary["guid"], binary["age"]) == (pdb["guid"], pdb["age"]))
    return {**common,
            "status": ("PE_PDB_GUID_AGE_MATCH_UNLINKED_TO_TRACE" if matched
                       else "PE_PDB_GUID_AGE_MISMATCH"),
            "binary": binary, "pdb": pdb,
            "identity_quality": ("GUID_AGE_CONSISTENT_UNAUTHENTICATED" if matched
                                 else "GUID_OR_AGE_DIFFERENT"),
            "pdb_name_matching": ("MATCH" if Path(binary["pdb_basename"]).name.casefold() ==
                                   Path(pdb_path).name.casefold() else "DIFFERENT_NAME_NOT_IDENTITY"),
            }
