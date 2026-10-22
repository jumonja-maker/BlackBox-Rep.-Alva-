"""Ensure the Windows Explorer icon of each PyInstaller EXE matches BLACK.BOX.

PE resources are inspected directly: a Qt window icon is not an EXE icon.
No Windows API or external dependencies; useful for release/build QA.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import struct
import sys


def _u16(data: bytes, pos: int) -> int:
    return struct.unpack_from("<H", data, pos)[0]


def _u32(data: bytes, pos: int) -> int:
    return struct.unpack_from("<I", data, pos)[0]


def _ico_frames(path: Path) -> Counter[bytes]:
    data = path.read_bytes()
    if len(data) < 6 or _u16(data, 0) != 0 or _u16(data, 2) != 1:
        raise ValueError("INVALID_ICO")
    count = _u16(data, 4)
    if not 1 <= count <= 32 or len(data) < 6 + 16 * count:
        raise ValueError("INVALID_ICO_ENTRIES")
    frames = []
    for i in range(count):
        size, offset = struct.unpack_from("<II", data, 6 + 16 * i + 8)
        if not size or offset < 6 + 16 * count or offset + size > len(data):
            raise ValueError("INVALID_ICO_FRAME")
        frames.append(data[offset:offset + size])
    return Counter(frames)


def _exe_frames(path: Path) -> Counter[bytes]:
    data = path.read_bytes()
    if len(data) < 256 or data[:2] != b"MZ":
        raise ValueError("NOT_PE_EXE")
    pe = _u32(data, 0x3C)
    if data[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("NOT_PE_EXE")
    optional = pe + 24
    magic = _u16(data, optional)
    if magic not in (0x10B, 0x20B):
        raise ValueError("UNSUPPORTED_PE")
    directory = optional + (112 if magic == 0x20B else 96)
    resources_rva = _u32(data, directory + 16)
    sections = []
    for i in range(_u16(data, pe + 6)):
        offset = optional + _u16(data, pe + 20) + 40 * i
        sections.append((_u32(data, offset + 12),
                         max(_u32(data, offset + 8), _u32(data, offset + 16)),
                         _u32(data, offset + 20)))

    def file_offset(rva: int) -> int:
        for start, size, raw in sections:
            if start <= rva < start + size:
                return raw + rva - start
        raise ValueError("BAD_PE_RESOURCE_RVA")

    base = file_offset(resources_rva)

    def entries(relative: int) -> dict[int, int]:
        position = base + relative
        count = _u16(data, position + 12) + _u16(data, position + 14)
        if count > 2048:
            raise ValueError("TOO_MANY_RESOURCES")
        return {_u32(data, position + 16 + 8 * i):
                _u32(data, position + 20 + 8 * i) for i in range(count)}

    def resource_type(kind: int) -> dict[int, bytes]:
        node = entries(0).get(kind)
        if node is None or not node & 0x80000000:
            raise ValueError("MISSING_PE_ICON_RESOURCES")
        result = {}
        for identifier, child in entries(node & 0x7FFFFFFF).items():
            if identifier & 0x80000000 or not child & 0x80000000:
                raise ValueError("BAD_PE_ICON_DIRECTORY")
            languages = entries(child & 0x7FFFFFFF)
            if not languages:
                raise ValueError("MISSING_PE_ICON_LANGUAGE")
            leaf = next(iter(languages.values()))
            if leaf & 0x80000000:
                raise ValueError("BAD_PE_ICON_LEAF")
            pointer = base + leaf
            position = file_offset(_u32(data, pointer))
            size = _u32(data, pointer + 4)
            result[identifier] = data[position:position + size]
        return result

    groups = resource_type(14)  # RT_GROUP_ICON
    frames = resource_type(3)   # RT_ICON
    if not groups:
        raise ValueError("MISSING_PE_GROUP_ICON")
    group = next(iter(groups.values()))
    if len(group) < 6 or _u16(group, 0) != 0 or _u16(group, 2) != 1:
        raise ValueError("INVALID_PE_GROUP_ICON")
    count = _u16(group, 4)
    if not 1 <= count <= 32 or len(group) < 6 + 14 * count:
        raise ValueError("INVALID_PE_GROUP_ENTRIES")
    output = []
    for i in range(count):
        entry = 6 + 14 * i
        size = _u32(group, entry + 8)
        frame = frames.get(_u16(group, entry + 12))
        if frame is None or len(frame) != size:
            raise ValueError("INVALID_PE_ICON_FRAME")
        output.append(frame)
    return Counter(output)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("Usage: verify_windows_exe_icons.py ICON.ico APP.exe HELPER.exe [...]",
              file=sys.stderr)
        return 2
    expected = _ico_frames(Path(argv[0]))
    for name in argv[1:]:
        observed = _exe_frames(Path(name))
        if observed != expected:
            print(f"FAIL: {Path(name).name} has a different Explorer icon",
                  file=sys.stderr)
            return 1
        print(f"PASS: {Path(name).name} has all {sum(observed.values())} BLACK.BOX icon sizes")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, struct.error) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
