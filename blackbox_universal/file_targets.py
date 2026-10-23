"""Read-only file selection and exact-path matching of Windows executables.

Browsing a file is NEVER execution. Only an EXE with a verified PE header may
be explicitly launched by the GUI after a separate user confirmation. DLL,
MSI, script, JAR and other files are metadata-only targets.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import stat
import struct

import psutil

HASH_LIMIT = 16 * 1024 * 1024
_MAX_PE_OFFSET = 1024 * 1024
_MACHINE = {0x014C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x01C4: "ARM"}
_FILE_KINDS = {
    ".exe": "Windows executable",
    ".dll": "Windows library",
    ".sys": "Windows driver",
    ".com": "Executable or command file",
    ".msi": "Windows Installer package",
    ".bat": "Command script",
    ".cmd": "Command script",
    ".ps1": "PowerShell script",
    ".py": "Python script",
    ".jar": "Java archive",
}


@dataclass(frozen=True)
class InspectedFile:
    path: Path
    kind: str
    size_bytes: int
    modified_utc: str
    architecture: str | None
    sha256: str | None
    executable_target: bool


def _pe_architecture(stream, size: int) -> str | None:
    """Read only bounded PE header offsets; do not map or load the file."""
    stream.seek(0)
    dos = stream.read(64)
    if len(dos) < 64 or dos[:2] != b"MZ":
        return None
    offset = struct.unpack_from("<I", dos, 0x3C)[0]
    if not (64 <= offset <= _MAX_PE_OFFSET and offset + 6 <= size):
        return None
    stream.seek(offset)
    header = stream.read(6)
    if len(header) != 6 or header[:4] != b"PE\0\0":
        return None
    return _MACHINE.get(struct.unpack_from("<H", header, 4)[0], "Unknown PE")


def inspect_file(path: str | Path) -> InspectedFile:
    """Inspect regular-file metadata without executing/loading its contents."""
    file_path = Path(path).expanduser().resolve(strict=True)
    info = file_path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("FILE_NOT_REGULAR")
    ext = file_path.suffix.lower()
    sha = None
    with file_path.open("rb") as stream:
        arch = _pe_architecture(stream, info.st_size) if ext in (".exe", ".dll", ".sys") else None
        if info.st_size <= HASH_LIMIT:
            stream.seek(0)
            digest = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
            sha = digest.hexdigest()
    modified = datetime.fromtimestamp(info.st_mtime, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return InspectedFile(
        path=file_path,
        kind=_FILE_KINDS.get(ext, "Other file"),
        size_bytes=info.st_size,
        modified_utc=modified,
        architecture=arch,
        sha256=sha,
        executable_target=(ext == ".exe" and arch is not None and arch != "Unknown PE"),
    )


def _path_key(value: str | Path) -> str:
    # Windows process paths are case-insensitive; Linux tests retain POSIX case.
    return os.path.normcase(os.path.realpath(os.path.abspath(str(value))))


def find_running_executable(path: str | Path) -> list[tuple[int, str]]:
    """Match actual process EXE paths; never guess from process names."""
    expected = _path_key(path)
    matched: list[tuple[int, str]] = []
    for process in psutil.process_iter(["pid", "name", "exe"], ad_value=None):
        try:
            fields = process.info
            candidate = fields.get("exe")
            pid = fields.get("pid")
            if candidate and type(pid) is int and pid > 0 and _path_key(candidate) == expected:
                matched.append((pid, str(fields.get("name") or "unknown")[:96]))
        except (psutil.Error, OSError, ValueError):
            continue
    return sorted(matched)
