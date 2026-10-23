"""GitHub Releases update discovery and cautious staging of a portable build.

No silent downloads, background installs, arbitrary URLs or release scraping.
The user must confirm each update. Verified SHA-256 is REQUIRED for the
official release asset. Incomplete/stale staging never touches an installation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import unicodedata
import shutil
import stat
import tempfile
from urllib import error, request
from urllib.parse import quote
import zipfile

from . import __version__

OWNER = "jumonja-maker"
REPO = "BlackBox-Rep.-Alva-"
RELEASE_API = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/latest"
RELEASES_API = f"https://api.github.com/repos/{OWNER}/{REPO}/releases?per_page=10"
ARCHIVE_NAME = "BLACK.BOX-Universal-Windows.zip"
EXECUTABLE_NAME = "BLACK.BOX-Universal.exe"
MAINTENANCE_NAME = "BLACK.BOX-Maintenance.exe"
INSTALL_MARKER = ".blackbox-portable.json"
MAX_ARCHIVE_BYTES = 350 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 1200 * 1024 * 1024
MAX_MEMBERS = 10000
_VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
_SHA256 = re.compile(r"^sha256:([0-9a-fA-F]{64})$")


class NoOfficialRelease(LookupError):
    """The public repository exists but has no stable GitHub Release."""


@dataclass(frozen=True)
class Release:
    version: str
    asset_url: str
    size: int
    sha256: str
    notes_url: str


def version_tuple(raw: str) -> tuple[int, int, int] | None:
    match = _VERSION.fullmatch(raw.strip())
    return tuple(int(v) for v in match.groups()) if match else None


def _open(url: str):
    return request.urlopen(request.Request(
        url, headers={"User-Agent": "BLACK.BOX-Universal-updater",
                      "Accept": "application/vnd.github+json"}),
        timeout=12)


def check_latest_release(current: str = __version__) -> Release | None:
    """Return only a strictly newer RELEASE with a trustworthy GitHub digest.

    A missing release or an unverified asset is not a green update indicator.
    Any network/metadata failure is reported as an exception, not 'no update'.
    """
    now = version_tuple(current)
    if now is None:
        raise ValueError("LOCAL_VERSION_INVALID")
    try:
        with _open(RELEASE_API) as connection:
            data = connection.read(256 * 1024 + 1)
    except error.HTTPError as exc:
        if exc.code != 404:
            raise
        # GitHub responds 404 when a public repo has no stable Release.
        # Verify the Releases endpoint itself is accessible before treating
        # that as a normal product state: a missing repo/permission/network
        # error must still be shown as a genuine update-check failure.
        with _open(RELEASES_API) as connection:
            listing = connection.read(256 * 1024 + 1)
        if len(listing) > 256 * 1024:
            raise ValueError("RELEASE_METADATA_TOO_LARGE")
        releases = json.loads(listing.decode("utf-8"))
        if type(releases) is not list or any(type(item) is not dict for item in releases):
            raise ValueError("RELEASE_LIST_INVALID")
        if any(not item.get("draft") and not item.get("prerelease")
               for item in releases):
            raise ValueError("RELEASE_METADATA_INCONSISTENT")
        raise NoOfficialRelease("NO_OFFICIAL_RELEASE") from None
    if len(data) > 256 * 1024:
        raise ValueError("RELEASE_METADATA_TOO_LARGE")
    payload = json.loads(data.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("RELEASE_METADATA_INVALID")
    tag = payload.get("tag_name")
    if payload.get("draft") or payload.get("prerelease") or not isinstance(tag, str):
        return None
    found = version_tuple(tag)
    if found is None or found <= now:
        return None
    for item in payload.get("assets", []):
        if not isinstance(item, dict) or item.get("name") != ARCHIVE_NAME:
            continue
        digest = item.get("digest") or ""
        match = _SHA256.fullmatch(digest)
        if not match:
            raise ValueError("RELEASE_DIGEST_MISSING")
        url = item.get("browser_download_url")
        expected = (f"https://github.com/{OWNER}/{REPO}/releases/"
                    f"download/{quote(tag, safe='')}/{ARCHIVE_NAME}")
        if url != expected:
            raise ValueError("RELEASE_ASSET_URL_UNTRUSTED")
        size = item.get("size")
        if type(size) is not int or not (1 <= size <= MAX_ARCHIVE_BYTES):
            raise ValueError("RELEASE_SIZE_INVALID")
        html_url = payload.get("html_url")
        if html_url != f"https://github.com/{OWNER}/{REPO}/releases/tag/{quote(tag, safe='')}":
            raise ValueError("RELEASE_NOTES_URL_UNTRUSTED")
        return Release(tag, url, size, match.group(1).lower(), html_url)
    raise ValueError("RELEASE_ARCHIVE_NOT_FOUND")


def runtime_directory() -> Path | None:
    """Portable updates allowed only for a bundled EXE with our install marker."""
    import sys
    if not getattr(sys, "frozen", False) or os.name != "nt":
        return None
    folder = Path(sys.executable).resolve().parent
    marker = folder / INSTALL_MARKER
    if marker.is_symlink() or not marker.is_file():
        return None
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
        if (value.get("product") != "blackbox-universal" or
                value.get("install_type") != "portable"):
            return None
    except (OSError, ValueError, AttributeError):
        return None
    if not (folder / MAINTENANCE_NAME).is_file():
        return None
    return folder


_WIN_DEVICE = re.compile(
    r"^(?:CON|PRN|AUX|NUL|(?:COM|LPT)[1-9\u00b9\u00b2\u00b3])(?:\.|$)",
    re.IGNORECASE,
)
_WIN_FORBIDDEN = frozenset('<>:"|?*')


def _valid_portable_component(part: str) -> bool:
    """Conservative Windows ZIP filenames: reject aliases and device paths."""
    return bool(part and part not in (".", "..") and
                not part.endswith((".", " ")) and
                not any(ord(c) < 32 or c in _WIN_FORBIDDEN for c in part) and
                _WIN_DEVICE.match(part) is None)


def _extract_release(zip_path: Path, dest: Path) -> Path:
    """Reject paths escaping the package, links, duplicate targets, and zip bombs."""
    root_name = "BLACK.BOX-Universal"
    root = dest / root_name
    seen = set()
    regular_files, directories = set(), set()
    used = 0
    # Never extract onto an existing root: it may be a directory junction or
    # symlink planted between staging and extraction by another actor.
    if root.exists() or root.is_symlink():
        raise ValueError("STAGING_NOT_EMPTY")
    with zipfile.ZipFile(zip_path) as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise ValueError("RELEASE_TOO_MANY_FILES")
        for item in members:
            original = item.filename
            if "\\" in original or "\x00" in original:
                raise ValueError("ARCHIVE_PATH_INVALID")
            raw_parts = original.rstrip("/").split("/")
            # Windows filesystem aliases (CON, trailing dots, ADS colons)
            # and noncanonical components can bypass path comparisons.
            if not raw_parts or any(not _valid_portable_component(part) for part in raw_parts):
                raise ValueError("ARCHIVE_PATH_INVALID")
            name = PurePosixPath(original)
            parts = name.parts
            if name.is_absolute() or parts[0] != root_name or len(parts) < 2:
                # An explicit root directory is allowed, but never a root file.
                if not (item.is_dir() and parts == (root_name,)):
                    raise ValueError("ARCHIVE_PATH_INVALID")
            canonical = unicodedata.normalize("NFC", original.rstrip("/")).casefold()
            if canonical in seen:
                raise ValueError("ARCHIVE_DUPLICATE_PATH")
            seen.add(canonical)
            kind = (item.external_attr >> 16) & 0o170000
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError("ARCHIVE_SPECIAL_FILE_REFUSED")
            if kind == stat.S_IFDIR and not item.is_dir():
                raise ValueError("ARCHIVE_TYPE_CONFLICT")
            if item.is_dir():
                directories.add(canonical)
            else:
                regular_files.add(canonical)
            used += item.file_size
            if used > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("ARCHIVE_TOO_LARGE")
        # A file must not act as a parent directory of any other archive entry.
        # Check *before* writing the first byte into the staging directory.
        for name in seen:
            parts = name.split("/")
            if any("/".join(parts[:i]) in regular_files
                   for i in range(1, len(parts))):
                raise ValueError("ARCHIVE_FILE_DIRECTORY_COLLISION")
        for item in members:
            if item.is_dir():
                continue
            dest_file = dest.joinpath(*PurePosixPath(item.filename).parts)
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(item) as source, dest_file.open("xb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
    if not (root / EXECUTABLE_NAME).is_file():
        raise ValueError("RELEASE_EXE_MISSING")
    if not (root / MAINTENANCE_NAME).is_file():
        raise ValueError("RELEASE_MAINTENANCE_MISSING")
    if not (root / INSTALL_MARKER).is_file():
        raise ValueError("RELEASE_MARKER_MISSING")
    try:
        marker = json.loads((root / INSTALL_MARKER).read_text(encoding="utf-8"))
        if marker != {"product": "blackbox-universal", "install_type": "portable"}:
            raise ValueError("RELEASE_MARKER_INVALID")
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("RELEASE_MARKER_INVALID") from error
    return root


def stage_release(release: Release, install: Path) -> Path:
    """Prepare complete replacement next to installation, without touching it."""
    install = Path(install).resolve()
    parent = install.parent
    workspace = Path(tempfile.mkdtemp(prefix=".blackbox-stage-", dir=parent))
    archive = workspace / "release.zip"
    try:
        total = 0
        digest = hashlib.sha256()
        with _open(release.asset_url) as connection, archive.open("xb") as target:
            while True:
                chunk = connection.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES or total > release.size:
                    raise ValueError("RELEASE_DOWNLOAD_TOO_LARGE")
                digest.update(chunk)
                target.write(chunk)
        if total != release.size or digest.hexdigest() != release.sha256:
            raise ValueError("RELEASE_CHECKSUM_MISMATCH")
        result = _extract_release(archive, workspace)
        archive.unlink()
        return result
    except Exception:
        shutil.rmtree(workspace, ignore_errors=True)
        raise
