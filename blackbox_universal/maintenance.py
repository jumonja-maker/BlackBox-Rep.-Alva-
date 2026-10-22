"""Explicit portable Windows maintenance — replacement/uninstall after app exit.

Built as a separate EXE so Windows never attempts to overwrite a running
application. Refuses unmarked directories, junctions and system roots.
No subprocess shell execution or internet is required.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from uuid import uuid4

from .releases import (EXECUTABLE_NAME, INSTALL_MARKER, MAINTENANCE_NAME,
                       _extract_release)
from .shortcuts import remove_shortcut_if_matches

SAVED_DIRS = ("logs", "sessions", "reports")
MARKER = {"product": "blackbox-universal", "install_type": "portable"}


class MaintenanceError(RuntimeError):
    pass


def _safe_install(path: Path) -> Path:
    """Only a specific, marked portable folder can be affected."""
    candidate = Path(os.path.abspath(path))
    if candidate.is_symlink() or not candidate.is_dir():
        raise MaintenanceError("INSTALL_FOLDER_INVALID")
    if candidate.parent == candidate or candidate.parent.parent == candidate.parent:
        raise MaintenanceError("SYSTEM_ROOT_REFUSED")
    if any(part.casefold() in ("windows", "program files",
                              "program files (x86)") for part in candidate.parts):
        raise MaintenanceError("SYSTEM_INSTALL_REFUSED")
    for name in (INSTALL_MARKER, EXECUTABLE_NAME, MAINTENANCE_NAME):
        item = candidate / name
        if item.is_symlink() or not item.is_file():
            raise MaintenanceError("PORTABLE_INSTALL_NOT_VERIFIED")
    try:
        manifest = json.loads((candidate / INSTALL_MARKER).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise MaintenanceError("PORTABLE_INSTALL_NOT_VERIFIED") from None
    if manifest != MARKER:
        raise MaintenanceError("PORTABLE_INSTALL_NOT_VERIFIED")
    return candidate


def _wait_closed(pid: int, deadline_seconds: int = 55) -> None:
    if os.name != "nt":
        raise MaintenanceError("WINDOWS_ONLY")
    import ctypes
    from ctypes import wintypes
    SYNCHRONIZE = 0x00100000
    WAIT_TIMEOUT = 0x102
    WAIT_OBJECT_0 = 0
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel32.OpenProcess(SYNCHRONIZE, False, pid)
    if not handle:
        # If the process no longer exists it is safe to proceed; any other
        # Windows failure stops rather than risking a half-applied update.
        if ctypes.get_last_error() == 87:  # ERROR_INVALID_PARAMETER
            return
        raise MaintenanceError("COULD_NOT_VERIFY_APP_EXIT")
    try:
        status = kernel32.WaitForSingleObject(handle, deadline_seconds * 1000)
        if status != WAIT_OBJECT_0:
            raise MaintenanceError(
                "APP_STILL_RUNNING" if status == WAIT_TIMEOUT else "WAIT_FAILED")
    finally:
        kernel32.CloseHandle(handle)


def _user_data_root() -> Path:
    return Path.home() / "Documents" / "BLACK.BOX Universal"


def _keep_local_logs(folder: Path, destination: Path) -> list[tuple[Path, Path]]:
    """Move logs/report evidence outside removable app directory, fail closed."""
    changed: list[tuple[Path, Path]] = []
    try:
        for name in SAVED_DIRS:
            source = folder / name
            if not source.exists() and not source.is_symlink():
                continue
            if source.is_symlink() or not source.is_dir():
                raise MaintenanceError("DATA_LINK_REFUSED")
            target = destination / name
            if target.exists():
                raise MaintenanceError("DATA_PRESERVE_COLLISION")
            destination.mkdir(parents=True, exist_ok=True)
            source.replace(target)
            changed.append((target, source))
        return changed
    except Exception:
        for copied, original in reversed(changed):
            copied.replace(original)
        raise


def uninstall(install: Path) -> None:
    install = _safe_install(install)
    data = _user_data_root()
    if data == install or install in data.parents or data in install.parents:
        raise MaintenanceError("DATA_LOCATION_INSIDE_INSTALL")
    preserved = data / ("Preserved-" + datetime.now().strftime("%Y%m%d-%H%M%S")
                        + "-" + uuid4().hex[:6])
    moves = _keep_local_logs(install, preserved)
    try:
        shutil.rmtree(install)
    except Exception:
        for moved, previous in reversed(moves):
            if previous.parent.exists() and moved.exists():
                moved.replace(previous)
        raise
    # Desktop link only removed if it actually points to this executable.
    try:
        remove_shortcut_if_matches(install / EXECUTABLE_NAME)
    except Exception:
        pass  # Do not undo successful removal due to optional shell-link issues.


def apply_update(install: Path, staged: Path) -> None:
    install = _safe_install(install)
    staged = Path(os.path.abspath(staged))
    if staged.is_symlink() or staged.parent.parent != install.parent:
        raise MaintenanceError("STAGING_ROOT_NOT_SIBLING")
    if not staged.parent.name.startswith(".blackbox-stage-"):
        raise MaintenanceError("UNAUTHORIZED_STAGING_FOLDER")
    _safe_install(staged)
    backup = install.parent / (".blackbox-old-" + uuid4().hex)
    moved: list[tuple[Path, Path]] = []
    old_renamed = False
    new_installed = False
    try:
        install.replace(backup)
        old_renamed = True
        staged.replace(install)
        new_installed = True
        for name in SAVED_DIRS:
            previous = backup / name
            if not previous.exists() and not previous.is_symlink():
                continue
            if previous.is_symlink() or not previous.is_dir():
                raise MaintenanceError("DATA_LINK_REFUSED")
            new_place = install / name
            if new_place.exists():
                raise MaintenanceError("UPDATE_DATA_COLLISION")
            previous.replace(new_place)
            moved.append((new_place, previous))
        # New version and user data are now committed. Do not roll back
        # to a partially deleted old version if antivirus delays cleanup.
        old_renamed = False
        for attempt in range(4):
            try:
                shutil.rmtree(backup)
                break
            except OSError:
                if attempt == 3:
                    # Keep the working new app; a preserved backup can be
                    # inspected/retried instead of risking irreversible loss.
                    break
                time.sleep(0.4)
        try:
            shutil.rmtree(staged.parent)
        except OSError:
            pass
    except Exception:
        # If deleting the backup partly succeeded, it must NOT be used as a
        # rollback source. Leave the new working installation intact.
        if old_renamed and backup.exists() and (backup / EXECUTABLE_NAME).is_file():
            for new_place, previous in reversed(moved):
                if new_place.exists():
                    new_place.replace(previous)
            if new_installed and install.exists():
                install.replace(staged)
            backup.replace(install)
        elif old_renamed and not install.exists() and backup.exists():
            backup.replace(install)
        raise
    try:
        subprocess.Popen([str(install / EXECUTABLE_NAME)], cwd=str(install),
                         close_fds=True)
    except OSError:
        pass  # Successful update must not be rolled back due to shell issues.


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("uninstall", "update"))
    parser.add_argument("--install", type=Path, required=True)
    parser.add_argument("--wait-pid", type=int, required=True)
    parser.add_argument("--staged", type=Path)
    opts = parser.parse_args(argv)
    try:
        if opts.wait_pid <= 0:
            raise MaintenanceError("INVALID_WAIT_PID")
        _safe_install(opts.install)
        if opts.command == "update" and opts.staged is None:
            raise MaintenanceError("STAGING_MISSING")
        _wait_closed(opts.wait_pid)
        if opts.command == "uninstall":
            uninstall(opts.install)
        else:
            apply_update(opts.install, opts.staged)
        return 0
    except Exception as error:
        # This is an independent, data-preserving diagnostic breadcrumb.
        root = _user_data_root()
        try:
            root.mkdir(parents=True, exist_ok=True)
            with (root / "maintenance-errors.log").open("a", encoding="utf-8") as log:
                log.write(datetime.now().isoformat() + "  " +
                          type(error).__name__ + "  " +
                          (str(error)[:160]) + "\n")
        except OSError:
            pass
        return 2


if __name__ == "__main__":
    sys.exit(main())
