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
from .shortcuts import SHORTCUT_TITLE, _desktop, remove_shortcut_if_matches

SAVED_DIRS = ("logs", "sessions", "reports")
MARKER = {"product": "blackbox-universal", "install_type": "portable"}
HELPER_TICKET = ".blackbox-maintenance-helper.json"
HELPER_TICKET_VALUE = {"product": "blackbox-universal", "role": "external-maintenance"}
HELPER_CLEANER = ".blackbox-maintenance-cleanup.vbs"

# This script does not accept a command or an arbitrary list of paths.
# It deletes only our known temporary helper files and an empty folder.
# Its external host can finish after the PyInstaller maintenance EXE exits.
_CLEAN_HELPER_VBS = r'''
Option Explicit
Dim fso, folder, helper, marker, script, attempt
If WScript.Arguments.Count <> 1 Then WScript.Quit 3
Set fso = CreateObject("Scripting.FileSystemObject")
folder = WScript.Arguments(0)
helper = fso.BuildPath(folder, "BLACK.BOX-Maintenance.exe")
marker = fso.BuildPath(folder, ".blackbox-maintenance-helper.json")
script = WScript.ScriptFullName
For attempt = 1 To 180
    On Error Resume Next
    If fso.FileExists(helper) Then fso.DeleteFile helper, True
    If Not fso.FileExists(helper) Then
        If fso.FileExists(marker) Then fso.DeleteFile marker, True
        If fso.FileExists(script) Then fso.DeleteFile script, True
        If fso.FolderExists(folder) Then fso.DeleteFolder folder, False
        If Not fso.FolderExists(folder) Then WScript.Quit 0
    End If
    Err.Clear
    On Error GoTo 0
    WScript.Sleep 500
Next
WScript.Quit 2
'''



class MaintenanceError(RuntimeError):
    pass


def _is_directory_link(path: Path) -> bool:
    """Recognize symlinks/junctions; fail closed on inaccessible paths.

    A missing path is not a link. Permission and filesystem errors are NOT
    evidence that a path is safe to delete or move.
    """
    import stat
    try:
        item = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise MaintenanceError("PATH_INSPECTION_FAILED") from None
    return (stat.S_ISLNK(item.st_mode) or
            bool(getattr(item, "st_file_attributes", 0) &
                 getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))


def _has_reparse_ancestor(path: Path) -> bool:
    """Check the complete path, not just its final directory component.

    A plain marked installation inside a junction is still outside the
    authorized filesystem tree. Do not follow it for update or deletion.
    """
    return any(_is_directory_link(parent) for parent in
               (path, *path.parents))


def _safe_install(path: Path) -> Path:
    """Only a specific, marked portable folder can be affected."""
    candidate = Path(os.path.abspath(path))
    if _has_reparse_ancestor(candidate) or not candidate.is_dir():
        raise MaintenanceError("INSTALL_FOLDER_INVALID")
    if candidate.parent == candidate or candidate.parent.parent == candidate.parent:
        raise MaintenanceError("SYSTEM_ROOT_REFUSED")
    if any(part.casefold() in ("windows", "program files",
                              "program files (x86)") for part in candidate.parts):
        raise MaintenanceError("SYSTEM_INSTALL_REFUSED")
    for name in (INSTALL_MARKER, EXECUTABLE_NAME, MAINTENANCE_NAME):
        item = candidate / name
        if _is_directory_link(item) or not item.is_file():
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
            if not source.exists() and not _is_directory_link(source):
                continue
            if _is_directory_link(source) or not source.is_dir():
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


def _detach_matching_desktop_shortcut(executable: Path) -> tuple[Path, bytes] | None:
    """Remove the *matching* link while its target still exists.

    Windows Shell Link resolution may lose the original target as soon as
    the EXE is deleted. Keep original shortcut bytes to restore on a failed
    directory removal, but never overwrite a new/foreign link on rollback.
    """
    if os.name != "nt":
        return None
    link = _desktop() / SHORTCUT_TITLE
    if _is_directory_link(link):
        raise MaintenanceError("SHORTCUT_LINK_REFUSED")
    try:
        original = link.read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        raise MaintenanceError("SHORTCUT_READ_FAILED") from None
    if len(original) > 1024 * 1024:
        raise MaintenanceError("SHORTCUT_TOO_LARGE")
    try:
        remove_shortcut_if_matches(executable)
    except (OSError, subprocess.SubprocessError):
        raise MaintenanceError("SHORTCUT_REMOVE_FAILED") from None
    if _is_directory_link(link):
        raise MaintenanceError("SHORTCUT_LINK_CHANGED")
    # A link for an unrelated program is never removed.
    return None if link.exists() else (link, original)


def _restore_desktop_shortcut(snapshot: tuple[Path, bytes] | None) -> None:
    if snapshot is None:
        return
    link, content = snapshot
    try:
        with link.open("xb") as output:
            output.write(content)
    except FileExistsError:
        pass  # Someone else created a shortcut; do not overwrite it.


def _remove_owned_qsettings() -> None:
    """Remove only BLACK.BOX Universal's own HKCU QSettings subtree."""
    if os.name != "nt":
        return
    import winreg
    root = winreg.HKEY_CURRENT_USER
    app_key = r"Software\BlackBox\BLACK.BOX Universal"

    def remove_subtree(path: str) -> None:
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                children = []
                index = 0
                while True:
                    try:
                        children.append(winreg.EnumKey(key, index))
                    except OSError as error:
                        if getattr(error, "winerror", None) != 259:  # ERROR_NO_MORE_ITEMS
                            raise
                        break
                    index += 1
        except FileNotFoundError:
            return
        for child in children:
            remove_subtree(path + "\\" + child)
        winreg.DeleteKey(root, path)

    try:
        remove_subtree(app_key)
    except OSError:
        raise MaintenanceError("QSETTINGS_REMOVE_FAILED") from None


def uninstall(install: Path) -> None:
    install = _safe_install(install)
    data = _user_data_root()
    if data == install or install in data.parents or data in install.parents:
        raise MaintenanceError("DATA_LOCATION_INSIDE_INSTALL")
    preserved = data / ("Preserved-" + datetime.now().strftime("%Y%m%d-%H%M%S")
                        + "-" + uuid4().hex[:6])
    moves = _keep_local_logs(install, preserved)
    shortcut_snapshot = None
    try:
        # The original EXE must still exist when Windows resolves its .lnk.
        shortcut_snapshot = _detach_matching_desktop_shortcut(
            install / EXECUTABLE_NAME)
        shutil.rmtree(install)
    except Exception:
        try:
            _restore_desktop_shortcut(shortcut_snapshot)
        finally:
            for moved, previous in reversed(moves):
                if previous.parent.exists() and moved.exists():
                    moved.replace(previous)
        raise
    # No program files remain. Remove only this application's Qt preferences;
    # the user's diagnostic sessions and their own files remain untouched.
    _remove_owned_qsettings()


def apply_update(install: Path, staged: Path) -> None:
    install = _safe_install(install)
    staged = Path(os.path.abspath(staged))
    if _has_reparse_ancestor(staged) or staged.parent.parent != install.parent:
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
            if not previous.exists() and not _is_directory_link(previous):
                continue
            if _is_directory_link(previous) or not previous.is_dir():
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


def prepare_external_helper(install: Path) -> Path:
    """Create a marker-scoped temporary frozen maintenance copy.

    The source install remains untouched. A failed preparation removes its
    own new temp folder. Never use a pre-existing temp directory.
    """
    install = _safe_install(install)
    scratch = Path(tempfile.mkdtemp(prefix="bb-maintenance-"))
    try:
        helper = scratch / MAINTENANCE_NAME
        shutil.copy2(install / MAINTENANCE_NAME, helper)
        (scratch / HELPER_TICKET).write_text(
            json.dumps(HELPER_TICKET_VALUE), encoding="utf-8")
        return helper
    except Exception:
        shutil.rmtree(scratch, ignore_errors=True)
        raise


def _schedule_external_helper_cleanup() -> None:
    """Schedule cleanup after our *own* frozen copy exits, never another EXE."""
    if os.name != "nt" or not getattr(sys, "frozen", False):
        return
    helper = Path(os.path.abspath(sys.executable))
    scratch = helper.parent
    if (helper.name != MAINTENANCE_NAME
            or not scratch.name.startswith("bb-maintenance-")
            or scratch.parent != Path(tempfile.gettempdir())):
        return
    if _has_reparse_ancestor(scratch):
        raise MaintenanceError("TEMP_HELPER_PATH_REFUSED")
    ticket = scratch / HELPER_TICKET
    if _is_directory_link(ticket) or not ticket.is_file():
        raise MaintenanceError("TEMP_HELPER_MARKER_MISSING")
    try:
        observed = json.loads(ticket.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise MaintenanceError("TEMP_HELPER_MARKER_INVALID") from None
    if observed != HELPER_TICKET_VALUE:
        raise MaintenanceError("TEMP_HELPER_MARKER_INVALID")
    cleaner = scratch / HELPER_CLEANER
    # Exclusive create: never overwrite a foreign file inside our folder.
    with cleaner.open("x", encoding="utf-16") as output:
        output.write(_CLEAN_HELPER_VBS)
    try:
        subprocess.Popen(
            ["cscript.exe", "//B", "//NoLogo", str(cleaner), str(scratch)],
            cwd=str(scratch.parent), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception:
        cleaner.unlink(missing_ok=True)
        raise MaintenanceError("TEMP_HELPER_CLEANUP_NOT_SCHEDULED") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("uninstall", "update"))
    parser.add_argument("--install", type=Path, required=True)
    parser.add_argument("--wait-pid", type=int, required=True)
    parser.add_argument("--staged", type=Path)
    opts = parser.parse_args(argv)
    def log_problem(error: Exception) -> None:
        # Independent breadcrumb, without changing user evidence.
        root = _user_data_root()
        try:
            root.mkdir(parents=True, exist_ok=True)
            with (root / "maintenance-errors.log").open("a", encoding="utf-8") as log:
                log.write(datetime.now().isoformat() + "  " +
                          type(error).__name__ + "  " +
                          (str(error)[:160]) + "\n")
        except OSError:
            pass

    status = 0
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
    except Exception as error:
        log_problem(error)
        status = 2
    # Even a failed maintenance attempt must not leave the transient helper.
    try:
        _schedule_external_helper_cleanup()
    except Exception as error:
        log_problem(error)
        status = 2
    return status


if __name__ == "__main__":
    sys.exit(main())
