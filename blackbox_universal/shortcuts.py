"""Create/remove a genuine Windows desktop .lnk, never install a service.

Uses the existing Windows Script Host COM bridge with positional arguments,
not PowerShell or shell command composition. A shortcut is removed only if its
target still matches this portable application's absolute executable path.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import subprocess
import tempfile

SHORTCUT_TITLE = "BLACK.BOX Universal.lnk"
_SCRIPT = r'''
Option Explicit
Dim sh, fso, args, mode, shortcut, target
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
Set args = WScript.Arguments
mode = args(0)
If mode = "create" Then
    Set shortcut = sh.CreateShortcut(args(1))
    shortcut.TargetPath = args(2)
    shortcut.WorkingDirectory = args(3)
    shortcut.IconLocation = args(2) & ",0"
    shortcut.Description = "BLACK.BOX Universal - local diagnostics"
    shortcut.Save
ElseIf mode = "remove" Then
    If fso.FileExists(args(1)) Then
        Set shortcut = sh.CreateShortcut(args(1))
        target = shortcut.TargetPath
        If LCase(fso.GetAbsolutePathName(target)) = _
           LCase(fso.GetAbsolutePathName(args(2))) Then
            fso.DeleteFile args(1), True
        End If
    End If
Else
    WScript.Quit 2
End If
'''


def _desktop() -> Path:
    if os.name != "nt":
        raise OSError("Desktop shortcut is Windows-only.")
    from ctypes import wintypes
    shell = ctypes.windll.shell32
    buf = ctypes.create_unicode_buffer(32768)
    # CSIDL_DESKTOPDIRECTORY: supports redirected OneDrive desktop paths.
    if shell.SHGetFolderPathW(None, 0x0010, None, 0, buf) != 0:
        raise OSError("Windows desktop location unavailable.")
    return Path(buf.value)


def _run(*args: str) -> None:
    with tempfile.TemporaryDirectory(prefix="bb-shortcut-") as temp:
        path = Path(temp) / "shortcut.vbs"
        path.write_text(_SCRIPT, encoding="utf-16")
        subprocess.run(["cscript.exe", "//NoLogo", str(path), *args],
                       timeout=15, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True)


def create_shortcut(executable: Path) -> Path:
    exe = Path(executable).resolve(strict=True)
    if exe.name != "BLACK.BOX-Universal.exe":
        raise ValueError("Not a BLACK.BOX Universal portable executable.")
    shortcut = _desktop() / SHORTCUT_TITLE
    _run("create", str(shortcut), str(exe), str(exe.parent))
    return shortcut


def remove_shortcut_if_matches(executable: Path) -> None:
    if os.name != "nt":
        return
    shortcut = _desktop() / SHORTCUT_TITLE
    _run("remove", str(shortcut), str(Path(os.path.abspath(executable))))
