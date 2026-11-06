"""Explicit standard ShellExecuteExW/runa​s broker for the diagnostic helper."""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
import os
from pathlib import Path
import subprocess
import sys
import threading


class ElevationCancelled(OSError):
    pass


class HelperProcess:
    def __init__(self, *, process=None, handle=None, pid=None):
        self.process, self.handle = process, handle
        self.pid = process.pid if process is not None else pid
        self._process_handle = getattr(process, "_handle", None) if process is not None else None
        self._close_lock = threading.RLock()
        self._handle_closed = False
        self._close_retry_allowed = True
        self.cleanup_evidence = {"confirmed": False, "status": "NOT_CLOSED",
                                 "scope": "DIAGNOSTIC_HELPER_PROCESS_HANDLE"}

    def _handle_failure(self, code, reason):
        if code == 6:
            # Do not retry a numeric slot that may already have been reused.
            self._close_retry_allowed = False
        self.cleanup_evidence = {"confirmed": False, "status": "RECOVERY_UNCONFIRMED",
            "scope": "DIAGNOSTIC_HELPER_PROCESS_HANDLE", "winerror": code, "reason": reason,
            "owner_retained": True, "retry_allowed": self._close_retry_allowed}
        error = OSError(code or 0, reason)
        error.cleanup_unconfirmed = error.owner_retained = True
        error.owner = self
        return error

    def alive(self) -> bool:
        if not self._close_retry_allowed:
            raise self._handle_failure(self.cleanup_evidence.get("winerror"), "HELPER_HANDLE_OWNERSHIP_LOST")
        if self.process is not None:
            return self.process.poll() is None
        return not self.wait_for_exit(timeout_ms=0)

    def wait_for_exit(self, *, timeout_ms: int = 0) -> bool:
        """Observe this held process handle; failed waits are never death proof."""
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 5000:
            raise ValueError("INVALID_HELPER_EXIT_WAIT")
        if not self._close_retry_allowed:
            raise self._handle_failure(self.cleanup_evidence.get("winerror"), "HELPER_HANDLE_OWNERSHIP_LOST")
        if self.process is not None:
            try:
                self.process.wait(timeout=timeout_ms / 1000)
                return True
            except subprocess.TimeoutExpired:
                return False
        if self.handle is None:
            return True
        kernel = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
        kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
        kernel.WaitForSingleObject.restype = W.DWORD
        observed = kernel.WaitForSingleObject(self.handle, timeout_ms)
        if observed == 0:  # WAIT_OBJECT_0: this exact process exited.
            return True
        if observed == 258:  # WAIT_TIMEOUT: still running.
            return False
        error = C.get_last_error() if observed == 0xFFFFFFFF else 0
        raise OSError(error, "HELPER_PROCESS_WAIT_UNCONFIRMED")

    def terminate(self) -> None:
        # Kill only this helper, not the unrelated target or a recovery guardian.
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
            return
        if self.handle is not None and self.alive():
            kernel = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
            kernel.TerminateProcess.argtypes = [W.HANDLE, W.UINT]
            kernel.TerminateProcess.restype = W.BOOL
            kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
            kernel.WaitForSingleObject.restype = W.DWORD
            if not kernel.TerminateProcess(self.handle, 1):
                error = C.get_last_error()
                # The helper can exit naturally after its cleanup ACK, between
                # alive() and TerminateProcess. Only this exact held handle's
                # signaled state can turn that denial into verified completion.
                if self.wait_for_exit(timeout_ms=0):
                    return
                raise OSError(error, "HELPER_TERMINATION_UNCONFIRMED")
            if not self.wait_for_exit(timeout_ms=5000):
                raise OSError("HELPER_TERMINATION_UNCONFIRMED")

    def close_handle(self) -> dict:
        """Consume this exact process capability only after its real close ACK.

        Popen owns a subprocess.Handle wrapper on Windows. Closing its numeric
        value behind that wrapper leaves a later destructor free to close a
        reused foreign slot, so use the wrapper's own checked Close operation.
        """
        with self._close_lock:
            if self._handle_closed:
                return dict(self.cleanup_evidence)
            if not self._close_retry_allowed:
                raise self._handle_failure(self.cleanup_evidence.get("winerror"), "HELPER_HANDLE_OWNERSHIP_LOST")
            if self.process is not None:
                handle = self._process_handle
                if handle is None or getattr(self.process, "_handle", None) is not handle:
                    raise self._handle_failure(None, "HELPER_POPEN_HANDLE_OWNERSHIP_NOT_VERIFIED")
                if getattr(handle, "closed", None) is not False or not callable(getattr(handle, "Close", None)):
                    self._close_retry_allowed = False
                    raise self._handle_failure(None, "HELPER_POPEN_HANDLE_ALREADY_CLOSED_OR_UNVERIFIED")
                # Popen must retain the observed return code before its native
                # handle closes; its own destructor/poll must not query a stale
                # process handle after successful cleanup.
                if self.process.returncode is None and self.process.poll() is None:
                    raise self._handle_failure(None, "HELPER_EXIT_NOT_OBSERVED_BEFORE_HANDLE_CLOSE")
                try:
                    handle.Close()  # _winapi.CloseHandle raises on native FALSE.
                except BaseException as primary:
                    code = getattr(primary, "winerror", None)
                    if code is None:
                        code = getattr(primary, "errno", None)
                    # CPython marks Handle.closed before the native call. A
                    # known failed close keeps the same capability retryable.
                    # ERROR_INVALID_HANDLE must stay closed to avoid GC reuse.
                    if code is not None and code != 6:
                        handle.closed = False
                    else:
                        self._close_retry_allowed = False
                    raise self._handle_failure(code, "HELPER_POPEN_HANDLE_CLOSE_UNCONFIRMED") from primary
                if getattr(handle, "closed", None) is not True:
                    self._close_retry_allowed = False
                    raise self._handle_failure(None, "HELPER_POPEN_HANDLE_CLOSE_ACK_MISSING")
            elif self.handle is not None:
                try:
                    kernel = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
                    kernel.CloseHandle.argtypes = [W.HANDLE]
                    kernel.CloseHandle.restype = W.BOOL
                    closed = bool(kernel.CloseHandle(self.handle))
                except BaseException as primary:
                    code = getattr(primary, "winerror", None)
                    if code is None:
                        code = getattr(primary, "errno", None)
                    raise self._handle_failure(code, "HELPER_PROCESS_HANDLE_CLOSE_UNCONFIRMED") from primary
                if not closed:
                    raise self._handle_failure(C.get_last_error(), "HELPER_PROCESS_HANDLE_CLOSE_UNCONFIRMED")
                self.handle = None
            self._handle_closed = True
            self.cleanup_evidence = {"confirmed": True, "status": "CONFIRMED",
                "scope": "DIAGNOSTIC_HELPER_PROCESS_HANDLE", "retained": 0}
            return dict(self.cleanup_evidence)


class ElevationBroker:
    def __init__(self, helper_executable: str | Path | None = None):
        self.helper_executable = Path(helper_executable).resolve() if helper_executable else None

    def command(self, arguments: list[str]) -> list[str]:
        if self.helper_executable is not None:
            if not self.helper_executable.is_file():
                raise FileNotFoundError("DIAGNOSTIC_HELPER_NOT_FOUND")
            return [str(self.helper_executable), *arguments]
        if getattr(sys, "frozen", False):
            root = Path(sys.executable).resolve().parent
            helper = root / "diagnostic" / "BLACK.BOX-Diagnostic.exe"
            if not helper.is_file():
                helper = root / "BLACK.BOX-Diagnostic.exe"
            if not helper.is_file():
                raise FileNotFoundError("DIAGNOSTIC_HELPER_NOT_PACKAGED")
            return [str(helper), *arguments]
        root = Path(__file__).resolve().parents[2]
        entry = root / "diagnostic_entry.py"
        if not entry.is_file():
            raise FileNotFoundError("DIAGNOSTIC_ENTRY_NOT_FOUND")
        executable = Path(sys.executable).resolve()
        windowed = executable.with_name("pythonw.exe")
        if os.name == "nt" and windowed.is_file():
            executable = windowed
        return [str(executable), str(entry), *arguments]

    def launch(self, arguments: list[str], *, elevated: bool = False) -> HelperProcess:
        if os.name != "nt":
            raise OSError("UNSUPPORTED_PLATFORM")
        command = self.command(arguments)
        if not elevated:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, close_fds=True,
                                       creationflags=0x8, cwd=str(Path(command[0]).parent))
            return HelperProcess(process=process)
        shell = C.WinDLL("shell32", use_last_error=True, winmode=0x800)
        kernel = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
        class ShellExecuteInfo(C.Structure):
            _fields_ = [("cbSize", W.DWORD), ("fMask", W.ULONG), ("hwnd", W.HWND),
                        ("lpVerb", W.LPCWSTR), ("lpFile", W.LPCWSTR), ("lpParameters", W.LPCWSTR),
                        ("lpDirectory", W.LPCWSTR), ("nShow", C.c_int), ("hInstApp", W.HINSTANCE),
                        ("lpIDList", C.c_void_p), ("lpClass", W.LPCWSTR), ("hkeyClass", W.HKEY),
                        ("dwHotKey", W.DWORD), ("hIcon", W.HANDLE), ("hProcess", W.HANDLE)]
        shell.ShellExecuteExW.argtypes = [C.POINTER(ShellExecuteInfo)]
        shell.ShellExecuteExW.restype = W.BOOL
        kernel.GetProcessId.argtypes = [W.HANDLE]
        kernel.GetProcessId.restype = W.DWORD
        info = ShellExecuteInfo()
        info.cbSize = C.sizeof(info)
        info.fMask = 0x40 | 0x100 | 0x400  # NOCLOSEPROCESS, NOASYNC, FLAG_NO_UI.
        info.lpVerb = "runas"
        info.lpFile = command[0]
        info.lpParameters = subprocess.list2cmdline(command[1:])
        info.lpDirectory = str(Path(command[0]).parent)
        info.nShow = 0
        if not shell.ShellExecuteExW(C.byref(info)):
            error = C.get_last_error()
            if error == 1223:
                raise ElevationCancelled(error, "UAC_CANCELLED")
            raise OSError(error, "UAC_LAUNCH_FAILED")
        if not info.hProcess:
            raise OSError("UAC_HELPER_PROCESS_HANDLE_MISSING")
        pid = kernel.GetProcessId(info.hProcess)
        if not pid:
            process = HelperProcess(handle=info.hProcess, pid=0)
            process.close_handle()
            raise OSError(C.get_last_error(), "UAC_HELPER_PID_MISSING")
        return HelperProcess(handle=info.hProcess, pid=pid)
