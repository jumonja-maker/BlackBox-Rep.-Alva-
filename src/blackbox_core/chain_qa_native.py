"""Frozen-safe reader for the existing Wave02 native QA fixture protocol.

The source harness compiles the unchanged fixture on hosted Windows. This module
only owns that supplied executable and independently queries Windows tokens.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import queue
import subprocess
import threading
import time

from .chain_qa import require, require_hosted_windows, save


# These capabilities belong to this independent QA query, never to the product
# helper. An unsuccessful CloseHandle must not be reported as successful cleanup
# or lose its exact handle when the acceptance harness catches an exception.
_TOKEN_HANDLES_LOCK = threading.RLock()
_PENDING_TOKEN_HANDLES = []


def _close_token_handles(kernel, handles, primary):
    failed = []
    for label, handle in handles:
        if not handle:
            continue
        try:
            if not kernel.CloseHandle(handle):
                failed.append((label, handle, C.get_last_error()))
        except BaseException as error:
            failed.append((label, handle, type(error).__name__))
    if failed:
        with _TOKEN_HANDLES_LOCK:
            _PENDING_TOKEN_HANDLES.append((kernel, failed))
        cleanup = OSError("R60_INDEPENDENT_TOKEN_QUERY_CLOSE_UNCONFIRMED: " +
                          ",".join(label for label, _handle, _error in failed))
        cleanup.cleanup_required = True
        if primary is not None:
            primary.add_note(str(cleanup))
        else:
            raise cleanup


class OwnedWaveProbe:
    """The independent oracle is separate from the product/helper under test."""
    def __init__(self, executable: Path, output: Path):
        require_hosted_windows()
        from blackbox_core.optional_jobs import OwnedProcess
        self.output = output.resolve()
        self.output.mkdir(parents=True, exist_ok=False)
        self.dump = self.output / "private-crash.dmp"
        self.stderr = (self.output / "fixture-stderr.log").open("wb")
        self.records: list[dict] = []
        self.pending: list[dict] = []
        self.lines: queue.Queue = queue.Queue(maxsize=256)
        self.owner = self.reader = None
        self.expected_crash = False
        try:
            self.owner = OwnedProcess([str(executable.resolve(strict=True)),
                str(self.output), str(self.dump)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=self.stderr, detach_console=True)
            self.process = self.owner.process
            self.reader = threading.Thread(target=self._read, name="wave02-oracle", daemon=True)
            self.reader.start()
            self.ready = self.receive("ready", timeout=20)
            require(self.ready["pid"] == self.process.pid and self.ready["created_100ns"] > 0
                    and self.ready["qpc_frequency"] > 0 and self.ready["hwnd"] > 0
                    and self.ready["ui_tid"] != self.ready["control_tid"],
                    "WAVE02_NATIVE_IDENTITY_OR_UI_ORACLE_INVALID")
            save(self.output / "ready.json", self.ready)
        except BaseException:
            self.close(kill=True)
            raise

    def _read(self):
        try:
            while True:
                line = self.process.stdout.readline(16385)
                if not line:
                    self.lines.put_nowait(EOFError("WAVE02_ORACLE_CLOSED"))
                    return
                require(len(line) <= 16384 and line.endswith(b"\n"), "WAVE02_ORACLE_LINE_BUDGET")
                item = json.loads(line)
                require(type(item) is dict and type(item.get("event")) is str,
                        "WAVE02_ORACLE_RECORD_INVALID")
                self.lines.put_nowait(item)
        except BaseException as error:
            try:
                self.lines.put_nowait(error)
            except queue.Full:
                pass

    def send(self, command):
        require(command in {"state", "freeze", "release", "file", "burst", "crash", "stop"},
                "WAVE02_CONTROL_COMMAND_NOT_ALLOWED")
        require(self.owner is not None and self.process.poll() is None,
                "WAVE02_TARGET_EXITED_BEFORE_COMMAND")
        if command == "crash":
            self.expected_crash = True
        self.process.stdin.write((command + "\n").encode("ascii"))
        self.process.stdin.flush()

    def receive(self, event, *, timeout=20):
        for index, record in enumerate(self.pending):
            if record["event"] == event:
                return self.pending.pop(index)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "WAVE02_ORACLE_TIMEOUT_" + event)
            try:
                item = self.lines.get(timeout=remaining)
            except queue.Empty as error:
                raise TimeoutError("WAVE02_ORACLE_TIMEOUT_" + event) from error
            if isinstance(item, BaseException):
                raise item
            self.records.append(item)
            require(len(self.records) <= 4096, "WAVE02_ORACLE_RECORD_BUDGET")
            if item["event"] == event:
                return item
            self.pending.append(item)

    def command(self, command, event=None, *, timeout=20):
        self.send(command)
        return self.receive(event or command, timeout=timeout)

    def close(self, *, kill=False):
        result = {"status": "NOT_STARTED"}
        try:
            if self.owner is not None:
                if self.process.poll() is None and not kill:
                    self.send("stop")
                    stopped = self.receive("normal_exit", timeout=20)
                    self.process.wait(timeout=10)
                    require(stopped.get("cleanup_complete") is True and self.process.returncode == 0,
                            "WAVE02_FIXTURE_NORMAL_CLEANUP_NOT_CONFIRMED")
                    result = {"status": "COMPLETED", "exit_code": 0, "oracle": stopped}
                elif self.expected_crash and not kill:
                    require((self.process.returncode & 0xFFFFFFFF) == 0xC0000005,
                            "WAVE02_EXPECTED_ACCESS_VIOLATION_EXIT_NOT_OBSERVED")
                    result = {"status": "OWNED_CRASH_EXIT_VERIFIED", "exit_code": self.process.returncode}
                else:
                    require(kill, "WAVE02_UNEXPECTED_TARGET_EXIT")
                    result = {"status": "FORCED_QA_CLEANUP", "exit_code": self.process.poll()}
        finally:
            if self.owner is not None:
                self.owner.close(kill=True)
                for stream in (self.process.stdin, self.process.stdout):
                    if stream is not None:
                        stream.close()
                if self.reader is not None:
                    self.reader.join(timeout=2)
                    require(not self.reader.is_alive(), "WAVE02_ORACLE_READER_NOT_CLOSED")
                self.owner = None
            self.stderr.close()
            save(self.output / "oracle-records.json", self.records)
        return result


def actual_token(pid):
    """Separate OpenProcessToken query of the real helper process."""
    require_hosted_windows()
    with _TOKEN_HANDLES_LOCK:
        require(not _PENDING_TOKEN_HANDLES, "R60_PRIOR_INDEPENDENT_TOKEN_QUERY_CLEANUP_UNCONFIRMED")
    kernel = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    advapi = C.WinDLL("advapi32", use_last_error=True, winmode=0x800)
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    kernel.OpenProcess.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    kernel.CloseHandle.restype = W.BOOL
    advapi.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
    advapi.OpenProcessToken.restype = W.BOOL
    advapi.GetTokenInformation.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)]
    advapi.GetTokenInformation.restype = W.BOOL
    process, token = kernel.OpenProcess(0x1000, False, pid), W.HANDLE()
    require(bool(process), "R60_HELPER_PROCESS_QUERY_HANDLE")
    primary = None
    try:
        require(advapi.OpenProcessToken(process, 8, C.byref(token)), "R60_HELPER_TOKEN_QUERY")
        elevated, elevation_type, needed = W.DWORD(), W.DWORD(), W.DWORD()
        require(advapi.GetTokenInformation(token, 20, C.byref(elevated), C.sizeof(elevated), C.byref(needed)),
                "R60_HELPER_TOKEN_ELEVATION_QUERY")
        require(advapi.GetTokenInformation(token, 18, C.byref(elevation_type), C.sizeof(elevation_type), C.byref(needed)),
                "R60_HELPER_TOKEN_TYPE_QUERY")
        return {"pid": pid, "elevated": elevated.value != 0, "elevation_type": elevation_type.value,
                "source": "INDEPENDENT_OPEN_PROCESS_TOKEN_GET_TOKEN_INFORMATION"}
    except BaseException as error:
        primary = error
        raise
    finally:
        _close_token_handles(kernel, (("token", token), ("process", process)), primary)
