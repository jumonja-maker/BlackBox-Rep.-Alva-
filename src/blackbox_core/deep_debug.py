"""Bounded, explicitly requested Windows x64 diagnostic interventions.

The debug object belongs to one worker thread. Original memory remains in this
process/its same-token recovery guardian, never in ordinary action-journal data.
This is a debugger, not a guarantee of reversible application execution.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import queue
import struct
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .deep_contracts import ProcessIdentity


MAX_WRITE = 4096
MAX_PRIVATE_BYTES = 65536
MAX_BREAKPOINTS = 32
MAX_SUSPENSIONS = 128
CONTEXT_FLAGS = 0x10001F
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
_ALIASES = {
    "debug_attach": "debug.attach", "debug_detach": "debug.detach",
    "debug_pause": "debug.pause", "debug_continue": "debug.continue",
    "debug_step": "debug.step", "debug_context": "debug.context",
    "breakpoint_add": "debug.breakpoint.add",
    "breakpoint_disable": "debug.breakpoint.disable",
    "breakpoint_remove": "debug.breakpoint.remove",
    "thread_suspend": "thread.suspend", "thread_resume": "thread.resume",
    "memory_write": "memory.write", "memory_restore": "memory.rollback",
}


class DebugError(Exception):
    def __init__(self, status: str, detail: str, winerror: int | None = None):
        super().__init__(detail)
        self.status, self.winerror = status, winerror


def _positive(value: Any, name: str, maximum: int = (1 << 64) - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
        raise DebugError("OPERATION_FAILED", f"INVALID_{name.upper()}")
    return value


def _hex(value: Any, name: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > MAX_WRITE * 2 or len(value) % 2:
        raise DebugError("OPERATION_FAILED", f"INVALID_{name.upper()}")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise DebugError("OPERATION_FAILED", f"INVALID_{name.upper()}") from exc
    if len(result) * 2 != len(value):
        raise DebugError("OPERATION_FAILED", f"INVALID_{name.upper()}")
    return result


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_native_amd64(process_machine: int, native_machine: int) -> None:
    if process_machine != 0 or native_machine != 0x8664:
        raise DebugError("INCOMPLETE_EVIDENCE", "NATIVE_AMD64_DEBUG_CONTEXT_REQUIRED")


def _result(status: str = "COMPLETED", **values: Any) -> dict[str, Any]:
    return {"status": status, "data": {}, "limitations": [], **values}


class _Context:
    """AMD64 CONTEXT requires a 16-byte aligned address, including under ctypes."""
    def __init__(self) -> None:
        self._allocation = ctypes.create_string_buffer(1232 + 15)
        self.address = (ctypes.addressof(self._allocation) + 15) & ~15
        self.pointer = ctypes.c_void_p(self.address)
        self.set32(48, CONTEXT_FLAGS)

    def get32(self, offset: int) -> int:
        return ctypes.c_uint32.from_address(self.address + offset).value

    def set32(self, offset: int, value: int) -> None:
        ctypes.c_uint32.from_address(self.address + offset).value = value

    def get64(self, offset: int) -> int:
        return ctypes.c_uint64.from_address(self.address + offset).value

    def set64(self, offset: int, value: int) -> None:
        ctypes.c_uint64.from_address(self.address + offset).value = value

    def public(self) -> dict[str, int]:
        names = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip")
        result = {name: self.get64(120 + index * 8) for index, name in enumerate(names)}
        result["eflags"] = self.get32(68)
        return result


class _DebugEvent(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint32), ("pid", ctypes.c_uint32),
                ("tid", ctypes.c_uint32), ("_padding", ctypes.c_uint32),
                ("information", ctypes.c_ubyte * 160)]

    def raw(self) -> bytes:
        return bytes(self.information)


class _WinAPI:
    def __init__(self, identity: ProcessIdentity):
        if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise DebugError("INCOMPLETE_EVIDENCE", "WINDOWS_X64_REQUIRED")
        from ctypes import wintypes as w
        self.k = ctypes.WinDLL("kernel32", use_last_error=True, winmode=0x800)
        self.identity = identity
        self.handle = None
        self.debug_handle = None
        self._access = 0x100000 | 0x1000
        prototypes = {
            "OpenProcess": (w.HANDLE, [w.DWORD, w.BOOL, w.DWORD]),
            "OpenThread": (w.HANDLE, [w.DWORD, w.BOOL, w.DWORD]),
            "CloseHandle": (w.BOOL, [w.HANDLE]),
            "GetCurrentProcess": (w.HANDLE, []),
            "DuplicateHandle": (w.BOOL, [w.HANDLE, w.HANDLE, w.HANDLE,
                                          ctypes.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD]),
            "GetProcessTimes": (w.BOOL, [w.HANDLE] + [ctypes.POINTER(w.FILETIME)] * 4),
            "GetThreadTimes": (w.BOOL, [w.HANDLE] + [ctypes.POINTER(w.FILETIME)] * 4),
            "GetProcessIdOfThread": (w.DWORD, [w.HANDLE]),
            "QueryFullProcessImageNameW": (w.BOOL, [w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD)]),
            "IsWow64Process": (w.BOOL, [w.HANDLE, ctypes.POINTER(w.BOOL)]),
            "WaitForSingleObject": (w.DWORD, [w.HANDLE, w.DWORD]),
            "ReadProcessMemory": (w.BOOL, [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                           ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]),
            "WriteProcessMemory": (w.BOOL, [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]),
            "VirtualProtectEx": (w.BOOL, [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                          w.DWORD, ctypes.POINTER(w.DWORD)]),
            "VirtualQueryEx": (ctypes.c_size_t, [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]),
            "FlushInstructionCache": (w.BOOL, [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t]),
            "SuspendThread": (w.DWORD, [w.HANDLE]), "ResumeThread": (w.DWORD, [w.HANDLE]),
            "GetThreadContext": (w.BOOL, [w.HANDLE, ctypes.c_void_p]),
            "SetThreadContext": (w.BOOL, [w.HANDLE, ctypes.c_void_p]),
            "DebugActiveProcess": (w.BOOL, [w.DWORD]),
            "DebugActiveProcessStop": (w.BOOL, [w.DWORD]),
            "DebugSetProcessKillOnExit": (w.BOOL, [w.BOOL]),
            "DebugBreakProcess": (w.BOOL, [w.HANDLE]),
            "CheckRemoteDebuggerPresent": (w.BOOL, [w.HANDLE, ctypes.POINTER(w.BOOL)]),
            "WaitForDebugEvent": (w.BOOL, [ctypes.POINTER(_DebugEvent), w.DWORD]),
            "ContinueDebugEvent": (w.BOOL, [w.DWORD, w.DWORD, w.DWORD]),
        }
        for name, (restype, argtypes) in prototypes.items():
            function = getattr(self.k, name)
            function.restype, function.argtypes = restype, argtypes
        # Query-only initially. Memory and debug rights are acquired only by the
        # operation needing them; a thread-only operation must not demand VM_WRITE.
        self.handle = self.k.OpenProcess(self._access, False, identity.pid)
        if not self.handle:
            self.fail("OPEN_PROCESS")
        try:
            self.verify()
            architecture = getattr(self.k, "IsWow64Process2", None)
            if architecture is None:
                raise DebugError("INCOMPLETE_EVIDENCE", "EXACT_DEBUG_CONTEXT_ARCHITECTURE_UNAVAILABLE")
            architecture.argtypes = [w.HANDLE, ctypes.POINTER(w.WORD), ctypes.POINTER(w.WORD)]
            architecture.restype = w.BOOL
            machine, native_machine = w.WORD(), w.WORD()
            if not architecture(self.handle, ctypes.byref(machine), ctypes.byref(native_machine)):
                self.fail("IS_WOW64_PROCESS2")
            _require_native_amd64(machine.value, native_machine.value)
        except BaseException:
            self.close()
            raise

    def fail(self, label: str) -> None:
        code = ctypes.get_last_error()
        status = "ACCESS_DENIED" if code == 5 else "OPERATION_FAILED"
        if code in (6, 87, 1168):
            status = "PROCESS_CHANGED"
        raise DebugError(status, f"{label}: {ctypes.FormatError(code).strip()}", code)

    def ensure_rights(self, rights: int) -> None:
        self.verify()
        if self._access & rights == rights:
            return
        new_access = self._access | rights
        replacement = self.k.OpenProcess(new_access, False, self.identity.pid)
        if not replacement:
            self.fail("OPEN_PROCESS_OPERATION_RIGHTS")
        previous = self.handle
        self.handle = replacement
        try:
            self.verify()
        except BaseException:
            self.handle = previous
            self.k.CloseHandle(replacement)
            raise
        self.k.CloseHandle(previous)
        self._access = new_access

    def break_process(self) -> None:
        self.verify()
        if self.debug_handle is None:
            # DebugBreakProcess documents PROCESS_ALL_ACCESS. Usually Windows
            # already supplied this exact-instance handle in CREATE_PROCESS_DEBUG_EVENT.
            self.ensure_rights(0x1FFFFF)
        if not self.k.DebugBreakProcess(self.debug_handle or self.handle):
            self.fail("DEBUG_BREAK_PROCESS")

    def retain_debug_process_handle(self, supplied_handle: int) -> None:
        """Keep our own duplicate, never close WaitForDebugEvent's HANDLE.

        Windows tracks CREATE_PROCESS/CREATE_THREAD handles and closes them
        on continued exit events or detach. Closing those numeric values
        early permits Windows to close an unrelated later handle after reuse.
        Only the accompanying image/DLL file handles belong to the caller.
        """
        from ctypes import wintypes as w
        if not supplied_handle or supplied_handle == 0xFFFFFFFFFFFFFFFF:
            raise DebugError("RECOVERY_UNCONFIRMED", "DEBUG_PROCESS_HANDLE_MISSING")
        owned = w.HANDLE()
        current = self.k.GetCurrentProcess()
        if not self.k.DuplicateHandle(current, supplied_handle, current,
                                      ctypes.byref(owned), 0, False, 2):
            self.fail("DUPLICATE_DEBUG_PROCESS_HANDLE")
        previous, self.debug_handle = self.debug_handle, owned.value
        if previous:
            self.k.CloseHandle(previous)

    def creation(self, handle: Any, *, thread: bool = False) -> int:
        from ctypes import wintypes as w
        values = [w.FILETIME() for _ in range(4)]
        method = self.k.GetThreadTimes if thread else self.k.GetProcessTimes
        if not method(handle, *(ctypes.byref(item) for item in values)):
            self.fail("GET_THREAD_TIMES" if thread else "GET_PROCESS_TIMES")
        return (values[0].dwHighDateTime << 32) | values[0].dwLowDateTime

    def verify(self) -> None:
        from ctypes import wintypes as w
        if not self.handle or self.k.WaitForSingleObject(self.handle, 0) != 0x102:
            raise DebugError("PROCESS_CHANGED", "TARGET_EXITED")
        if self.creation(self.handle) != self.identity.created_100ns:
            raise DebugError("PROCESS_CHANGED", "PROCESS_CREATION_TIME_CHANGED")
        if self.identity.image_path:
            size = w.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            if not self.k.QueryFullProcessImageNameW(self.handle, 0, buffer, ctypes.byref(size)):
                self.fail("QUERY_IMAGE")
            if os.path.normcase(buffer.value) != os.path.normcase(self.identity.image_path):
                raise DebugError("PROCESS_CHANGED", "PROCESS_IMAGE_CHANGED")

    def thread(self, tid: int, created: int | None = None, *, rights: int = 0x0018) -> tuple[Any, int]:
        self.verify()
        handle = self.k.OpenThread(0x100000 | 0x0800 | rights, False, tid)
        if not handle:
            self.fail("OPEN_THREAD")
        try:
            if self.k.GetProcessIdOfThread(handle) != self.identity.pid:
                raise DebugError("PROCESS_CHANGED", "THREAD_OWNER_CHANGED")
            actual = self.creation(handle, thread=True)
            if created is not None and actual != created:
                raise DebugError("PROCESS_CHANGED", "THREAD_CREATION_TIME_CHANGED")
            if self.k.WaitForSingleObject(handle, 0) != 0x102:
                raise DebugError("PROCESS_CHANGED", "THREAD_EXITED")
            return handle, actual
        except BaseException:
            self.k.CloseHandle(handle)
            raise

    def read(self, address: int, size: int) -> bytes:
        self.ensure_rights(0x0010)
        if not 0 < size <= MAX_WRITE or address <= 0 or address + size > (1 << 47):
            raise DebugError("OPERATION_FAILED", "MEMORY_RANGE_OUT_OF_BOUNDS")
        buffer = ctypes.create_string_buffer(size)
        count = ctypes.c_size_t()
        if not self.k.ReadProcessMemory(self.handle, address, buffer, size, ctypes.byref(count)):
            self.fail("READ_PROCESS_MEMORY")
        if count.value != size:
            raise DebugError("INCOMPLETE_EVIDENCE", "SHORT_MEMORY_READ")
        return buffer.raw

    def executable_address(self, address: int) -> bool:
        return bool(self.executable_protection(address))

    def executable_protection(self, address: int) -> int:
        self.ensure_rights(0x0400)
        info = ctypes.create_string_buffer(48)
        if self.k.VirtualQueryEx(self.handle, address, info, len(info)) != len(info):
            self.fail("VIRTUAL_QUERY_BREAKPOINT")
        state, protection = struct.unpack_from("<II", info.raw, 32)
        if state != 0x1000 or not bool(protection & 0xF0) or protection & (0x100 | 0x01):
            raise DebugError("OPERATION_FAILED", "BREAKPOINT_ADDRESS_NOT_EXECUTABLE")
        return protection

    def restore_executable_protection(self, address: int, original: int) -> None:
        """Restore only a recorded original protection or our temporary RWX state."""
        from ctypes import wintypes as w
        self.ensure_rights(0x0008)
        current = self.executable_protection(address)
        if current == original:
            return
        if current != 0x40:
            raise DebugError("RECOVERY_UNCONFIRMED", "BREAKPOINT_PAGE_PROTECTION_CHANGED_EXTERNALLY")
        ignored = w.DWORD()
        if not self.k.VirtualProtectEx(self.handle, address, 1, original, ctypes.byref(ignored)):
            raise DebugError("RECOVERY_UNCONFIRMED", "PAGE_PROTECTION_RESTORE_FAILED", ctypes.get_last_error())
        if self.executable_protection(address) != original:
            raise DebugError("RECOVERY_UNCONFIRMED", "PAGE_PROTECTION_RESTORE_READBACK_FAILED")

    def replace(self, address: int, expected: bytes, value: bytes, *, executable: bool = False,
                original_protection: int | None = None) -> None:
        from ctypes import wintypes as w
        self.ensure_rights(0x0010 | 0x0020 | 0x0008)
        if len(expected) != len(value) or self.read(address, len(expected)) != expected:
            raise DebugError("OPERATION_FAILED", "EXPECTED_BYTES_MISMATCH")
        old_protection = w.DWORD()
        changed_protection = False
        if executable:
            if len(value) != 1 or original_protection is None:
                raise DebugError("OPERATION_FAILED", "BREAKPOINT_PROTECTION_INTENT_REQUIRED")
            current = self.executable_protection(address)
            if current not in (original_protection, 0x40):
                raise DebugError("RECOVERY_UNCONFIRMED", "BREAKPOINT_PAGE_PROTECTION_CHANGED_EXTERNALLY")
            if not self.k.VirtualProtectEx(self.handle, address, len(value), 0x40,
                                           ctypes.byref(old_protection)):
                self.fail("VIRTUAL_PROTECT_BREAKPOINT")
            changed_protection = True
        try:
            count = ctypes.c_size_t()
            buffer = ctypes.create_string_buffer(value)
            if not self.k.WriteProcessMemory(self.handle, address, buffer, len(value), ctypes.byref(count)):
                code = ctypes.get_last_error()
                try:
                    unchanged = self.read(address, len(expected)) == expected
                except BaseException:
                    unchanged = False
                status = "ACCESS_DENIED" if code == 5 else "OPERATION_FAILED"
                if not unchanged:
                    status = "RECOVERY_UNCONFIRMED"
                raise DebugError(status, "WRITE_PROCESS_MEMORY_FAILED; " +
                                 ("ORIGINAL_BYTES_VERIFIED" if unchanged else "PARTIAL_CHANGE_NOT_EXCLUDED"), code)
            if count.value != len(value):
                raise DebugError("RECOVERY_UNCONFIRMED", "SHORT_MEMORY_WRITE")
            if not self.k.FlushInstructionCache(self.handle, address, len(value)):
                raise DebugError("RECOVERY_UNCONFIRMED", "MEMORY_CHANGED_BUT_INSTRUCTION_CACHE_FLUSH_FAILED",
                                 ctypes.get_last_error())
            if self.read(address, len(value)) != value:
                raise DebugError("RECOVERY_UNCONFIRMED", "MEMORY_WRITE_READBACK_MISMATCH")
        finally:
            if changed_protection:
                self.restore_executable_protection(address, original_protection)

    def context(self, handle: Any) -> _Context:
        result = _Context()
        if not self.k.GetThreadContext(handle, result.pointer):
            self.fail("GET_THREAD_CONTEXT")
        return result

    def set_context(self, handle: Any, context: _Context) -> None:
        if not self.k.SetThreadContext(handle, context.pointer):
            self.fail("SET_THREAD_CONTEXT")

    def close(self) -> None:
        if self.debug_handle:
            self.k.CloseHandle(self.debug_handle)
            self.debug_handle = None
        if self.handle:
            self.k.CloseHandle(self.handle)
            self.handle = None


@dataclass
class _Command:
    operation: str
    parameters: dict[str, Any]
    deadline: float
    cancel: Any
    done: threading.Event
    result: dict[str, Any] | None = None


class DebugSession:
    """An isolated diagnostic backend; service must additionally enforce its scope."""
    def __init__(self, identity: ProcessIdentity, *, recovery_handle: int | None = None):
        self.identity = identity
        self.state = "IDLE"
        self._queue: queue.Queue[_Command] = queue.Queue(maxsize=16)
        self._stopping = threading.Event()
        self._worker: threading.Thread | None = None
        self._start_lock = threading.Lock()
        self._api: _WinAPI | None = None
        self._attached = False
        self._event: _DebugEvent | None = None
        self._event_continue = DBG_CONTINUE
        self._breakpoints: dict[str, dict[str, Any]] = {}
        self._changes: dict[str, dict[str, Any]] = {}
        self._suspensions: dict[str, dict[str, Any]] = {}
        self._stepping: dict[str, Any] | None = None
        self._paused_breakpoint: str | None = None
        self._pause_requested = False
        self._guard: Any = None
        self._recovery_handle = recovery_handle
        self._fatal: dict[str, Any] | None = None
        self._closed = False
        self._close_command: _Command | None = None
        self._close_result: dict[str, Any] | None = None
        self._owner_retained = False

    def execute(self, operation: str, parameters: dict[str, Any], *, deadline: float | None = None,
                cancel_event: Any = None) -> dict[str, Any]:
        operation = _ALIASES.get(operation, operation)
        deadline = time.monotonic() + 15 if deadline is None else deadline
        if self._closed:
            return _result("OPERATION_FAILED", error="DEBUG_SESSION_CLOSED")
        if self._owner_retained and operation not in {
                "debug.detach", "debug.context", "debug.breakpoints", "debug.state"}:
            return _result("RECOVERY_UNCONFIRMED", error="UNRECOVERED_BREAKPOINT_CONTEXT_HELD",
                           data={"state": self.state, "owner_retained": True, "retry_cleanup_required": True})
        if self._worker is not None and not self._worker.is_alive():
            return self._fatal or _result("OPERATION_FAILED", error="DEBUG_WORKER_STOPPED")
        if os.name != "nt":
            return _result("INCOMPLETE_EVIDENCE", error="WINDOWS_X64_REQUIRED",
                           limitations=["No Windows intervention is emulated on this platform."])
        if not isinstance(parameters, dict):
            return _result("OPERATION_FAILED", error="INVALID_PARAMETERS")
        with self._start_lock:
            if self._worker is None:
                self._worker = threading.Thread(target=self._run, name="blackbox-debug-owner", daemon=True)
                self._worker.start()
        command = _Command(operation, dict(parameters), deadline, cancel_event, threading.Event())
        try:
            self._queue.put_nowait(command)
        except queue.Full:
            return _result("OPERATION_FAILED", error="DEBUG_COMMAND_QUEUE_FULL")
        while not command.done.wait(0.05):
            if time.monotonic() > deadline + 2:
                # A native transition may still be cleaning up. Never report verified cancellation.
                return _result("RECOVERY_UNCONFIRMED", error="DEBUG_COMMAND_COMPLETION_UNCONFIRMED",
                               data={"state": self.state})
        return command.result or _result("OPERATION_FAILED", error="EMPTY_DEBUG_RESULT")

    def close(self) -> dict[str, Any]:
        if self._closed:
            # A timeout closes the public command interface, not necessarily
            # the native worker. Only its acknowledged cleanup result can
            # replace the previously returned unconfirmed status.
            if self._close_command is not None and self._close_command.done.is_set():
                self._close_result = self._close_command.result or _result(
                    "RECOVERY_UNCONFIRMED", error="EMPTY_CLEANUP_RESULT")
                if self._close_result.get("data", {}).get("owner_retained") is True:
                    self._closed = False  # Only a new cleanup retry may release the held event.
            return self._close_result or self._fatal or _result(
                "RECOVERY_UNCONFIRMED", error="DEBUG_CLEANUP_RESULT_NOT_OBSERVED",
                data={"state": self.state})
        if self._worker is None:
            self._closed = True
            self._close_result = _result(data={"state": "DETACHED", "owned_resources_remaining": 0})
            return self._close_result
        command = _Command("_close", {}, time.monotonic() + 10, None, threading.Event())
        try:
            self._queue.put(command, timeout=1)
        except queue.Full:
            return _result("RECOVERY_UNCONFIRMED", error="CLEANUP_QUEUE_FULL",
                           data={"state": self.state, "owner_retained": True, "retry_cleanup_required": True})
        self._close_command = command
        command.done.wait(12)
        self._closed = True
        if not command.done.is_set():
            self._close_result = _result("RECOVERY_UNCONFIRMED", error="DEBUG_CLEANUP_UNCONFIRMED",
                data={"state": self.state, "owner_retained": True, "retry_cleanup_required": True,
                      "cleanup_acknowledgement_pending": True})
        else:
            self._close_result = command.result or _result("RECOVERY_UNCONFIRMED", error="EMPTY_CLEANUP_RESULT")
            if self._close_result.get("data", {}).get("owner_retained") is True:
                self._closed = False
        return self._close_result

    def _run(self) -> None:
        try:
            self._api = _WinAPI(self.identity)
            while not self._stopping.is_set():
                try:
                    command = self._queue.get(timeout=0.02)
                except queue.Empty:
                    command = None
                if command is not None:
                    try:
                        if command.operation == "_close":
                            command.result = self._cleanup()
                            self._fatal = command.result if command.result["status"] != "COMPLETED" else None
                            if command.result.get("data", {}).get("owner_retained") is not True:
                                self._stopping.set()
                        else:
                            self._check(command)
                            command.result = self._dispatch(command)
                    except DebugError as exc:
                        if (self._unsafe_breakpoint_ids() or self._stepping) and self._event is not None:
                            command.result = self._retain_debug_owner(str(exc), winerror=exc.winerror)
                        else:
                            command.result = _result(exc.status, error=str(exc),
                                                     winerror=exc.winerror, data={"state": self.state})
                    except BaseException as exc:
                        if (self._unsafe_breakpoint_ids() or self._stepping) and self._event is not None:
                            command.result = self._retain_debug_owner(f"{type(exc).__name__}: {exc}",
                                                                     winerror=getattr(exc, "winerror", None))
                        else:
                            command.result = _result("OPERATION_FAILED", error=f"{type(exc).__name__}: {exc}",
                                                     data={"state": self.state})
                    finally:
                        command.done.set()
                if self._attached and self._event is None:
                    try:
                        self._pump(10)
                    except BaseException as exc:
                        if (self._unsafe_breakpoint_ids() or self._stepping) and self._event is not None:
                            self._fatal = self._retain_debug_owner(
                                f"DEBUG_EVENT_RECOVERY_REQUIRED: {type(exc).__name__}: {exc}",
                                winerror=getattr(exc, "winerror", None))
                        else:
                            raise
        except BaseException as exc:
            self.state = "ERROR"
            self._fatal = _result("RECOVERY_UNCONFIRMED" if self._attached else "OPERATION_FAILED",
                                  error=f"DEBUG_WORKER_FAILED: {type(exc).__name__}: {exc}")
        finally:
            if not self._stopping.is_set() and self._api:
                cleanup = self._cleanup()
                if self._fatal is None or cleanup["status"] != "COMPLETED":
                    self._fatal = cleanup
                else:
                    self._fatal["cleanup"] = cleanup
            if self._api:
                self._api.close()
            while True:
                try:
                    command = self._queue.get_nowait()
                except queue.Empty:
                    break
                command.result = self._fatal or _result("OPERATION_FAILED", error="DEBUG_WORKER_STOPPED")
                command.done.set()

    def _check(self, command: _Command) -> None:
        if command.cancel is not None and command.cancel.is_set():
            raise DebugError("CANCELLED", "CANCELLED_BEFORE_NATIVE_ACTION")
        if time.monotonic() >= command.deadline:
            raise DebugError("TIMED_OUT", "DEADLINE_BEFORE_NATIVE_ACTION")
        if self._api is None:
            raise DebugError("OPERATION_FAILED", "DEBUG_BACKEND_NOT_READY")
        self._api.verify()

    def _confirmed(self, parameters: dict[str, Any]) -> None:
        if parameters.get("_confirmed") is not True:
            raise DebugError("OPERATION_FAILED", "EXPLICIT_CONFIRMATION_REQUIRED")

    def _snapshot(self) -> dict[str, Any]:
        result: dict[str, Any] = {"state": self.state, "attached": self._attached,
                                  "owned_suspensions": len(self._suspensions),
                                  "breakpoints": len(self._breakpoints),
                                  "pending_memory_changes": len(self._changes)}
        if self._owner_retained:
            result.update(owner_retained=True, retry_cleanup_required=True)
        if self._event:
            result["stopped_tid"] = self._event.tid
            handle, created = self._api.thread(self._event.tid, rights=0)
            self._api.k.CloseHandle(handle)
            result["thread_created_100ns"] = created
        if self._guard:
            result["guardian_pid"] = self._guard.pid
            result["recovery_report_handle_configured"] = self._recovery_handle is not None
        return result

    def _unsafe_breakpoint_ids(self) -> list[str]:
        return [identifier for identifier, item in self._breakpoints.items()
                if (identifier == self._paused_breakpoint or item.get("hit_context"))
                and item.get("hit_context", {}).get("phase") != "rewind_verified"]

    def _retain_debug_owner(self, error: str, *, winerror: int | None = None,
                            native_failures: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        self.state = "RECOVERY_UNCONFIRMED"
        self._owner_retained = True
        event = self._event
        return _result("RECOVERY_UNCONFIRMED", error=error, winerror=winerror,
                       data={"state": self.state, "attached": self._attached, "owner_retained": True,
                             "retry_cleanup_required": True, "unsafe_breakpoint_ids": self._unsafe_breakpoint_ids(),
                             "remaining_breakpoint_ids": list(self._breakpoints),
                             "pending_single_step": self._stepping is not None,
                             "held_debug_event": {"pid": event.pid, "tid": event.tid, "code": event.code} if event else None,
                             "native_cleanup_failures": native_failures or [],
                             "owned_resources_remaining": len(self._breakpoints) + len(self._changes) + len(self._suspensions)},
                       limitations=["Unverified owned execution changes remain stopped; retry cleanup before continuing.",
                                    "Parent loss or the original session deadline can still end the owner; recovery then remains best effort."])

    def _ensure_guard(self) -> None:
        if self._guard is None:
            from .deep_debug_guardian import RecoveryGuardian
            self._guard = RecoveryGuardian(self.identity, recovery_handle=self._recovery_handle)
        self._sync_guard()

    def _sync_guard(self) -> None:
        if self._guard:
            self._guard.update({
                "breakpoints": [{k: v for k, v in item.items() if k != "handle"}
                                for item in self._breakpoints.values()],
                "changes": list(self._changes.values()),
                "suspensions": [{k: v for k, v in item.items() if k != "handle"}
                                for item in self._suspensions.values()],
                "stepping": self._stepping,
            })

    def _dispatch(self, command: _Command) -> dict[str, Any]:
        operation, p = command.operation, command.parameters
        if operation == "debug.state":
            return _result(data=self._snapshot())
        if operation == "debug.breakpoints":
            return _result(data={"breakpoints": [{"breakpoint_id": key, "address": item["address"],
                                                  "enabled": item["enabled"], "installed": item["installed"]}
                                                 for key, item in self._breakpoints.items()]})
        if operation in {"debug.attach", "debug.pause", "debug.continue", "debug.step",
                         "debug.breakpoint.add", "debug.breakpoint.disable", "debug.breakpoint.remove",
                         "thread.suspend", "thread.resume", "memory.write", "memory.rollback"}:
            self._confirmed(p)
        before = self._snapshot()
        if operation == "debug.attach":
            self._attach(command)
        elif operation == "debug.detach":
            return self._cleanup()
        elif operation == "debug.pause":
            self._require_attached()
            if self._event is None:
                self._check(command)
                self._pause_requested = True
                self._api.break_process()
                self._until_stopped(command)
        elif operation == "debug.continue":
            self._continue(command, step=False)
        elif operation == "debug.step":
            self._continue(command, step=True)
        elif operation == "debug.context":
            return self._context_result(p)
        elif operation == "debug.breakpoint.add":
            return self._add_breakpoint(p, command=command)
        elif operation in ("debug.breakpoint.disable", "debug.breakpoint.remove"):
            return self._remove_breakpoint(p, remove=operation.endswith("remove"), command=command)
        elif operation == "thread.suspend":
            return self._suspend(p, command=command)
        elif operation == "thread.resume":
            return self._resume(p, command=command)
        elif operation == "memory.write":
            return self._write_memory(p, command=command)
        elif operation == "memory.rollback":
            return self._rollback_memory(p, command=command)
        else:
            raise DebugError("OPERATION_FAILED", "UNSUPPORTED_DEBUG_OPERATION")
        return _result(data=self._snapshot(), before=before, after=self._snapshot(),
                       limitations=["Continuing or stepping application execution is not reversible."])

    def _attach(self, command: _Command) -> None:
        from ctypes import wintypes as w
        if self._attached:
            return
        self._api.ensure_rights(0x0400)
        present = w.BOOL()
        if not self._api.k.CheckRemoteDebuggerPresent(self._api.handle, ctypes.byref(present)):
            self._api.fail("CHECK_REMOTE_DEBUGGER")
        if present.value:
            raise DebugError("ALREADY_DEBUGGED", "TARGET_HAS_ANOTHER_DEBUGGER")
        self._ensure_guard()
        self._check(command)
        self.state = "ATTACHING"
        if not self._api.k.DebugActiveProcess(self.identity.pid):
            self.state = "ATTACH_FAILED"
            self._api.fail("DEBUG_ACTIVE_PROCESS")
        self._attached = True
        # Must be called by the thread owning this debug object, immediately after attach.
        if not self._api.k.DebugSetProcessKillOnExit(False):
            # Preserve ownership when the first detach attempt also fails;
            # normal cleanup must still retry the actual attached debug object.
            self._attached = not bool(self._api.k.DebugActiveProcessStop(self.identity.pid))
            self.state = "RECOVERY_UNCONFIRMED"
            raise DebugError("RECOVERY_UNCONFIRMED", "DEBUG_KILL_ON_EXIT_CONFIGURATION_FAILED")
        self.state = "ATTACHED"
        self._pause_requested = True  # Windows emits its initial attachment breakpoint.
        self._until_stopped(command)

    def _require_attached(self) -> None:
        if not self._attached:
            raise DebugError("OPERATION_FAILED", "DEBUGGER_NOT_ATTACHED")

    def _until_stopped(self, command: _Command) -> None:
        while self._event is None and self._attached:
            try:
                self._check(command)
            except DebugError:
                cleanup = self._cleanup()
                if cleanup["status"] != "COMPLETED":
                    raise DebugError("RECOVERY_UNCONFIRMED", "CANCELLED_DEBUG_TRANSITION_CLEANUP_UNCONFIRMED")
                raise
            self._pump(25)
        if not self._attached:
            raise DebugError("PROCESS_CHANGED", "TARGET_EXITED_DURING_DEBUG_TRANSITION")

    def _pump(self, milliseconds: int) -> None:
        event = _DebugEvent()
        if not self._api.k.WaitForDebugEvent(ctypes.byref(event), milliseconds):
            error = ctypes.get_last_error()
            if error in (0, 121):
                return
            self._api.fail("WAIT_FOR_DEBUG_EVENT")
        # From this instant Windows has stopped the event thread/process. Save
        # ownership before touching memory/context so every failure path can
        # continue or detach this actual pending event instead of losing it.
        self._event = event
        self._event_continue = DBG_EXCEPTION_NOT_HANDLED if event.code == 1 else DBG_CONTINUE
        raw = event.raw()
        if event.code in (3, 6):
            # CREATE_PROCESS.hFile and LOAD_DLL.hFile are caller-owned.
            # hProcess and every CREATE_THREAD/CREATE_PROCESS.hThread are
            # system-managed debug handles; WaitForDebugEvent retains them.
            file_handle = struct.unpack_from("<Q", raw, 0)[0]
            if file_handle and file_handle != 0xFFFFFFFFFFFFFFFF:
                self._api.k.CloseHandle(file_handle)
            if event.code == 3 and event.pid == self.identity.pid:
                self._api.retain_debug_process_handle(struct.unpack_from("<Q", raw, 8)[0])
        if event.pid != self.identity.pid:
            code = DBG_EXCEPTION_NOT_HANDLED if event.code == 1 else DBG_CONTINUE
            if not self._api.k.ContinueDebugEvent(event.pid, event.tid, code):
                self._api.fail("CONTINUE_NON_TARGET_DEBUG_EVENT")
            self._event = None
            return
        if event.code == 5:
            self._api.k.ContinueDebugEvent(event.pid, event.tid, DBG_CONTINUE)
            self._attached = False
            self.state = "TARGET_EXITED"
            self._event = None
            return
        if event.code != 1:
            if not self._api.k.ContinueDebugEvent(event.pid, event.tid, DBG_CONTINUE):
                self._api.fail("CONTINUE_DEBUG_EVENT")
            self._event = None
            return
        exception = struct.unpack_from("<I", raw, 0)[0]
        address = struct.unpack_from("<Q", raw, 16)[0]
        first_chance = struct.unpack_from("<I", raw, 152)[0]
        matching = next(((key, item) for key, item in self._breakpoints.items()
                         if item["address"] == address and item["installed"]), None)
        if exception == EXCEPTION_BREAKPOINT and matching:
            self._event_continue = DBG_CONTINUE
            self.state = "PAUSED"
            key, item = matching
            self._paused_breakpoint = key
            handle, created = self._api.thread(event.tid)
            try:
                item["hit_context"] = {"tid": event.tid, "created_100ns": created,
                                       "rip_before": address + 1, "phase": "rewind_pending"}
                self._sync_guard()
                context = self._api.context(handle)
                if context.get64(248) not in (address, address + 1):
                    raise DebugError("RECOVERY_UNCONFIRMED", "BREAKPOINT_INSTRUCTION_POINTER_UNEXPECTED")
                self._api.replace(address, b"\xcc", bytes.fromhex(item["original_hex"]), executable=True,
                                  original_protection=item["original_protection"])
                item["installed"] = False
                context.set64(248, address)
                self._api.set_context(handle, context)
                if self._api.context(handle).get64(248) != address:
                    raise DebugError("RECOVERY_UNCONFIRMED", "BREAKPOINT_RIP_REWIND_READBACK_FAILED")
                item["hit_context"]["phase"] = "rewind_verified"
            finally:
                self._api.k.CloseHandle(handle)
            self._event = event
            self._event_continue = DBG_CONTINUE
            self.state = "PAUSED"
            self._sync_guard()
            return
        if exception == EXCEPTION_SINGLE_STEP and self._stepping and event.tid == self._stepping["tid"]:
            self._event_continue = DBG_CONTINUE
            self.state = "PAUSED"
            step = self._stepping
            handle, _ = self._api.thread(event.tid, step["created_100ns"])
            try:
                context = self._api.context(handle)
                if not step["original_tf"]:
                    context.set32(68, context.get32(68) & ~0x100)
                    self._api.set_context(handle, context)
            finally:
                self._api.k.CloseHandle(handle)
            breakpoint = self._breakpoints.get(step.get("breakpoint_id"))
            if breakpoint and breakpoint["enabled"]:
                breakpoint.pop("hit_context", None)
                self._api.replace(breakpoint["address"], bytes.fromhex(breakpoint["original_hex"]),
                                  b"\xcc", executable=True,
                                  original_protection=breakpoint["original_protection"])
                breakpoint["installed"] = True
            self._stepping = None
            self._paused_breakpoint = None
            self._sync_guard()
            if step["pause_after"]:
                self._event, self._event_continue = event, DBG_CONTINUE
                self.state = "PAUSED"
                return
            if not self._api.k.ContinueDebugEvent(event.pid, event.tid, DBG_CONTINUE):
                self._api.fail("CONTINUE_AFTER_OWN_STEP")
            self._event = None
            self.state = "RUNNING"
            return
        if exception == EXCEPTION_BREAKPOINT and self._pause_requested:
            self._pause_requested = False
            self._event, self._event_continue = event, DBG_CONTINUE
            self.state = "PAUSED"
            return
        # Never swallow application access violations or another component's int3.
        if not first_chance:
            self._event, self._event_continue = event, DBG_EXCEPTION_NOT_HANDLED
            self.state = "PAUSED_EXCEPTION"
            return
        if not self._api.k.ContinueDebugEvent(event.pid, event.tid, DBG_EXCEPTION_NOT_HANDLED):
            self._api.fail("CONTINUE_UNOWNED_EXCEPTION")
        self._event = None

    def _continue(self, command: _Command, *, step: bool) -> None:
        self._require_attached()
        if self._event is None:
            raise DebugError("OPERATION_FAILED", "NO_STOPPED_DEBUG_EVENT")
        if self._stepping is not None:
            raise DebugError("RECOVERY_UNCONFIRMED", "PREVIOUS_SINGLE_STEP_TRANSITION_REQUIRES_CLEANUP")
        event = self._event
        if self._paused_breakpoint:
            breakpoint = self._breakpoints.get(self._paused_breakpoint)
            if breakpoint and breakpoint.get("hit_context", {}).get("phase") != "rewind_verified":
                raise DebugError("RECOVERY_UNCONFIRMED", "BREAKPOINT_INSTRUCTION_POINTER_NOT_VERIFIED")
        if step or self._paused_breakpoint:
            handle, created = self._api.thread(event.tid)
            try:
                context = self._api.context(handle)
                self._stepping = {"tid": event.tid, "created_100ns": created,
                                  "original_tf": bool(context.get32(68) & 0x100),
                                  "breakpoint_id": self._paused_breakpoint, "pause_after": step}
                self._sync_guard()
                try:
                    self._check(command)
                except DebugError:
                    self._stepping = None  # No SetThreadContext effect has happened.
                    self._sync_guard()
                    raise
                context.set32(68, context.get32(68) | 0x100)
                self._api.set_context(handle, context)
            finally:
                self._api.k.CloseHandle(handle)
        try:
            self._check(command)
        except DebugError:
            if self._stepping is not None:
                cleanup = self._cleanup()
                if cleanup["status"] != "COMPLETED":
                    raise DebugError("RECOVERY_UNCONFIRMED", "CANCELLED_STEP_CLEANUP_UNCONFIRMED")
            raise
        if not self._api.k.ContinueDebugEvent(event.pid, event.tid, self._event_continue):
            self._api.fail("CONTINUE_DEBUG_EVENT")
        self._event = None
        self.state = "RUNNING"
        if step:
            self._until_stopped(command)

    def _context_result(self, p: dict[str, Any]) -> dict[str, Any]:
        if self._event is None:
            raise DebugError("OPERATION_FAILED", "CONTEXT_REQUIRES_PAUSED_DEBUG_EVENT")
        tid = _positive(p.get("tid", self._event.tid), "tid", 0xFFFFFFFF)
        if tid != self._event.tid:
            raise DebugError("OPERATION_FAILED", "CONTEXT_REQUIRES_EVENT_THREAD")
        created = p.get("thread_created_100ns")
        if created is not None:
            _positive(created, "thread_created_100ns")
        handle, actual = self._api.thread(tid, created, rights=0x0008)
        try:
            registers = self._api.context(handle).public()
        finally:
            self._api.k.CloseHandle(handle)
        return _result(data={"source": "LIVE_WINDOWS_DEBUG_EVENT", "tid": tid, "stopped_tid": tid,
                             "thread_created_100ns": actual, "registers": registers,
                             "state": self.state})

    def _add_breakpoint(self, p: dict[str, Any], *, command: _Command | None = None) -> dict[str, Any]:
        self._require_attached()
        if self._event is None:
            raise DebugError("OPERATION_FAILED", "BREAKPOINT_CHANGE_REQUIRES_PAUSED_PROCESS")
        address = _positive(p.get("address"), "address", (1 << 47) - 1)
        if len(self._breakpoints) >= MAX_BREAKPOINTS:
            raise DebugError("LIMIT_REACHED", "BREAKPOINT_LIMIT")
        if any(item["address"] == address for item in self._breakpoints.values()):
            raise DebugError("OPERATION_FAILED", "BREAKPOINT_ALREADY_EXISTS")
        original = self._api.read(address, 1)
        original_protection = self._api.executable_protection(address)
        if original == b"\xcc":
            raise DebugError("OPERATION_FAILED", "EXISTING_INT3_IS_NOT_OWNED")
        self._ensure_guard()
        identifier = uuid.uuid4().hex
        item = {"breakpoint_id": identifier, "address": address, "original_hex": original.hex(),
                "enabled": True, "installed": True, "original_protection": original_protection}
        self._breakpoints[identifier] = item
        self._sync_guard()  # recovery intent is durable in the separate live guardian first.
        try:
            if command is not None:
                self._check(command)
        except DebugError:
            del self._breakpoints[identifier]  # No code/protection effect yet.
            self._sync_guard()
            raise
        try:
            self._api.replace(address, original, b"\xcc", executable=True,
                              original_protection=original_protection)
        except BaseException:
            # Keep the intent until cleanup compares actual bytes; partial writes are not assumed absent.
            raise
        return _result(data={"breakpoint_id": identifier, "address": address, "enabled": True},
                       before={"code_sha256": _digest(original)}, after={"code_sha256": _digest(b"\xcc")},
                       limitations=["Software breakpoint temporarily modifies one code byte.",
                                    "Other threads can cross the address during a single-step rearm window."])

    def _remove_breakpoint(self, p: dict[str, Any], *, remove: bool,
                           command: _Command | None = None) -> dict[str, Any]:
        self._require_attached()
        if self._event is None:
            raise DebugError("OPERATION_FAILED", "BREAKPOINT_CHANGE_REQUIRES_PAUSED_PROCESS")
        identifier = p.get("breakpoint_id")
        item = self._breakpoints.get(identifier)
        if item is None:
            raise DebugError("OPERATION_FAILED", "UNKNOWN_BREAKPOINT")
        self._restore_breakpoint_context(item)
        if command is not None:
            self._check(command)
        if item["installed"]:
            self._api.replace(item["address"], b"\xcc", bytes.fromhex(item["original_hex"]), executable=True,
                              original_protection=item["original_protection"])
        self._api.restore_executable_protection(item["address"], item["original_protection"])
        item["installed"] = item["enabled"] = False
        if remove:
            del self._breakpoints[identifier]
            if self._paused_breakpoint == identifier:
                self._paused_breakpoint = None
        self._sync_guard()
        return _result(data={"breakpoint_id": identifier, "enabled": False, "removed": remove,
                             "original_byte_verified": True})

    def _restore_breakpoint_context(self, item: dict[str, Any]) -> None:
        hit = item.get("hit_context")
        if not hit and self._paused_breakpoint == item["breakpoint_id"]:
            if self._event is None:
                raise DebugError("RECOVERY_UNCONFIRMED", "BREAKPOINT_STOP_CONTEXT_NO_LONGER_HELD")
            # An OpenThread failure on first INT3 handling can precede the
            # first acknowledged hit-context record. Retry identity capture
            # only while the actual debug event is still held by this thread.
            handle, created = self._api.thread(self._event.tid)
            self._api.k.CloseHandle(handle)
            hit = {"tid": self._event.tid, "created_100ns": created,
                   "rip_before": item["address"] + 1, "phase": "rewind_pending"}
            item["hit_context"] = hit
            self._sync_guard()
        if not hit or hit["phase"] == "rewind_verified":
            return
        if self._event is None or self._event.tid != hit["tid"]:
            raise DebugError("RECOVERY_UNCONFIRMED", "BREAKPOINT_STOP_CONTEXT_NO_LONGER_HELD")
        handle, _ = self._api.thread(hit["tid"], hit["created_100ns"])
        try:
            context = self._api.context(handle)
            rip = context.get64(248)
            if rip == hit["rip_before"] == item["address"] + 1:
                context.set64(248, item["address"])
                self._api.set_context(handle, context)
            elif rip != item["address"]:
                raise DebugError("RECOVERY_UNCONFIRMED", "BREAKPOINT_INSTRUCTION_POINTER_CHANGED")
            if self._api.context(handle).get64(248) != item["address"]:
                raise DebugError("RECOVERY_UNCONFIRMED", "BREAKPOINT_RIP_RESTORE_READBACK_FAILED")
            hit["phase"] = "rewind_verified"
        finally:
            self._api.k.CloseHandle(handle)

    def _suspend(self, p: dict[str, Any], *, command: _Command | None = None) -> dict[str, Any]:
        tid = _positive(p.get("tid"), "tid", 0xFFFFFFFF)
        created = _positive(p.get("thread_created_100ns"), "thread_created_100ns")
        if len(self._suspensions) >= MAX_SUSPENSIONS:
            raise DebugError("LIMIT_REACHED", "OWNED_SUSPENSION_LIMIT")
        if any(item["tid"] == tid and item["created_100ns"] == created for item in self._suspensions.values()):
            raise DebugError("OPERATION_FAILED", "THREAD_ALREADY_SUSPENDED_BY_THIS_SESSION")
        self._ensure_guard()
        handle, _ = self._api.thread(tid, created, rights=0x0002)
        identifier = uuid.uuid4().hex
        item = {"suspension_id": identifier, "tid": tid, "created_100ns": created,
                "phase": "pending", "handle": handle}
        self._suspensions[identifier] = item
        self._sync_guard()
        try:
            if command is not None:
                self._check(command)
        except DebugError:
            del self._suspensions[identifier]  # The OS count has not changed.
            self._api.k.CloseHandle(handle)
            self._sync_guard()
            raise
        previous = self._api.k.SuspendThread(handle)
        if previous == 0xFFFFFFFF:
            try:
                self._api.fail("SUSPEND_THREAD")
            except DebugError:
                del self._suspensions[identifier]
                self._api.k.CloseHandle(handle)
                self._sync_guard()
                raise
        item.update(phase="active", previous_count=previous)
        self._sync_guard()
        return _result(data={"suspension_id": identifier, "tid": tid,
                             "thread_created_100ns": created, "previous_suspend_count": previous,
                             "owned_increment": 1},
                       limitations=["An abrupt failure between the OS call and acknowledgement may leave recovery unconfirmed."])

    def _resume(self, p: dict[str, Any], *, command: _Command | None = None) -> dict[str, Any]:
        identifier = p.get("suspension_id")
        if identifier is None:
            tid = _positive(p.get("tid"), "tid", 0xFFFFFFFF)
            created = _positive(p.get("thread_created_100ns"), "thread_created_100ns")
            identifier = next((key for key, item in self._suspensions.items()
                               if item["tid"] == tid and item["created_100ns"] == created), None)
        item = self._suspensions.get(identifier)
        if item is None or item["phase"] != "active":
            raise DebugError("OPERATION_FAILED", "NO_OWNED_SUSPENSION")
        item["phase"] = "resuming"
        self._sync_guard()  # Guardian will not double-resume an uncertain in-flight decrement.
        try:
            if command is not None:
                self._check(command)
        except DebugError:
            item["phase"] = "active"  # No OS decrement; retain the owned increment.
            self._sync_guard()
            raise
        previous = self._api.k.ResumeThread(item["handle"])
        if previous == 0xFFFFFFFF or previous == 0:
            raise DebugError("RECOVERY_UNCONFIRMED", "OWNED_THREAD_RESUME_UNCONFIRMED")
        self._api.k.CloseHandle(item["handle"])
        del self._suspensions[identifier]
        self._sync_guard()
        return _result(data={"suspension_id": identifier, "owned_decrement": 1,
                             "remaining_suspend_count_observed": previous - 1,
                             "other_suspend_counts_preserved": True})

    def _write_memory(self, p: dict[str, Any], *, command: _Command | None = None) -> dict[str, Any]:
        address = _positive(p.get("address"), "address", (1 << 47) - 1)
        original, value = _hex(p.get("expected_hex"), "expected_hex"), _hex(p.get("value_hex"), "value_hex")
        if len(original) != len(value):
            raise DebugError("OPERATION_FAILED", "MEMORY_WRITE_SIZE_MISMATCH")
        if len(self._changes) >= 64:
            raise DebugError("LIMIT_REACHED", "PRIVATE_MEMORY_CHANGE_COUNT_BUDGET")
        if sum(len(bytes.fromhex(item["original_hex"])) for item in self._changes.values()) + len(value) > MAX_PRIVATE_BYTES:
            raise DebugError("LIMIT_REACHED", "PRIVATE_MEMORY_RECOVERY_BUDGET")
        if any(address < item["address"] + len(bytes.fromhex(item["value_hex"])) and
               item["address"] < address + len(value) for item in self._changes.values()):
            raise DebugError("OPERATION_FAILED", "OVERLAPPING_UNRESTORED_MEMORY_CHANGE")
        if any(address <= item["address"] < address + len(value) for item in self._breakpoints.values()):
            raise DebugError("OPERATION_FAILED", "MEMORY_WRITE_OVERLAPS_OWN_BREAKPOINT")
        if self._api.read(address, len(original)) != original:
            raise DebugError("OPERATION_FAILED", "EXPECTED_BYTES_MISMATCH")
        self._ensure_guard()
        identifier = uuid.uuid4().hex
        item = {"change_id": identifier, "address": address, "original_hex": original.hex(),
                "value_hex": value.hex()}
        self._changes[identifier] = item
        self._sync_guard()
        try:
            if command is not None:
                self._check(command)
        except DebugError:
            del self._changes[identifier]  # No WriteProcessMemory effect yet.
            self._sync_guard()
            raise
        self._api.replace(address, original, value)
        return _result(data={"change_id": identifier, "address": address, "size": len(value),
                             "readback_verified": True, "recovery_bytes_retained_privately": True},
                       before={"sha256": _digest(original)}, after={"sha256": _digest(value)},
                       limitations=["The target can modify or consume these bytes immediately.",
                                    "Restoring bytes cannot undo effects already caused by application execution."])

    def _rollback_memory(self, p: dict[str, Any], *, command: _Command | None = None) -> dict[str, Any]:
        identifier = p.get("change_id", p.get("operation_id"))
        item = self._changes.get(identifier)
        if item is None:
            raise DebugError("OPERATION_FAILED", "UNKNOWN_MEMORY_CHANGE")
        original, value = bytes.fromhex(item["original_hex"]), bytes.fromhex(item["value_hex"])
        if command is not None:
            self._check(command)
        self._api.replace(item["address"], value, original)
        del self._changes[identifier]
        self._sync_guard()
        return _result(data={"change_id": identifier, "original_bytes_verified": True},
                       after={"sha256": _digest(original)},
                       limitations=["Only the selected bytes were restored; application side effects cannot be reversed."])

    def _cleanup(self) -> dict[str, Any]:
        errors: list[str] = []
        native_failures: list[dict[str, Any]] = []

        def record_caught_failure(label: str, failure: BaseException) -> None:
            errors.append(f"{label}: {failure}")
            code = getattr(failure, "winerror", None)
            if code is not None:
                native_failures.append({"operation": label, "winerror": code, "detail": str(failure)})

        def record_native_failure(label: str) -> None:
            # Capture GetLastError before another API/guardian call overwrites
            # it. Cleanup remains unconfirmed even for an ordinary Win32 error.
            try:
                self._api.fail(label)
            except DebugError as failure:
                errors.append(str(failure))
                native_failures.append({"operation": label, "winerror": failure.winerror,
                                        "detail": str(failure)})

        self.state = "DETACHING"
        if self._guard:
            try:
                self._sync_guard()
            except BaseException as exc:
                # Do not resume against a stale live guardian plan: it could
                # decrement the same suspension again. First establish that
                # the owned guardian has exited, then perform local cleanup.
                try:
                    self._guard.abandon()
                    self._guard = None
                    errors.append(f"GUARDIAN_UNAVAILABLE_LOCAL_RECOVERY: {exc}")
                except BaseException as stop_error:
                    errors.append(f"GUARDIAN_SHUTDOWN_UNCONFIRMED: {stop_error}")
                    self.state = "RECOVERY_UNCONFIRMED"
                    if (self._breakpoints or self._stepping) and self._attached and self._event is not None:
                        return self._retain_debug_owner("; ".join(errors))
                    # A live guardian may still act on the old acknowledged
                    # plan. Do not race it with another ResumeThread decrement
                    # or memory restoration. The helper's owner will terminate
                    # this failed session; the guardian retains recovery intent.
                    return _result("RECOVERY_UNCONFIRMED", error="; ".join(errors),
                                   data={"state": self.state, "attached": self._attached,
                                         "owned_resources_remaining": len(self._breakpoints) +
                                         len(self._changes) + len(self._suspensions)},
                                   limitations=["Local cleanup deferred because guardian shutdown was not confirmed."])
        # If running, an owned debug-break provides a consistent context for RIP/TF cleanup.
        if self._attached and self._event is None:
            try:
                self._pause_requested = True
                self._api.break_process()
                finish = time.monotonic() + 3
                while self._event is None and self._attached and time.monotonic() < finish:
                    self._pump(20)
                if self._attached and self._event is None:
                    errors.append("NO_CONFIRMED_STOP_FOR_CLEANUP")
            except BaseException as exc:
                record_caught_failure("DEBUG_STOP_FOR_CLEANUP", exc)
        if self._stepping:
            try:
                item = self._stepping
                handle, _ = self._api.thread(item["tid"], item["created_100ns"])
                try:
                    context = self._api.context(handle)
                    if not item["original_tf"]:
                        context.set32(68, context.get32(68) & ~0x100)
                        self._api.set_context(handle, context)
                        if self._api.context(handle).get32(68) & 0x100:
                            raise DebugError("RECOVERY_UNCONFIRMED", "TRAP_FLAG_RESTORE_READBACK_FAILED")
                finally:
                    self._api.k.CloseHandle(handle)
                self._stepping = None
            except BaseException as exc:
                record_caught_failure("TRAP_FLAG", exc)
        for identifier, item in list(self._breakpoints.items()):
            try:
                self._restore_breakpoint_context(item)
                current = self._api.read(item["address"], 1)
                original = bytes.fromhex(item["original_hex"])
                if current == b"\xcc":
                    self._api.replace(item["address"], current, original, executable=True,
                                      original_protection=item["original_protection"])
                elif current != original:
                    raise DebugError("RECOVERY_UNCONFIRMED", "BREAKPOINT_BYTE_CHANGED_EXTERNALLY")
                self._api.restore_executable_protection(item["address"], item["original_protection"])
                del self._breakpoints[identifier]
            except BaseException as exc:
                record_caught_failure("BREAKPOINT", exc)
        if (self._breakpoints or self._stepping) and self._attached and self._event is not None:
            # Continuing an owned INT3 at address+1 would knowingly execute
            # an unverified instruction stream. Unrestored TF, code bytes
            # and page protection likewise make execution unsafe. Keep the
            # event, debug owner and guardian alive for a cleanup retry.
            # Helper/service preserve only the original finite session lease.
            return self._retain_debug_owner("; ".join(errors),
                winerror=native_failures[0]["winerror"] if native_failures else None,
                native_failures=native_failures)
        for identifier in list(self._changes):
            try:
                item = self._changes[identifier]
                original = bytes.fromhex(item["original_hex"])
                current = self._api.read(item["address"], len(original))
                if current == original:
                    del self._changes[identifier]
                else:
                    self._rollback_memory({"change_id": identifier})
            except BaseException as exc:
                record_caught_failure("MEMORY_RESTORE", exc)
        for identifier in list(self._suspensions):
            try:
                self._resume({"suspension_id": identifier})
            except BaseException as exc:
                record_caught_failure("THREAD_RESUME", exc)
        if self._event is not None:
            event = self._event
            if not self._api.k.ContinueDebugEvent(event.pid, event.tid, self._event_continue):
                record_native_failure("CONTINUE_BEFORE_DETACH_FAILED")
            else:
                self._event = None
        if self._attached:
            if not self._api.k.DebugActiveProcessStop(self.identity.pid):
                record_native_failure("DEBUG_ACTIVE_PROCESS_STOP_FAILED")
            else:
                self._attached = False
                self._event = None
                self._owner_retained = False
                self._paused_breakpoint = None
                self._pause_requested = False
                if self._api.debug_handle:
                    self._api.k.CloseHandle(self._api.debug_handle)
                    self._api.debug_handle = None
        self.state = "RECOVERY_UNCONFIRMED" if errors else "DETACHED"
        if self._guard:
            try:
                self._sync_guard()
                self._guard.finish(clean=not errors)
                self._guard = None
            except BaseException as exc:
                errors.append(f"GUARDIAN: {exc}")
                self.state = "RECOVERY_UNCONFIRMED"
        for item in self._suspensions.values():
            if item.get("handle"):
                self._api.k.CloseHandle(item["handle"])
                item["handle"] = None
        return _result("RECOVERY_UNCONFIRMED" if errors else "COMPLETED",
                       data={"state": self.state, "attached": self._attached,
                             "owned_resources_remaining": len(self._breakpoints) + len(self._changes) + len(self._suspensions),
                             "native_cleanup_failures": native_failures},
                       error="; ".join(errors) if errors else None,
                       winerror=native_failures[0]["winerror"] if native_failures else None,
                       limitations=["Byte and suspension cleanup cannot reverse application-side effects."])
