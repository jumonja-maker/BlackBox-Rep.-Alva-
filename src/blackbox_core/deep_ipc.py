"""Local named-pipe transport with ACL, peer PID checks and finite I/O.

The random pipe name/nonce are not the authorization boundary: both endpoints
also verify the exact peer process instance. Remote pipe clients are refused.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
import json
import os
import struct
import time

from .deep_contracts import MAX_MESSAGE_BYTES, bounded_json


class IPCError(OSError):
    pass


def _kernel():
    if os.name != "nt":
        raise IPCError("UNSUPPORTED_PLATFORM")
    dll = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    dll.CloseHandle.argtypes = [W.HANDLE]
    dll.CloseHandle.restype = W.BOOL
    dll.ReadFile.argtypes = [W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p]
    dll.ReadFile.restype = W.BOOL
    dll.WriteFile.argtypes = [W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p]
    dll.WriteFile.restype = W.BOOL
    dll.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD, W.DWORD, W.HANDLE]
    dll.CreateFileW.restype = W.HANDLE
    dll.SetNamedPipeHandleState.argtypes = [W.HANDLE, C.POINTER(W.DWORD), C.c_void_p, C.c_void_p]
    dll.SetNamedPipeHandleState.restype = W.BOOL
    dll.GetNamedPipeClientProcessId.argtypes = [W.HANDLE, C.POINTER(W.ULONG)]
    dll.GetNamedPipeClientProcessId.restype = W.BOOL
    dll.GetNamedPipeServerProcessId.argtypes = [W.HANDLE, C.POINTER(W.ULONG)]
    dll.GetNamedPipeServerProcessId.restype = W.BOOL
    return dll


def check_deadline(deadline: float, cancel_event=None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise InterruptedError("DIAGNOSTIC_OPERATION_CANCELLED")
    if time.monotonic() >= deadline:
        raise TimeoutError("DIAGNOSTIC_OPERATION_TIMED_OUT")


def current_user_sid() -> str:
    kernel = _kernel()
    adv = C.WinDLL("advapi32", use_last_error=True, winmode=0x800)
    adv.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
    adv.OpenProcessToken.restype = W.BOOL
    adv.GetTokenInformation.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)]
    adv.GetTokenInformation.restype = W.BOOL
    adv.ConvertSidToStringSidW.argtypes = [C.c_void_p, C.POINTER(W.LPWSTR)]
    adv.ConvertSidToStringSidW.restype = W.BOOL
    kernel.GetCurrentProcess.restype = W.HANDLE
    kernel.LocalFree.argtypes = [C.c_void_p]
    kernel.LocalFree.restype = C.c_void_p
    token = W.HANDLE()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 0x8, C.byref(token)):
        raise IPCError(C.get_last_error(), "OPEN_GUI_TOKEN_FAILED")
    try:
        size = W.DWORD()
        adv.GetTokenInformation(token, 1, None, 0, C.byref(size))
        if not 0 < size.value <= 65536:
            raise IPCError("INVALID_TOKEN_USER_SIZE")
        buffer = C.create_string_buffer(size.value)
        if not adv.GetTokenInformation(token, 1, buffer, size, C.byref(size)):
            raise IPCError(C.get_last_error(), "TOKEN_USER_FAILED")
        sid_pointer = C.c_void_p.from_buffer(buffer).value
        text = W.LPWSTR()
        if not adv.ConvertSidToStringSidW(sid_pointer, C.byref(text)):
            raise IPCError(C.get_last_error(), "TOKEN_SID_FAILED")
        try:
            return text.value
        finally:
            kernel.LocalFree(C.cast(text, C.c_void_p))
    finally:
        kernel.CloseHandle(token)


def token_is_elevated() -> bool:
    if os.name != "nt":
        return False
    kernel = _kernel()
    adv = C.WinDLL("advapi32", use_last_error=True, winmode=0x800)
    adv.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
    adv.OpenProcessToken.restype = W.BOOL
    adv.GetTokenInformation.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)]
    adv.GetTokenInformation.restype = W.BOOL
    kernel.GetCurrentProcess.restype = W.HANDLE
    token, elevated, size = W.HANDLE(), W.DWORD(), W.DWORD()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 0x8, C.byref(token)):
        raise IPCError(C.get_last_error(), "OPEN_HELPER_TOKEN_FAILED")
    try:
        if not adv.GetTokenInformation(token, 20, C.byref(elevated), C.sizeof(elevated), C.byref(size)):
            raise IPCError(C.get_last_error(), "TOKEN_ELEVATION_QUERY_FAILED")
        return bool(elevated.value)
    finally:
        kernel.CloseHandle(token)


class PipeChannel:
    def __init__(self, handle: int):
        self.handle = handle
        self.kernel = _kernel()
        self._input = bytearray()
        self._frame_size = None

    def peer_pid(self, *, server: bool) -> int:
        pid = W.ULONG()
        api = self.kernel.GetNamedPipeClientProcessId if server else self.kernel.GetNamedPipeServerProcessId
        if not api(self.handle, C.byref(pid)):
            raise IPCError(C.get_last_error(), "PIPE_PEER_PID_UNAVAILABLE")
        return pid.value

    def _read(self, count: int, *, deadline: float, cancel_event=None) -> bytes:
        while len(self._input) < count:
            check_deadline(deadline, cancel_event)
            buffer = C.create_string_buffer(min(16384, count - len(self._input)))
            actual = W.DWORD()
            ok = self.kernel.ReadFile(self.handle, buffer, len(buffer), C.byref(actual), None)
            error = C.get_last_error() if not ok else 0
            if actual.value:
                self._input.extend(buffer.raw[:actual.value])
            elif ok or error in (232, 536):
                time.sleep(0.01)
            else:
                raise IPCError(error, "DIAGNOSTIC_PIPE_READ_FAILED")
        output = bytes(self._input[:count])
        del self._input[:count]
        return output

    def send(self, message: dict, *, deadline: float, cancel_event=None) -> None:
        raw = bounded_json(message)
        payload = struct.pack("<I", len(raw)) + raw
        offset = 0
        while offset < len(payload):
            check_deadline(deadline, cancel_event)
            chunk = payload[offset:offset + 16384]
            buffer = C.create_string_buffer(chunk)
            actual = W.DWORD()
            ok = self.kernel.WriteFile(self.handle, buffer, len(chunk), C.byref(actual), None)
            error = C.get_last_error() if not ok else 0
            if not ok:
                raise IPCError(error, "DIAGNOSTIC_PIPE_WRITE_FAILED")
            if actual.value:
                offset += actual.value
            else:
                time.sleep(0.01)

    def receive(self, *, deadline: float, cancel_event=None) -> dict:
        if self._frame_size is None:
            self._frame_size = struct.unpack("<I", self._read(4, deadline=deadline, cancel_event=cancel_event))[0]
        count = self._frame_size
        if not 0 < count <= MAX_MESSAGE_BYTES:
            raise IPCError("DIAGNOSTIC_FRAME_BUDGET_EXCEEDED")
        raw = self._read(count, deadline=deadline, cancel_event=cancel_event)
        self._frame_size = None
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise IPCError("DIAGNOSTIC_FRAME_NOT_OBJECT")
        return data

    def close(self) -> None:
        if self.handle is not None:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class PipeServer(PipeChannel):
    def __init__(self, name: str):
        if not name.startswith("\\\\.\\pipe\\BLACKBOX-DEEP-") or len(name) > 180:
            raise ValueError("INVALID_DIAGNOSTIC_PIPE_NAME")
        kernel = _kernel()
        adv = C.WinDLL("advapi32", use_last_error=True, winmode=0x800)
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [W.LPCWSTR, W.DWORD, C.POINTER(C.c_void_p), C.c_void_p]
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = W.BOOL
        kernel.CreateNamedPipeW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.DWORD, C.c_void_p]
        kernel.CreateNamedPipeW.restype = W.HANDLE
        kernel.LocalFree.argtypes = [C.c_void_p]
        kernel.LocalFree.restype = C.c_void_p
        class SecurityAttributes(C.Structure):
            _fields_ = [("length", W.DWORD), ("descriptor", C.c_void_p), ("inherit", W.BOOL)]
        descriptor = C.c_void_p()
        sid = current_user_sid()
        sddl = f"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})"
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, C.byref(descriptor), None):
            raise IPCError(C.get_last_error(), "PIPE_SECURITY_DESCRIPTOR_FAILED")
        try:
            security = SecurityAttributes(C.sizeof(SecurityAttributes), descriptor, False)
            # FIRST_PIPE_INSTANCE + PIPE_REJECT_REMOTE_CLIENTS + PIPE_NOWAIT.
            handle = kernel.CreateNamedPipeW(name, 0x3 | 0x80000, 0x8 | 0x1, 1,
                                            65536, 65536, 0, C.byref(security))
            if handle in (None, C.c_void_p(-1).value):
                raise IPCError(C.get_last_error(), "CREATE_DIAGNOSTIC_PIPE_FAILED")
        finally:
            kernel.LocalFree(descriptor)
        super().__init__(handle)
        self.name = name

    def accept(self, expected_pid: int, *, deadline: float, cancel_event=None) -> None:
        self.kernel.ConnectNamedPipe.argtypes = [W.HANDLE, C.c_void_p]
        self.kernel.ConnectNamedPipe.restype = W.BOOL
        while True:
            check_deadline(deadline, cancel_event)
            ok = self.kernel.ConnectNamedPipe(self.handle, None)
            error = C.get_last_error() if not ok else 0
            if ok or error == 535:
                # NOWAIT success can mean that an instance has become
                # available. A client PID is the proof that it is connected.
                pid = W.ULONG()
                if self.kernel.GetNamedPipeClientProcessId(self.handle, C.byref(pid)):
                    if pid.value != expected_pid:
                        raise IPCError("UNEXPECTED_DIAGNOSTIC_PIPE_CLIENT")
                    return
                if C.get_last_error() not in (232, 233, 536):
                    raise IPCError(C.get_last_error(), "PIPE_PEER_PID_UNAVAILABLE")
                time.sleep(0.01)
                continue
            if error not in (536, 232):
                raise IPCError(error, "CONNECT_DIAGNOSTIC_PIPE_FAILED")
            time.sleep(0.01)


def connect_pipe(name: str, expected_server_pid: int, *, deadline: float) -> PipeChannel:
    kernel = _kernel()
    kernel.WaitNamedPipeW.argtypes = [W.LPCWSTR, W.DWORD]
    kernel.WaitNamedPipeW.restype = W.BOOL
    while True:
        check_deadline(deadline)
        handle = kernel.CreateFileW(name, 0xC0000000, 0, None, 3, 0x100000 | 0x10000, None)
        if handle not in (None, C.c_void_p(-1).value):
            break
        if C.get_last_error() not in (2, 231):
            raise IPCError(C.get_last_error(), "OPEN_DIAGNOSTIC_PIPE_FAILED")
        kernel.WaitNamedPipeW(name, 100)
        time.sleep(0.01)
    channel = PipeChannel(handle)
    try:
        state = W.DWORD(1)  # PIPE_NOWAIT, byte read mode.
        if not kernel.SetNamedPipeHandleState(handle, C.byref(state), None, None):
            raise IPCError(C.get_last_error(), "SET_DIAGNOSTIC_PIPE_MODE_FAILED")
        if channel.peer_pid(server=False) != expected_server_pid:
            raise IPCError("UNEXPECTED_DIAGNOSTIC_PIPE_SERVER")
        return channel
    except BaseException:
        channel.close()
        raise
