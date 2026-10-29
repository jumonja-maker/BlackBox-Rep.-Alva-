"""Explicit system-wide ETW capture with an isolated elevated output boundary.

WPR writes only into a random administrator-owned directory. A separate owner
retains that directory and the named recording until helper completion, EOF or
a finite lease. The final user-selected path is never opened while elevated:
only the GUI's already-created and authenticated file HANDLE is written.
"""
from __future__ import annotations

import ctypes as C
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
from uuid import UUID, uuid4

from . import deep_native_win as W
from .deep_contracts import ProcessIdentity, result
from .deep_native import NativeError, _check, _integer, _os_error, verify_identity

PROFILE = "GeneralProfile.Light"
MAX_TRACE_BYTES = 256 * 1024**2
STAGING_SDDL = "O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"
_STAGE_NAME = re.compile(r"BLACKBOX-Deep-[0-9a-f]{32}\Z")
_JOURNAL_NAME = re.compile(r"BLACKBOX_[0-9a-f]{32}\.trace\.json\Z")
_FILE_NAME = re.compile(r"(?:BLACKBOX_[0-9a-f]{32}\.trace\.json(?:\.[0-9a-f]{32}\.tmp)?|trace-[0-9a-f]{32}\.etl)\Z")


def validate_policy(parameters):
    allowed = {"duration_seconds", "profile", "systemwide_confirmed"}
    if not isinstance(parameters, dict) or set(parameters) - allowed:
        raise ValueError("INVALID_ETW_PARAMETERS")
    seconds = _integer(parameters.get("duration_seconds", 5), "duration_seconds", 1, 30)
    if parameters.get("profile", PROFILE) != PROFILE:
        raise ValueError("INVALID_ETW_PROFILE")
    if parameters.get("systemwide_confirmed") is not True:
        raise NativeError("CONFIRMATION_REQUIRED", "SYSTEM_WIDE_TRACE_CONFIRMATION_REQUIRED")
    return seconds


class _SecurityAttributes(C.Structure):
    _fields_ = [("size", W.U32), ("descriptor", W.PTR), ("inherit", W.BOOL)]


class _FileInfo(C.Structure):
    _fields_ = [("attributes", W.U32), ("created", W.FILETIME),
                ("accessed", W.FILETIME), ("written", W.FILETIME),
                ("volume", W.U32), ("size_high", W.U32), ("size_low", W.U32),
                ("links", W.U32), ("index_high", W.U32), ("index_low", W.U32)]


def _known_program_data():
    # The elevated helper must never trust inherited ProgramData/SystemRoot.
    shell = W.library("shell32")
    ole = W.library("ole32")
    get = W.bind(shell, "SHGetKnownFolderPath", W.I32, W.PTR, W.U32, W.HANDLE, C.POINTER(W.PTR))
    free = W.bind(ole, "CoTaskMemFree", None, W.PTR)
    guid = C.create_string_buffer(UUID("62ab5d82-fdc1-4dc3-a9dd-070d1d495d97").bytes_le)
    output = W.PTR()
    code = get(guid, 0, None, C.byref(output))
    if code < 0 or not output.value:
        raise NativeError("OPERATION_FAILED", "KNOWN_PROGRAM_DATA_UNAVAILABLE", code)
    try:
        path = Path(C.wstring_at(output))
        if not path.is_absolute():
            raise ValueError("PROGRAM_DATA_NOT_ABSOLUTE")
        return path
    finally:
        free(output)


def _trusted_wpr():
    kernel = W.library("kernel32")
    get = W.bind(kernel, "GetSystemDirectoryW", W.U32, C.c_wchar_p, W.U32)
    buffer = C.create_unicode_buffer(32768)
    count = get(buffer, len(buffer))
    if not 0 < count < len(buffer):
        raise _os_error("SYSTEM_DIRECTORY_UNAVAILABLE")
    path = Path(buffer.value) / "wpr.exe"
    attrs = W.bind(kernel, "GetFileAttributesW", W.U32, C.c_wchar_p)(str(path))
    if attrs == 0xFFFFFFFF or attrs & (0x400 | 0x10):
        raise NativeError("OPERATION_FAILED", "SYSTEM_WPR_TOOL_UNAVAILABLE")
    return str(path)


class ProtectedStaging:
    """A pinned, non-reparse, BA-owned direct child of real ProgramData."""
    def __init__(self, path=None):
        self.kernel = W.Kernel()
        self.path = None
        self.handles = []
        self.created = False
        self.root = _known_program_data()
        self._create_file = W.bind(self.kernel.dll, "CreateFileW", W.HANDLE,
                                  C.c_wchar_p, W.U32, W.U32, W.PTR, W.U32, W.U32, W.HANDLE)
        self._info = W.bind(self.kernel.dll, "GetFileInformationByHandle", W.BOOL,
                           W.HANDLE, C.POINTER(_FileInfo))
        try:
            # Pin every ancestor before creating/opening the stage. Sharing
            # excludes DELETE so an unprivileged caller cannot rename it.
            for parent in reversed((self.root, *self.root.parents)):
                self._pin(parent)
            if path is None:
                self.path = self.root / ("BLACKBOX-Deep-" + uuid4().hex)
                self._create()
                self.created = True
            else:
                self.path = Path(path)
                if (self.path.parent != self.root or not _STAGE_NAME.fullmatch(self.path.name)):
                    raise ValueError("INVALID_PROTECTED_TRACE_DIRECTORY")
            handle = self._pin(self.path)
            self._validate_acl(handle)
        except BaseException:
            self.close()
            if self.created and self.path is not None:
                try:
                    self.path.rmdir()
                except OSError:
                    pass
            raise

    def _pin(self, path):
        # FILE_LIST_DIRECTORY establishes a read access in Windows share
        # accounting. Metadata-only FILE_READ_ATTRIBUTES/READ_CONTROL handles
        # do not prevent rename/delete merely by omitting FILE_SHARE_DELETE.
        # Retain attributes/security queries and open the reparse point itself.
        handle = self._create_file(str(path), 0x1 | 0x80 | 0x20000, 1 | 2, None, 3,
                                   0x02000000 | 0x00200000, None)
        if not handle or handle == W.INVALID_HANDLE:
            raise _os_error("PROTECTED_TRACE_DIRECTORY_OPEN_FAILED")
        info = _FileInfo()
        if (not self._info(handle, C.byref(info)) or
                not info.attributes & 0x10 or info.attributes & 0x400):
            self.kernel.close(handle)
            raise NativeError("ACCESS_DENIED", "TRACE_DIRECTORY_REPARSE_OR_IDENTITY_INVALID")
        self.handles.append(handle)
        return handle

    def _create(self):
        adv = W.library("advapi32")
        convert = W.bind(adv, "ConvertStringSecurityDescriptorToSecurityDescriptorW", W.BOOL,
                         C.c_wchar_p, W.U32, C.POINTER(W.PTR), W.PTR)
        create = W.bind(self.kernel.dll, "CreateDirectoryW", W.BOOL, C.c_wchar_p,
                        C.POINTER(_SecurityAttributes))
        free = W.bind(self.kernel.dll, "LocalFree", W.PTR, W.PTR)
        sd = W.PTR()
        if not convert(STAGING_SDDL, 1, C.byref(sd), None):
            raise _os_error("PROTECTED_TRACE_DACL_BUILD_FAILED")
        try:
            sa = _SecurityAttributes(C.sizeof(_SecurityAttributes), sd, False)
            if not create(str(self.path), C.byref(sa)):
                raise _os_error("PROTECTED_TRACE_DIRECTORY_CREATE_FAILED")
        finally:
            free(sd)

    def _validate_acl(self, handle):
        adv = W.library("advapi32")
        get = W.bind(adv, "GetSecurityInfo", W.U32, W.HANDLE, W.U32, W.U32,
                     C.POINTER(W.PTR), W.PTR, C.POINTER(W.PTR), W.PTR, C.POINTER(W.PTR))
        control = W.bind(adv, "GetSecurityDescriptorControl", W.BOOL, W.PTR,
                         C.POINTER(W.U16), C.POINTER(W.U32))
        to_sid = W.bind(adv, "ConvertSidToStringSidW", W.BOOL, W.PTR, C.POINTER(W.PTR))
        ace = W.bind(adv, "GetAce", W.BOOL, W.PTR, W.U32, C.POINTER(W.PTR))
        free = W.bind(self.kernel.dll, "LocalFree", W.PTR, W.PTR)
        owner, dacl, sd = W.PTR(), W.PTR(), W.PTR()
        code = get(handle, 1, 1 | 4, C.byref(owner), None, C.byref(dacl), None, C.byref(sd))
        if code:
            raise _os_error("PROTECTED_TRACE_DACL_QUERY_FAILED", code)
        def sid_string(pointer):
            value = W.PTR()
            if not to_sid(pointer, C.byref(value)):
                raise _os_error("PROTECTED_TRACE_SID_INVALID")
            try:
                return C.wstring_at(value)
            finally:
                free(value)
        try:
            flags, revision = W.U16(), W.U32()
            if (not owner.value or not dacl.value or
                    not control(sd, C.byref(flags), C.byref(revision)) or
                    not flags.value & 0x1000 or sid_string(owner) != "S-1-5-32-544"):
                raise NativeError("ACCESS_DENIED", "PROTECTED_TRACE_OWNER_OR_DACL_INVALID")
            # ACL header: byte revision, byte reserved, WORD size, WORD count.
            count = C.c_uint16.from_address(dacl.value + 4).value
            observed = set()
            if count != 2:
                raise NativeError("ACCESS_DENIED", "PROTECTED_TRACE_DACL_HAS_UNEXPECTED_ACES")
            for index in range(count):
                item = W.PTR()
                if not ace(dacl, index, C.byref(item)):
                    raise _os_error("PROTECTED_TRACE_ACE_INVALID")
                header = (C.c_ubyte * 4).from_address(item.value)
                mask = W.U32.from_address(item.value + 4).value
                if header[0] != 0 or header[1] != 3 or mask != 0x1F01FF:
                    raise NativeError("ACCESS_DENIED", "PROTECTED_TRACE_ACE_PERMISSIONS_INVALID")
                observed.add(sid_string(item.value + 8))
            if observed != {"S-1-5-32-544", "S-1-5-18"}:
                raise NativeError("ACCESS_DENIED", "PROTECTED_TRACE_DACL_PRINCIPALS_INVALID")
        finally:
            free(sd)

    def close(self):
        for handle in reversed(self.handles):
            self.kernel.close(handle)
        self.handles.clear()

    def cleanup(self):
        # Files are never opened through recursively traversed user paths.
        # Refuse foreign directories/entries instead of deleting recursively.
        failures = []
        if self.path is not None:
            try:
                for item in self.path.iterdir():
                    attrs = W.bind(self.kernel.dll, "GetFileAttributesW", W.U32, C.c_wchar_p)(str(item))
                    if (not _FILE_NAME.fullmatch(item.name) or attrs == 0xFFFFFFFF or attrs & (0x10 | 0x400)):
                        failures.append("UNEXPECTED_STAGING_ENTRY")
                        continue
                    try:
                        item.unlink()
                    except OSError:
                        failures.append("STAGING_FILE_DELETE_FAILED")
            except OSError:
                failures.append("STAGING_ENUMERATION_FAILED")
        self.close()
        if self.path is not None and not failures:
            try:
                self.path.rmdir()
            except OSError:
                failures.append("STAGING_DIRECTORY_DELETE_FAILED")
        return failures


def _capture_factory(folder, *, profile):
    from .windows_research import WprCapture
    capture = WprCapture(folder, profile=profile)
    capture.tool = _trusted_wpr()
    return capture


def _native_lease(event):
    """Read only the inherited stdin HANDLE, including windowed helpers."""
    try:
        kernel = W.Kernel()
        get = W.bind(kernel.dll, "GetStdHandle", W.HANDLE, W.U32)
        read = W.bind(kernel.dll, "ReadFile", W.BOOL, W.HANDLE, W.PTR, W.U32, C.POINTER(W.U32), W.PTR)
        count, byte = W.U32(), C.create_string_buffer(1)
        read(get(0xFFFFFFF6), byte, 1, C.byref(count), None)
    finally:
        # Any byte, EOF, or broken pipe finishes the owner's finite lease.
        event.set()


def owner_main(arguments=None):
    """Separate named WPR owner; crash EOF also removes protected staging."""
    from .deep_ipc import token_is_elevated
    from .trace_owner import _read, run
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) != 1 or os.name != "nt" or not token_is_elevated():
        return 2
    journal = Path(arguments[0])
    if not _JOURNAL_NAME.fullmatch(journal.name):
        return 2
    stage = ProtectedStaging(journal.parent)
    lost = threading.Event()
    thread = threading.Thread(target=_native_lease, args=(lost,), name="deep-trace-lease", daemon=True)
    thread.start()
    code = 1
    cleanup = []
    uncertain_capture = False
    try:
        data = _read(journal)
        policy = data.get("policy", {})
        validate_policy({"duration_seconds": policy.get("duration_s"), "profile": policy.get("profile"),
                         "systemwide_confirmed": data.get("consent") == "EXPLICIT_USER_COMMAND"})
        if policy.get("max_output_bytes") != MAX_TRACE_BYTES:
            raise ValueError("INVALID_PROTECTED_TRACE_BUDGET")
        if not lost.is_set():
            verify_identity(ProcessIdentity.from_dict(data["target"]))
            # If a guardian fails without publishing a terminal state, retain
            # its protected journal for explicit named-instance recovery.
            uncertain_capture = True
            code = run(journal, capture_factory=_capture_factory, lease_lost=lost)
            terminal = _read(journal)
            uncertain_capture = terminal.get("state") not in ("COMPLETED", "FAILED")
            # Allow the helper to copy and read back the completed output.
            # Parent death/explicit completion closes stdin; a hung helper
            # cannot retain privileged data indefinitely.
            lost.wait(60)
    finally:
        if uncertain_capture:
            stage.close()
            cleanup = ["NAMED_CAPTURE_RECOVERY_UNCONFIRMED"]
        else:
            cleanup = stage.cleanup()
    return code if not cleanup else 3


def _copy_verified(kernel, file_handle, path, *, deadline, cancel_event):
    initial = W.I64()
    if kernel.file_type(file_handle) != 1 or not kernel.file_size(file_handle, C.byref(initial)) or initial.value:
        raise ValueError("ETW_REQUIRES_EMPTY_REGULAR_FILE_HANDLE")
    size = path.stat().st_size
    if not 1 <= size <= MAX_TRACE_BYTES:
        raise NativeError("LIMIT_REACHED", "ETW_OUTPUT_BUDGET_EXCEEDED")
    digest, copied = hashlib.sha256(), 0
    if not kernel.file_pointer(file_handle, 0, None, 0):
        raise _os_error("ETW_OUTPUT_SEEK_FAILED")
    with path.open("rb") as source:
        while True:
            _check(deadline, cancel_event)
            block = source.read(1024 * 1024)
            if not block:
                break
            if copied + len(block) > MAX_TRACE_BYTES:
                raise NativeError("LIMIT_REACHED", "ETW_OUTPUT_CHANGED_OR_EXCEEDED_BUDGET")
            count = W.U32()
            buffer = C.create_string_buffer(block)
            if (not kernel.write_file(file_handle, buffer, len(block), C.byref(count), None) or
                    count.value != len(block)):
                raise _os_error("ETW_USER_OUTPUT_WRITE_FAILED")
            digest.update(block)
            copied += len(block)
    if copied != size or not kernel.flush_file(file_handle):
        raise NativeError("INCOMPLETE_EVIDENCE", "ETW_OUTPUT_FLUSH_OR_LENGTH_UNCONFIRMED")
    if not kernel.file_pointer(file_handle, 0, None, 0):
        raise _os_error("ETW_OUTPUT_READBACK_SEEK_FAILED")
    read = W.bind(kernel.dll, "ReadFile", W.BOOL, W.HANDLE, W.PTR, W.U32, C.POINTER(W.U32), W.PTR)
    actual, readback = hashlib.sha256(), 0
    buffer, count = C.create_string_buffer(1024 * 1024), W.U32()
    while readback < copied:
        _check(deadline, cancel_event)
        wanted = min(len(buffer), copied - readback)
        if not read(file_handle, buffer, wanted, C.byref(count), None) or count.value != wanted:
            raise _os_error("ETW_OUTPUT_READBACK_FAILED")
        actual.update(buffer.raw[:wanted])
        readback += wanted
    final = W.I64()
    if (not kernel.file_size(file_handle, C.byref(final)) or final.value != copied or
            actual.digest() != digest.digest()):
        raise NativeError("INCOMPLETE_EVIDENCE", "ETW_OUTPUT_READBACK_MISMATCH")
    return {"trace_bytes": copied, "sha256": digest.hexdigest(), "saved_verified": True,
            "max_output_bytes": MAX_TRACE_BYTES, "size_policy": "CHECKED_AFTER_WPR_MEMORY_MODE_FLUSH"}


def capture_etw(target, parameters, *, file_handle, deadline, cancel_event=None):
    from .deep_ipc import token_is_elevated
    from .trace_owner import TraceSupervisor, _read, _write
    seconds = validate_policy(parameters)
    target = ProcessIdentity.from_dict(target)
    if os.name != "nt":
        return result("profile.etw", "UNSUPPORTED_PLATFORM", error="WINDOWS_ETW_REQUIRED")
    if not token_is_elevated():
        return result("profile.etw", "ADMIN_REQUIRED", error="SYSTEM_WPR_REQUIRES_ELEVATED_HELPER",
                      next_action="REQUEST_UAC_FOR_THIS_OPERATION")
    _integer(file_handle, "file_handle", 1)
    _check(deadline, cancel_event)
    verify_identity(target)
    kernel = W.Kernel()
    # Validate the supplied duplicate before privileged capture starts.
    initial = W.I64()
    if kernel.file_type(file_handle) != 1 or not kernel.file_size(file_handle, C.byref(initial)) or initial.value:
        raise ValueError("ETW_REQUIRES_EMPTY_REGULAR_FILE_HANDLE")
    stage = ProtectedStaging()
    supervisor = None
    process = None
    response = None
    try:
        supervisor = TraceSupervisor(stage.path, seconds=seconds, max_output_bytes=MAX_TRACE_BYTES,
                                     target=target.to_dict(), profile=PROFILE,
                                     session_path=stage.path / "no-session-v2.sqlite3")
        # Existing TraceSupervisor policy/journal and named-capture ownership
        # are reused; this route additionally pins and cleans protected files.
        with supervisor.path.open("xb"):
            pass
        _write(supervisor.path, supervisor.data)
        arguments = ([sys.executable, "--deep-trace-owner", str(supervisor.path)] if getattr(sys, "frozen", False)
                     else [sys.executable, "-m", "blackbox_core.deep_profiling", str(supervisor.path)])
        child_environment = os.environ.copy()
        if not getattr(sys, "frozen", False):
            # The source helper inserts src only into its own sys.path. Its
            # independent owner must also find the checked-out package when
            # launched outside an editable installation.
            child_environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env=child_environment,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        supervisor.process = process
        # Owner now pins stage independently. Helper retains pins until copy.
        while True:
            _check(deadline, cancel_event)
            verify_identity(target)
            current = _read(supervisor.path)
            if current.get("instance") != supervisor.instance:
                raise NativeError("RECOVERY_UNCONFIRMED", "TRACE_OWNER_IDENTITY_MISMATCH")
            state = current.get("state")
            if state in ("COMPLETED", "FAILED", "CLEANUP_REQUIRED"):
                break
            if process.poll() is not None:
                raise NativeError("RECOVERY_UNCONFIRMED", "TRACE_OWNER_EXITED_BEFORE_TERMINAL_JOURNAL")
            if cancel_event is not None:
                cancel_event.wait(.1)
            else:
                time.sleep(.1)
        if state != "COMPLETED":
            status = "RECOVERY_UNCONFIRMED" if state == "CLEANUP_REQUIRED" else "OPERATION_FAILED"
            response = result("profile.etw", status, error=current.get("error", "WPR_CAPTURE_FAILED"),
                              data={"instance": supervisor.instance, "cleanup": current.get("cleanup")})
        else:
            captured = current.get("result", {})
            name = captured.get("path", "")
            if not isinstance(name, str) or not re.fullmatch(r"trace-[0-9a-f]{32}\.etl", name):
                raise NativeError("INCOMPLETE_EVIDENCE", "UNTRUSTED_TRACE_OUTPUT_NAME")
            copied = _copy_verified(kernel, file_handle, stage.path / name, deadline=deadline, cancel_event=cancel_event)
            if copied["sha256"] != captured.get("sha256"):
                raise NativeError("INCOMPLETE_EVIDENCE", "TRACE_OWNER_COPY_HASH_MISMATCH")
            copied.update(instance=supervisor.instance, duration_seconds=seconds, profile=PROFILE,
                          scope="SYSTEM_WIDE_MAY_INCLUDE_OTHER_PROCESSES", target=target.to_dict(),
                          target_relation="CAPTURE_SELECTION_ONLY_NOT_PID_EVENT_CORRELATION_PROOF",
                          lost_events=None, automatic_share_allowed=False)
            response = result("profile.etw", "COMPLETED", data=copied, source="ETW_WPR_NAMED_PROTECTED_CAPTURE",
                              limitations=["SYSTEM_WIDE_TRACE_INCLUDES_OTHER_PROCESSES",
                                           "LOSS_AND_CLOCK_ALIGNMENT_REQUIRE_DECODER_EVIDENCE",
                                           "STAGING_SIZE_CHECKED_AFTER_FLUSH_NOT_HARD_DISK_QUOTA"])
    except Exception as exc:
        status = ("CANCELLED" if isinstance(exc, InterruptedError) else
                  "TIMED_OUT" if isinstance(exc, TimeoutError) else
                  getattr(exc, "status", "OPERATION_FAILED"))
        response = result("profile.etw", status,
                          error=str(exc)[:1000], winerror=getattr(exc, "winerror", None),
                          data={"instance": supervisor.instance if supervisor else None,
                                "saved_verified": False})
    finally:
        # Release helper pins before notifying owner: its cleanup must be
        # able to remove the directory. It alone retains a pin until removal.
        stage.close()
        if supervisor is not None:
            supervisor.request_stop()
        if process is not None:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                # Never kill the WPR owner: EOF + its finite command limits
                # must finish our named session even when helper is killed.
                pass
        if process is None:
            cleanup = stage.cleanup()
        elif process.poll() is not None:
            cleanup = [] if process.returncode in (0, 1) and not stage.path.exists() else ["STAGING_OR_CAPTURE_CLEANUP_UNCONFIRMED"]
        else:
            cleanup = ["NAMED_TRACE_OWNER_STILL_STOPPING"]
        if response is not None:
            response.setdefault("data", {})["cleanup"] = "CONFIRMED" if not cleanup else cleanup
            if cleanup:
                response["status"] = "RECOVERY_UNCONFIRMED"
                response["limitations"] = list(response.get("limitations", [])) + cleanup
    return response


if __name__ == "__main__":
    raise SystemExit(owner_main())
