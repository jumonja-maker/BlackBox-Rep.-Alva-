"""Finite same-token recovery guardian for one exact process instance.

Only inherited/duplicated pipes and an optional GUI-created report handle cross
this boundary. The guardian accepts no command lines, filenames or new targets.
It restores compare-matching owned bytes and at most our own suspension count.
"""
from __future__ import annotations

import ctypes
import argparse
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
from typing import Any

from .deep_contracts import ProcessIdentity
from .deep_debug import DebugError, MAX_WRITE, MAX_PRIVATE_BYTES, _WinAPI, _hex, _positive


MAX_MESSAGE = 512 * 1024
MAX_LIFETIME_SECONDS = 16 * 60


def _identity_dict(identity: ProcessIdentity) -> dict[str, Any]:
    return {"pid": identity.pid, "created_100ns": identity.created_100ns,
            "image_path": identity.image_path}


def _reader(stream: Any, output: queue.Queue[Any], maximum: int) -> None:
    try:
        while True:
            line = stream.readline(maximum + 1)
            if not line:
                output.put(None)
                return
            if len(line) > maximum or not line.endswith(b"\n"):
                output.put(ValueError("GUARDIAN_PROTOCOL_SIZE"))
                return
            output.put(json.loads(line.decode("utf-8")))
    except BaseException as exc:
        output.put(exc)


class RecoveryGuardian:
    def __init__(self, identity: ProcessIdentity, *, recovery_handle: int | None = None):
        self._closed = False
        self._sequence = 0
        self._messages: queue.Queue[Any] = queue.Queue(maxsize=8)
        self._lock = threading.Lock()
        executable = sys.executable
        if not getattr(sys, "frozen", False):
            windowed = Path(executable).with_name("pythonw.exe")
            if windowed.is_file():
                executable = str(windowed)
            arguments = [executable, "-m", "blackbox_core.deep_debug_guardian"]
        else:
            arguments = [executable, "--debug-guardian"]
        # A frozen --windowed application has no Python standard streams. Pass
        # only these two explicitly inherited pipe handles and open them in the
        # child, independently of console/CRT initialization.
        import msvcrt
        child_read, parent_write = os.pipe()
        parent_read, child_write = os.pipe()
        read_handle, write_handle = msvcrt.get_osfhandle(child_read), msvcrt.get_osfhandle(child_write)
        startup = subprocess.STARTUPINFO()
        startup.lpAttributeList = {"handle_list": [read_handle, write_handle]}
        child_environment = os.environ.copy()
        if not getattr(sys, "frozen", False):
            source_root = str(Path(__file__).resolve().parents[1])
            child_environment["PYTHONPATH"] = source_root + os.pathsep + child_environment.get("PYTHONPATH", "")
        try:
            os.set_handle_inheritable(read_handle, True)
            os.set_handle_inheritable(write_handle, True)
            self.process = subprocess.Popen(
                arguments + ["--guardian-input-handle", str(read_handle),
                             "--guardian-output-handle", str(write_handle)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                startupinfo=startup, close_fds=True, creationflags=0x00000008,
                env=child_environment)
        except BaseException:
            os.close(parent_write)
            os.close(parent_read)
            raise
        finally:
            os.close(child_read)
            os.close(child_write)
        self.process.stdin = os.fdopen(parent_write, "wb", buffering=0)
        self.process.stdout = os.fdopen(parent_read, "rb", buffering=8192)
        self.pid = self.process.pid
        threading.Thread(target=_reader, args=(self.process.stdout, self._messages, 8192),
                         daemon=True, name="blackbox-guardian-replies").start()
        api = _WinAPI(identity)
        child_handle = None
        local_parent = None
        duplicated = ctypes.c_void_p()
        try:
            from ctypes import wintypes as w
            api.k.DuplicateHandle.argtypes = [w.HANDLE, w.HANDLE, w.HANDLE,
                                              ctypes.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD]
            api.k.DuplicateHandle.restype = w.BOOL
            api.k.GetCurrentProcess.restype = w.HANDLE
            local_parent = api.k.OpenProcess(0x100000 | 0x1000, False, os.getpid())
            if not local_parent:
                api.fail("GUARDIAN_PARENT_IDENTITY")
            parent_created = api.creation(local_parent)
            if recovery_handle is not None:
                child_handle = api.k.OpenProcess(0x0040, False, self.pid)
                if not child_handle:
                    api.fail("GUARDIAN_OPEN_CHILD_FOR_DUPLICATE")
                if not api.k.DuplicateHandle(api.k.GetCurrentProcess(), recovery_handle,
                                             child_handle, ctypes.byref(duplicated), 0, False, 2):
                    api.fail("GUARDIAN_DUPLICATE_REPORT_HANDLE")
            self._send({"kind": "init", "identity": _identity_dict(identity),
                        "parent_pid": os.getpid(), "parent_created_100ns": parent_created,
                        "recovery_handle": duplicated.value})
        except BaseException:
            self.process.terminate()
            self.process.wait(timeout=5)
            raise
        finally:
            if local_parent:
                api.k.CloseHandle(local_parent)
            if child_handle:
                api.k.CloseHandle(child_handle)
            api.close()

    def _send(self, message: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if self._closed or self.process.poll() is not None:
                raise DebugError("RECOVERY_UNCONFIRMED", "RECOVERY_GUARDIAN_NOT_ALIVE")
            self._sequence += 1
            message["sequence"] = self._sequence
            encoded = json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
            if len(encoded) > MAX_MESSAGE:
                raise DebugError("LIMIT_REACHED", "RECOVERY_PLAN_TOO_LARGE")
            write_finished: queue.Queue[Any] = queue.Queue(maxsize=1)
            def write_message() -> None:
                try:
                    self.process.stdin.write(encoded)
                    self.process.stdin.flush()
                    write_finished.put(None)
                except BaseException as exc:
                    write_finished.put(exc)
            threading.Thread(target=write_message, daemon=True,
                             name="blackbox-guardian-plan-write").start()
            try:
                failure = write_finished.get(timeout=4)
            except queue.Empty as exc:
                self._closed = True
                raise DebugError("RECOVERY_UNCONFIRMED", "RECOVERY_GUARDIAN_WRITE_TIMEOUT") from exc
            if failure is not None:
                raise DebugError("RECOVERY_UNCONFIRMED", "RECOVERY_GUARDIAN_PIPE_FAILED") from failure
            try:
                reply = self._messages.get(timeout=4)
            except queue.Empty as exc:
                raise DebugError("RECOVERY_UNCONFIRMED", "RECOVERY_GUARDIAN_ACK_TIMEOUT") from exc
            if not isinstance(reply, dict) or reply.get("sequence") != self._sequence or reply.get("status") != "ACK":
                raise DebugError("RECOVERY_UNCONFIRMED", "RECOVERY_GUARDIAN_REJECTED_PLAN")
            return reply

    def update(self, plan: dict[str, Any]) -> None:
        validate_plan(plan)
        self._send({"kind": "plan", "plan": plan})

    def finish(self, *, clean: bool) -> None:
        reply = self._send({"kind": "finish", "clean": clean})
        self._closed = True
        self.process.stdin.close()
        self.process.wait(timeout=5)
        if self.process.stdout:
            self.process.stdout.close()
        if reply.get("recovery_status") == "RECOVERY_UNCONFIRMED":
            raise DebugError("RECOVERY_UNCONFIRMED", "GUARDIAN_RECOVERY_UNCONFIRMED")


def validate_plan(plan: Any) -> None:
    if not isinstance(plan, dict) or set(plan) != {"breakpoints", "changes", "suspensions", "stepping"}:
        raise ValueError("INVALID_RECOVERY_PLAN")
    total = 0
    for name, limit in (("breakpoints", 32), ("changes", 64), ("suspensions", 128)):
        items = plan[name]
        if not isinstance(items, list) or len(items) > limit:
            raise ValueError("RECOVERY_PLAN_COUNT")
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("INVALID_RECOVERY_ITEM")
            if name == "suspensions":
                _positive(item.get("tid"), "tid", 0xFFFFFFFF)
                _positive(item.get("created_100ns"), "created_100ns")
                if item.get("phase") not in ("pending", "active", "resuming"):
                    raise ValueError("INVALID_SUSPENSION_PHASE")
                if item["phase"] == "active" and (isinstance(item.get("previous_count"), bool) or
                                                  not isinstance(item.get("previous_count"), int) or
                                                  not 0 <= item["previous_count"] < 128):
                    raise ValueError("INVALID_SUSPENSION_COUNT")
            else:
                address = _positive(item.get("address"), "address", (1 << 47) - 1)
                original = _hex(item.get("original_hex"), "original_hex")
                if name == "breakpoints":
                    if len(original) != 1 or original == b"\xcc":
                        raise ValueError("INVALID_BREAKPOINT_RESTORE")
                    hit = item.get("hit_context")
                    if hit is not None:
                        if not isinstance(hit, dict) or hit.get("phase") not in ("rewind_pending", "rewind_verified"):
                            raise ValueError("INVALID_BREAKPOINT_HIT_CONTEXT")
                        _positive(hit.get("tid"), "tid", 0xFFFFFFFF)
                        _positive(hit.get("created_100ns"), "created_100ns")
                        _positive(hit.get("rip_before"), "rip_before", (1 << 47) - 1)
                else:
                    value = _hex(item.get("value_hex"), "value_hex")
                    if len(original) != len(value):
                        raise ValueError("INVALID_CHANGE_RESTORE_SIZE")
                if address + len(original) > 1 << 47:
                    raise ValueError("RECOVERY_ADDRESS_WRAP")
                total += len(original)
    if total > MAX_PRIVATE_BYTES + 32:
        raise ValueError("RECOVERY_PRIVATE_BYTES_BUDGET")
    step = plan["stepping"]
    if step is not None:
        if not isinstance(step, dict) or not isinstance(step.get("original_tf"), bool):
            raise ValueError("INVALID_STEP_RESTORE")
        _positive(step.get("tid"), "tid", 0xFFFFFFFF)
        _positive(step.get("created_100ns"), "created_100ns")


def recover(api: _WinAPI, plan: dict[str, Any], *, reason: str) -> dict[str, Any]:
    """No new debugging/injection; attempt only recorded, compare-matching cleanup."""
    validate_plan(plan)
    errors: list[str] = []
    restored = {"breakpoints": 0, "memory_changes": 0, "thread_suspensions": 0, "trap_flags": 0}
    try:
        api.verify()
    except DebugError as exc:
        return {"status": "RECOVERY_UNCONFIRMED", "reason": reason, "error": str(exc),
                "target_identity": _identity_dict(api.identity), "restored": restored}
    # Remove executable traps before resuming any thread held by this session.
    for item in plan["breakpoints"]:
        try:
            original = bytes.fromhex(item["original_hex"])
            current = api.read(item["address"], 1)
            if current == b"\xcc":
                api.replace(item["address"], current, original, executable=True)
            elif current != original:
                raise DebugError("RECOVERY_UNCONFIRMED", "BREAKPOINT_BYTES_CHANGED_EXTERNALLY")
            restored["breakpoints"] += 1
            # A debug event may arrive between the last acknowledged plan and
            # helper death. Bytes alone cannot establish the instruction pointer.
            if reason != "HELPER_REQUESTED_RECOVERY":
                errors.append("BREAKPOINT_EXECUTION_CONTEXT_RECOVERY_NOT_ESTABLISHED")
        except BaseException as exc:
            errors.append(f"BREAKPOINT: {exc}")
    for item in plan["changes"]:
        try:
            original, value = bytes.fromhex(item["original_hex"]), bytes.fromhex(item["value_hex"])
            current = api.read(item["address"], len(original))
            if current == value:
                api.replace(item["address"], value, original)
            elif current != original:
                raise DebugError("RECOVERY_UNCONFIRMED", "MEMORY_BYTES_CHANGED_EXTERNALLY")
            restored["memory_changes"] += 1
        except BaseException as exc:
            errors.append(f"MEMORY: {exc}")
    step = plan["stepping"]
    if step and not step["original_tf"]:
        handle = None
        incremented = False
        try:
            handle, _ = api.thread(step["tid"], step["created_100ns"], rights=0x001A)
            previous = api.k.SuspendThread(handle)
            if previous == 0xFFFFFFFF:
                api.fail("GUARDIAN_SUSPEND_FOR_CONTEXT")
            incremented = True
            context = api.context(handle)
            context.set32(68, context.get32(68) & ~0x100)
            api.set_context(handle, context)
            if api.context(handle).get32(68) & 0x100:
                raise DebugError("RECOVERY_UNCONFIRMED", "TRAP_FLAG_READBACK_FAILED")
            restored["trap_flags"] += 1
        except BaseException as exc:
            errors.append(f"TRAP_FLAG: {exc}")
        finally:
            if handle:
                if incremented and api.k.ResumeThread(handle) == 0xFFFFFFFF:
                    errors.append("GUARDIAN_OWN_CONTEXT_SUSPEND_NOT_RESUMED")
                api.k.CloseHandle(handle)
    for item in plan["suspensions"]:
        handle = None
        try:
            if item["phase"] != "active":
                raise DebugError("RECOVERY_UNCONFIRMED", "IN_FLIGHT_SUSPENSION_COUNT_UNKNOWN")
            handle, _ = api.thread(item["tid"], item["created_100ns"], rights=0x0002)
            previous = api.k.ResumeThread(handle)
            if previous in (0, 0xFFFFFFFF):
                raise DebugError("RECOVERY_UNCONFIRMED", "OWNED_RESUME_NOT_CONFIRMED")
            restored["thread_suspensions"] += 1
        except BaseException as exc:
            errors.append(f"THREAD: {exc}")
        finally:
            if handle:
                api.k.CloseHandle(handle)
    return {"status": "RECOVERY_UNCONFIRMED" if errors else "COMPLETED", "reason": reason,
            "target_identity": _identity_dict(api.identity), "restored": restored, "errors": errors,
            "limitations": ["Selected bytes and owned suspension decrements only; application execution is not reversible.",
                            "A debugger crash before kill-on-exit setup or during a native transition can remain unsafe."]}


def _write_report(handle: int | None, result: dict[str, Any]) -> None:
    if not handle:
        return
    import msvcrt
    descriptor = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
    with os.fdopen(descriptor, "wb", closefd=True) as stream:
        stream.seek(0)
        stream.write(json.dumps(result, ensure_ascii=True, sort_keys=True).encode("ascii")[:32768])
        stream.truncate()
        stream.flush()
        os.fsync(stream.fileno())


def main() -> int:
    if os.name != "nt":
        return 2
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--guardian-input-handle", type=int, required=True)
    parser.add_argument("--guardian-output-handle", type=int, required=True)
    options, remaining = parser.parse_known_args()
    if remaining not in ([], ["--debug-guardian"], ["--deep-debug-guardian"]):
        return 3
    import msvcrt
    input_handle = _positive(options.guardian_input_handle, "guardian_input_handle")
    output_handle = _positive(options.guardian_output_handle, "guardian_output_handle")
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    kernel.GetFileType.argtypes, kernel.GetFileType.restype = [w.HANDLE], w.DWORD
    if kernel.GetFileType(input_handle) != 3 or kernel.GetFileType(output_handle) != 3:
        return 3
    input_stream = os.fdopen(msvcrt.open_osfhandle(input_handle, os.O_RDONLY | os.O_BINARY), "rb", buffering=65536)
    output_stream = os.fdopen(msvcrt.open_osfhandle(output_handle, os.O_WRONLY | os.O_BINARY), "wb", buffering=0)
    def reply(value: dict[str, Any]) -> None:
        output_stream.write(json.dumps(value, ensure_ascii=True).encode("ascii") + b"\n")
        output_stream.flush()
    incoming: queue.Queue[Any] = queue.Queue(maxsize=8)
    threading.Thread(target=_reader, args=(input_stream, incoming, MAX_MESSAGE),
                     daemon=True, name="blackbox-guardian-input").start()
    api = None
    parent = None
    recovery_handle = None
    plan: dict[str, Any] = {"breakpoints": [], "changes": [], "suspensions": [], "stepping": None}
    sequence = 0
    result: dict[str, Any] | None = None
    try:
        initial = incoming.get(timeout=10)
        if not isinstance(initial, dict) or initial.get("kind") != "init" or initial.get("sequence") != 1:
            return 3
        identity = ProcessIdentity.from_dict(initial["identity"])
        api = _WinAPI(identity)
        parent_pid = _positive(initial.get("parent_pid"), "parent_pid", 0xFFFFFFFF)
        parent_created = _positive(initial.get("parent_created_100ns"), "parent_created_100ns")
        parent = api.k.OpenProcess(0x100000 | 0x1000, False, parent_pid)
        if not parent or api.creation(parent) != parent_created:
            raise ValueError("GUARDIAN_PARENT_IDENTITY_MISMATCH")
        # Compare actual creator PID; command-line parent claims alone are not proof.
        import psutil
        if psutil.Process(os.getpid()).ppid() != parent_pid:
            raise ValueError("GUARDIAN_NOT_OWNED_BY_DECLARED_PARENT")
        recovery_handle = initial.get("recovery_handle")
        if recovery_handle is not None:
            _positive(recovery_handle, "recovery_handle")
        sequence = 1
        reply({"status": "ACK", "sequence": sequence})
        finish_at = time.monotonic() + MAX_LIFETIME_SECONDS
        while True:
            if api.k.WaitForSingleObject(parent, 0) != 0x102:
                result = recover(api, plan, reason="HELPER_EXITED")
                break
            if time.monotonic() >= finish_at:
                result = recover(api, plan, reason="GUARDIAN_DEADLINE")
                break
            try:
                message = incoming.get(timeout=0.025)
            except queue.Empty:
                continue
            if not isinstance(message, dict):
                result = recover(api, plan, reason="HELPER_PIPE_CLOSED_OR_INVALID")
                break
            if message.get("sequence") != sequence + 1:
                raise ValueError("GUARDIAN_SEQUENCE_MISMATCH")
            sequence += 1
            kind = message.get("kind")
            if kind == "plan":
                validate_plan(message.get("plan"))
                plan = message["plan"]
                reply({"status": "ACK", "sequence": sequence})
            elif kind == "finish":
                remaining = bool(plan["breakpoints"] or plan["changes"] or plan["suspensions"] or plan["stepping"])
                if message.get("clean") is True and not remaining:
                    result = {"status": "COMPLETED", "reason": "NORMAL_HELPER_CLEANUP",
                              "target_identity": _identity_dict(identity), "owned_resources_remaining": 0}
                else:
                    result = recover(api, plan, reason="HELPER_REQUESTED_RECOVERY")
                _write_report(recovery_handle, result)
                recovery_handle = None
                reply({"status": "ACK", "sequence": sequence, "recovery_status": result["status"]})
                break
            else:
                raise ValueError("GUARDIAN_COMMAND_NOT_ALLOWED")
        _write_report(recovery_handle, result)
        recovery_handle = None
        return 0 if result.get("status") == "COMPLETED" else 4
    except BaseException as exc:
        if api:
            try:
                result = recover(api, plan, reason="GUARDIAN_PROTOCOL_FAILURE")
                result["protocol_error"] = type(exc).__name__
                result["status"] = "RECOVERY_UNCONFIRMED"
                _write_report(recovery_handle, result)
                recovery_handle = None
            except BaseException:
                pass
        return 5
    finally:
        if api:
            if parent:
                api.k.CloseHandle(parent)
            if recovery_handle:
                api.k.CloseHandle(recovery_handle)
            api.close()
        output_stream.close()


if __name__ == "__main__":
    raise SystemExit(main())
