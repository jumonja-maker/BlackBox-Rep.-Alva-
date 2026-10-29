"""Finite, explicitly scoped diagnostic worker. No arbitrary command execution."""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
import hmac
import os
import threading
import time

from .deep_contracts import (ActionRequest, DEEP_ACTIONS, MAX_SESSION_SECONDS,
                             ProcessIdentity, bounded_json, result, validate_profile_parameters)
from .deep_ipc import check_deadline, connect_pipe, token_is_elevated

_FORBIDDEN_PARAMETERS = frozenset({"handle", "file_handle", "recovery_handle", "source_handle",
                                  "source_file_handle", "command", "shell", "executable", "argv"})
LOCAL_OPERATIONS = frozenset({"timeline", "compare", "trace_evidence", "dump_inspect",
                             "dump_read_memory", "symbols_verify"})


def validate_parameters(parameters: dict) -> None:
    if _FORBIDDEN_PARAMETERS.intersection(parameters) or any(k.startswith("_") for k in parameters):
        raise ValueError("UNTRUSTED_NATIVE_HANDLE_OR_COMMAND")


class DiagnosticActionEngine:
    """Worker-owned coordination, independent of the sampling subsystem."""
    def __init__(self, target: ProcessIdentity, operations: list[str], *, recovery_handle=None,
                 inspector_factory=None, debug_factory=None, controller_pid=None):
        from .deep_native import ProcessInspector
        self.target = ProcessIdentity.from_dict(target)
        self.operations = frozenset(operations)
        if not self.operations or not self.operations <= DEEP_ACTIONS.keys() or self.operations & LOCAL_OPERATIONS:
            raise ValueError("INVALID_DIAGNOSTIC_SCOPE")
        self.inspector = (inspector_factory or ProcessInspector)(self.target)
        self.debug_factory = debug_factory
        self.debug = None
        self.recovery_handle = recovery_handle
        self.interventions_started = False
        self.profile_recovery = []
        self.controller_pid = controller_pid

    def execute(self, request: ActionRequest, *, cancel_event=None, file_handle=None) -> dict:
        from .deep_native import verify_identity
        if request.target != self.target:
            return result(request.operation, "PROCESS_CHANGED", error="SESSION_TARGET_IDENTITY_MISMATCH")
        if request.operation not in self.operations:
            return result(request.operation, "ACCESS_DENIED", error="OPERATION_OUTSIDE_APPROVED_SESSION_SCOPE",
                          next_action="END_SESSION_AND_APPROVE_A_NEW_OPERATION_SCOPE")
        validate_parameters(request.parameters)
        spec = DEEP_ACTIONS[request.operation]
        if spec.confirmation_required and not request.confirmed:
            return result(request.operation, "CONFIRMATION_REQUIRED", error="EXPLICIT_ACTION_CONFIRMATION_REQUIRED",
                          next_action="REVIEW_TARGET_PARAMETERS_AND_IMPACT")
        deadline = time.monotonic() + request.timeout_seconds
        check_deadline(deadline, cancel_event)
        verified = verify_identity(self.target)
        if isinstance(verified, dict) and verified.get("status") not in (None, "AVAILABLE", "COMPLETED", "OK"):
            return verified
        own_controllers = {os.getpid(), self.controller_pid}
        if spec.mode == "INTERVENE" and request.operation != "profile.etw" and self.target.pid in own_controllers:
            return result(request.operation, "OPERATION_FAILED", error="CONTROL_PROCESS_INTERVENTION_UNSAFE",
                          next_action="USE_A_SEPARATE_BLACKBOX_INSTANCE_TO_CONTROL_THIS_PROCESS",
                          limitations=["Stopping this session's GUI or helper would remove its control and cleanup path."])
        parameters = dict(request.parameters)
        if "length" in parameters and "size" not in parameters:
            parameters["size"] = parameters.pop("length")
        if request.operation in ("dump", "profile.etw"):
            if not file_handle:
                return result(request.operation, "ACCESS_DENIED", error="GUI_CREATED_OUTPUT_HANDLE_REQUIRED")
            if request.operation == "dump":
                parameters["file_handle"] = file_handle
        if request.operation == "capabilities":
            from .deep_native import probe_access
            names = parameters.get("operations", sorted(self.operations))
            if (set(parameters) - {"operations"} or not isinstance(names, list) or not names
                    or any(not isinstance(name, str) for name in names)
                    or len(names) > len(DEEP_ACTIONS) or len(names) != len(set(names))
                    or not set(names) <= self.operations):
                raise ValueError("INVALID_CAPABILITY_OPERATION_FILTER")
            operations = []
            for name in sorted(names):
                check_deadline(deadline, cancel_event)
                info = dict(DEEP_ACTIONS[name].to_dict())
                try:
                    if name == "profile.etw":
                        probe = {"status": "AVAILABLE" if token_is_elevated() else "ADMIN_REQUIRED",
                                 "source": "HELPER_TOKEN_ELEVATION_CHECK",
                                 "limitations": ["WPR availability and recording permissions are rechecked when capture starts."]}
                    else:
                        probe = probe_access(self.target, name)
                    info.update(probe)
                except Exception as exc:
                    info.update(status="OPERATION_FAILED", error=str(exc)[:1000])
                if info.get("status") == "ACCESS_DENIED" and not token_is_elevated():
                    info.update(status="ADMIN_REQUIRED", next_action="REQUEST_UAC_FOR_THIS_OPERATION")
                info["operation"] = name
                if DEEP_ACTIONS[name].mode == "INTERVENE" and name != "profile.etw" and self.target.pid in own_controllers:
                    info.update(status="OPERATION_FAILED", error="CONTROL_PROCESS_INTERVENTION_UNSAFE",
                                next_action="USE_A_SEPARATE_BLACKBOX_INSTANCE_TO_CONTROL_THIS_PROCESS")
                operations.append(info)
            return result("capabilities", "COMPLETED", data={"operations": operations})
        if request.operation == "profile.etw":
            validate_profile_parameters(parameters)
            if not token_is_elevated():
                return result("profile.etw", "ADMIN_REQUIRED", error="ETW_PROFILE_REQUIRES_SCOPED_ADMINISTRATOR_HELPER",
                              next_action="REQUEST_UAC_FOR_THIS_OPERATION")
            from .deep_profiling import capture_etw
            self.interventions_started = True
            captured = capture_etw(self.target, parameters, file_handle=file_handle,
                                   deadline=deadline, cancel_event=cancel_event)
            if captured.get("status") == "RECOVERY_UNCONFIRMED":
                self.profile_recovery.append(captured)
            return captured
        if request.operation == "snapshot":
            sections = {}
            for name in ("threads", "modules", "memory_map", "network", "disk"):
                check_deadline(deadline, cancel_event)
                sections[name] = self.inspector.execute(name, {}, deadline=deadline, cancel_event=cancel_event)
            complete = all(v.get("status") in ("COMPLETED", "AVAILABLE", "OK") for v in sections.values())
            return result("snapshot", "COMPLETED" if complete else "INCOMPLETE_EVIDENCE", data=sections,
                          limitations=["Dynamic sections are sequential observations, not an atomic process snapshot."])
        if request.operation.startswith(("debug.", "thread.", "memory.")):
            if self.debug is None:
                from .deep_debug import DebugSession
                self.debug = (self.debug_factory or DebugSession)(self.target, recovery_handle=self.recovery_handle)
            parameters["_confirmed"] = request.confirmed
            if spec.mode == "INTERVENE":
                self.interventions_started = True
            return self.debug.execute(request.operation, parameters, deadline=deadline, cancel_event=cancel_event)
        return self.inspector.execute(request.operation, parameters, deadline=deadline, cancel_event=cancel_event)

    def close(self) -> dict:
        errors = list(self.profile_recovery)
        cleanup = None
        if self.debug is not None:
            try:
                cleanup = self.debug.close()
                if isinstance(cleanup, dict) and cleanup.get("status") not in ("COMPLETED", "AVAILABLE", "DETACHED", "OK"):
                    errors.append(cleanup)
            except Exception as exc:
                errors.append({"error": str(exc)[:1000]})
        try:
            self.inspector.close()
        except Exception as exc:
            errors.append({"error": str(exc)[:1000]})
        return result("session.close", "RECOVERY_UNCONFIRMED" if errors else "COMPLETED",
                      data={"debug_cleanup": cleanup, "errors": errors},
                      limitations=["Cleanup covers only actions owned by this diagnostic session."])


def _parent_handle(parent: ProcessIdentity):
    from .deep_native import verify_identity
    verify_identity(parent)
    kernel = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    kernel.OpenProcess.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    kernel.CloseHandle.restype = W.BOOL
    kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
    kernel.WaitForSingleObject.restype = W.DWORD
    handle = kernel.OpenProcess(0x1000 | 0x40 | 0x100000, False, parent.pid)
    if not handle:
        raise OSError(C.get_last_error(), "PARENT_INSTANCE_HANDLE_UNAVAILABLE")
    try:
        verify_identity(parent)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    return kernel, handle


def _duplicate_parent_file(kernel, parent_handle, source_value):
    if type(source_value) is not int or not 0 < source_value < 2**64:
        raise ValueError("INVALID_GUI_FILE_HANDLE")
    kernel.GetCurrentProcess.restype = W.HANDLE
    kernel.DuplicateHandle.argtypes = [W.HANDLE, W.HANDLE, W.HANDLE, C.POINTER(W.HANDLE), W.DWORD, W.BOOL, W.DWORD]
    kernel.DuplicateHandle.restype = W.BOOL
    kernel.GetFileType.argtypes = [W.HANDLE]
    kernel.GetFileType.restype = W.DWORD
    target = W.HANDLE()
    if not kernel.DuplicateHandle(parent_handle, source_value, kernel.GetCurrentProcess(), C.byref(target), 0, False, 2):
        raise OSError(C.get_last_error(), "GUI_FILE_HANDLE_DUPLICATION_FAILED")
    if kernel.GetFileType(target) != 1:
        kernel.CloseHandle(target)
        raise ValueError("GUI_OUTPUT_MUST_BE_REGULAR_FILE_HANDLE")
    return target.value


def run_helper(pipe_name: str, nonce: str, parent: ProcessIdentity) -> int:
    from .deep_native import capture_identity
    if os.name != "nt" or len(nonce) != 64 or any(c not in "0123456789abcdef" for c in nonce):
        return 2
    elevated = token_is_elevated()
    if elevated:
        from .windows_research import enable_debug_privilege
        enable_debug_privilege()
    kernel, parent_handle = _parent_handle(parent)
    channel = None
    engine = None
    recovery_handle = None
    active = None
    active_cancel = None
    active_id = None
    send_lock = threading.Lock()
    fatal = threading.Event()
    try:
        channel = connect_pipe(pipe_name, parent.pid, deadline=time.monotonic() + 30)
        own = capture_identity(os.getpid())
        own = own.to_dict() if hasattr(own, "to_dict") else own
        channel.send({"kind": "hello", "protocol": 1, "nonce": nonce, "identity": own,
                      "permission_level": "ADMINISTRATOR" if elevated else "STANDARD"}, deadline=time.monotonic() + 10)
        init = channel.receive(deadline=time.monotonic() + 30)
        if (init.get("kind") != "init" or not hmac.compare_digest(str(init.get("nonce", "")), nonce)
                or init.get("parent") != parent.to_dict()):
            raise ValueError("INVALID_SESSION_HANDSHAKE")
        target = ProcessIdentity.from_dict(init["target"])
        operations = init["operations"]
        if not isinstance(operations, list) or len(operations) > len(DEEP_ACTIONS) or len(set(operations)) != len(operations):
            raise ValueError("INVALID_OPERATION_SCOPE")
        duration = init.get("session_seconds", MAX_SESSION_SECONDS)
        if type(duration) not in (int, float) or not 1 <= duration <= MAX_SESSION_SECONDS:
            raise ValueError("INVALID_SESSION_LIFETIME")
        if init.get("require_admin") is True and not elevated:
            raise PermissionError("ELEVATED_TOKEN_NOT_GRANTED")
        recovery_handle = _duplicate_parent_file(kernel, parent_handle, init["recovery_source_handle"])
        engine = DiagnosticActionEngine(target, operations, recovery_handle=recovery_handle, controller_pid=parent.pid)
        expires = time.monotonic() + duration
        channel.send({"kind": "ready", "target": target.to_dict(), "operations": operations,
                      "permission_level": "ADMINISTRATOR" if elevated else "STANDARD"}, deadline=time.monotonic() + 10)

        def execute_message(message, cancel):
            nonlocal fatal
            identifier = message.get("request_id")
            try:
                req = ActionRequest.from_dict(message["request"])
                validate_parameters(req.parameters)
                output_handle = None
                attachment = message.get("attachment")
                if attachment is not None:
                    if (req.operation not in ("dump", "profile.etw") or not isinstance(attachment, dict)
                            or set(attachment) != {"source_file_handle"}):
                        raise ValueError("INVALID_DIAGNOSTIC_ATTACHMENT")
                    output_handle = _duplicate_parent_file(kernel, parent_handle, attachment["source_file_handle"])
                try:
                    response = engine.execute(req, cancel_event=cancel, file_handle=output_handle)
                finally:
                    # The engine borrows this handle. Close exactly once even if
                    # target validation or the operation deadline failed early.
                    if output_handle:
                        kernel.CloseHandle(output_handle)
                response.setdefault("operation", req.operation)
                if response.get("status") == "ACCESS_DENIED" and not elevated:
                    response.update(status="ADMIN_REQUIRED", next_action="REQUEST_UAC_FOR_THIS_OPERATION")
            except InterruptedError as exc:
                response = result("unknown", "CANCELLED", error=str(exc))
            except TimeoutError as exc:
                response = result("unknown", "TIMED_OUT", error=str(exc))
            except Exception as exc:
                status = getattr(exc, "status", "OPERATION_FAILED")
                response = result("unknown", status, error=str(exc)[:2000], winerror=getattr(exc, "winerror", None))
            if response.get("status") == "ACCESS_DENIED" and not elevated:
                response.update(status="ADMIN_REQUIRED", next_action="REQUEST_UAC_FOR_THIS_OPERATION")
            response["permission_level"] = "ADMINISTRATOR" if elevated else "STANDARD"
            try:
                bounded_json(response)
            except (ValueError, TypeError):
                response = result(response.get("operation", "unknown"), "INCOMPLETE_EVIDENCE",
                                  error="DIAGNOSTIC_RESULT_EXCEEDED_TRANSPORT_BUDGET",
                                  limitations=["Operation may have executed; payload omitted. Review session cleanup before retrying."])
            try:
                with send_lock:
                    channel.send({"kind": "result", "request_id": identifier, "result": response},
                                 deadline=time.monotonic() + 10)
            except Exception:
                fatal.set()

        while time.monotonic() < expires and not fatal.is_set():
            if kernel.WaitForSingleObject(parent_handle, 0) != 258:
                break
            if active is not None and not active.is_alive():
                active, active_cancel, active_id = None, None, None
            try:
                message = channel.receive(deadline=min(expires, time.monotonic() + 0.2))
            except TimeoutError:
                continue
            kind = message.get("kind")
            if kind == "cancel":
                if message.get("request_id") == active_id and active_cancel is not None:
                    active_cancel.set()
                continue
            if kind == "close":
                if active_cancel is not None:
                    active_cancel.set()
                if active is not None:
                    active.join(timeout=5)
                cleanup = engine.close() if active is None or not active.is_alive() else result(
                    "session.close", "RECOVERY_UNCONFIRMED", error="OPERATION_DID_NOT_STOP_BEFORE_SESSION_CLOSE")
                with send_lock:
                    channel.send({"kind": "closed", "result": cleanup}, deadline=time.monotonic() + 5)
                engine = None if cleanup["status"] == "COMPLETED" else engine
                break
            if kind == "execute" and active is not None:
                # A sequential GUI request can arrive immediately after the
                # previous worker sent its result but before its Thread has
                # returned. Reap that finalization window before rejecting an
                # actually concurrent operation.
                active.join(timeout=1)
                if not active.is_alive():
                    active, active_cancel, active_id = None, None, None
            if kind != "execute" or active is not None or not isinstance(message.get("request_id"), str):
                raise ValueError("DIAGNOSTIC_PROTOCOL_SEQUENCE_ERROR")
            active_id = message["request_id"]
            active_cancel = threading.Event()
            active = threading.Thread(target=execute_message, args=(message, active_cancel), daemon=True,
                                      name="blackbox-diagnostic-operation")
            active.start()
        return 0
    finally:
        if active_cancel is not None:
            active_cancel.set()
        if active is not None:
            active.join(timeout=5)
        if engine is not None and (active is None or not active.is_alive()):
            try:
                engine.close()
            except Exception:
                pass
        if recovery_handle is not None:
            kernel.CloseHandle(recovery_handle)
        if channel is not None:
            channel.close()
        kernel.CloseHandle(parent_handle)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="BLACK.BOX Diagnostic Helper")
    parser.add_argument("--deep-helper", action="store_true", required=True)
    parser.add_argument("--pipe", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--parent-pid", required=True, type=int)
    parser.add_argument("--parent-created-100ns", required=True, type=int)
    parser.add_argument("--parent-image", required=True)
    args = parser.parse_args(argv)
    return run_helper(args.pipe, args.nonce, ProcessIdentity(args.parent_pid, args.parent_created_100ns, args.parent_image))
