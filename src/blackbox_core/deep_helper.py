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
from .deep_ipc import check_deadline, connect_pipe, token_authority, token_is_elevated

_FORBIDDEN_PARAMETERS = frozenset({"handle", "file_handle", "recovery_handle", "source_handle",
                                  "source_file_handle", "command", "shell", "executable", "argv"})
LOCAL_OPERATIONS = frozenset({"timeline", "compare", "trace_evidence", "dump_inspect",
                             "dump_read_memory", "symbols_verify"})


def validate_parameters(parameters: dict) -> None:
    if _FORBIDDEN_PARAMETERS.intersection(parameters) or any(k.startswith("_") for k in parameters):
        raise ValueError("UNTRUSTED_NATIVE_HANDLE_OR_COMMAND")


_PARAMETER_KEYS = {
    "processes": {"limit"}, "modules": {"limit", "hash_files"}, "threads": {"limit"},
    "handles": {"limit", "name_limit"},
    "memory_map": {"limit", "start_address", "mapped_file_limit"},
    "memory_read": {"address", "size", "length"},
    "wait_chains": {"limit", "tid", "thread_created_100ns", "created_100ns"},
    "network": {"limit"}, "disk": {"limit"}, "snapshot": set(),
    "thread_stacks": {"limit", "max_frames", "tid", "thread_created_100ns", "created_100ns", "pdb_path", "module_base"},
    "dump": {"full", "max_bytes"}, "profile.etw": {"duration_seconds", "profile", "systemwide_confirmed"},
    "capabilities": {"operations"}, "timeline": {"limit"}, "compare": {"before_id", "after_id"},
    "trace_evidence": {"index_path", "process_instance", "tid", "start_ms", "end_ms", "limit",
                       "include_waits", "expected_source_trace_sha256"},
    "dump_inspect": {"path", "max_bytes", "limit"},
    "dump_read_memory": {"path", "address", "size", "max_bytes"},
    "symbols_verify": {"pe_path", "pdb_path", "rva"},
    "debug.context": {"tid", "thread_created_100ns"}, "debug.breakpoints": set(),
    "debug.attach": set(), "debug.pause": set(), "debug.continue": set(), "debug.step": set(), "debug.detach": set(),
    "debug.breakpoint.add": {"address"}, "debug.breakpoint.disable": {"breakpoint_id"},
    "debug.breakpoint.remove": {"breakpoint_id"},
    "thread.suspend": {"tid", "thread_created_100ns"},
    "thread.resume": {"suspension_id", "tid", "thread_created_100ns"},
    "memory.write": {"address", "expected_hex", "value_hex"},
    "memory.rollback": {"change_id", "operation_id"},
}


def validate_operation_parameters(operation: str, parameters: dict, *, allow_output: bool = False) -> None:
    """Refuse ignored options before they can become an apparent successful run."""
    validate_parameters(parameters)
    allowed = _PARAMETER_KEYS[operation]
    if allow_output and operation in ("dump", "profile.etw"):
        allowed = allowed | {"destination", "path", "output_path"}
    if set(parameters) - allowed:
        raise ValueError("UNSUPPORTED_OPERATION_PARAMETER")
    alternatives = ({"size", "length"}, {"created_100ns", "thread_created_100ns"},
                    {"change_id", "operation_id"}, {"destination", "path", "output_path"})
    if any(len(set(parameters) & names) > 1 for names in alternatives):
        raise ValueError("AMBIGUOUS_OPERATION_PARAMETER")
    if operation in ("wait_chains", "thread_stacks"):
        if {"created_100ns", "thread_created_100ns"} & set(parameters) and "tid" not in parameters:
            raise ValueError("THREAD_CREATION_TIME_REQUIRES_EXACT_TID")
    if operation == "thread_stacks" and "module_base" in parameters and not parameters.get("pdb_path"):
        raise ValueError("SYMBOL_MODULE_BASE_REQUIRES_PDB")
    if operation == "thread.resume" and "suspension_id" in parameters and {"tid", "thread_created_100ns"} & set(parameters):
        raise ValueError("AMBIGUOUS_OWNED_SUSPENSION_IDENTITY")


class DiagnosticActionEngine:
    """Worker-owned coordination, independent of the sampling subsystem."""
    def __init__(self, target: ProcessIdentity, operations: list[str], *, recovery_handle=None,
                 inspector_factory=None, debug_factory=None, controller_pid=None, probe_operations=None):
        from .deep_native import ProcessInspector
        self.target = ProcessIdentity.from_dict(target)
        self.operations = frozenset(operations)
        if not self.operations or not self.operations <= DEEP_ACTIONS.keys() or self.operations & LOCAL_OPERATIONS:
            raise ValueError("INVALID_DIAGNOSTIC_SCOPE")
        # Access probes describe Windows rights. They never extend the set of
        # executable operations authorized for this exact target context.
        self.probe_operations = self.operations if probe_operations is None else _operation_scope(probe_operations)
        self.inspector = (inspector_factory or ProcessInspector)(self.target)
        self.debug_factory = debug_factory
        self.debug = None
        self.recovery_handle = recovery_handle
        self.interventions_started = False
        self.profile_recovery = []
        self.retained_cleanup = None
        self.controller_pid = controller_pid

    def execute(self, request: ActionRequest, *, cancel_event=None, file_handle=None) -> dict:
        self._execution_identity_verified = False
        self._execution_attempted = False
        response = self._execute(request, cancel_event=cancel_event, file_handle=file_handle)
        if self._execution_identity_verified and self._execution_attempted:
            response["diagnostic_execution"] = {"source": "DIAGNOSTIC_HELPER", "source_verified": True,
                                                  "target_verified": response.get("status") != "PROCESS_CHANGED",
                                                  "target": self.target.to_dict()}
        return response

    def _execute(self, request: ActionRequest, *, cancel_event=None, file_handle=None) -> dict:
        from .deep_native import verify_identity
        if request.target != self.target:
            return result(request.operation, "PROCESS_CHANGED", error="SESSION_TARGET_IDENTITY_MISMATCH")
        if request.operation not in self.operations:
            return result(request.operation, "ACCESS_DENIED", error="OPERATION_OUTSIDE_APPROVED_SESSION_SCOPE",
                          next_action="END_SESSION_AND_APPROVE_A_NEW_OPERATION_SCOPE")
        if self.retained_cleanup is not None and request.operation not in (
                "debug.detach", "debug.context", "debug.breakpoints", "capabilities"):
            return result(request.operation, "RECOVERY_UNCONFIRMED", error="OWNED_DEBUG_CONTEXT_REQUIRES_CLEANUP",
                          data={"owner_retained": True, "retry_cleanup_required": True})
        validate_parameters(request.parameters)
        spec = DEEP_ACTIONS[request.operation]
        if spec.confirmation_required and not request.confirmed:
            return result(request.operation, "CONFIRMATION_REQUIRED", error="EXPLICIT_ACTION_CONFIRMATION_REQUIRED",
                          next_action="REVIEW_TARGET_PARAMETERS_AND_IMPACT")
        validate_operation_parameters(request.operation, request.parameters)
        deadline = time.monotonic() + request.timeout_seconds
        check_deadline(deadline, cancel_event)
        verified = verify_identity(self.target)
        if isinstance(verified, dict) and verified.get("status") not in (None, "AVAILABLE", "COMPLETED", "OK"):
            return verified
        self._execution_identity_verified = True
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
            names = parameters.get("operations", sorted(self.probe_operations))
            if (set(parameters) - {"operations"} or not isinstance(names, list) or not names
                    or any(not isinstance(name, str) for name in names)
                    or len(names) > len(DEEP_ACTIONS) or len(names) != len(set(names))
                    or not set(names) <= self.probe_operations):
                raise ValueError("INVALID_CAPABILITY_OPERATION_FILTER")
            operations = []
            self._execution_attempted = True
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
            self._execution_attempted = True
            self.interventions_started = True
            captured = capture_etw(self.target, parameters, file_handle=file_handle,
                                   deadline=deadline, cancel_event=cancel_event)
            if captured.get("status") == "RECOVERY_UNCONFIRMED":
                self.profile_recovery.append(captured)
            return captured
        if request.operation == "snapshot":
            self._execution_attempted = True
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
            self._execution_attempted = True
            answer = self.debug.execute(request.operation, parameters, deadline=deadline, cancel_event=cancel_event)
            if answer.get("data", {}).get("owner_retained"):
                self.retained_cleanup = answer
            elif request.operation == "debug.detach" and answer.get("status") == "COMPLETED":
                self.retained_cleanup = None
            return answer
        self._execution_attempted = True
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
        retained = bool(isinstance(cleanup, dict) and cleanup.get("data", {}).get("owner_retained"))
        if retained:
            self.retained_cleanup = cleanup
            return result("session.close", "RECOVERY_UNCONFIRMED", retains_service=True,
                          data={"debug_cleanup": cleanup, "errors": errors,
                                "owner_retained": True, "retry_cleanup_required": True},
                          limitations=["Cleanup is retryable only within the original helper lease; unverified held debug context must not be silently resumed."])
        try:
            self.inspector.close()
        except Exception as exc:
            errors.append({"error": str(exc)[:1000]})
        return result("session.close", "RECOVERY_UNCONFIRMED" if errors else "COMPLETED",
                      data={"debug_cleanup": cleanup, "errors": errors},
                      limitations=["Cleanup covers only actions owned by this diagnostic session."])


def _close_after_cancel(engine, active, active_cancel):
    """A live native worker still owns its state even after cancellation grace."""
    if active_cancel is not None:
        active_cancel.set()
    if active is not None:
        active.join(timeout=5)
    if active is not None and active.is_alive():
        return result("session.close", "RECOVERY_UNCONFIRMED", retains_service=True,
                      error="OPERATION_DID_NOT_STOP_BEFORE_SESSION_CLOSE",
                      data={"owner_retained": True, "retry_cleanup_required": True,
                            "operation_cancellation_pending": True},
                      limitations=["The active native owner is retained only within the original helper lease; retry cleanup after cancellation is acknowledged."])
    return engine.close() if engine is not None else result("session.close", "COMPLETED", data={})


def _operation_scope(operations):
    if (type(operations) is not list or not operations or len(operations) > len(DEEP_ACTIONS)
            or any(type(name) is not str for name in operations)
            or len(operations) != len(set(operations))
            or not set(operations) <= set(DEEP_ACTIONS) - LOCAL_OPERATIONS):
        raise ValueError("INVALID_OPERATION_SCOPE")
    return frozenset(operations)


class ManagedDiagnosticContext:
    """One finite elevated helper lease, with sequential consent-bound engines.

    This extends the same diagnostic engine; it does not grant arbitrary native
    access. An unconfirmed cleanup keeps the old owner and forbids a new bind
    until the caller explicitly retries release and receives verified cleanup.
    """
    def __init__(self, operations, *, duration=MAX_SESSION_SECONDS, recovery_handle=None,
                 controller_pid=None, engine_factory=None, identity_verifier=None,
                 token_verifier=None, clock=None):
        from .deep_native import verify_identity
        if type(duration) not in (int, float) or not 1 <= duration <= MAX_SESSION_SECONDS:
            raise ValueError("INVALID_SESSION_LIFETIME")
        self.operations = _operation_scope(operations)
        self._clock = clock or time.monotonic
        self._token_verifier = token_verifier or token_is_elevated
        self._identity_verifier = identity_verifier or verify_identity
        self._engine_factory = engine_factory or DiagnosticActionEngine
        self.recovery_handle = recovery_handle
        self.controller_pid = controller_pid
        self.engine = None
        self.cleanup_required = False
        if not self._token_verifier():
            raise PermissionError("ELEVATED_TOKEN_NOT_GRANTED")
        self.expires = self._clock() + duration

    def _authority(self, operation):
        if self._clock() >= self.expires:
            return result(operation, "SESSION_EXPIRED", error="ADMINISTRATIVE_LEASE_EXPIRED")
        if not self._token_verifier():
            return result(operation, "ACCESS_DENIED", error="ELEVATED_TOKEN_NOT_GRANTED")
        return None

    def _retained(self, operation, cleanup):
        self.cleanup_required = True
        return result(operation, "RECOVERY_UNCONFIRMED", retains_service=True,
                      error="PREVIOUS_TARGET_CLEANUP_UNCONFIRMED",
                      data={"owner_retained": True, "retry_cleanup_required": True,
                            "target": self.engine.target.to_dict() if self.engine is not None else None,
                            "cleanup": cleanup},
                      next_action="RETRY_EXPLICIT_TARGET_RELEASE_BEFORE_RETARGETING")

    def status(self):
        authority = token_authority()
        verified = self._token_verifier() is True and authority.get("elevated") is True
        data = {"target": self.engine.target.to_dict() if self.engine is not None else None,
                "operations": sorted(self.engine.operations) if self.engine is not None else [],
                "allowed_operations": sorted(self.operations), "permission_level": "ADMINISTRATOR" if verified else "STANDARD",
                "elevated_verified": verified, "expires_in_seconds": max(0, self.expires - self._clock()),
                "token_authority": authority,
                "cleanup_required": self.cleanup_required, "owner_retained": self.cleanup_required}
        status = ("RECOVERY_UNCONFIRMED" if self.cleanup_required else "SESSION_EXPIRED"
                  if self._clock() >= self.expires else "COMPLETED" if verified else "ACCESS_DENIED")
        return result("session.status", status, data=data)

    def bind(self, target, operations, *, confirmed=False):
        target = ProcessIdentity.from_dict(target)
        scope = _operation_scope(operations)
        blocked = self._authority("target.bind")
        if blocked is not None:
            return blocked
        if not scope <= self.operations:
            return result("target.bind", "ACCESS_DENIED", error="OPERATION_OUTSIDE_APPROVED_SESSION_SCOPE")
        if confirmed is not True:
            return result("target.bind", "CONFIRMATION_REQUIRED", next_action="AUTHORIZE_TARGET_AND_OPERATION_SCOPE")
        if self.cleanup_required:
            return self._retained("target.bind", {"status": "RECOVERY_UNCONFIRMED"})
        self._identity_verifier(target)
        if self.engine is not None and self.engine.target == target and self.engine.operations == scope:
            return result("target.bind", "COMPLETED", data={"target": target.to_dict(), "operations": sorted(scope)})
        cleanup = self.release()
        if cleanup["status"] != "COMPLETED":
            return self._retained("target.bind", cleanup)
        # Cleanup can take time: recheck both the token/lease and exact target
        # after closing the old owner, before constructing any new native owner.
        blocked = self._authority("target.bind")
        if blocked is not None:
            return blocked
        self._identity_verifier(target)
        self.engine = self._engine_factory(target, sorted(scope), recovery_handle=self.recovery_handle,
                                           controller_pid=self.controller_pid, probe_operations=sorted(self.operations))
        return result("target.bind", "COMPLETED", data={"target": target.to_dict(), "operations": sorted(scope)})

    def release(self, *, active=None, active_cancel=None):
        try:
            cleanup = _close_after_cancel(self.engine, active, active_cancel)
        except Exception as exc:
            cleanup = result("session.close", "RECOVERY_UNCONFIRMED", error=str(exc)[:1000])
        if cleanup.get("status") != "COMPLETED":
            return self._retained("target.release", cleanup)
        self.engine = None
        self.cleanup_required = False
        return result("target.release", "COMPLETED", data={"target": None, "operations": [], "cleanup": cleanup})

    def execute(self, request, *, cancel_event=None, file_handle=None):
        blocked = self._authority(request.operation)
        if blocked is not None:
            return blocked
        if self.engine is None or request.target != self.engine.target:
            return result(request.operation, "CONFIRMATION_REQUIRED", next_action="AUTHORIZE_TARGET_AND_OPERATION_SCOPE")
        if self.cleanup_required and request.operation not in ("debug.detach", "debug.context", "debug.breakpoints", "capabilities"):
            return self._retained(request.operation, {"status": "RECOVERY_UNCONFIRMED"})
        try:
            response = self.engine.execute(request, cancel_event=cancel_event, file_handle=file_handle)
        except BaseException:
            if self.engine.interventions_started:
                self.cleanup_required = True
            raise
        if response.get("status") == "RECOVERY_UNCONFIRMED" or response.get("data", {}).get("owner_retained"):
            self.cleanup_required = True
        return response


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
    managed = None
    recovery_handle = None
    active = None
    active_cancel = None
    active_id = None
    send_lock = threading.Lock()
    fatal = threading.Event()
    terminal_cleanup_attempted = False
    closed_by_request = False
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
        session_mode = init.get("session_mode", "TARGET_BOUND")
        if session_mode not in ("TARGET_BOUND", "ADMIN_LEASE"):
            raise ValueError("INVALID_SESSION_MODE")
        if session_mode == "ADMIN_LEASE" and (init.get("target") is not None or init.get("require_admin") is not True):
            raise ValueError("INVALID_ADMIN_LEASE_HANDSHAKE")
        target = None if session_mode == "ADMIN_LEASE" else ProcessIdentity.from_dict(init["target"])
        operations = init["operations"]
        _operation_scope(operations)
        duration = init.get("session_seconds", MAX_SESSION_SECONDS)
        if type(duration) not in (int, float) or not 1 <= duration <= MAX_SESSION_SECONDS:
            raise ValueError("INVALID_SESSION_LIFETIME")
        if init.get("require_admin") is True and not token_is_elevated():
            raise PermissionError("ELEVATED_TOKEN_NOT_GRANTED")
        recovery_handle = _duplicate_parent_file(kernel, parent_handle, init["recovery_source_handle"])
        if session_mode == "ADMIN_LEASE":
            managed = ManagedDiagnosticContext(operations, duration=duration, recovery_handle=recovery_handle,
                                                controller_pid=parent.pid)
            expires = managed.expires
        else:
            engine = DiagnosticActionEngine(target, operations, recovery_handle=recovery_handle, controller_pid=parent.pid)
            expires = time.monotonic() + duration
        ready = {"kind": "ready", "target": target.to_dict() if target else None, "operations": operations,
                 "permission_level": "ADMINISTRATOR" if elevated else "STANDARD"}
        if managed is not None:
            observed = managed.status()
            if observed["status"] != "COMPLETED":
                raise PermissionError("ADMIN_LEASE_TOKEN_OR_LIFETIME_NOT_VERIFIED")
            ready.update(session_mode=session_mode, elevated_verified=observed["data"]["elevated_verified"],
                         token_authority=observed["data"]["token_authority"],
                         expires_in_seconds=observed["data"]["expires_in_seconds"],
                         helper_identity=own)
        channel.send(ready, deadline=time.monotonic() + 10)

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
                    owner = managed if managed is not None else engine
                    response = owner.execute(req, cancel_event=cancel, file_handle=output_handle)
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
                if managed is not None and managed.cleanup_required:
                    response = managed._retained("unknown", response)
            except TimeoutError as exc:
                response = result("unknown", "TIMED_OUT", error=str(exc))
                if managed is not None and managed.cleanup_required:
                    response = managed._retained("unknown", response)
            except Exception as exc:
                status = getattr(exc, "status", "OPERATION_FAILED")
                response = result("unknown", status, error=str(exc)[:2000], winerror=getattr(exc, "winerror", None))
                if managed is not None and managed.cleanup_required:
                    response = managed._retained("unknown", response)
            if response.get("status") == "ACCESS_DENIED" and not elevated:
                response.update(status="ADMIN_REQUIRED", next_action="REQUEST_UAC_FOR_THIS_OPERATION")
            try:
                granted = token_is_elevated() if managed is not None else elevated
            except Exception:
                granted = False
                response.setdefault("limitations", []).append("Post-operation helper token authority could not be observed.")
            response["permission_level"] = "ADMINISTRATOR" if granted else "STANDARD"
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
            if managed is not None and not hmac.compare_digest(str(message.get("nonce", "")), nonce):
                raise PermissionError("INVALID_SESSION_MESSAGE_NONCE")
            if kind == "cancel":
                if message.get("request_id") == active_id and active_cancel is not None:
                    active_cancel.set()
                continue
            if kind == "close":
                closing_context = ({"target": managed.engine.target.to_dict() if managed.engine is not None else None,
                                    "operations": sorted(managed.engine.operations) if managed.engine is not None else []}
                                   if managed is not None else None)
                cleanup = (managed.release(active=active, active_cancel=active_cancel) if managed is not None
                           else _close_after_cancel(engine, active, active_cancel))
                closed = {"kind": "closed", "result": cleanup}
                if managed is not None:
                    closed.update(reason="EXPLICIT_CLOSE", nonce=nonce, identity=own,
                                  context=closing_context, context_released=managed.engine is None)
                with send_lock:
                    channel.send(closed, deadline=time.monotonic() + 5)
                if cleanup.get("data", {}).get("owner_retained"):
                    # Keep the owning debug thread/event for an explicit retry.
                    # Do not renew expires: parent death or original TTL is the
                    # finite, explicitly unconfirmed last-resort boundary.
                    continue
                engine = None if cleanup["status"] == "COMPLETED" else engine
                closed_by_request = True
                break
            if managed is not None and kind in ("target.bind", "target.release", "session.status"):
                identifier = message.get("request_id")
                if not isinstance(identifier, str) or not 0 < len(identifier) <= 128:
                    raise ValueError("INVALID_DIAGNOSTIC_REQUEST_ID")
                response_kind = {"target.bind": "target.bound", "target.release": "target.released",
                                 "session.status": "session.status"}[kind]
                if kind == "target.bind" and active is not None:
                    active.join(timeout=1)
                    if not active.is_alive():
                        active, active_cancel, active_id = None, None, None
                try:
                    if kind == "session.status":
                        response = managed.status()
                        response["data"]["helper_identity"] = own
                    elif kind == "target.release":
                        response = managed.release(active=active, active_cancel=active_cancel)
                    elif active is not None and active.is_alive():
                        # A bind is never an implicit cancellation or recovery
                        # retry; the current native worker retains ownership.
                        response = result("target.bind", "RECOVERY_UNCONFIRMED", retains_service=True,
                                          error="TARGET_OPERATION_STILL_ACTIVE",
                                          data={"owner_retained": True, "retry_cleanup_required": True})
                        managed.cleanup_required = True
                    else:
                        response = managed.bind(message["target"], message["operations"],
                                                confirmed=message.get("confirmed") is True)
                except Exception as exc:
                    response = result(kind, getattr(exc, "status", "OPERATION_FAILED"),
                                      error=str(exc)[:2000], winerror=getattr(exc, "winerror", None),
                                      data={"target": managed.engine.target.to_dict() if managed.engine is not None else None,
                                            "operations": sorted(managed.engine.operations) if managed.engine is not None else [],
                                            "cleanup_required": managed.cleanup_required,
                                            "context_verified": True})
                if kind == "target.bind":
                    context = response.setdefault("data", {})
                    context.update(context_verified=True,
                                   target=managed.engine.target.to_dict() if managed.engine is not None else None,
                                   operations=sorted(managed.engine.operations) if managed.engine is not None else [],
                                   cleanup_required=managed.cleanup_required)
                with send_lock:
                    channel.send({"kind": response_kind, "request_id": identifier, "result": response},
                                 deadline=time.monotonic() + 10)
                if active is not None and not active.is_alive():
                    active, active_cancel, active_id = None, None, None
                continue
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
        if (managed is not None and not closed_by_request and not fatal.is_set()
                and time.monotonic() >= expires and kernel.WaitForSingleObject(parent_handle, 0) == 258):
            # The terminal result belongs to this authenticated lease/context,
            # and is sent before closing the pipe. A recovery file from an old
            # guardian/context cannot substitute for this acknowledgement.
            closing_context = {"target": managed.engine.target.to_dict() if managed.engine is not None else None,
                               "operations": sorted(managed.engine.operations) if managed.engine is not None else []}
            terminal_cleanup_attempted = True
            cleanup = managed.release(active=active, active_cancel=active_cancel)
            with send_lock:
                channel.send({"kind": "expired", "reason": "LEASE_EXPIRED", "nonce": nonce,
                              "identity": own, "context": closing_context,
                              "context_released": managed.engine is None, "result": cleanup},
                             deadline=time.monotonic() + 5)
        return 0
    finally:
        if active_cancel is not None:
            active_cancel.set()
        if active is not None:
            active.join(timeout=5)
        if (not terminal_cleanup_attempted and (managed is not None or engine is not None)
                and (active is None or not active.is_alive())):
            try:
                managed.release() if managed is not None else engine.close()
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
