"""GUI-token coordinator for bounded, explicitly approved process diagnostics."""
from __future__ import annotations

from datetime import datetime, timezone
from copy import deepcopy
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import threading
import time
from uuid import uuid4

from .deep_contracts import (ActionRequest, DEEP_ACTIONS, MAX_SESSION_SECONDS,
                             ProcessIdentity, canonical_operation, describe_actions, result)
from .deep_elevation import ElevationBroker, ElevationCancelled
from .deep_helper import (DiagnosticActionEngine, LOCAL_OPERATIONS, validate_parameters,
                          validate_operation_parameters)
from .deep_ipc import PipeServer, check_deadline
from .deep_journal import EvidenceJournal, journal_metadata
from .deep_tool_contracts import attach_run_receipt, begin_run, describe_tool


def verify_helper_hello(hello: dict, nonce: str, actual: ProcessIdentity, expected_executable: str) -> None:
    if (hello.get("kind") != "hello" or hello.get("protocol") != 1
            or not hmac.compare_digest(str(hello.get("nonce", "")), nonce)
            or ProcessIdentity.from_dict(hello.get("identity")) != actual
            or os.path.normcase(actual.image_path) != os.path.normcase(str(Path(expected_executable).resolve()))):
        raise PermissionError("HELPER_IDENTITY_HANDSHAKE_FAILED")


class CapabilityManager:
    def __init__(self, service):
        self.service = service

    def inspect(self, identity: ProcessIdentity) -> dict:
        return self.service.execute(ActionRequest("capabilities", identity, timeout_seconds=30))


class InspectorService:
    def __init__(self, journal_root: str | Path | None = None, *, helper_executable: str | Path | None = None):
        if journal_root is None:
            base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share")
            journal_root = base / "BLACK.BOX" / "deep-inspection" / uuid4().hex
        self.journal_root = Path(journal_root)
        self.journal = EvidenceJournal(self.journal_root)
        self.broker = ElevationBroker(helper_executable)
        self.capability_manager = CapabilityManager(self)
        self.helper = None
        self._channel = None
        self._target = None
        self._scope = frozenset()
        self._expires = 0.0
        self._permission = "STANDARD"
        self._recovery_stream = None
        self._recovery_path = None
        self._lock = threading.RLock()
        self._interventions_started = False
        self._active_request_id = None
        self._owner_retained = False
        self._admin_session_managed = False
        self._admin_state = "INACTIVE"
        self._elevated_verified = False
        self._helper_identity = None
        self._helper_token_authority = None
        self._session_nonce = None
        self._session_catalog = frozenset()
        self._cleanup_unconfirmed = False
        self._expiry_cleanup = None
        self._pending_close_context = None

    @property
    def helper_pid(self):
        return self.helper.pid if self.helper is not None else None

    @property
    def admin_active(self) -> bool:
        return bool(self.helper is not None and self.helper.alive() and self._permission == "ADMINISTRATOR"
                    and self._elevated_verified and not self._owner_retained and not self._cleanup_unconfirmed
                    and self._admin_state == "ACTIVE" and time.monotonic() < self._expires)

    def identity(self, pid: int) -> ProcessIdentity:
        from .deep_native import capture_identity
        return ProcessIdentity.from_dict(capture_identity(pid))

    def session_status(self, *, refresh: bool = False) -> dict:
        # Only the serialized worker requests a heartbeat. Internal journal
        # snapshots must not consume a native operation's in-flight reply.
        with self._lock:
            if refresh and self._admin_session_managed and self.helper is not None:
                if time.monotonic() >= self._expires:
                    self._consume_expiry_cleanup()
                elif self.helper.alive():
                    try:
                        answer = self._managed_exchange("session.status")
                        data = answer.get("data", {})
                        self._helper_token_authority = data.get("token_authority", self._helper_token_authority)
                        if data.get("cleanup_required") or answer.get("status") == "RECOVERY_UNCONFIRMED":
                            self._owner_retained = self._cleanup_unconfirmed = True
                        if (answer.get("status") != "COMPLETED" or data.get("elevated_verified") is not True
                                or data.get("permission_level") != "ADMINISTRATOR"
                                or not isinstance(data.get("token_authority"), dict)
                                or data["token_authority"].get("elevated") is not True
                                or self._helper_identity is None
                                or data.get("helper_identity") != self._helper_identity.to_dict()
                                or data.get("target") != (self._target.to_dict() if self._target else None)
                                or data.get("operations") != sorted(self._scope)):
                            raise PermissionError("ADMINISTRATIVE_HEARTBEAT_VERIFICATION_FAILED")
                        self._elevated_verified = True
                        if data.get("cleanup_required"):
                            self._owner_retained = self._cleanup_unconfirmed = True
                        elif not self._cleanup_unconfirmed:
                            self._admin_state = "ACTIVE"
                    except Exception:
                        self._elevated_verified = False
                        self._admin_state = "FAILED"
                        if self._interventions_started:
                            self._owner_retained = self._cleanup_unconfirmed = True
            alive = bool(self.helper is not None and self.helper.alive())
            remaining = max(0, round(self._expires - time.monotonic(), 3))
            if self._owner_retained or self._cleanup_unconfirmed:
                state = "CLEANUP_REQUIRED"
            elif self.helper is not None and not alive:
                if self._interventions_started:
                    self._cleanup_unconfirmed = True
                    state = "CLEANUP_REQUIRED"
                else:
                    state = "EXPIRED" if self._expires and not remaining else "FAILED"
            elif self.helper is not None and not remaining:
                state = "EXPIRED"
            elif self.admin_active:
                state = "ACTIVE"
            else:
                state = self._admin_state if self._admin_state != "ACTIVE" else "FAILED"
            self._admin_state = state
            return {"active": bool(alive and remaining and not self._owner_retained and not self._cleanup_unconfirmed),
                "helper_pid": self.helper_pid, "admin_active": self.admin_active,
                "state": state, "elevated_verified": bool(self.admin_active),
                "admin_session_managed": self._admin_session_managed,
                "helper_identity": self._helper_identity.to_dict() if self._helper_identity else None,
                "helper_token_authority": self._helper_token_authority,
                "permission_level": self._permission,
                "expires_in_seconds": remaining, "remaining_seconds": remaining,
                "session_deadline_monotonic": self._expires,
                "target": self._target.to_dict() if self._target else None,
                "operations": sorted(self._scope),
                "allowed_operations": sorted(self._session_catalog or self._scope),
                "owner_retained": self._owner_retained,
                "cleanup_required": self._owner_retained or self._cleanup_unconfirmed,
                "expiry_cleanup": deepcopy(self._expiry_cleanup),
                "recovery_report": str(self._recovery_path) if self._recovery_path else None,
                "recovery": self.recovery_status()}

    def recovery_status(self) -> dict:
        if self._recovery_path is None:
            return {"status": "NOT_COLLECTED"}
        try:
            # Separate read handle: guardian's duplicated write handle shares
            # an offset with the original GUI stream, so do not seek that stream.
            with self._recovery_path.open("rb") as stream:
                raw = stream.read(32769)
            if not raw:
                return {"status": "NOT_COLLECTED", "reason": "GUARDIAN_HAS_NOT_WRITTEN_RECOVERY_RESULT"}
            if len(raw) > 32768:
                raise ValueError("RECOVERY_REPORT_BUDGET_EXCEEDED")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("RECOVERY_REPORT_NOT_OBJECT")
            return data
        except (OSError, ValueError) as exc:
            return {"status": "RECOVERY_UNCONFIRMED", "error": str(exc)[:1000]}

    def capabilities(self, identity: ProcessIdentity) -> dict:
        return self.capability_manager.inspect(identity)

    def _start_session(self, target: ProcessIdentity | None, operations: list[str], *, elevated: bool,
                       cancel_event=None, admin_lease: bool = False, session_seconds=MAX_SESSION_SECONDS) -> dict:
        self._expiry_cleanup = None
        self._pending_close_context = None
        if os.name != "nt":
            return result("session.open", "UNSUPPORTED_PLATFORM", next_action="USE_WINDOWS_10_OR_11_X64")
        parent = self.identity(os.getpid())
        nonce = secrets.token_hex(32)
        pipe = PipeServer("\\\\.\\pipe\\BLACKBOX-DEEP-" + uuid4().hex)
        self._channel = pipe
        self._recovery_path = self.journal_root / ("recovery-" + uuid4().hex + ".json")
        arguments = ["--deep-helper", "--pipe", pipe.name, "--nonce", nonce,
                     "--parent-pid", str(parent.pid), "--parent-created-100ns", str(parent.created_100ns),
                     "--parent-image", parent.image_path]
        try:
            self._recovery_stream = self._recovery_path.open("x+b")
            check_deadline(time.monotonic() + 1, cancel_event)
            self.helper = self.broker.launch(arguments, elevated=elevated)
            if not self.helper.alive():
                raise OSError("DIAGNOSTIC_HELPER_EXITED_DURING_STARTUP")
            deadline = time.monotonic() + 30
            pipe.accept(self.helper.pid, deadline=deadline, cancel_event=cancel_event)
            hello = pipe.receive(deadline=deadline, cancel_event=cancel_event)
            if not self.helper.alive():
                raise OSError("DIAGNOSTIC_HELPER_INSTANCE_EXITED")
            actual = self.identity(self.helper.pid)
            if not self.helper.alive():
                raise OSError("DIAGNOSTIC_HELPER_INSTANCE_EXITED")
            expected_executable = self.broker.command(arguments)[0]
            verify_helper_hello(hello, nonce, actual, expected_executable)
            permission = hello.get("permission_level")
            if permission not in ("STANDARD", "ADMINISTRATOR") or (elevated and permission != "ADMINISTRATOR"):
                raise PermissionError("HELPER_TOKEN_NOT_ELEVATED")
            import msvcrt
            target_data = target.to_dict() if target else None
            started = time.monotonic()
            pipe.send({"kind": "init", "nonce": nonce, "parent": parent.to_dict(), "target": target_data,
                       "operations": operations, "require_admin": elevated,
                       "session_mode": "ADMIN_LEASE" if admin_lease else "TARGET_BOUND",
                       "session_seconds": session_seconds,
                       "recovery_source_handle": msvcrt.get_osfhandle(self._recovery_stream.fileno())},
                      deadline=deadline, cancel_event=cancel_event)
            ready = pipe.receive(deadline=deadline, cancel_event=cancel_event)
            if (ready.get("kind") != "ready" or ready.get("target") != target_data
                    or ready.get("operations") != operations or ready.get("permission_level") != permission):
                raise PermissionError("HELPER_SCOPE_HANDSHAKE_FAILED")
            if admin_lease and (ready.get("session_mode") != "ADMIN_LEASE" or ready.get("elevated_verified") is not True):
                raise PermissionError("ADMINISTRATIVE_LEASE_HANDSHAKE_FAILED")
            if admin_lease and (ready.get("helper_identity") != actual.to_dict()
                                or not isinstance(ready.get("token_authority"), dict)
                                or ready["token_authority"].get("elevated") is not True):
                raise PermissionError("ADMINISTRATIVE_HELPER_AUTHORITY_NOT_VERIFIED")
            if not self.helper.alive() or time.monotonic() >= started + session_seconds:
                raise OSError("DIAGNOSTIC_HELPER_EXITED_OR_EXPIRED_DURING_STARTUP")
            self._target, self._scope = target, frozenset() if admin_lease else frozenset(operations)
            self._permission, self._expires = permission, started + session_seconds
            self._helper_identity = actual
            self._helper_token_authority = ready.get("token_authority")
            self._session_nonce = nonce
            self._session_catalog = frozenset(operations)
            self._admin_session_managed = admin_lease
            self._elevated_verified = permission == "ADMINISTRATOR"
            self._admin_state = "ACTIVE" if elevated else "INACTIVE"
            self._interventions_started = False
            self._owner_retained = False
            self._cleanup_unconfirmed = False
            self._expiry_cleanup = None
            return result("session.open", "COMPLETED", data=self.session_status(), permission_level=permission)
        except BaseException:
            self._discard_helper(force=True)
            raise

    def _discard_helper(self, *, force: bool) -> None:
        errors = []
        if self._channel is not None:
            self._channel.close()
            self._channel = None
        if self.helper is not None:
            try:
                if force and self.helper.alive():
                    self.helper.terminate()
            except Exception as exc:
                errors.append(str(exc))
            if errors and self.helper.alive():
                # A failed termination must not erase the only held identity
                # of a still-live privileged owner. Keep it visible/retryable.
                self._owner_retained = True
                raise OSError("; ".join(errors))
            else:
                self.helper.close_handle()
                self.helper = None
        if self._recovery_stream is not None:
            self._recovery_stream.close()
            self._recovery_stream = None
        self._target, self._scope, self._expires = None, frozenset(), 0.0
        self._permission = "STANDARD"
        self._owner_retained = False
        self._elevated_verified = False
        self._helper_identity = None
        self._helper_token_authority = None
        self._session_nonce = None
        self._session_catalog = frozenset()
        self._admin_session_managed = False
        if errors:
            raise OSError("; ".join(errors))

    def _accept_expiry_cleanup(self, message: dict) -> dict:
        expected_context = {"target": self._target.to_dict() if self._target else None,
                            "operations": sorted(self._scope)}
        expired = message.get("kind") == "expired" and message.get("reason") == "LEASE_EXPIRED" and time.monotonic() >= self._expires
        requested_close = (message.get("kind") == "closed" and message.get("reason") == "EXPLICIT_CLOSE"
                           and self._pending_close_context is not None and message.get("context") == self._pending_close_context)
        if (not self._admin_session_managed or self._helper_identity is None or not self._session_nonce
                or not (expired or requested_close)
                or not hmac.compare_digest(str(message.get("nonce", "")), self._session_nonce)
                or message.get("identity") != self._helper_identity.to_dict()
                or message.get("context") != expected_context):
            raise PermissionError("INVALID_TERMINAL_LEASE_CLEANUP_ACKNOWLEDGEMENT")
        cleanup = message.get("result")
        if not isinstance(cleanup, dict) or not isinstance(cleanup.get("data"), dict):
            raise ValueError("INVALID_TERMINAL_LEASE_CLEANUP_RESULT")
        data = cleanup["data"]
        confirmed = bool(cleanup.get("status") == "COMPLETED" and message.get("context_released") is True
                         and data.get("target") is None and data.get("operations") == []
                         and not data.get("owner_retained")
                         and isinstance(data.get("cleanup"), dict) and data["cleanup"].get("status") == "COMPLETED")
        if cleanup.get("status") == "COMPLETED" and not confirmed:
            raise PermissionError("TERMINAL_LEASE_CONTEXT_RELEASE_NOT_VERIFIED")
        proof = {**cleanup, "confirmed": confirmed, "source": "AUTHENTICATED_HELPER_TERMINAL_ACK",
                 "helper_identity": self._helper_identity.to_dict(), "closed_context": expected_context,
                 "session_nonce_verified": True, "reason": message["reason"],
                 "original_deadline_monotonic": self._expires, "ack_received_monotonic": time.monotonic()}
        self._expiry_cleanup = proof
        self._pending_close_context = None
        self._elevated_verified = False
        if confirmed:
            self._target, self._scope = None, frozenset()
            self._interventions_started = self._owner_retained = self._cleanup_unconfirmed = False
            self._admin_state = "EXPIRED" if time.monotonic() >= self._expires else "INACTIVE"
        else:
            self._owner_retained = self._cleanup_unconfirmed = True
            self._admin_state = "CLEANUP_REQUIRED"
        try:
            self.journal.append({**proof, "operation_id": uuid4().hex, "operation": "session.expired",
                                 "target": expected_context["target"], "permission_level": self._permission})
            proof["journal_recorded"] = True
        except Exception:
            proof["journal_recorded"] = False
            self._cleanup_unconfirmed = True
            self._admin_state = "CLEANUP_REQUIRED"
        return proof

    def _consume_expiry_cleanup(self) -> dict | None:
        """Read a queued terminal ACK even after the authenticated peer exited."""
        if self._expiry_cleanup is not None:
            return self._expiry_cleanup
        if (not self._admin_session_managed or self._channel is None or self.helper is None
                or time.monotonic() < self._expires and self._pending_close_context is None):
            return None
        try:
            deadline = time.monotonic() + 25
            late_results = []
            for _ in range(4):
                response = self._channel.receive(deadline=deadline)
                if response.get("kind") == "result":
                    late_results.append({"request_id": response.get("request_id"),
                                         "status": response.get("result", {}).get("status")})
                    continue
                proof = self._accept_expiry_cleanup(response)
                if late_results:
                    proof["late_result_statuses"] = late_results
                return proof
            raise ValueError("TERMINAL_LEASE_CLEANUP_ACKNOWLEDGEMENT_NOT_RECEIVED")
        except Exception:
            self._elevated_verified = False
            if self._interventions_started or self._owner_retained or self._cleanup_unconfirmed:
                self._owner_retained = self._cleanup_unconfirmed = True
                self._admin_state = "CLEANUP_REQUIRED"
            return None

    def _managed_exchange(self, kind: str, *, cancel_event=None, **fields) -> dict:
        if not self._admin_session_managed or self._channel is None or not self._session_nonce:
            raise PermissionError("NO_AUTHENTICATED_ADMINISTRATIVE_LEASE")
        identifier = uuid4().hex
        expected = {"target.bind": "target.bound", "target.release": "target.released",
                    "session.status": "session.status"}[kind]
        deadline = time.monotonic() + (20 if kind != "session.status" else 5)
        self._channel.send({"kind": kind, "request_id": identifier, "nonce": self._session_nonce, **fields},
                           deadline=deadline, cancel_event=cancel_event)
        late_results = []
        for _ in range(4):
            response = self._channel.receive(deadline=deadline, cancel_event=cancel_event)
            if response.get("kind") == "expired":
                self._accept_expiry_cleanup(response)
                raise TimeoutError("ADMINISTRATIVE_LEASE_EXPIRED")
            if kind == "target.release" and response.get("kind") == "result":
                late_results.append({"request_id": response.get("request_id"),
                                     "status": response.get("result", {}).get("status")})
                continue
            break
        if response.get("kind") != expected or response.get("request_id") != identifier:
            raise PermissionError("ADMINISTRATIVE_CONTEXT_RESPONSE_IDENTITY_MISMATCH")
        answer = response.get("result")
        if not isinstance(answer, dict) or not isinstance(answer.get("status"), str):
            raise ValueError("INVALID_ADMINISTRATIVE_CONTEXT_RESPONSE")
        if late_results:
            answer.setdefault("data", {})["late_result_statuses"] = late_results
        return answer

    def start_admin_session(self, *, confirmed: bool = False, cancel_event=None,
                            session_seconds=MAX_SESSION_SECONDS) -> dict:
        """Request one finite elevated helper, without authorizing a target."""
        if (type(session_seconds) not in (int, float) or not math.isfinite(session_seconds)
                or not 1 <= session_seconds <= MAX_SESSION_SECONDS):
            raise ValueError("INVALID_SESSION_LIFETIME")
        if confirmed is not True:
            return result("session.elevate", "CONFIRMATION_REQUIRED",
                          uac={"requested": False, "result": "NOT_STARTED"},
                          data={"execution_started": False, "session_seconds": session_seconds},
                          next_action="REVIEW_ADMINISTRATIVE_LEASE_AND_UAC_PROMPT")
        with self._lock:
            if self._admin_session_managed and self.helper is not None and time.monotonic() >= self._expires:
                self._consume_expiry_cleanup()
            if self._owner_retained or self._cleanup_unconfirmed:
                return self._retained_result("session.elevate", "PREVIOUS_OWNER_CLEANUP_REQUIRES_EXPLICIT_RETRY")
            if self._admin_session_managed and self.admin_active:
                return result("session.elevate", "COMPLETED", data=self.session_status(),
                              uac={"requested": False, "result": "CURRENT_SESSION"})
            identifier = uuid4().hex
            base = {"action_id": identifier, "operation": "session.elevate", "target": None,
                    "source": "BLACKBOX_DIAGNOSTIC_ADMINISTRATIVE_LEASE",
                    "parameters": {"session_seconds": session_seconds,
                                   "operations": sorted(set(DEEP_ACTIONS) - LOCAL_OPERATIONS)},
                    "confirmation_provided": True, "permission_level": self._permission}
            try:
                self.journal.append({**base, "operation_id": identifier + ":requested", "phase": "REQUESTED",
                                     "uac": {"requested": True, "result": "PENDING"}})
            except Exception as exc:
                self._admin_state = "FAILED"
                return result("session.elevate", "OPERATION_FAILED", operation_id=identifier,
                              error="DURABLE_UAC_INTENT_FAILED", data={"error_type": type(exc).__name__},
                              uac={"requested": False, "result": "NOT_STARTED"})
            cleanup = self.end_admin_session()
            if cleanup.get("status") != "COMPLETED":
                return cleanup
            self._admin_state = "REQUESTING_UAC"
            try:
                answer = self._start_session(None, sorted(set(DEEP_ACTIONS) - LOCAL_OPERATIONS), elevated=True,
                                             admin_lease=True, session_seconds=session_seconds,
                                             cancel_event=cancel_event)
                if answer.get("status") != "COMPLETED":
                    self._admin_state = "FAILED"
                answer["uac"] = {"requested": True,
                                 "result": "TOKEN_VERIFIED" if answer.get("status") == "COMPLETED" else "FAILED"}
            except ElevationCancelled:
                self._admin_state = "DENIED"
                answer = result("session.elevate", "UAC_CANCELLED",
                                data={"ordinary_observation_available": True},
                                uac={"requested": True, "result": "CANCELLED"})
            except InterruptedError as exc:
                self._admin_state = "DENIED"
                answer = result("session.elevate", "CANCELLED", error=str(exc),
                                uac={"requested": True, "result": "CANCELLED"})
            except Exception as exc:
                self._admin_state = "DENIED" if isinstance(exc, PermissionError) else "FAILED"
                answer = result("session.elevate", "ACCESS_DENIED" if isinstance(exc, PermissionError) else "OPERATION_FAILED",
                                error=str(exc)[:2000], winerror=getattr(exc, "winerror", None),
                                uac={"requested": True, "result": "FAILED"})
            answer.update(operation="session.elevate", operation_id=identifier)
            try:
                answer["journal"] = self.journal.append({**base, **answer,
                    "operation_id": identifier + ":result", "phase": "RESULT"})
            except Exception as exc:
                cleanup = self.end_admin_session()
                self._admin_state = "FAILED"
                answer = result("session.elevate", "RECOVERY_UNCONFIRMED", operation_id=identifier,
                                error="UAC_RESULT_JOURNAL_FAILED", data={"cleanup": cleanup,
                                "error_type": type(exc).__name__}, uac=answer.get("uac"))
            return answer

    def bind_target(self, target: ProcessIdentity, operations: list[str], *, confirmed: bool = False,
                    cancel_event=None) -> dict:
        """Authorize an exact target context; this never launches another helper."""
        target = ProcessIdentity.from_dict(target)
        if type(operations) is not list or not operations or len(operations) > len(DEEP_ACTIONS):
            raise ValueError("INVALID_ELEVATED_OPERATION_SCOPE_INPUT")
        scope = sorted({canonical_operation(name) for name in operations} | {"capabilities"})
        if set(scope) & LOCAL_OPERATIONS:
            raise ValueError("INVALID_ELEVATED_OPERATION_SCOPE")
        with self._lock:
            if confirmed is not True:
                return result("target.bind", "CONFIRMATION_REQUIRED", data={"execution_started": False},
                              next_action="AUTHORIZE_TARGET_AND_OPERATION_SCOPE")
            if self._owner_retained or self._cleanup_unconfirmed:
                return self._retained_result("target.bind", "PREVIOUS_OWNER_CLEANUP_REQUIRES_EXPLICIT_RETRY")
            if not self._admin_session_managed or not self.admin_active:
                return result("target.bind", "SESSION_EXPIRED" if self._expires and time.monotonic() >= self._expires
                              else "ADMIN_REQUIRED", next_action="START_AN_ADMINISTRATIVE_SESSION")
            identifier = uuid4().hex
            base = {"action_id": identifier, "operation": "target.bind", "target": target.to_dict(),
                    "parameters": {"operations": scope}, "confirmation_provided": True,
                    "permission_level": self._permission, "source": "ADMINISTRATIVE_TARGET_CONTEXT"}
            try:
                self.journal.append({**base, "operation_id": identifier + ":requested", "phase": "REQUESTED"})
            except Exception as exc:
                return result("target.bind", "OPERATION_FAILED", error="DURABLE_TARGET_CONSENT_FAILED",
                              data={"execution_started": False, "error_type": type(exc).__name__})
            try:
                answer = self._managed_exchange("target.bind", target=target.to_dict(), operations=scope,
                                                confirmed=True, cancel_event=cancel_event)
                if answer.get("status") == "COMPLETED":
                    data = answer.get("data", {})
                    if data.get("target") != target.to_dict() or data.get("operations") != scope:
                        raise PermissionError("ADMINISTRATIVE_TARGET_BIND_ACKNOWLEDGEMENT_MISMATCH")
                    self._target, self._scope = target, frozenset(scope)
                    self._interventions_started = False
                elif answer.get("status") == "RECOVERY_UNCONFIRMED":
                    answer = self._retained_result("target.bind", "PREVIOUS_CONTEXT_CLEANUP_UNCONFIRMED", cleanup=answer)
                else:
                    data = answer.get("data", {})
                    if (data.get("context_verified") is True and data.get("target") is None
                            and data.get("operations") == [] and data.get("cleanup_required") is False):
                        # The helper verified the previous owner's release but
                        # the new process exited/changed before context creation.
                        self._target, self._scope = None, frozenset()
                        self._interventions_started = False
                if answer.get("error") == "ELEVATED_TOKEN_NOT_GRANTED":
                    self._elevated_verified = False
                    self._admin_state = "FAILED"
            except Exception as exc:
                answer = (result("target.bind", "SESSION_EXPIRED", data={"expiry_cleanup": deepcopy(self._expiry_cleanup)})
                          if self._expiry_cleanup and self._expiry_cleanup.get("confirmed") else
                          self._retained_result("target.bind", "TARGET_BIND_ACKNOWLEDGEMENT_LOST: " + str(exc)[:1000]))
            answer["operation_id"] = identifier
            try:
                answer["journal"] = self.journal.append({**base, **answer,
                    "operation_id": identifier + ":result", "phase": "RESULT"})
            except Exception as exc:
                answer = self._retained_result("target.bind", "TARGET_CONSENT_RESULT_JOURNAL_FAILED: " + str(exc)[:1000])
            return answer

    def clear_target(self, *, cancel_event=None) -> dict:
        """Explicitly clean a context, retaining the original elevated lease."""
        with self._lock:
            if not self._admin_session_managed:
                return self.end_admin_session()
            if self._target is None and not self._owner_retained and not self._cleanup_unconfirmed:
                return result("target.release", "COMPLETED", data={"target": None, "operations": []})
            closing_target = self._target.to_dict() if self._target else None
            try:
                answer = self._managed_exchange("target.release", cancel_event=cancel_event)
                if answer.get("status") == "COMPLETED":
                    if answer.get("data", {}).get("target") is not None:
                        raise PermissionError("ADMINISTRATIVE_CONTEXT_RELEASE_ACKNOWLEDGEMENT_MISMATCH")
                    self._target, self._scope = None, frozenset()
                    self._owner_retained = self._cleanup_unconfirmed = False
                    self._interventions_started = False
                    self._admin_state = "ACTIVE"
                else:
                    answer = self._retained_result("target.release", "PREVIOUS_CONTEXT_CLEANUP_UNCONFIRMED", cleanup=answer)
            except Exception as exc:
                answer = (result("target.release", "COMPLETED", data={"target": None, "operations": [],
                                  "expiry_cleanup": deepcopy(self._expiry_cleanup)})
                          if self._expiry_cleanup and self._expiry_cleanup.get("confirmed") else
                          self._retained_result("target.release", "TARGET_RELEASE_ACKNOWLEDGEMENT_LOST: " + str(exc)[:1000]))
            try:
                answer["journal"] = self.journal.append({**answer, "operation_id": uuid4().hex,
                    "operation": "target.release", "target": closing_target,
                    "source": "ADMINISTRATIVE_TARGET_CONTEXT_CLEANUP", "permission_level": self._permission})
            except Exception as exc:
                answer = self._retained_result("target.release", "CONTEXT_CLEANUP_JOURNAL_FAILED: " + str(exc)[:1000])
            return answer

    def set_target(self, target: ProcessIdentity | None, *, cancel_event=None) -> dict:
        # Selection is deliberately separate from target authorization.
        target = ProcessIdentity.from_dict(target) if target is not None else None
        with self._lock:
            if target is not None and target == self._target and not self._owner_retained and not self._cleanup_unconfirmed:
                return result("target.select", "COMPLETED", data={"target": target.to_dict()})
            return self.clear_target(cancel_event=cancel_event)

    def _ensure_session(self, request: ActionRequest, cancel_event=None) -> dict | None:
        managed = self._admin_session_managed
        if managed and self.helper is not None and time.monotonic() >= self._expires:
            self._consume_expiry_cleanup()
        if managed and self._admin_state == "FAILED" and not self._owner_retained:
            return result(request.operation, "OPERATION_FAILED", error="ADMINISTRATIVE_HELPER_VERIFICATION_FAILED",
                          next_action="END_SESSION_AND_REVIEW_HELPER_FAILURE")
        if self.helper is not None:
            if not self.helper.alive() or time.monotonic() >= self._expires:
                unconfirmed = self._interventions_started
                # Let the helper finish its original finite lease cleanup.
                # Killing a held INT3 owner immediately could resume unsafe RIP.
                if unconfirmed and self.helper.alive() and time.monotonic() < self._expires + 30:
                    return self._retained_result(request.operation, "SESSION_EXPIRED_CLEANUP_PENDING")
                try:
                    self._discard_helper(force=True)
                except Exception as exc:
                    if self.helper is not None and self.helper.alive():
                        return self._retained_result(request.operation, "EXPIRED_HELPER_STOP_UNCONFIRMED: " + str(exc)[:1000])
                    raise
                if unconfirmed:
                    self._cleanup_unconfirmed = True
                    self._admin_state = "CLEANUP_REQUIRED"
                    return result(request.operation, "RECOVERY_UNCONFIRMED", error="PREVIOUS_INTERVENTION_SESSION_TERMINATED",
                                  next_action="REVIEW_RECOVERY_REPORT_BEFORE_STARTING_A_NEW_SESSION")
            elif self._target != request.target:
                if managed:
                    if self._owner_retained or self._cleanup_unconfirmed:
                        return self._retained_result(request.operation, "PREVIOUS_OWNER_CLEANUP_REQUIRES_EXPLICIT_RETRY")
                    return result(request.operation, "CONFIRMATION_REQUIRED", data={"execution_started": False},
                                  next_action="AUTHORIZE_TARGET_AND_OPERATION_SCOPE")
                closed = self.end_admin_session()
                if closed["status"] != "COMPLETED":
                    return closed
            elif request.operation not in self._scope:
                if managed:
                    return result(request.operation, "CONFIRMATION_REQUIRED", data={"execution_started": False},
                                  next_action="AUTHORIZE_TARGET_AND_OPERATION_SCOPE")
                return result(request.operation, "ACCESS_DENIED", error="OPERATION_OUTSIDE_APPROVED_SESSION_SCOPE",
                              next_action="END_SESSION_AND_APPROVE_A_NEW_OPERATION_SCOPE")
            elif self._owner_retained and request.operation not in (
                    "debug.detach", "debug.context", "debug.breakpoints", "capabilities"):
                return self._retained_result(request.operation, "PREVIOUS_OWNER_CLEANUP_REQUIRES_RETRY")
            else:
                return None
        if managed:
            self._admin_state = "EXPIRED"
            return result(request.operation, "SESSION_EXPIRED", next_action="START_AN_ADMINISTRATIVE_SESSION")
        opened = self._start_session(request.target, sorted(set(DEEP_ACTIONS) - LOCAL_OPERATIONS),
                                     elevated=False, cancel_event=cancel_event)
        return opened if opened["status"] != "COMPLETED" else None

    def _retained_result(self, operation: str, error: str, *, cleanup=None) -> dict:
        self._owner_retained = True
        self._cleanup_unconfirmed = True
        self._admin_state = "CLEANUP_REQUIRED"
        return result(operation, "RECOVERY_UNCONFIRMED", error=error, retains_service=True,
                      data={"owner_retained": True, "retry_cleanup_required": True,
                            "helper_pid": self.helper_pid, "target": self._target.to_dict() if self._target else None,
                            "expires_in_seconds": max(0, self._expires - time.monotonic()),
                            "cleanup": cleanup},
                      limitations=["The original helper lease is not extended. Retry cleanup before it expires; owner exit at the finite lease/cleanup boundary can resume an unverified debug context."])

    def elevate(self, target: ProcessIdentity, operations: list[str], *, confirmed: bool = False, cancel_event=None) -> dict:
        target = ProcessIdentity.from_dict(target)
        # Reject malformed/unbounded command input before constructing audit
        # metadata. Known typed scope refusals are still diagnostic outcomes.
        if type(operations) is not list or len(operations) > len(DEEP_ACTIONS):
            raise ValueError("INVALID_ELEVATED_OPERATION_SCOPE_INPUT")
        scope = sorted({canonical_operation(name) for name in operations} | {"capabilities"})
        if self._admin_session_managed and confirmed is True and operations and not set(scope) & LOCAL_OPERATIONS:
            return self.bind_target(target, operations, confirmed=True, cancel_event=cancel_event)
        if confirmed is not True or not operations or set(scope) & LOCAL_OPERATIONS:
            identifier = uuid4().hex
            answer = (result("session.elevate", "CONFIRMATION_REQUIRED",
                             next_action="REVIEW_OPERATION_SCOPE_AND_UAC_PROMPT") if confirmed is not True else
                      result("session.elevate", "OPERATION_FAILED", error="INVALID_ELEVATED_OPERATION_SCOPE"))
            answer.update(operation_id=identifier, uac={"requested": False, "result": "NOT_STARTED"})
            answer["data"] = {"execution_started": False, "changes": "NONE"}
            base = {"action_id": identifier, "operation": "session.elevate", "target": target.to_dict(),
                    "source": "BLACKBOX_DIAGNOSTIC_SESSION_ELEVATION", "permission_level": self._permission,
                    "parameters": {"operations": scope}, "confirmation_provided": confirmed is True,
                    "uac": answer["uac"], "before": {"elevation": "NOT_STARTED"}}
            with self._lock:
                try:
                    self.journal.append({**base, "operation_id": identifier + ":requested", "phase": "REQUESTED"})
                except Exception as exc:
                    return result("session.elevate", "OPERATION_FAILED", operation_id=identifier,
                                  error="DURABLE_UAC_INTENT_FAILED", uac=answer["uac"],
                                  data={"execution_started": False, "error_type": type(exc).__name__})
                try:
                    answer["journal"] = self.journal.append({**base, **answer, "operation_id": identifier + ":result",
                                                             "phase": "RESULT", "after": {"elevation": "NOT_STARTED"}})
                except Exception as exc:
                    return result("session.elevate", "OPERATION_FAILED", operation_id=identifier,
                                  error="UAC_REFUSAL_RESULT_JOURNAL_FAILED", uac=answer["uac"],
                                  data={"execution_started": False, "reported_operation_status": answer["status"],
                                        "error_type": type(exc).__name__})
            return answer
        identifier = uuid4().hex
        with self._lock:
            try:
                self.journal.append({"operation_id": identifier + ":requested", "action_id": identifier,
                                     "operation": "session.elevate", "target": target.to_dict(),
                                     "parameters": {"operations": scope}, "phase": "REQUESTED",
                                     "uac": {"requested": True, "result": "PENDING"}, "permission_level": self._permission})
            except Exception as exc:
                return result("session.elevate", "OPERATION_FAILED", operation_id=identifier,
                              error="DURABLE_UAC_INTENT_FAILED: " + str(exc)[:1000],
                              uac={"requested": False, "result": "NOT_STARTED"})
            cleanup = self.end_admin_session()
            if cleanup["status"] != "COMPLETED":
                return cleanup
            try:
                self._admin_state = "REQUESTING_UAC"
                answer = self._start_session(target, scope, elevated=True, cancel_event=cancel_event)
                answer["uac"] = {"requested": True, "result": "TOKEN_VERIFIED" if answer["status"] == "COMPLETED" else "FAILED"}
                answer["limitations"].append("Secure Desktop visibility is controlled by Windows; this result verifies the granted helper token.")
            except ElevationCancelled:
                self._admin_state = "DENIED"
                answer = result("session.elevate", "UAC_CANCELLED", data={"ordinary_observation_available": True},
                                uac={"requested": True, "result": "CANCELLED"}, next_action="CONTINUE_WITH_CURRENT_PERMISSIONS")
            except InterruptedError as exc:
                self._admin_state = "DENIED"
                answer = result("session.elevate", "CANCELLED", error=str(exc), uac={"requested": True, "result": "CANCELLED"})
            except Exception as exc:
                self._admin_state = "DENIED" if isinstance(exc, PermissionError) else "FAILED"
                answer = result("session.elevate", "ACCESS_DENIED" if isinstance(exc, PermissionError) else "OPERATION_FAILED",
                                error=str(exc)[:2000], winerror=getattr(exc, "winerror", None),
                                uac={"requested": True, "result": "FAILED"})
            answer.update(operation="session.elevate", operation_id=identifier)
            try:
                self.journal.append({**answer, "operation_id": identifier + ":result", "action_id": identifier,
                                     "target": target.to_dict(), "phase": "RESULT"})
            except Exception as exc:
                cleanup = self.end_admin_session()
                answer = result("session.elevate", "RECOVERY_UNCONFIRMED", operation_id=identifier,
                                error="UAC_RESULT_JOURNAL_FAILED: " + str(exc)[:1000],
                                data={"reported_status": answer.get("status"), "cleanup": cleanup},
                                uac=answer.get("uac"),
                                limitations=["Cleanup of the new elevated session was requested because its durable result could not be recorded; inspect the reported cleanup status."])
            return answer

    def _local(self, request: ActionRequest, cancel_event=None, *, deadline=None) -> dict:
        p = dict(request.parameters)
        deadline = deadline if deadline is not None else time.monotonic() + request.timeout_seconds
        if request.operation == "timeline":
            return result("timeline", "COMPLETED", data={"entries": self.journal.timeline(limit=p.get("limit", 200))})
        if request.operation == "compare":
            comparison = self.journal.compare(p["before_id"], p["after_id"])
            if comparison["target"] != request.target.to_dict():
                return result("compare", "PROCESS_CHANGED", error="COMPARISON_TARGET_DOES_NOT_MATCH_SELECTED_INSTANCE")
            return result("compare", "COMPLETED", data=comparison)
        if request.operation == "trace_evidence":
            from .deep_trace import build_trace_evidence
            return build_trace_evidence(p.pop("index_path"), request.target.to_dict(), cancel_event=cancel_event, deadline=deadline, **p)
        if request.operation == "symbols_verify":
            from .deep_trace import verify_local_symbols
            return verify_local_symbols(p.pop("pe_path"), p.pop("pdb_path"), cancel_event=cancel_event, deadline=deadline, **p)
        if request.operation == "dump_inspect":
            from .deep_dump import inspect_dump
            return inspect_dump(p.pop("path"), cancel_event=cancel_event, deadline=deadline, **p)
        if request.operation == "dump_read_memory":
            from .deep_dump import read_dump_memory
            return read_dump_memory(p.pop("path"), p.pop("address"), p.pop("size"), cancel_event=cancel_event, deadline=deadline, **p)
        raise ValueError("LOCAL_OPERATION_NOT_IMPLEMENTED")

    def _cancel_active(self, identifier: str) -> dict:
        permission = self._permission
        if self._expiry_cleanup is not None:
            return result("unknown", "RECOVERY_UNCONFIRMED",
                          error="OPERATION_RESULT_NOT_OBSERVED_BEFORE_LEASE_EXPIRY",
                          permission_level=permission, data={"expiry_cleanup": deepcopy(self._expiry_cleanup)},
                          limitations=["Terminal cleanup does not prove whether the interrupted action committed an effect; do not retry automatically."])
        try:
            deadline = time.monotonic() + 5
            message = {"kind": "cancel", "request_id": identifier}
            if self._admin_session_managed:
                message["nonce"] = self._session_nonce
            self._channel.send(message, deadline=deadline)
            response = self._channel.receive(deadline=deadline)
            if response.get("kind") == "expired":
                self._accept_expiry_cleanup(response)
                return self._cancel_active(identifier)
            if response.get("kind") == "result" and response.get("request_id") == identifier:
                value = response["result"]
                value["cancellation_requested"] = True
                return value
        except Exception:
            pass
        if self._interventions_started and self.helper is not None and self.helper.alive():
            cleanup = self.end_admin_session()
            if cleanup.get("data", {}).get("owner_retained"):
                return self._retained_result("unknown", "INTERVENTION_CANCELLATION_ACKNOWLEDGEMENT_LOST", cleanup=cleanup)
            return result("unknown", "RECOVERY_UNCONFIRMED",
                          error="INTERVENTION_CANCELLATION_ACKNOWLEDGEMENT_LOST",
                          permission_level=permission, data={"cleanup": cleanup},
                          limitations=["The original action result is unknown even if subsequent cleanup completed."])
        try:
            self._discard_helper(force=True)
        except Exception as exc:
            return result("unknown", "RECOVERY_UNCONFIRMED", error=str(exc))
        return result("unknown", "RECOVERY_UNCONFIRMED" if self._interventions_started else "CANCELLED",
                      error="HELPER_STOPPED_AFTER_CANCELLATION_GRACE",
                      permission_level=permission,
                      limitations=["A started native action may have completed before cancellation; inspect recovery evidence."])

    def _artifact_access(self, request: ActionRequest, identifier: str, cancel_event=None, *, operation_deadline=None) -> dict | None:
        """Probe before creating a file so a denied attempt leaves no collision.

        This is an observation, not a granted right: native writing still
        rechecks exact target identity and actual Windows permissions.
        """
        probe_id = identifier + ":access"
        remaining = (request.timeout_seconds if operation_deadline is None else
                     min(request.timeout_seconds, operation_deadline - time.monotonic()))
        if remaining < .1:
            raise TimeoutError("DIAGNOSTIC_OPERATION_TIMED_OUT")
        probe = ActionRequest("capabilities", request.target, {"operations": [request.operation]},
                              timeout_seconds=min(15, remaining))
        deadline = time.monotonic() + probe.timeout_seconds + 2
        self._active_request_id = probe_id
        try:
            envelope = {"kind": "execute", "request_id": probe_id, "request": probe.to_dict()}
            if self._admin_session_managed:
                envelope["nonce"] = self._session_nonce
            self._channel.send(envelope,
                               deadline=deadline, cancel_event=cancel_event)
            response = self._channel.receive(deadline=deadline, cancel_event=cancel_event)
            if response.get("kind") == "expired":
                self._accept_expiry_cleanup(response)
                raise TimeoutError("ADMINISTRATIVE_LEASE_EXPIRED")
        except InterruptedError:
            return self._cancel_active(probe_id)
        except TimeoutError:
            answer = self._cancel_active(probe_id)
            answer["deadline_exceeded"] = True
            if answer.get("status") == "CANCELLED":
                answer["status"] = "TIMED_OUT"
            return answer
        finally:
            self._active_request_id = None
        if response.get("kind") != "result" or response.get("request_id") != probe_id:
            raise ValueError("DIAGNOSTIC_ACCESS_PROBE_IDENTITY_MISMATCH")
        answer = response["result"]
        if answer.get("status") != "COMPLETED":
            return {**answer, "operation": request.operation}
        rows = answer.get("data", {}).get("operations", [])
        if len(rows) != 1 or rows[0].get("operation") != request.operation:
            raise ValueError("DIAGNOSTIC_ACCESS_PROBE_SCOPE_MISMATCH")
        access = rows[0]
        if access.get("status") != "AVAILABLE":
            return result(request.operation, access.get("status", "OPERATION_FAILED"),
                          data={"access_probe": access}, error=access.get("error", access.get("reason")),
                          next_action=access.get("next_action", "REVIEW_OPERATION_ACCESS_STATUS"),
                          limitations=["No output file was created; permissions will be rechecked on retry."])
        return None

    def execute(self, request: ActionRequest | dict, cancel_event=None) -> dict:
        request = request if isinstance(request, ActionRequest) else ActionRequest.from_dict(request)
        validate_parameters(request.parameters)
        identifier = uuid4().hex
        spec = DEEP_ACTIONS[request.operation]
        with self._lock:
            run_context = begin_run(request, run_id=identifier, permission_level=self._permission)
            operation_deadline = run_context.deadline_monotonic_ns / 1_000_000_000
            base = {"action_id": identifier, "operation": request.operation,
                    "target": request.target.to_dict(), "source": "BLACKBOX_DIAGNOSTIC_ACTION_ENGINE",
                    "parameters": request.parameters, "permission_level": self._permission,
                    "uac": {"requested": False, "result": "CURRENT_SESSION"},
                    "confirmation": {"required": spec.confirmation_required, "provided": request.confirmed},
                    "before": {"session": self.session_status()}, "limitations": [],
                    "run_context": run_context.to_dict(),
                    "tool_descriptor": describe_tool(request.operation).to_dict()}
            # A durable intent is mandatory BEFORE any process intervention.
            try:
                self.journal.append({**base, "operation_id": identifier + ":requested", "phase": "REQUESTED"})
            except Exception as exc:
                return attach_run_receipt(run_context, result(request.operation, "OPERATION_FAILED", operation_id=identifier,
                              error="DURABLE_INTENT_FAILED: " + str(exc)[:1000],
                              next_action="RESTORE_JOURNAL_STORAGE_BEFORE_RETRYING"), execution_started=False)
            dump_stream = None
            output_path = None
            operation_permission = self._permission
            intervention_dispatch_attempted = False
            execution_started = False
            execution_source = None
            execution_source_verified = False
            execution_target_verified = False
            execution_helper_pid = None
            execution_reply_verified = False
            try:
                validate_operation_parameters(request.operation, request.parameters, allow_output=True)
                check_deadline(operation_deadline, cancel_event)
                if spec.confirmation_required and not request.confirmed:
                    answer = result(request.operation, "CONFIRMATION_REQUIRED",
                                    data={"execution_started": False, "changes": "NONE"},
                                    next_action="CONFIRM_TARGET_PARAMETERS_AND_OPERATION_IMPACT")
                elif request.operation in LOCAL_OPERATIONS:
                    execution_started = True
                    execution_source = "LOCAL_DIAGNOSTIC_OPERATION"
                    answer = self._local(request, cancel_event, deadline=operation_deadline)
                    execution_source_verified = request.operation == "timeline"
                elif os.name != "nt":
                    answer = result(request.operation, "UNSUPPORTED_PLATFORM", next_action="USE_WINDOWS_10_OR_11_X64")
                else:
                    blocked = self._ensure_session(request, cancel_event)
                    check_deadline(operation_deadline, cancel_event)
                    if (blocked is None and request.operation == "profile.etw"
                            and self._permission != "ADMINISTRATOR"):
                        # Refuse before reserving the output file. The UI can
                        # retry this exact destination after scoped UAC without
                        # an abandoned empty file or unsafe path-based deletion.
                        blocked = result("profile.etw", "ADMIN_REQUIRED",
                                         error="ETW_PROFILE_REQUIRES_SCOPED_ADMINISTRATOR_HELPER",
                                         next_action="REQUEST_UAC_FOR_THIS_OPERATION")
                    if blocked is None and request.operation == "dump":
                        blocked = self._artifact_access(request, identifier, cancel_event,
                                                        operation_deadline=operation_deadline)
                    if blocked is not None:
                        answer = blocked
                    else:
                        operation_permission = self._permission
                        execution_helper_pid = self.helper_pid
                        execution_source = "DIAGNOSTIC_HELPER"
                        parameters = dict(request.parameters)
                        envelope = {"kind": "execute", "request_id": identifier}
                        if self._admin_session_managed:
                            envelope["nonce"] = self._session_nonce
                        if request.operation in ("dump", "profile.etw"):
                            import msvcrt
                            destination = parameters.pop("destination", None)
                            if destination is None:
                                destination = parameters.pop("path", parameters.pop("output_path", None))
                            if not isinstance(destination, str) or not destination or "\0" in destination:
                                raise ValueError("EXPLICIT_ARTIFACT_DESTINATION_REQUIRED")
                            output_path = Path(destination)
                            dump_stream = output_path.open("x+b")
                            envelope["attachment"] = {"source_file_handle": msvcrt.get_osfhandle(dump_stream.fileno())}
                        remaining = min(request.timeout_seconds, operation_deadline - time.monotonic())
                        if remaining < .1:
                            raise TimeoutError("DIAGNOSTIC_OPERATION_TIMED_OUT")
                        remote = ActionRequest(request.operation, request.target, parameters,
                                               request.confirmed, remaining)
                        envelope["request"] = remote.to_dict()
                        self._active_request_id = identifier
                        if spec.mode == "INTERVENE" or request.operation in ("thread_stacks", "profile.etw"):
                            self._interventions_started = True
                        deadline = operation_deadline + 2
                        try:
                            intervention_dispatch_attempted = spec.mode == "INTERVENE" or request.operation == "thread_stacks"
                            execution_started = None  # Sending can commit before its acknowledgement is lost.
                            self._channel.send(envelope, deadline=deadline, cancel_event=cancel_event)
                            response = self._channel.receive(deadline=deadline, cancel_event=cancel_event)
                            if response.get("kind") == "expired":
                                self._accept_expiry_cleanup(response)
                                raise TimeoutError("ADMINISTRATIVE_LEASE_EXPIRED")
                            if response.get("kind") != "result" or response.get("request_id") != identifier:
                                raise ValueError("DIAGNOSTIC_RESPONSE_IDENTITY_MISMATCH")
                            answer = response["result"]
                            execution_reply_verified = True
                        except InterruptedError:
                            answer = self._cancel_active(identifier)
                        except TimeoutError:
                            answer = self._cancel_active(identifier)
                            if answer["status"] == "CANCELLED":
                                answer["status"] = "TIMED_OUT"
                            answer["deadline_exceeded"] = True
                        finally:
                            self._active_request_id = None
                if execution_reply_verified or answer.get("cancellation_requested") is True:
                    evidence = answer.get("diagnostic_execution", {})
                    if (isinstance(evidence, dict) and evidence.get("source") == "DIAGNOSTIC_HELPER"
                            and evidence.get("target") == request.target.to_dict()
                            and evidence.get("source_verified") is True):
                        execution_started = True
                        execution_source_verified = True
                        execution_target_verified = evidence.get("target_verified") is True
                    elif answer.get("status") in ("CONFIRMATION_REQUIRED", "PROCESS_CHANGED", "ACCESS_DENIED",
                                                  "ADMIN_REQUIRED", "SESSION_EXPIRED"):
                        execution_started = False
                if self._admin_session_managed and answer.get("error") == "ELEVATED_TOKEN_NOT_GRANTED":
                    self._elevated_verified = False
                    self._admin_state = "FAILED"
                    if self._interventions_started:
                        self._owner_retained = self._cleanup_unconfirmed = True
                if request.operation == "snapshot" and answer.get("status") in ("COMPLETED", "INCOMPLETE_EVIDENCE"):
                    snapshot = answer.get("data", {})
                    snapshot_id = self.journal.snapshot(request.target.to_dict(), snapshot)
                    answer["data"] = {"snapshot_id": snapshot_id, "snapshot": snapshot}
                if answer.get("data", {}).get("owner_retained"):
                    self._owner_retained = True
                if (self._admin_session_managed and self.helper is not None
                        and answer.get("status") == "RECOVERY_UNCONFIRMED"
                        and not (self._expiry_cleanup and self._expiry_cleanup.get("confirmed"))):
                    self._owner_retained = self._cleanup_unconfirmed = True
                    self._admin_state = "CLEANUP_REQUIRED"
                    answer["retains_service"] = True
                    answer.setdefault("data", {}).update(owner_retained=True, retry_cleanup_required=True)
                elif (request.operation == "debug.detach" and answer.get("status") == "COMPLETED"
                      and not self._admin_session_managed):
                    self._owner_retained = False
                    self._cleanup_unconfirmed = False
                    self._admin_state = "ACTIVE" if self._elevated_verified else "INACTIVE"
                if output_path is not None:
                    answer.setdefault("data", {})["destination"] = str(output_path)
                    answer["data"]["sensitive_artifact"] = True
                    answer["data"]["automatic_share_export"] = False
            except InterruptedError as exc:
                answer = result(request.operation, "CANCELLED", error=str(exc))
            except TimeoutError as exc:
                answer = result(request.operation, "TIMED_OUT", error=str(exc))
            except Exception as exc:
                status = getattr(exc, "status", "OPERATION_FAILED")
                if intervention_dispatch_attempted:
                    # A living helper can have performed the native effect
                    # before its pipe/reply fails. Liveness is not an ACK.
                    cleanup = self.end_admin_session()
                    if cleanup.get("data", {}).get("owner_retained"):
                        answer = self._retained_result(request.operation, "INTERVENTION_RESULT_ACKNOWLEDGEMENT_LOST: " + str(exc)[:1000], cleanup=cleanup)
                    else:
                        answer = result(request.operation, "RECOVERY_UNCONFIRMED",
                                        error="INTERVENTION_RESULT_ACKNOWLEDGEMENT_LOST: " + str(exc)[:1000],
                                        data={"cleanup": cleanup},
                                        limitations=["A native action may have completed; subsequent cleanup does not prove it never ran. Do not retry automatically."])
                else:
                    if self._interventions_started and self.helper is not None and not self.helper.alive():
                        status = "RECOVERY_UNCONFIRMED"
                    answer = result(request.operation, status, error=str(exc)[:2000], winerror=getattr(exc, "winerror", None))
            finally:
                if dump_stream is not None:
                    dump_stream.close()
            answer.update(operation=request.operation, operation_id=identifier)
            answer.setdefault("permission_level", operation_permission)
            answer.setdefault("limitations", [])
            receipt_arguments = dict(execution_started=execution_started, source=execution_source,
                                     source_verified=execution_source_verified,
                                     target_verified=execution_target_verified, helper_pid=execution_helper_pid)
            answer = attach_run_receipt(run_context, answer, **receipt_arguments)
            # Imported trace payloads and live memory are not ordinary metadata.
            journal_answer = dict(answer)
            if request.operation in ("trace_evidence", "memory_read", "dump_read_memory"):
                journal_answer["data"] = {"omitted": "SENSITIVE_OR_IMPORTED_PAYLOAD",
                                          "returned_status": answer.get("status")}
            elif request.operation == "timeline":
                journal_answer["data"] = {"returned_entries": len(answer.get("data", {}).get("entries", [])),
                                          "query_limit": request.parameters.get("limit", 200)}
            elif request.operation == "compare":
                journal_answer["data"] = {k: answer.get("data", {}).get(k) for k in
                                          ("before_id", "after_id", "changed_sections", "acquisition_metadata_changes",
                                           "comparison_scope", "interpretation")}
            try:
                recorded = self.journal.append({**base, **journal_answer,
                                                "operation_id": identifier + ":result", "action_id": identifier,
                                                "phase": "RESULT"})
                answer["journal"] = recorded
            except Exception as exc:
                failure = "RESULT_JOURNAL_COMMIT_FAILED: " + str(exc)[:1000]
                reported = {"reported_operation_status": answer.get("status")}
                if (self.helper is not None and (self._owner_retained
                        or self._admin_session_managed and self._interventions_started)):
                    answer = self._retained_result(request.operation, failure, cleanup=reported)
                    answer["operation_id"] = identifier
                    answer["limitations"].append("The durable result could not be recorded; do not repeat the action blindly.")
                elif answer.get("status") == "CONFIRMATION_REQUIRED":
                    answer = result(request.operation, "OPERATION_FAILED", operation_id=identifier,
                                    error="REFUSAL_RESULT_JOURNAL_COMMIT_FAILED",
                                    data={**reported, "execution_started": False},
                                    limitations=["The action was not started; its confirmation refusal could not be durably recorded."])
                else:
                    answer = result(request.operation, "RECOVERY_UNCONFIRMED", operation_id=identifier,
                                    error=failure, data=reported,
                                    limitations=["The action may have completed; its durable result could not be recorded. Do not repeat blindly."])
                answer = attach_run_receipt(run_context, answer, **receipt_arguments)
            return answer

    def export_journal(self, destination: str | Path, *, cancel_event=None) -> dict:
        identifier = uuid4().hex
        with self._lock:
            base = {"action_id": identifier, "operation": "journal.export", "target": None,
                    "source": "BLACKBOX_DIAGNOSTIC_JOURNAL_EXPORT", "permission_level": "GUI_TOKEN_NO_ELEVATION",
                    "uac": {"requested": False, "result": "NOT_REQUIRED"},
                    "parameters": {"format": "JSONL", "destination": "EXPLICIT_USER_SELECTION_OMITTED"},
                    "before": {"publication": "NOT_STARTED"},
                    "changes": {"process_state": "UNCHANGED", "artifact": "CREATE_NEW_METADATA_SNAPSHOT"},
                    "limitations": ["The export is an immutable prefix through REQUESTED; its publication RESULT remains in the local journal and a later export."]}
            try:
                self.journal.append({**base, "operation_id": identifier + ":requested", "phase": "REQUESTED"})
            except Exception as exc:
                return result("journal.export", "OPERATION_FAILED", operation_id=identifier,
                              error="DURABLE_EXPORT_INTENT_FAILED", data={"export_published": False,
                              "error_type": type(exc).__name__, "winerror": getattr(exc, "winerror", None)},
                              next_action="RESTORE_JOURNAL_STORAGE_BEFORE_RETRYING")
            path = None
            try:
                receipt = self.journal.export_snapshot(destination, cancel_event=cancel_event)
                path = receipt.pop("path")
                answer = result("journal.export", "COMPLETED", data={**receipt, "export_published": True,
                                "memory_and_dumps": "EXCLUDED", "export_scope": "SNAPSHOT_THROUGH_EXPORT_REQUESTED"},
                                limitations=base["limitations"])
            except Exception as exc:
                # Exception text can contain the user-selected destination or
                # other filesystem paths. Record only typed/native codes.
                code = (str(exc) if type(exc) in (ValueError, InterruptedError) and str(exc) in
                        {"JOURNAL_HASH_CHAIN_MISMATCH", "JOURNAL_EXPORT_CANCELLED"} else
                        "JOURNAL_EXPORT_DESTINATION_EXISTS" if isinstance(exc, FileExistsError) else
                        "JOURNAL_EXPORT_ACCESS_DENIED" if isinstance(exc, PermissionError) else "JOURNAL_EXPORT_FAILED")
                answer = result("journal.export", "CANCELLED" if isinstance(exc, InterruptedError) else "OPERATION_FAILED",
                                error=code, data={"export_published": False if isinstance(exc, (FileExistsError, InterruptedError)) or
                                code == "JOURNAL_HASH_CHAIN_MISMATCH" else "UNCONFIRMED",
                                "memory_and_dumps": "EXCLUDED", "error_type": type(exc).__name__,
                                "winerror": getattr(exc, "winerror", None), "errno": getattr(exc, "errno", None)})
            answer["operation_id"] = identifier
            try:
                answer["journal"] = self.journal.append({**base, **answer, "operation_id": identifier + ":result",
                                                        "phase": "RESULT", "after": {"publication": answer["data"]["export_published"]}})
            except Exception as exc:
                answer = result("journal.export", "RECOVERY_UNCONFIRMED", operation_id=identifier,
                                error="EXPORT_RESULT_JOURNAL_COMMIT_FAILED",
                                data={**answer["data"], "reported_export_status": answer["status"],
                                      "journal_error_type": type(exc).__name__},
                                limitations=["Publication may have completed; the outcome was not durably recorded. Do not retry automatically or overwrite the destination."])
            if path is not None:
                answer["data"]["path"] = path  # UI response only, never the audit record.
            return answer

    def end_admin_session(self) -> dict:
        with self._lock:
            if self.helper is None:
                if self._cleanup_unconfirmed:
                    if self._expiry_cleanup and self._expiry_cleanup.get("confirmed"):
                        # An explicit retry may repair the durable cleanup
                        # record after the verified owner has already exited.
                        try:
                            self.journal.append({**self._expiry_cleanup, "operation_id": uuid4().hex,
                                "operation": "session.close", "source": "TERMINAL_CLEANUP_JOURNAL_RETRY"})
                            self._expiry_cleanup["journal_recorded"] = True
                            self._cleanup_unconfirmed = self._owner_retained = False
                            self._admin_state = "INACTIVE"
                            return result("session.close", "COMPLETED", data={"active": False,
                                          "expiry_cleanup": deepcopy(self._expiry_cleanup)})
                        except Exception as exc:
                            return result("session.close", "RECOVERY_UNCONFIRMED", error="CLEANUP_JOURNAL_FAILED: " + str(exc)[:1000],
                                          data={"active": False, "cleanup_required": True})
                    return result("session.close", "RECOVERY_UNCONFIRMED", data={"active": False,
                                  "cleanup_required": True, "recovery": self.recovery_status()},
                                  error="PREVIOUS_OWNER_RECOVERY_NOT_VERIFIED")
                self._admin_state = "INACTIVE"
                return result("session.close", "COMPLETED", data={"active": False})
            had_interventions = self._interventions_started or self._cleanup_unconfirmed or self._owner_retained
            closing_target = self._target.to_dict() if self._target is not None else None
            closing_permission = self._permission
            expired_managed = self._admin_session_managed and time.monotonic() >= self._expires
            pending_close = self._admin_session_managed and self._pending_close_context is not None
            terminal = self._consume_expiry_cleanup() if expired_managed or pending_close else None
            answer = result("session.close", "RECOVERY_UNCONFIRMED" if had_interventions else "COMPLETED",
                            limitations=["No successful cleanup acknowledgement was received."])
            if terminal is not None:
                answer = result("session.close", "COMPLETED" if terminal.get("confirmed") else "RECOVERY_UNCONFIRMED",
                                data={"expiry_cleanup": deepcopy(terminal)},
                                limitations=["Terminal cleanup acknowledges resource release; late operation results remain separate observations."])
            late_results = []
            try:
                if not expired_managed and not pending_close and self.helper.alive() and self._channel is not None:
                    deadline = time.monotonic() + 20
                    envelope = {"kind": "close"}
                    if self._admin_session_managed:
                        envelope["nonce"] = self._session_nonce
                        self._expiry_cleanup = None
                        self._pending_close_context = {"target": closing_target, "operations": sorted(self._scope)}
                    self._channel.send(envelope, deadline=deadline)
                    for _ in range(4):
                        response = self._channel.receive(deadline=deadline)
                        if response.get("kind") == "expired":
                            terminal = self._accept_expiry_cleanup(response)
                            answer = result("session.close", "COMPLETED" if terminal.get("confirmed") else "RECOVERY_UNCONFIRMED",
                                            data={"expiry_cleanup": deepcopy(terminal)})
                            break
                        if response.get("kind") == "closed":
                            if self._admin_session_managed:
                                terminal = self._accept_expiry_cleanup(response)
                                answer = result("session.close", "COMPLETED" if terminal.get("confirmed") else "RECOVERY_UNCONFIRMED",
                                                data={"expiry_cleanup": deepcopy(terminal)})
                            else:
                                answer = response["result"]
                            break
                        if response.get("kind") != "result":
                            raise ValueError("UNEXPECTED_SESSION_CLEANUP_REPLY")
                        # Cancellation/lost-ACK recovery can leave one completed
                        # operation reply in flight. Do not confuse it with the
                        # explicit cleanup acknowledgement or retain payloads.
                        late_results.append({"request_id": response.get("request_id"),
                                             "status": response.get("result", {}).get("status")})
            except Exception as exc:
                answer["error"] = str(exc)[:2000]
            alive = self.helper is not None and self.helper.alive()
            retained = bool(answer.get("data", {}).get("owner_retained"))
            if (alive and (retained or had_interventions and answer.get("status") != "COMPLETED")
                    and time.monotonic() < self._expires + 30):
                answer = self._retained_result("session.close", answer.get("error") or "OWNED_DEBUG_CONTEXT_CLEANUP_UNCONFIRMED",
                                               cleanup=answer)
            else:
                try:
                    self._discard_helper(force=True)
                except Exception as exc:
                    answer = (self._retained_result("session.close", str(exc)[:2000], cleanup=answer)
                              if self.helper is not None and self.helper.alive() else
                              result("session.close", "RECOVERY_UNCONFIRMED", error=str(exc)[:2000]))
                if self.helper is None:
                    self._interventions_started = False
                    self._cleanup_unconfirmed = answer.get("status") != "COMPLETED"
                    self._admin_state = "CLEANUP_REQUIRED" if self._cleanup_unconfirmed else "INACTIVE"
            answer.setdefault("data", {})["recovery"] = self.recovery_status()
            if late_results:
                answer["data"]["late_result_statuses"] = late_results
            try:
                self.journal.append({**answer, "operation_id": uuid4().hex, "source": "DIAGNOSTIC_SESSION_CLEANUP",
                                     "target": closing_target, "permission_level": closing_permission})
                if terminal and terminal.get("confirmed") and self.helper is None:
                    terminal["journal_recorded"] = True
                    self._owner_retained = self._cleanup_unconfirmed = False
                    self._admin_state = "INACTIVE"
            except Exception as exc:
                self._cleanup_unconfirmed = True
                self._admin_state = "CLEANUP_REQUIRED"
                answer = (self._retained_result("session.close", "CLEANUP_JOURNAL_FAILED: " + str(exc)[:1000], cleanup=answer)
                          if self._owner_retained and self.helper is not None else
                          result("session.close", "RECOVERY_UNCONFIRMED", error="CLEANUP_JOURNAL_FAILED: " + str(exc)[:1000]))
            return answer

    def close(self) -> dict:
        return self.end_admin_session()


__all__ = ["ActionRequest", "CapabilityManager", "DiagnosticActionEngine", "InspectorService",
           "ProcessIdentity", "describe_actions"]
