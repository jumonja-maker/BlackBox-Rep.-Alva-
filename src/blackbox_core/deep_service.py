"""GUI-token coordinator for bounded, explicitly approved process diagnostics."""
from __future__ import annotations

from datetime import datetime, timezone
import hmac
import json
import os
from pathlib import Path
import secrets
import threading
import time
from uuid import uuid4

from .deep_contracts import (ActionRequest, DEEP_ACTIONS, MAX_SESSION_SECONDS,
                             ProcessIdentity, canonical_operation, describe_actions, result)
from .deep_elevation import ElevationBroker, ElevationCancelled
from .deep_helper import DiagnosticActionEngine, LOCAL_OPERATIONS, validate_parameters
from .deep_ipc import PipeServer, check_deadline
from .deep_journal import EvidenceJournal, journal_metadata


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

    @property
    def helper_pid(self):
        return self.helper.pid if self.helper is not None else None

    @property
    def admin_active(self) -> bool:
        return bool(self.helper is not None and self.helper.alive() and self._permission == "ADMINISTRATOR"
                    and time.monotonic() < self._expires)

    def identity(self, pid: int) -> ProcessIdentity:
        from .deep_native import capture_identity
        return ProcessIdentity.from_dict(capture_identity(pid))

    def session_status(self) -> dict:
        return {"active": bool(self.helper is not None and self.helper.alive() and time.monotonic() < self._expires),
                "helper_pid": self.helper_pid, "admin_active": self.admin_active,
                "permission_level": self._permission,
                "expires_in_seconds": max(0, round(self._expires - time.monotonic(), 3)),
                "target": self._target.to_dict() if self._target else None,
                "operations": sorted(self._scope),
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

    def _start_session(self, target: ProcessIdentity, operations: list[str], *, elevated: bool, cancel_event=None) -> dict:
        if os.name != "nt":
            return result("session.open", "UNSUPPORTED_PLATFORM", next_action="USE_WINDOWS_10_OR_11_X64")
        parent = self.identity(os.getpid())
        nonce = secrets.token_hex(32)
        pipe = PipeServer("\\\\.\\pipe\\BLACKBOX-DEEP-" + uuid4().hex)
        self._channel = pipe
        self._recovery_path = self.journal_root / ("recovery-" + uuid4().hex + ".json")
        self._recovery_stream = self._recovery_path.open("x+b")
        arguments = ["--deep-helper", "--pipe", pipe.name, "--nonce", nonce,
                     "--parent-pid", str(parent.pid), "--parent-created-100ns", str(parent.created_100ns),
                     "--parent-image", parent.image_path]
        try:
            check_deadline(time.monotonic() + 1, cancel_event)
            self.helper = self.broker.launch(arguments, elevated=elevated)
            deadline = time.monotonic() + 30
            pipe.accept(self.helper.pid, deadline=deadline, cancel_event=cancel_event)
            hello = pipe.receive(deadline=deadline, cancel_event=cancel_event)
            actual = self.identity(self.helper.pid)
            expected_executable = self.broker.command(arguments)[0]
            verify_helper_hello(hello, nonce, actual, expected_executable)
            permission = hello.get("permission_level")
            if permission not in ("STANDARD", "ADMINISTRATOR") or (elevated and permission != "ADMINISTRATOR"):
                raise PermissionError("HELPER_TOKEN_NOT_ELEVATED")
            import msvcrt
            pipe.send({"kind": "init", "nonce": nonce, "parent": parent.to_dict(), "target": target.to_dict(),
                       "operations": operations, "require_admin": elevated,
                       "session_seconds": MAX_SESSION_SECONDS,
                       "recovery_source_handle": msvcrt.get_osfhandle(self._recovery_stream.fileno())},
                      deadline=deadline, cancel_event=cancel_event)
            ready = pipe.receive(deadline=deadline, cancel_event=cancel_event)
            if (ready.get("kind") != "ready" or ready.get("target") != target.to_dict()
                    or ready.get("operations") != operations or ready.get("permission_level") != permission):
                raise PermissionError("HELPER_SCOPE_HANDSHAKE_FAILED")
            self._target, self._scope = target, frozenset(operations)
            self._permission, self._expires = permission, time.monotonic() + MAX_SESSION_SECONDS
            self._interventions_started = False
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
            finally:
                self.helper.close_handle()
                self.helper = None
        if self._recovery_stream is not None:
            self._recovery_stream.close()
            self._recovery_stream = None
        self._target, self._scope, self._expires = None, frozenset(), 0.0
        self._permission = "STANDARD"
        if errors:
            raise OSError("; ".join(errors))

    def _ensure_session(self, request: ActionRequest, cancel_event=None) -> dict | None:
        if self.helper is not None:
            if not self.helper.alive() or time.monotonic() >= self._expires:
                unconfirmed = self._interventions_started
                self._discard_helper(force=True)
                if unconfirmed:
                    return result(request.operation, "RECOVERY_UNCONFIRMED", error="PREVIOUS_INTERVENTION_SESSION_TERMINATED",
                                  next_action="REVIEW_RECOVERY_REPORT_BEFORE_STARTING_A_NEW_SESSION")
            elif self._target != request.target:
                closed = self.end_admin_session()
                if closed["status"] != "COMPLETED":
                    return closed
            elif request.operation not in self._scope:
                return result(request.operation, "ACCESS_DENIED", error="OPERATION_OUTSIDE_APPROVED_SESSION_SCOPE",
                              next_action="END_SESSION_AND_APPROVE_A_NEW_OPERATION_SCOPE")
            else:
                return None
        opened = self._start_session(request.target, sorted(set(DEEP_ACTIONS) - LOCAL_OPERATIONS),
                                     elevated=False, cancel_event=cancel_event)
        return opened if opened["status"] != "COMPLETED" else None

    def elevate(self, target: ProcessIdentity, operations: list[str], *, confirmed: bool = False, cancel_event=None) -> dict:
        target = ProcessIdentity.from_dict(target)
        if confirmed is not True:
            return result("session.elevate", "CONFIRMATION_REQUIRED", next_action="REVIEW_OPERATION_SCOPE_AND_UAC_PROMPT")
        scope = sorted({canonical_operation(name) for name in operations} | {"capabilities"})
        if not operations or set(scope) & LOCAL_OPERATIONS:
            return result("session.elevate", "OPERATION_FAILED", error="INVALID_ELEVATED_OPERATION_SCOPE")
        identifier = uuid4().hex
        with self._lock:
            self.journal.append({"operation_id": identifier + ":requested", "action_id": identifier,
                                 "operation": "session.elevate", "target": target.to_dict(),
                                 "parameters": {"operations": scope}, "phase": "REQUESTED",
                                 "uac": {"requested": True, "result": "PENDING"}, "permission_level": self._permission})
            cleanup = self.end_admin_session()
            if cleanup["status"] != "COMPLETED":
                return cleanup
            try:
                answer = self._start_session(target, scope, elevated=True, cancel_event=cancel_event)
                answer["uac"] = {"requested": True, "result": "TOKEN_VERIFIED" if answer["status"] == "COMPLETED" else "FAILED"}
                answer["limitations"].append("Secure Desktop visibility is controlled by Windows; this result verifies the granted helper token.")
            except ElevationCancelled:
                answer = result("session.elevate", "UAC_CANCELLED", data={"ordinary_observation_available": True},
                                uac={"requested": True, "result": "CANCELLED"}, next_action="CONTINUE_WITH_CURRENT_PERMISSIONS")
            except InterruptedError as exc:
                answer = result("session.elevate", "CANCELLED", error=str(exc), uac={"requested": True, "result": "CANCELLED"})
            except Exception as exc:
                answer = result("session.elevate", "ACCESS_DENIED" if isinstance(exc, PermissionError) else "OPERATION_FAILED",
                                error=str(exc)[:2000], winerror=getattr(exc, "winerror", None),
                                uac={"requested": True, "result": "FAILED"})
            answer.update(operation="session.elevate", operation_id=identifier)
            self.journal.append({**answer, "operation_id": identifier + ":result", "action_id": identifier,
                                 "target": target.to_dict(), "phase": "RESULT"})
            return answer

    def _local(self, request: ActionRequest, cancel_event=None) -> dict:
        p = dict(request.parameters)
        deadline = time.monotonic() + request.timeout_seconds
        if request.operation == "timeline":
            return result("timeline", "COMPLETED", data={"entries": self.journal.timeline(limit=p.get("limit", 200))})
        if request.operation == "compare":
            return result("compare", "COMPLETED", data=self.journal.compare(p["before_id"], p["after_id"]))
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
        try:
            deadline = time.monotonic() + 5
            self._channel.send({"kind": "cancel", "request_id": identifier}, deadline=deadline)
            response = self._channel.receive(deadline=deadline)
            if response.get("kind") == "result" and response.get("request_id") == identifier:
                value = response["result"]
                value["cancellation_requested"] = True
                return value
        except Exception:
            pass
        try:
            self._discard_helper(force=True)
        except Exception as exc:
            return result("unknown", "RECOVERY_UNCONFIRMED", error=str(exc))
        return result("unknown", "RECOVERY_UNCONFIRMED" if self._interventions_started else "CANCELLED",
                      error="HELPER_STOPPED_AFTER_CANCELLATION_GRACE",
                      limitations=["A started native action may have completed before cancellation; inspect recovery evidence."])

    def execute(self, request: ActionRequest | dict, cancel_event=None) -> dict:
        request = request if isinstance(request, ActionRequest) else ActionRequest.from_dict(request)
        validate_parameters(request.parameters)
        identifier = uuid4().hex
        spec = DEEP_ACTIONS[request.operation]
        if spec.confirmation_required and not request.confirmed:
            return result(request.operation, "CONFIRMATION_REQUIRED", operation_id=identifier,
                          next_action="CONFIRM_TARGET_PARAMETERS_AND_OPERATION_IMPACT")
        with self._lock:
            base = {"action_id": identifier, "operation": request.operation,
                    "target": request.target.to_dict(), "source": "BLACKBOX_DIAGNOSTIC_ACTION_ENGINE",
                    "parameters": request.parameters, "permission_level": self._permission,
                    "uac": {"requested": False, "result": "CURRENT_SESSION"},
                    "before": {"session": self.session_status()}, "limitations": []}
            # A durable intent is mandatory BEFORE any process intervention.
            try:
                self.journal.append({**base, "operation_id": identifier + ":requested", "phase": "REQUESTED"})
            except Exception as exc:
                return result(request.operation, "OPERATION_FAILED", operation_id=identifier,
                              error="DURABLE_INTENT_FAILED: " + str(exc)[:1000],
                              next_action="RESTORE_JOURNAL_STORAGE_BEFORE_RETRYING")
            dump_stream = None
            output_path = None
            try:
                check_deadline(time.monotonic() + request.timeout_seconds, cancel_event)
                if request.operation in LOCAL_OPERATIONS:
                    answer = self._local(request, cancel_event)
                elif os.name != "nt":
                    answer = result(request.operation, "UNSUPPORTED_PLATFORM", next_action="USE_WINDOWS_10_OR_11_X64")
                else:
                    blocked = self._ensure_session(request, cancel_event)
                    if blocked is not None:
                        answer = blocked
                    else:
                        parameters = dict(request.parameters)
                        envelope = {"kind": "execute", "request_id": identifier}
                        if request.operation == "dump":
                            import msvcrt
                            destination = parameters.pop("destination", None)
                            if destination is None:
                                destination = parameters.pop("path", parameters.pop("output_path", None))
                            if not isinstance(destination, str) or not destination or "\0" in destination:
                                raise ValueError("EXPLICIT_DUMP_DESTINATION_REQUIRED")
                            output_path = Path(destination)
                            dump_stream = output_path.open("x+b")
                            envelope["attachment"] = {"source_file_handle": msvcrt.get_osfhandle(dump_stream.fileno())}
                        remote = ActionRequest(request.operation, request.target, parameters,
                                               request.confirmed, request.timeout_seconds)
                        envelope["request"] = remote.to_dict()
                        self._active_request_id = identifier
                        if spec.mode == "INTERVENE" or request.operation == "thread_stacks":
                            self._interventions_started = True
                        deadline = time.monotonic() + request.timeout_seconds + 2
                        try:
                            self._channel.send(envelope, deadline=deadline, cancel_event=cancel_event)
                            response = self._channel.receive(deadline=deadline, cancel_event=cancel_event)
                            if response.get("kind") != "result" or response.get("request_id") != identifier:
                                raise ValueError("DIAGNOSTIC_RESPONSE_IDENTITY_MISMATCH")
                            answer = response["result"]
                        except InterruptedError:
                            answer = self._cancel_active(identifier)
                        except TimeoutError:
                            answer = self._cancel_active(identifier)
                            if answer["status"] == "CANCELLED":
                                answer["status"] = "TIMED_OUT"
                            answer["deadline_exceeded"] = True
                        finally:
                            self._active_request_id = None
                if request.operation == "snapshot" and answer.get("status") in ("COMPLETED", "INCOMPLETE_EVIDENCE"):
                    snapshot = answer.get("data", {})
                    snapshot_id = self.journal.snapshot(request.target.to_dict(), snapshot)
                    answer["data"] = {"snapshot_id": snapshot_id, "snapshot": snapshot}
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
                if self._interventions_started and self.helper is not None and not self.helper.alive():
                    status = "RECOVERY_UNCONFIRMED"
                answer = result(request.operation, status, error=str(exc)[:2000], winerror=getattr(exc, "winerror", None))
            finally:
                if dump_stream is not None:
                    dump_stream.close()
            answer.update(operation=request.operation, operation_id=identifier)
            answer.setdefault("permission_level", self._permission)
            answer.setdefault("limitations", [])
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
                                          ("before_id", "after_id", "changed_sections", "interpretation")}
            try:
                recorded = self.journal.append({**base, **journal_answer,
                                                "operation_id": identifier + ":result", "action_id": identifier,
                                                "phase": "RESULT"})
                answer["journal"] = recorded
            except Exception as exc:
                answer = result(request.operation, "RECOVERY_UNCONFIRMED", operation_id=identifier,
                                error="RESULT_JOURNAL_COMMIT_FAILED: " + str(exc)[:1000],
                                data={"reported_operation_status": answer.get("status")},
                                limitations=["The action may have completed; its durable result could not be recorded. Do not repeat blindly."])
            return answer

    def export_journal(self, destination: str | Path) -> dict:
        with self._lock:
            path = self.journal.export(destination)
        return result("journal.export", "COMPLETED", data={"path": str(path), "memory_and_dumps": "EXCLUDED"})

    def end_admin_session(self) -> dict:
        with self._lock:
            if self.helper is None:
                return result("session.close", "COMPLETED", data={"active": False})
            had_interventions = self._interventions_started
            answer = result("session.close", "RECOVERY_UNCONFIRMED" if had_interventions else "COMPLETED",
                            limitations=["No successful cleanup acknowledgement was received."])
            try:
                if self.helper.alive() and self._channel is not None:
                    deadline = time.monotonic() + 20
                    self._channel.send({"kind": "close"}, deadline=deadline)
                    response = self._channel.receive(deadline=deadline)
                    if response.get("kind") == "closed":
                        answer = response["result"]
            except Exception as exc:
                answer["error"] = str(exc)[:2000]
            finally:
                try:
                    self._discard_helper(force=True)
                except Exception as exc:
                    answer = result("session.close", "RECOVERY_UNCONFIRMED", error=str(exc)[:2000])
            self._interventions_started = False
            answer.setdefault("data", {})["recovery"] = self.recovery_status()
            try:
                self.journal.append({**answer, "operation_id": uuid4().hex, "source": "DIAGNOSTIC_SESSION_CLEANUP"})
            except Exception as exc:
                answer = result("session.close", "RECOVERY_UNCONFIRMED", error="CLEANUP_JOURNAL_FAILED: " + str(exc)[:1000])
            return answer

    def close(self) -> dict:
        return self.end_admin_session()


__all__ = ["ActionRequest", "CapabilityManager", "DiagnosticActionEngine", "InspectorService",
           "ProcessIdentity", "describe_actions"]
