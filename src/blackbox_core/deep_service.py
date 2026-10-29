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
        self._owner_retained = False

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
                "owner_retained": self._owner_retained,
                "cleanup_required": self._owner_retained,
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
            self._owner_retained = False
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
        if errors:
            raise OSError("; ".join(errors))

    def _ensure_session(self, request: ActionRequest, cancel_event=None) -> dict | None:
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
                    return result(request.operation, "RECOVERY_UNCONFIRMED", error="PREVIOUS_INTERVENTION_SESSION_TERMINATED",
                                  next_action="REVIEW_RECOVERY_REPORT_BEFORE_STARTING_A_NEW_SESSION")
            elif self._target != request.target:
                closed = self.end_admin_session()
                if closed["status"] != "COMPLETED":
                    return closed
            elif request.operation not in self._scope:
                return result(request.operation, "ACCESS_DENIED", error="OPERATION_OUTSIDE_APPROVED_SESSION_SCOPE",
                              next_action="END_SESSION_AND_APPROVE_A_NEW_OPERATION_SCOPE")
            elif self._owner_retained and request.operation not in (
                    "debug.detach", "debug.context", "debug.breakpoints", "capabilities"):
                return self._retained_result(request.operation, "PREVIOUS_OWNER_CLEANUP_REQUIRES_RETRY")
            else:
                return None
        opened = self._start_session(request.target, sorted(set(DEEP_ACTIONS) - LOCAL_OPERATIONS),
                                     elevated=False, cancel_event=cancel_event)
        return opened if opened["status"] != "COMPLETED" else None

    def _retained_result(self, operation: str, error: str, *, cleanup=None) -> dict:
        self._owner_retained = True
        return result(operation, "RECOVERY_UNCONFIRMED", error=error, retains_service=True,
                      data={"owner_retained": True, "retry_cleanup_required": True,
                            "helper_pid": self.helper_pid, "target": self._target.to_dict() if self._target else None,
                            "expires_in_seconds": max(0, self._expires - time.monotonic()),
                            "cleanup": cleanup},
                      limitations=["The original helper lease is not extended. Retry cleanup before it expires; owner exit at the finite lease/cleanup boundary can resume an unverified debug context."])

    def elevate(self, target: ProcessIdentity, operations: list[str], *, confirmed: bool = False, cancel_event=None) -> dict:
        target = ProcessIdentity.from_dict(target)
        if confirmed is not True:
            return result("session.elevate", "CONFIRMATION_REQUIRED", next_action="REVIEW_OPERATION_SCOPE_AND_UAC_PROMPT")
        scope = sorted({canonical_operation(name) for name in operations} | {"capabilities"})
        if not operations or set(scope) & LOCAL_OPERATIONS:
            return result("session.elevate", "OPERATION_FAILED", error="INVALID_ELEVATED_OPERATION_SCOPE")
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

    def _local(self, request: ActionRequest, cancel_event=None) -> dict:
        p = dict(request.parameters)
        deadline = time.monotonic() + request.timeout_seconds
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

    def _artifact_access(self, request: ActionRequest, identifier: str, cancel_event=None) -> dict | None:
        """Probe before creating a file so a denied attempt leaves no collision.

        This is an observation, not a granted right: native writing still
        rechecks exact target identity and actual Windows permissions.
        """
        probe_id = identifier + ":access"
        probe = ActionRequest("capabilities", request.target, {"operations": [request.operation]},
                              timeout_seconds=min(15, request.timeout_seconds))
        deadline = time.monotonic() + probe.timeout_seconds + 2
        self._active_request_id = probe_id
        try:
            self._channel.send({"kind": "execute", "request_id": probe_id, "request": probe.to_dict()},
                               deadline=deadline, cancel_event=cancel_event)
            response = self._channel.receive(deadline=deadline, cancel_event=cancel_event)
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
            operation_permission = self._permission
            intervention_dispatch_attempted = False
            try:
                check_deadline(time.monotonic() + request.timeout_seconds, cancel_event)
                if request.operation in LOCAL_OPERATIONS:
                    answer = self._local(request, cancel_event)
                elif os.name != "nt":
                    answer = result(request.operation, "UNSUPPORTED_PLATFORM", next_action="USE_WINDOWS_10_OR_11_X64")
                else:
                    blocked = self._ensure_session(request, cancel_event)
                    if (blocked is None and request.operation == "profile.etw"
                            and self._permission != "ADMINISTRATOR"):
                        # Refuse before reserving the output file. The UI can
                        # retry this exact destination after scoped UAC without
                        # an abandoned empty file or unsafe path-based deletion.
                        blocked = result("profile.etw", "ADMIN_REQUIRED",
                                         error="ETW_PROFILE_REQUIRES_SCOPED_ADMINISTRATOR_HELPER",
                                         next_action="REQUEST_UAC_FOR_THIS_OPERATION")
                    if blocked is None and request.operation == "dump":
                        blocked = self._artifact_access(request, identifier, cancel_event)
                    if blocked is not None:
                        answer = blocked
                    else:
                        operation_permission = self._permission
                        parameters = dict(request.parameters)
                        envelope = {"kind": "execute", "request_id": identifier}
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
                        remote = ActionRequest(request.operation, request.target, parameters,
                                               request.confirmed, request.timeout_seconds)
                        envelope["request"] = remote.to_dict()
                        self._active_request_id = identifier
                        if spec.mode == "INTERVENE" or request.operation in ("thread_stacks", "profile.etw"):
                            self._interventions_started = True
                        deadline = time.monotonic() + request.timeout_seconds + 2
                        try:
                            intervention_dispatch_attempted = spec.mode == "INTERVENE" or request.operation == "thread_stacks"
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
                if answer.get("data", {}).get("owner_retained"):
                    self._owner_retained = True
                elif request.operation == "debug.detach" and answer.get("status") == "COMPLETED":
                    self._owner_retained = False
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
                failure = "RESULT_JOURNAL_COMMIT_FAILED: " + str(exc)[:1000]
                reported = {"reported_operation_status": answer.get("status")}
                if self._owner_retained and self.helper is not None:
                    answer = self._retained_result(request.operation, failure, cleanup=reported)
                    answer["operation_id"] = identifier
                    answer["limitations"].append("The durable result could not be recorded; do not repeat the action blindly.")
                else:
                    answer = result(request.operation, "RECOVERY_UNCONFIRMED", operation_id=identifier,
                                    error=failure, data=reported,
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
            closing_target = self._target.to_dict() if self._target is not None else None
            closing_permission = self._permission
            answer = result("session.close", "RECOVERY_UNCONFIRMED" if had_interventions else "COMPLETED",
                            limitations=["No successful cleanup acknowledgement was received."])
            late_results = []
            try:
                if self.helper.alive() and self._channel is not None:
                    deadline = time.monotonic() + 20
                    self._channel.send({"kind": "close"}, deadline=deadline)
                    for _ in range(4):
                        response = self._channel.receive(deadline=deadline)
                        if response.get("kind") == "closed":
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
            answer.setdefault("data", {})["recovery"] = self.recovery_status()
            if late_results:
                answer["data"]["late_result_statuses"] = late_results
            try:
                self.journal.append({**answer, "operation_id": uuid4().hex, "source": "DIAGNOSTIC_SESSION_CLEANUP",
                                     "target": closing_target, "permission_level": closing_permission})
            except Exception as exc:
                answer = (self._retained_result("session.close", "CLEANUP_JOURNAL_FAILED: " + str(exc)[:1000], cleanup=answer)
                          if self._owner_retained and self.helper is not None else
                          result("session.close", "RECOVERY_UNCONFIRMED", error="CLEANUP_JOURNAL_FAILED: " + str(exc)[:1000]))
            return answer

    def close(self) -> dict:
        return self.end_admin_session()


__all__ = ["ActionRequest", "CapabilityManager", "DiagnosticActionEngine", "InspectorService",
           "ProcessIdentity", "describe_actions"]
