"""Serialized, cancellable GUI boundary for the diagnostic action service.

The service owns one administrative lease independently of the selected target.
Native identity checks, target cleanup, UAC and authenticated status refreshes
always run in this worker, never on the Qt event loop.
"""
from __future__ import annotations

from copy import deepcopy
import math
import threading
import time

import psutil

from PySide6.QtCore import QObject, QThread, QTimer, Signal


def _failure(operation, code, detail=""):
    return {"operation": operation, "status": code, "error": detail,
            "data": {}, "limitations": [], "next_action": None}


def _retained(result):
    return bool(result.get("retains_service") or (result.get("data") or {}).get("owner_retained"))


class _DeepTask(QThread):
    result_ready = Signal(object)

    def __init__(self, owner, command, service, identity, factory):
        super().__init__(owner)
        self.command = command
        self.service = service
        self.identity = identity
        self.factory = factory
        self.cancel_event = threading.Event()

    def cancel(self):
        self.cancel_event.set()

    def _target(self):
        """Bind the ordinary observer's instance to an unchanged native FILETIME."""
        if self.identity is not None:
            return self.identity
        pid, created = self.command["target"]
        if created is None or not math.isfinite(created):
            raise ProcessLookupError("SELECTED_INSTANCE_IDENTITY_MISSING")
        before = psutil.Process(pid).create_time()
        if abs(before - created) > .000001:
            raise ProcessLookupError("SELECTED_PROCESS_INSTANCE_CHANGED")
        identity = self.service.identity(pid)
        after = psutil.Process(pid).create_time()
        if abs(after - created) > .000001:
            raise ProcessLookupError("SELECTED_PROCESS_INSTANCE_CHANGED")
        self.identity = identity
        return identity

    def _session_status(self):
        reader = getattr(self.service, "session_status", None)
        if not callable(reader):
            return None
        # Only the serialized worker may send a helper heartbeat. Journal-side
        # status reads in the service deliberately do not refresh the pipe.
        return reader(refresh=True)

    def _owned(self, command, kind, operation):
        """Choose the R60 ownership guard before any legacy target selector."""
        owner = command["native_owner_run_id"]
        expected = command.get("expected_context")
        if kind == "owned_release":
            return self.service.release_native_context(owner, expected_context=expected)
        target = self._target()
        expected_target = command.get("expected_target")
        if expected_target is not None:
            actual = target.to_dict()
            if (type(expected_target) is not dict or type(expected_target.get("pid")) is not int
                    or type(expected_target.get("created_100ns")) is not int
                    or actual.get("pid") != expected_target["pid"]
                    or actual.get("created_100ns") != expected_target["created_100ns"]):
                raise ProcessLookupError("WORKFLOW_EXACT_PROCESS_IDENTITY_CHANGED")
        if kind in ("elevate", "authorize_target"):
            if kind == "elevate":
                session = self._session_status() or {}
                if (session.get("admin_session_managed") and session.get("state") == "ACTIVE"
                        and session.get("elevated_verified") is True):
                    answer = {"status": "COMPLETED", "data": {}}
                else:
                    answer = self.service.start_admin_session_owned(owner_run_id=owner,
                        expected_context=expected, confirmed=True, cancel_event=self.cancel_event)
                if answer.get("status") != "COMPLETED":
                    return answer
                expected = answer.get("native_context_ownership") or expected
            answer = self.service.bind_target_owned(target, command["operations"], owner_run_id=owner,
                expected_context=expected, confirmed=True, cancel_event=self.cancel_event)
        else:
            from blackbox_core.deep_contracts import ActionRequest
            request = ActionRequest(operation="capabilities" if kind == "capabilities" else operation,
                target=target, parameters=command.get("parameters", {}),
                confirmed=command.get("confirmed", False),
                timeout_seconds=command.get("timeout_seconds", 15))
            answer = self.service.execute_owned(request, owner_run_id=owner,
                expected_context=expected, cancel_event=self.cancel_event)
        return dict(answer, target=target.to_dict())

    def run(self):
        command = self.command
        kind = command["kind"]
        operation = command.get("operation", kind)
        try:
            if kind == "close":
                result = self.service.close() if self.service is not None else {
                    "status": "COMPLETED", "data": {"cleanup": "NO_SESSION"}}
                if result.get("status") in ("COMPLETED", "DETACHED") and not _retained(result):
                    self.service = None
                    self.identity = None
            else:
                if self.service is None:
                    self.service = self.factory()
                if self.cancel_event.is_set():
                    raise InterruptedError("DIAGNOSTIC_CANCELLED")
                if kind == "clear_target":
                    result = self.service.set_target(None, cancel_event=self.cancel_event)
                    self.identity = None
                elif kind == "start_admin":
                    result = self.service.start_admin_session(confirmed=True, cancel_event=self.cancel_event)
                elif kind == "session_status":
                    result = {"status": "COMPLETED", "data": {}}
                elif kind == "end_admin":
                    result = self.service.end_admin_session()
                elif kind == "export":
                    result = self.service.export_journal(command["destination"], cancel_event=self.cancel_event)
                elif command.get("native_owner_run_id"):
                    result = self._owned(command, kind, operation)
                else:
                    target = self._target()
                    selector = getattr(self.service, "set_target", None)
                    selection = selector(target, cancel_event=self.cancel_event) if callable(selector) else None
                    if selection and selection.get("status") not in ("COMPLETED", "DETACHED"):
                        result = selection
                    elif kind == "elevate":
                        starter = getattr(self.service, "start_admin_session", None)
                        binder = getattr(self.service, "bind_target", None)
                        if callable(starter) and callable(binder):
                            # The old Deep button joins the very same managed
                            # lease as the top control; it cannot create a
                            # second, target-bound elevation mechanism.
                            session = self._session_status() or {}
                            if (session.get("admin_session_managed") and session.get("state") == "ACTIVE"
                                    and session.get("elevated_verified") is True):
                                result = {"status": "COMPLETED", "data": {}}
                            else:
                                result = starter(confirmed=True, cancel_event=self.cancel_event)
                            if result.get("status") == "COMPLETED":
                                result = binder(target, command["operations"], confirmed=True,
                                                cancel_event=self.cancel_event)
                        else:
                            result = self.service.elevate(target, command["operations"], confirmed=True,
                                                          cancel_event=self.cancel_event)
                    elif kind == "authorize_target":
                        result = self.service.bind_target(target, command["operations"], confirmed=True,
                                                          cancel_event=self.cancel_event)
                    else:
                        from blackbox_core.deep_contracts import ActionRequest
                        request = ActionRequest(
                            operation="capabilities" if kind == "capabilities" else operation,
                            target=target, parameters=command.get("parameters", {}),
                            confirmed=command.get("confirmed", False),
                            timeout_seconds=command.get("timeout_seconds", 30 if kind == "capabilities" else 15))
                        result = self.service.execute(request, cancel_event=self.cancel_event)
                    result = dict(result)
                    result["target"] = target.to_dict()
            result = dict(result or {})
            result.setdefault("operation", operation)
        except (ProcessLookupError, psutil.NoSuchProcess) as exc:
            result = _failure(operation, "PROCESS_CHANGED", str(exc))
        except InterruptedError as exc:
            result = _failure(operation, "CANCELLED", str(exc))
        except (PermissionError, psutil.AccessDenied) as exc:
            result = _failure(operation, "ACCESS_DENIED", str(exc))
        except Exception as exc:
            result = _failure(operation, getattr(exc, "status", "OPERATION_FAILED"), str(exc)[:1000])
        if kind == "close" and (result.get("status") not in ("COMPLETED", "DETACHED") or self.service is not None):
            result["retains_service"] = self.service is not None
            result["status"] = "RECOVERY_UNCONFIRMED"
        if self.service is not None:
            try:
                session = self._session_status()
                if session is not None:
                    result["diagnostic_session"] = session
            except Exception as exc:
                # A successful operation is still evidence; a failed heartbeat
                # must remove the administrative claim without relabelling it.
                result["diagnostic_session"] = {"state": "FAILED", "elevated_verified": False,
                    "expires_in_seconds": 0, "error": str(exc)[:1000]}
        elif kind == "close":
            result["diagnostic_session"] = {"state": "INACTIVE", "elevated_verified": False,
                                              "expires_in_seconds": 0}
        result["generation"] = command["generation"]
        result["request_kind"] = kind
        result["request_tag"] = command.get("tag", "")
        if command.get("native_owner_run_id"):
            result["native_owner_run_id"] = command["native_owner_run_id"]
        if command.get("native_owner_run_id") and self.service is not None:
            journal = getattr(self.service, "journal", None)
            if getattr(journal, "path", None) is not None:
                # Actual owner reference only; the R60 worker makes the SQLite
                # snapshot after this operation has completed.
                result["_journal_path"] = str(journal.path)
        self.result_ready.emit(result)


class DeepInspectorBridge(QObject):
    """Lazy diagnostic owner with independent lease and target generations."""
    result_ready = Signal(object)
    # Owner-only receipts remain observable after a UI target generation change.
    # Legacy widgets still receive only current-generation results below.
    owned_result_ready = Signal(object)
    busy_changed = Signal(bool)
    target_changed = Signal()
    admin_status_changed = Signal(object)
    closed = Signal(object)
    recovery_required = Signal(object)
    idle = Signal()

    def __init__(self, parent=None, *, service_factory=None, journal_root=None):
        super().__init__(parent)
        if service_factory is None:
            def service_factory():
                from blackbox_core.deep_service import InspectorService
                return InspectorService(journal_root=journal_root)
        self._factory = service_factory
        self._service = None
        self._identity = None
        self.worker = None
        self._queued_command = None
        self.target = None
        self.generation = 0
        self.admin_active = False
        self.admin_state = "INACTIVE"
        self.admin_remaining_seconds = 0
        self.admin_checked_at = ""
        self._admin_status = {"state": "INACTIVE", "elevated_verified": False}
        self._admin_expires = 0.0
        self._admin_verified_at = 0.0
        self._last_status_poll = 0.0
        self._reset_pending = False
        self._closing = False
        self._close_result = None
        self.cleanup_required = False
        self._status_timer = QTimer(self)
        self._status_timer.setInterval(500)
        self._status_timer.timeout.connect(self._expire_admin_status)
        self._status_timer.start()

    @property
    def busy(self):
        work = self.worker is not None and self.worker.command["kind"] != "session_status"
        return work or self._queued_command is not None or self._reset_pending or self.cleanup_required

    @property
    def has_session(self):
        return self._service is not None or self.worker is not None

    def set_target(self, pid, created):
        target = (int(pid), float(created) if created is not None else None) if pid else None
        if target == self.target:
            return
        self.target = target
        self.generation += 1
        self._identity = None
        self._queued_command = None
        self._reset_pending = self.has_session
        self._publish_admin_status()
        self.target_changed.emit()
        if self.worker is not None:
            self.worker.cancel()
        elif self._service is not None:
            self._start_reset()

    def _start_reset(self):
        # Compatibility owners lacking target cleanup retain their old close
        # behavior. The production service preserves its one helper here.
        kind = "clear_target" if not self._closing and callable(getattr(self._service, "set_target", None)) else "close"
        return self._start({"kind": kind})

    def _start(self, command):
        packet = deepcopy(command)
        packet["generation"] = self.generation
        packet["target"] = self.target
        if self.worker is not None:
            if self.worker.command["kind"] == "session_status" and packet["kind"] != "session_status" and self._queued_command is None:
                self._queued_command = packet
                self.busy_changed.emit(True)
                return True
            return False
        task = _DeepTask(self, packet, self._service, self._identity, self._factory)
        self.worker = task
        task.result_ready.connect(self._receive)
        task.finished.connect(self._finished)
        if packet["kind"] != "session_status":
            self.busy_changed.emit(True)
        task.start()
        return True

    def submit(self, operation, parameters=None, *, confirmed=False, tag="", timeout_seconds=15,
               native_owner_run_id=None, expected_context=None, expected_target=None):
        if self.busy or self._closing or self.target is None:
            return False
        return self._start({"kind": "action", "operation": operation,
                            "parameters": parameters or {}, "confirmed": confirmed,
                            "tag": tag, "timeout_seconds": timeout_seconds,
                            "native_owner_run_id": native_owner_run_id, "expected_context": expected_context,
                            "expected_target": expected_target})

    def capabilities(self):
        if self.busy or self._closing or self.target is None:
            return False
        return self._start({"kind": "capabilities"})

    def start_admin(self):
        if self.busy or self._closing:
            return False
        self.admin_state = "REQUESTING_UAC"
        self._admin_status = {"state": "REQUESTING_UAC", "elevated_verified": False}
        self._admin_expires = 0.0
        self._publish_admin_status()
        return self._start({"kind": "start_admin"})

    def elevate(self, operations, *, native_owner_run_id=None, expected_context=None, expected_target=None, tag=""):
        if self.busy or self._closing or self.target is None:
            return False
        return self._start({"kind": "elevate", "operations": list(operations), "tag": tag,
                            "native_owner_run_id": native_owner_run_id, "expected_context": expected_context,
                            "expected_target": expected_target})

    def authorize_target(self, operations, *, native_owner_run_id=None, expected_context=None, expected_target=None, tag=""):
        if self.busy or self._closing or self.target is None:
            return False
        return self._start({"kind": "authorize_target", "operations": list(operations), "tag": tag,
                            "native_owner_run_id": native_owner_run_id, "expected_context": expected_context,
                            "expected_target": expected_target})

    def release_native_context(self, owner_run_id, expected_context, *, tag=""):
        if self.worker is not None or self._closing or self._service is None:
            return False
        return self._start({"kind": "owned_release", "operation": "target.release", "tag": tag,
                            "native_owner_run_id": owner_run_id, "expected_context": expected_context})

    def end_admin(self):
        if self.busy or self._closing or self._service is None:
            return False
        self.admin_active = False
        self._admin_status = dict(self._admin_status, verification_pending=True)
        self.admin_status_changed.emit(dict(self._admin_status, active=False))
        return self._start({"kind": "end_admin"})

    def export(self, destination):
        if self.busy or self._closing or self._service is None and self.target is None:
            return False
        return self._start({"kind": "export", "destination": str(destination)})

    def cancel(self):
        self._queued_command = None
        if self.worker is not None:
            self.worker.cancel()

    def cancel_request(self, tag, generation, target):
        """Cancel only an exact caller request, retaining foreign/shared owners.

        A queued action may sit behind the administrative heartbeat. Removing
        that queued packet must not cancel the heartbeat or a chain's worker.
        This only requests cancellation; it never confirms cleanup.
        """
        if type(tag) is not str or not tag or type(generation) is not int:
            return False
        if type(target) is not tuple or len(target) != 2:
            return False

        def matches(command):
            return (isinstance(command, dict) and command.get("tag") == tag
                    and command.get("generation") == generation
                    and command.get("target") == target)

        matched = False
        if matches(self._queued_command):
            self._queued_command = None
            matched = True
            self.busy_changed.emit(bool(self.busy))
        task = self.worker
        if task is not None and matches(task.command):
            task.cancel()
            matched = True
        return matched

    def retry_cleanup(self):
        if self.worker is not None or not self.cleanup_required or self._service is None:
            return False
        self._reset_pending = True
        return self._start({"kind": "close"})

    def shutdown(self):
        if self._closing:
            if self.cleanup_required:
                self.retry_cleanup()
            return
        self._closing = True
        self.generation += 1
        self._queued_command = None
        self._publish_admin_status()
        if self.worker is not None:
            self._reset_pending = True
            self.worker.cancel()
        elif self._service is not None:
            self._reset_pending = True
            self._start({"kind": "close"})
        else:
            self._status_timer.stop()
            self.closed.emit({"status": "COMPLETED", "data": {"cleanup": "NO_SESSION"}})

    def _apply_admin_status(self, session):
        self._admin_status = dict(session)
        self.admin_state = str(session.get("state", "INACTIVE"))
        try:
            remaining = max(0, float(session.get("remaining_seconds", session.get("expires_in_seconds", 0)) or 0))
            remaining = min(900, remaining) if math.isfinite(remaining) else 0
        except (ValueError, TypeError):
            remaining = 0
        now = time.monotonic()
        self._admin_expires = now + remaining
        deadline = session.get("session_deadline_monotonic")
        if type(deadline) in (int, float) and math.isfinite(deadline):
            # Service and bridge share this process's monotonic clock. Preserve
            # its original deadline rather than adding heartbeat transit time.
            self._admin_expires = min(self._admin_expires, max(0, deadline))
        self._admin_verified_at = time.monotonic() if session.get("elevated_verified") is True else 0.0
        self.admin_checked_at = time.strftime("%H:%M:%S") if self._admin_verified_at else ""
        self._publish_admin_status()

    def _publish_admin_status(self):
        remaining = max(0, int(math.ceil(self._admin_expires - time.monotonic())))
        self.admin_remaining_seconds = remaining
        fresh = bool(self._admin_verified_at and time.monotonic() - self._admin_verified_at <= 3)
        ending = ((self.worker is not None and self.worker.command["kind"] == "end_admin") or
                  (self._queued_command is not None and self._queued_command["kind"] == "end_admin"))
        self.admin_active = bool(self.admin_state == "ACTIVE" and self._admin_status.get("elevated_verified") is True
            and remaining > 0 and fresh and not self._admin_status.get("verification_pending")
            and not ending and not self.cleanup_required and not self._reset_pending and not self._closing)
        self.admin_status_changed.emit(dict(self._admin_status, state=self.admin_state,
            active=self.admin_active, remaining_seconds=remaining,
            verification_pending=self.admin_state == "ACTIVE" and not self.admin_active))

    def _receive(self, result):
        # Administrative state belongs to the shared lease, including a launch
        # finishing after target selection invalidated an action generation.
        session = result.get("diagnostic_session")
        if isinstance(session, dict):
            self._apply_admin_status(session)
            if session.get("state") == "CLEANUP_REQUIRED":
                self.cleanup_required = True
                self._close_result = dict(result, status="RECOVERY_UNCONFIRMED")
        kind = result.get("request_kind")
        if result.get("native_owner_run_id"):
            self.owned_result_ready.emit(result)
        if (kind == "owned_release" and result.get("status") == "COMPLETED"
                and (result.get("cleanup") or {}).get("confirmed") is True):
            self.cleanup_required = False
            self._close_result = None
        if kind in ("close", "clear_target"):
            self._close_result = result
            if result.get("status") not in ("COMPLETED", "DETACHED"):
                self.result_ready.emit(result)
            return
        if kind == "session_status":
            if self.admin_state == "CLEANUP_REQUIRED":
                self.cleanup_required = True
                self._close_result = dict(result, status="RECOVERY_UNCONFIRMED")
            return
        if _retained(result):
            self.cleanup_required = True
            self._close_result = result
        if result.get("generation") != self.generation or self._closing:
            return
        self.result_ready.emit(result)

    def _expire_admin_status(self):
        if self.admin_state == "ACTIVE" and time.monotonic() >= self._admin_expires:
            self.admin_state = "EXPIRED"
        self._publish_admin_status()
        if (self._service is not None and callable(getattr(self._service, "session_status", None))
                and not self._closing and not self._reset_pending and not self.cleanup_required
                and self.worker is None and time.monotonic() - self._last_status_poll >= 1):
            self._last_status_poll = time.monotonic()
            self._start({"kind": "session_status"})

    def _finished(self):
        task = self.worker
        if task is None:
            return
        self.worker = None
        self._service = task.service
        kind = task.command["kind"]
        if task.command["generation"] == self.generation and kind not in ("close", "clear_target"):
            self._identity = task.identity
        task.deleteLater()
        if kind in ("close", "clear_target"):
            self._reset_pending = False
            self._identity = None
            self.cleanup_required = (self._service is not None if kind == "close" else
                (self._close_result or {}).get("status") not in ("COMPLETED", "DETACHED"))
        elif self._reset_pending or self._closing:
            self._queued_command = None
            self._start_reset()
            return
        if self.cleanup_required:
            self.admin_state = "CLEANUP_REQUIRED"
            self._publish_admin_status()
            self.busy_changed.emit(True)
            self.recovery_required.emit(self._close_result or _failure("close", "RECOVERY_UNCONFIRMED"))
            return
        if self._closing and kind != "close":
            self._start({"kind": "close"})
            return
        queued = self._queued_command
        self._queued_command = None
        if queued is not None and queued["generation"] == self.generation and not self._closing:
            self._start(queued)
            return
        self._publish_admin_status()
        if kind != "session_status":
            self.busy_changed.emit(False)
        if self._closing:
            self._status_timer.stop()
            self.closed.emit(self._close_result or _failure("close", "RECOVERY_UNCONFIRMED"))
        elif kind != "session_status":
            self.idle.emit()
