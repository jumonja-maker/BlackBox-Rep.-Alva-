"""Serialized, cancellable GUI boundary for the diagnostic action service.

No native operation, process identity query, helper launch or journal I/O runs
on the Qt event loop. A generation binds every result to the selected instance.
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
        """Bind first action to the instance selected by the ordinary observer."""
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
        # Native FILETIME is retained unchanged for every subsequent operation.
        self.identity = identity
        return identity

    def run(self):
        command = self.command
        operation = command.get("operation", command["kind"])
        try:
            if command["kind"] == "close":
                result = self.service.close() if self.service is not None else {
                    "status": "COMPLETED", "data": {"cleanup": "NO_SESSION"}}
                self.service = None
                self.identity = None
            else:
                if self.service is None:
                    self.service = self.factory()
                target = self._target()
                if self.cancel_event.is_set():
                    raise InterruptedError("DIAGNOSTIC_CANCELLED")
                if command["kind"] == "capabilities":
                    from blackbox_core.deep_contracts import ActionRequest
                    result = self.service.execute(ActionRequest("capabilities", target, timeout_seconds=30),
                                                  cancel_event=self.cancel_event)
                elif command["kind"] == "elevate":
                    result = self.service.elevate(
                        target, command["operations"], confirmed=True,
                        cancel_event=self.cancel_event)
                elif command["kind"] == "end_admin":
                    result = self.service.end_admin_session()
                elif command["kind"] == "export":
                    result = self.service.export_journal(command["destination"])
                else:
                    from blackbox_core.deep_contracts import ActionRequest
                    request = ActionRequest(
                        operation=operation, target=target,
                        parameters=command.get("parameters", {}),
                        confirmed=command.get("confirmed", False),
                        timeout_seconds=command.get("timeout_seconds", 15))
                    result = self.service.execute(request, cancel_event=self.cancel_event)
                result = dict(result)
                result["target"] = target.to_dict()
                result["admin_active"] = bool(self.service.admin_active)
                status_reader = getattr(self.service, "session_status", None)
                if callable(status_reader):
                    result["diagnostic_session"] = status_reader()
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
        if command["kind"] == "close" and result.get("status") not in ("COMPLETED", "DETACHED"):
            result["status"] = "RECOVERY_UNCONFIRMED"
        result["generation"] = command["generation"]
        result["request_kind"] = command["kind"]
        result["request_tag"] = command.get("tag", "")
        self.result_ready.emit(result)


class DeepInspectorBridge(QObject):
    """Lazy service owner; selecting or expanding a panel does not query Windows."""
    result_ready = Signal(object)
    busy_changed = Signal(bool)
    target_changed = Signal()
    closed = Signal(object)
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
        self.target = None
        self.generation = 0
        self.admin_active = False
        self.admin_checked_at = ""
        self._admin_expires = 0.0
        self._reset_pending = False
        self._closing = False
        self._close_result = None
        self._status_timer = QTimer(self)
        self._status_timer.setInterval(500)
        self._status_timer.timeout.connect(self._expire_admin_status)
        self._status_timer.start()

    @property
    def busy(self):
        return self.worker is not None or self._reset_pending

    @property
    def has_session(self):
        return self._service is not None or self.worker is not None

    def set_target(self, pid, created):
        target = (int(pid), float(created) if created is not None else None) if pid else None
        if target == self.target:
            return
        self.target = target
        self.generation += 1
        self.admin_active = False
        self._identity = None
        self.target_changed.emit()
        if self.worker is not None:
            self._reset_pending = True
            self.worker.cancel()
        elif self._service is not None:
            self._reset_pending = True
            self._start({"kind": "close"})

    def _start(self, command):
        if self.worker is not None:
            return False
        packet = deepcopy(command)
        packet["generation"] = self.generation
        packet["target"] = self.target
        task = _DeepTask(self, packet, self._service, self._identity, self._factory)
        self.worker = task
        task.result_ready.connect(self._receive)
        task.finished.connect(self._finished)
        self.busy_changed.emit(True)
        task.start()
        return True

    def submit(self, operation, parameters=None, *, confirmed=False, tag="", timeout_seconds=15):
        if self.busy or self._closing or self.target is None:
            return False
        return self._start({"kind": "action", "operation": operation,
                            "parameters": parameters or {}, "confirmed": confirmed,
                            "tag": tag, "timeout_seconds": timeout_seconds})

    def capabilities(self):
        if self.busy or self._closing or self.target is None:
            return False
        return self._start({"kind": "capabilities"})

    def elevate(self, operations):
        if self.busy or self._closing or self.target is None:
            return False
        return self._start({"kind": "elevate", "operations": list(operations)})

    def end_admin(self):
        if self.busy or self._closing or self.target is None:
            return False
        return self._start({"kind": "end_admin"})

    def export(self, destination):
        if self.busy or self._closing or self.target is None:
            return False
        return self._start({"kind": "export", "destination": str(destination)})

    def cancel(self):
        if self.worker is not None:
            self.worker.cancel()

    def shutdown(self):
        if self._closing:
            return
        self._closing = True
        self.generation += 1
        if self.worker is not None:
            self._reset_pending = True
            self.worker.cancel()
        elif self._service is not None:
            self._reset_pending = True
            self._start({"kind": "close"})
        else:
            self._status_timer.stop()
            self.closed.emit({"status": "COMPLETED", "data": {"cleanup": "NO_SESSION"}})

    def _receive(self, result):
        if result.get("request_kind") == "close":
            self._close_result = result
            # Recovery information belongs to the old session, even when the
            # selected target changed. Never silently discard failed cleanup.
            if result.get("status") not in ("COMPLETED", "DETACHED"):
                self.result_ready.emit(result)
            return
        if result.get("generation") != self.generation or self._closing:
            return
        self.admin_active = bool(result.get("admin_active", False))
        self.admin_checked_at = time.strftime("%H:%M:%S") if self.admin_active else ""
        remaining = result.get("diagnostic_session", {}).get("expires_in_seconds", 0)
        self._admin_expires = time.monotonic() + max(0, float(remaining or 0))
        if self.admin_active and not remaining:
            # Without a current session deadline there is no live ACTIVE claim.
            self.admin_active = False
        self.result_ready.emit(result)

    def _expire_admin_status(self):
        if self.admin_active and time.monotonic() >= self._admin_expires:
            self.admin_active = False
            self.busy_changed.emit(self.busy)

    def _finished(self):
        task = self.worker
        if task is None:
            return
        self.worker = None
        self._service = task.service
        if task.command["generation"] == self.generation:
            self._identity = task.identity
        task.deleteLater()
        if task.command["kind"] == "close":
            self._reset_pending = False
            self.admin_active = False
            self._identity = None
        elif self._reset_pending or self._closing:
            self._start({"kind": "close"})
            return
        self.busy_changed.emit(False)
        if self._closing:
            self._status_timer.stop()
            self.closed.emit(self._close_result or _failure("close", "RECOVERY_UNCONFIRMED"))
        else:
            self.idle.emit()
