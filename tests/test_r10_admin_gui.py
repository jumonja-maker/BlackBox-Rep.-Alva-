"""R10 Qt and worker contracts, executed exclusively by GitHub-hosted QA.

These doubles verify consent, generations and UI ownership. They do not claim
native execution or physical Windows Secure Desktop acceptance.
"""
import os
import threading
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtWidgets import QApplication, QMessageBox, QWidget

from blackbox_core.deep_contracts import ProcessIdentity
from blackbox_universal.deep_inspector_bridge import DeepInspectorBridge
from blackbox_universal.deep_inspector_panel import OverviewInspectorPanel


class ConsentBridge(QObject):
    result_ready = Signal(object)
    busy_changed = Signal(bool)
    target_changed = Signal()
    idle = Signal()
    closed = Signal(object)
    recovery_required = Signal(object)

    def __init__(self):
        super().__init__()
        self.target = (234, 1000.)
        self.generation = 1
        self.busy = self.admin_active = self.cleanup_required = False
        self.calls = []

    def submit(self, operation, parameters=None, **kwargs):
        self.calls.append((operation, parameters, kwargs))
        return True

    def authorize_target(self, operations):
        self.calls.append(("authorize_target", operations))
        return True

    def set_target(self, pid, created):
        self.target = (pid, created) if pid else None
        self.generation += 1
        self.target_changed.emit()

    def capabilities(self):
        return True

    def end_admin(self):
        return True

    def cancel(self):
        pass

    def retry_cleanup(self):
        return True


class LeaseService:
    """A deterministic administrative owner, not a Windows backend substitute."""

    def __init__(self, *, denied=False):
        self.denied = denied
        self.state = "INACTIVE"
        self.launches = 0
        self.expires = 0
        self.target = None
        self.scope = set()
        self.events = []
        self.thread_ids = []
        self.cleanup_failure = False
        self.crashed = False
        self.unverified = False
        self.closed = False
        self.status_entered = threading.Event()
        self.status_gate = None
        self.action_entered = threading.Event()
        self.block_action = False
        self.cleanup_entered = threading.Event()
        self.cleanup_gate = None

    def _record(self, kind, value=None):
        self.thread_ids.append(threading.get_ident())
        self.events.append((kind, value))

    def identity(self, pid):
        self._record("identity", pid)
        return ProcessIdentity(pid, 133400000000000000 + pid, "controlled.exe")

    def start_admin_session(self, *, confirmed=False, cancel_event=None):
        self._record("start_admin", confirmed)
        self.launches += 1
        if self.denied:
            self.state = "DENIED"
            return {"operation": "session.elevate", "status": "UAC_CANCELLED", "data": {}}
        self.state = "ACTIVE"
        self.expires = time.monotonic() + 900
        return {"operation": "session.elevate", "status": "COMPLETED", "data": {}}

    def set_target(self, target, *, cancel_event=None):
        self._record("select", target.pid if target else None)
        if target is not None and target == self.target:
            return {"status": "COMPLETED", "data": {}}
        self.cleanup_entered.set()
        if self.cleanup_gate is not None and not self.cleanup_gate.wait(4):
            raise RuntimeError("CONTROLLED_CLEANUP_GATE_NOT_RELEASED")
        if self.cleanup_failure:
            self.state = "CLEANUP_REQUIRED"
            return {"status": "RECOVERY_UNCONFIRMED", "retains_service": True,
                    "data": {"owner_retained": True}, "error": "CONTROLLED_CLEANUP_FAILURE"}
        if self.target:
            self._record("cleanup", self.target.pid)
        self.target = None
        self.scope.clear()
        return {"status": "COMPLETED", "data": {}}

    def bind_target(self, target, operations, *, confirmed=False, cancel_event=None):
        self._record("bind", (target.pid, list(operations), confirmed))
        if not confirmed or self.state != "ACTIVE":
            return {"status": "CONFIRMATION_REQUIRED", "data": {}}
        self.target = target
        self.scope = set(operations)
        return {"operation": "target.bind", "status": "COMPLETED", "data": {}}

    def execute(self, request, *, cancel_event=None):
        self._record("execute", (request.target.pid, request.operation, request.confirmed))
        self.action_entered.set()
        if self.block_action:
            if not cancel_event.wait(4):
                raise RuntimeError("CONTROLLED_ACTION_CANCELLATION_MISSING")
            return {"status": "CANCELLED", "data": {}}
        if request.operation != "processes" and self.state == "ACTIVE" and (
                request.target != self.target or request.operation not in self.scope):
            return {"operation": request.operation, "status": "CONFIRMATION_REQUIRED", "data": {},
                    "next_action": "AUTHORIZE_TARGET_AND_OPERATION_SCOPE"}
        return {"operation": request.operation, "status": "COMPLETED", "data": {"pid": request.target.pid}}

    def session_status(self, *, refresh=False):
        self._record("status", refresh)
        self.status_entered.set()
        if self.status_gate is not None and not self.status_gate.wait(4):
            raise RuntimeError("CONTROLLED_STATUS_GATE_NOT_RELEASED")
        remaining = max(0, self.expires - time.monotonic())
        if self.crashed:
            self.state = "FAILED"
        elif self.state == "ACTIVE" and not remaining:
            self.state = "EXPIRED"
        return {"state": self.state, "elevated_verified": self.state == "ACTIVE" and not self.unverified,
                "remaining_seconds": remaining, "expires_in_seconds": remaining,
                "helper_pid": 777 if self.state == "ACTIVE" else None,
                "admin_session_managed": self.launches > 0}

    def end_admin_session(self):
        self._record("end_admin")
        if self.cleanup_failure:
            self.state = "CLEANUP_REQUIRED"
            return {"status": "RECOVERY_UNCONFIRMED", "retains_service": True,
                    "data": {"owner_retained": True}}
        self.state = "INACTIVE"
        self.expires = 0
        self.target = None
        self.scope.clear()
        return {"status": "COMPLETED", "data": {"cleanup": "VERIFIED"}}

    def close(self):
        answer = self.end_admin_session()
        self.closed = answer["status"] == "COMPLETED"
        return answer


class R10AdminBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.service = LeaseService()
        self.bridge = DeepInspectorBridge(service_factory=lambda: self.service)
        self.bridge._status_timer.stop()
        self.results = []
        self.bridge.result_ready.connect(self.results.append)
        self.process_patch = patch("blackbox_universal.deep_inspector_bridge.psutil.Process")
        process = self.process_patch.start()
        process.return_value.create_time.return_value = 1000.

    def wait(self, predicate, timeout=5):
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(.005)
        self.app.processEvents()
        self.assertTrue(predicate())

    def idle(self):
        self.wait(lambda: self.bridge.worker is None)

    def tearDown(self):
        self.service.cleanup_failure = False
        self.service.block_action = False
        if self.service.status_gate is not None:
            self.service.status_gate.set()
        if self.service.cleanup_gate is not None:
            self.service.cleanup_gate.set()
        self.bridge.cancel()
        self.bridge.shutdown()
        self.idle()
        if self.bridge.cleanup_required:
            self.bridge.retry_cleanup()
            self.idle()
        self.bridge.deleteLater()
        self.app.processEvents()
        self.process_patch.stop()

    def start_session(self):
        self.assertTrue(self.bridge.start_admin())
        self.idle()
        self.assertTrue(self.bridge.admin_active)

    def test_start_before_selection_uses_worker_and_close_releases_unbound_helper(self):
        made = []
        self.bridge._factory = lambda: (made.append(threading.get_ident()), self.service)[1]
        self.assertIsNone(self.bridge.target)
        self.start_session()
        self.assertEqual(self.service.launches, 1)
        self.assertFalse(any(kind == "identity" for kind, _ in self.service.events))
        self.assertNotEqual(made[0], threading.get_ident())
        self.assertTrue(all(tid != threading.get_ident() for tid in self.service.thread_ids))
        closed = []
        self.bridge.closed.connect(closed.append)
        self.bridge.shutdown()
        self.idle()
        self.assertTrue(self.service.closed)
        self.assertEqual(closed[0]["status"], "COMPLETED")
        self.assertFalse(self.bridge.has_session)

    def test_two_targets_keep_one_lease_and_require_fresh_target_scope(self):
        self.start_session()
        deadline = self.service.expires
        for pid in (123, 456):
            self.bridge.set_target(pid, 1000.)
            self.idle()
            self.assertIs(self.bridge._service, self.service)
            self.assertTrue(self.bridge.submit("memory_read", {"address": 4096, "size": 8}))
            self.idle()
            self.assertEqual(self.results[-1]["status"], "CONFIRMATION_REQUIRED")
            self.assertTrue(self.bridge.authorize_target(["memory_read"]))
            self.idle()
            self.assertTrue(self.bridge.submit("memory_read", {"address": 4096, "size": 8}))
            self.idle()
            self.assertEqual(self.results[-1]["status"], "COMPLETED")
            self.assertEqual(self.results[-1]["target"]["pid"], pid)
        self.assertEqual(self.service.launches, 1)
        self.assertEqual(self.service.expires, deadline)
        self.assertIn(("cleanup", 123), self.service.events)
        self.assertEqual([entry[1][0] for entry in self.service.events if entry[0] == "bind"], [123, 456])

    def test_legacy_deep_button_starts_the_same_managed_lease_and_then_reuses_it(self):
        self.bridge.set_target(123, 1000.)
        self.assertTrue(self.bridge.elevate(["memory_read"]))
        self.idle()
        self.assertEqual(self.results[-1]["request_kind"], "elevate")
        self.assertEqual(self.results[-1]["status"], "COMPLETED")
        self.assertTrue(self.bridge.admin_active)
        original_deadline = self.service.expires
        self.bridge.set_target(456, 1000.)
        self.idle()
        self.assertTrue(self.bridge.elevate(["memory_read"]))
        self.idle()
        self.assertEqual(self.service.launches, 1)
        self.assertEqual(self.service.expires, original_deadline)
        self.assertEqual(self.service.target.pid, 456)

    def test_denial_keeps_ordinary_read_available_without_retrying_uac(self):
        self.service.denied = True
        self.assertTrue(self.bridge.start_admin())
        self.idle()
        self.assertEqual(self.bridge.admin_state, "DENIED")
        self.assertFalse(self.bridge.admin_active)
        self.bridge.set_target(123, 1000.)
        self.idle()
        self.assertTrue(self.bridge.submit("processes"))
        self.idle()
        self.assertEqual(self.results[-1]["status"], "COMPLETED")
        self.assertEqual(self.service.launches, 1)

    def test_status_is_worker_verified_and_crash_unverified_and_expiry_remove_active(self):
        self.start_session()
        self.service.unverified = True
        self.bridge._expire_admin_status()
        self.idle()
        self.assertFalse(self.bridge.admin_active)
        self.service.unverified = False
        self.service.crashed = True
        self.bridge._last_status_poll = 0
        self.bridge._expire_admin_status()
        self.idle()
        self.assertEqual(self.bridge.admin_state, "FAILED")
        self.assertFalse(self.bridge.admin_active)
        self.service.crashed = False
        self.service.state = "ACTIVE"
        self.service.expires = time.monotonic() - 1
        self.bridge._last_status_poll = 0
        self.bridge._expire_admin_status()
        self.idle()
        self.assertEqual(self.bridge.admin_state, "EXPIRED")
        self.assertFalse(self.bridge.admin_active)
        self.assertTrue(all(tid != threading.get_ident() for tid in self.service.thread_ids))

    def test_cleanup_failure_retains_owner_and_blocks_new_target_until_explicit_retry(self):
        self.start_session()
        self.bridge.set_target(123, 1000.)
        self.idle()
        self.bridge.authorize_target(["memory.write"])
        self.idle()
        self.service.cleanup_failure = True
        recovery = []
        self.bridge.recovery_required.connect(recovery.append)
        self.bridge.set_target(456, 1000.)
        self.idle()
        self.assertTrue(self.bridge.cleanup_required)
        self.assertIs(self.bridge._service, self.service)
        self.assertFalse(self.bridge.admin_active)
        self.assertEqual(recovery[-1]["status"], "RECOVERY_UNCONFIRMED")
        self.assertFalse(self.bridge.submit("memory.write", {}, confirmed=True))
        self.assertFalse(self.bridge.authorize_target(["memory.write"]))
        self.assertFalse(any(kind == "bind" and value[0] == 456 for kind, value in self.service.events))
        self.service.cleanup_failure = False
        self.assertTrue(self.bridge.retry_cleanup())
        self.idle()
        self.assertFalse(self.bridge.cleanup_required)
        self.assertFalse(self.bridge.has_session)

    def test_action_queued_during_heartbeat_is_discarded_when_target_changes(self):
        self.start_session()
        self.bridge.set_target(123, 1000.)
        self.idle()
        self.service.status_entered.clear()
        self.service.status_gate = threading.Event()
        self.bridge._last_status_poll = 0
        self.bridge._expire_admin_status()
        self.wait(self.service.status_entered.is_set)
        self.assertFalse(self.bridge.busy)
        self.assertTrue(self.bridge.submit("memory.write", {"address": 4096}, confirmed=True))
        self.bridge.set_target(456, 1000.)
        self.service.status_gate.set()
        self.idle()
        self.assertFalse(any(kind == "execute" for kind, _ in self.service.events))
        self.assertEqual(self.bridge.target, (456, 1000.))

    def test_target_change_cancels_old_action_and_drops_old_evidence(self):
        self.start_session()
        self.bridge.set_target(123, 1000.)
        self.idle()
        self.results.clear()
        self.service.block_action = True
        self.bridge.submit("processes")
        self.wait(self.service.action_entered.is_set)
        self.bridge.set_target(456, 1000.)
        self.idle()
        self.assertEqual(self.results, [])
        self.assertIs(self.bridge._service, self.service)
        self.assertIsNone(self.bridge._identity)

    def test_shutdown_during_target_release_still_closes_the_shared_helper(self):
        self.start_session()
        self.service.cleanup_gate = threading.Event()
        self.bridge.set_target(123, 1000.)
        self.wait(self.service.cleanup_entered.is_set)
        closed = []
        self.bridge.closed.connect(closed.append)
        self.bridge.shutdown()
        self.service.cleanup_gate.set()
        self.idle()
        self.assertTrue(self.service.closed)
        self.assertFalse(self.bridge.has_session)
        self.assertEqual(closed[-1]["status"], "COMPLETED")


class R10AdminToolbarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        from blackbox_universal.window import UniversalWindow
        self.window = UniversalWindow(allow_update_check=False)
        self.window._timer.stop()
        self.bridge = self.window.deep_inspector_panel.bridge
        self.bridge._status_timer.stop()
        self.service = LeaseService()
        self.bridge._factory = lambda: self.service
        self.window._set_language("EN")
        self.window.show()
        self.app.processEvents()

    def wait(self, predicate, timeout=5):
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(.005)
        self.app.processEvents()
        self.assertTrue(predicate())

    def tearDown(self):
        self.service.cleanup_failure = False
        self.bridge.shutdown()
        self.wait(lambda: self.bridge.worker is None)
        with patch("blackbox_universal.window.QMessageBox.warning"):
            self.window.close()
        self.window.deleteLater()
        self.app.processEvents()

    def consent(self, *, accept, after_open=None):
        observed = []
        def choose():
            dialog = self.app.activeModalWidget()
            observed.append((dialog.text(), dialog.objectName(),
                             dialog.standardButton(dialog.defaultButton())))
            if after_open:
                after_open()
            if accept:
                button = next(item for item in dialog.buttons()
                              if dialog.buttonRole(item) == QMessageBox.ButtonRole.AcceptRole)
            else:
                button = dialog.button(QMessageBox.StandardButton.Cancel)
            button.click()
        QTimer.singleShot(0, choose)
        self.window.admin_button.click()
        self.assertEqual(observed[0][1], "adminSessionConsent")
        self.assertEqual(observed[0][2], QMessageBox.StandardButton.Cancel)
        return observed[0][0]

    def test_persistent_top_control_before_target_has_explanation_and_cancel_default(self):
        self.assertIsNone(self.bridge.target)
        self.assertTrue(self.window.admin_button.isVisible())
        self.assertTrue(self.window.admin_button.isEnabled())
        self.assertEqual(self.window.admin_button.parentWidget().objectName(), "toolbar")
        text = self.consent(accept=False)
        self.assertIn("900 seconds", text)
        self.assertIn("Each new target", text)
        self.assertFalse(self.bridge.has_session)
        self.assertEqual(self.service.launches, 0)
        self.assertEqual(len(self.window.PAGES), 5)

    def test_active_remaining_and_end_action_are_bilingual_and_end_without_target(self):
        self.consent(accept=True)
        self.wait(lambda: self.bridge.worker is None)
        self.assertTrue(self.bridge.admin_active)
        self.assertIn("Administrator session active", self.window.admin_button.text())
        self.assertIn("Remaining:", self.window.admin_button.text())
        self.window._set_language("RU")
        self.assertIn("Административная сессия активна", self.window.admin_button.text())
        self.assertIn("Осталось:", self.window.admin_button.text())
        self.assertEqual(self.window.admin_end_action.text(), "Завершить сеанс")
        self.assertTrue(self.window.admin_end_action.isEnabled())
        self.assertIsNone(self.bridge.target)
        self.window.admin_end_action.trigger()
        self.wait(lambda: self.bridge.worker is None)
        self.assertFalse(self.bridge.admin_active)
        self.assertEqual(self.service.state, "INACTIVE")
        self.assertIn("Включить права администратора", self.window.admin_button.text())

    def test_declined_uac_keeps_navigation_reports_and_decoder_page_contract(self):
        self.service.denied = True
        self.consent(accept=True)
        self.wait(lambda: self.bridge.worker is None)
        self.assertEqual(self.bridge.admin_state, "DENIED")
        self.assertFalse(self.window.admin_button.property("adminActive"))
        for page in ("dashboard", "processes", "reports", "settings"):
            self.window._navigate(page)
            self.assertEqual(self.window.stack.currentIndex(), self.window._page_ids[page])
        from blackbox_universal.decoder_window import DecoderWindow
        self.assertEqual(len(DecoderWindow.PAGES), 6)
        self.assertEqual(DecoderWindow.PAGES[-1][0], "decoder")

    def test_closing_window_with_unbound_admin_helper_waits_for_cleanup(self):
        self.consent(accept=True)
        self.wait(lambda: self.bridge.worker is None)
        self.assertIsNone(self.bridge.target)
        self.assertFalse(self.window.close())
        self.wait(lambda: self.bridge.worker is None and self.service.closed)
        self.wait(lambda: not self.window.isVisible())


class R10TargetConsentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_target_change_during_scope_consent_never_binds_replacement(self):
        parent = QWidget()
        parent.language = "EN"
        bridge = ConsentBridge()
        panel = OverviewInspectorPanel(parent, bridge=bridge)
        try:
            panel._request("memory_read", {"address": 4096, "size": 8})
            panel._receive({"operation": "memory_read", "status": "CONFIRMATION_REQUIRED", "data": {},
                "target": {"pid": 234, "created_100ns": 133400000000000234},
                "next_action": "AUTHORIZE_TARGET_AND_OPERATION_SCOPE"})
            count = len(bridge.calls)
            with patch("blackbox_universal.deep_inspector_panel.QMessageBox") as boxes:
                dialog = boxes.return_value
                grant = object()
                dialog.addButton.return_value = grant
                dialog.clickedButton.return_value = grant
                dialog.exec.side_effect = lambda: panel.set_target(235, 2000., "replacement")
                panel._elevate()
            self.assertEqual(len(bridge.calls), count)
            self.assertIsNone(panel._pending_retry)
            self.assertIn("CANCELLED", panel.status_label.text())
            self.assertIn("133400000000000234", boxes.call_args.args[2])
        finally:
            panel.deleteLater()
            parent.deleteLater()
            self.app.processEvents()

    def test_capabilities_has_its_own_target_consent_and_never_retries_a_previous_action(self):
        parent = QWidget()
        parent.language = "EN"
        bridge = ConsentBridge()
        panel = OverviewInspectorPanel(parent, bridge=bridge)
        try:
            panel._request("memory_read", {"address": 4096, "size": 8})
            panel._capabilities()
            self.assertEqual(panel._last_request["operation"], "capabilities")
            panel._receive({"operation": "capabilities", "status": "CONFIRMATION_REQUIRED", "data": {},
                "target": {"pid": 234, "created_100ns": 133400000000000234},
                "next_action": "AUTHORIZE_TARGET_AND_OPERATION_SCOPE"})
            self.assertFalse(panel.elevate_button.isHidden())
            with patch("blackbox_universal.deep_inspector_panel.QMessageBox") as boxes:
                dialog = boxes.return_value
                grant = object()
                dialog.addButton.return_value = grant
                dialog.clickedButton.return_value = grant
                panel._elevate()
            self.assertEqual(bridge.calls[-1], ("authorize_target", ["capabilities"]))
            panel._receive({"operation": "target.bind", "request_kind": "authorize_target",
                            "status": "COMPLETED", "data": {}})
            panel._idle()
            self.assertEqual(bridge.calls[-1][0], "capabilities")
        finally:
            panel.deleteLater()
            parent.deleteLater()
            self.app.processEvents()
