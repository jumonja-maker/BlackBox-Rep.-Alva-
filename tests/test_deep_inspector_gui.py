"""BB-DEEP-001 Qt contracts; executed only by GitHub-hosted CI.

Backend doubles test GUI choices and lifecycle, not native Windows behavior.
Actual Windows inspection and intervention have a separate acceptance job.
"""
import os
import threading
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication, QMessageBox, QWidget

from blackbox_core.deep_contracts import ProcessIdentity
from blackbox_universal.deep_inspector_bridge import DeepInspectorBridge
from blackbox_universal.deep_inspector_panel import OverviewInspectorPanel, SECTIONS


class FakeBridge(QObject):
    result_ready = Signal(object)
    busy_changed = Signal(bool)
    target_changed = Signal()
    idle = Signal()
    closed = Signal(object)

    def __init__(self):
        super().__init__()
        self.target = (234, 1000.0)
        self.generation = 1
        self.busy = False
        self.admin_active = False
        self.calls = []

    def submit(self, operation, parameters=None, **kwargs):
        if self.busy:
            return False
        self.calls.append((operation, parameters or {}, kwargs))
        return True

    def capabilities(self):
        self.calls.append(("capabilities", {}, {}))
        return True

    def elevate(self, operations):
        self.calls.append(("elevate", {"operations": operations}, {}))
        return True

    def end_admin(self):
        self.calls.append(("end_admin", {}, {}))
        return True

    def export(self, destination):
        self.calls.append(("export", {"destination": destination}, {}))
        return True

    def cancel(self):
        self.calls.append(("cancel", {}, {}))

    def shutdown(self):
        self.calls.append(("shutdown", {}, {}))
        self.closed.emit({"status": "COMPLETED"})

    def set_target(self, pid, created):
        value = (pid, created) if pid else None
        if value != self.target:
            self.target = value
            self.generation += 1
            self.target_changed.emit()


class DeepInspectorGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = QWidget()
        self.window.language = "EN"
        self.bridge = FakeBridge()
        self.panel = OverviewInspectorPanel(self.window, bridge=self.bridge)
        self.panel.resize(850, 800)
        self.panel.show()
        self.app.processEvents()

    def tearDown(self):
        self.panel.close()
        self.window.close()
        self.panel.deleteLater()
        self.window.deleteLater()
        self.app.processEvents()

    def test_nine_sections_are_local_and_opening_never_starts_work(self):
        self.assertEqual(self.panel.section.count(), 9)
        self.assertEqual(self.panel.pages.count(), 9)
        for index, (key, _, _) in enumerate(SECTIONS):
            self.panel.section.setCurrentIndex(index)
            self.assertEqual(self.panel.section.currentData(), key)
            self.assertEqual(self.panel.pages.currentIndex(), index)
        self.assertEqual(self.bridge.calls, [])

    def test_required_controls_exist_and_translate_without_commands(self):
        required = {"capabilities", "before", "after", "compare", "cancel", "end_admin",
                    "processes", "modules", "threads", "thread_stacks", "wait_chains", "handles",
                    "memory_map", "memory_read", "memory.write", "memory.rollback", "network", "disk",
                    "debug.attach", "debug.pause", "debug.continue", "debug.step", "debug.context", "debug.detach",
                    "debug.breakpoints", "debug.breakpoint.add", "debug.breakpoint.disable", "debug.breakpoint.remove",
                    "thread.suspend", "thread.resume", "dump", "dump_inspect", "symbols_verify", "export", "trace_evidence"}
        self.assertTrue(required.issubset(self.panel._action_buttons))
        english = {k: b.text() for k, b in self.panel._action_buttons.items()}
        self.window.language = "RU"
        self.panel.retranslate()
        for key in required:
            self.assertNotEqual(self.panel._action_buttons[key].text(), english[key], key)
            self.assertEqual(self.panel._action_buttons[key].accessibleName(), self.panel._action_buttons[key].text())
        self.window.language = "EN"
        self.panel.retranslate()
        self.assertEqual({k: b.text() for k, b in self.panel._action_buttons.items()}, english)
        self.assertEqual(self.bridge.calls, [])

    def test_read_buttons_dispatch_real_operation_names(self):
        for key in ("processes", "modules", "threads", "handles", "memory_map", "network", "disk", "wait_chains", "timeline", "debug.breakpoints", "debug.context"):
            self.panel._action_buttons[key].click()
            self.assertEqual(self.bridge.calls[-1][0], key)

    def test_memory_input_validation_precedes_confirmation_and_write(self):
        self.panel.memory_address.setText("0x12340000")
        self.panel.expected_bytes.setText("01 02")
        self.panel.new_bytes.setText("03")
        with patch.object(self.panel, "_confirm") as confirm:
            self.panel._action_buttons["memory.write"].click()
        confirm.assert_not_called()
        self.assertEqual(self.bridge.calls, [])
        self.assertIn("MEMORY_BYTES_MUST_HAVE_EQUAL_BOUNDED_LENGTH", self.panel.status_label.text())

    def test_memory_write_exact_bytes_and_restore_id_require_confirmation(self):
        self.panel.memory_address.setText("0x12340000")
        self.panel.expected_bytes.setText("01 02")
        self.panel.new_bytes.setText("03 04")
        with patch.object(self.panel, "_confirm", return_value=False):
            self.panel._action_buttons["memory.write"].click()
        self.assertEqual(self.bridge.calls, [])
        with patch.object(self.panel, "_confirm", return_value=True) as confirmation:
            self.panel._action_buttons["memory.write"].click()
        operation, parameters, options = self.bridge.calls[-1]
        self.assertEqual(operation, "memory.write")
        self.assertEqual(parameters, {"address": 0x12340000, "expected_hex": "0102", "value_hex": "0304"})
        self.assertTrue(options["confirmed"])
        confirmation.assert_called_once_with(operation, parameters)
        self.panel._receive({"operation": "memory.write", "status": "COMPLETED", "data": {"change_id": "change-1"}})
        self.assertEqual(self.panel.write_id.text(), "change-1")
        with patch.object(self.panel, "_confirm", return_value=True):
            self.panel._action_buttons["memory.rollback"].click()
        self.assertEqual(self.bridge.calls[-1][1], {"change_id": "change-1"})

    def test_thread_selection_carries_lifetime_not_tid_alone(self):
        result = {"operation": "threads", "status": "COMPLETED", "data": {
            "threads": [{"tid": 75, "thread_created_100ns": 133400000000000000}]}}
        self.panel._show_result("threads", result)
        self.panel._tables["threads"].selectRow(0)
        self.app.processEvents()
        with patch.object(self.panel, "_confirm", return_value=True):
            self.panel._action_buttons["thread.suspend"].click()
        self.assertEqual(self.bridge.calls[-1][1], {"tid": 75, "thread_created_100ns": 133400000000000000})
        self.panel.thread_created.clear()
        count = len(self.bridge.calls)
        self.panel._action_buttons["thread.resume"].click()
        self.assertEqual(len(self.bridge.calls), count)

    def test_debug_buttons_confirm_and_propagate_stopped_context(self):
        self.panel._receive({"operation": "debug.pause", "status": "COMPLETED", "data": {
            "state": "PAUSED", "stopped_tid": 23, "thread_created_100ns": 123456}})
        self.assertEqual(self.panel.debug_tid.text(), "23")
        self.assertEqual(self.panel.debug_state_label.text(), "DEBUG: PAUSED")
        self.panel.breakpoint_address.setText("0x20000")
        self.panel.breakpoint_id.setText("bp-1")
        for operation in ("debug.attach", "debug.pause", "debug.continue", "debug.step", "debug.detach",
                          "debug.breakpoint.add", "debug.breakpoint.disable", "debug.breakpoint.remove"):
            count = len(self.bridge.calls)
            with patch.object(self.panel, "_confirm", return_value=False):
                self.panel._action_buttons[operation].click()
            self.assertEqual(len(self.bridge.calls), count)
            with patch.object(self.panel, "_confirm", return_value=True):
                self.panel._action_buttons[operation].click()
            self.assertEqual(self.bridge.calls[-1][0], operation)
            self.assertTrue(self.bridge.calls[-1][2]["confirmed"])

    def test_before_after_stay_separate_and_target_change_invalidates_them(self):
        self.assertFalse(self.panel._action_buttons["compare"].isEnabled())
        self.panel._receive({"operation": "snapshot", "request_tag": "before", "status": "COMPLETED", "data": {"snapshot_id": "before-1"}})
        self.panel._receive({"operation": "snapshot", "request_tag": "after", "status": "COMPLETED", "data": {"snapshot_id": "after-1"}})
        self.assertTrue(self.panel._action_buttons["compare"].isEnabled())
        self.panel._action_buttons["compare"].click()
        self.assertEqual(self.bridge.calls[-1][1], {"before_id": "before-1", "after_id": "after-1"})
        self.panel.set_target(235, 1001., "replacement")
        self.assertIsNone(self.panel._before_id)
        self.assertIsNone(self.panel._after_id)
        self.assertFalse(self.panel._action_buttons["compare"].isEnabled())

    def test_busy_operation_disables_mutation_but_keeps_cancel(self):
        self.bridge.busy = True
        self.bridge.busy_changed.emit(True)
        self.assertFalse(self.panel._action_buttons["memory.write"].isEnabled())
        self.assertFalse(self.panel._action_buttons["debug.attach"].isEnabled())
        self.assertTrue(self.panel.cancel_button.isEnabled())
        self.panel.cancel_button.click()
        self.assertEqual(self.bridge.calls[-1][0], "cancel")

    def test_uac_cancel_never_retries_the_requested_operation(self):
        self.panel._request("modules")
        self.panel._receive({"operation": "modules", "status": "ADMIN_REQUIRED", "data": {}})
        self.assertFalse(self.panel.elevate_button.isHidden())
        self.panel._pending_retry = dict(self.panel._last_request)
        self.panel._receive({"operation": "elevate", "request_kind": "elevate", "status": "UAC_CANCELLED", "data": {}})
        count = len(self.bridge.calls)
        self.panel._idle()
        self.assertEqual(len(self.bridge.calls), count)
        self.assertIn("UAC_CANCELLED", self.panel.status_label.text())

    def test_recovery_unconfirmed_is_visible_and_not_rendered_as_success(self):
        self.panel._receive({"operation": "debug.detach", "status": "RECOVERY_UNCONFIRMED",
                             "data": {}, "limitations": ["OWN_THREAD_RESUME_NOT_CONFIRMED"]})
        self.assertIn("RECOVERY_UNCONFIRMED", self.panel.status_label.text())
        self.assertIn("OWN_THREAD_RESUME_NOT_CONFIRMED", self.panel.summary.text())
        self.assertIn("bold", self.panel.status_label.styleSheet())

    def test_file_dialog_actions_only_submit_explicit_chosen_paths(self):
        with patch("blackbox_universal.deep_inspector_panel.QFileDialog.getOpenFileName",
                   side_effect=[("sample.exe", ""), ("sample.pdb", ""), ("saved.dmp", ""), ("trace.sqlite3", "")]):
            self.panel._symbols()
            self.panel._inspect_dump()
            self.panel._trace()
        self.assertEqual(self.bridge.calls[-3][0:2], ("symbols_verify", {"pe_path": "sample.exe", "pdb_path": "sample.pdb"}))
        self.assertEqual(self.bridge.calls[-2][0:2], ("dump_inspect", {"path": "saved.dmp"}))
        self.assertEqual(self.bridge.calls[-1][0:2], ("trace_evidence", {"index_path": "trace.sqlite3", "limit": 200}))
        self.assertNotIn("process_instance", self.bridge.calls[-1][1])

    def test_dump_type_destination_and_confirmation_are_explicit(self):
        with patch("blackbox_universal.deep_inspector_panel.QInputDialog.getItem", return_value=("Extended dump with memory", True)), \
             patch("blackbox_universal.deep_inspector_panel.QFileDialog.getSaveFileName", return_value=("selected.dmp", "")), \
             patch.object(self.panel, "_confirm", return_value=True):
            self.panel._dump()
        operation, params, options = self.bridge.calls[-1]
        self.assertEqual(operation, "dump")
        self.assertEqual(params["destination"], "selected.dmp")
        self.assertTrue(params["full"])
        self.assertTrue(options["confirmed"])

    def test_table_output_is_bounded_and_treated_as_plain_text(self):
        self.panel._receive({"operation": "processes", "status": "INCOMPLETE_EVIDENCE", "data": {
            "rows": [{"pid": i, "name": "<script>not markup</script>"} for i in range(800)]}})
        table = self.panel._tables["processes"]
        self.assertEqual(table.rowCount(), 500)
        self.assertIn("500 / 800", self.panel.summary.text())
        self.assertEqual(table.item(0, 1).text(), "<script>not markup</script>")


class _FakeService:
    def __init__(self, *, block=False, close_failure=False):
        self.admin_active = False
        self.block = block
        self.close_failure = close_failure
        self.started = threading.Event()
        self.closed = False
        self.identities = []
        self.executed = []

    def identity(self, pid):
        self.identities.append(pid)
        return ProcessIdentity(pid, 133400000000000000, "controlled.exe")

    def execute(self, request, cancel_event=None):
        self.executed.append(request)
        self.started.set()
        if self.block:
            if not cancel_event.wait(4):
                raise TimeoutError("TEST_CANCEL_NOT_RECEIVED")
            return {"status": "CANCELLED", "operation": request.operation, "data": {}}
        return {"status": "COMPLETED", "operation": request.operation, "data": {"pid": request.target.pid}}

    def close(self):
        self.closed = True
        if self.close_failure:
            raise RuntimeError("CONTROLLED_CLEANUP_FAILURE")
        return {"status": "COMPLETED", "data": {"cleanup": "VERIFIED"}}


class DeepInspectorBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def wait(self, predicate, timeout=5):
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(.005)
        self.app.processEvents()
        self.assertTrue(predicate())

    def test_lazy_identity_and_worker_do_not_run_on_select(self):
        made = []
        service = _FakeService()
        bridge = DeepInspectorBridge(service_factory=lambda: (made.append(threading.get_ident()), service)[1])
        bridge.set_target(123, 1000.)
        self.assertEqual(made, [])
        results = []
        bridge.result_ready.connect(results.append)
        with patch("psutil.Process") as process:
            process.return_value.create_time.return_value = 1000.
            self.assertTrue(bridge.submit("modules"))
            self.wait(lambda: bridge.worker is None)
        self.assertNotEqual(made[0], threading.get_ident())
        self.assertEqual(results[0]["status"], "COMPLETED")
        bridge.shutdown()
        self.wait(lambda: bridge.worker is None)
        self.assertTrue(service.closed)

    def test_pid_reuse_before_first_action_refuses_native_execution(self):
        service = _FakeService()
        bridge = DeepInspectorBridge(service_factory=lambda: service)
        bridge.set_target(123, 1000.)
        results = []
        bridge.result_ready.connect(results.append)
        with patch("psutil.Process") as process:
            process.return_value.create_time.return_value = 2000.
            bridge.submit("memory_read", {"address": 1, "size": 1})
            self.wait(lambda: bridge.worker is None)
        self.assertEqual(results[0]["status"], "PROCESS_CHANGED")
        self.assertEqual(service.identities, [])
        self.assertEqual(service.executed, [])
        bridge.shutdown()
        self.wait(lambda: bridge.worker is None)

    def test_switch_cancels_old_work_and_drops_stale_evidence_then_closes(self):
        service = _FakeService(block=True)
        bridge = DeepInspectorBridge(service_factory=lambda: service)
        bridge.set_target(123, 1000.)
        results = []
        bridge.result_ready.connect(results.append)
        with patch("psutil.Process") as process:
            process.return_value.create_time.return_value = 1000.
            bridge.submit("modules")
            self.wait(service.started.is_set)
            bridge.set_target(456, 2000.)
            self.wait(lambda: bridge.worker is None and not bridge.busy)
        self.assertEqual(results, [])
        self.assertTrue(service.closed)
        self.assertIsNone(bridge._identity)

    def test_async_close_failure_surfaces_recovery_unconfirmed(self):
        service = _FakeService(close_failure=True)
        bridge = DeepInspectorBridge(service_factory=lambda: service)
        bridge.set_target(123, 1000.)
        with patch("psutil.Process") as process:
            process.return_value.create_time.return_value = 1000.
            bridge.submit("modules")
            self.wait(lambda: bridge.worker is None)
        closed = []
        bridge.closed.connect(closed.append)
        bridge.shutdown()
        self.wait(lambda: len(closed) == 1)
        self.assertEqual(closed[0]["status"], "RECOVERY_UNCONFIRMED")
        self.assertIn("CONTROLLED_CLEANUP_FAILURE", closed[0]["error"])
