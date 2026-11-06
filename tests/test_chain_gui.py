"""R60 actual Qt editor and runtime consent contracts; hosted CI execution only.

Controlled consent doubles below test races; native effects are covered by the
separate source/frozen hosted harness and are never inferred from these doubles.
"""
from copy import deepcopy
import faulthandler
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QObject, QPoint, Qt, Signal, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox, QWidget

from blackbox_core.deep_contracts import ProcessIdentity
from blackbox_universal.chain_builder import ObjectParameterEditor, ConditionParameterEditor, OptionalParameterEditor
from blackbox_universal.chain_bridge import _ChainTask
from blackbox_universal.deep_inspector_bridge import DeepInspectorBridge, _DeepTask
from blackbox_universal.deep_inspector_panel import OverviewInspectorPanel
from blackbox_universal.window import UniversalWindow


class ChainEditorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.window = UniversalWindow(output_root=Path(self.temp.name), allow_update_check=False)
        self.window._timer.stop()
        self.window.show()
        self.panel = self.window.chain_builder_panel
        self.window.overview_tabs.setCurrentWidget(self.panel)
        self.results = []
        self.panel.bridge.result_ready.connect(lambda op, value, error: self.results.append((op, value, error)))
        self.wait_idle()
        self.assertIn("observe", self.panel.catalog)

    def wait_idle(self):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            self.app.processEvents()
            if not self.panel.bridge.busy:
                return
            # A native/SQLite worker must be able to reacquire Python's GIL.
            # Qt's nested qWait loop can starve it on Windows; the existing
            # asynchronous GUI fixtures yield with sleep for the same reason.
            time.sleep(.005)
        worker = self.panel.bridge.worker
        engine = getattr(worker, "engine", None)
        print("CHAIN_GUI_TIMEOUT_BOUNDARY", {
            "operation": getattr(worker, "operation", None),
            "engine_state": getattr(engine, "_state", None),
            "node_states": {key: value.get("state") for key, value in
                            getattr(engine, "_records", {}).items()},
            "qt_worker_running": worker.isRunning() if worker is not None else False}, flush=True)
        faulthandler.dump_traceback(all_threads=True)
        self.fail("CHAIN_GUI_WORKER_DID_NOT_FINISH")

    def tearDown(self):
        from qt_test_support import close_and_drain
        close_and_drain(self.window, self.app, timeout=15)
        self.temp.cleanup()

    def add(self, tool):
        for index in range(self.panel.palette.count()):
            item = self.panel.palette.item(index)
            if item.data(Qt.ItemDataRole.UserRole) == tool:
                self.panel.palette.setCurrentItem(item)
                self.panel.add_button.click()
                return self.panel.document["nodes"][-1]
        self.fail("MISSING_TOOL_" + tool)

    def test_internal_overview_tab_preserves_five_page_embedder_api(self):
        self.assertEqual(len(self.window.PAGES), 5)
        self.assertEqual(self.window.stack.count(), 5)
        self.assertEqual(self.window.overview_tabs.count(), 2)
        self.assertIs(self.window.overview_tabs.widget(1), self.panel)
        original = self.window.deep_inspector_panel.bridge
        for language in ("RU", "EN", "RU", "EN"):
            self.window._set_language(language)
            self.assertIs(self.window.deep_inspector_panel.bridge, original)
            self.assertEqual(self.panel.document["nodes"], [])
            self.assertEqual(self.window.probe.active, False)
        for key, _ in self.window.PAGES:
            self.window._navigate(key)
            self.assertEqual(self.window.stack.currentIndex(), self.window._page_ids[key])

    def test_real_canvas_mouse_move_keyboard_move_and_zoom_preserve_coordinates(self):
        node = self.add("process_select")
        self.panel.fit_graph()
        item = self.panel.canvas.items_by_id[node["node_id"]]
        self.panel.canvas.resetTransform()
        self.panel.canvas.centerOn(item)
        self.app.processEvents()
        canvas = self.panel.canvas
        point = canvas.mapFromScene(item.scenePos() + QPoint(100, 20))
        before = list(node["position"])
        QTest.mousePress(canvas.viewport(), Qt.MouseButton.LeftButton, pos=point)
        QTest.mouseMove(canvas.viewport(), point + QPoint(45, 30), delay=30)
        QTest.mouseRelease(canvas.viewport(), Qt.MouseButton.LeftButton, pos=point + QPoint(45, 30))
        self.app.processEvents()
        self.assertNotEqual(node["position"], before)
        item.setSelected(True)
        canvas.setFocus()
        moved = list(node["position"])
        QTest.keyClick(canvas, Qt.Key.Key_Right)
        self.assertEqual(node["position"][0], moved[0] + 10)
        transform = canvas.transform().m11()
        QTest.keyClick(canvas, Qt.Key.Key_Plus)
        self.assertGreater(canvas.transform().m11(), transform)
        self.assertEqual(node["position"][0], moved[0] + 10)

    def test_keyboard_connection_controls_use_worker_type_check_and_show_exact_rejection(self):
        source = self.add("process_select")
        target = self.add("observe")
        self.panel.source_node.setCurrentIndex(self.panel.source_node.findData(source["node_id"]))
        self.panel.target_node.setCurrentIndex(self.panel.target_node.findData(target["node_id"]))
        self.panel.source_port.setCurrentIndex(self.panel.source_port.findData("process"))
        self.panel.target_port.setCurrentIndex(self.panel.target_port.findData("process"))
        self.panel.connect_button.setFocus()
        QTest.keyClick(self.panel.connect_button, Qt.Key.Key_Space)
        self.wait_idle()
        self.assertEqual(len(self.panel.document["edges"]), 1)
        decoder = self.add("decode_trace")
        self.panel.target_node.setCurrentIndex(self.panel.target_node.findData(decoder["node_id"]))
        self.panel.target_port.setCurrentIndex(self.panel.target_port.findData("trace"))
        QTest.keyClick(self.panel.connect_button, Qt.Key.Key_Space)
        self.wait_idle()
        self.assertEqual(len(self.panel.document["edges"]), 1)
        self.assertIn("INCOMPATIBLE_PORT_TYPES", self.panel.status.text())
        self.assertFalse(self.window.probe.active)

    def test_cancel_paused_run_is_a_worker_cleanup_action_and_never_resumes_tools(self):
        self.add("CHECKPOINT")
        self.panel.start_button.click()
        self.wait_idle()
        self.assertEqual(self.panel.snapshot["state"], "WAITING_FOR_HUMAN")
        prior = self.panel.snapshot["run_id"]
        self.assertIsNotNone(self.panel.bridge._paused_run)
        self.assertTrue(self.panel.cancel_button.isEnabled())
        self.panel.cancel_button.click()
        self.wait_idle()
        self.assertEqual(self.panel.snapshot["run_id"], prior)
        self.assertEqual(self.panel.snapshot["state"], "CANCELLED")
        self.assertIsNone(self.panel.bridge._paused_run)
        self.assertFalse(self.window.deep_inspector_panel.bridge.has_session)

    def test_timed_out_native_packet_retains_late_actual_owner_reference(self):
        bridge = self.panel.bridge
        deep = self.window.deep_inspector_panel.bridge
        deep.target = (234, 1000.)
        target = ProcessIdentity(234, 116444746000000000, "owned.exe").to_dict()
        runtime = SimpleNamespace(owned_session_run_id=None)
        context = SimpleNamespace(run_id="late-run", cancel=threading.Event(), runtime=runtime)
        packet = {"request_id": "attempt", "event": threading.Event(), "context": context,
            "tag": "chain:late-run:node:attempt", "operation": "memory.write", "target": target,
            "generation": deep.generation, "expires": time.monotonic() - 1}
        bridge._requests[packet["request_id"]] = packet
        bridge._native = packet
        bridge._expire_requests()
        self.assertTrue(packet["event"].is_set())
        self.assertIs(bridge._native, packet)
        actual = {"owner_run_id": "late-run", "context_id": "real-returned-opaque-reference"}
        bridge._native_result({"request_kind": "action", "request_tag": packet["tag"],
            "status": "COMPLETED", "native_context_ownership": actual})
        self.assertEqual(bridge._native_contexts["late-run"], actual)
        self.assertEqual(runtime.owned_session_run_id, "late-run")
        self.assertIsNone(bridge._native)
        # This is an injected receipt boundary test, not proof of native cleanup.
        bridge._native_contexts.clear()
        bridge._owned_session_run_id = None

    def test_nested_policy_and_runtime_memory_payload_are_separate_typed_forms(self):
        node = self.add("observe")
        editor = self.panel._fields["policy"]
        self.assertIsInstance(editor, ObjectParameterEditor)
        enabled, profile = editor.fields["profile"]
        enabled.setChecked(True)
        profile.setCurrentIndex(profile.findData("INCIDENT_BURST"))
        self.panel.apply_button.click()
        self.assertEqual(node["parameters"]["policy"], {"profile": "INCIDENT_BURST"})
        memory = self.add("deep.memory.write")
        self.panel.apply_button.click()
        self.assertEqual(memory["parameters"]["parameters"], {})
        serialized = str(self.panel.document)
        self.assertNotIn("expected_hex", serialized)
        self.assertNotIn("value_hex", serialized)
        self.assertNotIn("confirmed", serialized)

    def test_save_open_profile_and_definition_remain_passive(self):
        self.add("process_select")
        saved = Path(self.temp.name) / "chain.bbchain.json"
        self.assertTrue(self.panel.bridge.submit("save", definition=self.panel.document, path=str(saved)))
        self.wait_idle()
        self.assertTrue(saved.is_file())
        old = deepcopy(self.panel.document)
        self.panel.bridge.submit("open", path=str(saved))
        self.wait_idle()
        self.assertEqual(self.panel.document, old)
        self.assertFalse(self.window.probe.active)
        self.assertFalse(any(op in ("start", "resume") for op, _, _ in self.results))
        # Existing source file is never overwritten by a second save.
        original = saved.read_bytes()
        self.panel.bridge.submit("save", definition=self.panel.document, path=str(saved))
        self.wait_idle()
        self.assertEqual(saved.read_bytes(), original)
        self.assertTrue(self.results[-1][2])

    def test_delete_and_edit_do_not_destroy_past_run_snapshot(self):
        node = self.add("process_select")
        snapshot = {"run_id": "past", "state": "PARTIAL", "nodes": [{"node_id": node["node_id"],
            "state": "COMPLETED", "run_receipt": {"run_id": "real-recorded-id"}, "cleanup": {"confirmed": False}}]}
        self.panel._snapshot(deepcopy(snapshot))
        self.panel.delete_nodes([node["node_id"]], [])
        self.assertEqual(self.panel.snapshot, snapshot)
        self.assertEqual(self.panel.document["nodes"], [])

    def test_typed_numeric_and_or_conditions_survive_language_change(self):
        node = self.add("CONDITION")
        editor = self.panel._fields["condition"]
        self.assertIsInstance(editor, ConditionParameterEditor)
        row = editor.rows[0]
        row["field"].setCurrentText("coverage.row_count")
        row["operator"].setCurrentIndex(row["operator"].findData("GE"))
        row["type"].setCurrentIndex(row["type"].findData("integer"))
        row["raw"].setText("10")
        editor.add_button.click()
        editor.combination.setCurrentIndex(editor.combination.findData("all"))
        expected = {"all": [{"field": "coverage.row_count", "op": "GE", "value": 10},
                             {"field": "status", "op": "EQ", "value": "COMPLETED"}]}
        self.assertEqual(editor.value(), expected)
        self.window._set_language("RU")
        self.assertEqual(self.panel._fields["condition"].value(), expected)
        self.panel.apply_button.click()
        self.assertEqual(node["parameters"], {"condition": expected})
        editor = self.panel._fields["condition"]
        editor.combination.setCurrentIndex(editor.combination.findData("any"))
        self.panel.apply_button.click()
        self.assertEqual(node["parameters"]["condition"], {"any": expected["all"]})

    def test_partial_evidence_requires_explicit_node_opt_in(self):
        node = self.add("investigate")
        self.assertFalse(node["allow_partial_inputs"])
        checkbox = self.panel._fields["_allow_partial"]
        checkbox.click()
        self.panel.apply_button.click()
        self.assertTrue(node["allow_partial_inputs"])
        self.window._set_language("RU")
        self.assertTrue(self.panel._fields["_allow_partial"].isChecked())
        self.assertIn("частич", self.panel._fields["_allow_partial"].toolTip())

    def test_loaded_thirty_two_flat_predicates_edit_without_losing_hidden_children(self):
        node = self.add("CONDITION")
        condition = {"all": [{"field": "coverage.row_count", "op": "GE", "value": index}
                              for index in range(32)]}
        node["parameters"] = {"condition": deepcopy(condition)}
        self.panel.select_node(node["node_id"])
        editor = self.panel._fields["condition"]
        self.assertFalse(editor.read_only)
        self.assertEqual(len(editor.rows), 32)
        editor.rows[0]["raw"].setText("-1")
        editor.rows[-1]["raw"].setText("64")
        editor.add_button.click()
        self.assertEqual(len(editor.rows), 32)
        condition["all"][0]["value"] = -1
        condition["all"][-1]["value"] = 64
        self.assertEqual(editor.value(), condition)
        self.window._set_language("RU")
        self.assertEqual(self.panel._fields["condition"].value(), condition)
        self.panel.apply_button.click()
        self.assertEqual(node["parameters"], {"condition": condition})

    def test_loaded_nested_predicate_is_explicitly_read_only_and_preserved_on_apply(self):
        node = self.add("CONDITION")
        condition = {"all": [{"status": "COMPLETED"},
                              {"any": [{"has_evidence": True}, {"sufficient": False},
                                       {"field": "cleanup.confirmed", "op": "EQ", "value": True}]}]}
        node["parameters"] = {"condition": deepcopy(condition)}
        self.panel.select_node(node["node_id"])
        editor = self.panel._fields["condition"]
        self.assertTrue(editor.read_only)
        self.assertFalse(editor.combination.isEnabled())
        self.assertFalse(editor.add_button.isEnabled())
        self.assertTrue(editor.preview.isReadOnly())
        self.assertIn('"any"', editor.preview.toPlainText())
        self.assertIn("read-only", editor.note.text())
        editor.add_clause()
        editor.combination.setCurrentIndex(editor.combination.findData("single"))
        self.assertEqual(editor.rows, [])
        self.assertEqual(editor.value(), condition)
        changed_copy = editor.value()
        changed_copy["all"].clear()
        self.assertEqual(editor.value(), condition)
        self.panel._fields["_title"].setText("Preserved nested rule")
        self.panel.apply_button.click()
        self.assertEqual(node["title"], "Preserved nested rule")
        self.assertEqual(node["parameters"], {"condition": condition})
        self.window._set_language("RU")
        editor = self.panel._fields["condition"]
        self.assertTrue(editor.read_only)
        self.assertIn("только для просмотра", editor.note.text())
        self.panel.apply_button.click()
        self.assertEqual(node["parameters"], {"condition": condition})
        self.window._set_language("EN")
        self.assertEqual(self.panel._fields["condition"].value(), condition)

    def test_omitted_predicate_value_stays_null_when_another_clause_is_edited(self):
        node = self.add("CONDITION")
        node["parameters"] = {"condition": {"all": [{"field": "value.metric", "op": "EQ"},
                                                    {"status": "COMPLETED"}]}}
        self.panel.select_node(node["node_id"])
        editor = self.panel._fields["condition"]
        self.assertEqual(editor.rows[0]["type"].currentData(), "null")
        editor.rows[1]["raw"].setText("PARTIAL")
        self.panel.apply_button.click()
        self.assertEqual(node["parameters"]["condition"], {"all": [
            {"field": "value.metric", "op": "EQ", "value": None},
            {"field": "status", "op": "EQ", "value": "PARTIAL"}]})

    def test_applying_wait_options_preserves_missing_filter_instead_of_implicit_zero(self):
        node = self.add("waits")
        optional = self.panel._fields["end_ms"]
        self.assertIsInstance(optional, OptionalParameterEditor)
        self.assertFalse(optional.enabled.isChecked())
        self.panel._fields["_allow_partial"].click()
        self.panel.apply_button.click()
        for key in ("process_instance", "tid", "start_ms", "end_ms"):
            self.assertNotIn(key, node["parameters"])
        optional = self.panel._fields["end_ms"]
        optional.enabled.click()
        optional.field.setValue(0)
        self.panel.apply_button.click()
        self.assertEqual(node["parameters"]["end_ms"], 0)
        self.window._set_language("RU")
        self.assertTrue(self.panel._fields["end_ms"].enabled.isChecked())
        self.assertEqual(self.panel._fields["end_ms"].field.value(), 0)

    def test_derived_evidence_boolean_ne_is_preserved_and_range_operator_is_rejected(self):
        node = self.add("CONDITION")
        editor = self.panel._fields["condition"]
        row = editor.rows[0]
        row["field"].setCurrentText("has_evidence")
        row["type"].setCurrentIndex(row["type"].findData("boolean"))
        row["boolean"].setCurrentIndex(row["boolean"].findData(True))
        row["operator"].setCurrentIndex(row["operator"].findData("NE"))
        self.panel.apply_button.click()
        self.assertEqual(node["parameters"], {"condition": {"has_evidence": False}})
        row = self.panel._fields["condition"].rows[0]
        row["operator"].setCurrentIndex(row["operator"].findData("GT"))
        self.panel.apply_button.click()
        self.assertIn("BOOLEAN_EVIDENCE_CONDITION_REQUIRES_EQ_OR_NE", self.panel.status.text())
        self.assertEqual(node["parameters"], {"condition": {"has_evidence": False}})
        self.window._set_language("EN")
        self.assertIn("saved source", self.panel.source_ids.toolTip())
        self.window._set_language("RU")
        self.assertIn("сохранённого источника", self.panel.source_ids.toolTip())

    def test_maximum_graph_can_be_edited_and_validated_while_qt_pumps(self):
        example = self.add("process_select")
        self.panel.document["nodes"] = [dict(deepcopy(example), node_id="large_" + str(index),
            budget_seconds=.01, position=[index % 16 * 320, index // 16 * 160]) for index in range(256)]
        self.panel._render()
        self.assertEqual(len(self.panel.canvas.items_by_id), 256)
        self.panel.fit_graph()
        beats = []
        QTimer.singleShot(0, lambda: beats.append(self.panel.bridge.busy))
        self.panel.validate_button.click()
        self.wait_idle()
        self.assertTrue(beats)
        self.assertTrue(beats[0], "MAX_GRAPH_VALIDATION_DID_NOT_RUN_IN_WORKER")
        self.assertEqual(len(self.panel.document["nodes"]), 256)
        self.assertFalse(self.window.probe.active)
        self.panel.document["nodes"].append(dict(deepcopy(example), node_id="overflow"))
        self.panel.validate_button.click()
        self.wait_idle()
        self.assertTrue(self.results[-1][2])
        self.assertEqual("WORKFLOW_GRAPH_SIZE_BUDGET", self.results[-1][2])
        self.assertFalse(self.window.probe.active)

    def test_bulk_progress_queues_one_wake_and_terminal_result_cannot_be_replaced(self):
        # This is an actual Qt handoff test with explicit injected progress;
        # it makes no claim about native diagnostic invocation or cleanup.
        bridge = self.panel.bridge
        task = _ChainTask(bridge, "start", {})
        wakes, displayed = [], []
        task.progress_available.connect(lambda: wakes.append(True), Qt.ConnectionType.DirectConnection)
        task.progress_available.connect(bridge._progress_ready, Qt.ConnectionType.QueuedConnection)
        task.result_ready.connect(bridge._receive)
        bridge.snapshot_changed.connect(displayed.append)
        bridge.worker = task
        try:
            def publish():
                for sequence in range(512):
                    task.publish_snapshot({"run_id": "bulk-fixture", "state": "RUNNING", "sequence": sequence,
                        "nodes": [{"node_id": "large_" + str(index), "state": "COMPLETED"} for index in range(256)]})
            producer = threading.Thread(target=publish, name="explicit-qt-progress-fixture")
            producer.start()
            producer.join(timeout=3)
            self.assertFalse(producer.is_alive())
            self.assertEqual(len(wakes), 1)
            self.assertEqual(displayed, [])
            self.assertTrue(task._progress_wake_pending)
            self.assertEqual(task._latest_progress["sequence"], 511)
            self.app.processEvents()
            self.assertEqual(len(displayed), 1)
            self.assertEqual(self.panel.snapshot["sequence"], 511)
            self.assertFalse(task._progress_wake_pending)
            self.assertIsNone(task._latest_progress)
            task.publish_snapshot({"run_id": "bulk-fixture", "state": "RUNNING", "sequence": 512, "nodes": []})
            self.assertEqual(len(wakes), 2)
            task.close_progress()
            terminal = {"run_id": "bulk-fixture", "state": "COMPLETED", "nodes": [], "folder": self.temp.name}
            task.result_ready.emit("start", terminal, "")
            self.app.processEvents()
            self.assertEqual(displayed[-1], terminal)
            self.assertEqual(len(displayed), 2)
            task.publish_snapshot({"run_id": "bulk-fixture", "state": "RUNNING", "sequence": 513, "nodes": []})
            self.app.processEvents()
            self.assertEqual(len(wakes), 2)
            self.assertEqual(self.panel.snapshot["state"], "COMPLETED")
        finally:
            bridge.worker = None
            task.close_progress()
            from qt_test_support import dispose_closed_fixture
            dispose_closed_fixture(task, self.app)


class GuardBridge(QObject):
    result_ready = Signal(object)
    busy_changed = Signal(bool)
    target_changed = Signal()
    idle = Signal()
    closed = Signal(object)
    recovery_required = Signal(object)
    admin_status_changed = Signal(object)

    def __init__(self):
        super().__init__()
        self.target, self.generation = (234, 1000.), 1
        self.busy = self.admin_active = self.cleanup_required = False
        self.calls = []

    def submit(self, operation, parameters=None, **kwargs):
        self.calls.append((operation, parameters, kwargs))
        return True

    def capabilities(self):
        return True

    def set_target(self, pid, created):
        self.target, self.generation = (pid, created), self.generation + 1
        self.target_changed.emit()

    def authorize_target(self, operations, **kwargs):
        self.calls.append(("authorize_target", operations, kwargs))
        return True

    def elevate(self, operations, **kwargs):
        self.calls.append(("elevate", operations, kwargs))
        return True

    def end_admin(self):
        self.calls.append(("end_admin", {}, {}))
        return True

    def retry_cleanup(self):
        self.calls.append(("retry_cleanup", {}, {}))
        return True

    def export(self, destination):
        self.calls.append(("export", {"destination": destination}, {}))
        return True

    def shutdown(self):
        self.calls.append(("shutdown", {}, {}))
        self.closed.emit({"status": "COMPLETED", "data": {"cleanup": "NO_SESSION"}})

    def cancel(self):
        pass


class RuntimeExecutionGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.parent = QWidget()
        self.parent.language = "EN"
        self.bridge = GuardBridge()
        self.panel = OverviewInspectorPanel(self.parent, bridge=self.bridge)
        self.live = True

    def tearDown(self):
        from qt_test_support import dispose_closed_fixture
        self.panel.investigation_graph_panel.shutdown()
        self.assertFalse(self.panel.investigation_graph_panel.bridge.busy)
        self.parent.close()
        dispose_closed_fixture(self.parent, self.app)
        self.bridge.shutdown()
        dispose_closed_fixture(self.bridge, self.app)

    def test_cancellation_inside_action_consent_modal_prevents_native_submit(self):
        def confirm(*_):
            self.live = False
            return True
        with patch.object(self.panel, "_confirm", side_effect=confirm):
            accepted = self.panel.request_investigation_action("memory.write", {}, tag="chain:attempt",
                execution_guard=lambda: self.live)
        self.assertFalse(accepted)
        self.assertEqual(self.bridge.calls, [])

    def test_cancelled_guard_after_uac_prevents_late_idle_retry(self):
        with patch.object(self.panel, "_confirm", return_value=True):
            self.assertTrue(self.panel.request_investigation_action("memory.write", {}, tag="chain:attempt",
                execution_guard=lambda: self.live))
        self.panel._pending_retry = dict(self.panel._last_request)
        self.panel._last_result = {"request_kind": "elevate", "status": "COMPLETED", "data": {}}
        self.live = False
        self.panel._idle()
        self.assertEqual(len(self.bridge.calls), 1)
        self.assertIsNone(self.panel._pending_retry)
        self.assertIsNone(self.panel._last_request)

    def test_generation_change_inside_modal_still_refuses_even_with_true_guard(self):
        def confirm(*_):
            self.bridge.set_target(235, 2000.)
            return True
        with patch.object(self.panel, "_confirm", side_effect=confirm):
            accepted = self.panel.request_investigation_action("memory.write", {}, execution_guard=lambda: True)
        self.assertFalse(accepted)
        self.assertEqual(self.bridge.calls, [])

    def test_legacy_action_and_legacy_uac_retry_without_guard_keep_original_behavior(self):
        with patch.object(self.panel, "_confirm", return_value=True):
            self.assertTrue(self.panel._request("memory.write", {}, tag="legacy"))
        self.panel._pending_retry = dict(self.panel._last_request)
        self.panel._last_result = {"request_kind": "elevate", "status": "COMPLETED", "data": {}}
        self.panel._idle()
        self.assertEqual(len(self.bridge.calls), 2)
        self.assertEqual(self.bridge.calls[-1][2]["tag"], "legacy")

    def test_guard_exceptions_and_non_boolean_truthy_values_fail_closed(self):
        for guard in (lambda: 1, lambda: (_ for _ in ()).throw(RuntimeError("guard failed"))):
            with patch.object(self.panel, "_confirm", return_value=True):
                self.assertFalse(self.panel.request_investigation_action("memory.write", {}, execution_guard=guard))
        self.assertEqual(self.bridge.calls, [])

    def test_exact_native_filetime_is_forwarded_beyond_float_ui_selection(self):
        identity = {"pid": 234, "created_100ns": 116444746000000001, "image_path": "owned.exe"}
        with patch.object(self.panel, "_confirm", return_value=True):
            self.assertTrue(self.panel.request_investigation_action("memory.write", {},
                native_owner_run_id="run-exact", expected_target=identity, execution_guard=lambda: True))
        self.assertEqual(self.bridge.calls[-1][2]["expected_target"], identity)


class NativeOwnerReceiptBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_one_filetime_tick_difference_blocks_owned_action_before_service_call(self):
        service = SimpleNamespace(execute_owned=lambda *_a, **_k: self.fail("EXECUTED_WRONG_INSTANCE"))
        target = ProcessIdentity(234, 116444746000000001, "owned.exe")
        command = {"native_owner_run_id": "run-exact", "expected_target": {
            "pid": 234, "created_100ns": target.created_100ns - 1}, "parameters": {}}
        task = _DeepTask(None, command, service, target, lambda: service)
        with self.assertRaisesRegex(ProcessLookupError, "WORKFLOW_EXACT_PROCESS_IDENTITY_CHANGED"):
            task._owned(command, "action", "memory.write")
        from qt_test_support import dispose_closed_fixture
        dispose_closed_fixture(task, self.app)

    def test_stale_ui_generation_still_delivers_owner_receipt_without_legacy_result(self):
        bridge = DeepInspectorBridge(service_factory=lambda: None)
        bridge._status_timer.stop()
        bridge.generation = 8
        owner, legacy = [], []
        bridge.owned_result_ready.connect(owner.append)
        bridge.result_ready.connect(legacy.append)
        result = {"generation": 7, "native_owner_run_id": "prior-run", "request_kind": "action",
                  "request_tag": "chain:prior-run:attempt", "status": "COMPLETED",
                  "native_context_ownership": {"owner_run_id": "prior-run", "context_id": "actual-ref"}}
        bridge._receive(result)
        self.assertEqual(owner, [result])
        self.assertEqual(legacy, [])
        from qt_test_support import dispose_closed_fixture
        dispose_closed_fixture(bridge, self.app)
