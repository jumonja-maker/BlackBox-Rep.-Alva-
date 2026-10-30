"""Hosted Qt contracts for BB-INV-003 (synthetic GUI fixtures only).

These doubles verify navigation, consent delegation and stale-result handling;
they do not stand in for the separate actual Windows acceptance evidence.
"""
from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import QApplication, QMessageBox, QWidget

from blackbox_core.investigation_graph_contracts import SCHEMA
from blackbox_universal.investigation_graph_bridge import InvestigationGraphBridge
from blackbox_universal.investigation_graph_panel import InvestigationGraphPanel


TARGET = {"pid": 234, "created_100ns": 133000000000000000, "image_path": "SYNTHETIC_GUI.exe"}


def fixture_case(count=3):
    kinds = ("INCIDENT", "THREAD", "STACK")
    nodes = [{"node_id": "n" + str(i), "observation_type": kinds[i % 3],
              "source_record_id": "SYNTHETIC_GUI:" + str(i), "source_identity": "source-a",
              "source_type": "DEEP_JOURNAL", "time_domain": "UNKNOWN",
              "completeness_status": "INCOMPLETE_EVIDENCE", "metadata": {}}
             for i in range(count)]
    return {"schema": SCHEMA, "case_id": "synthetic-gui-case", "algorithm_version": "3.0.0",
            "target_identity": None, "nodes": nodes, "edges": [], "sources": [], "coverage": {},
            "limitations": ["SYNTHETIC_GUI_CONTRACT_ONLY"], "hypotheses": [{
                "hypothesis_id": "h1", "category": "UI_UNRESPONSIVE", "status": "INCONCLUSIVE",
                "description": "Unknown cause", "description_ru": "Причина неизвестна"}],
            "actions": [{"operation": "memory.write", "availability": "NOT_ESTABLISHED", "parameters": {}}]}


class NativeBridgeDouble(QObject):
    result_ready = Signal(object)
    busy_changed = Signal(bool)
    target_changed = Signal()

    def __init__(self):
        super().__init__()
        self.generation, self.target, self.busy = 1, (234, 1000.0), False
        self.cancel = Mock()


class DeepPanelDouble(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.bridge, self.calls = NativeBridgeDouble(), []
        self.elevation_calls = 0

    def request_investigation_elevation(self):
        self.elevation_calls += 1

    def request_investigation_action(self, operation, parameters=None, *, tag=""):
        self.calls.append((operation, deepcopy(parameters or {}), tag))
        return True


class ReaderDouble(QObject):
    result_ready = Signal(str, object, str, int)
    busy_changed = Signal(bool)
    closed = Signal()

    def __init__(self):
        super().__init__()
        self.busy, self.generation, self.calls = False, 0, []

    def submit(self, operation, **arguments):
        if self.busy:
            return False
        self.calls.append((operation, deepcopy(arguments)))
        return True

    def cancel(self):
        pass

    def invalidate(self):
        self.generation += 1

    def shutdown(self):
        self.closed.emit()


class InvestigationGuiContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.window = QWidget()
        self.window.language = "EN"
        self.window._investigation_root = Path(self.tmp.name)
        self.window.probe = SimpleNamespace(session_folder=None)
        self.deep, self.reader = DeepPanelDouble(self.window), ReaderDouble()
        self.panel = InvestigationGraphPanel(self.window, self.deep, bridge=self.reader)

    def tearDown(self):
        self.panel.shutdown()
        self.window.close()
        self.window.deleteLater()
        self.app.processEvents()
        self.tmp.cleanup()

    def bind_fixture(self):
        self.panel.load_case(fixture_case())
        self.panel.experiment_case = deepcopy(self.panel.case)
        self.panel.experiment_case.update(case_id="synthetic-gui-experiment", target_identity=deepcopy(TARGET))
        self.panel._live_identity = deepcopy(TARGET)
        self.panel._live_token = (self.deep.bridge.generation, self.deep.bridge.target)
        self.panel._controls()

    def result(self, phase, *, status="COMPLETED", data=None):
        pending = self.panel._pending_native
        self.assertEqual(pending["phase"], phase)
        operation = self.deep.calls[-1][0]
        self.deep.bridge.result_ready.emit({"request_tag": pending["tag"], "operation": operation,
            "operation_id": "synthetic-operation-" + phase, "status": status, "target": deepcopy(TARGET),
            "data": data or {}})

    def test_open_has_seven_local_sections_and_never_starts_helper_or_reader(self):
        self.panel.open_case_context([], incident_id=9)
        self.assertEqual(self.panel.section.count(), 7)
        self.assertEqual(self.panel.pages.count(), 7)
        for i in range(7):
            self.panel.section.setCurrentIndex(i)
            self.assertEqual(self.panel.pages.currentIndex(), i)
        self.assertEqual(self.reader.calls, [])
        self.assertEqual(self.deep.calls, [])

    def test_primary_pages_remain_six_and_legacy_five(self):
        from blackbox_universal.decoder_window import DecoderWindow
        from blackbox_universal.window import UniversalWindow
        self.assertEqual(len(UniversalWindow.PAGES), 5)
        self.assertEqual(len(DecoderWindow.PAGES), 6)
        self.assertEqual(DecoderWindow.PAGES[-1][0], "decoder")

    def test_empty_saved_source_does_not_guess_live_target(self):
        self.assertFalse(self.panel.build_case())
        self.assertEqual(self.reader.calls, [])
        self.assertEqual(self.deep.calls, [])

    def test_sources_are_built_in_worker_with_private_destination(self):
        descriptor = {"source_type": "SESSION", "path": "/SYNTHETIC/saved-session"}
        self.panel.open_case_context([descriptor], selection={"start_ns": 10, "end_ns": 20})
        self.assertTrue(self.panel.build_case())
        operation, arguments = self.reader.calls[-1]
        self.assertEqual(operation, "build")
        self.assertEqual(arguments["sources"], [descriptor])
        self.assertIsNone(arguments["target_identity"])
        self.assertEqual(Path(arguments["index_path"]).parent, Path(self.tmp.name))
        self.assertEqual(list(Path(self.tmp.name).iterdir()), [])

    def test_models_virtualize_and_graph_draws_only_bounded_neighborhood(self):
        self.panel.load_case(fixture_case(10000))
        self.assertEqual(self.panel.nodes_model.rowCount(), 100)
        self.assertEqual(len(self.panel.graph.rendered_node_ids), 80)
        self.assertTrue(self.panel.select_node("n9999"))
        self.assertEqual(self.panel.nodes_model.offset, 9900)
        self.assertEqual(self.panel.node_table.selectionModel().selectedRows()[0].row(), 99)
        self.assertIn("n9999", self.panel.graph.rendered_node_ids)
        self.assertLessEqual(len(self.panel.graph.rendered_node_ids), 80)

    def test_temporal_coincidence_does_not_create_thread_or_stack_navigation(self):
        case = fixture_case()
        case["edges"] = [{"from_node": "n0", "to_node": "n1", "relation_type": "TEMPORAL_COINCIDENCE"},
                         {"from_node": "n1", "to_node": "n2", "relation_type": "DIRECT_REFERENCE", "relation": "THREAD_STACK"}]
        self.panel.load_case(case)
        self.panel.select_node("n0")
        self.panel.show_thread()
        self.assertEqual(self.panel._selected_node_id, "n0")
        self.assertIn("NOT_ESTABLISHED", self.panel.status.text())
        case["edges"][0]["relation_type"] = "DIRECT_REFERENCE"
        case["edges"][0]["relation"] = "THREAD_REFERENCE"
        self.panel.show_thread()
        self.assertEqual(self.panel._selected_node_id, "n1")
        self.panel.show_stack()
        self.assertEqual(self.panel._selected_node_id, "n2")

    def test_ru_en_retranslate_preserves_explicit_input_and_plain_text(self):
        case = fixture_case()
        case["limitations"] = ["<img src='secret' onerror='execute'>"]
        self.panel.load_case(case)
        self.panel.parameters.setPlainText('{"address":4096,"expected_hex":"01","value_hex":"02"}')
        explicit = self.panel.parameters.toPlainText()
        english = self.panel.before_button.text()
        self.window.language = "RU"
        self.panel.retranslate()
        self.assertNotEqual(self.panel.before_button.text(), english)
        model = self.panel._models["hypotheses"]
        self.assertEqual(model.data(model.index(0, 1)), "Причина неизвестна")
        self.assertEqual(self.panel.parameters.toPlainText(), explicit)
        self.assertEqual(self.panel.overview.textFormat(), Qt.TextFormat.PlainText)
        self.assertIn("<img", self.panel.overview.text())
        self.window.language = "EN"
        self.panel.retranslate()
        self.assertEqual(self.panel.before_button.text(), english)

    def test_stack_to_module_and_symbol_use_only_recorded_reference_links(self):
        case = fixture_case(5)
        case["nodes"][3]["observation_type"] = "MODULE"
        case["nodes"][4]["observation_type"] = "FUNCTION"
        case["edges"] = [{"from_node": "n2", "to_node": "n3", "relation_type": "DIRECT_REFERENCE", "relation": "MODULE_REFERENCE"},
                         {"from_node": "n4", "to_node": "n3", "relation_type": "DIRECT_REFERENCE", "relation": "FUNCTION_MODULE"}]
        self.panel.load_case(case)
        self.panel.select_node("n2")
        self.panel.show_module()
        self.assertEqual(self.panel._selected_node_id, "n3")
        self.panel.show_module()
        self.assertEqual(self.panel._selected_node_id, "n4")

    def test_same_process_other_thread_stack_and_module_never_supply_selected_thread(self):
        case = fixture_case(6)
        for row, kind in zip(case["nodes"], ("PROCESS", "THREAD", "THREAD", "STACK", "MODULE", "FUNCTION")):
            row["observation_type"] = kind
        case["edges"] = [
            {"from_node": "n0", "to_node": "n1", "relation_type": "EXACT_IDENTITY", "relation": "PROCESS_EVIDENCE"},
            {"from_node": "n0", "to_node": "n2", "relation_type": "EXACT_IDENTITY", "relation": "PROCESS_EVIDENCE"},
            {"from_node": "n2", "to_node": "n3", "relation_type": "DIRECT_REFERENCE", "relation": "STACK_REFERENCE"},
            {"from_node": "n3", "to_node": "n5", "relation_type": "DIRECT_REFERENCE", "relation": "THREAD_STACK"},
            {"from_node": "n5", "to_node": "n4", "relation_type": "DIRECT_REFERENCE", "relation": "FUNCTION_MODULE"}]
        self.panel.load_case(case)
        self.panel.select_node("n1")
        self.panel.show_stack()
        self.assertEqual(self.panel._selected_node_id, "n1")
        self.panel.show_module()
        self.assertEqual(self.panel._selected_node_id, "n1")
        self.assertIn("NOT_ESTABLISHED", self.panel.status.text())
        self.panel.select_node("n2")
        self.panel.show_stack()
        self.assertEqual(self.panel._selected_node_id, "n3")
        self.panel.show_module()
        self.assertEqual(self.panel._selected_node_id, "n4")

    def test_same_thread_other_snapshot_does_not_replace_missing_observation_stack(self):
        case = fixture_case()
        case["nodes"][0]["observation_type"] = "THREAD"
        case["edges"] = [
            {"from_node": "n0", "to_node": "n1", "relation_type": "EXACT_IDENTITY", "relation": "THREAD_EVIDENCE"},
            {"from_node": "n1", "to_node": "n2", "relation_type": "DIRECT_REFERENCE", "relation": "THREAD_STACK"}]
        self.panel.load_case(case)
        self.panel.select_node("n0")
        self.panel.show_stack()
        self.assertEqual(self.panel._selected_node_id, "n0")

    def test_aligned_trace_navigation_uses_index_digest_not_composite_source_manifest(self):
        case = fixture_case(1)
        node = case["nodes"][0]
        node.update(source_type="TRACE_INDEX", time_bounds={"start": 10, "end": 20, "unit": "ms"},
                    process_identity={"pid": 234, "process_instance": 17}, thread_identity={"tid": 8})
        case["sources"] = [{"source_id": "source-a", "source_type": "TRACE_INDEX", "source_file_count": 3,
            "index_sha256": "a" * 64, "source_sha256": "b" * 64, "trace_sha256": "c" * 64}]
        case["_source_paths"] = {"source-a": "/SYNTHETIC/aligned-index.sqlite3"}
        self.window.decoder_panel = SimpleNamespace(open_index_interval=Mock(return_value=True))
        self.window._navigate = Mock()
        self.panel.load_case(case)
        self.panel.select_node("n0")
        self.assertTrue(self.panel.open_trace_interval())
        arguments = self.window.decoder_panel.open_index_interval.call_args.kwargs
        self.assertEqual(arguments["expected_index_sha256"], "a" * 64)
        self.assertEqual(arguments["expected_trace_sha256"], "c" * 64)
        self.assertEqual(arguments["process_instance"], 17)
        del case["sources"][0]["index_sha256"]
        self.window.decoder_panel.open_index_interval.reset_mock()
        self.assertFalse(self.panel.open_trace_interval())
        self.window.decoder_panel.open_index_interval.assert_not_called()

    def test_minidump_source_picker_requests_real_minidump_bytes_not_json(self):
        with patch("blackbox_universal.investigation_graph_panel.QInputDialog.getItem",
                   return_value=("Saved minidump (metadata only)", True)), \
                patch("blackbox_universal.investigation_graph_panel.QFileDialog.getOpenFileName",
                      return_value=("SYNTHETIC.dmp", "")) as picker:
            self.panel.choose_source()
        self.assertIn("*.dmp", picker.call_args.args[3])
        self.assertNotIn("*.json", picker.call_args.args[3])
        self.assertEqual(self.panel.sources[0]["source_type"], "DUMP_METADATA")

    def test_manual_merge_requires_reason_without_invalid_empty_split_list(self):
        self.panel.load_case(fixture_case())
        self.panel._grouping = {"groups": []}
        with patch("blackbox_universal.investigation_graph_panel.QInputDialog.getText",
                   side_effect=[("group-a,group-b", True), ("Explicit user explanation", True)]):
            self.panel.manual_group("MERGE")
        operation, arguments = self.reader.calls[-1]
        self.assertEqual(operation, "group_change")
        self.assertIsNone(arguments["case_ids"])
        self.assertEqual(arguments["reason"], "Explicit user explanation")

    def test_cancel_live_binding_never_dispatches_or_binds_by_pid(self):
        self.panel.load_case(fixture_case())
        with patch.object(QMessageBox, "exec", return_value=QMessageBox.StandardButton.Cancel):
            self.assertFalse(self.panel.bind_live_target())
        self.assertIsNone(self.panel._live_identity)
        self.assertEqual(self.deep.calls, [])

    def test_target_change_inside_confirmation_invalidates_consent(self):
        self.panel.load_case(fixture_case())
        def change_target():
            self.deep.bridge.generation += 1
            self.deep.bridge.target = (999, 2000.0)
            return QMessageBox.StandardButton.Yes
        with patch.object(QMessageBox, "exec", side_effect=change_target):
            self.assertFalse(self.panel.bind_live_target())
        self.assertEqual(self.deep.calls, [])

    def test_confirmed_binding_requires_native_creation_time_then_new_case_fork(self):
        self.panel.load_case(fixture_case())
        with patch.object(QMessageBox, "exec", return_value=QMessageBox.StandardButton.Yes):
            self.assertTrue(self.panel.bind_live_target())
        self.assertEqual(self.deep.calls[-1][0], "capabilities")
        self.assertIsNone(self.panel._live_identity)
        self.result("bind", data={"operations": []})
        self.assertEqual(self.panel._live_identity, TARGET)
        operation, arguments = self.reader.calls[-1]
        self.assertEqual(operation, "fork")
        self.assertEqual(arguments["target_identity"], TARGET)
        self.assertIsNone(self.panel.case["target_identity"])

    def test_before_action_after_compare_are_separate_manual_native_requests(self):
        self.bind_fixture()
        self.assertTrue(self.panel.capture_before())
        self.assertEqual([c[0] for c in self.deep.calls], ["snapshot"])
        self.result("before", data={"snapshot_id": "snapshot-before"})
        self.assertEqual(len(self.deep.calls), 1)
        explicit = {"address": 4096, "expected_hex": "01", "value_hex": "02"}
        import json
        self.panel.parameters.setPlainText(json.dumps(explicit))
        self.assertTrue(self.panel.run_action())
        self.assertEqual(self.deep.calls[-1][:2], ("memory.write", explicit))
        self.result("action", data={"change_id": "synthetic-change", "readback_verified": True})
        self.assertEqual(len(self.deep.calls), 2)
        self.assertFalse(self.panel.run_action())
        self.assertTrue(self.panel.capture_after())
        self.result("after", data={"snapshot_id": "snapshot-after"})
        self.assertFalse(self.panel.capture_after())
        self.assertTrue(self.panel.compare_measurements())
        self.assertEqual(self.deep.calls[-1][1], {"before_id": "snapshot-before", "after_id": "snapshot-after"})
        self.result("compare", data={"before_id": "snapshot-before", "after_id": "snapshot-after", "changed_sections": ["memory"]})
        self.assertFalse(self.panel.compare_measurements())
        self.assertEqual(self.panel._experiment["status"], "INCONCLUSIVE")
        self.assertFalse(self.panel._experiment["root_cause_proven"])
        self.assertEqual([c[0] for c in self.deep.calls], ["snapshot", "memory.write", "snapshot", "compare"])
        self.assertEqual([c[1]["record"]["phase"] for c in self.reader.calls if c[0] == "record_experiment"],
                         ["BEFORE", "ACTION", "AFTER", "COMPARE"])

    def test_failed_before_retry_starts_new_experiment_and_recovery_blocks_retry(self):
        self.bind_fixture()
        self.panel.capture_before()
        previous = self.panel._experiment["experiment_id"]
        self.result("before", status="CANCELLED")
        self.assertTrue(self.panel.capture_before())
        self.assertNotEqual(self.panel._experiment["experiment_id"], previous)
        self.result("before", status="RECOVERY_UNCONFIRMED")
        self.assertFalse(self.panel.capture_before())
        self.assertFalse(self.panel.before_button.isEnabled())

    def test_stale_native_result_cannot_apply_to_new_target_or_replace_history(self):
        self.bind_fixture()
        self.panel._capabilities = {"operations": [{"operation": "memory.write", "status": "AVAILABLE"}]}
        historical = self.panel.case
        self.panel.capture_before()
        old_tag = self.panel._pending_native["tag"]
        self.deep.bridge.generation += 1
        self.deep.bridge.target = (999, 2000.0)
        self.deep.bridge.target_changed.emit()
        self.deep.bridge.result_ready.emit({"request_tag": old_tag, "operation": "snapshot", "status": "COMPLETED",
            "target": TARGET, "data": {"snapshot_id": "must-not-apply"}})
        self.assertIs(self.panel.case, historical)
        self.assertIsNone(self.panel._experiment)
        self.assertIsNone(self.panel._live_identity)
        self.assertIsNone(self.panel._pending_native)
        self.assertIsNone(self.panel._capabilities)
        self.assertEqual(self.reader.calls, [])

    def test_uac_is_explicit_and_uses_existing_deep_elevation_path(self):
        self.bind_fixture()
        self.panel.capture_before()
        self.result("before", status="ADMIN_REQUIRED")
        self.assertTrue(self.panel.uac_button.isEnabled())
        self.assertEqual(len(self.deep.calls), 1)
        self.panel.uac_button.click()
        self.assertEqual(self.deep.elevation_calls, 1)
        self.deep.bridge.result_ready.emit({"request_kind": "elevate", "status": "UAC_CANCELLED"})
        self.assertIsNone(self.panel._pending_native)
        self.assertIsNotNone(self.panel.case)
        self.assertEqual(len(self.deep.calls), 1)

    def test_export_uses_new_experiment_case_with_original_provenance(self):
        self.bind_fixture()
        self.panel.experiment_case["origin_case_id"] = self.panel.case["case_id"]
        self.assertTrue(self.panel.export_to(Path(self.tmp.name) / "handoff.html", format="html"))
        operation, arguments = self.reader.calls[-1]
        self.assertEqual(operation, "export")
        self.assertEqual(arguments["format"], "html")
        self.assertEqual(arguments["case"]["origin_case_id"], self.panel.case["case_id"])
        self.assertEqual(self.deep.calls, [])

    def test_read_cancel_for_close_preserves_export_when_native_cleanup_keeps_window(self):
        self.panel.load_case(fixture_case())
        closed = []
        self.panel.closed.connect(lambda: closed.append(True))
        self.reader.busy = True
        self.panel.cancel_for_window_close()
        self.assertEqual(closed, [])
        self.reader.busy = False
        self.reader.busy_changed.emit(False)
        self.assertEqual(closed, [True])
        self.assertFalse(self.panel._closing)
        self.assertTrue(self.panel.export_to(Path(self.tmp.name) / "retained.json"))


class InvestigationReaderLifecycleContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def wait_until(self, predicate):
        deadline = time.monotonic() + 5
        while not predicate() and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(0.005)
        self.assertTrue(predicate(), "bounded GUI worker did not finish")

    def test_invalidated_worker_payload_is_discarded_and_cancellation_is_seen(self):
        entered, release, cancelled = threading.Event(), threading.Event(), threading.Event()
        def load(path, *, budget):
            entered.set()
            release.wait(3)
            if budget.cancel_event.is_set():
                cancelled.set()
            budget.check()
            return fixture_case()
        owner = InvestigationGraphBridge(api=SimpleNamespace(load_investigation=load))
        answers = []
        owner.result_ready.connect(lambda *packet: answers.append(packet))
        self.assertTrue(owner.submit("open", path="SYNTHETIC_GUI_INDEX"))
        self.assertTrue(entered.wait(3))
        self.assertFalse(owner.submit("open", path="second"))
        owner.invalidate()
        release.set()
        self.wait_until(lambda: not owner.busy)
        self.assertTrue(cancelled.is_set())
        self.assertEqual(answers, [])
        owner.shutdown()

    def test_manual_action_catalog_includes_real_contract_write_without_hypothesis_edit(self):
        case = fixture_case()
        original = deepcopy(case["hypotheses"])
        owner = InvestigationGraphBridge(api=SimpleNamespace(suggest_diagnostic_actions=lambda *a, **kw: []))
        answers = []
        owner.result_ready.connect(lambda *packet: answers.append(packet))
        self.assertTrue(owner.submit("actions", case=case, capabilities={"operations": [
            {"operation": "memory.write", "status": "AVAILABLE"}]}, target_identity=TARGET))
        self.wait_until(lambda: not owner.busy)
        self.assertEqual(answers[0][2], "")
        actions = answers[0][1]["actions"]
        write = next(row for row in actions if row["operation"] == "memory.write")
        self.assertEqual(write["availability"], "AVAILABLE")
        self.assertTrue(write["confirmation_required"])
        self.assertIn("expected_hex", write["required_parameters"])
        self.assertEqual(write["selection_basis"], "EXPLICIT_MANUAL_TOOL_NOT_HYPOTHESIS_RECOMMENDATION")
        self.assertEqual(case["hypotheses"], original)
        owner.shutdown()
