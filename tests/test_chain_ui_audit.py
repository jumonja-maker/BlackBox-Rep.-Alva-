"""Real Qt graph state regressions with explicit process-free controller DTOs."""
from copy import deepcopy
import os
from pathlib import Path
import sys
import tempfile
import traceback
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QObject, Qt, Signal, QMimeData, QPointF
from PySide6.QtGui import QDropEvent
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QVBoxLayout, QWidget

from blackbox_universal.chain_builder import ChainBuilderPanel, ChainHistoryPanel, MIME
from qt_test_support import dispose_closed_fixture


class PassiveChainBridge(QObject):
    result_ready = Signal(str, object, str)
    snapshot_changed = Signal(object)
    busy_changed = Signal(bool)
    human_required = Signal(object)

    def __init__(self, parent):
        super().__init__(parent)
        self.calls = []
        self.worker = self._native = self._paused_run = None

    @property
    def busy(self):
        return self.worker is not None

    def submit(self, operation, **arguments):
        self.calls.append((operation, deepcopy(arguments)))
        return True

    def pause(self):
        pass

    def cancel(self):
        pass

    def grant_permission(self):
        pass

    def continue_human(self):
        return False


class ChainStateAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.errors = []
        self.old_hook = sys.excepthook
        sys.excepthook = lambda kind, value, tb: self.errors.append(
            "".join(traceback.format_exception(kind, value, tb)))
        self.host = QWidget()
        self.host.language = "EN"
        self.bridge = PassiveChainBridge(self.host)
        self.panel = ChainBuilderPanel(self.host, Path(self.temp.name), bridge=self.bridge)
        self.layout = QVBoxLayout(self.host)
        self.layout.addWidget(self.panel)
        self.panel._received("catalog", {"tools": {"observe": {
            "inputs": {"source":{"types":["SESSION"]}}, "outputs": {"sample":{"types":["SESSION"]}},
            "parameters": {"duration_seconds": {"type": "number", "default": 1, "min": .01, "max": 10}},
            "descriptor": {}, "resources": []}},
            "controls": {"CONDITION": {"inputs": {}, "outputs": {}}}}, "")
        self.host.resize(1300, 850)
        self.host.show()
        self.app.processEvents()
        self.bridge.calls.clear()

    def tearDown(self):
        try:
            self.host.close()
            dispose_closed_fixture(self.host, self.app)
            self.assertEqual(self.errors, [], "Qt callback errors must fail the audit gate")
        finally:
            sys.excepthook = self.old_hook
            self.temp.cleanup()

    def add_node(self, tool="observe"):
        self.panel.add_tool(tool)
        return self.panel.document["nodes"][-1]

    def test_import_same_node_id_rebuilds_inspector_and_drops_previous_preview_and_colors(self):
        node = self.add_node()
        self.panel._fields["duration_seconds"].setValue(2.5)  # Unapplied old-file draft.
        self.panel._snapshot({"run_id": "previous", "state": "COMPLETED", "nodes": [
            {"node_id": node["node_id"], "state": "COMPLETED"}]})
        self.panel.validation = {"ready": True}
        self.panel._show_validation()
        incoming = deepcopy(self.panel.document)
        incoming["nodes"][0]["parameters"]["duration_seconds"] = 7.125
        self.panel._received("open", {"definition": incoming}, "")
        self.assertEqual(self.panel._fields["duration_seconds"].value(), 7.125)
        self.assertEqual(self.panel.snapshot, {})
        self.assertEqual(self.panel.validation, {})
        self.assertEqual(self.panel.effective.toPlainText(), "")
        self.assertEqual(self.panel.canvas.items_by_id[node["node_id"]].state, "")
        self.panel.apply_parameters()
        self.assertEqual(self.panel.document["nodes"][0]["parameters"]["duration_seconds"], 7.125)
        self.assertEqual(self.bridge.calls, [])

    def test_edited_definition_keeps_saved_receipt_but_never_paints_it_as_current_execution(self):
        node = self.add_node()
        receipt = {"run_id": "saved", "state": "PARTIAL", "nodes": [{"node_id": node["node_id"],
            "state": "COMPLETED", "run_receipt": {"marker": "TEST_ONLY_SAVED_RECEIPT"},
            "cleanup": {"confirmed": False}}]}
        self.panel._snapshot(deepcopy(receipt))
        self.assertIn("TEST_ONLY_SAVED_RECEIPT", self.panel.details.toPlainText())
        self.panel.validation = {"ready": True}
        self.panel._show_validation()
        self.panel._fields["duration_seconds"].setValue(4)
        self.panel.apply_parameters()
        for language in ("RU", "EN"):
            self.host.language = language
            self.panel.retranslate()
            self.assertEqual(self.panel.snapshot, receipt)
            self.assertNotIn("TEST_ONLY_SAVED_RECEIPT", self.panel.details.toPlainText())
            self.assertEqual(self.panel.canvas.items_by_id[node["node_id"]].state, "")
            self.assertEqual(self.panel.effective.toPlainText(), "")
        self.assertEqual(self.bridge.calls, [])

    def test_focus_and_unchanged_apply_or_delete_do_not_change_run_definition_identity(self):
        node = self.add_node()
        original = deepcopy(self.panel.document)
        self.panel._title_changed()
        self.panel._profile_changed()
        self.panel._budget_changed()
        self.panel._overrides_changed()
        self.panel._positions_changed({node["node_id"]:list(node["position"])})
        self.panel.apply_parameters()
        self.panel.delete_nodes([],[])
        self.assertEqual(self.panel.document,original)
        self.assertEqual(self.bridge.calls,[])

    def test_canvas_deselection_and_replacement_clear_inspector_and_pending_wire(self):
        node = self.add_node()
        canvas = self.panel.canvas
        canvas.pending_port = (node["node_id"], "outputs", "receipt")
        canvas._drag_start = {node["node_id"]: canvas.items_by_id[node["node_id"]].pos()}
        self.panel._render()
        self.assertIsNone(canvas.pending_port)
        self.assertEqual(canvas._drag_start, {})
        changes = []
        canvas.positions_changed.connect(changes.append)
        QTest.mouseRelease(canvas.viewport(), Qt.MouseButton.LeftButton)
        self.assertEqual(changes, [])
        canvas.scene().clearSelection()
        self.assertIsNone(self.panel._selected)
        self.assertEqual(self.panel._fields, {})
        self.assertEqual(self.panel.details.toPlainText(), "")
        self.assertFalse(self.panel.apply_button.isEnabled())

    def test_delete_selection_button_removes_selected_wire_without_deleting_its_nodes(self):
        a,b = self.add_node(),self.add_node()
        self.panel.document["edges"]=[{"edge_id":"TEST_ONLY_WIRE","source_node":a["node_id"],
            "source_port":"sample","target_node":b["node_id"],"target_port":"source"}]
        self.panel._render()
        self.panel.canvas.scene().clearSelection()
        self.panel.canvas.edge_items["TEST_ONLY_WIRE"].setSelected(True)
        self.panel.delete_button.click()
        self.assertEqual(self.panel.document["edges"],[])
        self.assertEqual({node["node_id"] for node in self.panel.document["nodes"]},{a["node_id"],b["node_id"]})
        self.assertEqual(self.bridge.calls,[])

    def test_invalid_or_oversized_drag_payload_cannot_escape_or_mutate_graph(self):
        original = deepcopy(self.panel.document)
        for payload in (b"\xff",b"X"*513):
            mime=QMimeData();mime.setData(MIME,payload)
            event=QDropEvent(QPointF(20,20),Qt.DropAction.CopyAction,mime,
                             Qt.MouseButton.LeftButton,Qt.KeyboardModifier.NoModifier)
            self.panel.canvas.dropEvent(event)
            self.assertFalse(event.isAccepted())
            self.assertEqual(self.panel.document,original)

    def test_nonfinite_typed_condition_is_rejected_without_mutating_graph(self):
        self.add_node("CONDITION")
        for raw in ("nan", "inf", "-inf"):
            with self.subTest(raw=raw):
                editor = self.panel._fields["condition"]
                editor.rows[0]["type"].setCurrentIndex(editor.rows[0]["type"].findData("number"))
                editor.rows[0]["raw"].setText(raw)
                original = deepcopy(self.panel.document)
                self.panel.apply_parameters()
                self.assertEqual(self.panel.document, original)
                self.assertIn("FINITE_CONDITION_VALUE_REQUIRED", self.panel.status.text())

    def test_loaded_fractional_run_node_repeat_and_profile_limits_survive_other_edits(self):
        self.panel.add_tool("observe", repeat=True)
        incoming = deepcopy(self.panel.document)
        incoming["budget"]["seconds"] = .125
        incoming["profile"]["overrides"]["max_seconds"] = .125
        incoming["nodes"][0]["budget_seconds"] = .125
        incoming["nodes"][0]["repeat_interval_seconds"] = .125
        self.panel._received("open", {"definition": incoming}, "")
        self.panel.select_node(incoming["nodes"][0]["node_id"])
        self.panel.apply_parameters()
        self.panel.parallel.setValue(3)
        self.panel.source_ids.setText("a"*64)
        self.panel._overrides_changed()
        self.assertEqual(self.panel.document["budget"]["seconds"], .125)
        self.assertEqual(self.panel.document["profile"]["overrides"]["max_seconds"], .125)
        self.assertEqual(self.panel.document["nodes"][0]["budget_seconds"], .125)
        self.assertEqual(self.panel.document["nodes"][0]["repeat_interval_seconds"], .125)

    def test_terminal_snapshot_clears_continue_and_permission_without_inventing_cleanup(self):
        self.add_node()
        self.panel._human({"state": "WAITING_FOR_HUMAN", "grant_permission": True})
        self.assertTrue(self.panel.resume_button.isEnabled())
        self.assertTrue(self.panel.grant_button.isEnabled())
        for state in ("COMPLETED", "CANCELLED", "RECOVERY_UNCONFIRMED"):
            self.panel._snapshot({"run_id": "saved", "state": state, "nodes": [],
                                   "cleanup": {"confirmed": False}})
            self.assertFalse(self.panel.resume_button.isEnabled())
            self.assertFalse(self.panel.grant_button.isEnabled())
            self.assertIs(self.panel.snapshot["cleanup"]["confirmed"], False)

    def test_history_refresh_preserves_run_identity_and_translation_without_selecting_another_run(self):
        history = ChainHistoryPanel(self.host, self.panel)
        self.layout.addWidget(history)
        a = {"run_id": "saved-a", "folder": "A", "title": "A", "state": "COMPLETED"}
        b = {"run_id": "saved-b", "folder": "B", "title": "B", "state": "FAILED"}
        history._received("history", [a, b], "")
        self.assertIsNone(history.selected())
        history.table.selectRow(0)
        history._received("history", [b, a], "")
        self.assertEqual(history.selected()["run_id"], "saved-a")
        self.assertEqual(self.panel.canvas.language, "EN")
        self.host.language = "RU"
        history.retranslate()
        self.assertEqual(history.table.item(1, 2).text(), "Завершено")
        self.assertEqual(history.table.item(0, 2).text(), "Ошибка")
        self.assertEqual(history.selected()["run_id"], "saved-a")
        # A hidden/previously translated canvas is independent of history's
        # current language in both directions; no execution is dispatched.
        self.panel.retranslate()
        self.assertEqual(self.panel.canvas.language, "RU")
        self.host.language = "EN"
        history.retranslate()
        self.assertEqual(history.table.item(1, 2).text(), "Completed")
        self.assertEqual(history.table.item(0, 2).text(), "Failed")
        self.assertEqual(history.selected()["run_id"], "saved-a")
        history._received("history", [b], "")
        self.assertIsNone(history.selected())
        self.assertFalse(history.open.isEnabled())
        history.open_selected()
        self.assertEqual(self.bridge.calls, [])


if __name__ == "__main__":
    unittest.main()
