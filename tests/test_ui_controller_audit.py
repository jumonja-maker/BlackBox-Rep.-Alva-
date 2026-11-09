"""Hosted ordinary GUI controller regressions with bounded recorded DTOs.

No process, recording, native helper or decoder is launched by these fixtures.
"""
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import traceback
from threading import Event
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication, QDialog, QTableWidgetItem, QVBoxLayout, QWidget

from blackbox_core.session_v2 import FILENAME
from blackbox_universal.decoder_panel import DecoderPanel
from blackbox_universal.measurement_help import MeasurementHelp
from blackbox_universal.library_panel import LibraryPanel
from blackbox_universal.preparation_dialog import PreparationDialog
from blackbox_universal.research_panel import ResearchPanel
from blackbox_universal.thread_detail_worker import ThreadDetailWorker
from qt_test_support import dispose_closed_fixture


class LegacyUiBridge(QObject):
    result_ready = Signal(str, object, str)
    updated = Signal()

    def __init__(self, parent, folder):
        super().__init__(parent)
        self.pid = 123
        self.active = True
        self.pending = False
        self.session_folder = folder
        self.last_error = None
        self.data = {"pid_creation_time": 1.25, "app_ready": False}
        self.calls = []

    def send(self, operation, **arguments):
        self.calls.append((str(len(self.calls)+1), operation, arguments))
        self.pending = True

    def complete(self, operation, result, error=""):
        self.pending = False
        self.result_ready.emit(operation, result, error)
        self.updated.emit()


class CorrelatedUiBridge(LegacyUiBridge):
    command_result = Signal(str, str, object, str)

    def send(self, operation, **arguments):
        super().send(operation, **arguments)
        return self.calls[-1][0]

    def complete(self, ident, operation, result, error=""):
        self.pending = False
        self.command_result.emit(ident, operation, result, error)
        self.result_ready.emit(operation, result, error)
        self.updated.emit()


class AnalysisReader(QObject):
    result_ready = Signal(object,str)
    finished = Signal()

    def __init__(self,parent):
        super().__init__(parent)
        self.kind = "minidump"
        self.cancel_event = Event()

    def start(self):
        pass


def episode(marker):
    return {"range_ms": [0, 1000], "chart": [{"elapsed_ms": 0, "cpu_percent": None}],
            "evidence": {"rows": [{"elapsed_ms": 0, "source": "USER", "quality": "USER_REPORTED", "kind": marker}],
                         "first_id": 1, "next_id": 1, "has_more": False},
            "facts": {"marker": marker}, "limitations": ["TEST_ONLY_IMPORTED"]}


class OrdinaryControllerAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.host = QWidget()
        self.host.language = "EN"
        self.host.probe = CorrelatedUiBridge(self.host, self.root/"A")
        self.layout = QVBoxLayout(self.host)
        self.errors = []
        self.old_hook = sys.excepthook
        sys.excepthook = lambda kind, value, tb: self.errors.append(
            "".join(traceback.format_exception(kind, value, tb)))

    def tearDown(self):
        try:
            for dialog in self.host.findChildren(QDialog):
                dialog.close()
            for panel in self.host.findChildren(DecoderPanel):
                self.assertIsNone(panel.worker)
                panel.cache.cleanup()
            self.host.close()
            dispose_closed_fixture(self.host, self.app)
            self.assertEqual(self.errors, [], "Qt callback errors must fail acceptance")
        finally:
            sys.excepthook = self.old_hook
            self.temp.cleanup()

    def research(self, *, legacy=False):
        if legacy:
            self.host.probe = LegacyUiBridge(self.host, self.root/"A")
        panel = ResearchPanel(self.host)
        self.layout.addWidget(panel)
        return panel

    def test_preparation_uses_exact_request_birth_and_recording_scope(self):
        panel = self.research()
        bridge = self.host.probe
        dialog = PreparationDialog(panel)
        inspect = bridge.calls[-1][0]
        bridge.complete("foreign-inspect", "inspect", {"runtime_candidates": ["dotnet"]})
        self.assertEqual(dialog.runtime.currentIndex(), 0)
        bridge.complete(inspect, "inspect", {"runtime_candidates": ["python"]})
        self.assertEqual(dialog.runtime.currentIndex(), 1)
        for changed in ("recording", "birth"):
            with self.subTest(changed=changed):
                dialog.generate_client()
                generated = bridge.calls[-1][0]
                result = {"folder": str(self.root/"generated-A")}
                bridge.complete("foreign-prepare", "prepare_client", result)
                self.assertIsNone(dialog.packet)
                if changed == "recording":
                    bridge.session_folder = self.root/"B"
                else:
                    bridge.data["pid_creation_time"] = 2.5
                bridge.data["app_ready"] = True
                bridge.complete(generated, "prepare_client", result)
                self.assertIsNone(dialog.packet)
                self.assertFalse(dialog.open_folder.isEnabled())
                self.assertIn("Waiting", dialog.verification.text())
                self.assertEqual(bridge.pid, 123)

    def test_valid_preparation_exposes_only_matching_generated_folder_and_stale_scope_cannot_open(self):
        panel = self.research()
        bridge = self.host.probe
        dialog = PreparationDialog(panel)
        bridge.complete(bridge.calls[-1][0], "inspect", {})
        dialog.generate_client()
        bridge.complete(bridge.calls[-1][0], "prepare_client", {"folder": str(self.root/"generated-A")})
        bridge.data["app_ready"] = True
        bridge.updated.emit()
        self.assertIn("received", dialog.verification.text())
        with patch("blackbox_universal.preparation_dialog.QDesktopServices.openUrl") as open_url:
            dialog.open_files()
            open_url.assert_called_once()
            bridge.session_folder = self.root/"B"
            dialog.open_files()
            open_url.assert_called_once()
        bridge.updated.emit()
        self.assertIsNone(dialog.packet)
        self.assertFalse(dialog.open_folder.isEnabled())
        self.assertIn("Waiting", dialog.verification.text())

    def test_preparation_dispatch_failures_are_explicit_and_legacy_accepts_only_owned_operations(self):
        panel = self.research(legacy=True)
        bridge = self.host.probe
        dialog = PreparationDialog(panel)
        bridge.complete("prepare_client", {"folder": "FOREIGN"})
        self.assertIsNone(dialog.packet)
        bridge.complete("inspect", {"runtime_candidates": ["python"]})
        with patch.object(bridge, "send", side_effect=RuntimeError("RESEARCH_HELPER_UNAVAILABLE")):
            dialog.generate_client()
        self.assertIn("RESEARCH_HELPER_UNAVAILABLE", dialog.instructions.toPlainText())
        dialog.generate_client()
        bridge.complete("prepare_client", {"folder": str(self.root/"generated-A")})
        self.assertIsNotNone(dialog.packet)

    def test_research_ignores_foreign_and_out_of_order_same_operation_results(self):
        panel = self.research()
        bridge = self.host.probe
        panel.folder = self.root/"A"
        panel.load_interval()
        request_a = bridge.calls[-1][0]
        panel.folder = self.root/"B"
        panel.load_interval()
        request_b = bridge.calls[-1][0]
        bridge.complete(request_b, "episode", episode("TEST_ONLY_B"))
        bridge.complete(request_a, "episode", episode("TEST_ONLY_A"))
        bridge.complete("foreign-same-op", "episode", episode("TEST_ONLY_FOREIGN"))
        self.assertEqual(panel.result["facts"]["marker"], "TEST_ONLY_B")
        self.assertIn("TEST_ONLY_B", panel.details.toPlainText())
        self.assertNotIn("TEST_ONLY_A", panel.details.toPlainText())
        panel.page(False)
        page_b = bridge.calls[-1][0]
        panel.folder = self.root/"C"
        panel.load_interval()
        bridge.complete(page_b, "evidence_page", episode("TEST_ONLY_OLD_PAGE")["evidence"])
        self.assertIsNone(panel.result)
        self.assertEqual(panel.table.rowCount(), 0)
        self.assertEqual(panel.details.toPlainText(), "")
        self.assertEqual(bridge.pid, 123)

    def test_foreign_main_window_comparison_cannot_replace_research_comparison_sources(self):
        panel = self.research()
        bridge = self.host.probe
        value = {"comparable_context": False, "context_mismatches": ["TEST_ONLY_CONTEXT"], "resource_comparison": {}}
        with patch("blackbox_universal.research_panel.QFileDialog.getExistingDirectory", side_effect=["A", "B"]):
            panel.compare()
        request = bridge.calls[-1][0]
        bridge.complete("foreign-compare", "compare", value)
        self.assertIsNone(panel._comparison_result)
        self.assertEqual(panel._comparison_pending_sources, ("A", "B"))
        bridge.complete(request, "compare", value)
        self.assertEqual(panel._comparison_sources, ("A", "B"))
        self.assertEqual(panel._comparison_result, value)

    def test_legacy_query_drains_old_request_then_runs_latest_selected_source(self):
        panel = self.research(legacy=True)
        bridge = self.host.probe
        bridge.complete("episode", episode("FOREIGN_WITHOUT_REQUEST"))
        self.assertIsNone(panel.result)
        panel.folder = self.root/"A"
        panel.load_interval()
        panel.folder = self.root/"B"
        panel.load_interval()
        self.assertEqual(len(bridge.calls), 1)
        bridge.complete("episode", episode("OLD_A"))
        self.assertIsNone(panel.result)
        self.app.processEvents()
        self.assertEqual(bridge.calls[-1][2]["folder"], str(self.root/"B"))
        bridge.complete("episode", episode("CURRENT_B"))
        self.assertEqual(panel.result["facts"]["marker"], "CURRENT_B")

    def test_new_explicit_query_replaces_a_scheduled_legacy_retry_and_destroyed_panel_sends_nothing(self):
        panel = self.research(legacy=True)
        bridge = self.host.probe
        panel.folder=self.root/"A";panel.load_interval()
        panel.folder=self.root/"B";panel.load_interval()
        bridge.complete("episode",episode("STALE_A"))
        panel.folder=self.root/"C";panel.load_interval()
        self.app.processEvents()
        self.assertEqual([call[2]['folder'] for call in bridge.calls],[str(self.root/"A"),str(self.root/"C")])
        panel.folder=self.root/"D";panel.load_interval()
        bridge.complete("episode",episode("STALE_C"))
        self.assertTrue(panel._retry_timer.isActive())
        panel.close();dispose_closed_fixture(panel,self.app)
        self.app.processEvents()
        self.assertEqual(len(bridge.calls),2)

    def test_pagination_clears_selected_previous_event_details(self):
        panel = self.research()
        panel.render_page(episode("OLD_SELECTED")["evidence"])
        panel.table.selectRow(0)
        self.assertIn("OLD_SELECTED", panel.details.toPlainText())
        panel.render_page(episode("NEW_PAGE")["evidence"])
        self.assertEqual(panel.details.toPlainText(), "")
        self.assertFalse(panel.table.selectionModel().selectedRows())
        panel.table.selectRow(0)
        self.assertIn("NEW_PAGE", panel.details.toPlainText())

    def test_health_permission_latency_and_error_changes_refresh_without_new_sample(self):
        bridge = self.host.probe
        record = {"samples": 1, "source": "TEST_ONLY", "status": "OK", "permissions": "STANDARD",
                  "sample_ms": 1, "latency_p95_ms": 2, "failures": 0, "overruns": 0,
                  "limitations": [], "source_error": None}
        bridge.data["sensor_health"] = {"base": record}
        panel = MeasurementHelp(self.host)
        self.layout.addWidget(panel)
        self.host.show()
        self.app.processEvents()
        record.update(permissions="UNKNOWN", sample_ms=3, latency_p95_ms=4,
                      source_error="TEST_ONLY_CHANGED_WITHOUT_SAMPLE")
        panel.refresh()
        self.assertEqual(panel.table.item(0, 3).text(), "UNKNOWN")
        self.assertEqual(panel.table.item(0, 4).text(), "3 / 4")
        self.assertIn("TEST_ONLY_CHANGED_WITHOUT_SAMPLE", panel.table.item(0, 0).toolTip())

    def test_library_known_zero_and_selected_entry_identity_survive_refresh_and_language(self):
        panel = LibraryPanel(self.host)
        self.layout.addWidget(panel)
        def row(ident):
            return {"entry_id":ident,"started_ns":0,"target_name":ident,"scenario":ident,
                    "scenario_version":"v1","target_version":"v1","completed_runs":0,"samples":0,
                    "state":"COMPLETED","origin":"IMPORTED","trash_eligible":False,
                    "workload":"TEST_ONLY_WORK","profile":"STANDARD","interval_ms":1000,
                    "configuration_changed":False,"size_bytes":None,"size_status":"UNKNOWN",
                    "file_trust":"UNVERIFIED_IMPORT","folder":str(self.root/ident)}
        a,b = row("A"),row("B")
        panel.rows=[a,b];panel.render_rows(panel.rows)
        self.assertEqual(panel.table.item(0,5).text(),"0")
        panel.table.selectRow(0)
        self.assertIn(str(self.root/"A"),panel.details.toPlainText())
        panel.rows=[b,a];panel.render_rows(panel.rows)
        self.assertEqual(panel.selected()[0]["entry_id"],"A")
        self.host.language="RU";panel.retranslate()
        self.assertEqual(panel.selected()[0]["entry_id"],"A")
        panel.rows=[b];panel.render_rows(panel.rows)
        self.assertEqual(panel.selected(),[])
        self.assertEqual(panel.details.toPlainText(),"")
        self.assertFalse(panel.open_button.isEnabled())
        self.assertEqual(self.host.probe.calls,[])

    def test_corrupt_schema2_thread_source_emits_a_bounded_error_packet(self):
        (self.root/FILENAME).write_bytes(b"TEST_ONLY_NOT_SQLITE")
        worker = ThreadDetailWorker(self.root, self.host)
        results = []
        worker.result_ready.connect(lambda value, error: results.append((value, error)))
        worker.run()
        self.assertEqual(results, [(None, "DETAIL_READ_UNAVAILABLE")])

    def test_failed_decoder_filter_page_clears_previous_rows_details_and_navigation(self):
        panel = DecoderPanel(self.host)
        self.layout.addWidget(panel)
        panel.index = self.root/"TEST_ONLY_INDEX.sqlite3"
        panel.rows = [{"event": {"name": "TEST_ONLY_OLD_EVENT"}}]
        panel.table.setRowCount(1)
        panel.table.setItem(0, 0, QTableWidgetItem("TEST_ONLY_OLD_EVENT"))
        panel.details.setPlainText("TEST_ONLY_OLD_EVENT")
        panel.next_button.setEnabled(True)
        with patch("blackbox_universal.decoder_panel.read_index", side_effect=sqlite3.DatabaseError("TEST_ONLY_BAD_INDEX")):
            panel.load_page()
        self.assertEqual(panel.state, "error")
        self.assertEqual(panel.rows, [])
        self.assertEqual(panel.table.rowCount(), 0)
        self.assertEqual(panel.details.toPlainText(), "")
        self.assertFalse(panel.next_button.isEnabled())
        self.assertFalse(panel.prev_button.isEnabled())
        self.assertFalse(panel.resolve_stack_button.isEnabled())

    def test_dump_selection_clears_unrelated_trace_rows_and_clock_context(self):
        self.host.probe.active = False
        panel = DecoderPanel(self.host)
        self.layout.addWidget(panel)
        panel.index = self.root/"TEST_ONLY_TRACE.sqlite3"
        panel.summary = {"TEST_ONLY_PREVIOUS_TRACE": True}
        panel.rows = [{"event": {"name": "TEST_ONLY_PREVIOUS_TRACE"}}]
        panel.table.setRowCount(1)
        panel.table.setItem(0,0,QTableWidgetItem("TEST_ONLY_PREVIOUS_TRACE"))
        panel.clock_review = panel.alignment_report = {"TEST_ONLY_PREVIOUS_CLOCK": True}
        reader = AnalysisReader(panel)
        with patch("blackbox_universal.decoder_panel.DecoderAnalysisWorker",return_value=reader):
            panel.start_analysis("minidump",{"path":self.root/"TEST_ONLY_DUMP.dmp"})
        self.assertIsNone(panel.index)
        self.assertIsNone(panel.summary)
        self.assertIsNone(panel.clock_review)
        self.assertIsNone(panel.alignment_report)
        self.assertEqual(panel.rows,[])
        self.assertEqual(panel.table.rowCount(),0)
        self.assertFalse(panel.export_button.isEnabled())
        reader.result_ready.emit(None,"TEST_ONLY_DUMP_UNAVAILABLE")
        reader.finished.emit()
        self.assertEqual(panel.state,"error")
        self.assertIsNone(panel.worker)
        self.assertEqual(panel.rows,[])

    def test_decoder_export_revalidates_selected_index_after_modal_dialog(self):
        panel = DecoderPanel(self.host)
        self.layout.addWidget(panel)
        a,b = self.root/"A.sqlite3",self.root/"B.sqlite3"
        panel.index = a
        def changed_source(*_args):
            panel.index = b
            return str(self.root/"export.sqlite3"),"SQLite"
        with patch("blackbox_universal.decoder_panel.QFileDialog.getSaveFileName",side_effect=changed_source), \
             patch("blackbox_universal.decoder_panel.export_index_copy") as export:
            panel.export_index()
            export.assert_not_called()
        with patch("blackbox_universal.decoder_panel.QFileDialog.getSaveFileName",return_value=(str(self.root/"export.sqlite3"),"SQLite")), \
             patch("blackbox_universal.decoder_panel.export_index_copy") as export:
            panel.export_index()
            export.assert_called_once_with(b,self.root/"export.sqlite3")


if __name__ == "__main__":
    unittest.main()
