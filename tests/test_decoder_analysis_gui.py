"""Production sixth page and cancellable worker lifecycle (offscreen)."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication
from blackbox_universal.decoder_window import DecoderWindow
from blackbox_universal.theme import set_retro_theme


class DecoderAnalysisGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        set_retro_theme(cls.app)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.window = DecoderWindow(output_root=Path(self.temp.name), allow_update_check=False)
        self.window._timer.stop()
        self.window.show()
        self.app.processEvents()

    def tearDown(self):
        from qt_test_support import close_and_drain
        self.window.decoder_panel.cancel()
        self.wait_idle()
        close_and_drain(self.window, self.app)
        self.temp.cleanup()

    def wait_idle(self):
        deadline = time.monotonic() + 8
        while self.window.decoder_panel.worker is not None and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(.01)
        self.assertIsNone(self.window.decoder_panel.worker)

    def test_module_catalog_and_calltree_worker_do_not_rewrite_index(self):
        import hashlib
        from test_decoder_modules import native_row, write_index
        from blackbox_universal.decoder_analysis import CallTreeDialog
        panel = self.window.decoder_panel
        index, summary = write_index(Path(self.temp.name), [native_row(), native_row(2)])
        panel.received({"path": str(index), "summary": summary}, "")
        digest = hashlib.sha256(index.read_bytes()).hexdigest()
        for language in ("EN", "RU"):
            self.window._set_language(language)
            panel.mode.setCurrentIndex(panel.mode.findData("modules"))
            panel.apply_button.click()
            self.assertEqual(panel.table.rowCount(), 1)
            self.assertEqual(panel.table.item(0, 4).text(), "test.exe")
            self.assertFalse(panel.resolve_stack_button.isEnabled())
        panel.start_calltree()
        self.wait_idle()
        self.assertEqual(panel.state, "decoded", panel.error)
        self.assertEqual(panel.analysis_report["coverage"]["samples_selected"], 2)
        self.assertTrue(panel.export_analysis_button.isEnabled())
        self.assertEqual(len(panel.findChildren(CallTreeDialog)), 1)
        self.assertEqual(hashlib.sha256(index.read_bytes()).hexdigest(), digest)
        panel.start_decode(Path(self.temp.name) / "missing.jsonl")
        self.assertIsNone(panel.analysis_report)
        self.assertFalse(panel.export_analysis_button.isEnabled())
        self.wait_idle()
        self.assertEqual(panel.state, "error")
        self.assertIsNone(panel.analysis_report)

    def test_symbol_worker_keeps_raw_frames_and_unverified_binding(self):
        from test_decoder_modules import native_row, write_index
        panel = self.window.decoder_panel
        index, summary = write_index(Path(self.temp.name), [native_row()])
        panel.received({"path": str(index), "summary": summary}, "")
        panel.mode.setCurrentIndex(panel.mode.findData("events"))
        panel.table.selectRow(0)
        self.assertTrue(panel.resolve_stack_button.isEnabled())
        raw = json.loads(json.dumps(panel.rows[0]["event"]))
        verdict = {"schema": "blackbox.native-symbol-report/1", "status": "REVIEWED",
                   "resolved_frames": 1, "frames": [{"symbol": {"name": "QA_function"}}],
                   "verification_class": "DERIVED_FROM_UNVERIFIED_TRACE_AND_LOCAL_FILES"}
        with patch("blackbox_universal.decoder_analysis.resolve_event_stack", return_value=verdict):
            panel.start_analysis("symbols", {"row": raw, "binary_path": Path("qa.exe"),
                                            "pdb_path": Path("qa.pdb")})
            self.wait_idle()
        self.assertEqual(panel.analysis_report["resolved_frames"], 1)
        self.assertIn("UNVERIFIED", panel.details.toPlainText())
        self.assertEqual(panel.rows[0]["event"], raw)
        self.assertEqual(panel.rows[0]["event"]["frames"][0]["name"], "")
        panel.table.clearSelection()
        self.assertFalse(panel.resolve_stack_button.isEnabled())

    def test_etw_source_filters_are_bilingual_snapshot_and_stale_results_clear(self):
        from test_decoder_cpu import etw_row
        from test_decoder_modules import write_index
        panel = self.window.decoder_panel
        index, summary = write_index(Path(self.temp.name),
            [etw_row(1), etw_row(2, tid=9), etw_row(3), etw_row(4)])
        panel.received({"path": str(index), "summary": summary}, "")
        panel.cpu_source.setCurrentIndex(panel.cpu_source.findData("etw"))
        panel.pid.setValue(42)
        panel.cpu_instance.setText("2"); panel.cpu_tid.setText("8")
        panel.cpu_start.setText("1"); panel.cpu_end.setText("3")
        for lang in ("RU", "EN"):
            self.window._set_language(lang)
            self.assertEqual(panel.cpu_instance.text(), "2")
            self.assertEqual(panel.cpu_source.currentData(), "etw")
        panel.start_calltree()
        self.assertFalse(panel.cpu_source.isEnabled())
        self.assertFalse(panel.cpu_start.isEnabled())
        self.wait_idle()
        self.assertEqual(panel.state, "decoded", panel.error)
        self.assertEqual(panel.analysis_report["coverage"]["samples_selected"], 1)
        self.assertEqual(panel.analysis_report["filters"]["tid"], 8)
        self.assertTrue(panel.cpu_source.isEnabled())
        panel.cpu_end.setText("5")
        self.assertIsNone(panel.analysis_report)
        self.assertFalse(panel.export_analysis_button.isEnabled())
        panel.cpu_end.setText("nan")
        panel.start_calltree()
        self.assertIsNone(panel.worker)
        self.assertIn("INVALID_CALLTREE_TIME_FILTER", panel.error)
        panel.cpu_reset.click()
        self.assertEqual(panel.cpu_end.text(), "")
        self.assertEqual(panel.cpu_instance.text(), "")
        self.assertEqual(panel.cpu_tid.text(), "")

    def test_symbol_tree_requires_explicit_pair_and_propagates_filter_snapshot(self):
        from test_decoder_cpu import etw_row
        from test_decoder_modules import write_index
        from blackbox_core.decoder_calltree import build_calltree
        panel = self.window.decoder_panel
        index, summary = write_index(Path(self.temp.name), [etw_row()])
        panel.received({"path": str(index), "summary": summary}, "")
        panel.cpu_source.setCurrentIndex(panel.cpu_source.findData("etw"))
        panel.cpu_instance.setText("2")
        # This mock tests only GUI consent/argument routing, not symbol accuracy.
        report = build_calltree(index, source="etw", process_instance=2)
        with patch("blackbox_universal.decoder_panel.QFileDialog.getOpenFileName",
                   side_effect=[("qa.exe", ""), ("qa.pdb", "")]), patch(
                   "blackbox_universal.decoder_analysis.build_calltree", return_value=report) as build:
            panel.choose_calltree_symbols()
            self.wait_idle()
        self.assertEqual(build.call_args.kwargs["source"], "etw")
        self.assertEqual(build.call_args.kwargs["process_instance"], 2)
        self.assertEqual(build.call_args.kwargs["binary_path"], Path("qa.exe"))
        self.assertEqual(build.call_args.kwargs["pdb_path"], Path("qa.pdb"))
        old = panel.analysis_report
        with patch("blackbox_universal.decoder_panel.QFileDialog.getOpenFileName", return_value=("", "")):
            panel.choose_calltree_symbols()
        self.assertIsNone(panel.worker)
        self.assertIs(panel.analysis_report, old)

    def test_analysis_cancel_and_close_drain_real_qthread(self):
        from test_decoder_modules import native_row, write_index
        panel = self.window.decoder_panel
        index, summary = write_index(Path(self.temp.name), [native_row()])
        panel.received({"path": str(index), "summary": summary}, "")
        def blocked(*args, cancel, **kwargs):
            if not cancel.wait(5):
                raise RuntimeError("TEST_ANALYSIS_NOT_CANCELLED")
            raise InterruptedError("CALLTREE_CANCELLED")
        with patch("blackbox_universal.decoder_analysis.build_calltree", side_effect=blocked):
            panel.start_calltree()
            self.assertFalse(panel.open_button.isEnabled())
            self.window.close()
            self.wait_idle()
        self.assertIn("CALLTREE_CANCELLED", panel.error)
        self.assertIsNone(panel.analysis_report)
        self.app.processEvents()


if __name__ == "__main__":
    unittest.main()
