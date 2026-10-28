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
