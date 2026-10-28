"""Saved minidumps stay useful after the original process exits.

Input below is an explicitly synthetic file-format fixture. Native capture
acceptance is separately executed by the Windows GitHub-hosted job.
"""
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication
from blackbox_universal.decoder_window import DecoderWindow
from blackbox_universal.decoder_analysis import DiagnosticReportDialog
from test_deep_dump import dump_bytes


class OfflineDumpGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.window = DecoderWindow(output_root=self.root, allow_update_check=False)
        self.window._timer.stop()
        self.window.show()
        self.panel = self.window.decoder_panel

    def wait_idle(self):
        deadline = time.monotonic() + 10
        while self.panel.worker is not None and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(.005)
        self.assertIsNone(self.panel.worker)

    def tearDown(self):
        from qt_test_support import close_and_drain
        self.panel.cancel()
        self.wait_idle()
        close_and_drain(self.window, self.app)
        self.temporary.cleanup()

    def test_open_saved_dump_without_selected_live_target_or_trace_index(self):
        path = self.root / "saved.dmp"
        path.write_bytes(dump_bytes())
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertIsNone(self.window.probe.pid)
        self.assertIsNone(self.panel.index)
        with patch("blackbox_universal.decoder_panel.QFileDialog.getOpenFileName",
                   return_value=(str(path), "")):
            self.panel.dump_button.click()
        self.wait_idle()
        report = self.panel.analysis_report
        self.assertEqual(report["schema"], "blackbox.deep-minidump/1")
        self.assertEqual(report["threads"][0]["context"]["rip"], 0x140000120)
        self.assertFalse(report["memory_contents_included"])
        self.assertNotIn("deadbeef", self.panel.details.toPlainText())
        self.assertIsNone(self.panel.index)
        self.assertTrue(self.panel.export_analysis_button.isEnabled())
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
        self.assertEqual(len(self.panel.findChildren(DiagnosticReportDialog)), 1)
        for language in ("RU", "EN"):
            self.window._set_language(language)
            self.assertTrue(self.panel.dump_button.text())

    def test_cancel_offline_dump_worker_preserves_viewer_lifecycle(self):
        def blocked(*args, cancel_event, **kwargs):
            self.assertTrue(cancel_event.wait(5))
            raise InterruptedError("DUMP_INSPECTION_CANCELLED")
        with patch("blackbox_core.deep_dump.inspect_dump", side_effect=blocked):
            self.panel.start_analysis("minidump", {"path": self.root / "placeholder.dmp"})
            self.panel.cancel_button.click()
            self.wait_idle()
        self.assertIn("DUMP_INSPECTION_CANCELLED", self.panel.error)
        self.assertTrue(self.panel.dump_button.isEnabled())
        self.assertFalse(self.panel.export_analysis_button.isEnabled())


if __name__ == "__main__":
    unittest.main()
