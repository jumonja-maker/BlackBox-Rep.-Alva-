"""Saved minidumps stay useful after the original process exits.

Input below is an explicitly synthetic file-format fixture. Native capture
acceptance is separately executed by the Windows GitHub-hosted job.
"""
import hashlib
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

    def open_fixture(self, name="saved.dmp"):
        path = self.root / name
        path.write_bytes(dump_bytes())
        self.panel.start_analysis("minidump", {"path": path})
        self.wait_idle()
        return path

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
            self.assertEqual(self.panel.export_analysis_button.text(),
                             "СОХРАНИТЬ МЕТАДАННЫЕ ДАМПА…" if language == "RU" else "SAVE DUMP METADATA…")
        destination = self.root / "metadata.json"
        with patch("blackbox_universal.decoder_panel.QFileDialog.getSaveFileName",
                   return_value=(str(destination), "JSON (*.json)")) as choose:
            self.panel.save_analysis()
        self.assertIn("dump metadata", choose.call_args.args[1])
        self.assertEqual(choose.call_args.args[2], "dump-metadata.json")
        self.assertNotIn("deadbeef", destination.read_text(encoding="utf-8"))
        self.panel.analysis_report = {"schema": "blackbox.thread-waits/1"}
        self.panel.render_status()
        self.assertEqual(self.panel.export_analysis_button.text(), "SAVE ANALYSIS…")

    def test_cancel_offline_dump_worker_preserves_viewer_lifecycle(self):
        path = self.root / "placeholder.dmp"
        path.write_bytes(dump_bytes())
        def blocked(*args, cancel_event, **kwargs):
            self.assertTrue(cancel_event.wait(5))
            raise InterruptedError("DUMP_INSPECTION_CANCELLED")
        with patch("blackbox_core.deep_dump.inspect_dump", side_effect=blocked):
            self.panel.start_analysis("minidump", {"path": path})
            self.panel.cancel_button.click()
            self.wait_idle()
        self.assertIn("DUMP_INSPECTION_CANCELLED", self.panel.error)
        self.assertTrue(self.panel.dump_button.isEnabled())
        self.assertFalse(self.panel.export_analysis_button.isEnabled())

    def test_private_saved_bytes_need_no_live_process_and_never_enter_metadata_export(self):
        self.assertTrue(self.panel.dump_memory_button.isHidden())
        path = self.open_fixture()
        self.assertFalse(self.panel.dump_memory_button.isHidden())
        metadata = self.panel.analysis_report
        self.assertIsNone(self.window.probe.pid)
        self.assertIsNone(self.panel.index)
        self.panel.dump_address.setText("0x1000")
        self.panel.dump_size.setValue(4)
        self.panel.dump_memory_button.click()
        self.wait_idle()
        self.assertIn("deadbeef", self.panel.dump_memory_view.toPlainText())
        self.assertIn("SAVED_MINIDUMP_MEMORY", self.panel.dump_memory_view.toPlainText())
        self.assertIs(self.panel.analysis_report, metadata)
        self.assertNotIn("deadbeef", json.dumps(metadata))
        self.assertNotIn("_dump_file_identity", metadata)
        self.assertNotIn("_dump_path", metadata)
        self.assertNotIn("deadbeef", self.panel.details.toPlainText())
        destination = self.root / "metadata-only.json"
        with patch("blackbox_universal.decoder_panel.QFileDialog.getSaveFileName", return_value=(str(destination), "JSON (*.json)")):
            self.panel.save_analysis()
        self.assertNotIn("deadbeef", destination.read_text(encoding="utf-8"))
        self.assertEqual(path.read_bytes(), dump_bytes())
        self.panel.mode.setCurrentIndex(1)
        self.app.processEvents()
        self.assertEqual(self.panel.dump_memory_view.toPlainText(), "")
        self.assertFalse(self.panel.dump_memory_button.isEnabled())
        self.assertTrue(self.panel.dump_memory_button.isHidden())
        self.panel.retranslate()
        self.assertTrue(self.panel.dump_memory_view.isHidden())

    def test_saved_memory_read_enforces_bounds_before_starting_worker(self):
        self.open_fixture()
        self.assertEqual(self.panel.dump_size.maximum(), 4096)
        self.panel.dump_address.setText("0x1000")
        with patch.object(self.panel.dump_size, "value", return_value=4097), \
             patch.object(self.panel, "start_analysis") as start:
            self.panel.read_saved_dump_memory()
        start.assert_not_called()
        self.assertIn("1_TO_4096", self.panel.error)
        self.panel.dump_address.setText("0xffffffffffffffff")
        self.panel.dump_size.setValue(4)
        self.panel.read_saved_dump_memory()
        self.assertIsNone(self.panel.worker)
        self.assertEqual(self.panel.dump_memory_view.toPlainText(), "")

    def test_changed_dump_file_is_refused_before_displaying_bytes(self):
        path = self.open_fixture()
        replacement = self.root / "replacement.dmp"
        replacement.write_bytes(dump_bytes(memory64=True))
        replacement.replace(path)
        self.panel.dump_address.setText("0x1000")
        self.panel.dump_size.setValue(4)
        self.panel.read_saved_dump_memory()
        self.wait_idle()
        self.assertIn("DUMP_CHANGED_SINCE_METADATA_INSPECTION", self.panel.error)
        self.assertEqual(self.panel.dump_memory_view.toPlainText(), "")
        self.assertIsNone(self.panel._dump_path)
        self.assertFalse(self.panel.dump_memory_button.isEnabled())

    def test_cancel_or_mode_change_discards_late_private_memory_result(self):
        for cancel_via_mode in (False, True):
            with self.subTest(cancel_via_mode=cancel_via_mode):
                self.open_fixture("memory-" + str(cancel_via_mode) + ".dmp")
                self.panel.dump_address.setText("0x1000")
                self.panel.dump_size.setValue(4)
                def late_result(*args, cancel_event, **kwargs):
                    self.assertTrue(cancel_event.wait(5))
                    return {"status": "COMPLETED", "data": {"value_hex": "deadbeef", "source": "SAVED_MINIDUMP_MEMORY"}}
                with patch("blackbox_core.deep_dump.read_dump_memory", side_effect=late_result):
                    self.panel.read_saved_dump_memory()
                    if cancel_via_mode:
                        self.panel.mode.setCurrentIndex(1 if self.panel.mode.currentIndex() != 1 else 0)
                    else:
                        self.panel.cancel()
                    self.wait_idle()
                self.assertEqual(self.panel.dump_memory_view.toPlainText(), "")
                self.assertNotIn("deadbeef", json.dumps(self.panel.analysis_report))
                self.assertIn("DUMP_SELECTION_CHANGED" if cancel_via_mode else "DUMP_MEMORY_READ_CANCELLED", self.panel.error)

    def test_opening_another_saved_dump_clears_previous_private_bytes(self):
        self.open_fixture("first.dmp")
        self.panel.dump_address.setText("0x1000")
        self.panel.dump_size.setValue(4)
        self.panel.read_saved_dump_memory()
        self.wait_idle()
        self.assertIn("deadbeef", self.panel.dump_memory_view.toPlainText())
        second = self.open_fixture("second.dmp")
        self.assertEqual(Path(self.panel._dump_path), second)
        self.assertEqual(self.panel.dump_memory_view.toPlainText(), "")
        self.assertEqual(self.panel.dump_address.text(), "")


if __name__ == "__main__":
    unittest.main()
