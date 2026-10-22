"""Cross-platform tests for real shell behavior (Qt runs offscreen in CI)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import psutil
from PySide6.QtWidgets import QApplication, QMessageBox, QPushButton

from blackbox_universal.monitor import (
    ReadOnlyProbe, available_processes, save_snapshot,
)
from blackbox_universal.theme import set_retro_theme
from blackbox_universal.window import UniversalWindow


class ObserverTests(unittest.TestCase):
    def test_attach_current_process_sample_stop_and_export(self):
        observer = ReadOnlyProbe()
        observer.attach(os.getpid())
        self.assertFalse(observer.active)
        observer.start()
        time.sleep(0.025)
        sample = observer.tick()
        self.assertIsNotNone(sample)
        self.assertGreaterEqual(sample["rss_mb"], 0)
        self.assertGreaterEqual(sample["process_count"], 1)
        observer.stop()
        self.assertFalse(observer.active)
        record = observer.snapshot()
        self.assertEqual(record["schema_version"], 1)
        self.assertEqual(record["alva_status"], "NOT_CONNECTED")
        self.assertFalse(record["root_cause_proven"])
        self.assertEqual(record["sample_count"], 1)
        self.assertEqual(record["observed_process"]["pid"], os.getpid())
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "observation.json"
            save_snapshot(destination, record)
            self.assertEqual(json.loads(destination.read_text(
                encoding="utf-8"))["observed_process"]["pid"], os.getpid())
            self.assertEqual([p.name for p in Path(folder).iterdir()],
                             ["observation.json"])

    def test_process_selection_does_not_start_observation(self):
        observer = ReadOnlyProbe()
        observer.attach(os.getpid())
        self.assertFalse(observer.active)
        self.assertEqual(observer.snapshot()["sample_count"], 0)

    def test_invalid_pid_is_not_mistaken_for_live_target(self):
        observer = ReadOnlyProbe()
        with self.assertRaises(psutil.NoSuchProcess):
            observer.attach(2**31 - 1)
        self.assertFalse(observer.active)

    def test_process_picker_returns_only_bounded_metadata(self):
        rows = available_processes(limit=10000)
        self.assertIsInstance(rows, list)
        self.assertTrue(all(set(r) ==
                            {"pid", "name", "rss_mb", "status"}
                            for r in rows))
        self.assertTrue(all(type(r["pid"]) is int for r in rows))
        self.assertNotIn("cmdline", json.dumps(rows))
        self.assertNotIn("environ", json.dumps(rows))


class QtShellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        set_retro_theme(cls.app)

    def setUp(self):
        self.window = UniversalWindow()
        self.window._timer.stop()

    def tearDown(self):
        self.window.close()

    def test_six_real_pages_and_classic_three_window_controls(self):
        self.assertEqual(len(self.window.PAGES), 6)
        self.assertEqual(self.window.stack.count(), 6)
        self.assertEqual(len(self.window._nav_buttons), 6)
        chrome = self.window.findChildren(QPushButton, "windowControl")
        self.assertEqual(len(chrome), 3)
        for key, _ in self.window.PAGES:
            self.window._navigate(key)
            self.assertEqual(self.window.stack.currentIndex(),
                             self.window._page_ids[key])
        self.assertTrue(self.window.windowTitle().startswith("BLACK.BOX"))

    def test_real_process_picker_filter_and_attach_workflow(self):
        target = {"pid": os.getpid(),
                  "name": psutil.Process().name(),
                  "rss_mb": 55.5, "status": "running"}
        with patch("blackbox_universal.window.available_processes",
                   return_value=[target]):
            self.window._refresh_process_list()
        self.window.process_search.setText(str(os.getpid()))
        self.assertEqual(self.window.process_table.rowCount(), 1)
        self.window.process_table.selectRow(0)
        self.window._attach_selected()
        self.assertEqual(self.window.probe.pid, os.getpid())
        self.assertFalse(self.window.probe.active)
        self.assertTrue(self.window.start_btn.isEnabled())
        self.window._start()
        self.window._tick()
        self.assertTrue(self.window.probe.active)
        self.assertGreater(self.window.probe.last["rss_mb"], 0)
        self.assertTrue(self.window.stop_btn.isEnabled())
        self.window._stop()
        self.assertFalse(self.window.probe.active)

    def test_export_only_after_user_selection_without_cloud_upload(self):
        with tempfile.TemporaryDirectory() as folder:
            dst = Path(folder) / "report.json"
            self.window.probe.attach(os.getpid())
            self.window.probe.start()
            self.window._tick()
            self.window._stop()
            with patch("blackbox_universal.window.QFileDialog.getSaveFileName",
                       return_value=(str(dst), "JSON files (*.json)")), \
                 patch.object(QMessageBox, "information", return_value=None):
                self.window._export()
            self.assertTrue(dst.is_file())
            report = json.loads(dst.read_text(encoding="utf-8"))
            self.assertEqual(report["source"], "local_read_only_psutil")
            self.assertFalse(report["root_cause_proven"])
            self.assertEqual(report["alva_status"], "NOT_CONNECTED")

    def test_alva_page_never_fakes_integration_or_diagnostic_evidence(self):
        self.window._navigate("alva")
        contents = " ".join(child.text() for child in
                            self.window.stack.currentWidget().findChildren(
                                __import__("PySide6.QtWidgets",
                                           fromlist=["QLabel"]).QLabel))
        self.assertIn("NOT CONNECTED", contents)
        self.assertIn("upstream foundation", contents)

    def test_sampling_interval_is_user_editable_and_connected(self):
        self.window.interval_combo.setCurrentIndex(2)
        self.assertEqual(self.window._timer.interval(), 5000)
        self.window.interval_combo.setCurrentIndex(0)
        self.assertEqual(self.window._timer.interval(), 1000)


if __name__ == "__main__":
    unittest.main()
