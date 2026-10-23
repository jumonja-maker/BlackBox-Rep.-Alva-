"""BB-DI-001: Qt report build is deferred and never owns GUI SQLite handle."""
from __future__ import annotations

from contextlib import closing
import os
from pathlib import Path
import sqlite3
from threading import Event, get_ident
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication
from blackbox_universal.window import UniversalWindow
from blackbox_universal.monitor import ReadOnlyProbe


def drain(app, condition, tries=500):
    for _ in range(tries):
        app.processEvents()
        if condition():
            return True
        time.sleep(0.006)
    return condition()


class QtReportWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root_patch = patch(
            "blackbox_universal.monitor._default_sessions_root",
            return_value=Path(self.temp.name))
        self.root_patch.start()
        self.window = UniversalWindow()
        self.window._timer.stop()
        self.window.probe.attach(os.getpid())
        self.window._start()

    def tearDown(self):
        self.assertTrue(drain(self.app, lambda:
                              self.window._report_worker is None and
                              self.window._base_sample_worker is None))
        self.window.close()
        self.app.processEvents()
        self.root_patch.stop()
        self.temp.cleanup()

    def test_report_io_runs_off_qt_and_blocks_restart_until_complete(self):
        entered, release = Event(), Event()
        from blackbox_universal.report_worker import write_report
        caller_thread = get_ident()
        report_threads = []

        def blocked_report(folder):
            report_threads.append(get_ident())
            entered.set()
            if not release.wait(5):
                raise RuntimeError("SYNTHETIC_TEST_REPORT_TIMEOUT")
            return write_report(folder)

        try:
            with patch("blackbox_universal.report_worker.write_report",
                       side_effect=blocked_report):
                self.window._stop()
                self.assertIsNotNone(self.window._report_worker)
                self.assertTrue(entered.wait(5))
                self.assertEqual(self.window._report_state, "saving")
                self.assertFalse(self.window.start_btn.isEnabled())
                self.assertFalse(self.window.investigate_current_btn.isEnabled())
                self.assertFalse(self.window.probe.active)
                self.window._attach_pid(os.getpid())
                self.window._start()
                self.assertEqual(self.window._report_state, "saving")
                self.assertEqual(self.window.probe.report_result, None)
                # User can still navigate and handle GUI events while report
                # generation is blocked in another Python thread.
                self.window._navigate("events")
                self.app.processEvents()
                self.assertEqual(self.window.stack.currentIndex(),
                                 self.window._page_ids["events"])
                self.assertTrue(self.window.isEnabled())
                release.set()
                self.assertTrue(drain(
                    self.app, lambda: self.window._report_worker is None))
            self.assertEqual(len(report_threads), 1)
            self.assertNotEqual(report_threads[0], caller_thread)
            self.assertEqual(self.window._report_state, "saved")
            self.assertIsNotNone(self.window.probe.report_result)
            folder = self.window.probe.session_folder
            self.assertTrue((folder / "report.json").is_file())
            self.assertTrue((folder / "report.html").is_file())
            self.assertTrue(self.window.start_btn.isEnabled())
            with closing(sqlite3.connect(folder / "session.sqlite3")) as db:
                self.assertEqual(db.execute(
                    "SELECT schema_version, exit_code FROM metadata").fetchone(),
                    (1, "COMPLETED"))
        finally:
            release.set()

    def test_close_during_report_defers_window_destruction(self):
        entered, release = Event(), Event()
        from blackbox_universal.report_worker import write_report

        def blocked_report(folder):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("SYNTHETIC_TEST_REPORT_TIMEOUT")
            return write_report(folder)

        try:
            with patch("blackbox_universal.report_worker.write_report",
                       side_effect=blocked_report):
                self.window._stop()
                self.assertTrue(entered.wait(5))
                self.window.close()
                self.assertTrue(self.window._pending_close)
                self.assertIsNotNone(self.window._report_worker)
                release.set()
                self.assertTrue(drain(
                    self.app, lambda: self.window._report_worker is None))
                self.app.processEvents()
            self.assertFalse(self.window._pending_close)
            self.assertTrue((self.window.probe.session_folder / "report.json").is_file())
        finally:
            release.set()

    def test_report_failure_is_explicit_not_fake_saved_success(self):
        with patch("blackbox_universal.report_worker.write_report",
                   side_effect=OSError("test filesystem failure")):
            self.window._stop()
            self.assertTrue(drain(
                self.app, lambda: self.window._report_worker is None))
        self.assertEqual(self.window._report_state, "unavailable")
        self.assertIsNone(self.window.probe.report_result)
        self.assertEqual(self.window.probe.last_error, "REPORT_UNAVAILABLE")
        self.assertIn("REPORT_UNAVAILABLE",
                      [event["code"] for event in self.window.probe.events])
        with closing(sqlite3.connect(
                self.window.probe.session_folder / "session.sqlite3")) as db:
            self.assertEqual(db.execute(
                "SELECT exit_code FROM metadata").fetchone()[0], "COMPLETED")


class SynchronousCompatibilityTests(unittest.TestCase):
    def test_explicit_core_stop_remains_synchronous_for_cli(self):
        with tempfile.TemporaryDirectory() as root:
            probe = ReadOnlyProbe(output_root=Path(root))
            probe.attach(os.getpid())
            probe.start()
            probe.tick()
            probe.stop()
            self.assertIsNotNone(probe.report_result)
            self.assertTrue((probe.session_folder / "report.json").is_file())
            self.assertTrue((probe.session_folder / "report.html").is_file())


if __name__ == "__main__":
    unittest.main()
