"""BB-DI-001: base sample and its SQLite writer are not on Qt GUI loop.

These tests use a real schema1 local SQLite store and a bounded QThread. The
blocking synthetic collector is test-only and proves shutdown never closes
SQLite while a worker still owns the transaction.
"""
from __future__ import annotations

from contextlib import closing
import os
from pathlib import Path
import sqlite3
from threading import Event
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication
from blackbox_universal.monitor import ReadOnlyProbe
from blackbox_universal.window import UniversalWindow
from blackbox_core.contracts import ObserverError
from blackbox_core.storage import write_sample_from_worker


def drain(app, predicate, *, cycles=400):
    """Bounded Qt signal processing after a QThread has finished."""
    for _ in range(cycles):
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


class WorkerStoreTests(unittest.TestCase):
    def test_independent_writer_preserves_gui_events_and_original_schema(self):
        with tempfile.TemporaryDirectory() as root:
            probe = ReadOnlyProbe(output_root=Path(root))
            probe.attach(os.getpid())
            probe.start()
            sample = probe._core.sample()
            probe._store.write_event({"kind": "test_gui_user_marker", "source": "USER"})
            seq = write_sample_from_worker(probe.session_folder, sample)
            self.assertEqual(seq, 1)
            probe.accept_background_sample(sample, seq)
            probe._store.write_event({"kind": "test_gui_followup", "source": "USER"})
            probe.stop()
            self.assertEqual(probe.total_samples, 1)
            with closing(sqlite3.connect(probe.session_folder / "session.sqlite3")) as db:
                self.assertEqual(db.execute(
                    "SELECT schema_version FROM metadata").fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT count(*) FROM samples").fetchone()[0], 1)
                self.assertGreaterEqual(db.execute("SELECT count(*) FROM events").fetchone()[0], 3)
            self.assertTrue((probe.session_folder / "report.html").is_file())

    def test_worker_refuses_closed_session_without_creating_another_db(self):
        with tempfile.TemporaryDirectory() as root:
            probe = ReadOnlyProbe(output_root=Path(root))
            probe.attach(os.getpid())
            probe.start()
            sample = probe._core.sample()
            probe.stop()
            folder = probe.session_folder
            with self.assertRaisesRegex(ObserverError, "storage:STORAGE_ERROR"):
                write_sample_from_worker(folder, sample)
            with closing(sqlite3.connect(folder / "session.sqlite3")) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM samples").fetchone()[0], 0)


class BackgroundQtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.patched_root = patch(
            "blackbox_universal.monitor._default_sessions_root",
            return_value=Path(self.temp.name))
        self.patched_root.start()
        self.window = UniversalWindow()
        self.window._timer.stop()
        self.window.probe.attach(os.getpid())
        self.window._start()

    def tearDown(self):
        worker = self.window._base_sample_worker
        if worker is not None:
            worker.wait(5000)
            drain(self.app, lambda: self.window._base_sample_worker is None)
        self.window.close()
        drain(self.app, lambda: self.window._base_sample_worker is None)
        self.patched_root.stop()
        self.temp.cleanup()

    def test_single_worker_backpressure_and_deferred_stop(self):
        entered, release = Event(), Event()
        original = self.window.probe._core.sample

        def slow_sample():
            entered.set()
            release.wait(10)
            return original()

        try:
            with patch.object(self.window.probe._core, "sample", side_effect=slow_sample):
                self.window._request_background_sample()
                worker = self.window._base_sample_worker
                self.assertIsNotNone(worker)
                self.assertTrue(entered.wait(5))
                self.window._request_background_sample()
                self.assertIs(worker, self.window._base_sample_worker)
                self.assertEqual(self.window.probe.total_samples, 0)
                self.window._stop()
                self.assertTrue(self.window.probe.active)
                self.assertEqual(self.window._pending_base_stop, "USER_STOPPED")
                self.assertFalse(self.window.stop_btn.isEnabled())
                # GUI remains responsive while process sensor is stuck.
                self.window._navigate("reports")
                self.app.processEvents()
                self.assertEqual(self.window.stack.count(), 5)
                release.set()
                self.assertTrue(worker.wait(5_000))
                self.assertTrue(drain(self.app, lambda: not self.window.probe.active))
                self.assertIsNone(self.window._base_sample_worker)
                folder = self.window.probe.session_folder
                self.assertTrue((folder / "report.json").is_file())
                with closing(sqlite3.connect(folder / "session.sqlite3")) as db:
                    self.assertEqual(db.execute(
                        "SELECT count(*) FROM samples").fetchone()[0], 1)
                    self.assertEqual(db.execute(
                        "SELECT exit_code FROM metadata").fetchone()[0], "COMPLETED")
        finally:
            release.set()

    def test_sensor_failure_stops_with_failure_code_not_fake_completion(self):
        def fail():
            raise ObserverError("PROCESS_EXITED", "sample")
        with patch.object(self.window.probe._core, "sample", side_effect=fail):
            self.window._request_background_sample()
            worker = self.window._base_sample_worker
            self.assertIsNotNone(worker)
            self.assertTrue(worker.wait(5000))
            self.assertTrue(drain(self.app, lambda: not self.window.probe.active))
        with closing(sqlite3.connect(
                self.window.probe.session_folder / "session.sqlite3")) as db:
            self.assertEqual(db.execute(
                "SELECT exit_code FROM metadata").fetchone()[0], "PROCESS_EXITED")
            self.assertEqual(db.execute("SELECT count(*) FROM samples").fetchone()[0], 0)

    def test_window_close_does_not_destroy_inflight_sqlite_writer(self):
        entered, release = Event(), Event()
        original = self.window.probe._core.sample

        def slow_sample():
            entered.set()
            release.wait(10)
            return original()
        try:
            with patch.object(self.window.probe._core, "sample", side_effect=slow_sample):
                self.window._request_background_sample()
                worker = self.window._base_sample_worker
                self.assertTrue(entered.wait(5))
                self.window.close()
                self.assertTrue(self.window.probe.active)
                self.assertTrue(self.window._pending_close)
                release.set()
                self.assertTrue(worker.wait(5000))
                self.assertTrue(drain(self.app, lambda: not self.window.probe.active))
                self.app.processEvents()
                self.assertIsNone(self.window._base_sample_worker)
                with closing(sqlite3.connect(
                        self.window.probe.session_folder / "session.sqlite3")) as db:
                    self.assertEqual(db.execute(
                        "SELECT exit_code FROM metadata").fetchone()[0], "INTERRUPTED")
        finally:
            release.set()


if __name__ == "__main__":
    unittest.main()
