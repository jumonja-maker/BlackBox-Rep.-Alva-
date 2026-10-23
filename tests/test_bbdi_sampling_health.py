"""BB-DI-001: observed Qt busy-tick backpressure is durable, not a fake OS gap."""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
from threading import Event
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from blackbox_core.contracts import ObserverError
from blackbox_core.report import summarize
from blackbox_core.sampling_health import BusyTickTracker


def drain(app, predicate, *, attempts=400) -> bool:
    for _ in range(attempts):
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


class BoundedGapCounterTests(unittest.TestCase):
    def test_bounded_busy_callback_episodes_with_explicit_limitations(self):
        counter = BusyTickTracker()
        self.assertIsNone(counter.drain())
        counter.skipped(100, 1000)
        counter.skipped(200, 1000)
        counter.skipped(300, 1000)
        event = counter.drain()
        self.assertEqual(event["missed_callback_count"], 3)
        self.assertEqual(event["first_skipped_monotonic_ns"], 100)
        self.assertEqual(event["last_skipped_monotonic_ns"], 300)
        self.assertEqual(event["scheduled_interval_ms"], 1000)
        self.assertFalse(event["root_cause_proven"])
        self.assertEqual(event["verification_class"], "OBSERVED_GUI_CALLBACK_ONLY")
        self.assertEqual(event["limitations"], "QT_COALESCED_CALLBACKS_NOT_COUNTED")
        self.assertIsNone(counter.drain())

    def test_interval_change_and_clock_reversal_remain_unverified(self):
        counter = BusyTickTracker()
        counter.skipped(300, 1000)
        counter.skipped(200, 2000)
        result = counter.drain()
        self.assertEqual(result["missed_callback_count"], 2)
        self.assertEqual(result["clock_quality"], "CALLBACK_CLOCK_REVERSAL")
        self.assertIsNone(result["scheduled_interval_ms"])
        for timestamp, interval in ((-1, 1000), (1.0, 1000), (2, 0), (2, 99999)):
            with self.assertRaisesRegex(ValueError, "INVALID_BUSY_TICK_CLOCK"):
                counter.skipped(timestamp, interval)
        self.assertIsNone(counter.drain())


class StoredBusyTickTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PySide6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        from blackbox_universal.window import UniversalWindow
        self.temp = tempfile.TemporaryDirectory()
        self.context = patch("blackbox_universal.monitor._default_sessions_root",
                             return_value=Path(self.temp.name))
        self.context.start()
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
        self.context.stop()
        self.temp.cleanup()

    def test_three_busy_callbacks_are_one_durable_episode_before_user_stop(self):
        entered, release = Event(), Event()
        original = self.window.probe._core.sample

        def slow():
            entered.set()
            if not release.wait(5):
                raise RuntimeError("TEST_SENSOR_TIMEOUT")
            return original()

        try:
            with patch.object(self.window.probe._core, "sample", side_effect=slow):
                self.window._request_background_sample()
                worker = self.window._base_sample_worker
                self.assertIsNotNone(worker)
                self.assertTrue(entered.wait(5))
                for _ in range(3):
                    self.window._request_background_sample()
                self.assertEqual(self.window.probe.total_samples, 0)
                self.window._stop()
                # No new skipped timer callbacks while already stopping.
                self.window._request_background_sample()
                release.set()
                self.assertTrue(worker.wait(5000))
                self.assertTrue(drain(self.app, lambda: not self.window.probe.active))
                folder = self.window.probe.session_folder
                report = summarize(folder)
                self.assertEqual(report["samples"], 1)
                self.assertEqual(report["observed_busy_timer_callbacks"], 3)
                self.assertEqual(report["observed_busy_timer_episodes"], 1)
                self.assertEqual(report["sampling_gap_count"], 0)
                self.assertEqual(report["busy_timer_coverage"],
                                 "OBSERVED_QT_CALLBACK_ONLY")
                self.assertEqual(self.window.probe.busy_timer_callbacks, 3)
                self.assertEqual(self.window.probe.busy_timer_episodes, 1)
                with closing(sqlite3.connect(folder / "session.sqlite3")) as db:
                    events = [json.loads(row[0]) for row in db.execute(
                        "SELECT data FROM events ORDER BY seq")]
                gaps = [x for x in events if x.get("code") ==
                        "BASE_TIMER_CALLBACK_SKIPPED_BUSY"]
                self.assertEqual(len(gaps), 1)
                self.assertEqual(gaps[0]["missed_callback_count"], 3)
                self.assertEqual(gaps[0]["source"], "QT_TIMER_SCHEDULER")
                self.assertIn("QT_COALESCED_CALLBACKS_NOT_COUNTED",
                              (folder / "report.json").read_text("utf-8"))
                self.assertIn("Only delivered Qt timer callbacks",
                              (folder / "report.html").read_text("utf-8"))
        finally:
            release.set()

    def test_failed_gap_write_must_not_finish_as_completed(self):
        entered, release = Event(), Event()
        original = self.window.probe._core.sample

        def slow():
            entered.set()
            if not release.wait(5):
                raise RuntimeError("TEST_SENSOR_TIMEOUT")
            return original()

        try:
            with patch.object(self.window.probe._core, "sample", side_effect=slow):
                self.window._request_background_sample()
                worker = self.window._base_sample_worker
                self.assertTrue(entered.wait(5))
                self.window._request_background_sample()
                with patch.object(self.window.probe, "record_busy_timer_gap",
                                  side_effect=ObserverError("STORAGE_ERROR", "storage")):
                    release.set()
                    self.assertTrue(worker.wait(5000))
                    self.assertTrue(drain(
                        self.app, lambda: not self.window.probe.active))
                with closing(sqlite3.connect(
                        self.window.probe.session_folder / "session.sqlite3")) as db:
                    self.assertEqual(db.execute(
                        "SELECT exit_code FROM metadata").fetchone()[0], "STORAGE_ERROR")
        finally:
            release.set()

    def test_invalid_imported_busy_marker_cannot_inflate_report_count(self):
        from blackbox_core.storage import SessionStore
        with tempfile.TemporaryDirectory() as root:
            store = SessionStore(Path(root), os.getpid())
            try:
                store.write_event({
                    "kind": "sampling_gap", "code": "BASE_TIMER_CALLBACK_SKIPPED_BUSY",
                    "source": "QT_TIMER_SCHEDULER",
                    "verification_class": "OBSERVED_GUI_CALLBACK_ONLY",
                    "missed_callback_count": "1000000000000",
                })
                store.finish("COMPLETED")
            finally:
                store.close()
            report = summarize(store.folder)
            self.assertEqual(report["observed_busy_timer_callbacks"], 0)
            self.assertEqual(report["invalid_busy_timer_events"], 1)


if __name__ == "__main__":
    unittest.main()
