"""BB-DI-001 opt-in incident smoke and boundary regression tests.

Only CPU and sampling-gap triggers; not Windows native hang or full M-023.
"""
from __future__ import annotations
from contextlib import closing

import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from blackbox_core.incidents import IncidentCapture
from blackbox_universal.monitor import ReadOnlyProbe


class IncidentUnitTests(unittest.TestCase):
    def test_sustained_high_cpu_emits_bounded_incident_then_cooldown(self):
        tracker = IncidentCapture(threshold=80, min_duration_ms=2000,
                                  pre_ms=5000, post_ms=2000, cooldown_ms=5000,
                                  max_incidents=2)
        records = []
        for seq, elapsed in enumerate(range(0, 11000, 1000), start=1):
            records.extend(tracker.observe(elapsed_ms=elapsed,
                                           sample_seq=seq, cpu_percent=95.0))
        started = [e for e in records if e["code"] == "AUTO_INCIDENT_STARTED"]
        completed = [e for e in records if e["code"] == "AUTO_INCIDENT_COMPLETED"]
        self.assertEqual(len(started), 1)
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]["first_sample_seq"], 1)
        self.assertEqual(completed[0]["trigger_sample_seq"], 3)
        self.assertEqual(completed[0]["last_sample_seq"], 5)
        self.assertEqual(completed[0]["status"], "CAPTURED")
        self.assertFalse(completed[0]["proven_root_cause"])

    def test_sampling_gap_is_not_mislabeled_as_hang_and_resets_cpu_run(self):
        detector = IncidentCapture(threshold=80, min_duration_ms=3000)
        detector.observe(elapsed_ms=0, sample_seq=1, cpu_percent=90.0)
        records = detector.observe(elapsed_ms=7000, sample_seq=2, cpu_percent=90.0)
        self.assertEqual([r["code"] for r in records], ["SAMPLING_GAP_OBSERVED"])
        self.assertEqual(records[0]["interpretation"], "OBSERVED_GAP_NOT_TARGET_HANG")
        self.assertIsNone(detector._active)

    def test_incomplete_incident_is_not_called_completed(self):
        detector = IncidentCapture(min_duration_ms=0, post_ms=20000)
        start = detector.observe(elapsed_ms=1000, sample_seq=1, cpu_percent=90.0)
        self.assertEqual(start[0]["code"], "AUTO_INCIDENT_STARTED")
        stop = detector.stop(elapsed_ms=1000, sample_seq=1)
        self.assertEqual(stop[0]["status"], "INCOMPLETE_RECORDING_STOPPED")
        self.assertEqual(detector.stop(elapsed_ms=1000, sample_seq=1), [])

    def test_bad_timestamps_do_not_become_incidents(self):
        detector = IncidentCapture()
        with self.assertRaises(ValueError):
            detector.observe(elapsed_ms=-1, sample_seq=1, cpu_percent=5)
        detector.observe(elapsed_ms=1000, sample_seq=1, cpu_percent=None)
        with self.assertRaises(ValueError):
            detector.observe(elapsed_ms=999, sample_seq=2, cpu_percent=3)

    def test_bounds_limit_incident_count_and_memory(self):
        detector = IncidentCapture(min_duration_ms=0, post_ms=0,
                                   cooldown_ms=0, max_incidents=3,
                                   gap_ms=1000000, pre_ms=1000000)
        all_events = []
        for i in range(620):
            # Each new incident requires an actual below-threshold recovery.
            value = 0 if i % 10 == 9 else 100
            all_events.extend(detector.observe(
                elapsed_ms=i, sample_seq=i+1, cpu_percent=value))
        self.assertEqual(detector.incidents, 3)
        self.assertEqual(len(detector._history), 512)
        self.assertGreater(detector.buffer_evictions, 0)
        self.assertEqual(sum(x["code"] == "AUTO_INCIDENT_COMPLETED"
                             for x in all_events), 3)


class PersistedIncidentTests(unittest.TestCase):
    def test_real_process_optin_creates_sqlite_events_without_os_claim(self):
        with tempfile.TemporaryDirectory() as root:
            probe = ReadOnlyProbe(output_root=Path(root))
            probe.attach(os.getpid())
            probe.start()
            try:
                self.assertIsNone(probe.incident_capture)
                probe.set_incident_capture(True)
                self.assertIsNotNone(probe.incident_capture)
                # Only alter *policy*, not the actual observed CPU samples.
                probe.incident_capture.threshold = 0.0001
                probe.incident_capture.min_duration_ms = 0
                probe.incident_capture.post_ms = 0
                probe.tick()
                probe.set_incident_capture(False)
                self.assertIsNone(probe.incident_capture)
            finally:
                probe.stop()
            with closing(sqlite3.connect(probe.session_folder / "session.sqlite3")) as connection:
                records = [json.loads(row[0]) for row in connection.execute(
                    "SELECT data FROM events ORDER BY seq")]
            starts = [row for row in records
                      if row.get("code") == "INCIDENT_CAPTURE_ENABLED"]
            self.assertEqual(len(starts), 1)
            auto = [row for row in records if row.get("kind") == "incident_boundary"]
            self.assertTrue(all(item["proven_root_cause"] is False for item in auto))
            self.assertTrue((probe.session_folder / "report.json").is_file())

    def test_qt_control_requires_active_observation(self):
        from PySide6.QtWidgets import QApplication
        from blackbox_universal.window import UniversalWindow
        app = QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as directory, patch(
                "blackbox_universal.monitor._default_sessions_root",
                return_value=Path(directory)):
            window = UniversalWindow()
            window._timer.stop()
            try:
                self.assertEqual(window.stack.count(), 5)
                self.assertFalse(window.auto_capture_btn.isEnabled())
                window.probe.attach(os.getpid())
                window._start()
                window._update_all()
                self.assertTrue(window.auto_capture_btn.isEnabled())
                window.auto_capture_btn.click()
                self.assertIsNotNone(window.probe.incident_capture)
                window._set_language("RU")
                self.assertIn("ВКЛ", window.auto_capture_btn.text())
                window._stop()
                self.assertFalse(window.auto_capture_btn.isEnabled())
            finally:
                from qt_test_support import close_and_drain
                close_and_drain(window,app)


if __name__ == "__main__":
    unittest.main()
