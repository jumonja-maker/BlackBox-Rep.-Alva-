"""BB-DI-001 detailed v2 sidecar: actual psutil observations and lifecycle.

A scoped, opt-in diagnostic path; this does not claim WCT/ETW/stack capture.
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

from blackbox_core.detailed_capture import (
    DetailedCapture, DetailSensorError, sample_process, summarize_detail)
from blackbox_universal.monitor import ReadOnlyProbe


class DetailedSensorTests(unittest.TestCase):
    def test_real_process_snapshot_has_distinct_memory_provenance_and_threads(self):
        import psutil
        pid = os.getpid()
        observed = sample_process(pid, psutil.Process(pid).create_time())
        self.assertEqual(observed["pid"], pid)
        self.assertGreater(observed["time_ns"], 0)
        self.assertGreater(observed["rss_bytes"], 0)
        self.assertEqual(observed["source"], "PSUTIL_EXTERNAL_COUNTERS_NOT_CAUSAL_PROOF")
        self.assertLessEqual(len(observed["threads"]), 256)
        self.assertLessEqual(len(observed["children"]), 64)
        self.assertIn(observed["thread_status"], ("OK", "ACCESS_DENIED_OR_UNSUPPORTED"))
        self.assertNotIn("stacks", observed)
        self.assertNotIn("wait_chain", observed)
        if observed["private_bytes"] is not None:
            self.assertGreaterEqual(observed["private_bytes"], 0)

    def test_creation_time_failure_cannot_rebind_pid(self):
        import psutil
        pid = os.getpid()
        with self.assertRaisesRegex(DetailSensorError, "PID_REUSED"):
            sample_process(pid, psutil.Process(pid).create_time()-123)


class SidecarLifecycleTests(unittest.TestCase):
    def test_optin_capture_writes_v2_and_keeps_v1_unchanged(self):
        with tempfile.TemporaryDirectory() as root:
            probe = ReadOnlyProbe(output_root=Path(root))
            probe.attach(os.getpid())
            probe.start()
            try:
                self.assertIsNone(probe.detailed_capture)
                probe.tick()
                probe.set_detailed_capture(True)
                self.assertIsNotNone(probe.detailed_capture)
                cap = probe.detailed_capture
                for _ in range(80):
                    if cap.samples:
                        break
                    time.sleep(0.025)
                self.assertGreater(cap.samples, 0, cap.error)
                probe.set_detailed_capture(False)
                self.assertIsNone(probe.detailed_capture)
            finally:
                probe.stop()
            db = probe.session_folder / "session.sqlite3"
            with closing(sqlite3.connect(db)) as conn:
                self.assertEqual(conn.execute(
                    "SELECT schema_version FROM metadata").fetchone()[0], 1)
            detail = summarize_detail(probe.session_folder)
            self.assertEqual(detail["schema_version"], 2)
            self.assertEqual(detail["status"], "STOPPED")
            self.assertGreaterEqual(detail["samples"], 1)
            self.assertGreaterEqual(detail["thread_records"], 1)
            self.assertFalse(detail["root_cause_proven"])
            report = (probe.session_folder / "report.html").read_text(encoding="utf-8")
            self.assertIn("Detailed process capture", report)

    def test_sidecar_exclusive_create_cannot_overwrite_preexisting_file(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            planted = folder / "detail-v2.sqlite3"
            planted.write_bytes(b"KEEP")
            cap = DetailedCapture(folder, os.getpid(), 1.0, time.monotonic_ns())
            with self.assertRaisesRegex(DetailSensorError, "DETAILED_SESSION_UNAVAILABLE"):
                cap.start()
            self.assertEqual(planted.read_bytes(), b"KEEP")

    def test_blocked_collector_retains_ownership_until_exit(self):
        """A slow OS API must not permit rebind while old SQLite is open."""
        entered, release = Event(), Event()

        def slow_collector(pid, created):
            entered.set()
            release.wait(10)
            raise DetailSensorError("SENSOR_UNAVAILABLE")

        with tempfile.TemporaryDirectory() as directory:
            probe = ReadOnlyProbe(output_root=Path(directory))
            probe.attach(os.getpid())
            probe.start()
            cap = None
            try:
                with patch("blackbox_universal.monitor.DetailedCapture",
                           side_effect=lambda folder, pid, created, origin: DetailedCapture(
                               folder, pid, created, origin, interval_s=0.5,
                               collector=slow_collector)):
                    probe.set_detailed_capture(True)
                cap = probe.detailed_capture
                self.assertTrue(entered.wait(5))
                probe.set_detailed_capture(False)
                self.assertIsNone(probe.detailed_capture)
                self.assertIs(probe._pending_detailed, cap)
                self.assertEqual(probe.last_error, "DETAILED_CAPTURE_STOP_PENDING")
                with self.assertRaisesRegex(RuntimeError, "DETAILED_CAPTURE_STOP_PENDING"):
                    probe.set_detailed_capture(True)
                probe.stop()
                with self.assertRaisesRegex(RuntimeError, "DETAILED_CAPTURE_STOP_PENDING"):
                    probe.attach(os.getpid())
                with self.assertRaisesRegex(RuntimeError, "DETAILED_CAPTURE_STOP_PENDING"):
                    probe.start()
                release.set()
                self.assertTrue(cap.stop(timeout=5))
                self.assertEqual(summarize_detail(probe.session_folder)["status"], "STOPPED")
                probe.attach(os.getpid())
                self.assertIsNone(probe._pending_detailed)
            finally:
                release.set()
                if cap is not None:
                    cap.stop(timeout=5)
                if probe.active:
                    probe.stop()

    def test_unexpected_collector_exception_is_not_clean_stop(self):
        def failing_collector(pid, created):
            raise RuntimeError("unexpected internal collector fault")

        with tempfile.TemporaryDirectory() as directory:
            cap = DetailedCapture(Path(directory), os.getpid(), 1.0,
                                  time.monotonic_ns(), collector=failing_collector)
            cap.start()
            self.assertTrue(cap.stop(timeout=5))
            self.assertEqual(cap.status, "SENSOR_INTERNAL_FAILURE")
            self.assertEqual(cap.error, "RuntimeError")
            self.assertEqual(summarize_detail(Path(directory))["status"],
                             "SENSOR_INTERNAL_FAILURE")

    def test_qt_deep_control_is_optin_and_keeps_five_pages(self):
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
                self.assertFalse(window.detailed_capture_btn.isEnabled())
                window.probe.attach(os.getpid())
                window._start()
                self.assertTrue(window.detailed_capture_btn.isEnabled())
                window.detailed_capture_btn.click()
                self.assertIsNotNone(window.probe.detailed_capture)
                window._set_language("RU")
                self.assertIn("ВКЛ", window.detailed_capture_btn.text())
                window._stop()
                self.assertFalse(window.detailed_capture_btn.isEnabled())
            finally:
                window.close()


if __name__ == "__main__":
    unittest.main()
