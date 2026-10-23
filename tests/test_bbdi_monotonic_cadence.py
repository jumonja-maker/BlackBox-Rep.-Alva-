"""BB-DI-001 real sample-spacing and instrumented worker health slice.

Synthetic elapsed clocks are test-only; real Qt integration samples this
Python process with external psutil and persists unmodified schema1 samples.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from blackbox_core.contracts import ObserverError, Sample
from blackbox_core.report import summarize
from blackbox_core.sampling_health import BaseWorkerTiming, MonotonicSampleCadence
from blackbox_core.storage import SessionStore


def _sample(ms: int) -> Sample:
    return Sample(ms, 2048, 1.0, 1, 0, 0, 0)


def _drain(app, predicate, *, loops=350):
    for _ in range(loops):
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.006)
    return predicate()


class MonotonicCadenceTests(unittest.TestCase):
    def test_real_spacing_does_not_fabricate_missing_count(self):
        meter = MonotonicSampleCadence()
        self.assertIsNone(meter.preview(1000, 1000))
        meter.commit(1000, 1000, was_extended=False)
        self.assertIsNone(meter.preview(2000, 1000))
        meter.commit(2000, 1000, was_extended=False)
        event = meter.preview(4800, 1000)
        self.assertEqual(event["observed_spacing_ms"], 2800)
        self.assertEqual(event["threshold_ms"], 2000)
        self.assertIsNone(event["missing_sample_count"])
        self.assertEqual(event["verification_class"],
                         "DERIVED_ADJACENT_OS_COUNTER_SNAPSHOTS")
        # A preview never mutates the baseline until an event is durable.
        self.assertEqual(meter.previous_elapsed_ms, 2000)
        self.assertEqual(meter.extended_pairs, 0)
        meter.commit(4800, 1000, was_extended=True)
        self.assertEqual(meter.comparable_pairs, 2)
        self.assertEqual(meter.extended_pairs, 1)
        self.assertEqual(meter.max_observed_spacing_ms, 2800)

    def test_interval_change_does_not_claim_gap_or_missing_samples(self):
        meter = MonotonicSampleCadence()
        meter.commit(1000, 1000, was_extended=False)
        self.assertIsNone(meter.preview(9000, 5000))
        meter.commit(9000, 5000, was_extended=False)
        self.assertEqual(meter.interval_changes, 1)
        self.assertEqual(meter.comparable_pairs, 0)
        self.assertIsNone(meter.preview(14000, 5000))
        meter.commit(14000, 5000, was_extended=False)
        self.assertEqual(meter.comparable_pairs, 1)
        self.assertEqual(meter.extended_pairs, 0)

    def test_bad_clock_is_rejected_and_state_is_preserved(self):
        meter = MonotonicSampleCadence()
        meter.commit(5000, 1000, was_extended=False)
        for ms, interval in ((4000, 1000), (-1, 1000),
                             (float("nan"), 1000), (6000, 0)):
            with self.assertRaises(ValueError):
                meter.preview(ms, interval)
        self.assertEqual(meter.previous_elapsed_ms, 5000)
        self.assertEqual(meter.extended_pairs, 0)

    def test_worker_timing_monotonic_brackets_and_invalid_clock(self):
        health = BaseWorkerTiming()
        health.observe(started_ns=1_000_000_000,
                       sensor_done_ns=1_040_000_000,
                       write_done_ns=1_051_000_000,
                       received_ns=1_090_000_000)
        self.assertEqual(health.completed_workers, 1)
        self.assertEqual(health.max_sensor_ms, 40)
        self.assertEqual(health.max_sqlite_ms, 11)
        self.assertEqual(health.max_signal_delivery_ms, 39)
        self.assertEqual(health.event(MonotonicSampleCadence())["source"],
                         "PYTHON_MONOTONIC_BRACKETS")
        with self.assertRaisesRegex(ValueError, "INVALID_WORKER_TIMING"):
            health.observe(started_ns=100, sensor_done_ns=99,
                           write_done_ns=200, received_ns=300)
        self.assertEqual(health.completed_workers, 1)


class PersistedCadenceTests(unittest.TestCase):
    def test_true_sqlite_samples_keep_schema1_and_monotonic_gap_event(self):
        from blackbox_universal.monitor import ReadOnlyProbe
        with tempfile.TemporaryDirectory() as root:
            monitor = ReadOnlyProbe(output_root=Path(root), background_events=True)
            monitor.attach(os.getpid())
            monitor.start()
            try:
                def push(ms: int, seq: int, start: int):
                    # Existing schema1 sample is already durable before the
                    # Qt callback receives it. This tests the real wrapper.
                    sample = _sample(ms)
                    from blackbox_core.storage import write_sample_from_worker
                    self.assertEqual(write_sample_from_worker(
                        monitor.session_folder, sample), seq)
                    monitor.accept_background_sample(
                        sample, seq, requested_interval_ms=1000,
                        worker_timing={"started_ns": start,
                                       "sensor_done_ns": start + 40_000_000,
                                       "write_done_ns": start + 50_000_000},
                        received_ns=start + 60_000_000)

                push(1000, 1, 1_000_000_000)
                push(4300, 2, 5_000_000_000)
                self.assertEqual(monitor.snapshot()[
                    "extended_monotonic_spacing_pairs"], 1)
                self.assertEqual(monitor.snapshot()["completed_base_workers"], 2)
            finally:
                monitor.stop()
            report = summarize(monitor.session_folder)
            self.assertEqual(report["samples"], 2)
            self.assertEqual(report["extended_monotonic_spacing_count"], 1)
            self.assertEqual(report["max_extended_monotonic_spacing_ms"], 3300)
            self.assertEqual(report["sampling_gap_count"], 0)
            self.assertEqual(report["observed_busy_timer_callbacks"], 0)
            self.assertEqual(report["worker_health_summary"]["completed_workers"], 2)
            self.assertEqual(report["worker_health_summary"]["max_sensor_ms"], 40)
            self.assertEqual(report["worker_health_summary"]["max_sqlite_ms"], 10)
            self.assertEqual(report["worker_health_summary"]["max_signal_delivery_ms"], 10)
            self.assertEqual(report["invalid_worker_health_events"], 0)
            self.assertIn("Actual snapshot spacing",
                          (monitor.session_folder / "report.html").read_text("utf-8"))
            with closing(sqlite3.connect(monitor.session_folder / "session.sqlite3")) as db:
                self.assertEqual(db.execute(
                    "SELECT schema_version FROM metadata").fetchone()[0], 1)
                saved = [json.loads(x[0]) for x in db.execute(
                    "SELECT data FROM events")]
                self.assertEqual(len([r for r in saved if r.get("code") ==
                                      "EXTENDED_MONOTONIC_SAMPLE_SPACING"]), 1)

    def test_failure_to_persist_gap_cannot_advance_monitor_baseline(self):
        from blackbox_universal.monitor import ReadOnlyProbe
        with tempfile.TemporaryDirectory() as root:
            probe = ReadOnlyProbe(output_root=Path(root))
            probe.attach(os.getpid())
            probe.start()
            try:
                probe.accept_background_sample(
                    _sample(1000), 1, requested_interval_ms=1000)
                with patch.object(probe._store, "write_event",
                                  side_effect=ObserverError("STORAGE_ERROR", "storage")):
                    with self.assertRaises(ObserverError):
                        probe.accept_background_sample(
                            _sample(4100), 2, requested_interval_ms=1000)
                self.assertEqual(probe.total_samples, 1)
                self.assertEqual(probe._sample_cadence.previous_elapsed_ms, 1000)
            finally:
                probe.stop()

    def test_imported_malformed_gap_never_counts_as_valid(self):
        with tempfile.TemporaryDirectory() as root:
            db = SessionStore(Path(root), os.getpid())
            try:
                db.write_event({"kind": "sampling_gap",
                                "code": "EXTENDED_MONOTONIC_SAMPLE_SPACING",
                                "previous_elapsed_ms": 1000,
                                "current_elapsed_ms": 1100,
                                "observed_spacing_ms": 4000,
                                "configured_interval_ms": 1000,
                                "threshold_ms": 2000,
                                "source": "BLACKBOX_MONOTONIC_SAMPLE_CLOCK",
                                "verification_class":
                                "DERIVED_ADJACENT_OS_COUNTER_SNAPSHOTS"})
                db.finish("COMPLETED")
            finally:
                db.close()
            report = summarize(db.folder)
            self.assertEqual(report["extended_monotonic_spacing_count"], 0)
            self.assertEqual(report["invalid_monotonic_spacing_events"], 1)

    def test_gui_worker_saves_timing_summary_without_main_thread_sampling(self):
        from PySide6.QtWidgets import QApplication
        from blackbox_universal.window import UniversalWindow
        app = QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as root, patch(
                "blackbox_universal.monitor._default_sessions_root",
                return_value=Path(root)):
            window = UniversalWindow()
            window._timer.stop()
            try:
                window.probe.attach(os.getpid())
                window._start()
                with patch.object(window.probe, "tick",
                                  side_effect=AssertionError("GUI called sync tick")):
                    window._request_background_sample()
                    worker = window._base_sample_worker
                    self.assertIsNotNone(worker)
                    self.assertTrue(worker.wait(5000))
                    self.assertTrue(_drain(
                        app, lambda: window._base_sample_worker is None))
                self.assertEqual(window.probe.total_samples, 1)
                self.assertEqual(window.probe.snapshot()["completed_base_workers"], 1)
                window._stop()
                self.assertTrue(_drain(
                    app, lambda: window._report_worker is None))
                result = summarize(window.probe.session_folder)
                self.assertEqual(result["worker_health_summary"]["completed_workers"], 1)
                self.assertEqual(result["extended_monotonic_spacing_count"], 0)
            finally:
                self.assertTrue(_drain(
                    app, lambda: window._report_worker is None))
                window.close()


if __name__ == "__main__":
    unittest.main()
