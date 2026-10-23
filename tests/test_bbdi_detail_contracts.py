"""BB-DI-001 additive detail schema2 provenance, clock, and atomicity.

Synthetic sample dictionaries are ONLY test fixtures; runtime records come
from the selected process through opt-in PSUTIL collection.
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

from blackbox_core.detail_contracts import (
    ClockAnchor, capture_clock_anchor, read_provenance, sample_field_statuses,
)
from blackbox_core.detailed_capture import DetailedCapture, summarize_detail
from blackbox_universal.monitor import ReadOnlyProbe


def _synthetic_process_snapshot(pid, created):
    return {
        "time_ns": time.monotonic_ns(), "sampling_duration_ns": 10,
        "pid": pid, "created": created,
        "rss_bytes": 200, "private_bytes": None, "uss_bytes": None,
        "handle_count": None, "cpu_user_s": 0.0, "cpu_system_s": 0.0,
        "thread_count": 1, "read_bytes": 0, "write_bytes": 0,
        "read_ops": 0, "write_ops": 0, "threads_omitted": 0,
        "children_total": 0, "children_omitted": 0, "thread_status": "OK",
        "threads": [{"tid": 1, "cpu_user_s": 0.0, "cpu_system_s": 0.0}],
        "children": [],
        "sensor_status": {
            "rss_bytes": "OK", "private_bytes": "ACCESS_DENIED",
            "uss_bytes": "UNSUPPORTED", "handle_count": "UNSUPPORTED",
            "io": "OK", "threads": "OK", "children": "OK",
        },
    }


class ClockAndStatusContractTests(unittest.TestCase):
    def test_clock_anchor_preserves_nanoseconds_without_faking_precision(self):
        anchor = ClockAnchor(100, 1_700_000_000_123_456_789, 44)
        self.assertEqual(anchor.estimate_utc_ns(210),
                         1_700_000_000_123_456_899)
        result = anchor.as_dict()
        self.assertTrue(result["utc_anchor_iso"].endswith(".123456789Z"))
        self.assertEqual(result["quality"], "ESTIMATED_WALL_CLOCK")
        self.assertIn("SYSTEM_CLOCK_CAN_ADJUST", result["warning"])
        with self.assertRaisesRegex(ValueError, "INVALID_CLOCK_ANCHOR"):
            ClockAnchor(-1, 1, 0)
        with self.assertRaisesRegex(ValueError, "INVALID_MONOTONIC_TIMESTAMP"):
            anchor.estimate_utc_ns(-1)
        live = capture_clock_anchor()
        self.assertGreater(live.utc_ns, 0)
        self.assertGreaterEqual(live.uncertainty_ns, 0)

    def test_zero_is_observed_but_null_is_a_reasoned_missing_value(self):
        fields = sample_field_statuses(_synthetic_process_snapshot(77, 2.0))
        self.assertEqual(fields["io_status"], "OK")  # genuine zero I/O
        self.assertEqual(fields["rss_status"], "OK")
        self.assertEqual(fields["private_status"], "ACCESS_DENIED")
        self.assertEqual(fields["uss_status"], "UNSUPPORTED")
        self.assertEqual(fields["handle_status"], "UNSUPPORTED")

    def test_status_cannot_disguise_missing_as_os_observed(self):
        x = _synthetic_process_snapshot(77, 2.0)
        x["sensor_status"]["private_bytes"] = "OK"
        with self.assertRaisesRegex(ValueError, "INCONSISTENT_SENSOR_STATUS"):
            sample_field_statuses(x)
        x["sensor_status"]["private_bytes"] = "ACCESS_DENIED"
        x["private_bytes"] = 0
        with self.assertRaisesRegex(ValueError, "INCONSISTENT_SENSOR_STATUS"):
            sample_field_statuses(x)
        x["private_bytes"] = None
        x["sensor_status"]["private_bytes"] = "USER_DECLARED"
        with self.assertRaisesRegex(ValueError, "INVALID_SENSOR_STATUS"):
            sample_field_statuses(x)

    def test_legacy_detail_contract_is_not_fabricated(self):
        with closing(sqlite3.connect(":memory:")) as db:
            existing = read_provenance(db)
            self.assertEqual(existing["contract_status"],
                             "LEGACY_DETAIL_V2_NO_PROVENANCE")
            self.assertIsNone(existing["clock_mapping"])
            self.assertEqual(existing["quality_samples"], 0)


class PersistedDetailContractTests(unittest.TestCase):
    def test_new_detail_sidecar_persists_clock_capabilities_and_qualities(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            origin = time.monotonic_ns()
            cap = DetailedCapture(folder, os.getpid(), 1.0, origin,
                                  interval_s=0.5, max_samples=1,
                                  collector=_synthetic_process_snapshot)
            cap.start()
            cap.thread.join(5)
            self.assertFalse(cap.thread.is_alive())
            self.assertEqual(cap.status, "CAPTURE_LIMIT_REACHED")
            summary = summarize_detail(folder)
            self.assertEqual(summary["samples"], 1)
            self.assertEqual(summary["schema_version"], 2)
            evidence = summary["provenance"]
            self.assertEqual(evidence["contract_status"], "OK")
            self.assertEqual(evidence["quality_samples"], 1)
            self.assertEqual(len(evidence["capabilities"]), 7)
            self.assertEqual(evidence["latest_quality"]["measurement_status"]
                             ["private_status"], "ACCESS_DENIED")
            self.assertEqual(evidence["latest_quality"]["measurement_status"]
                             ["io_status"], "OK")
            clock = evidence["clock_mapping"]
            self.assertEqual(clock["quality"], "ESTIMATED_WALL_CLOCK")
            self.assertGreater(clock["utc_anchor_ns"], 0)
            self.assertTrue(clock["utc_anchor_iso"].endswith("Z"))
            with closing(sqlite3.connect(folder / "detail-v2.sqlite3")) as db:
                self.assertEqual(db.execute(
                    "SELECT count(*) FROM detail_sample_quality").fetchone()[0], 1)
                self.assertEqual(db.execute(
                    "SELECT count(*) FROM process_samples").fetchone()[0], 1)

    def test_failed_generator_rolls_back_process_and_thread_rows(self):
        def malformed(pid, created):
            record = _synthetic_process_snapshot(pid, created)
            record["threads"] = [{"tid": 1, "cpu_user_s": 0.5}]
            return record

        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            cap = DetailedCapture(folder, os.getpid(), 1.0,
                                  time.monotonic_ns(), interval_s=0.5,
                                  collector=malformed)
            cap.start()
            for _ in range(80):
                if cap.error is not None:
                    break
                time.sleep(0.025)
            self.assertEqual(cap.error, "SENSOR_DATA_INVALID")
            self.assertTrue(cap.stop(5))
            with closing(sqlite3.connect(cap.path)) as db:
                for table in ("process_samples", "thread_samples",
                              "detail_sample_quality"):
                    self.assertEqual(db.execute(
                        "SELECT count(*) FROM " + table).fetchone()[0], 0)
                self.assertGreaterEqual(db.execute(
                    "SELECT count(*) FROM sensor_errors").fetchone()[0], 1)

    def test_original_schema1_and_html_report_still_work(self):
        with tempfile.TemporaryDirectory() as root:
            probe = ReadOnlyProbe(output_root=Path(root))
            probe.attach(os.getpid())
            probe.start()
            try:
                probe.tick()
                probe.set_detailed_capture(True)
                cap = probe.detailed_capture
                for _ in range(100):
                    if cap.samples > 0:
                        break
                    time.sleep(0.03)
                self.assertGreater(cap.samples, 0, cap.error)
            finally:
                probe.stop()
            folder = probe.session_folder
            with closing(sqlite3.connect(folder / "session.sqlite3")) as db:
                self.assertEqual(db.execute(
                    "SELECT schema_version FROM metadata LIMIT 1").fetchone()[0], 1)
            report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["detailed_capture"]["provenance"]
                             ["contract_status"], "OK")
            html = (folder / "report.html").read_text(encoding="utf-8")
            self.assertIn("Timestamp and measurement quality", html)
            self.assertIn("OS-observed metrics do not prove", html)


if __name__ == "__main__":
    unittest.main()
