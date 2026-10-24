"""Independent BB-DI-001 experiment-slice regression suite.

Partial implementation only; these tests are NOT evidence of full M-021/22.
"""
from __future__ import annotations
from contextlib import closing

import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from blackbox_core.actions import ActionCycle
from blackbox_core.experiments import ExperimentAccumulator, compare_experiments
from blackbox_core.report import summarize
from blackbox_universal.monitor import ReadOnlyProbe


def event(experiment_id: str, action_id: str, duration_ms: int) -> dict:
    return {"kind": "action_marker", "event": "ACTION_COMPLETED",
            "experiment_id": experiment_id, "action_id": action_id,
            "duration_ns": duration_ms * 1_000_000,
            "source": "USER_COMMAND_UNVERIFIED"}


class ExperimentStatisticsTests(unittest.TestCase):
    def test_deterministic_median_p95_and_mad(self):
        acc = ExperimentAccumulator()
        for i, value in enumerate((100, 200, 300, 400, 500)):
            acc.observe(event("a"*32, f"{i:032x}", value))
        result = acc.result()
        self.assertEqual(len(result["experiments"]), 1)
        exp = result["experiments"][0]
        self.assertEqual(exp["repeats"], 5)
        self.assertEqual(exp["duration_ms"], {
            "minimum": 100.0, "median": 300.0, "p95": 480.0,
            "maximum": 500.0, "mad": 100.0})
        self.assertEqual(exp["warnings"], [])
        self.assertFalse(result["root_cause_proven"])

    def test_duplicate_malformed_and_overflow_explicit(self):
        acc = ExperimentAccumulator()
        for i in range(30):
            acc.observe(event("a"*32, f"{i:032x}", 100 + i))
        acc.observe(event("a"*32, "0"*32, 200))
        acc.observe(event("not-valid", "b"*32, 100))
        data = acc.result()
        self.assertEqual(data["invalid_completed_markers"], 1)
        exp = data["experiments"][0]
        self.assertEqual(exp["repeats"], 20)
        self.assertEqual(exp["actions_omitted"], 10)
        self.assertEqual(exp["duplicate_markers_ignored"], 1)
        self.assertIn("PARTIAL_COVERAGE", exp["warnings"])
        self.assertEqual(len(exp["duration_ms"]), 5)

    def test_conservative_comparison(self):
        def make(v):
            acc = ExperimentAccumulator()
            for i, duration in enumerate(v):
                acc.observe(event("a"*32, f"{i:032x}", duration))
            return acc.result()["experiments"][0]
        before = make([100, 100, 100, 100])
        after = make([80, 80, 80, 80])
        comparison = compare_experiments(before, after)
        self.assertEqual(comparison["delta_median_ms"], -20)
        self.assertEqual(comparison["relative_change_percent"], -20)
        self.assertIn("INSUFFICIENT_REPEATS", comparison["warnings"])
        self.assertIn("INCOMPARABLE_CONFIG_NOT_VERIFIED", comparison["warnings"])
        self.assertFalse(comparison["speedup_proven"])

    def test_invalid_comparison_payload_fails(self):
        with self.assertRaisesRegex(ValueError, "INVALID_EXPERIMENT"):
            compare_experiments({"repeats": True}, {})


class RealSessionExperimentTests(unittest.TestCase):
    def test_two_repeats_persist_same_experiment_id_in_sqlite_and_reports(self):
        with tempfile.TemporaryDirectory() as path:
            probe = ReadOnlyProbe(output_root=Path(path))
            probe.attach(os.getpid())
            probe.start()
            probe.actions.cool_down_ms = 0
            try:
                probe.tick()
                for _ in range(2):
                    probe.prepare_action(baseline_ms=0)
                    probe.tick()  # ARMED -> BASELINE
                    probe.begin_action()
                    probe.finish_action()
                    probe.tick()  # complete from COOL_DOWN
                self.assertEqual(probe.actions.state, "COMPLETED")
                self.assertEqual(len(probe.actions.completed), 2)
                ids = {row["experiment_id"] for row in probe.actions.completed}
                self.assertEqual(len(ids), 1)
            finally:
                probe.stop()
            with closing(sqlite3.connect(probe.session_folder / "session.sqlite3")) as db:
                events = [json.loads(row[0]) for row in db.execute(
                    "SELECT data FROM events ORDER BY seq")]
            completed = [row for row in events if row.get("event") == "ACTION_COMPLETED"]
            self.assertEqual(len(completed), 2)
            self.assertEqual({row["experiment_id"] for row in completed}, ids)
            report = summarize(probe.session_folder)
            groups = report["experiment_summary"]["experiments"]
            self.assertEqual(len(groups), 1)
            self.assertEqual(groups[0]["repeats"], 2)
            self.assertEqual(groups[0]["warnings"], [])
            self.assertEqual(report["observation_errors"], {})
            html = (probe.session_folder / "report.html").read_text(encoding="utf-8")
            self.assertIn("Repeat experiments", html)
            self.assertIn("Median ms", html)
            self.assertIn("not", html.lower())


if __name__ == "__main__":
    unittest.main()
