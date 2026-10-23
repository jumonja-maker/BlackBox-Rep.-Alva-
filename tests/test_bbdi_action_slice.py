"""BB-DI-001 narrow, real action-capture slice; NOT full feature acceptance."""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from blackbox_core.actions import ActionCycle, ActionError
from blackbox_universal.monitor import ReadOnlyProbe
from blackbox_core.report import summarize


class ActionClockTests(unittest.TestCase):
    def setUp(self):
        self.ns = [10_000_000_000]
        self.events = []
        self.action = ActionCycle(clock=lambda: self.ns[0],
                                  baseline_ms=5000, cool_down_ms=1000)

    def test_baseline_real_command_times_and_full_state_machine(self):
        self.assertEqual(self.action.state, "IDLE")
        prepared = self.action.prepare(self.events.append)
        self.assertEqual(prepared["state"], "ARMED")
        self.assertEqual(self.action.advance(self.events.append)["state"], "BASELINE")
        with self.assertRaisesRegex(ActionError, "BASELINE_NOT_READY"):
            self.action.begin(self.events.append)
        self.assertFalse(self.action.ready_to_start())
        self.ns[0] += 5_000_000_000
        self.assertTrue(self.action.ready_to_start())
        started = self.action.begin(self.events.append)
        self.assertEqual(started["timestamp_monotonic_ns"], 15_000_000_000)
        self.assertEqual(started["source"], "USER_COMMAND_UNVERIFIED")
        self.ns[0] += 312_000_000
        ended = self.action.finish(self.events.append)
        self.assertEqual(ended["duration_ns"], 312_000_000)
        self.assertEqual(self.action.state, "COOL_DOWN")
        self.assertIsNone(self.action.advance(self.events.append))
        self.ns[0] += 1_000_000_000
        completed = self.action.advance(self.events.append)
        self.assertEqual(completed["state"], "COMPLETED")
        self.assertEqual(self.action.completed[0]["duration_ns"], 312_000_000)
        next_action = self.action.prepare(self.events.append)
        self.assertNotEqual(prepared["action_id"], next_action["action_id"])
        self.assertEqual(len(self.events), 6)

    def test_failed_event_write_leaves_no_ghost_transition(self):
        def fail(_):
            raise OSError("disk is full")
        with self.assertRaises(OSError):
            self.action.prepare(fail)
        self.assertEqual(self.action.state, "IDLE")
        self.action.prepare(self.events.append)
        with self.assertRaises(OSError):
            self.action.advance(fail)
        self.assertEqual(self.action.state, "ARMED")
        self.action.advance(self.events.append)
        self.ns[0] += 5_000_000_000
        with self.assertRaises(OSError):
            self.action.begin(fail)
        self.assertEqual(self.action.state, "BASELINE")

    def test_stop_preserves_explicit_abort_not_fake_completion(self):
        self.action.prepare(self.events.append)
        self.action.abort(self.events.append)
        self.assertEqual(self.action.state, "ABORTED")
        self.assertEqual(self.events[-1]["event"], "ACTION_ABORTED")
        self.assertEqual(self.action.completed, [])
        self.assertIsNone(self.action.abort(self.events.append))

    def test_monotonic_clock_reversal_is_rejected(self):
        self.action.prepare(self.events.append)
        self.ns[0] -= 1
        with self.assertRaisesRegex(ActionError, "INVALID_MONOTONIC_CLOCK"):
            self.action.advance(self.events.append)
        self.assertEqual(self.action.state, "ARMED")


class DurableActionTests(unittest.TestCase):
    def test_real_sqlite_action_markers_roundtrip_without_changing_schema_one(self):
        with tempfile.TemporaryDirectory() as temp:
            probe = ReadOnlyProbe(output_root=Path(temp))
            probe.attach(os.getpid())
            probe.start()
            probe.tick()
            probe.prepare_action(baseline_ms=0)
            self.assertEqual(probe.actions.state, "ARMED")
            probe.tick()
            started = probe.begin_action()
            ended = probe.finish_action()
            self.assertGreaterEqual(ended["timestamp_monotonic_ns"], started["timestamp_monotonic_ns"])
            probe.actions.cool_down_ms = 0
            probe.tick()
            self.assertEqual(probe.actions.state, "COMPLETED")
            probe.stop()
            with closing(sqlite3.connect(probe.session_folder / "session.sqlite3")) as db:
                version = db.execute("SELECT schema_version FROM metadata").fetchone()[0]
                entries = [json.loads(row[0]) for row in db.execute(
                    "SELECT data FROM events ORDER BY seq")]
            events = [x for x in entries if x.get("kind") == "action_marker"]
            self.assertEqual(version, 1)
            self.assertEqual([x["event"] for x in events],
                             ["ACTION_PREPARED", "BASELINE_STARTED", "ACTION_STARTED",
                              "ACTION_ENDED", "ACTION_COMPLETED"])
            self.assertEqual(len({x["action_id"] for x in events}), 1)
            self.assertTrue(all(x["source"] == "USER_COMMAND_UNVERIFIED" for x in events))
            self.assertTrue(all(type(x["session_elapsed_ms"]) is int for x in events))
            self.assertTrue(all(x["pid"] == os.getpid() for x in events))
            self.assertEqual(summarize(probe.session_folder)["observation_errors"], {})
            self.assertTrue((probe.session_folder / "report.json").is_file())

    def test_stop_of_unfinished_action_persists_abort(self):
        with tempfile.TemporaryDirectory() as temp:
            probe = ReadOnlyProbe(output_root=Path(temp))
            probe.attach(os.getpid())
            probe.start()
            probe.prepare_action(baseline_ms=0)
            probe.stop()
            with closing(sqlite3.connect(probe.session_folder / "session.sqlite3")) as db:
                events = [json.loads(row[0]) for row in db.execute("SELECT data FROM events")]
            self.assertEqual([x["event"] for x in events if x.get("kind") == "action_marker"],
                             ["ACTION_PREPARED", "ACTION_ABORTED"])


    def test_user_problem_between_samples_uses_command_timestamp_not_previous_sample(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            probe = ReadOnlyProbe(output_root=Path(temp))
            probe.attach(os.getpid())
            probe.start()
            probe.tick()
            previous = probe.last_elapsed_ms
            now = probe._recording_origin_ns + (previous + 250) * 1_000_000
            with patch("blackbox_universal.monitor.time.monotonic_ns", return_value=now):
                when = probe.mark_problem("delayed window")
            self.assertEqual(when, previous + 250)
            probe.stop()
            with closing(sqlite3.connect(probe.session_folder / "session.sqlite3")) as db:
                rows = [json.loads(row[0]) for row in db.execute("SELECT data FROM events")]
            mark = next(x for x in rows if x.get("kind") == "user_problem")
            self.assertEqual(mark["elapsed_ms"], previous + 250)
            self.assertEqual(mark["previous_sample_elapsed_ms"], previous)
            self.assertEqual(mark["timestamp_precision"], "COMMAND_MONOTONIC_NS")
            self.assertIsNone(mark["nearest_sample_id"])
            self.assertEqual(mark["source"], "USER")


class QtActionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PySide6.QtWidgets import QApplication
        cls.application = QApplication.instance() or QApplication([])

    def test_five_pages_with_real_action_buttons_and_ru_en(self):
        from unittest.mock import patch
        from blackbox_universal.window import UniversalWindow
        with tempfile.TemporaryDirectory() as temp, patch(
                "blackbox_universal.monitor._default_sessions_root", return_value=Path(temp)):
            window = UniversalWindow()
            window._timer.stop()
            try:
                self.assertEqual(window.stack.count(), 5)
                self.assertFalse(window.action_begin_btn.isEnabled())
                window.probe.attach(os.getpid())
                window._start()
                window._tick()
                self.assertTrue(window.action_prepare_btn.isEnabled())
                window._prepare_action()
                self.assertIn(window.probe.actions.state, ("ARMED", "BASELINE"))
                window._set_language("RU")
                self.assertIn("НАЧАТЬ", window.action_begin_btn.text())
                window._set_language("EN")
                self.assertIn("BEGIN", window.action_begin_btn.text())
                window._stop()
                self.assertFalse(window.action_end_btn.isEnabled())
            finally:
                window.close()


if __name__ == "__main__":
    unittest.main()
