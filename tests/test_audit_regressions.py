"""Regression checks for the 2026-10-23 full technical audit.

Tests exercise actual SQLite/HTML, missing OS metrics, rollback on failure,
and sequential background checks without requiring private Alva modules.
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
from PySide6.QtWidgets import QApplication

from blackbox_rep_alva.contracts import Sample, ObserverError
from blackbox_rep_alva.report import summarize, write_report
from blackbox_rep_alva.storage import SessionStore
from blackbox_universal.monitor import ReadOnlyProbe
from blackbox_universal.window import UniversalWindow


class AuditCoreRegressions(unittest.TestCase):
    def test_missing_metrics_stay_unknown_in_sqlite_snapshot_and_chart(self):
        with tempfile.TemporaryDirectory() as tmp:
            monitor = ReadOnlyProbe(Path(tmp))
            monitor.attach(os.getpid())
            monitor.start()
            unknown = Sample(elapsed_ms=100, rss_bytes=None, cpu_percent=None,
                             num_threads=None, read_bytes=None,
                             write_bytes=None, children_count=None)
            with patch.object(monitor._core, "sample", return_value=unknown):
                point = monitor.tick()
            self.assertIsNone(point["cpu_pct"])
            self.assertIsNone(point["rss_mb"])
            self.assertIsNone(point["process_count"])
            self.assertIsNone(point["thread_count"])
            self.assertIsNone(monitor.snapshot()["recent_samples"][0]["rss_mb"])
            folder = monitor.session_folder
            monitor.stop()
            with closing(sqlite3.connect(folder / "session.sqlite3")) as db:
                self.assertEqual(db.execute(
                    "SELECT rss_bytes, cpu_percent, children_count FROM samples"
                ).fetchone(), (None, None, None))
            self.assertIsNone(summarize(folder)["peak_rss_bytes"])

    def test_lifecycle_events_survive_into_sqlite_without_fake_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            probe = ReadOnlyProbe(Path(tmp))
            probe.attach(os.getpid())
            probe.start()
            probe.tick()
            probe.stop()
            with closing(sqlite3.connect(probe.session_folder / "session.sqlite3")) as db:
                rows = [json.loads(row[0]) for row in db.execute(
                    "SELECT data FROM events ORDER BY seq")]
            self.assertEqual(
                [x["code"] for x in rows if x["kind"] == "observer_lifecycle"],
                ["OBSERVATION_STARTED", "USER_STOPPED"])
            self.assertEqual(summarize(probe.session_folder)["observation_errors"], {})

    def test_alva_evidence_is_described_inside_normal_html(self):
        from blackbox_universal.platform_connector import _write_diagnostics
        with tempfile.TemporaryDirectory() as tmp:
            store = SessionStore(Path(tmp), os.getpid())
            folder = store.folder
            store.finish("COMPLETED")
            store.close()
            write_report(folder)
            result = {
                "status": "ok",
                "extended_diagnostics": {
                    "accepted_checks": 1, "declared_stages": 4,
                    "observed_pipeline_status": "error",
                    "first_unverified_component": "<unsupported>"}}
            overview = _write_diagnostics(result, folder, "evidence-checks.json")
            self.assertEqual(overview["reviewed_checks"], 1)
            html = (folder / "report.html").read_text(encoding="utf-8")
            self.assertIn("Requires review", html)
            self.assertIn("1/4", html)
            self.assertIn("&lt;unsupported&gt;", html)
            self.assertNotIn("<unsupported>", html)
            self.assertIn("root cause", html)

    def test_json_html_publication_rolls_back_if_second_replace_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SessionStore(Path(tmp), os.getpid())
            folder = store.folder
            store.finish("COMPLETED")
            store.close()
            real_replace = os.replace
            calls = [0]

            def replace_then_fail(source, destination):
                calls[0] += 1
                if calls[0] == 2:
                    raise OSError("simulated filesystem failure")
                return real_replace(source, destination)

            with patch("blackbox_rep_alva.report.os.replace",
                       side_effect=replace_then_fail):
                with self.assertRaises(ObserverError):
                    write_report(folder)
            self.assertFalse((folder / "report.json").exists())
            self.assertFalse((folder / "report.html").exists())
            self.assertFalse(list(folder.glob(".blackbox-report-*.tmp")))
            self.assertEqual(write_report(folder)["sample_count"], 0)


class AuditQtRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_two_fast_sessions_are_queued_and_stale_result_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("blackbox_universal.monitor._default_sessions_root",
                       return_value=Path(tmp)):
                window = UniversalWindow()
            window._timer.stop()
            try:
                s1, s2 = Path(tmp) / "one", Path(tmp) / "two"
                for session in (s1, s2):
                    session.mkdir()
                    (session / "report.json").write_text("{}", encoding="utf-8")
                window._alva_interpreter = ""
                window._alva_worker = object()  # first session still processing
                window._active_alva_session = s1
                window.probe.session_folder = s2
                window._set_evidence_status("saved")
                with patch("blackbox_universal.window.bundled_runtime_available",
                           return_value=True):
                    window._finalize_alva_if_configured()
                self.assertEqual(len(window._alva_queue), 1)
                window._private_diagnostics_result(
                    {"status": "ok", "reviewed_checks": 4,
                     "declared_checks": 4, "evidence_status": "ok"}, "")
                self.assertEqual(window._evidence_status[0], "saved")
                self.assertEqual(window._alva_results_by_session[s1]["status"], "ok")
                with patch.object(window, "_start_alva_worker") as launch:
                    window._alva_finished()
                    launch.assert_called_once_with(None, s2, persist=True)
                self.assertFalse(window._alva_queue)
            finally:
                window._alva_worker = None
                window.close()

    def test_chart_and_cards_do_not_crash_on_missing_values(self):
        with patch("blackbox_universal.monitor._default_sessions_root",
                   return_value=Path(tempfile.gettempdir())):
            window = UniversalWindow()
        window._timer.stop()
        try:
            window.probe.history.append({
                "seconds": 1, "cpu_pct": None, "rss_mb": None,
                "process_count": None, "thread_count": None})
            window._update_all()
            self.assertEqual(window.card_cpu.value.text(), "—")
            self.assertEqual(window.card_ram.value.text(), "—")
            self.assertEqual(window.card_child.value.text(), "—")
            self.assertIsNone(window.chart._cpu[-1])
        finally:
            window.close()


if __name__ == "__main__":
    unittest.main()
