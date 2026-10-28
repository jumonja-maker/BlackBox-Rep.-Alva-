"""End-to-end Investigation 0.1.2 handoff into BLACK.BOX Qt and SQLite.

No external service, subprocess, fake hang witness, or original report rewrite.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication

from blackbox_core.storage import SessionStore
from blackbox_core.contracts import Sample
from blackbox_universal.investigation_worker import (
    InvestigationWorker, latest_bounded_interval, read_user_markers)
from blackbox_universal.investigation_view import (
    finding_details, summary_text, title)
from blackbox_universal.monitor import ReadOnlyProbe
from blackbox_universal.window import UniversalWindow


class InvestigationIntegrationTests(unittest.TestCase):
    def make_session(self, root: Path) -> Path:
        """Real, fully closed SQLite fixture with bounded Windows QA cleanup.

        On loaded Windows CI a fresh FULL-synchronous v2 writer can take longer
        than the *production* five-second stop barrier. Only this disposable
        fixture extends that wait; the actual writer, commit and v1/v2
        completion verification are unchanged. Never fake committed rows.
        """
        observer = ReadOnlyProbe(root)
        observer.attach(os.getpid())
        observer.start()
        writer = observer._store.v2
        real_finish = writer.finish

        def finish_for_qa(code, *, timeout=5.0):
            return real_finish(code, timeout=max(timeout, 45.0))

        try:
            for _ in range(4):
                time.sleep(0.012)
                observer.tick()
            observer.mark_problem("Settings dialog took too long")
            with patch.object(writer, "finish", finish_for_qa):
                observer.stop()
            self.assertFalse(writer.thread.is_alive(), "QA_V2_WRITER_NOT_REAPED")
            self.assertIsNone(writer.failure, "QA_V2_WRITER_FAILED")
            self.assertEqual(
                observer.session_state, "COMPLETED",
                "QA_SESSION_NOT_DURABLY_COMPLETED: " +
                str(observer.last_error or writer.failure))
            return observer.session_folder
        finally:
            # TemporaryDirectory must never remove an actively-owned Windows
            # SQLite DB. A real failure still fails assertions; do not ignore
            # WinError 32, abandon a writer, or manufacture completion.
            if observer.active:
                with patch.object(writer, "finish", finish_for_qa):
                    observer.stop("UI_CLOSED", defer_report=True)
            if writer.thread.is_alive():
                writer.thread.join(timeout=60.0)
            self.assertFalse(writer.thread.is_alive(),
                             "QA_V2_SQLITE_OWNER_STILL_ACTIVE_AT_CLEANUP")

    def test_real_user_marker_and_worker_exports_are_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = self.make_session(Path(directory))
            db = folder / "session.sqlite3"
            old_report = folder / "report.html"
            original_hash = {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (db, old_report, folder / "report.json")
            }
            markers = read_user_markers(folder)
            self.assertEqual(len(markers), 1)
            self.assertEqual(markers[0]["kind"], "user_problem")
            self.assertEqual(markers[0]["source"], "USER")
            self.assertNotIn("EXTERNAL_OS_OBSERVATION", json.dumps(markers))
            worker = InvestigationWorker(folder, "RU")
            packets = []
            worker.result_ready.connect(lambda payload, error: packets.append((payload, error)))
            # Synchronous call to avoid requiring an event loop for this core test.
            worker.run()
            self.assertEqual(len(packets), 1)
            payload, error = packets[0]
            self.assertEqual(error, "")
            report = payload["result"]
            self.assertEqual(report["schema_version"], 2)
            self.assertEqual(report["markers"][0]["source"], "USER")
            self.assertEqual(report["claims"]["internal_root_cause"], "UNKNOWN")
            self.assertEqual(report["coverage"]["omitted_samples"], 0)
            self.assertTrue(Path(payload["html"]).is_file())
            self.assertIn("Расследование BLACK.BOX",
                          Path(payload["html"]).read_text(encoding="utf-8"))
            self.assertTrue(Path(payload["json"]).is_file())
            for name, previous in original_hash.items():
                self.assertEqual(hashlib.sha256((folder / name).read_bytes()).hexdigest(),
                                 previous, f"Original file modified: {name}")

    def test_latest_interval_for_bounded_session(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = self.make_session(Path(directory))
            lo, hi, total = latest_bounded_interval(folder)
            self.assertLessEqual(lo, hi)
            self.assertEqual(total, 4)

    def test_bilingual_evidence_is_never_promoted_to_proven_cause(self):
        candidate = {
            "code": "MEMORY_GROWTH_CANDIDATE",
            "start_ms": 1000, "end_ms": 4000,
            "interpretation": "CANDIDATE_NOT_CAUSAL_PROOF",
            "facts": [{"metric": "rss_bytes", "growth_bytes": 5000}],
            "limitation": "Memory growth is not proof of a leak; repeat equivalent operations and inspect allocations.",
        }
        self.assertIn("не доказанная причина", finding_details(candidate, "RU"))
        self.assertIn("not a proven root cause", finding_details(candidate, "EN"))
        self.assertIn("рост памяти", title("MEMORY_GROWTH_CANDIDATE", "RU"))
        report = {"findings": [candidate], "coverage": {
            "total_samples": 5000, "selected_samples": 4096,
            "omitted_samples": 904, "full_session_covered": False}}
        self.assertIn("частичный интервал", summary_text(report, "RU"))
        self.assertIn("Partial interval", summary_text(report, "EN"))


class InvestigationQtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root_patcher = patch("blackbox_universal.monitor._default_sessions_root",
                                  return_value=Path(self.temp.name))
        self.root_patcher.start()
        self.window = UniversalWindow()
        self.window._timer.stop()

    def tearDown(self):
        for _ in range(500):
            self.app.processEvents()
            if (self.window._report_worker is None and
                    self.window._base_sample_worker is None):
                break
            __import__("time").sleep(0.01)
        self.assertIsNone(self.window._report_worker)
        self.window.close()
        self.app.processEvents()
        self.root_patcher.stop()
        self.temp.cleanup()

    def test_exactly_five_pages_with_investigation_tables_and_controls(self):
        self.assertEqual(self.window.stack.count(), 5)
        self.assertEqual(len(self.window.PAGES), 5)
        self.assertEqual(self.window.investigation_table.objectName(), "investigationFindings")
        self.assertEqual(self.window.event_investigation_table.objectName(),
                         "eventInvestigationFindings")
        self.assertFalse(self.window.mark_problem_btn.isEnabled())
        self.assertFalse(self.window.investigate_current_btn.isEnabled())

    def test_mark_problem_is_disabled_until_real_sample_and_saved_to_sqlite(self):
        self.window.probe.attach(os.getpid())
        self.window._start()
        self.assertFalse(self.window.mark_problem_btn.isEnabled())
        self.window._tick()
        self.assertTrue(self.window.mark_problem_btn.isEnabled())
        with patch("blackbox_universal.window.QInputDialog.getText",
                   return_value=("Window delayed", True)):
            self.window._mark_problem()
        self.window._stop()
        for _ in range(500):
            self.app.processEvents()
            if self.window._report_worker is None:
                break
            __import__("time").sleep(0.01)
        self.assertIsNone(self.window._report_worker)
        markers = read_user_markers(self.window.probe.session_folder)
        self.assertEqual(len(markers), 1)
        self.assertEqual(markers[0]["note"], "Window delayed")
        self.assertTrue(self.window.investigate_current_btn.isEnabled())

    def test_visual_findings_survive_page_switches_and_translate(self):
        finding = {"code": "HIGH_IO_RATE", "start_ms": 1300, "end_ms": 1300,
                   "interpretation": "CANDIDATE_NOT_CAUSAL_PROOF",
                   "facts": [{"metric": "read_bps", "bytes_per_second": 2000000}],
                   "limitation": "Byte throughput does not reveal operation latency, path or responsible code."}
        self.window._investigation_result = {
            "schema_version": 2, "findings": [finding],
            "coverage": {"total_samples": 22, "selected_samples": 22,
                         "omitted_samples": 0, "full_session_covered": True},
            "warnings": [], "claims": {"internal_root_cause": "UNKNOWN"}}
        self.window._render_investigation_findings()
        self.assertEqual(self.window.investigation_table.rowCount(), 1)
        self.assertEqual(self.window.event_investigation_table.rowCount(), 1)
        self.window._navigate("reports")
        self.assertEqual(self.window.investigation_table.item(0, 0).text(), "1.30 s")
        self.window.investigation_table.selectRow(0)
        self.assertIn("не доказанная причина",
                      self.window.investigation_details.toPlainText())
        self.window._set_language("RU")
        self.assertIn("Высокая скорость", self.window.investigation_table.item(0, 1).text())
        self.assertIn("не установлена", self.window.investigation_summary.text())
        self.window._navigate("events")
        self.assertEqual(self.window.event_investigation_table.rowCount(), 1)


if __name__ == "__main__":
    unittest.main()
