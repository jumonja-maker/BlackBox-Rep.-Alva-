"""Deterministic audit regressions: visible but false-looking diagnostic results.

All SQLite sources in these tests are explicitly synthetic. No process is
killed or attached, and no OS performance event is treated as attestation.
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
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from blackbox_core.event_stream import event_page
from blackbox_core.interval_report import export_interval
from blackbox_core.process_tree import resource_tree_page
from blackbox_core.session_v2 import SessionV2Writer, FILENAME
from blackbox_core.session_view import SessionView
from blackbox_universal.monitor import available_processes


def synthetic_session(folder, *, samples=(), events=(), detailed=()):
    origin = time.monotonic_ns()
    pid, created = os.getpid(), time.time()
    writer = SessionV2Writer(folder, pid=pid, created=created,
                             name="SYNTHETIC_AUDIT_ONLY", origin_ns=origin)
    for ordinal, item in enumerate(samples, 1):
        second, period, cpu = item
        writer.submit("base", {
            "time_ns": origin + second * 1_000_000_000,
            "pid": pid, "created": created,
            "requested_interval_ns": period * 1_000_000_000,
            "cpu_user_s": float(cpu), "cpu_system_s": 0.,
            "rss_bytes": None,
            "correlation_key": f"audit:{ordinal}"})
    for ordinal, item in enumerate(detailed, 1):
        second, cpu = item
        writer.submit("detail", {
            "time_ns": origin + second * 1_000_000_000,
            "pid": pid, "created": created,
            "requested_interval_ns": 1_000_000_000,
            "cpu_user_s": cpu, "cpu_system_s": 0.,
            "rss_bytes": 4096,
            "thread_capture_status": "OK",
            "threads": [{"tid": 987654, "cpu_user_s": cpu,
                         "cpu_system_s": 0.}],
            "correlation_key": f"detail-audit:{ordinal}"})
    for ordinal, code in enumerate(events):
        writer.submit("event", {
            "kind": "observer_error", "code": code,
            "_recorded_ns": origin + (ordinal+1)*1_000_000_000})
    writer.finish("COMPLETED", timeout=25)
    return origin, pid, created


class DiagnosticTruthRegressions(unittest.TestCase):
    def test_status_rows_cannot_claim_complete_with_no_samples_or_missing_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            synthetic_session(folder)
            with SessionView.open(folder) as view:
                result = view.interval(series="STANDARD")
            self.assertEqual(result["coverage"]["selected_samples"], 0)
            self.assertEqual(result["coverage"]["quality_contract"], "NO_SAMPLES")
            self.assertEqual(result["coverage"]["actually_observed_metric_values"], 0)
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            synthetic_session(folder, samples=[(1, 1, 0.)])
            with SessionView.open(folder) as view:
                result = view.interval(series="STANDARD")
            self.assertEqual(result["coverage"]["selected_samples"], 1)
            # CPU cumulative clock is observed, RSS/IO/etc are not.
            self.assertEqual(result["coverage"]["quality_contract"],
                             "PARTIAL_METRIC_FIELDS_OBSERVED")
            self.assertGreater(result["coverage"]["unavailable_metric_values"], 0)
            with closing(sqlite3.connect(folder / FILENAME)) as db:
                db.execute("UPDATE measurements_quality SET measurement_status='OK' "
                           "WHERE metric='rss_bytes'")
                db.commit()
            with SessionView.open(folder) as view:
                corrupted = view.interval(series="STANDARD")
            self.assertEqual(corrupted["coverage"]["quality_contract"],
                             "QUALITY_STATUS_INCONSISTENT_OR_MISSING")

    def test_interval_export_without_identifiers_has_no_root_pid_or_tids(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            origin, pid, created = synthetic_session(
                folder, detailed=[(1, 0.), (2, .3)])
            packet = export_interval(folder, folder, prefix="audit-anonymous",
                                     include_identifiers=False, include_notes=False)
            report = json.loads((folder / "audit-anonymous.json").read_text(encoding="utf-8"))
            self.assertIs(report["privacy"]["process_identifiers_included"], False)
            self.assertEqual(report["thread_cpu_analysis"]["status"], "OK")
            self.assertNotIn("pid", report["thread_cpu_analysis"])
            self.assertNotIn("creation_time", report["thread_cpu_analysis"])
            self.assertNotIn("instance_id", report["thread_cpu_analysis"])
            for row in report["thread_cpu_analysis"]["top_threads"]:
                self.assertNotIn("tid", row)
                self.assertNotIn("pid", row)
            self.assertNotIn("pid", report["metadata"])
            self.assertNotIn("creation_time", report["metadata"])
            self.assertEqual(packet["report"]["thread_cpu_analysis"],
                             report["thread_cpu_analysis"])

    def test_tree_cpu_excludes_configured_cadence_switch(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            origin, _, _ = synthetic_session(folder, samples=[
                (1, 1, 0.), (4, 3, 30.), (5, 3, 31.)])
            with SessionView.open(folder) as view:
                page = resource_tree_page(view, origin, origin+6*10**9)
            root = next(row["resources"] for row in page["rows"]
                        if row["instance_id"] == page["root_instance_id"])
            # 30 CPU seconds across the 1s->3s scheduling boundary are
            # not a comparable pair; only 4s->5s contributes.
            self.assertAlmostEqual(root["cpu_seconds"], 1.0)
            self.assertAlmostEqual(root["cpu_peak_percent_one_cpu"], 100.)

    def test_unicode_event_search_is_case_insensitive_and_literal(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            synthetic_session(folder, events=["СОБЫТИЕ_ОШИБКА", "ГРАФИК%_ПАУЗА"])
            russian = event_page(folder, search="событие")
            self.assertEqual([row["code"] for row in russian["rows"]],
                             ["СОБЫТИЕ_ОШИБКА"])
            literal = event_page(folder, search="график%_пауза")
            self.assertEqual([row["code"] for row in literal["rows"]],
                             ["ГРАФИК%_ПАУЗА"])
            self.assertEqual(event_page(folder, search="графикX_пауза")["rows"], [])

    def test_imported_text_counters_are_never_explained_as_zero_cpu(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            synthetic_session(folder, detailed=[(1, 0.), (2, 2.)])
            with closing(sqlite3.connect(folder / FILENAME)) as db:
                # SQLite REAL is not STRICT: this TEXT may pass CHECK(value>=0).
                db.execute("UPDATE thread_samples SET cpu_user_s='zzzz' WHERE tid=987654")
                self.assertEqual(db.execute(
                    "SELECT typeof(cpu_user_s) FROM thread_samples LIMIT 1").fetchone()[0],
                    "text")
                db.commit()
            with SessionView.open(folder) as view:
                with self.assertRaisesRegex(Exception, "INVALID_IMPORTED_THREAD_COUNTER"):
                    view.thread_summary()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            origin, _, _ = synthetic_session(folder, samples=[
                (1, 1, 0.), (2, 1, 2.), (3, 1, 3.)])
            with closing(sqlite3.connect(folder / FILENAME)) as db:
                db.execute("UPDATE samples SET cpu_user_s='bogus' "
                           "WHERE series='STANDARD' AND series_seq=2")
                db.commit()
            with SessionView.open(folder) as view:
                with self.assertRaisesRegex(Exception, "INVALID_IMPORTED_PROCESS_RESOURCE_COUNTER"):
                    resource_tree_page(view, origin, origin+4*10**9)

    def test_schema1_report_does_not_present_sqlite_text_as_peak_rss(self):
        from blackbox_core.contracts import ObserverError, Sample
        from blackbox_core.report import summarize, write_report
        from blackbox_core.storage import SessionStore
        with tempfile.TemporaryDirectory() as tmp:
            store = SessionStore(Path(tmp), os.getpid())
            folder = store.folder
            store.write_sample(Sample(
                elapsed_ms=1000, rss_bytes=2048, cpu_percent=5.,
                num_threads=2, read_bytes=10, write_bytes=20,
                children_count=0))
            store.finish("COMPLETED")
            store.close()
            with closing(sqlite3.connect(folder / "session.sqlite3")) as db:
                db.execute("UPDATE samples SET rss_bytes='BAD_TEXT_COUNTER'")
                db.commit()
            with self.assertRaises(ObserverError):
                summarize(folder)
            with self.assertRaises(ObserverError):
                write_report(folder)
            self.assertFalse((folder / "report.json").exists())
            self.assertFalse((folder / "report.html").exists())

    def test_tree_rss_summary_rejects_text_before_sqlite_sum_casts_to_zero(self):
        from blackbox_core.process_tree import tree_totals
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            origin, _, _ = synthetic_session(folder, detailed=[(1, 0.), (2, 1.)])
            with closing(sqlite3.connect(folder / FILENAME)) as db:
                db.execute("UPDATE samples SET rss_bytes='TEXT_NOT_BYTES' "
                           "WHERE series='DETAILED' AND series_seq=2")
                db.commit()
            with SessionView.open(folder) as view:
                with self.assertRaisesRegex(Exception, "INVALID_IMPORTED_TREE_RSS"):
                    tree_totals(view, origin, origin+3*10**9)

    def test_full_discovery_survives_rss_inspection_budget(self):
        discovered = [{"pid": 2000+i, "name": f"a-synthetic-{i:04}"}
                      for i in range(503)]
        discovered.append({"pid": 900000, "name": "zz-audit-target"})
        with patch("blackbox_universal.monitor.list_processes",
                   return_value=discovered), patch("psutil.Process") as factory:
            factory.return_value.memory_info.return_value = SimpleNamespace(
                rss=10*1024*1024)
            factory.return_value.status.return_value = "running"
            rows = available_processes(limit=3)
            self.assertEqual(factory.call_count, 3)
        self.assertEqual(len(rows), 504)
        self.assertEqual(rows[-1]["pid"], 900000)
        self.assertIsNone(rows[-1]["rss_mb"])
        self.assertEqual(rows[-1]["status"], "not sampled")
        self.assertEqual(rows[0]["rss_mb"], 10.)
        with self.assertRaises(ValueError):
            available_processes(limit=0)


class ProcessPickerQtRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PySide6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])

    def test_exact_pid_remains_searchable_after_five_hundred(self):
        from blackbox_universal.window import UniversalWindow
        window = UniversalWindow(allow_update_check=False)
        window._timer.stop()
        try:
            window._process_rows = [
                {"pid": i+2000, "name": f"a-synthetic-{i:04}", "rss_mb": None,
                 "status": "not sampled"} for i in range(510)]
            window._process_rows.append({"pid": 912345,
                "name": "zz-specific-target", "rss_mb": None,
                "status": "not sampled"})
            window._filter_processes()
            self.assertEqual(window.process_table.rowCount(), 500)
            self.assertIn("511", window.process_count.text())
            window._filter_processes("912345")
            self.assertEqual(window.process_table.rowCount(), 1)
            self.assertEqual(window.process_table.item(0, 1).text(), "912345")
            self.assertIn("1", window.process_count.text())
        finally:
            window.close()


if __name__ == "__main__":
    unittest.main()
