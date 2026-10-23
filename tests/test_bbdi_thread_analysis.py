"""BB-DI-001: validated per-TID CPU deltas, gaps and Qt/report integration."""
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

from blackbox_core.detail_analysis import analyze_detail_threads
from blackbox_universal.monitor import ReadOnlyProbe


def fixture(folder: Path, *, counter_reset: bool = False,
            skipped_seq: bool = False) -> Path:
    """Synthetic only inside tests; never a user-facing OS observation."""
    path = folder / "detail-v2.sqlite3"
    with closing(sqlite3.connect(path)) as db:
        db.executescript("""
            CREATE TABLE detail_metadata
                (schema_version INTEGER, pid INTEGER, created REAL,
                 monotonic_origin_ns INTEGER, status TEXT);
            CREATE TABLE process_samples
                (seq INTEGER PRIMARY KEY, time_monotonic_ns INTEGER,
                 thread_status TEXT, threads_omitted INTEGER,
                 rss_bytes INTEGER, private_bytes INTEGER, handles INTEGER);
            CREATE TABLE thread_samples
                (sample_seq INTEGER, pid INTEGER, tid INTEGER,
                 cpu_user_s REAL, cpu_system_s REAL);
            CREATE TABLE child_samples (sample_seq INTEGER);
            CREATE TABLE sensor_errors (seq INTEGER);
        """)
        db.execute("INSERT INTO detail_metadata VALUES (2, 77, 123.0, 0, 'STOPPED')")
        sequence = [1, 2, 3, 5] if skipped_seq else [1, 2, 3, 4]
        for seq in sequence:
            db.execute("INSERT INTO process_samples VALUES (?,?,?,?,?,?,?)",
                       (seq, seq*1_000_000_000, "OK", 0, 10, 8, 2))
        records = [
            (1, 77, 101, 0.0, 0.0),
            (2, 77, 101, 1.0, 0.0),
            # TID 101 disappeared in seq3; matching seq4/5 is NOT joined.
            (sequence[-1], 77, 101, 1.5, 0.0),
            (2, 77, 102, 0.0, 0.0),
            (3, 77, 102, 0.5, 0.0),
            (sequence[-1], 77, 102, 0.8, 0.0),
            (1, 77, 202, 1.0, 0.0),
            (2, 77, 202, 0.25 if counter_reset else 1.25, 0.0),
        ]
        db.executemany("INSERT INTO thread_samples VALUES (?,?,?,?,?)", records)
        db.commit()
    return path


class ThreadDeltaTests(unittest.TestCase):
    def test_rates_are_derived_from_adjacent_same_tid_only(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            fixture(folder)
            result = analyze_detail_threads(folder)
            self.assertEqual(result["status"], "OK")
            self.assertTrue(result["tid_reuse_uncertain"])
            self.assertEqual(result["source_kind"], "PSUTIL")
            self.assertEqual(result["verification_class"], "DERIVED")
            rows = {r["tid"]: r for r in result["top_threads"]}
            self.assertAlmostEqual(rows[101]["cpu_percent"], 100)
            self.assertEqual(rows[101]["observed_pairs"], 1)
            self.assertAlmostEqual(rows[102]["cpu_percent"], 40)
            self.assertAlmostEqual(rows[102]["peak_cpu_percent"], 50)
            self.assertEqual(rows[102]["observed_pairs"], 2)
            self.assertAlmostEqual(rows[202]["cpu_percent"], 25)
            self.assertFalse(result["root_cause_proven"])

    def test_discontinuity_and_counter_reset_never_produce_fake_rate(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            fixture(folder, skipped_seq=True, counter_reset=True)
            result = analyze_detail_threads(folder)
            rows = {r["tid"]: r for r in result["top_threads"]}
            self.assertNotIn(202, rows)
            self.assertEqual(rows[102]["observed_pairs"], 1)
            self.assertEqual(result["counter_resets"], 1)
            self.assertGreater(result["gaps"], 0)
            self.assertIn("THREAD_CPU_COUNTER_RESET", result["warnings"])
            self.assertIn("NON_ADJACENT_OR_INVALID_SAMPLE_GAPS", result["warnings"])

    def test_readonly_source_hash_is_unchanged_and_missing_is_not_zero(self):
        import hashlib
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            result = analyze_detail_threads(folder)
            self.assertEqual(result["status"], "NOT_RECORDED")
            self.assertEqual(result["top_threads"], [])
            path = fixture(folder)
            before = hashlib.sha256(path.read_bytes()).digest()
            analyze_detail_threads(folder)
            self.assertEqual(before, hashlib.sha256(path.read_bytes()).digest())
            with self.assertRaisesRegex(ValueError, "INVALID_MAX_SAMPLES"):
                analyze_detail_threads(folder, max_samples=1000000)
            path.unlink()
            path.symlink_to(folder / "missing.db")
            self.assertEqual(analyze_detail_threads(folder)["status"], "NOT_RECORDED")

    def test_json_html_include_derived_thread_cpu_but_not_os_hang(self):
        with tempfile.TemporaryDirectory() as root:
            probe = ReadOnlyProbe(output_root=Path(root))
            probe.attach(os.getpid())
            probe.start()
            try:
                probe.tick()
                fixture(probe.session_folder)
            finally:
                probe.stop()
            folder = probe.session_folder
            report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            cpu = report["thread_cpu_analysis"]
            self.assertEqual(cpu["status"], "OK")
            self.assertEqual(cpu["top_threads"][0]["tid"], 101)
            self.assertFalse(cpu["root_cause_proven"])
            html = (folder / "report.html").read_text(encoding="utf-8")
            self.assertIn("Per-thread CPU", html)
            self.assertIn("TID reuse between samples cannot be ruled out", html)

    def test_existing_five_page_qt_shows_real_saved_tid_rows(self):
        from PySide6.QtWidgets import QApplication
        from blackbox_universal.window import UniversalWindow
        app = QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as root, patch(
                "blackbox_universal.monitor._default_sessions_root",
                return_value=Path(root)):
            folder = Path(root)
            fixture(folder)
            window = UniversalWindow()
            window._timer.stop()
            try:
                self.assertEqual(window.stack.count(), 5)
                window.probe.pid = 77
                window.probe.session_folder = folder
                window._update_all()
                self.assertTrue(window.thread_detail_refresh.isEnabled())
                window.thread_detail_refresh.click()
                worker = window._thread_detail_worker
                self.assertIsNotNone(worker)
                self.assertTrue(worker.wait(5000))
                for _ in range(5):
                    app.processEvents()
                self.assertGreaterEqual(window.thread_detail_table.rowCount(), 2)
                self.assertEqual(window.thread_detail_table.item(0, 0).text(), "101")
                self.assertIn("TID_REUSE_CANNOT_BE_EXCLUDED",
                              window.thread_detail_status.text())
            finally:
                worker = window._thread_detail_worker
                if worker is not None:
                    worker.wait(5000)
                    app.processEvents()
                window.close()


if __name__ == "__main__":
    unittest.main()
