"""BB-DI-001 arbitrary interval regression: old SQLite remains byte-identical."""
from __future__ import annotations
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from blackbox_core.storage import SessionStore
from blackbox_investigation import analyze_session
from blackbox_universal.investigation_worker import session_bounds


class ReadOnlyIntervalTests(unittest.TestCase):
    def test_middle_of_large_old_schema1_session_is_queryable_read_only(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            store = SessionStore(root, os.getpid())
            name = store.folder
            try:
                # 100001 samples, equivalent to a multi-hour monitoring volume.
                store.db.executemany(
                    "INSERT INTO samples (seq,elapsed_ms,rss_bytes,cpu_percent,"
                    "num_threads,read_bytes,write_bytes,children_count) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    ((n, n*250, 123456, 17.0, 2, n*100, n*20, 0)
                     for n in range(1, 100002)))
                store.db.commit()
                store.finish("COMPLETED")
            finally:
                store.close()
            file = name / "session.sqlite3"
            original = hashlib.sha256(file.read_bytes()).hexdigest()
            self.assertEqual(session_bounds(name), (250, 25_000_250, 100001))
            report = analyze_session(
                name, interval_start_ms=12_000_000, interval_end_ms=12_060_000)
            self.assertEqual(report["coverage"]["total_samples"], 100001)
            self.assertFalse(report["coverage"]["full_session_covered"])
            self.assertGreater(report["coverage"]["selected_samples"], 200)
            self.assertEqual(hashlib.sha256(file.read_bytes()).hexdigest(), original)

    def test_missing_session_or_empty_samples_fail_bounded(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                session_bounds(Path(root) / "missing")


class QtIntervalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PySide6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])

    def test_interval_dialog_passes_exact_user_bounds_without_auto_tail(self):
        from blackbox_universal.window import UniversalWindow
        from blackbox_core.contracts import Sample
        with tempfile.TemporaryDirectory() as root:
            store = SessionStore(Path(root), os.getpid())
            name = store.folder
            store.write_sample(Sample(
                elapsed_ms=50000, rss_bytes=1234, cpu_percent=30,
                num_threads=3, read_bytes=3, write_bytes=4,
                children_count=0))
            store.write_sample(Sample(
                elapsed_ms=60000, rss_bytes=1234, cpu_percent=30,
                num_threads=3, read_bytes=3, write_bytes=4,
                children_count=0))
            store.finish("COMPLETED")
            store.close()
            window = UniversalWindow()
            window._timer.stop()
            try:
                with patch("blackbox_universal.window.QFileDialog.getExistingDirectory",
                           return_value=str(name)), patch(
                    "blackbox_universal.window.QInputDialog.getText",
                    side_effect=[("50000", True), ("60000", True)]), patch.object(
                    window, "_begin_investigation") as begin:
                    window._select_investigation_interval()
                    begin.assert_called_once_with(
                        folder=name, interval=(50000, 60000))
            finally:
                window.close()


if __name__ == "__main__":
    unittest.main()
