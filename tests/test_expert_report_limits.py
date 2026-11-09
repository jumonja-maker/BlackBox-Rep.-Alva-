"""Imported report budgets and identity-bound publication rollback.

Fixtures are disposable SQLite/JSON inputs, never proof of a target root cause.
Execution belongs to the repository's GitHub-hosted acceptance jobs.
"""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from blackbox_core.contracts import MAX_EVENT_BYTES, ObserverError
from blackbox_core.report import MAX_REPORT_ERROR_CODES, summarize, write_report
from blackbox_core.storage import SessionStore, _open_ro


class ExpertReportLimitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        store = SessionStore(Path(self.temp.name), 42)
        self.folder = store.folder
        store.finish("COMPLETED")
        store.close()
        self.database = self.folder / "session.sqlite3"

    def append(self, rows):
        with closing(sqlite3.connect(self.database)) as db:
            db.executemany("INSERT INTO events(data) VALUES (?)", ((row,) for row in rows))
            db.commit()

    def rejected_without_source_change(self):
        before = hashlib.sha256(self.database.read_bytes()).hexdigest()
        with self.assertRaises(ObserverError) as raised:
            summarize(self.folder)
        self.assertEqual((raised.exception.code, raised.exception.stage), ("INVALID_DATA", "report"))
        self.assertEqual(hashlib.sha256(self.database.read_bytes()).hexdigest(), before)
        self.assertFalse((self.folder / "report.json").exists())

    def test_oversized_sqlite_value_is_rejected_before_loading_it(self):
        with closing(sqlite3.connect(self.database)) as db:
            db.execute("UPDATE metadata SET probe=?", ("x" * (2 * 1024 * 1024),))
            db.commit()
        self.rejected_without_source_change()

    def test_oversized_deep_and_nonfinite_events_fail_without_partial_summary(self):
        for raw in (
                json.dumps({"kind": "unknown", "data": "x" * MAX_EVENT_BYTES}),
                '{"kind":"unknown","data":' + '[' * 1200 + '0' + ']' * 1200 + '}',
                '{"kind":"unknown","data":NaN}'):
            with self.subTest(case=raw[:40]):
                with closing(sqlite3.connect(self.database)) as db:
                    db.execute("DELETE FROM events")
                    db.commit()
                self.append([raw])
                self.rejected_without_source_change()

    def test_many_distinct_imported_error_codes_do_not_grow_an_unbounded_result(self):
        self.append(json.dumps({"kind": "observer_error", "code": "IMPORTED_" + str(i)})
                    for i in range(MAX_REPORT_ERROR_CODES + 1))
        self.rejected_without_source_change()

    def test_event_scan_limit_never_returns_a_successful_partial_summary(self):
        self.append(['{"kind":"unknown"}'] * 4)
        with patch("blackbox_core.report.MAX_REPORT_EVENTS", 3):
            self.rejected_without_source_change()

    def test_expired_sqlite_budget_interrupts_query_and_preserves_database(self):
        before = self.database.read_bytes()
        with patch("blackbox_core.storage.time.monotonic", return_value=1):
            db = _open_ro(self.folder)
        with closing(db), patch("blackbox_core.storage.time.monotonic", return_value=100):
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n "
                           "WHERE x<10000) SELECT sum(x) FROM n").fetchone()
        self.assertEqual(self.database.read_bytes(), before)

    def test_second_publish_collision_rolls_back_only_our_own_html(self):
        real_link = os.link
        html, output = self.folder / "report.html", self.folder / "report.json"

        def collision(source, target):
            if Path(target) == output:
                output.write_bytes(b"FOREIGN_JSON")
                raise FileExistsError("simulated competing publisher")
            return real_link(source, target)

        with patch("blackbox_core.report.os.link", side_effect=collision):
            with self.assertRaises(ObserverError):
                write_report(self.folder)
        self.assertFalse(html.exists())
        self.assertEqual(output.read_bytes(), b"FOREIGN_JSON")
        self.assertEqual(list(self.folder.glob(".blackbox-report-*")), [])

    def test_rollback_preserves_a_replacement_from_another_writer(self):
        real_link = os.link
        html, output = self.folder / "report.html", self.folder / "report.json"
        before = self.database.read_bytes()

        def replacement(source, target):
            if Path(target) == output:
                html.unlink()
                html.write_bytes(b"FOREIGN_HTML")
                output.write_bytes(b"FOREIGN_JSON")
                raise FileExistsError("simulated replacement plus publish collision")
            return real_link(source, target)

        with patch("blackbox_core.report.os.link", side_effect=replacement):
            with self.assertRaises(ObserverError):
                write_report(self.folder)
        self.assertEqual(html.read_bytes(), b"FOREIGN_HTML")
        self.assertEqual(output.read_bytes(), b"FOREIGN_JSON")
        self.assertEqual(self.database.read_bytes(), before)
        self.assertEqual(list(self.folder.glob(".blackbox-report-*")), [])
