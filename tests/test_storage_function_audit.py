"""Whole-program storage paths: actual SQL snapshots, budgets and malformed data."""
from contextlib import closing
import json
import math
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from blackbox_core.casebook import CaseBook, action_statistics, episode, evidence_page, readonly
from blackbox_core.interval_report import _safe_native_details, math_isfinite
from blackbox_core.library_files import read_json, tree_summary
from blackbox_core.session_view import SessionReadError, SessionView
from blackbox_core.storage import SessionStore


class ResearchStorageFunctionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.book = CaseBook(self.root, 42, 1., {"warmup_count": 0})
        self.addCleanup(self.book.db.close)

    def add_action(self, ordinal, duration):
        ref = self.book.put("TEST_ONLY_ACTION", {"ordinal": ordinal})
        self.book.db.execute("INSERT INTO action_runs VALUES(?,?,?,?)",
                             (str(ordinal).zfill(32), None, duration, ref))
        self.book.db.commit()

    def test_quantiles_and_mean_share_one_actual_wal_snapshot(self):
        self.add_action(1, 10_000_000)
        self.add_action(2, 20_000_000)
        injected, errors = [], []

        def connection(path):
            db = readonly(path)

            def trace(sql):
                if sql.startswith("WITH measured") and not injected:
                    injected.append(True)
                    try:self.add_action(3, 1_000_000_000)
                    except BaseException as error:errors.append(error)

            db.set_trace_callback(trace)
            return db

        with patch("blackbox_core.casebook.readonly", side_effect=connection):
            result = action_statistics(self.root)
        self.assertEqual(errors, [])
        self.assertEqual(injected, [True])
        self.assertEqual(self.book.db.execute("SELECT count(*) FROM action_runs").fetchone()[0], 3)
        self.assertEqual(result["repeats"], 2)
        self.assertEqual(result["duration_ms"]["median"], 15)
        self.assertEqual(result["variability_ms"]["mean"], 15)

    def test_invalid_imported_action_durations_never_become_zero_or_negative_statistics(self):
        self.add_action(1, 10_000_000)
        for value in (-1, "invalid", 9_000_000_000_000_000_000):
            with self.subTest(value=value):
                self.book.db.execute("UPDATE action_runs SET duration_ns=?", (value,))
                self.book.db.commit()
                with self.assertRaisesRegex(ValueError, "INVALID_RESEARCH_ACTION_DURATION"):
                    action_statistics(self.root)
                self.assertEqual(self.book.db.execute("SELECT duration_ns FROM action_runs").fetchone()[0], value)

    def test_evidence_byte_pages_keep_every_row_and_stable_forward_backward_cursors(self):
        expected = [self.book.put("TEST_ONLY_PAGE", {"payload": "x" * 30000}) for _ in range(80)]
        cursor, forward, pages = 0, [], 0
        while True:
            page = evidence_page(self.root, after_id=cursor, limit=500)
            self.assertLessEqual(sum(len(json.dumps(row,ensure_ascii=True,separators=(',',':')).encode('ascii'))
                                     for row in page['rows']), page['page_byte_budget'])
            self.assertTrue(page["rows"])
            pages += 1
            forward.extend(row["id"] for row in page["rows"])
            if not page["has_more"]:break
            self.assertGreater(page["next_id"], cursor)
            cursor = page["next_id"]
        self.assertGreater(pages, 1)
        self.assertEqual(forward, expected)
        backward, before = [], expected[-1] + 1
        while True:
            page = evidence_page(self.root, before_id=before, limit=500)
            backward[:0] = [row["id"] for row in page["rows"]]
            if not page["has_more"]:break
            self.assertLess(page["first_id"], before)
            before = page["first_id"]
        self.assertEqual(backward, expected)

    def test_malformed_evidence_is_explicit_and_scalar_payloads_remain_valid(self):
        ref = self.book.put("TEST_ONLY", {})
        for raw in ('{"x":NaN}', '{"x":1e400}', '{"x":1,"x":2}', '"'+'x'*33000+'"'):
            with self.subTest(raw=raw[:25]):
                self.book.db.execute("UPDATE evidence SET data=? WHERE id=?", (raw, ref))
                self.book.db.commit()
                with self.assertRaises(ValueError):evidence_page(self.root)
                self.assertEqual(self.book.db.execute("SELECT data FROM evidence WHERE id=?", (ref,)).fetchone()[0], raw)
        for value in (None, False, 0, [], "text"):
            self.book.db.execute("UPDATE evidence SET data=? WHERE id=?", (json.dumps(value), ref))
            self.book.db.commit()
            self.assertEqual(evidence_page(self.root)["rows"][0]["data"], value)

    def test_producer_metadata_cannot_create_records_its_reader_rejects(self):
        for kwargs in ({"quality": "x"*257}, {"source": []}, {"operation_id": "x"*257}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.book.put("TEST_ONLY", {}, **kwargs)
        with self.assertRaises(ValueError):self.book.set_context("x"*257, {})
        self.assertEqual(self.book.db.execute("SELECT count(*) FROM evidence").fetchone()[0], 0)

    def test_failed_casebook_initialization_closes_its_actual_connection(self):
        folder = self.root / "failed"
        folder.mkdir()
        real_connect, captured = sqlite3.connect, []

        def connect(*args, **kwargs):
            db = real_connect(*args, **kwargs)
            captured.append(db)
            return db

        with patch("blackbox_core.casebook.sqlite3.connect", side_effect=connect), \
             patch.object(CaseBook, "set_context", side_effect=ValueError("TEST_ONLY_SETUP_FAILURE")):
            with self.assertRaisesRegex(ValueError, "TEST_ONLY_SETUP_FAILURE"):
                CaseBook(folder, 42, 1., {})
        self.assertEqual(len(captured), 1)
        with self.assertRaises(sqlite3.ProgrammingError):captured[0].execute("SELECT 1")


class LegacyClockAndMarkerTests(unittest.TestCase):
    def test_episode_never_labels_malformed_sql_counters_as_measured_facts(self):
        with tempfile.TemporaryDirectory() as temp:
            store=SessionStore(Path(temp),42)
            folder=store.folder
            store.db.execute("INSERT INTO samples VALUES(1,0,NULL,NULL,NULL,NULL,NULL,NULL)")
            store.db.commit()
            store.finish('COMPLETED')
            store.close()
            book=CaseBook(folder,42,1.,{})
            book.close('COMPLETED')
            for field,value in (('rss_bytes','invalid'),('cpu_percent','invalid'),('cpu_percent',float('inf'))):
                with self.subTest(field=field,value=value):
                    with closing(sqlite3.connect(folder/'session.sqlite3')) as db:
                        db.execute('UPDATE samples SET rss_bytes=NULL,cpu_percent=NULL')
                        db.execute('UPDATE samples SET '+field+'=?',(value,))
                        db.commit()
                    before=(folder/'session.sqlite3').read_bytes()
                    with self.assertRaisesRegex(ValueError,'INVALID_RESEARCH_SAMPLE_COUNTER'):
                        episode(folder,0,100)
                    self.assertEqual((folder/'session.sqlite3').read_bytes(),before)

    def test_invalid_legacy_clock_is_rejected_before_multiplier_or_integer_conversion(self):
        for value in ("bad", 1.5, -1, 2**63-1):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temp:
                store = SessionStore(Path(temp), 42)
                store.db.execute("INSERT INTO samples VALUES(1,?,NULL,NULL,NULL,NULL,NULL,NULL)", (value,))
                store.db.commit()
                folder = store.folder
                store.finish("COMPLETED")
                store.close()
                before = (folder / "session.sqlite3").read_bytes()
                with SessionView.open(folder) as view:
                    with self.assertRaisesRegex(SessionReadError, "INVALID_IMPORTED_SAMPLE_CLOCK"):
                        view.bounds()
                    if value == 1.5:
                        with self.assertRaisesRegex(SessionReadError, "INVALID_IMPORTED_SAMPLE_CLOCK"):
                            list(view.reader.iter_samples(0, 10_000_000))
                self.assertEqual((folder / "session.sqlite3").read_bytes(), before)

    def test_invalid_read_policy_never_opens_a_connection(self):
        for policy in (float("nan"), float("inf"), 10**330, True, 0, -1):
            with self.subTest(policy=policy), patch("blackbox_core.session_view.sqlite3.connect") as connect:
                with self.assertRaisesRegex(SessionReadError, "INVALID_SESSION_READ_POLICY"):
                    SessionView.open(Path("TEST_ONLY_NOT_OPENED"), timeout_s=policy)
                connect.assert_not_called()

    def test_marker_growth_after_stat_cannot_bypass_actual_read_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "marker.json"
            path.write_bytes(b'{"x":1}')
            original, grown = Path.open, []

            def open_path(item, mode="r", *args, **kwargs):
                if item == path and mode.startswith("r") and not grown:
                    grown.append(True)
                    with original(path, "ab") as target:target.write(b" "*512)
                return original(item, mode, *args, **kwargs)

            with patch.object(Path, "open", open_path):
                with self.assertRaisesRegex(ValueError, "LIBRARY_INVALID_MARKER"):
                    read_json(path, 16)
            self.assertEqual(grown, [True])

    def test_nonfinite_summary_budgets_do_not_disable_directory_limits(self):
        for value in (float("nan"), float("inf"), 10**330, True, 0):
            with self.subTest(value=value), patch("blackbox_core.library_files.os.scandir") as scan:
                with self.assertRaisesRegex(ValueError, "LIBRARY_INVALID_SUMMARY_BUDGET"):
                    tree_summary(Path("TEST_ONLY_NOT_SCANNED"), max_seconds=value)
                scan.assert_not_called()

    def test_native_export_handles_invalid_shapes_without_mutation_or_invented_values(self):
        for value in (None, [], 0, "text"):
            self.assertEqual(_safe_native_details(value), {})
        malformed = {"wct": {"status": [], "method": {}, "win32_code": 10**330,
                              "timeout_ms": float("nan")}}
        output = _safe_native_details(malformed)["wct"]
        self.assertEqual(output["status"], "UNKNOWN")
        self.assertEqual(output["method"], "UNVERIFIED_METHOD")
        self.assertEqual(output["win32_code"], 10**330)
        self.assertNotIn("timeout_ms", output)
        self.assertEqual(malformed["wct"]["status"], [])
        self.assertTrue(math.isnan(malformed["wct"]["timeout_ms"]))
        deep = {}
        for _ in range(100):deep = {"nodes": [deep]}
        projected = _safe_native_details({"wct": deep})["wct"]
        for _ in range(4):projected = projected["nodes"][0]
        self.assertTrue(projected["export_detail_limit_reached"])
        self.assertTrue(math_isfinite(10**330))
        self.assertFalse(math_isfinite(float("inf")))
