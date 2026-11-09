"""Hosted regressions for legacy analysis import/publication boundaries.

Fixtures are synthetic SQLite/JSON, with byte identity checked after refusals.
No application, process sampler, native helper or external service is used.
"""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from blackbox_investigation import InvestigationError, analyze, analyze_snapshot, compare_reports, load_session
from blackbox_investigation.__main__ import _commit_export
from blackbox_investigation.optin_probe import observe_selected_process
from blackbox_core.detail_analysis import analyze_detail_threads


def fixture_session(folder, *, count=4):
    folder.mkdir()
    path = folder / "session.sqlite3"
    with sqlite3.connect(path) as db:
        db.executescript('''
            CREATE TABLE metadata(schema_version INTEGER NOT NULL, session_id TEXT NOT NULL,
                pid INTEGER NOT NULL, started_utc TEXT NOT NULL, ended_utc TEXT,
                exit_code TEXT, probe TEXT NOT NULL);
            CREATE TABLE samples(seq INTEGER PRIMARY KEY,elapsed_ms INTEGER NOT NULL,
                rss_bytes INTEGER,cpu_percent REAL,num_threads INTEGER,read_bytes INTEGER,
                write_bytes INTEGER,children_count INTEGER);
        ''')
        db.execute("INSERT INTO metadata VALUES (1,'synthetic-import',234,'2026-11-09',NULL,NULL,'psutil')")
        db.executemany("INSERT INTO samples VALUES (?,?,?,?,?,?,?,?)",
            ((i + 1, i * 1000, 1024, 1.0, 1, i * 20, i * 10, 0) for i in range(count)))
    return path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class LegacyAnalysisReadContracts(unittest.TestCase):
    def test_valid_full_4096_sample_contract_remains_read_only(self):
        with tempfile.TemporaryDirectory() as temp:
            path = fixture_session(Path(temp) / "session", count=4096)
            before = digest(path)
            result = load_session(path.parent)
            self.assertEqual(len(result["samples"]), 4096)
            self.assertTrue(result["coverage"]["full_session_covered"])
            self.assertEqual(result["pid"], 234)
            self.assertEqual(digest(path), before)

    def test_oversized_metadata_is_rejected_before_materialization_without_source_change(self):
        with tempfile.TemporaryDirectory() as temp:
            path = fixture_session(Path(temp) / "session")
            with sqlite3.connect(path) as db:
                db.execute("UPDATE metadata SET probe=?", ("x" * (1024 * 1024 + 1),))
            before = digest(path)
            with self.assertRaisesRegex(InvestigationError, "INVALID_SESSION"):
                load_session(path.parent)
            self.assertEqual(digest(path), before)
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_sql_aggregate_deadline_refuses_work_without_source_change(self):
        with tempfile.TemporaryDirectory() as temp:
            path = fixture_session(Path(temp) / "session", count=4096)
            before = digest(path)
            with patch("blackbox_investigation.sqlite_adapter.time.monotonic", side_effect=[0.0] + [100.0] * 50):
                with self.assertRaisesRegex(InvestigationError, "INVALID_SESSION"):
                    load_session(path.parent)
            self.assertEqual(digest(path), before)

    def test_failed_connection_budget_setup_closes_the_read_owner(self):
        with tempfile.TemporaryDirectory() as temp:
            path = fixture_session(Path(temp) / "session")
            before = digest(path)
            connection = Mock()
            connection.setlimit.side_effect = sqlite3.OperationalError("synthetic setup failure")
            with patch("blackbox_investigation.sqlite_adapter.sqlite3.connect", return_value=connection):
                with self.assertRaisesRegex(InvestigationError, "INVALID_SESSION"):
                    load_session(path.parent)
            connection.close.assert_called_once_with()
            self.assertEqual(digest(path), before)

    def test_caller_supplied_birth_is_retained_but_never_claimed_os_verified(self):
        identity = {"pid": 234, "creation_time": 1000.0}
        with patch("psutil.Process") as process:
            result = analyze([], identity=identity)
            process.assert_not_called()
        self.assertEqual(result["identity"], identity)
        self.assertFalse(result["provenance"]["pid_creation_verified"])
        self.assertEqual(result["provenance"]["os_proof"], "NOT_ATTESTED")
        self.assertEqual(result["provenance"]["sample_source"], "APP_SUPPLIED_UNAUTHENTICATED")
        self.assertEqual(identity, {"pid": 234, "creation_time": 1000.0})

    def test_unrepresentable_snapshot_and_identity_values_have_stable_invalid_codes(self):
        snapshot = {"schema_version": 1, "product": "BLACK.BOX Universal",
                    "observed_process": {"pid": 234}, "recent_samples": [
                        {"seconds": 0, "rss_mb": 1.0, "process_count": 1}]}
        for field, code in (("seconds", "INVALID_ELAPSED_MS"), ("rss_mb", "INVALID_RSS_BYTES")):
            for value in (10 ** 330, float("nan"), float("inf")):
                with self.subTest(field=field, value_type=type(value).__name__):
                    source = deepcopy(snapshot)
                    source["recent_samples"][0][field] = value
                    with self.assertRaisesRegex(InvestigationError, code):
                        analyze_snapshot(source)
        with self.assertRaisesRegex(InvestigationError, "INVALID_IDENTITY"):
            analyze([], identity={"pid": 234, "creation_time": 10 ** 330})
        report = analyze([])
        report["summary"]["rss_bytes"].update(count=1, median=10 ** 330)
        with self.assertRaisesRegex(InvestigationError, "INVALID_COMPARISON"):
            compare_reports(report, deepcopy(report))


class LegacyProbeInputContracts(unittest.TestCase):
    def test_unrepresentable_or_nonfinite_birth_never_reaches_process_lookup(self):
        with patch("psutil.Process") as process:
            for value in (10 ** 330, float("nan"), float("inf"), -float("inf")):
                with self.subTest(value_type=type(value).__name__):
                    with self.assertRaisesRegex(InvestigationError, "INVALID_CREATION_TIME"):
                        observe_selected_process(234, expected_created=value)
            process.assert_not_called()


def detail_fixture(folder):
    folder.mkdir()
    path = folder / "detail-v2.sqlite3"
    with sqlite3.connect(path) as db:
        db.executescript("""
            CREATE TABLE detail_metadata(schema_version INTEGER,pid INTEGER,created REAL);
            CREATE TABLE process_samples(seq INTEGER PRIMARY KEY,time_monotonic_ns INTEGER,
                thread_status TEXT,threads_omitted INTEGER);
            CREATE TABLE thread_samples(sample_seq INTEGER,pid INTEGER,tid INTEGER,
                cpu_user_s REAL,cpu_system_s REAL);
        """)
        db.execute("INSERT INTO detail_metadata VALUES(2,234,1000.0)")
        db.executemany("INSERT INTO process_samples VALUES(?,?,?,?)",
            [(1, 0, "OK", 0), (2, 1000000000, "OK", 0)])
        db.executemany("INSERT INTO thread_samples VALUES(?,?,?,?,?)",
            [(1, 234, 17, 1.0, 0.0), (2, 234, 17, 1.5, 0.0)])
    return path


class LegacyDetailReadContracts(unittest.TestCase):
    def test_valid_positive_tid_adjacent_cpu_is_unchanged_and_source_is_read_only(self):
        with tempfile.TemporaryDirectory() as temp:
            path = detail_fixture(Path(temp) / "detail")
            before = digest(path)
            result = analyze_detail_threads(path.parent)
            self.assertEqual(result["status"], "OK")
            self.assertEqual(result["pair_count"], 1)
            self.assertEqual(result["top_threads"][0]["tid"], 17)
            self.assertEqual(result["top_threads"][0]["cpu_percent"], 50.0)
            self.assertEqual(digest(path), before)

    def test_zero_tid_cannot_be_reported_as_a_measured_target_thread(self):
        with tempfile.TemporaryDirectory() as temp:
            path = detail_fixture(Path(temp) / "detail")
            with sqlite3.connect(path) as db:
                db.execute("UPDATE thread_samples SET tid=0")
            before = digest(path)
            result = analyze_detail_threads(path.parent)
            self.assertEqual(result["status"], "INVALID_DETAILED_DATA")
            self.assertEqual(result["top_threads"], [])
            self.assertIn("INVALID_THREAD_COUNTER", result["warnings"])
            self.assertEqual(digest(path), before)

    def test_oversized_detail_value_is_controlled_and_source_is_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            path = detail_fixture(Path(temp) / "detail")
            with sqlite3.connect(path) as db:
                db.execute("UPDATE detail_metadata SET created=?", ("x" * (1024 * 1024 + 1),))
            before = digest(path)
            result = analyze_detail_threads(path.parent)
            self.assertEqual(result["status"], "DETAIL_READ_UNAVAILABLE")
            self.assertEqual(result["top_threads"], [])
            self.assertEqual(digest(path), before)

    def test_detail_scan_deadline_stops_unindexed_work_without_source_change(self):
        with tempfile.TemporaryDirectory() as temp:
            path = detail_fixture(Path(temp) / "detail")
            with sqlite3.connect(path) as db:
                db.executemany("INSERT INTO thread_samples VALUES(?,?,?,?,?)",
                    ((1000, 234, 100 + i, 1.0, 0.0) for i in range(4096)))
            before = digest(path)
            with patch("blackbox_core.detail_analysis.time.monotonic", side_effect=[0.0] + [100.0] * 50):
                result = analyze_detail_threads(path.parent)
            self.assertEqual(result["status"], "DETAIL_READ_UNAVAILABLE")
            self.assertEqual(result["top_threads"], [])
            self.assertEqual(digest(path), before)


class LegacyAnalysisPublicationContracts(unittest.TestCase):
    def test_later_collision_rolls_back_only_its_own_first_link(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first, second = root / "out.json", root / "out.html"
            second.write_bytes(b"pre-existing HTML")
            with self.assertRaises(FileExistsError):
                _commit_export({"json": first, "html": second}, {"json": b"our JSON", "html": b"our HTML"})
            self.assertFalse(first.exists())
            self.assertEqual(second.read_bytes(), b"pre-existing HTML")
            self.assertEqual(list(root.glob(".investigation-*.pending")), [])

    def test_later_failure_preserves_foreign_replacement_and_primary_error(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first, second = root / "out.json", root / "out.html"
            real_link = os.link
            primary = FileExistsError("synthetic second publication collision")

            def compete(source, target):
                if Path(target) == second:
                    first.unlink()
                    first.write_bytes(b"foreign replacement")
                    raise primary
                return real_link(source, target)

            with patch("blackbox_investigation.__main__.os.link", side_effect=compete):
                with self.assertRaises(FileExistsError) as caught:
                    _commit_export({"json": first, "html": second}, {"json": b"our JSON", "html": b"our HTML"})
            self.assertIs(caught.exception, primary)
            self.assertEqual(first.read_bytes(), b"foreign replacement")
            self.assertFalse(second.exists())
            self.assertEqual(list(root.glob(".investigation-*.pending")), [])
