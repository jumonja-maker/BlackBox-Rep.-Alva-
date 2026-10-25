"""Large real SQLite queries must pass while the time limit stays fail-closed."""
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from blackbox_core.session_completion import CompletionNotConfirmed, confirm_v2_completion


def database(path, count):
    with closing(sqlite3.connect(path)) as db:
        db.executescript("""
            PRAGMA user_version=2;
            CREATE TABLE sessions(session_uuid TEXT,schema_version INTEGER,
                monotonic_origin_ns INTEGER,status TEXT,
                ended_monotonic_ns INTEGER,exit_code TEXT);
            INSERT INTO sessions VALUES('scale',2,100,'CLOSED',200,'COMPLETED');
            CREATE TABLE samples(instance_id INTEGER,series TEXT,
                series_seq INTEGER,correlation_key TEXT);
        """)
        db.executemany("INSERT INTO samples VALUES(1,'STANDARD',?,?)",
                       ((n, f"schema1:{n}") for n in range(1, count + 1)))
        db.commit()


def verify(path, count):
    confirm_v2_completion(path, session_uuid="scale", origin_ns=100,
                          exit_code="COMPLETED", expected_standard_samples=count)


class CompletionScaleTests(unittest.TestCase):
    def test_standard_longrun_and_100001_rows_are_read_without_mutation(self):
        # 9906 is the count in the failed old Standard endurance artifact.
        # The larger fixture is a query-scale check, NOT elapsed endurance.
        for count in (9906, 100001):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as root:
                path = Path(root) / "session-v2.sqlite3"
                database(path, count)
                before = hashlib.sha256(path.read_bytes()).digest()
                verify(path, count)
                self.assertEqual(before, hashlib.sha256(path.read_bytes()).digest())

    def test_real_deadline_still_cancels_large_verification(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "session-v2.sqlite3"
            database(path, 9906)
            before = hashlib.sha256(path.read_bytes()).digest()
            with patch("blackbox_core.session_completion.time.monotonic",
                       side_effect=[0.0, 6.0]):
                with self.assertRaisesRegex(CompletionNotConfirmed,
                                            "V2_COMPLETION_READ_FAILED"):
                    verify(path, 9906)
            self.assertEqual(before, hashlib.sha256(path.read_bytes()).digest())

    def test_large_matching_count_cannot_hide_wrong_source_mapping(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "session-v2.sqlite3"
            database(path, 9906)
            with closing(sqlite3.connect(path)) as db:
                db.execute("UPDATE samples SET correlation_key='wrong' WHERE series_seq=5000")
                db.commit()
            with self.assertRaisesRegex(CompletionNotConfirmed,
                                        "V2_COMPLETION_BASE_MAPPING_MISMATCH"):
                verify(path, 9906)


if __name__ == "__main__":
    unittest.main()
