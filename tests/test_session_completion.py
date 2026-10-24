"""Read-only close postconditions; these fixtures do not prove the old QA cause."""
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest

from blackbox_core.session_completion import CompletionNotConfirmed, confirm_v2_completion


def make_db(path, *, status="CLOSED", ended=200, code="COMPLETED"):
    with closing(sqlite3.connect(path)) as db:
        db.executescript("""
            PRAGMA user_version=2;
            CREATE TABLE sessions(session_uuid TEXT, schema_version INTEGER,
                monotonic_origin_ns INTEGER, status TEXT,
                ended_monotonic_ns INTEGER, exit_code TEXT);
        """)
        db.execute("INSERT INTO sessions VALUES ('test-session',2,100,?,?,?)",
                   (status, ended, code))
        db.commit()


class CompletionReadTests(unittest.TestCase):
    def check(self, path, **overrides):
        args = dict(session_uuid="test-session", origin_ns=100,
                    exit_code="COMPLETED")
        args.update(overrides)
        return confirm_v2_completion(path, **args)

    def test_closed_same_instance_is_read_without_source_mutation(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "session-v2.sqlite3"
            make_db(path)
            before = hashlib.sha256(path.read_bytes()).hexdigest()
            self.check(path)
            self.assertEqual(before, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_recording_state_is_rejected_and_never_repaired(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "session-v2.sqlite3"
            make_db(path, status="RECORDING", ended=None, code=None)
            before = path.read_bytes()
            with self.assertRaisesRegex(CompletionNotConfirmed, "V2_COMPLETION_NOT_CLOSED"):
                self.check(path)
            self.assertEqual(before, path.read_bytes())
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute(
                    "SELECT status,ended_monotonic_ns,exit_code FROM sessions"
                ).fetchone(), ("RECORDING", None, None))

    def test_wrong_instance_and_exit_code_cannot_be_success(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "session-v2.sqlite3"
            make_db(path)
            for changes, reason in (({"session_uuid": "other"}, "IDENTITY_MISMATCH"),
                                    ({"origin_ns": 99}, "IDENTITY_MISMATCH"),
                                    ({"exit_code": "INTERRUPTED"}, "NOT_CLOSED")):
                with self.subTest(changes=changes):
                    with self.assertRaisesRegex(CompletionNotConfirmed, reason):
                        self.check(path, **changes)

    def test_invalid_end_time_and_extra_session_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "session-v2.sqlite3"
            make_db(path, ended=99)
            with self.assertRaisesRegex(CompletionNotConfirmed, "NOT_CLOSED"):
                self.check(path)
            with closing(sqlite3.connect(path)) as db:
                db.execute("INSERT INTO sessions SELECT * FROM sessions")
                db.commit()
            with self.assertRaisesRegex(CompletionNotConfirmed, "INVALID_CARDINALITY"):
                self.check(path)

    def test_missing_or_corrupt_database_is_not_created_or_changed(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "session-v2.sqlite3"
            with self.assertRaises(CompletionNotConfirmed):
                self.check(path)
            self.assertFalse(path.exists())
            path.write_bytes(b"not SQLite")
            with self.assertRaises(CompletionNotConfirmed):
                self.check(path)
            self.assertEqual(path.read_bytes(), b"not SQLite")

    def test_schema_and_symlink_checks_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "source.sqlite3"
            make_db(path)
            with closing(sqlite3.connect(path)) as db:
                db.execute("PRAGMA user_version=1")
            with self.assertRaisesRegex(CompletionNotConfirmed, "SCHEMA_MISMATCH"):
                self.check(path)
            alias = Path(root) / "session-v2.sqlite3"
            try:
                alias.symlink_to(path)
            except (OSError, NotImplementedError):
                return  # Windows tokens can lack symlink creation permission.
            with self.assertRaisesRegex(CompletionNotConfirmed, "UNSAFE_PATH"):
                self.check(alias)

    def test_closed_commit_in_wal_is_seen_despite_older_reader(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "session-v2.sqlite3"
            make_db(path, status="RECORDING", ended=None, code=None)
            with closing(sqlite3.connect(path)) as writer, closing(sqlite3.connect(path)) as old:
                writer.execute("PRAGMA journal_mode=WAL")
                old.execute("BEGIN")
                self.assertEqual(old.execute("SELECT status FROM sessions").fetchone(),
                                 ("RECORDING",))
                writer.execute("UPDATE sessions SET status='CLOSED',"
                               "ended_monotonic_ns=200,exit_code='COMPLETED'")
                writer.commit()
                self.check(path)
                self.assertEqual(old.execute("SELECT status FROM sessions").fetchone(),
                                 ("RECORDING",))
                old.rollback()


if __name__ == "__main__":
    unittest.main()
