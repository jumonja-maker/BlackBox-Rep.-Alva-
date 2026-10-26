"""Read-only close postconditions; these fixtures do not prove the old QA cause."""
from contextlib import closing
import hashlib
from pathlib import Path
import os
import sqlite3
import time
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

    def test_actual_writer_finish_does_not_require_checkpointing_active_reader(self):
        # A real SessionV2Writer must commit CLOSED while a read-only
        # Investigation view retains an earlier WAL snapshot. SQLite WAL
        # durability does not depend on a blocking TRUNCATE checkpoint.
        from blackbox_core.storage import SessionStore
        from blackbox_core.probe import PsutilProbe
        with tempfile.TemporaryDirectory() as root:
            pid = os.getpid()
            probe = PsutilProbe(pid)
            store = SessionStore(Path(root), pid)
            try:
                store.enable_v2(pid=pid, created=probe.created,
                                name="self-test", origin_ns=probe.origin_ns)
                self.assertTrue(store.v2._ready.wait(5))
                self.assertIsNone(store.v2.failure)
                with closing(sqlite3.connect(store.v2.path)) as older:
                    older.execute("BEGIN")
                    self.assertEqual(
                        older.execute("SELECT status FROM sessions").fetchone(),
                        ("RECORDING",))
                    started = time.monotonic()
                    store.finish("COMPLETED")
                    self.assertLess(time.monotonic() - started, 4.5)
                    self.assertTrue(store.finished)
                    confirm_v2_completion(
                        store.v2.path, session_uuid=store.v2.session_uuid,
                        origin_ns=store.v2.origin_ns, exit_code="COMPLETED")
                    self.assertEqual(
                        older.execute("SELECT status FROM sessions").fetchone(),
                        ("RECORDING",))
                    older.rollback()
            finally:
                store.close()

    def test_1806_standard_rows_do_not_trigger_sqlite_progress_interrupt(self):
        # Exact archived 1h DETAILED failure: a fully CLOSED v2 database
        # carried 1806 matching base samples, but the old progress callback
        # unconditionally returned 1 every 10000 VM operations, causing
        # sqlite3.OperationalError("interrupted") and a false STORAGE_ERROR.
        # This must use an actual SQLite aggregate, not a mock.
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "session-v2.sqlite3"
            make_db(path)
            with closing(sqlite3.connect(path)) as db:
                db.execute("CREATE TABLE samples (instance_id INTEGER,"
                           "series TEXT,series_seq INTEGER,"
                           "correlation_key TEXT)")
                db.executemany(
                    "INSERT INTO samples VALUES (1,'STANDARD',?,?)",
                    ((seq, f"schema1:{seq}") for seq in range(1, 1807)))
                db.commit()
            # Reproduces a >10000-instruction COUNT/MIN/MAX/SUM over real rows.
            self.check(path, expected_standard_samples=1806)

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
