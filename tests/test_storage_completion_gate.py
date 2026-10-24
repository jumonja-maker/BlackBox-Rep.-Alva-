"""Durable-close integration with schema1/v2 and unchanged export refusal."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import tempfile
import time
import unittest

from blackbox_core.contracts import ObserverError
from blackbox_core.storage import SessionStore
from blackbox_core.session_completion import confirm_v2_completion


class StoreCompletionTests(unittest.TestCase):
    def test_real_writer_closes_before_primary_success(self):
        with tempfile.TemporaryDirectory() as root:
            store = SessionStore(Path(root), os.getpid())
            try:
                store.enable_v2(pid=os.getpid(), created=time.time(), name="QA",
                                origin_ns=time.monotonic_ns())
                store.write_event({"kind": "observer_lifecycle", "code": "QA_EVENT"})
                store.finish("COMPLETED")
                self.assertFalse(store.v2.thread.is_alive())
                confirm_v2_completion(store.v2.path,
                                      session_uuid=store.v2.session_uuid,
                                      origin_ns=store.v2.origin_ns,
                                      exit_code="COMPLETED")
                self.assertEqual(store.db.execute(
                    "SELECT exit_code FROM metadata").fetchone(), ("COMPLETED",))
                store.finish("COMPLETED")  # idempotent
            finally:
                store.close()

    def test_missing_closed_commit_is_failure_not_primary_completed(self):
        with tempfile.TemporaryDirectory() as root:
            store = SessionStore(Path(root), os.getpid())
            path = store.folder / "session-v2.sqlite3"
            with closing(sqlite3.connect(path)) as db:
                db.executescript("""
                    PRAGMA user_version=2;
                    CREATE TABLE sessions(session_uuid TEXT, schema_version INTEGER,
                        monotonic_origin_ns INTEGER, status TEXT,
                        ended_monotonic_ns INTEGER, exit_code TEXT);
                    INSERT INTO sessions VALUES ('qa',2,100,'RECORDING',NULL,NULL);
                """)
            before = hashlib.sha256(path.read_bytes()).hexdigest()
            # A fault-injected owner returns without a close commit. This is
            # NOT a claim that this caused the preserved aecc export failure.
            store.v2 = SimpleNamespace(path=path, session_uuid="qa", origin_ns=100,
                                       failure=None, finish=lambda code: None)
            try:
                with self.assertRaises(ObserverError):
                    store.finish("COMPLETED")
                self.assertEqual(store.db.execute(
                    "SELECT exit_code FROM metadata").fetchone(), ("STORAGE_ERROR",))
                evidence = [json.loads(row[0]) for row in store.db.execute(
                    "SELECT data FROM events")]
                self.assertEqual(evidence[-1]["reason"], "V2_COMPLETION_NOT_CLOSED")
                self.assertEqual(store.v2.failure, "V2_COMPLETION_NOT_CLOSED")
                self.assertTrue(store.finished)
            finally:
                store.close()
            self.assertEqual(before, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_export_of_recording_still_refused_no_guard_bypass(self):
        from blackbox_core.interval_report import export_interval
        from blackbox_core.session_view import SessionReadError
        with tempfile.TemporaryDirectory() as root:
            store = SessionStore(Path(root), os.getpid())
            output = Path(root) / "exports"
            output.mkdir()
            unrelated = output / "keep.txt"
            unrelated.write_text("user file", encoding="utf-8")
            try:
                store.enable_v2(pid=os.getpid(), created=time.time(), name="QA",
                                origin_ns=time.monotonic_ns())
                self.assertTrue(store.v2._ready.wait(5))
                with self.assertRaisesRegex(SessionReadError, "EXPORT_REQUIRES_CLOSED_SESSION"):
                    export_interval(store.folder, output, prefix="blocked")
                self.assertFalse(list(output.glob("blocked*")))
                self.assertEqual(unrelated.read_text("utf-8"), "user file")
                with closing(sqlite3.connect(store.v2.path)) as db:
                    self.assertEqual(db.execute("SELECT status FROM sessions").fetchone(),
                                     ("RECORDING",))
                store.finish("COMPLETED")
            finally:
                store.close()

    def test_legacy_without_v2_keeps_original_contract(self):
        with tempfile.TemporaryDirectory() as root:
            store = SessionStore(Path(root), os.getpid())
            try:
                store.write_event({"kind": "legacy"})
                store.finish("COMPLETED")
                self.assertEqual(store.db.execute(
                    "SELECT schema_version,exit_code FROM metadata").fetchone(),
                    (1, "COMPLETED"))
                self.assertFalse((store.folder / "session-v2.sqlite3").exists())
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
