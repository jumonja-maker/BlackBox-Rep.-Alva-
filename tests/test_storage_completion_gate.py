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

from blackbox_core.contracts import ObserverError, Sample
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

    @staticmethod
    def _base_sample():
        return Sample(1000, 4096, 0.0, 1, None, None, 0)

    @staticmethod
    def _base_payload(store, *, correlation_key="schema1:1"):
        v2 = store.v2
        now = time.monotonic_ns()
        return {
            "time_ns": now, "capture_started_ns": now,
            "capture_ended_ns": now, "pid": v2.pid,
            "created": v2.created, "correlation_key": correlation_key,
            "requested_interval_ns": 1_000_000_000,
            "rss_bytes": 4096, "cpu_percent": 0.0, "thread_count": 1,
        }

    @staticmethod
    def _start_pair(root):
        store = SessionStore(Path(root), os.getpid())
        store.enable_v2(
            pid=os.getpid(), created=time.time(), name="QA",
            origin_ns=time.monotonic_ns())
        assert store.v2._ready.wait(5) and not store.v2.failure
        return store

    @staticmethod
    def _reason(store):
        return [json.loads(data)["reason"] for (data,) in store.db.execute(
            "SELECT data FROM events") if '"reason"' in data]

    def test_closed_v2_with_missing_base_snapshot_cannot_certify_v1_completed(self):
        # The retained aecc fixture has v1=43, v2 STANDARD=27 plus DETAILED=13.
        # Recreate the *cardinality failure*, not a claim about its root cause.
        with tempfile.TemporaryDirectory() as root:
            store = self._start_pair(root)
            try:
                store.write_sample(self._base_sample())
                # An unrelated DETAILED row cannot make up for missing
                # accepted STANDARD samples.
                store.v2.submit("detail", self._base_payload(
                    store, correlation_key="detail:1"))
                with self.assertRaisesRegex(ObserverError, "STORAGE_ERROR"):
                    store.finish("COMPLETED")
                self.assertTrue(store.finished)
                self.assertEqual(store.db.execute(
                    "SELECT exit_code FROM metadata").fetchone()[0],
                    "STORAGE_ERROR")
                self.assertIn("V2_COMPLETION_BASE_COUNT_MISMATCH",
                              self._reason(store))
                self.assertFalse(store.v2.thread.is_alive())
            finally:
                store.close()

    def test_closed_v2_with_extra_base_snapshot_cannot_certify_v1_completed(self):
        with tempfile.TemporaryDirectory() as root:
            store = self._start_pair(root)
            try:
                store.v2.submit("base", self._base_payload(store))
                with self.assertRaisesRegex(ObserverError, "STORAGE_ERROR"):
                    store.finish("COMPLETED")
                self.assertEqual(store.db.execute(
                    "SELECT exit_code FROM metadata").fetchone()[0],
                    "STORAGE_ERROR")
                self.assertIn("V2_COMPLETION_BASE_COUNT_MISMATCH",
                              self._reason(store))
            finally:
                store.close()

    def test_same_count_but_wrong_correlation_is_not_a_complete_mirror(self):
        with tempfile.TemporaryDirectory() as root:
            store = self._start_pair(root)
            try:
                store.write_sample(self._base_sample())
                store.v2.submit("base", self._base_payload(
                    store, correlation_key="NOT_THE_SOURCE_SAMPLE"))
                with self.assertRaisesRegex(ObserverError, "STORAGE_ERROR"):
                    store.finish("COMPLETED")
                self.assertIn("V2_COMPLETION_BASE_MAPPING_MISMATCH",
                              self._reason(store))
                self.assertEqual(store.db.execute(
                    "SELECT exit_code FROM metadata").fetchone()[0],
                    "STORAGE_ERROR")
            finally:
                store.close()

    def test_exact_base_parity_allows_valid_run_with_optional_detail(self):
        with tempfile.TemporaryDirectory() as root:
            store = self._start_pair(root)
            try:
                store.write_sample(self._base_sample())
                store.v2.submit("base", self._base_payload(store))
                store.v2.submit("detail", self._base_payload(
                    store, correlation_key="detail:1"))
                store.finish("COMPLETED")
                self.assertEqual(store.db.execute(
                    "SELECT exit_code FROM metadata").fetchone()[0],
                    "COMPLETED")
                confirm_v2_completion(
                    store.v2.path, session_uuid=store.v2.session_uuid,
                    origin_ns=store.v2.origin_ns, exit_code="COMPLETED",
                    expected_standard_samples=1)
            finally:
                store.close()

    def test_early_readonly_v2_snapshot_is_not_evidence_of_final_writer_state(self):
        # Establish a real, independent alternative explanation for a
        # RECORDING archived SQLite alongside a later COMPLETED primary DB.
        # This does NOT establish how the old aecc QA copy was captured.
        with tempfile.TemporaryDirectory() as root:
            store = self._start_pair(root)
            archived = Path(root) / "controlled-before-stop.sqlite3"
            try:
                store.write_sample(self._base_sample())
                store.v2.submit("base", self._base_payload(store))
                store.v2._commands.join()  # only this already-accepted row
                with closing(sqlite3.connect(store.v2.path)) as live, closing(
                        sqlite3.connect(archived)) as snapshot:
                    live.backup(snapshot)
                store.finish("COMPLETED")
                with closing(sqlite3.connect(archived)) as copy:
                    self.assertEqual(copy.execute(
                        "SELECT status,exit_code FROM sessions").fetchone(),
                        ("RECORDING", None))
                confirm_v2_completion(
                    store.v2.path, session_uuid=store.v2.session_uuid,
                    origin_ns=store.v2.origin_ns, exit_code="COMPLETED",
                    expected_standard_samples=1)
                self.assertEqual(store.db.execute(
                    "SELECT exit_code FROM metadata").fetchone()[0],
                    "COMPLETED")
                with closing(sqlite3.connect(store.v2.path)) as live:
                    self.assertEqual(live.execute(
                        "SELECT status,exit_code FROM sessions").fetchone(),
                        ("CLOSED", "COMPLETED"))
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
