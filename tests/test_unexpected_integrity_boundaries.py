"""Adversarial contracts: no false completed logs, links, or resource deltas.

The failures below are deterministic and exercise real SQLite writes, source
tail offsets and finalization (not the platform-dependent endurance QA).
"""
from __future__ import annotations

from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from blackbox_core.casebook import CaseBook, context
from blackbox_core.contracts import ObserverError, Sample
from blackbox_core.experiment_metrics import measure_interval
from blackbox_core.instrumentation import EventTail, EventWriter
from blackbox_core.research_worker import ResearchSession
from blackbox_core.storage import SessionStore
from blackbox_universal.base_sample_worker import BaseSampleWorker
from blackbox_universal.monitor import ReadOnlyProbe


def unavailable_sample():
    return Sample(elapsed_ms=100, rss_bytes=None, cpu_percent=None,
                  num_threads=None, read_bytes=None, write_bytes=None,
                  children_count=None)


class ResearchIndexIntegrityTests(unittest.TestCase):
    def test_completed_action_points_to_actual_research_evidence_not_legacy_seq(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SessionStore(Path(tmp), os.getpid())
            book = CaseBook(store.folder, os.getpid(), time.time(),
                            {"origin_monotonic_ns": time.monotonic_ns()})
            try:
                for index in range(4):
                    book.put("other_evidence", {"index": index}, mirror=False)
                store.write_event({
                    "kind": "action_marker", "event": "ACTION_COMPLETED",
                    "action_id": "action-1", "experiment_id": "experiment-1",
                    "duration_ns": 456_000_000})
                book.sync_legacy()
                with closing(sqlite3.connect(book.path)) as db:
                    row = db.execute(
                        "SELECT evidence_ref FROM action_runs WHERE action_id='action-1'"
                    ).fetchone()
                    self.assertIsNotNone(row)
                    ref = row[0]
                    # Its id is different from the session.sqlite3 event seq.
                    self.assertGreater(ref, 4)
                    kind, payload = db.execute(
                        "SELECT kind,data FROM evidence WHERE id=?", (ref,)
                    ).fetchone()
                    self.assertEqual(kind, "ACTION_COMPLETED")
                    self.assertIn('"action-1"', payload)
            finally:
                book.close("INCOMPLETE")
                store.finish("COMPLETED")
                store.close()

    def test_failed_sample_insert_does_not_advance_seq_or_leave_open_txn(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SessionStore(Path(tmp), os.getpid())
            try:
                store.db.execute(
                    "CREATE TRIGGER reject_sample BEFORE INSERT ON samples "
                    "BEGIN SELECT RAISE(ABORT, 'no space'); END")
                store.db.commit()
                with self.assertRaises(ObserverError):
                    store.write_sample(unavailable_sample())
                self.assertEqual(store.seq, 0)
                store.db.execute("DROP TRIGGER reject_sample")
                store.db.commit()
                store.write_sample(unavailable_sample())
                self.assertEqual(store.seq, 1)
                self.assertEqual(store.db.execute(
                    "SELECT seq FROM samples").fetchone()[0], 1)
            finally:
                store.finish("COMPLETED")
                store.close()


class MeasurementIntegrityTests(unittest.TestCase):
    def test_interval_switch_excludes_unobserved_cpu_and_io_span(self):
        def row(seq, stamp, interval, cpu, read):
            return {
                "series_seq": seq, "time_ns": stamp,
                "requested_interval_ns": interval,
                "cpu_user_s": cpu, "cpu_system_s": 0,
                "read_bytes": read, "write_bytes": read,
                "read_ops": read, "write_ops": read,
                "rss_bytes": 1024, "private_bytes": None,
                "uss_bytes": None, "handle_count": None,
                "thread_count": 1,
            }
        rows = [
            row(1, 0, 1_000_000_000, 0, 0),
            row(2, 3_000_000_000, 3_000_000_000, 30, 300),
            row(3, 4_000_000_000, 3_000_000_000, 31, 310),
        ]
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.execute(
            "CREATE TABLE events(event_type TEXT,source_kind TEXT,"
            "measurement_status TEXT,observed_ns INTEGER,recorded_ns INTEGER)")
        view = SimpleNamespace(
            db=db, reader=SimpleNamespace(
                iter_samples=lambda *args, **kwargs: iter(rows)))
        result = measure_interval(view, 0, 4_000_000_000, series="STANDARD")
        self.assertEqual(result["gaps"], 1)
        self.assertEqual(result["pair_count"]["cpu_seconds"], 1)
        self.assertEqual(result["metrics"]["cpu_seconds"], 1)
        self.assertEqual(result["metrics"]["read_bytes"], 10)
        self.assertEqual(result["covered_ns"]["cpu_seconds"], 1_000_000_000)


class StopDurabilityTests(unittest.TestCase):
    def start_probe(self, root):
        probe = ReadOnlyProbe(Path(root))
        probe.attach(os.getpid())
        probe.start()
        probe.tick()
        self.assertTrue(probe.active)
        return probe

    def exit_code(self, probe):
        with closing(sqlite3.connect(
                probe.session_folder / "session.sqlite3")) as db:
            return db.execute("SELECT exit_code FROM metadata").fetchone()[0]

    def test_aborted_action_log_failure_cannot_mark_completed(self):
        with tempfile.TemporaryDirectory() as tmp:
            probe = self.start_probe(tmp)
            with patch.object(probe.actions, "abort",
                              side_effect=ObserverError("STORAGE_ERROR", "storage")):
                probe.stop(defer_report=True)
            self.assertEqual(probe.session_state, "STORAGE_ERROR")
            self.assertEqual(self.exit_code(probe), "STORAGE_ERROR")

    def test_final_lifecycle_event_failure_cannot_mark_completed(self):
        with tempfile.TemporaryDirectory() as tmp:
            probe = self.start_probe(tmp)
            store = probe._store
            original = store.write_lifecycle_event

            def selective_failure(record):
                if record.get("code") == "USER_STOPPED":
                    raise ObserverError("STORAGE_ERROR", "storage")
                return original(record)

            with patch.object(store, "write_lifecycle_event",
                              side_effect=selective_failure):
                probe.stop(defer_report=True)
            self.assertEqual(probe.session_state, "STORAGE_ERROR")
            self.assertEqual(self.exit_code(probe), "STORAGE_ERROR")


class CooperativeLogIntegrityTests(unittest.TestCase):
    def test_same_inode_same_size_spool_rewrite_invalidates_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            writer = EventWriter(path, "a" * 32)
            tail = EventTail(path, "a" * 32, os.getpid())
            self.assertTrue(writer.emit("blackbox.ready"))
            self.assertEqual(len(tail.poll()), 1)
            self.assertTrue(tail.ready)
            original = path.read_bytes()
            changed = original.replace(b"blackbox.ready", b"blackbox.wait!")
            self.assertNotEqual(original, changed)
            self.assertEqual(len(changed), len(original))
            path.write_bytes(changed)  # preserves inode, size and offset
            rows = tail.poll()
            self.assertEqual([row["kind"] for row in rows], ["blackbox.wait!"])
            self.assertFalse(tail.ready)
            self.assertEqual(tail.discontinuities, 1)

    def test_deleted_spool_after_ready_is_reported_as_discontinuity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            writer = EventWriter(path, "b" * 32)
            tail = EventTail(path, "b" * 32, os.getpid())
            self.assertTrue(writer.emit("blackbox.ready"))
            tail.poll()
            self.assertTrue(tail.ready)
            path.unlink()
            self.assertEqual(tail.poll(), [])
            self.assertFalse(tail.ready)
            self.assertEqual(tail.discontinuities, 1)

    def test_stop_checks_spool_continuity_even_without_unread_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = ResearchSession(Path(tmp))
            session.command({"op": "attach", "args": {"pid": os.getpid()}})
            session.command({"op": "start"})
            try:
                writer = EventWriter(session.tail.path, session.tail.token)
                self.assertTrue(writer.emit("blackbox.ready"))
                session._application_events()
                self.assertTrue(session.tail.ready)
                session.tail.path.unlink()
                session.stop()
                health = context(session.probe.session_folder)["capture_health"]
                self.assertEqual(health["app_file_discontinuities"], 1)
                self.assertFalse(health["application_event_ready"])
                self.assertEqual(context(session.probe.session_folder)["state"], "INCOMPLETE")
            finally:
                session.stop()

    def test_application_sqlite_failure_is_explicit_not_silent_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = ResearchSession(Path(tmp))
            session.command({"op": "attach", "args": {"pid": os.getpid()}})
            session.command({"op": "start"})
            try:
                writer = EventWriter(session.tail.path, session.tail.token)
                self.assertTrue(writer.emit("blackbox.ready"))
                original = session.book.put

                def break_application_only(kind, *args, **kwargs):
                    if kind == "blackbox.ready":
                        raise sqlite3.OperationalError("synthetic research SQLite fault")
                    return original(kind, *args, **kwargs)

                with patch.object(session.book, "put",
                                  side_effect=break_application_only):
                    session._application_events()
                self.assertTrue(session.probe.active)
                self.assertTrue(session.app_source_error.startswith(
                    "APPLICATION_EVENT_PERSISTENCE_UNCONFIRMED"))
                self.assertEqual(session.app_events_unconfirmed, 1)
                session.stop()
                health = context(session.probe.session_folder)["capture_health"]
                self.assertEqual(
                    health["application_event_persistence_unconfirmed_rows"], 1)
                self.assertEqual(context(session.probe.session_folder)["state"], "INCOMPLETE")
            finally:
                session.stop()


class QtSampleWorkerIntegrityTests(unittest.TestCase):
    def test_unexpected_sqlite_failure_is_not_described_as_sample_failure(self):
        class GoodProbe:
            last_observation = None

            def sample(self):
                return unavailable_sample()

        worker = BaseSampleWorker(GoodProbe(), Path("."))
        received = []
        worker.result_ready.connect(lambda packet, error: received.append((packet, error)))
        with patch("blackbox_universal.base_sample_worker.write_sample_from_worker",
                   side_effect=RuntimeError("unexpected SQLite IO fault")):
            worker.run()
        self.assertEqual(received, [(None, "STORAGE_ERROR")])


if __name__ == "__main__":
    unittest.main()
