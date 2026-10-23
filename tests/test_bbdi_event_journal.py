"""BB-DI-001 bounded durable event journal and GUI schema1 integration.

No Windows user interaction is simulated as an OS-verified hang. All test
fixtures are local synthetic events, never user diagnostic measurements.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
from threading import Event, get_ident
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from blackbox_core.contracts import ObserverError
from blackbox_core.storage import SessionStore
from blackbox_universal.monitor import ReadOnlyProbe


def saved_events(folder: Path) -> list[dict]:
    with closing(sqlite3.connect(folder / "session.sqlite3")) as db:
        return [json.loads(row[0]) for row in db.execute(
            "SELECT data FROM events ORDER BY seq")]


class JournalCoreTests(unittest.TestCase):
    def test_worker_owned_sqlite_preserves_fifo_and_durable_command_ack(self):
        with tempfile.TemporaryDirectory() as root:
            store = SessionStore(Path(root), os.getpid())
            store.enable_background_events(queue_capacity=3)
            journal = store._journal
            parent_id = get_ident()
            worker_ids = []
            original = journal._write_one

            def observe(db, payload):
                worker_ids.append(get_ident())
                return original(db, payload)

            try:
                with patch.object(journal, "_write_one", side_effect=observe):
                    store.write_lifecycle_event({"kind": "observer_lifecycle",
                                                 "code": "FIRST"})
                    store.write_event({"kind": "action_marker",
                                       "event": "ACTION_STARTED", "source": "USER_COMMAND_UNVERIFIED"})
                    store.write_lifecycle_event({"kind": "observer_lifecycle",
                                                 "code": "LAST"})
                    store.finish("COMPLETED")
            finally:
                store.close()
            entries = saved_events(store.folder)
            self.assertEqual([e.get("code", e.get("event")) for e in entries],
                             ["FIRST", "ACTION_STARTED", "LAST"])
            self.assertEqual(len(worker_ids), 3)
            self.assertNotIn(parent_id, worker_ids)
            with closing(sqlite3.connect(store.folder / "session.sqlite3")) as db:
                self.assertEqual(db.execute(
                    "SELECT schema_version, exit_code FROM metadata").fetchone(),
                    (1, "COMPLETED"))

    def test_full_bounded_queue_rejects_extra_event_without_partial_data(self):
        entered, release = Event(), Event()
        with tempfile.TemporaryDirectory() as root:
            store = SessionStore(Path(root), os.getpid())
            store.enable_background_events(queue_capacity=1)
            journal = store._journal
            original = journal._write_one

            def slow(db, payload):
                entered.set()
                self.assertTrue(release.wait(5))
                original(db, payload)

            try:
                with patch.object(journal, "_write_one", side_effect=slow):
                    store.write_lifecycle_event({"kind": "test", "n": 1})
                    self.assertTrue(entered.wait(5))
                    store.write_lifecycle_event({"kind": "test", "n": 2})
                    self.assertEqual(journal.pending, 1)
                    with self.assertRaisesRegex(
                            ObserverError, "storage:STORAGE_ERROR"):
                        store.write_lifecycle_event({"kind": "test", "n": 3})
                    release.set()
                    store.finish("COMPLETED")
            finally:
                release.set()
                store.close()
            self.assertEqual([e["n"] for e in saved_events(store.folder)], [1, 2])

    def test_unexpected_writer_exception_must_not_acknowledge_user_action(self):
        with tempfile.TemporaryDirectory() as root:
            store = SessionStore(Path(root), os.getpid())
            store.enable_background_events()
            try:
                with patch.object(store._journal, "_write_one",
                                  side_effect=RuntimeError("injected fault")):
                    with self.assertRaisesRegex(
                            ObserverError, "storage:STORAGE_ERROR"):
                        store.write_event({"kind": "action_marker",
                                           "event": "ACTION_PREPARED"})
                self.assertTrue(store._journal.failed)
                with self.assertRaises(ObserverError):
                    store.finish("COMPLETED")
            finally:
                store.close()
            self.assertEqual(saved_events(store.folder), [])
            with closing(sqlite3.connect(store.folder / "session.sqlite3")) as db:
                self.assertIsNone(db.execute(
                    "SELECT exit_code FROM metadata").fetchone()[0])

    def test_schema1_old_sync_default_does_not_start_an_event_thread(self):
        with tempfile.TemporaryDirectory() as root:
            store = SessionStore(Path(root), os.getpid())
            try:
                self.assertIsNone(store._journal)
                store.write_event({"kind": "legacy"})
                store.finish("COMPLETED")
            finally:
                store.close()
            self.assertEqual(saved_events(store.folder), [{"kind": "legacy"}])


class QtEventJournalTests(unittest.TestCase):
    def test_gui_production_session_preserves_action_events_and_user_markers(self):
        from PySide6.QtWidgets import QApplication
        from blackbox_universal.window import UniversalWindow
        app = QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as root, patch(
                "blackbox_universal.monitor._default_sessions_root",
                return_value=Path(root)):
            window = UniversalWindow()
            window._timer.stop()
            try:
                self.assertTrue(window.probe.background_events)
                self.assertEqual(window.stack.count(), 5)
                window.probe.attach(os.getpid())
                window._start()
                self.assertIsNotNone(window.probe._store._journal)
                window.probe.tick()
                window.probe.mark_problem("test only")
                window.probe.prepare_action(baseline_ms=0)
                window.probe.tick()
                window.probe.begin_action()
                window.probe.finish_action()
                window.probe.actions.cool_down_ms = 0
                window.probe.tick()
                window._stop()
                folder = window.probe.session_folder
                events = saved_events(folder)
                codes = [e.get("event") for e in events
                         if e.get("kind") == "action_marker"]
                self.assertEqual(codes,
                                 ["ACTION_PREPARED", "BASELINE_STARTED",
                                  "ACTION_STARTED", "ACTION_ENDED",
                                  "ACTION_COMPLETED"])
                self.assertEqual(
                    len([e for e in events if e.get("kind") == "user_problem"]), 1)
                self.assertEqual(events[0]["code"], "OBSERVATION_STARTED")
                self.assertEqual(events[-1]["code"], "USER_STOPPED")
                self.assertIsNone(window.probe._store)
                self.assertTrue((folder / "report.json").is_file())
                self.assertTrue((folder / "report.html").is_file())
                app.processEvents()
            finally:
                window.close()


if __name__ == "__main__":
    unittest.main()
