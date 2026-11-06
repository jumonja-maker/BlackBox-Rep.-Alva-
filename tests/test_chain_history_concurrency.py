"""Actual file/SQL interleavings; cleanup payloads are storage fixtures, not native proof."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import psutil

from blackbox_core.chain_contracts import WorkflowError
from blackbox_core.chain_store import WorkflowRunStore
from blackbox_core.deep_journal import EvidenceJournal
from test_chain_engine import workflow


def cleanup_fixture():
    return {"cleanup": {"confirmed": False, "status": "RECOVERY_UNCONFIRMED", "bytes": 12},
            "scope": "STORAGE_FIXTURE_NOT_NATIVE_PROOF"}


class HistoryConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = WorkflowRunStore.create(self.root / "runs", workflow([{"node_id": "read", "tool_id": "read"}]))

    @contextmanager
    def unpublished_writer(self):
        published, release = threading.Event(), threading.Event()
        errors = []
        original = EvidenceJournal.append

        def append(journal, record):
            if record.get("event") == "run.cleanup":
                published.set()  # Actual immutable sidecar has already been published/read back.
                if not release.wait(10):
                    raise AssertionError("TEST_WRITER_BARRIER_TIMEOUT")
            return original(journal, record)

        def write():
            try:
                self.store.append("run.cleanup", data=cleanup_fixture())
            except BaseException as error:
                errors.append(error)

        with patch.object(EvidenceJournal, "append", append):
            thread = threading.Thread(target=write, name="history-real-writer")
            thread.start()
            try:
                self.assertTrue(published.wait(10), "actual sidecar publication must reach the barrier")
                yield
            finally:
                release.set()
                thread.join(10)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])

    def test_actual_uncommitted_sidecar_is_busy_then_reopens_without_false_corruption(self):
        with self.unpublished_writer():
            self.assertTrue((self.store.folder / ".events" / "2.json").is_file())
            with self.assertRaisesRegex(WorkflowError, "WORKFLOW_HISTORY_BUSY"):
                WorkflowRunStore.open(self.store.folder)
        reopened = WorkflowRunStore.open(self.store.folder)
        self.assertEqual(reopened.read_events()[-1]["data"], cleanup_fixture())
        self.assertFalse((self.store.folder / ".writer.json").exists())

    def test_commit_and_writer_release_after_sql_snapshot_is_busy_not_an_orphan(self):
        reader = WorkflowRunStore.open(self.store.folder)
        original, injected = os.scandir, []

        def scan(path):
            if Path(path) == self.store.folder / ".events" and not injected:
                injected.append(True)
                self.store.append("run.cleanup", data=cleanup_fixture())
                self.assertFalse((self.store.folder / ".writer.json").exists())
            return original(path)

        with patch("blackbox_core.chain_store.os.scandir", side_effect=scan):
            with self.assertRaisesRegex(WorkflowError, "WORKFLOW_HISTORY_BUSY"):
                reader.read_events()
        self.assertEqual(injected, [True])
        self.assertEqual(WorkflowRunStore.open(self.store.folder).read_events()[-1]["data"], cleanup_fixture())

    def test_own_new_writer_claim_cannot_hide_a_stable_orphan_during_budget_refresh(self):
        other = WorkflowRunStore.open(self.store.folder)
        other.append("run.state", data={"state": "RUNNING"})  # Make this facade's cached event count stale.
        orphan = self.store.folder / ".events" / "3.json"
        orphan.write_bytes(b"{}")
        with self.assertRaisesRegex(WorkflowError, "WORKFLOW_EVENT_ORPHAN_OR_FOREIGN_RECORD"):
            self.store.acquire_writer()
        self.assertFalse((self.store.folder / ".writer.json").exists())
        self.assertTrue(orphan.is_file())

    def test_stale_process_instance_marker_does_not_hide_an_unbound_next_record(self):
        orphan = self.store.folder / ".events" / "2.json"
        orphan.write_bytes(b"{}")
        marker = {"schema": "blackbox.workflow-writer/1", "run_id": self.store.run_id,
                  "pid": os.getpid(), "process_created": psutil.Process().create_time() + 1,
                  "owner_nonce": "stale-instance-fixture"}
        (self.store.folder / ".writer.json").write_text(json.dumps(marker), encoding="utf-8")
        with self.assertRaisesRegex(WorkflowError, "WORKFLOW_EVENT_ORPHAN_OR_FOREIGN_RECORD"):
            WorkflowRunStore.open(self.store.folder)
        self.assertTrue(orphan.is_file())

    def test_known_sidecar_corruption_is_not_hidden_by_an_actual_live_other_writer(self):
        self.store.append("run.cleanup", data=cleanup_fixture())
        known = self.store.folder / ".events" / "2.json"
        with self.unpublished_writer():
            document = json.loads(known.read_bytes())
            document["data"]["cleanup"]["confirmed"] = True
            known.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(WorkflowError, "WORKFLOW_EVENT_BINDING_CHANGED"):
                WorkflowRunStore.open(self.store.folder)

    def test_same_facade_read_cannot_overwrite_a_newer_append_sequence(self):
        reading, release, writer_started, writer_done = (threading.Event() for _ in range(4))
        errors, original = [], os.scandir

        def scan(path):
            if Path(path) == self.store.folder / ".events" and threading.current_thread().name == "history-reader":
                reading.set()
                if not release.wait(10):
                    raise AssertionError("TEST_READER_BARRIER_TIMEOUT")
            return original(path)

        def read():
            try:
                self.store.read_events()
            except BaseException as error:
                errors.append(error)

        def write():
            writer_started.set()
            try:
                self.store.append("run.cleanup", data=cleanup_fixture())
            except BaseException as error:
                errors.append(error)
            finally:
                writer_done.set()

        with patch("blackbox_core.chain_store.os.scandir", side_effect=scan):
            reader = threading.Thread(target=read, name="history-reader")
            writer = threading.Thread(target=write, name="history-same-facade-writer")
            reader.start()
            try:
                self.assertTrue(reading.wait(10))
                writer.start()
                self.assertTrue(writer_started.wait(10))
                self.assertFalse(writer_done.wait(.1), "append must wait for the existing facade read")
            finally:
                release.set()
                reader.join(10)
                if writer.ident is not None:
                    writer.join(10)
            self.assertFalse(reader.is_alive())
            self.assertFalse(writer.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(self.store._event_count, 2)
        self.store.append("run.cleanup", data=cleanup_fixture())
        records = WorkflowRunStore.open(self.store.folder).read_events()
        self.assertEqual([row["sequence"] for row in records], [1, 2, 3])
        self.assertEqual(records[-1]["journal_binding"]["event_record_path"], ".events/3.json")
