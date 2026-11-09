"""Actual SQLite/WAL interleavings must not mix a run's report generations."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from blackbox_core.chain_contracts import WorkflowError
from blackbox_core.chain_engine import WorkflowEngine
from blackbox_core.chain_reports import _document, export_workflow_run
from blackbox_core.chain_store import WorkflowRunStore
from test_chain_engine import adapter, outcome, workflow


class ChainReportCohortTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        definition = workflow([{"node_id": "actual", "tool_id": "read"}])
        self.store = WorkflowRunStore.create(self.root / "runs", definition)
        result = WorkflowEngine(definition, catalog={"read": adapter(
            "read", lambda ctx, inputs, params: outcome(ctx))}, store=self.store).run()
        self.assertEqual(result["state"], "COMPLETED")
        self.journal = self.store.folder / "journal" / "deep-inspection.sqlite3"

    def test_report_hydrates_only_the_captured_verified_events(self):
        original = self.store.read_events
        captured = []

        def capture_then_advance():
            records = original()
            if not captured:
                captured.append(records)
                self.store.append("run.state", data={"state": "WAITING_FOR_HUMAN"})
            return records

        with patch.object(self.store, "read_events", side_effect=capture_then_advance):
            # Main-file hash check is retained. With no pinned reader it may
            # detect this write first, which is also a truthful refusal.
            try:
                document, _ = _document(self.store, None, time.monotonic() + 30)
            except WorkflowError as error:
                self.assertIn("RUN_CHANGED_DURING_READ", str(error))
            else:
                self.assertEqual(document["run"]["state"], "COMPLETED")
                self.assertEqual(document["verification"]["journal_head"],
                                 [captured[0][-1]["sequence"], captured[0][-1]["record_sha256"]])

    def test_wal_only_advance_prevents_stale_report_publication(self):
        destination = self.root / "report.json"
        original = self.store.read_events
        advanced = []
        with closing(sqlite3.connect(self.journal)) as pinned:
            # The product also supports DELETE journals. Explicitly create
            # this fixture's WAL interleaving rather than assuming OS defaults.
            self.assertEqual(pinned.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            pinned.execute("BEGIN")
            pinned.execute("SELECT count(*) FROM actions").fetchone()
            before = hashlib.sha256(self.journal.read_bytes()).hexdigest()

            def capture_then_advance():
                records = original()
                if not advanced:
                    advanced.append(True)
                    self.store.append("run.state", data={"state": "WAITING_FOR_HUMAN"})
                    self.assertEqual(hashlib.sha256(self.journal.read_bytes()).hexdigest(), before,
                                     "fixture must exercise an actual WAL-only commit")
                return records

            with patch.object(self.store, "read_events", side_effect=capture_then_advance):
                with self.assertRaisesRegex(WorkflowError, "RUN_CHANGED_BEFORE_PUBLICATION"):
                    export_workflow_run(self.store, destination)
            self.assertFalse(destination.exists())
            self.assertEqual(advanced, [True])
            pinned.rollback()
        self.assertEqual(self.store.load_state()["state"], "WAITING_FOR_HUMAN")

    def test_stable_report_binds_current_verified_hash_chain_head(self):
        records = self.store.read_events()
        destination = self.root / "stable.json"
        export_workflow_run(self.store, destination)
        value = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(value["run"]["state"], "COMPLETED")
        self.assertEqual(value["verification"]["journal_head"],
                         [records[-1]["sequence"], records[-1]["record_sha256"]])
