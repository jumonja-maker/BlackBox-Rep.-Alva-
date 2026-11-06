"""Lossless workflow event persistence; synthetic ACKs are storage fixtures only.

All filesystem/SQLite execution belongs to the hosted CI test gate. None of
these fixtures establishes actual native cleanup or a saved native capability.
"""
from contextlib import closing
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from blackbox_core.chain_contracts import WorkflowError
from blackbox_core.chain_qa import independent_journal
from blackbox_core.chain_store import WorkflowRunStore
from blackbox_core.deep_journal import journal_metadata
from test_chain_engine import workflow


def nested_cleanup():
    acknowledgement = {"confirmed": False, "status": "RECOVERY_UNCONFIRMED",
                       "reason_code": "FIXTURE_CHECKED_CLOSE_FAILED", "bytes": 123}
    for _ in range(12):
        acknowledgement = {"evidence": acknowledgement}
    return {"cleanup": {"confirmed": False, "status": "RECOVERY_UNCONFIRMED",
                        "native_context": acknowledgement},
            "scope": "SYNTHETIC_METADATA_STORAGE_FIXTURE_NOT_NATIVE_PROOF"}


class WorkflowMetadataBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.definition = workflow([{"node_id": "read", "tool_id": "read"}])
        self.store = WorkflowRunStore.create(self.root / "runs", self.definition)

    def append_cleanup(self, data=None):
        data = nested_cleanup() if data is None else data
        self.store.append("run.cleanup", data=data)
        event = self.store.read_events()[-1]
        return data, event, self.store.folder / event["journal_binding"]["event_record_path"]

    def test_full_nested_cleanup_ack_and_numeric_sizes_survive_passive_reopen(self):
        value = nested_cleanup()
        self.assertNotEqual(journal_metadata(value), value)
        expected, event, path = self.append_cleanup(value)
        self.assertEqual(event["data"], expected)
        self.assertFalse(event["data"]["cleanup"]["confirmed"])
        self.assertEqual(event["journal_binding"]["event_record_path"], ".events/2.json")
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                         event["journal_binding"]["event_record_sha256"])
        self.assertNotIn("cleanup", event["journal_binding"])
        before = {p.relative_to(self.store.folder).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in self.store.folder.rglob("*") if p.is_file()}
        # A passive read never initializes a new journal, invokes native code,
        # or turns a saved unconfirmed cleanup into an acknowledgement.
        with patch("blackbox_core.chain_store.EvidenceJournal", side_effect=AssertionError("PASSIVE_OPEN_WROTE")):
            reopened = WorkflowRunStore.open(self.store.folder)
            self.assertEqual(reopened.read_events()[-1]["data"], expected)
            self.assertEqual(reopened.load_state()["cleanup"], expected["cleanup"])
            independent, proof = independent_journal(self.store.folder)
            self.assertEqual(independent[-1]["data"], expected)
            self.assertTrue(proof["hashchain_verified"])
        after = {p.relative_to(self.store.folder).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in self.store.folder.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_wrapper_depth_is_included_in_the_lossless_boundary(self):
        leaf = {"actual_boundary": "FIXTURE_UNCONFIRMED"}
        for _ in range(10):
            leaf = {"evidence": leaf}
        value = {"state": "PARTIAL", "metadata": leaf}
        self.assertEqual(journal_metadata(value), value)
        self.assertNotEqual(journal_metadata({"data": value}), {"data": value})
        self.store.append("run.state", data=value)
        event = WorkflowRunStore.open(self.store.folder).read_events()[-1]
        self.assertEqual(event["data"], value)
        self.assertIn("event_record_path", event["journal_binding"])

    def test_changed_or_missing_cleanup_sidecar_cannot_fall_back_to_a_summary(self):
        _, _, path = self.append_cleanup()
        original = path.read_bytes()
        document = json.loads(original)
        document["data"]["cleanup"]["confirmed"] = True
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(WorkflowError, "WORKFLOW_EVENT_BINDING_CHANGED"):
            WorkflowRunStore.open(self.store.folder)
        path.unlink()
        with self.assertRaises((OSError, ValueError)):
            WorkflowRunStore.open(self.store.folder)
        self.assertFalse(path.exists())

    def _rebind_journal(self, path):
        stamp = path.stat()
        previous = "0" * 64
        with closing(sqlite3.connect(self.store.folder / "journal" / "deep-inspection.sqlite3")) as db, db:
            rows = db.execute("SELECT sequence,record_json FROM actions ORDER BY sequence").fetchall()
            for sequence, raw in rows:
                record = json.loads(raw)
                if record["event"] == "run.cleanup":
                    record["data"].update(event_record_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                        event_record_size_bytes=stamp.st_size, event_record_file_identity={"device": stamp.st_dev,
                            "inode": stamp.st_ino, "size": stamp.st_size, "mtime_ns": stamp.st_mtime_ns})
                raw = json.dumps(record, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
                digest = hashlib.sha256(previous.encode("ascii") + raw.encode("utf-8")).hexdigest()
                db.execute("UPDATE actions SET record_json=?,previous_sha256=?,record_sha256=? WHERE sequence=?",
                           (raw, previous, digest, sequence))
                previous = digest

    def test_recomputed_local_hashes_do_not_allow_a_different_event_or_owner_binding(self):
        _, _, path = self.append_cleanup()
        original = json.loads(path.read_bytes())
        for key, value in (("run_id", "different-run"), ("definition_sha256", "0" * 64),
                           ("event", "run.state"), ("node_id", "read"), ("sequence", 3)):
            with self.subTest(field=key):
                changed = deepcopy(original)
                changed[key] = value
                path.write_text(json.dumps(changed), encoding="utf-8")
                self._rebind_journal(path)
                with self.assertRaisesRegex(WorkflowError, "WORKFLOW_EVENT_ENVELOPE_INVALID"):
                    WorkflowRunStore.open(self.store.folder)

    def test_sensitive_values_are_redacted_before_lossless_event_persistence(self):
        value = nested_cleanup()
        value["cleanup"]["native_context_ref"] = {"context_id": "fixture-private-live-capability"}
        value["api_key"] = "fixture-secret-never-persist"
        _, event, path = self.append_cleanup(value)
        raw = path.read_text(encoding="utf-8")
        self.assertNotIn("fixture-private-live-capability", raw)
        self.assertNotIn("fixture-secret-never-persist", raw)
        self.assertIn("SENSITIVE_PAYLOAD", raw)
        self.assertFalse(event["data"]["cleanup"]["confirmed"])

    def test_oversized_metadata_is_rejected_before_journal_or_sidecar_publication(self):
        before = self.store.read_events()
        value = nested_cleanup()
        value["large_metadata"] = ["x" * 32768] * 20
        with self.assertRaisesRegex(WorkflowError, "WORKFLOW_RECORD_BYTE_BUDGET"):
            self.store.append("run.cleanup", data=value)
        self.assertEqual(self.store.read_events(), before)
        self.assertEqual(list((self.store.folder / ".events").iterdir()), [])

    def test_history_budget_includes_the_full_event_record_and_checks_before_write(self):
        before = self.store.read_events()
        with patch("blackbox_core.chain_store.MAX_HISTORY_METADATA_BYTES", self.store._history_metadata_bytes + 100):
            with self.assertRaisesRegex(WorkflowError, "WORKFLOW_HISTORY_METADATA_BUDGET"):
                self.store.append("run.cleanup", data=nested_cleanup())
        self.assertEqual(self.store.read_events(), before)
        self.assertEqual(list((self.store.folder / ".events").iterdir()), [])

    def test_shallow_existing_events_remain_inline_and_legacy_directory_stays_passive(self):
        (self.store.folder / ".events").rmdir()
        self.store.append("run.state", data={"state": "COMPLETED"})
        opened = WorkflowRunStore.open(self.store.folder)
        event = opened.read_events()[-1]
        self.assertEqual(event["data"], {"state": "COMPLETED"})
        self.assertNotIn("journal_binding", event)
        self.assertFalse((self.store.folder / ".events").exists())

    def test_orphan_event_record_is_rejected_without_importing_or_deleting_it(self):
        _, _, path = self.append_cleanup()
        orphan = path.with_name("999.json")
        orphan.write_bytes(path.read_bytes())
        with self.assertRaisesRegex(WorkflowError, "WORKFLOW_EVENT_ORPHAN_OR_FOREIGN_RECORD"):
            WorkflowRunStore.open(self.store.folder)
        with self.assertRaisesRegex(AssertionError, "R60_EVENT_RECORD_ORPHAN_OR_FOREIGN"):
            independent_journal(self.store.folder)
        self.assertTrue(orphan.is_file())


if __name__ == "__main__":
    unittest.main()
