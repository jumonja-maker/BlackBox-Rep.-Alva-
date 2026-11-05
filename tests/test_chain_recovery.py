"""Persisted-intent recovery and source immutability; no native PASS claims."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from blackbox_core.chain_contracts import PortSpec, WorkflowDefinition, WorkflowError
from blackbox_core.chain_engine import WorkflowEngine
from blackbox_core.chain_store import WorkflowRunStore
from test_chain_engine import adapter, edge, node_records, outcome, workflow


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_unfinished_effectful_intent_is_uncertain_and_never_automatically_repeated(self):
        calls = []
        definition = workflow([{"node_id": "effect", "tool_id": "effect"}])
        value = definition.to_dict()
        value["profile"] = {"profile_id": "application", "overrides": {"allow_effectful": True}}
        definition = WorkflowDefinition.from_dict(value)
        store = WorkflowRunStore.create(self.root / "runs", definition)
        store.append("node.intent", node_id="effect", data={"node_id": "effect", "node_run_id": "lost-ack-call",
            "iteration": 0, "state": "RUNNING", "execution_started": None,
            "started_monotonic_ns": 1, "read_only": False, "tool_id": "effect"})
        catalog = {"effect": adapter("effect", lambda ctx, inputs, params: calls.append(ctx.node_id), read_only=False)}
        restored = WorkflowEngine.restore(WorkflowRunStore.open(store.folder), catalog=catalog)
        self.assertEqual(calls, [])
        self.assertIn("RECOVERY_UNCONFIRMED", {row["state"] for row in restored.snapshot()["nodes"]})
        resumed = restored.resume()
        self.assertEqual(calls, [])
        self.assertNotEqual(resumed["state"], "COMPLETED")

    def test_reopen_and_preview_do_not_dispatch_even_a_readonly_call(self):
        calls = []
        definition = workflow([{"node_id": "read", "tool_id": "read"}])
        store = WorkflowRunStore.create(self.root / "runs", definition)
        reopened = WorkflowRunStore.open(store.folder)
        restored = WorkflowEngine.restore(reopened, catalog={"read": adapter("read",
            lambda ctx, inputs, params: calls.append(ctx.node_id))})
        restored.snapshot()
        reopened.load_state()
        self.assertEqual(calls, [])
        self.assertEqual(reopened.definition.fingerprint, definition.fingerprint)

    def test_checkpoint_reopen_resume_keeps_completed_results_immutable(self):
        calls = []
        def execute(ctx, inputs, params):
            calls.append(ctx.node_id)
            return outcome(ctx)
        definition = workflow([{"node_id": "saved", "tool_id": "read"},
            {"node_id": "checkpoint", "kind": "CHECKPOINT", "budget_seconds": 1},
            {"node_id": "after", "tool_id": "consume"}], [
                edge("saved", "checkpoint", port="receipt", target="after"),
                edge("saved", "after"), edge("checkpoint", "after", port="continue", target="when")])
        catalog = {"read": adapter("read", execute), "consume": adapter("consume", execute,
                                                               inputs={"input": PortSpec(("REPORT",))})}
        store = WorkflowRunStore.create(self.root / "runs", definition)
        paused = WorkflowEngine(definition, catalog=catalog, store=store).run()
        self.assertEqual(paused["state"], "WAITING_FOR_HUMAN")
        previous = deepcopy(node_records(paused)["saved"])
        restored = WorkflowEngine.restore(WorkflowRunStore.open(store.folder), catalog=catalog)
        self.assertEqual(calls, ["saved"])
        complete = restored.resume()
        self.assertEqual(complete["state"], "COMPLETED")
        self.assertEqual(calls, ["saved", "after"])
        self.assertEqual(node_records(complete)["saved"], previous)

    def test_resume_refuses_changed_file_and_retains_original_completed_metadata(self):
        calls = []
        def execute(ctx, inputs, params):
            calls.append(ctx.node_id)
            return outcome(ctx)
        definition = workflow([{"node_id": "saved", "tool_id": "read"},
            {"node_id": "checkpoint", "kind": "CHECKPOINT", "budget_seconds": 1},
            {"node_id": "after", "tool_id": "consume"}], [
                edge("saved", "checkpoint", port="receipt", target="after"),
                edge("saved", "after"), edge("checkpoint", "after", port="continue", target="when")])
        catalog = {"read": adapter("read", execute), "consume": adapter("consume", execute,
                                                               inputs={"input": PortSpec(("REPORT",))})}
        store = WorkflowRunStore.create(self.root / "runs", definition)
        engine = WorkflowEngine(definition, catalog=catalog, store=store)
        paused = engine.run()
        previous = deepcopy(node_records(paused)["saved"])
        artifact = previous["outputs"]["report"][0]
        Path(artifact["value"]["_path"]).write_text("changed after explicit checkpoint", encoding="utf-8")
        resumed = engine.resume()
        self.assertNotEqual(resumed["state"], "COMPLETED")
        self.assertEqual(calls, ["saved"])
        self.assertEqual(node_records(resumed)["saved"], previous)

    def test_sql_journal_corruption_cannot_restore_an_apparently_complete_run(self):
        definition = workflow([{"node_id": "read", "tool_id": "read"}])
        store = WorkflowRunStore.create(self.root / "runs", definition)
        engine = WorkflowEngine(definition, catalog={"read": adapter("read", lambda ctx, inputs, params: outcome(ctx))},
                                store=store)
        self.assertEqual(engine.run()["state"], "COMPLETED")
        journal = next(Path(store.folder).rglob("deep-inspection.sqlite3"))
        with sqlite3.connect(journal) as db:
            db.execute("UPDATE actions SET record_sha256=? WHERE sequence=(SELECT max(sequence) FROM actions)",
                       ("0" * 64,))
        with self.assertRaises((ValueError, RuntimeError)):
            WorkflowRunStore.open(store.folder).read_events()


class StoreBoundaryTests(unittest.TestCase):
    """Real local SQL/filesystem boundaries executed only in hosted CI."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.definition = workflow([{"node_id": "read", "tool_id": "read"}])
        self.store = WorkflowRunStore.create(self.root / "runs", self.definition)

    def result(self):
        # This is deliberately metadata, not a fabricated native invocation.
        value = {"node_id": "read", "node_run_id": "fixture-result", "iteration": 0,
                 "state": "COMPLETED", "component_status": "FIXTURE_METADATA_ONLY",
                 "execution_started": False, "run_receipt": None, "run_context": None,
                 "outputs": {"report": [{"kind": "REPORT", "artifact_id": "fixture",
                     "value": {"bytes": 123, "_path": str(self.root / "source.json")}}]},
                 "cleanup": {"status": "NO_NATIVE_RESOURCES", "confirmed": True},
                 "started_monotonic_ns": 1, "ended_monotonic_ns": 2}
        self.store.append("node.result", node_id="read", data=value)
        return value, self.store.folder / ".results" / "fixture-result.json"

    def test_private_result_keeps_numeric_file_size_and_full_bound_record(self):
        value, sidecar = self.result()
        events = self.store.read_events()
        event = next(item for item in events if item["event"] == "node.result")
        self.assertEqual(event["data"], value)
        self.assertEqual(event["data"]["outputs"]["report"][0]["value"]["bytes"], 123)
        self.assertEqual(hashlib.sha256(sidecar.read_bytes()).hexdigest(),
                         event["journal_binding"]["result_sha256"])
        self.assertNotIn("outputs", event["journal_binding"])

    def test_result_sidecar_changed_bytes_are_rejected(self):
        _, sidecar = self.result()
        document = json.loads(sidecar.read_text(encoding="utf-8"))
        document["node"]["component_status"] = "FORGED_COMPLETED"
        sidecar.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(ValueError):
            WorkflowRunStore.open(self.store.folder)

    def test_even_rebound_sidecar_cannot_claim_another_run_or_node(self):
        # These local hashes are not authentication. Deliberately recomputing
        # every local hash must still fail the envelope's semantic binding.
        _, sidecar = self.result()
        envelope = json.loads(sidecar.read_text(encoding="utf-8"))
        envelope["run_id"] = "different-run"
        envelope["node"]["node_id"] = "different-node"
        sidecar.write_text(json.dumps(envelope), encoding="utf-8")
        stamp = sidecar.stat()
        journal = self.store.folder / "journal" / "deep-inspection.sqlite3"
        previous = "0" * 64
        with sqlite3.connect(journal) as db:
            rows = db.execute("SELECT sequence,record_json FROM actions ORDER BY sequence").fetchall()
            for sequence, raw in rows:
                record = json.loads(raw)
                if record["event"] == "node.result":
                    record["data"].update(result_sha256=hashlib.sha256(sidecar.read_bytes()).hexdigest(),
                        result_size_bytes=stamp.st_size, result_file_identity={"device": stamp.st_dev,
                            "inode": stamp.st_ino, "size": stamp.st_size, "mtime_ns": stamp.st_mtime_ns})
                raw = json.dumps(record, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
                digest = hashlib.sha256(previous.encode("ascii") + raw.encode("utf-8")).hexdigest()
                db.execute("UPDATE actions SET record_json=?,previous_sha256=?,record_sha256=? WHERE sequence=?",
                           (raw, previous, digest, sequence))
                previous = digest
        with self.assertRaisesRegex(WorkflowError, "WORKFLOW_RESULT_ENVELOPE_INVALID"):
            WorkflowRunStore.open(self.store.folder)

    def test_missing_result_sidecar_is_not_replaced_with_journal_summary(self):
        _, sidecar = self.result()
        sidecar.unlink()
        with self.assertRaises((OSError, ValueError)):
            WorkflowRunStore.open(self.store.folder)
        self.assertFalse(sidecar.exists())

    def test_open_missing_journal_does_not_initialize_an_empty_database(self):
        path = self.store.folder / "journal" / "deep-inspection.sqlite3"
        path.unlink()
        with self.assertRaises(ValueError):
            WorkflowRunStore.open(self.store.folder)
        self.assertFalse(path.exists())

    def test_open_is_passive_and_preserves_all_history_files(self):
        self.result()
        def files():
            return {path.relative_to(self.store.folder).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in self.store.folder.rglob("*") if path.is_file()}
        before = files()
        with WorkflowRunStore.open(self.store.folder) as opened:
            opened.load_state()
        self.assertEqual(files(), before)

    def test_two_facades_cannot_acquire_the_same_active_history(self):
        other = WorkflowRunStore.open(self.store.folder)
        self.store.acquire_writer()
        try:
            with self.assertRaisesRegex(WorkflowError, "WORKFLOW_RUN_WRITER_BUSY"):
                other.acquire_writer()
            with self.assertRaisesRegex(WorkflowError, "WORKFLOW_RUN_WRITER_BUSY"):
                other.append("run.state", data={"state": "RUNNING"})
        finally:
            self.store.release_writer()
        other.acquire_writer()
        other.release_writer()

    def test_writer_release_refuses_replaced_ownership_record(self):
        self.store.acquire_writer()
        path = self.store.folder / ".writer.json"
        marker = json.loads(path.read_text(encoding="utf-8"))
        marker["owner_nonce"] = "different-owner"
        path.write_text(json.dumps(marker), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.store.release_writer()
        self.assertTrue(path.exists(), "unowned lock must not be removed")

    def test_close_cannot_drop_writer_pinned_by_a_retained_live_worker(self):
        other = WorkflowRunStore.open(self.store.folder)
        self.store.acquire_writer()
        self.store.pin_writer()
        try:
            self.assertFalse(self.store.close(), "a live worker still owns the history writer")
            self.assertTrue((self.store.folder / ".writer.json").exists())
            with self.assertRaisesRegex(WorkflowError, "WORKFLOW_RUN_WRITER_BUSY"):
                other.acquire_writer()
            with self.assertRaisesRegex(WorkflowError, "WORKFLOW_WRITER_RETAINED_BY_LIVE_WORKER"):
                self.store.release_writer()
        finally:
            self.store.unpin_writer()
            self.store.release_writer()
        self.assertFalse((self.store.folder / ".writer.json").exists())
        self.assertTrue(self.store.close())
        other.acquire_writer()
        other.release_writer()

    def test_raw_sensitive_payload_is_redacted_before_private_persistence(self):
        value = {"node_id": "read", "node_run_id": "sensitive-result", "iteration": 0,
                 "state": "PARTIAL", "payload": "a-secret-memory-payload", "native_context_ownership": {
                     "context_id": "private-live-context", "owner_run_id": self.store.run_id}}
        self.store.append("node.result", node_id="read", data=value)
        raw = (self.store.folder / ".results" / "sensitive-result.json").read_text(encoding="ascii")
        self.assertNotIn("a-secret-memory-payload", raw)
        self.assertNotIn("private-live-context", raw)
        self.assertIn("SENSITIVE_PAYLOAD", raw)


if __name__ == "__main__":
    unittest.main()
