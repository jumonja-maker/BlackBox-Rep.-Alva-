"""Independent JSON/HTML, source, no-clobber and cancellation report oracles."""
from html.parser import HTMLParser
import json
from pathlib import Path
import tempfile
import threading
import unittest

from blackbox_core.chain_engine import WorkflowEngine
from blackbox_core.chain_reports import export_workflow_run
from blackbox_core.chain_store import WorkflowRunStore, load_definition, save_definition
from blackbox_core.chain_qa import independent_journal
from test_chain_engine import adapter, outcome, workflow, edge
from blackbox_core.chain_contracts import PortSpec


class WorkflowHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.active = False
        self.documents = []
        self.parts = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "script" and values.get("id") == "blackbox-workflow-data":
            if self.active or self.documents:
                raise AssertionError("DUPLICATE_WORKFLOW_HTML_METADATA")
            self.active = True

    def handle_data(self, data):
        if self.active:
            self.parts.append(data)

    def handle_endtag(self, tag):
        if self.active and tag == "script":
            self.documents.append(json.loads("".join(self.parts)))
            self.active = False


class WorkflowReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.definition = workflow([{"node_id": "actual-file", "tool_id": "read"}])
        self.store = WorkflowRunStore.create(self.root / "runs", self.definition)
        catalog = {"read": adapter("read", lambda ctx, inputs, params: outcome(ctx))}
        self.snapshot = WorkflowEngine(self.definition, catalog=catalog, store=self.store).run()
        self.assertEqual(self.snapshot["state"], "COMPLETED")

    def test_real_definition_round_trip_is_passive_and_preserves_fingerprint(self):
        path = self.root / "saved.bbchain.json"
        save_definition(self.definition, path)
        before = path.read_bytes()
        loaded = load_definition(path)
        self.assertEqual(loaded.fingerprint, self.definition.fingerprint)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(len(list((self.root / "runs").iterdir())), 1)

    def test_json_html_have_same_semantics_and_preserve_receipt_and_unknown_trust(self):
        parsed = {}
        journal_before = independent_journal(self.store.folder)[1]["sha256"]
        for format in ("json", "html"):
            destination = self.root / ("report." + format)
            receipt = export_workflow_run(self.store, destination, format=format)
            self.assertTrue(receipt["readback_verified"])
            raw = destination.read_text(encoding="utf-8")
            if format == "json":
                parsed[format] = json.loads(raw)
            else:
                reader = WorkflowHTML()
                reader.feed(raw)
                self.assertEqual(len(reader.documents), 1)
                self.assertFalse(reader.active)
                parsed[format] = reader.documents[0]
            document = parsed[format]
            self.assertEqual(document["schema"], "blackbox.workflow-report/1")
            self.assertEqual(document["run"]["run_id"], self.store.run_id)
            self.assertEqual(document["source_trust"], "UNVERIFIED_IMPORT")
            self.assertEqual(document["root_cause"], "UNKNOWN")
            self.assertIn("events", document)
            self.assertIn("links", document)
            self.assertNotIn(str(self.root), raw)
            results = [event for event in document["events"] if event.get("event") == "node.result"]
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["data"]["run_receipt"]["operation"], "qa.fixture.call")
            self.assertTrue(results[0]["data"]["cleanup"]["confirmed"])
        self.assertEqual(parsed["json"], parsed["html"])
        self.assertEqual(independent_journal(self.store.folder)[1]["sha256"], journal_before)

    def test_declared_link_binds_actual_artifact_and_receipt_without_causal_claim(self):
        definition = workflow([{"node_id": "first", "tool_id": "read"},
            {"node_id": "second", "tool_id": "consume"}], [edge("first", "second")])
        store = WorkflowRunStore.create(self.root / "linked-runs", definition)
        catalog = {"read": adapter("read", lambda ctx, inputs, params: outcome(ctx)),
            "consume": adapter("consume", lambda ctx, inputs, params: outcome(ctx),
                               inputs={"input": PortSpec(("REPORT",))})}
        snapshot = WorkflowEngine(definition, catalog=catalog, store=store).run()
        self.assertEqual(snapshot["state"], "COMPLETED")
        destination = self.root / "linked.json"
        export_workflow_run(store, destination)
        document = json.loads(destination.read_text())
        first = next(item for item in snapshot["nodes"] if item["node_id"] == "first")
        self.assertEqual(document["links"][0]["source_artifact_ids"],
                         [first["outputs"]["report"][0]["artifact_id"]])
        self.assertEqual(document["links"][0]["receipt_refs"], [first["run_receipt"]["run_id"]])
        self.assertEqual(document["links"][0]["link_scope"],
                         "DECLARED_WORKFLOW_DEPENDENCY_NOT_CAUSAL_PROOF")
        self.assertEqual(document["root_cause"], "UNKNOWN")

    def test_export_rejects_symlink_destination_and_preserves_its_owner_file(self):
        original = self.root / "owner.txt"
        original.write_text("existing owner data")
        destination = self.root / "symlink.json"
        try:
            destination.symlink_to(original)
        except (OSError, NotImplementedError):
            self.skipTest("Native symlink creation unavailable; no symlink acceptance claimed")
        with self.assertRaises((ValueError, FileExistsError)):
            export_workflow_run(self.store, destination)
        self.assertEqual(original.read_text(), "existing owner data")

    def test_export_refuses_existing_destination_without_changing_it(self):
        destination = self.root / "existing.json"
        destination.write_bytes(b"existing owner document")
        with self.assertRaises(FileExistsError):
            export_workflow_run(self.store, destination)
        self.assertEqual(destination.read_bytes(), b"existing owner document")

    def test_pre_cancelled_export_publishes_no_partial_report_and_preserves_run(self):
        destination = self.root / "cancelled.json"
        cancelled = threading.Event()
        cancelled.set()
        before = independent_journal(self.store.folder)[1]["sha256"]
        with self.assertRaises((InterruptedError, ValueError)):
            export_workflow_run(self.store, destination, cancel=cancelled)
        self.assertFalse(destination.exists())
        self.assertEqual(independent_journal(self.store.folder)[1]["sha256"], before)


if __name__ == "__main__":
    unittest.main()
