"""R10 receipt/Investigation 3 integration; fixtures are not native evidence.

These tests execute exclusively on GitHub-hosted runners. Actual elevated-token
and two-process native effects are covered separately by the Windows R10 E2E.
"""
from pathlib import Path
import hashlib
import json
import tempfile
import unittest

from blackbox_core.deep_contracts import ActionRequest, ProcessIdentity, result
from blackbox_core.deep_journal import EvidenceJournal
from blackbox_core.deep_tool_contracts import begin_run, attach_run_receipt
from blackbox_core.investigation_v3 import (create_investigation,
    export_investigation, load_investigation)


class R10InvestigationCompatibility(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.journal = EvidenceJournal(self.root / "journal")

    def record(self, identity, run_id, *, asserted_verified=False):
        request = ActionRequest("memory.write", identity,
            {"address": 4096, "expected_hex": "00000000", "value_hex": "f00dcafe"},
            confirmed=True)
        context = begin_run(request, run_id=run_id, permission_level="ADMINISTRATOR")
        base = {"action_id": run_id, "target": identity.to_dict(),
                "operation": request.operation,
                "source": "SYNTHETIC_FORMAT_FIXTURE_NOT_NATIVE_CAPTURE"}
        self.journal.append({**base, "operation_id": run_id + ":requested",
                             "phase": "REQUESTED", "run_context": context.to_dict()})
        answer = attach_run_receipt(context,
            result(request.operation, "COMPLETED", operation_id=run_id,
                   source=base["source"],
                   data={"change_id": "fixture-" + run_id,
                         "before_hex": "00000000", "after_hex": "f00dcafe"}),
            execution_started=None, source=base["source"],
            source_verified=asserted_verified, target_verified=asserted_verified,
            helper_pid=900)
        self.journal.append({**base, **answer,
                             "operation_id": run_id + ":result", "phase": "RESULT"})

    def build(self, **kwargs):
        return create_investigation(
            [{"source_type": "DEEP_JOURNAL", "path": str(self.journal.path)}],
            **kwargs)

    def test_two_target_receipts_survive_graph_index_and_export_readback(self):
        first = ProcessIdentity(501, 111111, r"C:\fixtures\first.exe")
        second = ProcessIdentity(502, 222222, r"C:\fixtures\second.exe")
        self.record(first, "run-A")
        self.record(second, "run-B")
        source_sha = hashlib.sha256(self.journal.path.read_bytes()).hexdigest()
        index = self.root / "investigation.sqlite3"
        case = self.build(index_path=index)
        loaded = load_investigation(index)
        self.assertEqual(case["case_id"], loaded["case_id"])
        outcomes = [node for node in loaded["nodes"]
                    if node["observation_type"] == "DIAGNOSTIC_ACTION"
                    and node["metadata"].get("phase") == "RESULT"]
        self.assertEqual(len(outcomes), 2)
        mapped = {node["metadata"]["run_receipt"]["run_id"]:
                  (node["process_identity"]["pid"],
                   node["process_identity"]["created_100ns"])
                  for node in outcomes}
        self.assertEqual(mapped, {"run-A": (501, 111111), "run-B": (502, 222222)})
        for node in outcomes:
            receipt = node["metadata"]["run_receipt"]
            self.assertEqual(receipt["contract_version"], 1)
            self.assertEqual(receipt["status"], "COMPLETED")
            self.assertFalse(receipt["cleanup"]["confirmed"])
        json_path, html_path = self.root / "report.json", self.root / "report.html"
        export_investigation(loaded, json_path)
        export_investigation(loaded, html_path, format="html")
        exported = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(exported["case_id"], case["case_id"])
        self.assertFalse(exported["root_cause_proven"])
        for path in (json_path, html_path):
            text = path.read_text(encoding="utf-8")
            self.assertIn("run-A", text)
            self.assertIn("run-B", text)
            self.assertNotIn("f00dcafe", text)
        self.assertEqual(hashlib.sha256(self.journal.path.read_bytes()).hexdigest(), source_sha)

    def test_imported_receipt_claims_never_join_reused_pid_lifetimes(self):
        self.record(ProcessIdentity(501, 111111), "old-instance", asserted_verified=True)
        self.record(ProcessIdentity(501, 222222), "new-instance", asserted_verified=True)
        case = self.build()
        self.assertTrue(case["sources"])
        self.assertTrue(all(source["verification_class"] == "UNVERIFIED_IMPORT"
                            for source in case["sources"]))
        nodes = {node["node_id"]: node for node in case["nodes"]}
        outcomes = [node for node in nodes.values()
                    if node["observation_type"] == "DIAGNOSTIC_ACTION"
                    and node["metadata"].get("phase") == "RESULT"]
        self.assertEqual(len(outcomes), 2)
        self.assertTrue(all(node["verification_class"] == "UNVERIFIED_IMPORT"
                            for node in outcomes))
        for edge in case["edges"]:
            if edge["relation_type"] != "EXACT_IDENTITY":
                continue
            identities = [nodes[edge[key]].get("process_identity")
                          for key in ("from_node", "to_node")]
            if all(identities):
                self.assertEqual(identities[0], identities[1])
