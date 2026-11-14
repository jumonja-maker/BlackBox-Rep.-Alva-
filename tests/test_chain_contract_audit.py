"""Concrete chain contract/condition/profile regressions; hosted execution only.

Preview adapters below are inert fixtures. These checks do not establish native
Windows rights, consent, instrumentation or collector acceptance.
"""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackbox_core.chain_adapters import build_catalog
from blackbox_core.chain_contracts import (Artifact, MAX_DEFINITION_BYTES, NodeDefinition,
    PortSpec, WorkflowDefinition, WorkflowError, json_data, parse_json)
from blackbox_core.chain_profiles import load_profile, verify_source_scope
from blackbox_core.chain_validation import evaluate_condition, validate_condition, validate_parameters, validate_workflow


def document(nodes=None, edges=(), **changes):
    return {"schema": "blackbox.workflow-definition/1", "workflow_id": "contract-audit",
            "title": "Inert contract fixture", "nodes": nodes or [{"node_id": "checkpoint", "kind": "CHECKPOINT"}],
            "edges": list(edges), **changes}


class ChainContractAuditTests(unittest.TestCase):
    def test_huge_budget_and_invalid_encoding_are_bounded_workflow_errors(self):
        huge = 10**330
        for raw in (b"\xff", "\ud800", '{"integer":' + "1" * 5000 + "}"):
            with self.subTest(raw_type=type(raw).__name__), self.assertRaises(WorkflowError):
                parse_json(raw)
        with self.assertRaises(WorkflowError):
            NodeDefinition.from_dict({"node_id": "budget", "kind": "CHECKPOINT", "budget_seconds": huge})
        result = validate_workflow(document(budget={"seconds": huge}), {})
        self.assertFalse(result["ready"])
        self.assertEqual(result["errors"][0]["code"], "INVALID_WORKFLOW_BUDGET")

    def test_shared_configuration_expansion_stops_at_the_existing_encoded_byte_budget(self):
        leaf = "x" * 8192
        shared = [leaf] * 1024
        with self.assertRaisesRegex(WorkflowError, "JSON_BYTE_BUDGET"):
            json_data({"many_shared_rows": [shared] * 1024})
        valid = {"small": [leaf] * 3, "zero": 0, "false": False}
        self.assertEqual(json_data(valid), valid)

    def test_artifact_shapes_do_not_invent_sources_or_clock_characters(self):
        valid = {"artifact_id": "artifact", "kind": "TRACE", "value": {}}
        for changes in ({"sources": {"fake": "source"}}, {"sources": ["source"]},
                        {"clock_domains": "CLOCK"}, {"clock_domains": [None]},
                        {"clock_domains": [""]}, {"kind": ["TRACE"]}):
            with self.subTest(changes=changes), self.assertRaises(WorkflowError):
                Artifact.from_dict({**valid, **changes})
        for missing in ("artifact_id", "kind", "value"):
            with self.subTest(missing=missing), self.assertRaises(WorkflowError):
                Artifact.from_dict({key: value for key, value in valid.items() if key != missing})
        for malformed in (None, "TRACE", (["TRACE"],)):
            with self.subTest(port=malformed), self.assertRaises(WorkflowError):
                PortSpec(malformed)
        artifact = Artifact.from_dict({**valid, "sources": [{"verification": "UNVERIFIED_IMPORT"}],
                                      "clock_domains": ["ORIGINAL_CLOCK_ID"]})
        self.assertEqual(artifact.clock_domains, ("ORIGINAL_CLOCK_ID",))

    def test_defaults_are_detached_and_obey_saved_authority_and_aggregate_parameter_bounds(self):
        adapter = build_catalog()["load_source"]
        first = validate_parameters(adapter, {"kind": "TRACE", "path": "fixture.etl"})
        first["selection"]["changed"] = True
        second = validate_parameters(adapter, {"kind": "TRACE", "path": "fixture.etl"})
        self.assertEqual(second["selection"], {})
        self.assertEqual(adapter.parameters["selection"]["default"], {})
        malicious = replace(adapter, parameters={"selection": {"type": "object", "default": {"confirmed": True}}})
        with self.assertRaisesRegex(WorkflowError, "SAVED_AUTHORITY"):
            validate_parameters(malicious, {})
        large = replace(adapter, parameters={str(n): {"type": "string", "default": "x" * 8192} for n in range(3)})
        with self.assertRaisesRegex(WorkflowError, "PARAMETER_BUDGET"):
            validate_parameters(large, {})

    def test_malformed_or_nonfinite_receipt_evidence_remains_unknown(self):
        predicates = [{"status": "COMPLETED"}, {"has_evidence": True}, {"sufficient": True},
                      {"field": "value.metric", "op": "NE", "value": 0}]
        for receipt in (None, [], "receipt"):
            for predicate in predicates:
                self.assertIsNone(evaluate_condition(predicate, receipt))
        for key in ("source", "coverage"):
            for value in (None, [], "malformed"):
                self.assertIsNone(evaluate_condition({"has_evidence": True} if key=="source" else {"sufficient": True},
                                                     {key: value}))
        for references in (None, {}, [None], [{}], [{"kind": []}]):
            self.assertIsNone(evaluate_condition({"has_evidence": False},
                {"result_references": references, "source": {"verified": True}, "execution_started": True}))
        for value in ({}, [], float("nan"), float("inf")):
            self.assertIsNone(evaluate_condition({"field": "value.metric", "op": "NE", "value": 0}, {"value": {"metric": value}}))
        self.assertTrue(evaluate_condition({"has_evidence": False},
            {"result_references": [], "source": {"verified": True}, "execution_started": True}))
        self.assertFalse(evaluate_condition({"field": "value.flag", "value": 1}, {"value": {"flag": True}}))
        for invalid in ({"field": "status"}, {"field": "value.metric", "value": float("nan")}, {"status": ""}):
            with self.subTest(invalid=invalid), self.assertRaises(WorkflowError):
                validate_condition(invalid)

    def test_graph_scope_and_condition_wrapper_mistakes_fail_passive_preview(self):
        value = document(profile={"profile_id": "case", "overrides": {"allowed_node_ids": ["typo"]}})
        self.assertEqual(validate_workflow(value, {})["errors"][0]["code"], "WORKFLOW_PROFILE_NODE_MISSING")
        # A receipt-producing inert tool avoids creating any process/native source.
        adapter = build_catalog()["export_report"]
        adapter = replace(adapter, inputs={}, outputs={}, parameters={}, execute=lambda *_: self.fail("preview executed"))
        value = document(nodes=[{"node_id": "source", "tool_id": "inert", "budget_seconds": 1},
            {"node_id": "condition", "kind": "CONDITION", "budget_seconds": 1,
             "parameters": {"condition": {"status": "COMPLETED"}, "ignored": False}}], edges=[{
                "edge_id": "receipt-condition", "source_node": "source", "source_port": "receipt",
                "target_node": "condition", "target_port": "input"}])
        result = validate_workflow(value, {"inert": adapter})
        self.assertIn("INVALID_WORKFLOW_CONDITION_FIELDS", [row["code"] for row in result["errors"]])

    def test_many_output_cannot_preview_as_a_single_typed_input(self):
        adapter = build_catalog()["export_report"]
        source = replace(adapter, inputs={}, outputs={"report": PortSpec(("REPORT",), many=True)}, parameters={})
        target = replace(adapter, inputs={"case": PortSpec(("REPORT",))}, outputs={}, parameters={})
        value = document(nodes=[{"node_id": "source", "tool_id": "source", "budget_seconds": 1},
                               {"node_id": "target", "tool_id": "target", "budget_seconds": 1}], edges=[{
            "edge_id": "source-target", "source_node": "source", "source_port": "report",
            "target_node": "target", "target_port": "case"}])
        result = validate_workflow(value, {"source": source, "target": target})
        self.assertEqual(result["errors"][0]["code"], "WORKFLOW_PORT_CARDINALITY_MISMATCH")
        target = replace(target, inputs={"case": PortSpec(("REPORT",), many=True)})
        self.assertTrue(validate_workflow(value, {"source": source, "target": target})["ready"])

    def test_profile_import_is_size_bounded_before_unbounded_file_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "oversized.bbprofile.json"
            path.write_bytes(b"x" * (MAX_DEFINITION_BYTES + 1))
            with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded read")):
                with self.assertRaises(WorkflowError):
                    load_profile(path)

    def test_uppercase_selected_hash_is_the_same_bytes_without_aliasing_different_files(self):
        from blackbox_core.chain_io import make_file_artifact
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "source.jsonl"
            path.write_text("explicit source fixture", encoding="utf-8")
            artifact = make_file_artifact("TRACE", path)
            digest = artifact.value["sha256"]
            before = deepcopy(artifact.to_dict())
            self.assertEqual(verify_source_scope(artifact, [digest.upper()])["byte_roots"], [digest])
            self.assertEqual(artifact.to_dict(), before)
            for invalid in (None, False, "all", {"source": digest}):
                with self.subTest(invalid=invalid), self.assertRaises(WorkflowError):
                    verify_source_scope(artifact, invalid)


if __name__ == "__main__":
    unittest.main()
