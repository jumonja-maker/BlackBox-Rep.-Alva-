"""R60 serialization boundary checks; these are not native acceptance evidence."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from blackbox_core.chain_contracts import (
    Artifact, MAX_INVOCATIONS, MAX_ITERATIONS, MAX_RUN_SECONDS, NodeDefinition,
    PortSpec, WorkflowDefinition, WorkflowError, canonical, parse_json,
)


def definition(**changes):
    value = {"schema": "blackbox.workflow-definition/1", "workflow_id": "qa-contract",
             "title": "Explicit read-only chain", "nodes": [{"node_id": "source", "tool_id": "load_source",
             "parameters": {"kind": "TRACE", "path": "local-recording.etl"}}], "edges": []}
    value.update(changes)
    return value


class WorkflowSerializationTests(unittest.TestCase):
    def test_round_trip_and_fingerprint_bind_exact_definition(self):
        workflow = WorkflowDefinition.from_dict(definition())
        reopened = WorkflowDefinition.from_dict(json.loads(canonical(workflow.to_dict())))
        self.assertEqual(reopened.to_dict(), workflow.to_dict())
        self.assertEqual(reopened.fingerprint, workflow.fingerprint)
        changed = deepcopy(workflow.to_dict())
        changed["nodes"][0]["position"] = [14, 22]
        self.assertNotEqual(WorkflowDefinition.from_dict(changed).fingerprint, workflow.fingerprint)

    def test_unknown_schema_and_automatic_execution_are_refused(self):
        for changes in ({"schema": "blackbox.workflow-definition/2"}, {"schema_version": True},
                        {"mode": "AUTOMATIC"}, {"revision": True}):
            with self.subTest(changes=changes), self.assertRaises(WorkflowError):
                WorkflowDefinition.from_dict(definition(**changes))

    def test_unknown_fields_never_become_ignored_authority(self):
        for changes in ({"confirmed": True}, {"helper_command": "snapshot"}, {"autorun": True}):
            with self.subTest(changes=changes), self.assertRaises(WorkflowError):
                WorkflowDefinition.from_dict(definition(**changes))

    def test_saved_authority_and_memory_payload_are_refused_recursively(self):
        for key in ("confirmed", "authorization", "password", "access_token", "expected_hex",
                    "value_hex", "replacement_hex", "memory_bytes", "payload", "api_secret"):
            value = definition()
            value["nodes"][0]["parameters"] = {"nested": [{key: "not-real-secret"}]}
            with self.subTest(key=key), self.assertRaisesRegex(WorkflowError, "SAVED_AUTHORITY_OR_PAYLOAD"):
                WorkflowDefinition.from_dict(value)

    def test_invalid_json_is_rejected_without_last_key_wins(self):
        for raw in ('{"nodes":[],"nodes":[]}', '{"number":NaN}', '{"number":Infinity}',
                    '[]', '{broken', '{"number":1e999}'):
            with self.subTest(raw=raw), self.assertRaises((WorkflowError, ValueError)):
                parse_json(raw)

    def test_graph_definition_bounds_reject_booleans_nonfinite_and_excess(self):
        for budget in ({"seconds": MAX_RUN_SECONDS + 1}, {"seconds": float("nan")},
                       {"seconds": True}, {"max_workers": 5}, {"max_workers": True},
                       {"max_owned_resources": 65}, {"max_output_bytes": 1023}):
            with self.subTest(budget=budget), self.assertRaises(WorkflowError):
                WorkflowDefinition.from_dict(definition(budget=budget))
        with self.assertRaises(WorkflowError):
            WorkflowDefinition.from_dict(definition(nodes=[{"node_id": str(n), "tool_id": "load_source"}
                                                         for n in range(257)]))

    def test_repeat_limits_allow_real_candidate_lifecycle_without_relaxing_caps(self):
        repeat = NodeDefinition.from_dict({"node_id": "repeat", "kind": "REPEAT", "tool_id": "load_source",
            "repeat_count": 331, "repeat_interval_seconds": 60, "budget_seconds": 5})
        self.assertEqual(repeat.repeat_count, 331)
        self.assertEqual(repeat.repeat_interval_seconds, 60)
        self.assertEqual(MAX_RUN_SECONDS, 21600)
        self.assertEqual(MAX_ITERATIONS, 4096)
        self.assertEqual(MAX_INVOCATIONS, 10000)
        for changes in ({"repeat_count": MAX_ITERATIONS + 1}, {"repeat_count": True},
                        {"repeat_interval_seconds": 3601}, {"repeat_interval_seconds": float("inf")}):
            with self.subTest(changes=changes), self.assertRaises(WorkflowError):
                NodeDefinition.from_dict({**repeat.to_dict(), **changes})

    def test_only_repeat_nodes_may_declare_repetition(self):
        for changes in ({"repeat_count": 2}, {"repeat_interval_seconds": 1}):
            with self.subTest(changes=changes), self.assertRaisesRegex(WorkflowError, "REPEAT_NODE_REQUIRED"):
                NodeDefinition.from_dict({"node_id": "ordinary", "tool_id": "load_source", **changes})

    def test_invalid_port_types_and_boolean_flags_are_refused(self):
        for types, flags in (((), {}), (("SESSION", "SESSION"), {}), (("SQLITE_AS_TRACE",), {}),
                             (("TRACE",), {"many": 1}), (("TRACE",), {"required": "yes"})):
            with self.subTest(types=types, flags=flags), self.assertRaises(WorkflowError):
                PortSpec(types, **flags)

    def test_artifact_round_trip_keeps_identity_clocks_and_unknown_coverage(self):
        artifact = Artifact("TRACE_INDEX", {"_path": "private/index.sqlite3", "sha256": "a" * 64,
            "bytes": 5}, sources=({"source_id": "saved-source", "verification": "UNVERIFIED_IMPORT"},),
            clock_domains=("TRACE_RECORDED:unverified",), coverage={"evidence_completeness": "UNKNOWN"})
        reopened = Artifact.from_dict(artifact.to_dict())
        self.assertEqual(reopened.to_dict(), artifact.to_dict())
        self.assertEqual(reopened.clock_domains, ("TRACE_RECORDED:unverified",))
        self.assertEqual(reopened.coverage["evidence_completeness"], "UNKNOWN")

    def test_public_artifact_removes_private_source_paths(self):
        artifact = Artifact("DUMP", {"_path": "C:/private/raw-memory.dmp", "memory_bytes": "sensitive",
                                    "sha256": "b" * 64}, coverage={"evidence_completeness": "UNKNOWN"})
        exported = canonical(artifact.to_dict(public=True))
        self.assertNotIn("C:/private/raw-memory.dmp", exported)
        self.assertNotIn('"sensitive"', exported)
        self.assertIn("b" * 64, exported)


class WorkflowValidationTests(unittest.TestCase):
    def setUp(self):
        from blackbox_core.chain_adapters import build_catalog
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name) / "saved.etl"
        self.source.write_bytes(b"explicit preflight fixture; decoder execution is not claimed")
        self.calls = []
        def forbidden(*arguments):
            self.calls.append(arguments)
            raise AssertionError("PREFLIGHT_MUST_NOT_EXECUTE")
        self.catalog = {key: replace(value, execute=forbidden) for key, value in build_catalog().items()}

    def graph(self, *, kind="TRACE"):
        return definition(nodes=[{"node_id": "source", "tool_id": "load_source", "budget_seconds": 10,
            "parameters": {"kind": kind, "path": str(self.source)}},
            {"node_id": "decoder", "tool_id": "decode_trace", "budget_seconds": 10}], edges=[{
                "edge_id": "source-decoder", "source_node": "source", "source_port": "source",
                "target_node": "decoder", "target_port": "trace"}])

    def check(self, value):
        from blackbox_core.chain_validation import validate_workflow
        before = self.source.read_bytes()
        result = validate_workflow(value, self.catalog)
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(self.calls, [])
        return result

    def test_valid_connected_deferred_input_preflight_has_no_execution(self):
        result = self.check(self.graph())
        self.assertTrue(result["ready"], result["errors"])
        self.assertIsNone(result["declared_budgets"]["measured_duration"])

    def test_session_sqlite_cannot_be_coerced_into_decoder_trace(self):
        result = self.check(self.graph(kind="SESSION"))
        self.assertFalse(result["ready"])
        self.assertIn("WORKFLOW_PORT_TYPE_MISMATCH", {row["code"] for row in result["errors"]})

    def test_cycle_missing_ports_and_duplicate_node_ids_are_refused(self):
        for mutate in ("cycle", "port", "duplicate"):
            value = self.graph()
            if mutate == "cycle":
                value["edges"].append({"edge_id": "self", "source_node": "source", "source_port": "source",
                                       "target_node": "source", "target_port": "source"})
            elif mutate == "port":
                value["edges"][0]["source_port"] = "imaginary-success"
            else:
                value["nodes"].append(deepcopy(value["nodes"][0]))
            with self.subTest(mutate=mutate):
                self.assertFalse(self.check(value)["ready"])

    def test_disconnected_required_input_unknown_tool_and_unknown_parameter_are_refused(self):
        for mutate in ("disconnected", "unknown-tool", "parameter"):
            value = self.graph()
            if mutate == "disconnected":
                value["edges"] = []
            elif mutate == "unknown-tool":
                value["nodes"][1]["tool_id"] = "unconnected-plugin"
            else:
                value["nodes"][0]["parameters"]["silent_retry"] = True
            with self.subTest(mutate=mutate):
                self.assertFalse(self.check(value)["ready"])

    def test_global_declared_cost_includes_every_repeat_and_interval(self):
        value = definition(nodes=[{"node_id": "repeat", "tool_id": "load_source", "kind": "REPEAT",
            "parameters": {"kind": "TRACE", "path": str(self.source)}, "repeat_count": 331,
            "repeat_interval_seconds": 60, "budget_seconds": 5}],
            budget={"seconds": 21600, "max_workers": 2},
            profile={"profile_id": "case", "overrides": {"max_seconds": 21600}})
        result = self.check(value)
        self.assertTrue(result["ready"], result["errors"])
        self.assertEqual(result["declared_budgets"]["maximum_declared_sequential_seconds"], 21455)
        value["profile"]["overrides"]["max_seconds"] = 21454
        self.assertFalse(self.check(value)["ready"])

    def test_effectful_repeat_is_refused_even_with_planning_opt_in(self):
        value = definition(nodes=[{"node_id": "target", "tool_id": "process_select", "parameters": {"pid": 1}},
            {"node_id": "effect", "kind": "REPEAT", "tool_id": "deep.dump", "repeat_count": 2}], edges=[{
                "edge_id": "target-effect", "source_node": "target", "source_port": "process",
                "target_node": "effect", "target_port": "process"}],
            profile={"profile_id": "application", "overrides": {"allow_effectful": True}})
        # Isolate the graph policy from platform discovery. This adapter is a
        # non-executing validation fixture even on Linux, never native evidence.
        self.catalog["process_select"] = replace(self.catalog["process_select"], available=True)
        self.catalog["deep.dump"] = replace(self.catalog["deep.dump"], available=True)
        result = self.check(value)
        self.assertFalse(result["ready"])
        self.assertIn("WORKFLOW_EFFECTFUL_REPEAT_REFUSED", {row["code"] for row in result["errors"]})

    def test_unknown_receipt_fields_and_missing_evidence_remain_unknown(self):
        from blackbox_core.chain_validation import evaluate_condition, validate_condition
        for condition in ({"field": "cleanup.confirmed", "value": True}, {"sufficient": True},
                          {"has_evidence": True}, {"status": "COMPLETED"}):
            with self.subTest(condition=condition):
                self.assertIsNone(evaluate_condition(condition, {}))
        self.assertFalse(evaluate_condition({"field": "execution_started", "value": 1},
                                           {"execution_started": True}))
        with self.assertRaises(WorkflowError):
            validate_condition({"field": "python.eval", "value": "execute"})


if __name__ == "__main__":
    unittest.main()
