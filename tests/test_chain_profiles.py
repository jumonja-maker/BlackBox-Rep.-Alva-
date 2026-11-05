"""Profiles are passive bounded plans, never saved native authorization."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from blackbox_core.chain_adapters import build_catalog
from blackbox_core.chain_contracts import Artifact, WorkflowDefinition, WorkflowError
from blackbox_core.chain_profiles import (builtin_profiles, effective_profile, load_profile,
                                          save_profile, validate_profile, verify_source_scope)


def workflow(profile=None, *, seconds=3600, workers=4):
    return WorkflowDefinition.from_dict({"schema": "blackbox.workflow-definition/1", "workflow_id": "qa-profile",
        "title": "Passive profile fixture", "nodes": [{"node_id": "source", "tool_id": "load_source",
        "parameters": {"kind": "TRACE", "path": "not-opened.etl"}}],
        "profile": profile or {"profile_id": "application", "overrides": {}},
        "budget": {"seconds": seconds, "max_workers": workers}})


class PassiveProfileTests(unittest.TestCase):
    def test_builtins_preserve_distinct_scopes_and_never_grant_consent(self):
        stock = builtin_profiles()
        self.assertEqual(set(stock), {"windows", "application", "case"})
        self.assertEqual(len({item["scope"] for item in stock.values()}), 3)
        for key in stock:
            plan = effective_profile(workflow({"profile_id": key, "overrides": {}}), build_catalog())
            self.assertFalse(plan["allow_effectful"])
            self.assertIsNone(plan["target"])
            self.assertEqual(plan["authority"], "NO_RUNTIME_AUTHORIZATION_OR_SAVED_CONSENT")

    def test_effective_limits_are_intersection_of_definition_and_profile(self):
        definition = workflow({"profile_id": "case", "overrides": {"max_seconds": 120,
            "max_workers": 1, "max_output_bytes": 8192, "allowed_tools": ["load_source"]}})
        plan = effective_profile(definition, build_catalog())
        self.assertEqual((plan["max_seconds"], plan["max_workers"], plan["max_output_bytes"]), (120, 1, 8192))
        self.assertEqual(plan["allowed_tools"], ["load_source"])
        self.assertFalse(plan["allow_effectful"])

    def test_planning_effectful_selection_is_still_not_runtime_authority(self):
        plan = effective_profile(workflow({"profile_id": "application", "overrides": {
            "allow_effectful": True, "target": {"pid": 42, "created_100ns": 123456}}}), build_catalog())
        self.assertTrue(plan["allow_effectful"])
        self.assertEqual(plan["target"], {"pid": 42, "created_100ns": 123456, "image_path": ""})
        self.assertEqual(plan["authority"], "NO_RUNTIME_AUTHORIZATION_OR_SAVED_CONSENT")

    def test_inherited_layers_have_explicit_order_and_overrides(self):
        profile = {"schema": "blackbox.workflow-profile/1", "profile_id": "qa-child", "title": "Child",
            "inherits": "case", "overrides": {"max_workers": 1, "max_seconds": 300}}
        definition = workflow({"profile_id": "qa-child", "overrides": {"max_seconds": 90}})
        plan = effective_profile(definition, build_catalog(), profiles={"qa-child": profile})
        self.assertEqual(plan["inherits_chain"], ["qa-child", "case"])
        self.assertEqual(plan["max_seconds"], 90)
        self.assertEqual(plan["max_workers"], 1)

    def test_inheritance_cycles_missing_parents_and_unknown_tools_are_refused(self):
        child = {"profile_id": "child", "title": "Child", "inherits": "child", "overrides": {}}
        with self.assertRaisesRegex(WorkflowError, "CYCLE_OR_DEPTH"):
            effective_profile(workflow({"profile_id": "child"}), build_catalog(), profiles={"child": child})
        for profile in ({"profile_id": "missing"}, {"profile_id": "case", "overrides": {
                "allowed_tools": ["unconnected-plugin"]}}):
            with self.subTest(profile=profile), self.assertRaises(WorkflowError):
                effective_profile(workflow(profile), build_catalog())

    def test_profile_roundtrip_is_create_new_and_never_opens_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "local.bbprofile.json"
            original = {"profile_id": "local", "title": "Passive local plan", "inherits": "case",
                        "overrides": {"allowed_tools": ["load_source"], "max_seconds": 120}}
            saved = save_profile(original, path)
            before = path.read_bytes()
            self.assertEqual(load_profile(path), saved)
            with self.assertRaises(FileExistsError):
                save_profile(original, path)
            self.assertEqual(path.read_bytes(), before)

    def test_profile_cannot_persist_confirmation_or_unbounded_settings(self):
        for overrides in ({"confirmed": True}, {"authorization": "saved"}, {"max_seconds": 21601},
                          {"max_workers": True}, {"max_workers": 5}, {"allow_effectful": "yes"},
                          {"source_ids": ["same", "same"]}):
            with self.subTest(overrides=overrides), self.assertRaises(WorkflowError):
                validate_profile({"profile_id": "qa", "overrides": overrides})

    def test_malformed_nested_selection_and_parent_fail_with_controlled_error(self):
        for overrides in ({"allowed_tools": [["load_source"]]}, {"source_ids": [{"id": "source"}]},
                          {"allowed_node_ids": [False]}):
            with self.subTest(overrides=overrides), self.assertRaises(WorkflowError):
                validate_profile({"profile_id": "qa", "overrides": overrides})
        with self.assertRaises(WorkflowError):
            effective_profile(workflow({"profile_id": "custom", "inherits": ["case"]}), build_catalog())

    def test_custom_catalog_cannot_replace_builtin_or_disagree_about_identity(self):
        with self.assertRaisesRegex(WorkflowError, "BUILTIN_PROFILE_REPLACEMENT"):
            effective_profile(workflow(), build_catalog(), profiles={"application": {
                "profile_id": "application", "inherits": "case", "overrides": {"allow_effectful": True}}})
        with self.assertRaisesRegex(WorkflowError, "PROFILE_IDENTITY_MISMATCH"):
            effective_profile(workflow({"profile_id": "custom"}), build_catalog(), profiles={"custom": {
                "profile_id": "different", "inherits": "case", "overrides": {}}})

    def test_discovery_and_preview_do_not_mutate_definition(self):
        definition = workflow()
        before = deepcopy(definition.to_dict())
        effective_profile(definition, build_catalog())
        self.assertEqual(definition.to_dict(), before)


class SelectedByteRootTests(unittest.TestCase):
    """Real file checks; metadata fixtures below do not claim native evidence."""
    def setUp(self):
        from blackbox_core.chain_io import make_file_artifact
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "owned-result"
        self.output.mkdir()
        path = self.root / "selected.jsonl"
        path.write_text("explicit source fixture\n", encoding="utf-8")
        self.source = make_file_artifact("TRACE", path)
        self.allowed = [self.source.value["sha256"]]

    def derived(self, *, path=None, upstream=None):
        from blackbox_core.chain_io import make_file_artifact
        path = path or self.output / "derived.sqlite3"
        path.write_text("fixture result, not a native trace index", encoding="utf-8")
        return make_file_artifact("TRACE_INDEX", path,
            metadata={"upstream_artifacts": [self.source.to_dict()] if upstream is None else upstream},
            sources=({"source_id": "actual-component-source-id", "verification_class": "UNVERIFIED_IMPORT"},),
            clock_domains=("UNALIGNED_COMPONENT_CLOCK",))

    def test_derived_component_ids_do_not_replace_selected_rehashed_roots(self):
        derived = self.derived()
        original = deepcopy(derived.to_dict())
        scope = verify_source_scope(derived, self.allowed, known_artifacts=(self.source,),
                                    inputs=(self.source,), output_dir=self.output)
        self.assertEqual(scope["byte_roots"], self.allowed)
        self.assertEqual(derived.to_dict(), original)
        self.assertNotIn(derived.sources[0]["source_id"], self.allowed)
        # This is the independently checked hand-off to the next real adapter.
        self.assertEqual(verify_source_scope(derived, self.allowed,
            known_artifacts=(self.source, derived))["byte_roots"], self.allowed)

    def test_empty_sources_do_not_allow_an_unselected_file(self):
        from blackbox_core.chain_io import make_file_artifact
        path = self.root / "unrelated.jsonl"
        path.write_text("different actual bytes", encoding="utf-8")
        unrelated = make_file_artifact("TRACE", path)
        self.assertEqual(unrelated.sources, ())
        with self.assertRaisesRegex(WorkflowError, "SOURCE_NOT_ALLOWED"):
            verify_source_scope(unrelated, self.allowed)
        spoofed = replace(unrelated, sources=({"source_id": self.allowed[0],
            "source_sha256": unrelated.value["sha256"], "verification_class": "UNVERIFIED_IMPORT"},))
        with self.assertRaisesRegex(WorkflowError, "SOURCE_NOT_ALLOWED"):
            verify_source_scope(spoofed, self.allowed)

    def test_unknown_or_changed_upstream_cannot_become_published_evidence(self):
        unknown = replace(self.source, artifact_id="unpublished-root")
        derived = self.derived(upstream=[unknown.to_dict()])
        with self.assertRaisesRegex(WorkflowError, "UNPUBLISHED_SOURCE_LINEAGE"):
            verify_source_scope(derived, self.allowed, known_artifacts=(self.source,),
                                inputs=(unknown,), output_dir=self.output)
        changed = replace(self.source, coverage={"evidence_completeness": "FORGED_COMPLETE"})
        derived = self.derived(upstream=[changed.to_dict()])
        with self.assertRaisesRegex(WorkflowError, "UNPUBLISHED_SOURCE_LINEAGE"):
            verify_source_scope(derived, self.allowed, known_artifacts=(self.source,),
                                inputs=(self.source,), output_dir=self.output)

    def test_a_real_other_selected_root_cannot_be_inserted_outside_call_inputs(self):
        from blackbox_core.chain_io import make_file_artifact
        path = self.root / "other.jsonl"
        path.write_text("a separately selected branch", encoding="utf-8")
        other = make_file_artifact("TRACE", path)
        derived = self.derived(upstream=[other.to_dict()])
        with self.assertRaisesRegex(WorkflowError, "SOURCE_OUTSIDE_CALL_INPUTS"):
            verify_source_scope(derived, self.allowed + [other.value["sha256"]],
                known_artifacts=(self.source, other), inputs=(self.source,), output_dir=self.output)

    def test_derived_file_outside_invocation_is_not_accepted_from_lineage_labels(self):
        derived = self.derived(path=self.root / "unowned-result.sqlite3")
        with self.assertRaisesRegex(WorkflowError, "UNOWNED_DERIVED_SOURCE"):
            verify_source_scope(derived, self.allowed, known_artifacts=(self.source,),
                                inputs=(self.source,), output_dir=self.output)

    def test_root_changed_on_disk_is_rejected_before_scope_can_accept_its_label(self):
        Path(self.source.value["_path"]).write_text("changed selected bytes", encoding="utf-8")
        with self.assertRaisesRegex(WorkflowError, "SOURCE_HASH_CHANGED"):
            verify_source_scope(self.source, self.allowed)

    def test_transitive_flat_lineage_is_resolved_against_actual_published_results(self):
        first = self.derived()
        flattened = deepcopy(first.to_dict())
        flattened["value"].pop("upstream_artifacts")
        next_output = self.root / "second-owned-result"
        next_output.mkdir()
        second = self.derived(path=next_output / "case.sqlite3",
                              upstream=[flattened, self.source.to_dict()])
        result = verify_source_scope(second, self.allowed, known_artifacts=(self.source, first),
                                     inputs=(first,), output_dir=next_output)
        self.assertEqual(result["byte_roots"], self.allowed)
        # A flat input reference must resolve through the full actual published
        # artifact too. It must not admit roots from another independent branch.
        result = verify_source_scope(second, self.allowed, known_artifacts=(self.source, first),
                                     inputs=(Artifact.from_dict(flattened),), output_dir=next_output)
        self.assertEqual(result["byte_roots"], self.allowed)
        self.assertIn("upstream_artifacts", first.value)

    def test_real_decoder_investigation_and_export_keep_restrictive_source_profile(self):
        from blackbox_core.chain_engine import WorkflowEngine
        from blackbox_core.chain_store import WorkflowRunStore
        trace = self.root / "actual-component-input.jsonl"
        rows = [{"schema_version": 1, "token": "EXPLICIT_FORMAT_FIXTURE_NOT_NATIVE_CAPTURE",
            "pid": 42, "tid": 43, "seq": value, "source_ns": value * 1000,
            "source_clock": "FORMAT_FIXTURE_CLOCK", "kind": "user.marker", "client_dropped": 0,
            "attributes": {"name": "fixture-" + str(value)}} for value in range(1, 4)]
        trace.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        digest = hashlib.sha256(trace.read_bytes()).hexdigest()
        def edge(source, port, target, input_port):
            return {"edge_id": source + "-" + target, "source_node": source, "source_port": port,
                    "target_node": target, "target_port": input_port}
        definition = WorkflowDefinition.from_dict({"schema": "blackbox.workflow-definition/1",
            "workflow_id": "restricted-real-offline", "title": "Actual offline components, selected byte root",
            "profile": {"profile_id": "case", "overrides": {"source_ids": [digest], "max_seconds": 120}},
            "budget": {"seconds": 120, "max_workers": 1}, "nodes": [
                {"node_id": "source", "tool_id": "load_source", "budget_seconds": 5,
                 "parameters": {"kind": "TRACE", "path": str(trace)}},
                {"node_id": "decode", "tool_id": "decode_trace", "budget_seconds": 20},
                {"node_id": "investigate", "tool_id": "investigate", "budget_seconds": 20},
                {"node_id": "reopen", "tool_id": "load_graph", "budget_seconds": 5},
                {"node_id": "export", "tool_id": "export_report", "budget_seconds": 10}],
            "edges": [edge("source", "source", "decode", "trace"),
                edge("decode", "index", "investigate", "evidence"),
                edge("investigate", "case", "reopen", "source"),
                edge("reopen", "case", "export", "case")]})
        store = WorkflowRunStore.create(self.root / "runs", definition)
        snapshot = WorkflowEngine(definition, catalog=build_catalog(), store=store).run()
        self.assertEqual(snapshot["state"], "COMPLETED", snapshot)
        nodes = {row["node_id"]: row for row in snapshot["nodes"]}
        index = nodes["decode"]["outputs"]["index"][0]
        self.assertNotEqual(index["sources"][0]["source_id"], digest)
        self.assertTrue(nodes["export"]["outputs"]["report"][0]["value"]["readback_verified"])
        self.assertEqual(hashlib.sha256(trace.read_bytes()).hexdigest(), digest)
        self.assertEqual(snapshot["coverage"]["root_cause"], "UNKNOWN")

    def test_real_load_source_cannot_publish_an_unselected_root_as_complete(self):
        from blackbox_core.chain_engine import WorkflowEngine
        from blackbox_core.chain_store import WorkflowRunStore
        definition = workflow({"profile_id": "case", "overrides": {"source_ids": ["0" * 64]}}).to_dict()
        definition["nodes"][0]["parameters"]["path"] = self.source.value["_path"]
        definition = WorkflowDefinition.from_dict(definition)
        store = WorkflowRunStore.create(self.root / "runs", definition)
        snapshot = WorkflowEngine(definition, catalog=build_catalog(), store=store).run()
        self.assertNotEqual(snapshot["state"], "COMPLETED")
        self.assertIn("SOURCE_NOT_ALLOWED", snapshot["nodes"][0]["reason_code"])


if __name__ == "__main__":
    unittest.main()
