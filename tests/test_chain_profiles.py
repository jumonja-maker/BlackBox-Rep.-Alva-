"""Profiles are passive bounded plans, never saved native authorization."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from blackbox_core.chain_adapters import build_catalog
from blackbox_core.chain_contracts import WorkflowDefinition, WorkflowError
from blackbox_core.chain_profiles import (builtin_profiles, effective_profile, load_profile,
                                          save_profile, validate_profile)


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


if __name__ == "__main__":
    unittest.main()
