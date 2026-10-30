"""Manual experiment contracts; no helper or Windows API is executed here."""
import json
import threading
import unittest

from blackbox_core.investigation_graph_contracts import SCHEMA, InvestigationBudget, InvestigationError
from blackbox_core.investigation_planner import (
    describe_diagnostic_actions, prepare_scenario, record_experiment_result, suggest_diagnostic_actions,
)


TARGET = {"pid": 20, "created_100ns": 123456789, "image_path": r"C:\Apps\probe.exe"}


def case(target=None):
    return {"schema": SCHEMA, "case_id": "case", "target_identity": target, "nodes": [], "edges": [],
            "hypotheses": [{"hypothesis_id": "hyp", "next_actions": ["memory.write", "thread_stacks", "registry.capture"]}]}


def capabilities(operation="memory.write", status="AVAILABLE"):
    return {"operation": "capabilities", "status": "COMPLETED", "target": TARGET,
            "data": {"operations": [{"operation": operation, "status": status}]}}


def result(phase, operation, identifier, data=None, status="COMPLETED", target=None):
    return {"experiment_id": "manual-run-1", "hypothesis_id": "hyp", "phase": phase,
            "operation": operation, "operation_id": identifier, "target": target or TARGET,
            "status": status, "data": data or {}}


class ManualPlannerContracts(unittest.TestCase):
    def test_historical_pid_does_not_enable_live_tools_without_current_target(self):
        data = case()
        data["nodes"] = [{"node_id": "historical", "process_identity": {"pid": TARGET["pid"]}}]
        actions = suggest_diagnostic_actions(data, capabilities=capabilities())
        self.assertNotEqual(next(row for row in actions if row["operation"] == "memory.write")["availability"], "AVAILABLE")
        self.assertNotIn("registry.capture", {row["operation"] for row in actions})

    def test_explicit_new_live_experiment_is_allowed_without_claiming_historical_binding(self):
        actions = suggest_diagnostic_actions(case(), capabilities=capabilities(), target_identity=TARGET)
        write = next(row for row in actions if row["operation"] == "memory.write")
        self.assertEqual(write["availability"], "AVAILABLE")
        self.assertEqual(write["historical_target_relation"], "NOT_ESTABLISHED")
        self.assertTrue(write["confirmation_required"])
        self.assertFalse(write["automatic_execution"])

    def test_live_case_target_cannot_be_silently_rebound(self):
        actions = suggest_diagnostic_actions(case(TARGET), target_identity={**TARGET, "created_100ns": 987654321},
                                             capabilities=capabilities())
        self.assertTrue(all(row["status"] == "PROCESS_CHANGED" for row in actions))

    def test_explicit_fork_preserves_unknown_relation_to_original_history(self):
        fork = {**case(TARGET), "origin_case_id": "original", "historical_target_relation": "NOT_ESTABLISHED"}
        actions = suggest_diagnostic_actions(fork, capabilities=capabilities(), target_identity=TARGET)
        self.assertTrue(all(row["historical_target_relation"] == "NOT_ESTABLISHED" for row in actions))
        updated = record_experiment_result(fork, result("BEFORE", "snapshot", "before", {"snapshot_id": "snapshot"}))
        self.assertEqual(updated["guided_experiments"][0]["historical_target_relation"], "NOT_ESTABLISHED")

    def test_admin_required_preserves_real_uac_route_without_granting_authority(self):
        actions = suggest_diagnostic_actions(case(TARGET), capabilities=capabilities("thread_stacks", "ADMIN_REQUIRED"))
        row = next(action for action in actions if action["operation"] == "thread_stacks")
        self.assertEqual(row["availability"], "ADMIN_REQUIRED")
        self.assertEqual(row["next_step"], "REQUEST_SCOPED_UAC_FOR_THIS_OPERATION")
        self.assertIn("DESCRIPTIVE_ONLY", row["contract"]["authority"])

    def test_manual_catalog_does_not_turn_a_tool_into_a_hypothesis_recommendation(self):
        data = case(TARGET)
        data["hypotheses"][0]["next_actions"] = ["thread_stacks"]
        descriptors = describe_diagnostic_actions(data, operations=["memory.write"], capabilities=capabilities())
        self.assertEqual(len(descriptors), 1)
        self.assertEqual(descriptors[0]["operation"], "memory.write")
        self.assertEqual(descriptors[0]["status"], "AVAILABLE")
        self.assertIn("EXPLICIT_MANUAL", descriptors[0]["selection_basis"])
        self.assertEqual(data["hypotheses"][0]["next_actions"], ["thread_stacks"])
        with self.assertRaises(InvestigationError):
            describe_diagnostic_actions(data, operations=["registry.capture"])

    def test_plan_is_manual_redacted_and_has_cleanup_contract_for_every_step(self):
        private = "5a" * 32
        plan = prepare_scenario(case(TARGET), "hyp", operation="memory.write",
            parameters={"address": 4096, "expected_hex": private, "value_hex": "aa" * 32}, capabilities=capabilities())
        self.assertEqual([row["kind"] for row in plan["steps"]], ["BEFORE", "ACTION", "AFTER", "COMPARE"])
        self.assertNotIn(private, json.dumps(plan))
        self.assertFalse(plan["automatic_execution"])
        self.assertEqual(plan["status"], "PREPARED_MANUAL")
        for step in plan["steps"]:
            self.assertTrue(step["cleanup"])
            self.assertTrue(step["cancel"])
            self.assertTrue(step["preconditions"])
        with self.assertRaises(ValueError):
            prepare_scenario(case(TARGET), "hyp", operation="memory.write", parameters={"command": "unsafe"})

    def test_existing_deep_parameter_aliases_are_not_artificially_rejected(self):
        plan = prepare_scenario(case(TARGET), "hyp", operation="memory_read",
                                parameters={"address": 4096, "size": 64})
        self.assertEqual(plan["missing_parameters"], [])
        dump = prepare_scenario(case(TARGET), "hyp", operation="dump", parameters={"destination": "chosen.dmp"})
        self.assertEqual(dump["missing_parameters"], [])
        with self.assertRaisesRegex(InvestigationError, "INVALID_EXPLICIT_LIVE_TARGET"):
            suggest_diagnostic_actions(case(), target_identity={**TARGET, "kind": "TRACE_PROCESS"})

    def test_real_result_ids_bind_before_after_without_causal_upgrade_or_private_payload(self):
        before = record_experiment_result(case(TARGET), result("BEFORE", "snapshot", "b", {"snapshot_id": "before"}))
        action = record_experiment_result(before, result("ACTION", "memory.write", "a", {
            "readback_verified": True, "value_hex": "private-memory", "unrecognized_payload": "private-unknown"}))
        after = record_experiment_result(action, result("AFTER", "snapshot", "c", {"snapshot_id": "after"}))
        compared = record_experiment_result(after, result("COMPARE", "compare", "d", {
            "before_id": "before", "after_id": "after", "changed_sections": ["memory"]}))
        experiment = compared["guided_experiments"][0]
        self.assertEqual(experiment["status"], "COMPARISON_RECORDED")
        self.assertEqual(experiment["hypothesis_status"], "INCONCLUSIVE")
        self.assertFalse(experiment["root_cause_proven"])
        self.assertNotIn("private-memory", json.dumps(compared))
        self.assertNotIn("private-unknown", json.dumps(compared))
        self.assertNotIn("guided_experiments", before.get("nodes", {}))

    def test_before_after_mismatch_and_reused_pid_are_rejected(self):
        before = record_experiment_result(case(TARGET), result("BEFORE", "snapshot", "b", {"snapshot_id": "before"}))
        with self.assertRaisesRegex(InvestigationError, "TARGET_CHANGED"):
            record_experiment_result(before, result("ACTION", "memory.write", "a", target={**TARGET, "created_100ns": 456}))
        action = record_experiment_result(before, result("ACTION", "memory.write", "a"))
        after = record_experiment_result(action, result("AFTER", "snapshot", "c", {"snapshot_id": "after"}))
        with self.assertRaisesRegex(InvestigationError, "SNAPSHOT_ID_MISMATCH"):
            record_experiment_result(after, result("COMPARE", "compare", "d", {"before_id": "foreign", "after_id": "after"}))

    def test_lost_acknowledgement_blocks_automatic_retry_and_review_does_not_clear_it(self):
        before = record_experiment_result(case(TARGET), result("BEFORE", "snapshot", "b", {"snapshot_id": "before"}))
        failed = record_experiment_result(before, result("ACTION", "memory.write", "a", status="RECOVERY_UNCONFIRMED"))
        with self.assertRaisesRegex(InvestigationError, "MUST_NOT_RETRY"):
            record_experiment_result(failed, result("AFTER", "snapshot", "c", {"snapshot_id": "after"}))
        reviewed = record_experiment_result(failed, result("REVIEW", "timeline", "review"))
        self.assertEqual(reviewed["guided_experiments"][0]["status"], "BLOCKED_RECOVERY_UNCONFIRMED")
        self.assertFalse(reviewed["guided_experiments"][0]["automatic_retry"])

    def test_failed_baseline_stops_run_and_review_cannot_unlock_action(self):
        failed = record_experiment_result(case(TARGET), result("BEFORE", "snapshot", "failed", status="CANCELLED"))
        with self.assertRaisesRegex(InvestigationError, "FAILED_STEP_REQUIRES_NEW_RUN"):
            record_experiment_result(failed, result("ACTION", "memory.write", "action"))
        reviewed = record_experiment_result(failed, result("REVIEW", "timeline", "review"))
        self.assertEqual(reviewed["guided_experiments"][0]["status"], "STOPPED_AT_FAILED_STEP")
        with self.assertRaisesRegex(InvestigationError, "FAILED_STEP_REQUIRES_NEW_RUN"):
            record_experiment_result(reviewed, result("AFTER", "snapshot", "after", {"snapshot_id": "after"}))

    def test_manual_step_order_and_cancellation_are_enforced(self):
        with self.assertRaisesRegex(InvestigationError, "OUT_OF_ORDER"):
            record_experiment_result(case(TARGET), result("ACTION", "memory.write", "a"))
        stop = threading.Event()
        stop.set()
        with self.assertRaises(InterruptedError):
            suggest_diagnostic_actions(case(TARGET), budget=InvestigationBudget(cancel_event=stop))
