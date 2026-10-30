"""Synthetic unit contracts; actual Windows workload acceptance runs separately."""
from copy import deepcopy
from threading import Event
import unittest
from unittest.mock import patch

from blackbox_core.investigation_graph_contracts import (
    ALGORITHM_VERSION, SCHEMA, InvestigationBudget, InvestigationError,
    evidence_edge, evidence_node, stable_id,
)
from blackbox_core.issue_grouping import (
    compare_investigations, group_recurrent_issues, issue_fingerprint, manual_group_change,
)


def case(label="one", *, version="A", app_hash="a" * 64, error=5):
    digest = stable_id("synthetic-source", label)
    source = {"source_id": stable_id("source", label), "source_type": "EVENTS_JSONL",
        "source_sha256": digest, "source_consistency": "STABLE_HASHED_NO_ACTIVE_WAL",
        "verification_class": "UNVERIFIED_IMPORT", "scan_complete": True,
        "application_events_complete": True, "application_client_dropped_total": 0,
        "application_order_errors": 0, "application_sequence_gaps": 0,
        "events_scanned": 3, "selected_events": 3}
    nodes = []
    for ordinal in (1, 2):
        code = error if ordinal == 1 else 0
        metadata = {"event_kind": "io.operation.end", "operation_scope": "producer-" + label,
            "operation_id": "operation-" + str(ordinal), "status": "ERROR" if code else "COMPLETED",
            "error_code": code, "winerror": code, "io_kind": "WRITE"}
        nodes.append(evidence_node(source, "record:" + str(ordinal), "FILE_OPERATION", metadata=metadata,
            process_identity={"kind": "LIVE_PROCESS", "pid": 123, "created_100ns": 133000000000000000},
            time_domain="APP_SOURCE:" + label,
            time_bounds={"start": ordinal, "end": ordinal, "unit": "ns", "uncertainty": None}))
    nodes.append(evidence_node(source, "record:3", "MEASUREMENT", metadata={
        "event_kind": "blackbox.completed", "status": "COMPLETED", "expected_operations": 2},
        time_domain="APP_SOURCE:" + label, time_bounds={"start": 3, "end": 3, "unit": "ns"}))
    return {"schema": SCHEMA, "algorithm_version": ALGORITHM_VERSION,
        "case_id": stable_id("case", label), "sources": [source], "nodes": nodes, "edges": [],
        "target_identity": None, "root_cause": "UNKNOWN", "root_cause_proven": False,
        "app_identity": {"application_id": "CONTROLLED_APPLICATION", "version": version,
            "sha256": app_hash, "verification_class": "QA_VERIFIED_SOURCE_BUILD"},
        "scenario": {"scenario_id": "SAME_FILE_OPERATION", "workload_id": "TWO_OPS",
            "operation_count": 2, "input_bytes": 29, "source_profile": "SDK_FILE_V1", "complete": True},
        "coverage": {"has_more": False, "next_cursor": [], "display_graph_complete": True,
            "events_omitted": 0, "nodes_omitted": 0, "edges_omitted": 0,
            "source_coverage": [{"source_id": source["source_id"], "events_scanned": 3, "selected_events": 3}]}}


def frame(*, guid="12345678-1234-5678-9abc-123456789abc", rva=23, digest=None):
    module = {"guid": guid, "age": 1, "image_size": 4096, "image_timestamp": 1234,
              "identity_status": "MATCH", "image_base": "0x10000000", "module_path": "C:\\first\\tool.dll"}
    if digest is not None:
        module["sha256"] = digest
    return {"address": "0x10000017", "rva": rva, "module_identity": module}


def stack_case(label="stack", **frame_kwargs):
    value = case(label)
    node = value["nodes"][0]
    node["observation_type"] = "INCIDENT"
    node["metadata"] = {"frames": [frame(**frame_kwargs)]}
    return value


def declared_case(label="one", **kwargs):
    value = case(label, **kwargs)
    value["app_identity"].update(verification_class="USER_SELECTED_FILE_SHA256",
        source_binding="USER_REPORTED", context_scope="ENTIRE_CASE")
    value["scenario"]["verification_class"] = "USER_REPORTED"
    return value


class IssueFingerprintContracts(unittest.TestCase):
    def fingerprint(self, value):
        return issue_fingerprint(value, value["nodes"][0])

    def test_error_anchor_ignores_pid_aslr_paths_message_and_source_filename(self):
        first, second = case(), case("two")
        second["nodes"][0]["process_identity"].update(pid=987, created_100ns=133000000000000001)
        second["nodes"][0]["metadata"].update(path="C:\\Users\\Other\\private.bin",
            address="0x7fffff00", message="Different localized text", filename="renamed.jsonl")
        original = deepcopy([first, second])
        result = group_recurrent_issues([first, second])
        self.assertEqual(len(result["groups"]), 1)
        self.assertEqual(result["groups"][0]["occurrence_count"], 2)
        self.assertEqual(result["groups"][0]["source_trust"], "UNVERIFIED_IMPORT")
        self.assertFalse(result["groups"][0]["root_cause_established"])
        self.assertEqual([first, second], original)

    def test_different_error_operation_build_family_and_context_do_not_false_merge(self):
        first = case()
        original = self.fingerprint(first)["fingerprint"]
        for field in ("error", "operation", "build", "family", "scenario", "workload"):
            with self.subTest(field=field):
                second = case("two")
                if field == "error":
                    second["nodes"][0]["metadata"].update(error_code=2, winerror=2)
                elif field == "operation":
                    second["nodes"][0]["metadata"]["io_kind"] = "READ"
                elif field == "build":
                    second["app_identity"]["sha256"] = "b" * 64
                elif field == "family":
                    second["app_identity"]["application_id"] = "OTHER_APPLICATION"
                elif field == "scenario":
                    second["scenario"]["scenario_id"] = "OTHER_SCENARIO"
                else:
                    second["scenario"]["workload_id"] = "OTHER_WORKLOAD"
                self.assertNotEqual(self.fingerprint(second)["fingerprint"], original)

    def test_missing_or_unverified_application_and_untyped_errors_are_candidates(self):
        for mutation in ("missing", "unverified", "class_object", "bool_code", "conflict", "bad_status", "path_operation"):
            with self.subTest(mutation=mutation):
                value = case()
                if mutation == "missing":
                    value["app_identity"] = None
                elif mutation == "unverified":
                    value["app_identity"]["verification_class"] = "UNVERIFIED_IMPORT"
                elif mutation == "class_object":
                    value["app_identity"]["verification_class"] = []
                elif mutation == "bool_code":
                    value["nodes"][0]["metadata"].update(error_code=True, winerror=True)
                elif mutation == "conflict":
                    value["nodes"][0]["metadata"]["winerror"] = 2
                elif mutation == "bad_status":
                    value["nodes"][0]["metadata"]["status"] = {"claimed": "ERROR"}
                else:
                    value["nodes"][0]["metadata"]["io_kind"] = "C:\\user\\secret"
                result = self.fingerprint(value)
                self.assertIsNone(result["fingerprint"])
                self.assertEqual(result["status"], "CANDIDATE")

    def test_normalized_verified_module_stack_ignores_absolute_address_and_user_path(self):
        for digest in (None, "c" * 64):
            with self.subTest(digest=digest):
                first, second = stack_case(digest=digest), stack_case("two", digest=digest)
                changed = second["nodes"][0]["metadata"]["frames"][0]
                changed["address"] = "0x40000017"
                changed["module_identity"].update(image_base="0x40000000", module_path="C:\\other\\tool.dll")
                self.assertEqual(self.fingerprint(first)["fingerprint"], self.fingerprint(second)["fingerprint"])
                self.assertIsNotNone(self.fingerprint(first)["fingerprint"])

    def test_malformed_guids_unmatched_modules_and_incomplete_stacks_never_strong(self):
        for mutation in ("hyphens", "zero", "unmatched", "class_object", "rva_outside", "missing", "omitted", "bare_address"):
            with self.subTest(mutation=mutation):
                value = stack_case()
                metadata = value["nodes"][0]["metadata"]
                item = metadata["frames"][0]
                if mutation == "hyphens":
                    item["module_identity"]["guid"] = "-" * 36
                elif mutation == "zero":
                    item["module_identity"]["guid"] = "00000000-0000-0000-0000-000000000000"
                elif mutation == "unmatched":
                    item["module_identity"]["identity_status"] = "UNVERIFIED_IMPORT"
                elif mutation == "class_object":
                    item["module_identity"].update(identity_status=[], verification_class={})
                elif mutation == "rva_outside":
                    item["rva"] = 8192
                elif mutation == "missing":
                    metadata["stack_status"] = "INCOMPLETE"
                elif mutation == "omitted":
                    metadata["frames_omitted"] = 1
                else:
                    del item["module_identity"]
                self.assertEqual(self.fingerprint(value)["status"], "CANDIDATE")

    def test_recorded_stack_ref_requires_actual_same_source_direct_edge(self):
        value = stack_case()
        incident = value["nodes"][0]
        stack = evidence_node(value["sources"][0], "stack:1", "STACK", metadata=incident["metadata"])
        incident["metadata"] = {"stack_ref": stack["node_id"]}
        value["nodes"].append(stack)
        self.assertEqual(self.fingerprint(value)["status"], "CANDIDATE")
        value["edges"].append(evidence_edge(incident["node_id"], stack["node_id"], "DIRECT_REFERENCE"))
        self.assertEqual(self.fingerprint(value)["status"], "MATCHING_RECORDED_ANCHORS")

    def test_earliest_record_uses_own_bounded_clock_not_lexical_record_identifier(self):
        value = case()
        source = value["sources"][0]
        original = value["nodes"][0]
        value["nodes"] = [evidence_node(source, "record:10", "FILE_OPERATION", metadata=original["metadata"],
            time_domain="clock-a", time_bounds={"start": 10, "end": 10, "unit": "ns"}),
            evidence_node(source, "record:2", "FILE_OPERATION", metadata=original["metadata"],
            time_domain="clock-a", time_bounds={"start": 2, "end": 3, "unit": "ns"}),
            evidence_node(source, "record:other-clock", "FILE_OPERATION", metadata=original["metadata"],
            time_domain="clock-b", time_bounds={"start": 1, "end": 1, "unit": "ns"})]
        result = group_recurrent_issues([value])["groups"][0]
        earliest_a = next(item for item in result["first_observations_by_source"] if item["time_domain"] == "clock-a")
        self.assertEqual(earliest_a["occurrences"][0]["source_record_id"], "record:2")
        self.assertEqual(result["first_observation_across_sources"], "NOT_ESTABLISHED_FOR_INDEPENDENT_CLOCKS")

    def test_overlapping_first_intervals_and_unknown_times_remain_ambiguous(self):
        value = case()
        first = value["nodes"][0]
        first["time_bounds"] = {"start": 1, "end": 5, "unit": "ns"}
        other = evidence_node(value["sources"][0], "overlap", "FILE_OPERATION", metadata=first["metadata"],
            time_domain=first["time_domain"], time_bounds={"start": 2, "end": 3, "unit": "ns"})
        missing = evidence_node(value["sources"][0], "unknown", "FILE_OPERATION", metadata=first["metadata"])
        value["nodes"].extend([other, missing])
        group = group_recurrent_issues([value])["groups"][0]
        self.assertEqual(group["first_observations_by_source"][0]["status"], "OVERLAPPING_FIRST_OBSERVATIONS")
        self.assertEqual(len(group["first_observations_by_source"][0]["occurrences"]), 2)
        self.assertEqual(group["observations_without_time"], 1)


class InvestigationComparisonContracts(unittest.TestCase):
    def test_distinct_actual_build_anchors_with_complete_matching_workload_are_comparable(self):
        result = compare_investigations(case(), case("two", version="B", app_hash="b" * 64))
        self.assertEqual(result["status"], "COMPARABLE")
        self.assertTrue(all(item["passed"] for item in result["checks"]))
        self.assertEqual(result["versions"], ["A", "B"])
        self.assertFalse(result["root_cause_established"])

    def test_missing_error_in_comparable_run_is_only_observed_absence(self):
        result = compare_investigations(case(), case("two", version="B", app_hash="b" * 64, error=0))
        self.assertEqual(result["status"], "COMPARABLE")
        self.assertEqual(result["differences"][0]["first_count"], 1)
        self.assertEqual(result["differences"][0]["second_count"], 0)
        self.assertEqual(result["differences"][0]["absence_means"], "NOT_OBSERVED_IN_THIS_COMPARABLE_RUN")
        self.assertEqual(result["interpretation"], "OBSERVED_DIFFERENCES_NOT_PROOF_OF_FIX_OR_CAUSATION")

    def test_incomplete_mismatched_or_unknown_coverage_is_never_comparable(self):
        for mutation in ("bool_operations", "missing_input", "different_workload", "incomplete_scenario",
                         "unknown_loss", "events_lost", "order_errors", "sequence_gap", "no_terminal",
                         "not_scanned", "omitted", "unknown_coverage", "omitted_operation", "same_build_relabel",
                         "same_capture", "bad_family", "unknown_source_kind", "bool_loss", "selection"):
            with self.subTest(mutation=mutation):
                first, second = case(), case("two", version="B", app_hash="b" * 64)
                source = second["sources"][0]
                if mutation == "bool_operations":
                    second["scenario"]["operation_count"] = True
                elif mutation == "missing_input":
                    del second["scenario"]["input_bytes"]
                elif mutation == "different_workload":
                    second["scenario"]["workload_id"] = "DIFFERENT"
                elif mutation == "incomplete_scenario":
                    second["scenario"]["complete"] = False
                elif mutation == "unknown_loss":
                    source["application_client_dropped_total"] = None
                elif mutation == "bool_loss":
                    source["application_client_dropped_total"] = False
                elif mutation == "events_lost":
                    source["application_client_dropped_total"] = 1
                elif mutation == "order_errors":
                    source["application_order_errors"] = 1
                elif mutation == "sequence_gap":
                    source["application_sequence_gaps"] = 1
                elif mutation == "no_terminal":
                    source["application_events_complete"] = False
                elif mutation == "not_scanned":
                    source["scan_complete"] = False
                elif mutation == "omitted":
                    second["coverage"]["events_omitted"] = 1
                elif mutation == "unknown_coverage":
                    del second["coverage"]["edges_omitted"]
                elif mutation == "omitted_operation":
                    second["nodes"][1]["metadata"]["operation_id"] = None
                elif mutation == "same_build_relabel":
                    second["app_identity"]["sha256"] = first["app_identity"]["sha256"]
                elif mutation == "same_capture":
                    second = deepcopy(first)
                    second["case_id"] = stable_id("relabelled-case")
                elif mutation == "bad_family":
                    second["app_identity"]["application_id"] = "OTHER"
                elif mutation == "selection":
                    source["selected_events"] = 2
                else:
                    source["source_type"] = "DUMP_METADATA"
                    for node in second["nodes"]:
                        node["source_type"] = "DUMP_METADATA"
                result = compare_investigations(first, second)
                self.assertEqual(result["status"], "NOT_COMPARABLE")
                self.assertTrue(result["reasons"])
                self.assertNotIn("differences", result)

    def test_known_operation_denominator_only_for_complete_recorded_workload(self):
        first, second = case(), case("two")
        second["sources"][0]["application_events_complete"] = False
        grouped = group_recurrent_issues([first, second])
        ratios = {row["case_id"]: row for row in grouped["groups"][0]["frequency"]["per_case_workload"]}
        self.assertEqual(ratios[first["case_id"]]["issues_per_recorded_operation"], .5)
        self.assertIsNone(ratios[second["case_id"]]["issues_per_recorded_operation"])
        self.assertIsNone(ratios[second["case_id"]]["recorded_operation_count"])
        self.assertEqual(len(grouped["groups"][0]["history"]), 2)

    def test_trace_identity_uses_capture_hash_even_when_private_index_hash_differs(self):
        first, second = case(), case("two")
        for value in (first, second):
            source = value["sources"][0]
            source.update(source_type="TRACE_INDEX", trace_input_sha256="d" * 64, decoded_status="DECODED",
                decoder_reported_lost_events=0, out_of_order_events=False, decode_errors_observed=False, event_sequence_gaps=0)
            value["coverage"]["source_coverage"][0]["events_total_after_cursor"] = 3
            for node in value["nodes"]:
                node["source_type"] = "TRACE_INDEX"
        result = compare_investigations(first, second)
        self.assertEqual(result["status"], "NOT_COMPARABLE")
        self.assertIn("SESSION_IDENTITIES", result["reasons"])


class DeclaredApplicationContextContracts(unittest.TestCase):
    def test_explicit_entire_case_declaration_allows_only_conditional_comparison(self):
        first = declared_case()
        second = declared_case("two", version="B", app_hash="b" * 64, error=0)
        result = compare_investigations(first, second)
        self.assertEqual(result["status"], "COMPARABLE_WITH_DECLARED_CONTEXT")
        self.assertEqual(result["context_provenance"], "USER_REPORTED")
        self.assertEqual(result["source_binding"], "NOT_ESTABLISHED")
        self.assertEqual(result["context_scope"], "ENTIRE_CASE")
        self.assertTrue(result["conditional"])
        self.assertFalse(result["root_cause_established"])
        self.assertIn("NOT_REGRESSION_OR_FIX_EVIDENCE", result["interpretation"])
        self.assertEqual(result["differences"][0]["second_count"], 0)
        self.assertTrue(result["differences"][0]["conditional"])
        self.assertEqual(result["differences"][0]["absence_means"], "NOT_OBSERVED_WITH_USER_DECLARED_CONTEXT")

    def test_declared_groups_are_separate_from_recorded_anchors_and_keep_conditional_history(self):
        declared = declared_case()
        grouped = group_recurrent_issues([declared, declared_case("two")])
        group = grouped["groups"][0]
        recorded = issue_fingerprint(case(), case()["nodes"][0])
        self.assertEqual(group["status"], "MATCHING_DECLARED_ANCHORS")
        self.assertNotEqual(group["fingerprint"], recorded["fingerprint"])
        self.assertEqual(group["occurrence_count"], 2)
        self.assertEqual(group["source_binding"], "NOT_ESTABLISHED")
        self.assertEqual(group["source_trust"], "UNVERIFIED_IMPORT")
        self.assertTrue(group["frequency"]["conditional"])
        self.assertTrue(all(row["conditional"] and row["verification_class"] == "USER_REPORTED"
                            for row in group["history"]))
        self.assertFalse(group["root_cause_established"])

    def test_missing_scope_hash_declared_workload_or_complete_source_is_not_enough(self):
        for mutation in ("no_hash", "bad_hash", "no_scope", "partial_scope", "no_binding",
                         "claimed_binding", "no_scenario_provenance", "incomplete_source", "missing_workload"):
            with self.subTest(mutation=mutation):
                first, second = declared_case(), declared_case("two")
                if mutation == "no_hash":
                    del second["app_identity"]["sha256"]
                elif mutation == "bad_hash":
                    second["app_identity"]["sha256"] = "no binary hash"
                elif mutation == "no_scope":
                    del second["app_identity"]["context_scope"]
                elif mutation == "partial_scope":
                    second["app_identity"]["context_scope"] = "SELECTED_INCIDENT"
                elif mutation == "no_binding":
                    del second["app_identity"]["source_binding"]
                elif mutation == "claimed_binding":
                    second["app_identity"]["source_binding"] = "OS_OBSERVED"
                elif mutation == "no_scenario_provenance":
                    del second["scenario"]["verification_class"]
                elif mutation == "incomplete_source":
                    second["sources"][0]["application_events_complete"] = False
                else:
                    del second["scenario"]["workload_id"]
                result = compare_investigations(first, second)
                self.assertEqual(result["status"], "NOT_COMPARABLE")
                self.assertNotIn("differences", result)
                if mutation != "incomplete_source":
                    fingerprint = issue_fingerprint(second, second["nodes"][0])
                    self.assertEqual(fingerprint["status"], "CANDIDATE")

    def test_declared_source_binding_cannot_be_promoted_by_changing_only_class(self):
        first, second = declared_case(), declared_case("two")
        for value in (first, second):
            value["app_identity"]["verification_class"] = "OS_OBSERVED"
        self.assertEqual(compare_investigations(first, second)["status"], "NOT_COMPARABLE")
        self.assertEqual(issue_fingerprint(first, first["nodes"][0])["status"], "CANDIDATE")


class ManualGroupingContracts(unittest.TestCase):
    def test_merge_split_preserve_original_events_reason_history_and_anchor_provenance(self):
        cases = [case(), case("two"), case("other-error", error=2)]
        originals = deepcopy(cases)
        grouped = group_recurrent_issues(cases)
        original_grouped = deepcopy(grouped)
        old_fingerprints = sorted(group["fingerprint"] for group in grouped["groups"])
        merged = manual_group_change(grouped, action="MERGE", group_ids=[row["group_id"] for row in grouped["groups"]],
                                     reason="These belong to one user investigation.")
        self.assertEqual(cases, originals)
        self.assertEqual(grouped, original_grouped)
        group = merged["groups"][0]
        self.assertEqual(group["original_fingerprints"], old_fingerprints)
        self.assertEqual(group["verification_class"], "USER_REPORTED")
        self.assertEqual(group["user_confirmation_scope"], "GROUP_MEMBERSHIP_ONLY")
        self.assertIsNone(group["fingerprint"])
        self.assertFalse(group["root_cause_established"])
        self.assertEqual(merged["manual_history"][0]["previous_groups"], original_grouped["groups"])
        split = manual_group_change(merged, action="SPLIT", group_ids=[group["group_id"]],
                                    case_ids=[cases[0]["case_id"]], reason="Keep this session separate.")
        self.assertEqual(len(split["groups"]), 2)
        self.assertEqual(len(split["manual_history"]), 2)
        self.assertEqual(sum(row["occurrence_count"] for row in split["groups"]), 3)
        self.assertTrue(all(row["original_fingerprints"] == old_fingerprints for row in split["groups"]))
        self.assertTrue(all(row["source_events_modified"] is False for row in split["manual_history"]))

    def test_invalid_manual_changes_refuse_empty_partitions_unknown_ids_and_missing_reason(self):
        grouped = group_recurrent_issues([case(), case("two")])
        identifier = grouped["groups"][0]["group_id"]
        for changes in ({"reason": " "}, {"group_ids": ["missing"]}, {"case_ids": []},
                        {"case_ids": ["missing-case"]}, {"case_ids": grouped["groups"][0]["case_ids"]},
                        {"action": "MERGE"}):
            with self.subTest(changes=changes):
                arguments = {"action": "SPLIT", "group_ids": [identifier],
                    "case_ids": [case()["case_id"]], "reason": "A recorded user reason"}
                arguments.update(changes)
                with self.assertRaises(InvestigationError):
                    manual_group_change(grouped, **arguments)

    def test_malformed_history_is_refused_before_copy(self):
        grouped = group_recurrent_issues([case(), case("two")])
        identifier = grouped["groups"][0]["group_id"]
        grouped["groups"][0]["history"] = "not a list"
        with patch("blackbox_core.issue_grouping.deepcopy") as copying:
            with self.assertRaisesRegex(InvestigationError, "INVALID_MANUAL_GROUP_HISTORY"):
                manual_group_change(grouped, action="SPLIT", group_ids=[identifier],
                                    case_ids=[case()["case_id"]], reason="Keep separate")
            copying.assert_not_called()

    def test_large_or_cancelled_input_is_refused_before_copy(self):
        grouped = group_recurrent_issues([case(), case("two")])
        identifier = grouped["groups"][0]["group_id"]
        with patch("blackbox_core.issue_grouping.deepcopy") as copying:
            with self.assertRaisesRegex(InvestigationError, "ISSUE_INPUT_BYTE_BUDGET"):
                manual_group_change(grouped, action="SPLIT", group_ids=[identifier],
                    case_ids=[case()["case_id"]], reason="Keep separate", budget=InvestigationBudget(max_result_bytes=1024))
            copying.assert_not_called()
        event = Event()
        event.set()
        with patch("blackbox_core.issue_grouping.deepcopy") as copying:
            with self.assertRaises(InterruptedError):
                manual_group_change(grouped, action="SPLIT", group_ids=[identifier],
                    case_ids=[case()["case_id"]], reason="Keep separate", budget=InvestigationBudget(cancel_event=event))
            copying.assert_not_called()

    def test_duplicate_case_ids_and_unbound_issue_node_are_refused(self):
        value = case()
        with self.assertRaisesRegex(InvestigationError, "DUPLICATE_ISSUE_CASE_ID"):
            group_recurrent_issues([value, deepcopy(value)])
        with self.assertRaisesRegex(InvestigationError, "ISSUE_NODE_NOT_IN_CASE"):
            issue_fingerprint(value, case("unrelated")["nodes"][0])


if __name__ == "__main__":
    unittest.main()
