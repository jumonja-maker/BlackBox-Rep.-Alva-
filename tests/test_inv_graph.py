"""Synthetic graph contracts; native evidence is tested separately in hosted CI."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
from threading import Event
import unittest

from blackbox_core.evidence_graph import build_graph, get_related_evidence, validate_case
from blackbox_core.investigation_graph_contracts import (InvestigationBudget, InvestigationError,
    evidence_node, stable_id)


def source(label="one", kind="DEEP_JOURNAL"):
    digest = stable_id("synthetic-source", label)
    return {"source_id": stable_id("source", kind, digest), "source_type": kind,
            "source_sha256": digest}


def process(pid=123, created=133000000000000000):
    return {"kind": "LIVE_PROCESS", "pid": pid, "created_100ns": created}


def node(src, record, kind="MEASUREMENT", *, target=None, metadata=None, clock="test-clock", stamp=1):
    return evidence_node(src, record, kind, process_identity=target or process(),
        metadata=metadata or {}, time_domain=clock,
        time_bounds={"start": stamp, "end": stamp, "unit": "ns", "uncertainty": None})


class EvidenceGraphContracts(unittest.TestCase):
    def normalized(self):
        a, b = source(), source("two")
        first = node(a, "records:1", "PROCESS")
        second = node(a, "records:2", metadata={"record_refs": ["records:1"]})
        third = node(b, "records:3", target=process(created=133000000000000001))
        return {"sources": [a, b], "nodes": [first, second, third], "coverage": {},
                "selection": {"start_ns": 0, "end_ns": 2}, "limitations": []}

    def test_source_order_and_path_do_not_change_graph_identity_or_edges(self):
        raw = self.normalized()
        first = build_graph(raw)
        other = deepcopy(raw)
        other["nodes"].reverse()
        other["sources"].reverse()
        second = build_graph(other)
        self.assertEqual(first, second)
        self.assertEqual(first["root_cause"], "UNKNOWN")
        self.assertFalse(first["root_cause_proven"])

    def test_real_index_adapter_case_identity_binds_effective_source_selection(self):
        """Controlled decoder interchange is a contract fixture, not native ETW proof."""
        from blackbox_core.decoder_index import PROTOCOL, build_index
        from blackbox_core.evidence_normalization import normalize_sources
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interchange, index = root / "fixture.jsonl", root / "fixture.sqlite3"
            rows = [{"type": "event", "ordinal": ordinal, "time_ms": stamp, "pid": pid, "tid": tid,
                     "process_instance": instance, "provider": "SELECTION_CONTRACT_FIXTURE",
                     "name": "FileIO/Write", "payload": {}, "frames": []}
                    for ordinal, stamp, pid, tid, instance in ((1, 10, 123, 7, 4), (2, 20, 456, 8, 5))]
            records = [{"type": "header", "protocol": PROTOCOL, "input_sha256": "a" * 64}, *rows,
                       {"type": "footer", "protocol": PROTOCOL, "rows": 2, "status": "DECODED",
                        "decoder_reported_lost_events": 0}]
            interchange.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
            build_index(interchange, index, input_sha256="a" * 64, format_name=".etl")
            first_filter = {"pid": 123, "process_instance": 4, "start_ms": 0, "end_ms": 15}
            second_filter = {"pid": 456, "process_instance": 5, "start_ms": 15, "end_ms": 30}
            def selected(path, filters):
                return build_graph(normalize_sources([{"source_type": "TRACE_INDEX", "path": path,
                                                       "selection": filters}]))
            first, second = selected(index, first_filter), selected(index, second_filter)
            narrower = selected(index, {**first_filter, "end_ms": 12})
            relocated = root / "relocated.sqlite3"
            shutil.copyfile(index, relocated)
            copied = selected(relocated, dict(reversed(list(first_filter.items()))))
            self.assertEqual(first["source_ids"], second["source_ids"])
            self.assertNotEqual(first["case_id"], second["case_id"])
            self.assertNotEqual(first["case_id"], narrower["case_id"])
            self.assertEqual(first["nodes"], narrower["nodes"])
            self.assertEqual(first["case_id"], copied["case_id"])
            self.assertEqual(first["nodes"], copied["nodes"])
            self.assertEqual(first["source_selections"][0]["selection"], first_filter)

    def test_filetime_difference_never_makes_exact_process_link(self):
        raw = self.normalized()
        different = raw["nodes"][-1]["node_id"]
        case = build_graph(raw)
        self.assertFalse(any(different in (edge["from_node"], edge["to_node"])
            and edge["relation_type"] == "EXACT_IDENTITY" for edge in case["edges"]))

    def test_imported_hypothesis_requires_real_refs_and_human_attribution(self):
        case = build_graph(self.normalized())
        base = {"hypothesis_id": "hypothesis-one", "status": "CANDIDATE",
                "supporting_nodes": [case["nodes"][0]["node_id"]], "root_cause_proven": False}
        case["hypotheses"] = [base]
        validate_case(case)
        for field, value, error in (("supporting_nodes", ["phantom"], "DANGLING_HYPOTHESIS"),
                ("root_cause_proven", True, "ROOT_CAUSE_PROOF"),
                ("status", "USER_CONFIRMED", "ATTRIBUTION"),
                ("status", "SUPPORTED_BY_CONTROLLED_EXPERIMENT", "NOT_IMPLEMENTED"),
                ("confidence_percent", 99, "CAUSAL_SCORE")):
            changed = deepcopy(case)
            changed["hypotheses"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(InvestigationError, error):
                validate_case(changed)
        case["hypotheses"][0].update(status="USER_CONFIRMED", user_verdict={
            "actor": "USER", "verification_class": "USER_REPORTED", "note": "Human interpretation"})
        validate_case(case)

    def test_imported_advice_cannot_invent_action_or_automatic_authority(self):
        case = build_graph(self.normalized())
        case["actions"] = [{"operation": "snapshot", "status": "NOT_ESTABLISHED", "automatic_execution": False}]
        validate_case(case)
        for field, value in (("operation", "invented.execute"), ("automatic_execution", True), ("status", "GUARANTEED")):
            changed = deepcopy(case)
            changed["actions"][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(InvestigationError, "DIAGNOSTIC_ADVICE"):
                validate_case(changed)

    def test_import_cannot_promote_claimed_os_authenticity(self):
        case = build_graph(self.normalized())
        case["nodes"][0]["metadata"]["recorded_verification_class"] = "OS_OBSERVED"
        validate_case(case)
        for where in ("nodes", "sources"):
            changed = deepcopy(case)
            changed[where][0]["verification_class"] = "OS_OBSERVED"
            with self.subTest(where=where), self.assertRaisesRegex(InvestigationError, "VERIFIED_PROVENANCE"):
                validate_case(changed)

    def test_imported_critical_path_cannot_use_phantom_nodes_or_duration(self):
        case = build_graph(self.normalized())
        case["critical_path"] = {"schema": "blackbox.critical-path/1", "status": "PARTIAL",
            "end_to_end_established": False, "segments": [], "dependencies": [], "path": [],
            "totals": {"running_ms": 0, "blocked_ms": 0, "ready_ms": 0}}
        validate_case(case)
        case["critical_path"]["segments"] = [{"segment_id": "one", "node_id": "phantom"}]
        with self.assertRaisesRegex(InvestigationError, "DANGLING_CRITICAL_PATH_NODE"):
            validate_case(case)
        case["critical_path"]["segments"] = []
        case["critical_path"]["totals"]["running_ms"] = -1
        with self.assertRaisesRegex(InvestigationError, "INVALID_CRITICAL_PATH_DURATION"):
            validate_case(case)

    def test_identical_native_lifetime_can_join_sources_without_authenticating_them(self):
        a, b = source(), source("two")
        case = build_graph({"sources": [a, b], "nodes": [node(a, "one", "PROCESS"), node(b, "two")]})
        self.assertEqual(len(case["edges"]), 1)
        self.assertEqual(case["edges"][0]["relation_type"], "EXACT_IDENTITY")
        self.assertTrue(all(value["verification_class"] == "UNVERIFIED_IMPORT" for value in case["nodes"]))

    def test_duplicate_source_node_id_with_different_content_is_rejected(self):
        raw = self.normalized()
        changed = deepcopy(raw["nodes"][0])
        changed["metadata"] = {"status": "different"}
        raw["nodes"].append(changed)
        with self.assertRaisesRegex(InvestigationError, "CONFLICTING_EVIDENCE_NODE_ID"):
            build_graph(raw)

    def test_changed_source_hash_cannot_hide_under_same_node_binding(self):
        raw = self.normalized()
        raw["sources"][0]["source_sha256"] = "f" * 64
        with self.assertRaisesRegex(InvestigationError, "NODE_SOURCE_IDENTITY_MISMATCH"):
            build_graph(raw)

    def test_graph_caps_are_visible_and_case_id_binds_build_parameters(self):
        raw = self.normalized()
        full = build_graph(raw)
        partial = build_graph(raw, budget=InvestigationBudget(max_nodes=1, max_edges=1))
        self.assertEqual(len(partial["nodes"]), 1)
        self.assertEqual(partial["coverage"]["nodes_omitted"], 2)
        self.assertFalse(partial["coverage"]["display_graph_complete"])
        self.assertIn("DISPLAY_NODE_BUDGET_REACHED", partial["limitations"])
        self.assertNotEqual(full["case_id"], partial["case_id"])

    def test_dangling_reference_remains_an_explicit_gap_without_false_link(self):
        raw = self.normalized()
        raw["nodes"][1]["metadata"]["record_refs"] = ["not-in-source-window"]
        case = build_graph(raw)
        self.assertTrue(any(gap["reason"] == "SOURCE_RECORD_NOT_INCLUDED" for gap in case["gaps"]))
        self.assertFalse(any(edge["relation_type"] == "DIRECT_REFERENCE" for edge in case["edges"]))

    def test_upstream_omission_count_is_not_erased_by_a_fitting_display_graph(self):
        raw = self.normalized()
        raw["coverage"] = {"nodes_omitted": 5000, "has_more": True, "events_omitted_is_lower_bound": True}
        case = build_graph(raw)
        self.assertEqual(case["coverage"]["nodes_omitted"], 5000)
        self.assertEqual(case["coverage"]["normalization_nodes_omitted"], 5000)
        self.assertEqual(case["coverage"]["graph_nodes_omitted"], 0)
        self.assertFalse(case["coverage"]["display_graph_complete"])
        self.assertTrue(case["coverage"]["events_omitted_is_lower_bound"])

    def test_related_queries_are_paged_and_keep_evidence_context(self):
        raw = self.normalized()
        case = build_graph(raw)
        selected = raw["nodes"][0]["node_id"]
        first = get_related_evidence(case, selected, limit=1)
        self.assertEqual(first["case_id"], case["case_id"])
        self.assertEqual(len(first["edges"]), 1)
        self.assertTrue(first["has_more"])
        second = get_related_evidence(case, selected, after=first["next_cursor"], limit=1)
        self.assertFalse(second["has_more"])
        self.assertNotEqual(first["edges"][0]["edge_id"], second["edges"][0]["edge_id"])

    def test_cancelled_budget_prevents_graph_and_query_work(self):
        event = Event()
        event.set()
        with self.assertRaises(InterruptedError):
            build_graph(self.normalized(), budget=InvestigationBudget(cancel_event=event))

    def test_import_rejects_dangling_edges_nonfinite_and_false_proof(self):
        original = build_graph(self.normalized())
        for mutation, message in (("dangling", "DANGLING_EVIDENCE_EDGE"),
                                  ("nonfinite", "NONFINITE"), ("proof", "ROOT_CAUSE_PROOF")):
            with self.subTest(mutation=mutation):
                case = deepcopy(original)
                if mutation == "dangling":
                    case["edges"][0]["to_node"] = "does-not-exist"
                elif mutation == "nonfinite":
                    case["nodes"][0]["metadata"]["value"] = float("nan")
                else:
                    case["root_cause_proven"] = True
                with self.assertRaisesRegex(InvestigationError, message):
                    validate_case(case)

    def test_import_rejects_cross_source_direct_pointer(self):
        case = build_graph(self.normalized())
        edge = next(edge for edge in case["edges"] if edge["relation_type"] == "DIRECT_REFERENCE")
        other_source_node = next(value for value in case["nodes"] if value["source_identity"] !=
                                 next(value["source_identity"] for value in case["nodes"] if value["node_id"] == edge["from_node"]))
        edge["to_node"] = other_source_node["node_id"]
        with self.assertRaisesRegex(InvestigationError, "CROSS_SOURCE_DIRECT_REFERENCE"):
            validate_case(case)

    def test_manual_annotations_are_data_and_do_not_change_source_identity(self):
        case = build_graph(self.normalized())
        case["guided_experiments"] = [{"operation_id": "manual-id", "status": "RECOVERY_UNCONFIRMED"}]
        case["user_annotations"] = [{"text": "USER_CONFIRMED is the user's statement"}]
        validate_case(case)
        self.assertFalse(case["root_cause_proven"])

    def test_real_uint64_kernel_addresses_remain_metadata_but_huge_integers_fail(self):
        raw = self.normalized()
        raw["nodes"][0]["metadata"]["instruction_address"] = 0xFFFFF80001234567
        case = build_graph(raw)
        self.assertTrue(any(value["metadata"].get("instruction_address") == 0xFFFFF80001234567
                            for value in case["nodes"]))
        raw["nodes"][0]["metadata"]["instruction_address"] = 2**256
        with self.assertRaisesRegex(InvestigationError, "OUT_OF_RANGE_INVESTIGATION_INTEGER"):
            build_graph(raw)


if __name__ == "__main__":
    unittest.main()
