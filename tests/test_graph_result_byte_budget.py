"""Oversized read-only graph views retain source evidence and honest coverage."""
from __future__ import annotations

import unittest
from blackbox_core.evidence_graph import build_graph, validate_case
from blackbox_core.investigation_v3 import _composed_graph_budget, _bound_case_projections
from blackbox_core.investigation_graph_contracts import (
    InvestigationBudget, InvestigationError, canonical_json, evidence_node,
)


class GraphResultByteBudgetTests(unittest.TestCase):
    def source_graph(self):
        source = {
            "source_type": "EVENTS_JSONL",
            "source_id": "source-observed",
            "source_sha256": "a" * 64,
            "verification_class": "UNVERIFIED_IMPORT",
            "coverage": {"capture_status": "UNKNOWN_CAPTURE_COMPLETENESS"},
        }
        nodes = [evidence_node(source, "record-" + str(i), "ANNOTATION",
                    metadata={"message": "X" * 4096, "ordinal": i})
                 for i in range(220)]
        return {"sources": [source], "nodes": nodes, "coverage": {},
                "limitations": [], "clock_relations": [], "selection": {}}

    def test_overflow_preserves_sources_and_partial_coverage(self):
        normalized = self.source_graph()
        budget = InvestigationBudget(max_nodes=1000, max_result_bytes=64 * 1024,
                                     timeout_seconds=90)
        first = build_graph(normalized, budget=budget)
        second = build_graph(normalized, budget=budget)
        self.assertEqual(first, second)
        self.assertGreater(len(first["nodes"]), 0)
        self.assertLess(len(first["nodes"]), 220)
        self.assertLessEqual(len(canonical_json(first).encode("ascii")),
                             budget.max_result_bytes)
        self.assertEqual(first["sources"], normalized["sources"])
        coverage = first["coverage"]
        self.assertEqual(coverage["unique_nodes"], 220)
        self.assertEqual(coverage["shown_nodes"], len(first["nodes"]))
        self.assertEqual(coverage["nodes_omitted"], 220 - len(first["nodes"]))
        self.assertFalse(coverage["display_graph_complete"])
        self.assertFalse(coverage["edge_candidate_scan_complete"])
        self.assertTrue(coverage["edges_omitted_is_lower_bound"])
        self.assertTrue(coverage["graph_byte_limited"])
        self.assertIn("DISPLAY_GRAPH_RESULT_BYTE_BUDGET_REACHED", first["limitations"])
        self.assertEqual(validate_case(first, budget=budget), first)

    def test_composed_graph_reserves_required_path_and_reports_display_loss(self):
        # A valid standalone graph can exceed the aggregate result cap once a
        # required critical path and private publication receipt are attached.
        # Reserve space in the *view*, never raise the caller's 128KiB limit.
        normalized = self.source_graph()
        budget = InvestigationBudget(max_nodes=1000, max_result_bytes=128 * 1024,
                                     timeout_seconds=90)
        unreserved = build_graph(normalized, budget=budget)
        base_bytes = len(canonical_json(unreserved).encode("ascii"))
        padding = max(1, budget.max_result_bytes - base_bytes + 4096)
        unreserved["critical_path"] = {"required_path_bytes": "P" * padding}
        with self.assertRaisesRegex(InvestigationError, "INVESTIGATION_RESULT_BYTE_BUDGET"):
            _bound_case_projections(unreserved, budget, reserved_bytes=2048)

        view_budget = _composed_graph_budget(budget)
        self.assertEqual(view_budget.max_result_bytes, 128 * 1024 * 2 // 3)
        self.assertEqual(view_budget.max_nodes, budget.max_nodes)
        self.assertEqual(view_budget.max_events, budget.max_events)
        self.assertEqual(view_budget.deadline, budget.deadline)
        case = build_graph(normalized, budget=view_budget)
        case["critical_path"] = {"required_path_bytes": "P" * padding}
        _bound_case_projections(case, budget, reserved_bytes=2048)
        self.assertEqual(case["critical_path"]["required_path_bytes"], "P" * padding)
        self.assertLessEqual(len(canonical_json(case).encode("ascii")) + 2048,
                             budget.max_result_bytes)
        self.assertEqual(case["sources"], normalized["sources"])
        self.assertTrue(case["coverage"]["graph_byte_limited"])
        self.assertGreater(case["coverage"]["nodes_omitted"], 0)
        self.assertFalse(case["coverage"]["display_graph_complete"])
        self.assertIn("DISPLAY_GRAPH_RESULT_BYTE_BUDGET_REACHED", case["limitations"])

    def test_impossible_budget_fails_closed(self):
        with self.assertRaisesRegex(InvestigationError,
                                    "INVESTIGATION_RESULT_BYTE_BUDGET"):
            build_graph(self.source_graph(),
                        budget=InvestigationBudget(max_nodes=1000,
                            max_result_bytes=1024, timeout_seconds=90))


if __name__ == "__main__":
    unittest.main()
