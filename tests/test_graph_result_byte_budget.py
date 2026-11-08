"""Oversized read-only graph views retain source evidence and honest coverage."""
from __future__ import annotations

import unittest
from blackbox_core.evidence_graph import build_graph, validate_case
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

    def test_impossible_budget_fails_closed(self):
        with self.assertRaisesRegex(InvestigationError,
                                    "INVESTIGATION_RESULT_BYTE_BUDGET"):
            build_graph(self.source_graph(),
                        budget=InvestigationBudget(max_nodes=1000,
                            max_result_bytes=1024, timeout_seconds=90))


if __name__ == "__main__":
    unittest.main()
