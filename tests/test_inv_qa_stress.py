"""Prevent the hosted stress harness from accepting incomplete work as PASS."""
import copy
import unittest

from tools.qa_inv_stress import validate_case


class InvestigationStressEvidenceContracts(unittest.TestCase):
    def completed(self):
        return {"outcome": "COMPLETED", "destination_exists": True,
                "leftover_private_indexes": [], "nodes": 256, "edges": 512,
                "index_bytes": 1024 * 1024, "first_page_records": 25,
                "coverage": {"events_examined": 250000, "nodes_omitted": 249744, "has_more": True}}

    def test_full_source_and_disclosed_bounded_projection_are_valid(self):
        validate_case(self.completed(), expected_rows=250000)

    def test_scanning_only_the_display_page_does_not_prove_250k_events(self):
        result = self.completed()
        result["coverage"]["events_examined"] = 256
        with self.assertRaisesRegex(AssertionError, "EXAMINE_FULL_SOURCE"):
            validate_case(result, expected_rows=250000)

    def test_a_large_graph_cannot_hide_omissions_behind_success(self):
        for key, value in (("nodes_omitted", 0), ("has_more", False)):
            result = self.completed()
            result["coverage"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(AssertionError, "OMISSIONS_NOT_DISCLOSED"):
                validate_case(result, expected_rows=250000)

    def test_failed_or_cancelled_work_cannot_publish_a_success_like_index(self):
        result = {"outcome": "InterruptedError", "destination_exists": True,
                  "leftover_private_indexes": []}
        with self.assertRaisesRegex(AssertionError, "PUBLISHED_FINAL_INDEX"):
            validate_case(result, expected_outcome="InterruptedError")

    def test_partial_private_indexes_fail_even_after_completed_result(self):
        result = self.completed()
        result["leftover_private_indexes"] = [".blackbox-investigation-abandoned.sqlite3"]
        with self.assertRaisesRegex(AssertionError, "PRIVATE_INDEX_LEFTOVER"):
            validate_case(result, expected_rows=250000)

    def test_memory_and_paging_bounds_cannot_be_silently_widened(self):
        for field, value in (("nodes", 257), ("edges", 513), ("index_bytes", 129 * 1024**2),
                             ("first_page_records", 26)):
            result = copy.deepcopy(self.completed())
            result[field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                validate_case(result, expected_rows=250000)


if __name__ == "__main__":
    unittest.main()
