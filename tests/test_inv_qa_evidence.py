"""QA evidence cannot strengthen application statements or cross-source joins."""
import unittest

from tools.qa_inv_common import graph_facts
from tools.qa_inv_native import assert_sdk_file_case


class InvestigationNativeQaEvidenceContracts(unittest.TestCase):
    def case(self):
        node = {"node_id": "a", "source_identity": "sdk", "source_record_id": "application:producer:2",
                "source_sha256": "a" * 64, "source_type": "EVENTS_JSONL",
                "observation_type": "FILE_OPERATION", "verification_class": "UNVERIFIED_IMPORT",
                "metadata": {"operation_id": "own-operation", "status": "ERROR", "error_code": 5}}
        return {"schema": "blackbox.investigation-graph/1", "case_id": "case", "coverage": {},
                "nodes": [node, {**node, "node_id": "b", "source_record_id": "application:producer:1"}],
                "edges": [{"edge_id": "e", "from_node": "b", "to_node": "a",
                           "relation_type": "DIRECT_REFERENCE", "limitations": [], "evidence_refs": ["a", "b"]}],
                "hypotheses": [{"category": "FILE_OPERATION_ERROR", "supporting_nodes": ["a"]}]}

    def oracle(self):
        return {"operations": [{"operation_id": "own-operation", "actual_winerror": 5, "status": "ERROR"}]}

    def test_actual_error_and_same_source_direct_reference_are_accepted(self):
        case = self.case()
        graph_facts(case)
        assert_sdk_file_case(case, self.oracle())

    def test_a_missing_application_error_code_is_not_the_known_windows_error(self):
        case = self.case()
        for node in case["nodes"]:
            node["metadata"] = {**node["metadata"], "error_code": None}
        with self.assertRaisesRegex(AssertionError, "RESULT_CHANGED"):
            assert_sdk_file_case(case, self.oracle())

    def test_app_statement_cannot_be_relabelled_os_observed(self):
        case = self.case()
        for node in case["nodes"]:
            node["verification_class"] = "OS_OBSERVED"
        with self.assertRaisesRegex(AssertionError, "PROMOTED_TO_OS_AUTHORITY"):
            assert_sdk_file_case(case, self.oracle())

    def test_same_operation_text_does_not_make_two_sources_a_direct_reference(self):
        case = self.case()
        case["nodes"][1]["source_identity"] = "another-trace"
        with self.assertRaisesRegex(AssertionError, "CROSS_SOURCE_REFERENCE"):
            graph_facts(case)

    def test_orphan_edge_or_duplicate_node_ids_never_pass_graph_evidence_validation(self):
        case = self.case()
        case["edges"][0]["to_node"] = "missing"
        with self.assertRaisesRegex(AssertionError, "EDGE_ENDPOINT"):
            graph_facts(case)
        case = self.case()
        case["nodes"][1]["node_id"] = "a"
        with self.assertRaisesRegex(AssertionError, "NODE_IDS"):
            graph_facts(case)


if __name__ == "__main__":
    unittest.main()
