"""Real saved JSONL integration; fixtures do not claim captured Windows evidence."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from blackbox_core.evidence_graph import validate_case
from blackbox_core.investigation_graph_contracts import InvestigationBudget, InvestigationError, canonical_json
from blackbox_core.investigation_v3 import (analyze_critical_path, create_investigation, export_investigation,
                                          load_investigation, _bound_case_projections)
from blackbox_core.issue_grouping import _bounded_input


class InvestigationAggregateBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "recorded-format-fixture.jsonl"
        rows = [{"schema_version": 1, "token": "BOUNDED_INTEGRATION_FIXTURE_NOT_AUTHENTICATED",
                 "pid": 42, "tid": 43, "seq": number, "source_ns": number * 1000,
                 "source_clock": "UNALIGNED_APPLICATION_FIXTURE", "kind": "io.operation.error",
                 "client_dropped": 0, "operation_id": "operation-" + str(number),
                 "attributes": {"status": "ERROR", "winerror": 5, "error_code": 5,
                                "operation": "WRITE", "note": "recorded detail " * 48}}
                for number in range(1, 401)]
        self.source.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        self.digest = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.sources = [{"source_type": "EVENTS_JSONL", "path": str(self.source)}]

    @staticmethod
    def size(value):
        return len(canonical_json(value).encode("ascii"))

    def test_exact_issue_input_budget_accepts_boundary_and_refuses_one_byte_less(self):
        value = [{"missing": None, "observed": True, "false": False, "empty": {}, "rows": [],
                  "text": "Русский текст", "number": number, "floating": 1.25} for number in range(100)]
        maximum = self.size(value)
        _bounded_input(value, InvestigationBudget(max_result_bytes=maximum))
        with self.assertRaisesRegex(InvestigationError, "ISSUE_INPUT_BYTE_BUDGET"):
            _bounded_input(value, InvestigationBudget(max_result_bytes=maximum - 1))

    def test_actual_file_graph_remains_reopenable_with_explicit_bounded_projection_omissions(self):
        full = create_investigation(self.sources)
        required = deepcopy(full)
        for model in ("issues", "actions", "hypotheses", "crash_investigation", "delay_investigation"):
            required.pop(model, None)
        # Derive a small contract-test budget that admits the complete source
        # graph/CP but rejects the aggregate of all computed displays.
        maximum = (self.size(required) + self.size(full)) // 2
        self.assertGreater(maximum - self.size(required), 16384)
        self.assertLess(maximum, self.size(full))
        destination = self.root / "bounded-investigation.sqlite3"
        limited = create_investigation(self.sources, index_path=destination,
                                        budget=InvestigationBudget(max_result_bytes=maximum))
        self.assertLessEqual(self.size(limited), maximum)
        self.assertEqual(limited["nodes"], full["nodes"])
        self.assertEqual(limited["edges"], full["edges"])
        self.assertEqual(limited["sources"], full["sources"])
        self.assertEqual(limited["case_id"], full["case_id"])
        self.assertEqual(limited["critical_path"], full["critical_path"])
        self.assertTrue(limited["_index_receipt"]["readback_verified"])
        self.assertNotIn("issues", limited)
        self.assertNotIn("issue_groups", limited["coverage"])
        self.assertNotIn("candidate_issues", limited["coverage"])
        self.assertEqual(limited["coverage"]["issue_analysis_status"], "NOT_INCLUDED_BYTE_BUDGET")
        self.assertEqual(limited["coverage"]["analysis_projection_completeness"], "PARTIAL")
        omitted = limited["coverage"]["omitted_models"]
        self.assertTrue(any(row["model"] == "issues" for row in omitted))
        self.assertTrue(all(row["reason"] == "AGGREGATE_CASE_RESULT_BYTE_BUDGET" and
                            row["computed_bytes"] > 0 for row in omitted))
        receipt = limited["run_receipt"]
        self.assertEqual(receipt["status"], "COMPLETED")
        self.assertTrue(receipt["execution_started"])
        self.assertTrue(receipt["cleanup"]["confirmed"])
        self.assertEqual(receipt["coverage"]["completeness"], "INCOMPLETE_EVIDENCE")
        self.assertEqual(receipt["coverage"]["source_evidence_completeness"],
                         limited["coverage"]["evidence_completeness"])
        self.assertEqual(limited["root_cause"], "UNKNOWN")
        self.assertFalse(limited["root_cause_proven"])
        validate_case(limited, budget=InvestigationBudget(max_result_bytes=maximum))
        indexed_before = hashlib.sha256(destination.read_bytes()).hexdigest()
        reopened = load_investigation(destination, budget=InvestigationBudget(max_result_bytes=maximum))
        self.assertLessEqual(self.size(reopened), maximum)
        self.assertEqual(reopened["nodes"], full["nodes"])
        self.assertEqual(reopened["sources"], full["sources"])
        self.assertEqual(reopened["critical_path"], full["critical_path"])
        self.assertEqual(analyze_critical_path(reopened, budget=InvestigationBudget(max_result_bytes=maximum)),
                         full["critical_path"])
        self.assertEqual(reopened["coverage"]["issue_analysis_status"], "NOT_INCLUDED_BYTE_BUDGET")
        exported = self.root / "bounded-report.json"
        export_investigation(reopened, exported, budget=InvestigationBudget(max_result_bytes=maximum))
        public = json.loads(exported.read_text(encoding="utf-8"))
        self.assertEqual(public["coverage"]["analysis_projection_completeness"], "PARTIAL")
        self.assertFalse(public["root_cause_proven"])
        self.assertEqual(public["sources"][0]["verification_class"], "UNVERIFIED_IMPORT")
        self.assertEqual(hashlib.sha256(destination.read_bytes()).hexdigest(), indexed_before)
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), self.digest)

    def test_required_graph_and_cp_cannot_be_silently_dropped_to_fit(self):
        full = create_investigation(self.sources)
        original_nodes, original_sources = deepcopy(full["nodes"]), deepcopy(full["sources"])
        with self.assertRaisesRegex(InvestigationError, "INVESTIGATION_RESULT_BYTE_BUDGET") as raised:
            _bound_case_projections(full, InvestigationBudget(max_result_bytes=1024))
        self.assertGreater(raised.exception.critical_path_bytes, 0)
        self.assertGreater(raised.exception.retained_graph_bytes, 0)
        self.assertGreaterEqual(raised.exception.actual_result_bytes, raised.exception.retained_graph_bytes)
        self.assertEqual(raised.exception.result_byte_limit, 1024)
        self.assertEqual(full["nodes"], original_nodes)
        self.assertEqual(full["sources"], original_sources)
        self.assertIn("critical_path", full)
        self.assertFalse(full["root_cause_proven"])
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), self.digest)

    def test_malformed_or_contradictory_omission_markers_are_refused(self):
        full = create_investigation(self.sources)
        marker = {"model": "issues", "reason": "AGGREGATE_CASE_RESULT_BYTE_BUDGET", "computed_bytes": 1000}
        for invalid in ([{**marker, "computed_bytes": True}], [{**marker, "computed_bytes": float("inf")}],
                        [{**marker, "model": "nodes"}], [{**marker, "reason": "USER_MESSAGE"}],
                        [marker, marker], [marker]):
            with self.subTest(invalid=invalid):
                case = deepcopy(full)
                case["coverage"]["omitted_models"] = invalid
                with self.assertRaisesRegex(InvestigationError, "INVALID_ANALYSIS_MODEL_OMISSIONS"):
                    _bound_case_projections(case, InvestigationBudget())

        # A format-valid saved import may still contain contradictory optional
        # coverage claims. The public load facade must refuse those claims.
        from blackbox_core.investigation_graph_store import save_investigation
        contradictory = deepcopy(full)
        contradictory["coverage"]["omitted_models"] = [marker]
        destination = self.root / "contradictory-model-marker.sqlite3"
        save_investigation(contradictory, destination)
        with self.assertRaisesRegex(InvestigationError, "INVALID_ANALYSIS_MODEL_OMISSIONS"):
            load_investigation(destination)
