"""Budget diagnostics preserve original failures; execution belongs to hosted CI."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from blackbox_core.evidence_normalization import normalize_sources
from blackbox_core.investigation_graph_contracts import InvestigationBudget, InvestigationError, canonical_json
from blackbox_core.investigation_v3 import create_investigation


class InvestigationFailureDiagnosticsTests(unittest.TestCase):
    @staticmethod
    def payload():
        return {"observed": "Форматная проверка " * 100, "unknown": None}

    def failure(self, budget):
        try:
            budget.result(self.payload())
        except InvestigationError as error:
            return error
        self.fail("the existing byte cap must reject this result")

    def test_result_boundary_keeps_same_limit_and_attaches_exact_numeric_measurement(self):
        value = self.payload()
        actual = len(canonical_json(value).encode("ascii"))
        self.assertIs(InvestigationBudget(max_result_bytes=actual).result(value), value)
        error = self.failure(InvestigationBudget(max_result_bytes=actual - 1))
        self.assertEqual(str(error), "INVESTIGATION_RESULT_BYTE_BUDGET")
        self.assertEqual(error.actual_result_bytes, actual)
        self.assertEqual(error.result_byte_limit, actual - 1)
        self.assertEqual(set(vars(error)), {"actual_result_bytes", "result_byte_limit"})

    def test_nested_stage_is_restored_without_leaking_into_the_next_call(self):
        budget = InvestigationBudget(max_result_bytes=1024)
        with budget.stage("NORMALIZE_SOURCES"):
            with budget.stage("BUILD_GRAPH"):
                inner = self.failure(budget)
            outer = self.failure(budget)
        unrelated = self.failure(budget)
        self.assertEqual(inner.analysis_stage, "BUILD_GRAPH")
        self.assertEqual(outer.analysis_stage, "NORMALIZE_SOURCES")
        self.assertFalse(hasattr(unrelated, "analysis_stage"))

    def test_stage_preserves_primary_exception_and_inner_known_stage_even_on_unwind(self):
        budget = InvestigationBudget()
        original = InvestigationError("SOURCE_CHANGED")
        original.analysis_stage = ["untrusted unsupported metadata"]
        with self.assertRaisesRegex(InvestigationError, "SOURCE_CHANGED") as caught:
            with budget.stage("NORMALIZE_SOURCES"):
                raise original
        self.assertIs(caught.exception, original)
        self.assertEqual(original.analysis_stage, "NORMALIZE_SOURCES")
        known = InvestigationError("INVALID_SOURCE_SIZE_MANIFEST")
        known.analysis_stage = "CRASH"
        with self.assertRaisesRegex(InvestigationError, "INVALID_SOURCE_SIZE_MANIFEST") as caught:
            with budget.stage("FINAL_CASE"):
                raise known
        self.assertIs(caught.exception, known)
        self.assertEqual(known.analysis_stage, "CRASH")
        self.assertFalse(hasattr(known, "actual_result_bytes"))
        for invalid in ([], False, "SOURCE_PRIVATE_PATH"):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                    InvestigationError, "INVALID_INVESTIGATION_ANALYSIS_STAGE"):
                with budget.stage(invalid):
                    self.fail("an unsupported stage must never run")

    def test_real_file_normalization_failure_reports_stage_and_bytes_without_changing_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "format-fixture.jsonl"
            rows = [{"schema_version": 1, "token": "SOURCE_FORMAT_FIXTURE_NOT_AUTHENTICATED",
                     "pid": 42, "tid": 43, "seq": number, "source_ns": number * 1000,
                     "source_clock": "FORMAT_CLOCK_NOT_ALIGNED", "kind": "user.marker", "client_dropped": 0,
                     "attributes": {"name": "fixture-" + str(number)}} for number in range(1, 4)]
            source.write_text("".join(canonical_json(row) + "\n" for row in rows), encoding="utf-8")
            before = hashlib.sha256(source.read_bytes()).hexdigest()
            sources = [{"source_type": "EVENTS_JSONL", "path": str(source)}]
            normalized = normalize_sources(sources)
            public = {key: value for key, value in normalized.items() if not key.startswith("_")}
            actual = len(canonical_json(public).encode("ascii"))
            self.assertGreater(actual, 1024)
            with self.assertRaisesRegex(InvestigationError, "INVESTIGATION_RESULT_BYTE_BUDGET") as caught:
                create_investigation(sources, budget=InvestigationBudget(max_result_bytes=1024))
            error = caught.exception
            self.assertEqual(error.analysis_stage, "NORMALIZE_SOURCES")
            self.assertEqual(error.actual_result_bytes, actual)
            self.assertEqual(error.result_byte_limit, 1024)
            self.assertEqual(error.run_receipt["status"], "OPERATION_FAILED")
            self.assertFalse(error.run_receipt["cleanup"]["confirmed"])
            self.assertEqual(error.run_receipt["coverage"]["completeness"], "UNKNOWN")
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)
