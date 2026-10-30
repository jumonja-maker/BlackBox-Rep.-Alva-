"""Deterministic interpretation contracts, distinct from native source tests."""
import unittest

from blackbox_core.hypothesis_engine import generate_hypotheses, record_hypothesis_verdict
from blackbox_core.investigation_graph_contracts import SCHEMA, evidence_edge


def node(identifier, kind, **metadata):
    return {"node_id": identifier, "observation_type": kind, "metadata": metadata,
            "source_identity": "source", "process_identity": {"kind": "SESSION_PROCESS", "instance_id": 1},
            "time_domain": "SESSION_MONOTONIC:source", "time_bounds": {"start": 1, "end": 1, "unit": "ns"}}


def case(*nodes, edges=()):
    return {"schema": SCHEMA, "case_id": "case", "nodes": list(nodes), "edges": list(edges)}


class HypothesisContracts(unittest.TestCase):
    def test_empty_case_has_no_invented_problem(self):
        self.assertEqual(generate_hypotheses(case()), [])

    def test_samples_are_candidates_not_cpu_percent_or_function_duration(self):
        result = generate_hypotheses(case(node("sample", "CPU_SAMPLE", frames=[{"name": "work"}])))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["category"], "HIGH_CPU")
        self.assertEqual(result[0]["status"], "CANDIDATE")
        self.assertFalse(result[0]["root_cause_proven"])
        self.assertNotIn("confidence", result[0])
        self.assertTrue(result[0]["description_ru"])

    def test_observed_cpu_incident_is_still_not_internal_cause(self):
        result = generate_hypotheses(case(node("high", "INCIDENT", code="INCIDENT_CPU_SUSTAINED")))
        self.assertEqual(result[0]["status"], "SUPPORTED_BY_OBSERVATION")
        self.assertFalse(result[0]["root_cause_proven"])
        self.assertEqual(result[0]["supporting_nodes"], ["high"])

    def test_application_error_not_transferred_to_temporally_near_etw_metadata(self):
        source = node("app", "FILE_OPERATION", event_kind="io.operation.end", status="ERROR", error_code=5)
        etw = node("etw", "FILE_OPERATION", event_name="FileIO/Write", size=4096)
        hypotheses = generate_hypotheses(case(source, etw, edges=[evidence_edge("app", "etw", "TEMPORAL_COINCIDENCE")]))
        file_error = next(row for row in hypotheses if row["category"] == "FILE_OPERATION_ERROR")
        self.assertEqual(file_error["supporting_nodes"], ["app"])
        self.assertFalse(file_error["root_cause_proven"])
        self.assertNotIn("status", etw["metadata"])

    def test_rss_growth_needs_comparable_adjacent_scoped_samples(self):
        first = node("a", "MEASUREMENT", metrics={"rss_bytes": 100}, series="STANDARD", series_seq=1)
        second = node("b", "MEASUREMENT", metrics={"rss_bytes": 200}, series="STANDARD", series_seq=2)
        second["time_bounds"] = {"start": 2, "end": 2, "unit": "ns"}
        observed = generate_hypotheses(case(first, second))
        self.assertEqual(observed[0]["category"], "MEMORY_GROWTH")
        self.assertFalse(observed[0]["root_cause_proven"])
        second["process_identity"] = {"kind": "SESSION_PROCESS", "instance_id": 2}
        self.assertEqual(generate_hypotheses(case(first, second)), [])
        second["process_identity"] = first["process_identity"]
        second["metadata"]["series_seq"] = 10
        self.assertEqual(generate_hypotheses(case(first, second)), [])

    def test_network_metadata_does_not_prove_network_failure(self):
        result = generate_hypotheses(case(node("packet", "NETWORK_OPERATION", transferred_bytes=100)))
        self.assertEqual(result[0]["status"], "CANDIDATE")
        self.assertIn("PROTOCOL_RESULT_OR_ERROR", result[0]["missing_data"])
        self.assertFalse(result[0]["root_cause_proven"])

    def test_cpu_or_wait_alone_does_not_prove_ui_unresponsiveness_or_deadlock(self):
        result = generate_hypotheses(case(node("wait", "WAIT_INTERVAL", quality="OBSERVED_SWITCH_PAIR", off_cpu_ms=40)))
        self.assertNotIn("UI_UNRESPONSIVE", {row["category"] for row in result})
        wait = next(row for row in result if row["category"] == "WAIT_OR_DEADLOCK")
        self.assertIn("COMPLETE_WAIT_DEPENDENCY_CYCLE", wait["missing_data"])

    def test_supported_categories_have_provenance_and_no_automatic_user_verdict(self):
        first = node("m1", "MEASUREMENT", metrics={"rss_bytes": 10}, series_seq=1)
        second = node("m2", "MEASUREMENT", metrics={"rss_bytes": 20}, series_seq=2)
        second["time_bounds"]["start"] = 2
        second["time_bounds"]["end"] = 2
        results = generate_hypotheses(case(first, second,
            node("cpu", "INCIDENT", code="CPU_SUSTAINED"),
            node("wait", "WAIT_INTERVAL", quality="OBSERVED_SWITCH_PAIR", off_cpu_ms=4),
            node("file", "FILE_OPERATION", status="ERROR", error_code=5),
            node("net", "NETWORK_OPERATION"), node("exit", "INCIDENT", code="PROCESS_EXIT_OBSERVED"),
            node("ui", "INCIDENT", code="UI_TIMEOUT"),
            node("action", "DIAGNOSTIC_ACTION", phase="RESULT", status="RECOVERY_UNCONFIRMED")))
        self.assertEqual(len(results), 9)
        for row in results:
            self.assertTrue(row["supporting_nodes"])
            self.assertTrue(row["alternatives"])
            self.assertTrue(row["missing_data"])
            self.assertFalse(row["root_cause_proven"])
            self.assertNotIn(row["status"], ("USER_CONFIRMED", "SUPPORTED_BY_CONTROLLED_EXPERIMENT"))

    def test_identity_contradiction_is_not_an_observation_contradiction(self):
        cpu = node("cpu", "INCIDENT", code="CPU_SUSTAINED")
        other = node("other", "PROCESS")
        result = generate_hypotheses(case(cpu, other, edges=[
            evidence_edge("cpu", "other", "CONTRADICTED", relation="PROCESS_LIFETIME_MISMATCH")]))
        self.assertEqual(result[0]["contradicting_nodes"], [])
        self.assertEqual(result[0]["status"], "SUPPORTED_BY_OBSERVATION")

    def test_user_confirmation_is_an_attributed_statement_and_preserves_original(self):
        original = generate_hypotheses(case(node("cpu", "CPU_SAMPLE")))[0]
        changed = record_hypothesis_verdict(original, "USER_CONFIRMED", user_note="Confirmed by user review.")
        self.assertEqual(original["status"], "CANDIDATE")
        self.assertEqual(changed["user_verdict"]["verification_class"], "USER_REPORTED")
        self.assertFalse(changed["root_cause_proven"])
