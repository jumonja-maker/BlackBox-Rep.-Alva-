"""Deterministic synthetic source/link semantics, not Windows native evidence."""
from copy import deepcopy
import unittest

from blackbox_core.decoder_alignment import ALIGNED, QPC_MODEL
from blackbox_core.evidence_correlation import computed_clock_relation
from blackbox_core.evidence_graph import build_graph, validate_case
from blackbox_core.investigation_graph_contracts import (InvestigationBudget, InvestigationError,
    evidence_node, stable_id)


def source(label="one", kind="TRACE_INDEX"):
    digest = stable_id("synthetic-source", label)
    result = {"source_id": stable_id("source", kind, digest), "source_type": kind,
              "source_sha256": digest}
    if kind == "TRACE_INDEX":
        result["trace_input_sha256"] = digest
    return result


def trace_process(src, instance=1):
    return {"kind": "TRACE_PROCESS", "trace_sha256": src["trace_input_sha256"],
            "process_instance": instance, "pid": 123}


def make(src, record, kind="MEASUREMENT", *, metadata=None, identity=None,
         thread=None, domain=None, start=1, end=None, unit="ms"):
    return evidence_node(src, record, kind, process_identity=identity or trace_process(src),
        thread_identity=thread, metadata=metadata or {}, time_domain=domain or "TRACE_RELATIVE:" + src["source_sha256"],
        time_bounds={"start": start, "end": start if end is None else end, "unit": unit, "uncertainty": None})


class EvidenceCorrelationContracts(unittest.TestCase):
    def test_exact_trace_lifetimes_reject_contradictory_pid_and_tid_labels(self):
        src = source()
        first = make(src, "first")
        second = make(src, "second", identity={**trace_process(src), "pid": 456})
        with self.assertRaisesRegex(InvestigationError, "CONTRADICTORY_TRACE_PROCESS_PID"):
            build_graph({"sources": [src], "nodes": [first, second]})
        thread = {**trace_process(src), "kind": "TRACE_THREAD", "thread_instance": 7, "tid": 77}
        first = make(src, "first", thread=thread)
        second = make(src, "second", thread={**thread, "tid": 88})
        with self.assertRaisesRegex(InvestigationError, "CONTRADICTORY_TRACE_THREAD_TID"):
            build_graph({"sources": [src], "nodes": [first, second]})

    def test_trace_label_types_and_parent_pid_are_checked_without_guessing_unknowns(self):
        src = source()
        for label in (True, "123", 1.5, 2**32):
            with self.subTest(label=label), self.assertRaisesRegex(InvestigationError, "TRACE_PROCESS_PID"):
                build_graph({"sources": [src], "nodes": [make(src, "one", identity={**trace_process(src), "pid": label})]})
        thread = {**trace_process(src), "kind": "TRACE_THREAD", "thread_instance": 7, "tid": 0}
        for label in (True, "7", 1.5, 2**32):
            with self.subTest(label=label), self.assertRaisesRegex(InvestigationError, "TRACE_THREAD_PID_OR_TID"):
                build_graph({"sources": [src], "nodes": [make(src, "one", thread={**thread, "tid": label})]})
        with self.assertRaisesRegex(InvestigationError, "CONFLICTING_THREAD_PROCESS_PID"):
            build_graph({"sources": [src], "nodes": [make(src, "one", thread={**thread, "pid": 456})]})
        # -1 denotes an unknown label; zero is retained as an actual Idle label.
        unknown = make(src, "unknown", identity={**trace_process(src), "pid": -1})
        idle = make(src, "idle", identity={**trace_process(src), "pid": 0},
                    thread={**thread, "pid": 0, "tid": 0})
        build_graph({"sources": [src], "nodes": [unknown, idle]})
        with self.assertRaisesRegex(InvestigationError, "CONTRADICTORY_TRACE_PROCESS_PID"):
            build_graph({"sources": [src], "nodes": [idle, make(src, "positive")]})

    def test_scheduler_participants_are_independent_but_keep_consistent_lifetime_labels(self):
        src = source()
        participant = {"pid": 456, "tid": 88, "process_instance": 2, "thread_instance": 8,
                       "attribution": "TRACELOG_THREAD_LIFETIME"}
        event = make(src, "ready", "SCHEDULER_EVENT", metadata={"thread_schedule": {"kind": "ready", "ready_thread": participant}})
        build_graph({"sources": [src], "nodes": [event]})
        contrary = make(src, "contrary", identity={**trace_process(src, 2), "pid": 789})
        with self.assertRaisesRegex(InvestigationError, "CONTRADICTORY_TRACE_PROCESS_PID"):
            build_graph({"sources": [src], "nodes": [event, contrary]})

    def test_same_pid_and_trace_index_from_other_trace_never_join(self):
        a, b = source(), source("other")
        case = build_graph({"sources": [a, b], "nodes": [make(a, "a", "PROCESS"), make(b, "b", "PROCESS")]})
        self.assertEqual(case["edges"], [])

    def test_raw_tid_and_float_creation_time_stay_unestablished(self):
        src = source("session", "SESSION")
        identity = {"kind": "SESSION_PROCESS", "instance_id": 1, "pid": 123, "creation_time": 1790000000.1}
        thread = {"kind": "SESSION_THREAD", "tid": 77, "exact": False}
        values = [make(src, str(i), identity=identity, thread=thread, domain="session", unit="ns") for i in range(2)]
        case = build_graph({"sources": [src], "nodes": values})
        self.assertFalse(any(edge["relation_type"] == "EXACT_IDENTITY" for edge in case["edges"]))
        self.assertGreater(case["coverage"]["identity_gaps"], 0)

    def test_temporal_overlap_is_never_dependency_or_causality(self):
        src = source()
        incident = make(src, "incident", "INCIDENT", start=2, end=5)
        event = make(src, "event", "CPU_SAMPLE", start=3)
        case = build_graph({"sources": [src], "nodes": [incident, event]})
        coincident = [edge for edge in case["edges"] if edge["relation_type"] == "TEMPORAL_COINCIDENCE"]
        self.assertEqual(len(coincident), 1)
        self.assertFalse(any(edge["relation_type"] == "OBSERVED_DEPENDENCY" for edge in case["edges"]))
        self.assertFalse(case["root_cause_proven"])

    def test_distinct_clock_domains_are_not_temporal_neighbors(self):
        src = source()
        case = build_graph({"sources": [src], "nodes": [make(src, "a", "INCIDENT", domain="a"),
                                                                  make(src, "b", domain="b")]})
        self.assertFalse(any(edge["relation_type"] == "TEMPORAL_COINCIDENCE" for edge in case["edges"]))

    def test_process_filetime_cannot_substitute_missing_thread_filetime(self):
        src = source("native", "DEEP_JOURNAL")
        identity = {"kind": "LIVE_PROCESS", "pid": 123, "created_100ns": 133000000000000000}
        thread = {"kind": "LIVE_THREAD", "pid": 123, "tid": 7, "created_100ns": identity["created_100ns"]}
        raw = {"sources": [src], "nodes": [make(src, "a", identity=identity, thread=thread)]}
        with self.assertRaisesRegex(InvestigationError, "INVALID_LIVE_THREAD_IDENTITY"):
            build_graph(raw)
        thread["thread_created_100ns"] = 133000000000000100
        case = build_graph(raw)
        self.assertEqual(case["coverage"]["exact_thread_groups"], 1)

    def test_operation_pair_requires_one_source_and_one_producer_scope(self):
        src = source("sdk", "EVENTS_JSONL")
        identity = {"kind": "APP_PROCESS", "pid": 123, "exact": False}
        begin = make(src, "1", "USER_ACTION", metadata={"operation_id": "same", "operation_scope": "writer-a", "phase": "BEGIN"},
                     identity=identity, domain="sdk-a")
        end = make(src, "2", "FILE_OPERATION", metadata={"operation_id": "same", "operation_scope": "writer-b", "phase": "END"},
                   identity=identity, domain="sdk-b", start=2)
        raw = {"sources": [src], "nodes": [begin, end]}
        self.assertFalse(any(edge["relation"] == "OPERATION_PAIR" for edge in build_graph(raw)["edges"]))
        end["metadata"]["operation_scope"] = "writer-a"
        end["time_domain"] = begin["time_domain"]
        self.assertTrue(any(edge["relation"] == "OPERATION_PAIR" for edge in build_graph(raw)["edges"]))

    def test_reversed_operation_boundary_is_contradicted_not_repaired(self):
        src = source("sdk", "EVENTS_JSONL")
        identity = {"kind": "APP_PROCESS", "pid": 123}
        values = [make(src, "1", metadata={"operation_id": "a", "operation_scope": "writer", "phase": "BEGIN"},
                       identity=identity, start=10),
                  make(src, "2", metadata={"operation_id": "a", "operation_scope": "writer", "phase": "END"},
                       identity=identity, start=2)]
        case = build_graph({"sources": [src], "nodes": values})
        self.assertEqual(case["edges"][0]["relation_type"], "CONTRADICTED")

    def test_ambiguous_record_reference_does_not_form_quadratic_proof_edges(self):
        src = source()
        values = [evidence_node(src, "same", "MODULE", metadata={"n": i}, subtype=str(i)) for i in range(20)]
        values.append(make(src, "ref", metadata={"record_refs": ["same"]}))
        case = build_graph({"sources": [src], "nodes": values})
        self.assertFalse(any(edge["relation_type"] == "DIRECT_REFERENCE" for edge in case["edges"]))
        self.assertEqual(case["coverage"]["ambiguous_record_references"], 1)

    def test_wct_chain_is_supported_only_inside_one_ordered_point_snapshot(self):
        src = source("journal", "DEEP_JOURNAL")
        identity = {"kind": "LIVE_PROCESS", "pid": 123, "created_100ns": 133000000000000000}
        first = make(src, "chain:0", "THREAD", identity=identity, unit="ns", domain="wct",
            metadata={"wct_snapshot_id": "snapshot", "wct_position": 0, "recorded_source": "WIN32_WCT", "record_refs": ["wait"]})
        second = make(src, "chain:1", "THREAD", identity=identity, unit="ns", domain="wct",
            metadata={"wct_snapshot_id": "snapshot", "wct_position": 1, "recorded_source": "WIN32_WCT", "record_refs": ["wait"],
                      "observed_dependencies": [{"record_ref": "chain:0", "snapshot_id": "snapshot", "source": "WIN32_WCT", "relation": "WCT_CHAIN"}]})
        raw = {"sources": [src], "nodes": [first, second]}
        case = build_graph(raw)
        self.assertEqual(len([edge for edge in case["edges"] if edge["relation_type"] == "OBSERVED_DEPENDENCY"]), 1)
        second["metadata"]["wct_snapshot_id"] = "other-snapshot"
        case = build_graph(raw)
        self.assertFalse(any(edge["relation_type"] == "OBSERVED_DEPENDENCY" for edge in case["edges"]))

    def clock_evidence(self):
        trace, session = source(), source("session", "SESSION")
        session["session_uuid"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        event = make(trace, "event", "CPU_SAMPLE")
        measured = make(session, "sample", identity={"kind": "SESSION_PROCESS", "instance_id": 1, "pid": 123},
                        domain="SESSION_MONOTONIC:" + session["source_id"], start=1000000, end=1002000, unit="ns")
        alignment = {"status": ALIGNED, "clock_model": QPC_MODEL, "frequency_hz": 1000000000,
            "session_origin_ns": 1000000, "valid_qpc_min_ticks": 1000000, "valid_qpc_max_ticks": 2000000,
            "offset_lower_ns": 0, "offset_upper_ns": 10, "session_uuid": session["session_uuid"],
            "source_trace_sha256": trace["trace_input_sha256"]}
        relation = computed_clock_relation(event["node_id"], measured["node_id"], alignment,
            {"source_ticks": "1001000"}, target_domain=measured["time_domain"])
        return {"sources": [trace, session], "nodes": [event, measured], "clock_relations": [relation]}

    def test_ready_boundary_is_scheduler_dependency_only_for_valid_wait_pair(self):
        src = source()
        identity = trace_process(src)
        thread = {"kind": "TRACE_THREAD", "trace_sha256": src["trace_input_sha256"],
                  "process_instance": 1, "thread_instance": 7, "tid": 77}
        event = make(src, "events:2", "SCHEDULER_EVENT", start=2, metadata={"thread_schedule": {
            "kind": "ready", "ready_thread": {"pid": 123, "tid": 77, "process_instance": 1,
            "thread_instance": 7, "attribution": "TRACELOG_THREAD_LIFETIME"}}})
        wait = make(src, "waits:1:2:3", "WAIT_INTERVAL", identity=identity, thread=thread, start=1, end=3,
            metadata={"ready_time_ms": 2, "off_cpu_ms": 2, "quality": "OBSERVED_SWITCH_PAIR",
                      "record_refs": ["events:2"]})
        raw = {"sources": [src], "nodes": [event, wait]}
        case = build_graph(raw)
        dependencies = [edge for edge in case["edges"] if edge["relation_type"] == "OBSERVED_DEPENDENCY"]
        self.assertEqual(len(dependencies), 1)
        self.assertIn("WAKER_THREAD_IS_NOT_ESTABLISHED_LOCK_OWNER", dependencies[0]["limitations"])
        wait["metadata"].update(quality="LOSS_OR_TRUNCATION_BOUNDARIES_ONLY", off_cpu_ms=None)
        case = build_graph(raw)
        self.assertFalse(any(edge["relation_type"] == "OBSERVED_DEPENDENCY" for edge in case["edges"]))

    def test_clock_projection_is_recomputed_and_bounds_source_and_window_are_retained(self):
        raw = self.clock_evidence()
        case = build_graph(raw)
        edge = next(edge for edge in case["edges"] if edge["relation_type"] == "BOUNDED_TIME_CORRELATION")
        self.assertEqual(edge["time_uncertainty"]["lower_ns"], 1001000)
        self.assertEqual(edge["time_uncertainty"]["width_ns"], 10)
        self.assertFalse(case["root_cause_proven"])
        changed = deepcopy(case)
        changed["edges"][0]["time_uncertainty"]["source_trace_sha256"] = "f" * 64
        with self.assertRaisesRegex(InvestigationError, "SOURCE_OR_WINDOW_MISMATCH"):
            validate_case(changed)

    def test_plain_json_clock_assertion_never_creates_a_bounded_edge(self):
        raw = self.clock_evidence()
        raw["clock_relations"] = [{"status": ALIGNED, "valid": True, "uncertainty": 0}]
        with self.assertRaisesRegex(InvestigationError, "RECOMPUTED_BY_SOURCE_ADAPTER"):
            build_graph(raw)

    def test_edge_limit_reports_omission_instead_of_unbounded_pairing(self):
        src = source()
        values = [make(src, str(i)) for i in range(100)]
        case = build_graph({"sources": [src], "nodes": values}, budget=InvestigationBudget(max_edges=2))
        self.assertEqual(len(case["edges"]), 2)
        self.assertGreater(case["coverage"]["edges_omitted"], 0)
        self.assertFalse(case["coverage"]["display_graph_complete"])


if __name__ == "__main__":
    unittest.main()
