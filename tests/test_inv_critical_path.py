"""Scheduling format fixtures; real native acceptance runs separately in CI."""
import threading
import unittest

from blackbox_core.critical_path import analyze_critical_path
from blackbox_core.investigation_graph_contracts import SCHEMA, InvestigationBudget, evidence_edge


TRACE = "a" * 64
THREAD = {"kind": "TRACE_THREAD", "trace_sha256": TRACE, "process_instance": 1,
          "thread_instance": 2, "pid": 30, "tid": 40}


def wait(identifier="wait", *, start=100, end=200, blocked=40, ready=60, quality="OBSERVED_SWITCH_PAIR", thread=None):
    return {"node_id": identifier, "source_identity": "source", "observation_type": "WAIT_INTERVAL",
            "thread_identity": thread or THREAD, "time_domain": "TRACE_RELATIVE:" + TRACE,
            "time_bounds": {"start": start, "end": end, "unit": "ms"},
            "metadata": {"quality": quality, "off_cpu_ms": end-start if quality == "OBSERVED_SWITCH_PAIR" else None,
                         "blocked_ms": blocked, "ready_delay_ms": ready, "source_event_ids": [10, 11, 12],
                         "waker_thread": {"tid": 999}, "waker_is_lock_owner": "NOT_ESTABLISHED"}}


def case(*nodes, edges=(), scheduler_complete=False, coverage=None):
    return {"schema": SCHEMA, "case_id": "case", "nodes": list(nodes), "edges": list(edges),
            "sources": [{"source_id": "source", "scheduler_complete": scheduler_complete}],
            "coverage": coverage or {}}


def raw_thread(*, idle=False):
    if idle:
        return {"attribution": "UNRESOLVED_THREAD", "pid": 0, "tid": 0}
    return {"attribution": "TRACELOG_THREAD_LIFETIME", "process_instance": 1, "thread_instance": 2,
            "pid": 30, "tid": 40}


def switch(identifier, ordinal, moment, *, entering):
    return {"node_id": identifier, "source_identity": "source", "observation_type": "SCHEDULER_EVENT",
            "thread_identity": THREAD, "time_domain": "TRACE_RELATIVE:" + TRACE,
            "time_bounds": {"start": moment, "end": moment, "unit": "ms"},
            "metadata": {"source_event_id": ordinal, "thread_schedule": {"kind": "switch",
                         "new_thread": raw_thread(idle=not entering), "old_thread": raw_thread(idle=entering)}}}


class CriticalPathContracts(unittest.TestCase):
    def test_wait_splits_reuse_reported_boundaries_and_do_not_identify_lock_owner(self):
        result = analyze_critical_path(case(wait()))
        self.assertEqual([(s["state"], s["duration_ms"]) for s in result["segments"]],
                         [("BLOCKED", 40), ("READY", 60)])
        self.assertEqual(result["totals"], {"running_ms": 0, "blocked_ms": 40, "ready_ms": 60})
        self.assertFalse(result["end_to_end_established"])
        self.assertTrue(any("LOCK_OWNERSHIP" in limit for limit in result["limitations"]))

    def test_loss_withholds_durations_instead_of_inventing_blocked_time(self):
        result = analyze_critical_path(case(wait(quality="LOSS_OR_TRUNCATION_BOUNDARIES_ONLY")))
        self.assertEqual(result["segments"][0]["state"], "INCOMPLETE")
        self.assertIsNone(result["segments"][0]["duration_ms"])
        self.assertEqual(result["totals"]["blocked_ms"], 0)

    def test_missing_ready_boundary_stays_unknown_instead_of_all_blocked(self):
        result = analyze_critical_path(case(wait(blocked=None, ready=None)))
        self.assertEqual(result["segments"][0]["state"], "UNKNOWN")
        self.assertEqual(result["totals"]["blocked_ms"], 0)
        self.assertEqual(result["totals"]["ready_ms"], 0)

    def test_running_requires_actual_pair_and_complete_source(self):
        nodes = (switch("dispatch", 1, 10, entering=True), switch("switchout", 2, 25, entering=False))
        result = analyze_critical_path(case(*nodes, scheduler_complete=True))
        self.assertEqual([(s["state"], s["duration_ms"]) for s in result["segments"]], [("RUNNING", 15)])
        self.assertEqual(analyze_critical_path(case(*nodes))["segments"], [])
        self.assertEqual(analyze_critical_path(case(*nodes, scheduler_complete=True,
                                                   coverage={"nodes_omitted": 1}))["segments"], [])

    def test_reordered_switches_cannot_be_fixed_by_sorting_timestamps(self):
        nodes = (switch("dispatch", 1, 30, entering=True), switch("switchout", 2, 20, entering=False))
        self.assertEqual(analyze_critical_path(case(*nodes, scheduler_complete=True))["segments"], [])

    def test_filtered_rows_do_not_bridge_an_unselected_process_intermediate_switches(self):
        departing = switch("depart", 1, 10, entering=False)
        arriving = switch("arrive", 4, 30, entering=True)
        other = {**raw_thread(), "pid": 90, "tid": 91, "process_instance": 9, "thread_instance": 10}
        departing["metadata"]["thread_schedule"]["new_thread"] = other
        arriving["metadata"]["thread_schedule"]["old_thread"] = other
        selected = case(departing, arriving, scheduler_complete=True)
        selected["sources"][0]["selection"] = {"pid": 30, "process_instance": 1}
        self.assertEqual(analyze_critical_path(selected)["segments"], [])

    def test_sample_is_not_a_running_duration_and_unknown_gap_is_not_interpolated(self):
        sample = {"node_id": "sample", "observation_type": "CPU_SAMPLE", "metadata": {"frames": ["hot"]}}
        self.assertEqual(analyze_critical_path(case(sample))["segments"], [])
        result = analyze_critical_path(case(wait("a"), wait("b", start=250, end=350)))
        self.assertTrue(any(item.get("state") == "UNKNOWN" and item.get("start") == 200 and
                            item.get("end") == 250 for item in result["unknowns"]))
        self.assertEqual(result["totals"]["running_ms"], 0)

    def test_same_raw_tid_different_lifetimes_do_not_form_one_sequence(self):
        other = {**THREAD, "thread_instance": 3}
        result = analyze_critical_path(case(wait("a"), wait("b", start=200, end=300, thread=other)))
        # Each wait may have its own BLOCKED -> READY boundary; no edge joins the lifetimes.
        a = {s["segment_id"] for s in result["segments"] if s["node_id"] == "a"}
        b = {s["segment_id"] for s in result["segments"] if s["node_id"] == "b"}
        self.assertFalse(any(e["from_segment"] in a and e["to_segment"] in b for e in result["dependencies"]))

    def test_incompatible_overlaps_withhold_numeric_state(self):
        result = analyze_critical_path(case(wait("a"), wait("b", start=120, end=220)))
        self.assertTrue(result["contradictions"])
        self.assertTrue(any(s["state"] == "INCOMPLETE" and s["duration_ms"] is None for s in result["segments"]))

    def test_nested_overlap_keeps_enclosing_frontier_and_withholds_all_three_durations(self):
        result = analyze_critical_path(case(
            wait("outer", start=0, end=10, blocked=10, ready=0),
            wait("first-inner", start=2, end=3, blocked=1, ready=0),
            wait("second-inner", start=4, end=5, blocked=1, ready=0)))
        self.assertEqual({s["node_id"] for s in result["segments"]}, {"outer", "first-inner", "second-inner"})
        self.assertTrue(all(s["state"] == "INCOMPLETE" and s["duration_ms"] is None for s in result["segments"]))
        self.assertEqual(result["totals"], {"running_ms": 0, "blocked_ms": 0, "ready_ms": 0})
        self.assertFalse(result["dependencies"])
        self.assertEqual(result["path"], [])
        self.assertIsNone(result["longest_observed_component_ms"])
        self.assertFalse(result["unknowns"], "Nested observations must not invent a gap inside the enclosing interval")

    def test_dependency_cannot_cross_unaligned_clock_domains(self):
        first, second = wait("a"), wait("b", start=300, end=400)
        second["time_domain"] = "TRACE_RELATIVE:" + "b" * 64
        result = analyze_critical_path(case(first, second, edges=[evidence_edge("a", "b", "OBSERVED_DEPENDENCY")]))
        self.assertTrue(any(row.get("reason") == "DEPENDENCY_CLOCK_RELATION_NOT_ESTABLISHED" for row in result["unknowns"]))

    def test_zero_boundary_dependency_cycle_has_no_critical_path(self):
        first = wait("a", start=100, end=100, blocked=None, ready=None)
        second = wait("b", start=100, end=100, blocked=None, ready=None, thread={**THREAD, "thread_instance": 3})
        result = analyze_critical_path(case(first, second, edges=[
            evidence_edge("a", "b", "OBSERVED_DEPENDENCY"), evidence_edge("b", "a", "OBSERVED_DEPENDENCY")]))
        self.assertEqual(result["status"], "CONTRADICTED")
        self.assertEqual(result["path"], [])
        self.assertIsNone(result["longest_observed_component_ms"])

    def test_cancelled_analysis_does_not_publish_a_result(self):
        stop = threading.Event()
        stop.set()
        with self.assertRaises(InterruptedError):
            analyze_critical_path(case(wait()), budget=InvestigationBudget(cancel_event=stop))
