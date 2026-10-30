"""Partial scheduling paths over existing typed observations, never gap interpolation.

Wait durations are the output of ``decoder_waits``. A sample is a running
point, not running time. Only coherent CSwitch dispatch/switch-out pairs can
add RUNNING spans, and only for an explicitly complete scheduler source.
"""
from __future__ import annotations

from collections import defaultdict
import heapq

from .investigation_graph_contracts import (
    SCHEMA, InvestigationError, canonical_json, finite_number, stable_id, use_budget,
)

STATES = ("RUNNING", "BLOCKED", "READY", "UNKNOWN", "INCOMPLETE")


def _nodes(case, budget):
    if (type(case) is not dict or case.get("schema") != SCHEMA or
            type(case.get("nodes")) is not list or type(case.get("edges", [])) is not list or
            len(case["nodes"]) > budget.max_nodes or len(case.get("edges", [])) > budget.max_edges):
        raise InvestigationError("INVALID_CRITICAL_PATH_CASE")
    nodes = {}
    for node in case["nodes"]:
        budget.check()
        if (type(node) is not dict or type(node.get("node_id")) is not str or
                node["node_id"] in nodes or type(node.get("metadata", {})) is not dict):
            raise InvestigationError("INVALID_CRITICAL_PATH_NODE")
        nodes[node["node_id"]] = node
    return nodes


def _thread_key(identity):
    if type(identity) is not dict:
        return None
    if identity.get("kind") == "TRACE_THREAD":
        required = ("trace_sha256", "process_instance", "thread_instance")
        if (type(identity.get("trace_sha256")) is str and len(identity["trace_sha256"]) == 64 and
                all(type(identity.get(key)) is int and identity[key] >= 0 for key in required[1:])):
            return canonical_json(["TRACE_THREAD", *[identity[key] for key in required]])
    if identity.get("kind") in ("LIVE_THREAD", "WINDOWS_THREAD"):
        required = ("pid", "created_100ns", "tid", "thread_created_100ns")
        if all(type(identity.get(key)) is int and identity[key] > 0 for key in required):
            return canonical_json(["LIVE_THREAD", *[identity[key] for key in required]])
    return None


def _bounds(node):
    bounds = node.get("time_bounds")
    if (type(bounds) is not dict or bounds.get("unit") != "ms" or
            not finite_number(bounds.get("start")) or not finite_number(bounds.get("end")) or
            bounds["end"] < bounds["start"] or
            type(node.get("time_domain")) is not str or node["time_domain"] == "UNKNOWN"):
        return None
    return float(bounds["start"]), float(bounds["end"])


def _segment(node, start, end, state, *, source_events=(), duration=True, limitations=()):
    return {"segment_id": stable_id("critical-segment", node["node_id"], start, end, state),
        "node_id": node["node_id"], "source_identity": node.get("source_identity"),
        "thread_identity": node.get("thread_identity"), "time_domain": node.get("time_domain"),
        "start": start, "end": end, "unit": "ms", "state": state,
        "duration_ms": end - start if duration else None,
        "source_event_ids": list(source_events), "verification_class": "DERIVED",
        "source_authenticity": "UNVERIFIED_IMPORT", "limitations": list(limitations)}


def _wait_segments(node):
    row, bounds = node["metadata"], _bounds(node)
    if bounds is None:
        return [], {"node_id": node["node_id"], "reason": "MISSING_OR_INCOMPATIBLE_TIME_BOUNDS"}
    a, b = bounds
    refs = row.get("source_event_ids", [])
    if type(refs) is not list or len(refs) > 4 or any(type(x) not in (int, str) for x in refs):
        refs = []
    valid = (row.get("quality") == "OBSERVED_SWITCH_PAIR" and _thread_key(node.get("thread_identity")) and
             finite_number(row.get("off_cpu_ms")) and
             abs(row["off_cpu_ms"] - (b-a)) <= max(1e-6, (b-a)*1e-10))
    if not valid:
        return [_segment(node, a, b, "INCOMPLETE", source_events=refs, duration=False,
                         limitations=["LOSS_ORDER_IDENTITY_OR_BOUNDARY_EVIDENCE_INCOMPLETE"])], None
    blocked, ready = row.get("blocked_ms"), row.get("ready_delay_ms")
    if (finite_number(blocked) and finite_number(ready) and blocked >= 0 and ready >= 0 and
            abs(blocked + ready - (b-a)) <= max(1e-6, (b-a)*1e-10)):
        cut = min(b, max(a, a + blocked))
        segments = []
        if cut > a:
            segments.append(_segment(node, a, cut, "BLOCKED", source_events=refs,
                            limitations=["WAIT_REASON_IS_NOT_A_LOCK_IDENTITY_OR_ROOT_CAUSE"]))
        if b > cut:
            segments.append(_segment(node, cut, b, "READY", source_events=refs,
                            limitations=["READY_THREAD_IS_NOT_PROOF_OF_LOCK_OWNERSHIP"]))
        return segments, None
    return [_segment(node, a, b, "UNKNOWN", source_events=refs, limitations=[
        "OFF_CPU_SWITCH_PAIR_OBSERVED_BUT_BLOCKED_READY_SPLIT_NOT_ESTABLISHED"])], None


def _raw_identity(raw, node):
    if (type(raw) is not dict or raw.get("attribution") != "TRACELOG_THREAD_LIFETIME" or
            any(type(raw.get(k)) is not int or raw[k] < 0 for k in ("process_instance", "thread_instance")) or
            any(type(raw.get(k)) is not int or raw[k] <= 0 for k in ("pid", "tid"))):
        return None
    domain = node.get("time_domain", "")
    if not domain.startswith("TRACE_RELATIVE:") or len(domain.split(":", 1)[1]) != 64:
        return None
    return {"kind": "TRACE_THREAD", "trace_sha256": domain.split(":", 1)[1],
            "process_instance": raw["process_instance"], "thread_instance": raw["thread_instance"],
            "pid": raw["pid"], "tid": raw["tid"]}


def _selected_thread(identity, selection):
    if identity is None:
        return None
    if (selection.get("pid") and identity["pid"] != selection["pid"] or
            selection.get("tid") and identity["tid"] != selection["tid"] or
            selection.get("process_instance") is not None and identity["process_instance"] != selection["process_instance"]):
        return None
    return identity


def _running_segments(case, nodes, budget):
    sources = {source.get("source_id"): source for source in case.get("sources", []) if type(source) is dict}
    coverage = case.get("coverage", {})
    if type(coverage) is not dict:
        return []
    # A graph display budget may omit an intermediate switch. Never bridge it.
    if any(coverage.get(key) for key in ("nodes_omitted", "events_omitted", "truncated", "has_more")):
        return []
    per_source = defaultdict(list)
    for node in nodes.values():
        if node.get("observation_type") == "SCHEDULER_EVENT":
            per_source[node.get("source_identity")].append(node)
    result = []
    for source_id, events in sorted(per_source.items(), key=lambda item: str(item[0])):
        source = sources.get(source_id, {})
        if source.get("scheduler_complete") is not True:
            continue
        selection = source.get("selection", {})
        if type(selection) is not dict:
            continue
        # Preserve original source order: sorting by time would hide reordering.
        ordinals = [node["metadata"].get("source_event_id") for node in events]
        if (any(type(value) is not int or value < 0 for value in ordinals) or
                len(set(ordinals)) != len(ordinals)):
            continue
        events.sort(key=lambda node: node["metadata"]["source_event_id"])
        active, previous_time = {}, None
        candidate, invalid = [], False
        for node in events:
            budget.check()
            row, bounds = node["metadata"].get("thread_schedule"), _bounds(node)
            if bounds is None or type(row) is not dict:
                invalid = True
                break
            now = bounds[0]
            if previous_time is not None and now < previous_time:
                invalid = True
                break
            previous_time = now
            if row.get("kind") != "switch":
                continue
            # Selected scheduler rows can also name another process. Its
            # intermediate switches may have been filtered out by the adapter;
            # never calculate that unselected thread's running interval.
            old = _selected_thread(_raw_identity(row.get("old_thread"), node), selection)
            new = _selected_thread(_raw_identity(row.get("new_thread"), node), selection)
            if old is None:
                # Unknown/idle threads cannot close a previously dispatched
                # application thread with a guessed lifetime.
                affected = row.get("old_thread", {})
                tid = affected.get("tid") if type(affected) is dict else None
                for key, state in list(active.items()):
                    if tid is None or state[0]["tid"] == tid:
                        active.pop(key, None)
            event_id = node["metadata"].get("source_event_id", node.get("source_record_id"))
            if old is not None:
                old_key = _thread_key(old)
                dispatch = active.pop(old_key, None)
                if dispatch and now > dispatch[1]:
                    original_identity, start, first_id, first_node = dispatch
                    proxy = {**first_node, "thread_identity": original_identity}
                    candidate.append(_segment(proxy, start, now, "RUNNING", source_events=[first_id, event_id],
                                              limitations=["PAIRED_SWITCH_BOUNDARIES_NOT_FUNCTION_EXECUTION_TIME"]))
            if new is not None:
                new_key = _thread_key(new)
                if old is not None and new_key == _thread_key(old):
                    continue
                # A second dispatch without a switch-out makes that span
                # ambiguous; restart at the newly observed boundary.
                active[new_key] = (new, now, event_id, node)
        if not invalid:
            result.extend(candidate)
    return result


def analyze_critical_path(case, *, budget=None):
    """Return a bounded partial path, timing diagram and explicit unknowns."""
    budget = use_budget(budget)
    nodes = _nodes(case, budget)
    segments, unknowns = [], []
    for node in nodes.values():
        budget.check()
        if node.get("observation_type") == "WAIT_INTERVAL":
            found, unknown = _wait_segments(node)
            segments.extend(found)
            if unknown:
                unknowns.append(unknown)
    segments.extend(_running_segments(case, nodes, budget))
    grouped = defaultdict(list)
    for segment in segments:
        grouped[(segment.get("source_identity"), segment.get("time_domain"),
                 _thread_key(segment.get("thread_identity")))].append(segment)
    links, contradictions = [], []
    for key, thread_segments in grouped.items():
        budget.check()
        thread_segments.sort(key=lambda value: (value["start"], value["end"], value["segment_id"]))
        frontier = None
        for segment in thread_segments:
            if frontier and segment["start"] < frontier["end"]:
                # Exact duplicate copies do not become additional measured time.
                if (segment["start"], segment["end"], segment["state"]) == (frontier["start"], frontier["end"], frontier["state"]):
                    segment["duration_ms"] = None
                    segment["state"] = "INCOMPLETE"
                else:
                    contradictions.append({"nodes": [frontier["node_id"], segment["node_id"]],
                                           "reason": "OVERLAPPING_INCOMPATIBLE_SCHEDULER_INTERVALS"})
                    for value in (frontier, segment):
                        value.update(state="INCOMPLETE", duration_ms=None)
            if frontier and segment["start"] > frontier["end"]:
                unknowns.append({"thread_identity": segment.get("thread_identity"), "time_domain": key[1],
                                 "start": frontier["end"], "end": segment["start"], "unit": "ms",
                                 "state": "UNKNOWN", "reason": "NO_OBSERVED_SCHEDULER_BOUNDARIES_FOR_GAP"})
            if frontier and key[2] is not None and segment["start"] == frontier["end"]:
                shared = set(map(str, frontier["source_event_ids"])) & set(map(str, segment["source_event_ids"]))
                if shared and frontier["state"] != "INCOMPLETE" and segment["state"] != "INCOMPLETE":
                    links.append((frontier["segment_id"], segment["segment_id"], "SHARED_RECORDED_BOUNDARY"))
            # Retain the enclosing interval, rather than just the preceding
            # row: a later short interval may still overlap that enclosing row.
            if frontier is None or segment["end"] >= frontier["end"]:
                frontier = segment
    segments.sort(key=lambda value: (str(value["time_domain"]), value["start"], value["segment_id"]))
    omitted = max(0, len(segments) - budget.max_nodes)
    segments = segments[:budget.max_nodes]
    by_segment = {segment["segment_id"]: segment for segment in segments}
    by_node = defaultdict(list)
    for segment in segments:
        by_node[segment["node_id"]].append(segment)
    for edge in case.get("edges", []):
        budget.check()
        if type(edge) is not dict:
            raise InvestigationError("INVALID_CRITICAL_PATH_EDGE")
        if edge.get("relation_type") != "OBSERVED_DEPENDENCY":
            continue
        before = by_node.get(edge.get("from_node"), [])
        after = by_node.get(edge.get("to_node"), [])
        for first in before[-2:]:
            for second in after[:2]:
                if (first["segment_id"] != second["segment_id"] and
                        first["time_domain"] == second["time_domain"] and
                        first["end"] <= second["start"] and
                        first["state"] != "INCOMPLETE" and second["state"] != "INCOMPLETE"):
                    links.append((first["segment_id"], second["segment_id"], str(edge.get("edge_id", ""))))
                elif first["time_domain"] != second["time_domain"]:
                    unknowns.append({"edge_id": edge.get("edge_id"), "reason": "DEPENDENCY_CLOCK_RELATION_NOT_ESTABLISHED"})
                elif first["end"] > second["start"]:
                    unknowns.append({"edge_id": edge.get("edge_id"),
                                     "reason": "DEPENDENCY_IS_NOT_A_FORWARD_INTERVAL_BOUNDARY"})
    outgoing, indegree = defaultdict(list), dict.fromkeys(by_segment, 0)
    kept_links = []
    for first, second, evidence in sorted(set(links)):
        if (first in by_segment and second in by_segment and len(kept_links) < budget.max_edges and
                by_segment[first]["state"] != "INCOMPLETE" and by_segment[second]["state"] != "INCOMPLETE"):
            outgoing[first].append(second)
            indegree[second] += 1
            kept_links.append({"from_segment": first, "to_segment": second, "evidence_ref": evidence})
    ready = [key for key, count in indegree.items() if count == 0]
    heapq.heapify(ready)
    scores, previous = {}, {}
    visited = 0
    while ready:
        budget.check()
        current = heapq.heappop(ready)
        visited += 1
        segment = by_segment[current]
        own = segment["duration_ms"] if segment["state"] in ("RUNNING", "BLOCKED", "READY") else 0
        scores[current] = scores.get(current, 0) + (own or 0)
        for following in outgoing[current]:
            if scores[current] > scores.get(following, -1):
                scores[following], previous[following] = scores[current], current
            indegree[following] -= 1
            if indegree[following] == 0:
                heapq.heappush(ready, following)
    cyclic = visited != len(by_segment)
    if cyclic:
        contradictions.append({"reason": "DEPENDENCY_CYCLE_CRITICAL_PATH_NOT_ESTABLISHED"})
    path = []
    measured = [key for key, segment in by_segment.items() if
                segment["state"] in ("RUNNING", "BLOCKED", "READY") and segment["duration_ms"] is not None]
    if measured and not cyclic:
        current = max(measured, key=lambda key: (scores[key], key))
        while current is not None:
            path.append(current)
            current = previous.get(current)
        path.reverse()
    totals = {state.lower() + "_ms": sum(value["duration_ms"] for value in segments
                if value["state"] == state and value["duration_ms"] is not None)
              for state in ("RUNNING", "BLOCKED", "READY")}
    return budget.result({"schema": "blackbox.critical-path/1", "status": "CONTRADICTED" if cyclic else
        "PARTIAL" if segments else "NOT_ESTABLISHED", "segments": segments, "dependencies": kept_links,
        "path": path, "longest_observed_component_ms": max(scores[key] for key in measured) if measured and not cyclic else None,
        "totals": totals, "unknowns": unknowns[:budget.max_nodes], "contradictions": contradictions[:200],
        "segments_omitted": omitted, "unknowns_omitted": max(0, len(unknowns)-budget.max_nodes),
        "duration_semantics": "SUM_OF_KNOWN_STATES_NOT_ELAPSED_COMPLETION_TIME",
        "end_to_end_established": False,
        "limitations": ["PARTIAL_OBSERVED_SUBGRAPH_NOT_AN_APPLICATION_END_TO_END_CRITICAL_PATH",
            "UNKNOWN_GAPS_NOT_INTERPOLATED", "CPU_SAMPLES_ARE_NOT_FUNCTION_EXECUTION_TIME",
            "READY_THREAD_IS_NOT_PROOF_OF_LOCK_OWNERSHIP", "IMPORTED_SOURCE_AUTHENTICITY_NOT_ESTABLISHED"]})
