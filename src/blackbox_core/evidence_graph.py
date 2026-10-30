"""Additive bounded Evidence Graph, preserving source identity and uncertainty."""
from __future__ import annotations

import re

from .evidence_correlation import (bounds, correlate_evidence, process_identity_key,
                                   thread_identity_key, validate_trace_identity_consistency)
from .investigation_graph_contracts import (ALGORITHM_VERSION, HYPOTHESIS_STATUSES, OBSERVATION_TYPES, RELATION_TYPES,
    SCHEMA, SOURCE_TYPES, InvestigationError, finite_number, stable_id, use_budget)

_SHA = re.compile(r"[0-9a-f]{64}\Z")


def _identifier(value, label, *, maximum=256):
    if type(value) is not str or not 1 <= len(value) <= maximum or "\0" in value:
        raise InvestigationError("INVALID_" + label)


def _json_shape(value, budget):
    pending, visited = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if visited % 128 == 0:
            budget.check()
        if depth > 32 or visited > 2_000_000:
            raise InvestigationError("INVESTIGATION_JSON_STRUCTURE_BUDGET")
        if type(item) is dict:
            if len(item) > 512 or any(type(key) is not str or len(key) > 512 for key in item):
                raise InvestigationError("INVALID_INVESTIGATION_JSON_KEYS")
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            if len(item) > 250_000:
                raise InvestigationError("INVESTIGATION_JSON_ARRAY_BUDGET")
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            if len(item) > 32768 or "\0" in item:
                raise InvestigationError("INVESTIGATION_JSON_STRING_BUDGET")
        elif item is not None and type(item) not in (bool, int, float):
            raise InvestigationError("UNSUPPORTED_INVESTIGATION_JSON_VALUE")
        elif type(item) is int and not -(2**63) <= item <= 2**64 - 1:
            raise InvestigationError("OUT_OF_RANGE_INVESTIGATION_INTEGER")
        elif type(item) is float and not finite_number(item):
            raise InvestigationError("NONFINITE_OR_OUT_OF_RANGE_INVESTIGATION_VALUE")


def _sources(values, budget):
    if type(values) is not list or len(values) > 64:
        raise InvestigationError("INVALID_INVESTIGATION_SOURCES")
    result = {}
    for source in values:
        budget.check()
        if type(source) is not dict or type(source.get("source_type")) is not str or source.get("source_type") not in SOURCE_TYPES:
            raise InvestigationError("INVALID_INVESTIGATION_SOURCE")
        if source.get("verification_class", "UNVERIFIED_IMPORT") != "UNVERIFIED_IMPORT":
            raise InvestigationError("IMPORTED_SOURCE_CANNOT_DECLARE_VERIFIED_PROVENANCE")
        _identifier(source.get("source_id"), "SOURCE_ID")
        digest = source.get("source_sha256")
        if type(digest) is not str or not _SHA.fullmatch(digest):
            raise InvestigationError("INVALID_SOURCE_SHA256")
        _json_shape(source, budget)
        identifier = source["source_id"]
        if identifier in result and result[identifier] != source:
            raise InvestigationError("CONFLICTING_SOURCE_IDENTITY")
        result[identifier] = dict(source)
    return result


def _node(node, sources, budget):
    if type(node) is not dict or type(node.get("observation_type")) is not str or node.get("observation_type") not in OBSERVATION_TYPES:
        raise InvestigationError("INVALID_EVIDENCE_NODE")
    for key in ("node_id", "source_identity", "time_domain", "verification_class", "completeness_status"):
        _identifier(node.get(key), "NODE_" + key.upper())
    _identifier(node.get("source_record_id"), "SOURCE_RECORD_ID", maximum=512)
    source = sources.get(node["source_identity"])
    if source is None or node.get("source_type") != source["source_type"] or node.get("source_sha256") != source["source_sha256"]:
        raise InvestigationError("NODE_SOURCE_IDENTITY_MISMATCH")
    if type(node.get("metadata")) is not dict:
        raise InvestigationError("INVALID_EVIDENCE_METADATA")
    if node["verification_class"] != "UNVERIFIED_IMPORT":
        raise InvestigationError("IMPORTED_NODE_CANNOT_DECLARE_VERIFIED_PROVENANCE")
    bounds(node)
    process_identity_key(node.get("process_identity"))
    thread_identity_key(node.get("thread_identity"), node.get("process_identity"))
    for identity in (node.get("process_identity"), node.get("thread_identity")):
        if identity is None:
            continue
        if identity.get("kind") in ("TRACE_PROCESS", "TRACE_THREAD") and source.get("trace_input_sha256") is not None:
            if identity.get("trace_sha256") != source["trace_input_sha256"]:
                raise InvestigationError("TRACE_IDENTITY_SOURCE_HASH_MISMATCH")
        if identity.get("kind") in ("SESSION_PROCESS", "SESSION_THREAD") and identity.get("source_id") is not None:
            if identity["source_id"] != node["source_identity"]:
                raise InvestigationError("SESSION_IDENTITY_SOURCE_MISMATCH")
    _json_shape(node, budget)
    return node


def _target(value):
    if value is None:
        return
    if type(value) is not dict or value.get("kind", "LIVE_PROCESS") != "LIVE_PROCESS":
        raise InvestigationError("INVALID_INVESTIGATION_TARGET_IDENTITY")
    if process_identity_key({**value, "kind": "LIVE_PROCESS"}) is None:
        raise InvestigationError("INVALID_INVESTIGATION_TARGET_IDENTITY")


def _models(case, nodes, edge_ids, budget):
    """Imported interpretations are bounded claims, never extra graph authority."""
    from .deep_contracts import DEEP_ACTIONS, STATUSES
    hypotheses = set()
    for row in case.get("hypotheses", []):
        budget.check()
        if type(row) is not dict or type(row.get("status")) is not str or row.get("status") not in HYPOTHESIS_STATUSES:
            raise InvestigationError("INVALID_IMPORTED_HYPOTHESIS_STATUS")
        identifier = row.get("hypothesis_id")
        _identifier(identifier, "HYPOTHESIS_ID")
        if identifier in hypotheses:
            raise InvestigationError("DUPLICATE_HYPOTHESIS_ID")
        hypotheses.add(identifier)
        for name in ("supporting_nodes", "contradicting_nodes"):
            refs = row.get(name, [])
            if type(refs) is not list or len(refs) > 200 or any(type(ref) is not str or ref not in nodes for ref in refs):
                raise InvestigationError("DANGLING_HYPOTHESIS_EVIDENCE_REFERENCE")
        if row.get("root_cause_proven", False) is not False:
            raise InvestigationError("HYPOTHESIS_CANNOT_DECLARE_ROOT_CAUSE_PROOF")
        # This version records controlled experiments as INCONCLUSIVE; no
        # source-imported status can bypass the missing-controls checks.
        if row["status"] == "SUPPORTED_BY_CONTROLLED_EXPERIMENT":
            raise InvestigationError("CONTROLLED_EXPERIMENT_PROOF_NOT_IMPLEMENTED")
        if any(name in row for name in ("confidence", "confidence_percent", "causal_score", "probability")):
            raise InvestigationError("HYPOTHESIS_CAUSAL_SCORE_NOT_SUPPORTED")
        if row["status"] == "USER_CONFIRMED":
            verdict = row.get("user_verdict")
            if (type(verdict) is not dict or verdict.get("actor") != "USER" or
                    verdict.get("verification_class") != "USER_REPORTED" or
                    type(verdict.get("note")) is not str or not verdict["note"].strip()):
                raise InvestigationError("USER_HYPOTHESIS_VERDICT_ATTRIBUTION_REQUIRED")
        actions = row.get("next_actions", [])
        if type(actions) is not list or len(actions) > len(DEEP_ACTIONS) or any(type(name) is not str or name not in DEEP_ACTIONS for name in actions):
            raise InvestigationError("INVALID_HYPOTHESIS_ACTION_REFERENCE")
    for row in case.get("actions", []):
        budget.check()
        if (type(row) is not dict or type(row.get("operation")) is not str or row.get("operation") not in DEEP_ACTIONS or
                type(row.get("status")) is not str or row.get("status") not in STATUSES | {"NOT_ESTABLISHED"} or
                type(row.get("availability", row.get("status"))) is not str or
                row.get("availability", row.get("status")) not in STATUSES | {"NOT_ESTABLISHED"} or
                row.get("automatic_execution") is not False):
            raise InvestigationError("INVALID_IMPORTED_DIAGNOSTIC_ADVICE")
        if row.get("root_cause_proven", False) is not False:
            raise InvestigationError("ADVICE_CANNOT_DECLARE_ROOT_CAUSE_PROOF")
    for name in ("issues", "guided_experiments", "user_annotations"):
        for row in case.get(name, []):
            budget.check()
            if type(row) is not dict:
                raise InvestigationError("INVALID_IMPORTED_" + name.upper())
            if row.get("root_cause_proven", False) is not False or row.get("root_cause_established", False) is not False:
                raise InvestigationError("IMPORTED_INTERPRETATION_CANNOT_DECLARE_ROOT_CAUSE_PROOF")
    path = case.get("critical_path")
    if path is None:
        return
    if (type(path) is not dict or path.get("schema") != "blackbox.critical-path/1" or
            path.get("status") not in ("PARTIAL", "NOT_ESTABLISHED", "CONTRADICTED") or
            path.get("end_to_end_established") is not False or path.get("root_cause_proven", False) is not False):
        raise InvestigationError("INVALID_IMPORTED_CRITICAL_PATH")
    segments, dependencies = path.get("segments"), path.get("dependencies")
    if (type(segments) is not list or len(segments) > budget.max_nodes or
            type(dependencies) is not list or len(dependencies) > budget.max_edges):
        raise InvestigationError("CRITICAL_PATH_ELEMENT_BUDGET")
    indexed = {}
    for segment in segments:
        budget.check()
        if type(segment) is not dict or type(segment.get("node_id")) is not str or segment.get("node_id") not in nodes:
            raise InvestigationError("DANGLING_CRITICAL_PATH_NODE")
        node = nodes[segment["node_id"]]
        identifier = segment.get("segment_id")
        _identifier(identifier, "CRITICAL_SEGMENT_ID")
        if identifier in indexed:
            raise InvestigationError("DUPLICATE_CRITICAL_SEGMENT_ID")
        indexed[identifier] = segment
        a, b, duration = segment.get("start"), segment.get("end"), segment.get("duration_ms")
        if (segment.get("state") not in ("RUNNING", "BLOCKED", "READY", "UNKNOWN", "INCOMPLETE") or
                segment.get("unit") != "ms" or not finite_number(a) or not finite_number(b) or b < a or
                segment.get("source_identity") != node["source_identity"] or segment.get("time_domain") != node["time_domain"] or
                node["observation_type"] not in ("WAIT_INTERVAL", "SCHEDULER_EVENT") or
                duration is not None and (not finite_number(duration) or duration < 0 or abs(duration-(b-a)) > max(1e-6, (b-a)*1e-10)) or
                segment.get("state") == "INCOMPLETE" and duration is not None):
            raise InvestigationError("INVALID_CRITICAL_PATH_SEGMENT")
    for row in dependencies:
        budget.check()
        if (type(row) is not dict or type(row.get("from_segment")) is not str or type(row.get("to_segment")) is not str or
                row.get("from_segment") not in indexed or row.get("to_segment") not in indexed or
                type(row.get("evidence_ref")) is not str or
                row["evidence_ref"] not in edge_ids and row["evidence_ref"] != "SHARED_RECORDED_BOUNDARY"):
            raise InvestigationError("DANGLING_CRITICAL_PATH_DEPENDENCY")
    route = path.get("path", [])
    if type(route) is not list or len(route) > len(indexed) or any(type(ref) is not str or ref not in indexed for ref in route):
        raise InvestigationError("DANGLING_CRITICAL_PATH_ROUTE")
    totals = path.get("totals", {})
    if type(totals) is not dict or len(totals) > 3:
        raise InvestigationError("INVALID_CRITICAL_PATH_TOTALS")
    for value in (path.get("longest_observed_component_ms"), *totals.values()):
        if value is not None and (not finite_number(value) or value < 0):
            raise InvestigationError("INVALID_CRITICAL_PATH_DURATION")


def validate_case(case, *, budget=None):
    """Validate a saved graph without authenticating any imported assertion.

    Extra algorithm output, redacted manual steps and user annotations remain
    data. Their mere presence grants no causal or controlled-experiment proof.
    """
    budget = use_budget(budget)
    if type(case) is not dict or case.get("schema") != SCHEMA or case.get("algorithm_version") != ALGORITHM_VERSION:
        raise InvestigationError("UNSUPPORTED_INVESTIGATION_GRAPH_SCHEMA")
    _identifier(case.get("case_id"), "CASE_ID")
    _target(case.get("target_identity"))
    if case.get("root_cause_proven", False) is not False:
        raise InvestigationError("GRAPH_CANNOT_DECLARE_AUTOMATIC_ROOT_CAUSE_PROOF")
    if case.get("file_trust", "UNVERIFIED_IMPORT") != "UNVERIFIED_IMPORT":
        raise InvestigationError("INVESTIGATION_IMPORT_AUTHENTICITY_NOT_ESTABLISHED")
    sources = _sources(case.get("sources"), budget)
    nodes, edges = case.get("nodes"), case.get("edges")
    if type(nodes) is not list or type(edges) is not list or len(nodes) > budget.max_nodes or len(edges) > budget.max_edges:
        raise InvestigationError("INVESTIGATION_GRAPH_ELEMENT_BUDGET")
    indexed = {}
    for node in nodes:
        _node(node, sources, budget)
        if node["node_id"] in indexed:
            raise InvestigationError("DUPLICATE_EVIDENCE_NODE_ID")
        indexed[node["node_id"]] = node
    validate_trace_identity_consistency(nodes, budget=budget)
    if "source_ids" in case and case["source_ids"] != sorted(sources):
        raise InvestigationError("CASE_SOURCE_IDS_MISMATCH")
    if "source_selections" in case and case["source_selections"] != [
            {"source_id": identifier, "selection": source.get("selection", {})}
            for identifier, source in sorted(sources.items())]:
        raise InvestigationError("CASE_SOURCE_SELECTIONS_MISMATCH")
    if "incident_ids" in case:
        incidents = case["incident_ids"]
        if (type(incidents) is not list or any(type(value) is not str or value not in indexed or
                indexed[value]["observation_type"] != "INCIDENT" for value in incidents)):
            raise InvestigationError("CASE_INCIDENT_IDS_MISMATCH")
    edge_ids = set()
    for edge in edges:
        budget.check()
        if type(edge) is not dict or type(edge.get("relation_type")) is not str or edge.get("relation_type") not in RELATION_TYPES:
            raise InvestigationError("INVALID_EVIDENCE_EDGE")
        _identifier(edge.get("edge_id"), "EDGE_ID")
        _identifier(edge.get("relation"), "EDGE_RELATION")
        _identifier(edge.get("from_node"), "EDGE_FROM_NODE")
        _identifier(edge.get("to_node"), "EDGE_TO_NODE")
        if edge["edge_id"] in edge_ids:
            raise InvestigationError("DUPLICATE_EVIDENCE_EDGE_ID")
        edge_ids.add(edge["edge_id"])
        if edge.get("from_node") not in indexed or edge.get("to_node") not in indexed:
            raise InvestigationError("DANGLING_EVIDENCE_EDGE")
        refs = edge.get("evidence_refs")
        if type(refs) is not list or not refs or len(refs) > 256 or any(type(ref) is not str or ref not in indexed for ref in refs):
            raise InvestigationError("DANGLING_EVIDENCE_REFERENCE")
        if edge.get("relation_type") == "EXACT_IDENTITY":
            first, second = indexed[edge["from_node"]], indexed[edge["to_node"]]
            first_process, second_process = process_identity_key(first.get("process_identity")), process_identity_key(second.get("process_identity"))
            first_thread = thread_identity_key(first.get("thread_identity"), first.get("process_identity"))
            second_thread = thread_identity_key(second.get("thread_identity"), second.get("process_identity"))
            if not (first_process is not None and first_process == second_process or
                    first_thread is not None and first_thread == second_thread):
                raise InvestigationError("UNSUPPORTED_EXACT_IDENTITY_EDGE")
            if edge["relation"] == "THREAD_EVIDENCE" and (first_thread is None or first_thread != second_thread):
                raise InvestigationError("UNSUPPORTED_EXACT_THREAD_IDENTITY_EDGE")
            if edge["relation"] == "PROCESS_EVIDENCE" and (first_process is None or first_process != second_process):
                raise InvestigationError("UNSUPPORTED_EXACT_PROCESS_IDENTITY_EDGE")
        if edge.get("relation_type") == "DIRECT_REFERENCE":
            if indexed[edge["from_node"]]["source_identity"] != indexed[edge["to_node"]]["source_identity"]:
                raise InvestigationError("UNSUPPORTED_CROSS_SOURCE_DIRECT_REFERENCE")
        if edge.get("relation_type") == "TEMPORAL_COINCIDENCE":
            first, second = indexed[edge["from_node"]], indexed[edge["to_node"]]
            a, b = bounds(first), bounds(second)
            if a is None or b is None or first["time_domain"] != second["time_domain"] or a[2] != b[2] or a[1] < b[0] or b[1] < a[0]:
                raise InvestigationError("UNSUPPORTED_TEMPORAL_COINCIDENCE")
        if edge.get("relation_type") == "OBSERVED_DEPENDENCY":
            first, second = indexed[edge["from_node"]], indexed[edge["to_node"]]
            a, b = first["metadata"], second["metadata"]
            same_source = first["source_identity"] == second["source_identity"]
            wct = (same_source and first["source_type"] == second["source_type"] == "DEEP_JOURNAL" and
                edge["relation"] == "WCT_CHAIN" and a.get("recorded_source") == b.get("recorded_source") == "WIN32_WCT" and
                type(a.get("wct_snapshot_id")) is str and a["wct_snapshot_id"] == b.get("wct_snapshot_id") and
                type(a.get("wct_position")) is int and b.get("wct_position") == a["wct_position"] + 1 and
                bool(a.get("record_refs")) and a.get("record_refs") == b.get("record_refs"))
            schedule = a.get("thread_schedule")
            ready = schedule.get("ready_thread") if type(schedule) is dict else None
            identity = second.get("thread_identity") or {}
            interval = bounds(first)
            scheduler = (same_source and edge["relation"] == "SCHEDULER_READY_BOUNDARY" and
                first["observation_type"] == "SCHEDULER_EVENT" and second["observation_type"] == "WAIT_INTERVAL" and
                type(schedule) is dict and schedule.get("kind") == "ready" and type(ready) is dict and
                ready.get("attribution") == "TRACELOG_THREAD_LIFETIME" and identity.get("kind") == "TRACE_THREAD" and
                ready.get("process_instance") == identity.get("process_instance") and
                ready.get("thread_instance") == identity.get("thread_instance") and interval is not None and
                interval[2] == "ms" and first["time_domain"] == second["time_domain"] and
                b.get("quality") == "OBSERVED_SWITCH_PAIR" and finite_number(b.get("off_cpu_ms")) and
                interval[0] == b.get("ready_time_ms") and first["source_record_id"] in b.get("record_refs", []))
            if not (wct or scheduler):
                raise InvestigationError("UNSUPPORTED_OBSERVED_DEPENDENCY_EDGE")
        if edge.get("relation_type") == "BOUNDED_TIME_CORRELATION":
            value = edge.get("time_uncertainty")
            if (type(value) is not dict or not all(finite_number(value.get(key)) for key in ("lower_ns", "upper_ns", "width_ns")) or
                    value["upper_ns"] < value["lower_ns"] or value["width_ns"] != value["upper_ns"] - value["lower_ns"] or
                    value.get("assessment_status") != "BOUNDED_LOCAL_CLOCK_CORRELATION"):
                raise InvestigationError("INVALID_BOUNDED_CLOCK_EDGE")
            from .decoder_alignment import QPC_MODEL, ORDER_MODEL
            first, second = indexed[edge["from_node"]], indexed[edge["to_node"]]
            first_source, second_source = sources[first["source_identity"]], sources[second["source_identity"]]
            trace = (first.get("process_identity") or {}).get("trace_sha256") or first_source.get("trace_input_sha256")
            target_bounds = bounds(second)
            if (trace != value.get("source_trace_sha256") or
                    second_source.get("session_uuid") != value.get("session_uuid") or
                    second["time_domain"] != value.get("target_domain") or
                    value.get("clock_model") not in (QPC_MODEL, ORDER_MODEL) or
                    target_bounds is None or target_bounds[2] != "ns" or
                    value["upper_ns"] < target_bounds[0] or value["lower_ns"] > target_bounds[1]):
                raise InvestigationError("BOUNDED_CLOCK_EDGE_SOURCE_OR_WINDOW_MISMATCH")
    for name in ("hypotheses", "actions", "issues", "guided_experiments", "user_annotations"):
        if name in case and (type(case[name]) is not list or len(case[name]) > 10000):
            raise InvestigationError("INVALID_INVESTIGATION_" + name.upper())
    _models(case, indexed, edge_ids, budget)
    if "_source_paths" in case:
        paths = case["_source_paths"]
        if (type(paths) is not dict or len(paths) > 64 or any(key not in sources or type(value) is not str or
                not 1 <= len(value) <= 32768 for key, value in paths.items())):
            raise InvestigationError("INVALID_PRIVATE_SOURCE_NAVIGATION_MAP")
    _json_shape(case, budget)
    return budget.result(case)


def build_graph(normalized, *, target_identity=None, scenario=None, app_identity=None, budget=None):
    budget = use_budget(budget)
    if type(normalized) is not dict:
        raise InvestigationError("INVALID_NORMALIZED_EVIDENCE")
    coverage = normalized.get("coverage", {})
    limits = normalized.get("limitations", [])
    clocks = normalized.get("clock_relations", ())
    if (type(coverage) is not dict or type(limits) is not list or len(limits) > 512 or
            any(type(value) is not str or len(value) > 512 for value in limits) or
            not isinstance(clocks, (list, tuple)) or len(clocks) > budget.max_events):
        raise InvestigationError("INVALID_NORMALIZED_EVIDENCE_METADATA")
    sources = _sources(normalized.get("sources"), budget)
    raw_nodes = normalized.get("nodes")
    if type(raw_nodes) is not list or len(raw_nodes) > budget.max_events:
        raise InvestigationError("INVALID_NORMALIZED_NODE_BUDGET")
    # Validate before retaining; input order does not decide which nodes fit.
    unique = {}
    for value in raw_nodes:
        node = _node(value, sources, budget)
        previous = unique.get(node["node_id"])
        if previous is not None and previous != node:
            raise InvestigationError("CONFLICTING_EVIDENCE_NODE_ID")
        unique[node["node_id"]] = node
    validate_trace_identity_consistency(raw_nodes, budget=budget)
    ordered = sorted(unique.values(), key=lambda node: node["node_id"])
    shown = ordered[:budget.max_nodes]
    omitted = max(0, len(ordered) - len(shown))
    upstream_omitted = coverage.get("nodes_omitted", 0)
    if type(upstream_omitted) is not int or not 0 <= upstream_omitted < 2**63:
        raise InvestigationError("INVALID_NORMALIZATION_OMISSION_COUNT")
    total_omitted = upstream_omitted + omitted
    _target(target_identity)
    correlations = correlate_evidence(shown, list(sources.values()),
        clock_relations=clocks, budget=budget)
    selection = normalized.get("selection", {})
    _json_shape(selection, budget)
    # The adapters retain the effective, merged filters on each source. The
    # normalizer's optional shared selection is not their authoritative view:
    # descriptor-local PID/lifetime/window/cursor filters may override it.
    # Source/node IDs still identify physical recorded evidence across views.
    source_selections = [{"source_id": identifier, "selection": source.get("selection", {})}
                         for identifier, source in sorted(sources.items())]
    identity = {"sources": source_selections, "selection": selection,
                "target_identity": target_identity, "scenario": scenario, "app_identity": app_identity,
                "algorithm": ALGORITHM_VERSION,
                "graph_parameters": {"max_events": budget.max_events, "max_nodes": budget.max_nodes,
                                     "max_edges": budget.max_edges}}
    _json_shape(identity, budget)
    limitations = sorted(set([*limits, *correlations["limitations"],
        "IMPORTED_GRAPH_IS_NOT_AUTHENTICATED_EVIDENCE", "CAUSAL_ROOT_CAUSE_NOT_AUTOMATICALLY_ESTABLISHED"]))
    if total_omitted:
        limitations.append("DISPLAY_NODE_BUDGET_REACHED")
    if correlations["coverage"]["edges_omitted"] or not correlations["coverage"]["edge_candidate_scan_complete"]:
        limitations.append("DISPLAY_EDGE_BUDGET_REACHED")
    case = {"schema": SCHEMA, "algorithm_version": ALGORITHM_VERSION,
        "case_id": stable_id("case", identity), "target_identity": target_identity,
        "graph_version": 1, "source_ids": sorted(sources),
        "incident_ids": sorted(node["node_id"] for node in shown if node["observation_type"] == "INCIDENT"),
        "sources": sorted(sources.values(), key=lambda source: source["source_id"]),
        "nodes": shown, "edges": correlations["edges"], "gaps": correlations["gaps"],
        "coverage": {**coverage, **correlations["coverage"],
            "normalized_nodes": len(raw_nodes), "unique_nodes": len(ordered),
            "shown_nodes": len(shown), "normalization_nodes_omitted": upstream_omitted,
            "graph_nodes_omitted": omitted, "nodes_omitted": total_omitted,
            "display_graph_complete": not total_omitted and not coverage.get("has_more", False) and
                not correlations["coverage"]["edges_omitted"] and correlations["coverage"]["edge_candidate_scan_complete"]},
        "selection": selection, "source_selections": source_selections,
        "limitations": limitations, "scenario": scenario,
        "app_identity": app_identity, "hypotheses": [], "actions": [], "issues": [],
        "root_cause": "UNKNOWN", "root_cause_proven": False,
        "file_trust": "UNVERIFIED_IMPORT",
        "analysis_provenance": "UNVERIFIED_DERIVATION_RECOMPUTE_SOURCES_FOR_CURRENT_LINK_VALIDATION",
        "verification_class": "DERIVED_FROM_UNVERIFIED_SOURCES"}
    return validate_case(case, budget=budget)


def get_related_evidence(case, node_id, *, after=0, limit=100, budget=None):
    budget = use_budget(budget)
    validate_case(case, budget=budget)
    if type(after) is not int or not 0 <= after <= 20_000 or type(limit) is not int or not 1 <= limit <= 200:
        raise InvestigationError("INVALID_RELATED_EVIDENCE_PAGE")
    _identifier(node_id, "RELATED_EVIDENCE_NODE_ID")
    indexed = {node["node_id"]: node for node in case["nodes"]}
    if node_id not in indexed:
        raise InvestigationError("EVIDENCE_NODE_NOT_FOUND")
    related = sorted([edge for edge in case["edges"] if node_id in (edge["from_node"], edge["to_node"])],
                     key=lambda edge: edge["edge_id"])
    page = related[after:after + limit]
    other_ids = sorted({edge["to_node"] if edge["from_node"] == node_id else edge["from_node"] for edge in page})
    return budget.result({"case_id": case["case_id"], "node": indexed[node_id], "edges": page,
        "nodes": [indexed[key] for key in other_ids], "total": len(related),
        "next_cursor": after + len(page), "has_more": after + len(page) < len(related),
        "gaps": [gap for gap in case.get("gaps", []) if gap["node_id"] == node_id]})
