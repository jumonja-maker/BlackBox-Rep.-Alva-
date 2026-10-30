"""Source-bound evidence links; matching numbers or names never grant identity."""
from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass, field
import re
from types import MappingProxyType

from .investigation_graph_contracts import (InvestigationError, evidence_edge,
    finite_number, use_budget)

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_CLOCK_ORIGIN = object()
MAX_NEIGHBORS = 8


def _int(value, minimum=0, maximum=2**64 - 1):
    return type(value) is int and minimum <= value <= maximum


def process_identity_key(identity):
    """Return exact live/trace identity only, never a converted float or PID."""
    if identity is None:
        return None
    if type(identity) is not dict:
        raise InvestigationError("INVALID_PROCESS_IDENTITY")
    kind = identity.get("kind")
    if kind == "LIVE_PROCESS":
        if not _int(identity.get("pid"), 1, 2**32 - 1) or not _int(identity.get("created_100ns"), 1):
            raise InvestigationError("INVALID_LIVE_PROCESS_IDENTITY")
        return kind, identity["pid"], identity["created_100ns"]
    if kind == "TRACE_PROCESS":
        trace = identity.get("trace_sha256")
        if type(trace) is not str or not _SHA.fullmatch(trace) or not _int(identity.get("process_instance")):
            raise InvestigationError("INVALID_TRACE_PROCESS_IDENTITY")
        if "pid" in identity and not _int(identity["pid"], -1, 2**32 - 1):
            raise InvestigationError("INVALID_TRACE_PROCESS_PID_LABEL")
        return kind, trace, identity["process_instance"]
    if kind in ("SESSION_PROCESS", "UNRESOLVED_PROCESS", "APP_PROCESS"):
        if "pid" in identity and not _int(identity["pid"], -1, 2**32 - 1):
            raise InvestigationError("INVALID_SCOPED_PROCESS_IDENTITY")
        if kind == "SESSION_PROCESS" and not _int(identity.get("instance_id"), 1):
            raise InvestigationError("INVALID_SESSION_PROCESS_IDENTITY")
        return None
    raise InvestigationError("UNSUPPORTED_PROCESS_IDENTITY_KIND")


def thread_identity_key(identity, process_identity=None):
    if identity is None:
        return None
    if type(identity) is not dict:
        raise InvestigationError("INVALID_THREAD_IDENTITY")
    kind = identity.get("kind")
    if kind == "LIVE_THREAD":
        parent = process_identity_key(process_identity)
        # The normalizer carries the process FILETIME in created_100ns and
        # the distinct thread FILETIME here. Never substitute the former.
        created = identity.get("thread_created_100ns")
        if parent is None or parent[0] != "LIVE_PROCESS" or not _int(identity.get("tid"), 1, 2**32 - 1) or not _int(created, 1):
            raise InvestigationError("INVALID_LIVE_THREAD_IDENTITY")
        if "pid" in identity and identity["pid"] != parent[1]:
            raise InvestigationError("CONFLICTING_THREAD_PROCESS_IDENTITY")
        if "created_100ns" in identity and identity["created_100ns"] != parent[2]:
            raise InvestigationError("CONFLICTING_THREAD_PROCESS_IDENTITY")
        return kind, *parent[1:], identity["tid"], created
    if kind == "TRACE_THREAD":
        trace = identity.get("trace_sha256")
        if (type(trace) is not str or not _SHA.fullmatch(trace) or
                not _int(identity.get("process_instance")) or not _int(identity.get("thread_instance"))):
            raise InvestigationError("INVALID_TRACE_THREAD_IDENTITY")
        if any(key in identity and not _int(identity[key], -1, 2**32 - 1) for key in ("pid", "tid")):
            raise InvestigationError("INVALID_TRACE_THREAD_PID_OR_TID_LABEL")
        parent = process_identity_key(process_identity)
        if parent is not None and parent != ("TRACE_PROCESS", trace, identity["process_instance"]):
            raise InvestigationError("CONFLICTING_THREAD_PROCESS_IDENTITY")
        if (type(process_identity) is dict and _int(process_identity.get("pid"), 0, 2**32 - 1) and
                _int(identity.get("pid"), 0, 2**32 - 1) and identity["pid"] != process_identity["pid"]):
            raise InvestigationError("CONFLICTING_THREAD_PROCESS_PID_LABEL")
        return kind, trace, identity["process_instance"], identity["thread_instance"]
    if kind in ("SESSION_THREAD", "UNRESOLVED_THREAD", "APP_THREAD"):
        if "tid" in identity and not _int(identity["tid"], -1, 2**32 - 1):
            raise InvestigationError("INVALID_SCOPED_THREAD_IDENTITY")
        return None
    raise InvestigationError("UNSUPPORTED_THREAD_IDENTITY_KIND")


def validate_trace_identity_consistency(nodes, *, budget):
    """Reject contradictory labels on exact trace lifetime indices in O(n)."""
    process_labels, thread_labels = {}, {}
    def register(identity, parent=None):
        if type(identity) is not dict:
            return
        kind = identity.get("kind")
        if kind not in ("TRACE_PROCESS", "TRACE_THREAD"):
            return
        key = process_identity_key(identity) if kind == "TRACE_PROCESS" else thread_identity_key(identity, parent)
        process_key = key[1:3]
        if _int(identity.get("pid"), 0, 2**32 - 1):
            previous = process_labels.setdefault(process_key, identity["pid"])
            if previous != identity["pid"]:
                raise InvestigationError("CONTRADICTORY_TRACE_PROCESS_PID_LABELS")
        if kind == "TRACE_THREAD" and _int(identity.get("tid"), 0, 2**32 - 1):
            previous = thread_labels.setdefault(key[1:], identity["tid"])
            if previous != identity["tid"]:
                raise InvestigationError("CONTRADICTORY_TRACE_THREAD_TID_LABELS")
    for node in nodes:
        budget.check()
        process = node.get("process_identity")
        register(process)
        register(node.get("thread_identity"), process)
        # Scheduler participants include independent waker/old/new processes.
        # Validate their own lifetime labels; never equate them to the header.
        domain, metadata = node.get("time_domain", ""), node.get("metadata", {})
        if node.get("source_type") != "TRACE_INDEX" or not domain.startswith("TRACE_RELATIVE:"):
            continue
        trace = domain.split(":", 1)[1]
        if _SHA.fullmatch(trace) is None:
            continue
        schedule = metadata.get("thread_schedule")
        participants = list(schedule.values()) if type(schedule) is dict else []
        sample = metadata.get("cpu_sample")
        if type(sample) is dict:
            participants.append(sample.get("thread"))
        for raw in participants:
            if type(raw) is dict and raw.get("attribution") == "TRACELOG_THREAD_LIFETIME":
                identity = {**raw, "kind": "TRACE_THREAD", "trace_sha256": trace}
                register(identity)


def _local_process_key(node):
    identity = node.get("process_identity")
    exact = process_identity_key(identity)
    if exact is not None:
        return exact
    if (type(identity) is dict and identity.get("kind") == "SESSION_PROCESS" and
            _int(identity.get("instance_id"), 1)):
        return "SESSION_PROCESS", node["source_identity"], identity["instance_id"]
    scope = node["metadata"].get("operation_scope")
    if type(identity) is dict and identity.get("kind") == "APP_PROCESS" and type(scope) is str and scope:
        return "APP_PRODUCER", node["source_identity"], scope
    return None


def bounds(node):
    value = node.get("time_bounds")
    if value is None:
        return None
    if (type(value) is not dict or not finite_number(value.get("start")) or
            not finite_number(value.get("end")) or value["end"] < value["start"] or
            value.get("unit") not in ("ns", "ms")):
        raise InvestigationError("INVALID_EVIDENCE_TIME_BOUNDS")
    uncertainty = value.get("uncertainty")
    if uncertainty is not None and (not finite_number(uncertainty) or uncertainty < 0):
        raise InvestigationError("INVALID_EVIDENCE_TIME_UNCERTAINTY")
    return value["start"], value["end"], value["unit"]


@dataclass(frozen=True)
class ComputedClockRelation:
    """Internal result of the existing clock projector, never a JSON assertion."""
    from_node: str
    to_node: str
    target_domain: str
    projection: dict
    session_origin_ns: int
    evidence_refs: tuple
    _origin: object = field(default=None, repr=False, compare=False)


def computed_clock_relation(first_node, second_node, alignment, event_row, *, target_domain,
                            evidence_refs=None):
    """The source adapter supplies its freshly assessed alignment and raw row.

    Projection is recomputed here rather than accepting imported ``aligned``
    flags. This internal object is consumed before serializing the case.
    """
    from .decoder_alignment import ALIGNED, project_event_time
    if type(alignment) is not dict or alignment.get("status") != ALIGNED:
        return None
    projected = project_event_time(alignment, event_row)
    origin = alignment.get("session_origin_ns")
    if projected.get("status") != ALIGNED or not _int(origin):
        return None
    return ComputedClockRelation(first_node, second_node, target_domain, MappingProxyType(dict(projected)), origin,
        tuple(evidence_refs or (first_node, second_node)), _CLOCK_ORIGIN)


def correlate_evidence(nodes, sources, *, clock_relations=(), budget=None):
    """Build O(n log n) identity/reference indices and bounded neighborhoods."""
    budget = use_budget(budget)
    validate_trace_identity_consistency(nodes, budget=budget)
    indexed = {node["node_id"]: node for node in nodes}
    sources_by_id = {source["source_id"]: source for source in sources}
    edges, edge_ids, gaps = [], set(), []
    counters = {"edge_candidates": 0, "edges_omitted": 0, "unresolved_references": 0,
                "identity_gaps": 0, "clock_relations_refused": 0, "gaps_omitted": 0,
                "edge_candidate_scan_complete": True, "ambiguous_record_references": 0}
    candidate_limit = max(budget.max_edges * 4, budget.max_nodes * 4)

    def gap(node, reason, **detail):
        counters["identity_gaps" if reason.startswith("IDENTITY_") else "unresolved_references"] += 1
        if len(gaps) < 256:
            gaps.append({"node_id": node["node_id"], "relation_type": "NOT_ESTABLISHED",
                         "reason": reason, **detail})
        else:
            counters["gaps_omitted"] += 1

    def add(first, second, kind, relation, *, refs=None, uncertainty=None, limitations=None):
        budget.check()
        if first == second:
            return
        if counters["edge_candidates"] >= candidate_limit:
            counters["edge_candidate_scan_complete"] = False
            return
        edge = evidence_edge(first, second, kind, relation=relation, evidence_refs=refs,
            time_uncertainty=uncertainty, limitations=["IMPORTED_SOURCE_NOT_AUTHENTICATED", *(limitations or [])])
        if edge["edge_id"] in edge_ids:
            return
        edge_ids.add(edge["edge_id"])
        counters["edge_candidates"] += 1
        if len(edges) >= budget.max_edges:
            counters["edges_omitted"] += 1
            return
        edges.append(edge)

    # A star per object avoids quadratic all-pair joins. Prefer entity nodes
    # as anchors so the resulting graph remains useful for navigation.
    process_groups, thread_groups, records = {}, {}, {}
    for node in nodes:
        budget.check()
        records.setdefault((node["source_identity"], node["source_record_id"]), []).append(node)
        process_key = process_identity_key(node.get("process_identity"))
        thread_key = thread_identity_key(node.get("thread_identity"), node.get("process_identity"))
        if process_key is not None:
            process_groups.setdefault(process_key, []).append(node)
        elif node.get("process_identity") is not None:
            gap(node, "IDENTITY_EXACT_PROCESS_LIFETIME_NOT_AVAILABLE")
        if thread_key is not None:
            thread_groups.setdefault(thread_key, []).append(node)
        elif node.get("thread_identity") is not None:
            gap(node, "IDENTITY_THREAD_LIFETIME_NOT_AVAILABLE")
    thread_anchors = set()
    for group in thread_groups.values():
        group.sort(key=lambda node: (node["observation_type"] != "THREAD", node["node_id"]))
        thread_anchors.add(group[0]["node_id"])
    for groups, entity, relation in ((process_groups, "PROCESS", "PROCESS_EVIDENCE"),
                                      (thread_groups, "THREAD", "THREAD_EVIDENCE")):
        for group in groups.values():
            if not counters["edge_candidate_scan_complete"]:
                break
            if entity == "PROCESS":
                # Connect a thread anchor once to its process. Connecting
                # every thread observation to both anchors wastes the 20k
                # edge budget without adding an identity proof.
                group = [node for node in group if node["node_id"] in thread_anchors or
                         thread_identity_key(node.get("thread_identity"), node.get("process_identity")) is None]
            group.sort(key=lambda node: (node["observation_type"] != entity, node["node_id"]))
            if not group:
                continue
            first = group[0]["node_id"]
            for node in group[1:]:
                add(first, node["node_id"], "EXACT_IDENTITY", relation,
                    limitations=["OBJECT_IDENTITY_EQUALITY_IS_NOT_SOURCE_AUTHENTICATION"])

    for node in nodes:
        budget.check()
        if not counters["edge_candidate_scan_complete"]:
            break
        metadata = node["metadata"]
        references = metadata.get("record_refs", [])
        if type(references) is not list or len(references) > 256 or any(type(ref) is not str or len(ref) > 512 for ref in references):
            raise InvestigationError("INVALID_EVIDENCE_RECORD_REFERENCES")
        for reference in sorted(set(references)):
            matches = records.get((node["source_identity"], reference), [])
            if not matches:
                gap(node, "SOURCE_RECORD_NOT_INCLUDED", source_record_id=reference)
            if len(matches) > MAX_NEIGHBORS:
                counters["ambiguous_record_references"] += 1
                gap(node, "SOURCE_RECORD_REFERENCE_AMBIGUOUS", source_record_id=reference)
                continue
            for other in matches:
                add(node["node_id"], other["node_id"], "DIRECT_REFERENCE",
                    metadata.get("record_ref_relation", "SOURCE_RECORD"))
        for key, relation in (("process_ref", "PROCESS_REFERENCE"), ("thread_ref", "THREAD_REFERENCE"),
                              ("stack_ref", "STACK_REFERENCE"), ("module_ref", "MODULE_REFERENCE")):
            reference = metadata.get(key)
            if reference is None:
                continue
            if type(reference) is not str or len(reference) > 256:
                raise InvestigationError("INVALID_EVIDENCE_NODE_REFERENCE")
            other = indexed.get(reference)
            if other is None:
                gap(node, "NODE_NOT_INCLUDED", reference=reference)
            elif other["source_identity"] != node["source_identity"]:
                # Raw cross-source references are not a validated join.
                gap(node, "CROSS_SOURCE_REFERENCE_NOT_ESTABLISHED", reference=reference)
            else:
                add(node["node_id"], reference, "DIRECT_REFERENCE", relation)

    # Local SDK action ancestry is source-scoped and explicit, not a shared
    # operation-id string across ETL and application event sources.
    def operation_scope(node):
        value = node["metadata"].get("operation_scope")
        if value is not None:
            if type(value) is not str or not 1 <= len(value) <= 256:
                raise InvestigationError("INVALID_EVIDENCE_OPERATION_SCOPE")
            return "SOURCE_PRODUCER", value
        key = process_identity_key(node.get("process_identity"))
        return ("NATIVE_TARGET", key) if node["source_type"] == "DEEP_JOURNAL" and key else None

    operations = {}
    for node in nodes:
        operation = node["metadata"].get("operation_id")
        if operation is not None:
            if type(operation) is not str or not 1 <= len(operation) <= 256:
                raise InvestigationError("INVALID_EVIDENCE_OPERATION_ID")
            scope = operation_scope(node)
            if scope is not None:
                operations.setdefault((node["source_identity"], scope, operation), []).append(node)
    parent_anchors = {}
    for key, values in operations.items():
        budget.check()
        starts = [value for value in values if str(value["metadata"].get("phase", "")).upper() in ("BEGIN", "REQUESTED")]
        parent_anchors[key] = starts[0] if len(starts) == 1 else None
    for group in operations.values():
        if not counters["edge_candidate_scan_complete"]:
            break
        group.sort(key=lambda node: node["node_id"])
        # Duplicate/multi-writer identifiers cannot manufacture operation pairs.
        if len(group) == 2:
            phases = {str(node["metadata"].get("phase", "")).upper(): node for node in group}
            if set(phases) in ({"REQUESTED", "RESULT"}, {"BEGIN", "END"}, {"BEGIN", "ERROR"}):
                first = phases.get("REQUESTED", phases.get("BEGIN"))
                second = phases.get("RESULT", phases.get("END", phases.get("ERROR")))
                first_bounds, second_bounds = bounds(first), bounds(second)
                reversed_order = (first_bounds is not None and second_bounds is not None and
                    first["time_domain"] == second["time_domain"] and first_bounds[2] == second_bounds[2] and
                    first_bounds[0] > second_bounds[1])
                if reversed_order:
                    add(first["node_id"], second["node_id"], "CONTRADICTED", "OPERATION_BOUNDARY_ORDER",
                        limitations=["IDENTIFIER_MATCH_DOES_NOT_REPAIR_REVERSED_CLOCK_BOUNDARIES"])
                else:
                    add(first["node_id"], second["node_id"], "DIRECT_REFERENCE", "OPERATION_PAIR")
        for node in group:
            parent = node["metadata"].get("parent_id")
            if parent is None:
                continue
            if type(parent) is not str or not 1 <= len(parent) <= 256:
                raise InvestigationError("INVALID_PARENT_OPERATION_ID")
            parent_node = parent_anchors.get((node["source_identity"], operation_scope(node), parent))
            if parent_node is not None:
                add(parent_node["node_id"], node["node_id"], "DIRECT_REFERENCE", "PARENT_OPERATION")
            else:
                gap(node, "PARENT_OPERATION_NOT_UNIQUELY_REFERENCED", operation_id=parent)

    # WCT supplies a dynamic ordered point snapshot, not a duration or a
    # transferable persistent lock-owner identity. Only the normalizer's
    # source/position/snapshot-constrained chain references qualify.
    for node in nodes:
        budget.check()
        if not counters["edge_candidate_scan_complete"]:
            break
        metadata = node["metadata"]
        dependencies = metadata.get("observed_dependencies", [])
        if type(dependencies) is not list or len(dependencies) > 32:
            raise InvestigationError("INVALID_OBSERVED_DEPENDENCY_REFERENCES")
        for dependency in dependencies:
            if type(dependency) is not dict or type(dependency.get("record_ref")) is not str:
                raise InvestigationError("INVALID_OBSERVED_DEPENDENCY_REFERENCE")
            previous = records.get((node["source_identity"], dependency["record_ref"]), [])
            supported = False
            if len(previous) == 1:
                other = previous[0]
                previous_metadata = other["metadata"]
                position = metadata.get("wct_position")
                supported = (node["source_type"] == "DEEP_JOURNAL" and other["source_type"] == "DEEP_JOURNAL" and
                    dependency.get("source") == "WIN32_WCT" and dependency.get("relation") == "WCT_CHAIN" and
                    metadata.get("recorded_source") == previous_metadata.get("recorded_source") == "WIN32_WCT" and
                    type(metadata.get("wct_snapshot_id")) is str and
                    metadata["wct_snapshot_id"] == previous_metadata.get("wct_snapshot_id") == dependency.get("snapshot_id") and
                    _int(position, 1, 16) and previous_metadata.get("wct_position") == position - 1 and
                    metadata.get("record_refs") and metadata.get("record_refs") == previous_metadata.get("record_refs"))
                if supported:
                    add(other["node_id"], node["node_id"], "OBSERVED_DEPENDENCY", "WCT_CHAIN",
                        limitations=["WCT_POINT_SNAPSHOT_ONLY_NOT_PERSISTENT_LOCK_OWNER_OR_DURATION",
                                     "WCT_CYCLE_IS_NOT_UNIVERSAL_APPLICATION_DEADLOCK_PROOF"])
            if not supported:
                gap(node, "WCT_DEPENDENCY_NOT_SUPPORTED_BY_SAME_SNAPSHOT", reference=dependency["record_ref"])

        if (node["observation_type"] == "WAIT_INTERVAL" and metadata.get("ready_time_ms") is not None and
                metadata.get("quality") == "OBSERVED_SWITCH_PAIR" and finite_number(metadata.get("off_cpu_ms"))):
            for reference in metadata.get("record_refs", []):
                for event in records.get((node["source_identity"], reference), [])[:MAX_NEIGHBORS]:
                    schedule = event["metadata"].get("thread_schedule")
                    ready = (schedule or {}).get("ready_thread") if type(schedule) is dict else None
                    identity = node.get("thread_identity") or {}
                    if (event["observation_type"] == "SCHEDULER_EVENT" and type(schedule) is dict and schedule.get("kind") == "ready" and
                            type(ready) is dict and ready.get("attribution") == "TRACELOG_THREAD_LIFETIME" and
                            identity.get("kind") == "TRACE_THREAD" and
                            ready.get("process_instance") == identity.get("process_instance") and
                            ready.get("thread_instance") == identity.get("thread_instance") and
                            event["time_domain"] == node["time_domain"] and bounds(event) is not None and
                            bounds(event)[2] == "ms" and bounds(event)[0] == metadata["ready_time_ms"]):
                        add(event["node_id"], node["node_id"], "OBSERVED_DEPENDENCY", "SCHEDULER_READY_BOUNDARY",
                            limitations=["WAKER_THREAD_IS_NOT_ESTABLISHED_LOCK_OWNER",
                                         "READY_EVENT_DESCRIBES_SCHEDULING_NOT_APPLICATION_ROOT_CAUSE"])

    # Same-domain temporal neighbors remain coincidence. Only incident/action
    # anchors receive a small neighborhood; a 10k-node graph never gets 100M
    # pairwise temporal edges, and separate clocks are not sorted together.
    domains = {}
    for node in nodes:
        interval = bounds(node)
        if interval is not None and node["time_domain"] != "UNKNOWN":
            domains.setdefault((node["time_domain"], interval[2]), []).append((interval[0], interval[1], node))
    for values in domains.values():
        if not counters["edge_candidate_scan_complete"]:
            break
        values.sort(key=lambda value: (value[0], value[2]["node_id"]))
        starts = [value[0] for value in values]
        for start, end, node in values:
            if not counters["edge_candidate_scan_complete"]:
                break
            if node["observation_type"] not in ("INCIDENT", "USER_ACTION", "DIAGNOSTIC_ACTION"):
                continue
            key = _local_process_key(node)
            if key is None:
                continue
            position = max(0, bisect_left(starts, start) - MAX_NEIGHBORS)
            for other_start, other_end, other in values[position:position + 2 * MAX_NEIGHBORS]:
                if other_start > end:
                    break
                if other_end < start or _local_process_key(other) != key:
                    continue
                add(node["node_id"], other["node_id"], "TEMPORAL_COINCIDENCE", "TIME_OVERLAP",
                    limitations=["TEMPORAL_COINCIDENCE_IS_NOT_DEPENDENCY_OR_CAUSE"])

    for item in clock_relations:
        budget.check()
        if not isinstance(item, ComputedClockRelation) or item._origin is not _CLOCK_ORIGIN:
            raise InvestigationError("CLOCK_RELATION_MUST_BE_RECOMPUTED_BY_SOURCE_ADAPTER")
        if not counters["edge_candidate_scan_complete"]:
            counters["clock_relations_refused"] += 1
            continue
        first, second = indexed.get(item.from_node), indexed.get(item.to_node)
        if first is None or second is None:
            counters["clock_relations_refused"] += 1
            continue
        projection = item.projection
        interval = bounds(second)
        trace = (first.get("process_identity") or {}).get("trace_sha256")
        source = sources_by_id[first["source_identity"]]
        trace = trace or source.get("trace_input_sha256")
        target_source = sources_by_id[second["source_identity"]]
        if (trace != projection.get("source_trace_sha256") or
                target_source.get("session_uuid") != projection.get("session_uuid") or
                second["time_domain"] != item.target_domain or interval is None or interval[2] != "ns"):
            counters["clock_relations_refused"] += 1
            continue
        low = projection["session_relative_lower_ns"] + item.session_origin_ns
        high = projection["session_relative_upper_ns"] + item.session_origin_ns
        if high < interval[0] or low > interval[1]:
            counters["clock_relations_refused"] += 1
            continue
        add(item.from_node, item.to_node, "BOUNDED_TIME_CORRELATION", "VALIDATED_CLOCK_WINDOW",
            refs=list(item.evidence_refs), uncertainty={"lower_ns": low, "upper_ns": high,
                "width_ns": high - low, "clock_model": projection["clock_model"],
                "source_trace_sha256": trace, "session_uuid": projection["session_uuid"],
                "target_domain": item.target_domain,
                "assessment_status": projection["status"]},
            limitations=["CLOCK_CORRELATION_NOT_PROCESS_IDENTITY_OR_CAUSALITY",
                         "LOCAL_CLOCK_ASSERTIONS_ARE_NOT_AUTHENTICATED"])

    return {"edges": sorted(edges, key=lambda edge: edge["edge_id"]), "gaps": gaps,
        "coverage": {**counters, "edges_omitted_is_lower_bound": not counters["edge_candidate_scan_complete"],
                     "shown_edges": len(edges), "exact_process_groups": len(process_groups),
                     "exact_thread_groups": len(thread_groups)},
        "limitations": ["EDGE_CLASSES_DO_NOT_AUTHENTICATE_EDITABLE_SOURCES",
                        "PID_TID_NAME_AND_UTC_ALONE_NEVER_ESTABLISH_LIVE_IDENTITY",
                        "TIME_COINCIDENCE_DOES_NOT_ESTABLISH_CAUSALITY"]}
