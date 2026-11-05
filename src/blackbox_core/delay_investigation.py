"""R30 projection of the existing evidence graph, scheduling path and I/O.

No collector or intervention lives here. Every displayed statement keeps its
source node, source clock and exact or explicitly unresolved identity. A WCT
owner is only the OS-reported thread in that very snapshot; a ReadyThread waker
and a simultaneous network/disk event are never promoted into lock ownership
or an application's internal cause.
"""
from __future__ import annotations

from collections import Counter
import heapq
import html

from .investigation_graph_contracts import SCHEMA, InvestigationError, finite_number, stable_id, use_budget

SCHEMA_DELAY = "blackbox.delay-investigation/1"
CATEGORIES = frozenset({"SCHEDULER_WAIT", "READY_DELAY", "WCT_CHAIN", "UI_FREEZE",
                       "FILE_IO_ERROR", "FILE_IO", "DISK_COMPLETION", "NETWORK_METADATA"})
STATUSES = frozenset({"OBSERVED", "SOURCE_REPORTED", "INCOMPLETE_EVIDENCE", "NOT_ESTABLISHED"})
_TEXT = {
    "SCHEDULER_WAIT": ("Recorded scheduler boundaries describe a non-running thread span; the wait reason is not a lock owner or root cause.",
        "Границы планировщика описывают интервал вне CPU; причина ожидания не устанавливает владельца блокировки или причину сбоя."),
    "READY_DELAY": ("A recorded ready-to-running interval describes scheduler delay, not time waiting for a lock.",
        "Записанный интервал готовности до выполнения описывает задержку планировщика, а не ожидание блокировки."),
    "WCT_CHAIN": ("A source records a Windows WCT point snapshot. Ownership below applies only to an explicitly owned mutex/critical-section edge in that snapshot.",
        "Источник содержит моментальный снимок Windows WCT. Указанный владелец относится только к явно занятому mutex/critical section в этом снимке."),
    "UI_FREEZE": ("The source records window responsiveness observations. The distance between probes is not a proven continuous freeze duration.",
        "Источник записал наблюдения отзывчивости окна. Интервал между проверками не доказывает непрерывную длительность зависания."),
    "FILE_IO_ERROR": ("A recorded file-operation result contains an error. Its source, request binding and error domain remain explicit; an application root cause is not established.",
        "В результате файловой операции записана ошибка. Источник, привязка запроса и область кода ошибки указаны отдельно; причина сбоя приложения не установлена."),
    "FILE_IO": ("A source records a file operation. Request boundaries, reported values and incomplete attribution remain distinct.",
        "Источник записал файловую операцию. Границы запроса, сообщённые значения и неполная привязка различаются."),
    "DISK_COMPLETION": ("Recorded disk-request/response metadata does not by itself prove that the application was delayed by this I/O.",
        "Записанные метаданные дискового запроса не доказывают, что именно эта операция задержала приложение."),
    "NETWORK_METADATA": ("Recorded endpoint/activity metadata contains no packet payload and does not establish a network cause of the delay.",
        "Метаданные соединений и активности не содержат сетевого payload и не устанавливают сетевую причину задержки."),
}
_PRIORITY = {"FILE_IO_ERROR": 0, "WCT_CHAIN": 1, "UI_FREEZE": 1, "READY_DELAY": 2,
             "SCHEDULER_WAIT": 3, "DISK_COMPLETION": 4, "FILE_IO": 5, "NETWORK_METADATA": 6}


def _int(value, low=0, high=2**63-1):
    return type(value) is int and low <= value <= high


def _records(node):
    metadata = node.get("metadata", {})
    if type(metadata) is not dict:
        return []
    values = [metadata]
    for name in ("fields", "attributes", "data", "detail", "context"):
        value = metadata.get(name)
        if type(value) is dict:
            values.append(value)
    return values


def _codes(node):
    return {value.upper() for record in _records(node) for key in
            ("code", "event_name", "event_kind", "trigger_code", "kind")
            if type(value := record.get(key)) is str and len(value) <= 256}


def _wct_snapshot(node):
    for record in _records(node):
        if (node.get("source_type") == "DEEP_JOURNAL" and record.get("operation") == "wait_chains" and
                record.get("source") == "WIN32_WCT" and type(record.get("nodes")) is list):
            return record
        wct = record.get("wct")
        if (node.get("source_type") == "SESSION" and node.get("metadata", {}).get("recorded_source") == "WCT" and
                "WCT_SNAPSHOT" in _codes(node) and type(wct) is dict and type(wct.get("nodes")) is list):
            return wct
    return None


def _wct_owners(snapshot):
    """wct.h: Owned=6, Thread=8, Mutex=3, CriticalSection=1.

    A SendMessage recipient, ALPC participant or a ready-thread waker is not a
    lock owner. WCT contains raw PID/TID labels, not creation FILETIMEs; those
    labels remain snapshot-scoped even when the inspected target was exact.
    """
    owners = []
    if (type(snapshot) is not dict or snapshot.get("status") != "OK" or snapshot.get("truncated") is True or
            type(snapshot.get("nodes")) is not list or len(snapshot["nodes"]) > 16):
        return owners
    nodes = snapshot["nodes"]
    for position in range(1, len(nodes)-1):
        before, lock, following = nodes[position-1:position+2]
        if (not all(type(value) is dict for value in (before, lock, following)) or
                before.get("object_type") != 8 or lock.get("object_type") not in (1, 3) or
                lock.get("object_status") != 6 or following.get("object_type") != 8 or
                not _int(following.get("pid"), 1, 2**32-1) or not _int(following.get("tid"), 1, 2**32-1)):
            continue
        owners.append({"pid": following["pid"], "tid": following["tid"], "lock_position": position,
            "lock_object_type": lock["object_type"], "scope": "THIS_WINDOWS_WCT_SNAPSHOT_ONLY",
            "identity_quality": "RAW_PID_TID_CREATION_FILETIME_NOT_RECORDED", "exact_instance": False,
            "basis": "WCT_OWNED_MUTEX_OR_CRITICAL_SECTION_FOLLOWED_BY_THREAD"})
    return owners


def _project_fields(records, fields):
    result = {}
    for key in fields:
        for record in records:
            value = record.get(key)
            if value is None or type(value) in (str, int, float, bool):
                if type(value) is float and not finite_number(value):
                    continue
                if key in record:
                    result[key] = value[:2048] if type(value) is str else value
                    break
    return result


def _win32_error(records):
    for record in records:
        for key in ("winerror", "win32_code", "win32_error"):
            if _int(record.get(key), 0, 2**32-1):
                return record[key]
        # error_code alone has no implicit Win32 domain. It is kept as a source
        # statement below, rather than converted into a Windows last-error.
    return None


def analyze_delay(case, *, budget=None, max_findings=1000):
    """Produce a bounded source-linked view for the existing Investigation UI."""
    budget = use_budget(budget)
    if (type(case) is not dict or case.get("schema") != SCHEMA or type(case.get("nodes")) is not list or
            len(case["nodes"]) > budget.max_nodes or not _int(max_findings, 1, 1000)):
        raise InvestigationError("INVALID_DELAY_INVESTIGATION")
    nodes = case["nodes"]
    indexed = {}
    sources = {source.get("source_id"): source for source in case.get("sources", []) if type(source) is dict}

    def trace_boundaries(node):
        source = sources.get(node.get("source_identity"), {})
        return (source.get("source_type") == "TRACE_INDEX" and source.get("decoded_status") == "DECODED" and
            source.get("decoder_reported_lost_events") == 0 and source.get("scan_complete") is True and
            source.get("out_of_order_events") is False and source.get("event_sequence_gaps") == 0)

    def exact_thread(node):
        from .evidence_correlation import thread_identity_key
        return thread_identity_key(node.get("thread_identity"), node.get("process_identity")) is not None

    def request_span(node, value):
        bounds, elapsed = node.get("time_bounds"), value.get("elapsed_ms")
        return (finite_number(elapsed) and elapsed >= 0 and type(bounds) is dict and bounds.get("unit") == "ms" and
            all(finite_number(bounds.get(key)) for key in ("start", "end")) and
            abs(elapsed - (bounds["end"]-bounds["start"])) <= max(1e-6, elapsed*1e-10))
    for node in nodes:
        budget.check()
        if (type(node) is not dict or type(node.get("node_id")) is not str or node["node_id"] in indexed or
                type(node.get("metadata", {})) is not dict):
            raise InvestigationError("INVALID_DELAY_EVIDENCE_NODE")
        indexed[node["node_id"]] = node
    critical = case.get("critical_path")
    if type(critical) is not dict:
        from .critical_path import analyze_critical_path
        critical = analyze_critical_path(case, budget=budget)
    segments = {}
    for segment in critical.get("segments", []):
        budget.check()
        if type(segment) is dict and segment.get("node_id") in indexed:
            segments.setdefault(segment["node_id"], []).append(segment)
    retained, counts, sequence = [], Counter(), 0

    def add(node, category, status, details):
        nonlocal sequence
        budget.check()
        sequence += 1
        counts[category] += 1
        selected_segments = segments.get(node["node_id"], [])[:16]
        refs = node["metadata"].get("record_refs", [])
        finding = {"finding_id": stable_id("delay-finding", node["node_id"], category),
            "category": category, "status": status, "description": _TEXT[category][0], "description_ru": _TEXT[category][1],
            "source_nodes": [node["node_id"]],
            "source_record_refs": [{"source_identity": node.get("source_identity"),
                "source_record_id": node.get("source_record_id")}],
            "recorded_boundary_refs": refs[:8] if type(refs) is list else [],
            "process_identity": node.get("process_identity"), "thread_identity": node.get("thread_identity"),
            "time_domain": node.get("time_domain", "UNKNOWN"), "time_bounds": node.get("time_bounds"),
            "critical_path_segments": [value["segment_id"] for value in selected_segments if type(value.get("segment_id")) is str],
            "details": details, "root_cause_proven": False, "source_authenticity": "UNVERIFIED_IMPORT"}
        score = (-_PRIORITY[category], -sequence)
        if len(retained) < max_findings:
            heapq.heappush(retained, (*score, finding))
        elif score > retained[0][:2]:
            heapq.heapreplace(retained, (*score, finding))

    for node in nodes:
        budget.check()
        row, kind = node["metadata"], node.get("observation_type")
        records, codes = _records(node), _codes(node)
        source_segments = segments.get(node["node_id"], [])
        contradicted = any(value.get("state") == "INCOMPLETE" for value in source_segments)
        if kind == "WAIT_INTERVAL" and "off_cpu_ms" in row:
            bounds = node.get("time_bounds")
            off_cpu = row.get("off_cpu_ms")
            valid = (row.get("quality") == "OBSERVED_SWITCH_PAIR" and finite_number(off_cpu) and off_cpu >= 0 and
                not contradicted and trace_boundaries(node) and exact_thread(node) and type(bounds) is dict and
                bounds.get("unit") == "ms" and all(finite_number(bounds.get(key)) for key in ("start", "end")) and
                abs(off_cpu - (bounds["end"] - bounds["start"])) <= max(1e-6, off_cpu*1e-10))
            split = (valid and all(finite_number(row.get(key)) and row[key] >= 0 for key in ("blocked_ms", "ready_delay_ms")) and
                abs(row["blocked_ms"] + row["ready_delay_ms"] - off_cpu) <= max(1e-6, off_cpu*1e-10))
            detail = _project_fields([row], ("quality", "wait_reason", "thread_state", "source_event_ids", "window_clipped"))
            detail.update(off_cpu_ms=row.get("off_cpu_ms") if valid else None,
                blocked_ms=row.get("blocked_ms") if split else None,
                ready_delay_ms=row.get("ready_delay_ms") if split else None,
                lock_owner="NOT_ESTABLISHED", waker_is_lock_owner="NOT_ESTABLISHED",
                duration_scope="THIS_RECORDED_SCHEDULER_INTERVAL_NOT_WHOLE_PROCESS_ELAPSED_TIME")
            add(node, "SCHEDULER_WAIT", "OBSERVED" if valid else "INCOMPLETE_EVIDENCE", detail)
            ready = row.get("ready_delay_ms")
            if split and ready > 0:
                add(node, "READY_DELAY", "OBSERVED", {"ready_delay_ms": ready,
                    "basis": "RECORDED_READY_BOUNDARY_OR_RECORDED_READY_SWITCH_OUT_STATE",
                    "lock_owner": "NOT_ESTABLISHED", "waker_is_lock_owner": "NOT_ESTABLISHED"})
        snapshot = _wct_snapshot(node)
        if snapshot is not None:
            owners = _wct_owners(snapshot)
            chain = [{key: item[key] for key in ("object_type", "object_status", "pid", "tid") if key in item}
                for item in snapshot.get("nodes", [])[:16] if type(item) is dict]
            add(node, "WCT_CHAIN", "SOURCE_REPORTED" if snapshot.get("status") == "OK" else "INCOMPLETE_EVIDENCE",
                {"snapshot_status": snapshot.get("status"), "chain": chain, "reported_owners": owners,
                 "lock_owner_status": "WINDOWS_WCT_SNAPSHOT_REPORTED_OWNER" if owners else "NOT_ESTABLISHED",
                 "persistent_owner": "NOT_ESTABLISHED", "wait_duration_ms": None,
                 "cycle_reported": snapshot.get("cycle_reported", snapshot.get("is_cycle")),
                 "cycle_is_application_deadlock_proof": False})
        if codes & {"UI_UNRESPONSIVE_OBSERVED", "UI_TIMEOUT", "UI_UNRESPONSIVE", "UI_RESPONSIVE_AGAIN"}:
            details = _project_fields(records, ("code", "native_result_status", "measurement_status",
                "consecutive_timeouts", "first_timeout_ns", "last_responsive_ns", "onset_exact"))
            details.update(continuous_freeze_duration_ms=None, duration_scope="POINT_RESPONSIVENESS_OBSERVATIONS",
                lock_owner="NOT_ESTABLISHED", recovered_observation="UI_RESPONSIVE_AGAIN" in codes)
            for record in records:
                window = record.get("window")
                if type(window) is dict:
                    details["window"] = {key: window[key] for key in ("pid", "tid", "hwnd") if _int(window.get(key), 1)}
                    break
            add(node, "UI_FREEZE", "SOURCE_REPORTED", details)
        if kind == "FILE_OPERATION":
            if row.get("request_boundary_phase") == "end":
                continue
            paired = row.get("file_io_pair") is True
            valid = (paired and row.get("quality") == "OBSERVED_REQUEST_PAIR" and
                row.get("status_attribution") == "MATCHED_RECORDED_REQUEST" and trace_boundaries(node) and exact_thread(node) and request_span(node, row))
            ntstatus = row.get("ntstatus") if valid and _int(row.get("ntstatus"), 0, 2**32-1) else None
            win32 = _win32_error(records)
            statuses = {str(record.get("status", "")).upper() for record in records}
            failed = (ntstatus is not None and ntstatus >> 30 == 3 or win32 not in (None, 0) or
                      not paired and bool(statuses & {"ERROR", "FAILED", "ACCESS_DENIED", "OPERATION_FAILED"}))
            details = _project_fields(records, ("operation", "quality", "status_name", "status_attribution",
                "requested_bytes", "transferred_bytes", "byte_count_scope", "file_name", "name_status", "duration_basis", "error_code", "error_code_basis"))
            details.update(ntstatus=ntstatus, ntstatus_severity=(ntstatus >> 30) if ntstatus is not None else None,
                win32_error=win32, win32_error_basis="RECORDED_SOURCE_FIELD" if win32 is not None else "NOT_RECORDED_NO_NTSTATUS_CONVERSION",
                elapsed_ms=row.get("elapsed_ms") if valid else None,
                duration_establishes_thread_wait=False, root_cause="UNKNOWN")
            # A raw OperationEnd may run on another thread. It remains visible
            # as raw evidence, never an issuer-bound error in this view.
            io = row.get("io_observation")
            if type(io) is dict and io.get("kind") == "file":
                if io.get("phase") == "end":
                    continue
                if not paired:
                    details.update(operation=io.get("operation"), elapsed_ms=None, ntstatus=None)
            add(node, "FILE_IO_ERROR" if failed else "FILE_IO",
                "OBSERVED" if valid else "INCOMPLETE_EVIDENCE" if paired else "SOURCE_REPORTED", details)
        if kind == "DISK_COMPLETION":
            pair = row.get("disk_io_pair") is True
            io = row.get("io_observation")
            value = row if pair else io if type(io) is dict and io.get("kind") == "disk" else None
            if value is not None:
                valid_pair = pair and value.get("quality") == "OBSERVED_REQUEST_PAIR" and trace_boundaries(node) and exact_thread(node) and request_span(node, value)
                details = _project_fields([value], ("operation", "disk_number", "quality", "transferred_bytes",
                    "duration_basis", "request_duration_basis", "outstanding_count_scope"))
                details.update(observed_request_ms=value.get("elapsed_ms") if valid_pair else None,
                    reported_response_ms=value.get("reported_response_ms") if pair else value.get("elapsed_ms"),
                    observed_outstanding_requests_at_start_lower_bound=value.get("observed_outstanding_requests_at_start_lower_bound") if valid_pair else None,
                    queue_delay_ms=None, device_service_ms=None, application_delay_proven=False)
                add(node, "DISK_COMPLETION", "OBSERVED" if valid_pair else "SOURCE_REPORTED", details)
        if kind == "NETWORK_OPERATION":
            io = row.get("io_observation")
            values = [io] if type(io) is dict and io.get("kind") == "network" else records
            details = _project_fields(values, ("protocol", "operation", "family", "transferred_bytes", "source_address", "destination_address",
                "source_port", "destination_port", "address_status", "byte_count_scope", "status", "state", "error_code", "winerror", "win32_code"))
            details.update(packet_contents="NOT_COLLECTED", network_cause_of_delay="NOT_ESTABLISHED")
            add(node, "NETWORK_METADATA", "SOURCE_REPORTED", details)
    findings = [item[2] for item in sorted(retained, key=lambda item: (-item[0], -item[1]))]
    coverage = case.get("coverage", {})
    if type(coverage) is not dict:
        coverage = {}
    omitted = sequence - len(findings)
    incomplete = bool(omitted or coverage.get("has_more") or coverage.get("nodes_omitted") or coverage.get("events_omitted") or
        any(row["status"] in {"INCOMPLETE_EVIDENCE", "NOT_ESTABLISHED"} for row in findings))
    result = {"schema": SCHEMA_DELAY, "status": "NO_RELEVANT_EVIDENCE" if not findings else
        "PARTIAL_EVIDENCE" if incomplete else "OBSERVATIONS_AVAILABLE", "findings": findings,
        "coverage": {"nodes_examined": len(nodes), "findings_available": sequence, "findings_represented": len(findings),
            "findings_omitted_budget": omitted, "categories": dict(counts),
            "source_events_omitted": coverage.get("events_omitted", 0), "source_nodes_omitted": coverage.get("nodes_omitted", 0)},
        "root_cause": "UNKNOWN", "root_cause_proven": False,
        "verification_class": "DERIVED", "source_authenticity": "UNVERIFIED_IMPORT",
        "limitations": ["DERIVED_VIEW_OF_EXISTING_GRAPH_NOT_A_NEW_COLLECTOR_OR_EVIDENCE_DATABASE",
            "CLOCK_DOMAINS_AND_SOURCE_IDENTITIES_ARE_NOT_JOINED_BY_RAW_PID_OR_TIME",
            "WCT_OWNERSHIP_IS_SNAPSHOT_SCOPED_WITHOUT_CREATION_FILETIME",
            "READY_WAKER_IS_NOT_A_LOCK_OWNER", "FILE_DISK_NETWORK_OBSERVATIONS_ARE_NOT_ROOT_CAUSE",
            "NO_QUEUE_SERVICE_SPLIT_WITHOUT_DEVICE_DISPATCH_BOUNDARY",
            "MISSING_SOURCES_AND_UNKNOWN_CLEANUP_REMAIN_UNKNOWN"]}
    validate_delay_report(result, nodes=indexed,
        critical_segments={value.get("segment_id") for value in critical.get("segments", []) if type(value) is dict}, budget=budget)
    return budget.result(result)


def validate_delay_report(report, *, nodes=None, critical_segments=None, budget=None):
    """Validate additive/imported display claims without granting evidence trust."""
    budget = use_budget(budget)
    if (type(report) is not dict or report.get("schema") != SCHEMA_DELAY or
            report.get("status") not in {"NO_RELEVANT_EVIDENCE", "PARTIAL_EVIDENCE", "OBSERVATIONS_AVAILABLE"} or
            report.get("root_cause") != "UNKNOWN" or report.get("root_cause_proven") is not False or
            report.get("source_authenticity") != "UNVERIFIED_IMPORT" or
            type(report.get("findings")) is not list or len(report["findings"]) > 1000 or
            type(report.get("coverage")) is not dict):
        raise InvestigationError("INVALID_DELAY_REPORT")
    seen = set()
    for finding in report["findings"]:
        budget.check()
        if (type(finding) is not dict or type(finding.get("finding_id")) is not str or finding["finding_id"] in seen or
                finding.get("category") not in CATEGORIES or finding.get("status") not in STATUSES or
                finding.get("root_cause_proven") is not False or finding.get("source_authenticity") != "UNVERIFIED_IMPORT" or
                type(finding.get("details")) is not dict or type(finding.get("source_nodes")) is not list or
                not 1 <= len(finding["source_nodes"]) <= 16 or
                any(type(ref) is not str or nodes is not None and ref not in nodes for ref in finding["source_nodes"]) or
                any(type(finding.get(key)) is not str or len(finding[key]) > 2048 for key in ("description", "description_ru"))):
            raise InvestigationError("INVALID_DELAY_FINDING")
        seen.add(finding["finding_id"])
        segments = finding.get("critical_path_segments", [])
        if (type(segments) is not list or len(segments) > 16 or
                any(type(ref) is not str or critical_segments is not None and ref not in critical_segments for ref in segments)):
            raise InvestigationError("DANGLING_DELAY_CRITICAL_PATH_REFERENCE")
        if nodes is not None:
            first = nodes[finding["source_nodes"][0]]
            expected_refs = [{"source_identity": nodes[ref].get("source_identity"),
                "source_record_id": nodes[ref].get("source_record_id")} for ref in finding["source_nodes"]]
            if (finding.get("source_record_refs") != expected_refs or
                    any(finding.get(key) != first.get(key) for key in
                        ("process_identity", "thread_identity", "time_domain", "time_bounds"))):
                raise InvestigationError("DELAY_SOURCE_NODE_BINDING_MISMATCH")
        owners = finding["details"].get("reported_owners", [])
        if type(owners) is not list or len(owners) > 16:
            raise InvestigationError("INVALID_DELAY_LOCK_OWNER")
        if owners:
            if finding["category"] != "WCT_CHAIN" or nodes is None:
                raise InvestigationError("UNSUPPORTED_DELAY_LOCK_OWNER_CLAIM")
            expected = [owner for ref in finding["source_nodes"] for owner in _wct_owners(_wct_snapshot(nodes[ref]))]
            if owners != expected:
                raise InvestigationError("UNSUPPORTED_DELAY_LOCK_OWNER_CLAIM")
        details = finding["details"]
        if (details.get("root_cause_proven", False) is not False or details.get("application_delay_proven", False) is not False or
                details.get("lock_owner", "NOT_ESTABLISHED") != "NOT_ESTABLISHED" or
                details.get("waker_is_lock_owner", "NOT_ESTABLISHED") != "NOT_ESTABLISHED" or
                details.get("network_cause_of_delay", "NOT_ESTABLISHED") != "NOT_ESTABLISHED" or
                details.get("queue_delay_ms") is not None or details.get("device_service_ms") is not None):
            raise InvestigationError("UNSUPPORTED_DELAY_CAUSAL_CLAIM")
    return report


def render_delay_html(report):
    """Human-readable supplement to the existing complete JSON/HTML export."""
    if report is None:
        return ""
    # Full node-reference validation happens at the export facade; HTML treats
    # every value as text, including a loaded interpretation's descriptions.
    rows = report.get("findings", []) if type(report) is dict else []
    if type(rows) is not list or len(rows) > 1000:
        raise InvestigationError("INVALID_DELAY_REPORT")
    result = "<h2>Delays and I/O / Задержки и I/O</h2><p>Root cause: UNKNOWN. Imported source statements remain unverified.</p>"
    result += "<table border='1'><tr><th>Observation</th><th>Status</th><th>Source evidence nodes</th></tr>"
    for row in rows:
        if type(row) is not dict:
            raise InvestigationError("INVALID_DELAY_FINDING")
        result += "<tr><td>" + html.escape(str(row.get("description", ""))) + "<br>" + html.escape(str(row.get("description_ru", "")))
        result += "</td><td>" + html.escape(str(row.get("status", ""))) + "</td><td>" + html.escape(", ".join(row.get("source_nodes", []))) + "</td></tr>"
    return result + "</table>"
