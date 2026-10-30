"""Deterministic, source-linked diagnostic hypotheses, without causal scores."""
from __future__ import annotations

from collections import defaultdict

from .investigation_graph_contracts import (
    SCHEMA, HYPOTHESIS_STATUSES, InvestigationError, canonical_json, finite_number,
    stable_id, use_budget,
)

CATEGORIES = ("HIGH_CPU", "EXECUTION_DELAY", "WAIT_OR_DEADLOCK", "MEMORY_GROWTH",
              "FILE_OPERATION_ERROR", "NETWORK_PROBLEM", "UNEXPECTED_EXIT",
              "UI_UNRESPONSIVE", "DIAGNOSTIC_ACTION_FAILED")

_TEXT = {
    "HIGH_CPU": ("Recorded CPU evidence may identify work contributing to the selected incident.",
                 "Данные CPU могут указать работу, связанную с выбранным инцидентом."),
    "EXECUTION_DELAY": ("The source records a delay; the operation limiting completion is not established.",
                        "Источник записал задержку; операция, ограничившая завершение, не установлена."),
    "WAIT_OR_DEADLOCK": ("Recorded waiting warrants inspecting the observed dependencies; a deadlock is not inferred from a wait reason.",
                         "Записанное ожидание требует проверки зависимостей; причина ожидания сама по себе не доказывает взаимоблокировку."),
    "MEMORY_GROWTH": ("Comparable observations show memory growth; cache, workload and allocation lifetime remain alternatives.",
                      "Сопоставимые наблюдения показывают рост памяти; возможны кэширование, иная нагрузка и срок жизни выделений."),
    "FILE_OPERATION_ERROR": ("A source reports a failed file operation; its identity and error provenance must be reviewed.",
                             "Источник сообщил об ошибке файловой операции; требуется проверить её идентичность и источник кода ошибки."),
    "NETWORK_PROBLEM": ("Recorded network activity may be relevant; metadata alone does not establish a network failure.",
                        "Сетевая активность может быть связана с проблемой; одни метаданные не доказывают сетевой сбой."),
    "UNEXPECTED_EXIT": ("The source records process termination; whether it was unexpected or a crash requires separate evidence.",
                        "Источник записал завершение процесса; неожиданность завершения и авария требуют отдельных доказательств."),
    "UI_UNRESPONSIVE": ("A source records an unresponsive-window observation; inspect the responsible thread and available coverage.",
                        "Источник записал неотзывчивость окна; исследуйте соответствующий поток и полноту наблюдений."),
    "DIAGNOSTIC_ACTION_FAILED": ("A diagnostic action did not produce a confirmed successful result; review its status before another action.",
                                 "Диагностическое действие не дало подтверждённого успешного результата; проверьте статус перед следующим действием."),
}

_ACTIONS = {
    "HIGH_CPU": ["thread_stacks", "profile.etw", "trace_evidence"],
    "EXECUTION_DELAY": ["wait_chains", "profile.etw", "snapshot"],
    "WAIT_OR_DEADLOCK": ["wait_chains", "thread_stacks", "profile.etw"],
    "MEMORY_GROWTH": ["memory_map", "dump", "snapshot"],
    "FILE_OPERATION_ERROR": ["handles", "disk", "profile.etw"],
    "NETWORK_PROBLEM": ["network", "profile.etw"],
    "UNEXPECTED_EXIT": ["trace_evidence", "dump_inspect"],
    "UI_UNRESPONSIVE": ["wait_chains", "thread_stacks", "profile.etw"],
    "DIAGNOSTIC_ACTION_FAILED": ["capabilities", "timeline"],
}

_ALTERNATIVES = {
    "HIGH_CPU": ["EXPECTED_WORKLOAD", "OTHER_EXECUTION_BETWEEN_SAMPLES", "OBSERVER_EFFECT"],
    "EXECUTION_DELAY": ["EXTERNAL_WAIT", "READY_QUEUE_DELAY", "UNOBSERVED_APPLICATION_WORK"],
    "WAIT_OR_DEADLOCK": ["EXPECTED_SYNCHRONIZATION", "EXTERNAL_RESOURCE_WAIT", "SCHEDULER_DELAY"],
    "MEMORY_GROWTH": ["RETAINED_CACHE", "DELAYED_GC", "DIFFERENT_WORKLOAD", "OBJECT_RETENTION"],
    "FILE_OPERATION_ERROR": ["ACCESS_POLICY", "RESOURCE_LIFETIME_CHANGE", "APPLICATION_REPORTED_ERROR"],
    "NETWORK_PROBLEM": ["EXPECTED_TRANSFER", "REMOTE_ENDPOINT_BEHAVIOR", "UNOBSERVED_NETWORK_ACTIVITY"],
    "UNEXPECTED_EXIT": ["NORMAL_COMPLETION", "USER_REQUESTED_EXIT", "EXTERNAL_TERMINATION", "PROCESS_FAILURE"],
    "UI_UNRESPONSIVE": ["LONG_WINDOW_HANDLER", "LOCK_OR_EXTERNAL_WAIT", "SCHEDULING_DELAY"],
    "DIAGNOSTIC_ACTION_FAILED": ["INSUFFICIENT_RIGHTS", "TARGET_CHANGED", "CANCELLATION", "INCOMPLETE_ACKNOWLEDGEMENT"],
}

_MISSING = {
    "HIGH_CPU": ["COMPARABLE_CPU_COUNTER_COVERAGE", "REPRESENTATIVE_STACKS", "MATCHED_WORKLOAD_CONTROLS"],
    "EXECUTION_DELAY": ["OPERATION_BOUNDARIES", "COMPLETE_SCHEDULER_CHAIN", "EXTERNAL_DEPENDENCY_EVIDENCE"],
    "WAIT_OR_DEADLOCK": ["LOCK_OR_OBJECT_IDENTITY", "TIME_LOCAL_OWNER_EVIDENCE", "COMPLETE_WAIT_DEPENDENCY_CYCLE"],
    "MEMORY_GROWTH": ["ALLOCATION_LIFETIMES", "OBJECT_RETENTION_EVIDENCE", "MATCHED_WORKLOAD_AND_GC_CONTROLS"],
    "FILE_OPERATION_ERROR": ["SOURCE_AUTHENTICITY", "EXACT_OPERATION_IDENTITY_ACROSS_SOURCES", "MATCHED_RETRY_CONTROL"],
    "NETWORK_PROBLEM": ["PROTOCOL_RESULT_OR_ERROR", "ENDPOINT_LIFETIME", "MATCHED_TRANSFER_CONTROL"],
    "UNEXPECTED_EXIT": ["EXPECTED_EXIT_POLICY", "CONFIRMED_EXIT_STATUS", "EXCEPTION_OR_TERMINATION_SOURCE"],
    "UI_UNRESPONSIVE": ["RELEVANT_WINDOW_THREAD", "TIME_LOCAL_WAIT_CHAIN", "HANDLER_AND_SCHEDULING_COVERAGE"],
    "DIAGNOSTIC_ACTION_FAILED": ["ACTUAL_CAPABILITY_RESULT", "DURABLE_RESULT_AND_CLEANUP_ACKNOWLEDGEMENT"],
}


def _records(node):
    metadata = node.get("metadata", {})
    if type(metadata) is not dict:
        return []
    values = [metadata]
    for key in ("attributes", "facts", "data", "detail", "context"):
        value = metadata.get(key)
        if type(value) is dict:
            values.append(value)
        elif type(value) is list:
            values.extend(item for item in value[:16] if type(item) is dict)
    return values


def _codes(node):
    return {str(record.get(key, "")).upper() for record in _records(node)
            for key in ("code", "event_kind", "event_name", "trigger_code", "kind")}


def _suffix(codes, wanted):
    return any(code == item or code.endswith("_" + item) for code in codes for item in wanted)


def _error(node):
    for row in _records(node):
        status = str(row.get("status", row.get("result", ""))).upper()
        code = row.get("error_code", row.get("winerror", row.get("win32_code")))
        if status in {"ERROR", "FAILED", "OPERATION_FAILED", "ACCESS_DENIED", "FAILURE"}:
            return True
        if type(code) is int and code != 0:
            return True
    return False


def _memory_growth(nodes, budget):
    grouped = defaultdict(list)
    selected = []
    for node in nodes:
        budget.check()
        if node.get("observation_type") != "MEASUREMENT":
            continue
        row, bounds = node.get("metadata", {}), node.get("time_bounds")
        metrics = row.get("metrics", {})
        if (type(metrics) is not dict or type(bounds) is not dict or
                not finite_number(bounds.get("start")) or
                type(row.get("series_seq")) is not int or type(node.get("process_identity")) is not dict):
            continue
        key = (node.get("source_identity"), node.get("time_domain"),
               canonical_json(node["process_identity"]), row.get("series", ""))
        grouped[key].append(node)
    for observations in grouped.values():
        observations.sort(key=lambda node: (node["metadata"]["series_seq"], node["node_id"]))
        previous = None
        for node in observations:
            if previous is not None:
                first, second = previous["metadata"], node["metadata"]
                a, b = previous["time_bounds"]["start"], node["time_bounds"]["start"]
                continuous = second["series_seq"] == first["series_seq"] + 1 and b > a
                if continuous and any(finite_number(first["metrics"].get(key)) and
                        finite_number(second["metrics"].get(key)) and
                        second["metrics"][key] > first["metrics"][key] >= 0
                        for key in ("rss_bytes", "private_bytes")):
                    selected.extend((previous, node))
            previous = node
    return selected


def generate_hypotheses(case, *, budget=None):
    """Generate candidates/support statements, never a percentage or root cause."""
    budget = use_budget(budget)
    if (type(case) is not dict or case.get("schema") != SCHEMA or
            type(case.get("nodes")) is not list or len(case["nodes"]) > budget.max_nodes):
        raise InvestigationError("INVALID_HYPOTHESIS_CASE")
    nodes = case["nodes"]
    by_id, groups = {}, defaultdict(list)
    observed_cpu = set()
    for node in nodes:
        budget.check()
        if (type(node) is not dict or type(node.get("node_id")) is not str or
                node["node_id"] in by_id or type(node.get("metadata", {})) is not dict):
            raise InvestigationError("INVALID_HYPOTHESIS_NODE")
        by_id[node["node_id"]] = node
        kind, row, codes = node.get("observation_type"), node.get("metadata", {}), _codes(node)
        if kind == "CPU_SAMPLE":
            groups["HIGH_CPU"].append(node)
        if _suffix(codes, {"CPU_SUSTAINED", "HIGH_CPU"}):
            groups["HIGH_CPU"].append(node)
            observed_cpu.add(node["node_id"])
        metrics = row.get("metrics", {})
        if type(metrics) is dict and finite_number(metrics.get("cpu_percent")) and metrics["cpu_percent"] >= 80:
            groups["HIGH_CPU"].append(node)
            observed_cpu.add(node["node_id"])
        if kind == "WAIT_INTERVAL":
            groups["WAIT_OR_DEADLOCK"].append(node)
            if finite_number(row.get("off_cpu_ms")) and row["off_cpu_ms"] > 0:
                groups["EXECUTION_DELAY"].append(node)
        if _suffix(codes, {"WCT_CYCLE", "WAIT_CHAIN", "WAIT_OBSERVED", "DEADLOCK_CANDIDATE"}):
            groups["WAIT_OR_DEADLOCK"].append(node)
        if _suffix(codes, {"RSS_GROWTH", "PRIVATE_GROWTH", "MEMORY_GROWTH"}):
            groups["MEMORY_GROWTH"].append(node)
        file_kind = kind == "FILE_OPERATION" or any("IO.OPERATION" in code or "FILE" in code for code in codes)
        if file_kind and _error(node):
            groups["FILE_OPERATION_ERROR"].append(node)
        if kind == "NETWORK_OPERATION" or _suffix(codes, {"NETWORK_ERROR", "NETWORK_TIMEOUT"}):
            groups["NETWORK_PROBLEM"].append(node)
        if _suffix(codes, {"PROCESS_EXIT_OBSERVED", "PROCESS_EXIT", "UNEXPECTED_EXIT", "PROCESS_TERMINATED"}):
            groups["UNEXPECTED_EXIT"].append(node)
        if _suffix(codes, {"UI_TIMEOUT", "UI_UNRESPONSIVE", "WINDOW_UNRESPONSIVE", "WM_NULL_TIMEOUT"}):
            groups["UI_UNRESPONSIVE"].append(node)
        if kind == "DIAGNOSTIC_ACTION" and row.get("phase") == "RESULT":
            if row.get("status") not in {"COMPLETED", "AVAILABLE", "DETACHED"}:
                groups["DIAGNOSTIC_ACTION_FAILED"].append(node)
    groups["MEMORY_GROWTH"].extend(_memory_growth(nodes, budget))
    hypotheses = []
    edges = case.get("edges", [])
    if type(edges) is not list or len(edges) > budget.max_edges:
        raise InvestigationError("INVALID_HYPOTHESIS_EDGES")
    for category in CATEGORIES:
        budget.check()
        supporting = sorted({node["node_id"] for node in groups.get(category, [])})
        if not supporting:
            continue
        contradictions = set()
        for edge in edges:
            if (type(edge) is dict and edge.get("relation_type") == "CONTRADICTED" and
                    edge.get("relation") in {"CONTRADICTS_OBSERVATION", "EXPLICIT_MEASUREMENT_CONTRADICTION"}):
                if edge.get("from_node") in supporting and edge.get("to_node") in by_id:
                    contradictions.add(edge["to_node"])
                elif edge.get("to_node") in supporting and edge.get("from_node") in by_id:
                    contradictions.add(edge["from_node"])
        status = "SUPPORTED_BY_OBSERVATION"
        if category == "HIGH_CPU" and not set(supporting) & observed_cpu:
            status = "CANDIDATE"
        if category in {"NETWORK_PROBLEM", "UNEXPECTED_EXIT"}:
            status = "CANDIDATE"
        if category == "WAIT_OR_DEADLOCK" and not any(
                node["metadata"].get("quality") == "OBSERVED_SWITCH_PAIR" for node in groups[category]):
            status = "CANDIDATE"
        if contradictions:
            status = "INCONCLUSIVE"
        description, description_ru = _TEXT[category]
        hypotheses.append({"hypothesis_id": stable_id("hypothesis", case.get("case_id"), category, supporting),
            "category": category, "description_code": "INV_" + category,
            "description": description, "description_ru": description_ru,
            "supporting_nodes": supporting[:200], "supporting_nodes_omitted": max(0, len(supporting)-200),
            "contradicting_nodes": sorted(contradictions)[:200],
            "alternatives": _ALTERNATIVES[category], "missing_data": _MISSING[category],
            "validation_method": "EXPLICIT_DIAGNOSTIC_ACTION_AND_COMPARABLE_REPEATED_MEASUREMENTS_WITH_CONTROLS",
            "status": status, "next_actions": _ACTIONS[category], "verification_class": "DERIVED",
            "root_cause_proven": False, "source_statement_count": len(supporting),
            "limitations": ["SOURCE_STATEMENTS_ARE_NOT_AUTHENTICATED", "OBSERVATION_IS_NOT_INTERNAL_ROOT_CAUSE",
                "TEMPORAL_ASSOCIATION_IS_NOT_CAUSATION", "MISSING_EVIDENCE_IS_NOT_NEGATIVE_EVIDENCE"]})
    return budget.result(hypotheses)


def record_hypothesis_verdict(hypothesis, status, *, user_note, budget=None):
    """Record an explicitly attributed human conclusion, without changing facts."""
    budget = use_budget(budget)
    if (type(hypothesis) is not dict or status not in HYPOTHESIS_STATUSES or
            status not in {"USER_CONFIRMED", "CONTRADICTED", "INCONCLUSIVE"} or
            type(user_note) is not str or not 1 <= len(user_note.strip()) <= 4096):
        raise InvestigationError("INVALID_USER_HYPOTHESIS_VERDICT")
    return budget.result({**hypothesis, "status": status, "user_verdict": {
        "actor": "USER", "note": user_note, "verification_class": "USER_REPORTED",
        "previous_status": hypothesis.get("status")}, "root_cause_proven": False})
