"""Recorded-anchor issue grouping and conservative run comparisons.

Matching hashes, error codes and stacks are recorded observations, not source
authentication or proof of a shared root cause. Manual changes preserve their
USER_REPORTED provenance and never rewrite source events.

An explicit entire-case declaration can enable conditional counts. Hashing a
user-selected file does not establish its binding to historical source events;
such results use a separate mode and never become regression or fix evidence.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
import json
import re
from uuid import UUID

from .evidence_graph import validate_case
from .investigation_graph_contracts import (
    InvestigationError, canonical_json, finite_number, stable_id, use_budget,
)

_SHA = re.compile(r"[0-9a-fA-F]{64}\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_OPERATION = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}(?:/[A-Za-z][A-Za-z0-9_.-]{0,63})?\Z")
_VERIFIED = {"OS_OBSERVED", "QA_VERIFIED_SOURCE_BUILD", "VERIFIED_FILE_SHA256",
             "PE_IDENTITY_MATCH", "RECORDED_VERIFIED_IDENTITY"}
_MATCHED = {"MATCH", "MATCHED", "VERIFIED", "LOADED_PE_IDENTITY_MATCH", "PE_IDENTITY_MATCH"}
_FAILURE_STATUSES = {"ERROR", "FAILED", "OPERATION_FAILED", "ACCESS_DENIED", "ADMIN_REQUIRED",
                     "PROTECTED_PROCESS", "RECOVERY_UNCONFIRMED", "TIMED_OUT"}
_ISSUE_TYPES = {"INCIDENT", "ERROR", "FILE_OPERATION", "NETWORK_OPERATION", "DIAGNOSTIC_ACTION"}


def _bounded_input(value, budget):
    """Check shape/byte bounds before sorting, serialization or deepcopy."""
    pending, count, size = [(value, 0)], 0, 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count % 128 == 0:
            budget.check()
        if depth > 32 or count > 2_000_000:
            raise InvestigationError("ISSUE_INPUT_STRUCTURE_BUDGET")
        if type(item) is dict:
            if len(item) > 512 or any(type(k) is not str or len(k) > 512 for k in item):
                raise InvestigationError("ISSUE_INPUT_FIELDS_BUDGET")
            size += 2 + len(item)
            for key, child in item.items():
                size += len(json.dumps(key, ensure_ascii=True)) + 1
                pending.append((child, depth + 1))
        elif type(item) in (list, tuple):
            if len(item) > 250_000:
                raise InvestigationError("ISSUE_INPUT_ARRAY_BUDGET")
            size += 2 + len(item)
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            if len(item) > 32768 or "\0" in item:
                raise InvestigationError("ISSUE_INPUT_STRING_BUDGET")
            size += len(json.dumps(item, ensure_ascii=True))
        elif item is None or type(item) is bool:
            size += 5
        elif (type(item) is int and -(2**63) <= item <= 2**64 - 1 or
              type(item) is float and finite_number(item)):
            size += len(str(item))
        else:
            raise InvestigationError("INVALID_ISSUE_INPUT_VALUE")
        if size > budget.max_result_bytes:
            raise InvestigationError("ISSUE_INPUT_BYTE_BUDGET")
    budget.check()


def _case(case, budget):
    _bounded_input(case, budget)
    validate_case(case, budget=budget)
    return case


def _application_identity(case, classes):
    value = case.get("app_identity")
    if type(value) is not dict:
        return None
    digest = value.get("sha256")
    family, version = value.get("application_id"), value.get("version")
    verification = value.get("verification_class")
    if (type(digest) is not str or not _SHA.fullmatch(digest) or
            type(verification) is not str or verification not in classes or
            type(family) is not str or _NAME.fullmatch(family) is None or
            type(version) is not str or not 1 <= len(version) <= 128 or
            any(ord(ch) < 32 for ch in version) or any(ch in version for ch in "\\/")):
        return None
    return {"sha256": digest.lower(), "application_id": family, "version": version,
            "verification_class": value["verification_class"]}


def _app(case):
    value = _application_identity(case, _VERIFIED)
    original = case.get("app_identity")
    if value is not None and original.get("source_binding") in ("USER_REPORTED", "NOT_ESTABLISHED"):
        return None
    return value


def _declared_app(case):
    value = _application_identity(case, {"USER_SELECTED_FILE_SHA256"})
    original = case.get("app_identity")
    if (value is None or original.get("source_binding") != "USER_REPORTED" or
            original.get("context_scope") != "ENTIRE_CASE"):
        return None
    return value


def _declared_context(case):
    scenario = case.get("scenario")
    return (_declared_app(case) is not None and _scenario(scenario) and
            scenario.get("verification_class") == "USER_REPORTED")


def _failure(node):
    if node.get("observation_type") not in _ISSUE_TYPES:
        return None
    metadata = node.get("metadata")
    if type(metadata) is not dict:
        return None
    fields = metadata.get("fields") if type(metadata.get("fields")) is dict else {}
    codes = [container[key] for container in (metadata, fields)
             for key in ("error_code", "winerror", "win32_code") if container.get(key) is not None]
    if (not codes or any(type(code) is not int or not 0 < code <= 2**32 - 1 for code in codes) or
            len(set(codes)) != 1):
        return None
    status = metadata.get("status", fields.get("status"))
    if status is not None and (type(status) is not str or status not in _FAILURE_STATUSES):
        return None
    if status is None and node["observation_type"] not in ("ERROR", "INCIDENT"):
        return None
    operation = (metadata.get("operation_kind") or metadata.get("io_kind") or metadata.get("operation") or
                 fields.get("io_kind") or fields.get("operation"))
    if type(operation) is not str or _OPERATION.fullmatch(operation) is None:
        return None
    namespace = "WIN32" if any(container.get(key) is not None for container in (metadata, fields)
                               for key in ("winerror", "win32_code")) else "SOURCE_DEFINED"
    return {"error_code": codes[0], "operation": operation.upper(), "error_namespace": namespace,
            "observation_type": node["observation_type"]}


def _guid(value):
    if type(value) is not str:
        return None
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        return None
    return str(parsed) if parsed.int and str(parsed) == value.lower() else None


def _frame_anchor(node):
    value = node.get("metadata", {})
    frames = value.get("frames")
    if (type(frames) is not list or not 1 <= len(frames) <= 32 or
            value.get("frames_omitted", 0) or value.get("frames_without_function_node", 0) or
            value.get("stack_status") in ("MISSING", "INCOMPLETE", "NOT_COLLECTED", "UNKNOWN")):
        return None
    anchors = []
    for frame in frames:
        if type(frame) is not dict:
            return None
        rva = frame.get("rva")
        module = frame.get("module_identity", frame.get("module"))
        if type(module) is not dict or type(rva) is not int or not 0 <= rva < 2**32:
            return None
        size, timestamp = module.get("image_size"), module.get("image_timestamp")
        if type(size) is not int or not 0 < size <= 2**32 - 1 or rva >= size:
            return None
        digest = module.get("sha256")
        verification, identity_status = module.get("verification_class"), module.get("identity_status")
        matched = (type(verification) is str and verification in _VERIFIED or
                   type(identity_status) is str and identity_status in _MATCHED)
        if type(digest) is str and _SHA.fullmatch(digest) and matched:
            anchors.append({"module_sha256": digest.lower(), "rva": rva})
            continue
        # Reuse the decoder's complete load-window/frame validation when this
        # is its recorded native module contract, rather than trust a GUID label.
        if module.get("schema") == "blackbox.trace-module/1":
            from .decoder_modules import validate_module_frame
            process, times = node.get("process_identity") or {}, node.get("time_bounds") or {}
            if times.get("unit") != "ms":
                return None
            try:
                checked = validate_module_frame({"pid": process.get("pid"),
                    "process_instance": process.get("process_instance"), "time_ms": times.get("start")}, frame)
            except (ValueError, TypeError, KeyError):
                return None
            if checked is None:
                return None
            guid, age = _guid(checked.get("pdb_guid")), checked.get("pdb_age")
        else:
            guid, age = _guid(module.get("guid", module.get("pdb_guid"))), module.get("age", module.get("pdb_age"))
            if not matched:
                return None
        if (guid is None or type(age) is not int or not 1 <= age <= 2**32 - 1 or
                type(timestamp) is not int or not 0 <= timestamp <= 2**32 - 1):
            return None
        anchors.append({"guid": guid, "age": age, "image_size": size,
                        "image_timestamp": timestamp, "rva": rva})
    return anchors


def _fingerprint(case, node, indexed, direct_refs):
    application, failure = _app(case), _failure(node)
    declared = application is None and _declared_context(case)
    if declared:
        application = _declared_app(case)
    stack = node
    reference = (node.get("metadata") or {}).get("stack_ref")
    if type(reference) is str and reference in indexed:
        candidate = indexed[reference]
        direct = (node["node_id"], reference) in direct_refs
        if direct and candidate.get("source_identity") == node.get("source_identity"):
            stack = candidate
    frames = _frame_anchor(stack)
    if application is None or failure is None and frames is None:
        result = {"status": "CANDIDATE", "fingerprint": None,
                "missing": ["VERIFIED_APPLICATION_AND_ERROR_OPERATION_OR_NORMALIZED_MODULE_STACK"],
                "root_cause_established": False}
        selected = _declared_app(case)
        if selected is not None:
            result.update(application_context=selected, source_binding="NOT_ESTABLISHED",
                          context_provenance="USER_REPORTED")
            result["missing"].append("COMPLETE_EXPLICIT_ENTIRE_CASE_CONTEXT_OR_RECORDED_ERROR_STACK")
        return result
    anchors = {"application_id": application["application_id"], "app_sha256": application["sha256"],
               "failure": failure, "stack": frames}
    scenario = case.get("scenario")
    if type(scenario) is dict:
        context = {key: scenario[key] for key in ("scenario_id", "workload_id", "source_profile")
                   if type(scenario.get(key)) is str and _NAME.fullmatch(scenario[key])}
        if context:
            anchors["scenario_context"] = context
    result = {"status": "MATCHING_DECLARED_ANCHORS" if declared else "MATCHING_RECORDED_ANCHORS",
            "fingerprint": stable_id("issue-fingerprint-declared" if declared else "issue-fingerprint", anchors),
            "anchors": anchors, "source_trust": "UNVERIFIED_IMPORT", "root_cause_established": False,
            "limitations": ["MATCHING_ERROR_OR_STACK_DOES_NOT_PROVE_COMMON_ROOT_CAUSE", "SOURCE_HASH_IS_NOT_AUTHENTICATION"]}
    if declared:
        result.update(context_provenance="USER_REPORTED", source_binding="NOT_ESTABLISHED",
                      context_scope="ENTIRE_CASE", conditional=True)
        result["limitations"].extend(["SELECTED_FILE_HASH_DOES_NOT_ESTABLISH_HISTORICAL_SOURCE_BINARY_IDENTITY",
            "APPLICATION_VERSION_AND_WORKLOAD_ARE_USER_DECLARATIONS", "NOT_REGRESSION_OR_FIX_EVIDENCE"])
    return result


def issue_fingerprint(case, node, *, budget=None):
    budget = use_budget(budget)
    _case(case, budget)
    if type(node) is not dict or node not in case["nodes"]:
        raise InvestigationError("ISSUE_NODE_NOT_IN_CASE")
    return budget.result(_fingerprint(case, node, {item["node_id"]: item for item in case["nodes"]},
        {(edge["from_node"], edge["to_node"]) for edge in case["edges"]
         if edge["relation_type"] == "DIRECT_REFERENCE"}))


def _time(item):
    value = item.get("time_bounds")
    if (type(value) is not dict or not finite_number(value.get("start")) or
            not finite_number(value.get("end")) or value["end"] < value["start"] or
            value.get("unit") not in ("ns", "ms", "s")):
        return None
    return value


def _summarize(group):
    occurrences = group["occurrences"]
    group["occurrence_count"] = len(occurrences)
    group["case_ids"] = sorted({item["case_id"] for item in occurrences})
    group["versions"] = sorted({item["application_version"] for item in occurrences
                                if type(item.get("application_version")) is str})
    domains = defaultdict(list)
    for item in occurrences:
        bounds = _time(item)
        if bounds is not None:
            domains[(item["source_identity"], item.get("time_domain"), bounds["unit"])].append(item)
    first = []
    for (source, domain, unit), rows in sorted(domains.items(), key=lambda pair: str(pair[0])):
        earliest_end = min(item["time_bounds"]["end"] for item in rows)
        candidates = [item for item in rows if item["time_bounds"]["start"] <= earliest_end]
        first.append({"source_identity": source, "time_domain": domain, "unit": unit,
                      "status": "EARLIEST_RECORDED_INTERVAL" if len(candidates) == 1 else "OVERLAPPING_FIRST_OBSERVATIONS",
                      "occurrences": sorted(candidates, key=lambda row: row["node_id"])})
    group["first_observations_by_source"] = first
    group["first_observation_across_sources"] = "NOT_ESTABLISHED_FOR_INDEPENDENT_CLOCKS"
    group["observations_without_time"] = sum(_time(item) is None for item in occurrences)
    counts = Counter(item["case_id"] for item in occurrences)
    group["frequency"] = {"unit": "OBSERVATIONS_PER_RECORDED_CASE", "counts": dict(sorted(counts.items())),
                          "elapsed_time_rate": "NOT_ESTABLISHED_ACROSS_INDEPENDENT_CLOCKS"}
    return group


def group_recurrent_issues(cases, *, budget=None):
    budget = use_budget(budget)
    if type(cases) not in (list, tuple) or not 1 <= len(cases) <= 100:
        raise InvestigationError("INVALID_ISSUE_CASE_COLLECTION")
    seen_cases = set()
    for case in cases:
        _case(case, budget)
        identifier = case["case_id"]
        if identifier in seen_cases:
            raise InvestigationError("INVALID_OR_DUPLICATE_ISSUE_CASE_ID")
        seen_cases.add(identifier)
    if sum(len(case["nodes"]) for case in cases) > budget.max_events:
        raise InvestigationError("ISSUE_GROUP_SCAN_BUDGET")
    groups, candidates, examined = {}, [], 0
    by_case = {case["case_id"]: case for case in cases}
    readiness = {case["case_id"]: _workload_ready(case, budget) for case in cases}
    for case in sorted(cases, key=lambda value: value["case_id"]):
        indexed = {node["node_id"]: node for node in case["nodes"]}
        direct_refs = {(edge["from_node"], edge["to_node"]) for edge in case["edges"]
                       if edge["relation_type"] == "DIRECT_REFERENCE"}
        application = _app(case) or _declared_app(case)
        scenario = case.get("scenario") if type(case.get("scenario")) is dict else {}
        seen_records = set()
        for node in case["nodes"]:
            budget.check()
            examined += 1
            if examined > budget.max_events:
                raise InvestigationError("ISSUE_GROUP_SCAN_BUDGET")
            if node["observation_type"] not in _ISSUE_TYPES:
                continue
            if _failure(node) is None and node["observation_type"] not in ("INCIDENT", "ERROR"):
                continue
            key = node["source_identity"], node["source_record_id"]
            if key in seen_records:
                continue
            seen_records.add(key)
            fingerprint = _fingerprint(case, node, indexed, direct_refs)
            occurrence = {"case_id": case["case_id"], "node_id": node["node_id"],
                "source_identity": node["source_identity"], "source_record_id": node["source_record_id"],
                "time_domain": node.get("time_domain"), "time_bounds": deepcopy(node.get("time_bounds")),
                "application_version": application["version"] if application else None,
                "application_sha256": application["sha256"] if application else None,
                "scenario_id": scenario.get("scenario_id")}
            if fingerprint["fingerprint"] is None:
                candidates.append({**occurrence, **fingerprint})
                continue
            group = groups.setdefault(fingerprint["fingerprint"], {"group_id": stable_id("issue-group", fingerprint["fingerprint"]),
                **fingerprint, "occurrences": [], "user_notes": [], "history": []})
            group["occurrences"].append(occurrence)
    for group in groups.values():
        group["occurrences"].sort(key=lambda item: (item["case_id"], item["source_identity"], item["source_record_id"], item["node_id"]))
        _summarize(group)
        declared = group.get("conditional") is True
        group["history"] = [{"case_id": key,
            "application_version": (_app(by_case[key]) or _declared_app(by_case[key]) or {}).get("version"),
            "observed_occurrences": count,
            "verification_class": "USER_REPORTED" if declared else "DERIVED_FROM_RECORDED_ANCHORS",
            "conditional": declared,
            "interpretation": "CONDITIONAL_ON_USER_DECLARED_CONTEXT" if declared else "RECORDED_OBSERVATIONS"}
            for key, count in sorted(Counter(item["case_id"] for item in group["occurrences"]).items())]
        group["frequency"]["conditional"] = declared
        group["frequency"]["per_case_workload"] = [{"case_id": key,
            "recorded_operation_count": by_case[key]["scenario"]["operation_count"] if readiness[key] else None,
            "observed_issue_count": count,
            "issues_per_recorded_operation": count / by_case[key]["scenario"]["operation_count"]
                if readiness[key] else None,
            "interpretation": "RECORDED_SCENARIO_DENOMINATOR_NOT_CAUSAL_RATE"}
            for key, count in group["frequency"]["counts"].items()]
    return budget.result({"status": "COMPLETED", "groups": sorted(groups.values(), key=lambda group: group["group_id"]),
                          "candidates": sorted(candidates, key=lambda row: (row["case_id"], row["node_id"])),
                          "cases_examined": len(cases), "nodes_examined": examined,
                          "root_cause_established": False, "source_events_modified": False})


def _scenario(value):
    if type(value) is not dict or value.get("complete") is not True:
        return False
    if any(type(value.get(key)) is not str or _NAME.fullmatch(value[key]) is None
           for key in ("scenario_id", "workload_id", "source_profile")):
        return False
    return (type(value.get("operation_count")) is int and 0 < value["operation_count"] <= 2**63 - 1 and
            type(value.get("input_bytes")) is int and 0 <= value["input_bytes"] <= 2**63 - 1)


def _source_ready(source, coverage):
    if (source.get("source_consistency") != "STABLE_HASHED_NO_ACTIVE_WAL" or
            type(coverage) is not dict or source.get("scan_complete") is not True):
        return False
    kind = source.get("source_type")
    if kind == "EVENTS_JSONL":
        return (source.get("application_events_complete") is True and
            source.get("application_client_dropped_total") == 0 and
            type(source.get("application_client_dropped_total")) is int and
            source.get("application_order_errors") == 0 and type(source.get("application_order_errors")) is int and
            source.get("application_sequence_gaps") == 0 and type(source.get("application_sequence_gaps")) is int and
            type(source.get("events_scanned")) is int and source["events_scanned"] > 0 and
            source.get("selected_events") == source["events_scanned"])
    if kind == "TRACE_INDEX":
        trace_hash = source.get("trace_input_sha256")
        return (type(trace_hash) is str and _SHA.fullmatch(trace_hash) is not None and
                source.get("decoded_status") == "DECODED" and
                type(source.get("decoder_reported_lost_events")) is int and source["decoder_reported_lost_events"] == 0 and
                source.get("out_of_order_events") is False and source.get("decode_errors_observed") is False and
                type(source.get("event_sequence_gaps")) is int and source["event_sequence_gaps"] == 0 and
                type(coverage.get("events_scanned")) is int and coverage["events_scanned"] > 0 and
                coverage.get("events_scanned") == coverage.get("events_total_after_cursor") and
                type(coverage.get("selected_events")) is int and coverage["selected_events"] == coverage["events_scanned"])
    if kind == "DEEP_JOURNAL":
        return (source.get("selected_prefix_complete") is True and coverage.get("hash_chain_checked") is True and
                type(source.get("journal_records_checked")) is int and source["journal_records_checked"] > 0 and
                source["journal_records_checked"] == source.get("journal_records_total"))
    if kind == "SESSION":
        return (source.get("source_closed") is True and type(source.get("writer_dropped_commands")) is int and
                source["writer_dropped_commands"] == 0 and type(source.get("sensor_errors_count")) is int and
                source["sensor_errors_count"] == 0 and type(source.get("samples_total")) is int and source["samples_total"] > 1)
    return False


def _workload_ready(case, budget=None):
    if not _scenario(case.get("scenario")):
        return False
    coverage = case.get("coverage")
    if (type(coverage) is not dict or coverage.get("has_more") is not False or
            coverage.get("display_graph_complete") is not True or
            any(type(coverage.get(key)) is not int or coverage[key] != 0
                for key in ("events_omitted", "nodes_omitted", "edges_omitted")) or coverage.get("next_cursor") != []):
        return False
    for key in ("incomplete_sources", "source_errors", "reported_lost_events"):
        if key in coverage and (type(coverage[key]) is not int or coverage[key] != 0):
            return False
    recorded = coverage.get("source_coverage")
    if type(recorded) is not list or len(recorded) != len(case.get("sources", [])):
        return False
    by_source = {item.get("source_id"): item for item in recorded
                 if type(item) is dict and type(item.get("source_id")) is str}
    if len(by_source) != len(recorded):
        return False
    if not case.get("sources") or not all(_source_ready(source, by_source.get(source["source_id"])) for source in case["sources"]):
        return False
    if any(source["source_type"] == "EVENTS_JSONL" for source in case["sources"]):
        operations = set()
        for node in case["nodes"]:
            if budget is not None:
                budget.check()
            metadata = node["metadata"]
            if node["source_type"] == "EVENTS_JSONL" and metadata.get("event_kind") == "io.operation.end":
                if (type(metadata.get("operation_id")) is not str or not metadata["operation_id"] or
                        type(metadata.get("operation_scope")) is not str or not metadata["operation_scope"]):
                    return False
                operations.add((node["source_identity"], metadata["operation_scope"], metadata["operation_id"]))
        if len(operations) != case["scenario"]["operation_count"]:
            return False
    return True


def _capture_keys(case):
    result = set()
    for source in case["sources"]:
        digest = source.get("trace_input_sha256") if source["source_type"] == "TRACE_INDEX" else None
        if type(digest) is not str or _SHA.fullmatch(digest) is None:
            digest = source["source_sha256"]
        result.add((source["source_type"], digest.lower()))
    return result


def _comparison_checks(first, second, budget, applications, mode):
    app1, app2 = applications
    checks = [("APPLICATION_CONTEXT", mode is not None),
              ("APPLICATION_IDENTITY", bool(app1 and app2 and app1["application_id"] == app2["application_id"])),
              ("VERSION_BUILD_IDENTITY", bool(app1 and app2 and
                  (app1["version"] == app2["version"] or app1["sha256"] != app2["sha256"]))),
              ("SESSION_IDENTITIES", first["case_id"] != second["case_id"] and
                   not bool(_capture_keys(first) & _capture_keys(second)))]
    scenario1 = first.get("scenario") if type(first.get("scenario")) is dict else {}
    scenario2 = second.get("scenario") if type(second.get("scenario")) is dict else {}
    checks.append(("TYPED_COMPLETE_SCENARIO", _scenario(scenario1) and _scenario(scenario2)))
    for key in ("scenario_id", "workload_id", "operation_count", "input_bytes", "source_profile"):
        checks.append((key.upper(), key in scenario1 and key in scenario2 and scenario1[key] == scenario2[key]))
    checks.append(("SUFFICIENT_RECORDED_COVERAGE", _workload_ready(first, budget) and _workload_ready(second, budget)))
    checks.append(("COMPARABLE_SOURCES", Counter(source["source_type"] for source in first["sources"]) ==
                   Counter(source["source_type"] for source in second["sources"])))
    return [{"condition": key, "passed": bool(value)} for key, value in checks]


def compare_investigations(first, second, *, budget=None):
    budget = use_budget(budget)
    _case(first, budget)
    _case(second, budget)
    applications = _app(first), _app(second)
    mode = "RECORDED_SOURCE_ANCHORS" if all(applications) else None
    if mode is None and _declared_context(first) and _declared_context(second):
        applications = _declared_app(first), _declared_app(second)
        mode = "DECLARED_ENTIRE_CASE"
    declared = mode == "DECLARED_ENTIRE_CASE"
    checks = _comparison_checks(first, second, budget, applications, mode)
    reasons = [item["condition"] for item in checks if not item["passed"]]
    result = {"status": "NOT_COMPARABLE" if reasons else
              "COMPARABLE_WITH_DECLARED_CONTEXT" if declared else "COMPARABLE", "checks": checks,
        "reasons": reasons, "first_case_id": first["case_id"], "second_case_id": second["case_id"],
        "interpretation": "OBSERVED_DIFFERENCES_NOT_PROOF_OF_FIX_OR_CAUSATION", "root_cause_established": False}
    if declared:
        result.update(context_provenance="USER_REPORTED", source_binding="NOT_ESTABLISHED",
                      context_scope="ENTIRE_CASE", conditional=True,
                      interpretation="CONDITIONAL_OBSERVATIONS_NOT_REGRESSION_OR_FIX_EVIDENCE",
                      limitations=["SELECTED_FILE_HASH_DOES_NOT_ESTABLISH_HISTORICAL_SOURCE_BINARY_IDENTITY",
                          "APPLICATION_VERSION_AND_WORKLOAD_ARE_USER_DECLARATIONS"])
    if reasons:
        return budget.result(result)
    def failures(case):
        counts, seen = Counter(), set()
        for node in case["nodes"]:
            budget.check()
            identity = node["source_identity"], node["source_record_id"]
            failure = _failure(node)
            if failure and identity not in seen:
                seen.add(identity)
                counts[canonical_json(failure)] += 1
        return counts
    old, new = failures(first), failures(second)
    result["differences"] = [{"recorded_error": json.loads(json_value), "first_count": old[json_value], "second_count": new[json_value],
        "delta": new[json_value] - old[json_value],
        "absence_means": "NOT_OBSERVED_WITH_USER_DECLARED_CONTEXT" if declared else "NOT_OBSERVED_IN_THIS_COMPARABLE_RUN",
        "conditional": declared}
        for json_value in sorted(old.keys() | new.keys())]
    result["versions"] = [app["version"] for app in applications]
    return budget.result(result)


def manual_group_change(grouping, *, action, group_ids, reason, case_ids=None, budget=None):
    budget = use_budget(budget)
    _bounded_input(grouping, budget)
    if type(grouping) is not dict or type(grouping.get("groups")) is not list:
        raise InvestigationError("INVALID_MANUAL_GROUPING_INPUT")
    if "manual_history" in grouping and type(grouping["manual_history"]) is not list:
        raise InvestigationError("INVALID_MANUAL_GROUP_HISTORY")
    if action not in ("MERGE", "SPLIT") or type(reason) is not str or not reason.strip() or len(reason) > 4096 or "\0" in reason:
        raise InvestigationError("MANUAL_GROUP_CHANGE_REQUIRES_REASON")
    if (type(group_ids) is not list or not 1 <= len(group_ids) <= 100 or
            any(type(item) is not str or not 1 <= len(item) <= 256 for item in group_ids) or
            len(set(group_ids)) != len(group_ids)):
        raise InvestigationError("INVALID_MANUAL_GROUP_IDS")
    if case_ids is not None and (type(case_ids) is not list or not 1 <= len(case_ids) <= 100 or
            any(type(item) is not str or not 1 <= len(item) <= 256 for item in case_ids) or len(set(case_ids)) != len(case_ids)):
        raise InvestigationError("INVALID_MANUAL_SPLIT_CASE_IDS")
    groups = grouping["groups"]
    if any(type(group) is not dict or type(group.get("group_id")) is not str or
           type(group.get("occurrences")) is not list for group in groups):
        raise InvestigationError("INVALID_MANUAL_GROUP_RECORD")
    if len({group["group_id"] for group in groups}) != len(groups):
        raise InvestigationError("DUPLICATE_MANUAL_GROUP_ID")
    selected = [group for group in groups if group["group_id"] in group_ids]
    if len(selected) != len(group_ids):
        raise InvestigationError("MANUAL_GROUP_NOT_FOUND")
    for group in selected:
        if (type(group.get("history", [])) is not list or type(group.get("user_notes", [])) is not list or
                group.get("fingerprint") is not None and type(group["fingerprint"]) is not str or
                type(group.get("original_fingerprints", [])) is not list or
                any(type(item) is not str for item in group.get("original_fingerprints", []))):
            raise InvestigationError("INVALID_MANUAL_GROUP_HISTORY")
        for item in group["occurrences"]:
            if type(item) is not dict or any(type(item.get(key)) is not str or not item[key]
                    for key in ("case_id", "node_id", "source_identity", "source_record_id")) or (
                    item.get("time_domain") is not None and type(item["time_domain"]) is not str):
                raise InvestigationError("INVALID_MANUAL_GROUP_OCCURRENCE")
    # The source passes shape/byte checks before a potentially costly copy.
    budget.check()
    value = deepcopy(grouping)
    selected = [group for group in value["groups"] if group["group_id"] in group_ids]
    original = [item for group in selected for item in group["occurrences"]]
    seen, unique = set(), []
    for item in original:
        key = item["case_id"], item["node_id"], item["source_identity"], item["source_record_id"]
        if key not in seen:
            seen.add(key)
            unique.append(item)
    original = sorted(unique, key=lambda item: (item["case_id"], item["source_identity"], item["source_record_id"], item["node_id"]))
    if action == "MERGE":
        if len(selected) < 2:
            raise InvestigationError("MANUAL_MERGE_NEEDS_TWO_GROUPS")
        partitions = [original]
    else:
        chosen = set(case_ids or [])
        if not chosen <= {item["case_id"] for item in original}:
            raise InvestigationError("MANUAL_SPLIT_UNKNOWN_CASE")
        partitions = [[item for item in original if item["case_id"] not in chosen],
                      [item for item in original if item["case_id"] in chosen]]
        if len(selected) != 1 or not all(partitions):
            raise InvestigationError("MANUAL_SPLIT_REQUIRES_NONEMPTY_PARTITIONS")
    if not original:
        raise InvestigationError("MANUAL_GROUP_REQUIRES_OCCURRENCES")
    changes = [group.get("history", []) for group in selected]
    notes = [note for group in selected for note in group.get("user_notes", [])]
    fingerprints = {fingerprint for group in selected for fingerprint in
                    ([group["fingerprint"]] if group.get("fingerprint") else []) + group.get("original_fingerprints", [])}
    replacements = []
    for index, rows in enumerate(partitions):
        replacement = {"group_id": stable_id("manual-group", action, sorted(group_ids), index, reason, sorted(case_ids or [])),
            "occurrences": rows, "status": "USER_CONFIRMED", "verification_class": "USER_REPORTED",
            "user_confirmation_scope": "GROUP_MEMBERSHIP_ONLY", "root_cause_established": False,
            "source_binding": "NOT_ESTABLISHED", "conditional": True,
            "source_trust": "UNVERIFIED_IMPORT", "fingerprint": None,
            "original_fingerprints": sorted(fingerprints),
            "history": [entry for history in changes for entry in history], "user_notes": notes}
        replacements.append(_summarize(replacement))
        replacement["frequency"]["conditional"] = True
    value["groups"] = sorted([group for group in value["groups"] if group["group_id"] not in group_ids] + replacements,
                             key=lambda group: group["group_id"])
    value.setdefault("manual_history", []).append({"change_id": stable_id("group-change", action, sorted(group_ids), sorted(case_ids or []), reason),
        "action": action, "previous_groups": selected, "new_group_ids": [item["group_id"] for item in replacements],
        "reason": reason.strip(), "verification_class": "USER_REPORTED", "source_events_modified": False,
        "root_cause_established": False})
    return budget.result(value)
