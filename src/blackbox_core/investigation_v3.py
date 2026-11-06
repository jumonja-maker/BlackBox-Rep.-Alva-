"""Investigation Engine 3 composes existing recorded diagnostic evidence.

This layer never starts a collector, requests UAC or owns a diagnostic helper.
Native experiments remain explicit steps through BB-DEEP-001.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from .investigation_graph_contracts import InvestigationError, canonical_json, stable_id, use_budget


def _context(value, name):
    if value is None:
        return {}
    if type(value) is not dict or len(canonical_json(value)) > 16384:
        raise InvestigationError("INVALID_INVESTIGATION_" + name)
    return value


def create_investigation(sources, *, target_identity=None, selection=None, scenario=None,
                         app_identity=None, budget=None, cancel_event=None, index_path=None):
    from .deep_tool_contracts import begin_evidence_run, record_evidence_failure
    budget = use_budget(budget, cancel_event=cancel_event)
    context = begin_evidence_run("investigation.create", target=target_identity,
        timeout_seconds=budget.timeout_seconds,
        parameters={"selection": selection or {}, "scenario": scenario or {}})
    try:
        return _create_investigation(sources, target_identity=target_identity, selection=selection,
            scenario=scenario, app_identity=app_identity, budget=budget,
            index_path=index_path, context=context)
    except Exception as error:
        record_evidence_failure(context, error)
        raise


def _create_investigation(sources, *, target_identity=None, selection=None, scenario=None,
                          app_identity=None, budget=None, index_path=None, context=None):
    from .evidence_normalization import normalize_sources, revalidate_sources
    from .evidence_graph import build_graph
    from .critical_path import analyze_critical_path as path
    from .hypothesis_engine import generate_hypotheses as hypotheses
    from .investigation_planner import suggest_diagnostic_actions as advisor
    from .issue_grouping import group_recurrent_issues as group
    budget = use_budget(budget)
    selected = _context(selection, "SELECTION")
    scenario = _context(scenario, "SCENARIO")
    app_identity = _context(app_identity, "APPLICATION_IDENTITY")
    normalized = normalize_sources(sources, selection=selected, budget=budget)
    case = build_graph(normalized, target_identity=target_identity, scenario=scenario,
                       app_identity=app_identity, budget=budget)
    # Each independent projection consumes the same validated base graph.
    # Passing previously derived displays to another algorithm only duplicates
    # metadata in its input budget; it supplies no additional recorded facts.
    grouped = group([case], budget=budget)
    critical = path(case, budget=budget)
    from .crash_investigation import project_crash_evidence
    crash = project_crash_evidence(case, budget=budget)
    from .delay_investigation import analyze_delay
    delay = analyze_delay({**case, "critical_path": critical}, budget=budget)
    generated = hypotheses(case, budget=budget)
    actions = advisor({**case, "hypotheses": generated}, target_identity=target_identity, budget=budget)
    case.update(critical_path=critical, delay_investigation=delay, hypotheses=generated,
                actions=actions, issues=grouped["groups"] + grouped["candidates"], crash_investigation=crash)
    case["coverage"]["issue_groups"] = len(grouped["groups"])
    case["coverage"]["candidate_issues"] = len(grouped["candidates"])
    case["coverage"]["issue_analysis_status"] = "COMPUTED"
    revalidate_sources(normalized, budget=budget)
    from .deep_tool_contracts import attach_evidence_run_receipt
    native_sources = [source for source in case["sources"] if source.get("native_resources_started")]
    native_cleanup = all(source.get("native_resource_cleanup", {}).get("confirmed") is True and
                         source.get("native_resource_cleanup", {}).get("offline_owner_retained") is False
                         for source in native_sources)
    def attach_receipt(value):
        partial = value["coverage"].get("analysis_projection_completeness") == "PARTIAL"
        result = attach_evidence_run_receipt(context, {**value, "status": "COMPLETED"},
            sources=value["sources"], source_revalidated=True, execution_started=True,
            coverage={"completeness": "INCOMPLETE_EVIDENCE" if partial else value["coverage"]["evidence_completeness"],
                      "source_evidence_completeness": value["coverage"]["evidence_completeness"],
                      "analysis_projection_completeness": "PARTIAL" if partial else "COMPLETE",
                      "display_graph_complete": value["coverage"]["display_graph_complete"],
                      "scope": "SOURCE_BOUND_ANALYSIS_NOT_ORIGINAL_CAPTURE_COMPLETENESS"},
            cleanup={"status": "CONFIRMED" if native_cleanup else "NOT_COLLECTED", "confirmed": native_cleanup,
                     "scope": "NORMALIZATION_SOURCE_READ_HANDLES_AND_OFFLINE_UNWIND" if native_sources else
                              "NORMALIZATION_SOURCE_READ_HANDLES",
                     "native_resources_started": bool(native_sources)})
        result.pop("status")  # The actual operation status lives in its receipt.
        return result

    # These paths remain private and are never removed to disguise an oversized
    # result. The aggregate limit includes required receipts and navigation.
    case["_source_paths"] = dict(normalized.get("_source_paths", {}))
    case = attach_receipt(case)
    # Reserve the bounded private publication receipt before publication starts.
    # Its path dominates its size; the remaining fixed schema is below 512 bytes.
    publication_reserve = (len(canonical_json(str(Path(index_path).absolute())).encode("ascii")) + 512
                           if index_path is not None else 0)
    _bound_case_projections(case, budget, reserved_bytes=publication_reserve + 128)
    # Nothing has been published yet: this replaces only an in-process draft
    # receipt, preserving the same actual run context and completed execution.
    case = attach_receipt(case)
    if index_path is not None:
        from .investigation_graph_store import save_investigation
        receipt = save_investigation(case, index_path, budget=budget,
                                    before_publish=lambda: revalidate_sources(normalized, budget=budget))
        case["_index_receipt"] = receipt
    return budget.result(case)


def _case_bytes(value, budget):
    """Count exact canonical bytes without allocating another complete graph."""
    encoder = json.JSONEncoder(sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    size = 0
    for ordinal, part in enumerate(encoder.iterencode(value)):
        if ordinal % 128 == 0:
            budget.check()
        size += len(part)  # ensure_ascii makes character and UTF-8 byte counts equal.
    budget.check()
    return size


def _bound_case_projections(case, budget, *, reserved_bytes=0, refreshed=()):
    """Keep source facts intact when derived displays exceed the aggregate cap.

    Whole optional models are omitted with measured coverage. No displayed
    graph node, recorded source, evidence count or uncertainty is rewritten to
    fit. The critical-path result remains available to its existing standalone
    report/export path. Required metadata plus graph/CP that cannot fit fails.
    """
    coverage = case["coverage"]
    names = {"issues", "actions", "hypotheses", "crash_investigation", "delay_investigation", "critical_path"}
    previous = coverage.get("omitted_models", [])
    if (type(previous) is not list or len(previous) > len(names) or any(
            type(row) is not dict or set(row) != {"model", "reason", "computed_bytes"} or
            type(row.get("model")) is not str or row["model"] not in names or
            row.get("reason") != "AGGREGATE_CASE_RESULT_BYTE_BUDGET" or
            type(row.get("computed_bytes")) is not int or not 0 <= row["computed_bytes"] <= 64 * 1024**2
            for row in previous) or len({row["model"] for row in previous}) != len(previous) or
            any(row["model"] in case and row["model"] not in refreshed for row in previous)):
        raise InvestigationError("INVALID_ANALYSIS_MODEL_OMISSIONS")
    issue_omitted = any(row["model"] == "issues" for row in previous)
    if (issue_omitted and (coverage.get("issue_analysis_status") != "NOT_INCLUDED_BYTE_BUDGET" or
                          "issue_groups" in coverage or "candidate_issues" in coverage) or
            not issue_omitted and coverage.get("issue_analysis_status") == "NOT_INCLUDED_BYTE_BUDGET"):
        raise InvestigationError("INVALID_ANALYSIS_MODEL_OMISSIONS")
    omitted = [dict(row) for row in previous if row["model"] not in refreshed]
    coverage["omitted_models"] = omitted
    coverage["analysis_projection_completeness"] = "PARTIAL" if omitted else "COMPLETE"
    refreshed_limits = {"ANALYSIS_MODEL_NOT_INCLUDED:" + model + ":AGGREGATE_CASE_RESULT_BYTE_BUDGET"
                        for model in refreshed}
    case["limitations"] = [row for row in case.get("limitations", []) if row not in refreshed_limits]
    # Preserve CP; delay references its segments, so dropping only optional
    # delay is safe. Advice derives from hypotheses and is dropped first.
    optional = ("issues", "actions", "hypotheses", "crash_investigation", "delay_investigation")
    size = _case_bytes(case, budget)
    for model in optional:
        if size + reserved_bytes <= budget.max_result_bytes:
            return case
        if model not in case or model == "hypotheses" and case.get("actions"):
            continue  # Never retain advice after removing its supporting model.
        value = case[model]
        model_bytes = _case_bytes(value, budget)
        old_coverage, old_limits = dict(coverage), list(case["limitations"])
        old_coverage["omitted_models"] = [dict(row) for row in omitted]
        metadata_bytes = _case_bytes(old_coverage, budget) + _case_bytes(old_limits, budget)
        omitted.append({"model": model, "reason": "AGGREGATE_CASE_RESULT_BYTE_BUDGET", "computed_bytes": model_bytes})
        coverage["analysis_projection_completeness"] = "PARTIAL"
        case["limitations"].append("ANALYSIS_MODEL_NOT_INCLUDED:" + model + ":AGGREGATE_CASE_RESULT_BYTE_BUDGET")
        if model == "issues":
            coverage.pop("issue_groups", None)
            coverage.pop("candidate_issues", None)
            coverage["issue_analysis_status"] = "NOT_INCLUDED_BYTE_BUDGET"
        # All other fields retain identical objects. Account for this field's
        # colon/comma exactly instead of serializing a large graph per model.
        reduced = (size - model_bytes - len(canonical_json(model)) - 2 +
                   _case_bytes(coverage, budget) + _case_bytes(case["limitations"], budget) - metadata_bytes)
        if reduced >= size:
            # An empty or small computed model costs less than its omission
            # marker. Keep it; declaring it absent would save no memory.
            omitted.pop()
            coverage.clear()
            coverage.update(old_coverage)
            coverage["omitted_models"] = omitted
            case["limitations"] = old_limits
            continue
        case.pop(model)
        size = reduced
    if size + reserved_bytes > budget.max_result_bytes:
        error = InvestigationError("INVESTIGATION_RESULT_BYTE_BUDGET")
        error.actual_result_bytes = size
        error.reserved_result_bytes = reserved_bytes
        error.result_byte_limit = budget.max_result_bytes
        try:
            error.critical_path_bytes = _case_bytes(case.get("critical_path", {}), budget)
            # This includes required run/navigation records and omission
            # metadata, but excludes all six derived model payloads.
            error.retained_graph_bytes = _case_bytes({key: value for key, value in case.items()
                                                      if key not in names}, budget)
        except (InterruptedError, TimeoutError):
            pass  # Diagnostic measurement cannot replace the primary failure.
        raise error
    return case


def build_evidence_graph(sources, **kwargs):
    return create_investigation(sources, **kwargs)


def get_related_evidence(case, node_id, *, after=0, limit=100, budget=None, cancel_event=None):
    from .evidence_graph import get_related_evidence as related
    return related(case, node_id, after=after, limit=limit,
                   budget=use_budget(budget, cancel_event=cancel_event))


def analyze_critical_path(case, *, budget=None, cancel_event=None):
    from .critical_path import analyze_critical_path as analyze
    return analyze(case, budget=use_budget(budget, cancel_event=cancel_event))


def analyze_delay(case, *, budget=None, cancel_event=None):
    from .delay_investigation import analyze_delay as analyze
    return analyze(case, budget=use_budget(budget, cancel_event=cancel_event))


def generate_hypotheses(case, *, budget=None, cancel_event=None):
    from .hypothesis_engine import generate_hypotheses as generate
    return generate(case, budget=use_budget(budget, cancel_event=cancel_event))


def suggest_diagnostic_actions(case, *, hypothesis_id=None, capabilities=None,
                               target_identity=None, budget=None, cancel_event=None):
    from .investigation_planner import suggest_diagnostic_actions as suggest
    return suggest(case, hypothesis_id=hypothesis_id, capabilities=capabilities,
                   target_identity=target_identity, budget=use_budget(budget, cancel_event=cancel_event))


def describe_diagnostic_actions(case, *, operations=None, capabilities=None, target_identity=None,
                                budget=None, cancel_event=None):
    from .investigation_planner import describe_diagnostic_actions as describe
    return describe(case, operations=operations, capabilities=capabilities,
                    target_identity=target_identity, budget=use_budget(budget, cancel_event=cancel_event))


def compare_investigations(first, second, *, budget=None, cancel_event=None):
    from .issue_grouping import compare_investigations as compare
    return compare(first, second, budget=use_budget(budget, cancel_event=cancel_event))


def group_recurrent_issues(cases, *, budget=None, cancel_event=None):
    from .issue_grouping import group_recurrent_issues as group
    return group(cases, budget=use_budget(budget, cancel_event=cancel_event))


def export_investigation(case, destination, *, format="json", budget=None, cancel_event=None):
    from .investigation_graph_store import export_investigation as export
    from .deep_tool_contracts import begin_evidence_run, attach_evidence_run_receipt, record_evidence_failure
    budget = use_budget(budget, cancel_event=cancel_event)
    sources = case.get("sources", []) if type(case) is dict else []
    context = begin_evidence_run("investigation.export", sources=sources,
        timeout_seconds=budget.timeout_seconds, parameters={"format": format})
    try:
        result = export(case, destination, format=format, budget=budget)
        return attach_evidence_run_receipt(context, result, sources=sources,
            execution_started=True,
            coverage={"completeness": "COMPLETE_FOR_EXPORTED_METADATA",
                      "source_capture_completeness": "NOT_ESTABLISHED"},
            cleanup={"status": "CONFIRMED", "confirmed": result.get("readback_verified") is True,
                     "scope": "EXPORT_PRIVATE_FILE_HANDLES_AND_STAGING"})
    except Exception as error:
        record_evidence_failure(context, error, sources=sources)
        raise


def load_investigation(path, *, budget=None, cancel_event=None):
    from .investigation_graph_store import load_investigation as load
    budget = use_budget(budget, cancel_event=cancel_event)
    case = load(path, budget=budget)
    # Recompute this display projection from the validated source-linked graph;
    # an imported cached interpretation never overrides current node/loss rules.
    from .critical_path import analyze_critical_path
    # Remove the old derived displays before recomputing. Their presence must
    # not make the same bounded source graph impossible to reopen.
    case.pop("delay_investigation", None)
    case.pop("critical_path", None)
    case["critical_path"] = analyze_critical_path(case, budget=budget)
    case["delay_investigation"] = analyze_delay(case, budget=budget)
    _bound_case_projections(case, budget, refreshed=("critical_path", "delay_investigation"))
    return budget.result(case)


def prepare_scenario(case, hypothesis_id, *, budget=None, cancel_event=None, **kwargs):
    from .investigation_planner import prepare_scenario as prepare
    return prepare(case, hypothesis_id, budget=use_budget(budget, cancel_event=cancel_event), **kwargs)


def record_experiment_result(case, record, *, budget=None, cancel_event=None):
    from .investigation_planner import record_experiment_result as record_result
    return record_result(case, record, budget=use_budget(budget, cancel_event=cancel_event))


def fork_for_experiment(case, target_identity, *, confirmed=False, budget=None, cancel_event=None):
    """Explicit new measurement target; never rewrite the historical graph's identity."""
    from .deep_contracts import ProcessIdentity
    from .evidence_graph import validate_case
    budget = use_budget(budget, cancel_event=cancel_event)
    validate_case(case, budget=budget)
    if confirmed is not True:
        raise InvestigationError("EXPLICIT_NEW_EXPERIMENT_TARGET_CONFIRMATION_REQUIRED")
    target = ProcessIdentity.from_dict(target_identity).to_dict()
    budget.result(case)
    value = deepcopy(case)
    value.update(case_id=stable_id("experiment-case", case["case_id"], target),
                 origin_case_id=case["case_id"], original_target_identity=case.get("target_identity"),
                 target_identity=target, historical_target_relation="NOT_ESTABLISHED", guided_experiments=[])
    value.pop("_index_receipt", None)
    value["limitations"] = list(dict.fromkeys([*value.get("limitations", []),
        "NEW_EXPERIMENT_TARGET_IS_NOT_AUTOMATICALLY_BOUND_TO_HISTORICAL_EVIDENCE",
        "ORIGINAL_GRAPH_IDENTITIES_AND_TIME_DOMAINS_REMAIN_UNCHANGED"]))
    value["actions"] = suggest_diagnostic_actions(value, target_identity=target, budget=budget)
    validate_case(value, budget=budget)
    return budget.result(value)
