"""Investigation Engine 3 composes existing recorded diagnostic evidence.

This layer never starts a collector, requests UAC or owns a diagnostic helper.
Native experiments remain explicit steps through BB-DEEP-001.
"""
from __future__ import annotations

from copy import deepcopy
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
    case["critical_path"] = path(case, budget=budget)
    from .delay_investigation import analyze_delay
    case["delay_investigation"] = analyze_delay(case, budget=budget)
    case["hypotheses"] = hypotheses(case, budget=budget)
    case["actions"] = advisor(case, target_identity=target_identity, budget=budget)
    grouped = group([case], budget=budget)
    case["issues"] = grouped["groups"] + grouped["candidates"]
    case["coverage"]["issue_groups"] = len(grouped["groups"])
    case["coverage"]["candidate_issues"] = len(grouped["candidates"])
    from .crash_investigation import project_crash_evidence
    case["crash_investigation"] = project_crash_evidence(case, budget=budget)
    revalidate_sources(normalized, budget=budget)
    from .deep_tool_contracts import attach_evidence_run_receipt
    native_sources = [source for source in case["sources"] if source.get("native_resources_started")]
    native_cleanup = all(source.get("native_resource_cleanup", {}).get("confirmed") is True and
                         source.get("native_resource_cleanup", {}).get("offline_owner_retained") is False
                         for source in native_sources)
    case = attach_evidence_run_receipt(context, {**case, "status": "COMPLETED"},
        sources=case["sources"], source_revalidated=True, execution_started=True,
        coverage={"completeness": case["coverage"]["evidence_completeness"],
                  "display_graph_complete": case["coverage"]["display_graph_complete"],
                  "scope": "SOURCE_BOUND_ANALYSIS_NOT_ORIGINAL_CAPTURE_COMPLETENESS"},
        cleanup={"status": "CONFIRMED" if native_cleanup else "NOT_COLLECTED", "confirmed": native_cleanup,
                 "scope": "NORMALIZATION_SOURCE_READ_HANDLES_AND_OFFLINE_UNWIND" if native_sources else
                          "NORMALIZATION_SOURCE_READ_HANDLES",
                 "native_resources_started": bool(native_sources)})
    case.pop("status")  # Keep the existing case schema; status lives in its receipt.
    if index_path is not None:
        from .investigation_graph_store import save_investigation
        receipt = save_investigation(case, index_path, budget=budget,
                                    before_publish=lambda: revalidate_sources(normalized, budget=budget))
        case["_index_receipt"] = receipt
    # Navigation paths are session-private and excluded by every store/export.
    case["_source_paths"] = dict(normalized.get("_source_paths", {}))
    return budget.result(case)


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
    case["critical_path"] = analyze_critical_path(case, budget=budget)
    case["delay_investigation"] = analyze_delay(case, budget=budget)
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
