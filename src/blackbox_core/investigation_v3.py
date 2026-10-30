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
    from .evidence_normalization import normalize_sources, revalidate_sources
    from .evidence_graph import build_graph
    from .critical_path import analyze_critical_path as path
    from .hypothesis_engine import generate_hypotheses as hypotheses
    from .investigation_planner import suggest_diagnostic_actions as advisor
    from .issue_grouping import group_recurrent_issues as group
    budget = use_budget(budget, cancel_event=cancel_event)
    selected = _context(selection, "SELECTION")
    scenario = _context(scenario, "SCENARIO")
    app_identity = _context(app_identity, "APPLICATION_IDENTITY")
    normalized = normalize_sources(sources, selection=selected, budget=budget)
    case = build_graph(normalized, target_identity=target_identity, scenario=scenario,
                       app_identity=app_identity, budget=budget)
    case["critical_path"] = path(case, budget=budget)
    case["hypotheses"] = hypotheses(case, budget=budget)
    case["actions"] = advisor(case, target_identity=target_identity, budget=budget)
    grouped = group([case], budget=budget)
    case["issues"] = grouped["groups"] + grouped["candidates"]
    case["coverage"]["issue_groups"] = len(grouped["groups"])
    case["coverage"]["candidate_issues"] = len(grouped["candidates"])
    if index_path is not None:
        from .investigation_graph_store import save_investigation
        receipt = save_investigation(case, index_path, budget=budget,
                                    before_publish=lambda: revalidate_sources(normalized, budget=budget))
        case["_index_receipt"] = receipt
    else:
        revalidate_sources(normalized, budget=budget)
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
    return export(case, destination, format=format,
                  budget=use_budget(budget, cancel_event=cancel_event))


def load_investigation(path, *, budget=None, cancel_event=None):
    from .investigation_graph_store import load_investigation as load
    return load(path, budget=use_budget(budget, cancel_event=cancel_event))


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
