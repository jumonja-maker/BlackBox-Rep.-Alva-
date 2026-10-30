"""Descriptive next actions and manually recorded experiment steps.

This module never creates a helper, requests UAC, executes an ActionRequest,
or retries an operation. The existing Overview/InspectorService path retains
all authority, confirmations, resource ownership and cleanup.
"""
from __future__ import annotations

from .deep_contracts import DEEP_ACTIONS
from .deep_journal import journal_metadata
from .investigation_graph_contracts import SCHEMA, InvestigationError, stable_id, use_budget

_LOCAL = frozenset({"timeline", "compare", "trace_evidence", "dump_inspect", "dump_read_memory", "symbols_verify"})
_REQUIRED = {
    "memory_read": ["address", "length"], "memory.write": ["address", "expected_hex", "value_hex"],
    "memory.rollback": ["change_id"], "dump": ["path"],
    "profile.etw": ["destination", "systemwide_confirmed"],
    "trace_evidence": ["index_path", "process_instance"], "dump_inspect": ["path"],
    "dump_read_memory": ["path", "address", "size"], "symbols_verify": ["pe_path", "pdb_path"],
    "debug.breakpoint.add": ["address"], "debug.breakpoint.disable": ["breakpoint_id"],
    "debug.breakpoint.remove": ["breakpoint_id"], "thread.suspend": ["tid", "thread_created_100ns"],
    "thread.resume": ["tid", "thread_created_100ns"], "compare": ["before_id", "after_id"],
}


def _case(case):
    if type(case) is not dict or case.get("schema") != SCHEMA or type(case.get("case_id")) is not str:
        raise InvestigationError("INVALID_INVESTIGATION_PLAN_CASE")


def _live_identity(value):
    if type(value) is not dict or value.get("kind") not in (None, "LIVE_PROCESS"):
        return None
    from .deep_contracts import ProcessIdentity
    try:
        return ProcessIdentity(value.get("pid"), value.get("created_100ns"), value.get("image_path", "")).to_dict()
    except (TypeError, ValueError):
        return None


def _same_target(first, second):
    if first is None or second is None:
        return False
    if any(first[key] != second[key] for key in ("pid", "created_100ns")):
        return False
    a, b = first.get("image_path", ""), second.get("image_path", "")
    return not a or not b or a.replace("/", "\\").casefold() == b.replace("/", "\\").casefold()


def _capabilities(value, target):
    if value is None:
        return {}, False
    if type(value) is dict:
        if value.get("target") is not None and not _same_target(_live_identity(value["target"]), target):
            return {}, True
        data = value.get("data", {})
        if type(data) is not dict:
            raise InvestigationError("INVALID_ACTION_CAPABILITIES")
        if value.get("status") not in (None, "COMPLETED"):
            return {}, False
        rows = value.get("operations", data.get("operations", []))
    elif type(value) is list:
        rows = value
    else:
        raise InvestigationError("INVALID_ACTION_CAPABILITIES")
    if type(rows) is not list or len(rows) > len(DEEP_ACTIONS):
        raise InvestigationError("INVALID_ACTION_CAPABILITIES")
    result = {}
    for row in rows:
        if type(row) is not dict or row.get("operation") not in DEEP_ACTIONS:
            raise InvestigationError("INVALID_ACTION_CAPABILITY_OPERATION")
        if row["operation"] in result:
            raise InvestigationError("DUPLICATE_ACTION_CAPABILITY")
        result[row["operation"]] = row
    return result, False


def suggest_diagnostic_actions(case, *, hypothesis_id=None, capabilities=None, target_identity=None, budget=None):
    """Return contract-backed advice; availability never grants execution rights."""
    budget = use_budget(budget)
    _case(case)
    hypotheses = case.get("hypotheses", [])
    if type(hypotheses) is not list or len(hypotheses) > 1000:
        raise InvestigationError("INVALID_PLAN_HYPOTHESES")
    selected = [row for row in hypotheses if type(row) is dict and
                (hypothesis_id is None or row.get("hypothesis_id") == hypothesis_id)]
    if hypothesis_id is not None and not selected:
        raise InvestigationError("HYPOTHESIS_NOT_FOUND")
    operations = {"capabilities", "snapshot", "timeline"}
    for hypothesis in selected:
        names = hypothesis.get("next_actions", [])
        if type(names) is not list or len(names) > len(DEEP_ACTIONS):
            raise InvestigationError("INVALID_HYPOTHESIS_ACTIONS")
        # Unknown/extension action names are not advertised as implemented.
        operations.update(name for name in names if type(name) is str and name in DEEP_ACTIONS)
    recorded_target, provided_target = _live_identity(case.get("target_identity")), _live_identity(target_identity)
    if target_identity is not None and provided_target is None:
        raise InvestigationError("INVALID_EXPLICIT_LIVE_TARGET")
    target = provided_target or recorded_target
    conflict = recorded_target is not None and provided_target is not None and not _same_target(recorded_target, provided_target)
    rows, capability_conflict = _capabilities(capabilities, target)
    actions = []
    for name in sorted(operations):
        budget.check()
        spec, observed = DEEP_ACTIONS[name], rows.get(name)
        parameters = {}
        if name == "profile.etw":
            from .deep_profiling import PROFILE
            parameters = {"profile": PROFILE, "duration_seconds": 5}
        status, reason = "NOT_ESTABLISHED", "CHECK_CAPABILITIES_FOR_THE_EXPLICIT_CURRENT_TARGET"
        if conflict or capability_conflict:
            status, reason = "PROCESS_CHANGED", "EXPLICIT_REBIND_OR_NEW_CASE_REQUIRED"
        elif name not in _LOCAL and target is None:
            reason = "SELECT_AND_VERIFY_A_LIVE_TARGET_FOR_THIS_NEW_ACTION"
        elif observed is not None:
            from .deep_contracts import STATUSES
            status = str(observed.get("status", "NOT_ESTABLISHED"))
            if status not in STATUSES:
                status = "NOT_ESTABLISHED"
            reason = str(observed.get("reason") or observed.get("error") or observed.get("next_action") or
                         "LAST_OBSERVED_CAPABILITY_RECHECKED_ON_EXECUTION")[:1000]
        elif name == "capabilities" and target is not None:
            # Capability collection is the explicit next measurement itself;
            # it makes no assertion that subsequent operations have access.
            status, reason = "AVAILABLE", "COLLECT_ACTUAL_CAPABILITIES_WITH_EXISTING_HELPER"
        elif name in _LOCAL:
            reason = "SELECT_THE_REQUIRED_RECORDED_SOURCE_OR_LOCAL_JOURNAL"
        required = list(_REQUIRED.get(name, []))
        actions.append({"action_id": stable_id("advice", case["case_id"], hypothesis_id, name, target),
            "operation": name, "parameters": parameters, "availability": status, "status": status,
            "reason": reason, "required_parameters": required, "target_identity": target,
            "historical_target_relation": "NOT_ESTABLISHED" if recorded_target is None or
                case.get("historical_target_relation") == "NOT_ESTABLISHED" else "EXACT_LIVE_TARGET_RECHECK_REQUIRED",
            "required_permissions": spec.required_rights, "impact": spec.impact,
            "timeout_seconds": spec.timeout_seconds, "confirmation_required": spec.confirmation_required,
            "contract": spec.to_dict(), "automatic_execution": False,
            "next_step": "REQUEST_SCOPED_UAC_FOR_THIS_OPERATION" if status == "ADMIN_REQUIRED" else "EXPLICIT_USER_SELECTION",
            "limitations": ["ADVICE_IS_NOT_AUTHORITY", "CAPABILITIES_ARE_RECHECKED_WHEN_EXECUTED",
                "HISTORICAL_PID_OR_TIME_DOES_NOT_BIND_A_LIVE_PROCESS", "NO_AUTOMATIC_INTERVENTION_OR_RETRY"]})
    return budget.result(actions)


def describe_diagnostic_actions(case, *, operations=None, capabilities=None, target_identity=None, budget=None):
    """Describe explicitly selectable Deep tools independently of recommendations.

    Selecting a manual tool is not evidence that a hypothesis recommends it.
    The same capability, exact-target and contract rules still apply.
    """
    budget = use_budget(budget)
    _case(case)
    names = sorted(DEEP_ACTIONS) if operations is None else operations
    if (type(names) is not list or len(names) > len(DEEP_ACTIONS) or
            any(type(name) is not str or name not in DEEP_ACTIONS for name in names) or
            len(set(names)) != len(names)):
        raise InvestigationError("INVALID_MANUAL_ACTION_CATALOG")
    catalog = {**case, "hypotheses": [{"hypothesis_id": "MANUAL_TOOL_CATALOG", "next_actions": names}]}
    descriptors = suggest_diagnostic_actions(catalog, hypothesis_id="MANUAL_TOOL_CATALOG", capabilities=capabilities,
                                            target_identity=target_identity, budget=budget)
    return budget.result([{**row, "selection_basis": "EXPLICIT_MANUAL_TOOL_NOT_HYPOTHESIS_RECOMMENDATION"}
                          for row in descriptors if row["operation"] in names])


def prepare_scenario(case, hypothesis_id, *, operation=None, parameters=None,
                     target_identity=None, capabilities=None, budget=None):
    """Prepare four manually advanced Deep steps; never execute them."""
    budget = use_budget(budget)
    advice = suggest_diagnostic_actions(case, hypothesis_id=hypothesis_id, capabilities=capabilities,
                                       target_identity=target_identity, budget=budget)
    candidates = [row for row in advice if row["operation"] not in ("capabilities", "snapshot", "timeline")]
    if operation is None:
        chosen = next((row for row in candidates if row["status"] in ("AVAILABLE", "ADMIN_REQUIRED")),
                      candidates[0] if candidates else next(row for row in advice if row["operation"] == "snapshot"))
    else:
        chosen = next((row for row in advice if row["operation"] == operation), None)
        # The caller may explicitly choose any implemented Deep action, but
        # cannot invent an operation or bypass its original contract.
        if chosen is None:
            if operation not in DEEP_ACTIONS:
                raise InvestigationError("SCENARIO_ACTION_NOT_IMPLEMENTED")
            extended = {**case, "hypotheses": [{"hypothesis_id": hypothesis_id, "next_actions": [operation]}]}
            chosen = next(row for row in suggest_diagnostic_actions(extended, hypothesis_id=hypothesis_id,
                capabilities=capabilities, target_identity=target_identity, budget=budget) if row["operation"] == operation)
    if parameters is not None and (type(parameters) is not dict or len(parameters) > 64):
        raise InvestigationError("INVALID_MANUAL_SCENARIO_PARAMETERS")
    actual_parameters = {**chosen["parameters"], **(parameters or {})}
    from .deep_helper import validate_parameters
    validate_parameters(actual_parameters)
    target = chosen["target_identity"]
    scenario_id = stable_id("manual-scenario", case["case_id"], hypothesis_id, chosen["operation"],
                            journal_metadata(actual_parameters), target)
    steps = []
    for phase, name, values in (("BEFORE", "snapshot", {}), ("ACTION", chosen["operation"], actual_parameters),
                                ("AFTER", "snapshot", {}),
                                ("COMPARE", "compare", {"before_id": "FROM_BEFORE_RESULT", "after_id": "FROM_AFTER_RESULT"})):
        budget.check()
        spec = DEEP_ACTIONS[name]
        steps.append({"step_id": stable_id("manual-step", scenario_id, phase), "kind": phase,
            "operation": name, "parameters": journal_metadata(values), "inputs": ["EXACT_LIVE_TARGET", "USER_SELECTION", "PREVIOUS_STEP_RESULT"],
            "outputs": [spec.output, "OPERATION_ID", "DURABLE_JOURNAL_REFERENCE"],
            "required_permissions": spec.required_rights, "impact": spec.impact,
            "timeout_seconds": spec.timeout_seconds, "confirmation_required": spec.confirmation_required,
            "preconditions": list(spec.preconditions) + ["CURRENT_TARGET_AND_PARAMETERS_RECHECKED", "USER_ADVANCES_THIS_STEP"],
            "continue_when": "USER_CHOOSES_NEXT_STEP_AND_PREVIOUS_RESULT_IS_CONFIRMED",
            "cancel": spec.stop_method, "cleanup": spec.cleanup, "failure_action": spec.failure_action,
            "execution_owner": "EXISTING_INSPECTOR_SERVICE_AND_OVERVIEW_DEEP_BRIDGE"})
    def supplied(name):
        if name == "length" and chosen["operation"] == "memory_read":
            return "length" in actual_parameters or "size" in actual_parameters
        if name in ("path", "destination") and chosen["operation"] in ("dump", "profile.etw"):
            return any(alias in actual_parameters for alias in ("destination", "path", "output_path"))
        return name in actual_parameters
    missing = [name for name in chosen["required_parameters"] if not supplied(name)]
    status = ("EXPLICIT_REBIND_REQUIRED" if chosen["status"] == "PROCESS_CHANGED" else
              "LIVE_TARGET_REQUIRED" if target is None else "PARAMETERS_REQUIRED" if missing else "PREPARED_MANUAL")
    return budget.result({"scenario_id": scenario_id, "case_id": case["case_id"], "hypothesis_id": hypothesis_id,
        "target_identity": target, "historical_target_relation": chosen["historical_target_relation"],
        "status": status, "capability_status": chosen["status"], "missing_parameters": missing,
        "steps": steps, "automatic_execution": False, "parameters_are_redacted_descriptions": True,
        "limitations": ["USER_CONFIRMATION_AND_UAC_REMAIN_IN_THE_EXISTING_ACTION_PATH",
                        "BEFORE_AFTER_DIFFERENCE_DOES_NOT_ESTABLISH_CAUSATION", "NO_AUTORETRY_AFTER_LOST_ACKNOWLEDGEMENT"]})


def record_experiment_result(case, record, *, budget=None):
    """Append a redacted manually obtained result; require an ordered exact target.

    A new run ID is required to repeat an experiment. Even a fully recorded
    before/action/after comparison remains INCONCLUSIVE about causal origin
    without additional controls. Human verdicts are separately attributed.
    """
    budget = use_budget(budget)
    _case(case)
    if type(record) is not dict:
        raise InvestigationError("INVALID_EXPERIMENT_RECORD")
    experiment_id = record.get("experiment_id", record.get("scenario_id"))
    phase = record.get("phase")
    if (type(experiment_id) is not str or not 1 <= len(experiment_id) <= 128 or
            phase not in ("BEFORE", "ACTION", "AFTER", "COMPARE", "REVIEW") or
            type(record.get("operation_id")) is not str or not 1 <= len(record["operation_id"]) <= 128 or
            record.get("operation") not in DEEP_ACTIONS):
        raise InvestigationError("INVALID_EXPERIMENT_RECORD_IDENTITY")
    target = _live_identity(record.get("target"))
    if target is None:
        raise InvestigationError("EXACT_EXPERIMENT_TARGET_REQUIRED")
    case_target = _live_identity(case.get("target_identity"))
    if case_target is not None and not _same_target(case_target, target):
        raise InvestigationError("EXPERIMENT_CASE_TARGET_CHANGED")
    experiments = case.get("guided_experiments", [])
    if (type(experiments) is not list or len(experiments) > 100 or
            any(type(item) is not dict or type(item.get("steps")) is not list or len(item["steps"]) > 5 or
                any(type(step) is not dict for step in item["steps"]) for item in experiments)):
        raise InvestigationError("EXPERIMENT_HISTORY_BUDGET")
    updated = list(experiments)
    existing = next((item for item in experiments if type(item) is dict and item.get("experiment_id") == experiment_id), None)
    history = [] if existing is None else list(existing.get("steps", []))
    if existing and not _same_target(_live_identity(existing.get("target_identity")), target):
        raise InvestigationError("EXPERIMENT_TARGET_CHANGED")
    if any(item.get("operation_id") == record["operation_id"] for item in history):
        return budget.result(case)
    if len(history) >= 5:
        raise InvestigationError("EXPERIMENT_STEP_BUDGET")
    was_unconfirmed = existing is not None and existing.get("status") == "BLOCKED_RECOVERY_UNCONFIRMED"
    was_failed = existing is not None and existing.get("status") == "STOPPED_AT_FAILED_STEP"
    if was_unconfirmed and phase != "REVIEW":
        raise InvestigationError("EXPERIMENT_UNCONFIRMED_RESULT_MUST_NOT_RETRY")
    if was_failed and phase != "REVIEW":
        raise InvestigationError("EXPERIMENT_FAILED_STEP_REQUIRES_NEW_RUN")
    order = ["BEFORE", "ACTION", "AFTER", "COMPARE"]
    expected = order[len(history)] if len(history) < len(order) else "REVIEW"
    if phase != expected and not ((was_unconfirmed or was_failed) and phase == "REVIEW"):
        raise InvestigationError("EXPERIMENT_MANUAL_STEP_OUT_OF_ORDER")
    if phase in ("BEFORE", "AFTER") and record["operation"] != "snapshot":
        raise InvestigationError("EXPERIMENT_SNAPSHOT_STEP_REQUIRED")
    if phase == "COMPARE" and record["operation"] != "compare":
        raise InvestigationError("EXPERIMENT_COMPARE_STEP_REQUIRED")
    status = record.get("status")
    if type(status) is not str or len(status) > 128:
        raise InvestigationError("INVALID_EXPERIMENT_RESULT_STATUS")
    result_data = record.get("data", {})
    if type(result_data) is not dict:
        raise InvestigationError("INVALID_EXPERIMENT_RESULT_DATA")
    if phase in ("BEFORE", "AFTER") and status in ("COMPLETED", "INCOMPLETE_EVIDENCE"):
        if type(result_data.get("snapshot_id")) is not str or not 1 <= len(result_data["snapshot_id"]) <= 128:
            raise InvestigationError("EXPERIMENT_SNAPSHOT_ID_REQUIRED")
    if phase == "COMPARE" and status == "COMPLETED":
        before = history[0].get("data", {}).get("snapshot_id")
        after = history[2].get("data", {}).get("snapshot_id")
        if not before or not after or result_data.get("before_id") != before or result_data.get("after_id") != after:
            raise InvestigationError("EXPERIMENT_COMPARISON_SNAPSHOT_ID_MISMATCH")
    # Preserve only experiment outcome metadata. Full snapshot bodies and
    # arbitrary imported fields are available through their source references,
    # never copied into the ordinary scenario/export record.
    allowed_data = {"snapshot_id", "before_id", "after_id", "changed_sections", "comparison_scope", "interpretation",
                    "reported_operation_status", "readback_verified", "restored_verified", "change_id", "size",
                    "owned_resources_remaining", "owner_retained", "retry_cleanup_required"}
    cleaned = journal_metadata({key: record[key] for key in
        ("phase", "operation", "operation_id", "status")})
    cleaned["target"] = target
    cleaned["data"] = journal_metadata({key: value for key, value in result_data.items() if key in allowed_data})
    for key in ("before", "after", "journal"):
        if type(record.get(key)) is dict:
            permitted = {"sha256", "status", "operation_id", "record_sha256", "chain", "payloads"}
            cleaned[key] = {name: value for name, value in record[key].items() if name in permitted and
                            type(value) in (str, int, bool, type(None))}
    history.append(cleaned)
    unconfirmed = status == "RECOVERY_UNCONFIRMED"
    completed = status in ("COMPLETED", "INCOMPLETE_EVIDENCE", "DETACHED")
    new = {"experiment_id": experiment_id, "hypothesis_id": record.get("hypothesis_id", existing.get("hypothesis_id") if existing else None),
        "target_identity": target, "historical_target_relation": "NOT_ESTABLISHED" if case_target is None or
            case.get("historical_target_relation") == "NOT_ESTABLISHED" else "EXACT_LIVE_TARGET",
        "steps": history, "status": "BLOCKED_RECOVERY_UNCONFIRMED" if unconfirmed or was_unconfirmed else
        "STOPPED_AT_FAILED_STEP" if was_failed else
        "COMPARISON_RECORDED" if phase == "COMPARE" and completed else "AWAITING_USER" if completed else "STOPPED_AT_FAILED_STEP",
        "hypothesis_status": "INCONCLUSIVE", "root_cause_proven": False, "automatic_retry": False,
        "missing_controls": ["REPEATED_MATCHED_WORKLOAD", "NEGATIVE_CONTROL", "COMPARABLE_SOURCE_COVERAGE"],
        "limitations": ["OBSERVED_STATE_CHANGE_IS_NOT_PROOF_OF_INTERNAL_CAUSE", "USER_MUST_EXPLICITLY_ADVANCE_EACH_ACTION"]}
    if existing is None:
        if len(updated) >= 100:
            raise InvestigationError("EXPERIMENT_HISTORY_BUDGET")
        updated.append(new)
    else:
        updated[updated.index(existing)] = new
    return budget.result({**case, "guided_experiments": updated})
