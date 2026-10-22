"""Real Alva P4 checked evidence pipeline over a *bounded observer summary*.

Runs pure, application-owned predicates on a frozen copy of existing samples,
never re-observes or mutates the target process. Called only by an authorized
external Alva worker; none of this source embeds the private Alva package.
"""
from __future__ import annotations

STAGE_NAMES = (
    "blackbox.evidence.samples",
    "blackbox.evidence.lifecycle",
    "blackbox.evidence.metrics",
    "blackbox.evidence.errors",
)
REVIEW_MARKER = "STRUCTURALLY_CONSISTENT_UNAUTHENTICATED"


def _echo(payload: dict) -> dict:
    """Single controlled app operation; no filesystem, network or side effect."""
    return dict(payload)


def _checked_bool(value: object, expected: dict) -> bool:
    return type(value) is dict and value == expected


def verified_session_evidence(alva: object, summary: dict, operation: str) -> dict:
    """Build real checked-pipeline + reviewer + Alva AI Handoff metadata.

    A rejected app-declared predicate means only 'verify this observer evidence'
    and never 'a defect has been proven in the observed external application'.
    No raw process name, PID, path, exception message or business data appears.
    """
    if operation not in ("ping", "inspect"):
        raise ValueError("BAD_OPERATION")
    if type(summary) is not dict:
        raise ValueError("BAD_SUMMARY")
    recorded = operation == "inspect"
    samples = summary["sample_count"]
    lifecycle = {"closed": summary["closed"], "state": summary["state"]}
    signal = {
        "cpu_observed": summary["peak_cpu_percent"] is not None,
        "memory_observed": summary["peak_rss_bytes"] is not None,
    }
    errors = {"count": summary["observation_error_count"]}
    sample_data = {"count": samples, "recorded_session": recorded}
    steps = [
        (STAGE_NAMES[0], _echo,
         lambda v: (_checked_bool(v, sample_data) and
                    (not recorded or samples > 0)),
         sample_data),
        (STAGE_NAMES[1], _echo,
         lambda v: (_checked_bool(v, lifecycle) and
                    (not recorded or lifecycle["closed"])),
         lifecycle),
        (STAGE_NAMES[2], _echo,
         lambda v: (_checked_bool(v, signal) and
                    (not recorded or samples == 0 or
                     signal["cpu_observed"] or signal["memory_observed"])),
         signal),
        (STAGE_NAMES[3], _echo,
         lambda v: (_checked_bool(v, errors) and
                    type(errors["count"]) is int and
                    0 <= errors["count"] <= 10 ** 9),
         errors),
    ]
    # Alva runs each declared method once, preflights before execution, and
    # stops on first rejected contract. It builds a verified-pipeline report.
    report = alva.run_checked_pipeline(steps)
    if (type(report) is not dict or report.get("status") != "ok"
            or type(report.get("result")) is not dict):
        raise ValueError("PIPELINE_UNAVAILABLE")
    review = alva.review_pipeline_evidence(report)
    if (type(review) is not dict or review.get("status") != "ok"
            or review.get("code") != REVIEW_MARKER
            or review.get("root_cause_proven") is not False
            or review.get("external_attestation") is not False):
        raise ValueError("PIPELINE_REVIEW_FAILED")
    handoff = alva.build_ai_handoff(report)
    if (type(handoff) is not dict or handoff.get("status") != "ok"
            or type(handoff.get("result")) is not dict):
        raise ValueError("HANDOFF_UNAVAILABLE")
    result = report["result"]
    ai = handoff["result"]
    if (result.get("evidence_origin") != "APP_SUPPLIED_NOT_AUTHENTICATED"
            or ai.get("permission_to_act") is not False
            or ai.get("root_cause_proven") is not False
            or ai.get("execution_attested") is not False
            or ai.get("review_required") is not True
            or ai.get("record_status") != REVIEW_MARKER):
        raise ValueError("EVIDENCE_PROVENANCE_REJECTED")
    declared = result.get("declared_stages")
    executed = result.get("executed_stages")
    accepted = result.get("accepted_checks")
    coverage = result.get("verification_coverage")
    status = result.get("observed_pipeline_status")
    first = result.get("first_unverified_component")
    action = result.get("next_action_code")
    if (type(declared) is not int or declared != len(STAGE_NAMES)
            or type(executed) is not int or not 1 <= executed <= declared
            or type(accepted) is not int or not 0 <= accepted <= executed
            or coverage not in ("ALL_DECLARED_CHECKS_ACCEPTED", "INCOMPLETE_OR_AMBIGUOUS")
            or status not in ("ok", "error")
            or first is not None and first not in STAGE_NAMES
            or type(action) is not str or not 1 <= len(action) <= 64):
        raise ValueError("PIPELINE_METADATA_INVALID")
    if (ai.get("declared_stages") != declared
            or ai.get("executed_stages") != executed
            or ai.get("accepted_checks") != accepted
            or ai.get("verification_coverage") != coverage
            or ai.get("observed_pipeline_status") != status
            or ai.get("first_unverified_component") != first):
        raise ValueError("HANDOFF_CORRELATION_FAILED")
    return {
        "diagnostic_pipeline": "REAL_ALVA_P4_CHECKED_PIPELINE",
        "declared_stages": declared,
        "executed_stages": executed,
        "accepted_checks": accepted,
        "observed_pipeline_status": status,
        "verification_coverage": coverage,
        "first_unverified_component": first,
        "next_action_code": action,
        "record_status": REVIEW_MARKER,
        "handoff_review_required": True,
        "permission_to_act": False,
        "root_cause_proven": False,
        "execution_attested": False,
    }
