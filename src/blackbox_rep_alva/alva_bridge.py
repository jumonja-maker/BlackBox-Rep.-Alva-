"""Optional Alva PREVIEW consumer bridge. Imports from installed platform, never vendors it.

Only process a minimal already-built local report summary. No file writes, network,
external commands, importing arbitrary adapters or hidden retry of observer tasks.
"""
from __future__ import annotations
from pathlib import Path
from .contracts import ObserverError
from .report import summarize

ALVA_PIN = "a44297c5408628d9447bbf7db394b95ebd33fa20"


def inspect_platform(session: Path | None = None) -> dict:
    """Probe an explicit installed Alva, optionally diagnose a bounded app-owned operation.

    This call verifies the *installed module API*, not Git origin or commit SHA.
    Installation SHA must independently be verified before trusting the result.
    """
    try:
        import alva
        from alva import Component
        from alva.host import ComponentHost
    except ImportError:
        return {"status": "unavailable", "platform": "Alva", "code": "ALVA_UNAVAILABLE",
                "required_ref": ALVA_PIN, "installed_version": None,
                "integration": "optional", "provenance_verified": False}
    version = getattr(alva, "__version__", "unknown")
    # Presence is discovery only, not a tested functional guarantee.
    available_apis = {name: callable(getattr(alva, name, None)) for name in (
        "Component", "CapabilityRegistry", "OperationTrace", "run_operation",
        "run_verified_pipeline", "run_checked_pipeline", "build_ai_handoff",
        "review_pipeline_evidence", "classify_failure", "build_report",
        "recheck_rejected_stage", "locate_source")}
    result = {"platform": "Alva", "status": "api_imported", "installed_version": version,
              "required_ref": ALVA_PIN, "provenance_verified": False,
              "integration": "optional", "api": "ComponentHost.invoke_with_diagnostics",
              "api_present_not_verified": available_apis}
    if session is None:
        return result
    source = summarize(session)
    # Fixed fields only. Alva never sees a file path, PID, event contents, or source document.
    values = {
        "samples": int(source["samples"]),
        "closed": source["state"] == "closed",
        "observer_error_count": sum(int(v) for v in source["observation_errors"].values()),
    }

    def inspect(payload: dict) -> dict:
        # Component business logic remains BLACK.BOX-owned. Validate strictly.
        if set(payload) != {"samples", "closed", "observer_error_count"}:
            raise ValueError("bad packet")
        if (type(payload["samples"]) is not int or payload["samples"] < 0 or
            type(payload["closed"]) is not bool or
            type(payload["observer_error_count"]) is not int or payload["observer_error_count"] < 0):
            raise ValueError("bad summary")
        return {"sampled": payload["samples"] > 0,
                "observation_state": "CLOSED" if payload["closed"] else "UNCERTAIN",
                "observer_errors_present": payload["observer_error_count"] > 0,
                "root_cause": "UNKNOWN"}

    try:
        with ComponentHost((Component("blackbox.report.inspect", inspect),), allow_dispatch=True) as host:
            with host.open_scope(permitted_operations=("blackbox.report.inspect",)) as scope:
                call = scope.invoke_with_diagnostics({"schema_version": 1,
                    "operation": "blackbox.report.inspect", "payload": values})
                application = call.response
                diagnostics = call.diagnostics
                execution_state = call.execution_state
        if not isinstance(application, dict) or application.get("status") != "ok":
            raise ObserverError("ALVA_FAILURE", "platform")
        if not isinstance(diagnostics, dict):
            raise ObserverError("ALVA_FAILURE", "platform")
        result.update({"status": "invoked", "operation": "blackbox.report.inspect",
                       "application_result": application.get("result"),
                       "execution_state": execution_state,
                       "diagnostic_status": diagnostics.get("status"),
                       "diagnostic_visibility": diagnostics.get("result", {}).get("visibility"),
                       "attestation": "UNATTESTED", "root_cause": "UNKNOWN"})
        return result
    except ObserverError:
        raise
    except Exception:
        # Avoid forwarding exception text, private paths or a fake success.
        raise ObserverError("ALVA_FAILURE", "platform") from None
