"""User-facing Alva access states for the public, self-sufficient desktop.

No network, subprocess, private Alva import, or authentication happens here.
An explicit external runtime handshake is the only way to assert connectivity.
"""
from __future__ import annotations

def unconfigured_access() -> dict:
    """A genuine missing-runtime result, never a fake platform success."""
    return {
        "status": "unavailable",
        "error_code": "ALVA_RUNTIME_NOT_CONFIGURED",
        "standalone_ready": True,
        "alva_bundled": False,
        "permission_to_act": False,
    }


def explain_access(result: object) -> str:
    """Plain language paired with the raw bounded diagnostic response."""
    if not isinstance(result, dict):
        return ("Alva connection was not verified. You can still monitor "
                "processes and save offline reports without Alva.")
    status = result.get("status")
    code = result.get("error_code") or result.get("code")
    if status == "ok":
        return (
            "The selected external Alva environment answered the limited "
            "diagnostic check. Its source/version is NOT authenticated. "
            "This does not prove a fault in the observed program. "
            "Ordinary BLACK.BOX monitoring remains independent."
        )
    if code == "ALVA_RUNTIME_NOT_CONFIGURED":
        return (
            "BLACK.BOX is ready: choose a process and start observing. "
            "All ordinary reports and offline AI Handoff work without "
            "Alva or Python. Advanced Alva checks are optional and "
            "currently require a separately authorized installation."
        )
    if code in ("ALVA_NOT_INSTALLED", "ALVA_UNAVAILABLE"):
        return (
            "The selected Python environment does not contain a usable "
            "Alva runtime. No installation was attempted. "
            "Choose a trusted environment with an authorized Alva install, "
            "or continue using BLACK.BOX normally without it."
        )
    if status in ("error", "unavailable"):
        return (
            "Alva connection could not be verified. BLACK.BOX has not "
            "modified the target or installed anything. "
            "Check the authorized Python environment or disconnect; "
            "ordinary offline reports remain available."
        )
    return (
        "Alva has not been verified. Monitoring, SQLite reports, comparisons "
        "and offline handoff remain available without it."
    )
