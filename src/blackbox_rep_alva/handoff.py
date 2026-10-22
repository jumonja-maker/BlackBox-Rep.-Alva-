"""An untrusted evidence packet for human/AI inspection, not instructions to execute."""
from __future__ import annotations
from pathlib import Path
from .report import summarize


def build_handoff(folder: Path) -> dict:
    result = summarize(folder)
    return {
        "schema_version": 1,
        "kind": "BLACKBOX_AI_HANDOFF",
        "source": "LOCAL_OBSERVER_UNATTESTED",
        "permission_to_act": False,
        "evidence": {
            "session_id": result["session_id"], "state": result["state"],
            "exit_code": result["exit_code"], "sample_count": result["samples"],
            "peak_rss_bytes": result["peak_rss_bytes"], "peak_cpu_percent": result["peak_cpu_percent"],
            "observation_error_codes": sorted(result["observation_errors"]),
        },
        "classification": {"source": "UNKNOWN", "confidence": "UNKNOWN",
                           "root_cause": "NOT_DETERMINED"},
        "safe_next_step": "Verify provenance, reproduce with consent, check app-specific evidence",
        "data_limit": "No source document content, command lines, environment or credentials",
    }
