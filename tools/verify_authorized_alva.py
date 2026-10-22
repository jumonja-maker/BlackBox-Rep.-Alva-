"""Opt-in local smoke for an AUTHORIZED Alva installation (no network/install).

Runs the actual public sidecar using the selected Python -I, requiring a
schema-2 P4 success and a conservative rejected-evidence case. Does NOT
authenticate a wheel or prove anything about a foreign target application.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

EXPECTED = (
    "blackbox.observer.samples", "blackbox.observer.lifecycle",
    "blackbox.observer.errors",
)


def _run(interpreter: Path, worker: Path, count: int) -> dict:
    summary = {
        "sample_count": count, "peak_rss_bytes": 2048,
        "peak_cpu_percent": 12.0, "observation_error_count": 0,
        "closed": True, "state": "COMPLETED",
    }
    request = {"schema_version": 1, "operation": "inspect", "summary": summary}
    env = os.environ.copy()
    for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT"):
        env.pop(key, None)
    try:
        result = subprocess.run(
            [str(interpreter), "-I", "-u", str(worker)],
            input=json.dumps(request, separators=(",", ":")).encode("ascii"),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20,
            cwd=str(worker.parent), env=env, check=False)
    except (OSError, subprocess.SubprocessError):
        raise ValueError("WORKER_UNAVAILABLE") from None
    if result.returncode != 0 or len(result.stdout) > 65536:
        raise ValueError("ALVA_WORKER_FAILED")
    try:
        packet = json.loads(result.stdout.decode("utf-8", "strict"))
    except (ValueError, UnicodeError):
        raise ValueError("INVALID_WORKER_JSON") from None
    return packet


def _check(packet: object, *, expected_pipeline: str) -> None:
    if type(packet) is not dict or packet.get("status") != "ok" or (
        packet.get("bridge_schema") != 2 or
        packet.get("alva_origin_authenticated") is not False or
        packet.get("target_root_cause_proven") is not False or
        packet.get("permission_to_act") is not False or
        type(packet.get("operations")) is not list or
        len(packet["operations"]) != len(EXPECTED) or
        [c.get("component") if type(c) is dict else None
         for c in packet["operations"]] != list(EXPECTED)):
        raise ValueError("SCOPED_CONTRACT_FAILED")
    extended = packet.get("extended_diagnostics")
    if (type(extended) is not dict or
            extended.get("diagnostic_pipeline") != "REAL_ALVA_P4_CHECKED_PIPELINE" or
            extended.get("declared_stages") != 4 or
            extended.get("observed_pipeline_status") != expected_pipeline or
            extended.get("permission_to_act") is not False or
            extended.get("root_cause_proven") is not False or
            extended.get("execution_attested") is not False or
            type(extended.get("host_trace_checks")) is not list or
            len(extended["host_trace_checks"]) != 3):
        raise ValueError("P4_CONTRACT_FAILED")
    if expected_pipeline == "ok":
        if (extended.get("accepted_checks") != 4 or
                extended.get("executed_stages") != 4):
            raise ValueError("P4_SUCCESS_COVERAGE_FAILED")
    else:
        if (extended.get("first_unverified_component") !=
                "blackbox.evidence.samples" or
                extended.get("executed_stages") != 1 or
                extended.get("accepted_checks") != 0):
            raise ValueError("P4_NEGATIVE_COVERAGE_FAILED")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("python", type=Path,
                        help="Previously authorized Python with private Alva installed")
    args = parser.parse_args(argv)
    python = args.python.expanduser()
    worker = (Path(__file__).resolve().parent.parent / "src" /
              "blackbox_rep_alva" / "alva_sidecar_worker.py")
    helper = worker.with_name("alva_evidence_pipeline.py")
    if (not python.is_absolute() or not python.is_file() or python.is_symlink() or
            python.name.casefold() not in ("python.exe", "python3.exe", "python", "python3") or
            not worker.is_file() or worker.is_symlink() or
            not helper.is_file() or helper.is_symlink()):
        print("BLOCKED: INVALID_AUTHORIZED_ENVIRONMENT", file=sys.stderr)
        return 2
    try:
        _check(_run(python, worker, 5), expected_pipeline="ok")
        _check(_run(python, worker, 0), expected_pipeline="error")
    except ValueError as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        return 1
    print("PASS: GENUINE_INSTALLED_ALVA_API_COMPATIBILITY (source identity not attested)")
    print("PASS: 3 SCOPED CALLS, 3 HOST TRACES, 4 P4 STAGES AND STRUCTURAL REVIEW")
    print("PASS: EMPTY-SAMPLE NEGATIVE REJECTED WITHOUT CLAIMING TARGET ROOT CAUSE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
