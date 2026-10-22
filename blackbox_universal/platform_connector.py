"""Safe optional external Alva connection for the frozen public GUI.

A user-selected *authorized* Python interpreter with independently installed
Alva runs a tiny public subprocess worker under Python isolated mode (-I).
Never install or distribute Alva. No local network endpoint or tunnel.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from blackbox_rep_alva.report import summarize

MAX_RESPONSE = 65536
MAX_REQUEST = 8192
OPS = ("blackbox.observer.samples", "blackbox.observer.lifecycle",
       "blackbox.observer.errors")


class ConnectionError(RuntimeError):
    """A bounded, non-sensitive problem marker (no path or exception text)."""


def _worker_path() -> Path:
    if getattr(sys, "frozen", False):
        root = Path(getattr(sys, "_MEIPASS"))
        worker = root / "alva_worker" / "alva_sidecar_worker.py"
    else:
        worker = Path(__file__).resolve().parent.parent / "src" / "blackbox_rep_alva" / "alva_sidecar_worker.py"
    if not worker.is_file() or worker.is_symlink():
        raise ConnectionError("ALVA_WORKER_MISSING")
    return worker


def _validate_python(executable: Path) -> Path:
    path = Path(executable).expanduser()
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ConnectionError("ALVA_INTERPRETER_INVALID")
    if path.name.casefold() not in ("python.exe", "python3.exe", "python", "python3"):
        raise ConnectionError("ALVA_INTERPRETER_INVALID")
    return path


def _summary(session: Path | None) -> dict:
    if session is None:
        return {"sample_count": 0, "peak_rss_bytes": None,
                "peak_cpu_percent": None, "observation_error_count": 0,
                "closed": False, "state": "UNKNOWN"}
    session = Path(session)
    if not session.is_dir() or session.is_symlink():
        raise ConnectionError("SESSION_INVALID")
    try:
        src = summarize(session)
    except Exception:
        raise ConnectionError("SESSION_SUMMARY_UNAVAILABLE") from None
    count = src.get("samples")
    peak = src.get("peak_rss_bytes")
    cpu = src.get("peak_cpu_percent")
    errors = src.get("observation_errors")
    closed = src.get("state") == "closed"
    status = src.get("exit_code") or "UNKNOWN"
    if (type(count) is not int or not 0 <= count <= 10**9
            or type(errors) is not dict
            or status not in ("COMPLETED", "INTERRUPTED", "PROCESS_EXITED",
                              "ACCESS_DENIED", "PID_REUSED", "SAMPLE_UNAVAILABLE",
                              "STORAGE_ERROR", "UNKNOWN")):
        raise ConnectionError("SESSION_SUMMARY_INVALID")
    error_count = sum(int(n) for n in errors.values() if type(n) is int and n >= 0)
    if error_count > 10**9:
        raise ConnectionError("SESSION_ERROR_COUNT_INVALID")
    for value in (peak, cpu):
        if value is not None and (type(value) not in (int, float)
                                  or not 0 <= value <= 10**15):
            raise ConnectionError("SESSION_METRIC_INVALID")
    return {
        "sample_count": count, "peak_rss_bytes": peak,
        "peak_cpu_percent": cpu, "observation_error_count": error_count,
        "closed": closed, "state": status}


def _validate_output(result: object) -> dict:
    if type(result) is not dict:
        raise ConnectionError("ALVA_WORKER_RESPONSE_INVALID")
    status = result.get("status")
    if status != "ok":
        code = result.get("error_code")
        if code in ("ALVA_NOT_INSTALLED", "ALVA_CONTRACT_OR_RUNTIME_FAILURE",
                    "ALVA_UNKNOWN_FAILURE"):
            return {"status": "unavailable" if code == "ALVA_NOT_INSTALLED" else "error",
                    "error_code": code, "permission_to_act": False}
        raise ConnectionError("ALVA_WORKER_ERROR_INVALID")
    if (result.keys() != {
            "status", "bridge_schema", "mode", "alva_version",
            "alva_origin_authenticated", "target_root_cause_proven",
            "permission_to_act", "evidence_origin", "operations",
            "component_count"} or result["bridge_schema"] != 1 or
            result["mode"] != "EXTERNAL_ALVA_SCOPED_INSPECTION" or
            result["alva_origin_authenticated"] is not False or
            result["target_root_cause_proven"] is not False or
            result["permission_to_act"] is not False or
            result["evidence_origin"] != "APP_SUPPLIED_NOT_AUTHENTICATED" or
            type(result["alva_version"]) is not str or
            len(result["alva_version"]) > 50 or
            result["component_count"] != 3 or
            type(result["operations"]) is not list or
            len(result["operations"]) != 3):
        raise ConnectionError("ALVA_WORKER_CONTRACT_REJECTED")
    for op, expected in zip(result["operations"], OPS):
        if (type(op) is not dict or
                op.keys() != {"component", "execution_state", "contract_verdict",
                              "visibility", "ai_handoff_status", "observation"} or
                op["component"] != expected or
                op["execution_state"] != "RESPONSE_AVAILABLE" or
                op["contract_verdict"] != "CHECK_ACCEPTED" or
                op["visibility"] != "SCOPE_ONLY" or
                op["ai_handoff_status"] != "ok" or
                type(op["observation"]) is not dict):
            raise ConnectionError("ALVA_WORKER_OPERATION_REJECTED")
    return result


def inspect_external(interpreter: Path, session: Path | None = None) -> dict:
    """Executes at most 3 fixed Alva operations; no raw session files pass."""
    py = _validate_python(interpreter)
    worker = _worker_path()
    payload = {"schema_version": 1, "operation": "inspect" if session else "ping",
               "summary": _summary(session)}
    encoded = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_REQUEST:
        raise ConnectionError("ALVA_REQUEST_TOO_LARGE")
    env = os.environ.copy()
    for var in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT"):
        env.pop(var, None)
    try:
        proc = subprocess.run([str(py), "-I", "-u", str(worker)],
                              input=encoded, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=20,
                              cwd=str(worker.parent), env=env, check=False)
    except (OSError, subprocess.SubprocessError):
        raise ConnectionError("ALVA_WORKER_UNAVAILABLE") from None
    if len(proc.stdout) > MAX_RESPONSE:
        raise ConnectionError("ALVA_WORKER_RESPONSE_TOO_LARGE")
    try:
        output = json.loads(proc.stdout.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise ConnectionError("ALVA_WORKER_RESPONSE_INVALID") from None
    result = _validate_output(output)
    if proc.returncode not in (0, 2) or (proc.returncode == 0) != (result["status"] == "ok"):
        raise ConnectionError("ALVA_WORKER_EXIT_CONFLICT")
    return result


def save_session_diagnostics(interpreter: Path, session: Path) -> dict:
    """Best-effort, append-only Alva report after the standalone session closes."""
    session = Path(session)
    target = session / "alva-diagnostics.json"
    try:
        result = inspect_external(interpreter, session)
    except ConnectionError as exc:
        result = {"status": "error", "error_code": str(exc),
                  "permission_to_act": False}
    try:
        with target.open("x", encoding="utf-8") as out:
            json.dump(result, out, ensure_ascii=False, sort_keys=True,
                      indent=2, allow_nan=False)
            out.write("\n")
    except OSError:
        return {"status": "error", "error_code": "ALVA_EVIDENCE_WRITE_FAILED"}
    return {"status": result["status"], "error_code": result.get("error_code"),
            "component_count": result.get("component_count", 0),
            "file": "alva-diagnostics.json"}
