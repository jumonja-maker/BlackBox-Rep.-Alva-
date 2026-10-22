"""Offline reports: summaries do not contain command lines, secrets, file paths."""
from __future__ import annotations
from html import escape
import hashlib
from contextlib import closing
import json
from pathlib import Path
import sqlite3
from .contracts import ObserverError, bounded
from .storage import _open_ro


def summarize(folder: Path) -> dict:
    try:
        with closing(_open_ro(Path(folder))) as db:
            row = db.execute("SELECT * FROM metadata LIMIT 1").fetchone()
            if row is None or row["schema_version"] != 1:
                raise ObserverError("UNSUPPORTED_SCHEMA", "report")
            agg = db.execute("""SELECT count(*) AS samples, MAX(rss_bytes) AS peak_rss_bytes,
                       MAX(cpu_percent) AS peak_cpu_percent, MAX(children_count) AS max_children,
                       MAX(elapsed_ms) AS elapsed_ms FROM samples""").fetchone()
            events = db.execute("SELECT data FROM events ORDER BY seq").fetchall()
            counts = {}
            for entry in events:
                record = json.loads(entry["data"])
                kind = record.get("code", "UNKNOWN")
                counts[kind] = counts.get(kind, 0) + 1
            result = {
                "schema_version": 1,
                "report_type": "BLACKBOX_PROCESS_OBSERVATION",
                "session_id": row["session_id"], "pid": row["pid"],
                "state": "closed" if row["ended_utc"] else "interrupted_or_live",
                "exit_code": row["exit_code"] or "UNKNOWN",
                "started_utc": row["started_utc"], "ended_utc": row["ended_utc"],
                "samples": agg["samples"],
                "peak_rss_bytes": agg["peak_rss_bytes"],
                "peak_cpu_percent": agg["peak_cpu_percent"],
                "max_children": agg["max_children"], "elapsed_ms": agg["elapsed_ms"],
                "observation_errors": counts,
                "root_cause": "UNKNOWN", "root_cause_confidence": "UNKNOWN",
                "execution_attested": False,
                "limitations": ["external_sampling_only", "no_proof_of_memory_leak",
                                "not_an_application_internal_trace"],
            }
            bounded(result, max_bytes=65536)
            return result
    except (sqlite3.Error, ValueError, KeyError, TypeError, json.JSONDecodeError):
        raise ObserverError("INVALID_DATA", "report") from None


def write_report(folder: Path) -> dict:
    folder = Path(folder)
    report = summarize(folder)
    # New report artifacts are session-local only; no arbitrary destination paths.
    if folder.is_symlink():
        raise ObserverError("STORAGE_ERROR", "storage")
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    path = folder / "report.json"
    if path.exists() or path.is_symlink():
        raise ObserverError("STORAGE_ERROR", "storage")
    try:
        with path.open("xb") as out:
            out.write(payload)
        html = "<!doctype html><meta charset=\"utf-8\"><title>BlackBox Report</title>" + (
            "<h1>BlackBox Process Observation</h1><pre>" +
            escape(json.dumps(report, indent=2, ensure_ascii=False)) + "</pre>")
        with (folder / "report.html").open("x", encoding="utf-8") as output:
            output.write(html)
    except OSError:
        raise ObserverError("STORAGE_ERROR", "storage") from None
    return {"report_sha256": hashlib.sha256(payload).hexdigest(),
            "report_file": "report.json", "sample_count": report["samples"],
            "session_id": report["session_id"]}


def compare(before: Path, after: Path) -> dict:
    a, b = summarize(before), summarize(after)
    values = {}
    for key in ("samples", "peak_rss_bytes", "peak_cpu_percent", "max_children", "elapsed_ms"):
        av, bv = a[key], b[key]
        values[key] = {"before": av, "after": bv, "delta": bv-av if av is not None and bv is not None else None}
    return {"schema_version": 1, "comparison": "OBSERVATION_ONLY",
            "before": a["session_id"], "after": b["session_id"],
            "metrics": values, "regression_proven": False,
            "reason": "sampling data alone does not establish regression or root cause"}
