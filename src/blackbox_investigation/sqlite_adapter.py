"""Bounded, read-only import of BLACK.BOX v0.3.4 session.sqlite3 schema 1."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from .model import InvestigationError, Policy, integer, validate_policy
from .engine import analyze


_EXPECTED_SAMPLES = ("seq", "elapsed_ms", "rss_bytes", "cpu_percent", "num_threads", "read_bytes", "write_bytes", "children_count")
_EXPECTED_META = ("schema_version", "session_id", "pid", "started_utc", "ended_utc", "exit_code", "probe")


def load_session(folder: str | Path, *, policy: Policy | None = None,
                 interval_start_ms: int | None = None, interval_end_ms: int | None = None) -> dict:
    """Use SQLite mode=ro and query_only; never change any BLACK.BOX session file."""
    policy = validate_policy(policy)
    if (interval_start_ms is None) != (interval_end_ms is None):
        raise InvestigationError("INTERVAL_BOUNDS_REQUIRED")
    if interval_start_ms is not None:
        integer(interval_start_ms, "INTERVAL_START")
        integer(interval_end_ms, "INTERVAL_END")
        if interval_start_ms > interval_end_ms or interval_end_ms > 30 * 24 * 3600 * 1000:
            raise InvestigationError("INVALID_INTERVAL")
    try:
        directory = Path(folder)
    except (TypeError, ValueError):
        raise InvestigationError("INVALID_SESSION_PATH") from None
    target = directory / "session.sqlite3"
    if not directory.is_dir() or directory.is_symlink() or target.is_symlink() or not target.is_file():
        raise InvestigationError("SESSION_UNAVAILABLE")
    if target.stat().st_size > 256 * 1024 * 1024:
        raise InvestigationError("SESSION_SIZE_LIMIT")
    db = None
    try:
        db = sqlite3.connect(target.resolve().as_uri() + "?mode=ro", uri=True, timeout=1)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA busy_timeout=500")
        meta_cols = tuple(row[1] for row in db.execute("PRAGMA table_info(metadata)"))
        sample_cols = tuple(row[1] for row in db.execute("PRAGMA table_info(samples)"))
        if meta_cols != _EXPECTED_META or sample_cols != _EXPECTED_SAMPLES:
            raise InvestigationError("UNSUPPORTED_BLACKBOX_SCHEMA")
        metas = db.execute("SELECT * FROM metadata LIMIT 2").fetchall()
        if len(metas) != 1 or metas[0]["schema_version"] != 1:
            raise InvestigationError("UNSUPPORTED_BLACKBOX_SCHEMA")
        meta = dict(metas[0])
        if type(meta["pid"]) is not int or meta["pid"] <= 0:
            raise InvestigationError("INVALID_SESSION_IDENTITY")
        coverage = db.execute("SELECT count(*) AS n, min(elapsed_ms) AS lo, max(elapsed_ms) AS hi FROM samples").fetchone()
        total = coverage["n"]
        if interval_start_ms is None:
            if total > policy.max_samples:
                raise InvestigationError("SESSION_INTERVAL_REQUIRED")
            selected = total
            raw = db.execute("SELECT elapsed_ms,rss_bytes,cpu_percent,num_threads,read_bytes,write_bytes,children_count "
                             "FROM samples ORDER BY seq LIMIT ?", (policy.max_samples + 1,)).fetchall()
        else:
            selected = db.execute("SELECT count(*) FROM samples WHERE elapsed_ms BETWEEN ? AND ?",
                                  (interval_start_ms, interval_end_ms)).fetchone()[0]
            if selected > policy.max_samples:
                raise InvestigationError("INTERVAL_TOO_LARGE")
            raw = db.execute("SELECT elapsed_ms,rss_bytes,cpu_percent,num_threads,read_bytes,write_bytes,children_count "
                             "FROM samples WHERE elapsed_ms BETWEEN ? AND ? ORDER BY seq LIMIT ?",
                             (interval_start_ms, interval_end_ms, policy.max_samples + 1)).fetchall()
        if len(raw) != selected:
            raise InvestigationError("SESSION_CHANGED_DURING_READ")
        samples = [dict(row) for row in raw]
        session_coverage = {"total_samples": total, "selected_samples": selected,
                            "omitted_samples": total - selected,
                            "session_start_ms": coverage["lo"], "session_end_ms": coverage["hi"],
                            "requested_interval_ms": [interval_start_ms, interval_end_ms] if interval_start_ms is not None else None,
                            "full_session_covered": selected == total}
        # Only the lifecycle exit code can be linked. An existing session has no
        # OS-verified window hang or PID creation-time column.
        exit_code = meta.get("exit_code")
        allowed_exits = ("COMPLETED", "INTERRUPTED", "PROCESS_EXITED", "PID_REUSED",
                         "ACCESS_DENIED", "SAMPLE_UNAVAILABLE", "STORAGE_ERROR")
        if exit_code is not None and exit_code not in allowed_exits:
            raise InvestigationError("INVALID_SESSION_STATUS")
        return {"pid": meta["pid"], "creation_time": None, "samples": samples,
                "session_id": str(meta["session_id"])[:96], "exit_code": exit_code,
                "ended": meta["ended_utc"] is not None,
                "probe": str(meta["probe"])[:64], "coverage": session_coverage}
    except InvestigationError:
        raise
    except (sqlite3.Error, ValueError, OverflowError, OSError):
        raise InvestigationError("INVALID_SESSION") from None
    finally:
        if db is not None:
            db.close()


def analyze_session(folder: str | Path, *, policy: Policy | None = None,
                    user_markers: list[dict] | None = None,
                    interval_start_ms: int | None = None,
                    interval_end_ms: int | None = None) -> dict:
    """Explicit intervals handle arbitrarily long bounded SQLite sessions.

    The original session remains read-only; summaries always reveal omitted rows.
    Schema-1 lifecycle is a recorded value, never a trusted OS attestation.
    """
    from .engine import _finding, _hash
    policy = validate_policy(policy)
    source = load_session(folder, policy=policy, interval_start_ms=interval_start_ms,
                          interval_end_ms=interval_end_ms)
    # A real USER command may arrive after the last periodic CPU sample.
    # Retain its timestamp but expose that the tail has no sampled CPU context.
    # Direct analyze() remains strict; never elevate such an event to OS evidence.
    report = analyze(source["samples"], markers=user_markers, policy=policy,
                     identity={"pid": source["pid"], "creation_time": None},
                     allow_trailing_user_ms=5000)
    coverage = source["coverage"]
    report["coverage"] = coverage
    if not coverage["full_session_covered"]:
        report["warnings"].append("PARTIAL_SESSION_INTERVAL")
    # No schema-1 PID creation-time, signed event, or OS window responsiveness witness.
    if source["exit_code"] == "PROCESS_EXITED" and source["samples"] and coverage["full_session_covered"]:
        elapsed = source["samples"][-1]["elapsed_ms"]
        finding = _finding("PROCESS_EXIT_RECORDED", elapsed, elapsed,
                           [{"metric": "session_exit_code", "value": "PROCESS_EXITED",
                             "source": "BLACKBOX_SQLITE_V1_METADATA", "verification": "RECORDED_NOT_ATTESTED"}],
                           "Local session metadata records an exit; it does not prove why or independently attest OS events.")
        if len(report["findings"]) < policy.max_findings:
            report["findings"].append(finding)
            report["findings"].sort(key=lambda x: (x["start_ms"], x["code"]))
        else:
            report["findings_omitted"] += 1
            if "FINDING_LIMIT_REACHED" not in report["warnings"]:
                report["warnings"].append("FINDING_LIMIT_REACHED")
    report["provenance"].update(sample_source="BLACKBOX_SQLITE_V1_READ_ONLY",
                                session_id=source["session_id"], session_exit_code=source["exit_code"],
                                session_ended=source["ended"], pid_creation_verified=False,
                                lifecycle_proof="RECORDED_NOT_ATTESTED")
    report["evidence_sha256"] = _hash({"analysis_hash": report["evidence_sha256"],
                                        "coverage": coverage, "findings": report["findings"],
                                        "lifecycle_proof": "RECORDED_NOT_ATTESTED"})
    return report
