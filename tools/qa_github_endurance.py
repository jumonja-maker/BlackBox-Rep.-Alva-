"""Explicit Windows Actions long-run QA; NEVER certify a shortened run as 8h.

Starts only a disposable, self-owned longrun target. Runs the existing real
PySide6 GUI + isolated helper production endurance harness, keeps periodic
progress, and independently verifies both persisted SQLite databases before
marking this particular GitHub test successful. No release or native trace.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def verify_sampling_coverage(*, count, span_seconds, max_gap_seconds, nonpositive_gaps,
                             requested_seconds, boundary_tolerance_seconds,
                             maximum_gap_seconds, minimum_count_interval_seconds, label):
    """Validate persisted coverage, independently of the harness wall clock."""
    minimum_span = max(0, requested_seconds - boundary_tolerance_seconds)
    if (type(count) is not int or count < 2 or
            not math.isfinite(span_seconds) or span_seconds < minimum_span):
        raise RuntimeError(label + "_PERSISTED_SPAN_TOO_SHORT")
    if (nonpositive_gaps or not math.isfinite(max_gap_seconds) or
            max_gap_seconds > maximum_gap_seconds):
        raise RuntimeError(label + "_PERSISTED_SAMPLE_GAP")
    minimum_count = max(2, math.ceil(minimum_span / minimum_count_interval_seconds) + 1)
    if count < minimum_count:
        raise RuntimeError(label + "_PERSISTED_SAMPLE_COVERAGE_TOO_LOW")
    return {"persisted_span_seconds": span_seconds, "max_sample_gap_seconds": max_gap_seconds,
            "persisted_samples": count, "minimum_required_samples": minimum_count,
            "requested_seconds": requested_seconds, "boundary_tolerance_seconds": boundary_tolerance_seconds,
            "maximum_gap_seconds": maximum_gap_seconds,
            "minimum_count_interval_seconds": minimum_count_interval_seconds,
            "nonincreasing_timestamps": nonpositive_gaps}


def _evidence(root: Path, profile: str, requested: int, expected_sha: str):
    output = root / "run"
    result = _read_json(output / "result.json")
    if result.get("state") != "COMPLETED":
        raise RuntimeError("QA_HARNESS_NOT_COMPLETED")
    source = result.get("source") or {}
    if (source.get("actual_source_sha") != expected_sha or
            source.get("source_identity_status") != "VERIFIED_EXPECTED_HEAD"):
        raise RuntimeError("QA_SOURCE_SHA_NOT_VERIFIED")
    phases = result.get("phases") or []
    if len(phases) != 1 or phases[0].get("phase") != profile:
        raise RuntimeError("QA_UNEXPECTED_PHASES")
    phase = phases[0]
    seconds = phase.get("actual_seconds")
    if type(seconds) not in (int, float) or seconds < requested:
        raise RuntimeError("QA_FULL_REQUESTED_DURATION_NOT_MET")
    if phase.get("recording_state") != "COMPLETED":
        raise RuntimeError("QA_PRIMARY_RECORDING_NOT_COMPLETED")
    session_text = phase.get("session")
    if not session_text:
        raise RuntimeError("QA_MISSING_SESSION")
    folder = Path(session_text).resolve()
    if not folder.is_relative_to((output / "sessions").resolve()):
        raise RuntimeError("QA_SESSION_OUTSIDE_OWNED_ROOT")
    primary_path = folder / "session.sqlite3"
    detail_path = folder / "session-v2.sqlite3"
    research_path = folder / "research.sqlite3"
    for path in (primary_path, detail_path, research_path):
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("QA_REQUIRED_DATABASE_UNAVAILABLE")
    source_hashes = {
        path.name: _digest(path) for path in
        (primary_path, detail_path, research_path)
    }
    with closing(sqlite3.connect(primary_path.as_uri() + "?mode=ro", uri=True)) as db:
        original = db.execute(
            "SELECT schema_version,pid,exit_code FROM metadata LIMIT 2").fetchall()
        n, first, last = db.execute(
            "SELECT COUNT(*),COALESCE(MIN(seq),0),COALESCE(MAX(seq),0) "
            "FROM samples").fetchone()
    with closing(sqlite3.connect(detail_path.as_uri() + "?mode=ro", uri=True)) as db:
        normalized = db.execute(
            "SELECT status,exit_code,writer_dropped_commands FROM sessions LIMIT 2"
        ).fetchall()
        targets = db.execute("SELECT root_pid FROM targets LIMIT 2").fetchall()
        mirrored, start, stop, mislinked = db.execute(
            "SELECT COUNT(*),COALESCE(MIN(series_seq),0),"
            "COALESCE(MAX(series_seq),0),"
            "COALESCE(SUM(CASE WHEN instance_id!=1 OR "
            "correlation_key!='schema1:' || series_seq "
            "THEN 1 ELSE 0 END),0) "
            "FROM samples WHERE series='STANDARD'").fetchone()
        errors = db.execute(
            "SELECT COUNT(*) FROM sensor_errors "
            "WHERE sensor_id='SCHEMA2_WRITER'").fetchone()[0]
        first_ns, last_ns = db.execute(
            "SELECT MIN(monotonic_ns),MAX(monotonic_ns) FROM samples "
            "WHERE series='STANDARD'").fetchone()
        max_gap_ns, nonpositive_gaps = db.execute("""
            SELECT MAX(gap),COALESCE(SUM(CASE WHEN gap<=0 THEN 1 ELSE 0 END),0)
            FROM (SELECT monotonic_ns-LAG(monotonic_ns) OVER(ORDER BY series_seq) gap
                  FROM samples WHERE series='STANDARD')
        """).fetchone()
    with closing(sqlite3.connect(research_path.as_uri() + "?mode=ro", uri=True)) as db:
        row = db.execute("SELECT data FROM context WHERE key='state'").fetchone()
        research_state = json.loads(row[0]) if row else None
    if (len(original) != 1 or original[0][0] != 1 or
            original[0][2] != "COMPLETED" or
            len(normalized) != 1 or normalized[0] !=
            ("CLOSED", "COMPLETED", 0) or
            len(targets) != 1 or targets[0][0] != original[0][1] or
            research_state != "COMPLETED"):
        raise RuntimeError("QA_PERSISTED_COMPLETION_NOT_CONFIRMED")
    if (n < 1 or first != 1 or last != n or
            mirrored != n or start != 1 or stop != n or
            mislinked != 0 or errors):
        raise RuntimeError("QA_V1_V2_STANDARD_PARITY_FAILURE")
    if type(first_ns) is not int or type(last_ns) is not int or first_ns >= last_ns:
        raise RuntimeError("QA_INSUFFICIENT_TIME_SERIES")
    # The production recorder starts at 2 s and adaptive throttling may use
    # 5 s. Permit half that worst-case sample density, a 30 s largest gap and
    # 10 s for the first/last saved sample around recording boundaries. A long
    # wall-clock phase with a short or sparse persisted recording never passes.
    sampling = verify_sampling_coverage(count=n, span_seconds=(last_ns - first_ns) / 1e9,
        max_gap_seconds=(max_gap_ns or 0) / 1e9, nonpositive_gaps=nonpositive_gaps,
        requested_seconds=requested, boundary_tolerance_seconds=10,
        maximum_gap_seconds=30, minimum_count_interval_seconds=10, label="QA_OBSERVER")
    if phase.get("recorded_samples", 0) < n:
        raise RuntimeError("QA_BRIDGE_REPORTED_FUZZY_SAMPLE_COUNT")
    # Validate *saved* read-only interval/zoom/export. Open at three distant
    # positions so a long history cannot be accepted by a tail-only viewer.
    from blackbox_core.interval_report import export_interval
    from blackbox_core.session_view import SessionView
    with SessionView.open(folder) as view:
        lo, hi, count = view.bounds("STANDARD", 1)
        if lo != first_ns or hi != last_ns or count != n:
            raise RuntimeError("QA_READONLY_BOUNDS_MISMATCH")
        middle = lo + (hi - lo) // 2
        starts = (lo, middle, max(lo, hi - 60_000_000_000))
        for start_ns in starts:
            selected = view.interval(
                start_ns, min(hi, start_ns + 60_000_000_000),
                series="STANDARD", instance_id=1)
            if selected.get("coverage", {}).get("selected_samples", 0) < 1:
                raise RuntimeError("QA_MIDDLE_MINUTE_NOT_READABLE")
    exports = root / "exports"
    exports.mkdir(exist_ok=True)
    report = export_interval(
        folder, exports, interval=(
            middle, min(hi, middle + 60_000_000_000)),
        series="STANDARD", instance_id=1,
        prefix=profile.lower() + "-middle-minute")
    for path in (primary_path, detail_path, research_path):
        if _digest(path) != source_hashes[path.name]:
            raise RuntimeError("QA_READONLY_ANALYSIS_CHANGED_SOURCE")
    result["actual_full_duration_for_this_ci_run"] = True
    return {
        "result": "PASS", "profile": profile, "requested_seconds": requested,
        "actual_seconds": seconds,
        "v1_base_samples": n, "v2_standard_samples": mirrored,
        "persisted_recording_coverage": sampling,
        "invalid_source_links": mislinked, "schema2_writer_errors": errors,
        "research_state": research_state,
        "primary_exit_code": original[0][2],
        "normalized_status": normalized[0][0],
        "source": source,
        "longrun_8h_original_requirement_met": bool(
            profile == "STANDARD" and seconds >= 28800),
        "original_profile_duration_met": bool(
            seconds >= (28800 if profile == "STANDARD" else 3600)),
        "not_a_physical_win10_11_acceptance": True,
        "off_on_overhead_1_3pp_not_certified": True,
        "source_hashes_sha256": source_hashes,
        "interval_export": report,
    }


def run(args):
    root = Path(args.output).resolve()
    if root.exists() and any(root.iterdir()):
        raise RuntimeError("QA_OUTPUT_DIRECTORY_NOT_EMPTY")
    root.mkdir(parents=True, exist_ok=True)
    target = None
    runner = None
    target_log = None
    qa_log = None
    verdict = {
        "result": "RUNNING", "profile": args.profile,
        "requested_seconds": args.duration_seconds,
        "expected_source_sha": args.expected_sha,
    }
    try:
        fixture = root / "fixture"
        fixture.mkdir()
        target_log = (root / "fixture.log").open("w", encoding="utf-8")
        ttl = args.duration_seconds + 600
        target = subprocess.Popen([
            sys.executable, "-u", "-m", "blackbox_core.qa_workloads",
            "longrun", str(fixture), "--seconds", str(ttl),
        ], stdin=subprocess.DEVNULL, stdout=target_log,
            stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 60
        ready = fixture / "ready.json"
        while not ready.is_file() and time.monotonic() < deadline:
            if target.poll() is not None:
                raise RuntimeError("QA_DISPOSABLE_TARGET_EXITED_BEFORE_READY")
            time.sleep(.2)
        if not ready.is_file():
            raise RuntimeError("QA_DISPOSABLE_TARGET_NOT_READY")
        identity = _read_json(ready)
        pid = identity.get("pid")
        if (identity.get("mode") != "longrun" or
                identity.get("fixture") != "REAL_OS_QA_ONLY" or
                type(pid) is not int or pid <= 0):
            raise RuntimeError("QA_INVALID_TARGET_IDENTITY")
        print("BB_QA_TARGET " + json.dumps({
            "pid": pid, "profile": args.profile,
            "requested_seconds": args.duration_seconds,
            "expected_sha": args.expected_sha,
        }), flush=True)
        qa_log = (root / "production-qa.log").open("w", encoding="utf-8")
        command = [
            sys.executable, "-u", "-m",
            "blackbox_universal.production_qa", "endurance",
            "--pid", str(pid), "--output", str(root / "run"),
            "--profile", args.profile,
            "--duration-seconds", str(args.duration_seconds),
            "--expected-sha", args.expected_sha,
        ]
        runner = subprocess.Popen(command, stdout=qa_log,
                                  stderr=subprocess.STDOUT)
        start = time.monotonic()
        last_log = 0.
        last_progress = start
        last_progress_stamp = None
        while runner.poll() is None:
            now = time.monotonic()
            if now - start > args.duration_seconds + 600:
                runner.kill()
                raise RuntimeError("QA_ENDURANCE_WATCHDOG_TIMEOUT")
            if target.poll() is not None:
                runner.kill()
                raise RuntimeError("QA_DISPOSABLE_TARGET_EXITED_EARLY")
            progress = root / "run" / "progress.json"
            if progress.is_file():
                try:
                    stamp = progress.stat().st_mtime_ns
                    if stamp != last_progress_stamp:
                        last_progress_stamp = stamp
                        last_progress = now
                except OSError:
                    pass
            if now - start > 180 and now - last_progress > 180:
                runner.kill()
                raise RuntimeError("QA_PROGRESS_NOT_UPDATING")
            if now - last_log >= 600 or last_log == 0:
                status = {}
                try:
                    if progress.is_file():
                        observed = _read_json(progress)
                        status = {
                            "completed_seconds": observed.get("actual_phase_seconds"),
                            "recorded_samples": observed.get("recorded_samples"),
                            "phase": observed.get("phase"),
                        }
                except (OSError, ValueError):
                    status = {"progress": "TEMPORARILY_UNAVAILABLE"}
                print("BB_QA_HEARTBEAT " + json.dumps({
                    "profile": args.profile, "elapsed_seconds": round(now-start),
                    **status}, allow_nan=False), flush=True)
                last_log = now
            time.sleep(5)
        qa_log.flush()
        if runner.returncode:
            raise RuntimeError("QA_HARNESS_FAILED_EXIT_" + str(runner.returncode))
        verdict = _evidence(
            root, args.profile, args.duration_seconds, args.expected_sha)
        print("BB_QA_VERIFIED " + json.dumps({
            key: verdict[key] for key in (
                "result", "profile", "actual_seconds",
                "v1_base_samples", "v2_standard_samples",
                "invalid_source_links", "normalized_status",
            )}, allow_nan=False), flush=True)
        return 0
    except Exception as exc:
        verdict.update(result="FAIL", error=type(exc).__name__ + ": " + str(exc)[:600])
        print("BB_QA_FAILURE " + json.dumps(verdict, allow_nan=False), flush=True)
        return 1
    finally:
        if runner is not None and runner.poll() is None:
            runner.kill()
            try:
                runner.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        if target is not None:
            (root / "fixture" / "stop.request").touch()
            try:
                target.wait(timeout=20)
            except subprocess.TimeoutExpired:
                target.terminate()
                try:
                    target.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    target.kill()
                    target.wait()
        if qa_log is not None:
            qa_log.close()
        if target_log is not None:
            target_log.close()
        (root / "qa-verdict.json").write_text(
            json.dumps(verdict, indent=2, ensure_ascii=False,
                       allow_nan=False) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=("STANDARD", "DETAILED"), required=True)
    parser.add_argument("--duration-seconds", type=int, required=True)
    parser.add_argument("--expected-sha", required=True)
    args = parser.parse_args()
    if (not 30 <= args.duration_seconds <= 19800 or
            len(args.expected_sha) != 40 or
            any(c not in "0123456789abcdef" for c in args.expected_sha)):
        parser.error("INVALID_DURATION_OR_SOURCE_SHA")
    raise SystemExit(run(args))


if __name__ == "__main__":
    main()
