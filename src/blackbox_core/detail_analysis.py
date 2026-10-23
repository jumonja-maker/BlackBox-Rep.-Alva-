"""Read-only, bounded TID CPU interval analysis of an opt-in detail-v2 sidecar.

Thread CPU time is cumulative. A percentage exists ONLY for adjacent process
samples where the same TID was observed twice. Windows/psutil do not provide
thread birth identity here: even adjacent matching TIDs can have been reused.
This is external-counter evidence, never a hang or root-cause proof.
"""
from __future__ import annotations

from contextlib import closing
from math import isfinite
from pathlib import Path
import sqlite3


def _seconds(value: object) -> float | None:
    if type(value) not in (int, float):
        return None
    result = float(value)
    return result if isfinite(result) and result >= 0 else None


def analyze_detail_threads(folder: Path, *, max_samples: int = 128,
                           top_n: int = 16) -> dict:
    """Derive bounded per-TID CPU% from truly adjacent, valid snapshots.

    Returned CPU% is single-core-equivalent: 100 means approximately one
    logical processor fully occupied; it is NOT normalized by host core count.
    Missing/mismatched samples are never converted into zero percent.
    """
    if type(max_samples) is not int or not 2 <= max_samples <= 256:
        raise ValueError("INVALID_MAX_SAMPLES")
    if type(top_n) is not int or not 1 <= top_n <= 64:
        raise ValueError("INVALID_TOP_N")
    folder = Path(folder)
    path = folder / "detail-v2.sqlite3"
    empty = {"status": "NOT_RECORDED", "source_kind": "PSUTIL",
             "verification_class": "DERIVED", "root_cause_proven": False,
             "tid_reuse_uncertain": True, "cpu_unit": "single_core_percent",
             "sample_window": 0, "pair_count": 0, "top_threads": [],
             "warnings": ["DETAIL_NOT_RECORDED"]}
    if folder.is_symlink() or path.is_symlink() or not path.is_file():
        return empty
    try:
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro",
                                     uri=True, timeout=1)) as db:
            db.execute("PRAGMA query_only=ON")
            row = db.execute(
                "SELECT schema_version, pid, created FROM detail_metadata LIMIT 1"
            ).fetchone()
            if (row is None or type(row[0]) is not int or row[0] != 2
                    or type(row[1]) is not int or row[1] <= 0
                    or _seconds(row[2]) is None or row[2] <= 0):
                return {**empty, "status": "UNSUPPORTED_DETAILED_SCHEMA",
                        "warnings": ["INVALID_DETAIL_METADATA"]}
            pid = row[1]
            samples = list(reversed(db.execute(
                "SELECT seq, time_monotonic_ns, thread_status, threads_omitted "
                "FROM process_samples ORDER BY seq DESC LIMIT ?", (max_samples,)
            ).fetchall()))
            if not samples:
                return {**empty, "status": "NO_SAMPLES", "warnings": ["NO_SAMPLES"]}
            # An indexed bounded interval; reject corrupted/oversized sidecars
            # rather than silently dropping later TIDs and distorting rankings.
            row_cap = max_samples * 256 + 1
            details = db.execute(
                "SELECT sample_seq, pid, tid, cpu_user_s, cpu_system_s "
                "FROM thread_samples WHERE sample_seq BETWEEN ? AND ? "
                "ORDER BY sample_seq, tid LIMIT ?",
                (samples[0][0], samples[-1][0], row_cap)
            ).fetchall()
            if len(details) >= row_cap:
                return {**empty, "status": "DETAIL_READ_LIMIT_REACHED",
                        "warnings": ["TOO_MANY_THREAD_ROWS"]}
            by_seq: dict[int, dict[int, tuple[float, float]]] = {}
            for seq, observed_pid, tid, user, system in details:
                if (type(seq) is not int or type(tid) is not int or tid < 0
                        or observed_pid != pid or _seconds(user) is None
                        or _seconds(system) is None):
                    return {**empty, "status": "INVALID_DETAILED_DATA",
                            "warnings": ["INVALID_THREAD_COUNTER"]}
                snapshot = by_seq.setdefault(seq, {})
                if tid in snapshot:
                    return {**empty, "status": "INVALID_DETAILED_DATA",
                            "warnings": ["DUPLICATE_TID_SAMPLE"]}
                snapshot[tid] = (float(user), float(system))
            # Separate observed TID lifetimes: a TID that disappears and
            # reappears must not reuse an earlier CPU aggregate.
            aggregates: dict[tuple[int, int], dict] = {}
            segment_starts: dict[int, int] = {}
            previous = None
            previous_threads: dict[int, tuple[float, float]] = {}
            pair_count = 0
            gap_count = 0
            counter_resets = 0
            omitted = False
            for seq, timestamp, thread_status, threads_omitted in samples:
                if (type(seq) is not int or type(timestamp) is not int
                        or seq <= 0 or timestamp < 0):
                    return {**empty, "status": "INVALID_DETAILED_DATA",
                            "warnings": ["INVALID_SAMPLE_TIME"]}
                current = by_seq.get(seq, {})
                if (thread_status != "OK" or threads_omitted is None
                        or type(threads_omitted) is not int or threads_omitted < 0):
                    omitted = True
                if threads_omitted is not None and threads_omitted > 0:
                    omitted = True
                comparable = False
                if previous is not None:
                    previous_seq, previous_time, previous_ok = previous
                    if (seq == previous_seq + 1 and timestamp > previous_time
                            and previous_ok and thread_status == "OK"):
                        comparable = True
                        dt = (timestamp - previous_time) / 1_000_000_000
                        pair_count += 1
                        for tid, (user, system) in current.items():
                            if tid not in previous_threads:
                                continue  # new TID: no fabricated delta
                            old_user, old_system = previous_threads[tid]
                            du, ds = user - old_user, system - old_system
                            if du < 0 or ds < 0:
                                counter_resets += 1
                                segment_starts[tid] = seq
                                continue  # start a new segment on reset
                            delta = du + ds
                            rate = 100.0 * delta / dt
                            if not isfinite(rate):
                                counter_resets += 1
                                continue
                            segment = segment_starts.get(tid, previous_seq)
                            record = aggregates.setdefault((tid, segment), {
                                "tid": tid, "pid": pid,
                                "segment_start_seq": segment,
                                "observed_pairs": 0,
                                "_cpu_delta": 0.0, "_elapsed": 0.0,
                                "peak_cpu_percent": 0.0, "last_seen_seq": seq})
                            record["_cpu_delta"] += delta
                            record["_elapsed"] += dt
                            record["observed_pairs"] += 1
                            record["last_seen_seq"] = seq
                            record["peak_cpu_percent"] = max(
                                record["peak_cpu_percent"], rate)
                    else:
                        gap_count += 1
                if comparable:
                    segment_starts = {tid: segment_starts.get(tid, seq)
                                      for tid in current}
                else:
                    segment_starts = {tid: seq for tid in current}
                previous = (seq, timestamp, thread_status == "OK")
                previous_threads = current
            threads = []
            for record in aggregates.values():
                average = 100.0 * record.pop("_cpu_delta") / record.pop("_elapsed")
                record["cpu_percent"] = round(average, 3)
                record["peak_cpu_percent"] = round(record["peak_cpu_percent"], 3)
                record["source_kind"] = "PSUTIL"
                record["verification_class"] = "DERIVED"
                record["tid_reuse_uncertain"] = True
                threads.append(record)
            threads.sort(key=lambda x: (-x["cpu_percent"], -x["peak_cpu_percent"],
                                        x["tid"], x["segment_start_seq"]))
            warnings = ["TID_REUSE_CANNOT_BE_EXCLUDED"]
            if omitted:
                warnings.append("THREAD_COVERAGE_PARTIAL")
            if gap_count:
                warnings.append("NON_ADJACENT_OR_INVALID_SAMPLE_GAPS")
            if counter_resets:
                warnings.append("THREAD_CPU_COUNTER_RESET")
            if len(samples) == max_samples:
                warnings.append("RECENT_WINDOW_ONLY")
            return {
                "status": "OK" if threads else "NO_COMPARABLE_THREAD_INTERVALS",
                "source_kind": "PSUTIL", "verification_class": "DERIVED",
                "root_cause_proven": False, "tid_reuse_uncertain": True,
                "cpu_unit": "single_core_percent", "pid": pid,
                "sample_window": len(samples), "pair_count": pair_count,
                "gaps": gap_count, "counter_resets": counter_resets,
                "threads_ranked": len(threads),
                "top_threads": threads[:top_n], "warnings": warnings,
            }
    except (sqlite3.Error, OSError, ValueError, TypeError, OverflowError):
        return {**empty, "status": "DETAIL_READ_UNAVAILABLE",
                "warnings": ["DETAIL_READ_UNAVAILABLE"]}
