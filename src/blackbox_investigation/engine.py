"""Offline explainable investigation of real observations, never a root-cause oracle."""
from __future__ import annotations

import hashlib
import json
import math
from statistics import median
from .model import InvestigationError, Policy, validate_policy, normalize_samples, normalize_markers


def _hash(data: object) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def _percentile(values: list[float], percent: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    position = (len(values) - 1) * percent / 100
    lower, upper = math.floor(position), math.ceil(position)
    return round(values[lower] + (values[upper] - values[lower]) * (position - lower), 4)


def _stats(values: list[float]) -> dict:
    return {"count": len(values), "min": min(values) if values else None,
            "mean": round(sum(values)/len(values), 4) if values else None,
            "median": median(values) if values else None,
            "p95": _percentile(values, 95), "max": max(values) if values else None}


def _finding(code: str, start: int, end: int, facts: list[dict], limitation: str, *, inference: bool = False) -> dict:
    return {"code": code, "start_ms": start, "end_ms": end, "facts": facts,
            "interpretation": "CANDIDATE_NOT_CAUSAL_PROOF" if inference else "OBSERVATION_ONLY",
            "limitation": limitation}


def analyze(samples: list[dict], *, markers: list[dict] | None = None, policy: Policy | None = None,
            identity: dict | None = None, allow_trailing_user_ms: int = 0) -> dict:
    """Analyze supplied, ordered samples; no OS access, no sampling and no unbounded state.

    A CPU 'episode' measures consecutive observed intervals and does not invent the
    behavior between samples. Thread CPU is only computed for a persistent TID.
    """
    policy = validate_policy(policy)
    rows = normalize_samples(samples, policy)
    first = rows[0]["elapsed_ms"] if rows else 0
    last = rows[-1]["elapsed_ms"] if rows else 0
    marks = normalize_markers(markers, policy, first, last,
                              allow_trailing_user_ms=allow_trailing_user_ms)
    if identity is not None:
        if type(identity) is not dict or type(identity.get("pid")) is not int or identity["pid"] <= 0:
            raise InvestigationError("INVALID_IDENTITY")
        creation = identity.get("creation_time")
        if creation is not None and (type(creation) not in (float, int) or creation <= 0 or
                                     not math.isfinite(creation) or creation > 1e100):
            raise InvestigationError("INVALID_IDENTITY")
        # Do not trust or forward arbitrary keys (paths, usernames, commands, secrets).
        ident = {"pid": identity["pid"], "creation_time": creation}
    else:
        ident = None
    findings: list[dict] = []
    timeline = []
    rates = []
    thread_hotspots = []
    cpu_start, cpu_last = None, None
    for ix, row in enumerate(rows):
        prev = rows[ix-1] if ix else None
        point = {"elapsed_ms": row["elapsed_ms"], "cpu_percent": row["cpu_percent"],
                 "rss_bytes": row["rss_bytes"], "private_bytes": row["private_bytes"], "uss_bytes": row["uss_bytes"],
                 "num_threads": row["num_threads"], "children_count": row["children_count"],
                 "read_bps": None, "write_bps": None, "threads": []}
        if prev:
            dt = row["elapsed_ms"] - prev["elapsed_ms"]
            if dt > policy.gap_alert_ms:
                findings.append(_finding("OBSERVATION_GAP", prev["elapsed_ms"], row["elapsed_ms"],
                                         [{"metric": "gap_ms", "value": dt}], "Nothing is observed inside the gap."))
            for key, rate_name in (("read_bytes", "read_bps"), ("write_bytes", "write_bps")):
                current, before = row[key], prev[key]
                if current is not None and before is not None:
                    if current < before:
                        findings.append(_finding("COUNTER_RESET", prev["elapsed_ms"], row["elapsed_ms"],
                                                 [{"metric": key, "from": before, "to": current}],
                                                 "Process or counter reset; negative I/O speed is invalid."))
                    elif dt <= policy.gap_alert_ms:
                        point[rate_name] = round((current-before)*1000/dt, 3)
                        rates.append(point[rate_name])
            old_threads = {t["tid"]: t["cpu_seconds"] for t in (prev["threads"] or [])}
            for t in row["threads"] or []:
                earlier = old_threads.get(t["tid"])
                if earlier is None or t["cpu_seconds"] is None:
                    continue
                delta = t["cpu_seconds"]-earlier
                if delta < 0:
                    continue  # TID reuse/counter reset: unknown, not negative CPU.
                if dt <= policy.gap_alert_ms:
                    pct = 100 * delta / (dt / 1000)
                    if 0 <= pct <= 110:
                        detail = {"tid": t["tid"], "cpu_percent_one_core": round(min(pct, 100), 3)}
                        point["threads"].append(detail)
                        thread_hotspots.append({"elapsed_ms": row["elapsed_ms"], **detail})
        timeline.append(point)
        if row["cpu_percent"] is not None and row["cpu_percent"] >= policy.cpu_alert_percent:
            if prev and cpu_last == prev["elapsed_ms"] and row["elapsed_ms"]-prev["elapsed_ms"] <= policy.gap_alert_ms:
                cpu_last = row["elapsed_ms"]
            else:
                if cpu_start is not None and cpu_last is not None and cpu_last-cpu_start >= policy.cpu_min_duration_ms:
                    findings.append(_finding("SUSTAINED_HIGH_CPU", cpu_start, cpu_last,
                                             [{"metric": "cpu_percent", "threshold": policy.cpu_alert_percent}],
                                             "High process CPU does not identify the executing function.", inference=True))
                cpu_start, cpu_last = row["elapsed_ms"], row["elapsed_ms"]
        else:
            if cpu_start is not None and cpu_last is not None and cpu_last-cpu_start >= policy.cpu_min_duration_ms:
                findings.append(_finding("SUSTAINED_HIGH_CPU", cpu_start, cpu_last,
                                         [{"metric": "cpu_percent", "threshold": policy.cpu_alert_percent}],
                                         "High process CPU does not identify the executing function.", inference=True))
            cpu_start, cpu_last = None, None
    if cpu_start is not None and cpu_last is not None and cpu_last-cpu_start >= policy.cpu_min_duration_ms:
        findings.append(_finding("SUSTAINED_HIGH_CPU", cpu_start, cpu_last,
                                 [{"metric": "cpu_percent", "threshold": policy.cpu_alert_percent}],
                                 "High process CPU does not identify the executing function.", inference=True))
    for field in ("rss_bytes", "private_bytes", "uss_bytes"):
        valid = [(r["elapsed_ms"], r[field]) for r in rows if r[field] is not None]
        if len(valid) >= 3:
            beginning, ending = valid[0], valid[-1]
            growth = ending[1]-beginning[1]
            if growth > 0 and growth >= policy.rss_growth_alert_bytes:
                findings.append(_finding("MEMORY_GROWTH_CANDIDATE", beginning[0], ending[0],
                                         [{"metric": field, "growth_bytes": growth, "first": beginning[1],
                                           "last": ending[1], "measured_points": len(valid)}],
                                         "Memory growth is not proof of a leak; repeat equivalent operations and inspect allocations.",
                                         inference=True))
    high_rate = [(p["elapsed_ms"], k, p[k]) for p in timeline for k in ("read_bps", "write_bps")
                 if p[k] is not None and p[k] >= policy.io_rate_alert_bps]
    for time, field, value in high_rate[:policy.max_findings]:
        findings.append(_finding("HIGH_IO_RATE", time, time,
                                 [{"metric": field, "bytes_per_second": value}],
                                 "Byte throughput does not reveal operation latency, path or responsible code.", inference=True))
    if thread_hotspots:
        hottest = max(thread_hotspots, key=lambda x: x["cpu_percent_one_core"])
        if hottest["cpu_percent_one_core"] >= 50:
            findings.append(_finding("HOT_THREAD_OBSERVED", hottest["elapsed_ms"], hottest["elapsed_ms"],
                                     [{"metric": "thread_cpu_percent_one_core", "tid": hottest["tid"],
                                       "value": hottest["cpu_percent_one_core"]}],
                                     "Without independently obtained stacks no function, wait state or root cause is known."))
    # User markers stay markers, not elevated to system findings.
    # The SQLite lifecycle adapter adds a separate RECORDED_NOT_ATTESTED finding.
    findings.sort(key=lambda f: (f["start_ms"], f["code"]))
    truncated = max(0, len(findings)-policy.max_findings)
    findings = findings[:policy.max_findings]
    anchor_times = {m["elapsed_ms"] for m in marks}
    anchor_times.update(f["start_ms"] for f in findings)
    capture = []
    for time in sorted(anchor_times)[:policy.max_events]:
        context = [p["elapsed_ms"] for p in timeline if time-policy.context_before_ms <= p["elapsed_ms"] <= time+policy.context_after_ms]
        capture.append({"anchor_ms": time, "first_sample_ms": context[0] if context else None,
                        "last_sample_ms": context[-1] if context else None, "sample_count": len(context)})
    summary = {"cpu_percent": _stats([r["cpu_percent"] for r in rows if r["cpu_percent"] is not None]),
               "rss_bytes": _stats([r["rss_bytes"] for r in rows if r["rss_bytes"] is not None]),
               "private_bytes": _stats([r["private_bytes"] for r in rows if r["private_bytes"] is not None]),
               "uss_bytes": _stats([r["uss_bytes"] for r in rows if r["uss_bytes"] is not None]),
               "io_bytes_per_second": _stats(rates),
               "observed_thread_intervals": len(thread_hotspots)}
    sanitized_rows = [{k: v for k, v in p.items() if k != "threads"} for p in timeline]
    result = {"schema_version": 2, "type": "BLACKBOX_INVESTIGATION", "identity": ident,
              "observation_count": len(rows), "observation_interval_ms": [first, last] if rows else None,
              "input_sha256": _hash({"samples": rows, "markers": marks, "identity": ident}),
              "summary": summary, "timeline": timeline, "markers": marks,
              "findings": findings, "findings_omitted": truncated, "captures": capture,
              "claims": {"internal_root_cause": "UNKNOWN", "deadlock": "NOT_PROVEN",
                         "memory_leak": "NOT_PROVEN", "causal_link": "NOT_PROVEN",
                         "source_stack": "NOT_OBSERVED", "etw": "NOT_OBSERVED", "wct": "NOT_OBSERVED"},
              "provenance": {"sample_source": "APP_SUPPLIED_UNAUTHENTICATED", "os_proof": "NOT_ATTESTED",
                             "digest_is_attestation": False, "input_contract_version": 2,
                             "pid_creation_verified": ident is not None and ident["creation_time"] is not None},
              "warnings": (["NO_OBSERVATIONS"] if not rows else []) +
                          (["FINDING_LIMIT_REACHED"] if truncated else []) +
                          (["UNSAMPLED_USER_MARKER"] if any(
                              m.get("sampling_context") == "UNSAMPLED_AFTER_LAST_OBSERVATION"
                              for m in marks) else []),
              "limitations": ["External counters do not establish application-internal cause.",
                              "Event coincidences do not demonstrate causality.",
                              "Unknown and unobserved measures are not imputed.",
                              "Thread CPU needs persistent TID; a reused TID is not independently attested.",
                              "No injection, tracing, dumps, registry access or process mutation."]}
    # Reproducible evidence digest excludes incidental output encoding and paths.
    result["evidence_sha256"] = _hash({"input": result["input_sha256"], "timeline": sanitized_rows,
                                       "findings": findings, "markers": marks})
    return result


def compare_reports(first: dict, second: dict) -> dict:
    """Compare two complete, well-formed v2 summaries; never trust imported JSON."""
    import re
    fields = ("cpu_percent", "rss_bytes", "private_bytes", "uss_bytes", "io_bytes_per_second")
    for report in (first, second):
        if (type(report) is not dict or report.get("type") != "BLACKBOX_INVESTIGATION" or
                type(report.get("schema_version")) is not int or report["schema_version"] != 2 or
                type(report.get("summary")) is not dict or
                type(report.get("evidence_sha256")) is not str or
                re.fullmatch(r"[0-9a-f]{64}", report["evidence_sha256"]) is None):
            raise InvestigationError("INVALID_COMPARISON")
        for field in fields:
            metric = report["summary"].get(field)
            if type(metric) is not dict or "median" not in metric or "count" not in metric:
                raise InvestigationError("INVALID_COMPARISON")
            if type(metric["count"]) is not int or metric["count"] < 0:
                raise InvestigationError("INVALID_COMPARISON")
            mid = metric["median"]
            if mid is not None and (type(mid) not in (int, float) or not math.isfinite(mid) or mid < 0):
                raise InvestigationError("INVALID_COMPARISON")
            if (metric["count"] == 0) != (mid is None):
                raise InvestigationError("INVALID_COMPARISON")
    diffs = {}
    for field in fields:
        a, b = first["summary"][field]["median"], second["summary"][field]["median"]
        diffs[field] = {"first_median": a, "second_median": b,
                        "delta": round(b-a, 4) if a is not None and b is not None else None}
    return {"schema_version": 2, "type": "BLACKBOX_INVESTIGATION_COMPARISON",
            "metrics": diffs, "performance_regression_proven": False,
            "interpretation": "SESSIONS_MAY_DIFFER_IN_WORKLOAD_AND_ENVIRONMENT",
            "first_digest": first["evidence_sha256"], "second_digest": second["evidence_sha256"]}
