"""Strict observational schema: unknown is never transformed into a fabricated zero."""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any


class InvestigationError(ValueError):
    """Predictable, non-sensitive failure codes for UI and CLI consumers."""
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def integer(value: Any, label: str, *, positive: bool = False, optional: bool = False) -> int | None:
    if value is None and optional:
        return None
    if type(value) is not int or value < (1 if positive else 0) or value > 2**63 - 1:
        raise InvestigationError("INVALID_" + label)
    return value


def number(value: Any, label: str, *, optional: bool = False) -> float | None:
    if value is None and optional:
        return None
    if type(value) not in (int, float):
        raise InvestigationError("INVALID_" + label)
    try:
        if not math.isfinite(value) or value < 0 or value > 1e100:
            raise InvestigationError("INVALID_" + label)
        return float(value)
    except (OverflowError, ValueError):
        raise InvestigationError("INVALID_" + label) from None


@dataclass(frozen=True)
class Policy:
    cpu_alert_percent: float = 80.0
    cpu_min_duration_ms: int = 2000
    rss_growth_alert_bytes: int = 64 * 1024 * 1024
    io_rate_alert_bps: float = 20 * 1024 * 1024
    gap_alert_ms: int = 5000
    context_before_ms: int = 10000
    context_after_ms: int = 10000
    max_samples: int = 4096
    max_events: int = 256
    max_threads_per_sample: int = 256
    max_findings: int = 64

    def __post_init__(self) -> None:
        for name in ("cpu_min_duration_ms", "rss_growth_alert_bytes", "gap_alert_ms",
                     "context_before_ms", "context_after_ms", "max_samples", "max_events",
                     "max_threads_per_sample", "max_findings"):
            integer(getattr(self, name), "POLICY")
        if not 1 <= self.max_samples <= 20000 or not 1 <= self.max_events <= 2000 or not 1 <= self.max_findings <= 200:
            raise InvestigationError("INVALID_POLICY")
        if not 1 <= self.max_threads_per_sample <= 2048:
            raise InvestigationError("INVALID_POLICY")
        if self.context_before_ms > 3600000 or self.context_after_ms > 3600000:
            raise InvestigationError("INVALID_POLICY")
        if self.cpu_min_duration_ms > 3600000 or self.gap_alert_ms > 3600000:
            raise InvestigationError("INVALID_POLICY")
        for value in (self.cpu_alert_percent, self.io_rate_alert_bps):
            number(value, "POLICY")
        if not 0 < self.cpu_alert_percent <= 6400 or self.io_rate_alert_bps <= 0:
            raise InvestigationError("INVALID_POLICY")


def validate_policy(policy: Policy | None) -> Policy:
    """Return a usable Policy or a stable public error, never AttributeError."""
    if policy is not None and type(policy) is not Policy:
        raise InvestigationError("INVALID_POLICY")
    return policy if policy is not None else Policy()


METRICS = ("cpu_percent", "rss_bytes", "private_bytes", "uss_bytes", "read_bytes", "write_bytes", "children_count", "num_threads")


def normalize_samples(raw: list[dict], policy: Policy) -> list[dict]:
    if type(raw) is not list or len(raw) > policy.max_samples:
        raise InvestigationError("SAMPLE_LIMIT")
    result: list[dict] = []
    previous = -1
    for item in raw:
        if type(item) is not dict:
            raise InvestigationError("INVALID_SAMPLE")
        elapsed = integer(item.get("elapsed_ms"), "ELAPSED_MS")
        if elapsed <= previous:
            raise InvestigationError("SAMPLE_ORDER_OR_DUPLICATE")
        if elapsed > 30 * 24 * 3600 * 1000:
            raise InvestigationError("SAMPLE_TIME_LIMIT")
        previous = elapsed
        row = {"elapsed_ms": elapsed}
        for key in METRICS:
            value = item.get(key)
            row[key] = number(value, key, optional=True) if key == "cpu_percent" else integer(value, key.upper(), optional=True)
        if row["cpu_percent"] is not None and row["cpu_percent"] > 6400:
            raise InvestigationError("INVALID_CPU_PERCENT")
        threads = item.get("threads")
        row["threads"] = None
        if threads is not None:
            if type(threads) is not list or len(threads) > policy.max_threads_per_sample:
                raise InvestigationError("THREAD_LIMIT")
            seen = set()
            records = []
            for t in threads:
                if type(t) is not dict:
                    raise InvestigationError("INVALID_THREAD")
                tid = integer(t.get("tid"), "TID", positive=True)
                if tid in seen:
                    raise InvestigationError("DUPLICATE_TID")
                seen.add(tid)
                cpu = number(t.get("cpu_seconds"), "THREAD_CPU", optional=True)
                records.append({"tid": tid, "cpu_seconds": cpu})
            row["threads"] = sorted(records, key=lambda t: t["tid"])
        result.append(row)
    return result


def normalize_markers(raw: list[dict] | None, policy: Policy, earliest: int, latest: int) -> list[dict]:
    if raw is None:
        return []
    if type(raw) is not list or len(raw) > policy.max_events:
        raise InvestigationError("EVENT_LIMIT")
    result: list[dict] = []
    for marker in raw:
        if type(marker) is not dict:
            raise InvestigationError("INVALID_MARKER")
        elapsed = integer(marker.get("elapsed_ms"), "MARKER_TIME")
        if elapsed < earliest or elapsed > latest:
            raise InvestigationError("MARKER_OUTSIDE_OBSERVATION")
        kind = marker.get("kind")
        if kind in ("observed_window_unresponsive", "observed_process_exit"):
            # Public caller strings cannot establish provenance, even if named OS/BLACKBOX.
            raise InvestigationError("UNATTESTED_SYSTEM_EVENT")
        if kind not in ("user_problem", "unverified_report"):
            raise InvestigationError("INVALID_MARKER_KIND")
        source = marker.get("source", "USER")
        if type(source) is not str or source not in ("USER", "EXTERNAL_UNVERIFIED"):
            raise InvestigationError("INVALID_MARKER_SOURCE")
        note = marker.get("note", "")
        if type(note) is not str or len(note) > 160 or any(ord(c) < 32 for c in note):
            raise InvestigationError("INVALID_MARKER_NOTE")
        result.append({"elapsed_ms": elapsed, "kind": kind, "note": note, "source": source, "verification": "UNVERIFIED"})
    return sorted(result, key=lambda e: (e["elapsed_ms"], e["kind"]))
