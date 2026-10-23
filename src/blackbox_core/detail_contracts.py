"""Typed, bounded provenance and clock contracts for detailed observations.

These are *external* PSUTIL counters, not process instrumentation or native
Windows hang evidence. Unknown is never silently coerced to measured zero.
Existing detail-v2 databases without these additive tables remain readable.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import math
import time

SOURCE_KIND = "PSUTIL"
VERIFICATION_CLASS = "OS_OBSERVED"  # for external PSUTIL counters, never WCT/ETW attestation
MEASUREMENT_STATUSES = frozenset({
    "OK", "NOT_OBSERVED", "NOT_APPLICABLE", "ACCESS_DENIED",
    "UNSUPPORTED", "SENSOR_TIMEOUT", "SAMPLED_GAP",
    "TRUNCATED", "INVALID",
})
# Canonical column keys, source and unit of one detailed process sample.
FIELD_UNITS = {
    "rss_bytes": "bytes",
    "private_bytes": "bytes",
    "uss_bytes": "bytes",
    "handle_count": "handles",
    "io": "bytes_and_ops_cumulative",
    "threads": "cumulative_cpu_seconds",
    "children": "process_instances",
}
FIELD_STATUS_COLUMNS = (
    "rss_status", "private_status", "uss_status", "handle_status",
    "io_status", "threads_status", "children_status",
)


def _nonnegative_int(value: object) -> bool:
    return type(value) is int and value >= 0


@dataclass(frozen=True)
class ClockAnchor:
    monotonic_ns: int
    utc_ns: int
    uncertainty_ns: int
    source: str = "PYTHON_MONOTONIC_NS_AND_TIME_NS"

    def __post_init__(self) -> None:
        if not (_nonnegative_int(self.monotonic_ns) and
                _nonnegative_int(self.utc_ns) and self.utc_ns > 0 and
                _nonnegative_int(self.uncertainty_ns) and
                self.source == "PYTHON_MONOTONIC_NS_AND_TIME_NS"):
            raise ValueError("INVALID_CLOCK_ANCHOR")

    def estimate_utc_ns(self, monotonic_ns: int) -> int:
        if not _nonnegative_int(monotonic_ns):
            raise ValueError("INVALID_MONOTONIC_TIMESTAMP")
        value = self.utc_ns + monotonic_ns - self.monotonic_ns
        if value <= 0:
            raise ValueError("INVALID_UTC_ESTIMATE")
        return value

    def as_dict(self) -> dict:
        seconds, nanos = divmod(self.utc_ns, 1_000_000_000)
        iso = (datetime.fromtimestamp(seconds, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S") + f".{nanos:09d}Z")
        return {"monotonic_anchor_ns": self.monotonic_ns,
                "utc_anchor_ns": self.utc_ns,
                "utc_anchor_iso": iso,
                "uncertainty_ns_at_anchor": self.uncertainty_ns,
                "source": self.source,
                "quality": "ESTIMATED_WALL_CLOCK",
                "warning": "SYSTEM_CLOCK_CAN_ADJUST_AFTER_ANCHOR"}


def capture_clock_anchor() -> ClockAnchor:
    """Bound synchronization uncertainty with a monotonic sampling bracket.

    This uncertainty applies AT THE ANCHOR, not for arbitrary future UTC wall
    time; a system-clock adjustment after the anchor cannot be inferred.
    """
    before = time.monotonic_ns()
    utc = time.time_ns()
    after = time.monotonic_ns()
    if after < before or utc <= 0:
        raise ValueError("INVALID_CLOCK_SOURCE")
    return ClockAnchor((before + after) // 2, utc,
                       (after - before + 1) // 2)


def _observed(value: object) -> bool:
    return (type(value) in (int, float) and
            math.isfinite(float(value)) and value >= 0)


def sample_field_statuses(sample: dict) -> dict[str, str]:
    """Validate all explicit per-field statuses against measured counters.

    Synthetic test collectors may omit sensor_status: in that case missing
    values become NOT_OBSERVED (not an invented permission denial).
    """
    if type(sample) is not dict:
        raise ValueError("INVALID_SENSOR_SAMPLE")
    requested = sample.get("sensor_status", {})
    if type(requested) is not dict:
        raise ValueError("INVALID_SENSOR_STATUS")
    for name, status in requested.items():
        if name not in FIELD_UNITS or status not in MEASUREMENT_STATUSES:
            raise ValueError("INVALID_SENSOR_STATUS")
    bases = {
        "rss_bytes": _observed(sample.get("rss_bytes")),
        "private_bytes": _observed(sample.get("private_bytes")),
        "uss_bytes": _observed(sample.get("uss_bytes")),
        "handle_count": _observed(sample.get("handle_count")),
        "io": (_observed(sample.get("read_bytes")) and
               _observed(sample.get("write_bytes"))),
        "threads": sample.get("thread_status") == "OK",
        "children": _observed(sample.get("children_total")),
    }
    out = {}
    for key, available in bases.items():
        status = requested.get(key, "OK" if available else "NOT_OBSERVED")
        # No explicit denial/unsupported status can coexist with an observed
        # numeric value: this would turn ambiguous imported data into proof.
        if (status == "OK") != bool(available):
            raise ValueError("INCONSISTENT_SENSOR_STATUS")
        out[key] = status
    for key, count in (
            ("threads", sample.get("threads_omitted")),
            ("children", sample.get("children_omitted"))):
        if count is not None:
            if not _nonnegative_int(count):
                raise ValueError("INVALID_OMISSION_COUNT")
            if count and out[key] == "OK":
                out[key] = "TRUNCATED"
    return {
        "rss_status": out["rss_bytes"],
        "private_status": out["private_bytes"],
        "uss_status": out["uss_bytes"],
        "handle_status": out["handle_count"],
        "io_status": out["io"],
        "threads_status": out["threads"],
        "children_status": out["children"],
    }


def read_provenance(connection) -> dict:
    """Read additive v2 contract tables, never modifying a historic session.

    Called on an existing read-only SQLite connection. Legacy detail-v2
    captures without these tables are *not* rewritten or invented.
    """
    try:
        tables = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
            "('detail_clock_mapping','detail_capabilities','detail_sample_quality')"
        )}
        required = {"detail_clock_mapping", "detail_capabilities",
                    "detail_sample_quality"}
        if tables != required:
            return {"status": "LEGACY_DETAIL_V2_NO_PROVENANCE",
                    "clock_mapping": None, "capabilities": [],
                    "latest_quality": None, "quality_samples": 0}
        clock_rows = connection.execute(
            "SELECT monotonic_anchor_ns, utc_anchor_ns, uncertainty_ns, "
            "clock_source FROM detail_clock_mapping LIMIT 2").fetchall()
        if len(clock_rows) != 1:
            raise ValueError("INVALID_CLOCK_CARDINALITY")
        clock = ClockAnchor(*clock_rows[0])
        rows = connection.execute(
            "SELECT field_name, source_kind, verification_class, unit "
            "FROM detail_capabilities ORDER BY field_name LIMIT 16").fetchall()
        if len(rows) != len(FIELD_UNITS):
            raise ValueError("INVALID_CAPABILITY_COUNT")
        actual = {}
        for name, source, verification, unit in rows:
            if (name not in FIELD_UNITS or FIELD_UNITS[name] != unit or
                    source != SOURCE_KIND or verification != VERIFICATION_CLASS or
                    name in actual):
                raise ValueError("INVALID_CAPABILITY")
            actual[name] = {"source_kind": source,
                            "verification_class": verification, "unit": unit}
        total = connection.execute(
            "SELECT count(*) FROM detail_sample_quality").fetchone()[0]
        columns = ", ".join(("sample_seq", "utc_estimate_ns", "source_kind",
                             "verification_class") + FIELD_STATUS_COLUMNS)
        records = connection.execute(
            "SELECT " + columns +
            " FROM detail_sample_quality ORDER BY sample_seq DESC LIMIT 1"
        ).fetchall()
        latest = None
        if records:
            item = records[0]
            if (type(item[0]) is not int or item[0] <= 0
                    or type(item[1]) is not int or item[1] <= 0
                    or item[2] != SOURCE_KIND
                    or item[3] != VERIFICATION_CLASS):
                raise ValueError("INVALID_QUALITY_ROW")
            statuses = dict(zip(FIELD_STATUS_COLUMNS, item[4:]))
            if any(status not in MEASUREMENT_STATUSES
                   for status in statuses.values()):
                raise ValueError("INVALID_QUALITY_STATUS")
            latest = {"sample_seq": item[0], "utc_estimate_ns": item[1],
                      "source_kind": item[2], "verification_class": item[3],
                      "measurement_status": statuses}
        return {"status": "OK", "clock_mapping": clock.as_dict(),
                "capabilities": [{"field": key, **actual[key]}
                                 for key in sorted(actual)],
                "latest_quality": latest, "quality_samples": total}
    except (ValueError, TypeError, OverflowError):
        return {"status": "INVALID_DETAIL_PROVENANCE",
                "clock_mapping": None, "capabilities": [],
                "latest_quality": None, "quality_samples": 0}
