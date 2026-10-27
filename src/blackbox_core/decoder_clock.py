"""Offline TraceEvent UTC-clock provenance.

TraceEvent.TimeStamp uses a trace clock (normally QPC) to reconstruct calendar
time. This projection is not an external NTP/UTC attestation, shared boot proof,
or safe clock alignment with BLACK.BOX session-v2. Imported JSONL is untrusted.
"""
from __future__ import annotations

from datetime import datetime, timezone

UNIX_EPOCH_DOTNET_TICKS = 621355968000000000
MAX_SQLITE_NS = 2**63 - 1
DRIFT_ALERT_NS = 10_000_000  # 10 ms discrepancy; indicative, NOT clock calibration
UTC_QUALITY = "TRACEEVENT_DERIVED_UTC_UNVERIFIED"


def _is_ascii_digits(value):
    return type(value) is str and 16 <= len(value) <= 19 and value.isascii() and value.isdecimal()


def _valid_source_ticks(value):
    # .NET serializes an Int64 QPC counter as ASCII decimal. Accept an
    # optional leading minus, but not repeated signs, Unicode numbers or
    # out-of-range values in an untrusted imported protocol.
    if type(value) is not str or not 1 <= len(value) <= 20:
        return False
    digits = value[1:] if value.startswith("-") else value
    return (bool(digits) and len(digits) <= 19 and
            digits.isascii() and digits.isdecimal() and
            -(2**63) <= int(value) <= 2**63-1)


class TraceClockAudit:
    """Do not silently convert unknown time sources to an aligned timeline."""

    def __init__(self):
        self.recorded = 0
        self.missing = 0
        self.offset_disagreements = 0
        self.earliest_ns = None
        self.latest_ns = None
        self._baseline_ns = None
        self.max_offset_disagreement_ns = 0
        # TraceEvent's original QPC-like counters are indexed without
        # projecting them onto the independent BLACK.BOX session clock.
        self.source_counter_observed = 0
        self.source_counter_missing = 0
        self.source_counter_min = None
        self.source_counter_max = None

    def project(self, row: dict) -> int | None:
        # Validate original counters even when the UTC projection is absent:
        # an untrusted malformed QPC must never reach a persistent index.
        source_ticks = row.get("source_ticks")
        if source_ticks is not None:
            if not _valid_source_ticks(source_ticks):
                raise ValueError("INVALID_TRACE_SOURCE_TICKS")
            value = int(source_ticks)
            self.source_counter_observed += 1
            if self.source_counter_min is None or value < self.source_counter_min:
                self.source_counter_min = value
            if self.source_counter_max is None or value > self.source_counter_max:
                self.source_counter_max = value
        else:
            self.source_counter_missing += 1
        ticks = row.get("utc_ticks")
        if ticks is None:
            self.missing += 1
            return None
        if not _is_ascii_digits(ticks):
            raise ValueError("INVALID_TRACE_UTC_TICKS")
        nanoseconds = (int(ticks) - UNIX_EPOCH_DOTNET_TICKS) * 100
        if not 0 < nanoseconds <= MAX_SQLITE_NS:
            raise ValueError("UNSUPPORTED_TRACE_UTC_RANGE")
        seconds, subsecond = divmod(nanoseconds, 1_000_000_000)
        utc = datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        row["utc_time_ns"] = nanoseconds
        row["utc_time_iso"] = utc + f".{subsecond:09d}Z"
        row["utc_projection_quality"] = UTC_QUALITY
        offset = nanoseconds - round(row["time_ms"] * 1_000_000)
        if self._baseline_ns is None:
            self._baseline_ns = offset
        else:
            delta = abs(offset - self._baseline_ns)
            self.max_offset_disagreement_ns = max(self.max_offset_disagreement_ns, delta)
            if delta > DRIFT_ALERT_NS:
                self.offset_disagreements += 1
        self.recorded += 1
        self.earliest_ns = nanoseconds if self.earliest_ns is None else min(self.earliest_ns, nanoseconds)
        self.latest_ns = nanoseconds if self.latest_ns is None else max(self.latest_ns, nanoseconds)
        return nanoseconds

    def summary(self):
        if self.recorded == 0:
            status = "TRACE_UTC_NOT_RECORDED"
        elif self.offset_disagreements:
            status = "TRACE_RELATIVE_VS_UTC_DISAGREEMENT_UNCERTAIN"
        elif self.missing:
            status = "PARTIAL_TRACE_UTC_PROJECTION"
        else:
            status = "TRACE_UTC_RECONSTRUCTED_NOT_INDEPENDENTLY_ATTESTED"
        return {
            "status": status,
            "events_with_utc_projection": self.recorded,
            "events_without_utc_projection": self.missing,
            "source_counter_events_observed": self.source_counter_observed,
            "source_counter_events_missing": self.source_counter_missing,
            "source_counter_min_ticks": self.source_counter_min,
            "source_counter_max_ticks": self.source_counter_max,
            "source_counter_provenance": "TRACE_INPUT_UNVERIFIED_NOT_A_BOOT_OR_SESSION_PROOF",
            "relative_vs_utc_offset_disagreements_over_10ms": self.offset_disagreements,
            "max_relative_vs_utc_offset_disagreement_ns": self.max_offset_disagreement_ns,
            "earliest_utc_ns": self.earliest_ns,
            "latest_utc_ns": self.latest_ns,
            "utc_precision_claim": "DATETIME_100NS_ENCODING_ONLY_NO_CAPTURE_ACCURACY_CLAIM",
            "trace_to_blackbox_session_clock_alignment": "NOT_ESTABLISHED",
            "same_boot_same_machine_and_time_sync": "NOT_VERIFIED",
            "utc_source": UTC_QUALITY,
        }
