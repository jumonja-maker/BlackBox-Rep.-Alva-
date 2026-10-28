"""Bounded, explicit correlation of an owned trace with one session clock.

This is consistency checking of local OS observations and hash-linked files,
not authentication of editable evidence. UTC is never used to align events.
Legacy captures and arbitrary imported traces remain NOT_ESTABLISHED.
"""
from __future__ import annotations

from contextlib import closing
from bisect import bisect_left, bisect_right
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import time
from uuid import UUID

from .trace_clock_evidence import (CLOCK_IDENTITY_SCHEMA, SCHEMA, ORDER_SAMPLES_SCHEMA,
                                   MAX_ORDER_SAMPLES, bracket,
                                   capture_trace_clock_bracket)

SESSION_CLOCK_SCHEMA = "blackbox.session-clock/1"
ALIGNMENT_SCHEMA = "blackbox.trace-session-alignment/1"
ALIGNED = "BOUNDED_LOCAL_CLOCK_CORRELATION"
NANO = 1_000_000_000
MAX_UNCERTAINTY_NS = 10_000_000
QPC_MODEL = "WINDOWS_QPC_PLUS_CONSTANT_OFFSET_WITH_OUTWARD_ROUNDING"
ORDER_MODEL = "MONOTONE_CROSS_CLOCK_OBSERVATION_BRACKETS_NO_INTERPOLATION"
_ORDER_FIELDS = ("qpc_before_ticks", "qpc_after_ticks", "monotonic_before_ns",
                 "monotonic_after_ns")
MAX_ORDER_POINTS = 520
QPC_ORDER_MARGIN_TICKS = 1


def _order_bounds(points, ticks):
    # Equal readings of a discrete QPC do NOT prove temporal order: another
    # clock may change while QPC still returns the same tick. Require strict
    # inequalities and enclose ties using earlier/later observations.
    # Microsoft additionally documents +/-1 QPC tick ordering ambiguity
    # across threads: the capture guardian and trace producer are distinct.
    lower = bisect_left([p["qpc_before_ticks"] for p in points],
                        ticks-QPC_ORDER_MARGIN_TICKS) - 1
    upper = bisect_right([p["qpc_after_ticks"] for p in points],
                         ticks+QPC_ORDER_MARGIN_TICKS)
    if lower < 0 or upper >= len(points):
        raise ValueError("EVENT_NOT_STRICTLY_ENCLOSED_BY_CLOCK_PROBES")
    return points[lower]["monotonic_before_ns"], points[upper]["monotonic_after_ns"]


def _order_max_width(points, minimum, maximum):
    # Bounds change only at integer probe-counter boundaries. Checking those
    # boundaries and their neighbors includes repeated/zero-width QPC probes.
    candidates = {minimum, maximum}
    for point in points:
        for key in ("qpc_before_ticks", "qpc_after_ticks"):
            candidates.update(point[key] + delta for delta in (-2, -1, 0, 1, 2)
                              if minimum <= point[key] + delta <= maximum)
    return max(high-low for low, high in (_order_bounds(points, q) for q in candidates))
_SESSION_COLUMNS = ("session_uuid", "monotonic_origin_ns", "anchor_monotonic_ns",
                    "anchor_utc_ns", "anchor_uncertainty_ns", "clock_source")


def _cancel(cancel):
    if cancel is not None and cancel.is_set():
        raise InterruptedError("CLOCK_ALIGNMENT_CANCELLED")


def _digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=True,
                                    allow_nan=False, separators=(",", ":")).encode()).hexdigest()


def _integer(value, minimum=0, maximum=2**63-1):
    return type(value) is int and minimum <= value <= maximum


def _uuid(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value and UUID(value).int != 0
    except (ValueError, AttributeError):
        return False


def session_clock_record(session_uuid, origin_ns, anchor):
    """Capture immutable recorder evidence; inability never stops recording."""
    record = {"schema": SESSION_CLOCK_SCHEMA, "session_uuid": session_uuid,
              "monotonic_origin_ns": origin_ns,
              "anchor_monotonic_ns": anchor.monotonic_ns,
              "anchor_utc_ns": anchor.utc_ns,
              "anchor_uncertainty_ns": anchor.uncertainty_ns,
              "clock_source": anchor.source,
              "evidence_class": "LOCAL_OS_OBSERVATION_NOT_AUTHENTICATED"}
    try:
        import psutil
        record.update(recorder_pid=os.getpid(),
                      recorder_created_utc_s=psutil.Process().create_time(),
                      clock_bracket=capture_trace_clock_bracket())
    except Exception as exc:
        record.update(status="SESSION_CLOCK_UNAVAILABLE", error_type=type(exc).__name__)
    return record


def _session_path(path):
    from .session_v2 import FILENAME, safe_path
    path = safe_path(path)
    return safe_path(path / FILENAME if path.is_dir() else path)


def read_session_clock(path, *, cancel=None):
    """Bounded read-only metadata query, including a live recorder's WAL."""
    _cancel(cancel)
    path = _session_path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 1024**3:
        raise ValueError("SESSION_CLOCK_FILE_UNAVAILABLE")
    deadline = time.monotonic() + 2
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=.5)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 65536)
        db.set_progress_handler(lambda: int(time.monotonic() > deadline or
                                (cancel is not None and cancel.is_set())), 1000)
        db.execute("BEGIN")  # Session row and clock record are one SQLite snapshot.
        if db.execute("PRAGMA user_version").fetchone()[0] != 2:
            raise ValueError("SESSION_SCHEMA_UNSUPPORTED")
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                          "AND name='clock_evidence'").fetchone():
            raise ValueError("SESSION_CLOCK_NOT_RECORDED")
        rows = db.execute("SELECT " + ",".join(_SESSION_COLUMNS) +
                          ",ended_monotonic_ns FROM sessions LIMIT 2").fetchall()
        if len(rows) != 1:
            raise ValueError("SESSION_IDENTITY_AMBIGUOUS")
        session = dict(zip((*_SESSION_COLUMNS, "ended_monotonic_ns"), rows[0]))
        raw = db.execute("SELECT evidence_json FROM clock_evidence WHERE schema=?",
                         (SESSION_CLOCK_SCHEMA,)).fetchone()
        if raw is None:
            raise ValueError("SESSION_CLOCK_NOT_RECORDED")
        record = json.loads(raw[0])
    _cancel(cancel)
    if (not isinstance(record, dict) or record.get("schema") != SESSION_CLOCK_SCHEMA or
            not _uuid(session["session_uuid"]) or
            any(record.get(key) != session[key] for key in _SESSION_COLUMNS) or
            not all(_integer(session[key]) for key in _SESSION_COLUMNS[1:5]) or
            not all(_integer(record.get(key)) for key in _SESSION_COLUMNS[1:5]) or
            session["clock_source"] != "PYTHON_MONOTONIC_NS_AND_TIME_NS"):
        raise ValueError("SESSION_CLOCK_METADATA_MISMATCH")
    immutable = {key: session[key] for key in _SESSION_COLUMNS}
    return {"session": session, "record": record,
            "binding": {"schema": SESSION_CLOCK_SCHEMA,
                        "session_uuid": session["session_uuid"],
                        "record_sha256": _digest({"session": immutable, "record": record})}}


def capture_session_binding(session_path):
    """Optional journal binding, never a reason to fail a user's capture."""
    try:
        return {"status": "SESSION_CLOCK_BOUND", **read_session_clock(session_path)["binding"]}
    except (OSError, ValueError, sqlite3.Error, TypeError, RecursionError) as exc:
        return {"status": "SESSION_CLOCK_NOT_BOUND", "reason": str(exc)[:120]}


def _checked_bracket(item):
    if (not isinstance(item, dict) or item.get("schema") != SCHEMA or
            item.get("status") != "BRACKET_OBSERVED_UNVERIFIED"):
        raise ValueError("CLOCK_BRACKET_UNAVAILABLE_OR_WIDE")
    check = bracket(item["qpc_before_ticks"], item["qpc_after_ticks"],
                    item["qpc_frequency_hz"], item["monotonic_before_ns"],
                    item["monotonic_after_ns"], item["sampled_utc_ns"],
                    pid=item["owner_pid"], clock_identity=item.get("clock_identity"))
    if item != check:
        raise ValueError("CLOCK_BRACKET_FIELDS_INCONSISTENT")
    identity = item.get("clock_identity")
    if (not isinstance(identity, dict) or identity.get("schema") != CLOCK_IDENTITY_SCHEMA or
            not _uuid(identity.get("boot_id")) or
            identity.get("boot_id_source") != "NT_SYSTEM_BOOT_ENVIRONMENT_INFORMATION" or
            identity.get("evidence_class") != "LOCAL_OS_OBSERVATION_NOT_AUTHENTICATED" or
            identity.get("monotonic_implementation") not in
                ("QueryPerformanceCounter()", "GetTickCount64()") or
            not _integer(identity.get("monotonic_resolution_ns"), 1,
                1_000_000 if identity.get("monotonic_implementation") ==
                "QueryPerformanceCounter()" else 250_000_000)):
        raise ValueError("BOOT_OR_MONOTONIC_CLOCK_IDENTITY_UNAVAILABLE")
    return item


def _checked_order_samples(series, capture):
    """Expand bounded compact records only after validating shared identity."""
    if series is None:
        return []
    reference = capture[0]
    if (not isinstance(series, dict) or series.get("schema") != ORDER_SAMPLES_SCHEMA or
            series.get("status") not in ("RECORDED", "SATURATED") or
            type(series.get("qpc_frequency_hz")) is not int or
            type(series.get("owner_pid")) is not int or
            any(series.get(key) != reference.get(key) for key in
                ("qpc_frequency_hz", "owner_pid", "clock_identity")) or
            not isinstance(series.get("points"), list) or
            len(series["points"]) > MAX_ORDER_SAMPLES):
        raise ValueError("INVALID_COMPACT_CLOCK_OBSERVATIONS")
    result = []
    for point in series["points"]:
        if not isinstance(point, list) or len(point) != 4:
            raise ValueError("INVALID_COMPACT_CLOCK_OBSERVATION")
        qb,qa,mb,ma = point
        checked = bracket(qb,qa,reference["qpc_frequency_hz"],mb,ma,
                          reference["sampled_utc_ns"],pid=reference["owner_pid"],
                          clock_identity=reference["clock_identity"])
        if (checked["status"] != "BRACKET_OBSERVED_UNVERIFIED" or
                qb < capture[0]["qpc_before_ticks"] or qa > capture[-1]["qpc_after_ticks"] or
                mb < capture[0]["monotonic_before_ns"] or ma > capture[-1]["monotonic_after_ns"] or
                result and (result[-1]["qpc_after_ticks"] > qb or
                            result[-1]["monotonic_after_ns"] > mb)):
            raise ValueError("COMPACT_CLOCK_OBSERVATION_OUTSIDE_ORDERED_CAPTURE")
        result.append(checked)
    return result


def assess_session_alignment(index_path, journal_path, session_path, *, cancel=None):
    """Check file identities, then derive implementation-specific clock bounds.

    Successful output is conditional on the recorded local OS assertions.
    It never upgrades import authenticity, capture completeness or causality.
    It is valid only inside the recorded guardian QPC window, never by
    extrapolating UTC or accepting a caller-supplied frequency/drift estimate.
    """
    from .decoder_index import read_index
    from .trace_owner import _read
    from .trace_clock_evidence import assess_trace_capture_metadata
    common = {"schema": ALIGNMENT_SCHEMA, "status": "NOT_ESTABLISHED",
              "trace_to_blackbox_session_clock_alignment": "NOT_ESTABLISHED",
              "verification_class": "HASH_LINKED_LOCAL_ASSERTIONS_NOT_AUTHENTICATED",
              "capture_complete": None, "root_cause": "UNKNOWN",
              "scope": "CAPTURE_WINDOW_ONLY_NO_UTC_ALIGNMENT_OR_EXTRAPOLATION"}

    def refused(reason, **extra):
        return {**common, "reason": reason, **extra}

    try:
        _cancel(cancel)
        meta = read_index(index_path, mode="events", limit=1)["summary"]
        data = _read(journal_path)
        review = assess_trace_capture_metadata(meta, data)
        if review.get("status") != "HASH_MATCHED_QPC_BRACKETS_UNVERIFIED":
            return refused(review.get("status", "CAPTURE_JOURNAL_NOT_VERIFIED"))
        _cancel(cancel)
        session_data = read_session_clock(session_path, cancel=cancel)
        session, record = session_data["session"], session_data["record"]
        binding = data.get("session_clock_binding")
        if binding != {"status": "SESSION_CLOCK_BOUND", **session_data["binding"]}:
            return refused("CAPTURE_SESSION_BINDING_MISMATCH_OR_ABSENT")
        if (not _integer(record.get("recorder_pid"), 1, 2**31-1) or
                not _integer(data.get("owner_pid"), 1, 2**31-1) or
                record["recorder_pid"] != data.get("owner_pid") or
                type(record.get("recorder_created_utc_s")) not in (int, float) or
                not math.isfinite(record["recorder_created_utc_s"]) or
                record["recorder_created_utc_s"] <= 0 or
                type(data.get("owner_created")) not in (int, float) or
                record["recorder_created_utc_s"] != data.get("owner_created")):
            return refused("RECORDER_PROCESS_INSTANCE_MISMATCH")
        stages = review["checked_clock_stages"]
        capture = [_checked_bracket(data["clock_anchors"][key]) for key in stages]
        samples = _checked_order_samples(data.get("clock_order_samples"), capture)
        ordered_capture = sorted([*capture,*samples], key=lambda p:p["qpc_before_ticks"])
        if any(before["qpc_after_ticks"] > after["qpc_before_ticks"] or
               before["monotonic_after_ns"] > after["monotonic_before_ns"]
               for before,after in zip(ordered_capture,ordered_capture[1:])):
            return refused("CLOCK_OBSERVATION_ORDER_INCONSISTENT")
        initial = _checked_bracket(record.get("clock_bracket"))
        if initial["owner_pid"] != record["recorder_pid"]:
            return refused("SESSION_CLOCK_RECORDER_PID_MISMATCH")
        all_anchors = [initial, *ordered_capture]
        boot_ids = {x["clock_identity"]["boot_id"] for x in all_anchors}
        if len(boot_ids) != 1:
            return refused("BOOT_ID_MISMATCH")
        frequencies = {x["qpc_frequency_hz"] for x in all_anchors}
        if len(frequencies) != 1:
            return refused("CLOCK_FREQUENCY_MISMATCH")
        frequency = next(iter(frequencies))
        implementations = {x["clock_identity"]["monotonic_implementation"]
                           for x in all_anchors}
        if len(implementations) != 1:
            return refused("MONOTONIC_CLOCK_IMPLEMENTATION_MISMATCH")
        implementation = next(iter(implementations))
        engine = meta.get("engine", {})
        if (not isinstance(engine, dict) or
                engine.get("trace_counter_kind") != "TRACEEVENT_SOURCE_COUNTER" or
                type(engine.get("trace_counter_frequency_hz")) is not int or
                engine["trace_counter_frequency_hz"] != frequency):
            return refused("TRACE_COUNTER_FREQUENCY_UNAVAILABLE_OR_MISMATCH")
        audit = meta.get("calendar_clock", {})
        if (not isinstance(audit, dict) or
                type(audit.get("source_counter_events_missing")) is not int or
                audit.get("source_counter_events_missing") != 0 or
                not _integer(audit.get("source_counter_events_observed"), 1) or
                audit["source_counter_events_observed"] != meta.get("rows")):
            return refused("TRACE_COUNTER_COVERAGE_INCOMPLETE")
        if audit.get("relative_vs_utc_offset_disagreements_over_10ms") != 0:
            return refused("TRACE_CLOCK_DISCONTINUITY")
        # Never align a session whose origin or end cannot bracket capture.
        if (initial["monotonic_after_ns"] > capture[0]["monotonic_before_ns"] or
                initial["qpc_after_ticks"] > capture[0]["qpc_before_ticks"] or
                session["monotonic_origin_ns"] > initial["monotonic_after_ns"] or
                session["ended_monotonic_ns"] is not None and
                (not _integer(session["ended_monotonic_ns"]) or
                 session["ended_monotonic_ns"] < capture[-1]["monotonic_after_ns"])):
            return refused("CAPTURE_OUTSIDE_SESSION_LIFETIME")
        accepted = {**common, "status": ALIGNED,
                    "trace_to_blackbox_session_clock_alignment": ALIGNED,
                    "source_trace_sha256": meta["input_sha256"],
                    "session_uuid": session["session_uuid"],
                    "session_record_sha256": session_data["binding"]["record_sha256"],
                    "journal_snapshot_sha256": _digest(data),
                    "index_summary_snapshot_sha256": _digest(meta),
                    "boot_id": next(iter(boot_ids)), "frequency_hz": frequency,
                    "session_origin_ns": session["monotonic_origin_ns"],
                    "valid_qpc_min_ticks": capture[0]["qpc_before_ticks"],
                    "valid_qpc_max_ticks": capture[-1]["qpc_after_ticks"],
                    "anchors_checked": len(all_anchors),
                    "additional_observations": len(samples),
                    "observation_sampling_status": (data["clock_order_samples"]["status"]
                                                    if data.get("clock_order_samples") is not None
                                                    else "NOT_RECORDED"),
                    "monotonic_implementation": implementation,
                    "monotonic_resolution_ns": max(x["clock_identity"]["monotonic_resolution_ns"]
                                                   for x in all_anchors),
                    "utc_used_for_mapping": False}
        if implementation == "GetTickCount64()":
            # CPython 3.11 on Windows uses GetTickCount64, not QPC, for
            # monotonic_ns. Their rates/offsets are not assumed identical.
            # Each probe samples M_before, Q_before, Q_after, M_after in that
            # order. An event Q > Q_before implies M(event) >= M_before;
            # Q < Q_after implies M(event) <= M_after. Neighboring probes
            # therefore enclose the session-clock reading without a drift,
            # interpolation or sub-tick precision claim. A long gap remains
            # a long uncertainty interval and is reported as such.
            points = [{key: point[key] for key in _ORDER_FIELDS} for point in ordered_capture]
            minimum = points[0]["qpc_before_ticks"] + QPC_ORDER_MARGIN_TICKS + 1
            maximum = points[-1]["qpc_after_ticks"] - QPC_ORDER_MARGIN_TICKS - 1
            if minimum > maximum:
                return refused("CLOCK_WINDOW_NOT_STRICTLY_ENCLOSED")
            _cancel(cancel)
            return {**accepted,
                    "reason": "SAME_BOOT_MONOTONE_OBSERVATION_ORDER_BOUNDS_ONLY",
                    "clock_model": ORDER_MODEL, "clock_order_brackets": points,
                    "qpc_ordering_margin_ticks": QPC_ORDER_MARGIN_TICKS,
                    "valid_qpc_min_ticks": minimum, "valid_qpc_max_ticks": maximum,
                    "uncertainty_width_ns": _order_max_width(points, minimum, maximum),
                    "uncertainty_scope": "MAXIMUM_EVENT_BRACKET_WIDTH_NOT_CONSTANT_OFFSET_ERROR",
                    "precision_quality": "COARSE_OBSERVATION_INTERVAL_NO_INTERPOLATION",
                    "limitations": ["EDITABLE_LOCAL_EVIDENCE_NOT_AUTHENTICATED",
                                    "NO_CAUSALITY_OR_CAPTURE_COMPLETENESS_CLAIM",
                                    "NO_COMMON_OSCILLATOR_OR_DRIFT_RATE_ASSUMPTION",
                                    "EVENT_UNCERTAINTY_MAY_SPAN_SECONDS_BETWEEN_PROBES",
                                    "BOUNDS_SESSION_CLOCK_READINGS_NOT_PHYSICAL_TIME_ACCURACY"]}
        # Proven QPC-backed CPython monotonic shares the oscillator. The offset
        # at every sampled bracket must have a nonempty intersection. Include
        # one QPC tick and the recorded Python resolution, rounding outward.
        lows, highs = [], []
        for point in all_anchors:
            resolution = point["clock_identity"]["monotonic_resolution_ns"]
            rounding = (NANO + frequency - 1) // frequency + resolution
            lows.append(point["monotonic_before_ns"] -
                        (point["qpc_after_ticks"] * NANO + frequency-1) // frequency - rounding)
            highs.append(point["monotonic_after_ns"] -
                         point["qpc_before_ticks"] * NANO // frequency + rounding)
        low, high = max(lows), min(highs)
        if low > high:
            return refused("QPC_MONOTONIC_OFFSET_DISCONTINUITY_OR_DRIFT")
        if not all(_integer(value, -(2**63)) for value in (low, high)):
            return refused("CLOCK_MODEL_RANGE_UNSUPPORTED")
        if high - low > MAX_UNCERTAINTY_NS:
            return refused("CLOCK_CORRELATION_UNCERTAINTY_TOO_WIDE")
        _cancel(cancel)
        return {**accepted,
                "reason": "SAME_BOOT_QPC_CONTRACT_AND_INTERSECTING_OBSERVATION_BOUNDS",
                "offset_lower_ns": low, "offset_upper_ns": high,
                "uncertainty_width_ns": high - low,
                "uncertainty_scope": "COMMON_OSCILLATOR_OFFSET_INTERVAL",
                "precision_quality": "OUTWARD_ROUNDED_QPC_OFFSET_BOUNDS",
                "clock_model": QPC_MODEL,
                "limitations": ["EDITABLE_LOCAL_EVIDENCE_NOT_AUTHENTICATED",
                                "NO_CAUSALITY_OR_CAPTURE_COMPLETENESS_CLAIM",
                                "ONLY_RECORDED_CLOCK_RESOLUTION_AND_BRACKET_BOUNDS"]}
    except InterruptedError:
        raise
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, OverflowError, RecursionError) as exc:
        _cancel(cancel)
        return refused("ALIGNMENT_EVIDENCE_UNAVAILABLE_OR_INVALID", error=str(exc)[:160])


def project_event_time(alignment, row):
    """Map one decoded event to an interval relative to the selected session."""
    from .decoder_clock import _valid_source_ticks
    if not isinstance(alignment, dict) or alignment.get("status") != ALIGNED:
        return {"status": "NOT_ESTABLISHED", "reason": "NO_ACCEPTED_ALIGNMENT"}
    raw = row.get("source_ticks") if isinstance(row, dict) else None
    if not _valid_source_ticks(raw):
        return {"status": "NOT_ESTABLISHED", "reason": "EVENT_COUNTER_UNAVAILABLE"}
    ticks = int(raw)
    try:
        frequency = alignment["frequency_hz"]
        origin = alignment["session_origin_ns"]
        minimum, maximum = alignment["valid_qpc_min_ticks"], alignment["valid_qpc_max_ticks"]
        if (not _integer(frequency, 1, 10**12) or not _integer(origin) or
                not all(_integer(x, -(2**63)) for x in (minimum, maximum)) or
                minimum > maximum):
            raise ValueError("INVALID_ALIGNMENT_MODEL")
        if not minimum <= ticks <= maximum:
            return {"status": "NOT_ESTABLISHED", "reason": "EVENT_OUTSIDE_CAPTURE_WINDOW"}
        model = alignment.get("clock_model", QPC_MODEL)
        if model == ORDER_MODEL:
            if (alignment.get("monotonic_implementation") != "GetTickCount64()" or
                    type(alignment.get("qpc_ordering_margin_ticks")) is not int or
                    alignment["qpc_ordering_margin_ticks"] != QPC_ORDER_MARGIN_TICKS):
                raise ValueError("INVALID_ALIGNMENT_MODEL")
            points = alignment["clock_order_brackets"]
            if not isinstance(points, list) or not 2 <= len(points) <= MAX_ORDER_POINTS:
                raise ValueError("INVALID_ALIGNMENT_MODEL")
            previous = None
            for point in points:
                if (not isinstance(point, dict) or
                        not all(_integer(point[key], -(2**63) if key.startswith("qpc_") else 0)
                                for key in _ORDER_FIELDS) or
                        point["qpc_before_ticks"] > point["qpc_after_ticks"] or
                        point["monotonic_before_ns"] > point["monotonic_after_ns"] or
                        previous is not None and
                        (previous["qpc_after_ticks"] > point["qpc_before_ticks"] or
                         previous["monotonic_after_ns"] > point["monotonic_before_ns"])):
                    raise ValueError("INVALID_ALIGNMENT_MODEL")
                previous = point
            if (points[0]["qpc_before_ticks"] + QPC_ORDER_MARGIN_TICKS + 1 != minimum or
                    points[-1]["qpc_after_ticks"] - QPC_ORDER_MARGIN_TICKS - 1 != maximum):
                raise ValueError("INVALID_ALIGNMENT_MODEL")
            lower, upper = _order_bounds(points, ticks)
            lower, upper = lower-origin, upper-origin
        elif model == QPC_MODEL:
            low, high = alignment["offset_lower_ns"], alignment["offset_upper_ns"]
            if (not all(_integer(x, -(2**63)) for x in (low, high)) or
                    low > high or high-low > MAX_UNCERTAINTY_NS):
                raise ValueError("INVALID_ALIGNMENT_MODEL")
            lower = ticks * NANO // frequency + low - origin
            upper = (ticks * NANO + frequency-1) // frequency + high - origin
        else:
            raise ValueError("INVALID_ALIGNMENT_MODEL")
        if lower > upper or not all(_integer(value, -(2**63)) for value in (lower, upper)):
            return {"status": "NOT_ESTABLISHED", "reason": "EVENT_TIME_RANGE_UNSUPPORTED"}
        return {"status": ALIGNED, "session_relative_lower_ns": lower,
                "session_relative_upper_ns": upper,
                "uncertainty_width_ns": upper - lower,
                "clock_model": model,
                "precision_quality": alignment.get("precision_quality"),
                "monotonic_resolution_ns": alignment.get("monotonic_resolution_ns"),
                "uncertainty_represents": "SESSION_CLOCK_READING_BOUNDS_NOT_PHYSICAL_TIME_ACCURACY",
                "session_uuid": alignment["session_uuid"],
                "source_trace_sha256": alignment["source_trace_sha256"],
                "verification_class": "LOCAL_EVIDENCE_NOT_AUTHENTICATED"}
    except (KeyError, TypeError, ValueError, OverflowError):
        return {"status": "NOT_ESTABLISHED", "reason": "INVALID_ALIGNMENT_MODEL"}
