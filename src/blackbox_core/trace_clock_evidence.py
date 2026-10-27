"""Capture-side Windows QPC/monotonic/UTC brackets and conservative review.

The clocks are sampled only for explicitly requested ETW/EventPipe capture.
These editable local journals are NOT signatures, calibrated clocks or proof
that a trace and BLACK.BOX session were recorded in the same boot.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import time

SCHEMA = "blackbox.trace-clock-bracket/1"
MAX_BRACKET_NS = 250_000_000  # warn when bracket is wider than 250ms


def bracket(qpc_before, qpc_after, frequency_hz, mono_before_ns,
            mono_after_ns, sampled_utc_ns, *, pid):
    """Build one bounded capture-side observation (pure, testable)."""
    numbers = (qpc_before, qpc_after, frequency_hz, mono_before_ns,
               mono_after_ns, sampled_utc_ns, pid)
    if (any(type(x) is not int for x in numbers) or
            not -2**63 <= qpc_before < 2**63 or
            not -2**63 <= qpc_after < 2**63 or
            not 0 < frequency_hz <= 10**12 or
            not 0 <= mono_before_ns <= mono_after_ns < 2**63 or
            not 0 < sampled_utc_ns < 2**63 or not 0 < pid < 2**31 or
            qpc_after < qpc_before):
        raise ValueError("INVALID_CAPTURE_CLOCK_BRACKET")
    qpc_width_ns = ((qpc_after - qpc_before) * 1_000_000_000 +
                    frequency_hz - 1) // frequency_hz
    mono_width_ns = mono_after_ns - mono_before_ns
    return {
        "schema": SCHEMA,
        "status": ("BRACKET_OBSERVED_UNVERIFIED"
                   if max(qpc_width_ns, mono_width_ns) <= MAX_BRACKET_NS
                   else "WIDE_BRACKET_UNRELIABLE"),
        "owner_pid": pid,
        "qpc_before_ticks": qpc_before, "qpc_after_ticks": qpc_after,
        "qpc_frequency_hz": frequency_hz, "qpc_bracket_width_ns": qpc_width_ns,
        "monotonic_before_ns": mono_before_ns,
        "monotonic_after_ns": mono_after_ns,
        "monotonic_bracket_width_ns": mono_width_ns,
        "sampled_utc_ns": sampled_utc_ns,
        "source": "WINDOWS_KERNEL32_QUERY_PERFORMANCE_COUNTER",
        "journal_authenticity": "UNVERIFIED_LOCAL_ASSERTION",
        "trace_to_session_alignment": "NOT_ESTABLISHED",
        "clock_precision_claim": "BRACKET_WIDTH_NOT_CROSS_CLOCK_CALIBRATION",
    }


def capture_trace_clock_bracket():
    """Best-effort opt-in capture probe; never interrupts the recorder.

    No QPC mock or platform override is accepted in production. Tests exercise
    bracket() directly; Windows CI exercises the actual kernel32 bindings.
    """
    if os.name != "nt":
        return {"schema": SCHEMA, "status": "WINDOWS_QPC_UNAVAILABLE",
                "trace_to_session_alignment": "NOT_ESTABLISHED"}
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        freq_function = kernel.QueryPerformanceFrequency
        freq_function.argtypes = [ctypes.POINTER(ctypes.c_longlong)]
        freq_function.restype = ctypes.c_int
        counter_function = kernel.QueryPerformanceCounter
        counter_function.argtypes = [ctypes.POINTER(ctypes.c_longlong)]
        counter_function.restype = ctypes.c_int
        freq = ctypes.c_longlong()
        if not freq_function(ctypes.byref(freq)):
            raise OSError(ctypes.get_last_error(), "QPC_FREQUENCY_FAILED")

        def read_counter():
            value = ctypes.c_longlong()
            if not counter_function(ctypes.byref(value)):
                raise OSError(ctypes.get_last_error(), "QPC_READ_FAILED")
            return value.value

        mono_before = time.monotonic_ns()
        qpc_before = read_counter()
        utc = time.time_ns()
        qpc_after = read_counter()
        mono_after = time.monotonic_ns()
        return bracket(qpc_before, qpc_after, freq.value,
                       mono_before, mono_after, utc, pid=os.getpid())
    except (OSError, ValueError, OverflowError, AttributeError) as exc:
        return {"schema": SCHEMA, "status": "CAPTURE_QPC_UNAVAILABLE",
                "error_type": type(exc).__name__,
                "trace_to_session_alignment": "NOT_ESTABLISHED"}


def assess_trace_capture_journal(index_path, journal_path):
    """Review all capture stages without claiming clock synchronization.

    The journal is editable. Coarse elapsed-time checks can REJECT discordant
    clocks, but even coherent records cannot attest origin, drift, or a
    relation to session-v2's independent monotonic timeline.
    """
    from .decoder_index import read_index
    from .trace_owner import _read

    summary = read_index(index_path, mode="events", limit=1)["summary"]
    raw = _read(journal_path)
    document_ok = isinstance(raw, dict)
    data = raw if document_ok else {}
    source = data.get("source")
    fmt = summary.get("format")
    stages_by_source = {
        "ETW_WPR": ("before_tool_start", "after_tool_start",
                    "before_tool_stop", "after_tool_stop"),
        "EVENTPIPE_DOTNET_TRACE": ("before_tool_spawn",
                                   "after_tool_spawn", "after_tool_exit"),
    }
    expected_format = {"ETW_WPR": ".etl",
                       "EVENTPIPE_DOTNET_TRACE": ".nettrace"}.get(source)
    common = {
        "verification_class": "UNVERIFIED_LOCAL_JOURNAL",
        "trace_to_blackbox_session_clock_alignment": "NOT_ESTABLISHED",
        "same_boot_and_process_identity": "NOT_INDEPENDENTLY_VERIFIED",
        "source": source, "index_format": fmt,
        "source_trace_sha256": summary.get("input_sha256"),
    }

    def response(status, **other):
        return {**common, "status": status, **other}

    if not document_ok:
        return response("INVALID_CAPTURE_JOURNAL")
    if expected_format is None or fmt != expected_format:
        return response("JOURNAL_AND_TRACE_SOURCE_MISMATCH")
    if data.get("state") != "COMPLETED" or not isinstance(data.get("result"), dict):
        return response("CAPTURE_NOT_COMPLETED")
    digest = data["result"].get("sha256")
    if (not isinstance(digest, str) or len(digest) != 64 or
            any(ch not in "0123456789abcdef" for ch in digest)):
        return response("CAPTURE_DIGEST_UNAVAILABLE")
    if digest != summary.get("input_sha256"):
        return response("JOURNAL_TRACE_HASH_MISMATCH")

    anchors = data.get("clock_anchors")
    if not isinstance(anchors, dict):
        return response("QPC_ANCHORS_NOT_RECORDED")
    names = stages_by_source[source]
    items = [anchors.get(name) for name in names]
    # First/last alone do not establish that startup, capture and shutdown
    # were measured. Missing/wide intermediate stages must fail closed.
    if not all(isinstance(item, dict) and
               item.get("schema") == SCHEMA and
               item.get("status") == "BRACKET_OBSERVED_UNVERIFIED"
               for item in items):
        return response("QPC_ANCHORS_INCOMPLETE_OR_UNRELIABLE")
    try:
        validated = []
        for item in items:
            check = bracket(item["qpc_before_ticks"], item["qpc_after_ticks"],
                            item["qpc_frequency_hz"], item["monotonic_before_ns"],
                            item["monotonic_after_ns"], item["sampled_utc_ns"],
                            pid=item["owner_pid"])
            if item != check:
                raise ValueError("MODIFIED_ANCHOR_FIELDS")
            validated.append(check)
    except (ValueError, KeyError, TypeError):
        return response("INVALID_QPC_ANCHOR_CONTRACT")

    if (len({item["owner_pid"] for item in validated}) != 1 or
            len({item["qpc_frequency_hz"] for item in validated}) != 1):
        return response("INCONSISTENT_CAPTURE_OWNER_OR_QPC_FREQUENCY")
    freq = validated[0]["qpc_frequency_hz"]
    for before, after in zip(validated, validated[1:]):
        if (before["qpc_after_ticks"] > after["qpc_before_ticks"] or
                before["monotonic_after_ns"] > after["monotonic_before_ns"] or
                before["sampled_utc_ns"] > after["sampled_utc_ns"]):
            return response("NONMONOTONIC_CAPTURE_CLOCK_ANCHORS")

        # These intervals conservatively bound elapsed time between separate
        # probes. Intersection is a necessary check, not a clock calibration.
        qpc_low_ns = ((after["qpc_before_ticks"] - before["qpc_after_ticks"])
                      * 1_000_000_000) // freq
        qpc_high_ns = (((after["qpc_after_ticks"] - before["qpc_before_ticks"])
                        * 1_000_000_000 + freq - 1) // freq)
        mono_low_ns = after["monotonic_before_ns"] - before["monotonic_after_ns"]
        mono_high_ns = after["monotonic_after_ns"] - before["monotonic_before_ns"]
        if (qpc_high_ns + 50_000_000 < mono_low_ns or
                mono_high_ns + 50_000_000 < qpc_low_ns):
            return response("QPC_MONOTONIC_ELAPSED_DISAGREEMENT")
        utc_elapsed_ns = after["sampled_utc_ns"] - before["sampled_utc_ns"]
        if (utc_elapsed_ns + 1_000_000_000 < qpc_low_ns or
                utc_elapsed_ns - 1_000_000_000 > qpc_high_ns):
            return response("UTC_QPC_ELAPSED_DISAGREEMENT")

    first, last = validated[0], validated[-1]
    # The already-indexed TraceEvent numeric QPC extrema are cheap to review:
    # never rescan 250k JSON rows on the Qt UI thread. Older indexes lack
    # these OPTIONAL audit fields and cannot receive a range verdict.
    trace_clock = summary.get("calendar_clock")
    trace_clock = trace_clock if isinstance(trace_clock, dict) else {}
    qpc_seen = trace_clock.get("source_counter_events_observed")
    qpc_missing = trace_clock.get("source_counter_events_missing")
    qpc_min = trace_clock.get("source_counter_min_ticks")
    qpc_max = trace_clock.get("source_counter_max_ticks")
    qpc_quality = "NOT_ASSESSED_LEGACY_INDEX_OR_MISSING_AUDIT"
    if qpc_seen is not None or qpc_missing is not None:
        counts_ok = (
            type(qpc_seen) is int and type(qpc_missing) is int and
            type(summary.get("rows")) is int and
            qpc_seen >= 0 and qpc_missing >= 0 and
            qpc_seen + qpc_missing == summary["rows"]
        )
        if not counts_ok:
            return response("INVALID_TRACE_QPC_AUDIT_SUMMARY")
        if qpc_seen:
            if (type(qpc_min) is not int or type(qpc_max) is not int or
                    not -(2**63) <= qpc_min <= qpc_max < 2**63):
                return response("INVALID_TRACE_QPC_AUDIT_SUMMARY")
            if (qpc_min < first["qpc_before_ticks"] or
                    qpc_max > last["qpc_after_ticks"]):
                return response(
                    "TRACE_QPC_COUNTER_OUTSIDE_GUARDIAN_WINDOW",
                    trace_qpc_counter_min_ticks=qpc_min,
                    trace_qpc_counter_max_ticks=qpc_max,
                    trace_qpc_range_quality="NUMERIC_ORIGIN_NOT_INDEPENDENTLY_ATTESTED",
                )
            qpc_quality = ("NUMERIC_RANGE_WITHIN_CAPTURE_BRACKETS_UNVERIFIED"
                           if not qpc_missing else
                           "PARTIAL_COUNTER_RANGE_WITHIN_BRACKETS_UNVERIFIED")
        elif qpc_min is not None or qpc_max is not None:
            return response("INVALID_TRACE_QPC_AUDIT_SUMMARY")
        else:
            qpc_quality = "NO_TRACE_QPC_COUNTERS_RECOVERED"

    return response(
        "HASH_MATCHED_QPC_BRACKETS_UNVERIFIED",
        clock_anchor_evidence="CAPTURE_SIDE_ONLY_NOT_TRACE_TIME_ALIGNMENT",
        clock_progression_quality="COARSE_CHECKS_PASSED_UNVERIFIED_NOT_CALIBRATED",
        trace_qpc_range_quality=qpc_quality,
        trace_qpc_counter_events_observed=qpc_seen,
        trace_qpc_counter_events_missing=qpc_missing,
        trace_qpc_counter_min_ticks=qpc_min,
        trace_qpc_counter_max_ticks=qpc_max,
        checked_clock_stages=list(names),
        before_tool={key: first[key] for key in
                     ("qpc_before_ticks", "qpc_after_ticks",
                      "monotonic_before_ns", "monotonic_after_ns",
                      "sampled_utc_ns")},
        after_tool={key: last[key] for key in
                    ("qpc_before_ticks", "qpc_after_ticks",
                     "monotonic_before_ns", "monotonic_after_ns",
                     "sampled_utc_ns")},
        qpc_frequency_hz=freq,
        qpc_tick_span_from_capture_brackets=(last["qpc_after_ticks"] -
                                             first["qpc_before_ticks"]),
    )
