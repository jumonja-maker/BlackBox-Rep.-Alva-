"""Bounded, typed ETW scheduler observations, not a deadlock/root-cause oracle.

Pairing uses TraceLog process AND thread lifetime indices, never PID/TID alone.
A CSwitch wait reason describes the switch-out; only a ReadyThread boundary
separates observed blocked and ready spans. No missing boundary is invented.
Imported records and absence of reported loss are not capture attestation.
"""
from __future__ import annotations

from contextlib import closing
import json
import math
import sqlite3
import time

from .decoder_cpu import ETW_PROVIDER, ETW_PROVIDER_GUID
from .session_v2 import safe_path

SCHEDULE_SCHEMA = "blackbox.thread-schedule/1"
SCHEDULE_EVENTS = {"switch": ("Thread/CSwitch", 36, "TRACEEVENT_CSWITCH"),
                   "ready": ("Dispatcher/ReadyThread", 50, "TRACEEVENT_READY_THREAD")}
MAX_SCHEDULE_EVENTS = 250_000
MAX_THREADS = 16_384
MAX_INTERVALS = 20_000


def _int(value, minimum=0, maximum=2**63-1):
    return type(value) is int and minimum <= value <= maximum


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and abs(value) < 1e15


def _identity(value, now):
    keys = {"pid", "tid", "process_instance", "thread_instance", "start_ms", "end_ms", "attribution"}
    if (type(value) is not dict or set(value) != keys or
            not _int(value["pid"], -1, 2**32-1) or not _int(value["tid"], -1, 2**32-1)):
        raise ValueError("INVALID_SCHEDULER_THREAD_IDENTITY")
    if value["attribution"] == "UNRESOLVED_THREAD":
        if any(value[k] is not None for k in ("process_instance", "thread_instance", "start_ms", "end_ms")):
            raise ValueError("INVALID_UNRESOLVED_THREAD_IDENTITY")
        return None
    if (value["attribution"] != "TRACELOG_THREAD_LIFETIME" or value["pid"] <= 0 or value["tid"] <= 0 or
            not _int(value["process_instance"]) or not _int(value["thread_instance"]) or
            not _number(value["start_ms"]) or not _number(value["end_ms"]) or
            not value["start_ms"] <= now <= value["end_ms"]):
        raise ValueError("INVALID_SCHEDULER_THREAD_LIFETIME")
    return (value["pid"], value["process_instance"], value["tid"], value["thread_instance"])


def validate_schedule_event(row):
    """Optional additive contract. Legacy scheduler rows require re-decode."""
    value = row.get("thread_schedule")
    if value is None:
        return None
    if type(value) is not dict or value.get("kind") not in SCHEDULE_EVENTS:
        raise ValueError("INVALID_SCHEDULER_CONTRACT")
    kind = value["kind"]
    event, opcode, parser = SCHEDULE_EVENTS[kind]
    fields = {"schema", "source", "parser", "kind", "processor_index"}
    fields |= ({"old_thread", "new_thread", "old_state_code", "old_state", "wait_reason_code", "wait_reason", "wait_mode"}
               if kind == "switch" else {"ready_thread", "waker_thread"})
    if (set(value) != fields or value["schema"] != SCHEDULE_SCHEMA or
            value["source"] != "ETW_KERNEL_SCHEDULER" or value["parser"] != parser or
            row.get("provider") != ETW_PROVIDER or row.get("provider_guid") != ETW_PROVIDER_GUID or
            row.get("name") != event or not _int(row.get("event_id"), 65535, 65535) or
            not _int(row.get("opcode"), opcode, opcode) or not _int(row.get("version"), 0, 255) or
            not _int(value["processor_index"], 0, 65535) or not _number(row.get("time_ms"))):
        raise ValueError("INVALID_SCHEDULER_SOURCE")
    identities = ("old_thread", "new_thread") if kind == "switch" else ("ready_thread", "waker_thread")
    for name in identities:
        _identity(value[name], row["time_ms"])
    current = value["new_thread" if kind == "switch" else "waker_thread"]
    if (current["tid"] != row.get("tid") or
            (current["pid"] >= 0 and row.get("pid", -1) >= 0 and current["pid"] != row["pid"]) or
            (current["process_instance"] is not None and row.get("process_instance") is not None and
             current["process_instance"] != row["process_instance"])):
        raise ValueError("CONFLICTING_SCHEDULER_CURRENT_THREAD")
    payload = row.get("payload", {})
    pairs = [("NewThreadID", value["new_thread"]["tid"]), ("OldThreadID", value["old_thread"]["tid"])] if kind == "switch" else [("AwakenedThreadID", value["ready_thread"]["tid"])]
    for key, expected in pairs:
        if key in payload and (type(payload[key]) is not int or payload[key] != expected):
            raise ValueError("CONFLICTING_SCHEDULER_PAYLOAD")
    if kind == "switch":
        for key in ("old_state_code", "wait_reason_code", "wait_mode"):
            if not _int(value[key], 0, 255):
                raise ValueError("INVALID_SCHEDULER_STATE")
        for key in ("old_state", "wait_reason"):
            if type(value[key]) is not str or not 1 <= len(value[key]) <= 128:
                raise ValueError("INVALID_SCHEDULER_STATE")
    return value


def build_wait_report(index_path, *, pid=0, process_instance=None, tid=None,
                      start_ms=None, end_ms=None, max_intervals=10_000, cancel=None):
    """Read-only ETW off-CPU report; filters clip observed intervals, not events.

    A reported loss or truncated index makes spans candidates only: neither an
    exact off-CPU duration nor its blocked/ready components is then asserted.
    """
    from .decoder_index import APP_ID, validate_event
    if (not _int(pid) or (process_instance is not None and not _int(process_instance)) or
            (tid is not None and not _int(tid)) or
            (start_ms is not None and not _number(start_ms)) or
            (end_ms is not None and not _number(end_ms)) or
            (start_ms is not None and end_ms is not None and start_ms >= end_ms) or
            not _int(max_intervals, 1, MAX_INTERVALS)):
        raise ValueError("INVALID_WAIT_FILTER")
    path = safe_path(index_path)
    if not path.is_file():
        raise ValueError("INVALID_INDEX_FILE")
    deadline = time.monotonic() + 30

    def check():
        if cancel is not None and cancel.is_set():
            raise InterruptedError("WAIT_ANALYSIS_CANCELLED")
        if time.monotonic() > deadline:
            raise TimeoutError("WAIT_ANALYSIS_DEADLINE")

    def selected(identity):
        return ((not pid or identity[0] == pid) and
                (process_instance is None or identity[1] == process_instance) and
                (tid is None or identity[2] == tid))

    counts = {key: 0 for key in (
        "candidate_events", "typed_events", "missing_typed_classification", "unresolved_identities",
        "unresolved_selected_identities", "pending_intervals_invalidated_by_identity",
        "selected_switch_outs", "selected_switch_ins", "selected_ready_events", "paired_intervals",
        "represented_intervals", "intervals_omitted_budget", "left_censored_switch_ins",
        "right_censored_switch_outs", "unmatched_ready_events", "duplicate_switch_outs",
        "duplicate_ready_events", "ambiguous_intervals", "out_of_order_events",
        "pending_intervals_invalidated_by_order", "events_with_decode_errors", "ready_state_conflicts",
        "zero_duration_intervals", "self_switches", "contradictory_self_switches")}
    pending = {}; identities = {}; intervals = []; last_time = None
    totals = {"observed_off_cpu_ms": 0.0, "observed_blocked_ms": 0.0, "observed_ready_delay_ms": 0.0}
    reason_totals = {}

    def thread_key(value, now):
        key = _identity(value, now)
        if key is None:
            counts["unresolved_identities"] += 1
            # A switch-in whose lifetime cannot be resolved can still name a
            # pending raw TID. It may represent hidden execution of that very
            # thread. Never bridge across it using a later resolved identity.
            # TID 0 is the idle thread and cannot be a positive application TID.
            raw_pid, raw_tid = value["pid"], value["tid"]
            if raw_tid != 0:
                affected = [key for key in pending if
                            (raw_tid < 0 or key[2] == raw_tid) and
                            (raw_pid <= 0 or key[0] == raw_pid)]
                for affected_key in affected:
                    if not pending[affected_key]["ambiguous"]:
                        counts["pending_intervals_invalidated_by_identity"] += 1
                    pending[affected_key]["ambiguous"] = True
                if ((not pid or raw_pid <= 0 or raw_pid == pid) and
                        (tid is None or raw_tid < 0 or raw_tid == tid)):
                    counts["unresolved_selected_identities"] += 1
            return None
        if not selected(key):
            return None
        bounds = (value["start_ms"], value["end_ms"])
        if key in identities and identities[key] != bounds:
            raise ValueError("SCHEDULER_LIFETIME_CHANGED_WITHIN_INDEX")
        if key not in identities and len(identities) >= MAX_THREADS:
            raise ValueError("WAIT_THREAD_BUDGET")
        identities[key] = bounds
        return key

    def close_interval(key, state, row, trusted_boundaries):
        if state["ambiguous"] or row["time_ms"] < state["start"]:
            counts["ambiguous_intervals"] += 1
            return
        original_start, original_end = state["start"], row["time_ms"]
        a = max(original_start, start_ms) if start_ms is not None else original_start
        b = min(original_end, end_ms) if end_ms is not None else original_end
        if b < a or b == a and original_end != original_start:
            return
        if b == a:
            counts["zero_duration_intervals"] += 1
            return
        counts["paired_intervals"] += 1
        span = b - a
        valid = trusted_boundaries and not state["errors"] and not row.get("errors")
        ready = state["ready"] if not state["ready_ambiguous"] else None
        blocked = ready_delay = None
        if valid:
            totals["observed_off_cpu_ms"] += span
            if state["state_code"] == 1:  # Ready/preempted, not waiting on a lock.
                ready_delay, blocked = span, 0.0
            elif state["state_code"] == 5 and ready is not None:
                cut = min(b, max(a, ready["time"]))
                blocked, ready_delay = cut-a, b-cut
            if blocked is not None:
                totals["observed_blocked_ms"] += blocked
                totals["observed_ready_delay_ms"] += ready_delay
            label = state["reason"] if state["state_code"] == 5 else "READY_OR_OTHER_STATE_NOT_WAIT_REASON"
            reason_totals[label] = reason_totals.get(label, 0.0) + span
        quality = ("LOSS_OR_TRUNCATION_BOUNDARIES_ONLY" if not trusted_boundaries else
                   "DECODE_ERROR_BOUNDARIES_ONLY" if not valid else
                   "READY_SPLIT_AMBIGUOUS" if state["ready_ambiguous"] else
                   "OBSERVED_SWITCH_PAIR")
        explanation = ("Recorded switch-out and switch-in bound an observed non-running span. "
                       "Kernel wait reason is not a lock identity, lock owner, or application root cause.")
        if not valid:
            explanation = "Loss, truncation or decode errors can hide intermediate execution; only boundary span is known."
        elif blocked is None:
            explanation += " No unique ReadyThread boundary: blocked time and ready-queue delay are unknown."
        result = {"pid": key[0], "process_instance": key[1], "tid": key[2], "thread_instance": key[3],
                  "start_ms": a, "end_ms": b, "source_start_ms": original_start, "source_end_ms": original_end,
                  "observed_span_ms": span, "off_cpu_ms": span if valid else None,
                  "blocked_ms": blocked, "ready_delay_ms": ready_delay,
                  "thread_state": state["state"], "thread_state_code": state["state_code"],
                  "wait_reason": state["reason"] if state["state_code"] == 5 else None,
                  "wait_reason_code": state["reason_code"] if state["state_code"] == 5 else None,
                  "ready_time_ms": ready["time"] if ready else None,
                  "waker_thread": ready["waker"] if ready else None,
                  "waker_is_lock_owner": "NOT_ESTABLISHED", "quality": quality,
                  "window_clipped": (a, b) != (original_start, original_end),
                  "source_event_ids": [state["event_id"], *([ready["id"]] if ready else []), row["ordinal"]],
                  "explanation": explanation}
        if len(intervals) < max_intervals:
            intervals.append(result)
            counts["represented_intervals"] += 1
        else:
            counts["intervals_omitted_budget"] += 1

    check()
    try:
        with closing(sqlite3.connect(path.resolve().as_uri()+"?mode=ro", uri=True, timeout=1)) as db:
            db.execute("PRAGMA query_only=ON"); db.execute("PRAGMA trusted_schema=OFF")
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2*1024**2)
            db.set_progress_handler(lambda: int(time.monotonic() > deadline or
                (cancel is not None and cancel.is_set())), 1000)
            if (db.execute("PRAGMA application_id").fetchone()[0] != APP_ID or
                    db.execute("PRAGMA user_version").fetchone()[0] not in (1, 2, 3, 4)):
                raise ValueError("INVALID_INDEX_SCHEMA")
            db.execute("BEGIN")
            summary = json.loads(db.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
            if type(summary) is not dict or summary.get("status") not in ("DECODED", "TRUNCATED"):
                raise ValueError("INVALID_INDEX_SUMMARY")
            loss = summary.get("decoder_reported_lost_events")
            if loss is not None and not _int(loss):
                raise ValueError("INVALID_INDEX_LOSS")
            # Unknown loss remains unknown; exact splits are withheld unless
            # the decoder explicitly reported zero and did not truncate.
            trusted_boundaries = summary["status"] == "DECODED" and loss == 0
            sql = "SELECT id,pid,time_ms,provider,name,data FROM events WHERE provider=? AND name IN (?,?) ORDER BY id"
            for event_id, stored_pid, stored_time, provider, name, raw in db.execute(sql,
                    (ETW_PROVIDER, SCHEDULE_EVENTS["switch"][0], SCHEDULE_EVENTS["ready"][0])):
                check(); counts["candidate_events"] += 1
                if counts["candidate_events"] > MAX_SCHEDULE_EVENTS:
                    raise ValueError("WAIT_EVENT_BUDGET")
                row = json.loads(raw)
                validate_event(row, event_id)
                if (row["pid"] != stored_pid or row["time_ms"] != stored_time or
                        row["provider"] != provider or row["name"] != name):
                    raise ValueError("INDEX_EVENT_METADATA_MISMATCH")
                now = row["time_ms"]
                if last_time is not None and now < last_time:
                    counts["out_of_order_events"] += 1
                    counts["pending_intervals_invalidated_by_order"] += len(pending)
                    pending.clear()
                last_time = now
                event = validate_schedule_event(row)
                if event is None:
                    counts["missing_typed_classification"] += 1
                    # An unclassified scheduler event may hide a relevant switch.
                    # Its timestamp also participates in ordering: a late legacy
                    # row can contradict a pair already emitted above.
                    for state in pending.values():
                        state["ambiguous"] = True
                    continue
                counts["typed_events"] += 1
                if row.get("errors"):
                    counts["events_with_decode_errors"] += 1
                if event["kind"] == "ready":
                    key = thread_key(event["ready_thread"], now)
                    if key is None:
                        continue
                    counts["selected_ready_events"] += 1
                    state = pending.get(key)
                    if state is None:
                        counts["unmatched_ready_events"] += 1
                    elif state["state_code"] != 5 or now < state["start"]:
                        counts["ready_state_conflicts"] += 1
                        state["ready_ambiguous"] = True
                    elif state["ready"] is not None:
                        counts["duplicate_ready_events"] += 1
                        state["ready_ambiguous"] = True
                    else:
                        state["ready"] = {"time": now, "id": event_id, "waker": event["waker_thread"]}
                        state["errors"] = state["errors"] or bool(row.get("errors"))
                    continue
                old = thread_key(event["old_thread"], now)
                new = thread_key(event["new_thread"], now)
                if old is not None and old == new:
                    counts["self_switches"] += 1
                    # A self-switch says this thread was executing at this
                    # timestamp. It contradicts a pending uninterrupted gap.
                    if pending.pop(old, None) is not None:
                        counts["contradictory_self_switches"] += 1
                        counts["ambiguous_intervals"] += 1
                    continue
                if new is not None:
                    counts["selected_switch_ins"] += 1
                    state = pending.pop(new, None)
                    if state is None:
                        counts["left_censored_switch_ins"] += 1
                    else:
                        close_interval(new, state, row, trusted_boundaries)
                if old is not None:
                    counts["selected_switch_outs"] += 1
                    duplicate = old in pending
                    counts["duplicate_switch_outs"] += int(duplicate)
                    pending[old] = {"start": now, "event_id": event_id, "state": event["old_state"],
                        "state_code": event["old_state_code"], "reason": event["wait_reason"],
                        "reason_code": event["wait_reason_code"], "ambiguous": duplicate,
                        "errors": bool(row.get("errors")), "ready": None, "ready_ambiguous": False}
            check()
    except sqlite3.OperationalError:
        check()
        raise
    counts["right_censored_switch_outs"] = len(pending)
    if counts["out_of_order_events"]:
        # A late event may fall inside a pair already emitted before we noticed
        # the order reversal. Withhold every numeric duration, including totals
        # for intervals omitted by the display budget; never double count
        # overlapping candidate gaps from a corrupted or reordered stream.
        for interval in intervals:
            interval.update(off_cpu_ms=None, blocked_ms=None, ready_delay_ms=None,
                quality="OUT_OF_ORDER_BOUNDARIES_ONLY",
                explanation="Event order reverses within the index; earlier spans may hide execution. Exact durations are withheld.")
        totals = dict.fromkeys(totals, 0.0)
        reason_totals.clear()
    partial = (not trusted_boundaries or counts["missing_typed_classification"] or
               counts["ambiguous_intervals"] or counts["out_of_order_events"] or
               counts["intervals_omitted_budget"] or counts["events_with_decode_errors"] or
               counts["unresolved_selected_identities"])
    status = ("NO_SCHEDULER_EVENTS" if not counts["candidate_events"] else
              "REDECODE_REQUIRED" if not counts["typed_events"] else
              "PARTIAL_EVIDENCE" if partial else
              "OBSERVED_INTERVALS" if counts["paired_intervals"] else "NO_COMPLETE_INTERVALS")
    return {"schema": "blackbox.thread-waits/1", "status": status,
            "source_trace_sha256": summary.get("input_sha256"), "intervals": intervals,
            "coverage": {**counts, "threads_in_scope": len(identities),
                "decoder_reported_lost_events": loss, "decode_status": summary["status"],
                "duration_totals_withheld_due_to_order": bool(counts["out_of_order_events"])},
            "totals": totals, "observed_off_cpu_by_switch_out_reason_ms": reason_totals,
            "totals_scope": "ALL_PAIRED_FILTERED_INTERVALS_INCLUDING_DISPLAY_BUDGET_OMISSIONS",
            "filters": {"pid": pid, "process_instance": process_instance, "tid": tid,
                        "start_ms_inclusive": start_ms, "end_ms_exclusive": end_ms},
            "measurement": "OBSERVED_SCHEDULER_INTERVALS_NOT_WHOLE_PROCESS_WALL_TIME",
            "capture_complete": None, "trace_to_session_alignment": "NOT_ESTABLISHED",
            "root_cause": "UNKNOWN", "verification_class": "UNVERIFIED_IMPORT",
            "limitations": ["THREAD_LIFETIME_INDICES_ARE_IMPORTED_METADATA",
                "ZERO_REPORTED_LOSS_IS_NOT_PROOF_OF_COMPLETE_CAPTURE", "NO_INVENTED_MISSING_BOUNDARIES",
                "WAIT_REASON_IS_NOT_LOCK_ID_OR_OWNER", "EVENTPIPE_CPU_SAMPLES_DO_NOT_ESTABLISH_OFF_CPU",
                "SUMS_ACROSS_THREADS_ARE_NOT_PROCESS_ELAPSED_TIME"]}
