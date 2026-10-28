"""Bounded historical evidence for Deep Inspection, never a PID-only live join.

TraceEvent ProcessIndex and ThreadIndex are local to one trace. They cannot be
compared with GetProcessTimes/GetThreadTimes creation FILETIMEs. Opening a trace
therefore requires an explicit trace instance and retains this uncertainty.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
import time

from .decoder_index import read_index
from .decoder_modules import module_key, validate_module_frame
from .decoder_waits import build_wait_report
from .session_v2 import safe_path

MAX_SCAN_EVENTS = 250_000
MAX_RESULT_BYTES = 768 * 1024
KERNEL_GUID = "9e814aad-3204-11d2-9a82-006008a86939"


def _integer(value, low=0, high=2**63 - 1):
    return type(value) is int and low <= value <= high


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and abs(value) < 1e15


def _identity(target):
    value = target.to_dict() if hasattr(target, "to_dict") else target
    if (type(value) is not dict or not _integer(value.get("pid"), 1, 2**32 - 1)
            or not _integer(value.get("created_100ns"), 1, 2**64 - 1)
            or type(value.get("image_path", "")) is not str
            or len(value.get("image_path", "")) > 32768 or "\0" in value.get("image_path", "")):
        raise ValueError("INVALID_LIVE_PROCESS_IDENTITY")
    return {"pid": value["pid"], "created_100ns": value["created_100ns"],
            "image_path": str(value.get("image_path", ""))[:32768]}


def _stamp(path):
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def _compact_event(row):
    # Payload values are diagnostic observations, not command parameters.
    # Keep only the displayed event's bounded fields; do not retain a trace's
    # full stacks in the Overview worker or normal evidence journal.
    result = {key: row.get(key) for key in
              ("ordinal", "time_ms", "pid", "tid", "process_instance", "provider",
               "provider_guid", "name", "event_id", "opcode", "stack_status")}
    result.update(source="HISTORICAL_TRACE", verification_class="UNVERIFIED_IMPORT",
                  payload=row["payload"], frames=row["frames"][:32],
                  frames_omitted=max(0, len(row["frames"]) - 32),
                  live_thread_relation="NOT_ESTABLISHED")
    return result


def _io_projection(row):
    """Expose recorded fields; do not derive transfer/latency from event names.

    Classic kernel metadata names are useful for navigation, but arbitrary
    providers named 'DiskIO' must never become physical disk measurements.
    Even matching imported GUIDs remain unverified claims from the input.
    """
    guid = row.get("provider_guid")
    if type(guid) is not str or guid.lower() != KERNEL_GUID:
        return None
    name = row.get("name", "")
    family = name.split("/", 1)[0]
    if family not in ("TcpIp", "UdpIp", "FileIO", "DiskIO"):
        return None
    category = "network" if family in ("TcpIp", "UdpIp") else "disk"
    payload = row["payload"]
    fields = {}
    for key in ("saddr", "daddr", "sport", "dport", "SourceAddress", "DestinationAddress",
                "SourcePort", "DestinationPort", "FileName", "FileObject", "FileKey",
                "Irp", "IrpPtr", "Offset", "DiskNumber", "IoFlags", "IssuingThreadId"):
        if key in payload and type(payload[key]) in (str, int, float, bool):
            fields[key] = payload[key]
    recorded_counts = {}
    for key in ("size", "Size", "IoSize", "TransferSize"):
        if key in payload and _integer(payload[key]):
            recorded_counts[key] = payload[key]
    # ElapsedTime/HighResResponseTime units differ across event schemas. Keep
    # these as raw fields; assigning milliseconds by their name would invent
    # a clock conversion, especially in damaged/legacy imports.
    recorded_timings = {key: payload[key] for key in
                        ("ElapsedTime", "HighResResponseTime", "ResponseTime")
                        if key in payload and _number(payload[key])}
    return {"category": category, "event_id": row["ordinal"],
            "trace_relative_ms": row["time_ms"], "pid": row["pid"],
            "process_instance": row["process_instance"], "tid": row["tid"],
            "provider_guid": row["provider_guid"], "event_name": name,
            "source": "HISTORICAL_KERNEL_EVENT_METADATA_UNVERIFIED",
            "fields": fields, "recorded_size_fields": recorded_counts,
            "recorded_timing_fields": recorded_timings, "latency_ms": None,
            "latency_status": "TYPED_UNIT_AND_BOUNDARY_EVIDENCE_REQUIRED",
            "transfer_total_bytes": None, "packet_contents": "NOT_COLLECTED",
            "physical_disk_activity": "NOT_ESTABLISHED",
            "thread_lifetime_binding": "NOT_ESTABLISHED"}


def build_trace_evidence(index_path, target, *, process_instance=None, tid=None,
                         start_ms=None, end_ms=None, limit=200,
                         cancel_event=None, deadline=None, include_waits=True):
    """Return an explicit trace-instance view and candidates, with no live join.

    ``process_instance=None`` is deliberately discovery-only. Even one matching
    PID in a trace is insufficient evidence that it represents today's process.
    The selected TID filters recorded observations, not a current thread handle.
    """
    target = _identity(target)
    if (process_instance is not None and not _integer(process_instance) or
            tid is not None and not _integer(tid, 1, 2**32 - 1) or
            start_ms is not None and not _number(start_ms) or
            end_ms is not None and not _number(end_ms) or
            start_ms is not None and end_ms is not None and start_ms >= end_ms or
            not _integer(limit, 1, 200) or type(include_waits) is not bool):
        raise ValueError("INVALID_HISTORICAL_TRACE_FILTER")
    if deadline is not None and not _number(deadline):
        raise ValueError("INVALID_HISTORICAL_TRACE_DEADLINE")
    stop = min(time.monotonic() + 30, deadline) if deadline is not None else time.monotonic() + 30

    def check():
        if cancel_event is not None and cancel_event.is_set():
            raise InterruptedError("HISTORICAL_TRACE_CANCELLED")
        if time.monotonic() >= stop:
            raise TimeoutError("HISTORICAL_TRACE_DEADLINE")

    check()
    path = safe_path(Path(index_path))
    before_stamp = _stamp(path)
    after = 0
    summary = None
    instances = {}
    events, modules, io_rows = [], {}, []
    examined = selected = unknown = omitted = 0
    result_bytes = 0
    exhausted = False
    while examined < MAX_SCAN_EVENTS:
        check()
        page = read_index(path, pid=target["pid"], after=after, limit=200)
        if summary is None:
            summary = page["summary"]
        elif page["summary"] != summary:
            raise ValueError("HISTORICAL_INDEX_CHANGED_DURING_READ")
        for item in page["rows"]:
            check()
            examined += 1
            row = item["event"]
            instance = row.get("process_instance")
            if instance is None:
                unknown += 1
                continue
            candidate = instances.setdefault(instance, {"process_instance": instance,
                "pid": row["pid"], "events": 0, "first_ms": row["time_ms"],
                "last_ms": row["time_ms"], "live_target_relation": "NOT_ESTABLISHED"})
            candidate["events"] += 1
            candidate["first_ms"] = min(candidate["first_ms"], row["time_ms"])
            candidate["last_ms"] = max(candidate["last_ms"], row["time_ms"])
            if len(instances) > 4096:
                raise ValueError("HISTORICAL_PROCESS_INSTANCE_BUDGET")
            if (process_instance is None or instance != process_instance or
                    tid is not None and row["tid"] != tid or
                    start_ms is not None and row["time_ms"] < start_ms or
                    end_ms is not None and row["time_ms"] >= end_ms):
                continue
            selected += 1
            compact = _compact_event(row)
            encoded_size = len(json.dumps(compact, ensure_ascii=True, allow_nan=False))
            if len(events) >= limit or result_bytes + encoded_size > MAX_RESULT_BYTES:
                omitted += 1
                continue
            events.append(compact)
            result_bytes += encoded_size
            for frame in row["frames"][:32]:
                module = validate_module_frame(row, frame)
                if module is not None:
                    key = module_key(row["pid"], module)
                    modules.setdefault(key, {"module_key": key, **module,
                        "association": "RECORDED_FRAME_WITHIN_TRACE_MODULE_LOAD_WINDOW",
                        "local_pe_pdb_match": "NOT_CHECKED"})
            projected = _io_projection(row)
            if projected is not None:
                io_rows.append(projected)
        after = page["next_cursor"]
        if not page["has_more"]:
            exhausted = True
            break
    check()
    if _stamp(path) != before_stamp:
        raise ValueError("HISTORICAL_INDEX_CHANGED_DURING_READ")
    waits = None
    # Existing analysis scans all scheduler identities, because CSwitch and
    # ReadyThread headers may name the other process. Do not prefilter its
    # input to the selected process's event-header PID.
    if process_instance is not None and include_waits:
        class _BudgetCancel:
            def is_set(self):
                check()
                return False
        waits = build_wait_report(path, pid=target["pid"], process_instance=process_instance,
                                  tid=tid, start_ms=start_ms, end_ms=end_ms,
                                  max_intervals=min(limit, 200), cancel=_BudgetCancel())
        check()
        if _stamp(path) != before_stamp:
            raise ValueError("HISTORICAL_INDEX_CHANGED_DURING_READ")
    limitations = ["TRACE_PROCESS_INDEX_IS_NOT_PROCESS_CREATION_FILETIME",
        "EXPLICIT_TRACE_INSTANCE_SELECTION_DOES_NOT_PROVE_SAME_LIVE_PROCESS",
        "HISTORICAL_STACK_IS_NOT_A_CURRENT_THREAD_STACK",
        "TRACE_RELATIVE_TIME_IS_NOT_THE_LIVE_INSPECTION_CLOCK",
        "IMPORTED_DATA_IS_NOT_AUTHENTICATED_CAPTURE_PROVENANCE",
        "ZERO_REPORTED_LOSS_IS_NOT_PROOF_OF_COMPLETE_CAPTURE",
        "DISPLAYED_NATIVE_MODULES_ARE_FRAME_ASSOCIATIONS_NOT_COMPLETE_INVENTORY",
        "RECORDED_NETWORK_AND_DISK_FIELDS_ARE_NOT_PACKET_CONTENTS_OR_DEVICE_TOTALS"]
    if not exhausted:
        limitations.append("EVENT_SCAN_BUDGET_REACHED")
    if omitted:
        limitations.append("DISPLAY_ROWS_OMITTED_BY_BUDGET")
    if summary["status"] != "DECODED" or summary.get("decoder_reported_lost_events") != 0:
        limitations.append("CAPTURE_LOSS_UNKNOWN_OR_IMPORT_INCOMPLETE")
    if unknown:
        limitations.append("EVENTS_WITHOUT_TRACE_PROCESS_INSTANCE_EXCLUDED")
    data = {"schema": "blackbox.deep-trace/1", "source": "HISTORICAL_TRACE",
        "source_trace_sha256": summary.get("input_sha256"), "trace_file": path.name,
        "target": target, "live_target_relation": "NOT_ESTABLISHED",
        "trace_to_live_clock_alignment": "NOT_ESTABLISHED",
        "verification_class": "UNVERIFIED_IMPORT", "capture_complete": None,
        "trace_selection": {"pid": target["pid"], "process_instance": process_instance,
                            "tid": tid, "start_ms": start_ms, "end_ms": end_ms},
        "candidate_instances": sorted(instances.values(), key=lambda item: item["process_instance"]),
        "events": events, "modules": list(modules.values()), "io_events": io_rows,
        "waits": waits, "coverage": {"scanned_header_pid_events": examined,
            "selected_events": selected, "shown_events": len(events), "omitted_events": omitted,
            "events_without_instance": unknown, "scan_complete": exhausted,
            "decode_status": summary["status"],
            "decoder_reported_lost_events": summary.get("decoder_reported_lost_events")}}
    # Modules/wait intervals are additional derived observations. Apply one
    # final aggregate budget as well as the per-event budget above.
    while len(json.dumps(data, ensure_ascii=True, allow_nan=False)) > 2 * 1024**2:
        check()
        if data["modules"]:
            del data["modules"][len(data["modules"]) // 2:]
        elif data["io_events"]:
            del data["io_events"][len(data["io_events"]) // 2:]
        elif data["events"]:
            drop = len(data["events"]) - len(data["events"]) // 2
            del data["events"][len(data["events"]) // 2:]
            data["coverage"]["shown_events"] -= drop
            data["coverage"]["omitted_events"] += drop
        elif data["waits"] is not None:
            data["waits"] = None
        else:
            raise ValueError("HISTORICAL_RESULT_BUDGET")
        if "AGGREGATE_RESULT_TRUNCATED" not in limitations:
            limitations.append("AGGREGATE_RESULT_TRUNCATED")
    # The operation completed, but linking this historical view to a live
    # process is explicitly incomplete. The caller must not turn this into a
    # live-state success badge merely because rows were found.
    return {"status": "INCOMPLETE_EVIDENCE", "data": data,
            "limitations": limitations, "next_action":
            "SELECT_TRACE_PROCESS_INSTANCE" if process_instance is None else
            "OPEN_TRACE_DECODER_FOR_RECORDED_INSTANCE", "error": None}


def verify_local_symbols(pe_path, pdb_path, *, rva=None, cancel_event=None, deadline=None):
    """Use the existing local PE/PDB reader without guessing a live load link."""
    from .decoder_native_symbols import load_native_symbols
    from .decoder_pdb import review_local_pe_pdb
    if rva is not None and not _integer(rva, 0, 2**32 - 1):
        raise ValueError("INVALID_SYMBOL_RVA")
    if deadline is not None and not _number(deadline):
        raise ValueError("INVALID_SYMBOL_DEADLINE")
    stop = min(time.monotonic() + 30, deadline) if deadline is not None else time.monotonic() + 30

    class _Cancel:
        def is_set(self):
            if cancel_event is not None and cancel_event.is_set():
                raise InterruptedError("LOCAL_SYMBOL_CHECK_CANCELLED")
            if time.monotonic() >= stop:
                raise TimeoutError("LOCAL_SYMBOL_CHECK_DEADLINE")
            return False

    guard = _Cancel()
    guard.is_set()
    identity = review_local_pe_pdb(pe_path, pdb_path)
    guard.is_set()
    matched = identity["status"] == "PE_PDB_GUID_AGE_MATCH_UNLINKED_TO_TRACE"
    data = {"source": "LOCAL_PE_PDB_FILES", "identity": identity,
            "live_module_binding": "NOT_ESTABLISHED", "rva": rva, "symbol": None}
    if matched and rva is not None:
        table = load_native_symbols(pe_path, pdb_path, cancel=guard)
        data["symbol"] = table.lookup(rva)
        data["native_symbols"] = table.summary()
    guard.is_set()
    return {"status": "COMPLETED" if matched else "INCOMPLETE_EVIDENCE", "data": data,
        "limitations": ["PE_PDB_IDENTITY_MATCH_IS_NOT_A_LIVE_MODULE_LOAD_BINDING",
            "LOCAL_FILES_ARE_NOT_AUTHENTICATED", "NO_SYMBOL_SERVER_OR_SOURCE_FILE_DOWNLOAD"],
        "next_action": "SELECT_RECORDED_MODULE_AND_RVA" if matched else "SELECT_MATCHING_LOCAL_PE_PDB",
        "error": None}
