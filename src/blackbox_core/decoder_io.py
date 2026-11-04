"""Typed kernel disk/network projections; never classify by payload names alone."""
from __future__ import annotations

import ipaddress
import hashlib
import math
import re

from .decoder_cpu import ETW_PROVIDER_GUID

IO_SCHEMA = "blackbox.trace-io/1"
MAX_IO_PENDING_METADATA_BYTES = 32 * 1024**2
_KEY = re.compile(r"[0-9a-f]{64}\Z")
_FILE_OPERATIONS = {
    64: ("create", "Create", "TRACEEVENT_FILE_IO_CREATE"),
    65: ("cleanup", "Cleanup", "TRACEEVENT_FILE_IO_SIMPLE"),
    66: ("close", "Close", "TRACEEVENT_FILE_IO_SIMPLE"),
    67: ("read", "Read", "TRACEEVENT_FILE_IO_READ_WRITE"),
    68: ("write", "Write", "TRACEEVENT_FILE_IO_READ_WRITE"),
    69: ("set_info", "SetInfo", "TRACEEVENT_FILE_IO_INFO"),
    70: ("delete", "Delete", "TRACEEVENT_FILE_IO_INFO"),
    71: ("rename", "Rename", "TRACEEVENT_FILE_IO_INFO"),
    72: ("dir_enum", "DirEnum", "TRACEEVENT_FILE_IO_DIRECTORY"),
    73: ("flush", "Flush", "TRACEEVENT_FILE_IO_SIMPLE"),
    74: ("query_info", "QueryInfo", "TRACEEVENT_FILE_IO_INFO"),
    75: ("fs_control", "FSControl", "TRACEEVENT_FILE_IO_INFO"),
    76: ("operation_end", "OperationEnd", "TRACEEVENT_FILE_IO_OP_END"),
    77: ("dir_notify", "DirNotify", "TRACEEVENT_FILE_IO_DIRECTORY"),
}
_NETWORK_PARSERS = {
    "TRACEEVENT_TcpIpTraceData": ("TCP", "IPv4", {"receive"}),
    "TRACEEVENT_TcpIpSendTraceData": ("TCP", "IPv4", {"send"}),
    "TRACEEVENT_TcpIpV6TraceData": ("TCP", "IPv6", {"receive"}),
    "TRACEEVENT_TcpIpV6SendTraceData": ("TCP", "IPv6", {"send"}),
    "TRACEEVENT_UdpIpTraceData": ("UDP", "IPv4", {"send", "receive"}),
    # The spelling is the actual public type in pinned TraceEvent 4.0.0.
    "TRACEEVENT_UpdIpV6TraceData": ("UDP", "IPv6", {"send", "receive"}),
}


def _int(value, minimum=0, maximum=2**63 - 1):
    return type(value) is int and minimum <= value <= maximum


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value < 1e15


def _require(value):
    if not value:
        raise ValueError("INVALID_TYPED_IO_CONTRACT")


def validate_io_observation(row):
    """Validate optional new fields while retaining older trace-index support."""
    value = row.get("io_observation")
    if value is None:
        return None
    _require(type(value) is dict and value.get("schema") == IO_SCHEMA and
             row.get("provider_guid") == ETW_PROVIDER_GUID and
             type(row.get("event_id")) is int and row["event_id"] == 65535 and
             _int(row.get("opcode"), 0, 255) and _int(row.get("version"), 0, 255))
    if value.get("kind") == "disk":
        fields = {"schema", "source", "parser", "kind", "operation", "transferred_bytes",
             "elapsed_ms", "response_qpc_ticks", "counter_frequency_hz", "duration_basis",
             "start_boundary_observed", "device_busy_time_established"}
        _require(set(value) in (fields, fields | {"request_key", "disk_number", "event_thread"}))
        _require(value["source"] == "ETW_KERNEL_DISK_IO" and value["parser"] == "TRACEEVENT_DISK_IO" and
                 row["opcode"] in (10, 11) and row["version"] in (2, 3) and
                 value["operation"] == ("read" if row["opcode"] == 10 else "write") and
                 row.get("name") == ("DiskIO/Read" if row["opcode"] == 10 else "DiskIO/Write") and
                 _int(value["transferred_bytes"], 0, 2**32 - 1) and _number(value["elapsed_ms"]) and
                 _int(value["response_qpc_ticks"]) and _int(value["counter_frequency_hz"], 1, 10**12) and
                 value["duration_basis"] == "COMPLETION_EVENT_REPORTED_QPC_DURATION" and
                 value["start_boundary_observed"] is False and value["device_busy_time_established"] is False)
        expected = value["response_qpc_ticks"] * 1000 / value["counter_frequency_hz"]
        _require(abs(value["elapsed_ms"] - expected) <= max(0.000001, expected * 1e-10))
        for key, actual in (("TransferSize", value["transferred_bytes"]),
                            ("HighResResponseTime", value["response_qpc_ticks"])):
            if key in row["payload"]:
                _require(type(row["payload"][key]) is int and row["payload"][key] == actual)
        if "request_key" in value:
            _validate_disk_request_identity(row, value)
    elif value.get("kind") == "network":
        _require(set(value) == {"schema", "source", "parser", "kind", "protocol", "operation", "family",
            "transferred_bytes", "source_address", "destination_address", "source_port", "destination_port",
            "address_status", "byte_count_scope", "packet_contents"})
        _require(value["source"] == "ETW_KERNEL_NETWORK" and value["parser"] in _NETWORK_PARSERS and
                 value["protocol"] in ("TCP", "UDP") and row["opcode"] in (10, 11, 26, 27) and
                 row["version"] in (1, 2) and
                 value["operation"] == ("send" if row["opcode"] in (10, 26) else "receive") and
                 value["family"] == ("IPv4" if row["opcode"] < 26 else "IPv6") and
                 _int(value["transferred_bytes"], 0, 2**32 - 1) and
                 _int(value["source_port"], 0, 65535) and _int(value["destination_port"], 0, 65535) and
                 value["byte_count_scope"] == "THIS_RECORDED_KERNEL_EVENT_NOT_PROCESS_OR_LINK_TOTAL" and
                 value["packet_contents"] == "NOT_COLLECTED")
        protocol, address_family, operations = _NETWORK_PARSERS[value["parser"]]
        _require(value["protocol"] == protocol and value["family"] == address_family and
                 value["operation"] in operations and
                 (address_family != "IPv6" or row["version"] == 2))
        family = "TcpIp" if value["protocol"] == "TCP" else "UdpIp"
        action = "Send" if value["operation"] == "send" else "Recv"
        suffix = "IPV6" if value["family"] == "IPv6" else ""
        # KernelTraceEventParser names IPv4 events without an explicit suffix.
        _require(row.get("name") == f"{family}/{action}{suffix}")
        present = True
        for key in ("source_address", "destination_address"):
            address = value[key]
            if address is None:
                present = False
                continue
            _require(type(address) is str and 1 <= len(address) <= 128)
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                raise ValueError("INVALID_TYPED_IO_ADDRESS") from None
            _require(parsed.version == (4 if value["family"] == "IPv4" else 6))
        _require(value["address_status"] == ("DECODED" if present else "INCOMPLETE_EVIDENCE"))
        for key, actual in (("size", value["transferred_bytes"]),
                            ("sport", value["source_port"]), ("dport", value["destination_port"])):
            if key in row["payload"]:
                _require(type(row["payload"][key]) is int and row["payload"][key] == actual)
    elif value.get("kind") == "file":
        _validate_file_observation(row, value)
    elif value.get("kind") == "disk_request":
        _require(set(value) == {"schema", "source", "parser", "kind", "operation", "request_key", "event_thread"} and
            value["source"] == "ETW_KERNEL_DISK_REQUEST" and value["parser"] == "TRACEEVENT_DISK_IO_INIT" and
            row["opcode"] in (12, 13) and row["version"] in (0, 1, 2, 3) and
            value["operation"] == ("read" if row["opcode"] == 12 else "write") and
            row.get("name") == ("DiskIO/ReadInit" if row["opcode"] == 12 else "DiskIO/WriteInit"))
        _validate_disk_request_identity(row, value)
    else:
        raise ValueError("INVALID_TYPED_IO_KIND")
    return value


def _pointer_key(pointer, kind):
    return hashlib.sha256(("blackbox.file-io/1:" + kind + ":" + format(pointer, "x")).encode("ascii")).hexdigest() if pointer else None


def _compact_io_boundary(row):
    """Never retain arbitrary event payloads/stacks while waiting for a pair."""
    value = {key: row[key] for key in ("ordinal", "pid", "tid", "time_ms", "name", "io_observation")}
    value["errors"] = bool(row.get("errors"))
    return value


def _pending_metadata_size(boundary):
    import json
    return len(json.dumps(boundary, ensure_ascii=True, separators=(",", ":")).encode("ascii"))


def _validate_disk_request_identity(row, value):
    from .decoder_waits import _identity
    _require(value["request_key"] is None or type(value["request_key"]) is str and _KEY.fullmatch(value["request_key"]) is not None)
    identity = _identity(value["event_thread"], row["time_ms"])
    thread = value["event_thread"]
    _require(thread["tid"] == row.get("tid") and
        (thread["pid"] < 0 or row.get("pid", -1) < 0 or thread["pid"] == row["pid"]) and
        (identity is None or row.get("process_instance") is None or identity[1] == row["process_instance"]))
    if "disk_number" in value:
        _require(_int(value["disk_number"], -1, 2**31-1))
    pointer = row.get("payload", {}).get("Irp")
    if pointer is not None:
        _require(_int(pointer, 0, 2**64-1) and _pointer_key(pointer, "disk-request") == value["request_key"])


def _validate_file_observation(row, value):
    from .decoder_waits import _identity
    _require(set(value) == {"schema", "source", "parser", "kind", "phase", "operation", "request_key",
        "file_object_key", "file_name", "name_status", "requested_bytes", "offset", "ntstatus",
        "status_domain", "event_thread", "key_basis", "transferred_bytes"})
    operation = _FILE_OPERATIONS.get(row.get("opcode"))
    _require(operation is not None and row.get("version") in (2, 3) and
        value["source"] == "ETW_KERNEL_FILE_IO" and value["operation"] == operation[0] and
        row.get("name") == "FileIO/" + operation[1] and value["parser"] == operation[2] and
        value["phase"] == ("end" if row["opcode"] == 76 else "start") and
        value["key_basis"] == "HASHED_KERNEL_REQUEST_TOKEN_SCOPED_TO_SOURCE_TRACE" and
        value["transferred_bytes"] is None)
    for field in ("request_key", "file_object_key"):
        _require(value[field] is None or type(value[field]) is str and _KEY.fullmatch(value[field]) is not None)
    name = value["file_name"]
    _require(name is None or type(name) is str and 1 <= len(name) <= 2048)
    _require(value["name_status"] in ("RECORDED", "UNAVAILABLE", "TRUNCATED") and
        (name is None) == (value["name_status"] == "UNAVAILABLE"))
    _require(type(row.get("time_ms")) in (int, float) and math.isfinite(row["time_ms"]) and abs(row["time_ms"]) < 1e15)
    identity = _identity(value["event_thread"], row["time_ms"])
    event_thread = value["event_thread"]
    _require(event_thread["tid"] == row.get("tid") and
        (event_thread["pid"] < 0 or row.get("pid", -1) < 0 or event_thread["pid"] == row["pid"]) and
        (identity is None or row.get("process_instance") is None or identity[1] == row["process_instance"]))
    if value["phase"] == "end":
        _require(_int(value["ntstatus"], 0, 2**32-1) and value["status_domain"] == "NTSTATUS" and
            all(value[key] is None for key in ("requested_bytes", "offset", "file_object_key", "file_name")))
        status = row.get("payload", {}).get("NtStatus")
        if status is not None:
            _require(_int(status, -(2**31), 2**32-1) and (status & 0xffffffff) == value["ntstatus"])
    else:
        _require(value["ntstatus"] is None and value["status_domain"] == "NOT_REPORTED_IN_START_EVENT")
        if value["operation"] in ("read", "write"):
            _require(_int(value["requested_bytes"], 0, 2**32-1) and _int(value["offset"], -(2**63), 2**63-1))
        else:
            _require(value["requested_bytes"] is None and value["offset"] is None)
    payload = row.get("payload", {})
    for field, typed, kind in (("IrpPtr", "request_key", "request"), ("FileObject", "file_object_key", "file-object")):
        if field in payload:
            _require(_int(payload[field], 0, 2**64-1) and _pointer_key(payload[field], kind) == value[typed])


def validate_io_clock(row, engine_header):
    """A disk event's unit conversion must agree with its source trace header."""
    value = row.get("io_observation")
    if value is None or value.get("kind") != "disk":
        return
    frequency = engine_header.get("trace_counter_frequency_hz") if type(engine_header) is dict else None
    if not _int(frequency, 1, 10**12) or frequency != value["counter_frequency_hz"]:
        raise ValueError("TYPED_DISK_IO_SOURCE_FREQUENCY_MISMATCH")


def build_file_io_report(index_path, *, pid=0, process_instance=None, tid=None,
                         start_ms=None, end_ms=None, max_operations=10_000, cancel=None):
    """Pair recorded FileIO request/completion boundaries, never guessed API calls.

    Kernel request tokens are scoped to this trace and an observed start. Exact
    issuing thread lifetime comes from the start, because asynchronous completion
    can run on a different thread. Loss/order/duplicate starts withhold request
    duration and status attribution; the raw completion status remains labelled
    separately. No NTSTATUS is silently converted into an observed Win32 error.
    """
    from contextlib import closing
    import json
    import sqlite3
    import time
    from .decoder_cpu import ETW_PROVIDER
    from .decoder_index import APP_ID, validate_event
    from .decoder_waits import _identity
    from .session_v2 import safe_path

    def finite(value):
        return type(value) in (int, float) and math.isfinite(value) and abs(value) < 1e15

    if (not _int(pid, 0, 2**32-1) or process_instance is not None and not _int(process_instance) or
            tid is not None and not _int(tid, 1, 2**32-1) or
            start_ms is not None and not finite(start_ms) or end_ms is not None and not finite(end_ms) or
            start_ms is not None and end_ms is not None and start_ms >= end_ms or
            not _int(max_operations, 1, 20_000)):
        raise ValueError("INVALID_FILE_IO_FILTER")
    path = safe_path(index_path)
    if not path.is_file():
        raise ValueError("INVALID_INDEX_FILE")
    deadline = time.monotonic() + 30

    def check():
        if cancel is not None and cancel.is_set():
            raise InterruptedError("FILE_IO_ANALYSIS_CANCELLED")
        if time.monotonic() > deadline:
            raise TimeoutError("FILE_IO_ANALYSIS_DEADLINE")

    def selected(identity, raw):
        return ((not pid or (identity[0] if identity else raw["pid"]) == pid) and
                (process_instance is None or identity is not None and identity[1] == process_instance) and
                (tid is None or (identity[2] if identity else raw["tid"]) == tid))

    counts = dict.fromkeys(("candidate_events", "typed_events", "missing_typed_classification",
        "unresolved_issuing_threads", "missing_request_keys", "duplicate_request_starts",
        "paired_operations", "represented_operations", "operations_omitted_budget",
        "unmatched_completions", "right_censored_requests", "events_with_decode_errors",
        "out_of_order_events", "ambiguous_pairs", "window_clipped_operations"), 0)
    pending, operations = {}, []
    pending_bytes = pending_peak = 0
    file_event_names = frozenset("FileIO/" + value[1] for value in _FILE_OPERATIONS.values())
    last_time = None
    status_names = {0: "STATUS_SUCCESS", 0x103: "STATUS_PENDING", 0xC0000022: "STATUS_ACCESS_DENIED",
                    0xC0000043: "STATUS_SHARING_VIOLATION", 0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
                    0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND", 0xC0000008: "STATUS_INVALID_HANDLE",
                    0xC0000120: "STATUS_CANCELLED", 0xC00000B5: "STATUS_IO_TIMEOUT"}

    def emit(state, end=None):
        first, observation, identity = state["row"], state["observation"], state["identity"]
        if not selected(identity, first):
            return
        a = first["time_ms"]
        b = end["time_ms"] if end is not None else a
        if b < a:
            counts["ambiguous_pairs"] += 1
            return
        if start_ms is not None and b < start_ms or end_ms is not None and a > end_ms:
            return
        left = max(a, start_ms) if start_ms is not None else a
        right = min(b, end_ms) if end_ms is not None else b
        clipped = (left, right) != (a, b)
        quality = ("RIGHT_CENSORED_REQUEST" if end is None else
                   "UNRESOLVED_ISSUING_THREAD" if identity is None else
                   "AMBIGUOUS_REQUEST_TOKEN" if state["ambiguous"] else
                   "DECODE_ERROR_BOUNDARIES_ONLY" if state["errors"] or end.get("errors") else
                   "WINDOW_CLIPPED_REQUEST" if clipped else "OBSERVED_REQUEST_PAIR")
        valid = quality == "OBSERVED_REQUEST_PAIR"
        final_status = end["io_observation"]["ntstatus"] if end is not None else None
        if end is not None:
            counts["paired_operations"] += 1
        counts["window_clipped_operations"] += int(clipped)
        request = observation["request_key"]
        identifier = hashlib.sha256(("blackbox.file-operation/1:" + trace + ":" +
            str(first["ordinal"]) + ":" + str(request)).encode("ascii")).hexdigest()
        record = {"operation_id": identifier, "operation": observation["operation"],
            "request_key": request, "file_object_key": observation["file_object_key"],
            "file_name": observation["file_name"], "name_status": observation["name_status"],
            "pid": identity[0] if identity else first["pid"],
            "process_instance": identity[1] if identity else None,
            "tid": identity[2] if identity else first["tid"],
            "thread_instance": identity[3] if identity else None,
            "issuing_thread": observation["event_thread"],
            "completion_thread": end["io_observation"]["event_thread"] if end is not None else None,
            "start_event_name": first["name"], "end_event_name": end["name"] if end is not None else None,
            "start_ms": left, "end_ms": right, "source_start_ms": a, "source_end_ms": b,
            "elapsed_ms": b-a if valid else None, "ntstatus": final_status if valid else None,
            "status_name": status_names.get(final_status, "UNRECOGNIZED_NTSTATUS") if valid else "NOT_ESTABLISHED",
            "observed_completion_ntstatus": final_status,
            "status_attribution": "MATCHED_RECORDED_REQUEST" if valid else "NOT_ESTABLISHED",
            "win32_error": None, "win32_error_basis": "NOT_RECORDED_BY_SELECTED_KERNEL_EVENTS",
            "requested_bytes": observation["requested_bytes"], "transferred_bytes": None,
            "byte_count_scope": "REQUESTED_SIZE_NOT_CONFIRMED_TRANSFERRED_SIZE",
            "offset": observation["offset"], "quality": quality, "window_clipped": clipped,
            "source_event_ids": [first["ordinal"], *([end["ordinal"]] if end is not None else [])],
            "duration_basis": "OBSERVED_FILE_IO_OPERATION_END_NOT_CALLER_BLOCKED_OR_DEVICE_COMPLETION_TIME",
            "root_cause": "UNKNOWN"}
        if len(operations) < max_operations:
            operations.append(record)
            counts["represented_operations"] += 1
        else:
            counts["operations_omitted_budget"] += 1

    check()
    try:
        with closing(sqlite3.connect(path.resolve().as_uri()+"?mode=ro", uri=True, timeout=1)) as db:
            db.execute("PRAGMA query_only=ON"); db.execute("PRAGMA trusted_schema=OFF")
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2*1024**2)
            db.set_progress_handler(lambda: int(time.monotonic() > deadline or
                cancel is not None and cancel.is_set()), 1000)
            if (db.execute("PRAGMA application_id").fetchone()[0] != APP_ID or
                    db.execute("PRAGMA user_version").fetchone()[0] not in (1, 2, 3, 4)):
                raise ValueError("INVALID_INDEX_SCHEMA")
            db.execute("BEGIN")
            summary = json.loads(db.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
            if (type(summary) is not dict or summary.get("status") not in ("DECODED", "TRUNCATED") or
                    not _int(summary.get("rows")) or type(summary.get("input_sha256")) is not str or
                    _KEY.fullmatch(summary["input_sha256"]) is None):
                raise ValueError("INVALID_INDEX_SUMMARY")
            trace = summary["input_sha256"]
            count, lo, hi = db.execute("SELECT count(*),min(id),max(id) FROM events").fetchone()
            if count != summary["rows"] or count and (lo != 1 or hi != count):
                raise ValueError("INDEX_SOURCE_ROW_COUNT_MISMATCH")
            loss = summary.get("decoder_reported_lost_events")
            if loss is not None and not _int(loss):
                raise ValueError("INVALID_INDEX_LOSS")
            trusted = summary["status"] == "DECODED" and loss == 0
            for event_id, stored_pid, stored_time, provider, name, raw in db.execute(
                    "SELECT id,pid,time_ms,provider,name,data FROM events WHERE provider=? AND name LIKE 'FileIO/%' ORDER BY id",
                    (ETW_PROVIDER,)):
                check()
                if name not in file_event_names:
                    continue
                counts["candidate_events"] += 1
                if counts["candidate_events"] > 250_000:
                    raise ValueError("FILE_IO_EVENT_BUDGET")
                row = json.loads(raw)
                validate_event(row, event_id)
                if (row["pid"], row["time_ms"], row["provider"], row["name"]) != (stored_pid, stored_time, provider, name):
                    raise ValueError("INDEX_EVENT_METADATA_MISMATCH")
                if last_time is not None and row["time_ms"] < last_time:
                    counts["out_of_order_events"] += 1
                    pending.clear()
                    pending_bytes = 0
                last_time = row["time_ms"]
                observation = row.get("io_observation")
                if observation is None or observation.get("kind") != "file":
                    counts["missing_typed_classification"] += 1
                    for state in pending.values():
                        state["ambiguous"] = True
                    continue
                counts["typed_events"] += 1
                counts["events_with_decode_errors"] += bool(row.get("errors"))
                key = observation["request_key"]
                if key is None:
                    counts["missing_request_keys"] += 1
                    for state in pending.values():
                        state["ambiguous"] = True
                    continue
                if observation["phase"] == "start":
                    identity = _identity(observation["event_thread"], row["time_ms"])
                    counts["unresolved_issuing_threads"] += identity is None
                    duplicate = key in pending
                    if duplicate:
                        counts["duplicate_request_starts"] += 1
                    if len(pending) >= 65_536 and not duplicate:
                        raise ValueError("FILE_IO_PENDING_REQUEST_BUDGET")
                    boundary = _compact_io_boundary(row)
                    retained_bytes = _pending_metadata_size(boundary)
                    pending_bytes += retained_bytes - (pending[key]["retained_bytes"] if duplicate else 0)
                    if pending_bytes > MAX_IO_PENDING_METADATA_BYTES:
                        raise ValueError("FILE_IO_PENDING_METADATA_BYTE_BUDGET")
                    pending_peak = max(pending_peak, pending_bytes)
                    pending[key] = {"row": boundary, "observation": observation, "identity": identity,
                        "ambiguous": duplicate, "errors": bool(row.get("errors")), "retained_bytes": retained_bytes}
                else:
                    state = pending.pop(key, None)
                    if state is None:
                        counts["unmatched_completions"] += 1
                    else:
                        pending_bytes -= state["retained_bytes"]
                        emit(state, row)
            check()
            counts["right_censored_requests"] = len(pending)
            for state in pending.values():
                check(); emit(state)
    except sqlite3.OperationalError:
        check()
        raise
    source_unreliable = (not trusted or counts["out_of_order_events"] or
        counts["missing_typed_classification"] or counts["duplicate_request_starts"] or counts["missing_request_keys"])
    if source_unreliable:
        for operation in operations:
            operation.update(elapsed_ms=None, ntstatus=None, status_name="NOT_ESTABLISHED",
                status_attribution="NOT_ESTABLISHED", quality="LOSS_ORDER_OR_REQUEST_BOUNDARIES_ONLY")
    partial = bool(source_unreliable or counts["unresolved_issuing_threads"] or
        counts["events_with_decode_errors"] or counts["operations_omitted_budget"] or
        counts["right_censored_requests"] or counts["unmatched_completions"] or counts["window_clipped_operations"])
    status = ("NO_FILE_IO_EVENTS" if not counts["candidate_events"] else
              "REDECODE_REQUIRED" if not counts["typed_events"] else
              "PARTIAL_EVIDENCE" if partial else "OBSERVED_OPERATIONS")
    check()
    return {"schema": "blackbox.file-operations/1", "status": status,
        "source_trace_sha256": trace, "operations": operations,
        "coverage": {**counts, "decode_status": summary["status"], "decoder_reported_lost_events": loss,
            "pending_metadata_peak_bytes": pending_peak,
            "pending_metadata_byte_budget": MAX_IO_PENDING_METADATA_BYTES,
            "pending_byte_measurement": "ENCODED_COMPACT_BOUNDARY_METADATA_NOT_PROCESS_RSS"},
        "filters": {"pid": pid, "process_instance": process_instance, "tid": tid,
                    "start_ms": start_ms, "end_ms": end_ms},
        "verification_class": "UNVERIFIED_IMPORT", "capture_complete": None,
        "trace_to_session_alignment": "NOT_ESTABLISHED", "root_cause": "UNKNOWN",
        "limitations": ["IMPORTED_KERNEL_METADATA_NOT_PRODUCER_AUTHENTICATION",
            "REQUEST_TOKEN_REUSE_REQUIRES_UNIQUE_OBSERVED_BOUNDARIES",
            "COMPLETION_THREAD_IS_NOT_NECESSARILY_THE_ISSUING_THREAD",
            "REQUEST_DURATION_IS_NOT_CALLER_BLOCKED_TIME_OR_DEVICE_SERVICE_TIME",
            "NTSTATUS_IS_NOT_AN_OBSERVED_WIN32_LAST_ERROR",
            "ZERO_REPORTED_LOSS_DOES_NOT_PROVE_COMPLETE_CAPTURE",
            "FILE_OBJECT_IS_NOT_A_LOCK_OWNER_OR_CAUSE"]}


def build_disk_io_report(index_path, *, pid=0, process_instance=None, tid=None,
                         start_ms=None, end_ms=None, max_requests=10_000, cancel=None):
    """Observed DiskIO Init/complete spans and lower-bound request concurrency.

    A matched request has two real boundaries. Its overlap count is explicitly
    the number of matched, filtered requests, not hardware queue depth; no
    dispatch-to-device boundary exists here to split queue from service time.
    Legacy completion-only records retain their original separate semantics.
    """
    from contextlib import closing
    import heapq
    import json
    import sqlite3
    import time
    from .decoder_cpu import ETW_PROVIDER
    from .decoder_index import APP_ID, validate_event
    from .decoder_waits import _identity
    from .session_v2 import safe_path

    def finite(value):
        return type(value) in (int, float) and math.isfinite(value) and abs(value) < 1e15

    if (not _int(pid, 0, 2**32-1) or process_instance is not None and not _int(process_instance) or
            tid is not None and not _int(tid, 1, 2**32-1) or
            start_ms is not None and not finite(start_ms) or end_ms is not None and not finite(end_ms) or
            start_ms is not None and end_ms is not None and start_ms >= end_ms or not _int(max_requests, 1, 20_000)):
        raise ValueError("INVALID_DISK_IO_FILTER")
    path = safe_path(index_path)
    if not path.is_file():
        raise ValueError("INVALID_INDEX_FILE")
    deadline = time.monotonic() + 30

    def check():
        if cancel is not None and cancel.is_set():
            raise InterruptedError("DISK_IO_ANALYSIS_CANCELLED")
        if time.monotonic() > deadline:
            raise TimeoutError("DISK_IO_ANALYSIS_DEADLINE")

    counts = dict.fromkeys(("candidate_events", "typed_request_events", "completion_events",
        "legacy_completion_only_events", "missing_typed_classification", "missing_request_keys",
        "unresolved_issuing_threads", "duplicate_request_starts", "unmatched_completions",
        "right_censored_requests", "out_of_order_events", "events_with_decode_errors",
        "operation_mismatches", "paired_requests", "requests_omitted_budget", "window_clipped_requests"), 0)
    pending, requests, last_time = {}, [], None
    pending_bytes = pending_peak = 0
    check()
    try:
        with closing(sqlite3.connect(path.resolve().as_uri()+"?mode=ro", uri=True, timeout=1)) as db:
            db.execute("PRAGMA query_only=ON"); db.execute("PRAGMA trusted_schema=OFF")
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2*1024**2)
            db.set_progress_handler(lambda: int(time.monotonic() > deadline or
                cancel is not None and cancel.is_set()), 1000)
            if (db.execute("PRAGMA application_id").fetchone()[0] != APP_ID or
                    db.execute("PRAGMA user_version").fetchone()[0] not in (1, 2, 3, 4)):
                raise ValueError("INVALID_INDEX_SCHEMA")
            db.execute("BEGIN")
            summary = json.loads(db.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
            if (type(summary) is not dict or summary.get("status") not in ("DECODED", "TRUNCATED") or
                    not _int(summary.get("rows")) or type(summary.get("input_sha256")) is not str or
                    _KEY.fullmatch(summary["input_sha256"]) is None):
                raise ValueError("INVALID_INDEX_SUMMARY")
            trace = summary["input_sha256"]
            count, lo, hi = db.execute("SELECT count(*),min(id),max(id) FROM events").fetchone()
            if count != summary["rows"] or count and (lo != 1 or hi != count):
                raise ValueError("INDEX_SOURCE_ROW_COUNT_MISMATCH")
            loss = summary.get("decoder_reported_lost_events")
            if loss is not None and not _int(loss):
                raise ValueError("INVALID_INDEX_LOSS")
            trusted = summary["status"] == "DECODED" and loss == 0
            names = ("DiskIO/ReadInit", "DiskIO/WriteInit", "DiskIO/Read", "DiskIO/Write")
            for event_id, stored_pid, stored_time, provider, name, raw in db.execute(
                    "SELECT id,pid,time_ms,provider,name,data FROM events WHERE provider=? AND name IN (?,?,?,?) ORDER BY id",
                    (ETW_PROVIDER, *names)):
                check(); counts["candidate_events"] += 1
                if counts["candidate_events"] > 250_000:
                    raise ValueError("DISK_IO_EVENT_BUDGET")
                row = json.loads(raw)
                validate_event(row, event_id)
                if (row["pid"], row["time_ms"], row["provider"], row["name"]) != (stored_pid, stored_time, provider, name):
                    raise ValueError("INDEX_EVENT_METADATA_MISMATCH")
                validate_io_clock(row, summary.get("engine"))
                now = row["time_ms"]
                if last_time is not None and now < last_time:
                    counts["out_of_order_events"] += 1
                    pending.clear()
                    pending_bytes = 0
                last_time = now
                value = row.get("io_observation")
                if value is None or value.get("kind") not in ("disk", "disk_request"):
                    counts["missing_typed_classification"] += 1
                    continue
                counts["events_with_decode_errors"] += bool(row.get("errors"))
                key = value.get("request_key")
                if value["kind"] == "disk" and "request_key" not in value:
                    counts["legacy_completion_only_events"] += 1
                    continue
                if key is None:
                    counts["missing_request_keys"] += 1
                    continue
                if value["kind"] == "disk_request":
                    counts["typed_request_events"] += 1
                    duplicate = key in pending
                    counts["duplicate_request_starts"] += duplicate
                    if len(pending) >= 65_536 and not duplicate:
                        raise ValueError("DISK_IO_PENDING_REQUEST_BUDGET")
                    boundary = _compact_io_boundary(row)
                    retained_bytes = _pending_metadata_size(boundary)
                    pending_bytes += retained_bytes - (pending[key][2] if duplicate else 0)
                    if pending_bytes > MAX_IO_PENDING_METADATA_BYTES:
                        raise ValueError("DISK_IO_PENDING_METADATA_BYTE_BUDGET")
                    pending_peak = max(pending_peak, pending_bytes)
                    pending[key] = (boundary, duplicate, retained_bytes)
                    continue
                counts["completion_events"] += 1
                state = pending.pop(key, None)
                if state is None:
                    counts["unmatched_completions"] += 1
                    continue
                first, duplicate, retained_bytes = state
                pending_bytes -= retained_bytes
                initial = first["io_observation"]
                if value["operation"] != initial["operation"]:
                    counts["operation_mismatches"] += 1
                    continue
                identity = _identity(initial["event_thread"], first["time_ms"])
                counts["unresolved_issuing_threads"] += identity is None
                if (identity is None or pid and identity[0] != pid or
                        process_instance is not None and identity[1] != process_instance or
                        tid is not None and identity[2] != tid):
                    continue
                a, b = first["time_ms"], now
                if b < a or start_ms is not None and b < start_ms or end_ms is not None and a > end_ms:
                    continue
                left = max(a, start_ms) if start_ms is not None else a
                right = min(b, end_ms) if end_ms is not None else b
                clipped = (left, right) != (a, b)
                valid = not duplicate and not first.get("errors") and not row.get("errors") and not clipped
                counts["paired_requests"] += 1
                counts["window_clipped_requests"] += clipped
                record = {"request_id": hashlib.sha256(("blackbox.disk-request/1:" + trace + ":" +
                        str(first["ordinal"]) + ":" + key).encode("ascii")).hexdigest(),
                    "request_key": key, "operation": value["operation"],
                    "pid": identity[0], "process_instance": identity[1], "tid": identity[2], "thread_instance": identity[3],
                    "issuing_thread": initial["event_thread"], "completion_thread": value["event_thread"],
                    "start_event_name": first["name"], "end_event_name": row["name"],
                    "disk_number": value["disk_number"], "start_ms": left, "end_ms": right,
                    "source_start_ms": a, "source_end_ms": b,
                    "elapsed_ms": b-a if valid else None, "reported_response_ms": value["elapsed_ms"],
                    "transferred_bytes": value["transferred_bytes"],
                    "observed_outstanding_requests_at_start_lower_bound": None,
                    "queue_delay_ms": None, "device_service_ms": None,
                    "quality": "OBSERVED_REQUEST_PAIR" if valid else "INCOMPLETE_REQUEST_BOUNDARIES",
                    "source_event_ids": [first["ordinal"], row["ordinal"]],
                    "request_duration_basis": "OBSERVED_INIT_TO_COMPLETE_NOT_DEVICE_SERVICE_OR_QUEUE_SPLIT",
                    "outstanding_count_scope": "MATCHED_FILTERED_REQUESTS_NOT_HARDWARE_QUEUE_DEPTH"}
                if len(requests) < max_requests:
                    requests.append(record)
                else:
                    counts["requests_omitted_budget"] += 1
            check()
            counts["right_censored_requests"] = len(pending)
    except sqlite3.OperationalError:
        check()
        raise
    unreliable = bool(not trusted or counts["out_of_order_events"] or counts["duplicate_request_starts"] or
        counts["missing_typed_classification"] or counts["missing_request_keys"] or counts["operation_mismatches"])
    if unreliable:
        for row in requests:
            check()
            row.update(elapsed_ms=None, quality="LOSS_ORDER_OR_REQUEST_BOUNDARIES_ONLY")
    else:
        groups = {}
        for row in requests:
            if row["quality"] == "OBSERVED_REQUEST_PAIR" and row["disk_number"] >= 0:
                groups.setdefault(row["disk_number"], []).append(row)
        for rows in groups.values():
            active = []
            for row in sorted(rows, key=lambda item: (item["start_ms"], item["request_id"])):
                check()
                while active and active[0] <= row["start_ms"]:
                    heapq.heappop(active)
                row["observed_outstanding_requests_at_start_lower_bound"] = len(active)
                heapq.heappush(active, row["end_ms"])
    partial = bool(unreliable or counts["unmatched_completions"] or counts["right_censored_requests"] or
        counts["unresolved_issuing_threads"] or counts["requests_omitted_budget"] or counts["events_with_decode_errors"] or
        counts["legacy_completion_only_events"] or counts["window_clipped_requests"])
    check()
    return {"schema": "blackbox.disk-requests/1", "status": "NO_DISK_REQUEST_EVENTS" if not counts["candidate_events"] else
        "PARTIAL_EVIDENCE" if partial else "OBSERVED_REQUESTS", "requests": requests,
        "source_trace_sha256": trace, "coverage": {**counts, "represented_requests": len(requests),
            "decoder_reported_lost_events": loss, "decode_status": summary["status"],
            "pending_metadata_peak_bytes": pending_peak,
            "pending_metadata_byte_budget": MAX_IO_PENDING_METADATA_BYTES,
            "pending_byte_measurement": "ENCODED_COMPACT_BOUNDARY_METADATA_NOT_PROCESS_RSS"},
        "verification_class": "UNVERIFIED_IMPORT", "capture_complete": None, "root_cause": "UNKNOWN",
        "limitations": ["OBSERVED_REQUEST_CONCURRENCY_IS_NOT_HARDWARE_QUEUE_DEPTH",
            "NO_DEVICE_DISPATCH_BOUNDARY_TO_SPLIT_QUEUE_AND_SERVICE_TIME",
            "COMPLETION_THREAD_NOT_ASSUMED_ISSUER", "ZERO_REPORTED_LOSS_NOT_CAPTURE_ATTESTATION",
            "DURATION_NOT_PROOF_OF_APPLICATION_DELAY_OR_ROOT_CAUSE"]}
