"""Bounded source adapters for Investigation Engine 3.

Sources are read-only, hash-bound, structurally checked observations. Importing
them never authenticates a producer, establishes a live PID binding, or grants
authority to execute a diagnostic command. Nonempty SQLite WALs are refused:
hashing the main file alone would otherwise misidentify the visible snapshot.
"""
from __future__ import annotations

from contextlib import contextmanager, closing
from bisect import bisect_left
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
from uuid import UUID

from .investigation_graph_contracts import (
    ALGORITHM_VERSION, InvestigationError, canonical_json, evidence_node,
    finite_number, stable_id, use_budget, SOURCE_TYPES,
)
from .session_v2 import safe_path

MAX_RECORD_BYTES = 512 * 1024
MAX_JSON_BYTES = 32 * 1024**2
MAX_METADATA_BYTES = 16 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_FILE_MARKER = re.compile(r"(?:^|[._/])(?:io[._/]operation|fileio)(?:$|[._/])")
_NETWORK_MARKER = re.compile(r"(?:^|[._/])(?:network|tcpip|udpip|tcp|udp)(?:$|[._/])")
_SOURCE_RECEIPT_ORIGIN = object()
_PRIVATE_KEYS = {"token", "nonce", "password", "secret", "environment", "environ", "cmdline",
    "command_line", "commandline", "bytes", "hex", "value_hex", "expected_hex", "original_hex",
    "replacement_hex", "before_hex", "after_hex", "content", "contents", "buffer", "memory_bytes",
    "data_hex", "file_handle", "handle", "raw", "data_base64", "registry_value", "value_data",
    "original_bytes", "expected_bytes", "replacement_bytes", "new_bytes", "old_bytes",
    "passwords", "authorization", "api_key", "private_key", "credentials", "credential",
    "connection_string", "environment_variables", "memory", "memory_contents"}
_PATH_KEYS = {"path", "image_path", "file", "filename", "file_name", "mapped_file_path", "source_file",
              "destination", "output_path", "pdb_path", "binary_path"}


def _int(value, low=0, high=2**63 - 1):
    return type(value) is int and low <= value <= high


def _require(condition, reason):
    if not condition:
        raise InvestigationError(reason)


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result, "DUPLICATE_SOURCE_JSON_KEY")
        result[key] = value
    return result


def _json(raw, *, maximum=MAX_RECORD_BYTES):
    _require(isinstance(raw, (str, bytes)) and len(raw) <= maximum, "SOURCE_JSON_RECORD_BUDGET")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(InvestigationError("NONFINITE_SOURCE_JSON")))
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InvestigationError("INVALID_SOURCE_JSON") from error
    _shape(value)
    return value


def _shape(value, depth=0):
    _require(depth <= 12, "SOURCE_JSON_DEPTH_BUDGET")
    if isinstance(value, dict):
        _require(len(value) <= 512, "SOURCE_JSON_FIELDS_BUDGET")
        for key, item in value.items():
            _require(type(key) is str and len(key) <= 256, "SOURCE_JSON_KEY_BUDGET")
            _shape(item, depth + 1)
    elif isinstance(value, list):
        _require(len(value) <= 20_000, "SOURCE_JSON_ARRAY_BUDGET")
        for item in value:
            _shape(item, depth + 1)
    elif isinstance(value, str):
        _require(len(value) <= 256 * 1024, "SOURCE_JSON_STRING_BUDGET")
    elif type(value) is float:
        _require(math.isfinite(value), "NONFINITE_SOURCE_NUMBER")
    elif value is not None and type(value) not in (int, bool):
        raise InvestigationError("UNSUPPORTED_SOURCE_VALUE")


def _metadata(value, *, depth=0):
    """A bounded display projection; raw byte/credential fields never survive."""
    if depth >= 7:
        return {"omitted": "METADATA_DEPTH_BUDGET"}
    if isinstance(value, dict):
        output = {}
        for key, item in list(value.items())[:96]:
            key = str(key)[:128]
            lower = key.lower()
            if lower in _PRIVATE_KEYS or lower.endswith(("_hex", "_bytes_raw", "_password", "_token", "_secret")):
                output[key] = {"omitted": "PRIVATE_SOURCE_FIELD"}
            elif lower in _PATH_KEYS and isinstance(item, str):
                output[key] = item.replace("\\", "/").rsplit("/", 1)[-1][:512]
            else:
                output[key] = _metadata(item, depth=depth + 1)
        if len(value) > 96:
            output["omitted_fields"] = len(value) - 96
        return output
    if isinstance(value, list):
        result = [_metadata(item, depth=depth + 1) for item in value[:128]]
        if len(value) > 128:
            result.append({"omitted_rows": len(value) - 128})
        return result
    if isinstance(value, str):
        return value[:2048]
    if value is None or type(value) in (int, bool):
        return value
    if type(value) is float:
        _require(math.isfinite(value), "NONFINITE_SOURCE_NUMBER")
        return value
    return {"omitted": "UNSUPPORTED_METADATA_VALUE"}


def _stamp(path):
    info = path.stat()
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _check_wal(path):
    for suffix in ("-wal", "-journal"):
        sibling = Path(str(path) + suffix)
        _require(not sibling.is_symlink(), "SOURCE_SIDECAR_SYMLINK")
        if sibling.exists() and sibling.stat().st_size:
            raise InvestigationError("SOURCE_WAL_ACTIVE" if suffix == "-wal" else "SOURCE_JOURNAL_ACTIVE")


def _hash_file(path, budget):
    digest = hashlib.sha256()
    amount = 0
    with path.open("rb") as stream:
        while True:
            budget.check()
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            amount += len(chunk)
            _require(amount <= budget.max_source_bytes, "INVESTIGATION_SOURCE_BYTE_BUDGET")
            digest.update(chunk)
    return digest.hexdigest()


class _StableSource:
    def __init__(self, paths, budget, *, absent_paths=()):
        self._origin = _SOURCE_RECEIPT_ORIGIN
        self.paths = [safe_path(Path(path)) for path in paths]
        self.budget = budget
        self.absent_paths = [safe_path(Path(path)) for path in absent_paths]
        self.stamps = {}
        self.hashes = {}
        self._verify_absent()
        for path in self.paths:
            budget.check()
            _require(path.is_file() and 0 < path.stat().st_size <= budget.max_source_bytes,
                     "INVESTIGATION_SOURCE_FILE_BUDGET")
            _check_wal(path)
            self.stamps[path] = _stamp(path)
            self.hashes[path] = _hash_file(path, budget)
            _check_wal(path)
            _require(_stamp(path) == self.stamps[path], "SOURCE_CHANGED")
        self._verify_absent()

    def _verify_absent(self):
        for path in self.absent_paths:
            self.budget.check()
            try:
                safe_path(path)
            except ValueError as error:
                raise InvestigationError("SOURCE_CHANGED") from error
            _require(not path.exists(), "SOURCE_CHANGED")

    def verify(self):
        try:
            self._verify_absent()
            for path in self.paths:
                self.budget.check()
                try:
                    safe_path(path)
                except ValueError as error:
                    raise InvestigationError("SOURCE_CHANGED") from error
                _check_wal(path)
                _require(_stamp(path) == self.stamps[path], "SOURCE_CHANGED")
                digest = _hash_file(path, self.budget)
                _check_wal(path)
                _require(_stamp(path) == self.stamps[path] and digest == self.hashes[path], "SOURCE_CHANGED")
            self._verify_absent()
        except OSError as error:
            raise InvestigationError("SOURCE_CHANGED") from error


@contextmanager
def _readonly(path, budget, required):
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=.5)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA cache_size=-4096")
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2 * 1024**2)
        db.set_progress_handler(lambda: _sql_cancel(budget), 1000)
        db.execute("BEGIN")
        _tables(db, required)
        yield db
        budget.check()


def _sql_cancel(budget):
    try:
        budget.check()
    except (InterruptedError, TimeoutError):
        return 1
    return 0


def _tables(db, names):
    names = set(names)
    if not names:
        return
    rows = db.execute("SELECT name,type,sql FROM sqlite_schema WHERE name IN (" +
                      ",".join("?" for _ in names) + ")", tuple(names)).fetchall()
    _require({r["name"] for r in rows} == names and all(r["type"] == "table" and
        isinstance(r["sql"], str) and not r["sql"].lstrip().upper().startswith("CREATE VIRTUAL") for r in rows),
        "INVALID_INVESTIGATION_SOURCE_TABLES")


def _bounds(start, end=None, unit="ns", uncertainty=None):
    if start is None:
        return None
    end = start if end is None else end
    _require(finite_number(start) and finite_number(end) and end >= start,
             "INVALID_INVESTIGATION_SOURCE_TIME")
    if unit == "ns":
        _require(_int(start) and _int(end), "INVALID_INVESTIGATION_NANOSECOND_TIME")
    return {"start": start, "end": end, "unit": unit, "uncertainty": uncertainty}


def _live_process(value):
    if not isinstance(value, dict):
        return None
    pid, created = value.get("pid"), value.get("created_100ns")
    if _int(pid, 1, 2**32 - 1) and _int(created, 1, 2**64 - 1):
        return {"kind": "LIVE_PROCESS", "pid": pid, "created_100ns": created}
    return None


def _trace_process(trace, row):
    instance = row.get("process_instance")
    if _int(instance) and _int(row.get("pid"), 1, 2**32 - 1):
        return {"kind": "TRACE_PROCESS", "trace_sha256": trace, "process_instance": instance, "pid": row["pid"]}
    return None


def _trace_thread(trace, row):
    process = _trace_process(trace, row)
    if process is None:
        return None
    schedule = row.get("thread_schedule")
    candidate = None
    if isinstance(schedule, dict):
        candidate = schedule.get("new_thread" if schedule.get("kind") == "switch" else "waker_thread")
    sample = row.get("cpu_sample")
    if isinstance(sample, dict) and isinstance(sample.get("thread"), dict):
        candidate = sample["thread"]
    if isinstance(candidate, dict) and _int(candidate.get("thread_instance")):
        return {**process, "kind": "TRACE_THREAD", "thread_instance": candidate["thread_instance"],
                "tid": row["tid"]}
    if _int(row.get("tid"), 1):
        return {"kind": "UNRESOLVED_THREAD", "trace_sha256": trace,
                "process_instance": row["process_instance"], "pid": row["pid"], "tid": row["tid"], "exact": False}
    return None


def _trace_entities(source, row, trace, domain, out):
    identities = []
    schedule = row.get("thread_schedule")
    if isinstance(schedule, dict):
        identities = [x for x in schedule.values() if isinstance(x, dict) and
                      x.get("attribution") == "TRACELOG_THREAD_LIFETIME"]
    process = _trace_process(trace, row)
    if process:
        identities.append({**process, "tid": row["tid"]})
    for identity in identities[:4]:
        process = _trace_process(trace, identity)
        if process is None:
            continue
        process_record = "trace-process:" + str(process["process_instance"])
        out.add(source, process_record, "PROCESS", process_identity=process, time_domain=domain,
            metadata={"pid": process["pid"], "process_instance": process["process_instance"],
                      "identity_basis": "TRACE_LOCAL_PROCESS_INDEX_NOT_LIVE_FILETIME"})
        if _int(identity.get("thread_instance")) and _int(identity.get("tid"), 1):
            thread = {**process, "kind": "TRACE_THREAD", "thread_instance": identity["thread_instance"],
                      "tid": identity["tid"]}
            out.add(source, process_record + ":thread:" + str(identity["thread_instance"]), "THREAD",
                process_identity=process, thread_identity=thread, time_domain=domain,
                metadata={"pid": process["pid"], "tid": identity["tid"],
                          "record_refs": [process_record], "record_ref_relation": "TRACE_THREAD_PROCESS"})


def _trace_frames(source, row, stack_record, process, thread, domain, bounds, out):
    from .decoder_modules import module_key, validate_module_frame
    refs = []
    for frame in row["frames"][:8]:
        out.budget.check()
        module = validate_module_frame(row, frame)
        if module is None:
            continue
        module_record = "modules:" + module_key(row["pid"], module)
        out.add(source, module_record, "MODULE", process_identity=process,
            time_domain=domain, metadata={**module, "module_identity": {
                "pdb_guid": module["pdb_guid"], "pdb_age": module["pdb_age"],
                "image_timestamp": module["image_timestamp"], "image_size": module["image_size"]}})
        function_record = module_record + ":rva:" + str(frame["rva"])
        out.add(source, function_record, "FUNCTION", process_identity=process, time_domain=domain,
            metadata={"name": frame["name"], "rva": frame["rva"], "module_identity": module,
                      "record_refs": [module_record], "record_ref_relation": "FUNCTION_MODULE",
                      "symbol_status": frame.get("symbol_status", "RECORDED_FRAME_NAME_NOT_AUTHENTICATED")})
        refs.append(function_record)
    stack = next((node for node in reversed(out.nodes) if node["source_record_id"] == stack_record and
                  node["source_identity"] == source["source_id"]), None)
    if stack is not None:
        stack["metadata"]["record_refs"].extend(refs)
        stack["metadata"]["frames_without_function_node"] = max(0, len(row["frames"]) - len(refs))


class _Output:
    def __init__(self, budget):
        self.budget = budget
        self.sources, self.nodes, self.clock_relations = [], [], []
        self.seen = set()
        self.coverage = {"events_examined": 0, "events_omitted": 0, "nodes_omitted": 0,
                         "has_more": False, "next_cursor": [], "source_coverage": []}
        self.limitations = {"SOURCE_FILE_NOT_AUTHENTICATED", "NO_AUTOMATIC_LIVE_TRACE_BINDING",
                            "UNKNOWN_SOURCE_DATA_NOT_RECONSTRUCTED"}
        self.source_paths = {}
        self.clock_candidates = []
        self.receipts = []

    def scan(self):
        self.budget.check()
        if self.coverage["events_examined"] >= self.budget.max_events:
            self.coverage["has_more"] = True
            return False
        self.coverage["events_examined"] += 1
        return True

    def add(self, source, record, kind, **fields):
        self.budget.check()
        metadata = _metadata(fields.pop("metadata", {}))
        if len(canonical_json(metadata)) > MAX_METADATA_BYTES:
            metadata = {"omitted": "METADATA_BYTE_BUDGET", "keys": list(metadata)[:64]}
            fields["completeness_status"] = "INCOMPLETE_EVIDENCE"
        node = evidence_node(source, record, kind, metadata=metadata, **fields)
        if node["node_id"] in self.seen:
            return node["node_id"]
        if len(self.nodes) >= self.budget.max_nodes:
            self.coverage["nodes_omitted"] += 1
            self.coverage["has_more"] = True
            return None
        self.nodes.append(node)
        self.seen.add(node["node_id"])
        return node["node_id"]


def _selection(spec, shared):
    _require(type(spec.get("selection", {})) is dict, "INVALID_INVESTIGATION_SELECTION")
    value = {**(shared or {}), **spec.get("selection", {})}
    for key in ("pid", "tid", "process_instance", "instance_id", "start_ns", "end_ns", "start_ms", "end_ms", "after"):
        if key in spec:
            value[key] = spec[key]
    _require(isinstance(value, dict) and len(value) <= 20, "INVALID_INVESTIGATION_SELECTION")
    allowed = {"pid", "tid", "process_instance", "instance_id", "start_ns", "end_ns", "start_ms", "end_ms", "after", "incident_id"}
    _require(not set(value) - allowed, "UNSUPPORTED_INVESTIGATION_SELECTION_FIELD")
    for key in ("pid", "tid", "process_instance", "instance_id", "start_ns", "end_ns", "after", "incident_id"):
        if value.get(key) is not None:
            _require(_int(value[key]), "INVALID_INVESTIGATION_FILTER_" + key.upper())
    for key in ("start_ms", "end_ms"):
        if value.get(key) is not None:
            _require(finite_number(value[key]), "INVALID_INVESTIGATION_FILTER_" + key.upper())
    for first, last in (("start_ns", "end_ns"), ("start_ms", "end_ms")):
        _require(value.get(first) is None or value.get(last) is None or value[first] <= value[last],
                 "INVALID_INVESTIGATION_TIME_WINDOW")
    return value


def _source(kind, stable, *, selection, extra=None, hash_roles=None):
    hashes = sorted(stable.hashes.values())
    manifest = sorted(zip(hash_roles or (str(index) for index in range(len(stable.paths))),
                          (stable.hashes[path] for path in stable.paths)))
    digest = hashes[0] if len(hashes) == 1 else hashlib.sha256(canonical_json(manifest).encode("ascii")).hexdigest()
    return {"source_id": stable_id("source", kind, digest), "source_type": kind,
            "source_sha256": digest, "source_file_count": len(hashes),
            "verification_class": "UNVERIFIED_IMPORT", "selection": selection,
            "content_hashes": hashes, "content_manifest": [{"role": role, "sha256": value} for role, value in manifest],
            "source_consistency": "STABLE_HASHED_NO_ACTIVE_WAL",
            **(extra or {})}


def _register_source(source, stable, path, out):
    """Aliases retain path receipts without rescanning identical observations."""
    old = next((item for item in out.sources if item["source_id"] == source["source_id"]), None)
    if old is not None:
        _require(old["selection"] == source["selection"], "DUPLICATE_SOURCE_SELECTION_AMBIGUOUS")
        stable.verify()
        out.receipts.append(stable)
        return False
    out.sources.append(source)
    out.source_paths[source["source_id"]] = str(path)
    return True


def _trace(spec, selection, out):
    from .decoder_index import APP_ID, _saved_json, read_index, validate_event
    from .decoder_io import validate_io_clock
    from .decoder_waits import build_wait_report
    from .decoder_cpu import classify_cpu_sample
    path = safe_path(Path(spec["path"]))
    extra_paths = []
    extra_roles = []
    for key in ("session_path", "clock_journal"):
        if spec.get(key):
            extra = safe_path(Path(spec[key]))
            if extra.is_dir():
                extra = extra / "session-v2.sqlite3"
            extra_paths.append(extra)
            extra_roles.append(key)
    stable = _StableSource([path, *extra_paths], out.budget)
    page = read_index(path, limit=1)
    summary = page["summary"]
    _require(isinstance(summary, dict) and type(summary.get("input_sha256")) is str and
             _HASH.fullmatch(summary["input_sha256"]) is not None and _int(summary.get("rows")) and
             summary.get("status") in ("DECODED", "TRUNCATED") and
             (summary.get("decoder_reported_lost_events") is None or _int(summary["decoder_reported_lost_events"])),
             "INVALID_INVESTIGATION_TRACE_SUMMARY")
    trace = summary["input_sha256"]
    source = _source("TRACE_INDEX", stable, selection=selection, hash_roles=["trace_index", *extra_roles],
        extra={"trace_sha256": trace, "trace_input_sha256": trace, "index_sha256": stable.hashes[path],
        "decoded_status": summary.get("status"), "decoder_reported_lost_events": summary.get("decoder_reported_lost_events"),
        "scheduler_complete": False, "time_domain": "TRACE_RELATIVE:" + trace})
    if not _register_source(source, stable, path, out):
        return
    domain = source["time_domain"]
    alignment = None
    if spec.get("session_path") and spec.get("clock_journal"):
        from .decoder_alignment import assess_session_alignment
        alignment = assess_session_alignment(path, spec["clock_journal"], spec["session_path"], cancel=out.budget)
        source["clock_alignment"] = _metadata(alignment)
    count = selected = schedule_nodes = schedule_omitted = 0
    previous_time = None
    out_of_order = errors = False
    after = selection.get("after", 0)
    last_identifier = after
    sequence_gaps = 0
    with _readonly(path, out.budget, {"metadata", "events"}) as db:
        _require(db.execute("PRAGMA application_id").fetchone()[0] == APP_ID, "INVALID_INDEX_SCHEMA")
        total = db.execute("SELECT count(*) FROM events WHERE id>?", (after,)).fetchone()[0]
        _require(db.execute("SELECT count(*) FROM events").fetchone()[0] == summary["rows"], "INDEX_SOURCE_ROW_COUNT_MISMATCH")
        for raw in db.execute("SELECT id,data,pid,time_ms,provider,name,has_stack FROM events WHERE id>? ORDER BY id", (after,)):
            if not out.scan():
                out.coverage["events_omitted"] += max(0, total - count)
                break
            count += 1
            sequence_gaps += raw["id"] != last_identifier + 1
            last_identifier = raw["id"]
            row = _saved_json(raw["data"])
            validate_event(row, raw["id"])
            validate_io_clock(row, summary.get("engine"))
            _require((row["pid"], row["time_ms"], row["provider"], row["name"], int(bool(row["frames"]))) ==
                     (raw["pid"], raw["time_ms"], raw["provider"], raw["name"], raw["has_stack"]),
                     "INDEX_EVENT_METADATA_MISMATCH")
            if previous_time is not None and row["time_ms"] < previous_time:
                out_of_order = True
            previous_time = row["time_ms"]
            errors |= bool(row.get("errors"))
            schedule = row.get("thread_schedule")
            # Scheduler headers can belong to another process. Keep them when
            # any typed participant names the selected process/thread.
            identities = [value for value in (schedule or {}).values() if isinstance(value, dict)]
            relevant_identity = any((not selection.get("pid") or item.get("pid") == selection["pid"]) and
                (not selection.get("tid") or item.get("tid") == selection["tid"]) and
                (selection.get("process_instance") is None or item.get("process_instance") == selection["process_instance"])
                for item in [row, *identities])
            if (not relevant_identity or
                    selection.get("start_ms") is not None and row["time_ms"] < selection["start_ms"] or
                    selection.get("end_ms") is not None and row["time_ms"] > selection["end_ms"]):
                continue
            selected += 1
            process, thread = _trace_process(trace, row), _trace_thread(trace, row)
            bounds = _bounds(row["time_ms"], unit="ms")
            record = "events:" + str(row["ordinal"])
            data = {"event_name": row["name"], "event_kind": row["name"], "provider": row["provider"],
                "provider_guid": row.get("provider_guid"), "source_event_id": row["ordinal"],
                "process_instance": row.get("process_instance"), "pid": row["pid"], "tid": row["tid"],
                "event_id": row.get("event_id"), "opcode": row.get("opcode"), "version": row.get("version"),
                "fields": row.get("payload", {}), "errors": row.get("errors", [])}
            typed = row.get("io_observation")
            cpu_source = "etw"
            cpu_class = classify_cpu_sample(row, cpu_source)
            if cpu_class == "OTHER_SOURCE":
                cpu_source = "dotnet"
                cpu_class = classify_cpu_sample(row, cpu_source)
            kind = "SCHEDULER_EVENT" if schedule is not None else "CPU_SAMPLE" if cpu_class == "PROCESS_SAMPLE" else \
                   "NETWORK_OPERATION" if typed and typed.get("kind") == "network" else \
                   "DISK_COMPLETION" if typed and typed.get("kind") == "disk" else \
                   "FILE_OPERATION" if row["name"].startswith(("FileIO/", "FileIo/")) else \
                   "ERROR" if row.get("errors") else "ANNOTATION"
            if schedule is not None:
                data["thread_schedule"] = schedule
                data["capture_complete"] = False
                schedule_nodes += 1
            if typed is not None:
                data["io_observation"] = typed
                data["operation"] = typed.get("operation")
                data["transferred_bytes"] = typed.get("transferred_bytes")
            if cpu_class != "OTHER_SOURCE":
                data["cpu_classification"] = cpu_class
                data["cpu_source"] = cpu_source
            if kind == "CPU_SAMPLE":
                if row.get("cpu_sample") is not None:
                    data.update(row["cpu_sample"])
                    data["cpu_sample"] = row["cpu_sample"]
                data["frames"] = row["frames"][:32]
                data["sample_count"] = 1
                data["sample_count_is_cpu_percentage"] = False
            # Reserve at least a quarter of the graph for derived wait spans
            # and source entities. Omitted raw events remain in the source.
            raw_node_limit = max(1, out.budget.max_nodes * 3 // 4)
            if len(out.nodes) >= raw_node_limit:
                out.coverage["nodes_omitted"] += 1
                schedule_omitted += int(schedule is not None)
                out.coverage["has_more"] = True
                continue
            node_id = out.add(source, record, kind, metadata=data, process_identity=process,
                              thread_identity=thread, time_domain=domain, time_bounds=bounds)
            if row["frames"]:
                event_node = next((item for item in reversed(out.nodes) if item["node_id"] == node_id), None)
                stack_id = out.add(source, record + ":stack", "STACK", metadata={"frames": row["frames"][:32],
                    "record_refs": [record], "record_ref_relation": "EVENT_STACK", "stack_status": row.get("stack_status")},
                    process_identity=process, thread_identity=thread, time_domain=domain, time_bounds=bounds)
                if event_node is not None:
                    event_node["metadata"]["stack_ref"] = stack_id
                if stack_id is not None and len(out.nodes) < raw_node_limit:
                    _trace_frames(source, row, record + ":stack", process, thread, domain, bounds, out)
            if len(out.nodes) < raw_node_limit:
                _trace_entities(source, row, trace, domain, out)
            if alignment is not None and node_id is not None:
                from .decoder_alignment import project_event_time
                projection = project_event_time(alignment, row)
                if projection.get("status") == "BOUNDED_LOCAL_CLOCK_CORRELATION":
                    out.clock_candidates.append((node_id, alignment, {"source_ticks": row.get("source_ticks")}))
    source["scheduler_complete"] = (count == total and after == 0 and not sequence_gaps and not schedule_omitted and not out_of_order and not errors and
        summary.get("status") == "DECODED" and source["decoder_reported_lost_events"] == 0)
    source.update(events_scanned=count, selected_events=selected, scheduler_nodes_omitted=schedule_omitted,
                  out_of_order_events=out_of_order, decode_errors_observed=errors,
                  event_sequence_gaps=sequence_gaps, scan_complete=count == total and after == 0)
    # Existing wait pairing scans all scheduler headers and refuses invented
    # spans when loss/order/decode evidence is incomplete.
    out.budget.check()
    if count == total and after == 0:
        waits = build_wait_report(path, pid=selection.get("pid", 0), process_instance=selection.get("process_instance"),
            tid=selection.get("tid"), start_ms=selection.get("start_ms"), end_ms=selection.get("end_ms"),
            max_intervals=min(10_000, out.budget.max_nodes), cancel=out.budget)
    else:
        # The existing analyzer needs the entire scheduler inventory. A bounded
        # prefix or continuation page cannot promise that inventory, and must
        # not start a second unbounded pass over a large source.
        waits = {"status": "INCOMPLETE_SOURCE_SCAN", "intervals": [],
                 "coverage": {"status": "NOT_ANALYZED_INCOMPLETE_SOURCE_SCAN"}}
        out.limitations.add("WAIT_ANALYSIS_REQUIRES_COMPLETE_SOURCE_SCAN")
    out.budget.check()
    source["wait_coverage"] = _metadata(waits.get("coverage", {}))
    source["scheduler_complete"] = bool(source["scheduler_complete"] and all(
        waits.get("coverage", {}).get(key) == 0 for key in ("missing_typed_classification",
        "unresolved_selected_identities", "events_with_decode_errors", "out_of_order_events",
        "contradictory_self_switches")))
    for node in out.nodes:
        if node["source_identity"] == source["source_id"] and node["observation_type"] == "SCHEDULER_EVENT":
            node["metadata"]["capture_complete"] = source["scheduler_complete"]
    for index, interval in enumerate(waits.get("intervals", [])):
        process = _trace_process(trace, interval)
        thread = {**(process or {}), "kind": "TRACE_THREAD", "thread_instance": interval["thread_instance"],
                  "tid": interval["tid"]}
        record = "waits:" + ":".join(str(x) for x in interval["source_event_ids"])
        out.add(source, record, "WAIT_INTERVAL", process_identity=process, thread_identity=thread,
            time_domain=domain, time_bounds=_bounds(interval["start_ms"], interval["end_ms"], "ms"),
            metadata={**interval, "record_refs": ["events:" + str(x) for x in interval["source_event_ids"]],
                      "record_ref_relation": "SCHEDULER_INTERVAL_BOUNDARY"})
    out.coverage["source_coverage"].append({"source_id": source["source_id"], "events_scanned": count,
        "selected_events": selected, "events_total_after_cursor": total, "wait_intervals": len(waits.get("intervals", []))})
    if count < total:
        out.coverage["next_cursor"].append({"source_id": source["source_id"], "source_sha256": source["source_sha256"],
            "after": last_identifier, "algorithm_version": ALGORITHM_VERSION, "selection": selection})
    stable.verify()
    out.receipts.append(stable)


def _classify(kind, *, status=None, attributes=None):
    name = str(kind).lower()
    if "incident" in name:
        return "INCIDENT"
    if _FILE_MARKER.search(name):
        return "FILE_OPERATION"
    if _NETWORK_MARKER.search(name):
        return "NETWORK_OPERATION"
    if "error" in name or "failed" in name or status in ("ERROR", "FAILED", "OPERATION_FAILED", "RECOVERY_UNCONFIRMED"):
        return "ERROR"
    if name.startswith(("user", "action.", "stage.", "operation.")):
        return "USER_ACTION"
    if name in ("process/stop", "process/terminate", "process.exit"):
        return "INCIDENT"
    return "ANNOTATION"


def _event_metadata(kind, payload, *, recorded_source, operation_id=None, parent_id=None):
    _require(isinstance(payload, dict), "INVALID_SOURCE_EVENT_PAYLOAD")
    attributes = payload.get("attributes", payload.get("data", payload)) if isinstance(payload, dict) else {}
    if not isinstance(attributes, dict):
        attributes = {}
    status = attributes.get("status", payload.get("status") if isinstance(payload, dict) else None)
    _require(status is None or type(status) is str and len(status) <= 128, "INVALID_SOURCE_OPERATION_STATUS")
    result = {"event_kind": kind, "event_name": kind, "recorded_source": recorded_source,
              "status": status, "operation_id": operation_id or payload.get("operation_id"),
              "parent_id": parent_id or payload.get("parent_id"), "fields": attributes}
    for key in ("io_kind", "latency_ns", "duration_ns", "byte_count", "error_code", "winerror", "win32_code",
                "code", "scenario", "application_version", "resource_id", "object_id", "file_id"):
        if key in attributes:
            result[key] = attributes[key]
    for key in ("error_code", "winerror", "win32_code"):
        if key in result:
            _require(_int(result[key], -(2**31), 2**32 - 1), "INVALID_RECORDED_ERROR_CODE")
    if "error_code" not in result:
        for key in ("winerror", "win32_code"):
            if _int(result.get(key)):
                result["error_code"] = result[key]
                break
    result["error_code_basis"] = "RECORDED_SOURCE_STATEMENT_NOT_ETW_INFERENCE" if "error_code" in result else "NOT_RECORDED"
    if "io_kind" in result:
        result["operation"] = result["io_kind"]
    suffix = str(kind).rsplit(".", 1)[-1].upper()
    if suffix in ("BEGIN", "END", "ERROR"):
        result["phase"] = suffix
    return result


def _events_jsonl(spec, selection, out):
    path = safe_path(Path(spec["path"]))
    stable = _StableSource([path], out.budget)
    source = _source("EVENTS_JSONL", stable, selection=selection)
    source["time_domain"] = "APP_SOURCE:" + source["source_id"]
    if not _register_source(source, stable, path, out):
        return
    after = selection.get("after", 0)
    scanned = selected = 0
    producer_state = {}
    order_errors = sequence_gaps = 0
    reached_eof = False
    producers = set()
    with path.open("rb") as stream:
        line_number = 0
        while True:
            out.budget.check()
            raw = stream.readline(MAX_RECORD_BYTES + 1)
            if not raw:
                reached_eof = True
                break
            line_number += 1
            _require(len(raw) <= MAX_RECORD_BYTES and raw.endswith(b"\n"), "PARTIAL_OR_OVERSIZED_APPLICATION_EVENT")
            if line_number <= after:
                continue
            if not out.scan():
                out.coverage["events_omitted"] += 1
                out.coverage["events_omitted_is_lower_bound"] = True
                out.coverage["next_cursor"].append({"source_id": source["source_id"],
                    "source_sha256": source["source_sha256"], "after": line_number - 1,
                    "algorithm_version": ALGORITHM_VERSION, "selection": selection})
                break
            scanned += 1
            row = _json(raw)
            _require(isinstance(row, dict) and row.get("schema_version") == 1 and
                     _int(row.get("pid"), 1, 2**32 - 1) and _int(row.get("tid"), 1, 2**32 - 1) and
                     _int(row.get("seq"), 1) and type(row.get("kind")) is str and len(row["kind"]) <= 256 and
                     _int(row.get("source_ns")) and type(row.get("source_clock")) is str and
                     isinstance(row.get("attributes"), dict), "INVALID_APPLICATION_EVENT")
            token = row.get("token")
            _require(type(token) is str and 16 <= len(token) <= 128, "INVALID_APPLICATION_PRODUCER")
            producer = hashlib.sha256(canonical_json([row["pid"], token, row["source_clock"]]).encode("ascii")).hexdigest()
            producers.add(producer)
            _require(len(producers) <= 128, "APPLICATION_PRODUCER_BUDGET")
            state = producer_state.setdefault(producer, {"seq": 0, "start": row["source_ns"], "last": None,
                "dropped": 0, "drop_known": True, "io_ends": 0, "terminal_seq": None, "expected_operations": None})
            _require(row["seq"] > state["seq"], "REPLAYED_APPLICATION_EVENT")
            if row["seq"] != state["seq"] + 1:
                sequence_gaps += 1
            if state["last"] is not None and row["source_ns"] < state["last"]:
                out.limitations.add("APPLICATION_EVENT_ORDER_UNCERTAIN")
                order_errors += 1
            state["seq"], state["last"] = row["seq"], row["source_ns"]
            state["io_ends"] += row["kind"] == "io.operation.end"
            if row["kind"] == "blackbox.completed" and row["attributes"].get("status") == "COMPLETED":
                state["terminal_seq"] = row["seq"]
                state["expected_operations"] = row["attributes"].get("expected_operations")
            dropped = row.get("client_dropped")
            state["drop_known"] &= _int(dropped)
            if _int(dropped):
                state["dropped"] = max(state["dropped"], dropped)
            for key in ("operation_id", "parent_id"):
                _require(row.get(key) is None or type(row[key]) is str and 1 <= len(row[key]) <= 128,
                         "INVALID_APPLICATION_OPERATION_ID")
            if (selection.get("pid") and row["pid"] != selection["pid"] or
                    selection.get("tid") and row["tid"] != selection["tid"] or
                    selection.get("start_ns") is not None and row["source_ns"] < selection["start_ns"] or
                    selection.get("end_ns") is not None and row["source_ns"] > selection["end_ns"]):
                continue
            selected += 1
            metadata = _event_metadata(row["kind"], row, recorded_source="APPLICATION_EVENT",
                                        operation_id=row.get("operation_id"), parent_id=row.get("parent_id"))
            metadata.update(producer_id=producer, source_sequence=row["seq"],
                            operation_scope=producer,
                            source_clock=row["source_clock"], client_dropped=row.get("client_dropped"),
                            attribution="APPLICATION_STATEMENT_NOT_AUTHENTICATED")
            process = {"kind": "APP_PROCESS", "source_id": source["source_id"],
                       "producer_id": producer, "pid": row["pid"], "exact": False}
            thread = {**process, "kind": "APP_THREAD", "tid": row["tid"], "exact": False}
            out.add(source, "application:" + producer + ":" + str(row["seq"]),
                _classify(row["kind"], status=metadata.get("status")), metadata=metadata,
                process_identity=process, thread_identity=thread,
                time_domain="APP_SOURCE:" + producer, time_bounds=_bounds(row["source_ns"]))
    drop_known = all(value["drop_known"] for value in producer_state.values())
    drops = sum(value["dropped"] for value in producer_state.values()) if drop_known else None
    duration = next(iter(producer_state.values())) if len(producer_state) == 1 else None
    complete = reached_eof and after == 0 and selected == scanned
    producer_finished = bool(producer_state) and all(value["terminal_seq"] == value["seq"] and
        _int(value["expected_operations"]) and value["expected_operations"] == value["io_ends"]
        for value in producer_state.values())
    source.update(events_scanned=scanned, selected_events=selected, producers=len(producers),
                  clock_alignment="NOT_ESTABLISHED", scan_complete=complete,
                  application_events_complete=bool(complete and producer_finished and drops == 0 and not order_errors and not sequence_gaps),
                  application_producer_completion_reported=producer_finished,
                  application_client_dropped_total=drops, application_order_errors=order_errors,
                  application_sequence_gaps=sequence_gaps,
                  observed_duration_ns=duration["last"] - duration["start"] if duration and not order_errors else None)
    out.coverage["source_coverage"].append({"source_id": source["source_id"], "events_scanned": scanned,
                                          "selected_events": selected})
    stable.verify()
    out.receipts.append(stable)


def _deep_rows(source, record, payload, stamp, out, selection=None):
    selection = selection or {}
    process = _live_process(payload.get("target"))
    domain = "NATIVE_CAPTURE:" + source["source_id"]
    data = payload.get("data", {})
    if not isinstance(data, dict):
        data = {}
    operation = payload.get("operation", "UNKNOWN")
    action = out.add(source, record, "DIAGNOSTIC_ACTION", process_identity=process,
        time_domain=domain, time_bounds=_bounds(stamp), metadata={**payload,
        "recorded_source": payload.get("source"), "phase": payload.get("phase"),
        "operation_id": payload.get("operation_id"), "action_id": payload.get("action_id"),
        "error_code": payload.get("winerror"), "record_refs": []})
    if payload.get("phase") == "RESULT" and payload.get("action_id"):
        if action is not None:
            action_node = next(node for node in reversed(out.nodes) if node["node_id"] == action)
            action_node["metadata"]["record_refs"] = ["actions:" + payload["action_id"] + ":requested"]
            action_node["metadata"]["record_ref_relation"] = "ACTION_RESULT"
            if operation == "snapshot" and isinstance(data.get("snapshot_id"), str):
                action_node["metadata"]["record_refs"].append("snapshots:" + data["snapshot_id"])
            elif operation == "compare":
                action_node["metadata"]["record_refs"].extend("snapshots:" + data[key] for key in
                    ("before_id", "after_id") if isinstance(data.get(key), str))
    if process is not None:
        out.add(source, "process:" + canonical_json(process), "PROCESS", process_identity=process,
                time_domain=domain, metadata={"pid": process["pid"], "created_100ns": process["created_100ns"],
                "record_refs": [record], "identity_basis": "RECORDED_NATIVE_FILETIME_NOT_IMPORT_AUTHENTICITY"})
    rows = data.get("rows", [])
    if not isinstance(rows, list):
        rows = []
    for index, item in enumerate(rows[:512]):
        out.budget.check()
        if not isinstance(item, dict):
            continue
        if selection.get("tid") and item.get("tid") != selection["tid"]:
            continue
        kind = "MODULE" if operation == "modules" else "THREAD" if operation in ("threads", "thread_stacks") else \
               "WAIT_INTERVAL" if operation == "wait_chains" else "NETWORK_OPERATION" if operation == "network" else \
               "MEASUREMENT"
        identity = None
        thread_created = item.get("created_100ns", item.get("thread_created_100ns"))
        if process and _int(item.get("tid"), 1) and _int(thread_created, 1, 2**64 - 1):
            identity = {"kind": "LIVE_THREAD", "pid": process["pid"],
                "created_100ns": process["created_100ns"], "tid": item["tid"],
                "thread_created_100ns": thread_created}
        metadata = {**item, "operation": operation, "record_refs": [record],
                    "record_ref_relation": "DIAGNOSTIC_RESULT_ROW"}
        if operation == "wait_chains":
            metadata.update(wct_snapshot_id=payload.get("operation_id"),
                wait_duration="NOT_ESTABLISHED_BY_POINT_SNAPSHOT", waker_is_lock_owner="NOT_ESTABLISHED")
        thread_node_id = out.add(source, record + ":row:" + str(index), kind, metadata=metadata,
            process_identity=process, thread_identity=identity, time_domain=domain, time_bounds=_bounds(stamp))
        if operation == "wait_chains" and isinstance(item.get("nodes"), list):
            previous_record = None
            for position, chain in enumerate(item["nodes"][:16]):
                if not isinstance(chain, dict):
                    continue
                chain_record = record + ":row:" + str(index) + ":wct:" + str(position)
                chain_meta = {**chain, "wct_snapshot_id": payload.get("operation_id"),
                    "wct_position": position, "recorded_source": "WIN32_WCT",
                    "record_refs": [record + ":row:" + str(index)], "cycle_reported": item.get("cycle_reported"),
                    "lock_owner_identity": "NOT_ESTABLISHED_OUTSIDE_THIS_WCT_SNAPSHOT"}
                if previous_record is not None:
                    chain_meta["observed_dependencies"] = [{"record_ref": previous_record,
                        "snapshot_id": payload.get("operation_id"), "relation": "WCT_CHAIN", "source": "WIN32_WCT"}]
                chain_thread = None
                chain_process = None
                if _int(chain.get("pid"), 1) and _int(chain.get("tid"), 1):
                    chain_process = {"kind": "UNRESOLVED_PROCESS", "pid": chain["pid"], "exact": False}
                    chain_thread = {"kind": "UNRESOLVED_THREAD", "pid": chain["pid"], "tid": chain["tid"],
                                    "snapshot_id": payload.get("operation_id"), "exact": False}
                out.add(source, chain_record, "THREAD" if chain_thread else "ANNOTATION", metadata=chain_meta,
                    process_identity=chain_process, thread_identity=chain_thread, time_domain=domain,
                    time_bounds=_bounds(stamp))
                previous_record = chain_record
        if isinstance(item.get("frames"), list) and item["frames"]:
            thread_node = next((n for n in reversed(out.nodes) if n["node_id"] == thread_node_id), None)
            stack_record = record + ":row:" + str(index) + ":stack"
            stack_id = out.add(source, stack_record, "STACK",
                metadata={"frames": item["frames"][:128], "record_refs": [record + ":row:" + str(index)],
                          "record_ref_relation": "THREAD_STACK", "stack_source": "CURRENT_NATIVE_SNAPSHOT"},
                process_identity=process, thread_identity=identity, time_domain=domain, time_bounds=_bounds(stamp))
            if thread_node is not None:
                thread_node["metadata"]["stack_ref"] = stack_id
            if stack_id is not None:
                _native_frames(source, item["frames"], stack_record, process, domain, out)


def _native_frames(source, frames, stack_record, process, domain, out):
    refs = []
    for frame in frames[:16]:
        out.budget.check()
        module = frame.get("module_identity") if isinstance(frame, dict) else None
        if (not isinstance(module, dict) or module.get("snapshot_binding") != "PSS_CLONE_PE_IDENTITY_AND_LAYOUT_MATCH" or
                not isinstance(module.get("snapshot_pe"), dict)):
            continue
        pe = module["snapshot_pe"]
        guid = pe.get("guid")
        try:
            valid_guid = type(guid) is str and str(UUID(guid)) == guid and UUID(guid).int != 0
        except (ValueError, TypeError, AttributeError):
            valid_guid = False
        _require(valid_guid and _int(pe.get("age"), 1, 2**32 - 1) and
                 _int(pe.get("machine"), 1, 2**16 - 1) and _int(pe.get("image_size"), 1, 2**32 - 1) and
                 _int(pe.get("image_timestamp"), 0, 2**32 - 1), "INVALID_NATIVE_SNAPSHOT_PE_IDENTITY")
        base, size, address, rva = module.get("base"), module.get("size"), frame.get("address"), frame.get("rva")
        _require(_int(base, 1, 2**64 - 1) and _int(size, 1, 2**32 - 1) and
                 _int(address, 1, 2**64 - 1) and _int(rva, 0, 2**32 - 1) and
                 base <= address < base + size and address - base == rva, "INVALID_NATIVE_FRAME_BINDING")
        module_record = "snapshot-modules:" + stable_id("pss_module", stack_record, module["snapshot_pe"], base, size)
        out.add(source, module_record, "MODULE", process_identity=process, time_domain=domain,
            metadata={"name": module.get("name"), "module_identity": module["snapshot_pe"],
                      "snapshot_binding": module["snapshot_binding"], "module_base": base, "image_size": size})
        function_record = module_record + ":rva:" + str(rva)
        symbol = frame.get("symbol")
        out.add(source, function_record, "FUNCTION", process_identity=process, time_domain=domain,
            metadata={"rva": rva, "address": address, "symbol": symbol,
                      "name": symbol.get("name") if isinstance(symbol, dict) else None,
                      "symbol_binding": frame.get("symbol_binding", "NOT_RESOLVED"),
                      "record_refs": [module_record], "record_ref_relation": "FUNCTION_MODULE"})
        refs.append(function_record)
    stack = next((n for n in reversed(out.nodes) if n["source_record_id"] == stack_record and
                  n["source_identity"] == source["source_id"]), None)
    if stack is not None:
        stack["metadata"]["record_refs"].extend(refs)
        stack["metadata"]["frames_without_function_node"] = max(0, len(frames) - len(refs))


def _deep_journal(spec, selection, out):
    path = safe_path(Path(spec["path"]))
    if path.is_dir():
        path = path / "deep-inspection.sqlite3"
    stable = _StableSource([path], out.budget)
    source = _source("DEEP_JOURNAL", stable, selection=selection)
    source["time_domain"] = "NATIVE_CAPTURE:" + source["source_id"]
    if not _register_source(source, stable, path, out):
        return
    previous = "0" * 64
    count = selected = snapshot_count = selected_snapshots = 0
    node_omissions_before = out.coverage["nodes_omitted"]
    with _readonly(path, out.budget, {"actions", "snapshots"}) as db:
        total = db.execute("SELECT count(*) FROM actions").fetchone()[0]
        snapshots_total = db.execute("SELECT count(*) FROM snapshots").fetchone()[0]
        for row in db.execute("SELECT sequence,operation_id,monotonic_ns,record_json,previous_sha256,record_sha256 FROM actions ORDER BY sequence"):
            if not out.scan():
                out.coverage["events_omitted"] += total - count
                break
            count += 1
            raw = row["record_json"]
            _require(isinstance(raw, str) and len(raw) <= MAX_RECORD_BYTES and _int(row["sequence"], 1) and
                     _int(row["monotonic_ns"]) and type(row["operation_id"]) is str and
                     1 <= len(row["operation_id"]) <= 128, "INVALID_DEEP_JOURNAL_RECORD")
            digest = hashlib.sha256(previous.encode("ascii") + raw.encode("utf-8")).hexdigest()
            _require(previous == row["previous_sha256"] and digest == row["record_sha256"], "DEEP_JOURNAL_HASH_CHAIN_MISMATCH")
            previous = digest
            payload = _json(raw)
            _require(isinstance(payload, dict) and payload.get("operation_id") == row["operation_id"] and
                     payload.get("monotonic_ns") == row["monotonic_ns"], "DEEP_JOURNAL_RECORD_METADATA_MISMATCH")
            _require(payload.get("action_id") is None or type(payload["action_id"]) is str and
                     1 <= len(payload["action_id"]) <= 128, "INVALID_DEEP_JOURNAL_ACTION_ID")
            _require(payload.get("phase") is None or type(payload["phase"]) is str and
                     payload["phase"] in ("REQUESTED", "RESULT"), "INVALID_DEEP_JOURNAL_PHASE")
            _require(payload.get("operation") is None or type(payload["operation"]) is str and
                     1 <= len(payload["operation"]) <= 80, "INVALID_DEEP_JOURNAL_OPERATION")
            target = payload.get("target")
            pid = target.get("pid") if isinstance(target, dict) else None
            if (selection.get("pid") and pid != selection["pid"] or
                    selection.get("start_ns") is not None and row["monotonic_ns"] < selection["start_ns"] or
                    selection.get("end_ns") is not None and row["monotonic_ns"] > selection["end_ns"]):
                continue
            selected += 1
            _deep_rows(source, "actions:" + row["operation_id"], payload, row["monotonic_ns"], out, selection)
        source.update(journal_records_checked=count, journal_records_total=total,
                      checked_chain_head_sha256=previous, selected_prefix_complete=count == total)
        if count == total:
            for row in db.execute("SELECT snapshot_id,identity_json,timestamp_utc,data_json FROM snapshots ORDER BY snapshot_id"):
                if not out.scan():
                    out.coverage["has_more"] = True
                    out.coverage["events_omitted"] += snapshots_total - snapshot_count
                    break
                snapshot_count += 1
                identity, data = _json(row["identity_json"]), _json(row["data_json"])
                _require(type(row["snapshot_id"]) is str and 1 <= len(row["snapshot_id"]) <= 128 and
                         isinstance(identity, dict) and isinstance(data, dict), "INVALID_DEEP_JOURNAL_SNAPSHOT")
                if selection.get("pid") and identity.get("pid") != selection["pid"]:
                    continue
                selected_snapshots += 1
                out.add(source, "snapshots:" + row["snapshot_id"], "MEASUREMENT",
                    process_identity=_live_process(identity), time_domain="UNKNOWN",
                    metadata={"snapshot_id": row["snapshot_id"], "snapshot": data,
                              "recorded_timestamp_utc": row["timestamp_utc"],
                              "snapshot_timestamp_is_execution_boundary": False})
        source.update(selected_events=selected, snapshot_records_checked=snapshot_count,
                      snapshot_records_total=snapshots_total,
                      scan_complete=count == total and snapshot_count == snapshots_total and selected == count and
                      selected_snapshots == snapshot_count and
                      not selection.get("tid") and out.coverage["nodes_omitted"] == node_omissions_before)
    out.coverage["source_coverage"].append({"source_id": source["source_id"], "events_scanned": count,
                                          "events_total": total, "hash_chain_checked": True})
    stable.verify()
    out.receipts.append(stable)


def _session(spec, selection, out):
    from .session_view import SessionView, SchemaV1Reader, SchemaV2Reader
    from .investigation_v2 import _persisted_findings
    folder = safe_path(Path(spec["path"]))
    if folder.is_file():
        _require(folder.name in ("session.sqlite3", "session-v2.sqlite3", "research.sqlite3"), "INVALID_SESSION_SOURCE_FILENAME")
        folder = folder.parent
    main = folder / "session-v2.sqlite3"
    if not main.is_file():
        main = folder / "session.sqlite3"
    paths = [main]
    absent_paths = [folder / "session-v2.sqlite3"] if main.name == "session.sqlite3" else []
    research = folder / "research.sqlite3"
    if research.is_file():
        paths.append(research)
    else:
        absent_paths.append(research)
    stable = _StableSource(paths, out.budget, absent_paths=absent_paths)
    source = _source("SESSION", stable, selection=selection, hash_roles=["session_main", *( ["research"] if len(paths) > 1 else [])])
    domain = "SESSION_MONOTONIC:" + source["source_id"]
    source["time_domain"] = domain
    if not _register_source(source, stable, folder, out):
        return
    count = 0
    initial_required = {"sessions", "targets", "samples", "process_instances", "events", "incidents", "thread_samples", "sensor_errors", "capabilities"} if main.name == "session-v2.sqlite3" else {"metadata", "samples"}
    with _readonly(main, out.budget, initial_required):
        pass
    # Pin the existing reader to the exact main file hashed above. Re-running
    # SessionView.open(folder)'s legacy/v2 discovery could select an unhashed
    # v2 file created after selection. Receipts also retain optional absence.
    reader_type = SchemaV2Reader if main.name == "session-v2.sqlite3" else SchemaV1Reader
    try:
        reader = reader_type(main, cancel=lambda: _sql_cancel(out.budget), timeout_s=min(30, out.budget.timeout_seconds))
    except (sqlite3.Error, OSError, KeyError, TypeError, IndexError) as error:
        out.budget.check()
        raise InvestigationError("INVALID_OR_UNSUPPORTED_SESSION") from error
    with SessionView(reader) as view:
        out.budget.check()
        required = {"sessions", "targets", "samples", "process_instances", "events", "incidents", "thread_samples", "sensor_errors"} if view.is_v2 else {"metadata", "samples"}
        _tables(view.db, required)
        source.update(session_uuid=view.metadata.get("session_uuid"), schema_version=view.metadata.get("schema_version"),
            clock_quality=view.metadata.get("clock_quality"), writer_dropped_commands=view.metadata.get("writer_dropped_commands"),
            recorded_status=view.metadata.get("recorded_status"))
        if not view.is_v2:
            source["time_domain"] = domain = "LEGACY_ELAPSED:" + source["source_id"]
            out.limitations.add("LEGACY_LIMITED_DATA")
        root = selection.get("instance_id", 1)
        _require(_int(root, 1), "INVALID_SESSION_INSTANCE")
        instance = view.db.execute("SELECT pid,creation_time FROM process_instances WHERE instance_id=?", (root,)).fetchone() if view.is_v2 else None
        _require(not view.is_v2 or instance is not None, "SESSION_INSTANCE_NOT_FOUND")
        process = {"kind": "SESSION_PROCESS", "source_id": source["source_id"], "instance_id": root,
                   "pid": instance["pid"] if instance else view.metadata.get("pid"),
                   "creation_time": instance["creation_time"] if instance else view.metadata.get("creation_time"), "exact": False}
        _require(not selection.get("pid") or process["pid"] == selection["pid"], "SESSION_INSTANCE_PID_MISMATCH")
        out.add(source, "process_instances:" + str(root), "PROCESS", process_identity=process,
            time_domain=domain, metadata={"session_uuid": source["session_uuid"], "executable_name": view.metadata.get("executable_name"),
                                       "identity_quality": "RECORDED_FLOAT_CREATION_NOT_EXACT_FILETIME"})
        series = "DETAILED" if view.is_v2 and view.bounds("DETAILED", root)[2] else "STANDARD" if root == 1 else "CHILD"
        lo, hi, total = view._range(selection.get("start_ns"), selection.get("end_ns"), series, root)
        source["selected_interval_ns"] = [lo, hi]
        if view.is_v2:
            source["sensor_errors_count"] = view.db.execute("SELECT count(*) FROM sensor_errors WHERE monotonic_ns BETWEEN ? AND ?", (lo, hi)).fetchone()[0]
            # Canonical Engine2 incident interpretation is reused, not cloned.
            # The primary-event FK determines a selected instance; global
            # sensor errors do not acquire a fabricated process identity.
            for finding in _persisted_findings(view, lo, hi, {"status": "SAVED_SOURCE_RECORDS_ONLY"}):
                if not out.scan():
                    break
                count += 1
                primary_id = finding.get("facts", [{}])[0].get("primary_event_id")
                chosen_process = None
                refs = []
                if _int(primary_id, 1):
                    primary = view.db.execute("SELECT instance_id FROM events WHERE event_id=?", (primary_id,)).fetchone()
                    _require(primary is not None, "MISSING_INCIDENT_PRIMARY_EVENT")
                    if primary["instance_id"] is not None and primary["instance_id"] != root:
                        continue
                    chosen_process = process if primary["instance_id"] == root else None
                    refs = ["events:" + str(primary_id)]
                incident_id = finding.get("detail", {}).get("incident_id")
                record = "incidents:" + str(incident_id) if incident_id is not None else "finding-v2:" + finding["finding_id"]
                out.add(source, record, "INCIDENT" if incident_id is not None else "ERROR", process_identity=chosen_process,
                    time_domain=domain, time_bounds=_bounds(finding["start_ns"], finding.get("end_ns") or finding["start_ns"]),
                    metadata={"code": finding["code"], "facts": finding.get("facts"), "group": finding.get("group"),
                              "incident_id": incident_id, "finding_v2": finding, "record_refs": refs,
                              "record_ref_relation": "INCIDENT_PRIMARY_EVENT", "root_cause": "NOT_ESTABLISHED",
                              "reused_engine": "BLACKBOX_INVESTIGATION_2"})
            for row in view.db.execute("SELECT * FROM events WHERE (instance_id=? OR instance_id IS NULL) AND coalesce(observed_ns,recorded_ns) BETWEEN ? AND ? ORDER BY event_id", (root, lo, hi)):
                if not out.scan():
                    break
                count += 1
                payload = _json(row["detail_json"])
                meta = _event_metadata(row["event_type"], payload, recorded_source=row["source_kind"])
                meta.update(measurement_status=row["measurement_status"], timestamp_precision=row["timestamp_precision"],
                            recorded_verification_class=row["verification_class"], correlation_key=row["correlation_key"])
                out.add(source, "events:" + str(row["event_id"]), _classify(row["event_type"], status=meta.get("status")),
                    process_identity=process if row["instance_id"] == root else None, time_domain=domain,
                    time_bounds=_bounds(row["observed_ns"] if row["observed_ns"] is not None else row["recorded_ns"]), metadata=meta)
        for row in view.reader.iter_samples(lo, hi, series=series, instance_id=root):
            if not out.scan():
                out.coverage["events_omitted"] += max(0, total - count)
                break
            count += 1
            record = "samples:" + str(row.get("sample_id", row.get("seq")))
            metrics = {key: row.get(key) for key in ("cpu_percent", "cpu_user_s", "cpu_system_s", "rss_bytes", "private_bytes",
                "uss_bytes", "handle_count", "thread_count", "read_bytes", "write_bytes", "read_ops", "write_ops")}
            node_id = out.add(source, record, "MEASUREMENT", process_identity=process,
                time_domain=domain, time_bounds=_bounds(row["time_ns"]), metadata={"metrics": metrics, "series": series,
                "series_seq": row["series_seq"], "requested_interval_ns": row.get("requested_interval_ns"),
                "recorded_source": "SESSION_COUNTER_SNAPSHOT", "counter_is_execution_duration": False})
            if view.is_v2 and node_id and len(out.nodes) < out.budget.max_nodes:
                for thread in view.db.execute("SELECT tid,cpu_user_s,cpu_system_s,identity_quality FROM thread_samples WHERE sample_id=? ORDER BY tid LIMIT 128", (row["sample_id"],)):
                    identity = {**process, "kind": "SESSION_THREAD", "tid": thread["tid"], "exact": False}
                    out.add(source, record + ":thread:" + str(thread["tid"]), "THREAD", process_identity=process,
                        thread_identity=identity, time_domain=domain, time_bounds=_bounds(row["time_ns"]),
                        metadata={**dict(thread), "record_refs": [record], "record_ref_relation": "SAMPLE_THREAD",
                                  "identity_warning": "TID_REUSE_CANNOT_BE_EXCLUDED"})
        source.update(samples_total=total, events_scanned=count, source_closed=view.metadata.get("recorded_status") in ("CLOSED", "COMPLETED", "STOPPED"),
                      scan_complete=out.coverage["events_examined"] < out.budget.max_events)
    if research in stable.hashes:
        # CaseBook stamps its own saved monotonic clock. Co-location, matching
        # PID or a repeated floating creation time cannot establish same boot.
        # The current context has no native boot-binding contract suitable for
        # projecting those times into the independently saved session domain.
        research_domain = "RESEARCH_MONOTONIC:" + stable.hashes[research]
        source.update(research_time_domain=research_domain, research_session_clock_alignment="NOT_ESTABLISHED")
        out.limitations.add("RESEARCH_SESSION_CLOCK_ALIGNMENT_NOT_ESTABLISHED")
        _research(research, source, process, research_domain, selection, out)
    out.coverage["source_coverage"].append({"source_id": source["source_id"], "events_scanned": count, "samples_total": total})
    stable.verify()
    out.receipts.append(stable)


def _research(path, source, process, domain, selection, out):
    fully_scanned = True
    if selection.get("start_ns") is not None or selection.get("end_ns") is not None:
        out.limitations.add("RESEARCH_TIME_FILTER_NOT_PROJECTED_FROM_SESSION")
    with _readonly(path, out.budget, {"context", "evidence", "operation_spans"}) as db:
        for row in db.execute("SELECT id,monotonic_ns,pid,process_created,tid,source,quality,kind,operation_id,data FROM evidence ORDER BY id"):
            if not out.scan():
                fully_scanned = False
                break
            _require(_int(row["id"], 1) and _int(row["monotonic_ns"]), "INVALID_RESEARCH_EVENT_IDENTITY")
            if (row["pid"] is not None and row["pid"] != process["pid"] or
                    selection.get("tid") and row["tid"] != selection["tid"]):
                continue
            payload = _json(row["data"])
            meta = _event_metadata(row["kind"], payload, recorded_source=row["source"], operation_id=row["operation_id"])
            meta["quality"] = row["quality"]
            if row["source"] == "APPLICATION_EVENT":
                meta["operation_scope"] = stable_id("research_producer", source["source_id"],
                    payload.get("pid"), payload.get("source_clock"))
                meta["attribution"] = "APPLICATION_STATEMENT_NOT_AUTHENTICATED"
            chosen_process = process if row["pid"] == process["pid"] and row["process_created"] == process["creation_time"] else None
            thread = {**chosen_process, "kind": "SESSION_THREAD", "tid": row["tid"], "exact": False} if chosen_process and _int(row["tid"], 1) else None
            out.add(source, "evidence:" + str(row["id"]), _classify(row["kind"], status=meta.get("status")),
                process_identity=chosen_process, thread_identity=thread, time_domain=domain,
                time_bounds=_bounds(row["monotonic_ns"]), metadata=meta)
    source["scan_complete"] = source["scan_complete"] and fully_scanned


def _investigation_v2(spec, selection, out):
    path = safe_path(Path(spec["path"]))
    _require(path.stat().st_size <= MAX_JSON_BYTES, "INVESTIGATION_V2_FILE_BUDGET")
    stable = _StableSource([path], out.budget)
    value = _json(path.read_bytes(), maximum=MAX_JSON_BYTES)
    _require(isinstance(value, dict) and value.get("engine") == "BLACKBOX_INVESTIGATION_2" and
             value.get("schema_version") == 2 and isinstance(value.get("findings"), list),
             "INVALID_INVESTIGATION_V2_REPORT")
    source = _source("INVESTIGATION_V2", stable, selection=selection)
    domain = "IMPORTED_INVESTIGATION_V2:" + source["source_id"]
    source["time_domain"] = domain
    if not _register_source(source, stable, path, out):
        return
    scanned = 0
    for finding in value["findings"]:
        if not out.scan():
            break
        scanned += 1
        _require(isinstance(finding, dict) and type(finding.get("finding_id")) is str and
                 type(finding.get("code")) is str, "INVALID_INVESTIGATION_V2_FINDING")
        out.add(source, "findings:" + finding["finding_id"], "INCIDENT", metadata={"recorded_finding": finding,
            "code": finding["code"], "root_cause": "NOT_ESTABLISHED", "attribution": "IMPORTED_ENGINE2_STATEMENT"},
            time_domain=domain, time_bounds=_bounds(finding.get("start_ns"), finding.get("end_ns") or finding.get("start_ns")))
    source.update(legacy_engine_preserved=True, original_findings_total=value.get("findings_total"),
                  original_has_more=value.get("has_more"), events_scanned=scanned,
                  scan_complete=scanned == len(value["findings"]) and value.get("has_more") is False)
    stable.verify()
    out.receipts.append(stable)


def _dump(spec, selection, out):
    from .deep_dump import inspect_dump
    path = safe_path(Path(spec["path"]))
    stable = _StableSource([path], out.budget)
    report = inspect_dump(path, max_bytes=min(out.budget.max_source_bytes, 2 * 1024**3),
                          cancel_event=out.budget, deadline=out.budget.deadline)
    source = _source("DUMP_METADATA", stable, selection=selection)
    if not _register_source(source, stable, path, out):
        return
    out.add(source, "minidump:metadata", "ARTIFACT", metadata={"kind": "SAVED_MINIDUMP", "report": report,
        "memory_contents_included": False, "live_process_binding": "NOT_ESTABLISHED"})
    stable.verify()
    out.receipts.append(stable)


def normalize_sources(sources, *, selection=None, budget=None):
    """Normalize explicit saved sources without mutating or executing them.

    ``after`` is a source-local event cursor for trace indices / JSONL. A
    returned omitted count or ``has_more`` is never capture completeness.
    Narrower time intervals can be analyzed in separate bounded passes.
    """
    budget = use_budget(budget)
    _require(type(sources) is list and 1 <= len(sources) <= 16, "INVALID_INVESTIGATION_SOURCE_LIST")
    _require(selection is None or isinstance(selection, dict), "INVALID_INVESTIGATION_SELECTION")
    out = _Output(budget)
    adapters = {"TRACE_INDEX": _trace, "SESSION": _session, "DEEP_JOURNAL": _deep_journal,
                "EVENTS_JSONL": _events_jsonl, "INVESTIGATION_V2": _investigation_v2, "DUMP_METADATA": _dump}
    for spec in sources:
        budget.check()
        _require(type(spec) is dict and spec.get("source_type") in SOURCE_TYPES and
                 isinstance(spec.get("path"), (str, Path)), "INVALID_INVESTIGATION_SOURCE_SPEC")
        chosen = _selection(spec, selection)
        try:
            adapters[spec["source_type"]](spec, chosen, out)
        except sqlite3.OperationalError:
            budget.check()
            raise InvestigationError("INVALID_OR_UNSUPPORTED_SQLITE_SOURCE") from None
        except (ValueError, OSError):
            budget.check()
            raise
    # Duplicate aliases of an identical input retain one source descriptor.
    by_source = {}
    for source in out.sources:
        old = by_source.get(source["source_id"])
        _require(old is None or old.get("selection") == source.get("selection"), "DUPLICATE_SOURCE_SELECTION_AMBIGUOUS")
        by_source[source["source_id"]] = source
    out.sources = sorted(by_source.values(), key=lambda x: x["source_id"])
    _finish_clocks(out)
    result = budget.result({"sources": out.sources, "nodes": out.nodes, "coverage": out.coverage,
        "limitations": sorted(out.limitations), "clock_relations": []})
    result["_source_paths"] = out.source_paths
    result["_source_receipts"] = tuple(out.receipts)
    result["clock_relations"] = out.clock_relations
    return result


def revalidate_sources(normalized, *, budget=None):
    """Recheck original bytes at the facade/store publication boundary.

    Receipts are private in-process objects, not authority loaded from an
    imported JSON graph. Persistence/export must omit private fields.
    """
    budget = use_budget(budget)
    receipts = normalized.get("_source_receipts") if isinstance(normalized, dict) else None
    _require(type(receipts) is tuple and 1 <= len(receipts) <= 16, "INVALID_SOURCE_REVALIDATION_RECEIPTS")
    for receipt in receipts:
        budget.check()
        _require(isinstance(receipt, _StableSource) and receipt._origin is _SOURCE_RECEIPT_ORIGIN,
                 "INVALID_SOURCE_REVALIDATION_RECEIPT")
        receipt.verify()
    budget.check()
    return {"status": "UNCHANGED", "sources_checked": len(receipts)}


def _finish_clocks(out):
    if not out.clock_candidates:
        return
    from .evidence_correlation import computed_clock_relation
    from .decoder_alignment import project_event_time
    sessions = {source.get("session_uuid"): source for source in out.sources if source["source_type"] == "SESSION"}
    targets = {}
    for node in out.nodes:
        if node["observation_type"] == "MEASUREMENT" and node.get("time_bounds") and node["time_bounds"].get("unit") == "ns":
            targets.setdefault(node["source_identity"], []).append((node["time_bounds"]["start"], node["node_id"]))
    for values in targets.values():
        values.sort()
    for node_id, alignment, raw in out.clock_candidates:
        out.budget.check()
        session = sessions.get(alignment.get("session_uuid"))
        if session is None:
            continue
        values = targets.get(session["source_id"], [])
        if not values:
            continue
        projected = project_event_time(alignment, raw)
        if projected.get("status") != "BOUNDED_LOCAL_CLOCK_CORRELATION":
            continue
        origin = alignment["session_origin_ns"]
        lower = projected["session_relative_lower_ns"] + origin
        upper = projected["session_relative_upper_ns"] + origin
        position = bisect_left(values, (lower, ""))
        if position >= len(values) or values[position][0] > upper:
            continue
        relation = computed_clock_relation(node_id, values[position][1], alignment, raw,
            target_domain=session["time_domain"], evidence_refs=[node_id, values[position][1]])
        if relation is not None:
            out.clock_relations.append(relation)


def registry_source_contract():
    """Reserved extension interface; this module contains no registry collector."""
    return {"source_type": "REGISTRY", "status": "NOT_IMPLEMENTED",
        "collector": False, "required_future_gates": ["WINDOWS_COLLECTOR", "TYPED_PARSER", "PERMISSIONS", "NATIVE_ACCEPTANCE"]}
