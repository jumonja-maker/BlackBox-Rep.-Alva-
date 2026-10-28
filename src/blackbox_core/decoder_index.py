"""Versioned, read-only trace index and conservative BLACK.BOX GC adapter.

A trace index is separate from recording databases. Imported claims remain
UNVERIFIED_IMPORT; trace-relative time is NOT aligned to an observer session.
"""
from __future__ import annotations
from contextlib import closing
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import tempfile
import time
from .decoder_profiles import ProfileBuilder, read_profiles
from .decoder_clock import TraceClockAudit
from .decoder_cpu import validate_cpu_sample, CpuSampleAudit
from .decoder_modules import ModuleCatalog, read_modules

PROTOCOL = "blackbox.trace-event/1"
MAX_LINE = 256 * 1024
MAX_EVENTS = 250_000
APP_ID = 0x42424431


def _integer(value, *, minimum=0):
    return type(value) is int and minimum <= value <= 2**63 - 1


def _number(value):
    return type(value) in (float, int) and math.isfinite(value) and abs(value) < 1e15


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def lines(path, cancel=None):
    with Path(path).open("rb") as stream:
        while True:
            if cancel is not None and cancel.is_set():
                raise InterruptedError("DECODER_CANCELLED")
            line = stream.readline(MAX_LINE + 1)
            if not line:
                return
            if len(line) > MAX_LINE or not line.endswith(b"\n"):
                raise ValueError("OVERSIZED_OR_PARTIAL_JSONL_RECORD")
            item = json.loads(line.decode("utf-8-sig"), object_pairs_hook=_pairs,
                              parse_constant=lambda x: (_ for _ in ()).throw(ValueError("NONFINITE_JSON")))
            if type(item) is not dict:
                raise ValueError("OBJECT_RECORD_REQUIRED")
            yield item


def file_hash(path, cancel=None):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            if cancel is not None and cancel.is_set():
                raise InterruptedError("DECODER_CANCELLED")
            digest.update(chunk)
    return digest.hexdigest()


def validate_event(row, expected):
    if (row.get("type") != "event" or row.get("ordinal") != expected or
            not _integer(row.get("ordinal"), minimum=1) or not _number(row.get("time_ms"))):
        raise ValueError("INVALID_EVENT_ID_OR_TIME")
    for key in ("pid", "tid"):
        if not _integer(row.get(key), minimum=-1):
            raise ValueError("INVALID_EVENT_IDENTITY")
    for key in ("provider", "name"):
        if type(row.get(key)) is not str or len(row[key]) > 512:
            raise ValueError("INVALID_EVENT_NAME")
    if row.get("process_instance") is not None and not _integer(row["process_instance"]):
        raise ValueError("INVALID_PROCESS_INSTANCE")
    if type(row.get("payload")) is not dict or len(row["payload"]) > 64:
        raise ValueError("INVALID_EVENT_PAYLOAD")
    if type(row.get("frames")) is not list or len(row["frames"]) > 128:
        raise ValueError("INVALID_STACK")
    for frame in row["frames"]:
        if (type(frame) is not dict or type(frame.get("name")) is not str or
                len(frame["name"]) > 2048 or type(frame.get("address")) is not str or
                len(frame["address"]) > 128):
            raise ValueError("INVALID_FRAME")
    validate_cpu_sample(row)


class GCAdapter:
    """Pair typed events only within one trace process instance and CLR instance.

    GC start/stop gives collection elapsed time, not a stop-the-world pause.
    Suspension envelopes and fully suspended intervals have distinct meanings.
    Duplicate starts, missing phases and unmatched ends never produce zeroes.
    """
    def __init__(self):
        self.gc = {}
        self.suspend = {}
        self.ambiguous = set()
        self.unmatched = 0
        self.pairs = 0

    def accept(self, row):
        sem = row.get("semantic")
        if not sem:
            return []
        if type(sem) is not dict:
            raise ValueError("INVALID_SEMANTIC_RECORD")
        process, runtime = row.get("process_instance"), sem.get("runtime")
        if not _integer(process) or not _integer(runtime):
            self.unmatched += 1
            return []
        identity = (process, row["pid"], runtime)
        kind = sem.get("kind")
        now = row["time_ms"]
        if kind in ("gc_start", "gc_stop"):
            if not _integer(sem.get("number")):
                self.unmatched += 1
                return []
            key = (*identity, sem["number"])
            if kind == "gc_start":
                if len(self.gc) >= 10000:
                    raise ValueError("GC_PAIRING_BUDGET")
                if key in self.gc:
                    self.ambiguous.add(key)
                    self.unmatched += 1
                self.gc[key] = row
                return []
            start = self.gc.pop(key, None)
            ambiguous = key in self.ambiguous
            self.ambiguous.discard(key)
            if not start or ambiguous or now < start["time_ms"]:
                self.unmatched += 1
                return []
            self.pairs += 1
            return [self._interval("GC_ELAPSED_NOT_PAUSE", start, row,
                                   start["semantic"])]
        if kind == "suspend_begin":
            if len(self.suspend) >= 10000:
                raise ValueError("SUSPEND_PAIRING_BUDGET")
            previous = self.suspend.get(identity)
            self.suspend[identity] = {"start": row, "invalid": previous is not None}
            if previous:
                self.unmatched += 1
        elif kind in ("suspend_end", "restart_begin"):
            state = self.suspend.get(identity)
            if not state:
                self.unmatched += 1
            elif kind in state:
                state["invalid"] = True
                self.unmatched += 1
            else:
                state[kind] = row
        elif kind == "restart_end":
            state = self.suspend.pop(identity, None)
            if not state or state["invalid"]:
                self.unmatched += 1
                return []
            start = state["start"]
            if now < start["time_ms"]:
                self.unmatched += 1
                return []
            result = [self._interval("RUNTIME_SUSPENSION_ENVELOPE", start, row,
                                     {"reason": start["semantic"].get("reason")})]
            a, b = state.get("suspend_end"), state.get("restart_begin")
            if a and b and start["time_ms"] <= a["time_ms"] <= b["time_ms"] <= now:
                result.append(self._interval("RUNTIME_FULLY_SUSPENDED", a, b, {}))
            else:
                self.unmatched += 1
            return result
        return []

    @staticmethod
    def _interval(kind, start, end, details):
        return {"kind": kind, "start_event": start["ordinal"], "end_event": end["ordinal"],
                "pid": start["pid"], "process_instance": start["process_instance"],
                "runtime": start.get("semantic", {}).get("runtime"),
                "start_ms": start["time_ms"], "duration_ms": end["time_ms"] - start["time_ms"],
                "details": details, "quality": "DERIVED_FROM_IMPORTED_EVENTS",
                "root_cause": "UNKNOWN"}

    def health(self):
        return {"gc_pairs": self.pairs, "unmatched_or_ambiguous": self.unmatched,
                "open_gc_starts": len(self.gc), "open_suspensions": len(self.suspend),
                "gc_elapsed_is_pause": False}


def own_events(path, cancel=None):
    """Our schema-1 JSONL is not an ETW format. Never trust its token or source label."""
    origins, sequences, producers = {}, {}, {}
    for ordinal, raw in enumerate(lines(path, cancel), 1):
        if (raw.get("schema_version") != 1 or not _integer(raw.get("pid"), minimum=1) or
                not _integer(raw.get("tid")) or not _integer(raw.get("source_ns")) or
                not _integer(raw.get("seq"), minimum=1) or
                type(raw.get("source_clock")) is not str or not 1 <= len(raw["source_clock"]) <= 80 or
                type(raw.get("kind")) is not str or not 1 <= len(raw["kind"]) <= 80):
            raise ValueError("INVALID_BLACKBOX_EVENT_SCHEMA")
        tid_kind = raw.get("tid_kind", "OS_NATIVE")
        if tid_kind not in ("OS_NATIVE", "RUNTIME_THREAD_ID"):
            raise ValueError("INVALID_APP_THREAD_KIND")
        # An application token identifies a writer, NOT an authenticated
        # source. Its opaque value must never enter a saved index. Without
        # one, distinct writers using the same PID/clock remain ambiguous.
        token = raw.get("token")
        if token is not None and (type(token) is not str or not 1 <= len(token) <= 128):
            raise ValueError("INVALID_APP_WRITER_TOKEN")
        producer_key = (raw["pid"], raw["source_clock"], token)
        if producer_key not in producers:
            if len(producers) >= 4096:
                raise ValueError("APPLICATION_PRODUCER_BUDGET")
            producers[producer_key] = len(producers) + 1
        producer = producers[producer_key]
        identity = (raw["pid"], raw["source_clock"], producer)
        sequence_key = (*identity, tid_kind, raw["tid"])
        if raw["seq"] <= sequences.get(sequence_key, -1):
            raise ValueError("REPLAYED_APPLICATION_EVENT")
        sequences[sequence_key] = raw["seq"]
        if len(origins) > 4096 or len(sequences) > 100000:
            raise ValueError("APPLICATION_IDENTITY_BUDGET")
        origin = origins.setdefault(identity, raw["source_ns"])
        raw = dict(raw)
        raw.pop("token", None)
        yield {"type": "event", "ordinal": ordinal, "time_ms": (raw["source_ns"] - origin) / 1e6,
               "pid": raw["pid"], "tid": raw["tid"], "process_instance": None,
               "provider": "BLACKBOX_APPLICATION_JSONL", "name": raw["kind"],
               "clock_scope": list(identity), "clock_alignment": "SEPARATE_PER_PRODUCER_NOT_ALIGNED",
               "producer_identity_quality": "TOKEN_PARTITIONED_NOT_VERIFIED" if token is not None
                                            else "NO_TOKEN_WRITER_AMBIGUOUS",
               "payload": raw, "payload_status": "UNVERIFIED_APPLICATION_STATEMENT",
               "frames": [], "stack_status": "NOT_RECORDED", "semantic": None}


def build_index(source, output, *, input_sha256, format_name, cancel=None):
    """Build privately; missing footer, corrupt records or cancellation cannot publish a DB."""
    output = Path(output)
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError("INDEX_DESTINATION_MUST_BE_NEW")
    fd, part_name = tempfile.mkstemp(prefix=".decoder-building-", dir=output.parent)
    os.close(fd)
    part = Path(part_name)
    db = None
    try:
        db = sqlite3.connect(part)
        db.execute(f"PRAGMA application_id={APP_ID}")
        db.execute("PRAGMA user_version=4")
        db.executescript("""
        CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE events(id INTEGER PRIMARY KEY,time_ms REAL NOT NULL,pid INTEGER,
            provider TEXT NOT NULL,name TEXT NOT NULL,has_stack INTEGER NOT NULL,
            utc_time_ns INTEGER,data TEXT NOT NULL);
        CREATE INDEX ix_events_pid ON events(pid,id);
        CREATE INDEX ix_events_utc ON events(utc_time_ns,id);
        CREATE INDEX ix_events_provider ON events(provider,id);
        CREATE INDEX ix_events_stack ON events(has_stack,id);
        CREATE TABLE intervals(id INTEGER PRIMARY KEY,kind TEXT NOT NULL,pid INTEGER,
            start_ms REAL NOT NULL,duration_ms REAL NOT NULL,data TEXT NOT NULL);
        """)
        adapter = GCAdapter()
        profiler = ProfileBuilder(db)
        clock_audit = TraceClockAudit()
        cpu_audit = CpuSampleAudit()
        modules = ModuleCatalog(db)
        engine_header = None
        footer = None
        rows = 0
        bounded = errors = without_fields = stacked = 0
        if format_name == ".jsonl":
            records = own_events(source, cancel)
            engine_header = {"engine": "BLACKBOX_APPLICATION_SCHEMA_1", "clock": "PER_PRODUCER_NOT_ALIGNED"}
        else:
            records = lines(source, cancel)
            engine_header = next(records, None)
            if (not engine_header or engine_header.get("type") != "header" or
                    engine_header.get("protocol") != PROTOCOL or
                    engine_header.get("input_sha256") != input_sha256):
                raise ValueError("INVALID_DECODER_HEADER_OR_INPUT_HASH")
        for row in records:
            if row.get("type") == "footer" and format_name != ".jsonl":
                footer = row
                if next(records, None) is not None:
                    raise ValueError("DATA_AFTER_FOOTER")
                break
            if rows == MAX_EVENTS:
                if format_name != ".jsonl":
                    raise ValueError("DECODER_EVENT_BUDGET")
                footer = {"status": "TRUNCATED", "rows": rows}
                break
            validate_event(row, rows + 1)
            modules.accept(row)
            utc_ns = clock_audit.project(row)
            cpu_audit.accept(row)
            rows += 1
            data = json.dumps(row, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
            if len(data) > MAX_LINE * 6:
                raise ValueError("INDEX_RECORD_BUDGET")
            bounded += bool(row.get("bounded"))
            errors += bool(row.get("errors"))
            without_fields += row.get("payload_status") == "NO_FIELDS_OR_SCHEMA"
            stacked += bool(row["frames"])
            db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?)", (rows, row["time_ms"], row["pid"],
                       row["provider"], row["name"], int(bool(row["frames"])), utc_ns, data))
            profiler.accept(row)
            for interval in adapter.accept(row):
                db.execute("INSERT INTO intervals(kind,pid,start_ms,duration_ms,data) VALUES(?,?,?,?,?)",
                           (interval["kind"], interval["pid"], interval["start_ms"], interval["duration_ms"],
                            json.dumps(interval, allow_nan=False)))
            if rows % 512 == 0:
                db.commit()
                if part.stat().st_size > 768 * 1024**2:
                    raise ValueError("INDEX_DISK_BUDGET")
        if format_name == ".jsonl" and footer is None:
            footer = {"status": "DECODED", "rows": rows}
        if (not footer or footer.get("rows") != rows or
                footer.get("status") not in ("DECODED", "TRUNCATED") or
                format_name != ".jsonl" and footer.get("protocol") != PROTOCOL):
            raise ValueError("MISSING_OR_INVALID_COMPLETION_FOOTER")
        profile_meta = profiler.finish()
        meta = {"schema": "blackbox.decoder-index/4", "engine": engine_header,
                "profiles": profile_meta, "calendar_clock": clock_audit.summary(),
                "cpu_samples": cpu_audit.summary(),
                "native_modules": modules.summary(),
                "input_sha256": input_sha256, "format": format_name, "rows": rows,
                "status": footer["status"], "bounded_events": bounded, "events_with_errors": errors,
                "events_without_fields_or_schema": without_fields, "events_with_stacks": stacked,
                "loss": None, "decoder_reported_lost_events": footer.get("decoder_reported_lost_events"),
                "capture_complete": None, "verification_class": "UNVERIFIED_IMPORT",
                "clock_alignment_to_session": "NOT_ESTABLISHED", "gc": adapter.health(),
                "limitations": ["NO_AUTOMATIC_ROOT_CAUSE", "NO_SYMBOL_SERVER_DOWNLOADS",
                    "NO_INVENTED_MISSING_STACKS", "GC_ELAPSED_IS_NOT_APPLICATION_PAUSE",
                    "DECODED_IS_NOT_PROOF_OF_COMPLETE_CAPTURE",
                    "CPU_PROFILER_EVENT_FREQUENCY_NOT_CPU_PERCENT",
                    "GC_AGGREGATE_DURATIONS_NOT_WALL_CLOCK_PAUSES",
                    "INDEX_V2_ADDS_DERIVED_PROFILES_WITHOUT_REWRITING_TRACE",
                    "TRACE_UTC_RECONSTRUCTION_NOT_AUTHENTICATED",
                    "TRACE_UTC_DOES_NOT_PROVE_SESSION_CLOCK_ALIGNMENT"]}
        db.execute("INSERT INTO metadata VALUES('summary',?)", (json.dumps(meta, allow_nan=False),))
        db.commit()
        if cancel is not None and cancel.is_set():
            raise InterruptedError("DECODER_CANCELLED")
        db.close()
        db = None
        # Create-new atomically: unlike os.replace, never overwrite an existing file.
        os.link(part, output)
        return meta
    finally:
        if db is not None:
            db.close()
        part.unlink(missing_ok=True)


def read_index(path, *, after=0, mode="events", pid=0, limit=200, search=""):
    if (not _integer(after) or not _integer(pid) or type(limit) is not int or
            not 1 <= limit <= 200 or type(search) is not str or len(search) > 120):
        raise ValueError("INVALID_INDEX_PAGE")
    if mode not in ("events", "stacks", "gc", "cpu_stacks", "gc_summary", "clock", "modules"):
        raise ValueError("INVALID_INDEX_MODE")
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("INVALID_INDEX_FILE")
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2 * 1024 * 1024)
        deadline = time.monotonic() + 1.5
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if db.execute("PRAGMA application_id").fetchone()[0] != APP_ID or version not in (1, 2, 3, 4):
            raise ValueError("INVALID_INDEX_SCHEMA")
        if mode == "modules":
            if version < 4:
                raise ValueError("REDECODE_REQUIRED_FOR_MODULE_IDENTITY")
            result = read_modules(db, after=after, pid=pid, limit=limit, search=search)
            result["summary"] = json.loads(db.execute(
                "SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
            return result
        if mode == "clock" and version < 3:
            raise ValueError("REDECODE_REQUIRED_FOR_CLOCK_VIEW")
        if mode in ("cpu_stacks", "gc_summary"):
            if version < 2:
                raise ValueError("REDECODE_REQUIRED_FOR_INDEX_V2_PROFILES")
            result = read_profiles(db, mode=mode, after=after, pid=pid,
                                   limit=limit, search=search)
            result["summary"] = json.loads(db.execute(
                "SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
            return result
        table = "intervals" if mode == "gc" else "events"
        sql, values = f"SELECT id,data FROM {table} WHERE id>?", [after]
        if pid:
            sql += " AND pid=?"
            values.append(pid)
        if mode == "stacks":
            sql += " AND has_stack=1"
        if mode == "clock":
            sql += " AND utc_time_ns IS NOT NULL"
        # Literal search for event names/providers and derived interval kinds.
        # Wildcards typed by a user must not silently match every event.
        if search.strip():
            needle = search.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern = "%" + needle + "%"
            if mode == "gc":
                sql += " AND kind LIKE ? ESCAPE '\\'"
                values.append(pattern)
            else:
                sql += " AND (name LIKE ? ESCAPE '\\' OR provider LIKE ? ESCAPE '\\')"
                values.extend((pattern, pattern))
        values.append(limit + 1)
        rows = db.execute(sql + " ORDER BY id LIMIT ?", values).fetchall()
        summary = json.loads(db.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
        return {"summary": summary, "rows": [{"index_id": r[0], "event": json.loads(r[1])} for r in rows[:limit]],
                "has_more": len(rows) > limit, "next_cursor": rows[min(len(rows), limit)-1][0] if rows else after}
