"""Bounded offline summaries. No CPU-time, pause, or causality is inferred.

Only Microsoft-DotNETCore-SampleProfiler Thread/Sample enters CPU stack
frequency. Ordinary ETW/GC event-associated stacks are NOT CPU samples.
"""
from __future__ import annotations
import hashlib
import json
import math
import sqlite3
from .decoder_limits import check_json_shape
from .decoder_modules import integer, number, validate_module_frame

SAMPLE_PROVIDER = "Microsoft-DotNETCore-SampleProfiler"
SAMPLE_EVENT = "Thread/Sample"
MAX_DISTINCT_STACKS = 8192


class ProfileBuilder:
    def __init__(self, db: sqlite3.Connection):
        self.db = db
        self.cpu_profiler_events = 0
        self.cpu_profiler_events_with_frames = 0
        self.cpu_profiler_events_without_frames = 0
        self.cpu_profiler_events_unindexed = 0
        self.distinct_stacks = 0
        self.unknown_process_instances = 0
        db.executescript("""
        CREATE TABLE stack_profiles (
            id INTEGER PRIMARY KEY, pid INTEGER NOT NULL,
            process_instance INTEGER NOT NULL, identity_quality TEXT NOT NULL,
            signature_sha256 TEXT NOT NULL, sample_count INTEGER NOT NULL,
            first_event_id INTEGER NOT NULL, last_event_id INTEGER NOT NULL,
            first_ms REAL NOT NULL, last_ms REAL NOT NULL,
            frame_count INTEGER NOT NULL, frames_without_names INTEGER NOT NULL,
            stack_status TEXT NOT NULL, frames_json TEXT NOT NULL,
            UNIQUE(pid,process_instance,signature_sha256));
        CREATE INDEX ix_stack_profiles_pid_id ON stack_profiles(pid,id);
        CREATE TABLE gc_profiles (
            id INTEGER PRIMARY KEY, kind TEXT NOT NULL, pid INTEGER NOT NULL,
            process_instance INTEGER NOT NULL, runtime INTEGER,
            generation INTEGER, gc_type TEXT,
            interval_count INTEGER NOT NULL, total_duration_ms REAL NOT NULL,
            max_duration_ms REAL NOT NULL, min_duration_ms REAL NOT NULL,
            first_start_ms REAL NOT NULL, last_end_ms REAL NOT NULL,
            first_event_id INTEGER NOT NULL, last_event_id INTEGER NOT NULL);
        CREATE INDEX ix_gc_profiles_pid_id ON gc_profiles(pid,id);
        """)

    def accept(self, row: dict) -> None:
        if row.get("provider") != SAMPLE_PROVIDER or row.get("name") != SAMPLE_EVENT:
            return
        self.cpu_profiler_events += 1
        frames = row["frames"]
        if not frames:
            self.cpu_profiler_events_without_frames += 1
            return
        self.cpu_profiler_events_with_frames += 1
        instance = row.get("process_instance")
        quality = ("TRACE_PROCESS_INSTANCE_INDEX" if instance is not None else
                   "UNKNOWN_PROCESS_INSTANCE_PID_REUSE_POSSIBLE")
        # Hash the *entire recorded stack* (frames + addresses + clipping).
        # Never group merely by an unverified method name or PID.
        serialized = json.dumps([row.get("stack_status"), frames],
                                ensure_ascii=True, separators=(",", ":"))
        fingerprint = hashlib.sha256(serialized.encode("ascii")).hexdigest()
        pid = row["pid"]
        # No stable instance identity: do NOT coalesce PID-reused events.
        if instance is None:
            self.unknown_process_instances += 1
        identity = instance if instance is not None else -row["ordinal"]
        found = self.db.execute("SELECT id FROM stack_profiles WHERE pid=? AND process_instance=? "
                                "AND signature_sha256=?", (pid, identity, fingerprint)).fetchone()
        if found is not None:
            self.db.execute("UPDATE stack_profiles SET sample_count=sample_count+1, "
                            "last_event_id=?,last_ms=? WHERE id=?",
                            (row["ordinal"], row["time_ms"], found[0]))
        elif self.distinct_stacks < MAX_DISTINCT_STACKS:
            self.db.execute("""INSERT INTO stack_profiles
                (pid,process_instance,identity_quality,signature_sha256,sample_count,
                 first_event_id,last_event_id,first_ms,last_ms,frame_count,
                 frames_without_names,stack_status,frames_json)
                 VALUES (?,?,?,?,1,?,?,?,?,?,?,?,?)""",
                (pid,identity,quality,fingerprint,row["ordinal"],row["ordinal"],
                 row["time_ms"],row["time_ms"],len(frames),
                 sum(not f["name"] for f in frames),str(row.get("stack_status") or "UNKNOWN"),
                 json.dumps(frames,ensure_ascii=True,separators=(",", ":"))))
            self.distinct_stacks += 1
        else:
            self.cpu_profiler_events_unindexed += 1

    def finish(self):
        # Rank once at build; stable count-descending keyset pagination.
        self.db.execute("ALTER TABLE stack_profiles ADD COLUMN display_rank INTEGER")
        ids = list(self.db.execute("SELECT id FROM stack_profiles ORDER BY sample_count DESC,id"))
        for i, (identifier,) in enumerate(ids, 1):
            self.db.execute("UPDATE stack_profiles SET display_rank=? WHERE id=?",
                            (i, identifier))
        self.db.execute("CREATE UNIQUE INDEX ix_stack_profiles_rank ON stack_profiles(display_rank)")
        # Runtime suspension intervals are NOT inferred GC pauses; summed
        # overlapping GC durations are NOT total application wall time.
        self.db.execute("""
        INSERT INTO gc_profiles
            (kind,pid,process_instance,runtime,generation,gc_type,
             interval_count,total_duration_ms,max_duration_ms,min_duration_ms,
             first_start_ms,last_end_ms,first_event_id,last_event_id)
        WITH annotated AS (
            SELECT kind,pid,
                CAST(coalesce(json_extract(data,'$.process_instance'),-1) AS INTEGER) AS process_instance,
                json_extract(data,'$.runtime') AS runtime,
                CASE WHEN kind='GC_ELAPSED_NOT_PAUSE'
                     THEN json_extract(data,'$.details.generation') END AS generation,
                CASE WHEN kind='GC_ELAPSED_NOT_PAUSE'
                     THEN json_extract(data,'$.details.gc_type') END AS gc_type,
                duration_ms,start_ms,
                start_ms+duration_ms AS end_ms,
                json_extract(data,'$.start_event') AS start_event,
                json_extract(data,'$.end_event') AS end_event
            FROM intervals
        )
        SELECT kind,pid,process_instance,runtime,generation,gc_type,
            count(*),sum(duration_ms),max(duration_ms),min(duration_ms),
            min(start_ms),max(end_ms),min(start_event),max(end_event)
        FROM annotated
        GROUP BY kind,pid,process_instance,runtime,generation,gc_type
        ORDER BY max(duration_ms) DESC,kind,pid,process_instance,runtime,generation
        """)
        count = self.db.execute("SELECT count(*) FROM gc_profiles").fetchone()[0]
        return {"cpu_profiler_provider": SAMPLE_PROVIDER,
                "cpu_profiler_event_name": SAMPLE_EVENT,
                "cpu_profiler_samples_recorded": self.cpu_profiler_events,
                "cpu_profiler_samples_with_stacks": self.cpu_profiler_events_with_frames,
                "cpu_profiler_samples_without_stacks": self.cpu_profiler_events_without_frames,
                "cpu_profiler_samples_omitted_from_groups": self.cpu_profiler_events_unindexed,
                "cpu_stack_groups_indexed": self.distinct_stacks,
                "cpu_profiler_samples_without_process_identity": self.unknown_process_instances,
                "cpu_stack_group_limit": MAX_DISTINCT_STACKS,
                "gc_summary_groups": count,
                "cpu_sample_interval_and_cpu_percent": "NOT_ESTABLISHED",
                "clock_alignment_to_session": "NOT_ESTABLISHED",
                "causality": "NOT_ESTABLISHED",
                "source_scope": "UNVERIFIED_TRACE_IMPORT"}


def _require_profile(value):
    if not value:
        raise ValueError("INVALID_INDEX_PROFILE")


def _profile_frames(raw):
    from .decoder_index import MAX_LINE, _pairs
    _require_profile(type(raw) is str and len(raw)<=MAX_LINE*6)
    try:
        frames = json.loads(raw, object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("NONFINITE_JSON")))
    except (RecursionError, json.JSONDecodeError) as error:
        raise ValueError("INVALID_INDEX_PROFILE") from error
    check_json_shape(frames)
    _require_profile(type(frames) is list and 1<=len(frames)<=128)
    return frames


def read_profiles(db: sqlite3.Connection, *, mode: str, after: int,
                  pid: int, limit: int, search: str, max_events=250000):
    if mode == "cpu_stacks":
        sql = ("SELECT display_rank,id,pid,process_instance,identity_quality,signature_sha256,"
               "sample_count,first_event_id,last_event_id,first_ms,last_ms,frame_count,"
               "frames_without_names,stack_status,frames_json FROM stack_profiles WHERE display_rank>?")
        values = [after]
        if pid:
            sql += " AND pid=?"
            values.append(pid)
        if search.strip():
            escaped = search.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            # Search decoded frame values, not JSON keys or ensure_ascii
            # escape sequences. JSON1 is already required by profile indexes;
            # this also reads existing v2/v3/v4 indexes without rewriting them.
            sql += (" AND EXISTS (SELECT 1 FROM json_each(stack_profiles.frames_json) AS frame "
                    "WHERE json_extract(frame.value,'$.name') LIKE ? ESCAPE '\\' "
                    "OR json_extract(frame.value,'$.address') LIKE ? ESCAPE '\\')")
            values.extend(("%"+escaped+"%", "%"+escaped+"%"))
        values.append(limit+1)
        rows = db.execute(sql+" ORDER BY display_rank LIMIT ?", values).fetchall()
        items = []
        for row in rows[:limit]:
            (rank,identifier,pid,instance,quality,hash_value,count,first,last,
             first_ms,last_ms,frame_count,unnamed,status,frames) = row
            _require_profile(integer(rank,1,MAX_DISTINCT_STACKS) and integer(identifier,1,MAX_DISTINCT_STACKS) and
                integer(pid,-1) and integer(instance,-max_events) and integer(count,1,max_events) and
                integer(first,1,max_events) and integer(last,first,max_events) and count<=last-first+1 and
                number(first_ms) and number(last_ms) and type(status) is str and len(status)<=512 and
                type(hash_value) is str and len(hash_value)==64 and
                (quality=="TRACE_PROCESS_INSTANCE_INDEX" if instance>=0 else
                 quality=="UNKNOWN_PROCESS_INSTANCE_PID_REUSE_POSSIBLE" and count==1 and first==last and instance==-first))
            frames = _profile_frames(frames)
            _require_profile(frame_count==len(frames) and type(frame_count) is int and
                type(unnamed) is int and unnamed==sum(not frame.get("name") for frame in frames if type(frame) is dict))
            from .decoder_index import validate_event
            synthetic = {"type":"event","ordinal":first,"pid":pid,"tid":0,"time_ms":first_ms,
                "process_instance":instance if instance>=0 else None,"provider":SAMPLE_PROVIDER,"name":SAMPLE_EVENT,
                "payload":{},"frames":frames,"stack_status":status}
            validate_event(synthetic,first)
            for frame in frames:
                validate_module_frame(synthetic,frame)
                validate_module_frame({**synthetic,"time_ms":last_ms},frame)
            candidates = (status,None,"") if status=="UNKNOWN" else (status,)
            _require_profile(any(hashlib.sha256(json.dumps([state,frames],ensure_ascii=True,
                separators=(",", ":")).encode("ascii")).hexdigest()==hash_value for state in candidates))
            items.append({"index_id":rank,"event":{
                "type":"CPU_PROFILER_RECORDED_STACK_GROUP","pid":pid,
                "process_instance":instance if instance>=0 else None,
                "identity_quality":quality,"provider":SAMPLE_PROVIDER,
                "name":SAMPLE_EVENT,"time_ms":first_ms,
                "first_time_ms":first_ms,"last_time_ms":last_ms,
                "recorded_sample_count":count,"first_event_id":first,"last_event_id":last,
                "stack_signature_sha256":hash_value,"frames":frames,
                "frame_count":frame_count,"frames_without_names":unnamed,"stack_status":status,
                "measurement":"EVENT_OCCURRENCES_NOT_CPU_TIME_OR_CPU_PERCENT",
                "verification_class":"UNVERIFIED_IMPORT","root_cause":"UNKNOWN"}})
        cursor = items[-1]["index_id"] if items else after
    elif mode == "gc_summary":
        sql = ("SELECT id,kind,pid,process_instance,runtime,generation,gc_type,interval_count,"
               "total_duration_ms,max_duration_ms,min_duration_ms,first_start_ms,last_end_ms,"
               "first_event_id,last_event_id FROM gc_profiles WHERE id>?")
        values = [after]
        if pid:
            sql += " AND pid=?"
            values.append(pid)
        if search.strip():
            escaped = search.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            sql += " AND (kind LIKE ? ESCAPE '\\' OR gc_type LIKE ? ESCAPE '\\')"
            values.extend(("%"+escaped+"%", "%"+escaped+"%"))
        values.append(limit+1)
        rows = db.execute(sql+" ORDER BY id LIMIT ?",values).fetchall()
        items = []
        for row in rows[:limit]:
            (rank,kind,pid,instance,runtime,generation,gc_type,count,total,peak,minimum,
             first,last,first_id,last_id) = row
            def duration(value):
                return type(value) in (int,float) and 0<=value<=max_events*2e15 and math.isfinite(value)
            _require_profile(integer(rank,1,max_events) and
                kind in ("GC_ELAPSED_NOT_PAUSE","RUNTIME_SUSPENSION_ENVELOPE","RUNTIME_FULLY_SUSPENDED") and
                integer(pid,-1) and integer(instance,0) and integer(runtime,0) and
                (generation is None or integer(generation,0)) and
                (gc_type is None or type(gc_type) in (str,int) and (type(gc_type) is int or len(gc_type)<=512)) and
                integer(count,1,max_events) and all(duration(value) for value in (total,peak,minimum)) and
                minimum<=peak and peak<=total and
                number(first) and number(last) and first<=last and
                integer(first_id,1,max_events) and integer(last_id,first_id,max_events))
            items.append({"index_id":rank,"event":{
                "type":"DERIVED_GC_INTERVAL_AGGREGATE","pid":pid,
                "process_instance":instance if instance>=0 else None,
                "runtime":runtime,"generation":generation,"gc_type":gc_type,
                "provider":"DERIVED_FROM_TYPED_CLR_EVENTS","name":kind,"kind":kind,
                "time_ms":first,"first_time_ms":first,"last_time_ms":last,
                "interval_count":count,"total_pair_duration_ms":total,
                "peak_pair_duration_ms":peak,"minimum_pair_duration_ms":minimum,
                "first_event_id":first_id,"last_event_id":last_id,
                "measurement":"SUM_OF_OBSERVED_PAIRS_NOT_WALL_TIME",
                "is_application_pause":False if kind=="GC_ELAPSED_NOT_PAUSE" else None,
                "verification_class":"UNVERIFIED_IMPORT","root_cause":"UNKNOWN"}})
        cursor = items[-1]["index_id"] if items else after
    else:
        raise ValueError("INVALID_PROFILE_MODE")
    return {"rows":items,"has_more":len(rows)>limit,"next_cursor":cursor}
