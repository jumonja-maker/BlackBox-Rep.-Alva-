"""Versioned, append-only session sidecar with one bounded writer owner.

The schema1 compatibility recording is never migrated in place. This module
receives producer DTOs, not imported files; consumer trust is assigned by the
read-only SessionView, never by a JSON ``source`` string.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import os
from pathlib import Path
from queue import Empty, Full, Queue
import sqlite3
from threading import Event, Lock, Thread
import time
from uuid import uuid4

from .contracts import ObserverError
from .detail_contracts import capture_clock_anchor, MEASUREMENT_STATUSES

FILENAME = "session-v2.sqlite3"
CONTRACT_VERSION = "bb-di-001/session/2.1"
UNITS = {
    "rss_bytes": "bytes", "private_bytes": "bytes", "uss_bytes": "bytes",
    "handle_count": "handles", "cpu_user_s": "seconds",
    "cpu_system_s": "seconds", "cpu_percent": "percentage_of_one_logical_cpu",
    "thread_count": "threads", "read_bytes": "bytes", "write_bytes": "bytes",
    "read_ops": "ops", "write_ops": "ops", "children_total": "processes",
}

DDL = """
PRAGMA user_version=2;
CREATE TABLE sessions (
    session_uuid TEXT PRIMARY KEY, schema_version INTEGER NOT NULL CHECK(schema_version=2),
    contract_version TEXT NOT NULL, started_utc_ns INTEGER NOT NULL,
    monotonic_origin_ns INTEGER NOT NULL, anchor_monotonic_ns INTEGER NOT NULL,
    anchor_utc_ns INTEGER NOT NULL, anchor_uncertainty_ns INTEGER NOT NULL,
    monotonic_resolution_ns INTEGER NOT NULL, clock_source TEXT NOT NULL,
    logical_cpu_count INTEGER, status TEXT NOT NULL, ended_monotonic_ns INTEGER,
    exit_code TEXT, writer_dropped_commands INTEGER NOT NULL DEFAULT 0);
CREATE TABLE targets (
    target_id INTEGER PRIMARY KEY CHECK(target_id=1), session_uuid TEXT NOT NULL REFERENCES sessions,
    root_pid INTEGER NOT NULL CHECK(root_pid>0), root_creation_time REAL NOT NULL,
    executable_name TEXT, source_kind TEXT NOT NULL, verification_class TEXT NOT NULL);
CREATE TABLE process_instances (
    instance_id INTEGER PRIMARY KEY, pid INTEGER NOT NULL CHECK(pid>0),
    creation_time REAL NOT NULL CHECK(creation_time>0), parent_pid INTEGER,
    executable_name TEXT, first_observed_ns INTEGER NOT NULL, last_observed_ns INTEGER NOT NULL,
    absence_observed_ns INTEGER, source_kind TEXT NOT NULL,
    UNIQUE(pid,creation_time));
CREATE TABLE samples (
    sample_id INTEGER PRIMARY KEY, instance_id INTEGER NOT NULL REFERENCES process_instances,
    series TEXT NOT NULL, series_seq INTEGER NOT NULL, correlation_key TEXT NOT NULL,
    monotonic_ns INTEGER NOT NULL, capture_started_ns INTEGER NOT NULL,
    capture_ended_ns INTEGER NOT NULL, writer_recorded_ns INTEGER NOT NULL,
    requested_interval_ns INTEGER NOT NULL, utc_estimate_ns INTEGER NOT NULL,
    rss_bytes INTEGER, private_bytes INTEGER, uss_bytes INTEGER, handle_count INTEGER,
    cpu_user_s REAL, cpu_system_s REAL, cpu_percent REAL, thread_count INTEGER,
    read_bytes INTEGER, write_bytes INTEGER, read_ops INTEGER, write_ops INTEGER,
    children_total INTEGER, threads_omitted INTEGER, children_omitted INTEGER,
    UNIQUE(instance_id,series,series_seq));
CREATE INDEX ix_v2_samples_interval ON samples(instance_id,series,monotonic_ns);
CREATE INDEX ix_v2_samples_time ON samples(monotonic_ns,sample_id);
CREATE TABLE measurements_quality (
    sample_id INTEGER NOT NULL REFERENCES samples, metric TEXT NOT NULL,
    measurement_status TEXT NOT NULL, source_kind TEXT NOT NULL,
    verification_class TEXT NOT NULL, unit TEXT NOT NULL, reason TEXT,
    accuracy TEXT NOT NULL, resolution_ns INTEGER NOT NULL, privilege_level TEXT NOT NULL,
    PRIMARY KEY(sample_id,metric));
CREATE TABLE thread_samples (
    sample_id INTEGER NOT NULL REFERENCES samples, tid INTEGER NOT NULL CHECK(tid>0),
    cpu_user_s REAL NOT NULL CHECK(cpu_user_s>=0),
    cpu_system_s REAL NOT NULL CHECK(cpu_system_s>=0),
    identity_quality TEXT NOT NULL, PRIMARY KEY(sample_id,tid));
CREATE INDEX ix_v2_threads_tid ON thread_samples(tid,sample_id);
CREATE TABLE child_process_samples (
    parent_sample_id INTEGER NOT NULL REFERENCES samples,
    child_sample_id INTEGER NOT NULL REFERENCES samples,
    PRIMARY KEY(parent_sample_id,child_sample_id));
CREATE TABLE windows (
    window_id INTEGER PRIMARY KEY, instance_id INTEGER NOT NULL REFERENCES process_instances,
    hwnd INTEGER NOT NULL, tid INTEGER NOT NULL, visible INTEGER NOT NULL,
    first_observed_ns INTEGER NOT NULL, last_observed_ns INTEGER NOT NULL,
    absence_observed_ns INTEGER, source_kind TEXT NOT NULL);
CREATE TABLE events (
    event_id INTEGER PRIMARY KEY, recorded_ns INTEGER NOT NULL, observed_ns INTEGER,
    instance_id INTEGER REFERENCES process_instances, event_type TEXT NOT NULL,
    source_kind TEXT NOT NULL, verification_class TEXT NOT NULL,
    timestamp_precision TEXT NOT NULL, correlation_key TEXT NOT NULL,
    measurement_status TEXT NOT NULL, detail_json TEXT NOT NULL);
CREATE INDEX ix_v2_events_time ON events(recorded_ns,event_id);
CREATE INDEX ix_v2_events_observed ON events(coalesce(observed_ns,recorded_ns),event_id);
CREATE INDEX ix_v2_events_type ON events(event_type,recorded_ns);
CREATE TABLE action_intervals (
    action_id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL, state TEXT NOT NULL,
    prepared_ns INTEGER, start_ns INTEGER, end_ns INTEGER, completed_ns INTEGER,
    verification_class TEXT NOT NULL);
CREATE TABLE experiments (
    experiment_id TEXT PRIMARY KEY, scenario_name TEXT, scenario_version TEXT,
    application_version TEXT, profile_json TEXT NOT NULL,
    metadata_status TEXT NOT NULL);
CREATE TABLE experiment_runs (
    experiment_id TEXT NOT NULL REFERENCES experiments,
    action_id TEXT NOT NULL REFERENCES action_intervals, attempt_order INTEGER NOT NULL,
    status TEXT NOT NULL, PRIMARY KEY(experiment_id,action_id),
    UNIQUE(experiment_id,attempt_order));
CREATE TABLE incidents (
    incident_id INTEGER PRIMARY KEY, trigger_code TEXT NOT NULL,
    start_ns INTEGER NOT NULL, end_ns INTEGER, status TEXT NOT NULL,
    primary_event_id INTEGER NOT NULL REFERENCES events,
    context_json TEXT NOT NULL, root_cause TEXT NOT NULL DEFAULT 'UNKNOWN');
CREATE TABLE artifacts (
    artifact_id INTEGER PRIMARY KEY, kind TEXT NOT NULL, filename TEXT NOT NULL,
    sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, privacy_level TEXT NOT NULL,
    creator TEXT NOT NULL, consent_record TEXT, coverage_json TEXT NOT NULL);
CREATE TABLE sensor_errors (
    error_id INTEGER PRIMARY KEY, monotonic_ns INTEGER NOT NULL, sensor_id TEXT NOT NULL,
    code TEXT NOT NULL, win32_code INTEGER, detail_safe TEXT);
CREATE INDEX ix_v2_errors_time ON sensor_errors(monotonic_ns);
CREATE TABLE capabilities (
    capability_id TEXT PRIMARY KEY, source_id TEXT NOT NULL,
    privilege_level TEXT NOT NULL, requires_optin INTEGER NOT NULL,
    supported_os TEXT NOT NULL, accuracy_notes TEXT NOT NULL,
    failure_reason TEXT);
"""


def safe_path(path: Path) -> Path:
    """Reject symlinks, Windows reparse points and unsafe Windows aliases."""
    path = Path(path).absolute()
    raw = str(path)
    if raw.startswith(("\\\\", "//")) or "\x00" in raw:
        raise ValueError("UNSAFE_SESSION_PATH")
    for part in path.parts[1:]:
        if ":" in part or part.endswith((" ", ".")):
            raise ValueError("UNSAFE_SESSION_PATH")
    for item in (path, *path.parents):
        try:
            st = item.lstat()
        except FileNotFoundError:
            continue
        if item.is_symlink() or getattr(st, "st_file_attributes", 0) & 0x400:
            raise ValueError("UNSAFE_SESSION_PATH")
    return path


@dataclass
class _Command:
    kind: str
    payload: str
    done: Event = field(default_factory=Event)
    failed: bool = False


class SessionV2Writer:
    """One SQLite owner, immutable messages and finite queue/disk budgets.

    submit() does not wait for disk. User command durability remains provided
    by the existing primary journal; finish() is the v2 durability barrier.
    A failed/overflowed mirror is explicit and must never be certified complete.
    """

    def __init__(self, folder: Path, *, pid: int, created: float, name: str | None,
                 origin_ns: int, capacity: int = 64, max_bytes: int = 256*1024*1024):
        if (type(pid) is not int or pid <= 0 or type(origin_ns) is not int or origin_ns < 0
                or type(created) not in (int, float) or not math.isfinite(created) or created <= 0
                or type(capacity) is not int or not 1 <= capacity <= 256
                or type(max_bytes) is not int or max_bytes < 1024):
            raise ValueError("INVALID_V2_CONTEXT")
        self.folder = safe_path(folder)
        self.path = safe_path(self.folder / FILENAME)
        self.pid, self.created, self.name = pid, created, str(name)[:96] if name is not None else None
        self.origin_ns = origin_ns
        self.anchor = capture_clock_anchor()
        self.session_uuid = str(uuid4())
        self.max_bytes = max_bytes
        self._commands: Queue[_Command | None] = Queue(capacity)
        self._gate = Lock()
        self._closed = False
        self._finish_data: dict | None = None
        self.failure: str | None = None
        self.dropped_commands = 0
        self._sequences: dict[str, int] = {}
        self._ready = Event()
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        self.thread = Thread(target=self._run, name="blackbox-schema2-writer", daemon=True)
        self.thread.start()

    def submit(self, kind: str, payload: dict) -> None:
        if kind not in ("base", "detail", "event", "error", "windows"):
            raise ValueError("INVALID_V2_COMMAND")
        encoded = json.dumps(payload, ensure_ascii=True, allow_nan=False,
                             separators=(",", ":"))
        if len(encoded) > (512*1024 if kind in ("detail","windows") else 16384):
            raise ValueError("V2_COMMAND_SIZE_LIMIT")
        with self._gate:
            if self._closed or self.failure or not self.thread.is_alive():
                raise ObserverError("STORAGE_ERROR", "storage")
            try:
                self._commands.put_nowait(_Command(kind, encoded))
            except Full:
                self.dropped_commands += 1
                self.failure = "V2_QUEUE_OVERFLOW"
                raise ObserverError("STORAGE_ERROR", "storage") from None

    def finish(self, code: str, *, timeout: float = 5.0) -> None:
        with self._gate:
            if not self._closed:
                self._finish_data = {"code": code, "ended_ns": time.monotonic_ns()}
                self._closed = True
        # The owner drains all accepted commands before closing; no sentinel
        # can get stuck behind a full queue. A timed-out owner stays referenced.
        self.thread.join(timeout)
        if self.thread.is_alive():
            self.failure = self.failure or "V2_FINISH_TIMEOUT"
        if self.thread.is_alive() or self.failure:
            raise ObserverError("STORAGE_ERROR", "storage")

    def _initialize(self, db: sqlite3.Connection) -> None:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.executescript(DDL)
        resolution = max(1, math.ceil(time.get_clock_info("monotonic").resolution*1e9))
        self.clock_resolution_ns=resolution
        db.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            self.session_uuid, 2, CONTRACT_VERSION,
            self.anchor.estimate_utc_ns(self.origin_ns), self.origin_ns,
            self.anchor.monotonic_ns, self.anchor.utc_ns, self.anchor.uncertainty_ns,
            resolution, self.anchor.source, os.cpu_count(), "RECORDING", None, None, 0,
        ))

    def _instance(self, db, pid, created, stamp, *, parent=None, name=None):
        if (type(pid) is not int or pid <= 0 or type(created) not in (int,float)
                or not math.isfinite(created) or created <= 0):
            raise ValueError("INVALID_PROCESS_INSTANCE")
        db.execute("""INSERT INTO process_instances
            (pid,creation_time,parent_pid,executable_name,first_observed_ns,last_observed_ns,source_kind)
            VALUES (?,?,?,?,?,?,'PSUTIL') ON CONFLICT(pid,creation_time) DO UPDATE SET
            last_observed_ns=max(last_observed_ns,excluded.last_observed_ns),
            absence_observed_ns=NULL""", (pid,created,parent,name,stamp,stamp))
        return db.execute("SELECT instance_id FROM process_instances WHERE pid=? AND creation_time=?",
                          (pid,created)).fetchone()[0]

    def _sample(self, db, data, series, *, parent_sample=None):
        stamp = data["time_ns"]
        if type(stamp) is not int or stamp < self.origin_ns:
            raise ValueError("INVALID_SAMPLE_CLOCK")
        began = data.get("capture_started_ns", stamp-data.get("sampling_duration_ns",0))
        ended = data.get("capture_ended_ns", stamp)
        if not (type(began) is int and type(ended) is int and 0 <= began <= stamp <= ended):
            raise ValueError("INVALID_CAPTURE_BRACKET")
        pid, created = data.get("pid",self.pid), data.get("created",self.created)
        instance = self._instance(db,pid,created,stamp,parent=data.get("parent_pid"),
                                  name=data.get("name"))
        sequence_key = f"{instance}:{series}"
        seq = self._sequences.get(sequence_key,0)+1
        interval_ns = data.get("requested_interval_ns",2_000_000_000)
        if type(interval_ns) is not int or interval_ns <= 0:
            raise ValueError("INVALID_SAMPLE_INTERVAL")
        values = []
        for key in UNITS:
            value = data.get(key)
            if value is not None and (type(value) not in (int,float)
                    or not math.isfinite(value) or value < 0):
                raise ValueError("INVALID_SAMPLE_COUNTER")
            values.append(value)
        columns = ("instance_id","series","series_seq","correlation_key","monotonic_ns",
                   "capture_started_ns","capture_ended_ns","writer_recorded_ns","requested_interval_ns",
                   "utc_estimate_ns",*UNITS,"threads_omitted","children_omitted")
        params = (instance,series,seq,str(data.get("correlation_key",f"{series}:{seq}"))[:128],stamp,
                  began,ended,time.monotonic_ns(),interval_ns,self.anchor.estimate_utc_ns(stamp),
                  *values,data.get("threads_omitted"),data.get("children_omitted"))
        sample_id = db.execute("INSERT INTO samples ("+",".join(columns)+") VALUES ("+
                               ",".join("?" for _ in columns)+")",params).lastrowid
        self._sequences[sequence_key] = seq
        status_map = data.get("field_status",{})
        for key, value in zip(UNITS,values):
            status = status_map.get(key,"OK" if value is not None else "NOT_OBSERVED")
            if status not in {"OK","NOT_OBSERVED","UNSUPPORTED","ACCESS_DENIED",
                              "SENSOR_TIMEOUT","SAMPLED_GAP","TRUNCATED","INVALID","NOT_APPLICABLE"}:
                raise ValueError("INVALID_FIELD_STATUS")
            if (status=="OK") != (value is not None):
                raise ValueError("INCONSISTENT_FIELD_STATUS")
            db.execute("INSERT INTO measurements_quality VALUES (?,?,?,?,?,?,?,?,?,?)", (
                sample_id,key,status,"PSUTIL","DERIVED" if key=="cpu_percent" else "OS_OBSERVED",UNITS[key],
                None if status=="OK" else status,
                "PSUTIL_INTERNAL_DELTA_INTERVAL" if key=="cpu_percent" else "COUNTER_SNAPSHOT",
                max(self.clock_resolution_ns,ended-began),"CURRENT_USER"))
        if series=="DETAILED":
            for metric,key,unit in (("thread_counters","thread_capture_status","cumulative_cpu_seconds"),
                                    ("child_counters","child_capture_status","process_instances")):
                status=data.get(key,"NOT_OBSERVED")
                if status not in {"OK","NOT_OBSERVED","ACCESS_DENIED","UNSUPPORTED","TRUNCATED",
                                  "SENSOR_TIMEOUT","SAMPLED_GAP","INVALID","NOT_APPLICABLE"}:
                    raise ValueError("INVALID_CAPTURE_STATUS")
                db.execute("INSERT INTO measurements_quality VALUES (?,?,?,?,?,?,?,?,?,?)",(
                    sample_id,metric,status,"PSUTIL","OS_OBSERVED",unit,
                    None if status=="OK" else status,"COUNTER_SNAPSHOT",
                    max(self.clock_resolution_ns,ended-began),"CURRENT_USER"))
            db.executemany("INSERT INTO thread_samples VALUES (?,?,?,?,?)", (
                (sample_id,t["tid"],t["cpu_user_s"],t["cpu_system_s"],"TID_REUSE_UNVERIFIED")
                for t in data.get("threads",())))
            observed = []
            for child in data.get("children",()):
                child_data = {**child,"time_ns":child.get("time_ns",stamp),
                              "capture_started_ns":child.get("capture_started_ns",began),
                              "capture_ended_ns":child.get("capture_ended_ns",ended),"requested_interval_ns":interval_ns,
                              "parent_pid":child.get("parent_pid",self.pid)}
                child_id,child_instance = self._sample(db,child_data,"CHILD",parent_sample=sample_id)
                observed.append(child_instance)
            if data.get("sensor_status",{}).get("children")=="OK" and not data.get("children_omitted"):
                # Absence is an observation, not an exact exit time. On denied
                # or truncated snapshots, do not manufacture disappearance.
                active = db.execute("SELECT instance_id FROM process_instances WHERE instance_id<>1 "
                                    "AND absence_observed_ns IS NULL").fetchall()
                for (child_instance,) in active:
                    if child_instance not in observed:
                        db.execute("UPDATE process_instances SET absence_observed_ns=? WHERE instance_id=?",
                                   (ended,child_instance))
        if parent_sample is not None:
            db.execute("INSERT INTO child_process_samples VALUES (?,?)",(parent_sample,sample_id))
        return sample_id,instance

    def _event(self, db, data, *, native_source=None):
        stamp = data.pop("_recorded_ns")
        kind = data.get("kind","")
        # This classification is determined by the producer entry point/kind,
        # never trusted from the incoming source/verification_class fields.
        user = kind in ("action_marker","user_problem","user_marker") or (kind=="research_evidence_ref" and data.get("reported_source")=="USER_MARKER")
        source = "USER" if user else "BLACKBOX_OBSERVER"
        verification = "USER_DECLARED" if user else "DERIVED"
        if native_source in ("WIN32","WCT"):
            source,verification=native_source,"OS_OBSERVED"
        observed = data.get("timestamp_monotonic_ns")
        precision = data.get("timestamp_precision","RECORDED_COMMAND_NS")
        if type(observed) is not int:
            ms = data.get("elapsed_ms",data.get("end_ms"))
            observed = self.origin_ns+ms*1_000_000 if type(ms) is int and ms>=0 else None
            precision = "SAMPLE_ELAPSED_MS" if observed is not None else "RECORDED_ONLY"
        code = str(data.get("event",data.get("code",kind)))[:96]
        event_id = db.execute("""INSERT INTO events
            (recorded_ns,observed_ns,instance_id,event_type,source_kind,verification_class,
             timestamp_precision,correlation_key,measurement_status,detail_json)
             VALUES (?,?,1,?,?,?,?,?,?,?)""", (
                 stamp,observed,code,source,verification,precision,
                 str(data.get("action_id",data.get("correlation_key",data.get("kind","event"))))[:128],
                 data.get("measurement_status","OK") if native_source else "OK",
                 json.dumps(data,ensure_ascii=True,allow_nan=False))).lastrowid
        if kind=="action_marker":
            action_id, experiment_id = data["action_id"],data["experiment_id"]
            db.execute("INSERT OR IGNORE INTO experiments VALUES (?,NULL,NULL,NULL,?,'UNSPECIFIED_SCENARIO')",
                       (experiment_id,'{"profile":"RECORDED_PER_SAMPLE"}'))
            db.execute("""INSERT INTO action_intervals
                (action_id,experiment_id,state,verification_class) VALUES (?,?,?,'USER_DECLARED')
                ON CONFLICT(action_id) DO UPDATE SET state=excluded.state""",
                       (action_id,experiment_id,data["state"]))
            column = {"ACTION_PREPARED":"prepared_ns","ACTION_STARTED":"start_ns",
                      "ACTION_ENDED":"end_ns","ACTION_COMPLETED":"completed_ns"}.get(code)
            if column:
                db.execute(f"UPDATE action_intervals SET {column}=? WHERE action_id=?",(observed,action_id))
            db.execute("""INSERT INTO experiment_runs VALUES (?,?,
                (SELECT coalesce(max(attempt_order),0)+1 FROM experiment_runs WHERE experiment_id=?),?)
                ON CONFLICT(experiment_id,action_id) DO UPDATE SET status=excluded.status""",
                       (experiment_id,action_id,experiment_id,data["state"]))
        elif kind=="incident_boundary":
            if code=="AUTO_INCIDENT_STARTED":
                db.execute("INSERT INTO incidents(trigger_code,start_ns,status,primary_event_id,context_json) "
                           "VALUES (?,?,'CAPTURING',?,?)",(data["trigger_code"],observed,event_id,
                                                         json.dumps(data,allow_nan=False)))
            elif code=="AUTO_INCIDENT_COMPLETED":
                start = self.origin_ns+data["start_ms"]*1_000_000
                end = self.origin_ns+data["end_ms"]*1_000_000
                db.execute("UPDATE incidents SET end_ns=?,status=?,context_json=? WHERE "
                           "trigger_code=? AND start_ns=? AND end_ns IS NULL",(
                               end,data["status"],json.dumps(data,allow_nan=False),data["trigger_code"],start))
        return event_id

    def _windows(self,db,data):
        if data["pid"]!=self.pid or abs(data["created"]-self.created)>.000001:
            raise ValueError("WINDOW_TARGET_IDENTITY_MISMATCH")
        windows,events=data["windows"],data["events"]
        if len(windows)>32 or len(events)>80:
            raise ValueError("WINDOW_BATCH_LIMIT")
        stamp=data["time_ns"]
        present=[]
        for window in windows:
            hwnd,tid=window["hwnd"],window["tid"]
            if type(hwnd) is not int or hwnd<=0 or type(tid) is not int or tid<=0:
                raise ValueError("INVALID_WINDOW_IDENTITY")
            present.append((hwnd,tid))
            old=db.execute("SELECT window_id FROM windows WHERE instance_id=1 AND hwnd=? AND tid=? "
                           "AND absence_observed_ns IS NULL",(hwnd,tid)).fetchone()
            if old:
                db.execute("UPDATE windows SET last_observed_ns=?,visible=? WHERE window_id=?",
                           (stamp,int(window["visible"]),old[0]))
            else:
                db.execute("""INSERT INTO windows(instance_id,hwnd,tid,visible,first_observed_ns,
                    last_observed_ns,source_kind) VALUES (1,?,?,?,?,?,'WIN32')""",
                           (hwnd,tid,int(window["visible"]),stamp,stamp))
        if not data.get("enumeration_omitted"):
            for row in db.execute("SELECT window_id,hwnd,tid FROM windows WHERE absence_observed_ns IS NULL").fetchall():
                if (row[1],row[2]) not in present:
                    db.execute("UPDATE windows SET absence_observed_ns=? WHERE window_id=?",(stamp,row[0]))
        db.execute("INSERT OR REPLACE INTO capabilities VALUES "
                   "('window_timeout','WIN32','CURRENT_USER',1,'Windows x64',"
                   "'WM_NULL timeout is an observation, not a proven root cause',NULL)")
        for event in events:
            code=event["code"]
            if code not in {"WINDOW_GONE","UI_UNRESPONSIVE_OBSERVED","UI_RESPONSIVE_AGAIN",
                            "WCT_SNAPSHOT","WINDOW_PROBE_STATUS","WINDOW_PROBE_RESULT","WINDOW_ENUMERATION_STATUS"}:
                raise ValueError("INVALID_NATIVE_EVENT_CODE")
            source="WCT" if code=="WCT_SNAPSHOT" else "WIN32"
            status=event.get("wct",event.get("check",{})).get("status","OK")
            measurement_status=status if status in MEASUREMENT_STATUSES else "NOT_OBSERVED"
            eid=self._event(db,{"_recorded_ns":time.monotonic_ns(),
                "timestamp_monotonic_ns":event["time_ns"],"timestamp_precision":"NATIVE_MONOTONIC_BRACKET",
                "kind":"native_window_observation","code":code,"measurement_status":measurement_status,
                "native_result_status":status,
                "correlation_key":("HWND:"+str(event.get("window",{}).get("hwnd"))+":TID:"+
                                   str(event.get("window",{}).get("tid"))),
                **event},native_source=source)
            if code=="UI_UNRESPONSIVE_OBSERVED":
                db.execute("INSERT INTO incidents(trigger_code,start_ns,status,primary_event_id,context_json) "
                    "VALUES ('UI_TIMEOUT',?,'OBSERVED',?,?)",(event["time_ns"],eid,json.dumps(event)))
            elif code=="UI_RESPONSIVE_AGAIN":
                for row in db.execute("SELECT incident_id,context_json FROM incidents WHERE trigger_code='UI_TIMEOUT' "
                                      "AND end_ns IS NULL").fetchall():
                    prior=json.loads(row[1])
                    if all(prior.get("window",{}).get(k)==event["window"].get(k) for k in ("pid","tid","hwnd")):
                        db.execute("UPDATE incidents SET end_ns=?,status='RECOVERY_OBSERVED' WHERE incident_id=?",
                                   (event["time_ns"],row[0]))
            elif code=="WCT_SNAPSHOT":
                db.execute("INSERT OR REPLACE INTO capabilities VALUES "
                    "('wait_chain','WCT','CURRENT_TOKEN/SE_DEBUG_MAY_BE_REQUIRED',1,'Windows x64',"
                    "'Async bounded wait; dynamic nodes/cycle, no object names',?)",(
                    None if status=="OK" else status,))

    def _run(self):
        db = None
        try:
            db = sqlite3.connect(self.path,timeout=1)
            self._initialize(db)
            db.execute("INSERT INTO targets VALUES (1,?,?,?,?,?,'OS_OBSERVED')",(
                self.session_uuid,self.pid,self.created,self.name,"PSUTIL"))
            self._instance(db,self.pid,self.created,self.origin_ns,name=self.name)
            db.execute("INSERT INTO capabilities VALUES "
                       "('process_counters','PSUTIL','CURRENT_USER',0,'Windows/Linux',"
                       "'External snapshots; between-sample activity may be missed',NULL)")
            db.commit()
            self._ready.set()
            while True:
                try:
                    command = self._commands.get(timeout=.05)
                except Empty:
                    if not self._closed:
                        continue
                    data = self._finish_data
                    code = "STORAGE_ERROR" if self.failure else data["code"]
                    if self.failure:
                        db.execute("INSERT INTO sensor_errors(monotonic_ns,sensor_id,code) VALUES (?,?,?)",
                                   (data["ended_ns"],"SCHEMA2_WRITER",self.failure[:96]))
                    db.execute("UPDATE sessions SET status='CLOSED',ended_monotonic_ns=?,exit_code=?,"
                               "writer_dropped_commands=?",(data["ended_ns"],code,self.dropped_commands))
                    db.commit()
                    db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    return
                try:
                    data = json.loads(command.payload)
                    if self.failure:
                        with self._gate:
                            self.dropped_commands += 1
                        command.failed=True
                        continue
                    storage_bytes=sum(p.stat().st_size for p in (
                        self.path,Path(str(self.path)+"-wal"),Path(str(self.path)+"-shm")) if p.exists())
                    if storage_bytes>=self.max_bytes:
                        raise ValueError("V2_DISK_LIMIT")
                    db.execute("BEGIN IMMEDIATE")
                    if command.kind in ("base","detail"):
                        self._sample(db,data,"STANDARD" if command.kind=="base" else "DETAILED")
                    elif command.kind=="event":
                        self._event(db,data)
                    elif command.kind=="windows":
                        self._windows(db,data)
                    else:
                        db.execute("INSERT INTO sensor_errors(monotonic_ns,sensor_id,code,win32_code) VALUES (?,?,?,?)",
                                   (data["time_ns"],data["sensor_id"],data["code"],data.get("win32_code")))
                    db.commit()
                except Exception as exc:
                    db.rollback()
                    self.failure = str(exc) if isinstance(exc,ValueError) else type(exc).__name__
                    with self._gate:
                        self.dropped_commands += 1
                    command.failed=True
                finally:
                    command.done.set()
                    self._commands.task_done()
        except Exception as exc:
            self.failure = type(exc).__name__
        finally:
            self._ready.set()
            if db is not None:
                db.close()
            while True:
                try:
                    pending=self._commands.get_nowait()
                except Empty:
                    break
                if pending is not None:
                    pending.failed=True
                    pending.done.set()
                self._commands.task_done()
