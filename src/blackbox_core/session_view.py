"""Read-only schema1/schema2 sessions, streaming intervals and bounded plots.

No imported source string authenticates evidence. Recorded producer metadata
is preserved separately from the consumer's UNVERIFIED_IMPORT trust boundary.
SQLite sorts/aggregates may spill to temporary disk; Python never accumulates
the complete history or a dictionary containing every historic TID.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
from pathlib import Path
import sqlite3
import time

from .session_v2 import CONTRACT_VERSION, FILENAME, UNITS, safe_path


class SessionReadError(ValueError):
    pass


def _number(value):
    return (type(value) in (int,float) and math.isfinite(value) and value>=0)


def _validated_process_instance(raw):
    """Validate imported scalar metadata before hierarchy arithmetic or Qt."""
    row=dict(raw)
    identity,pid=row["instance_id"],row["pid"]
    parent,created=row["parent_pid"],row["creation_time"]
    first,last=row["first_observed_ns"],row["last_observed_ns"]
    absent=row["absence_observed_ns"]
    if (type(identity) is not int or identity<=0 or type(pid) is not int or pid<=0
            or (parent is not None and (type(parent) is not int or parent<0))
            or type(created) not in (int,float) or not math.isfinite(created) or created<=0
            or type(first) is not int or first<0 or type(last) is not int or last<first
            or (absent is not None and (type(absent) is not int or absent<last))):
        raise SessionReadError("INVALID_IMPORTED_PROCESS_INSTANCE")
    return row


@dataclass
class _Stats:
    count: int = 0
    missing: int = 0
    minimum: float | None = None
    maximum: float | None = None
    mean: float = 0.0
    first: float | None = None
    last: float | None = None

    def observe(self,value):
        if not _number(value):
            self.missing+=1
            return
        self.count+=1
        self.first=value if self.first is None else self.first
        self.last=value
        self.minimum=value if self.minimum is None else min(self.minimum,value)
        self.maximum=value if self.maximum is None else max(self.maximum,value)
        self.mean+=(value-self.mean)/self.count

    def result(self,unit):
        return {"unit":unit,"observed_count":self.count,"missing_count":self.missing,
                "min":self.minimum,"max":self.maximum,"mean":self.mean if self.count else None,
                "first":self.first,"last":self.last,
                "delta":self.last-self.first if self.count>=2 else None}


class _Reader:
    def __init__(self,path: Path,*,cancel=None,timeout_s=30):
        self.path=safe_path(path)
        if not self.path.is_file() or self.path.stat().st_size>2*1024**3:
            raise SessionReadError("SESSION_UNAVAILABLE_OR_SIZE_LIMIT")
        self.db=sqlite3.connect(self.path.as_uri()+"?mode=ro",uri=True,timeout=.5)
        self.db.row_factory=sqlite3.Row
        self.db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,1024*1024)
        self.db.execute("PRAGMA query_only=ON")
        self.db.execute("PRAGMA trusted_schema=OFF")
        self.db.execute("PRAGMA cache_size=-4096")
        self.db.execute("PRAGMA temp_store=FILE")
        self._cancel=cancel
        self._timeout_s=timeout_s
        self._deadline=time.monotonic()+timeout_s
        self.db.set_progress_handler(lambda: int(time.monotonic()>self._deadline or
            (self._cancel is not None and self._cancel())),10000)
        self.db.execute("BEGIN")

    def renew_deadline(self):
        self._deadline=time.monotonic()+self._timeout_s

    def close(self):
        self.db.close()


class SchemaV1Reader(_Reader):
    def __init__(self,path,**kwargs):
        super().__init__(path,**kwargs)
        try:
            cols=tuple(r[1] for r in self.db.execute("PRAGMA table_info(samples)"))
            expected=("seq","elapsed_ms","rss_bytes","cpu_percent","num_threads",
                      "read_bytes","write_bytes","children_count")
            if cols!=expected:
                raise SessionReadError("UNSUPPORTED_SCHEMA1")
            rows=self.db.execute("SELECT * FROM metadata LIMIT 2").fetchall()
            if len(rows)!=1 or rows[0]["schema_version"]!=1:
                raise SessionReadError("UNSUPPORTED_SCHEMA1")
            meta=dict(rows[0])
            self.metadata={"schema_version":1,"session_uuid":meta["session_id"],
                "pid":meta["pid"],"creation_time":None,"monotonic_origin_ns":0,
                "recorded_status":meta["exit_code"],"file_trust":"UNVERIFIED_IMPORT",
                "clock_quality":"LEGACY_ELAPSED_MS_ONLY","warnings":["LEGACY_LIMITED_DATA"],
                "capabilities":["PROCESS_CPU_PERCENT","RSS","IO_BYTES","THREAD_COUNT"]}
        except Exception:
            self.close()
            raise

    def bounds(self,series="STANDARD",instance_id=1):
        row=self.db.execute("SELECT min(elapsed_ms),max(elapsed_ms),count(*) FROM samples").fetchone()
        return ((row[0]*1_000_000 if row[0] is not None else None),
                (row[1]*1_000_000 if row[1] is not None else None),row[2])

    def iter_samples(self,start,end,*,series="STANDARD",instance_id=1):
        # No index may be added to a historic file. This is a streaming scan
        # on v1; v2 uses ix_v2_samples_interval. Unsupported fields stay NULL.
        cursor=self.db.execute("SELECT * FROM samples WHERE elapsed_ms BETWEEN ? AND ? ORDER BY seq",
                               ((start+999999)//1_000_000,end//1_000_000))
        for raw in cursor:
            row={k:None for k in UNITS}
            row.update(dict(raw))
            row.update(time_ns=raw["elapsed_ms"]*1_000_000,series_seq=raw["seq"],
                       thread_count=raw["num_threads"],children_total=raw["children_count"],
                       requested_interval_ns=None)
            if any(row[k] is not None and not _number(row[k]) for k in UNITS):
                raise SessionReadError("INVALID_IMPORTED_COUNTER")
            yield row


class SchemaV2Reader(_Reader):
    def __init__(self,path,**kwargs):
        super().__init__(path,**kwargs)
        try:
            rows=self.db.execute("SELECT * FROM sessions LIMIT 2").fetchall()
            if (len(rows)!=1 or rows[0]["schema_version"]!=2 or
                    rows[0]["contract_version"] not in (CONTRACT_VERSION,"bb-di-001/session/2.0")):
                raise SessionReadError("UNSUPPORTED_SCHEMA2_CONTRACT")
            meta=dict(rows[0])
            targets=self.db.execute("SELECT * FROM targets LIMIT 2").fetchall()
            if len(targets)!=1 or targets[0]["session_uuid"]!=meta["session_uuid"]:
                raise SessionReadError("INVALID_SCHEMA2_TARGET")
            target=dict(targets[0])
            self.metadata={**meta,"pid":target["root_pid"],"creation_time":target["root_creation_time"],
                "executable_name":target["executable_name"],"file_trust":"UNVERIFIED_IMPORT",
                "recorded_verification_class":target["verification_class"],
                "verification_class":"UNVERIFIED_IMPORT","clock_quality":"ANCHORED_UTC_ESTIMATE",
                "clock_uncertainty_model":("BRACKET_PLUS_REPORTED_CLOCK_RESOLUTIONS" if
                    meta["contract_version"]==CONTRACT_VERSION else "LEGACY_BRACKET_MODEL_NOT_REATTESTED"),
                "recorded_status":meta["status"],
                "warnings":["SOURCE_FILE_NOT_AUTHENTICATED","TID_REUSE_CANNOT_BE_EXCLUDED",
                            "SYSTEM_CLOCK_CAN_ADJUST_AFTER_ANCHOR"],
                "capabilities":[dict(r) for r in self.db.execute("SELECT * FROM capabilities LIMIT 64")]}
            self.root_instance=self.db.execute("SELECT instance_id FROM process_instances WHERE pid=? "
                "AND creation_time=?",(target["root_pid"],target["root_creation_time"])).fetchone()[0]
        except Exception:
            self.close()
            raise

    def bounds(self,series="STANDARD",instance_id=1):
        return tuple(self.db.execute("SELECT min(monotonic_ns),max(monotonic_ns),count(*) "
            "FROM samples WHERE instance_id=? AND series=?",(instance_id,series)).fetchone())

    def iter_samples(self,start,end,*,series="STANDARD",instance_id=1):
        cursor=self.db.execute("SELECT * FROM samples WHERE instance_id=? AND series=? AND "
            "monotonic_ns BETWEEN ? AND ? ORDER BY monotonic_ns,sample_id",(instance_id,series,start,end))
        for raw in cursor:
            row=dict(raw)
            row["time_ns"]=row["monotonic_ns"]
            if any(row[k] is not None and not _number(row[k]) for k in UNITS):
                raise SessionReadError("INVALID_IMPORTED_COUNTER")
            yield row


class SessionView:
    def __init__(self,reader):
        self.reader=reader
        self.metadata=reader.metadata
        self.db=reader.db
        self.is_v2=isinstance(reader,SchemaV2Reader)

    @classmethod
    def open(cls,folder: Path,**kwargs):
        folder=safe_path(folder)
        try:
            path=folder/FILENAME
            if path.exists():
                return cls(SchemaV2Reader(path,**kwargs))
            return cls(SchemaV1Reader(folder/"session.sqlite3",**kwargs))
        except (sqlite3.Error,OSError,KeyError,TypeError,IndexError) as exc:
            raise SessionReadError("INVALID_OR_UNSUPPORTED_SESSION") from exc

    def __enter__(self):
        return self

    def __exit__(self,*args):
        self.reader.close()

    def bounds(self,series="STANDARD",instance_id=1):
        return self.reader.bounds(series,instance_id)

    def _range(self,start,end,series,instance_id):
        lo,hi,total=self.bounds(series,instance_id)
        if self.is_v2:
            # Include command/incident tails after the last periodic sample.
            # No resource measurement is invented for these unsampled tails.
            event_lo,event_hi=self.db.execute("SELECT min(coalesce(observed_ns,recorded_ns)),"
                                             "max(coalesce(observed_ns,recorded_ns)) FROM events").fetchone()
            lo=min(x for x in (lo,event_lo,self.metadata["monotonic_origin_ns"]) if x is not None)
            hi=max(x for x in (hi,event_hi,self.metadata.get("ended_monotonic_ns"),lo) if x is not None)
        start=lo if start is None else start
        end=hi if end is None else end
        if total==0 and not self.is_v2:
            return 0,0,0
        if (type(start) is not int or type(end) is not int or start<0 or end<start):
            raise SessionReadError("INVALID_INTERVAL")
        return start,end,total

    def interval(self,start_ns=None,end_ns=None,*,series="STANDARD",instance_id=1,buckets=256):
        if type(buckets) is not int or not 1<=buckets<=2000:
            raise SessionReadError("INVALID_BUCKET_COUNT")
        self.reader.renew_deadline()
        start,end,total=self._range(start_ns,end_ns,series,instance_id)
        units={**UNITS,"read_bps":"bytes/s","write_bps":"bytes/s",
               "cpu_interval_percent":"percentage_of_one_logical_cpu"}
        stats={k:_Stats() for k in units}
        tracks=("cpu_interval_percent","rss_bytes","private_bytes","uss_bytes",
                "handle_count","read_bps","write_bps","thread_count","children_total")
        plot={k:{} for k in tracks}
        segments={k:0 for k in tracks}
        previous=None
        count=0
        gaps=0
        resets=0
        observed_duration=0
        covered_cpu_seconds=0.0
        cpu_pairs=0
        expected_slots_estimate=0
        first_time=last_time=None
        for row in self.reader.iter_samples(start,end,series=series,instance_id=instance_id):
            stamp=row["time_ns"]
            if type(stamp) is not int or stamp<0:
                raise SessionReadError("INVALID_SAMPLE_CLOCK")
            count+=1
            first_time=stamp if first_time is None else first_time
            last_time=stamp
            derived={"read_bps":None,"write_bps":None,"cpu_interval_percent":None}
            continuous=False
            if previous is not None:
                dt=stamp-previous["time_ns"]
                interval=row.get("requested_interval_ns")
                old_interval=previous.get("requested_interval_ns")
                spacing_ok=(interval is None or dt<=max(2*interval,interval+500_000_000))
                continuous=(dt>0 and row["series_seq"]==previous["series_seq"]+1 and spacing_ok)
                if interval and interval==old_interval and dt>0:
                    expected_slots_estimate+=max(1,dt//interval)
                if continuous:
                    observed_duration+=dt
                    for raw_key,out_key in (("read_bytes","read_bps"),("write_bytes","write_bps")):
                        a,b=previous.get(raw_key),row.get(raw_key)
                        if _number(a) and _number(b):
                            if b>=a:
                                derived[out_key]=(b-a)*1e9/dt
                            else:
                                resets+=1
                    old_cpu=(previous.get("cpu_user_s"),previous.get("cpu_system_s"))
                    cpu=(row.get("cpu_user_s"),row.get("cpu_system_s"))
                    if all(_number(v) for v in (*old_cpu,*cpu)):
                        if cpu[0]>=old_cpu[0] and cpu[1]>=old_cpu[1]:
                            delta=cpu[0]-old_cpu[0]+cpu[1]-old_cpu[1]
                            derived["cpu_interval_percent"]=100*delta*1e9/dt
                            covered_cpu_seconds+=delta
                            cpu_pairs+=1
                        else:
                            resets+=1
                else:
                    gaps+=1
            if not self.is_v2:
                derived["cpu_interval_percent"]=row.get("cpu_percent")
            complete={**row,**derived}
            bucket=min(buckets-1,(stamp-start)*buckets//max(1,end-start+1))
            for key,stat in stats.items():
                stat.observe(complete.get(key))
            for key in tracks:
                value=complete.get(key)
                if not continuous or not _number(value):
                    segments[key]+=1
                if not _number(value):
                    continue
                point={"time_ns":stamp,"value":value,"segment":segments[key]}
                b=plot[key].get(bucket)
                if b is None:
                    plot[key][bucket]={"first":point,"last":point,"min":point,"max":point}
                else:
                    b["last"]=point
                    if value<b["min"]["value"]:
                        b["min"]=point
                    if value>b["max"]["value"]:
                        b["max"]=point
            previous=row
        plots={}
        for key,groups in plot.items():
            points={}
            for group in groups.values():
                for point in group.values():
                    points[(point["time_ns"],point["segment"])]=point
            plots[key]=sorted(points.values(),key=lambda p:(p["time_ns"],p["segment"]))
        statuses=[]
        errors=0
        native=[]
        if self.is_v2:
            statuses=[dict(r) for r in self.db.execute("""SELECT q.metric,q.measurement_status,count(*) AS count
                FROM samples s JOIN measurements_quality q USING(sample_id)
                WHERE s.instance_id=? AND s.series=? AND s.monotonic_ns BETWEEN ? AND ?
                GROUP BY q.metric,q.measurement_status""",(instance_id,series,start,end))]
            errors=self.db.execute("SELECT count(*) FROM sensor_errors WHERE monotonic_ns BETWEEN ? AND ?",
                                   (start,end)).fetchone()[0]
            native=[dict(r) for r in self.db.execute("""SELECT source_kind,event_type,measurement_status,
                count(*) AS count FROM events WHERE coalesce(observed_ns,recorded_ns) BETWEEN ? AND ? AND source_kind IN ('WIN32','WCT')
                GROUP BY source_kind,event_type,measurement_status""",(start,end))]
        return {"schema_version":2,"source_schema_version":self.metadata["schema_version"],
            "file_trust":"UNVERIFIED_IMPORT","verification_class":"DERIVED",
            "root_cause":"UNKNOWN","metadata":self.metadata,"series":series,"instance_id":instance_id,
            "selected_interval_ns":[start,end],"metrics":{k:v.result(units[k]) for k,v in stats.items()},
            "cpu_time_seconds_over_comparable_pairs":covered_cpu_seconds if cpu_pairs else None,
            "quality_counts":statuses,"coverage":{"selected_samples":count,"total_samples":total,
                "quality_contract":("COMPLETE" if sum(r["count"] for r in statuses if r["metric"] in UNITS)==count*len(UNITS)
                                    and self.is_v2 else "LEGACY_LIMITED_DATA" if not self.is_v2 else "PARTIAL_OR_INVALID"),
                "outside_selected_interval":total-count,"first_sample_ns":first_time,"last_sample_ns":last_time,
                "observed_comparable_duration_ns":observed_duration,"spacing_gap_pairs":gaps,
                "counter_resets":resets,"sensor_error_records":errors,"exact_missed_samples":None,
                "expected_slots_estimate_between_samples":expected_slots_estimate if self.is_v2 else None,
                "limitations":["BETWEEN_SAMPLE_ACTIVITY_UNKNOWN","SCHEDULE_COVERAGE_IS_AN_ESTIMATE",
                    "BOUNDS_EXCLUDE_PARTIAL_COUNTER_PAIRS"]},
            "native_windows_observations":{"file_trust":"UNVERIFIED_IMPORT","counts":native,
                "status":"RECORDED" if native else "NOT_RECORDED","root_cause":"UNKNOWN"},
            "timeline":{"method":"FIRST_MIN_MAX_LAST","buckets":buckets,"tracks":plots},
            "warnings":self.metadata["warnings"]}

    def thread_summary(self,start_ns=None,end_ns=None,*,top_n=32,instance_id=1):
        if type(top_n) is not int or not 1<=top_n<=256:
            raise SessionReadError("INVALID_TOP_N")
        if not self.is_v2:
            return {"status":"LEGACY_LIMITED_DATA","top_threads":[],"root_cause_proven":False}
        self.reader.renew_deadline()
        start,end,total=self._range(start_ns,end_ns,"DETAILED",instance_id)
        args=(instance_id,start,end)
        cte="""WITH selected AS (
            SELECT sample_id,series_seq,monotonic_ns,requested_interval_ns,threads_omitted
            FROM samples WHERE instance_id=? AND series='DETAILED' AND monotonic_ns BETWEEN ? AND ?
        ), observations AS (
            SELECT t.tid,t.cpu_user_s,t.cpu_system_s,s.*,
            lag(series_seq) OVER w AS previous_seq,lag(monotonic_ns) OVER w AS previous_ns,
            lag(cpu_user_s) OVER w AS previous_user,lag(cpu_system_s) OVER w AS previous_system
            FROM selected s JOIN thread_samples t USING(sample_id)
            WINDOW w AS (PARTITION BY tid ORDER BY series_seq)
        ), boundaries AS (
            SELECT *,CASE WHEN previous_seq IS NULL OR series_seq<>previous_seq+1 OR
                monotonic_ns<=previous_ns OR
                monotonic_ns-previous_ns>max(2*requested_interval_ns,requested_interval_ns+500000000) OR
                cpu_user_s<previous_user OR cpu_system_s<previous_system THEN 1 ELSE 0 END AS boundary
            FROM observations
        ), segments AS (
            SELECT *,sum(boundary) OVER (PARTITION BY tid ORDER BY series_seq) AS segment_id,
                CASE WHEN boundary=0 THEN cpu_user_s-previous_user+cpu_system_s-previous_system END AS delta,
                CASE WHEN boundary=0 THEN (monotonic_ns-previous_ns)/1000000000.0 END AS dt
            FROM boundaries
        ), ranked AS (
            SELECT tid,segment_id,min(series_seq) AS segment_start_seq,max(series_seq) AS last_seen_seq,
                count(*) AS observed_samples,count(delta) AS observed_pairs,sum(delta) AS cpu_seconds,
                sum(dt) AS observed_seconds,max(100.0*delta/dt) AS peak_cpu_percent,
                100.0*sum(delta)/sum(dt) AS cpu_percent
            FROM segments GROUP BY tid,segment_id
        ) """
        totals=self.db.execute(cte+"SELECT count(*),sum(cpu_seconds),sum(cpu_seconds IS NULL) FROM ranked",args).fetchone()
        ranked=[dict(r) for r in self.db.execute(cte+"SELECT * FROM ranked ORDER BY cpu_seconds DESC,tid,segment_id LIMIT ?",
                                                (*args,top_n))]
        selected_count,omitted=self.db.execute("""SELECT count(*),sum(threads_omitted) FROM samples
            WHERE instance_id=? AND series='DETAILED' AND monotonic_ns BETWEEN ? AND ?""",args).fetchone()
        capture_quality=[dict(r) for r in self.db.execute("""SELECT measurement_status,count(*) AS count
            FROM measurements_quality q JOIN samples s USING(sample_id) WHERE s.instance_id=?
            AND s.series='DETAILED' AND s.monotonic_ns BETWEEN ? AND ? AND q.metric='thread_counters'
            GROUP BY measurement_status""",args)]
        process=self.db.execute("SELECT pid,creation_time FROM process_instances WHERE instance_id=?",(instance_id,)).fetchone()
        for row in ranked:
            pid=process[0]
            row.update(pid=pid,source_kind="PSUTIL",verification_class="DERIVED",
                       tid_reuse_uncertain=True,
                       observed_presence_percent=100*row["observed_samples"]/selected_count if selected_count else None)
        return {"status":"OK" if totals[1] is not None else
                        "THREADS_NOT_OBSERVED_FOR_INSTANCE" if selected_count==0 else "NO_COMPARABLE_THREAD_INTERVALS",
            "instance_id":instance_id,"pid":process[0] if process else None,
            "creation_time":process[1] if process else None,
            "top_threads":ranked,"threads_ranked":totals[0],"top_n":top_n,
            "omitted_from_top":max(0,totals[0]-len(ranked)),"truncated":totals[0]>len(ranked) or bool(omitted),
            "recorded_omitted_thread_observations":omitted,
            "capture_quality":capture_quality,
            "capture_quality_contract":"NOT_RECORDED" if selected_count==0 else
                                       "COMPLETE" if sum(r["count"] for r in capture_quality)==selected_count
                                       else "LEGACY_NO_CAPTURE_STATUS",
            "omitted_cpu_seconds":max(0,totals[1]-sum(r["cpu_seconds"] or 0 for r in ranked))
                                  if totals[1] is not None else None,
            "segments_without_comparable_pairs":totals[2] or 0,
            "omitted_cpu_quality":"PARTIAL_OR_UNKNOWN" if totals[2] else "OBSERVED_PAIRS_ONLY",
            "sample_window":selected_count,"pair_count":max(0,selected_count-1),
            "selected_interval_ns":[start,end],"total_session_samples":total,
            "source_kind":"PSUTIL","verification_class":"DERIVED","file_trust":"UNVERIFIED_IMPORT",
            "root_cause_proven":False,"tid_reuse_uncertain":True,"cpu_unit":"single_core_percent",
            "warnings":["TID_REUSE_CANNOT_BE_EXCLUDED","PRESENCE_IS_OBSERVED_SNAPSHOT_FRACTION",
                        "RANKED_BY_CUMULATIVE_CPU_OVER_COMPARABLE_PAIRS"]}

    def process_page(self,*,after=0,limit=100):
        if type(limit) is not int or not 1<=limit<=256 or type(after) is not int or after<0:
            raise SessionReadError("INVALID_PAGE")
        if not self.is_v2:
            return {"rows":[],"has_more":False,"status":"LEGACY_LIMITED_DATA"}
        rows=[_validated_process_instance(r) for r in self.db.execute("SELECT instance_id,pid,creation_time,parent_pid,"
            "substr(executable_name,1,512) AS executable_name,first_observed_ns,last_observed_ns,"
            "absence_observed_ns,substr(source_kind,1,64) AS source_kind FROM process_instances WHERE instance_id>? "
                                              "ORDER BY instance_id LIMIT ?",(after,limit+1))]
        return {"rows":rows[:limit],"has_more":len(rows)>limit,
                "limitations":["ABSENCE_IS_NOT_EXACT_EXIT_TIME","SHORT_LIVED_CHILDREN_MAY_BE_MISSED",
                               "SUM_RSS_DOUBLE_COUNTS_SHARED_PAGES"]}

    def event_page(self,start_ns=0,end_ns=2**63-1,*,after=(0,0),limit=100):
        if type(limit) is not int or not 1<=limit<=200 or len(after)!=2:
            raise SessionReadError("INVALID_PAGE")
        if not self.is_v2:
            return {"rows":[],"has_more":False,"status":"LEGACY_LIMITED_DATA"}
        raw=self.db.execute("""SELECT event_id,recorded_ns,observed_ns,instance_id,event_type,
            source_kind,verification_class,timestamp_precision,correlation_key,measurement_status,
            substr(detail_json,1,16385) AS detail_json,length(detail_json) AS detail_size,
            coalesce(observed_ns,recorded_ns) AS event_time_ns FROM events
            WHERE coalesce(observed_ns,recorded_ns) BETWEEN ? AND ?
            AND (coalesce(observed_ns,recorded_ns),event_id)>(?,?)
            ORDER BY coalesce(observed_ns,recorded_ns),event_id LIMIT ?""",(start_ns,end_ns,*after,limit+1)).fetchall()
        rows=[]
        for item in raw[:limit]:
            row=dict(item)
            if row.pop("detail_size")>16384:
                raise SessionReadError("IMPORTED_EVENT_SIZE_LIMIT")
            row["recorded_verification_class"]=row["verification_class"]
            row["verification_class"]="UNVERIFIED_IMPORT"
            row["detail"]=json.loads(row.pop("detail_json"))
            rows.append(row)
        return {"rows":rows,"has_more":len(raw)>limit,
                "next_cursor":[rows[-1]["event_time_ns"],rows[-1]["event_id"]] if rows else None}
