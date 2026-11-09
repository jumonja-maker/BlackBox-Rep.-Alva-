"""Indexed, additive research evidence. Does not mutate legacy recordings."""
from __future__ import annotations
from contextlib import closing
import hashlib
from html import escape
import json
import os
from pathlib import Path
import platform
import sqlite3
import tempfile
import time
from uuid import uuid4
import zipfile

from .detail_contracts import capture_clock_anchor


def compact(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def readonly(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("INVALID_RESEARCH_PATH")
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    db.execute("PRAGMA trusted_schema=OFF")
    db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1024*1024)
    return db


class CaseBook:
    def __init__(self, folder, pid, created, context, *, on_evidence=None):
        self.folder, self.pid, self.created = Path(folder), pid, created
        self.path = self.folder / "research.sqlite3"
        fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(self.path, timeout=2)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
          CREATE TABLE context(key TEXT PRIMARY KEY, data TEXT NOT NULL);
          CREATE TABLE evidence(id INTEGER PRIMARY KEY, monotonic_ns INTEGER NOT NULL,
            received_ns INTEGER NOT NULL, elapsed_ms INTEGER NOT NULL, pid INTEGER,
            process_created REAL, tid INTEGER, source TEXT NOT NULL, quality TEXT NOT NULL,
            kind TEXT NOT NULL, operation_id TEXT, data TEXT NOT NULL);
          CREATE INDEX ix_evidence_time ON evidence(elapsed_ms,id);
          CREATE INDEX ix_evidence_monotonic ON evidence(monotonic_ns,id);
          CREATE INDEX ix_evidence_operation ON evidence(operation_id,id);
          CREATE INDEX ix_evidence_kind ON evidence(kind,id);
          CREATE TABLE operation_spans(operation_id TEXT, begin_ref INTEGER, end_ref INTEGER,
             start_ms INTEGER, end_ms INTEGER, duration_ns INTEGER, source_clock TEXT,
             PRIMARY KEY(operation_id,begin_ref,end_ref));
          CREATE INDEX ix_span_end ON operation_spans(end_ms,begin_ref);
          CREATE TABLE action_runs(action_id TEXT PRIMARY KEY, experiment_id TEXT,
             duration_ns INTEGER NOT NULL, evidence_ref INTEGER NOT NULL);
          CREATE INDEX ix_action_duration ON action_runs(duration_ns);
        """)
        self.anchor = capture_clock_anchor()
        self.origin = context.get("origin_monotonic_ns",self.anchor.monotonic_ns)
        self.last_legacy = 0
        self.state = "RECORDING"
        self.on_evidence=on_evidence
        self.set_context("schema_version", 2)
        self.set_context("clock", self.anchor.as_dict())
        self.set_context("recording_origin_ns", self.origin)
        self.set_context("target", {"pid": pid, "created": created})
        self.set_context("environment", {"platform": platform.platform(),
            "machine": platform.machine(), "logical_cpus": os.cpu_count(),
            "python": platform.python_version()})
        self.set_context("experiment", context)
        self.set_context("state", self.state)

    def set_context(self, key, value):
        data = compact(value)
        if len(data) > 65536:
            raise ValueError("CONTEXT_TOO_LARGE")
        self.db.execute("INSERT OR REPLACE INTO context VALUES (?,?)", (key, data))
        self.db.commit()

    def put(self, kind, payload, *, source="BLACKBOX", quality="OBSERVED",
            at_ns=None, tid=None, operation_id=None, mirror=True):
        data = compact(payload)
        if len(data) > 32768 or len(kind) > 80 or len(source) > 80:
            raise ValueError("EVIDENCE_TOO_LARGE")
        now = time.monotonic_ns()
        at = now if at_ns is None else at_ns
        if type(at) is not int or at < 0 or at > now + 1_000_000_000:
            raise ValueError("INVALID_EVIDENCE_CLOCK")
        cursor = self.db.execute("INSERT INTO evidence VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?)",
            (at, now, (at-self.origin)//1_000_000, self.pid, self.created,
             tid, source, quality, kind, operation_id, data))
        if source == "APPLICATION_EVENT" and kind == "operation.end" and operation_id:
            previous = self.db.execute("SELECT id,elapsed_ms,data FROM evidence WHERE operation_id=? "
                "AND kind='operation.begin' AND id<? ORDER BY id DESC LIMIT 1", (operation_id,cursor.lastrowid)).fetchone()
            if previous:
                start=json.loads(previous[2])
                if (start.get("pid")==payload.get("pid") and
                        start.get("source_clock")==payload.get("source_clock") and
                        type(payload.get("source_ns")) is int and
                        type(start.get("source_ns")) is int and
                        payload["source_ns"]>=start["source_ns"]):
                    self.db.execute("INSERT OR IGNORE INTO operation_spans VALUES(?,?,?,?,?,?,?)",
                        (operation_id,previous[0],cursor.lastrowid,previous[1],(at-self.origin)//1_000_000,
                         payload["source_ns"]-start["source_ns"],payload.get("source_clock")))
        self.db.commit()
        if mirror and self.on_evidence:
            self.on_evidence({"kind":"research_evidence_ref","code":kind,
                "source":"BLACKBOX_RESEARCH_INDEX","reported_source":source,
                "measurement_status":quality,"timestamp_monotonic_ns":at,
                "evidence_ref":f"research.sqlite3:evidence:{cursor.lastrowid}"})
        return cursor.lastrowid

    def sync_legacy(self, *, drain=False):
        with closing(readonly(self.folder / "session.sqlite3")) as db:
            # Freeze the frontier. Ordinary ticks stay bounded to one page;
            # finalization reads every committed page from the stopped owner.
            end=db.execute("SELECT COALESCE(MAX(seq),0) FROM events").fetchone()[0]
            while self.last_legacy<end:
                rows = db.execute("SELECT seq,data FROM events WHERE seq>? AND seq<=? ORDER BY seq LIMIT 1000",
                                  (self.last_legacy,end))
                count=0
                for row in rows:
                    count+=1
                    payload = json.loads(row["data"])
                    if payload.get("kind")=="research_evidence_ref":
                        self.last_legacy=row["seq"]
                        continue
                    kind = payload.get("event", payload.get("kind", "legacy_event"))
                    at = payload.get("timestamp_monotonic_ns")
                    evidence_id = self.put(str(kind)[:80], {"legacy_event_seq": row["seq"], "event": payload},
                             source=payload.get("source", "BLACKBOX_LEGACY"),
                             quality="USER_REPORTED" if payload.get("source", "").startswith("USER") else "OBSERVED",
                             at_ns=at, operation_id=payload.get("action_id"),mirror=False)
                    if (kind=="ACTION_COMPLETED" and type(payload.get("duration_ns")) is int and
                            0<=payload["duration_ns"]<=30*86400*10**9 and
                            isinstance(payload.get("action_id"),str)):
                        self.db.execute("INSERT OR IGNORE INTO action_runs VALUES(?,?,?,?)",
                            (payload["action_id"],payload.get("experiment_id"),payload["duration_ns"],evidence_id))
                        self.db.commit()
                    self.last_legacy=row["seq"]
                if not drain or not count:break

    def close(self, state="COMPLETED"):
        self.state = state
        try:
            self.set_context("state", state)
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            self.db.close()


def context(folder):
    # Native writers limit each JSON value to 64 KiB and keep a small set of
    # keys. Apply an aggregate import budget before export/compare can retain
    # an arbitrary context table in Python. Overflow is an error, never a
    # silently truncated statement of the recording's conditions.
    max_rows,max_bytes,max_value_bytes=128,2*1024**2,65536
    result={};total=0;deadline=time.monotonic()+3
    def pairs(items):
        value={}
        for key,item in items:
            if key in value:raise ValueError('INVALID_RESEARCH_CONTEXT_DUPLICATE_KEY')
            value[key]=item
        return value
    def constant(_):raise ValueError('INVALID_RESEARCH_CONTEXT_NONFINITE_JSON')
    with closing(readonly(Path(folder)/"research.sqlite3")) as db:
        db.set_progress_handler(lambda:int(time.monotonic()>=deadline),1000)
        rows=db.execute("SELECT substr(key,1,257),substr(data,1,65537),"
                        "length(CAST(key AS BLOB)),length(CAST(data AS BLOB)) "
                        "FROM context LIMIT ?",(max_rows+1,))
        for ordinal,row in enumerate(rows,1):
            key,raw,key_bytes,value_bytes=row
            if (ordinal>max_rows or type(key) is not str or not key or
                    type(raw) is not str or type(key_bytes) is not int or not 1<=key_bytes<=256 or
                    type(value_bytes) is not int or not 1<=value_bytes<=max_value_bytes):
                raise ValueError('RESEARCH_CONTEXT_BUDGET_EXCEEDED')
            total+=key_bytes+value_bytes
            if total>max_bytes:raise ValueError('RESEARCH_CONTEXT_BUDGET_EXCEEDED')
            if key in result:raise ValueError('INVALID_RESEARCH_CONTEXT_DUPLICATE_KEY')
            result[key]=json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)
        return result


def evidence_page(folder, *, start_ms=0, end_ms=2**63-1, after_id=0, before_id=None, limit=100):
    if not all(type(x) is int for x in (start_ms, end_ms, after_id, limit)) or not (
            -60000 <= start_ms <= end_ms <= 2**63-1 and after_id >= 0 and 1 <= limit <= 500):
        raise ValueError("INVALID_EVIDENCE_INTERVAL")
    with closing(readonly(Path(folder)/"research.sqlite3")) as db:
        # id cursor retains deterministic paging for delayed source events.
        if before_id is not None:
            if type(before_id) is not int or before_id<1:raise ValueError("INVALID_EVIDENCE_CURSOR")
            rows = db.execute("SELECT * FROM evidence WHERE elapsed_ms BETWEEN ? AND ? "
                "AND id<? ORDER BY id DESC LIMIT ?",(start_ms,end_ms,before_id,limit+1)).fetchall()
        else:
            rows = db.execute("SELECT * FROM evidence WHERE elapsed_ms BETWEEN ? AND ? "
                              "AND id>? ORDER BY id LIMIT ?", (start_ms,end_ms,after_id,limit+1)).fetchall()
        more = len(rows)>limit
        rows=rows[:limit]
        if before_id is not None:rows=list(reversed(rows))
        result = []
        for row in rows:
            entry = dict(row); entry["data"] = json.loads(entry["data"])
            entry["evidence_ref"] = f"research.sqlite3:evidence:{entry['id']}"
            result.append(entry)
        return {"rows": result, "has_more": more,
                "next_id": result[-1]["id"] if result else after_id,
                "first_id":result[0]["id"] if result else None,
                "range_ms": [start_ms,end_ms], "file_trust": "UNVERIFIED_IMPORT"}


def episode(folder, start_ms, end_ms):
    page = evidence_page(folder,start_ms=start_ms,end_ms=end_ms)
    with closing(readonly(Path(folder)/"session.sqlite3")) as db:
        r = db.execute("SELECT count(*) AS samples, max(cpu_percent) AS peak_cpu_percent, "
                       "max(rss_bytes) AS peak_rss_bytes, min(rss_bytes) AS min_rss_bytes "
                       "FROM samples WHERE elapsed_ms BETWEEN ? AND ?", (start_ms,end_ms)).fetchone()
        metrics = dict(r)
        # Bounded chart data: SQL aggregation reads the selected interval only.
        width=max(1,(end_ms-start_ms)//300)
        bins=[dict(x) for x in db.execute("SELECT (elapsed_ms-?)/? AS bucket, "
             "min(elapsed_ms) AS elapsed_ms,max(cpu_percent) AS cpu_percent, "
             "max(rss_bytes) AS rss_bytes FROM samples WHERE elapsed_ms BETWEEN ? AND ? "
             "GROUP BY bucket ORDER BY bucket LIMIT 302",(start_ms,width,start_ms,end_ms))]
    facts=[{"classification":"MEASURED_FACT","metrics":metrics,
            "evidence_ref":f"session.sqlite3:samples:elapsed_ms:{start_ms}..{end_ms}"}]
    with closing(readonly(Path(folder)/"research.sqlite3")) as db:
        spans=[dict(r) for r in db.execute("SELECT * FROM operation_spans WHERE end_ms BETWEEN ? AND ? "
                "ORDER BY end_ms LIMIT 101",(start_ms,end_ms))]
    for span in spans[:100]:
        facts.append({"classification":"APPLICATION_REPORTED_OPERATION",
            "duration_ns":span["duration_ns"],"source_clock":span["source_clock"],
            "evidence_refs":[f"research.sqlite3:evidence:{span['begin_ref']}",f"research.sqlite3:evidence:{span['end_ref']}"],
            "operation_id":span["operation_id"],"source_trust":"UNAUTHENTICATED"})
    normalised=None
    if (Path(folder)/"session-v2.sqlite3").is_file():
        from .session_view import SessionView
        origin=context(folder)["recording_origin_ns"]
        with SessionView.open(folder) as view:
            normalised=view.interval(origin+start_ms*10**6,origin+end_ms*10**6,buckets=300)
    return {"schema_version":2,"range_ms":[start_ms,end_ms],"facts":facts,
            "normalised_interval":normalised,
            "evidence":page,"chart":bins,"hypotheses":[],"root_cause_proven":False,
            "operation_spans_truncated":len(spans)>100,
            "limitations":["Counters do not establish causality.",
            "Source events are application supplied; receipt time is not execution time.",
            "Sampling may miss short events; unknown loss is not zero loss."]}


def compare_cases(first, second):
    from .deep_tool_contracts import begin_evidence_run,attach_evidence_run_receipt,record_evidence_failure
    sources=({'source_type':'RESEARCH_SESSION','role':'before','producer_authentication':'NOT_ESTABLISHED'},
             {'source_type':'RESEARCH_SESSION','role':'after','producer_authentication':'NOT_ESTABLISHED'})
    run=begin_evidence_run('research.compare',sources=sources,timeout_seconds=30)
    try:
        from .session_v2 import safe_path
        first,second=safe_path(Path(first)),safe_path(Path(second))
        answer=_compare_cases(first,second)
        if time.monotonic_ns()>=run.deadline_monotonic_ns:raise TimeoutError('COMPARISON_DEADLINE')
        from .investigation_graph_contracts import stable_id
        sources=tuple({'source_type':'RESEARCH_INDEX','role':role,'filename':'research.sqlite3',
            'recording_run_id':answer['comparability']['run_contexts'][role].get('run_id'),
            'source_id':(stable_id('recording-run',answer['comparability']['run_contexts'][role]['run_id'])
                if type(answer['comparability']['run_contexts'][role].get('run_id')) is str else None),
            'source_sha256':None,'source_size_bytes':(folder/'research.sqlite3').stat().st_size,
            'producer_authentication':'NOT_ESTABLISHED'} for role,folder in (('before',first),('after',second)))
        result=attach_evidence_run_receipt(run,{**answer,'status':'COMPLETED'},sources=sources,
            coverage={'completeness':'UNKNOWN','scope':'RECORDED_COMPARISON','comparison_status':answer['comparison_status']},
            cleanup={'status':'COMPLETED','confirmed':True,'scope':'READ_ONLY_COMPARISON_HANDLES_CLOSED_NO_NATIVE_OWNER'},
            source_revalidated=False,execution_started=True)
        result.pop('status',None)
        return result
    except BaseException as exc:
        record_evidence_failure(run,exc,sources=sources)
        raise


def _compare_cases(first, second):
    from .report import summarize
    a,b=context(first),context(second)
    required=("scenario","workload","profile","interval_ms")
    ca,cb=a.get("experiment",{}),b.get("experiment",{})
    reasons=[k for k in required if not ca.get(k) or ca.get(k)!=cb.get(k)]
    if (ca.get("scenario_version") or cb.get("scenario_version")) and ca.get("scenario_version")!=cb.get("scenario_version"):
        reasons.append("scenario_version")
    if ca.get("warmup_count",0)!=cb.get("warmup_count",0):reasons.append("warmup_count")
    if ca.get("capture_policy")!=cb.get("capture_policy"):reasons.append("capture_policy")
    if a.get("environment") != b.get("environment"):
        reasons.append("environment")
    if a.get("capabilities",{}).get("privilege")!=b.get("capabilities",{}).get("privilege"):
        reasons.append("privilege")
    if a.get("configuration_changed") or b.get("configuration_changed"):
        reasons.append("recording_configuration_changed")
    from .experiment_metrics import resource_statistics,compare_resources
    ra=resource_statistics(first,warmup_count=ca.get("warmup_count",0))
    rb=resource_statistics(second,warmup_count=cb.get("warmup_count",0))
    sa,sb=summarize(first),summarize(second)
    ta,tb=action_statistics(first),action_statistics(second)
    am,bm=(ta.get('duration_ms') or {}).get('median'),(tb.get('duration_ms') or {}).get('median')
    delta=bm-am if am is not None and bm is not None else None
    partial=any(r.get('resource_unobserved_runs') or any(v.get('missing_repeats') or
        v.get('minimum_observed_fraction') is not None and v['minimum_observed_fraction']<.8 for v in r.get('metrics',{}).values()) for r in (ra,rb))
    from .experiments import assess_comparability
    comparability=assess_comparability(a,b,before_resources=ra,after_resources=rb,
        before_repeats=ta['repeats'],after_repeats=tb['repeats'],context_mismatches=reasons)
    reasons=comparability['context_mismatches']
    keys=("peak_rss_bytes","peak_cpu_percent","elapsed_ms")
    return {"schema_version":2,"comparison":"OBSERVATION_ONLY","source_trust":"UNVERIFIED_IMPORT",
        "comparison_status":comparability['status'],"comparability":comparability,
        "comparable_context":comparability['status']=='COMPARABLE',"context_mismatches":reasons,
        "context_warnings":([] if ca.get("scenario_version") and cb.get("scenario_version") else ["scenario_version_not_recorded"])+([] if ca.get("capture_policy") and cb.get("capture_policy") else ["capture_policy_not_recorded"]),
        "target_versions":{"before":ca.get("target_version"),"after":cb.get("target_version")},
        "resource_experiments":{"before":ra,"after":rb},
        "resource_comparison":compare_resources(ra,rb),
        "duration_comparison":{"unit":"milliseconds","before_median":am,"after_median":bm,"absolute_delta":delta,
            "percent_delta":100*delta/abs(am) if delta is not None and am else None,"before_repeats":ta['repeats'],"after_repeats":tb['repeats'],
            "before_variability":ta.get('variability_ms'),"after_variability":tb.get('variability_ms'),"speedup_proven":False},
        "comparison_flags":{"insufficient_repeats":min(ta['repeats'],tb['repeats'])<2,"incomparable_config":bool(reasons),"partial_coverage":partial},
        "metrics":{k:{"before":sa[k],"after":sb[k],
                     "delta":sb[k]-sa[k] if sa[k] is not None and sb[k] is not None else None} for k in keys},
        "experiments":{"before":ta,"after":tb},
        "speedup_proven":False,"causal_link_proven":False}


def _comparison_sources(folder, *, cancel=None):
    """Reuse the existing hash and path contracts for a stopped source set."""
    from .session_v2 import safe_path
    result={}
    folder=safe_path(Path(folder))
    filenames=('session.sqlite3','session-v2.sqlite3','research.sqlite3','detail-v2.sqlite3')
    for name in (*filenames,*(name+'-wal' for name in filenames)):
        path=folder/name
        if not path.exists():continue
        path=safe_path(path);before=path.stat()
        if not path.is_file() or before.st_size>2*1024**3:raise ValueError('COMPARISON_SOURCE_SIZE_LIMIT')
        if name.endswith('-wal') and before.st_size==0:continue
        value=_hash(path,cancel)
        after=path.stat()
        key=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)
        if key(before)!=key(after):raise ValueError('COMPARISON_SOURCE_CHANGED')
        result[name]={'sha256':value,'size_bytes':after.st_size,'identity':key(after)}
    if 'research.sqlite3' not in result:raise ValueError('RESEARCH_SOURCE_REQUIRED')
    return result


def export_comparison(before, after, destination, *, format='json', cancel=None):
    from .deep_tool_contracts import begin_evidence_run,attach_evidence_run_receipt,record_evidence_failure
    run=begin_evidence_run('research.export_comparison',parameters={'format':format},timeout_seconds=30)
    try:
        answer=_export_comparison(before,after,destination,format=format,cancel=cancel)
        return attach_evidence_run_receipt(run,answer,sources=answer['source_identities'],
            coverage={'completeness':'UNKNOWN','scope':'COMPARISON_METADATA','comparison_status':answer['comparison_status']},
            cleanup={'status':'COMPLETED','confirmed':True,'scope':'OWNED_EXPORT_STAGE_PUBLISHED_AND_REMOVED'},
            source_revalidated=answer['source_revalidated'],execution_started=True)
    except BaseException as exc:
        record_evidence_failure(run,exc)
        raise


def _export_comparison(before, after, destination, *, format='json', cancel=None):
    """Export the existing comparison through the common no-clobber journal."""
    if format not in ('json','html'):raise ValueError('INVALID_COMPARISON_FORMAT')
    from .session_v2 import safe_path
    from .package_privacy import redact
    from .export_recovery import export_stage,same
    from .owned_unlink import file_identity
    destination=safe_path(Path(destination))
    if destination.exists() or destination.is_symlink():raise FileExistsError('EXPORT_DESTINATION_EXISTS')
    deadline=time.monotonic()+30
    def interrupted():
        if time.monotonic()>=deadline:raise TimeoutError('COMPARISON_EXPORT_DEADLINE')
        return bool(cancel and cancel())
    for folder in (before,after):
        if context(folder).get('state')=='RECORDING':raise ValueError('STOP_RECORDING_BEFORE_EXPORT')
    originals=(_comparison_sources(before,cancel=interrupted),_comparison_sources(after,cancel=interrupted))
    comparison=compare_cases(before,after)
    from .investigation_graph_contracts import stable_id
    public_sources=[]
    for entries in originals:
        public_sources.append({name:{'source_id':stable_id('recording-file',name,row['sha256'],row['size_bytes']),
            'source_sha256':row['sha256'],'source_size_bytes':row['size_bytes'],
            'producer_authentication':'NOT_ESTABLISHED'} for name,row in entries.items()})
    payload=redact({'schema':'blackbox.experiment-comparison.v1','comparison':comparison,
        'sources':{'before':public_sources[0],'after':public_sources[1]},
        'source_trust':'UNVERIFIED_IMPORT','privacy':'METADATA_ONLY_NO_MEMORY_OR_DUMP_BYTES',
        'causal_link_proven':False})
    raw=compact(payload)
    if len(raw.encode('utf-8'))>4*1024**2:raise ValueError('COMPARISON_EXPORT_SIZE_LIMIT')
    with export_stage(destination.parent,kind='EXPERIMENT_COMPARISON') as tx:
        staged=tx.reserve('comparison.'+format)
        if format=='json':content=raw
        else:
            from blackbox_universal.experiment_view import comparison_text
            content=('<!doctype html><html lang="en"><meta charset="utf-8"><title>BLACK.BOX experiment comparison</title>'
                '<h1>BLACK.BOX experiment comparison</h1><pre>'+escape(comparison_text(payload['comparison'],'EN'))+
                '</pre><h2>Recorded metadata</h2><pre id="blackbox-comparison-data">'+escape(raw)+'</pre></html>')
        staged.write_text(content,encoding='utf-8')
        readback=load_comparison(staged)
        if {k:v for k,v in readback.items() if k!='import_source'}!=payload:raise ValueError('COMPARISON_READBACK_MISMATCH')
        if originals!=(_comparison_sources(before,cancel=interrupted),_comparison_sources(after,cancel=interrupted)):
            raise ValueError('COMPARISON_SOURCE_CHANGED')
        tx.prepare({destination.name:staged});digest=_hash(staged,interrupted);size=staged.stat().st_size
        expected_identity=tx.data['files'][0]['identity'];expected_parent=tx.data['output_identity']
        tx.publish()
    # Publication has committed and common staging cleanup is complete. A
    # foreign replacement is retained: never enter automatic rollback/deletion
    # merely because final public read-back cannot confirm our own bytes.
    try:
        if (not same(file_identity(destination.parent),expected_parent) or
            not same(file_identity(destination),expected_identity) or
            destination.stat().st_size!=size or _hash(destination,interrupted)!=digest):
            raise ValueError('COMPARISON_PUBLICATION_UNCONFIRMED')
        public_readback=load_comparison(destination)
        if ({k:v for k,v in public_readback.items() if k!='import_source'}!=payload or
            public_readback['import_source']['source_sha256']!=digest or
            public_readback['import_source']['source_size_bytes']!=size or
            not same(file_identity(destination),expected_identity) or
            not same(file_identity(destination.parent),expected_parent)):
            raise ValueError('COMPARISON_PUBLICATION_UNCONFIRMED')
    except BaseException as exc:
        exc.publication_unconfirmed=True
        raise
    return {'status':'COMPLETED','schema':'blackbox.experiment-comparison.v1',
        'format':format,'path':str(destination),'sha256':digest,'size_bytes':size,
        'readback_verified':True,'source_revalidated':True,'source_modified':False,
        'publication_identity_verified':True,
        'source_trust':'UNVERIFIED_IMPORT','comparison_status':comparison['comparison_status'],
        'source_identities':[{'source_type':'RESEARCH_FILES','role':role,'files':entries,
            'source_id':stable_id('recording-files',entries),
            'producer_authentication':'NOT_ESTABLISHED'} for role,entries in zip(('before','after'),public_sources)]}


def load_comparison(path):
    """Read bounded metadata only; a saved report never authenticates itself."""
    from .session_v2 import safe_path
    path=safe_path(Path(path))
    if not path.is_file() or path.stat().st_size>8*1024**2:raise ValueError('COMPARISON_IMPORT_SIZE_LIMIT')
    with path.open('rb') as stream:
        before=os.fstat(stream.fileno());data=stream.read(8*1024**2+1);after=os.fstat(stream.fileno())
    key=lambda item:(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns)
    if len(data)>8*1024**2:raise ValueError('COMPARISON_IMPORT_SIZE_LIMIT')
    if key(before)!=key(after) or key(after)!=key(safe_path(path).stat()) or len(data)!=before.st_size:
        raise ValueError('COMPARISON_IMPORT_CHANGED')
    raw=data.decode('utf-8')
    if raw.lstrip().lower().startswith(('<!doctype html','<html')):
        from html.parser import HTMLParser
        class Metadata(HTMLParser):
            def __init__(self):super().__init__(convert_charrefs=True);self.parts=[];self.inside=False;self.seen=0
            def handle_starttag(self,tag,attrs):
                if tag=='pre' and dict(attrs).get('id')=='blackbox-comparison-data':self.inside=True;self.seen+=1
            def handle_endtag(self,tag):
                if tag=='pre':self.inside=False
            def handle_data(self,data):
                if self.inside:self.parts.append(data)
        parser=Metadata();parser.feed(raw);parser.close()
        if parser.seen!=1 or parser.inside:raise ValueError('INVALID_COMPARISON_HTML')
        raw=''.join(parser.parts)
    def invalid_constant(_):raise ValueError('INVALID_COMPARISON_REPORT')
    value=json.loads(raw,parse_constant=invalid_constant)
    if (type(value) is not dict or value.get('schema')!='blackbox.experiment-comparison.v1' or
        type(value.get('comparison')) is not dict or
        value['comparison'].get('comparison_status') not in ('COMPARABLE','NOT_COMPARABLE','INCONCLUSIVE')):
        raise ValueError('INVALID_COMPARISON_REPORT')
    value['source_trust']='UNVERIFIED_IMPORT'
    from .experiments import validate_comparison_presentation
    validate_comparison_presentation(value['comparison'])
    value['comparison']['source_trust']='UNVERIFIED_IMPORT'
    value['comparison']['speedup_proven']=False;value['comparison']['causal_link_proven']=False
    if type(value['comparison'].get('comparability')) is dict:
        value['comparison']['comparability'].update(file_trust='UNVERIFIED_IMPORT',speedup_proven=False,causal_link_proven=False)
    value['causal_link_proven']=False
    value['import_source']={'source_sha256':hashlib.sha256(data).hexdigest(),'source_size_bytes':len(data),
        'content_integrity':'HASHED_STABLE_FILE','producer_authentication':'NOT_ESTABLISHED'}
    return value


def action_statistics(folder, *, warmup_count=None):
    """Exact SQLite quantiles; all runs remain stored, no Python history list."""
    if warmup_count is None:warmup_count=context(folder).get("experiment",{}).get("warmup_count",0)
    if type(warmup_count) is not int or not 0<=warmup_count<=10000:raise ValueError("INVALID_WARMUP_COUNT")
    with closing(readonly(Path(folder)/"research.sqlite3")) as db:
        total=db.execute("SELECT count(*) FROM action_runs").fetchone()[0]
        warmup=min(warmup_count,total);n=total-warmup
        if not n:return {"repeats":0,"total_repeats":total,"warmups_excluded":warmup,"duration_ms":None}
        # TEMP views are unavailable on query_only; use a parameterized CTE.
        cte="WITH measured AS (SELECT * FROM action_runs ORDER BY evidence_ref LIMIT -1 OFFSET ?) "
        def quantile(q):
            import math
            index=(n-1)*q;lo=int(index);hi=math.ceil(index)
            vals=[r[0] for r in db.execute(cte+"SELECT duration_ns FROM measured ORDER BY duration_ns LIMIT ? OFFSET ?",(warmup,hi-lo+1,lo))]
            return (vals[0]+(vals[-1]-vals[0])*(index-lo))/1_000_000
        middle=quantile(.5)
        mean=m2=0.;count=0
        for row in db.execute(cte+'SELECT duration_ns/1000000.0 FROM measured',(warmup,)):
            count+=1;diff=row[0]-mean;mean+=diff/count;m2+=diff*(row[0]-mean)
        q1,q3=quantile(.25),quantile(.75)
        import math
        return {"repeats":n,"total_repeats":total,"warmups_excluded":warmup,
            "duration_ms":{"minimum":quantile(0),"median":middle,"p95":quantile(.95),"maximum":quantile(1)},
            "variability_ms":{"mean":mean,"sample_stddev":math.sqrt(max(0.,m2)/(count-1)) if count>=2 else None,
                "q1":q1,"q3":q3,"iqr":q3-q1,"statistical_significance_proven":False},
            "source":"USER_COMMAND_DURATION_NOT_INTERNAL_FUNCTION_RUNTIME",
            "warnings":["P95_UNSTABLE_SMALL_SAMPLE"] if n<20 else [],"speedup_proven":False}


def _check_cancel(cancel):
    if cancel is not None and cancel():raise InterruptedError("RESEARCH_OPERATION_CANCELLED")


def _hash(path, cancel=None):
    digest=hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b""):
            _check_cancel(cancel)
            digest.update(chunk)
    return digest.hexdigest()


def export_case(folder, destination, *, include_sensitive=False, cancel=None):
    """Consistent SQLite backups, streamed pages, exclusive final publication."""
    folder,destination=Path(folder),Path(destination)
    _check_cancel(cancel)
    if include_sensitive:
        artifacts=Path(folder)/"artifacts"
        if artifacts.is_dir():
            for journal in artifacts.glob("*.trace.json"):
                if journal.is_symlink() or journal.stat().st_size>65536:raise ValueError("INVALID_TRACE_JOURNAL")
                state=json.loads(journal.read_text(encoding="utf-8")).get("state")
                if state not in ("COMPLETED","FAILED","RECOVERED_NAMED_CANCEL","RECOVERED_OWNED_TOOL_STOP"):
                    raise ValueError("STOP_TRACE_BEFORE_SENSITIVE_EXPORT")
    if destination.exists() or destination.is_symlink():
        raise ValueError("EXPORT_DESTINATION_EXISTS")
    meta=context(folder)
    if meta.get("state")=="RECORDING":
        raise ValueError("STOP_RECORDING_BEFORE_EXPORT")
    from .export_recovery import export_stage
    with export_stage(destination.parent,kind='RESEARCH_PACKAGE') as tx:
        staging=tx.stage; entries=[]
        for name in ("session.sqlite3","session-v2.sqlite3","research.sqlite3","detail-v2.sqlite3"):
            source=folder/name
            if source.exists():
                target=tx.reserve(name)
                with closing(readonly(source)) as src, closing(sqlite3.connect(target)) as dst:
                    src.backup(dst,pages=256,sleep=0.01,progress=lambda *_:_check_cancel(cancel))
        privacy={"policy":"EXPLICIT_SENSITIVE_EXPORT","universal_secret_detection":False}
        if not include_sensitive:
            from .package_privacy import redact_copies
            privacy=redact_copies(staging,cancel=cancel)
        meta=context(staging)
        report=tx.reserve("report.json")
        from .experiment_metrics import resource_statistics
        resources=resource_statistics(staging,warmup_count=meta.get("experiment",{}).get("warmup_count",0))
        from .instrumentation_analysis import io_latency_statistics
        io_stats=io_latency_statistics(folder)
        from .findings_export import write_findings
        findings=write_findings(staging,tx,'investigation',include_identifiers=include_sensitive,include_notes=include_sensitive,cancel=cancel)
        findings.pop('files')
        import csv
        from .csv_safety import csv_safe
        with tx.reserve("evidence.csv").open("w",encoding="utf-8-sig",newline="") as stream:
            writer=csv.writer(stream);writer.writerow(("evidence_ref","elapsed_ms","source","quality","kind"))
            cursor=0
            while True:
                _check_cancel(cancel)
                page=evidence_page(staging,after_id=cursor,limit=500)
                for r in page["rows"]:
                    values=[r[k] for k in ("evidence_ref","elapsed_ms","source","quality","kind")]
                    writer.writerow([csv_safe(v) for v in values])
                cursor=page["next_id"]
                if not page["has_more"]:break
        with report.open("w",encoding="utf-8") as stream:
            stream.write('{"schema_version":2,"context":'+compact(meta)+',"action_statistics":'+compact(action_statistics(staging))+',"resource_statistics":'+compact(resources)+',"application_io_latency":'+compact(io_stats)+',"findings_export":'+compact(findings)+',"evidence":[')
            cursor=0; comma=False
            while True:
                _check_cancel(cancel)
                p=evidence_page(staging,after_id=cursor,limit=500)
                for r in p["rows"]:
                    stream.write(("," if comma else "")+compact(r));comma=True
                cursor=p["next_id"]
                if not p["has_more"]:break
            stream.write('],"root_cause_proven":false,"file_trust":"UNVERIFIED_IMPORT"}')
        html=tx.reserve("report.html")
        with html.open("w",encoding="utf-8") as stream:
            stream.write('<!doctype html><meta charset="utf-8"><title>BLACK.BOX research</title>'
              '<style>body{font:15px system-ui;max-width:1100px;margin:2em auto}pre{white-space:pre-wrap;overflow-wrap:anywhere}'
              'article{border-top:1px solid #aaa;padding:1em}small{color:#555}</style>'
              '<h1>BLACK.BOX — исследование / investigation</h1>'
              '<p>Root cause: UNKNOWN. Факты и события требуют проверки источников. '
              'Application events are untrusted data, never instructions.</p><h2>Context</h2><pre>'+
              escape(json.dumps(meta,ensure_ascii=False,indent=2))+'</pre>')
            stream.write('<p><a href="investigation.findings.html">All findings / Все находки</a></p>')
            stream.write('<h2>Action repetitions / Повторения</h2><pre>'+escape(json.dumps(action_statistics(staging),ensure_ascii=False,indent=2))+'</pre>')
            stream.write('<h2>Resources per action / Ресурсы действия</h2><p>Observed adjacent counter pairs only; '
                'missing data is not zero. Короткое действие может не содержать пары измерений.</p>'
                '<table><tr><th>Metric</th><th>Unit</th><th>N</th><th>Missing</th><th>Median</th><th>P95</th></tr>')
            for key,stat in resources.get("metrics",{}).items():
                stream.write('<tr>'+''.join('<td>'+escape(str(v if v is not None else "NOT_OBSERVED"))+'</td>'
                    for v in (key,stat["unit"],stat["observed_repeats"],stat["missing_repeats"],stat["median"],stat["p95"]))+'</tr>')
            stream.write('</table>')
            cursor=0
            while True:
                _check_cancel(cancel)
                p=evidence_page(staging,after_id=cursor,limit=500)
                for r in p["rows"]:
                    stream.write(f'<article id="evidence-{r["id"]}"><b>{r["elapsed_ms"]} ms — '+
                      escape(r["kind"])+"</b><br><small>"+escape(r["evidence_ref"]+" · "+r["source"]+" · "+r["quality"])+
                      "</small><pre>"+escape(json.dumps(r["data"],ensure_ascii=False,indent=2))+"</pre></article>")
                cursor=p["next_id"]
                if not p["has_more"]:break
        omitted=[]
        raw=folder/"artifacts"
        raw_files=[]
        if raw.is_dir() and not raw.is_symlink():
            for f in sorted(raw.iterdir()):
                if f.is_file() and not f.is_symlink():raw_files.append((f,"artifacts/"+f.name))
                else:omitted.append('artifacts/'+f.name+'/UNCONFIRMED_OR_NONREGULAR_NOT_PACKAGED')
        app_log=folder/"application-events.jsonl"
        if app_log.is_file() and not app_log.is_symlink():raw_files.append((app_log,"application-events.jsonl"))
        for f,name in raw_files:
            if include_sensitive:
                target=staging/name
                if target.parent!=staging and not target.parent.exists():tx.reserve('artifacts',directory=True)
                target=tx.reserve(name)
                with f.open('rb') as src,target.open('wb') as dst:
                    remaining=os.fstat(src.fileno()).st_size
                    while remaining:
                        _check_cancel(cancel);data=src.read(min(1024*1024,remaining))
                        if not data:raise ValueError("RAW_SOURCE_TRUNCATED_DURING_EXPORT")
                        dst.write(data);remaining-=len(data)
            else:omitted.append(name)
        for f in sorted(staging.rglob("*")):
            if f.is_file():entries.append({"name":f.relative_to(staging).as_posix(),
                "size":f.stat().st_size,"sha256":_hash(f,cancel)})
        if not include_sensitive:
            from .package_privacy import redact
            omitted=redact(omitted)
        manifest={"schema_version":1,"kind":"BLACKBOX_RESEARCH_PACKAGE",
            "files":entries,"omitted":omitted,"complete_package":not omitted and include_sensitive,
            "recording_state":meta.get("state"),"capture_health":meta.get("capture_health"),
            "coverage_assessment":"SOURCE_SPECIFIC_UNKNOWN_LOSS_IS_NOT_ZERO",
            "raw_source_policy":"BYTE_BOUNDARY_AT_EXPORT_NOT_TIME_ALIGNED",
            "csv_policy":"FORMULA_PREFIXES_ESCAPED_SOURCE_FIELDS_FOLLOW_PRIVACY_POLICY",
            "privacy":privacy,"integrity_is_not_authenticity":True,"sensitive_artifacts_included":include_sensitive}
        tx.reserve("manifest.json").write_text(compact(manifest),encoding="utf-8")
        archive=tx.reserve("package.zip")
        with zipfile.ZipFile(archive,"w",zipfile.ZIP_DEFLATED,allowZip64=True) as out:
            for f in sorted(staging.rglob("*")):
                if f.is_file() and f!=archive:
                    with f.open("rb") as src,out.open(f.relative_to(staging).as_posix(),"w",force_zip64=True) as dst:
                        for data in iter(lambda:src.read(1024*1024),b""):
                            _check_cancel(cancel);dst.write(data)
        # Same-filesystem exclusive link protects an existing destination.
        with archive.open("rb+") as stream:os.fsync(stream.fileno())
        digest=_hash(archive,cancel)
        _check_cancel(cancel)
        tx.prepare({destination.name:archive});tx.publish()
    return {"path":str(destination),"sha256":digest,"manifest":manifest}


def verify_package(path, *, max_total_bytes=4*1024**3):
    """Validate without extracting or executing any untrusted package member."""
    with zipfile.ZipFile(path) as z:
        infos=z.infolist();names=[i.filename for i in infos]
        if len(names)>10000 or len(set(names))!=len(names):raise ValueError("INVALID_PACKAGE_MEMBERS")
        if sum(i.file_size for i in infos)>max_total_bytes:raise ValueError("PACKAGE_SIZE_BUDGET_EXCEEDED")
        if any(n.startswith(("/","\\")) or "\\" in n or ":" in n or ".." in Path(n).parts for n in names):
            raise ValueError("INVALID_PACKAGE_PATH")
        if "manifest.json" not in names or z.getinfo("manifest.json").file_size>2*1024*1024:
            raise ValueError("INVALID_PACKAGE_MANIFEST")
        m=json.loads(z.read("manifest.json"))
        if m.get("kind")!="BLACKBOX_RESEARCH_PACKAGE" or type(m.get("files")) is not list:
            raise ValueError("INVALID_PACKAGE_MANIFEST")
        expected={r["name"] for r in m["files"]}
        if expected|{"manifest.json"} != set(names) or len(expected)!=len(m["files"]):
            raise ValueError("PACKAGE_MEMBER_MISMATCH")
        for r in m["files"]:
            info=z.getinfo(r["name"])
            if info.file_size!=r["size"]:raise ValueError("PACKAGE_SIZE_MISMATCH")
            digest=hashlib.sha256()
            with z.open(info) as stream:
                for data in iter(lambda:stream.read(1024*1024),b""):digest.update(data)
            if digest.hexdigest()!=r["sha256"]:raise ValueError("PACKAGE_HASH_MISMATCH")
        return {"integrity":"VERIFIED","authenticity":"UNVERIFIED","manifest":m}


def recover_case(folder,destination):
    """Copy committed observations; never alter the interrupted source."""
    import psutil
    folder,destination=Path(folder),Path(destination)
    original=context(folder)
    pid,created=original.get("worker_pid"),original.get("worker_created")
    if original.get("state")=="RECORDING" and pid is not None:
        try:
            p=psutil.Process(pid)
            if created is None or abs(p.create_time()-created)<.000001:
                raise ValueError("RECORDING_OWNER_STILL_ACTIVE")
        except psutil.NoSuchProcess:pass
    destination.mkdir(exist_ok=False)
    for name in ("session.sqlite3","session-v2.sqlite3","research.sqlite3","detail-v2.sqlite3"):
        source=folder/name
        if source.exists():
            with closing(readonly(source)) as src,closing(sqlite3.connect(destination/name)) as dst:
                src.backup(dst,pages=256,sleep=.01)
    with closing(sqlite3.connect(destination/"research.sqlite3")) as db:
        db.execute("INSERT OR REPLACE INTO context VALUES('recovery',?)",(compact({"original_state":original.get("state"),
            "source_folder":str(folder),"coverage":"COMMITTED_SQLITE_ROWS_ONLY","raw_artifacts_not_copied":True}),))
        db.execute("INSERT OR REPLACE INTO context VALUES('state','\"RECOVERED_INCOMPLETE\"')")
        db.commit()
    return {"folder":str(destination),"state":"RECOVERED_INCOMPLETE"}
