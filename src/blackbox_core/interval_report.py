"""Offline schema2 interval exports, streamed CSV and explicit ZIP selection.

Publication uses exclusive hard links. Rollback removes only files still
sharing the stage inode, never a different writer's replacement. Inputs and
previous reports are read-only. No arbitrary files enter a bundle.
"""
from __future__ import annotations
import csv
from html import escape
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from uuid import uuid4
import zipfile

from .session_v2 import FILENAME, UNITS, safe_path
from .session_view import SessionView, SessionReadError


def digest(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()


def _redact_metadata(report,include_identifiers):
    if not include_identifiers:
        report["metadata"]={k:v for k,v in report["metadata"].items()
            if k not in ("pid","creation_time","executable_name","session_uuid")}


def human_html(report,threads):
    def safe(value):
        return escape(str(value if value is not None else "UNAVAILABLE"),quote=True)
    metrics="".join("<tr>"+"".join("<td>"+safe(v)+"</td>" for v in (
        key,stat["unit"],stat["observed_count"],stat["missing_count"],stat["min"],stat["max"],
        stat["mean"],stat["delta"]))+"</tr>" for key,stat in report["metrics"].items())
    rows="".join("<tr>"+"".join("<td>"+safe(r.get(key))+"</td>" for key in (
        "tid","segment_start_seq","cpu_seconds","cpu_percent","peak_cpu_percent",
        "observed_presence_percent"))+"</tr>" for r in threads.get("top_threads",()))
    native="".join("<tr>"+"".join("<td>"+safe(row[key])+"</td>" for key in
        ("source_kind","event_type","measurement_status","count"))+"</tr>"
        for row in report.get("native_windows_observations",{}).get("counts",()))
    charts=[]
    lo,hi=report["selected_interval_ns"]
    for key,points in report["timeline"]["tracks"].items():
        if not points:
            continue
        maximum=max(p["value"] for p in points) or 1
        if key=="cpu_interval_percent":
            maximum=max(100,maximum)
        paths=[]
        segment=None
        for p in points:
            command="M" if p["segment"]!=segment else "L"
            paths.append(f'{command}{10+780*(p["time_ns"]-lo)/max(1,hi-lo):.3f},'
                         f'{95-80*p["value"]/maximum:.3f}')
            segment=p["segment"]
        charts.append("<h3>"+safe(key)+"</h3><p>0–"+safe(maximum)+" "+
            safe(report["metrics"][key]["unit"])+"</p><svg viewBox='0 0 800 110' role='img' "
            "aria-label='First min max last, gaps retained'><path fill='none' stroke='#246d70' "
            "stroke-width='2' d='"+" ".join(paths)+"'/></svg>")
    return ("<!doctype html><html lang='ru'><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<title>BLACK.BOX — selected interval</title><style>body{font:15px sans-serif;max-width:1100px;"
        "margin:2em auto;padding:1em;background:#fffaf0;color:#302c43}table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #d8c8c8;padding:.4em}svg{width:100%;max-height:160px}pre{white-space:pre-wrap}</style>"
        "<h1>Расследование выбранного интервала / Interval investigation</h1>"
        "<h2>Что наблюдалось / Observations</h2><p>Samples: "+safe(report["coverage"]["selected_samples"])+
        "; range (monotonic ns): "+safe([lo,hi])+"; source: PSUTIL; file trust: UNVERIFIED_IMPORT.</p>"
        "<h2>Подтверждающие измерения / Supporting measurements</h2>"
        "<p>Statistics use every available selected row. Plots use first/min/max/last; gaps are not zero. "
        "CPU 100% equals one logical CPU; multicore values may exceed 100%.</p>"
        "<table><tr><th>Metric</th><th>Unit</th><th>Observed</th><th>Missing</th><th>Min</th>"
        "<th>Max</th><th>Mean</th><th>Delta</th></tr>"+metrics+"</table>"+"".join(charts)+
        "<h2>Потоки / Threads</h2><p>Ranked by cumulative CPU over valid adjacent pairs. "
        "Presence is the fraction of observed snapshots, not continuous lifetime. Hidden segments: "+
        safe(threads.get("omitted_from_top"))+"</p><table><tr><th>TID</th><th>Segment</th><th>CPU seconds</th>"
        "<th>Mean CPU %</th><th>Peak CPU %</th><th>Observed presence %</th></tr>"+rows+"</table>"
        "<h2>Windows / WCT</h2><p>Recorded producer observations; source file is UNVERIFIED_IMPORT.</p>"
        "<table><tr><th>Source</th><th>Observation</th><th>Status</th><th>Count</th></tr>"+native+"</table>"
        "<h2>Что нельзя установить / Limitations</h2><p>Root cause: UNKNOWN. "
        "Memory growth is not proof of a leak; a CPU sample is not WCT or Windows UI evidence. "
        "TID reuse cannot be excluded. Bounds exclude partial counter pairs; activity between samples is unknown.</p>"
        "<pre>"+safe(json.dumps(report["coverage"],ensure_ascii=False,indent=2))+"</pre>"
        "<h2>Checksums / Контрольные суммы источников</h2><pre>"+
        safe(json.dumps(report.get("source_checksums",{}),indent=2))+"</pre></html>")


def export_interval(folder: Path,output: Path,*,interval=None,series=None,instance_id=1,
                    include_identifiers=False,include_notes=False,bundle=False,prefix=None,cancel=None):
    if any(type(flag) is not bool for flag in (include_identifiers,include_notes,bundle)):
        raise ValueError("INVALID_EXPORT_CONSENT")
    folder,output=safe_path(folder),safe_path(output)
    if not output.is_dir():
        raise ValueError("EXPORT_DIRECTORY_REQUIRED")
    prefix=prefix or "interval-"+uuid4().hex
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}",prefix):
        raise ValueError("INVALID_EXPORT_PREFIX")
    stage={}
    published=[]
    try:
        with SessionView.open(folder,cancel=cancel) as view:
            if (view.metadata["recorded_status"]!="CLOSED" if view.is_v2 else
                    view.metadata["recorded_status"] is None):
                raise SessionReadError("EXPORT_REQUIRES_CLOSED_SESSION")
            series=series or ("DETAILED" if view.is_v2 and view.bounds("DETAILED",instance_id)[2]
                              else "STANDARD" if instance_id==1 else "CHILD")
            start,end=interval or (None,None)
            report=view.interval(start,end,series=series,instance_id=instance_id)
            threads=view.thread_summary(start,end,instance_id=instance_id)
            report["thread_cpu_analysis"]=threads
            report["privacy"]={"process_identifiers_included":include_identifiers,
                               "user_notes_included":include_notes,"raw_databases_included":False,
                               "traces_or_dumps_included":False}
            report["source_checksums"]={}
            for name in ("session.sqlite3",FILENAME):
                path=safe_path(folder/name)
                if path.is_file():
                    report["source_checksums"][name]=digest(path)
            _redact_metadata(report,include_identifiers)
            if not include_identifiers:
                for row in threads.get("top_threads",()):
                    row.pop("pid",None)
                    row.pop("tid",None)
            def stage_file(suffix):
                fd,name=tempfile.mkstemp(prefix=".bb-interval-",suffix=".tmp",dir=output)
                os.close(fd)
                path=Path(name)
                stage[prefix+suffix]=path
                return path
            csv_path=stage_file(".csv")
            lo,hi=report["selected_interval_ns"]
            with csv_path.open("w",encoding="utf-8",newline="") as stream:
                writer=csv.writer(stream)
                writer.writerow(("time_monotonic_ns",*UNITS))
                for index,row in enumerate(view.reader.iter_samples(lo,hi,series=series,instance_id=instance_id)):
                    if cancel is not None and index%256==0 and cancel():
                        raise SessionReadError("CANCELLED")
                    values=[row.get(key) for key in UNITS]
                    if any(v is not None and (type(v) not in (int,float) or not math_isfinite(v)) for v in values):
                        raise SessionReadError("INVALID_IMPORTED_COUNTER")
                    writer.writerow((row["time_ns"],*values))
            report["csv_sha256"]=digest(csv_path)
            event_path=stage_file(".events.jsonl")
            event_count=0
            cursor=(0,0)
            with event_path.open("w",encoding="utf-8") as stream:
                while True:
                    page=view.event_page(lo,hi,after=cursor,limit=200)
                    for event in page["rows"]:
                        # Raw detail is opt-in. Arbitrary strings in imported
                        # JSON never affect the reader-assigned trust class.
                        if not include_notes:
                            detail=event.pop("detail",{})
                            if event.get("source_kind") in ("WIN32","WCT"):
                                event["detail"]={k:detail[k] for k in ("check","wct","window",
                                    "consecutive_timeouts","first_timeout_ns","last_responsive_ns",
                                    "onset_exact","duration_is_observation_bound") if k in detail}
                        elif "detail" in event:
                            # Explicitly selected user notes, not arbitrary
                            # imported command lines, titles or environment.
                            detail=event["detail"]
                            event["detail"]={k:detail[k] for k in ("note","comment") if
                                k in detail and detail.get("kind") in ("user_problem","user_marker")}
                        if not include_identifiers:
                            event.pop("instance_id",None)
                            if "detail" in event:
                                for key in ("pid","pid_creation_time"):
                                    event["detail"].pop(key,None)
                            def strip_ids(value):
                                if isinstance(value,dict):
                                    return {k:strip_ids(v) for k,v in value.items() if k not in
                                            ("pid","tid","hwnd","pid_creation_time")}
                                if isinstance(value,list):
                                    return [strip_ids(v) for v in value]
                                return value
                            if "detail" in event:
                                event["detail"]=strip_ids(event["detail"])
                        stream.write(json.dumps(event,ensure_ascii=False,allow_nan=False)+"\n")
                        event_count+=1
                    if not page["has_more"]:
                        break
                    cursor=page["next_cursor"]
            report["event_export"]={"count":event_count,"file":prefix+".events.jsonl",
                                    "sha256":digest(event_path)}
            stage_file(".html").write_text(human_html(report,threads),encoding="utf-8")
            stage_file(".json").write_text(json.dumps(report,ensure_ascii=False,allow_nan=False,indent=2)+"\n",encoding="utf-8")
            manifest={"schema_version":2,"privacy":report["privacy"],"files":[
                {"filename":name,"sha256":digest(path),"size_bytes":path.stat().st_size}
                for name,path in stage.items()]}
            stage_file(".manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
            if bundle:
                members=list(stage.items())
                archive=stage_file(".zip")
                with zipfile.ZipFile(archive,"w",compression=zipfile.ZIP_DEFLATED) as z:
                    for name,path in members:
                        z.write(path,name)
            for name,path in stage.items():
                with path.open("r+b") as f:
                    os.fsync(f.fileno())
                destination=output/name
                os.link(path,destination)
                published.append((path,destination))
            return {"schema_version":2,"files":[str(target) for _,target in published],
                    "sample_count":report["coverage"]["selected_samples"],"event_count":event_count,
                    "manifest":str(output/(prefix+".manifest.json")),"report":report}
    except Exception:
        for path,target in reversed(published):
            try:
                if os.path.samestat(path.stat(),target.lstat()):
                    target.unlink()
            except OSError:
                pass
        raise
    finally:
        for path in stage.values():
            path.unlink(missing_ok=True)


def math_isfinite(value):
    # Keep raw JSON/CSV numeric contracts finite even for adversarial SQLite.
    import math
    return math.isfinite(value) and value>=0
