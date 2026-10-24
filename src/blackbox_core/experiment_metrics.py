"""Resource use over completed action intervals, with bounded offline quantiles.

Only adjacent, continuous cumulative-counter pairs are integrated. No boundary
extrapolation, unknown-to-zero conversion or counter-reset subtraction. Short
actions can legitimately have no observed resource pair.
"""
from __future__ import annotations
from contextlib import closing
import math
from pathlib import Path
import sqlite3
import tempfile

from .session_view import SessionView

METRICS={'cpu_seconds':'seconds','rss_peak_bytes':'bytes','rss_delta_bytes':'bytes',
    'private_peak_bytes':'bytes','private_delta_bytes':'bytes','handles_peak':'handles',
    'handles_delta':'handles','read_bytes':'bytes','write_bytes':'bytes','ui_timeouts':'events','read_ops':'ops','write_ops':'ops','uss_peak_bytes':'bytes','uss_delta_bytes':'bytes','threads_peak':'threads','sampling_gaps':'gaps','observation_errors':'events'}


def _valid(v):return type(v) in (int,float) and math.isfinite(v) and v>=0


def measure_interval(view,start,end,*,series):
    peaks={};first={};last={};field_counts={};totals={'cpu_seconds':0.,'read_bytes':0,'write_bytes':0,'read_ops':0,'write_ops':0}
    coverage={k:0 for k in totals};pairs={k:0 for k in totals}
    previous=None;samples=0;gaps=0;resets=0
    for row in view.reader.iter_samples(start,end,series=series,instance_id=1):
        samples+=1
        for field in ('rss_bytes','private_bytes','uss_bytes','handle_count','thread_count'):
            value=row.get(field)
            if _valid(value):
                field_counts[field]=field_counts.get(field,0)+1
                first.setdefault(field,value);last[field]=value;peaks[field]=max(peaks.get(field,value),value)
        if previous:
            dt=row['time_ns']-previous['time_ns'];requested=row.get('requested_interval_ns')
            continuous=(dt>0 and row['series_seq']==previous['series_seq']+1 and
                (not requested or dt<=max(2*requested,requested+500_000_000)))
            if not continuous:gaps+=1
            else:
                for metric,fields in (('cpu_seconds',('cpu_user_s','cpu_system_s')),
                    ('read_bytes',('read_bytes',)),('write_bytes',('write_bytes',)),('read_ops',('read_ops',)),('write_ops',('write_ops',))):
                    values=[(previous.get(k),row.get(k)) for k in fields]
                    if all(_valid(a) and _valid(b) for a,b in values):
                        if all(b>=a for a,b in values):
                            totals[metric]+=sum(b-a for a,b in values);pairs[metric]+=1;coverage[metric]+=dt
                        else:resets+=1
        previous=row
    metrics={m:totals[m] if pairs[m] else None for m in totals}
    for field,peak,delta in (('rss_bytes','rss_peak_bytes','rss_delta_bytes'),
        ('private_bytes','private_peak_bytes','private_delta_bytes'),('uss_bytes','uss_peak_bytes','uss_delta_bytes'),('handle_count','handles_peak','handles_delta')):
        metrics[peak]=peaks.get(field)
        metrics[delta]=last[field]-first[field] if field_counts.get(field,0)>=2 else None
    timeout=view.db.execute("SELECT count(*) FROM events WHERE event_type='UI_UNRESPONSIVE_OBSERVED' "
        "AND coalesce(observed_ns,recorded_ns) BETWEEN ? AND ?",(start,end)).fetchone()[0]
    # Zero is meaningful only if native observation was actually enabled.
    native=view.db.execute("SELECT count(*) FROM events WHERE source_kind='WIN32' AND event_type IN ('WINDOW_PROBE_RESULT','UI_UNRESPONSIVE_OBSERVED','UI_RESPONSIVE_AGAIN') AND measurement_status IN ('OK','SENSOR_TIMEOUT') "
        "AND coalesce(observed_ns,recorded_ns) BETWEEN ? AND ?",(start,end)).fetchone()[0]
    metrics['ui_timeouts']=timeout if native else None
    metrics['threads_peak']=peaks.get('thread_count');metrics['sampling_gaps']=gaps if samples>=2 else None
    has_errors=view.db.execute("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='sensor_errors'").fetchone()
    metrics['observation_errors']=view.db.execute('SELECT count(*) FROM sensor_errors WHERE monotonic_ns BETWEEN ? AND ?',(start,end)).fetchone()[0] if has_errors and samples else None
    return {'metrics':metrics,'samples':samples,'gaps':gaps,'counter_resets':resets,
        'pair_count':pairs,'covered_ns':coverage,
        'covered_fraction':{k:coverage[k]/max(1,end-start) for k in totals},
        'requested_ns':end-start,'source_series':series,'boundary_extrapolation':False}


def resource_statistics(folder,*,warmup_count=0):
    if type(warmup_count) is not int or not 0<=warmup_count<=10000:raise ValueError('INVALID_WARMUP_COUNT')
    folder=Path(folder)
    if not (folder/'session-v2.sqlite3').is_file():return {'status':'LEGACY_LIMITED_DATA','repeats':0,'metrics':{}}
    # SQLite owns the ordered quantiles, not an ever-growing Python run list.
    with SessionView.open(folder) as view, tempfile.TemporaryDirectory(prefix='blackbox-metric-quantiles-') as temp:
        if not view.is_v2:return {'status':'LEGACY_LIMITED_DATA','repeats':0,'metrics':{}}
        with closing(sqlite3.connect(Path(temp)/'values.sqlite3')) as db:
            db.execute('PRAGMA cache_size=-2048');db.execute('CREATE TABLE metric(metric TEXT,value REAL,coverage REAL)')
            count=0;preview=[];incomplete=0
            rows=view.db.execute("SELECT action_id,experiment_id,start_ns,end_ns FROM action_intervals "
                "WHERE state='COMPLETED' AND start_ns IS NOT NULL AND end_ns>=start_ns ORDER BY completed_ns,action_id LIMIT -1 OFFSET ?",(warmup_count,))
            for action in rows:
                count+=1;start,end=action['start_ns'],action['end_ns']
                # Detailed has private/handles; Standard is the primary CPU/I/O
                # feed. Never add the two series (that would double count).
                standard=measure_interval(view,start,end,series='STANDARD')
                detail=measure_interval(view,start,end,series='DETAILED')
                metrics=standard['metrics']
                for key in ('private_peak_bytes','private_delta_bytes','handles_peak','handles_delta','uss_peak_bytes','uss_delta_bytes'):
                    metrics[key]=detail['metrics'][key]
                if detail['metrics']['threads_peak'] is not None:metrics['threads_peak']=detail['metrics']['threads_peak']
                if not standard['pair_count']['cpu_seconds']:incomplete+=1
                for metric,value in metrics.items():
                    covered=standard['covered_fraction'].get(metric)
                    if value is not None:db.execute('INSERT INTO metric VALUES(?,?,?)',(metric,value,covered))
                if len(preview)<20:preview.append({'action_id':action['action_id'],'experiment_id':action['experiment_id'],
                    'interval_ns':[start,end],**standard,'metrics':dict(metrics),'detail_samples':detail['samples']})
            db.execute('CREATE INDEX ix_metric_order ON metric(metric,value)');db.commit()
            result={}
            for metric,unit in METRICS.items():
                n,coverage=db.execute('SELECT count(*),min(coverage) FROM metric WHERE metric=?',(metric,)).fetchone()
                def q(percent):
                    if not n:return None
                    index=(n-1)*percent;lo=int(index);hi=math.ceil(index)
                    values=[r[0] for r in db.execute('SELECT value FROM metric WHERE metric=? ORDER BY value LIMIT ? OFFSET ?',(metric,hi-lo+1,lo))]
                    return values[0]+(values[-1]-values[0])*(index-lo)
                result[metric]={'unit':unit,'observed_repeats':n,'missing_repeats':count-n,
                    'minimum':q(0),'median':q(.5),'p95':q(.95),'maximum':q(1),
                    'minimum_observed_fraction':coverage}
            return {'status':'OBSERVED_INTERVALS' if count else 'NO_COMPLETED_ACTIONS','repeats':count,
                'warmups_excluded':warmup_count,'resource_unobserved_runs':incomplete,'metrics':result,
                'runs_preview':preview,'runs_omitted_from_preview':max(0,count-len(preview)),
                'file_trust':'UNVERIFIED_IMPORT','warnings':(['P95_UNSTABLE_SMALL_SAMPLE'] if count<20 else [])+
                    (['ACTIONS_WITHOUT_RESOURCE_PAIRS'] if incomplete else []),
                'limitations':['COUNTERS_WITHIN_ACTION_ONLY_NO_BOUNDARY_EXTRAPOLATION',
                    'MISSING_NATIVE_OBSERVATION_IS_NOT_ZERO_TIMEOUTS','RESOURCE_GROWTH_IS_NOT_PROVEN_LEAK']}


def compare_resources(before,after):
    result={}
    for key,unit in METRICS.items():
        a=before.get('metrics',{}).get(key,{});b=after.get('metrics',{}).get(key,{})
        av,bv=a.get('median'),b.get('median')
        delta=bv-av if av is not None and bv is not None else None
        result[key]={'unit':unit,'before_median':av,'after_median':bv,'absolute_delta':delta,
            'percent_delta':100*delta/abs(av) if delta is not None and av!=0 else None,
            'before_observed_repeats':a.get('observed_repeats',0),'after_observed_repeats':b.get('observed_repeats',0),
            'sufficient_repeats':min(a.get('observed_repeats',0),b.get('observed_repeats',0))>=2}
    return result
