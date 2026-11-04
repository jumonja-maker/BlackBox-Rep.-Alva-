"""Bounded statistics for explicitly user-timed application action experiments.

This is command-to-command duration, not target-internal function runtime.
No statistical significance or causal speedup can be inferred from these values.
"""
from __future__ import annotations

import math
import hashlib
import os
from pathlib import Path
import stat
import sys
import time
from uuid import uuid4
from statistics import median

_LIMIT = 20
_MAX_GROUPS = 16
_MAX_NS = 30 * 24 * 3600 * 1_000_000_000


def _recorded_instance(value):
    if type(value) is not dict:return None
    from .deep_contracts import ProcessIdentity
    try:return ProcessIdentity(value.get('pid'),value.get('created_100ns'))
    except (TypeError,ValueError):return None


def capture_run_identity(pid, *, expected_created=None, max_image_bytes=512*1024*1024,
                         timeout_seconds=2.0):
    """Record one run's actual image/instance, without granting privileges.

    The image hash detects content identity, not publisher authentication.
    Missing access/time budget leaves an explicit unknown and never prevents
    ordinary observation. Hashing occurs before the recording starts.
    """
    if (type(pid) is not int or pid<=0 or
        expected_created is not None and (type(expected_created) not in (int,float) or not math.isfinite(expected_created) or expected_created<=0) or
        type(max_image_bytes) is not int or
        not 1024<=max_image_bytes<=1024**3 or type(timeout_seconds) not in (int,float) or
        not math.isfinite(timeout_seconds) or not 0<timeout_seconds<=10):
        raise ValueError('INVALID_RUN_IDENTITY_BUDGET')
    result={'schema_version':1,'run_id':uuid4().hex,'process_identity':None,
        'identity_status':'NOT_ESTABLISHED','image':None,'image_status':'NOT_OBSERVED',
        'producer_authentication':'NOT_ESTABLISHED',
        'hash_budget':{'max_image_bytes':max_image_bytes,'timeout_seconds':timeout_seconds,
            'enforcement':'COOPERATIVE_BETWEEN_LOCAL_FILE_READS'},
        'clock_domain':{'source':'BLACKBOX_LOCAL_MONOTONIC_NS',
            'cross_run_alignment':'NOT_ESTABLISHED',
            'measurement_semantics':'WITHIN_RUN_DURATIONS_ONLY'},'limitations':[]}
    started=time.monotonic();deadline=started+timeout_seconds
    try:
        from blackbox_universal import __version__ as recorder_version
        result['recorder_version']=recorder_version
        if getattr(sys,'frozen',False):
            from blackbox_universal.provenance import source_identity
            result['recorder_build']=source_identity()
        else:result['recorder_build']={'status':'SOURCE_BUILD_NOT_RECORDED_AT_RUNTIME'}
    except Exception:
        result.setdefault('recorder_version',None)
        result['recorder_build']={'status':'NOT_RECORDED'}
    try:
        import psutil
        process=psutil.Process(pid)
        before_created=process.create_time()
        if expected_created is not None and abs(before_created-expected_created)>0.000001:
            raise ValueError('TARGET_INSTANCE_CHANGED')
        if os.name=='nt':
            from .deep_native import capture_identity, verify_identity
            identity=capture_identity(pid)
            result['process_identity']={'pid':identity.pid,'created_100ns':identity.created_100ns}
            result['identity_status']='OS_OBSERVED_EXACT_FILETIME'
            image=Path(identity.image_path)
        else:
            identity=None
            result['process_identity']={'pid':pid,'created_unix_seconds':before_created}
            result['identity_status']='PSUTIL_BIRTH_NOT_WINDOWS_FILETIME'
            image=Path(process.exe())
        raw_path=str(image)
        if raw_path.startswith('//') or raw_path.startswith('\\\\') and (
            not raw_path.startswith('\\\\?\\') or raw_path.upper().startswith('\\\\?\\UNC\\')):
            raise ValueError('NETWORK_IMAGE_HASH_NOT_ATTEMPTED')
        # No arbitrary caller-supplied file or symbol-server download.
        for entry in (image,*image.parents):
            st=entry.lstat()
            if stat.S_ISLNK(st.st_mode) or getattr(st,'st_file_attributes',0)&0x400:
                raise ValueError('IMAGE_PATH_REPARSE_OR_SYMLINK')
        digest=hashlib.sha256();count=0
        with image.open('rb') as stream:
            before=os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size>max_image_bytes:
                raise ValueError('IMAGE_SIZE_BUDGET_EXCEEDED')
            while True:
                if time.monotonic()>=deadline:raise TimeoutError('IMAGE_HASH_DEADLINE')
                block=stream.read(min(1024*1024,max_image_bytes-count+1))
                if not block:break
                count+=len(block)
                if count>max_image_bytes:raise ValueError('IMAGE_SIZE_BUDGET_EXCEEDED')
                digest.update(block)
            after=os.fstat(stream.fileno())
        key=lambda item:(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns)
        if key(before)!=key(after) or key(after)!=key(image.stat()) or count!=before.st_size:
            raise ValueError('IMAGE_CHANGED_DURING_HASH')
        file_version=None
        if identity is not None:
            from .deep_native import _file_version
            file_version=_file_version(str(image))
            if key(after)!=key(image.stat()):raise ValueError('IMAGE_CHANGED_DURING_HASH')
        if identity is not None:verify_identity(identity)
        elif process.create_time()!=before_created:raise ValueError('TARGET_INSTANCE_CHANGED')
        if time.monotonic()>=deadline:raise TimeoutError('IMAGE_HASH_DEADLINE')
        from .investigation_graph_contracts import stable_id
        value=digest.hexdigest()
        result['image']={'source_id':stable_id('application-image',value,count),
            'source_type':'APPLICATION_IMAGE','source_sha256':value,'source_size_bytes':count,
            'provenance':'LOCAL_OS_IMAGE_PATH_HASH_AT_CAPTURE',
            'file_version':file_version,
            'producer_authentication':'NOT_ESTABLISHED','content_integrity':'HASHED_STABLE_FILE'}
        result['image_status']='HASHED_STABLE_FILE'
    except Exception as exc:
        # Fixed error code/type only; no source image path or arbitrary text.
        result['image_status']='NOT_OBSERVED'
        reason=getattr(exc,'reason',None)
        if reason is None:reason=str(exc) if type(exc) in (ValueError,TimeoutError) else type(exc).__name__
        if reason in ('TARGET_INSTANCE_CHANGED','PROCESS_INSTANCE_CHANGED','PROCESS_ALREADY_EXITED') or getattr(exc,'status',None)=='PROCESS_CHANGED':
            result['identity_status']='PROCESS_CHANGED_DURING_CAPTURE'
        result['limitations'].append(reason)
        result['limitations']=[str(v)[:128] for v in result['limitations']]
    result['capture_elapsed_ms']=round((time.monotonic()-started)*1000,3)
    return result


def assess_comparability(first, second, *, before_resources, after_resources,
                         before_repeats, after_repeats, context_mismatches=()):
    """Compare recorded conditions, retaining each exact run's identity.

    Distinct process instances can repeat the same measured workload/build;
    they never become the same evidence target. No cross-run timestamp
    alignment, producer authentication, significance or causal fix is inferred.
    """
    mismatches=list(context_mismatches);unknown=[];runs=[]
    for label,meta,resources,repeats in (('before',first,before_resources,before_repeats),
                                        ('after',second,after_resources,after_repeats)):
        exp=meta.get('experiment',{})
        if type(exp) is not dict:
            unknown.append(label+'.experiment_context');runs.append({});continue
        run=exp.get('run_identity')
        if type(run) is not dict:
            unknown.append(label+'.run_identity');runs.append({});continue
        runs.append(run)
        target=run.get('process_identity',{})
        if (run.get('identity_status')!='OS_OBSERVED_EXACT_FILETIME' or _recorded_instance(target) is None):
            unknown.append(label+'.exact_process_identity')
        image=run.get('image')
        if (type(image) is not dict or image.get('content_integrity')!='HASHED_STABLE_FILE' or
            type(image.get('source_sha256')) is not str or len(image['source_sha256'])!=64 or
            any(c not in '0123456789abcdef' for c in image['source_sha256'])):
            unknown.append(label+'.image_hash')
        clock=run.get('clock_domain',{})
        if type(clock) is not dict or clock.get('source')!='BLACKBOX_LOCAL_MONOTONIC_NS' or type(exp.get('origin_monotonic_ns')) is not int:
            unknown.append(label+'.local_clock')
        if meta.get('state') not in ('COMPLETED','USER_STOPPED'):
            unknown.append(label+'.recording_not_complete')
        health=meta.get('capture_health',{})
        if type(health) is not dict:health={}
        if (health.get('finalization_errors') or health.get('recording_resources_closed') is not True):
            unknown.append(label+'.cleanup_not_confirmed')
        if type(repeats) is not int or repeats<2:unknown.append(label+'.insufficient_repeats')
        required=['cpu_seconds','rss_peak_bytes','read_bytes','write_bytes']
        policy=exp.get('capture_policy',{})
        if exp.get('profile')=='DETAILED':required+=['private_peak_bytes','handles_peak']
        if type(policy) is dict and policy.get('windows_enabled'):required.append('ui_timeouts')
        for key in required:
            metric=resources.get('metrics',{}).get(key,{})
            if (metric.get('median') is None or metric.get('missing_repeats',1) or
                key in ('cpu_seconds','read_bytes','write_bytes') and
                (metric.get('minimum_observed_fraction') is None or metric['minimum_observed_fraction']<.8)):
                unknown.append(label+'.sensor_coverage.'+key)
        incident=health.get('incident_coverage')
        if type(incident) is dict and (incident.get('dropped_triggers') or incident.get('samples_not_retained') or incident.get('capacity_evictions')):
            unknown.append(label+'.incident_retention_loss')
    a,b=runs
    ia=a.get('image') if type(a.get('image')) is dict else {}
    ib=b.get('image') if type(b.get('image')) is dict else {}
    if ia.get('source_sha256') and ib.get('source_sha256') and ia['source_sha256']!=ib['source_sha256']:
        mismatches.append('target_image_hash')
    ca,cb=first.get('experiment',{}),second.get('experiment',{})
    if type(ca) is not dict:ca={}
    if type(cb) is not dict:cb={}
    for key in ('scenario','workload','profile','interval_ms'):
        if not ca.get(key) or not cb.get(key):unknown.append('context.'+key)
        elif ca[key]!=cb[key]:mismatches.append(key)
    if ca.get('capture_policy')!=cb.get('capture_policy'):mismatches.append('capture_policy')
    if ca.get('scenario_version')!=cb.get('scenario_version'):mismatches.append('scenario_version')
    if ca.get('warmup_count',0)!=cb.get('warmup_count',0):mismatches.append('warmup_count')
    if ca.get('target_version')!=cb.get('target_version'):mismatches.append('target_version')
    if type(a.get('run_id')) is str and a.get('run_id') and a.get('run_id')==b.get('run_id'):
        mismatches.append('same_recording_reused')
    relation='NOT_ESTABLISHED'
    pa,pb=_recorded_instance(a.get('process_identity')),_recorded_instance(b.get('process_identity'))
    if pa is not None and pb is not None and a.get('identity_status')==b.get('identity_status')=='OS_OBSERVED_EXACT_FILETIME':
        relation='SAME_EXACT_INSTANCE' if (pa.pid,pa.created_100ns)==(pb.pid,pb.created_100ns) else 'DISTINCT_EXACT_INSTANCES'
    status='NOT_COMPARABLE' if mismatches else 'INCONCLUSIVE' if unknown else 'COMPARABLE'
    return {'schema_version':1,'status':status,'context_mismatches':list(dict.fromkeys(mismatches)),
        'unknowns':list(dict.fromkeys(unknown)),
        'run_contexts':{'before':a,'after':b},'process_relation':relation,
        'identity_merge_performed':False,'cross_run_clock_alignment':'NOT_ESTABLISHED',
        'semantics':'RECORDED_CONDITIONS_AND_WITHIN_RUN_METRICS_ONLY',
        'file_trust':'UNVERIFIED_IMPORT','speedup_proven':False,'causal_link_proven':False}


def validate_comparison_presentation(value):
    """Reject malformed imported numeric/text shapes before they reach Qt."""
    def number(v):return v is None or type(v) in (int,float) and abs(v)<=2**64-1 and math.isfinite(v)
    def fail():raise ValueError('INVALID_COMPARISON_REPORT')
    if type(value) is not dict or type(value.get('schema_version')) is not int or value['schema_version']!=2 or type(value.get('comparable_context')) is not bool:fail()
    if (value.get('comparison_status')=='COMPARABLE')!=value['comparable_context']:fail()
    for key in ('context_mismatches','context_warnings'):
        rows=value.get(key,[])
        if type(rows) is not list or len(rows)>128 or any(type(v) is not str or len(v)>256 for v in rows):fail()
    flags=value.get('comparison_flags',{})
    if type(flags) is not dict or len(flags)>64 or any(type(k) is not str or len(k)>128 or type(v) is not bool for k,v in flags.items()):fail()
    comparability=value.get('comparability',{})
    if type(comparability) is not dict:fail()
    unknowns=comparability.get('unknowns',[])
    if type(unknowns) is not list or len(unknowns)>128 or any(type(v) is not str or len(v)>256 for v in unknowns):fail()
    if comparability.get('process_relation') not in (None,'NOT_ESTABLISHED','SAME_EXACT_INSTANCE','DISTINCT_EXACT_INSTANCES'):fail()
    duration=value.get('duration_comparison')
    if duration is not None:
        if type(duration) is not dict:fail()
        if any(not number(duration.get(k)) for k in ('before_median','after_median','absolute_delta','percent_delta')):fail()
        if any(type(duration.get(k)) is not int or not 0<=duration[k]<=10000000 for k in ('before_repeats','after_repeats')):fail()
        for key in ('before_variability','after_variability'):
            row=duration.get(key)
            if row is not None and (type(row) is not dict or any(k not in row or not number(row[k]) for k in ('iqr','sample_stddev'))):fail()
    resources=value.get('resource_comparison',{})
    from .experiment_metrics import METRICS
    if type(resources) is not dict or len(resources)>len(METRICS):fail()
    for key,row in resources.items():
        if key not in METRICS or type(row) is not dict or row.get('unit')!=METRICS[key]:fail()
        if any(not number(row.get(k)) for k in ('before_median','after_median','absolute_delta','percent_delta')):fail()
        if any(type(row.get(k)) is not int or not 0<=row[k]<=10000000 for k in ('before_observed_repeats','after_observed_repeats')):fail()
        if type(row.get('sufficient_repeats')) is not bool:fail()
    return value


def _p95(values: list[float]) -> float:
    ordered = sorted(values)
    index = (len(ordered) - 1) * 0.95
    lo = int(index)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (index - lo)


def _valid_id(value: object) -> bool:
    return (type(value) is str and len(value) == 32 and
            all(ch in "0123456789abcdef" for ch in value))


class ExperimentAccumulator:
    """Stream completed action rows without retaining arbitrary event text."""

    def __init__(self):
        self._groups: dict[str, dict] = {}
        self.invalid = 0
        self.groups_omitted = 0

    def observe(self, event: object) -> None:
        if type(event) is not dict or event.get("kind") != "action_marker":
            return
        if event.get("event") != "ACTION_COMPLETED":
            return
        eid, aid = event.get("experiment_id"), event.get("action_id")
        duration = event.get("duration_ns")
        if not (_valid_id(eid) and _valid_id(aid) and
                type(duration) is int and 0 <= duration <= _MAX_NS):
            self.invalid += 1
            return
        group = self._groups.get(eid)
        if group is None:
            if len(self._groups) >= _MAX_GROUPS:
                self.groups_omitted += 1
                return
            group = {"experiment_id": eid, "durations_ns": [],
                     "seen_actions": set(), "duplicates": 0, "omitted": 0}
            self._groups[eid] = group
        if aid in group["seen_actions"]:
            group["duplicates"] += 1
            return
        # Limit memory, but preserve a correct 'partial coverage' warning.
        if len(group["seen_actions"]) >= _LIMIT:
            group["omitted"] += 1
            return
        group["seen_actions"].add(aid)
        group["durations_ns"].append(duration)

    def result(self) -> dict:
        groups = []
        for group in self._groups.values():
            values = [v / 1_000_000 for v in group["durations_ns"]]
            middle = median(values)
            mad = median([abs(x - middle) for x in values])
            groups.append({
                "experiment_id": group["experiment_id"],
                "repeats": len(values),
                "duration_ms": {
                    "minimum": round(min(values), 3),
                    "median": round(middle, 3),
                    "p95": round(_p95(values), 3),
                    "maximum": round(max(values), 3),
                    "mad": round(mad, 3),
                },
                "actions_omitted": group["omitted"],
                "duplicate_markers_ignored": group["duplicates"],
                "warnings": (["INSUFFICIENT_REPEATS"] if len(values) < 2 else []) +
                            (["PARTIAL_COVERAGE"] if group["omitted"] else []),
                "source": "USER_COMMAND_UNVERIFIED",
                "runtime_semantics": "TIME_BETWEEN_USER_COMMANDS_NOT_INTERNAL_FUNCTION",
            })
        return {"experiments": groups, "groups_omitted": self.groups_omitted,
                "invalid_completed_markers": self.invalid,
                "root_cause_proven": False}


def compare_experiments(first: dict, second: dict, *,
                        same_workload: bool = False) -> dict:
    """Conservative comparison; caller must explicitly affirm same workload."""
    for candidate in (first, second):
        if (type(candidate) is not dict or
                type(candidate.get("repeats")) is not int or
                not 1 <= candidate["repeats"] <= _LIMIT or
                type(candidate.get("duration_ms")) is not dict):
            raise ValueError("INVALID_EXPERIMENT")
        metrics = candidate["duration_ms"]
        for key in ("median", "p95", "minimum", "maximum"):
            number = metrics.get(key)
            if type(number) not in (int, float) or not math.isfinite(number) or number < 0:
                raise ValueError("INVALID_EXPERIMENT")
    base = first["duration_ms"]["median"]
    new = second["duration_ms"]["median"]
    warnings = []
    if first["repeats"] < 5 or second["repeats"] < 5:
        warnings.append("INSUFFICIENT_REPEATS")
    if not same_workload:
        warnings.append("INCOMPARABLE_CONFIG_NOT_VERIFIED")
    if first.get("actions_omitted") or second.get("actions_omitted"):
        warnings.append("PARTIAL_COVERAGE")
    return {
        "before_median_ms": base, "after_median_ms": new,
        "delta_median_ms": round(new-base, 3),
        "relative_change_percent": round(100*(new-base)/base, 3) if base else None,
        "warnings": warnings,
        "speedup_proven": False,
        "causal_link_proven": False,
        "semantics": "USER_COMMAND_DURATION_COMPARISON",
    }
