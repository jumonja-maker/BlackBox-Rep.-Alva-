"""Bounded multi-signal incident windows over actual measurements.

An incident is an observed threshold/context window, never proof of a leak,
hang or internal cause. Pre/post references address persisted sample ranges;
unavailable sensors remain NULL and are not interpreted as zero.
"""
from __future__ import annotations
from collections import deque
import json
import math


class IncidentCapture:
    def __init__(self, *, threshold=85.0, min_duration_ms=3000,
                 gap_ms=5500, pre_ms=60000, post_ms=20000,
                 cooldown_ms=30000, max_incidents=20,
                 memory_growth_bytes=32*1024*1024, handle_growth=128,
                 growth_window_ms=10000, io_rate_bytes_s=64*1024*1024,
                 gap_incidents=False, enabled_triggers=None, cpu_reference="ABSOLUTE",
                 max_buffer_samples=512, max_buffer_bytes=1024*1024):
        if (type(threshold) not in (float,int) or not math.isfinite(threshold) or not 0<threshold<=6400 or
            any(type(x) is not int or x<0 for x in (min_duration_ms,gap_ms,pre_ms,post_ms,cooldown_ms,
                memory_growth_bytes,handle_growth,growth_window_ms,io_rate_bytes_s)) or
            type(max_incidents) is not int or not 1<=max_incidents<=1000 or post_ms>60000 or
            growth_window_ms>60000 or any(value>86400000 for value in (pre_ms,gap_ms,min_duration_ms,cooldown_ms)) or
            type(gap_incidents) is not bool or
            type(max_buffer_samples) is not int or not 1<=max_buffer_samples<=4096 or
            type(max_buffer_bytes) is not int or not 1024<=max_buffer_bytes<=16*1024*1024):
            raise ValueError('INVALID_INCIDENT_POLICY')
        from .capture_policy import TRIGGERS
        if enabled_triggers is not None and (type(enabled_triggers) not in (list,tuple) or not enabled_triggers or any(t not in TRIGGERS for t in enabled_triggers)):
            raise ValueError('INVALID_INCIDENT_TRIGGERS')
        if cpu_reference not in ('ABSOLUTE','BASELINE_DELTA'):raise ValueError('INVALID_CPU_REFERENCE')
        self.enabled_triggers=frozenset(TRIGGERS if enabled_triggers is None else enabled_triggers)
        self.cpu_reference=cpu_reference;self._baseline_cpu=[]
        self.threshold=float(threshold);self.min_duration_ms=min_duration_ms;self.gap_ms=gap_ms
        self.pre_ms=pre_ms;self.post_ms=post_ms;self.cooldown_ms=cooldown_ms;self.max_incidents=max_incidents
        self.memory_growth_bytes=memory_growth_bytes;self.handle_growth=handle_growth
        self.growth_window_ms=growth_window_ms;self.io_rate_bytes_s=io_rate_bytes_s;self.gap_incidents=gap_incidents
        self.max_buffer_samples=max_buffer_samples;self.max_buffer_bytes=max_buffer_bytes
        self._history=deque(maxlen=max_buffer_samples);self._history_costs=deque()
        self._buffer_bytes=0;self._last_seq=None;self._last_gap_ms=None
        self.observed_samples=0;self.time_evictions=0;self.byte_evictions=0
        self.samples_not_retained=0;self.sampling_gaps=0
        self._missing={key:0 for key in ('cpu_percent','rss_bytes','private_bytes','handle_count','read_bytes','write_bytes')}
        self._last_time=None;self._cpu_since=None;self._active=None;self._requires_rearm=False
        self._next_allowed_ms=0;self._latched=set();self._previous_io=None
        self.incidents=0;self.buffer_evictions=0;self.dropped_triggers=0

    @staticmethod
    def _valid(value):return value is None or type(value) in (int,float) and 0<=value<=2**64-1 and math.isfinite(value)

    def _evict(self, reason):
        self._history.popleft();self._buffer_bytes-=self._history_costs.popleft()
        if reason=='TIME':self.time_evictions+=1
        else:
            self.buffer_evictions+=1
            if reason=='BYTES':self.byte_evictions+=1

    def _retain(self, current):
        # One ring serves both growth and prehistory. No second hidden deque
        # keeps objects alive after they have been evicted by the byte budget.
        keep_ms=max(self.pre_ms,self.growth_window_ms)
        while self._history and current['elapsed_ms']-self._history[0]['elapsed_ms']>keep_ms+self.gap_ms:
            self._evict('TIME')
        # Keep one real predecessor for a growth pair that straddles the
        # requested boundary; it is not counted as requested prehistory.
        while len(self._history)>1 and current['elapsed_ms']-self._history[1]['elapsed_ms']>keep_ms:
            self._evict('TIME')
        encoded=json.dumps(current,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode('ascii')
        # Conservative accounting includes per-row Python container/scalar
        # overhead and worst-case storage for the bounded reference string.
        cost=len(encoded)+1024+4*len(current.get('detail_ref') or '')
        while self._history and (len(self._history)>=self.max_buffer_samples or self._buffer_bytes+cost>self.max_buffer_bytes):
            self._evict('BYTES' if self._buffer_bytes+cost>self.max_buffer_bytes else 'SAMPLES')
        if cost>self.max_buffer_bytes:
            self.samples_not_retained+=1
            return
        self._history.append(current);self._history_costs.append(cost);self._buffer_bytes+=cost

    def coverage(self):
        """Bounded recorder metadata, not a whole-process RSS/quota claim."""
        return {'schema_version':1,'observed_samples':self.observed_samples,
            'retained_samples':len(self._history),'max_buffer_samples':self.max_buffer_samples,
            'accounted_buffer_bytes':self._buffer_bytes,'max_buffer_bytes':self.max_buffer_bytes,
            'memory_budget_semantics':'CONSERVATIVE_ROW_ACCOUNTING_NOT_PROCESS_RSS_QUOTA',
            'requested_pre_ms':self.pre_ms,'growth_window_ms':self.growth_window_ms,
            'history_retention':'MAX_PRE_OR_GROWTH_WINDOW_PLUS_ONE_BOUNDARY_SAMPLE',
            'capacity_evictions':self.buffer_evictions,'byte_evictions':self.byte_evictions,
            'normal_time_evictions':self.time_evictions,'samples_not_retained':self.samples_not_retained,
            'sampling_gaps_observed':self.sampling_gaps,'missing_sensor_values':dict(self._missing),
            'incidents_completed':self.incidents,'dropped_triggers':self.dropped_triggers,
            'active':self._active is not None,'source':'BLACKBOX_LOCAL_MONOTONIC_SAMPLING',
            'raw_recording_deleted':False}

    def observe(self, *, elapsed_ms, sample_seq, cpu_percent, rss_bytes=None, private_bytes=None,
                handle_count=None, read_bytes=None, write_bytes=None, detail_ref=None):
        values=(cpu_percent,rss_bytes,private_bytes,handle_count,read_bytes,write_bytes)
        if (type(elapsed_ms) is not int or elapsed_ms<0 or type(sample_seq) is not int or sample_seq<=0 or
            any(not self._valid(v) for v in values) or
            detail_ref is not None and (type(detail_ref) is not str or len(detail_ref)>512) or
            self._last_time is not None and elapsed_ms<self._last_time or
            self._last_seq is not None and sample_seq<=self._last_seq):raise ValueError('INVALID_INCIDENT_SAMPLE')
        previous=self._last_time
        sequence_gap=self._last_seq is not None and sample_seq!=self._last_seq+1
        discontinuous=previous is not None and (elapsed_ms-previous>self.gap_ms or sequence_gap)
        self._last_time=elapsed_ms;self._last_seq=sample_seq;events=[];candidates=[]
        self.observed_samples+=1
        current={'sample_seq':sample_seq,'elapsed_ms':elapsed_ms,'cpu_percent':cpu_percent,
            'rss_bytes':rss_bytes,'private_bytes':private_bytes,'handle_count':handle_count,
            'read_bytes':read_bytes,'write_bytes':write_bytes,'detail_ref':detail_ref}
        self._retain(current)
        for key in self._missing:
            if current[key] is None:self._missing[key]+=1
        if discontinuous:
            self._cpu_since=None;self._previous_io=None;self._last_gap_ms=elapsed_ms;self.sampling_gaps+=1
            events.append({'kind':'sampling_gap','code':'SAMPLING_GAP_OBSERVED','start_ms':previous,
                'end_ms':elapsed_ms,'gap_ms':elapsed_ms-previous,'source':'BLACKBOX_LOCAL_MONOTONIC_SAMPLING',
                'sequence_gap':sequence_gap,'interpretation':'OBSERVED_GAP_NOT_TARGET_HANG'})
            if self.gap_incidents:candidates.append(('SAMPLING_GAP',{'gap_ms':elapsed_ms-previous}))
        threshold=self.threshold
        if self.cpu_reference=='BASELINE_DELTA':
            from statistics import median
            if cpu_percent is not None and len(self._baseline_cpu)<30:self._baseline_cpu.append(cpu_percent)
            threshold=(median(self._baseline_cpu)+self.threshold) if len(self._baseline_cpu)>=3 else float('inf')
        if cpu_percent is not None and cpu_percent>=threshold:
            if self._cpu_since is None:self._cpu_since=elapsed_ms
            if elapsed_ms-self._cpu_since>=self.min_duration_ms:
                candidates.append(('CPU_SUSTAINED',{'threshold_percent_one_cpu':self.threshold,'observed_percent':cpu_percent}))
        else:
            self._cpu_since=None;self._requires_rearm=False;self._latched.discard('CPU_SUSTAINED')
        # Preserve one point just before the growth window, so elapsed-time
        # comparisons use an actual pair rather than a guessed sample count.
        growth=list(self._history)
        if self._last_gap_ms is not None:growth=[r for r in growth if r['elapsed_ms']>=self._last_gap_ms]
        first_growth=0
        while first_growth+1<len(growth) and elapsed_ms-growth[first_growth+1]['elapsed_ms']>=self.growth_window_ms:first_growth+=1
        growth=growth[first_growth:]
        active_codes=set()
        for field,code,limit in (('private_bytes','PRIVATE_GROWTH',self.memory_growth_bytes),
            ('rss_bytes','RSS_GROWTH',self.memory_growth_bytes),('handle_count','HANDLE_GROWTH',self.handle_growth)):
            first=next((r for r in growth if r[field] is not None),None)
            value=current[field]
            if limit and first and value is not None and elapsed_ms-first['elapsed_ms']>=self.growth_window_ms:
                delta=value-first[field]
                if delta>=limit:
                    active_codes.add(code);candidates.append((code,{'metric':field,'delta':delta,'threshold':limit,
                        'first_seq':first['sample_seq'],'observed_window_ms':elapsed_ms-first['elapsed_ms'],
                        'interpretation':'GROWTH_OBSERVED_NOT_A_PROVEN_LEAK'}))
            if code not in active_codes:self._latched.discard(code)
        if read_bytes is not None and write_bytes is not None:
            before=self._previous_io
            if before and elapsed_ms>before[0] and read_bytes>=before[1] and write_bytes>=before[2]:
                rate=((read_bytes-before[1])+(write_bytes-before[2]))*1000/(elapsed_ms-before[0])
                if self.io_rate_bytes_s and rate>=self.io_rate_bytes_s:
                    active_codes.add('IO_BURST');candidates.append(('IO_BURST',{'observed_bytes_s':rate,
                        'threshold_bytes_s':self.io_rate_bytes_s,'observed_window_ms':elapsed_ms-before[0],
                        'interpretation':'THROUGHPUT_NOT_IO_LATENCY'}))
            self._previous_io=(elapsed_ms,read_bytes,write_bytes)
        else:self._previous_io=None
        if 'IO_BURST' not in active_codes:self._latched.discard('IO_BURST')
        candidates=[(c,d) for c,d in candidates if c in self.enabled_triggers]
        ready=[(c,d) for c,d in candidates if c not in self._latched]
        if self._active is not None:
            for code,data in candidates:
                self._active['secondary_signals'].setdefault(code,data)
        elif ready and elapsed_ms>=self._next_allowed_ms:
            code,data=ready[0]
            if self.incidents>=self.max_incidents:
                self.dropped_triggers+=len(ready);self._latched.update(c for c,_ in ready)
            else:
                events.append(self._begin(code,data,sample_seq,elapsed_ms))
                # A one-sample growth/I/O pulse can coincide with the primary
                # CPU trigger and disappear before the next observation.
                for secondary,detail in candidates:
                    if secondary!=code:self._active['secondary_signals'].setdefault(secondary,detail)
        if self._active and elapsed_ms-self._active['start_ms']>=self.post_ms:
            events.append(self._complete(sample_seq,elapsed_ms,status='CAPTURED'))
        return events

    def _begin(self,code,data,seq,stamp):
        pre=[row for row in self._history if stamp-self.pre_ms<=row['elapsed_ms']<=stamp]
        first=pre[0] if pre else {'sample_seq':seq,'elapsed_ms':stamp}
        coverage=self.coverage()
        complete=stamp-first['elapsed_ms']>=self.pre_ms and not (
            self._last_gap_ms is not None and self._last_gap_ms>=stamp-self.pre_ms)
        coverage.update(pre_observed_count=len(pre),observed_pre_ms=stamp-first['elapsed_ms'],
            prehistory_complete=complete,coverage_state='COMPLETE_FOR_REQUESTED_WINDOW' if complete else 'INCOMPLETE',
            claim='OBSERVED_SAMPLE_REFERENCES_NOT_CONTINUOUS_OS_EVENT_CAPTURE')
        self._latched.add(code)
        source=('USER_MARKER' if code=='MANUAL_PROBLEM' else 'APPLICATION_EVENT' if code=='APP_CRASH_MARKER' else 'WIN32_APPLICATION_EVENTLOG' if code=='CRASH_OBSERVED'
                else 'WIN32_WINDOW_CAPTURE' if code=='UI_TIMEOUT' else 'BLACKBOX_EXTERNAL_COUNTERS')
        self._active={'start_ms':stamp,'trigger_code':code,'trigger_detail':data,
            'pre_first_seq':first['sample_seq'],'trigger_seq':seq,'pre_observed_count':len(pre),
            'buffer_evictions_before':self.buffer_evictions,'secondary_signals':{},
            'pre_observed_ms':stamp-first['elapsed_ms'],'capture_coverage':coverage,'source':source}
        return {'kind':'incident_boundary','code':'AUTO_INCIDENT_STARTED','source':source,
            'trigger_code':code,'elapsed_ms':stamp,'sample_seq':seq,'pre_first_seq':first['sample_seq'],
            'pre_observed_count':len(pre),'threshold_percent_one_cpu':self.threshold,
            'trigger_detail':data,'requested_pre_ms':self.pre_ms,'observed_pre_ms':stamp-first['elapsed_ms'],
            'capture_coverage':coverage,'root_cause':'UNKNOWN','proven_root_cause':False}

    def _complete(self,seq,time,*,status):
        current=self._active;self._active=None;self._requires_rearm=True;self.incidents+=1
        self._next_allowed_ms=time+self.cooldown_ms
        post_complete=status=='CAPTURED' and time-current['start_ms']>=self.post_ms
        post_gap=self._last_gap_ms is not None and self._last_gap_ms>current['start_ms']
        complete=current['capture_coverage']['prehistory_complete'] and post_complete and not post_gap
        return {'kind':'incident_boundary','code':'AUTO_INCIDENT_COMPLETED','trigger_code':current['trigger_code'],
            'trigger_detail':current['trigger_detail'],'start_ms':current['start_ms'],'end_ms':time,
            'first_sample_seq':current['pre_first_seq'],'trigger_sample_seq':current['trigger_seq'],'last_sample_seq':seq,
            'pre_observed_count':current['pre_observed_count'],'buffer_evictions_before':current['buffer_evictions_before'],
            'requested_pre_ms':self.pre_ms,'observed_pre_ms':current['pre_observed_ms'],
            'requested_post_ms':self.post_ms,
            'observed_post_ms':max(0,min(time,self._history[-1]['elapsed_ms'] if self._history else current['start_ms'])-current['start_ms']),
            'post_span_quality':'AVAILABLE_SNAPSHOT_BOUNDARIES_NOT_CONTINUOUS_COVERAGE',
            'secondary_signals':current['secondary_signals'],'dropped_triggers':self.dropped_triggers,
            'capture_coverage':{**current['capture_coverage'],
                'coverage_state':'COMPLETE_FOR_REQUESTED_WINDOW' if complete else 'INCOMPLETE',
                'post_complete':post_complete,'sampling_gap_during_post':post_gap,
                'buffer_at_completion':self.coverage(),
                'completion_status':status},
            'context_refs':{'base_samples':f"session.sqlite3:samples:{current['pre_first_seq']}..{seq}",
                'detail_threads_children':'session-v2.sqlite3:interval', 'windows_wct':'session-v2.sqlite3:events:interval'},
            'coverage':'ONLY_AVAILABLE_PERSISTED_SOURCES_NO_IMPUTATION','status':status,
            'source':current['source'],'root_cause':'UNKNOWN','proven_root_cause':False}

    def trigger(self, code, *, elapsed_ms, sample_seq, evidence_ref, verification):
        """Route a real observed/user boundary; callers retain its source ref.

        A manual marker is user declared. PROCESS_EXIT is never promoted to
        CRASH_OBSERVED. No trigger starts ETW, dumps or native intervention.
        """
        allowed={'UI_TIMEOUT':('OS_OBSERVED',),
            'MANUAL_PROBLEM':('USER_DECLARED',),
            'APP_CRASH_MARKER':('APP_SUPPLIED_UNAUTHENTICATED',),
            'CRASH_OBSERVED':('OS_OBSERVED_MATCHED_CRASH',)}
        if (code not in allowed or verification not in allowed[code] or
            type(elapsed_ms) is not int or elapsed_ms<0 or
            type(sample_seq) is not int or sample_seq<=0 or
            type(evidence_ref) is not str or not evidence_ref or len(evidence_ref)>512 or
            self._last_time is not None and elapsed_ms<self._last_time):
            raise ValueError('INVALID_INCIDENT_TRIGGER')
        if code not in self.enabled_triggers:return []
        detail={'evidence_ref':evidence_ref,'verification_class':verification,
            'timestamp_semantics':'OBSERVER_RECEIPT_FOR_EXTERNAL_TRIGGER',
            'interpretation':'USER_REPORTED_PROBLEM_NOT_PROVEN_CAUSE' if code=='MANUAL_PROBLEM' else
                'APPLICATION_REPORTED_CRASH_MARKER_NOT_OS_CRASH_PROOF' if code=='APP_CRASH_MARKER' else 'OBSERVED_BOUNDARY_NOT_PROVEN_CAUSE'}
        if self._active is not None:
            self._active['secondary_signals'].setdefault(code,detail);return []
        if elapsed_ms<self._next_allowed_ms or self.incidents>=self.max_incidents:
            self.dropped_triggers+=1;return []
        rows=[self._begin(code,detail,sample_seq,elapsed_ms)]
        if self.post_ms==0:rows.append(self._complete(sample_seq,elapsed_ms,status='CAPTURED'))
        return rows

    def process_exited(self,*,elapsed_ms,sample_seq):
        events=[]
        if self._active:events.append(self._complete(sample_seq,elapsed_ms,status='INCOMPLETE_PROCESS_EXITED'))
        if self.incidents<self.max_incidents and "PROCESS_EXIT_OBSERVED" in self.enabled_triggers:
            events.append(self._begin('PROCESS_EXIT_OBSERVED',{'exit_code':None,
                'interpretation':'PROCESS_EXIT_NOT_PROVEN_CRASH'},sample_seq,elapsed_ms))
            events.append(self._complete(sample_seq,elapsed_ms,status='NO_POST_TARGET_EXITED'))
        else:self.dropped_triggers+=1
        return events

    def stop(self,*,elapsed_ms,sample_seq):
        if not self._active:return []
        return [self._complete(sample_seq,elapsed_ms,status='INCOMPLETE_RECORDING_STOPPED')]
