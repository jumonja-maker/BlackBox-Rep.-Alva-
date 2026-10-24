"""Bounded multi-signal incident windows over actual measurements.

An incident is an observed threshold/context window, never proof of a leak,
hang or internal cause. Pre/post references address persisted sample ranges;
unavailable sensors remain NULL and are not interpreted as zero.
"""
from __future__ import annotations
from collections import deque
import math


class IncidentCapture:
    def __init__(self, *, threshold=85.0, min_duration_ms=3000,
                 gap_ms=5500, pre_ms=60000, post_ms=20000,
                 cooldown_ms=30000, max_incidents=20,
                 memory_growth_bytes=32*1024*1024, handle_growth=128,
                 growth_window_ms=10000, io_rate_bytes_s=64*1024*1024,
                 gap_incidents=False, enabled_triggers=None, cpu_reference="ABSOLUTE"):
        if (type(threshold) not in (float,int) or not math.isfinite(threshold) or not 0<threshold<=6400 or
            any(type(x) is not int or x<0 for x in (min_duration_ms,gap_ms,pre_ms,post_ms,cooldown_ms,
                memory_growth_bytes,handle_growth,growth_window_ms,io_rate_bytes_s)) or
            type(max_incidents) is not int or not 1<=max_incidents<=1000 or post_ms>60000 or
            growth_window_ms>60000 or type(gap_incidents) is not bool):
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
        self._history=deque(maxlen=512);self._growth=deque(maxlen=512)
        self._last_time=None;self._cpu_since=None;self._active=None;self._requires_rearm=False
        self._next_allowed_ms=0;self._latched=set();self._previous_io=None
        self.incidents=0;self.buffer_evictions=0;self.dropped_triggers=0

    @staticmethod
    def _valid(value):return value is None or type(value) in (int,float) and math.isfinite(value) and value>=0

    def observe(self, *, elapsed_ms, sample_seq, cpu_percent, rss_bytes=None, private_bytes=None,
                handle_count=None, read_bytes=None, write_bytes=None, detail_ref=None):
        values=(cpu_percent,rss_bytes,private_bytes,handle_count,read_bytes,write_bytes)
        if (type(elapsed_ms) is not int or elapsed_ms<0 or type(sample_seq) is not int or sample_seq<=0 or
            any(not self._valid(v) for v in values) or
            self._last_time is not None and elapsed_ms<self._last_time):raise ValueError('INVALID_INCIDENT_SAMPLE')
        previous=self._last_time;discontinuous=previous is not None and elapsed_ms-previous>self.gap_ms
        self._last_time=elapsed_ms;events=[];candidates=[]
        while self._history and elapsed_ms-self._history[0]['elapsed_ms']>self.pre_ms:self._history.popleft()
        if len(self._history)==self._history.maxlen:self.buffer_evictions+=1
        current={'sample_seq':sample_seq,'elapsed_ms':elapsed_ms,'cpu_percent':cpu_percent,
            'rss_bytes':rss_bytes,'private_bytes':private_bytes,'handle_count':handle_count,
            'read_bytes':read_bytes,'write_bytes':write_bytes,'detail_ref':detail_ref}
        self._history.append(current)
        if discontinuous:
            self._cpu_since=None;self._growth.clear();self._previous_io=None
            events.append({'kind':'sampling_gap','code':'SAMPLING_GAP_OBSERVED','start_ms':previous,
                'end_ms':elapsed_ms,'gap_ms':elapsed_ms-previous,'source':'BLACKBOX_LOCAL_MONOTONIC_SAMPLING',
                'interpretation':'OBSERVED_GAP_NOT_TARGET_HANG'})
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
        while len(self._growth)>1 and elapsed_ms-self._growth[1]['elapsed_ms']>=self.growth_window_ms:self._growth.popleft()
        self._growth.append(current)
        active_codes=set()
        for field,code,limit in (('private_bytes','PRIVATE_GROWTH',self.memory_growth_bytes),
            ('rss_bytes','RSS_GROWTH',self.memory_growth_bytes),('handle_count','HANDLE_GROWTH',self.handle_growth)):
            first=next((r for r in self._growth if r[field] is not None),None)
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
            else:events.append(self._begin(code,data,sample_seq,elapsed_ms))
        if self._active and elapsed_ms-self._active['start_ms']>=self.post_ms:
            events.append(self._complete(sample_seq,elapsed_ms,status='CAPTURED'))
        return events

    def _begin(self,code,data,seq,stamp):
        first=self._history[0] if self._history else {'sample_seq':seq,'elapsed_ms':stamp}
        self._latched.add(code)
        self._active={'start_ms':stamp,'trigger_code':code,'trigger_detail':data,
            'pre_first_seq':first['sample_seq'],'trigger_seq':seq,'pre_observed_count':len(self._history),
            'buffer_evictions_before':self.buffer_evictions,'secondary_signals':{},
            'pre_observed_ms':stamp-first['elapsed_ms']}
        return {'kind':'incident_boundary','code':'AUTO_INCIDENT_STARTED','source':'BLACKBOX_EXTERNAL_COUNTERS',
            'trigger_code':code,'elapsed_ms':stamp,'sample_seq':seq,'pre_first_seq':first['sample_seq'],
            'pre_observed_count':len(self._history),'threshold_percent_one_cpu':self.threshold,
            'trigger_detail':data,'requested_pre_ms':self.pre_ms,'observed_pre_ms':stamp-first['elapsed_ms'],
            'root_cause':'UNKNOWN','proven_root_cause':False}

    def _complete(self,seq,time,*,status):
        current=self._active;self._active=None;self._requires_rearm=True;self.incidents+=1
        self._next_allowed_ms=time+self.cooldown_ms
        return {'kind':'incident_boundary','code':'AUTO_INCIDENT_COMPLETED','trigger_code':current['trigger_code'],
            'trigger_detail':current['trigger_detail'],'start_ms':current['start_ms'],'end_ms':time,
            'first_sample_seq':current['pre_first_seq'],'trigger_sample_seq':current['trigger_seq'],'last_sample_seq':seq,
            'pre_observed_count':current['pre_observed_count'],'buffer_evictions_before':current['buffer_evictions_before'],
            'requested_pre_ms':self.pre_ms,'observed_pre_ms':current['pre_observed_ms'],
            'requested_post_ms':self.post_ms,
            'observed_post_ms':max(0,min(time,self._history[-1]['elapsed_ms'] if self._history else current['start_ms'])-current['start_ms']),
            'post_span_quality':'AVAILABLE_SNAPSHOT_BOUNDARIES_NOT_CONTINUOUS_COVERAGE',
            'secondary_signals':current['secondary_signals'],'dropped_triggers':self.dropped_triggers,
            'context_refs':{'base_samples':f"session.sqlite3:samples:{current['pre_first_seq']}..{seq}",
                'detail_threads_children':'session-v2.sqlite3:interval', 'windows_wct':'session-v2.sqlite3:events:interval'},
            'coverage':'ONLY_AVAILABLE_PERSISTED_SOURCES_NO_IMPUTATION','status':status,
            'source':'BLACKBOX_EXTERNAL_COUNTERS','root_cause':'UNKNOWN','proven_root_cause':False}

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
