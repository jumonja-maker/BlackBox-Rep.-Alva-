"""Fixed sensor contract and local health/backoff. No dynamic plugin imports.

A deadline passed to sample is a cooperative budget, never a claim that Python
can interrupt an arbitrary syscall. Disposable native processes enforce their
own hard deadline. Optional failure never changes a different source to zero.
"""
from __future__ import annotations
from dataclasses import dataclass
import time
from typing import Protocol
from collections import deque


@dataclass(frozen=True)
class Capability:
    sensor_id: str
    source: str
    availability: str
    mode: str = 'PASSIVE'
    deadline_kind: str = 'COOPERATIVE_BUDGET'
    permissions: str = 'CURRENT_USER'
    requires_optin: bool = False
    supported_os: tuple = ('Windows','Linux','Darwin')
    accuracy: str = 'SOURCE_SPECIFIC_NOT_CONTINUOUS'
    limitation: str = 'Activity between samples is not observed'
    reason: str | None = None


class Sensor(Protocol):
    def capabilities(self) -> Capability: ...
    def start(self, context: dict) -> None: ...
    def sample(self, deadline: float) -> dict: ...
    def stop(self) -> None: ...
    def health(self) -> dict: ...


class CallbackSensor:
    """Adapter for an existing real collector or its current health snapshot."""
    def __init__(self, capability, sample, *, enabled=lambda: True):
        self.capability=capability; self.collect=sample; self.enabled=enabled
        self.running=False; self.last=None
    def capabilities(self): return self.capability
    def start(self, context): self.running=True
    def sample(self, deadline):
        if not self.running: return {'status':'STOPPED'}
        if not self.enabled(): return {'status':'DISABLED'}
        self.last=self.collect(deadline)
        return self.last
    def stop(self): self.running=False
    def health(self): return self.last or {'status':'NOT_OBSERVED'}


class SensorRegistry:
    def __init__(self, allowed, *, clock=time.monotonic, max_backoff_s=60):
        self.allowed=frozenset(allowed); self.entries={}; self.clock=clock
        self.max_backoff_s=max_backoff_s; self.started=False
    def register(self, sensor):
        cap=sensor.capabilities(); name=cap.sensor_id
        if self.started or name not in self.allowed or name in self.entries: raise ValueError('INVALID_SENSOR_REGISTRATION')
        self.entries[name]={'sensor':sensor, 'capability':cap, 'status':'NOT_STARTED',
            'failures':0, 'consecutive_failures':0, 'overruns':0, 'samples':0,
            'next_retry':0.0, 'last_attempt':None, 'last_success':None, 'error':None, 'sample_ms':None,'latencies_ms':deque(maxlen=128),'latency_p95_ms':None}
    def start(self, context):
        self.started=True
        for row in self.entries.values():
            try: row['sensor'].start(context); row['status']='WAITING'
            except Exception as exc: self._failed(row, exc)
    def _failed(self, row, exc):
        row['failures']+=1; row['consecutive_failures']+=1
        row['error']=(getattr(exc,'code',None) or (type(exc).__name__+': '+str(exc)))[:300]
        row['status']='BACKOFF'
        row['next_retry']=self.clock()+min(self.max_backoff_s, 2**min(10,row['consecutive_failures']-1))
    def sample(self, name, *, budget_s=1.0):
        row=self.entries[name]; now=self.clock()
        if not self.started: return None
        if now < row['next_retry']: return None
        row['last_attempt']=now
        try:
            value=row['sensor'].sample(now+budget_s)
            if type(value) is not dict or type(value.get('status')) is not str: raise ValueError('INVALID_SENSOR_RESULT')
            row['sample_ms']=(self.clock()-now)*1000
            row['latencies_ms'].append(row['sample_ms'])
            times=sorted(row['latencies_ms']);row['latency_p95_ms']=times[int((len(times)-1)*.95)]
            row['status']=value['status']; row['last_success']=self.clock()
            row['samples']+=1; row['consecutive_failures']=0; row['error']=None
            if self.clock()>now+budget_s: row['overruns']+=1
            return value
        except Exception as exc: self._failed(row, exc); return None
    def health(self):
        now=self.clock(); result={}
        for name,row in self.entries.items():
            cap=row['capability']; last=row['last_success']
            try:producer=row['sensor'].health()
            except Exception as exc:producer={'status':'HEALTH_UNAVAILABLE','error':type(exc).__name__}
            if not isinstance(producer,dict):producer={'status':'INVALID_SENSOR_HEALTH'}
            producer_ns=producer.get('producer_heartbeat_ns')
            result[name]={'permissions':cap.permissions,'requires_optin':cap.requires_optin,
                'capability_id':cap.sensor_id,'source_id':cap.source,'privilege_level':cap.permissions,
                'accuracy_notes':cap.accuracy,'failure_reason':row['error'] or cap.reason,
                'supported_os':list(cap.supported_os),'accuracy':cap.accuracy,'limitations':cap.limitation,
                'unavailable_reason':cap.reason,'latency_p95_ms':row['latency_p95_ms'],
                'latency_window_count':len(row['latencies_ms']),'latency_window_limit':128,'source':cap.source,'availability':cap.availability,'mode':cap.mode,
                'deadline_kind':cap.deadline_kind,'status':row['status'],
                'heartbeat_age_ms':max(0,(now-last)*1000) if last is not None else None,
                'heartbeat_kind':'SENSOR_SAMPLE_OR_HEALTH_READ_SEE_MODE',
                'producer_heartbeat_age_ms':max(0,(time.monotonic_ns()-producer_ns)/1e6) if type(producer_ns) is int else None,
                'source_error':producer.get('error'),
                'last_attempt_monotonic':row['last_attempt'], 'failures':row['failures'],
                'consecutive_failures':row['consecutive_failures'],'overruns':row['overruns'],
                'samples':row['samples'],'sample_ms':row['sample_ms'], 'error':row['error'],
                'retry_after_ms':max(0,(row['next_retry']-now)*1000)}
        return result
    def stop(self):
        for row in self.entries.values():
            try: row['sensor'].stop(); row['status']='STOPPED'
            except Exception as exc: self._failed(row, exc)
        self.started=False
