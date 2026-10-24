"""Bounded optional-process owner with hard deadlines and owned-tree cleanup."""
from __future__ import annotations
from collections import deque
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

from .operation_worker import OPERATIONS, MAX_RESULT_BYTES


class OwnedProcess:
    """A kill boundary confined to our operation and its own descendants."""
    def __init__(self, args):
        self.job = None
        options = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.name == 'nt':
            import ctypes as C
            from ctypes import wintypes as W
            self.kernel = C.WinDLL('kernel32', use_last_error=True)
            k = self.kernel
            k.CreateJobObjectW.argtypes=[C.c_void_p, W.LPCWSTR]; k.CreateJobObjectW.restype=W.HANDLE
            k.AssignProcessToJobObject.argtypes=[W.HANDLE,W.HANDLE]; k.AssignProcessToJobObject.restype=W.BOOL
            k.TerminateJobObject.argtypes=[W.HANDLE,W.UINT]; k.TerminateJobObject.restype=W.BOOL
            k.CloseHandle.argtypes=[W.HANDLE]; k.CloseHandle.restype=W.BOOL
            class Basic(C.Structure):
                _fields_=[('process_time',C.c_int64),('job_time',C.c_int64),('flags',W.DWORD),
                    ('min_working',C.c_size_t),('max_working',C.c_size_t),('active',W.DWORD),
                    ('affinity',C.c_size_t),('priority',W.DWORD),('scheduling',W.DWORD)]
            class Io(C.Structure):_fields_=[(n,C.c_uint64) for n in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]
            class Limits(C.Structure):
                _fields_=[('basic',Basic),('io',Io),('process_memory',C.c_size_t),
                    ('job_memory',C.c_size_t),('peak_process',C.c_size_t),('peak_job',C.c_size_t)]
            k.SetInformationJobObject.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD];k.SetInformationJobObject.restype=W.BOOL
            self.job = k.CreateJobObjectW(None, None)
            if not self.job: raise OSError(C.get_last_error(), 'OPTIONAL_JOB_CREATION_FAILED')
            limits=Limits();limits.basic.flags=0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not k.SetInformationJobObject(self.job,9,C.byref(limits),C.sizeof(limits)):
                k.CloseHandle(self.job);self.job=None
                raise OSError(C.get_last_error(),'OPTIONAL_JOB_LIMIT_FAILED')
            options['creationflags'] = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        else: options['start_new_session'] = True
        try:
            self.process = subprocess.Popen(args, **options)
            if self.job and not self.kernel.AssignProcessToJobObject(self.job, int(self.process._handle)):
                self.process.kill(); self.process.wait(timeout=5)
                raise OSError('OPTIONAL_JOB_ASSIGNMENT_FAILED')
        except BaseException:
            if self.job:
                self.kernel.TerminateJobObject(self.job,1)
                self.kernel.CloseHandle(self.job); self.job=None
            raise

    def close(self, *, kill=False):
        if kill or self.process.poll() is None:
            if os.name == 'nt': self.kernel.TerminateJobObject(self.job, 1)
            else:
                try: os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            try: self.process.wait(timeout=2)
            except subprocess.TimeoutExpired: pass
        if self.job:
            self.kernel.TerminateJobObject(self.job,1)
            self.kernel.CloseHandle(self.job); self.job=None


class OptionalJobs:
    def __init__(self, *, limit=8, clock=time.monotonic, launcher=OwnedProcess):
        self.queue = deque(); self.current = None; self.limit = limit
        self.clock = clock; self.launcher = launcher
        self.completed = 0; self.failed = 0; self.timed_out = 0; self.cancelled = 0
        self.last_progress = clock()

    @property
    def busy(self): return bool(self.current or self.queue)

    def submit(self, command, packet, *, seconds=75):
        if command.get('op') not in OPERATIONS: raise ValueError('UNKNOWN_OPTIONAL_OPERATION')
        if len(self.queue)+(1 if self.current else 0) >= self.limit: raise ValueError('OPTIONAL_QUEUE_FULL')
        if not 0 < seconds <= 600: raise ValueError('INVALID_OPTIONAL_DEADLINE')
        self.queue.append({'command': command, 'packet': packet, 'seconds': seconds, 'queued_at':self.clock()})

    def _launch(self):
        item = self.queue.popleft(); self._launch_command=item['command']; temp = tempfile.TemporaryDirectory(prefix='blackbox-operation-')
        root = Path(temp.name); spec=root/'request.json'; output=root/'result.json'
        try:
            spec.write_text(json.dumps(item['packet'], allow_nan=False), encoding='utf-8')
            if getattr(sys, 'frozen', False): args=[sys.executable, '--research-operation', str(spec), str(output)]
            else: args=[sys.executable, '-m', 'blackbox_core.operation_worker', str(spec), str(output)]
            owner=self.launcher(args)
            (root/'ready').touch(exist_ok=False)
        except BaseException: temp.cleanup(); raise
        item.update(temp=temp, output=output, owner=owner, deadline=self.clock()+item['seconds'], started_at=self.clock())
        self.current=item

    def poll(self):
        results=[]
        if not self.current and self.queue:
            try: self._launch()
            except Exception as exc:
                self.failed+=1
                # _launch consumed exactly one item; retain its command for acknowledgement.
                return [{'command': getattr(self, '_launch_command', {}), 'result':None, 'error':'OPTIONAL_START_FAILED: '+str(exc)[:300]}]
        item=self.current
        if not item: return results
        proc=item['owner'].process; rc=proc.poll(); expired=self.clock()>=item['deadline']
        if rc is None and not expired: return results
        result={'result':None, 'error':None}
        try:
            if expired and rc is None:
                self.timed_out+=1; result['error']='OPTIONAL_OPERATION_TIMEOUT'
            elif rc != 0: result['error']='OPTIONAL_OPERATION_EXIT_'+str(rc)
            elif item['output'].is_symlink() or not item['output'].is_file() or item['output'].stat().st_size>MAX_RESULT_BYTES:
                result['error']='OPTIONAL_RESULT_UNAVAILABLE'
            else:
                result=json.loads(item['output'].read_text(encoding='utf-8'))
                if type(result) is not dict or 'error' not in result: raise ValueError('INVALID_OPTIONAL_RESULT')
            if result.get('error'): self.failed+=1
            else: self.completed+=1
            result.update(command=item['command'], queue_ms=(item['started_at']-item['queued_at'])*1000,
                          operation_ms=(self.clock()-item['started_at'])*1000)
            results.append(result)
        except (OSError, ValueError, TypeError) as exc:
            self.failed+=1; results.append({'command':item['command'], 'result':None, 'error':'INVALID_OPTIONAL_RESULT: '+str(exc)[:300]})
        finally:
            item['owner'].close(kill=expired and rc is None); item['temp'].cleanup(); self.current=None
            self.last_progress=self.clock()
        return results

    def cancel(self):
        pending=list(self.queue); self.queue.clear()
        if self.current:
            item=self.current; self.current=None
            item['owner'].close(kill=True); item['temp'].cleanup(); pending.insert(0,item)
        self.cancelled+=len(pending)
        return [{'command':i['command'], 'result':None, 'error':'OPTIONAL_OPERATION_CANCELLED_RESULT_UNCONFIRMED'} for i in pending]

    def health(self):
        return {'status':'RUNNING' if self.current else 'QUEUED' if self.queue else 'IDLE',
            'queued':len(self.queue), 'limit':self.limit, 'completed':self.completed, 'failed':self.failed,
            'timed_out':self.timed_out, 'cancelled':self.cancelled,
            'current_op':self.current['command'].get('op') if self.current else None,
            'current_age_ms':(self.clock()-self.current['started_at'])*1000 if self.current else None}
