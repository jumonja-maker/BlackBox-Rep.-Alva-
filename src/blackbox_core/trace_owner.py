"""Opt-in WPR guardian. EOF and a short TTL stop only our named recording.

The guardian survives an abrupt recorder exit long enough to stop the trace;
its stdin is an ownership lease, not an interactive console. No global WPR
stop/cancel is ever issued. The journal remains for explicit recovery.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from threading import Event, Thread
import time
from uuid import uuid4
from .library_files import replace_owned_status
from .trace_clock_evidence import (capture_trace_clock_bracket,
                                   new_clock_order_samples, append_clock_order_sample)
from .windows_research import WPR_PROFILES

MAX_JOURNAL_BYTES=65536


def _read(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_JOURNAL_BYTES:
        raise ValueError('INVALID_TRACE_JOURNAL')
    return json.loads(path.read_text(encoding='utf-8'))


def _write(path,data):
    path=Path(path)
    if path.is_symlink():raise ValueError('INVALID_TRACE_JOURNAL')
    temp=path.with_name(path.name+'.'+uuid4().hex+'.tmp')
    raw=json.dumps(data,ensure_ascii=True,allow_nan=False).encode('ascii')
    if len(raw)>MAX_JOURNAL_BYTES:raise ValueError('TRACE_JOURNAL_BUDGET')
    try:
        with temp.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        replace_owned_status(temp,path)
    finally:
        if temp.exists():temp.unlink()


def run(journal, *, capture_factory=None, lease_lost=None):
    from .windows_research import WprCapture
    path=Path(journal);data=_read(path)
    seconds=data['policy']['duration_s'];max_bytes=data['policy']['max_output_bytes']
    profile=data['policy'].get('profile','GeneralProfile.Light')
    if type(profile) is not str or profile not in WPR_PROFILES:
        raise ValueError('INVALID_WPR_PROFILE')
    if type(seconds) is not int or not 1<=seconds<=60 or type(max_bytes) is not int or not 1024**2<=max_bytes<=1024**3:
        raise ValueError('INVALID_TRACE_POLICY')
    if lease_lost is None:
        # The scoped diagnostic owner supplies its own native stdin lease and
        # avoids importing the recording worker into the isolated helper.
        from .research_worker import _streams
        inp,_=_streams();lease_lost=Event()
        def lease():
            # Any command or EOF means finish; no arbitrary instruction.
            inp.readline(64);lease_lost.set()
        Thread(target=lease,name='blackbox-trace-lease',daemon=True).start()
    capture=(capture_factory or WprCapture)(path.parent,profile=profile);capture.instance=data['instance']
    if capture.tool:
        tool=Path(capture.tool);digest=hashlib.sha256()
        with tool.open('rb') as stream:
            for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
        data['tool']={'name':tool.name,'sha256':digest.hexdigest(),'bytes':tool.stat().st_size,
            'distribution':'INSTALLED_MICROSOFT_WINDOWS_COMPONENT_NOT_BUNDLED'}
    if not capture.instance.startswith('BLACKBOX_') or len(capture.instance)!=41 or any(c not in '0123456789abcdef' for c in capture.instance[9:]):
        raise ValueError('INVALID_OWNED_TRACE_INSTANCE')
    import psutil
    data['guardian_created']=psutil.Process().create_time()
    data.update(guardian_pid=os.getpid(),state='STARTING',started_monotonic_ns=time.monotonic_ns(),
                source='ETW_WPR',lost_events=None,decoded=False)
    _write(path,data)
    try:
        # Capture-side Windows QPC/monotonic/UTC brackets. These are
        # unauthenticated journal evidence, NOT a calibrated TraceEvent clock
        # or proof of shared boot with BLACK.BOX session-v2.
        data['clock_anchors']={'before_tool_start':capture_trace_clock_bracket()}
        data['start_result']=capture.start();data['state']='RECORDING'
        data['clock_anchors']['after_tool_start']=capture_trace_clock_bracket()
        data['clock_order_samples']=new_clock_order_samples(data['clock_anchors']['after_tool_start'])
        deadline=time.monotonic()+seconds;_write(path,data)
        next_clock_sample=time.monotonic()+.2
        while not lease_lost.wait(min(.1,max(0,deadline-time.monotonic()))) and time.monotonic()<deadline:
            if time.monotonic()>=next_clock_sample:
                append_clock_order_sample(data['clock_order_samples'],capture_trace_clock_bracket())
                next_clock_sample=time.monotonic()+.2
        data['stop_reason']='LEASE_EOF_OR_EXPLICIT_STOP' if lease_lost.is_set() else 'TTL_EXPIRED'
        data['state']='STOPPING'
        data['clock_anchors']['before_tool_stop']=capture_trace_clock_bracket()
        _write(path,data)
        result=capture.stop()
        data['clock_anchors']['after_tool_stop']=capture_trace_clock_bracket()
        output=path.parent/result['path']
        digest=hashlib.sha256()
        with output.open('rb') as stream:
            for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
        result.update(sha256=digest.hexdigest(),size_policy='CHECKED_AFTER_MEMORY_MODE_FLUSH_NOT_HARD_DISK_QUOTA')
        if result['bytes']>max_bytes:result['status']='OUTPUT_BUDGET_EXCEEDED_RETAINED'
        data.update(state='COMPLETED',result=result)
    except BaseException as exc:
        data.update(state='FAILED',error=(type(exc).__name__+': '+str(exc))[:1000])
        if capture.active:
            try:capture.cancel();data['cleanup']='NAMED_CANCEL_CONFIRMED'
            except BaseException as error:
                data['state']='CLEANUP_REQUIRED';data['cleanup_error']=(type(error).__name__+': '+str(error))[:1000]
    finally:
        data['ended_monotonic_ns']=time.monotonic_ns()
        if isinstance(data.get('clock_anchors'),dict):
            data['clock_anchors']['guardian_finally']=capture_trace_clock_bracket()
        _write(path,data)
    return 0 if data['state']=='COMPLETED' else 1


class TraceSupervisor:
    def __init__(self,folder,*,seconds=30,max_output_bytes=256*1024**2,target=None,profile="GeneralProfile.Light",session_path=None):
        if type(profile) is not str or profile not in WPR_PROFILES:
            raise ValueError("INVALID_WPR_PROFILE")
        if type(seconds) is not int or not 1<=seconds<=60:raise ValueError('INVALID_TRACE_DURATION')
        if type(max_output_bytes) is not int or not 1024**2<=max_output_bytes<=1024**3:raise ValueError('INVALID_TRACE_SIZE_POLICY')
        self.folder=Path(folder);self.instance='BLACKBOX_'+uuid4().hex
        self.path=self.folder/(self.instance+'.trace.json');self.process=None;self.reported=False;self._terminal_result=None
        self.data={'schema_version':1,'instance':self.instance,'state':'RESERVED',
            'consent':'EXPLICIT_USER_COMMAND','target':target,
            'scope':'SYSTEM_WIDE_MAY_INCLUDE_OTHER_PROCESSES',
            'policy':{'duration_s':seconds,'max_output_bytes':max_output_bytes,'profile':profile,
                'mode':'WPR_CIRCULAR_MEMORY','disk_quota':'NOT_HARD_LIMIT'},
            'recovery':'ONLY_THIS_NAMED_INSTANCE_MAY_BE_CANCELLED'}
        import psutil
        self.data.update(owner_pid=os.getpid(),owner_created=psutil.Process().create_time())
        from .decoder_alignment import capture_session_binding
        self.data['session_clock_binding']=capture_session_binding(
            session_path if session_path is not None else self.folder.parent/'session-v2.sqlite3')
    @property
    def active(self):return self.process is not None and self.process.poll() is None
    def start(self):
        if self.path.exists() or self.path.is_symlink():raise ValueError('TRACE_JOURNAL_EXISTS')
        with self.path.open('xb'):pass
        _write(self.path,self.data)
        args=[sys.executable,'--trace-owner',str(self.path)] if getattr(sys,'frozen',False) else [sys.executable,'-m','blackbox_core.trace_owner',str(self.path)]
        self.process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        return {'source':'ETW_WPR','status':'START_REQUESTED','instance':self.instance,
            'journal':self.path.name,**self.data['policy'],'lost_events':None}
    def request_stop(self):
        if self.process is not None and self.process.stdin is not None:
            self.process.stdin.close();self.process.stdin=None
    def poll(self):
        if self.process is None:return None
        if self.reported:return None
        # Check exit first: a guardian can publish its final journal and exit
        # between a preceding file read and poll(). Read after observed exit.
        code=self.process.poll()
        unavailable=False
        try:
            current=_read(self.path)
            if not isinstance(current,dict) or current.get('instance')!=self.instance:
                raise ValueError('INVALID_OWNED_TRACE_JOURNAL')
            self.data=current
        except (OSError,ValueError):
            unavailable=True
        if code is None:
            return ({'source':'ETW_WPR','status':'JOURNAL_UNAVAILABLE','lost_events':None}
                    if unavailable else None)
        # A dead guardian cannot still be recording. Keep the original journal
        # untouched: only explicit named-instance recovery can confirm cleanup.
        # Cache the terminal observation because research_worker may consume
        # poll() before finalization later calls stop().
        self.request_stop()  # Release the dead child's remaining stdin pipe.
        state=self.data.get('state','UNKNOWN')
        reason=None
        if unavailable:
            status,reason='CLEANUP_REQUIRED','JOURNAL_UNAVAILABLE'
        elif state not in ('COMPLETED','FAILED','CLEANUP_REQUIRED'):
            status,reason='CLEANUP_REQUIRED','GUARDIAN_EXITED_WITHOUT_FINAL_STATE'
        elif state=='COMPLETED' and code!=0:
            status,reason='CLEANUP_REQUIRED','GUARDIAN_ABNORMAL_EXIT'
        else:
            status=state
        result={'source':'ETW_WPR','status':status,
            'journal':self.path.name,'instance':self.instance,'exit_code':code,
            'details':self.data,'lost_events':None}
        if reason is not None:
            result.update(reason=reason,last_journal_state=state)
        self._terminal_result=result
        self.reported=True
        return result
    def stop(self):
        self.request_stop()
        if self.process is None:return None
        try:self.process.wait(timeout=75)
        except subprocess.TimeoutExpired:
            # Never terminate the observed target or another profiler. The
            # guardian retains its own command deadlines and recovery journal.
            return {'source':'ETW_WPR','status':'CLEANUP_UNCONFIRMED_GUARDIAN_STILL_RUNNING',
                'instance':self.instance,'journal':self.path.name,'lost_events':None}
        result=self.poll()
        return result or self._terminal_result


if __name__=='__main__':raise SystemExit(run(sys.argv[1]))
