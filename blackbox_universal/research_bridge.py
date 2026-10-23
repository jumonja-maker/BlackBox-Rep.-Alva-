"""Asynchronous facade: the production GUI owns no recording SQLite handle."""
from __future__ import annotations
from collections import deque
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace
from uuid import uuid4

from PySide6.QtCore import QObject,QProcess,QProcessEnvironment,QTimer,Signal
from .monitor import ReadOnlyProbe


class WindowCaptureProxy:
    def __init__(self,bridge):self.bridge=bridge
    def snapshot(self):
        return self.bridge.data.get("window_capture_status","UNKNOWN"),self.bridge.data.get("observed_windows",[])
    @property
    def selected_hwnd(self):return self.bridge.data.get("selected_hwnd")
    @selected_hwnd.setter
    def selected_hwnd(self,hwnd):self.bridge.send("select_window",hwnd=hwnd)


class ResearchBridge(QObject):
    updated=Signal()
    result_ready=Signal(str,object,str)
    terminated=Signal()

    def __init__(self,parent=None,output_root=None):
        super().__init__(parent)
        empty=ReadOnlyProbe(output_root=output_root)
        for key in ("pid","name","active","started_at","session_folder","session_state",
                    "report_result","last_error","history","events","total_samples","last_elapsed_ms"):
            setattr(self,key,getattr(empty,key))
        self.actions=SimpleNamespace(state="IDLE",completed=[],ready_to_start=lambda:False)
        self.detailed_capture=None;self.incident_capture=None
        self.window_capture=None;self._window_proxy=WindowCaptureProxy(self)
        self.data=empty.snapshot();self.capabilities={};self._queue=[];self._pending={}
        self.closing=False;self.last_response=time.monotonic();self._stop_deadline=None
        self.process=QProcess(self)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)
        env=QProcessEnvironment.systemEnvironment();env.insert("PYTHONUTF8","1")
        self.process.setProcessEnvironment(env)
        self._buffer=bytearray()
        self._stderr=""
        self.process.readyReadStandardOutput.connect(self._read)
        self.process.readyReadStandardError.connect(self._stderr_ready)
        self.process.started.connect(self._flush)
        self.process.finished.connect(self._finished)
        self.process.errorOccurred.connect(self._process_error)
        if getattr(sys,"frozen",False):args=["--research-worker"]
        else:args=[str(Path(__file__).resolve().parent.parent/"app.py"),"--research-worker"]
        if output_root is not None:args.extend(["--research-root",str(output_root)])
        self.process.start(sys.executable,args)
        self._watchdog=QTimer(self);self._watchdog.timeout.connect(self._check_deadline);self._watchdog.start(500)

    @property
    def pending(self):return bool(self._pending)

    @property
    def alive(self):return self.process.state()!=QProcess.ProcessState.NotRunning

    def send(self,op,**args):
        if len(self._pending)>=64:raise RuntimeError("RESEARCH_COMMAND_QUEUE_FULL")
        if self.process.state()==QProcess.ProcessState.NotRunning:raise RuntimeError("RESEARCH_HELPER_UNAVAILABLE")
        ident=uuid4().hex
        packet={"id":ident,"op":op,"args":args,"issued_ns":time.monotonic_ns()}
        encoded=(json.dumps(packet,ensure_ascii=True,allow_nan=False)+"\n").encode("ascii")
        if len(encoded)>16384:raise ValueError("RESEARCH_COMMAND_TOO_LARGE")
        self._pending[ident]=op;self._queue.append(encoded)
        if op in ("stop","quit"):self._stop_deadline=time.monotonic()+90
        self._flush();self.updated.emit();return ident

    def _flush(self):
        if self.process.state()!=QProcess.ProcessState.Running:return
        while self._queue:
            if self.process.bytesToWrite()>1024*1024:return
            data=self._queue.pop(0)
            if self.process.write(data)!=len(data):
                self.last_error="RESEARCH_COMMAND_NOT_SENT";break
        if self.closing and not self._queue:
            # Let the helper's stdin reader finish before Python shutdown;
            # leaving a daemon blocked in buffered stdin can hang finalization.
            self.process.closeWriteChannel()

    def _read(self):
        self._buffer.extend(bytes(self.process.readAllStandardOutput()))
        if len(self._buffer)>8*1024*1024:
            self.last_error="RESEARCH_PROTOCOL_OVERFLOW";self.process.kill();return
        while b"\n" in self._buffer:
            line,_,rest=self._buffer.partition(b"\n");self._buffer=bytearray(rest)
            try:
                packet=json.loads(line)
                if type(packet) is not dict:raise ValueError()
                self.last_response=time.monotonic()
                if packet.get("type")=="snapshot":self._apply(packet["snapshot"])
                elif packet.get("type")=="result":
                    op=self._pending.pop(packet.get("id"),packet.get("op",""))
                    if op in ("stop","quit"):self._stop_deadline=None
                    if op in ("attach","start") and not packet.get("error"):
                        self.last_error=None
                    else:self.last_error=packet.get("error") or self.last_error
                    self.result_ready.emit(op,packet.get("result"),packet.get("error") or "")
                elif packet.get("type")=="error":self.last_error=packet.get("error")
            except (ValueError,KeyError,TypeError):self.last_error="INVALID_RESEARCH_PROTOCOL"
        self.updated.emit();self._flush()

    def _apply(self,data):
        self.data=data
        self.pid=data.get("pid");self.name=data.get("name","")
        self.active=bool(data.get("observation_active_at_export"))
        self.session_state=data.get("session_state","NO_SESSION")
        self.session_folder=Path(data["session_folder"]) if data.get("session_folder") else None
        self.started_at=data.get("started_at_utc");self.total_samples=data.get("sample_count",0)
        self.history=deque(data.get("recent_samples",[]),maxlen=360)
        self.events=deque(data.get("recent_events",[]),maxlen=300)
        self.last_elapsed_ms=int(self.history[-1]["seconds"]*1000) if self.history else None
        self.actions=SimpleNamespace(state=data.get("action_state","IDLE"),completed=data.get("completed_actions",[]),
                                     ready_to_start=lambda:bool(self.data.get("action_ready")))
        self.detailed_capture=SimpleNamespace(samples=data.get("detail_sample_count",0)) if data.get("detail_enabled") else None
        self.incident_capture=True if data.get("incident_enabled") else None
        self.window_capture=self._window_proxy if data.get("window_capture_enabled") else None
        self.report_result=data.get("report_result");self.capabilities=data.get("capabilities",{})
        self.last_error=data.get("last_error") or self.last_error

    @property
    def last(self):return self.history[-1] if self.history else {"seconds":0,"cpu_pct":None,"rss_mb":None,"process_count":None,"thread_count":None}

    def snapshot(self):return dict(self.data)
    def attach(self,pid):return self.send("attach",pid=pid)
    def start(self):return self.send("start")
    def stop(self,reason="USER_STOPPED",**unused):return self.send("stop",reason=reason)
    def prepare_action(self,**args):return self.send("prepare",**args)
    def begin_action(self):return self.send("begin")
    def finish_action(self):return self.send("end")
    def mark_problem(self,note=""):return self.send("mark",note=note)
    def set_detailed_capture(self,enabled):return self.send("detailed",enabled=enabled)
    def set_incident_capture(self,enabled,**args):return self.send("incidents",enabled=enabled,**args)
    def set_window_capture(self,enabled):return self.send("windows",enabled=enabled)

    def shutdown(self):
        if self.alive and not self.closing:
            self.closing=True;self.send("quit")

    def _check_deadline(self):
        if self._stop_deadline is not None and time.monotonic()>self._stop_deadline:
            self.last_error="HELPER_STOP_TIMEOUT_PARTIAL_SESSION_RETAINED"
            self.process.kill()
        elif self.active and time.monotonic()-self.last_response>15 and not self.pending:
            self.last_error="HELPER_NOT_RESPONDING_RECORDING_STATE_UNKNOWN"
            self.updated.emit()

    def _process_error(self,error):
        if error==QProcess.ProcessError.FailedToStart:
            self.last_error="RESEARCH_HELPER_START_FAILED";self.updated.emit()

    def _stderr_ready(self):
        self._stderr=(self._stderr+bytes(self.process.readAllStandardError()).decode("utf-8",errors="replace"))[-4096:]

    def _finished(self,*args):
        if not self.closing:
            self.last_error=f"RESEARCH_HELPER_EXITED_{self.process.exitCode()}: "+self._stderr
        if self.active:self.session_state="INTERRUPTED_UNCONFIRMED"
        self.data["session_state"]=self.session_state
        self.data["observation_active_at_export"]=False
        self.data["snapshot_cache_status"]="HELPER_EXITED"
        self.active=False;self._pending.clear();self._queue.clear();self._watchdog.stop()
        self.updated.emit();self.terminated.emit()
