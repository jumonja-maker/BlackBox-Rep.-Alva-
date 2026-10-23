"""Opt-in bounded EventPipe collection through a locally installed tool."""
from __future__ import annotations
import os
from pathlib import Path
import shutil
import subprocess
import time
from uuid import uuid4


class DotnetTrace:
    def __init__(self,folder,pid,seconds=10,*,tool=None):
        if type(seconds) is not int or not 1<=seconds<=86400:raise ValueError("INVALID_TRACE_DURATION")
        self.tool=tool or shutil.which("dotnet-trace")
        if not self.tool:raise OSError("DOTNET_TRACE_TOOL_UNAVAILABLE")
        self.folder=Path(folder);self.pid=pid;self.seconds=seconds
        stem="eventpipe-"+uuid4().hex
        self.path=self.folder/(stem+".nettrace");self.log_path=self.folder/(stem+".log")
        self.process=None;self.log=None;self.deadline=None

    def start(self):
        if self.process is not None:raise ValueError("TRACE_ALREADY_STARTED")
        days,remaining=divmod(self.seconds,86400);hours,remaining=divmod(remaining,3600);minutes,seconds=divmod(remaining,60)
        duration=f"{days:02}:{hours:02}:{minutes:02}:{seconds:02}"
        self.log=self.log_path.open("xb")
        try:
            self.process=subprocess.Popen([self.tool,"collect","--process-id",str(self.pid),
                "--duration",duration,"--buffersize","16","--format","NetTrace","--output",str(self.path)],
                stdin=subprocess.DEVNULL,stdout=self.log,stderr=self.log,
                creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        except BaseException:self.log.close();raise
        self.deadline=time.monotonic()+self.seconds+60
        return {"source":"EVENTPIPE_DOTNET_TRACE","status":"START_REQUESTED",
                "target_pid":self.pid,"duration_seconds":self.seconds,"buffer_mb":16,
                "lost_events":None,"runtime_handshake_verified":False}

    def poll(self):
        if self.process is None:return None
        rc=self.process.poll()
        if rc is None:
            if time.monotonic()>self.deadline:return self.stop()
            return None
        self.log.close();self.process=None
        size=self.path.stat().st_size if self.path.is_file() else 0
        return {"source":"EVENTPIPE_DOTNET_TRACE","status":"CAPTURED" if rc==0 and size>0 else "FAILED",
                "exit_code":rc,"path":self.path.name,"bytes":size,"lost_events":None,"decoded":False}

    def stop(self):
        if self.process is None:return None
        if self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=3)
        result=self.poll()
        if result:result["status"]="INTERRUPTED_TRACE_NOT_CERTIFIED"
        return result
