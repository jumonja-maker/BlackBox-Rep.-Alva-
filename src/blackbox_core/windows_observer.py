"""Read-only Win32 window responsiveness and asynchronous WCT adapters.

No titles/object names, privilege changes, broadcasts or injected messages.
Only WM_NULL is sent to verified individual HWNDs, from the sensor worker.
ABI: winuser.h / wct.h, x64; fixed-width Windows integers also permit Linux
layout tests. Official API references and remaining limits: ADR-04.
"""
from __future__ import annotations
import ctypes as C
import os
from threading import Event, Lock, Thread
import time

DWORD=C.c_uint32
BOOL=C.c_int32
PTR=C.c_size_t
CALLBACK=getattr(C,"WINFUNCTYPE",C.CFUNCTYPE)


class LockObject(C.Structure):
    _fields_=[("ObjectName",C.c_uint16*128),("Timeout",C.c_int64),("Alertable",BOOL)]


class ThreadObject(C.Structure):
    _fields_=[("ProcessId",DWORD),("ThreadId",DWORD),("WaitTime",DWORD),("ContextSwitches",DWORD)]


class NodeUnion(C.Union):
    _fields_=[("LockObject",LockObject),("ThreadObject",ThreadObject)]


class WaitChainNode(C.Structure):
    _fields_=[("ObjectType",C.c_int32),("ObjectStatus",C.c_int32),("data",NodeUnion)]


WctCallback=CALLBACK(None,C.c_void_p,PTR,DWORD,C.POINTER(DWORD),C.POINTER(WaitChainNode),C.POINTER(BOOL))
EnumCallback=CALLBACK(BOOL,C.c_void_p,C.c_ssize_t)


def win32_status(code):
    return {0:"OK",5:"ACCESS_DENIED",50:"UNSUPPORTED",120:"UNSUPPORTED",
            1460:"SENSOR_TIMEOUT",1400:"WINDOW_GONE",1168:"NOT_OBSERVED",
            1223:"CANCELLED",234:"TRUNCATED",565:"TRUNCATED"}.get(code,"UNKNOWN")


def verify_identity(pid,created):
    import psutil
    try:
        return abs(psutil.Process(pid).create_time()-created)<=.000001
    except (psutil.Error,OSError):
        return False


class WindowsNative:
    def __init__(self):
        if os.name!="nt":
            raise RuntimeError("UNSUPPORTED_OS")
        if C.sizeof(WaitChainNode)!=280 or C.sizeof(PTR)!=8:
            raise RuntimeError("UNSUPPORTED_WINDOWS_ABI")
        self.user=C.WinDLL("user32",use_last_error=True)
        self.advapi=C.WinDLL("advapi32",use_last_error=True)
        self.user.EnumWindows.argtypes=[EnumCallback,C.c_ssize_t]
        self.user.EnumWindows.restype=BOOL
        self.user.GetWindowThreadProcessId.argtypes=[C.c_void_p,C.POINTER(DWORD)]
        self.user.GetWindowThreadProcessId.restype=DWORD
        self.user.IsWindowVisible.argtypes=[C.c_void_p]
        self.user.IsWindowVisible.restype=BOOL
        self.user.SendMessageTimeoutW.argtypes=[C.c_void_p,DWORD,PTR,C.c_ssize_t,DWORD,DWORD,C.POINTER(PTR)]
        self.user.SendMessageTimeoutW.restype=C.c_ssize_t
        self.advapi.OpenThreadWaitChainSession.argtypes=[DWORD,WctCallback]
        self.advapi.OpenThreadWaitChainSession.restype=C.c_void_p
        self.advapi.GetThreadWaitChain.argtypes=[C.c_void_p,PTR,DWORD,DWORD,C.POINTER(DWORD),
                                               C.POINTER(WaitChainNode),C.POINTER(BOOL)]
        self.advapi.GetThreadWaitChain.restype=BOOL
        self.advapi.CloseThreadWaitChainSession.argtypes=[C.c_void_p]
        self.advapi.CloseThreadWaitChainSession.restype=None

    def owner(self,hwnd):
        pid=DWORD()
        tid=self.user.GetWindowThreadProcessId(C.c_void_p(hwnd),C.byref(pid))
        return int(pid.value),int(tid)

    def enumerate(self,pid,limit=32):
        rows=[]
        omitted=0
        def visit(hwnd,param):
            nonlocal omitted
            try:
                owner,tid=self.owner(hwnd)
                if owner==pid:
                    if len(rows)<limit:
                        rows.append({"hwnd":int(hwnd),"pid":owner,"tid":tid,
                                     "visible":bool(self.user.IsWindowVisible(hwnd))})
                    else:
                        omitted+=1
                return 1
            except Exception:
                return 0
        callback=EnumCallback(visit)  # Strong reference through EnumWindows.
        C.set_last_error(0)
        ok=self.user.EnumWindows(callback,0)
        code=C.get_last_error() if not ok else 0
        return {"status":win32_status(code) if ok or code else "UNKNOWN",
                "win32_code":code,"windows":rows,"omitted":omitted}

    def responsiveness(self,window,timeout_ms=150):
        if type(timeout_ms) is not int or not 50<=timeout_ms<=500:
            raise ValueError("INVALID_WINDOW_TIMEOUT")
        began=time.monotonic_ns()
        expected=(window["pid"],window["tid"])
        if self.owner(window["hwnd"])!=expected:
            return {"status":"WINDOW_GONE","win32_code":None,"started_ns":began,
                    "ended_ns":time.monotonic_ns(),"timeout_ms":timeout_ms,
                    "method":"GetWindowThreadProcessId/OWNER_IDENTITY_CHECK",
                    "reason":"HWND_OWNER_NO_LONGER_MATCHES"}
        result=PTR()
        C.set_last_error(0)
        # WM_NULL=0. Never HWND_BROADCAST or NOTIMEOUTIFNOTHUNG.
        ok=self.user.SendMessageTimeoutW(C.c_void_p(window["hwnd"]),0,0,0,0x1|0x2|0x20,
                                         timeout_ms,C.byref(result))
        code=C.get_last_error() if not ok else 0
        status="OK" if ok else win32_status(code) if code else "UNKNOWN"
        if self.owner(window["hwnd"])!=expected:
            # Preserve the actual SendMessage result code. An owner mismatch
            # is not evidence that Win32 returned ERROR_INVALID_WINDOW_HANDLE.
            status="WINDOW_GONE"
        return {"status":status,"win32_code":code,"started_ns":began,
                "ended_ns":time.monotonic_ns(),"timeout_ms":timeout_ms,
                "method":"SendMessageTimeoutW/WM_NULL/SMTO_BLOCK|ABORTIFHUNG|ERRORONEXIT"}

    def wait_chain(self,tid,timeout_s=.3):
        if type(tid) is not int or not 0<tid<2**32 or not .05<=timeout_s<=1:
            raise ValueError("INVALID_WCT_REQUEST")
        done=Event()
        packet={"status":"UNKNOWN","win32_code":None,"nodes":[],"is_cycle":None}
        def completed(handle,context,status,count,nodes,cycle):
            try:
                code=int(status)
                packet.update(status=win32_status(code),win32_code=code)
                n=int(count[0]) if count else 0
                # ERROR_MORE_DATA may report required count >16; never read
                # beyond the caller-owned array, regardless of callback data.
                if code in (0,234,565) and nodes:
                    result=[]
                    for index in range(min(n,16)):
                        node=nodes[index]
                        value={"object_type":int(node.ObjectType),"object_status":int(node.ObjectStatus)}
                        if node.ObjectType==8:  # WctThreadType, wct.h.
                            t=node.data.ThreadObject
                            value.update(pid=int(t.ProcessId),tid=int(t.ThreadId),
                                         wait_time_raw=int(t.WaitTime),context_switches=int(t.ContextSwitches))
                        # ObjectName is intentionally never decoded or saved.
                        result.append(value)
                    packet.update(nodes=result,is_cycle=bool(cycle[0]) if cycle else None,
                                  reported_node_count=n,truncated=n>16 or code in (234,565))
            except Exception:
                packet.update(status="INVALID",nodes=[],is_cycle=None)
            finally:
                done.set()
        callback=WctCallback(completed)
        began=time.monotonic_ns()
        C.set_last_error(0)
        handle=self.advapi.OpenThreadWaitChainSession(1,callback)  # WCT_ASYNC_OPEN_FLAG.
        if not handle:
            code=C.get_last_error()
            return {**packet,"status":win32_status(code) if code else "UNKNOWN","win32_code":code,
                    "started_ns":began,"ended_ns":time.monotonic_ns(),"tid":tid}
        count=DWORD(16)
        nodes=(WaitChainNode*16)()
        cycle=BOOL()
        timed_out=False
        try:
            C.set_last_error(0)
            ok=self.advapi.GetThreadWaitChain(handle,0,1,tid,C.byref(count),nodes,C.byref(cycle))
            code=C.get_last_error() if not ok else 0
            if not ok and code!=997:  # ERROR_IO_PENDING is normal async admission.
                packet.update(status=win32_status(code) if code else "UNKNOWN",win32_code=code)
            else:
                timed_out=not done.wait(timeout_s)
        finally:
            # Documented cancellation invokes/joins outstanding callbacks.
            # All callback/array/count references remain alive until return.
            cleanup_began=time.monotonic_ns()
            self.advapi.CloseThreadWaitChainSession(handle)
            cleanup_ended=time.monotonic_ns()
        if timed_out:
            packet.update(status="SENSOR_TIMEOUT",nodes=[],is_cycle=None)
        return {**packet,"tid":tid,"started_ns":began,"ended_ns":time.monotonic_ns(),
                "observer_deadline_exceeded":timed_out,
                "cleanup_duration_ns":cleanup_ended-cleanup_began,
                "deadline_ns":began+int(timeout_s*1e9),"method":"ASYNCHRONOUS_GET_THREAD_WAIT_CHAIN",
                "root_cause":"UNKNOWN","limitation":"DYNAMIC_SNAPSHOT_NOT_COMPLETE_ROOT_CAUSE"}


class WindowCapture:
    """One low-frequency worker; no per-HWND or per-TID thread fanout."""
    def __init__(self,pid,created,writer,*,adapter=None,identity=None,interval_s=2.,consecutive=2):
        if not 1<=interval_s<=30 or type(consecutive) is not int or not 2<=consecutive<=5:
            raise ValueError("INVALID_WINDOW_POLICY")
        self.pid,self.created,self.writer=pid,created,writer
        self.adapter=adapter
        self.identity=identity or verify_identity
        self.interval_s,self.consecutive=interval_s,consecutive
        self.selected_hwnd=None
        self.stop_event=Event()
        self.thread=None
        self.status="NOT_STARTED"
        self._windows={}
        self._view=()
        self.last_poll_completed_ns=None
        self._lock=Lock()

    def snapshot(self):
        with self._lock:
            return self.status,self._view

    def start(self):
        # Native callbacks must finish before Python interpreter finalization.
        self.thread=Thread(target=self._run,name="blackbox-windows-observer",daemon=False)
        self.thread.start()

    def stop(self,timeout=0):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout)
            return not self.thread.is_alive()
        return True

    def _run(self):
        try:
            self.adapter=self.adapter or WindowsNative()
            while not self.stop_event.is_set():
                if not self.identity(self.pid,self.created):
                    self.status="TARGET_IDENTITY_UNAVAILABLE"
                    break
                self.poll()
                self.last_poll_completed_ns=time.monotonic_ns()
                self.stop_event.wait(self.interval_s)
        except RuntimeError as exc:
            self.status=str(exc) if str(exc) in ("UNSUPPORTED_OS","UNSUPPORTED_WINDOWS_ABI") else "SENSOR_FAILURE"
            if self.writer:
                try:
                    self.writer.submit("error",{"time_ns":time.monotonic_ns(),"sensor_id":"WIN32_WCT",
                                                "code":self.status})
                except Exception:
                    pass
        except Exception:
            self.status="SENSOR_FAILURE"
            if self.writer:
                try:
                    self.writer.submit("error",{"time_ns":time.monotonic_ns(),"sensor_id":"WIN32_WCT",
                                                "code":"WINDOW_SENSOR_FAILURE"})
                except Exception:
                    pass

    def poll(self):
        result=self.adapter.enumerate(self.pid)
        stamp=time.monotonic_ns()
        self.status=result["status"]
        if self.status!="OK":
            if self.writer:
                self.writer.submit("error",{"time_ns":stamp,"sensor_id":"WIN32_ENUMERATION",
                    "code":self.status,"win32_code":result.get("win32_code")})
            return
        windows=result["windows"]
        self.status="NOT_APPLICABLE" if not windows else "OBSERVING"
        events=[{"code":"WINDOW_ENUMERATION_STATUS","time_ns":stamp,
                 "check":{"status":"NOT_APPLICABLE" if not windows else "OK","method":"EnumWindows",
                          "win32_code":0,"enumeration_omitted":result.get("omitted",0)}}]
        current={w["hwnd"]:w for w in windows}
        for hwnd,old in list(self._windows.items()):
            if hwnd not in current or current[hwnd]["tid"]!=old["window"]["tid"]:
                if hwnd in current or not result.get("omitted"):
                    events.append({"code":"WINDOW_GONE","window":old["window"],"time_ns":stamp,
                                   "onset":"BETWEEN_LAST_PRESENT_AND_ABSENCE_OBSERVATION"})
                del self._windows[hwnd]
        chosen=sorted(windows,key=lambda w:(w["hwnd"]!=self.selected_hwnd,not w["visible"],w["hwnd"]))[:4]
        for window in chosen:
            state=self._windows.setdefault(window["hwnd"],{
                "window":window,"timeouts":0,"unresponsive":False,"last_responsive_ns":None,
                "first_timeout_ns":None})
            state["window"]=window
            check=self.adapter.responsiveness(window)
            when=check["ended_ns"]
            events.append({"code":"WINDOW_PROBE_RESULT","window":window,"time_ns":when,"check":check})
            if check["status"]=="SENSOR_TIMEOUT":
                state["timeouts"]+=1
                state["first_timeout_ns"]=state["first_timeout_ns"] or when
                if state["timeouts"]>=self.consecutive and not state["unresponsive"]:
                    state["unresponsive"]=True
                    events.append({"code":"UI_UNRESPONSIVE_OBSERVED","window":window,"time_ns":when,
                        "check":check,"consecutive_timeouts":state["timeouts"],
                        "last_responsive_ns":state["last_responsive_ns"],
                        "first_timeout_ns":state["first_timeout_ns"],"onset_exact":False})
                    chain=self.adapter.wait_chain(window["tid"])
                    events.append({"code":"WCT_SNAPSHOT","window":window,
                                   "time_ns":chain["ended_ns"],"wct":chain})
            elif check["status"]=="OK":
                if state["unresponsive"]:
                    events.append({"code":"UI_RESPONSIVE_AGAIN","window":window,"time_ns":when,
                                   "check":check,"first_timeout_ns":state["first_timeout_ns"],
                                   "duration_is_observation_bound":True})
                state.update(timeouts=0,unresponsive=False,last_responsive_ns=when,first_timeout_ns=None)
            else:
                state["timeouts"]=0
                events.append({"code":"WINDOW_PROBE_STATUS","window":window,"time_ns":when,"check":check})
        # Enumeration is not a probe of every window. Persist explicit quota.
        for window in windows:
            self._windows.setdefault(window["hwnd"],{"window":window,"timeouts":0,
                "unresponsive":False,"last_responsive_ns":None,"first_timeout_ns":None})
        if not self.identity(self.pid,self.created):
            self.status="TARGET_IDENTITY_UNAVAILABLE"
            return
        if self.writer:
            self.writer.submit("windows",{"time_ns":stamp,"windows":windows,"events":events,
                "pid":self.pid,"created":self.created,"enumeration_omitted":result.get("omitted",0),
                "probe_omitted":max(0,len(windows)-len(chosen))})
        with self._lock:
            self._view=tuple({**v["window"],"consecutive_timeouts":v["timeouts"],
                              "unresponsive_observed":v["unresponsive"]} for v in self._windows.values())
