"""Explicit Windows observation APIs; loaded only on Windows, off the GUI.

The caller owns an isolated helper process, providing a final cancellation
boundary for native calls. No remote thread creation or process injection.
"""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from uuid import uuid4


def _status(error):
    return "ACCESS_DENIED" if error==5 else "TIMEOUT" if error in (1460,258) else "NOT_OBSERVED"


def privilege():
    if os.name!="nt":return {"mode":"STANDARD","windows":False}
    return {"mode":"ADMINISTRATOR" if C.windll.shell32.IsUserAnAdmin() else "STANDARD","windows":True}


def capabilities():
    win=os.name=="nt"
    return {"privilege":privilege(),"process_counters":"AVAILABLE",
        "hwnd":"AVAILABLE" if win else "UNSUPPORTED_PLATFORM",
        "wct":"REQUIRES_PROBE_AND_DEBUG_PRIVILEGE" if win else "UNSUPPORTED_PLATFORM",
        "minidump":"EXPLICIT_OPT_IN" if win else "UNSUPPORTED_PLATFORM",
        "etw_wpr":"AVAILABLE_TOOL" if win and shutil.which("wpr.exe") else "TOOL_UNAVAILABLE",
        "dotnet_trace":"AVAILABLE_TOOL" if shutil.which("dotnet-trace") else "TOOL_UNAVAILABLE",
        "native_symbols":"LOCAL_SYMBOLS_REQUIRED_FOR_NAMES",
        "loss_counters":"UNKNOWN_UNLESS_REPORTED_BY_SOURCE"}


def window_observations(pid, *, timeout_ms=100, limit=4):
    if os.name!="nt":return {"status":"UNSUPPORTED_PLATFORM","source":"WIN32_HWND","windows":[]}
    if not 1<=timeout_ms<=1000 or not 1<=limit<=16:raise ValueError("INVALID_HWND_POLICY")
    user=C.WinDLL("user32",use_last_error=True)
    callback_type=C.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM)
    user.EnumWindows.argtypes=[callback_type,W.LPARAM];user.EnumWindows.restype=W.BOOL
    user.GetWindowThreadProcessId.argtypes=[W.HWND,C.POINTER(W.DWORD)];user.GetWindowThreadProcessId.restype=W.DWORD
    user.SendMessageTimeoutW.argtypes=[W.HWND,W.UINT,W.WPARAM,W.LPARAM,W.UINT,W.UINT,C.POINTER(C.c_size_t)]
    user.SendMessageTimeoutW.restype=C.c_ssize_t
    found=[];truncated=False
    @callback_type
    def collect(hwnd,_):
        nonlocal truncated
        target=W.DWORD()
        tid=user.GetWindowThreadProcessId(hwnd,C.byref(target))
        if target.value==pid:
            if len(found)>=limit:truncated=True;return False
            # Revalidate immediately before sending WM_NULL (no window titles).
            start=time.monotonic_ns();answer=C.c_size_t();C.set_last_error(0)
            ok=user.SendMessageTimeoutW(hwnd,0,0,0,0x2|0x20,timeout_ms,C.byref(answer))
            error=C.get_last_error()
            found.append({"hwnd":int(hwnd),"tid":int(tid),
                "status":"RESPONDED" if ok else _status(error),"winerror":error if not ok else None,
                "duration_ns":time.monotonic_ns()-start,
                "interpretation":"WM_NULL_RESPONSE_ONLY_NOT_CAUSE"})
        return True
    C.set_last_error(0);ok=user.EnumWindows(collect,0);err=C.get_last_error()
    return {"source":"WIN32_HWND","status":"TRUNCATED" if truncated else
            "OK" if ok or found else _status(err),"windows":found,"omitted_count":None if truncated else 0}


def enable_debug_privilege():
    if os.name!="nt":return False
    adv=C.WinDLL("advapi32",use_last_error=True);kernel=C.WinDLL("kernel32",use_last_error=True)
    class Luid(C.Structure):_fields_=[("low",W.DWORD),("high",W.LONG)]
    class Entry(C.Structure):_fields_=[("luid",Luid),("attributes",W.DWORD)]
    class Privileges(C.Structure):_fields_=[("count",W.DWORD),("entry",Entry)]
    kernel.GetCurrentProcess.restype=W.HANDLE
    adv.OpenProcessToken.argtypes=[W.HANDLE,W.DWORD,C.POINTER(W.HANDLE)];adv.OpenProcessToken.restype=W.BOOL
    adv.LookupPrivilegeValueW.argtypes=[W.LPCWSTR,W.LPCWSTR,C.POINTER(Luid)];adv.LookupPrivilegeValueW.restype=W.BOOL
    adv.AdjustTokenPrivileges.argtypes=[W.HANDLE,W.BOOL,C.c_void_p,W.DWORD,C.c_void_p,C.c_void_p];adv.AdjustTokenPrivileges.restype=W.BOOL
    kernel.CloseHandle.argtypes=[W.HANDLE];kernel.CloseHandle.restype=W.BOOL
    token=W.HANDLE()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(),0x20|0x8,C.byref(token)):return False
    try:
        p=Privileges();p.count=1;p.entry.attributes=2
        if not adv.LookupPrivilegeValueW(None,"SeDebugPrivilege",C.byref(p.entry.luid)):return False
        C.set_last_error(0)
        return bool(adv.AdjustTokenPrivileges(token,False,C.byref(p),0,None,None)) and C.get_last_error()==0
    finally:kernel.CloseHandle(token)


_pending_wct=[]


def wait_chain(tid, *, timeout_s=0.25):
    if os.name!="nt":return {"status":"UNSUPPORTED_PLATFORM","source":"WIN32_WCT","nodes":[]}
    # Keep callback, count and arrays alive until the callback has RETURNED.
    # Timed-out native callbacks are retained; a bounded helper process owns them.
    _pending_wct[:]=[r for r in _pending_wct if not r["returned"].is_set()]
    if len(_pending_wct)>=16:return {"status":"TIMEOUT","source":"WIN32_WCT","nodes":[],"reason":"PENDING_CALLBACK_BUDGET"}
    class Lock(C.Structure):
        _fields_=[("name",W.WCHAR*128),("timeout",C.c_int64),("alertable",W.BOOL)]
    class Thread(C.Structure):
        _fields_=[("pid",W.DWORD),("tid",W.DWORD),("wait_ms",W.DWORD),("switches",W.DWORD)]
    class Object(C.Union):_fields_=[("lock",Lock),("thread",Thread)]
    class Node(C.Structure):_fields_=[("type",C.c_int),("status",C.c_int),("object",Object)]
    api=C.WinDLL("advapi32",use_last_error=True)
    callback_type=C.WINFUNCTYPE(None,W.HANDLE,C.c_size_t,W.DWORD,C.POINTER(W.DWORD),C.POINTER(Node),C.POINTER(W.BOOL))
    state={"returned":threading.Event(),"result":None,"nodes":(Node*16)(),"count":W.DWORD(16),"cycle":W.BOOL()}
    @callback_type
    def callback(handle,ctx,error,count,nodes,cycle):
        try:
            n=min(count[0],16) if count and error in (0,234,565) else 0
            rows=[]
            for i in range(n):
                r={"object_type":nodes[i].type,"object_status":nodes[i].status}
                if nodes[i].type==8:
                    r.update(pid=nodes[i].object.thread.pid,tid=nodes[i].object.thread.tid,
                             wait_time_ms=nodes[i].object.thread.wait_ms)
                # Object names deliberately omitted; may contain private paths.
                rows.append(r)
            state["result"]={"status":"OK" if error==0 else "TRUNCATED" if error in (234,565) else _status(error),
                "source":"WIN32_WCT","tid":tid,"winerror":int(error),"nodes":rows,
                "cycle_reported":bool(cycle[0]) if cycle else None,
                "coverage":"SUPPORTED_WCT_SYNCHRONIZATION_ONLY_DYNAMIC_SNAPSHOT"}
        finally:state["returned"].set()
    state["callback"]=callback
    api.OpenThreadWaitChainSession.argtypes=[W.DWORD,callback_type];api.OpenThreadWaitChainSession.restype=W.HANDLE
    api.CloseThreadWaitChainSession.argtypes=[W.HANDLE];api.CloseThreadWaitChainSession.restype=None
    api.GetThreadWaitChain.argtypes=[W.HANDLE,C.c_size_t,W.DWORD,W.DWORD,C.POINTER(W.DWORD),C.POINTER(Node),C.POINTER(W.BOOL)]
    api.GetThreadWaitChain.restype=W.BOOL
    handle=api.OpenThreadWaitChainSession(1,callback)
    if not handle:return {"source":"WIN32_WCT","status":_status(C.get_last_error()),"nodes":[]}
    _pending_wct.append(state)
    try:
        C.set_last_error(0)
        api.GetThreadWaitChain(handle,0,7,tid,C.byref(state["count"]),state["nodes"],C.byref(state["cycle"]))
        error=C.get_last_error()
        if error not in (0,997):return {"source":"WIN32_WCT","status":_status(error),"winerror":error,"nodes":[]}
        if not state["returned"].wait(timeout_s):return {"source":"WIN32_WCT","status":"TIMEOUT","nodes":[]}
        return state["result"]
    finally:
        # This API returns after outstanding callbacks have called and
        # returned; only then may their Python references/arrays be released.
        api.CloseThreadWaitChainSession(handle)
        _pending_wct.remove(state)


def minidump(pid, destination, *, full=False):
    if os.name!="nt":raise OSError("UNSUPPORTED_PLATFORM")
    import msvcrt
    path=Path(destination)
    if path.exists() or path.is_symlink():raise ValueError("DUMP_DESTINATION_EXISTS")
    kernel=C.WinDLL("kernel32",use_last_error=True);dbg=C.WinDLL("dbghelp",use_last_error=True)
    kernel.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];kernel.OpenProcess.restype=W.HANDLE
    kernel.CloseHandle.argtypes=[W.HANDLE];kernel.CloseHandle.restype=W.BOOL
    dbg.MiniDumpWriteDump.argtypes=[W.HANDLE,W.DWORD,W.HANDLE,W.DWORD,C.c_void_p,C.c_void_p,C.c_void_p]
    dbg.MiniDumpWriteDump.restype=W.BOOL
    handle=kernel.OpenProcess(0x400|0x10|0x40,False,pid)
    if not handle:raise OSError(C.get_last_error(),"OPEN_PROCESS_FOR_DUMP_FAILED")
    try:
        with path.open("xb") as stream:
            flags=0x1000|0x800|(0x2 if full else 0)
            if not dbg.MiniDumpWriteDump(handle,pid,msvcrt.get_osfhandle(stream.fileno()),flags,None,None,None):
                raise OSError(C.get_last_error(),"MINIDUMP_WRITE_FAILED")
            stream.flush();os.fsync(stream.fileno())
        return {"source":"DBGHELP_MINIDUMP","path":path.name,"bytes":path.stat().st_size,
                "full_memory":full,"status":"CAPTURED","symbol_resolution":"NOT_PERFORMED"}
    finally:kernel.CloseHandle(handle)


class WprCapture:
    """An explicitly named, private WPR instance; never stop the global one."""
    def __init__(self, folder):
        self.folder=Path(folder);self.instance="BLACKBOX_"+uuid4().hex
        self.tool=shutil.which("wpr.exe") if os.name=="nt" else None
        self.active=False

    def _run(self,args,timeout=20):
        if not self.tool:raise OSError("WPR_TOOL_UNAVAILABLE")
        # Output is spooled, not accumulated in an unbounded communicate buffer.
        import tempfile
        with tempfile.TemporaryFile() as log:
            p=subprocess.Popen([self.tool,*args,"-instancename",self.instance],stdout=log,stderr=log,
                creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
            try:p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                p.kill();p.wait(timeout=5);raise OSError("WPR_COMMAND_TIMEOUT") from None
            log.seek(0);output=log.read(16384).decode("utf-8",errors="replace")
        if p.returncode:raise OSError(f"WPR_COMMAND_FAILED_{p.returncode}: "+output[:1000])
        return output

    def start(self):
        if self.active:raise ValueError("WPR_ALREADY_ACTIVE")
        self.active=True
        try:
            self._run(["-start","GeneralProfile.Light"])
        except BaseException:
            # A start timeout leaves ownership uncertain. Cancel only this
            # random named instance, never another profiler's recording.
            try:self.cancel()
            except OSError:pass
            raise
        return {"source":"ETW_WPR","status":"RECORDING","instance":self.instance,
            "scope":"SYSTEM_WIDE_TRACE_MAY_INCLUDE_OTHER_PROCESSES",
            "retention":"WPR_MEMORY_MODE_CIRCULAR","lost_events":None}

    def stop(self):
        if not self.active:raise ValueError("WPR_NOT_ACTIVE")
        output=self.folder/("trace-"+uuid4().hex+".etl")
        self._run(["-stop",str(output),"BLACK.BOX explicit investigation","-skipPdbGen"],timeout=60)
        self.active=False
        if not output.is_file() or output.stat().st_size==0:raise OSError("WPR_OUTPUT_MISSING")
        return {"source":"ETW_WPR","status":"CAPTURED","path":output.name,
                "bytes":output.stat().st_size,"lost_events":None,"decoded":False}

    def cancel(self):
        if self.active:
            self._run(["-cancel"]);self.active=False
