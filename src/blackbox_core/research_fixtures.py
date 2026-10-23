"""Controlled real applications for observer acceptance; explicit QA only."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

KINDS=("idle","cpu","stable-memory","growing-memory","released-memory","io",
       "children","app-events","gui-hang","wait-chain","crash","burst")


def run(kind,seconds=3,ready=None,event_config=None):
    if kind not in KINDS or not 0<seconds<=24*3600:raise ValueError("INVALID_FIXTURE")
    info={"pid":os.getpid(),"tid":threading.get_native_id(),"kind":kind,"started_ns":time.monotonic_ns()}
    children=[];held=[];stop=threading.Event()
    if kind=="wait-chain":
        if os.name!="nt":raise OSError("WINDOWS_FIXTURE_REQUIRED")
        import ctypes as C
        from ctypes import wintypes as W
        k=C.WinDLL("kernel32",use_last_error=True)
        k.CreateMutexW.argtypes=[C.c_void_p,W.BOOL,W.LPCWSTR];k.CreateMutexW.restype=W.HANDLE
        k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.WaitForSingleObject.restype=W.DWORD
        k.ReleaseMutex.argtypes=[W.HANDLE];k.CloseHandle.argtypes=[W.HANDLE]
        mutex=k.CreateMutexW(None,True,None)
        if not mutex:raise OSError("FIXTURE_MUTEX_FAILED")
        def wait():
            info["wait_tid"]=threading.get_native_id()
            k.WaitForSingleObject(mutex,int(seconds*1000)+1000)
            k.ReleaseMutex(mutex)
        thread=threading.Thread(target=wait);thread.start()
        while "wait_tid" not in info:time.sleep(.001)
    if kind=="gui-hang":
        if os.name!="nt":raise OSError("WINDOWS_FIXTURE_REQUIRED")
        import ctypes as C
        from ctypes import wintypes as W
        u=C.WinDLL("user32",use_last_error=True);k=C.WinDLL("kernel32",use_last_error=True)
        callback=C.WINFUNCTYPE(C.c_ssize_t,W.HWND,W.UINT,W.WPARAM,W.LPARAM)
        u.DefWindowProcW.argtypes=[W.HWND,W.UINT,W.WPARAM,W.LPARAM];u.DefWindowProcW.restype=C.c_ssize_t
        @callback
        def wndproc(h,m,w,l):return u.DefWindowProcW(h,m,w,l)
        class WC(C.Structure):
            _fields_=[("style",W.UINT),("proc",callback),("extra1",C.c_int),("extra2",C.c_int),
                      ("instance",W.HINSTANCE),("icon",W.HICON),("cursor",W.HANDLE),
                      ("brush",W.HBRUSH),("menu",W.LPCWSTR),("name",W.LPCWSTR)]
        k.GetModuleHandleW.argtypes=[W.LPCWSTR];k.GetModuleHandleW.restype=W.HMODULE
        u.RegisterClassW.argtypes=[C.POINTER(WC)];u.RegisterClassW.restype=W.WORD
        u.CreateWindowExW.argtypes=[W.DWORD,W.LPCWSTR,W.LPCWSTR,W.DWORD,C.c_int,C.c_int,C.c_int,C.c_int,W.HWND,W.HMENU,W.HINSTANCE,C.c_void_p]
        u.CreateWindowExW.restype=W.HWND
        wc=WC();wc.proc=wndproc;wc.instance=k.GetModuleHandleW(None);wc.name="BlackBoxControlledHang"
        if not u.RegisterClassW(C.byref(wc)):raise OSError("FIXTURE_WINDOW_CLASS_FAILED")
        hwnd=u.CreateWindowExW(0,wc.name,"BLACK.BOX test",0,0,0,100,100,None,None,wc.instance,None)
        if not hwnd:raise OSError("FIXTURE_WINDOW_FAILED")
        info["hwnd"]=int(hwnd)
    if ready:Path(ready).write_text(json.dumps(info),encoding="utf-8")
    end=time.monotonic()+seconds
    try:
        if kind=="cpu":
            value=1
            while time.monotonic()<end:value=(value*1664525+1013904223)&0xffffffff
        elif kind in ("stable-memory","growing-memory","released-memory"):
            if kind!="growing-memory":held.append(bytearray(8*1024*1024))
            while time.monotonic()<end:
                if kind=="growing-memory":held.append(bytearray(256*1024))
                elif kind=="released-memory":held.clear()
                time.sleep(.1)
        elif kind=="io":
            with tempfile.TemporaryFile() as f:
                while time.monotonic()<end:
                    f.write(b"x"*65536);f.flush();f.seek(0);f.read(65536);f.seek(0);time.sleep(.02)
        elif kind=="children":
            for _ in range(2):children.append(subprocess.Popen([sys.executable,"-c",f"import time;time.sleep({seconds+2})"]))
            time.sleep(seconds)
        elif kind in ("app-events","burst"):
            from .instrumentation import EventWriter
            cfg=json.loads(Path(event_config).read_text());writer=EventWriter(cfg["path"],cfg["token"])
            writer.emit("blackbox.ready")
            while time.monotonic()<end:
                with writer.operation("controlled.operation"):pass
                if kind!="burst":time.sleep(.05)
        elif kind=="crash":raise RuntimeError("CONTROLLED_FIXTURE_EXCEPTION")
        else:time.sleep(seconds)
    finally:
        if kind=="wait-chain":
            k.ReleaseMutex(mutex);thread.join(2);k.CloseHandle(mutex)
        for p in children:
            if p.poll() is None:p.terminate()
            p.wait(timeout=5)
    return 0


def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument("kind",choices=KINDS)
    p.add_argument("--seconds",type=float,default=3);p.add_argument("--ready");p.add_argument("--event-config")
    a=p.parse_args(argv);return run(a.kind,a.seconds,a.ready,a.event_config)


if __name__=="__main__":raise SystemExit(main())
