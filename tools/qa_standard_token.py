"""Run the frozen research scenario with admin SID/privileges removed.

CI-only: no accounts, policies, services or system settings are changed.
The restricted token is a temporary child of the runner's own token.
"""
from __future__ import annotations
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import subprocess


def run(exe,output):
    if os.name!="nt":raise OSError("WINDOWS_REQUIRED")
    exe,output=Path(exe).resolve(),Path(output).resolve()
    if not exe.is_file() or output.exists():raise ValueError("INVALID_QA_PATH")
    kernel=C.WinDLL("kernel32",use_last_error=True);adv=C.WinDLL("advapi32",use_last_error=True)
    class Sid(C.Structure):_fields_=[("sid",C.c_void_p),("attributes",W.DWORD)]
    class Startup(C.Structure):
        _fields_=[("cb",W.DWORD),("reserved",W.LPWSTR),("desktop",W.LPWSTR),("title",W.LPWSTR),
            ("x",W.DWORD),("y",W.DWORD),("width",W.DWORD),("height",W.DWORD),
            ("cols",W.DWORD),("rows",W.DWORD),("fill",W.DWORD),("flags",W.DWORD),
            ("show",W.WORD),("reserved_bytes",W.WORD),("reserved_ptr",C.c_void_p),
            ("stdin",W.HANDLE),("stdout",W.HANDLE),("stderr",W.HANDLE)]
    class Process(C.Structure):
        _fields_=[("process",W.HANDLE),("thread",W.HANDLE),("pid",W.DWORD),("tid",W.DWORD)]
    kernel.GetCurrentProcess.restype=W.HANDLE
    kernel.CloseHandle.argtypes=[W.HANDLE];kernel.CloseHandle.restype=W.BOOL
    kernel.LocalFree.argtypes=[C.c_void_p];kernel.LocalFree.restype=C.c_void_p
    kernel.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];kernel.WaitForSingleObject.restype=W.DWORD
    kernel.GetExitCodeProcess.argtypes=[W.HANDLE,C.POINTER(W.DWORD)];kernel.GetExitCodeProcess.restype=W.BOOL
    kernel.TerminateProcess.argtypes=[W.HANDLE,W.UINT];kernel.TerminateProcess.restype=W.BOOL
    adv.OpenProcessToken.argtypes=[W.HANDLE,W.DWORD,C.POINTER(W.HANDLE)];adv.OpenProcessToken.restype=W.BOOL
    adv.ConvertStringSidToSidW.argtypes=[W.LPCWSTR,C.POINTER(C.c_void_p)];adv.ConvertStringSidToSidW.restype=W.BOOL
    adv.CreateRestrictedToken.argtypes=[W.HANDLE,W.DWORD,W.DWORD,C.POINTER(Sid),W.DWORD,C.c_void_p,W.DWORD,C.c_void_p,C.POINTER(W.HANDLE)]
    adv.CreateRestrictedToken.restype=W.BOOL
    adv.CreateProcessAsUserW.argtypes=[W.HANDLE,W.LPCWSTR,W.LPWSTR,C.c_void_p,C.c_void_p,W.BOOL,W.DWORD,C.c_void_p,W.LPCWSTR,C.POINTER(Startup),C.POINTER(Process)]
    adv.CreateProcessAsUserW.restype=W.BOOL
    original=W.HANDLE();restricted=W.HANDLE();admin_sid=C.c_void_p();process=Process()
    try:
        if not adv.OpenProcessToken(kernel.GetCurrentProcess(),0xB,C.byref(original)):
            raise OSError(C.get_last_error(),"QA_OPEN_TOKEN_FAILED")
        if not adv.ConvertStringSidToSidW("S-1-5-32-544",C.byref(admin_sid)):
            raise OSError(C.get_last_error(),"QA_ADMIN_SID_FAILED")
        disable=Sid(admin_sid,0)
        if not adv.CreateRestrictedToken(original,1,1,C.byref(disable),0,None,0,None,C.byref(restricted)):
            raise OSError(C.get_last_error(),"QA_RESTRICT_TOKEN_FAILED")
        startup=Startup();startup.cb=C.sizeof(startup)
        command=C.create_unicode_buffer(subprocess.list2cmdline([str(exe),"--research-e2e",str(output)]))
        if not adv.CreateProcessAsUserW(restricted,str(exe),command,None,None,False,0,None,str(exe.parent),C.byref(startup),C.byref(process)):
            raise OSError(C.get_last_error(),"QA_RESTRICTED_START_FAILED")
        if kernel.WaitForSingleObject(process.process,120000)!=0:
            kernel.TerminateProcess(process.process,1)
            raise TimeoutError("STANDARD_TOKEN_QA_TIMEOUT")
        exit_code=W.DWORD()
        if not kernel.GetExitCodeProcess(process.process,C.byref(exit_code)) or exit_code.value!=0:
            raise RuntimeError("STANDARD_TOKEN_GUI_FAILED")
        proof=json.loads((output/"e2e.json").read_text())
        if proof.get("status")!="PASS" or proof.get("privilege",{}).get("mode")!="STANDARD":
            raise RuntimeError("STANDARD_TOKEN_NOT_CONFIRMED")
        print(json.dumps({"status":"PASS","token":"ADMIN_SID_DISABLED_PRIVILEGES_REMOVED","proof":proof}))
    finally:
        for handle in (process.thread,process.process,restricted,original):
            if handle:kernel.CloseHandle(handle)
        if admin_sid:kernel.LocalFree(admin_sid)


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("exe");parser.add_argument("output")
    args=parser.parse_args();run(args.exe,args.output)
