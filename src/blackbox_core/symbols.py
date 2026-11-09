"""Local native symbol identity checks and explicit offline stack inspection."""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
import os
from pathlib import Path
import shutil
import subprocess
import time
from uuid import uuid4

MAX_CDB_LOG_BYTES = 64 * 1024**2


def symbol_identity(path):
    if os.name!="nt":raise OSError("UNSUPPORTED_PLATFORM")
    path=Path(path)
    if not path.is_file() or path.is_symlink():raise ValueError("INVALID_SYMBOL_FILE")
    class Info(C.Structure):
        _fields_=[("sizeofstruct",W.DWORD),("file",W.WCHAR*261),("stripped",W.BOOL),
            ("timestamp",W.DWORD),("size",W.DWORD),("dbgfile",W.WCHAR*261),
            ("pdbfile",W.WCHAR*261),("guid",C.c_ubyte*16),("sig",W.DWORD),("age",W.DWORD)]
    api=C.WinDLL("dbghelp",use_last_error=True)
    function=api.SymSrvGetFileIndexInfoW
    function.argtypes=[W.LPCWSTR,C.POINTER(Info),W.DWORD];function.restype=W.BOOL
    info=Info();info.sizeofstruct=C.sizeof(info)
    if not function(str(path.resolve()),C.byref(info),0):
        raise OSError(C.get_last_error(),"SYMBOL_IDENTITY_UNAVAILABLE")
    return {"guid":bytes(info.guid).hex(),"signature":info.sig,"age":info.age,
            "source":"DBGHELP_SYMSRV_FILE_INDEX"}


def verify_symbols(binary,pdb):
    a,b=symbol_identity(binary),symbol_identity(pdb)
    known=(any(bytes.fromhex(a["guid"])) or a["signature"]!=0)
    return {"binary":a,"symbols":b,"status":"MATCH" if known and
        (a["guid"],a["signature"],a["age"])==(b["guid"],b["signature"],b["age"]) else "MISMATCH_OR_UNKNOWN",
        "meaning":"NATIVE_DEBUG_IDENTITY_ONLY_NOT_PROGRAM_CORRECTNESS"}


def debugger_tool():
    if os.name!="nt":return None
    found=shutil.which("cdb.exe")
    if found:return found
    candidate=Path(os.environ.get("ProgramFiles(x86)","C:/Program Files (x86)"))/"Windows Kits/10/Debuggers/x64/cdb.exe"
    return str(candidate) if candidate.is_file() else None


def inspect_dump(dump,output_folder,symbol_folder=None):
    """Fixed debugger commands only. Never interpret application text as code."""
    tool=debugger_tool()
    if not tool:raise OSError("LOCAL_CDB_TOOL_UNAVAILABLE")
    dump=Path(dump)
    if not dump.is_file() or dump.is_symlink():raise ValueError("INVALID_DUMP_FILE")
    args=[tool,"-z",str(dump.resolve())]
    if symbol_folder is not None:
        symbols=Path(symbol_folder)
        if not symbols.is_dir() or str(symbols).startswith(("\\\\","//")):
            raise ValueError("LOCAL_SYMBOL_DIRECTORY_REQUIRED")
        args.extend(["-y",str(symbols.resolve())])
    args.extend(["-c",".reload;~* kb;q"])
    output=Path(output_folder)/("stacks-"+uuid4().hex+".txt")
    env={**os.environ,"_NT_SYMBOL_PATH":str(symbol_folder or ""),"_NT_ALT_SYMBOL_PATH":""}
    with output.open("xb") as log:
        process=subprocess.Popen(args,stdout=log,stderr=log,env=env,
            creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        deadline=time.monotonic()+60
        try:
            while True:
                if os.fstat(log.fileno()).st_size>MAX_CDB_LOG_BYTES:
                    raise OSError("STACK_ANALYSIS_OUTPUT_BUDGET_EXCEEDED")
                remaining=deadline-time.monotonic()
                if remaining<=0:raise OSError("STACK_ANALYSIS_TIMEOUT")
                try:
                    process.wait(timeout=min(.1,remaining))
                    break
                except subprocess.TimeoutExpired:
                    pass
            if os.fstat(log.fileno()).st_size>MAX_CDB_LOG_BYTES:
                raise OSError("STACK_ANALYSIS_OUTPUT_BUDGET_EXCEEDED")
        except BaseException:
            # Only this actual debugger child is stopped. Its outer optional
            # worker retains its existing Job Object/process-group boundary.
            if process.poll() is None:
                process.kill();process.wait(timeout=5)
            raise
    with output.open("rb") as stream:preview=stream.read(8192).decode("utf-8",errors="replace")
    return {"source":"CDB_OFFLINE_DUMP","path":output.name,"exit_code":process.returncode,
        "status":"DEBUGGER_OUTPUT" if process.returncode==0 else "DEBUGGER_FAILED",
        "preview":preview,"symbols_fully_resolved":None,"root_cause_proven":False,
        "output_budget_bytes":MAX_CDB_LOG_BYTES,"output_budget_enforcement":"POLLED_SOFT_LIMIT_NOT_FILESYSTEM_QUOTA"}
