"""Local library file boundaries. No recursive deletion is provided here."""
from __future__ import annotations
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import time
from uuid import uuid4

from .session_v2 import safe_path


def checked(path):
    return safe_path(Path(path))


def read_json(path, limit=16384):
    path=checked(path)
    if not path.is_file() or path.stat().st_size>limit:raise ValueError('LIBRARY_INVALID_MARKER')
    data=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data,dict):raise ValueError('LIBRARY_INVALID_MARKER')
    return data


def atomic_json(path,data,*,exclusive=False,max_bytes=65536):
    path=checked(path);tmp=path.with_name(path.name+'.'+uuid4().hex+'.tmp')
    raw=json.dumps(data,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode('ascii')
    if type(max_bytes) is not int or not 1<=max_bytes<=8*1024**2 or len(raw)>max_bytes:raise ValueError('LIBRARY_MARKER_TOO_LARGE')
    try:
        with tmp.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        if exclusive:os.link(tmp,path)
        else:os.replace(tmp,path)
    finally:
        if tmp.exists():tmp.unlink()


def identity(path):
    stat=checked(path).stat()
    return [stat.st_dev,stat.st_ino]


def tree_summary(folder,*,max_files=10000,max_seconds=.5):
    """Bounded metadata-only estimate. Unknown size is never zero bytes."""
    folder=checked(folder);start=time.monotonic();files=0;size=0;digest=hashlib.sha256()
    stack=[(folder,0)]
    while stack:
        parent,depth=stack.pop()
        if depth>12:return {'bytes':None,'files':files,'status':'DEPTH_LIMIT','fingerprint':None}
        # Retain at most max_files names; no file contents are read.
        with os.scandir(parent) as entries:
            names=[]
            for item in entries:
                if files+len(names)>=max_files or time.monotonic()-start>max_seconds:
                    return {'bytes':None,'files':files,'status':'SIZE_ESTIMATE_BUDGET','fingerprint':None}
                names.append(item.name)
        for name in sorted(names):
            path=checked(parent/name);stat=path.lstat();files+=1
            relative=path.relative_to(folder).as_posix()
            # SQLite readers update SHM locks without changing observations.
            # Nonempty WAL remains part of the evidence-change check.
            volatile=name.endswith('.sqlite3-shm') or name.endswith('.sqlite3-wal') and stat.st_size==0
            is_dir=path.is_dir()
            if not volatile:
                # Read-only SQLite opens can create/remove lock sidecars and
                # change directory metadata; child names/content stats below
                # still detect actual non-volatile evidence changes.
                parts=[relative,stat.st_mode,stat.st_ino] if is_dir else [relative,stat.st_mode,stat.st_size,stat.st_mtime_ns,stat.st_ino]
                digest.update(json.dumps(parts,ensure_ascii=True).encode())
            if is_dir:stack.append((path,depth+1))
            elif path.is_file():size+=stat.st_size
            else:raise ValueError('LIBRARY_UNSUPPORTED_FILE_TYPE')
    return {'bytes':size,'files':files,'status':'METADATA_ESTIMATE','fingerprint':digest.hexdigest()}


def windows_move_error(code,destination):
    """Normalize atomic native collision without hiding its original code."""
    error=(FileExistsError(errno.EEXIST,'LIBRARY_DESTINATION_EXISTS',str(destination))
        if code in (80,183) else OSError(code,'LIBRARY_MOVE_FAILED',str(destination)))
    error.winerror=code
    return error

def move_no_replace(source,destination):
    """Atomic same-volume rename that refuses an existing destination."""
    source,destination=checked(source),checked(destination)
    if destination.exists():raise FileExistsError('LIBRARY_DESTINATION_EXISTS')
    if os.name=='nt':
        from ctypes import wintypes as W
        k=ctypes.WinDLL('kernel32',use_last_error=True)
        k.MoveFileW.argtypes=[W.LPCWSTR,W.LPCWSTR];k.MoveFileW.restype=W.BOOL
        if not k.MoveFileW(str(source),str(destination)):
            raise windows_move_error(ctypes.get_last_error(),destination)
    elif os.name=='posix':
        libc=ctypes.CDLL(None,use_errno=True)
        rename=getattr(libc,'renameat2',None)
        if rename is None:raise OSError('LIBRARY_ATOMIC_MOVE_UNAVAILABLE')
        rename.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];rename.restype=ctypes.c_int
        if rename(-100,os.fsencode(source),-100,os.fsencode(destination),1)!=0:
            code=ctypes.get_errno();raise OSError(code,os.strerror(code))
    else:raise OSError('LIBRARY_ATOMIC_MOVE_UNAVAILABLE')
