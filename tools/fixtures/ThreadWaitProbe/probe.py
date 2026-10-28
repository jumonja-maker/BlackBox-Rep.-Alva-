"""Owned Win32 Sleep/event/mutex fixture. No foreign process manipulation."""
from __future__ import annotations
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import sys
import threading
import time


def main():
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('WINDOWS_DISPOSABLE_CI_REQUIRED')
    output = Path(sys.argv[1])
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentThreadId.restype = wintypes.DWORD
    kernel.QueryPerformanceCounter.argtypes = [ctypes.POINTER(ctypes.c_longlong)]
    kernel.QueryPerformanceCounter.restype = wintypes.BOOL
    kernel.QueryPerformanceFrequency.argtypes = [ctypes.POINTER(ctypes.c_longlong)]
    kernel.QueryPerformanceFrequency.restype = wintypes.BOOL
    kernel.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateEventW.restype = wintypes.HANDLE
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateMutexW.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    for name in ['SetEvent', 'ReleaseMutex', 'CloseHandle']:
        getattr(kernel, name).argtypes = [wintypes.HANDLE]
        getattr(kernel, name).restype = wintypes.BOOL
    kernel.Sleep.argtypes = [wintypes.DWORD]
    kernel.Sleep.restype = None
    def qpc():
        value = ctypes.c_longlong()
        if not kernel.QueryPerformanceCounter(ctypes.byref(value)):
            raise ctypes.WinError(ctypes.get_last_error())
        return value.value
    frequency = ctypes.c_longlong()
    if not kernel.QueryPerformanceFrequency(ctypes.byref(frequency)):
        raise ctypes.WinError(ctypes.get_last_error())
    event = kernel.CreateEventW(None, False, False, None)
    mutex = kernel.CreateMutexW(None, True, None)
    if not event or not mutex:
        raise ctypes.WinError(ctypes.get_last_error())
    records = []; failures = []
    def run(role, operation):
        tid = kernel.GetCurrentThreadId()
        try:
            begin = qpc(); result = operation(); end = qpc()
            records.append(dict(role=role, tid=tid, begin_qpc=begin, end_qpc=end, result=result))
        except BaseException as exc:
            failures.append(type(exc).__name__+': '+str(exc))
    def event_wait():
        result = kernel.WaitForSingleObject(event, 3000)
        if result != 0:
            raise RuntimeError('EVENT_WAIT_DID_NOT_SIGNAL_'+str(result))
        return 'WAIT_OBJECT_0'
    def mutex_wait():
        result = kernel.WaitForSingleObject(mutex, 3000)
        if result != 0:
            raise RuntimeError('MUTEX_WAIT_DID_NOT_ACQUIRE_'+str(result))
        if not kernel.ReleaseMutex(mutex):
            raise ctypes.WinError(ctypes.get_last_error())
        return 'WAIT_OBJECT_0'
    threads = [threading.Thread(target=run, args=('Sleep', lambda: kernel.Sleep(220))),
               threading.Thread(target=run, args=('EventWait', event_wait)),
               threading.Thread(target=run, args=('MutexWait', mutex_wait))]
    released = False
    try:
        for thread in threads:
            thread.start()
        kernel.Sleep(350)
        if not kernel.SetEvent(event):
            raise ctypes.WinError(ctypes.get_last_error())
        kernel.Sleep(100)
        if not kernel.ReleaseMutex(mutex):
            raise ctypes.WinError(ctypes.get_last_error())
        released = True
        for thread in threads:
            thread.join(timeout=5)
            if thread.is_alive():
                raise RuntimeError('FIXTURE_THREAD_DID_NOT_FINISH')
        if failures or len(records) != 3:
            raise RuntimeError('FIXTURE_FAILURES:'+repr(failures))
        payload = dict(schema='blackbox.wait-fixture/1', status='PASS', pid=os.getpid(),
                       qpc_frequency_hz=frequency.value, observations=records)
        with output.open('x', encoding='utf-8') as stream:
            json.dump(payload, stream, indent=2)
    finally:
        if not released:
            kernel.ReleaseMutex(mutex)
        kernel.SetEvent(event)
        for thread in threads:
            if thread.ident is not None:
                thread.join(timeout=4)
        kernel.CloseHandle(event); kernel.CloseHandle(mutex)


if __name__ == '__main__':main()
