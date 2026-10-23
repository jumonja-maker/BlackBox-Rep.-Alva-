"""Explicit QA-owned real processes. Never used by ordinary observation.

CPU uses two native hashlib workloads (GIL released). UI has actual native Qt
windows with freeze/recovery buttons. Waitchain uses two real Win32 mutexes.
All modes self-exit at TTL or the fixture-local stop marker; no other target
is ever signalled or modified. This is a test stand, not synthetic telemetry.
"""
from __future__ import annotations
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
from threading import Barrier,Event,Thread,get_native_id
import time


def run_fixture(mode,directory,*,ttl_s=75):
    directory=Path(directory)
    directory.mkdir(parents=True,exist_ok=True)
    stop=Event()
    tids=[]
    threads=[]
    deadline=time.monotonic()+ttl_s
    def cpu():
        tids.append(get_native_id())
        while not stop.is_set():
            hashlib.pbkdf2_hmac("sha256",b"BLACKBOX-QA-FIXTURE",b"fixed-public-test-salt",100000)
    if mode in ("cpu","ui"):
        for _ in range(2):
            t=Thread(target=cpu,daemon=True);t.start();threads.append(t)
    elif mode=="waitchain":
        if os.name!="nt":
            raise RuntimeError("WAIT_CHAIN_FIXTURE_REQUIRES_WINDOWS")
        kernel=C.WinDLL("kernel32",use_last_error=True)
        kernel.CreateMutexW.argtypes=[C.c_void_p,C.c_int32,C.c_wchar_p]
        kernel.CreateMutexW.restype=C.c_void_p
        kernel.WaitForSingleObject.argtypes=[C.c_void_p,C.c_uint32]
        kernel.WaitForSingleObject.restype=C.c_uint32
        a,b=kernel.CreateMutexW(None,False,None),kernel.CreateMutexW(None,False,None)
        if not a or not b:
            raise RuntimeError("FIXTURE_MUTEX_CREATE_FAILED")
        barrier=Barrier(2)
        def waiting(own,other):
            tids.append(get_native_id())
            if kernel.WaitForSingleObject(own,5000)!=0:
                return
            barrier.wait(timeout=5)
            kernel.WaitForSingleObject(other,0xffffffff)
        for own,other in ((a,b),(b,a)):
            t=Thread(target=waiting,args=(own,other),daemon=True);t.start();threads.append(t)
        # These waiters intentionally survive to fixture-process exit. Closing
        # their handles while waits are pending would be undefined Windows API
        # behavior. The OS releases this fixture's handles on its own exit.
    def ready(hwnd=None):
        sensor_pid=os.getpid()
        pid_source="OS_GETPID"
        if os.name=="posix" and Path("/proc/self/stat").is_file():
            # psutil reads the /proc namespace, which can differ from the
            # child-control namespace in an isolated executor. Keep both real
            # OS identities explicit; never substitute CPU measurements.
            sensor_pid=int(Path("/proc/self/stat").read_text().split(" ",1)[0])
            pid_source="PROC_SELF_STAT_PID_NAMESPACE"
        data={"fixture":"BB-DI-001/REAL_OS_WORKLOAD","mode":mode,"pid":os.getpid(),
              "sensor_pid":sensor_pid,"sensor_pid_source":pid_source,
              "thread_ids":tids,"hwnd":hwnd,"ttl_seconds":ttl_s}
        with (directory/"ready.json").open("x",encoding="utf-8") as f:
            json.dump(data,f)
    def should_stop():
        return time.monotonic()>=deadline or (directory/"stop.request").exists()
    if mode=="ui":
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication,QWidget,QVBoxLayout,QPushButton,QLabel
        app=QApplication.instance() or QApplication([])
        window=QWidget();window.setWindowTitle("BLACK.BOX QA fixture (public test text)")
        layout=QVBoxLayout(window)
        layout.addWidget(QLabel("FIX-02 · real UI block and recovery"))
        for seconds in (2,8):
            button=QPushButton(f"Freeze {seconds}s")
            button.clicked.connect(lambda checked=False,s=seconds:time.sleep(s))
            layout.addWidget(button)
        layout.addWidget(QPushButton("Recovered"))
        window.show()
        QTimer.singleShot(300,lambda:ready(int(window.winId())))
        QTimer.singleShot(1500,lambda:time.sleep(5))
        timer=QTimer();timer.timeout.connect(lambda:app.quit() if should_stop() else None);timer.start(100)
        app.exec()
    else:
        time.sleep(.1)
        ready()
        while not should_stop():
            time.sleep(.05)
    stop.set()
    if mode!="waitchain":
        for thread in threads:
            thread.join(timeout=1)
    return 0
