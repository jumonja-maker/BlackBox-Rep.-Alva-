"""Bounded optional-process owner with hard deadlines and owned-tree cleanup."""
from __future__ import annotations
from collections import deque
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from uuid import uuid4

from .operation_worker import OPERATIONS, MAX_RESULT_BYTES


class OwnedProcessCleanupUnconfirmed(OSError):
    """The original owner remains available for explicit cleanup retry."""
    cleanup_required = True
    def __init__(self, owner, reason):
        self.owner = owner
        super().__init__('OPTIONAL_CLEANUP_UNCONFIRMED: ' + reason)


class OwnedProcess:
    """A kill boundary confined to our operation and its own descendants."""
    _owners = {}
    _owners_lock = threading.RLock()
    _spawn_lock = threading.RLock()
    MAX_OWNERS = 32

    def __init__(self, args, *, stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=None,
                 detach_console=False):
        self.job = None; self.process = None; self._closed = False
        self._platform = os.name; self._job_assigned = False
        self._boundary_released = False; self._thread_handles = []
        self._cleanup_resources = []; self.cleanup_required = False
        self._close_lock = threading.RLock()
        self.cleanup_evidence = {'status': 'NOT_COLLECTED'}
        self._owner_key = uuid4().hex
        # Reserve before creating a process. An uncertain owner is never evicted
        # to admit a new one, including after a constructor failure.
        with self._owners_lock:
            if len(self._owners) >= self.MAX_OWNERS:
                raise OSError('OPTIONAL_RETAINED_OWNER_BUDGET')
            self._owners[self._owner_key] = self
        self.windows_creation_flags = 0
        options = dict(stdin=stdin,stdout=stdout,stderr=stderr,env=env)
        try:
            self._launch(args, options, detach_console)
        except BaseException as original:
            try:
                self.close(kill=True)
            except OwnedProcessCleanupUnconfirmed as cleanup:
                cleanup.add_note('Original startup failure: ' + type(original).__name__)
                raise cleanup from original
            raise

    def _launch(self, args, options, detach_console):
        if self._platform == 'nt':
            import ctypes as C
            from ctypes import wintypes as W
            self.kernel = C.WinDLL('kernel32', use_last_error=True)
            k = self.kernel
            k.CreateJobObjectW.argtypes=[C.c_void_p, W.LPCWSTR]; k.CreateJobObjectW.restype=W.HANDLE
            k.AssignProcessToJobObject.argtypes=[W.HANDLE,W.HANDLE]; k.AssignProcessToJobObject.restype=W.BOOL
            k.TerminateJobObject.argtypes=[W.HANDLE,W.UINT]; k.TerminateJobObject.restype=W.BOOL
            k.CloseHandle.argtypes=[W.HANDLE]; k.CloseHandle.restype=W.BOOL
            k.GetCurrentProcess.argtypes=[]; k.GetCurrentProcess.restype=W.HANDLE
            k.DuplicateHandle.argtypes=[W.HANDLE,W.HANDLE,W.HANDLE,C.POINTER(W.HANDLE),W.DWORD,W.BOOL,W.DWORD]
            k.DuplicateHandle.restype=W.BOOL
            k.GetProcessIdOfThread.argtypes=[W.HANDLE]; k.GetProcessIdOfThread.restype=W.DWORD
            k.ResumeThread.argtypes=[W.HANDLE]; k.ResumeThread.restype=W.DWORD
            k.QueryInformationJobObject.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD,C.c_void_p]
            k.QueryInformationJobObject.restype=W.BOOL
            class Accounting(C.Structure):
                _fields_=[('user',C.c_int64),('kernel',C.c_int64),('period_user',C.c_int64),
                    ('period_kernel',C.c_int64),('faults',W.DWORD),('total',W.DWORD),
                    ('active',W.DWORD),('terminated',W.DWORD)]
            self._accounting_type = Accounting
            class Basic(C.Structure):
                _fields_=[('process_time',C.c_int64),('job_time',C.c_int64),('flags',W.DWORD),
                    ('min_working',C.c_size_t),('max_working',C.c_size_t),('active',W.DWORD),
                    ('affinity',C.c_size_t),('priority',W.DWORD),('scheduling',W.DWORD)]
            class Io(C.Structure):_fields_=[(n,C.c_uint64) for n in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]
            class Limits(C.Structure):
                _fields_=[('basic',Basic),('io',Io),('process_memory',C.c_size_t),
                    ('job_memory',C.c_size_t),('peak_process',C.c_size_t),('peak_job',C.c_size_t)]
            k.SetInformationJobObject.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD];k.SetInformationJobObject.restype=W.BOOL
            self.job = k.CreateJobObjectW(None, None)
            if not self.job: raise OSError(C.get_last_error(), 'OPTIONAL_JOB_CREATION_FAILED')
            limits=Limits();limits.basic.flags=0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not k.SetInformationJobObject(self.job,9,C.byref(limits),C.sizeof(limits)):
                raise OSError(C.get_last_error(),'OPTIONAL_JOB_LIMIT_FAILED')
            # Offline decoder helpers need only their redirected file handles.
            # Detaching avoids the console startup path; it still uses the same
            # token and owned job. Other optional operations retain their mode.
            self.windows_creation_flags = (getattr(subprocess, 'DETACHED_PROCESS', 0x8)
                                           if detach_console else
                                           getattr(subprocess, 'CREATE_NO_WINDOW', 0)) | 0x4
            # No child code can spawn an escaping descendant before job binding.
            options['creationflags'] = self.windows_creation_flags
        else: options['start_new_session'] = True
        if self._platform == 'nt':
            self._popen_suspended(args, options)
        else:
            self.process = subprocess.Popen(args, **options)
        if self.job:
            self._resume_initial_thread()

    def _popen_suspended(self, args, options):
        """Retain the exact CreateProcess thread capability before Popen closes it.

        CPython's Windows Popen does not expose its primary thread handle. A
        restricted token can use the original creation capability while being
        unable to reopen the same thread by TID. Duplicate that existing grant,
        without changing tokens, DACLs or requested access. The private CPython
        hook is active only during this launching thread's Popen call; foreign
        threads are delegated unchanged and OwnedProcess launches serialize.
        """
        import ctypes as C
        from ctypes import wintypes as W
        api = getattr(subprocess, '_winapi', None)
        if api is None or not callable(getattr(api, 'CreateProcess', None)):
            raise OSError('OPTIONAL_CPYTHON_CREATE_PROCESS_HOOK_UNAVAILABLE')
        command_line = (args if isinstance(args, str) else
                        subprocess.list2cmdline([args] if isinstance(args, os.PathLike) else args))
        creation_flags = options.get('creationflags', 0)
        with self._spawn_lock:
            launching_thread = threading.get_ident()
            original = api.CreateProcess
            active = True
            creating = False
            self._initial_thread_capture = None
            def capture(*arguments, **keywords):
                nonlocal creating
                # Match the one requested launch as well as its thread. An
                # unrelated Popen from a same-thread audit hook also delegates.
                matches = (active and threading.get_ident() == launching_thread and len(arguments) >= 6 and
                           arguments[1] == command_line and arguments[5] == creation_flags)
                if not matches or creating:
                    return original(*arguments, **keywords)
                creating = True
                try:
                    result = original(*arguments, **keywords)
                finally:
                    creating = False
                if active:
                    if self._initial_thread_capture is not None:
                        self._initial_thread_capture['error'] = OSError('OPTIONAL_MULTIPLE_INITIAL_THREAD_CREATIONS')
                        return result
                    process_handle, thread_handle, pid, tid = result
                    entry = {'process_handle': int(process_handle), 'pid': pid, 'tid': tid,
                             'handle': None, 'error': None}
                    self._initial_thread_capture = entry
                    duplicate = W.HANDLE()
                    try:
                        # Bind while hp is still the exact creation capability,
                        # including if Popen later fails before returning its
                        # process object. The retained job then owns cleanup.
                        if not self.kernel.AssignProcessToJobObject(self.job, process_handle):
                            raise OSError('OPTIONAL_JOB_ASSIGNMENT_FAILED')
                        self._job_assigned = True
                        current = self.kernel.GetCurrentProcess()
                        if not self.kernel.DuplicateHandle(current, thread_handle, current,
                                C.byref(duplicate), 0, False, 0x2):  # DUPLICATE_SAME_ACCESS
                            raise OSError(C.get_last_error(), 'OPTIONAL_INITIAL_THREAD_DUPLICATE_FAILED')
                        if not duplicate.value:
                            raise OSError('OPTIONAL_INITIAL_THREAD_DUPLICATE_MISSING')
                        entry['handle'] = duplicate.value
                        self._thread_handles.append(duplicate.value)
                    except BaseException as error:
                        # Return the unchanged tuple first, so Popen acquires hp
                        # and closes its original ht even when duplication fails.
                        # The caller then kills only that suspended owned child.
                        entry['error'] = error
                return result
            try:
                api.CreateProcess = capture
                self.process = subprocess.Popen(args, **options)
            finally:
                active = False
                if api.CreateProcess is capture:
                    api.CreateProcess = original

    def _resume_initial_thread(self):
        entry = self._initial_thread_capture
        if (entry is None or entry['pid'] != self.process.pid or
                entry['process_handle'] != int(self.process._handle)):
            raise OSError('OPTIONAL_INITIAL_THREAD_CREATION_IDENTITY_UNCONFIRMED')
        if entry['error'] is not None:
            raise entry['error']
        handle = entry['handle']
        if (not self._job_assigned or handle is None or
                self.kernel.GetProcessIdOfThread(handle) != self.process.pid or
                self.process.poll() is not None):
            raise OSError('OPTIONAL_INITIAL_THREAD_IDENTITY_CHANGED')
        if self.kernel.ResumeThread(handle) != 1:
            raise OSError('OPTIONAL_INITIAL_THREAD_RESUME_UNCONFIRMED')
        if not self.kernel.CloseHandle(handle):
            raise OSError('OPTIONAL_INITIAL_THREAD_HANDLE_CLOSE_FAILED')
        self._thread_handles.remove(handle)
        self._initial_thread_capture = None

    def _job_empty(self):
        import ctypes as C
        info = self._accounting_type()
        if not self.kernel.QueryInformationJobObject(self.job, 1, C.byref(info), C.sizeof(info), None):
            raise OSError('OPTIONAL_JOB_ACCOUNTING_UNCONFIRMED')
        return info.active == 0

    def retain_cleanup_resource(self, resource):
        """Keep a private staging object alive while its child can still use it."""
        with self._close_lock:
            if self._closed:
                resource.cleanup()
            elif not any(value is resource for value in self._cleanup_resources):
                self._cleanup_resources.append(resource)

    @classmethod
    def pending_cleanup(cls):
        with cls._owners_lock:
            return [{'owner_id': key, 'pid': owner.process.pid if owner.process else None,
                     'cleanup': dict(owner.cleanup_evidence)}
                    for key, owner in cls._owners.items() if owner.cleanup_required]

    @classmethod
    def retry_pending_cleanup(cls, *, check=None):
        """Explicit retry of cleanup only; never starts or repeats an operation."""
        with cls._owners_lock:
            pending = [owner for owner in cls._owners.values() if owner.cleanup_required]
        results = []
        for owner in pending:
            if check is not None:
                check()
            try:
                owner.close(kill=True)
            except OwnedProcessCleanupUnconfirmed:
                pass
            results.append(dict(owner.cleanup_evidence))
            if check is not None:
                check()
        return results

    def close(self, *, kill=False):
        with self._close_lock:
            self._close_locked(kill=kill)

    def _close_locked(self, *, kill):
        if self._closed:return
        deadline = time.monotonic() + 2
        try:
            self._close_boundary(deadline, kill)
            for resource in list(self._cleanup_resources):
                resource.cleanup()
                self._cleanup_resources.remove(resource)
        except Exception as error:
            self.cleanup_required = True
            self.cleanup_evidence = {'status': 'RECOVERY_UNCONFIRMED', 'owner_retained': True,
                                     'reason': str(error)[:240]}
            raise OwnedProcessCleanupUnconfirmed(self, str(error)[:240]) from error
        self._closed = True; self.cleanup_required = False
        self.cleanup_evidence = {'status': 'COMPLETED', 'owner_retained': False,
            'scope': ('WINDOWS_JOB_EMPTY_AND_LEADER_EXIT_AND_HANDLE_CLOSED' if self._platform == 'nt'
                      else 'OWNED_GROUP_SIGNAL_ACCEPTED_OR_ABSENT_AND_LEADER_EXIT')}
        with self._owners_lock:
            self._owners.pop(self._owner_key, None)

    def _close_boundary(self, deadline, kill):
        if self._boundary_released:
            return
        if self._platform != 'nt' and self.process is not None:
            # Popen owns a fresh session/process group. A normal exit of its
            # leader does not mean its descendants have exited: finish the
            # owned group before relinquishing this cleanup capability.
            try: os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        elif self._platform == 'nt':
            if self.job and self._job_assigned:
                # A false termination result is acceptable only if the SAME job
                # is independently proved empty below, never merely on leader exit.
                self._termination_accepted = bool(self.kernel.TerminateJobObject(self.job, 1))
            elif self.process is None and getattr(self, '_initial_thread_capture', None) is not None:
                # A failed Popen did not transfer hp, and the child was not
                # bound. Never certify cleanup using an empty unrelated job or
                # retry an unowned numeric process handle.
                raise OSError('OPTIONAL_CREATED_PROCESS_OWNERSHIP_UNCONFIRMED')
            elif self.process is not None and self.process.poll() is None:
                self.process.kill()  # Constructor failed before job assignment.
        if self.process is not None:
            self.process.wait(timeout=max(0, deadline - time.monotonic()))
            if self.process.poll() is None:
                raise OSError('OPTIONAL_PROCESS_EXIT_UNCONFIRMED')
        if self.job:
            while not self._job_empty():
                if time.monotonic() >= deadline:
                    raise OSError('OPTIONAL_JOB_MEMBERS_REMAIN' +
                                  (': TERMINATE_JOB_FAILED' if not getattr(self, '_termination_accepted', True) else ''))
                time.sleep(min(.01, max(0, deadline - time.monotonic())))
            if not self.kernel.CloseHandle(self.job):
                raise OSError('OPTIONAL_JOB_HANDLE_CLOSE_UNCONFIRMED')
            self.job = None
        for handle in list(self._thread_handles):
            if not self.kernel.CloseHandle(handle):
                raise OSError('OPTIONAL_THREAD_HANDLE_CLOSE_UNCONFIRMED')
            self._thread_handles.remove(handle)
        self._boundary_released = True


class OptionalJobs:
    def __init__(self, *, limit=8, clock=time.monotonic, launcher=OwnedProcess):
        self.queue = deque(); self.current = None; self.limit = limit
        self.clock = clock; self.launcher = launcher
        self.completed = 0; self.failed = 0; self.timed_out = 0; self.cancelled = 0
        self.last_progress = clock()

    @property
    def busy(self): return bool(self.current or self.queue)

    def submit(self, command, packet, *, seconds=75):
        if self.current and self.current.get('cleanup_required'):
            raise ValueError('OPTIONAL_CLEANUP_REQUIRED')
        if command.get('op') not in OPERATIONS: raise ValueError('UNKNOWN_OPTIONAL_OPERATION')
        if len(self.queue)+(1 if self.current else 0) >= self.limit: raise ValueError('OPTIONAL_QUEUE_FULL')
        if not 0 < seconds <= 600: raise ValueError('INVALID_OPTIONAL_DEADLINE')
        self.queue.append({'command': command, 'packet': packet, 'seconds': seconds, 'queued_at':self.clock()})

    def _launch(self):
        item = self.queue.popleft(); self._launch_command=item['command']; temp = tempfile.TemporaryDirectory(prefix='blackbox-operation-')
        root = Path(temp.name); spec=root/'request.json'; output=root/'result.json'
        owner = None
        try:
            spec.write_text(json.dumps(item['packet'], allow_nan=False), encoding='utf-8')
            if getattr(sys, 'frozen', False): args=[sys.executable, '--research-operation', str(spec), str(output)]
            else: args=[sys.executable, '-m', 'blackbox_core.operation_worker', str(spec), str(output)]
            owner=self.launcher(args)
            (root/'ready').touch(exist_ok=False)
        except BaseException as error:
            # The ready-marker write can fail after Popen succeeds. Keep the
            # owner until its bounded cleanup has run; a temp failure must not
            # replace the diagnostic for the original startup failure.
            owner = owner or getattr(error, 'owner', None)
            cleanup_error = None
            try:
                if isinstance(error, OwnedProcessCleanupUnconfirmed):
                    raise error
                if owner is not None:
                    owner.close(kill=True)
                temp.cleanup()
            except Exception as failed_cleanup:
                cleanup_error = failed_cleanup
                error.add_note('Owned operation cleanup failed: '+str(failed_cleanup)[:200])
            if cleanup_error is not None:
                item.update(temp=temp, output=output, owner=owner,
                            deadline=self.clock(), started_at=self.clock(), cleanup_required=True)
                self.current = item
            raise
        item.update(temp=temp, output=output, owner=owner, deadline=self.clock()+item['seconds'], started_at=self.clock())
        self.current=item

    def poll(self):
        results=[]
        if not self.current and self.queue:
            try: self._launch()
            except Exception as exc:
                self.failed+=1
                # _launch consumed exactly one item; retain its command for acknowledgement.
                return [{'command': getattr(self, '_launch_command', {}), 'result':None,
                         'error':'OPTIONAL_START_FAILED: '+str(exc)[:300],
                         'cleanup': {'status': 'RECOVERY_UNCONFIRMED' if self.current else 'COMPLETED',
                                     'owner_retained': self.current is not None}}]
        item=self.current
        if not item: return results
        if item.get('cleanup_required'):
            return results  # Explicit Stop/cleanup retry only; never repeat the operation.
        proc=item['owner'].process
        try:
            rc=proc.poll()
        except (OSError, subprocess.SubprocessError) as exc:
            item['cleanup_required'] = True
            self.failed += 1
            return [{'command':item['command'], 'result':None,
                     'error':'OPTIONAL_PROCESS_EXIT_UNCONFIRMED: '+str(exc)[:240],
                     'cleanup':{'status':'RECOVERY_UNCONFIRMED','owner_retained':True}}]
        expired=self.clock()>=item['deadline']
        if rc is None and not expired: return results
        result={'result':None, 'error':None}
        try:
            if expired and rc is None:
                self.timed_out+=1; result['error']='OPTIONAL_OPERATION_TIMEOUT'
            elif rc != 0: result['error']='OPTIONAL_OPERATION_EXIT_'+str(rc)
            elif item['output'].is_symlink() or not item['output'].is_file() or item['output'].stat().st_size>MAX_RESULT_BYTES:
                result['error']='OPTIONAL_RESULT_UNAVAILABLE'
            else:
                result=json.loads(item['output'].read_text(encoding='utf-8'))
                if type(result) is not dict or 'error' not in result: raise ValueError('INVALID_OPTIONAL_RESULT')
            result.update(command=item['command'], queue_ms=(item['started_at']-item['queued_at'])*1000,
                          operation_ms=(self.clock()-item['started_at'])*1000)
        except (OSError, ValueError, TypeError) as exc:
            result={'command':item['command'], 'result':None, 'error':'INVALID_OPTIONAL_RESULT: '+str(exc)[:300]}
        try:
            self._cleanup_item(item, kill=expired and rc is None)
        except Exception as exc:
            item['cleanup_required'] = True
            self.failed += 1
            return [{'command': item['command'], 'result': None,
                     'error': 'OPTIONAL_CLEANUP_UNCONFIRMED: '+str(exc)[:240],
                     'operation_error': result.get('error'),
                     'cleanup': {'status': 'RECOVERY_UNCONFIRMED', 'owner_retained': True}}]
        self.current = None; self.last_progress = self.clock()
        result['cleanup'] = {'status': 'COMPLETED', 'owner_retained': False}
        if result.get('error'): self.failed += 1
        else: self.completed += 1
        return [result]

    @staticmethod
    def _cleanup_item(item, *, kill):
        if item['owner'] is not None:
            item['owner'].close(kill=kill)
        item['temp'].cleanup()

    def cancel(self):
        pending=list(self.queue); self.queue.clear()
        results=[]
        if self.current:
            item=self.current
            try:
                self._cleanup_item(item, kill=True)
            except Exception as exc:
                item['cleanup_required'] = True
                results.append({'command':item['command'], 'result':None,
                    'error':'OPTIONAL_CLEANUP_UNCONFIRMED: '+str(exc)[:240],
                    'cleanup':{'status':'RECOVERY_UNCONFIRMED','owner_retained':True}})
            else:
                self.current=None; pending.insert(0,item)
        self.cancelled+=len(pending)
        return results + [{'command':i['command'], 'result':None,
            'error':'OPTIONAL_OPERATION_CANCELLED_RESULT_UNCONFIRMED',
            'cleanup':{'status':'COMPLETED','owner_retained':False}} for i in pending]

    def health(self):
        return {'status':'RECOVERY_UNCONFIRMED' if self.current and self.current.get('cleanup_required') else
                        'RUNNING' if self.current else 'QUEUED' if self.queue else 'IDLE',
            'cleanup_required':bool(self.current and self.current.get('cleanup_required')),
            'queued':len(self.queue), 'limit':self.limit, 'completed':self.completed, 'failed':self.failed,
            'timed_out':self.timed_out, 'cancelled':self.cancelled,
            'current_op':self.current['command'].get('op') if self.current else None,
            'current_age_ms':(self.clock()-self.current['started_at'])*1000 if self.current else None}
