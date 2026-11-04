"""Ownership failures remain inspectable; executed exclusively in hosted CI."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from blackbox_core.optional_jobs import OwnedProcess, OwnedProcessCleanupUnconfirmed, OptionalJobs


class OwnedCleanupContracts(unittest.TestCase):
    def owner(self):
        value = OwnedProcess.__new__(OwnedProcess)
        value.job = 37
        value.process = Mock(pid=123, returncode=0)
        value.process.poll.return_value = 0
        value.process.wait.return_value = 0
        value.kernel = Mock()
        value.kernel.TerminateJobObject.return_value = 1
        value.kernel.CloseHandle.return_value = 1
        value._job_empty = Mock(return_value=True)
        value._platform = 'nt'; value._job_assigned = True
        value._boundary_released = False; value._thread_handles = []
        value._cleanup_resources = []; value._close_lock = threading.RLock()
        value._owner_key = 'test-owned-cleanup'
        value._closed = False; value.cleanup_required = False
        value.cleanup_evidence = {'status': 'NOT_COLLECTED'}
        return value

    def test_failed_termination_is_not_success_when_owned_job_members_remain(self):
        owner = self.owner()
        owner.kernel.TerminateJobObject.return_value = 0
        owner._job_empty.return_value = False
        with patch('blackbox_core.optional_jobs.time.monotonic', side_effect=[0, 0, 3]):
            with self.assertRaises(OwnedProcessCleanupUnconfirmed) as raised:
                owner.close(kill=True)
        self.assertIs(raised.exception.owner, owner)
        self.assertFalse(owner._closed)
        self.assertTrue(owner.cleanup_required)
        self.assertEqual(owner.job, 37)
        owner.kernel.CloseHandle.assert_not_called()

    def test_failed_termination_with_same_empty_job_and_dead_leader_is_confirmed(self):
        owner = self.owner(); owner.kernel.TerminateJobObject.return_value = 0
        owner.close(kill=True)
        self.assertTrue(owner._closed)
        self.assertIsNone(owner.job)
        self.assertEqual(owner.cleanup_evidence['status'], 'COMPLETED')

    def test_job_query_failure_retains_owner_and_never_closes_capability(self):
        owner = self.owner(); owner._job_empty.side_effect = OSError('query failed')
        with self.assertRaises(OwnedProcessCleanupUnconfirmed): owner.close()
        self.assertFalse(owner._closed)
        owner.kernel.CloseHandle.assert_not_called()

    def test_wait_timeout_is_not_swallowed_and_staging_survives_until_retry(self):
        owner = self.owner()
        owner.process.wait.side_effect = subprocess.TimeoutExpired('owned', 2)
        stage = Mock()
        with self.assertRaises(OwnedProcessCleanupUnconfirmed): owner.close(kill=True)
        owner.retain_cleanup_resource(stage)
        stage.cleanup.assert_not_called()
        owner.process.wait.side_effect = None
        owner.close(kill=True)
        stage.cleanup.assert_called_once_with()
        self.assertTrue(owner._closed)

    def test_failed_handle_close_remains_unconfirmed_until_exact_owner_retry(self):
        owner = self.owner(); owner.kernel.CloseHandle.return_value = 0
        with self.assertRaises(OwnedProcessCleanupUnconfirmed): owner.close()
        self.assertEqual(owner.job, 37)
        owner.kernel.CloseHandle.return_value = 1
        owner.close()
        self.assertTrue(owner._closed)
        count = owner.kernel.TerminateJobObject.call_count
        owner.close(kill=True)
        self.assertEqual(owner.kernel.TerminateJobObject.call_count, count)

    def test_registry_budget_refuses_before_launch_and_never_evicts_an_owner(self):
        with patch.object(OwnedProcess, 'MAX_OWNERS', 0), \
             patch('blackbox_core.optional_jobs.subprocess.Popen') as launch:
            with self.assertRaisesRegex(OSError, 'OWNER_BUDGET'):
                OwnedProcess(['not-launched'])
        launch.assert_not_called()

    def test_cancelled_cleanup_scan_does_not_start_another_owner_attempt(self):
        first, second = self.owner(), self.owner()
        first.cleanup_required = second.cleanup_required = True
        check = Mock(side_effect=[None, InterruptedError('cancelled')])
        with patch.object(OwnedProcess, '_owners', {'first':first,'second':second}):
            with self.assertRaises(InterruptedError):
                OwnedProcess.retry_pending_cleanup(check=check)
        self.assertTrue(first._closed)
        second.kernel.TerminateJobObject.assert_not_called()
        self.assertEqual(second.job, 37)

    def test_optional_result_is_not_completed_and_owner_or_temp_not_discarded(self):
        jobs = OptionalJobs(); owner = self.owner()
        owner._job_empty.side_effect = OSError('query failed')
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / 'result.json'
            output.write_text('{"result": {"value": 1}, "error": null}')
            stage = Mock()
            item = {'owner': owner, 'temp': stage, 'output': output,
                    'command': {'op': 'inspect', 'id': 'original'},
                    'deadline': float('inf'), 'started_at': jobs.clock(), 'queued_at': jobs.clock()}
            jobs.current = item
            result = jobs.poll()[0]
            self.assertIn('CLEANUP_UNCONFIRMED', result['error'])
            self.assertIs(jobs.current, item)
            self.assertEqual(jobs.completed, 0)
            stage.cleanup.assert_not_called()
            self.assertEqual(jobs.poll(), [])
            self.assertEqual(jobs.health()['status'], 'RECOVERY_UNCONFIRMED')
            with self.assertRaisesRegex(ValueError, 'CLEANUP_REQUIRED'):
                jobs.submit({'op': 'inspect'}, {'op': 'inspect'})
            owner._job_empty.side_effect = None
            owner._job_empty.return_value = True
            jobs.cancel()
            self.assertIsNone(jobs.current)
            stage.cleanup.assert_called_once_with()

    def test_cancel_failure_retains_current_and_reports_cleanup_separately(self):
        jobs = OptionalJobs(); owner = self.owner()
        owner.kernel.CloseHandle.return_value = 0
        stage = Mock()
        jobs.current = {'owner': owner, 'temp': stage, 'command': {'op': 'inspect'}, 'started_at': jobs.clock()}
        result = jobs.cancel()[0]
        self.assertEqual(result['cleanup']['status'], 'RECOVERY_UNCONFIRMED')
        self.assertIs(jobs.current['owner'], owner)
        stage.cleanup.assert_not_called()
        owner.kernel.CloseHandle.return_value = 1
        jobs.cancel()
        self.assertFalse(jobs.busy)

    def test_unconfirmed_old_resource_blocks_target_change_and_new_recording(self):
        from blackbox_core.research_worker import ResearchSession
        session = ResearchSession.__new__(ResearchSession)
        session.jobs = Mock()
        session.jobs.health.return_value = {'cleanup_required': True}
        for operation in ('attach', 'start'):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(ValueError, 'CLEANUP_UNCONFIRMED'):
                    session.command({'op':operation, 'args':{}})


class InitialThreadCapabilityContracts(unittest.TestCase):
    """Private CPython interception contracts; native proof is separate below."""
    def owner(self):
        import ctypes as C
        from ctypes import wintypes as W
        owner = OwnedProcess.__new__(OwnedProcess)
        owner._thread_handles = []
        owner._job_assigned = True
        owner.job = 37
        owner.process = None
        owner.kernel = Mock()
        owner.kernel.GetCurrentProcess.return_value = 900
        owner.kernel.GetProcessIdOfThread.return_value = 42
        owner.kernel.ResumeThread.return_value = 1
        owner.kernel.CloseHandle.return_value = 1
        owner.kernel.AssignProcessToJobObject.return_value = 1
        def duplicate(source, handle, target, result, access, inherit, flags):
            self.assertEqual((source, target, access, inherit, flags), (900, 900, 0, False, 0x2))
            C.cast(result, C.POINTER(W.HANDLE)).contents.value = 101
            return 1
        owner.kernel.DuplicateHandle.side_effect = duplicate
        return owner

    def process(self):
        process = Mock(pid=42, _handle=70)
        process.poll.return_value = None
        return process

    def create(self, api, label='owned', flags=0):
        return api.CreateProcess(None, label, None, None, False, flags, None, None, None)

    def test_exact_creation_capability_is_duplicated_then_resumed_only_after_binding(self):
        owner, process = self.owner(), self.process()
        original = Mock(return_value=(70, 80, 42, 43))
        api = SimpleNamespace(CreateProcess=original)
        def popen(*args, **options):
            self.assertEqual(self.create(api, flags=0xC), (70, 80, 42, 43))
            owner.kernel.ResumeThread.assert_not_called()
            return process
        with patch('blackbox_core.optional_jobs.subprocess._winapi', api, create=True), \
                patch('blackbox_core.optional_jobs.subprocess.Popen', side_effect=popen):
            owner._popen_suspended(['owned'], {'creationflags': 0xC})
        self.assertIs(api.CreateProcess, original)
        self.assertEqual(owner._thread_handles, [101])
        owner.kernel.AssignProcessToJobObject.assert_called_once_with(37, 70)
        owner._resume_initial_thread()
        owner.kernel.ResumeThread.assert_called_once_with(101)
        owner.kernel.CloseHandle.assert_called_once_with(101)
        self.assertEqual(owner._thread_handles, [])
        owner.kernel.OpenThread.assert_not_called()

    def test_simultaneous_foreign_create_process_is_delegated_without_capture(self):
        owner, process = self.owner(), self.process()
        calls = []
        def original(*arguments):
            label = arguments[1]
            calls.append(label)
            return (170, 180, 142, 143) if label == 'foreign' else (70, 80, 42, 43)
        api = SimpleNamespace(CreateProcess=original)
        foreign_result = []
        def popen(*args, **options):
            foreign = threading.Thread(target=lambda: foreign_result.append(self.create(api, 'foreign')))
            foreign.start(); foreign.join(timeout=5)
            self.assertFalse(foreign.is_alive())
            self.create(api)
            return process
        with patch('blackbox_core.optional_jobs.subprocess._winapi', api, create=True), \
                patch('blackbox_core.optional_jobs.subprocess.Popen', side_effect=popen):
            owner._popen_suspended(['owned'], {})
        self.assertEqual(foreign_result, [(170, 180, 142, 143)])
        self.assertEqual(calls, ['foreign', 'owned'])
        self.assertEqual(owner._initial_thread_capture['pid'], 42)
        self.assertEqual(owner.kernel.DuplicateHandle.call_count, 1)
        self.assertEqual(owner.kernel.DuplicateHandle.call_args.args[1], 80)
        self.assertIs(api.CreateProcess, original)

    def test_popen_after_create_failure_retains_the_job_boundary_before_return(self):
        owner = self.owner(); owner._job_assigned = False
        original = Mock(return_value=(70, 80, 42, 43))
        api = SimpleNamespace(CreateProcess=original)
        def popen(*args, **options):
            self.create(api)
            self.assertTrue(owner._job_assigned)
            raise OSError('CONTROLLED_POPEN_AFTER_CREATE_FAILURE')
        with patch('blackbox_core.optional_jobs.subprocess._winapi', api, create=True), \
                patch('blackbox_core.optional_jobs.subprocess.Popen', side_effect=popen):
            with self.assertRaisesRegex(OSError, 'POPEN_AFTER_CREATE'):
                owner._popen_suspended(['owned'], {})
        self.assertIsNone(owner.process)
        self.assertTrue(owner._job_assigned)
        self.assertEqual(owner._thread_handles, [101])
        self.assertIs(api.CreateProcess, original)
        owner.kernel.ResumeThread.assert_not_called()

    def test_same_thread_unrelated_command_is_never_bound_or_captured(self):
        owner, process = self.owner(), self.process()
        def original(*arguments):
            return (170, 180, 142, 143) if arguments[1] == 'foreign' else (70, 80, 42, 43)
        api = SimpleNamespace(CreateProcess=original)
        def popen(*args, **options):
            self.assertEqual(self.create(api, 'foreign'), (170, 180, 142, 143))
            owner.kernel.AssignProcessToJobObject.assert_not_called()
            self.create(api)
            return process
        with patch('blackbox_core.optional_jobs.subprocess._winapi', api, create=True), \
                patch('blackbox_core.optional_jobs.subprocess.Popen', side_effect=popen):
            owner._popen_suspended(['owned'], {})
        owner.kernel.AssignProcessToJobObject.assert_called_once_with(37, 70)
        self.assertEqual(owner.kernel.DuplicateHandle.call_count, 1)

    def test_reentrant_identical_create_process_call_is_not_bound_or_captured(self):
        owner, process = self.owner(), self.process()
        nested = False
        nested_results = []
        api = SimpleNamespace()
        def original(*arguments, **keywords):
            nonlocal nested
            if nested:
                return (170, 180, 142, 143)
            nested = True
            try:
                nested_results.append(api.CreateProcess(*arguments, **keywords))
                owner.kernel.AssignProcessToJobObject.assert_not_called()
            finally:
                nested = False
            return (70, 80, 42, 43)
        api.CreateProcess = original
        def popen(*args, **options):
            self.create(api)
            return process
        with patch('blackbox_core.optional_jobs.subprocess._winapi', api, create=True), \
                patch('blackbox_core.optional_jobs.subprocess.Popen', side_effect=popen):
            owner._popen_suspended(['owned'], {})
        self.assertEqual(nested_results, [(170, 180, 142, 143)])
        owner.kernel.AssignProcessToJobObject.assert_called_once_with(37, 70)
        self.assertEqual(owner.kernel.DuplicateHandle.call_args.args[1], 80)

    def test_duplicate_failure_waits_for_popen_ownership_and_never_resumes(self):
        owner, process = self.owner(), self.process()
        owner.kernel.DuplicateHandle.side_effect = OSError('CONTROLLED_DUPLICATE_FAILURE')
        original = Mock(return_value=(70, 80, 42, 43))
        api = SimpleNamespace(CreateProcess=original)
        def popen(*args, **options):
            self.assertEqual(self.create(api), (70, 80, 42, 43))
            return process
        with patch('blackbox_core.optional_jobs.subprocess._winapi', api, create=True), \
                patch('blackbox_core.optional_jobs.subprocess.Popen', side_effect=popen):
            owner._popen_suspended(['owned'], {})
        self.assertIs(owner.process, process)
        with self.assertRaisesRegex(OSError, 'CONTROLLED_DUPLICATE_FAILURE'):
            owner._resume_initial_thread()
        owner.kernel.ResumeThread.assert_not_called()
        self.assertEqual(owner._thread_handles, [])
        self.assertIs(api.CreateProcess, original)

    def test_mismatched_process_handle_or_unassigned_job_cannot_resume(self):
        for change in ('process', 'thread', 'job'):
            with self.subTest(change=change):
                owner = self.owner(); owner.process = self.process()
                owner._thread_handles = [101]
                owner._initial_thread_capture = {'process_handle': 70, 'pid': 42, 'tid': 43,
                                                  'handle': 101, 'error': None}
                if change == 'process': owner.process._handle = 170
                if change == 'thread': owner.kernel.GetProcessIdOfThread.return_value = 142
                if change == 'job': owner._job_assigned = False
                with self.assertRaisesRegex(OSError, 'IDENTITY'):
                    owner._resume_initial_thread()
                owner.kernel.ResumeThread.assert_not_called()
                owner.kernel.CloseHandle.assert_not_called()
                self.assertEqual(owner._thread_handles, [101])

    def test_external_hook_replacement_is_preserved_and_old_capture_deactivated(self):
        owner, process = self.owner(), self.process()
        original = Mock(return_value=(70, 80, 42, 43))
        api = SimpleNamespace(CreateProcess=original)
        replacements = []
        def popen(*args, **options):
            capture = api.CreateProcess
            self.create(api)
            def replacement(*values, **keywords):
                return capture(*values, **keywords)
            replacements.append(replacement)
            api.CreateProcess = replacement
            return process
        with patch('blackbox_core.optional_jobs.subprocess._winapi', api, create=True), \
                patch('blackbox_core.optional_jobs.subprocess.Popen', side_effect=popen):
            owner._popen_suspended(['owned'], {})
        self.assertIs(api.CreateProcess, replacements[0])
        api.CreateProcess('later-unrelated')
        self.assertEqual(owner.kernel.DuplicateHandle.call_count, 1)

    def test_unexpected_suspend_count_retains_capability_for_cleanup(self):
        for count in (0, 2, 0xFFFFFFFF):
            with self.subTest(count=count):
                owner = self.owner(); owner.process = self.process()
                owner._thread_handles = [101]
                owner._initial_thread_capture = {'process_handle': 70, 'pid': 42, 'tid': 43,
                                                  'handle': 101, 'error': None}
                owner.kernel.ResumeThread.return_value = count
                with self.assertRaisesRegex(OSError, 'RESUME_UNCONFIRMED'):
                    owner._resume_initial_thread()
                owner.kernel.CloseHandle.assert_not_called()
                self.assertEqual(owner._thread_handles, [101])


@unittest.skipUnless(os.name == 'nt', 'Actual Windows job membership and descendant exit')
class NativeOwnedCleanup(unittest.TestCase):
    def test_popen_after_create_failure_still_kills_job_owned_suspended_child(self):
        owners, processes = [], []
        actual_popen = subprocess.Popen
        class ObservedOwner(OwnedProcess):
            def _popen_suspended(self, args, options):
                owners.append(self)
                return super()._popen_suspended(args, options)
        def fail_after_create(*args, **options):
            process = actual_popen(*args, **options)
            processes.append(process)
            raise OSError('CONTROLLED_POPEN_AFTER_CREATE_FAILURE')
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / 'must-not-execute-after-create-error'
            try:
                with patch('blackbox_core.optional_jobs.subprocess.Popen', side_effect=fail_after_create):
                    with self.assertRaisesRegex(OSError, 'POPEN_AFTER_CREATE_FAILURE'):
                        ObservedOwner([sys.executable, '-c',
                            'import pathlib,sys;pathlib.Path(sys.argv[1]).write_text("unexpected")', str(marker)],
                            detach_console=True)
                self.assertEqual(len(owners), 1)
                self.assertEqual(len(processes), 1)
                self.assertIsNone(owners[0].process)
                self.assertTrue(owners[0]._closed)
                self.assertIsNotNone(processes[0].wait(timeout=5))
                self.assertFalse(marker.exists())
            finally:
                for process in processes:
                    if process.poll() is None: process.kill()
                    process.wait(timeout=5)

    def test_duplicate_failure_kills_only_suspended_owned_child_before_any_code_runs(self):
        import ctypes as C
        owners = []
        class DuplicateDenied(OwnedProcess):
            def _popen_suspended(self, args, options):
                owners.append(self)
                duplicate = self.kernel.DuplicateHandle
                def deny(*arguments):
                    C.set_last_error(5)
                    return 0
                self.kernel.DuplicateHandle = deny
                try:
                    return super()._popen_suspended(args, options)
                finally:
                    self.kernel.DuplicateHandle = duplicate
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / 'must-not-execute'
            with self.assertRaisesRegex(OSError, 'INITIAL_THREAD_DUPLICATE_FAILED'):
                DuplicateDenied([sys.executable, '-c',
                    'import pathlib,sys;pathlib.Path(sys.argv[1]).write_text("unexpected")', str(marker)],
                    detach_console=True)
            self.assertEqual(len(owners), 1)
            owner = owners[0]
            self.assertIsNotNone(owner.process)
            self.assertIsNotNone(owner.process.poll())
            self.assertTrue(owner._closed)
            self.assertFalse(owner.cleanup_required)
            self.assertIsNone(owner.job)
            self.assertFalse(marker.exists(), 'Suspended child ran despite failure to retain its initial capability')

    def test_simultaneous_foreign_popen_runs_and_survives_owned_cleanup(self):
        import subprocess as sp
        api = sp._winapi
        original = api.CreateProcess
        waiting, foreign_ready = threading.Event(), threading.Event()
        owners, errors = [], []
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / 'foreign-started'
            def observe(*arguments, **keywords):
                if threading.current_thread().name == 'owned-capability-test':
                    waiting.set()
                    if not foreign_ready.wait(15):
                        raise TimeoutError('FOREIGN_POPEN_DID_NOT_RUN_CONCURRENTLY')
                return original(*arguments, **keywords)
            def launch():
                try:
                    owners.append(OwnedProcess([sys.executable, '-c', 'import time;time.sleep(60)'],
                                               detach_console=True))
                except BaseException as error:
                    errors.append(error)
            thread = threading.Thread(target=launch, name='owned-capability-test')
            foreign = None
            with patch.object(api, 'CreateProcess', side_effect=observe) as observer:
                thread.start()
                try:
                    self.assertTrue(waiting.wait(15))
                    foreign = sp.Popen([sys.executable, '-c',
                        'import pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text("ready");time.sleep(60)',
                        str(marker)])
                    until = time.monotonic() + 15
                    while not marker.exists() and foreign.poll() is None and time.monotonic() < until:
                        time.sleep(.01)
                    self.assertTrue(marker.exists(), 'Foreign process was suspended or otherwise altered')
                    foreign_ready.set(); thread.join(timeout=15)
                    self.assertFalse(thread.is_alive())
                    self.assertFalse(errors)
                    self.assertEqual(len(owners), 1)
                    self.assertEqual(owners[0].windows_creation_flags, 0xC)
                    self.assertIs(api.CreateProcess, observer)
                    owners[0].close(kill=True)
                    self.assertIsNone(foreign.poll(), 'Foreign process was captured or killed')
                finally:
                    foreign_ready.set(); thread.join(timeout=15)
                    for owner in owners: owner.close(kill=True)
                    if foreign is not None:
                        if foreign.poll() is None: foreign.kill()
                        foreign.wait(timeout=5)

    def test_immediate_descendant_is_in_job_and_dies_after_leader_exit(self):
        import ctypes as C
        from ctypes import wintypes as W
        import psutil
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / 'child.txt'
            code = ('import pathlib,subprocess,sys;'
                    'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]);'
                    'pathlib.Path(sys.argv[1]).write_text(str(p.pid))')
            owner = OwnedProcess([sys.executable, '-c', code, str(marker)])
            unrelated = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'])
            child = None; handle = None
            kernel = C.WinDLL('kernel32', use_last_error=True)
            kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]; kernel.OpenProcess.restype = W.HANDLE
            kernel.IsProcessInJob.argtypes = [W.HANDLE, W.HANDLE, C.POINTER(W.BOOL)]
            kernel.IsProcessInJob.restype = W.BOOL
            kernel.CloseHandle.argtypes = [W.HANDLE]; kernel.CloseHandle.restype = W.BOOL
            kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]; kernel.WaitForSingleObject.restype = W.DWORD
            try:
                self.assertEqual(owner.process.wait(timeout=20), 0)
                child = psutil.Process(int(marker.read_text()))
                handle = kernel.OpenProcess(0x1000 | 0x100000, False, child.pid)
                self.assertTrue(handle)
                member = W.BOOL()
                self.assertTrue(kernel.IsProcessInJob(handle, owner.job, C.byref(member)))
                self.assertTrue(member.value, 'Descendant escaped before job assignment')
                owner.close(kill=False)
                self.assertEqual(kernel.WaitForSingleObject(handle, 2000), 0)
                self.assertIsNone(unrelated.poll(), 'A foreign process was terminated')
                self.assertTrue(owner._closed)
            finally:
                try:
                    owner.close(kill=True)
                finally:
                    if child is not None:
                        try:
                            child.kill()
                        except psutil.NoSuchProcess:
                            pass
                    if handle: kernel.CloseHandle(handle)
                    unrelated.kill(); unrelated.wait(timeout=5)
