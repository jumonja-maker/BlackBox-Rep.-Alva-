"""Ownership failures remain inspectable; executed exclusively in hosted CI."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
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


@unittest.skipUnless(os.name == 'nt', 'Actual Windows job membership and descendant exit')
class NativeOwnedCleanup(unittest.TestCase):
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
