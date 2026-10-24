import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from blackbox_core.optional_jobs import OptionalJobs, OwnedProcess
from blackbox_core.operation_worker import execute

class OptionalJobsTests(unittest.TestCase):
    def test_owned_process_close_is_idempotent_and_never_signals_again(self):
        from unittest.mock import patch
        owner=OwnedProcess([sys.executable,'-c','import time;time.sleep(20)'])
        owner.close(kill=True);self.assertIsNotNone(owner.process.poll())
        with patch('blackbox_core.optional_jobs.os.killpg',side_effect=AssertionError('second signal forbidden'),create=True):
            owner.close(kill=True)
    def drain(self,jobs,timeout=12):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            rows=jobs.poll()
            if rows:return rows
            time.sleep(.01)
        self.fail('operation never completed')
    def test_real_disposable_process_and_bounded_result(self):
        jobs=OptionalJobs();jobs.submit({'op':'processes','id':'a'},{'op':'processes','args':{}})
        try:
            r=self.drain(jobs)[0];self.assertIsNone(r['error']);self.assertIsInstance(r['result'],list)
            self.assertNotEqual(r['pid'],os.getpid());self.assertEqual(r['command']['id'],'a')
            self.assertEqual(jobs.health()['completed'],1)
        finally:jobs.cancel()
    def test_real_hard_deadline_kills_only_our_owned_child(self):
        children=[]
        def launch(args):
            p=OwnedProcess([sys.executable,'-c','import time;time.sleep(60)']);children.append(p.process);return p
        jobs=OptionalJobs(launcher=launch)
        jobs.submit({'op':'native','id':'timeout'},{'op':'native'},seconds=.1)
        try:
            r=self.drain(jobs)[0];self.assertEqual(r['error'],'OPTIONAL_OPERATION_TIMEOUT')
            self.assertIsNotNone(children[0].poll());self.assertEqual(jobs.health()['timed_out'],1)
            self.assertTrue(subprocess.run([sys.executable,'-c','pass'],timeout=5).returncode==0)
        finally:jobs.cancel()
    def test_launch_failure_retains_command_id_for_acknowledgement(self):
        def fail(args):raise OSError('fixture')
        jobs=OptionalJobs(launcher=fail);jobs.submit({'op':'inspect','id':'lost'},{'op':'inspect'})
        row=jobs.poll()[0];self.assertEqual(row['command']['id'],'lost');self.assertIn('START_FAILED',row['error'])
    def test_queue_limit_and_unknown_operation(self):
        jobs=OptionalJobs(limit=1);jobs.submit({'op':'inspect'},{'op':'inspect'})
        with self.assertRaisesRegex(ValueError,'QUEUE_FULL'):jobs.submit({'op':'inspect'},{'op':'inspect'})
        with self.assertRaisesRegex(ValueError,'UNKNOWN'):jobs.submit({'op':'shell'},{})
        self.assertEqual(len(jobs.cancel()),1)
    def test_pid_birth_mismatch_is_refused_before_native_capture(self):
        with self.assertRaises(ValueError):execute({'op':'native','pid':os.getpid(),'created':1})
    def test_cancel_running_child_returns_explicit_unconfirmed_status(self):
        jobs=OptionalJobs(launcher=lambda args:OwnedProcess([sys.executable,'-c','import time;time.sleep(60)']))
        jobs.submit({'op':'dump','id':'cancel'},{'op':'dump'});jobs.poll();p=jobs.current['owner'].process
        result=jobs.cancel()[0];self.assertIn('UNCONFIRMED',result['error']);self.assertIsNotNone(p.poll())

class SamplerIsolationTests(unittest.TestCase):
    def test_real_sampling_commits_while_disposable_operation_is_waiting(self):
        from blackbox_core.research_worker import ResearchSession
        from blackbox_core.casebook import readonly
        from contextlib import closing
        with tempfile.TemporaryDirectory() as tmp:
            s=ResearchSession(tmp);s.command({'op':'attach','args':{'pid':os.getpid()}});s.command({'op':'start'})
            s.jobs.launcher=lambda args:OwnedProcess([sys.executable,'-c','import time;time.sleep(60)'])
            try:
                s.submit_optional({'op':'native','id':'slow','args':{}});self.assertEqual(s.poll_optional(),[])
                first=s.probe.total_samples
                for _ in range(6):s.tick();time.sleep(.02)
                self.assertGreaterEqual(s.probe.total_samples-first,6);self.assertTrue(s.jobs.busy)
                with closing(readonly(s.probe.session_folder/'session.sqlite3')) as db:
                    self.assertGreaterEqual(db.execute('SELECT count(*) FROM samples').fetchone()[0],6)
                process=s.jobs.current['owner'].process;s.stop()
                self.assertIsNotNone(process.poll())
                self.assertIn('CANCELLED',s.poll_optional()[0]['error'])
            finally:s.stop()
