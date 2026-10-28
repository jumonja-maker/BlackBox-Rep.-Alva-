"""Real owned-process regressions; no process-name kills or external targets."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from blackbox_core.optional_jobs import OptionalJobs, OwnedProcess


class OptionalOwnershipAuditTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux subreaper fixture; not Windows Job Object evidence')
    def test_parent_exit_does_not_abandon_owned_descendant_or_signal_other_group(self):
        script = r'''
import ctypes,json,os,signal,subprocess,sys,tempfile,time
from pathlib import Path
from blackbox_core.optional_jobs import OwnedProcess
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(36,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),'PR_SET_CHILD_SUBREAPER')
def changes(marker):
 before=marker.read_text()
 time.sleep(.14)
 return marker.read_text()!=before
result={};owner=None;child=None;other=None
try:
 with tempfile.TemporaryDirectory() as folder:
  marker=Path(folder)/'child.pid';heartbeat=Path(folder)/'heartbeat'
  child_code='import ctypes,sys,time;from pathlib import Path;ctypes.CDLL(None).prctl(1,0);p=Path(sys.argv[1]);\nwhile True:p.write_text(str(time.monotonic_ns()));time.sleep(.02)'
  parent_code='import subprocess,sys,time;from pathlib import Path;p=subprocess.Popen([sys.executable,"-c",'+repr(child_code)+',sys.argv[2]]);\nwhile not Path(sys.argv[2]).exists():time.sleep(.01)\nPath(sys.argv[1]).write_text(str(p.pid))'
  other=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],start_new_session=True)
  owner=OwnedProcess([sys.executable,'-c',parent_code,str(marker),str(heartbeat)])
  owner.process.wait(timeout=8);child=int(marker.read_text())
  result['aliveBeforeClose']=changes(heartbeat)
  owner.close(kill=False)
  time.sleep(.06)
  result['aliveAfterOrdinaryClose']=changes(heartbeat)
  owner.close(kill=True)
  result['aliveAfterForcedClose']=changes(heartbeat)
  result['unrelatedGroupAlive']=other.poll() is None
finally:
 if owner:
  try:os.killpg(owner.process.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  owner.process.wait(timeout=3)
 if child:
  until=time.monotonic()+3
  while time.monotonic()<until:
   found,status=os.waitpid(child,os.WNOHANG)
   if found:result['reapedOwnedDescendant']=True;break
   time.sleep(.01)
 if other:other.kill();other.wait(timeout=3)
print(json.dumps(result))
'''
        completed = subprocess.run([sys.executable, '-c', script], capture_output=True,
                                   text=True, timeout=18, check=True)
        result = json.loads(completed.stdout)
        self.assertTrue(result['aliveBeforeClose'])
        self.assertFalse(result['aliveAfterOrdinaryClose'], result)
        self.assertFalse(result['aliveAfterForcedClose'], result)
        self.assertTrue(result['unrelatedGroupAlive'], result)
        self.assertTrue(result['reapedOwnedDescendant'], result)

    def test_ready_marker_failure_closes_already_started_owned_process(self):
        owners = []
        def launch(_args):
            owner = OwnedProcess([sys.executable, '-c', 'import time;time.sleep(60)'])
            owners.append(owner)
            return owner
        jobs = OptionalJobs(launcher=launch)
        jobs.submit({'op':'inspect','id':'startup'}, {'op':'inspect'})
        original = Path.touch
        def no_ready(path, *args, **kwargs):
            if path.name == 'ready':
                raise OSError('fixture ready marker write failed')
            return original(path, *args, **kwargs)
        try:
            with patch('blackbox_core.optional_jobs.Path.touch', no_ready):
                rows = jobs.poll()
            self.assertIn('OPTIONAL_START_FAILED', rows[0]['error'])
            self.assertEqual(rows[0]['command']['id'], 'startup')
            self.assertIsNotNone(owners[0].process.poll(), 'Startup lost the owner after Popen')
            self.assertTrue(owners[0]._closed)
            self.assertFalse(jobs.busy)
        finally:
            for owner in owners:
                owner.close(kill=True)
            jobs.cancel()

    def test_launch_failure_cleanup_preserves_primary_error_if_temp_cleanup_fails(self):
        owners = []
        temporary_roots = []
        class BrokenTemp:
            def __init__(self, **_kwargs):
                self.real = tempfile.TemporaryDirectory(); self.name = self.real.name
            def cleanup(self):
                raise OSError('secondary temp cleanup failure')
        def launch(_args):
            owner = OwnedProcess([sys.executable, '-c', 'import time;time.sleep(60)'])
            owners.append(owner); return owner
        jobs = OptionalJobs(launcher=launch)
        jobs.submit({'op':'inspect','id':'primary'}, {'op':'inspect'})
        original = Path.touch
        def no_ready(path, *args, **kwargs):
            if path.name == 'ready':raise OSError('primary ready write failure')
            return original(path, *args, **kwargs)
        # Capture the factory before patching tempfile's shared module object.
        real_temporary = tempfile.TemporaryDirectory
        def make_temp(**_kwargs):
            value = BrokenTemp.__new__(BrokenTemp)
            value.real = real_temporary(); value.name = value.real.name
            temporary_roots.append(value.real)
            return value
        try:
            with patch('blackbox_core.optional_jobs.tempfile.TemporaryDirectory', make_temp), patch('blackbox_core.optional_jobs.Path.touch', no_ready):
                row = jobs.poll()[0]
            self.assertIn('primary ready write failure', row['error'])
            self.assertIsNotNone(owners[0].process.poll())
        finally:
            for owner in owners:owner.close(kill=True)
            jobs.cancel()
            for temporary in temporary_roots:temporary.cleanup()
