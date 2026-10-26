"""Installed CLI works outside the source checkout and without Qt imports."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import psutil


class InstalledResearchCliTests(unittest.TestCase):
    def test_installed_capture_from_foreign_working_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            env={**os.environ,"PYTHONPATH":""}
            target=None
            # Some PID namespaces expose the parent observer but not newly
            # spawned PIDs through procfs. Use a verified read-only ancestor.
            for pid in (os.getpid(),os.getppid()):
                try:
                    candidate=psutil.Process(pid);candidate.memory_info();candidate.cpu_times()
                    target=pid;break
                except psutil.Error:pass
            if target is None:self.skipTest("No accessible observer/ancestor in this PID namespace")
            run=subprocess.run([sys.executable,"-m","blackbox_core","research","record", "--pid",str(target),
                "--output",str(root/"sessions"),"--seconds",".25","--interval",".1"],cwd=root,env=env,
                capture_output=True,text=True,timeout=20)
            self.assertEqual(run.returncode,0,run.stdout+run.stderr)
            result=json.loads(run.stdout);folder=Path(result["folder"])
            self.assertGreater(result["samples"],0)
            self.assertTrue((folder/"research.sqlite3").is_file())
            self.assertTrue((folder/"session-v2.sqlite3").is_file())


if __name__=="__main__":unittest.main()
