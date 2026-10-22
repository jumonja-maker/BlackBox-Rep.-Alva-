"""No destructive target operations or false provenance claims."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from blackbox_rep_alva.contracts import ObserverError, Sample
from blackbox_rep_alva.storage import SessionStore
from blackbox_rep_alva.report import write_report, summarize
from blackbox_rep_alva.handoff import build_handoff
from blackbox_rep_alva.recorder import record
from blackbox_rep_alva.cli import main
from io import StringIO
from contextlib import redirect_stdout


class SafetyTests(unittest.TestCase):
    def test_refuses_symlink_output_root(self):
        with tempfile.TemporaryDirectory() as temp:
            real=Path(temp)/"real";real.mkdir()
            link=Path(temp)/"link"
            try:link.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):self.skipTest("symlink creation prohibited")
            with self.assertRaises(ObserverError):SessionStore(link,42)
            self.assertEqual(list(real.iterdir()),[])

    def test_report_source_database_read_only(self):
        with tempfile.TemporaryDirectory() as temp:
            store=SessionStore(Path(temp),42)
            store.write_sample(Sample(1,128,2.0,None,None,None,None))
            folder=store.folder
            store.finish("COMPLETED");store.close()
            database=folder/"session.sqlite3"
            before=hashlib.sha256(database.read_bytes()).digest()
            result=summarize(folder)
            packet=build_handoff(folder)
            after=hashlib.sha256(database.read_bytes()).digest()
            self.assertEqual(before,after)
            self.assertFalse(packet["permission_to_act"])
            self.assertFalse(result["execution_attested"])
            self.assertNotIn("password",json.dumps(packet))

    def test_existing_report_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            store=SessionStore(Path(temp),42)
            folder=store.folder
            store.finish("COMPLETED");store.close()
            report=folder/"report.json"
            report.write_bytes(b"NOT_YOURS")
            with self.assertRaises(ObserverError):write_report(folder)
            self.assertEqual(report.read_bytes(),b"NOT_YOURS")

    def test_fake_probe_never_terminates_target(self):
        class Probe:
            def __init__(self,pid):self.pid=pid
            def sample(self):return Sample(1,20,0.5,1,0,0,0)
            def terminate(self):raise AssertionError("must never terminate target")
            def kill(self):raise AssertionError("must never kill target")
        with tempfile.TemporaryDirectory() as temp:
            ticks=iter([0.0,0.0,0.001,1.0])
            result=record(9,Path(temp),duration=0.2,interval=0.1,
                          probe_factory=Probe,clock=lambda:next(ticks),sleeper=lambda _:None)
            self.assertEqual(result["state"],"COMPLETED")
            self.assertGreaterEqual(result["samples"],1)

    def test_cli_without_alva_installed(self):
        # Normal report path must not need to import private platform at all.
        with tempfile.TemporaryDirectory() as temp:
            store=SessionStore(Path(temp),42)
            folder=store.folder
            store.finish("COMPLETED");store.close()
            with patch.dict("sys.modules",{"alva":None,"alva.host":None}):
                with redirect_stdout(StringIO()) as stream:
                    status=main(["summary",str(folder)])
            self.assertEqual(status,0)
            self.assertIn('"root_cause": "UNKNOWN"',stream.getvalue())