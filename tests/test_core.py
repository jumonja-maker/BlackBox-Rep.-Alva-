from __future__ import annotations
import json
from pathlib import Path
import os
import tempfile
import unittest
from blackbox_rep_alva.contracts import ObserverError, Sample, event, bounded
from blackbox_rep_alva.storage import SessionStore
from blackbox_rep_alva.report import summarize, compare, write_report
from blackbox_rep_alva.handoff import build_handoff
from blackbox_rep_alva.recorder import record


class EvidenceTests(unittest.TestCase):
    def test_storage_report_and_handoff(self):
        with tempfile.TemporaryDirectory() as temp:
            store = SessionStore(Path(temp), os.getpid())
            store.write_sample(Sample(10, 512, 11.0, 2, None, None, 0))
            store.write_sample(Sample(20, 1024, 12.0, 2, None, None, 1))
            store.write_event(event("observer_warning", "SAMPLE_UNAVAILABLE", "sample", 18))
            path = store.folder
            store.finish("COMPLETED"); store.close()
            report = summarize(path)
            self.assertEqual(report["samples"], 2)
            self.assertEqual(report["peak_rss_bytes"], 1024)
            self.assertEqual(report["observation_errors"], {"SAMPLE_UNAVAILABLE": 1})
            self.assertEqual(report["root_cause"], "UNKNOWN")
            handoff = build_handoff(path)
            self.assertFalse(handoff["permission_to_act"])
            self.assertEqual(handoff["classification"]["source"], "UNKNOWN")
            res = write_report(path)
            self.assertEqual(res["sample_count"], 2)
            self.assertIn("execution_attested", (path/"report.json").read_text())
            with self.assertRaises(ObserverError):
                write_report(path)

    def test_incomplete_not_success(self):
        with tempfile.TemporaryDirectory() as temp:
            store=SessionStore(Path(temp),7)
            folder=store.folder
            store.close()
            result=summarize(folder)
            self.assertEqual(result["state"],"interrupted_or_live")
            self.assertEqual(result["exit_code"],"UNKNOWN")

    def test_no_existing_session_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ObserverError):
                SessionStore(Path(temp)/"missing", 5)

    def test_invalid_data_fails_closed(self):
        with self.assertRaises(ObserverError): bounded({"password": "a"*9000})
        with self.assertRaises(ObserverError): Sample(1,-1,None,None,None,None,None).as_dict()
        with self.assertRaises(ObserverError): event("error", "SAMPLE_UNAVAILABLE", "sample", 1)

    def test_compare_no_regression_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            a=SessionStore(Path(tmp),1); a.write_sample(Sample(0,10,1.0,1,0,0,0)); p=a.folder; a.finish("COMPLETED"); a.close()
            b=SessionStore(Path(tmp),2); b.write_sample(Sample(0,20,2.0,1,0,0,0)); q=b.folder; b.finish("COMPLETED"); b.close()
            result=compare(p,q)
            self.assertEqual(result["metrics"]["peak_rss_bytes"]["delta"],10)
            self.assertFalse(result["regression_proven"])

    def test_offline_real_self_process_smoke(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=record(os.getpid(),Path(tmp),duration=0.22,interval=0.1)
            self.assertEqual(result["state"],"COMPLETED")
            self.assertGreaterEqual(result["samples"],1)

    def test_fake_probe_exit(self):
        class Fake:
            def __init__(self, pid): pass
            def sample(self): raise ObserverError("PROCESS_EXITED","sample")
        with tempfile.TemporaryDirectory() as tmp:
            result=record(55,Path(tmp),duration=0.2,interval=0.1,probe_factory=Fake)
            self.assertEqual(result["state"],"PROCESS_EXITED")
            self.assertEqual(summarize(Path(result["folder"]))["observation_errors"],{"PROCESS_EXITED":1})

    def test_report_corrupt_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/"session.sqlite3").write_bytes(b"not sqlite")
            with self.assertRaises(ObserverError):summarize(p)


if __name__=="__main__":unittest.main()
