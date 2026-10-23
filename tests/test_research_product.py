"""Production research, real local process IO and adversarial evidence tests."""
from __future__ import annotations
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import shutil
from unittest.mock import patch
import zipfile

from blackbox_core.casebook import (CaseBook,context,episode,evidence_page,
    export_case,verify_package,recover_case,compare_cases)
from blackbox_core.instrumentation import EventWriter,EventTail
from blackbox_core.preparation import write_preparation
from blackbox_core.research_worker import ResearchSession
from blackbox_core.windows_research import window_observations,wait_chain,minidump,enable_debug_privilege


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/"events.jsonl"
        self.writer=EventWriter(self.path,"a"*32);self.tail=EventTail(self.path,"a"*32,os.getpid())
    def tearDown(self):self.temp.cleanup()
    def test_control_event_is_received(self):
        self.assertTrue(self.writer.emit("blackbox.ready"));rows=self.tail.poll()
        self.assertTrue(self.tail.ready);self.assertEqual(rows[0]["pid"],os.getpid());self.assertNotIn("token",rows[0])
    def test_operation_has_two_linkable_boundaries(self):
        with self.writer.operation("Сохранение") as ident:pass
        rows=self.tail.poll();self.assertEqual([r["kind"] for r in rows],["operation.begin","operation.end"])
        self.assertEqual(rows[0]["operation_id"],ident);self.assertEqual(rows[1]["operation_id"],ident)
    def test_target_exception_is_not_swallowed(self):
        with self.assertRaisesRegex(RuntimeError,"target"):
            with self.writer.operation("failure"):raise RuntimeError("target")
        self.assertEqual([r["kind"] for r in self.tail.poll()],["operation.begin","operation.error","operation.end"])
    def test_oversized_event_fails_without_crashing_target(self):
        self.assertFalse(self.writer.emit("huge",text="x"*20000));self.assertEqual(self.writer.dropped,1)
    def test_nan_rejected(self):self.assertFalse(self.writer.emit("invalid",value=float("nan")))
    def test_wrong_process_or_token_does_not_verify(self):
        EventWriter(self.path,"b"*32).emit("blackbox.ready");self.assertEqual(self.tail.poll(),[]);self.assertFalse(self.tail.ready)
    def test_partial_line_survives(self):
        self.writer.emit("blackbox.ready");raw=self.path.read_bytes();self.path.write_bytes(raw[:20])
        self.assertEqual(self.tail.poll(),[])
        with self.path.open("ab") as f:f.write(raw[20:])
        self.assertEqual(len(self.tail.poll()),1)
    def test_replay_rejected(self):
        self.writer.emit("blackbox.ready");raw=self.path.read_bytes();self.tail.poll()
        with self.path.open("ab") as f:f.write(raw)
        self.assertEqual(self.tail.poll(),[]);self.assertEqual(self.tail.invalid,1)
    def test_generated_python_client_is_standalone(self):
        folder=Path(self.temp.name)/"client"
        write_preparation(folder,self.path,"a"*32)
        env={**os.environ,"PYTHONPATH":""}
        subprocess.run([sys.executable,str(folder/"example.py")],cwd=folder,env=env,check=True,timeout=10)
        # It was another process, not the currently selected PID.
        self.assertEqual(self.tail.poll(),[])
        self.assertFalse(self.tail.ready)
    @unittest.skipUnless(shutil.which("node"),"Node runtime not installed")
    def test_generated_node_client_preserves_runtime_tid_kind(self):
        folder=Path(self.temp.name)/"node-client";write_preparation(folder,self.path,"a"*32)
        (folder/"main.cjs").write_text("const {BlackBoxEvents}=require('./blackbox-events.cjs'); const bb=new BlackBoxEvents('blackbox-config.json'); bb.emit('blackbox.ready'); bb.operation('test',async()=>{}).then(()=>{});")
        child=subprocess.Popen(["node","main.cjs"],cwd=folder);self.assertEqual(child.wait(timeout=10),0)
        tail=EventTail(self.path,"a"*32,child.pid);rows=tail.poll()
        self.assertTrue(tail.ready);self.assertEqual(rows[0]["tid_kind"],"RUNTIME_THREAD_ID")
        self.assertEqual(rows[0]["tid"],0);self.assertIsInstance(rows[0]["source_ns"],int)
    def test_invalid_operation_type_cannot_break_recorder(self):
        self.writer.emit("operation.begin",operation_id={"bad":"id"})
        self.assertEqual(self.tail.poll(),[]);self.assertEqual(self.tail.invalid,1)
    def test_file_replacement_invalidates_old_ready(self):
        self.writer.emit("blackbox.ready");self.tail.poll();self.assertTrue(self.tail.ready)
        self.path.unlink();self.path.write_text("{}\n");self.tail.poll();self.assertFalse(self.tail.ready)


class CaseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.session=ResearchSession(self.root);self.session.command({"op":"attach","args":{"pid":os.getpid()}})
        self.session.command({"op":"start"});self.session.tick();self.folder=self.session.probe.session_folder
    def tearDown(self):self.session.stop();self.temp.cleanup()
    def test_real_session_records_monotonic_context(self):
        self.assertEqual(context(self.folder)["schema_version"],2)
        self.assertEqual(context(self.folder)["recording_origin_ns"],self.session.probe._recording_origin_ns)
    def test_interval_evidence_links_and_measured_facts(self):
        self.session.book.put("fact",{"value":0})
        result=episode(self.folder,0,60000)
        self.assertFalse(result["root_cause_proven"])
        self.assertTrue(result["facts"][0]["metrics"]["samples"]>=1)
        self.assertIn("research.sqlite3:evidence:",result["evidence"]["rows"][-1]["evidence_ref"])
    def test_paging_covers_more_than_one_page_without_duplicates(self):
        for n in range(123):self.session.book.put("fixture",{"n":n})
        ids=[];cursor=0
        while True:
            p=evidence_page(self.folder,after_id=cursor,limit=20)
            ids.extend(r["id"] for r in p["rows"]);cursor=p["next_id"]
            if not p["has_more"]:break
        self.assertEqual(len(ids),len(set(ids)));self.assertGreaterEqual(len(ids),123)
    def test_invalid_interval_refused(self):
        with self.assertRaises(ValueError):episode(self.folder,100,0)
    def test_null_zero_and_access_denied_preserved(self):
        self.session.book.put("quality",{"zero":0,"unknown":None},quality="ACCESS_DENIED")
        row=evidence_page(self.folder)["rows"][-1]
        self.assertEqual(row["data"]["zero"],0);self.assertIsNone(row["data"]["unknown"]);self.assertEqual(row["quality"],"ACCESS_DENIED")
    def test_application_ready_and_operation_duration(self):
        writer=EventWriter(self.session.tail.path,self.session.tail.token)
        writer.emit("blackbox.ready")
        with writer.operation("Save"):pass
        self.session.tick()
        self.assertTrue(self.session.tail.ready)
        facts=episode(self.folder,0,60000)["facts"]
        self.assertEqual(facts[-1]["classification"],"APPLICATION_REPORTED_OPERATION")
        self.assertGreaterEqual(facts[-1]["duration_ns"],0);self.assertEqual(len(facts[-1]["evidence_refs"]),2)
    def test_export_requires_stop(self):
        with self.assertRaisesRegex(ValueError,"STOP_RECORDING"):export_case(self.folder,self.root/"out.zip")
    def test_export_roundtrip_and_html_escaping(self):
        self.session.book.put("<script>bad()</script>",{"note":"<img onerror=bad()>"})
        self.session.stop();dest=self.root/"out.zip";result=export_case(self.folder,dest)
        self.assertEqual(verify_package(dest)["integrity"],"VERIFIED")
        self.assertFalse(verify_package(dest)["authenticity"]=="VERIFIED")
        with zipfile.ZipFile(dest) as z:
            self.assertIn("evidence.csv",z.namelist())
            self.assertNotIn("<script>bad()",z.read("report.html").decode())
            self.assertIn("&lt;script&gt;",z.read("report.html").decode())
        self.assertEqual(len(result["sha256"]),64)
    def test_export_never_overwrites(self):
        self.session.stop();dest=self.root/"out.zip";dest.write_bytes(b"original")
        with self.assertRaises(ValueError):export_case(self.folder,dest)
        self.assertEqual(dest.read_bytes(),b"original")
    def test_cancelled_export_does_not_publish_or_leave_staging(self):
        self.session.stop();dest=self.root/"cancelled.zip";calls=[]
        def cancel():
            calls.append(1);return len(calls)>3
        with self.assertRaises(InterruptedError):export_case(self.folder,dest,cancel=cancel)
        self.assertFalse(dest.exists());self.assertEqual(list(self.root.glob("blackbox-case-*")),[])
    def test_raw_artifact_omissions_are_declared(self):
        raw=self.folder/"artifacts";raw.mkdir();(raw/"snapshot.dmp").write_bytes(b"private")
        self.session.stop();dest=self.root/"out.zip"
        manifest=export_case(self.folder,dest)["manifest"]
        self.assertFalse(manifest["complete_package"]);self.assertEqual(manifest["omitted"],["artifacts/snapshot.dmp"])
    def test_opt_in_raw_artifacts(self):
        raw=self.folder/"artifacts";raw.mkdir();(raw/"snapshot.dmp").write_bytes(b"private")
        self.session.stop();dest=self.root/"out.zip"
        export_case(self.folder,dest,include_sensitive=True)
        with zipfile.ZipFile(dest) as z:self.assertEqual(z.read("artifacts/snapshot.dmp"),b"private")
    def test_active_owner_prevents_recovery(self):
        with self.assertRaisesRegex(ValueError,"OWNER_STILL_ACTIVE"):recover_case(self.folder,self.root/"recovered")
    def test_recovery_preserves_original_and_marks_incomplete(self):
        self.session.stop()
        from blackbox_core.casebook import _hash
        before=_hash(self.folder/"research.sqlite3")
        out=self.root/"recovered";recover_case(self.folder,out)
        self.assertEqual(context(out)["state"],"RECOVERED_INCOMPLETE")
        self.assertEqual(_hash(self.folder/"research.sqlite3"),before)
    def test_schema_has_time_index(self):
        with closing(sqlite3.connect(self.folder/"session.sqlite3")) as db:
            plan=str(db.execute("EXPLAIN QUERY PLAN SELECT * FROM samples WHERE elapsed_ms BETWEEN 0 AND 1000").fetchall())
            self.assertIn("ix_samples_elapsed",plan)
    def test_statistics_include_all_repeats_beyond_old_twenty_limit(self):
        from blackbox_core.casebook import action_statistics
        for n in range(101):
            self.session.book.db.execute("INSERT INTO action_runs VALUES(?,?,?,?)",(str(n),"e",n*1000000,n+1))
        self.session.book.db.commit()
        result=action_statistics(self.folder)
        self.assertEqual(result["repeats"],101);self.assertEqual(result["duration_ms"]["median"],50)
        self.assertEqual(result["duration_ms"]["p95"],95)
        warmed=action_statistics(self.folder,warmup_count=1)
        self.assertEqual(warmed["repeats"],100);self.assertEqual(warmed["duration_ms"]["minimum"],1)
    def test_evidence_backwards_page(self):
        for n in range(220):self.session.book.put("fixture",{"n":n})
        first=evidence_page(self.folder,limit=100);second=evidence_page(self.folder,after_id=first["next_id"],limit=100)
        back=evidence_page(self.folder,before_id=second["first_id"],limit=100)
        self.assertEqual([r["id"] for r in first["rows"]],[r["id"] for r in back["rows"]])
    def test_unknown_command_does_not_execute_anything(self):
        with self.assertRaisesRegex(ValueError,"UNKNOWN_RESEARCH_COMMAND"):
            self.session.command({"op":"shell","args":{"command":"echo unsafe"}})
    def test_context_cannot_change_mid_recording(self):
        with self.assertRaises(ValueError):self.session.command({"op":"configure","args":{"scenario":"changed"}})
    def test_foreign_native_calls_on_linux_are_honest(self):
        if os.name=="nt":self.skipTest("Linux capability case")
        self.assertEqual(window_observations(os.getpid())["status"],"UNSUPPORTED_PLATFORM")
        self.assertEqual(wait_chain(1)["status"],"UNSUPPORTED_PLATFORM")


class PackageAdversarialTests(unittest.TestCase):
    def test_path_traversal_refused_without_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Path(tmp)/"bad.zip"
            with zipfile.ZipFile(f,"w") as z:z.writestr("../escape","bad")
            with self.assertRaises(ValueError):verify_package(f)
    def test_total_size_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Path(tmp)/"bad.zip"
            with zipfile.ZipFile(f,"w") as z:z.writestr("large",b"0"*100)
            with self.assertRaisesRegex(ValueError,"SIZE_BUDGET"):verify_package(f,max_total_bytes=10)


@unittest.skipUnless(os.name=="nt","Windows native APIs")
class WindowsResearchTests(unittest.TestCase):
    def test_real_minidump_of_owned_child(self):
        child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(20)"])
        try:
            with tempfile.TemporaryDirectory() as temp:
                p=Path(temp)/"child.dmp";r=minidump(child.pid,p)
                self.assertEqual(r["status"],"CAPTURED");self.assertGreater(p.stat().st_size,100)
                with p.open("rb") as stream:self.assertEqual(stream.read(4),b"MDMP")
        finally:child.terminate();child.wait(timeout=5)
    def test_real_wct_current_thread_has_source_and_status(self):
        import threading
        enable_debug_privilege();r=wait_chain(threading.get_native_id())
        self.assertEqual(r["source"],"WIN32_WCT")
        self.assertIn(r["status"],("OK","ACCESS_DENIED","NOT_OBSERVED","TIMEOUT","TRUNCATED"))
        # A failure status does not certify native coverage or invented nodes.
        if r["status"] not in ("OK","TRUNCATED"):self.assertEqual(r["nodes"],[])


if __name__=="__main__":unittest.main()
