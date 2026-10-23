"""Contract/streaming/Qt evidence. Ordered fake history is TEST ONLY, not endurance."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import csv
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from threading import Event
import time
import tracemalloc
import unittest
from unittest.mock import patch
import zipfile

os.environ.setdefault("QT_QPA_PLATFORM","offscreen")
from blackbox_core.contracts import ObserverError,Sample
from blackbox_core.session_v2 import SessionV2Writer,FILENAME
from blackbox_core.session_view import SessionView,SessionReadError
from blackbox_core.interval_report import export_interval,digest
from blackbox_core.storage import SessionStore
from blackbox_universal.monitor import ReadOnlyProbe

ORIGIN=1_000_000_000


def writer(folder,**options):
    return SessionV2Writer(folder,pid=123,created=1.0,name="TEST_ONLY.exe",origin_ns=ORIGIN,**options)


def observation(seq,**values):
    return {"time_ns":ORIGIN+seq*1_000_000_000,"pid":123,"created":1.0,
        "cpu_user_s":float(seq),"cpu_system_s":0.0,"rss_bytes":100,
        "read_bytes":seq*100,"write_bytes":0,"read_ops":seq,"write_ops":0,
        "thread_count":1,"threads_omitted":0,"children_total":0,"children_omitted":0,
        "sensor_status":{"children":"OK"},"threads":[],"children":[],
        "thread_capture_status":"OK","child_capture_status":"OK",
        "requested_interval_ns":1_000_000_000,**values}


def synthetic_history(folder,count=100001):
    """Accelerated ordered FIX-11 subfixture; does NOT certify 8h Standard."""
    w=writer(folder)
    w.finish("COMPLETED")
    with closing(sqlite3.connect(folder/FILENAME)) as db:
        db.execute("""WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?)
            INSERT INTO samples (instance_id,series,series_seq,correlation_key,monotonic_ns,
                capture_started_ns,capture_ended_ns,writer_recorded_ns,requested_interval_ns,utc_estimate_ns,
                rss_bytes,cpu_user_s,cpu_system_s,read_bytes,write_bytes)
            SELECT 1,'STANDARD',i,'TEST_ONLY:'||i,?+i*1000000000,?+i*1000000000,
                ?+i*1000000000,?+i*1000000000,1000000000,?+i*1000000000,
                CASE WHEN i=50000 THEN 1000000000 WHEN i=50001 THEN NULL ELSE 100 END,
                i*.5+CASE WHEN i>=50000 THEN 4 ELSE 0 END,0,i*100,0 FROM n""",
            (count,*([ORIGIN]*5)))
        db.execute("UPDATE sessions SET ended_monotonic_ns=?",(ORIGIN+(count+1)*1_000_000_000,))
        db.commit()


class Schema2ContractTests(unittest.TestCase):
    def test_event_range_and_cursor_use_observation_time_not_writer_delay(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);w=writer(folder)
            for order in (1,2):
                w.submit("event",{"kind":"user_marker","code":"USER_COMMENT",
                    "timestamp_monotonic_ns":ORIGIN+order*10**9,"_recorded_ns":ORIGIN+(order+10)*10**9})
            w.finish("COMPLETED")
            with SessionView.open(folder) as v:
                first=v.event_page(ORIGIN,ORIGIN+3*10**9,limit=1)
                self.assertTrue(first["has_more"])
                second=v.event_page(ORIGIN,ORIGIN+3*10**9,after=first["next_cursor"],limit=1)
                self.assertEqual(first["rows"][0]["event_time_ns"],ORIGIN+10**9)
                self.assertEqual(second["rows"][0]["event_time_ns"],ORIGIN+2*10**9)
                self.assertNotEqual(first["rows"][0]["event_id"],second["rows"][0]["event_id"])

    def test_quality_resolution_cannot_be_finer_than_the_capture_clock(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temp,patch(
                "blackbox_core.session_v2.time.get_clock_info",return_value=SimpleNamespace(resolution=1.)):
            folder=Path(temp);w=writer(folder);w.submit("base",observation(1));w.finish("COMPLETED")
            with SessionView.open(folder) as v:
                self.assertEqual(v.metadata["monotonic_resolution_ns"],1_000_000_000)
                self.assertEqual(v.db.execute("SELECT min(resolution_ns) FROM measurements_quality").fetchone()[0],
                                 1_000_000_000)

    def test_denied_thread_capture_keeps_reason_and_unknown_cpu(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);w=writer(folder)
            w.submit("detail",observation(1,thread_count=4,thread_capture_status="ACCESS_DENIED",threads=[]))
            w.finish("COMPLETED")
            with SessionView.open(folder) as v:
                result=v.thread_summary()
                self.assertEqual(result["top_threads"],[])
                self.assertIsNone(result["omitted_cpu_seconds"])
                self.assertEqual(result["capture_quality"],[{"measurement_status":"ACCESS_DENIED","count":1}])
                self.assertEqual(v.interval(series="DETAILED")["metrics"]["thread_count"]["max"],4)

    def test_normalized_20_remains_readonly_without_invented_capture_quality(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);w=writer(folder);w.submit("detail",observation(1));w.finish("COMPLETED")
            # A test-only older-contract fixture, never migration of user data.
            with closing(sqlite3.connect(folder/FILENAME)) as db:
                db.execute("UPDATE sessions SET contract_version='bb-di-001/session/2.0'")
                db.execute("ALTER TABLE samples RENAME COLUMN writer_recorded_ns TO persisted_ns")
                db.execute("DELETE FROM measurements_quality WHERE metric IN ('thread_counters','child_counters')")
                db.commit()
            before=digest(folder/FILENAME)
            with SessionView.open(folder) as v:
                self.assertEqual(v.thread_summary()["capture_quality_contract"],"LEGACY_NO_CAPTURE_STATUS")
            self.assertEqual(before,digest(folder/FILENAME))

    def test_schema2_sink_failure_cannot_prevent_primary_shutdown(self):
        with tempfile.TemporaryDirectory() as temp:
            p=ReadOnlyProbe(Path(temp));p.attach(os.getpid());p.start();p.tick()
            p._store.v2.failure="TEST_ONLY_INJECTED_STORAGE_FAILURE"
            p._optional_sensor_error("TEST_ONLY","INJECTED")
            p.stop()
            self.assertFalse(p.active)
            self.assertEqual(p.session_state,"STORAGE_ERROR")
            with closing(sqlite3.connect(p.session_folder/"session.sqlite3")) as db:
                self.assertEqual(db.execute("SELECT exit_code FROM metadata").fetchone()[0],"STORAGE_ERROR")

    def test_real_standard_and_detailed_records_share_identity_and_clock(self):
        with tempfile.TemporaryDirectory() as temp:
            p=ReadOnlyProbe(Path(temp))
            p.attach(os.getpid())
            self.assertIsNone(p.session_folder)
            p.start()
            p.tick()
            p.set_detailed_capture(True)
            cap=p.detailed_capture
            for _ in range(200):
                if cap.samples:
                    break
                time.sleep(.01)
            self.assertGreater(cap.samples,0,cap.error)
            p.mark_problem("test note")
            p.stop()
            self.assertIsNone(p.last_error)
            with SessionView.open(p.session_folder) as view:
                self.assertTrue(view.is_v2)
                self.assertEqual(view.metadata["pid"],os.getpid())
                self.assertGreater(view.metadata["anchor_utc_ns"],0)
                self.assertEqual(view.metadata["file_trust"],"UNVERIFIED_IMPORT")
                self.assertEqual(view.interval()["coverage"]["selected_samples"],1)
                detail=view.interval(series="DETAILED")
                self.assertGreater(detail["metrics"]["rss_bytes"]["min"],0)
                self.assertGreater(view.thread_summary()["threads_ranked"],0)
                self.assertEqual(view.db.execute("PRAGMA foreign_key_check").fetchall(),[])
                self.assertEqual(view.db.execute("SELECT count(*) FROM measurements_quality").fetchone()[0],
                                 view.db.execute("SELECT count(*) FROM samples").fetchone()[0]*13+
                                 view.db.execute("SELECT count(*) FROM samples WHERE series='DETAILED'").fetchone()[0]*2)

    def test_zero_missing_reset_and_spacing_are_distinct(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);w=writer(folder)
            for x in (observation(1,read_bytes=0),observation(2,read_bytes=0),
                      observation(3,read_bytes=5),observation(4,read_bytes=1),observation(10,read_bytes=40)):
                w.submit("base",x)
            w.finish("COMPLETED")
            with SessionView.open(folder) as view:
                report=view.interval()
                self.assertIsNone(report["metrics"]["private_bytes"]["max"])
                self.assertEqual(report["metrics"]["read_bps"]["min"],0)
                self.assertEqual(report["metrics"]["read_bps"]["max"],5)
                self.assertEqual(report["coverage"]["counter_resets"],1)
                self.assertEqual(report["coverage"]["spacing_gap_pairs"],1)
                self.assertIsNone(report["coverage"]["exact_missed_samples"])
                self.assertGreater(len(set(p["segment"] for p in report["timeline"]["tracks"]["rss_bytes"])),1)

    def test_action_events_are_normalized_and_import_cannot_attest_os(self):
        with tempfile.TemporaryDirectory() as temp:
            p=ReadOnlyProbe(Path(temp));p.attach(os.getpid());p.start();p.tick()
            p.prepare_action(baseline_ms=0);p.begin_action();p.finish_action()
            p.actions.cool_down_ms=0;p.tick()
            p._store.write_event({"kind":"user_problem","source":"WIN32",
                                  "verification_class":"OS_OBSERVED","code":"UI_UNRESPONSIVE_OBSERVED"})
            p.stop()
            with SessionView.open(p.session_folder) as v:
                action=v.db.execute("SELECT * FROM action_intervals").fetchone()
                self.assertEqual(action["state"],"COMPLETED")
                self.assertGreaterEqual(action["end_ns"],action["start_ns"])
                events=v.event_page()["rows"]
                forged=next(e for e in events if e["event_type"]=="UI_UNRESPONSIVE_OBSERVED")
                self.assertEqual(forged["source_kind"],"USER")
                self.assertEqual(forged["recorded_verification_class"],"USER_DECLARED")
                self.assertEqual(forged["verification_class"],"UNVERIFIED_IMPORT")

    def test_child_history_keeps_100_identities_and_pid_reuse_separate(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);w=writer(folder)
            children=[{"pid":1000+i,"created":2.0,"rss_bytes":i,"parent_pid":123} for i in range(100)]
            w.submit("detail",observation(1,children=children,children_total=100))
            w.submit("detail",observation(2,children=[{"pid":1000,"created":3.0,"rss_bytes":33}],children_total=1))
            w.finish("COMPLETED")
            with SessionView.open(folder) as v:
                rows=v.process_page(limit=256)["rows"]
                self.assertEqual(len(rows),102)
                reused=[r for r in rows if r["pid"]==1000]
                self.assertEqual(len(reused),2)
                self.assertIsNotNone(reused[0]["absence_observed_ns"])
                self.assertIsNone(reused[1]["absence_observed_ns"])
                self.assertEqual(v.interval(series="CHILD",instance_id=reused[0]["instance_id"])
                                 ["metrics"]["rss_bytes"]["first"],0)

    def test_queue_overflow_is_bounded_and_finish_records_failure(self):
        entered,release=Event(),Event()
        original=SessionV2Writer._initialize
        def blocked(self,db):
            entered.set();release.wait(5);original(self,db)
        with tempfile.TemporaryDirectory() as temp,patch.object(SessionV2Writer,"_initialize",blocked):
            folder=Path(temp);w=writer(folder,capacity=1)
            try:
                self.assertTrue(entered.wait(3))
                w.submit("base",observation(1))
                with self.assertRaises(ObserverError):
                    w.submit("base",observation(2))
                self.assertEqual(w.dropped_commands,1)
            finally:
                release.set()
                with self.assertRaises(ObserverError):
                    w.finish("COMPLETED")
            self.assertFalse(w.thread.is_alive())
            with SessionView.open(folder) as v:
                self.assertEqual(v.metadata["exit_code"],"STORAGE_ERROR")
                # One rejected command plus one accepted command discarded
                # after fail-closed overflow, not an invented OS gap count.
                self.assertEqual(v.metadata["writer_dropped_commands"],2)

    def test_late_invalid_tid_rolls_back_all_schema2_entities(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);w=writer(folder)
            w.submit("detail",observation(1,threads=[{"tid":0,"cpu_user_s":0.,"cpu_system_s":0.}]))
            with self.assertRaises(ObserverError):
                w.finish("COMPLETED")
            with SessionView.open(folder) as v:
                self.assertEqual(v.db.execute("SELECT count(*) FROM samples").fetchone()[0],0)
                self.assertEqual(v.db.execute("SELECT count(*) FROM measurements_quality").fetchone()[0],0)
                self.assertEqual(v.metadata["exit_code"],"STORAGE_ERROR")

    def test_legacy_reader_and_exports_preserve_database_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);store=SessionStore(root,123)
            for i in range(5):
                store.write_sample(Sample(i*1000,100,None,1,None,None,0))
            store.finish("COMPLETED");store.close()
            source=store.folder/"session.sqlite3";before=digest(source)
            with SessionView.open(store.folder) as v:
                r=v.interval(1_000_000_000,3_000_000_000)
                self.assertEqual(r["coverage"]["selected_samples"],3)
                self.assertIn("LEGACY_LIMITED_DATA",r["warnings"])
                self.assertIsNone(r["metrics"]["private_bytes"]["max"])
                self.assertEqual(v.thread_summary()["status"],"LEGACY_LIMITED_DATA")
            export_interval(store.folder,root)
            self.assertEqual(before,digest(source))
            self.assertFalse((store.folder/FILENAME).exists())


class FullIntervalTests(unittest.TestCase):
    def test_default_export_drops_unknown_imported_metadata_and_native_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);w=writer(folder);w.submit("base",observation(1));w.finish("COMPLETED")
            with closing(sqlite3.connect(folder/FILENAME)) as db:
                db.execute("ALTER TABLE sessions ADD COLUMN command_line TEXT")
                db.execute("UPDATE sessions SET command_line='DO_NOT_EXPORT_SECRET'")
                detail=json.dumps({"check":{"status":"OK","method":"EnumWindows",
                    "command_line":"DO_NOT_EXPORT_SECRET"},"wct":{"nodes":[{"object_type":8,
                    "object_name":"DO_NOT_EXPORT_SECRET"}]}})
                db.execute("""INSERT INTO events(recorded_ns,observed_ns,instance_id,event_type,source_kind,
                    verification_class,timestamp_precision,correlation_key,measurement_status,detail_json)
                    VALUES (?,?,1,'WCT_SNAPSHOT','WCT','OS_OBSERVED','TEST_ONLY','TEST_ONLY','OK',?)""",
                    (ORIGIN+10**9,ORIGIN+10**9,detail))
                db.commit()
            before=digest(folder/FILENAME)
            packet=export_interval(folder,folder,prefix="privacy")
            for name in packet["files"]:
                if not name.endswith(".zip"):
                    self.assertNotIn("DO_NOT_EXPORT_SECRET",Path(name).read_text())
            self.assertEqual(before,digest(folder/FILENAME))

    def test_100k_early_minute_full_statistics_peak_and_bounded_memory(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);synthetic_history(folder)
            before=digest(folder/FILENAME)
            with SessionView.open(folder,timeout_s=120) as v:
                minute=v.interval(ORIGIN+1000*10**9,ORIGIN+1060*10**9)
                self.assertEqual(minute["coverage"]["selected_samples"],61)
                self.assertEqual(minute["coverage"]["total_samples"],100001)
                tracemalloc.start()
                full=v.interval(buckets=32)
                _,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
                self.assertEqual(full["coverage"]["selected_samples"],100001)
                self.assertEqual(full["metrics"]["rss_bytes"]["max"],1000000000)
                self.assertAlmostEqual(full["metrics"]["cpu_interval_percent"]["max"],450)
                self.assertEqual(full["metrics"]["rss_bytes"]["missing_count"],1)
                self.assertLess(peak,12*1024*1024)
                self.assertLessEqual(len(full["timeline"]["tracks"]["rss_bytes"]),32*4)
                self.assertEqual(max(p["value"] for p in full["timeline"]["tracks"]["rss_bytes"]),1000000000)
            self.assertEqual(before,digest(folder/FILENAME))

    def test_top_tid_uses_full_interval_cumulative_cpu_and_churn_segments(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);w=writer(folder)
            for seq,threads in enumerate(([(1,0),(2,0)],[(1,1),(2,.7)],[(2,1.4)],[(1,10),(2,2.1)],[(1,10.1),(2,2.8)]),1):
                w.submit("detail",observation(seq,threads=[{"tid":tid,"cpu_user_s":value,"cpu_system_s":0.}
                                                           for tid,value in threads]))
            w.finish("COMPLETED")
            with SessionView.open(folder) as v:
                result=v.thread_summary(top_n=1)
                self.assertEqual(result["top_threads"][0]["tid"],2)
                self.assertAlmostEqual(result["top_threads"][0]["cpu_seconds"],2.8)
                self.assertEqual(result["omitted_from_top"],2)
                self.assertTrue(result["truncated"])
                full=v.thread_summary()
                ones=[t for t in full["top_threads"] if t["tid"]==1]
                self.assertEqual(len(ones),2)
                self.assertAlmostEqual(sum(r["cpu_seconds"] for r in ones),1.1)
                self.assertEqual(ones[0]["observed_presence_percent"],40)

    def test_export_streams_more_than_4096_rows_and_optin_zip_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);synthetic_history(folder,6000)
            before=digest(folder/FILENAME)
            packet=export_interval(folder,folder,bundle=True,prefix="test-selected")
            with (folder/"test-selected.csv").open(newline="",encoding="utf-8") as f:
                self.assertEqual(sum(1 for _ in csv.reader(f)),6001)
            self.assertEqual(packet["sample_count"],6000)
            manifest=json.loads(Path(packet["manifest"]).read_text())
            with zipfile.ZipFile(folder/"test-selected.zip") as z:
                for record in manifest["files"]:
                    self.assertEqual(hashlib.sha256(z.read(record["filename"])).hexdigest(),record["sha256"])
                self.assertFalse(any("sqlite3" in name for name in z.namelist()))
            self.assertNotIn("executable_name",packet["report"]["metadata"])
            self.assertEqual(before,digest(folder/FILENAME))

    def test_two_exporters_never_clobber_or_remove_another_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);w=writer(folder);w.submit("base",observation(1));w.finish("COMPLETED")
            def export():
                try:
                    return export_interval(folder,folder,prefix="collision")
                except FileExistsError:
                    return None
            with ThreadPoolExecutor(max_workers=2) as pool:
                results=list(pool.map(lambda _:export(),range(2)))
            self.assertEqual(sum(r is not None for r in results),1)
            manifest=json.loads((folder/"collision.manifest.json").read_text())
            for row in manifest["files"]:
                self.assertEqual(digest(folder/row["filename"]),row["sha256"])
            self.assertEqual(list(folder.glob(".bb-interval-*")),[])


class IntervalQtTests(unittest.TestCase):
    def test_real_ui_opens_v2_zoom_changes_full_query_and_keeps_target(self):
        from PySide6.QtWidgets import QApplication
        from blackbox_universal.window import UniversalWindow
        app=QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);synthetic_history(folder,6000)
            with closing(sqlite3.connect(folder/FILENAME)) as db:
                # Explicit synthetic imported evidence for the Qt handler;
                # actual Win32/WCT measurements are separate Windows tests.
                db.execute("""INSERT INTO events(recorded_ns,observed_ns,instance_id,event_type,source_kind,
                    verification_class,timestamp_precision,correlation_key,measurement_status,detail_json)
                    VALUES (?,?,1,'WCT_SNAPSHOT','WCT','OS_OBSERVED','TEST_ONLY','TEST_ONLY','OK',?)""",
                    (ORIGIN+1005*10**9,ORIGIN+1005*10**9,json.dumps({"wct":{
                        "method":"TEST_ONLY_FAKE_WCT","is_cycle":True,"nodes":[]}})))
                db.commit()
            window=UniversalWindow();window._timer.stop()
            window.probe.pid=98765
            window.probe.session_folder=folder
            def drain():
                deadline=time.monotonic()+8
                while window._interval_worker is not None and time.monotonic()<deadline:
                    app.processEvents();time.sleep(.005)
                self.assertIsNone(window._interval_worker)
            try:
                window.load_interval_current.click();drain()
                self.assertEqual(window.stack.count(),5)
                self.assertEqual(window._interval_packet["interval"]["coverage"]["selected_samples"],6000)
                window.session_timeline.range_requested.emit(ORIGIN+1000*10**9,ORIGIN+1060*10**9)
                drain()
                self.assertEqual(window._interval_packet["interval"]["coverage"]["selected_samples"],61)
                self.assertEqual(window.probe.pid,98765)
                self.assertGreater(window.process_history_table.rowCount(),0)
                self.assertIn("UNKNOWN",window.interval_summary.text())
                window.session_event_table.selectRow(0);drain()
                self.assertIn("WCT_SNAPSHOT",window.session_event_details.toPlainText())
                self.assertIn("UNVERIFIED_IMPORT",window.session_event_details.toPlainText())
                self.assertIn("is_cycle",window.session_event_details.toPlainText())
            finally:
                drain();window.close();app.processEvents()


if __name__=="__main__":
    unittest.main()
