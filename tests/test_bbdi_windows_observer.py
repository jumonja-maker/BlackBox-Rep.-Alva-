"""Portable ABI/fake tests plus real, opt-in owned Windows fixture processes."""
from contextlib import closing
import ctypes
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

from blackbox_core.windows_observer import WaitChainNode,WindowCapture,WindowsNative,win32_status
from blackbox_core.session_v2 import SessionV2Writer,FILENAME
from blackbox_core.session_view import SessionView


class FakeNative:
    def __init__(self,statuses,*,no_windows=False):
        self.statuses=iter(statuses)
        self.no_windows=no_windows
        self.calls=0
    def enumerate(self,pid):
        return {"status":"OK","win32_code":0,"omitted":0,"windows":[] if self.no_windows else
                [{"hwnd":100,"pid":pid,"tid":99,"visible":True}]}
    def responsiveness(self,window):
        status=next(self.statuses)
        return {"status":status,"win32_code":1460 if status=="SENSOR_TIMEOUT" else 0,
                "started_ns":time.monotonic_ns(),"ended_ns":time.monotonic_ns(),
                "method":"TEST_ONLY_FAKE_NATIVE","timeout_ms":150}
    def wait_chain(self,tid):
        self.calls+=1
        return {"status":"ACCESS_DENIED","win32_code":5,"nodes":[],"is_cycle":None,
                "ended_ns":time.monotonic_ns(),"method":"TEST_ONLY_FAKE_WCT"}


class WindowContractTests(unittest.TestCase):
    def test_x64_wct_layout_is_exact_without_host_wchar_size_assumptions(self):
        self.assertEqual(ctypes.sizeof(WaitChainNode),280)
        self.assertEqual(WaitChainNode.data.offset,8)
        self.assertEqual(WaitChainNode.ObjectStatus.offset,4)

    def test_consecutive_timeout_recovery_and_gone_are_real_separate_types(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)
            writer=SessionV2Writer(folder,pid=123,created=1.,name="TEST_ONLY",origin_ns=time.monotonic_ns())
            adapter=FakeNative(["OK","SENSOR_TIMEOUT","SENSOR_TIMEOUT","OK"])
            cap=WindowCapture(123,1.,writer,adapter=adapter,identity=lambda *_:True)
            for _ in range(4):
                cap.poll()
            adapter.no_windows=True;cap.poll()
            self.assertEqual(cap.status,"NOT_APPLICABLE")
            self.assertEqual(adapter.calls,1)
            writer.finish("COMPLETED")
            with SessionView.open(folder) as view:
                events=view.event_page()["rows"]
                codes=[r["event_type"] for r in events]
                self.assertEqual(codes.count("UI_UNRESPONSIVE_OBSERVED"),1)
                self.assertLess(codes.index("UI_UNRESPONSIVE_OBSERVED"),codes.index("UI_RESPONSIVE_AGAIN"))
                self.assertIn("WINDOW_GONE",codes)
                wct=next(r for r in events if r["event_type"]=="WCT_SNAPSHOT")
                self.assertEqual(wct["measurement_status"],"ACCESS_DENIED")
                self.assertEqual(wct["detail"]["wct"]["win32_code"],5)
                self.assertEqual(wct["verification_class"],"UNVERIFIED_IMPORT")
                self.assertIsNotNone(view.db.execute("SELECT absence_observed_ns FROM windows").fetchone()[0])
                self.assertEqual(view.db.execute("SELECT status FROM incidents").fetchone()[0],"RECOVERY_OBSERVED")

    def test_generic_zero_error_is_not_fabricated_as_timeout(self):
        cap=WindowCapture(123,1.,None,adapter=FakeNative(["UNKNOWN","UNKNOWN"]),identity=lambda *_:True)
        cap.poll();cap.poll()
        self.assertFalse(cap.snapshot()[1][0]["unresponsive_observed"])
        self.assertEqual(win32_status(5),"ACCESS_DENIED")
        self.assertEqual(win32_status(999999),"UNKNOWN")

    @unittest.skipIf(os.name=="nt","Non-Windows compatibility path")
    def test_linux_does_not_load_or_fabricate_win32(self):
        with self.assertRaisesRegex(RuntimeError,"UNSUPPORTED_OS"):
            WindowsNative()
        cap=WindowCapture(123,1.,None);cap.start();cap.stop(timeout=2)
        self.assertEqual(cap.status,"UNSUPPORTED_OS")

    def test_identity_change_prevents_native_event_persistence(self):
        class Sink:
            def submit(self,*args):
                raise AssertionError("changed PID must not create native evidence")
        cap=WindowCapture(123,1.,Sink(),adapter=FakeNative(["OK"]),identity=lambda *_:False)
        cap.poll()
        self.assertEqual(cap.status,"TARGET_IDENTITY_UNAVAILABLE")


@unittest.skipUnless(os.name=="nt","Real Win32 fixtures require Windows x64")
class RealWindowsFixtureTests(unittest.TestCase):
    def fixture(self,folder,mode):
        env=os.environ.copy();env["QT_QPA_PLATFORM"]="windows"
        process=subprocess.Popen([sys.executable,str(Path(__file__).resolve().parents[1]/"app.py"),
            "--qa-fixture",mode,"--qa-output",str(folder)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        deadline=time.monotonic()+15
        while not (folder/"ready.json").exists() and time.monotonic()<deadline:
            self.assertIsNone(process.poll(),"native fixture exited early")
            time.sleep(.05)
        self.assertTrue((folder/"ready.json").is_file(),"native fixture startup timeout")
        return process,json.loads((folder/"ready.json").read_text())

    def stop_fixture(self,process,folder):
        (folder/"stop.request").touch()
        self.assertEqual(process.wait(timeout=15),0)

    def test_real_ui_block_timeout_then_recovery_and_native_wct_status(self):
        import psutil
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);fixture=root/"fixture";fixture.mkdir();recording=root/"recording";recording.mkdir()
            process,data=self.fixture(fixture,"ui")
            writer=SessionV2Writer(recording,pid=process.pid,created=psutil.Process(process.pid).create_time(),
                                   name="REAL_WINDOWS_UI_FIXTURE",origin_ns=time.monotonic_ns())
            cap=WindowCapture(process.pid,psutil.Process(process.pid).create_time(),writer,interval_s=1)
            cap.start()
            try:
                deadline=time.monotonic()+14
                codes=[]
                while time.monotonic()<deadline:
                    try:
                        with closing(sqlite3.connect(recording/FILENAME,timeout=.5)) as db:
                            codes=[r[0] for r in db.execute("SELECT event_type FROM events ORDER BY event_id")]
                    except sqlite3.Error:
                        pass
                    if "UI_RESPONSIVE_AGAIN" in codes:
                        break
                    time.sleep(.1)
                self.assertIn("UI_UNRESPONSIVE_OBSERVED",codes)
                self.assertIn("UI_RESPONSIVE_AGAIN",codes)
                self.assertIn("WCT_SNAPSHOT",codes)
                self.assertNotEqual(cap.status,"SENSOR_FAILURE")
            finally:
                self.assertTrue(cap.stop(timeout=5))
                writer.finish("COMPLETED")
                self.stop_fixture(process,fixture)
            with SessionView.open(recording) as view:
                events=view.event_page()["rows"]
                timed=next(e for e in events if e["event_type"]=="UI_UNRESPONSIVE_OBSERVED")
                self.assertEqual(timed["source_kind"],"WIN32")
                self.assertEqual(timed["detail"]["check"]["win32_code"],1460)
                self.assertEqual(timed["detail"]["consecutive_timeouts"],2)
                print("BB_DI_001_REAL_UI_EVIDENCE "+json.dumps({"timeout":timed["detail"],
                    "wct":[e["detail"] for e in events if e["event_type"]=="WCT_SNAPSHOT"]}))

    def test_real_mutex_cycle_or_exact_permission_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)
            process,data=self.fixture(folder,"waitchain")
            try:
                result=WindowsNative().wait_chain(data["thread_ids"][0],timeout_s=1)
                self.assertIn(result["status"],("OK","ACCESS_DENIED","UNSUPPORTED"),result)
                if result["status"]=="OK":
                    self.assertGreater(len(result["nodes"]),1)
                    self.assertTrue(result["is_cycle"],result)
                elif result["status"]=="ACCESS_DENIED":
                    self.assertEqual(result["win32_code"],5)
                else:
                    self.assertIn(result["win32_code"],(50,120))
                self.assertLessEqual(len(result["nodes"]),16)
                self.assertNotIn("object_name",str(result).lower())
                print("BB_DI_001_REAL_WCT_EVIDENCE "+json.dumps(result))
            finally:
                self.stop_fixture(process,folder)

    def test_real_non_gui_fixture_has_no_windows_not_a_no_hang_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);process,data=self.fixture(folder,"cpu")
            try:
                result=WindowsNative().enumerate(process.pid)
                self.assertEqual(result["status"],"OK")
                self.assertEqual(result["windows"],[])
                cap=WindowCapture(process.pid,1.,None,adapter=FakeNative([],no_windows=True),identity=lambda *_:True)
                cap.poll()
                self.assertEqual(cap.status,"NOT_APPLICABLE")
                print("BB_DI_001_NON_GUI_ENUMERATION "+json.dumps(result))
            finally:
                self.stop_fixture(process,folder)
