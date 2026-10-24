"""Explicit real-process Qt/frozen QA driver, no synthetic measurements.

Only the local QA file picker and public fixture note entry are automated.
Sampling, action transitions, native probes, SQLite and report workers are the
production paths. The bundled EXE launches itself as the owned workload.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

from PySide6 import __version__ as qt_version
from PySide6.QtCore import QObject,QTimer
from PySide6.QtWidgets import QCheckBox,QDialog,QApplication
import psutil
from blackbox_core.interval_report import digest
from blackbox_core.session_v2 import FILENAME,safe_path
from blackbox_universal.theme import font_coverage
from blackbox_universal.provenance import source_identity


class DeepSmoke(QObject):
    def __init__(self,app,window,output,commit_sha):
        super().__init__(window)
        self.app,self.window=app,window
        root=safe_path(output);root.mkdir(parents=True,exist_ok=True)
        self.run=Path(tempfile.mkdtemp(prefix="real-process-",dir=root))
        self.fixture=self.run/"fixture";self.fixture.mkdir()
        self.exports=self.run/"exports";self.exports.mkdir()
        self.commit_sha=commit_sha
        self.started=time.monotonic()
        self.last_progress=0
        self.phase="BOOT"
        self.attempt=0
        self.child=None
        self.error=None
        self.hashes={}
        self.result={"scope":"REAL_QT_ACTION_THREAD_INCIDENT_INTERVAL_EXPORT",
            "full_bb_di_001_accepted":False,"frozen":bool(getattr(sys,"frozen",False)),
            **source_identity(commit_sha),
            "os":platform.platform(),"python":platform.python_version(),"psutil":psutil.__version__,
            "pyside6":qt_version,"limitations":["NOT_8H_OR_1H_ENDURANCE","NOT_PHYSICAL_WIN10_WIN11_QA",
                "NO_ETW_ACCEPTANCE","NO_FULL_INCIDENT_CARD_RESOURCE_COMPARE_ACCEPTANCE"]}
        self.result["font_coverage"] = font_coverage(app)
        self.timer=QTimer(self);self.timer.setInterval(100);self.timer.timeout.connect(self.poll)

    def start(self):
        executable=[sys.executable]
        if not getattr(sys,"frozen",False):
            executable.append(str(Path(__file__).resolve().parents[1]/"app.py"))
        env=os.environ.copy()
        if os.name=="nt":
            env["QT_QPA_PLATFORM"]="windows"  # Real HWND, not Qt's offscreen fake handle.
        self.log=(self.fixture/"process.log").open("wb")
        self.child=subprocess.Popen(executable+["--qa-fixture","ui","--qa-output",str(self.fixture)],
            cwd=self.fixture,env=env,stdin=subprocess.DEVNULL,stdout=self.log,stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        self.timer.start()

    def _require(self,condition,code):
        if not condition:
            raise RuntimeError(code)

    def poll(self):
        try:
            if time.monotonic()-self.started>65 and self.phase not in ("ERROR","EXIT"):
                raise RuntimeError("DEEP_SMOKE_DEADLINE")
            w=self.window
            if time.monotonic()-self.last_progress>=1:
                self.last_progress=time.monotonic()
                (self.run/"qa-progress.json").write_text(json.dumps({"phase":self.phase,
                    "elapsed_seconds":time.monotonic()-self.started,"active":w.probe.active,
                    "pending":getattr(w.probe,"pending",False),"error":w.probe.last_error,
                    "action_state":w.probe.actions.state}),encoding="utf-8")
            if getattr(w,"_isolated",False) and w.probe.pending and self.phase not in ("ERROR","EXIT"):
                return
            if self.phase=="BOOT":
                self._require(self.result["font_coverage"]["ok"], "RU_EN_FONT_GLYPHS_MISSING")
                self._require(self.result["source_identity_status"]!="MISMATCH_OR_DIRTY","ACTUAL_CHECKOUT_MISMATCH")
                ready=self.fixture/"ready.json"
                if not ready.is_file():
                    self._require(self.child.poll() is None,"FIXTURE_EXITED_BEFORE_READY")
                    return
                data=json.loads(ready.read_text())
                self._require(data["pid"]==self.child.pid,"FIXTURE_IDENTITY_MISMATCH")
                self.result.update(fixture_control_pid=data["pid"],sensor_pid=data["sensor_pid"],
                                   sensor_pid_source=data["sensor_pid_source"])
                if not getattr(w,"_isolated",False):w.probe.output_root=self.run/"sessions"
                w._attach_pid(data["sensor_pid"])
                self.phase="ATTACHED"
            elif self.phase=="ATTACHED":
                if w.probe.pid!=self.result["sensor_pid"]:return
                self._require(not w.probe.active and not w.stop_btn.isEnabled(),"ATTACH_STARTED_RECORDING")
                w.start_btn.click()
                self.phase="STARTED"
            elif self.phase=="STARTED":
                if not w.probe.active:return
                # Public Settings controls configure a conservative test
                # detector on shared CI hardware. These are thresholds, not
                # substitute CPU measurements or an assertion of a defect.
                w.cpu_trigger_threshold.setValue(1.)
                w.cpu_trigger_duration.setValue(1000)
                self.result["cpu_trigger_policy"]={"threshold_percent_one_cpu":1.,"sustained_ms":1000}
                w.detailed_capture_btn.click();self.phase="ENABLE_INCIDENTS"
            elif self.phase=="ENABLE_INCIDENTS":
                if w.probe.detailed_capture is None:return
                w.auto_capture_btn.click();self.phase="ENABLE_WINDOWS"
            elif self.phase=="ENABLE_WINDOWS":
                if w.probe.incident_capture is None:return
                if os.name=="nt":
                    w.window_capture_btn.click()
                self.phase="PREPARE"
            elif self.phase=="PREPARE":
                cap=w.probe.detailed_capture
                if w.probe.total_samples<1 or cap is None or cap.samples<1:
                    return
                with patch("blackbox_universal.window.QInputDialog.getText",return_value=("BB-DI-001 public QA note",True)):
                    w.mark_problem_btn.click()
                self.phase="PREPARE_ACTION"
            elif self.phase=="PREPARE_ACTION":
                w.action_prepare_btn.click()
                self.phase="BASELINE"
            elif self.phase=="BASELINE":
                if w.action_begin_btn.isEnabled():
                    w.action_begin_btn.click()
                    self.phase="BEGIN_CONFIRMED"
            elif self.phase=="BEGIN_CONFIRMED":
                if w.probe.actions.state=="RUNNING":
                    self.action_until=time.monotonic()+1.5
                    self.phase="RUNNING"
            elif self.phase=="RUNNING":
                if time.monotonic()>=self.action_until:
                    w.action_end_btn.click()
                    self.phase="COOL"
            elif self.phase=="COOL":
                if w.probe.actions.state!="COMPLETED":
                    return
                self.attempt+=1
                if self.attempt<3:
                    w.action_repeat_btn.click()
                    self.phase="BASELINE"
                else:
                    w.stop_btn.click()
                    self.phase="REPORT"
            elif self.phase=="REPORT":
                if w.probe.active or w._report_worker is not None:
                    return
                self._require(w.probe.last_error is None and w.probe.report_result is not None,"REPORT_FAILED")
                folder=w.probe.session_folder
                self.hashes={name:digest(folder/name) for name in ("session.sqlite3",FILENAME,"report.json","report.html")}
                with sqlite3.connect(folder/FILENAME) as db:
                    self.result.update(samples=db.execute("SELECT count(*) FROM samples").fetchone()[0],
                        thread_records=db.execute("SELECT count(*) FROM thread_samples").fetchone()[0],
                        completed_actions=db.execute("SELECT count(*) FROM action_intervals WHERE state='COMPLETED'").fetchone()[0],
                        incidents=db.execute("SELECT count(*) FROM incidents").fetchone()[0],
                        native_events=[list(r) for r in db.execute("SELECT event_type,count(*) FROM events "
                            "WHERE source_kind IN ('WIN32','WCT') GROUP BY event_type")])
                self._require(self.result["completed_actions"]==3,"ACTION_ROWS_MISSING")
                self._require(self.result["thread_records"]>0,"REAL_TID_ROWS_MISSING")
                self._require(self.result["incidents"]>0,"REAL_AUTO_INCIDENT_NOT_OBSERVED")
                w.load_interval_current.click()
                self.phase="INTERVAL"
            elif self.phase=="INTERVAL":
                if w._interval_worker is not None:
                    return
                packet=w._interval_packet
                self._require(packet is not None,"UI_INTERVAL_HANDLER_FAILED")
                threads=packet["threads"]["top_threads"]
                self._require(any((r["cpu_seconds"] or 0)>0 for r in threads),"REAL_TID_CPU_DELTA_MISSING")
                self.result["thread_cpu_seconds"]=sum(r["cpu_seconds"] or 0 for r in threads)
                w.investigate_current_btn.click()
                self.phase="INVESTIGATION"
            elif self.phase=="INVESTIGATION":
                if w._investigation_worker is not None or w._investigation_busy:
                    return
                self._require(w._investigation_result is not None and "error" not in w._investigation_result,
                              "INVESTIGATION_HANDLER_FAILED")
                w.analysis_panel.load.click();self.phase='INVESTIGATION_V2'
            elif self.phase=='INVESTIGATION_V2':
                panel=w.analysis_panel
                if panel._busy:return
                packet=panel.packet
                self._require(packet is not None and packet['engine']=='BLACKBOX_INVESTIGATION_2','INVESTIGATION_V2_HANDLER_FAILED')
                self._require(packet['root_cause']=='UNKNOWN' and packet['findings_total']>0,'INVESTIGATION_V2_FACTS_MISSING')
                index=next((i for i,r in enumerate(packet['findings']) if r['detail'].get('incident_id')),None)
                self._require(index is not None,'INCIDENT_CARD_ROW_MISSING')
                panel.table.selectRow(index);panel.card.click();self.phase='INCIDENT_CARD'
            elif self.phase=='INCIDENT_CARD':
                panel=w.analysis_panel
                if panel._busy:return
                packet=panel.card_packet
                self._require(packet is not None and packet['status']=='OBSERVATION_ONLY','INCIDENT_CARD_HANDLER_FAILED')
                self._require(bool(packet['snapshots']),'INCIDENT_CARD_SNAPSHOTS_MISSING')
                self.result['investigation_v2_and_incident_card_ui']=True
                w.events_panel.load.click();self.phase='UNIFIED_EVENTS'
            elif self.phase=='UNIFIED_EVENTS':
                panel=w.events_panel
                if panel._busy:return
                self._require(panel.packet is not None and panel.packet['total_matching']>0,'UNIFIED_EVENT_UI_FAILED')
                self._require(all(r['verification_class']=='UNVERIFIED_IMPORT' for r in panel.packet['rows']),'UNIFIED_EVENT_TRUST_ESCALATED')
                self.result['unified_events_ui']=True
                for language in ("RU","EN"):
                    w._set_language(language)
                    for page,_ in w.PAGES:
                        w._navigate(page)
                        w.grab().save(str(self.run/f"{language}-{page}.png"))
                w._navigate("reports")
                self.phase="EXPORT_DIALOG"
                def accept_privacy():
                    dialog=QApplication.activeModalWidget()
                    self._require(isinstance(dialog,QDialog),"PRIVACY_DIALOG_MISSING")
                    controls=dialog.findChildren(QCheckBox)
                    self._require(len(controls)==3 and not any(c.isChecked() for c in controls),"PRIVACY_DEFAULTS_UNSAFE")
                    controls[-1].setChecked(True)  # Explicit QA-selected ZIP.
                    dialog.accept()
                QTimer.singleShot(30,accept_privacy)
                with patch("blackbox_universal.window.QFileDialog.getExistingDirectory",return_value=str(self.exports)):
                    w.export_interval_btn.click()
                self.phase="EXPORT"
            elif self.phase=="EXPORT":
                if w._interval_export_worker is not None:
                    return
                packet=w._interval_export_result
                self._require(isinstance(packet,dict) and "error" not in packet,"EXPORT_HANDLER_FAILED")
                self._require(any(name.endswith(".zip") for name in packet["files"]),"EXPLICIT_ZIP_MISSING")
                self._require(all(digest(w.probe.session_folder/name)==value for name,value in self.hashes.items()),
                              "REANALYSIS_CHANGED_ORIGINAL_FILES")
                manifest=json.loads(Path(packet["manifest"]).read_text())
                self._require(all(digest(self.exports/r["filename"])==r["sha256"] for r in manifest["files"]),
                              "EXPORT_DIGEST_MISMATCH")
                self.result.update(result="PASS",source_sha256=self.hashes,
                    export_files=[Path(name).name for name in packet["files"]],
                    elapsed_seconds=time.monotonic()-self.started,root_cause="UNKNOWN")
                self.phase="EXIT"
                (self.fixture/"stop.request").touch()
            elif self.phase=="ERROR":
                if w.probe.active:
                    w._stop()
                if w._base_sample_worker is None and w._report_worker is None:
                    self.phase="EXIT"
            elif self.phase=="EXIT":
                if self.child.poll() is None:
                    return
                self.log.close()
                self.timer.stop()
                (self.run/"qa-summary.json").write_text(json.dumps(self.result,indent=2)+"\n",encoding="utf-8")
                if getattr(w,"_isolated",False) and w.probe.alive:
                    # Publish success after the production owner exits too.
                    self.result["result"]="AWAITING_HELPER_SHUTDOWN" if not self.error else "FAIL"
                    def finished():
                        exit_code=w.probe.process.exitCode()
                        self.result["helper_exit_code"]=exit_code
                        self.result["result"]="FAIL" if self.error or exit_code else "PASS"
                        (self.run/"qa-summary.json").write_text(json.dumps(self.result,indent=2)+"\n",encoding="utf-8")
                        self.app.exit(1 if self.result["result"]!="PASS" else 0)
                    w.probe.terminated.connect(finished)
                    w.close()
                else:
                    w.close();self.app.exit(1 if self.error else 0)
        except Exception as exc:
            self.error=type(exc).__name__+":"+str(exc)
            self.result.update(result="FAIL",error=self.error,phase=self.phase)
            self.phase="ERROR"
            (self.fixture/"stop.request").touch()
