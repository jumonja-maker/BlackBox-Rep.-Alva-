"""Real source/frozen Qt → isolated owner → evidence → package → verify QA."""
from __future__ import annotations
import json
import os
from pathlib import Path
import time
from PySide6.QtCore import QTimer


def run_e2e(app,window,destination):
    destination=Path(destination);destination.mkdir(parents=True,exist_ok=False)
    bridge=window.probe
    # Root is an explicit worker option; the normal production root is kept.
    state={"step":0,"began":time.monotonic(),"verified":False,"episode":False,"client":None,"compared":False,"first":None}
    timer=QTimer(window);timer.setInterval(80)
    def result(op,payload,error):
        if error:fail("COMMAND_"+op+": "+error);return
        if op=="verify":state["verified"]=payload.get("integrity")=="VERIFIED"
        if op=="episode":state["episode"]=bool(payload["evidence"]["rows"])
        if op=="prepare_client":state["client"]=payload
        if op=="compare":
            state["compared"]=(payload.get("experiments",{}).get("before",{}).get("repeats")==1 and
                               payload.get("experiments",{}).get("after",{}).get("repeats")==1)
    bridge.result_ready.connect(result)
    def finalized():
        if state.get("proof"):
            proof=state["proof"]
            proof["status"]="PASS" if bridge.process.exitCode()==0 else "FAIL"
            proof["helper_exit_code"]=bridge.process.exitCode()
            (destination/"e2e.json").write_text(json.dumps(proof),encoding="utf-8")
            if proof["status"]!="PASS":app.exit(1)
    bridge.terminated.connect(finalized)
    def fail(reason):
        timer.stop();(destination/"e2e.json").write_text(json.dumps({"status":"FAIL","reason":reason}),encoding="utf-8")
        bridge.shutdown();QTimer.singleShot(300,lambda:app.exit(1))
    def advance():
        (destination/"progress.json").write_text(json.dumps({"step":state["step"],"pending":bridge.pending,
            "active":bridge.active,"action":bridge.actions.state,"error":bridge.last_error}),encoding="utf-8")
        if time.monotonic()-state["began"]>60:fail("E2E_DEADLINE");return
        step=state["step"]
        if bridge.pending:return
        if step==0:window._attach_pid(os.getpid())
        elif step==1:
            if bridge.pid!=os.getpid():return
            bridge.send("configure",scenario="Frozen EXE action roundtrip",workload="local-self",target_version="QA")
        elif step==2:window.start_btn.click()
        elif step==3:
            if not bridge.active:return
            bridge.send("prepare_client")
        elif step==4:
            if state["client"] is None:return
            client=state["client"]
            if not (Path(client["folder"])/"blackbox_event_client.py").is_file():fail("FROZEN_CLIENT_SOURCE_MISSING");return
            from blackbox_core.instrumentation import EventWriter
            writer=EventWriter(client["event_path"],client["token"])
            writer.emit("blackbox.ready")
            with writer.operation("Instrumented GUI QA operation"):pass
            bridge.prepare_action(baseline_ms=0)
        elif step==5:
            if not bridge.actions.ready_to_start():return
            window.action_begin_btn.click()
        elif step==6:
            if bridge.actions.state!="RUNNING":return
            bridge.mark_problem("QA_USER_MARKER")
        elif step==7:window.action_end_btn.click()
        elif step==8:
            if bridge.actions.state!="COMPLETED":return
            window.stop_btn.click()
        elif step==9:
            if bridge.active or bridge.report_result is None:return
            bridge.send("export",destination=str(destination/"investigation.zip"))
        elif step==10:bridge.send("verify",path=str(destination/"investigation.zip"))
        elif step==11:bridge.send("episode",start_ms=0,end_ms=60000)
        elif step==12:
            if not state["verified"] or not state["episode"] or not bridge.data.get("app_ready"):
                fail("MISSING_ROUNDTRIP_EVIDENCE");return
            state["first"]=str(bridge.session_folder)
            bridge.send("configure",target_version="QA second version")
        elif step==13:window.start_btn.click()
        elif step==14:
            if not bridge.active:return
            bridge.prepare_action(baseline_ms=0)
        elif step==15:
            if not bridge.actions.ready_to_start():return
            window.action_begin_btn.click()
        elif step==16:
            if bridge.actions.state!="RUNNING":return
            window.action_end_btn.click()
        elif step==17:
            if bridge.actions.state!="COMPLETED":return
            window.stop_btn.click()
        elif step==18:
            if bridge.active or bridge.report_result is None:return
            bridge.send("compare",before=state["first"],after=str(bridge.session_folder))
        elif step==19:
            if not state["compared"]:fail("COMPARISON_MISSING");return
            if window.stack.count()!=5:fail("PAGE_COUNT");return
            state["proof"]={"status":"AWAITING_HELPER_SHUTDOWN","scenario":"REAL_QT_ISOLATED_ACTION_PACKAGE_ROUNDTRIP",
                "folder":str(bridge.session_folder),"helper_pid":bridge.data.get("helper_pid"),"gui_pid":os.getpid(),
                "privilege":bridge.capabilities.get("privilege"),"verified":True,
                "generated_client":True,"application_control_event":True,"two_recordings_compared":True}
            (destination/"e2e.json").write_text(json.dumps(state["proof"]),encoding="utf-8")
            timer.stop();window.close();return
        state["step"]+=1
    timer.timeout.connect(advance);timer.start()
    window._research_e2e_timer=timer
