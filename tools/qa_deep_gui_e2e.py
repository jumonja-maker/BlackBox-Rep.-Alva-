"""Actual Qt buttons -> bridge -> diagnostic helper -> owned Windows C fixture.

This executes the SOURCE GUI. --helper can select the packaged diagnostic
helper; it does not certify a frozen GUI or interactive Secure Desktop.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from tools.qa_deep_inspection import Probe, build_probe, file_hash, require, require_hosted_windows, save
from tools.qa_deep_journal import verify_action_journal


def run(args):
    require_hosted_windows()
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    import psutil
    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication, QMessageBox, QScrollArea
    from blackbox_core.deep_journal import journal_metadata
    from blackbox_core.deep_service import InspectorService
    from blackbox_universal.decoder_window import DecoderWindow
    from blackbox_universal.provenance import source_identity
    from blackbox_universal.theme import set_retro_theme

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    helper = args.helper.resolve(strict=True) if args.helper else None
    proof = {"status": "RUNNING", "source_sha": os.environ.get("GITHUB_SHA"),
             "scope": "SOURCE_GUI_REAL_QT_BUTTONS_BRIDGE_HELPER_AND_OWNED_NATIVE_FIXTURE",
             "gui_form": "PYTHON_SOURCE_NOT_FROZEN_GUI", "language": "EN",
             "diagnostic_helper_form": "FROZEN_ONEDIR" if helper else "PYTHON_SOURCE",
             "secure_desktop": "NOT_TESTED", "physical_windows_10_11": "NOT_TESTED",
             "selection": "EXISTING_GUI_ATTACH_COMMAND_WITH_OBSERVER_CACHED_CREATION_TIME",
             "actions": [], "confirmations": [], "unexpected_dialogs": []}
    app = window = probe = pulse = dialog_timer = None
    closed, results, services = [], [], []
    dialog_plan = {"operation": None, "decision": None, "answered": False}
    pulse_state = {"ticks": 0, "last": None, "max_gap_seconds": 0.0}

    def pump_until(predicate, *, timeout=40):
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline:
            app.processEvents()
            QTest.qWait(5)
        app.processEvents()
        require(predicate(), "GUI_ACTION_OR_CLEANUP_DEADLINE")

    try:
        expected_sha = os.environ.get("BB_QA_SOURCE_SHA", os.environ.get("GITHUB_SHA", ""))
        proof["source"] = source_identity(expected_sha)
        require(proof["source"]["source_identity_status"] == "VERIFIED_EXPECTED_HEAD",
                "GUI_QA_EXACT_SOURCE_CHECKOUT_REQUIRED")
        proof["source_sha"] = proof["source"]["actual_source_sha"]
        if helper:
            manifest = helper.parent / "_internal/blackbox-build.json"
            require(manifest.is_file() and manifest.stat().st_size <= 4096,
                    "GUI_QA_PACKAGED_HELPER_BUILD_MANIFEST_REQUIRED")
            helper_source = json.loads(manifest.read_text(encoding="utf-8"))
            require(helper_source.get("source_sha") == proof["source_sha"] and
                    helper_source.get("tracked_worktree_clean") is True,
                    "GUI_QA_PACKAGED_HELPER_SOURCE_MISMATCH")
            proof["diagnostic_helper_build_manifest"] = helper_source
        executable = args.probe.resolve(strict=True) if args.probe else build_probe(output / "build")
        probe = Probe(executable, output / "probe")
        oracle = probe.ready
        created = psutil.Process(probe.process.pid).create_time()
        proof["target"] = {"pid": oracle["pid"], "created_100ns": oracle["created_100ns"]}
        proof["probe_sha256"] = file_hash(executable)
        if helper:
            proof["diagnostic_helper_sha256"] = file_hash(helper)
        app = QApplication.instance() or QApplication([])
        app.setQuitOnLastWindowClosed(False)
        set_retro_theme(app)
        window = DecoderWindow(isolated=True, output_root=output / "sessions", allow_update_check=False)
        window._set_language("EN")
        window.resize(1330, 850)
        window.show()
        app.processEvents()
        panel, bridge = window.deep_inspector_panel, window.deep_inspector_panel.bridge
        require(not bridge.has_session and panel.isHidden(), "GUI_DEEP_PANEL_MUST_START_LAZY_AND_COLLAPSED")

        def create_real_service():
            service = InspectorService(journal_root=output / "journal", helper_executable=helper)
            services.append((service, threading.get_ident()))
            return service

        # Configure the real backend's output directory and optional packaged
        # helper before its first lazy construction. No command/result is mocked.
        bridge._factory = create_real_service
        bridge.result_ready.connect(results.append)
        bridge.closed.connect(closed.append)
        window._navigate("dashboard")
        QTest.mouseClick(window.deep_inspector_toggle, Qt.MouseButton.LeftButton)
        app.processEvents()
        require(panel.isVisible() and not bridge.has_session, "EXPANDING_PANEL_STARTED_NATIVE_ACTION")

        def tick():
            now = time.monotonic()
            if pulse_state["last"] is not None:
                pulse_state["max_gap_seconds"] = max(pulse_state["max_gap_seconds"], now - pulse_state["last"])
            pulse_state["last"] = now
            pulse_state["ticks"] += 1

        pulse = QTimer()
        pulse.setInterval(20)
        pulse.timeout.connect(tick)
        pulse.start()

        def respond_to_actual_dialog():
            active = QApplication.activeModalWidget()
            if not isinstance(active, QMessageBox):
                return
            operation = dialog_plan["operation"]
            if operation is not None and not dialog_plan["answered"]:
                intended = QMessageBox.StandardButton.Yes if dialog_plan["decision"] else QMessageBox.StandardButton.Cancel
                valid = (f"PID {oracle['pid']}" in active.text() and
                         active.defaultButton() == active.button(QMessageBox.StandardButton.Cancel))
                proof["confirmations"].append({"operation": operation,
                    "decision": "YES" if dialog_plan["decision"] else "CANCEL",
                    "actual_modal_dialog": True, "target_pid_displayed_and_cancel_default": valid})
                dialog_plan["answered"] = True
                if not valid:
                    proof["unexpected_dialogs"].append("CONFIRMATION_TARGET_OR_DEFAULT_MISMATCH")
                    intended = QMessageBox.StandardButton.Cancel
                button = active.button(intended)
                if button is not None:
                    QTest.mouseClick(button, Qt.MouseButton.LeftButton)
            elif operation is None:
                proof["unexpected_dialogs"].append(active.windowTitle())
                button = active.button(QMessageBox.StandardButton.Cancel) or active.button(QMessageBox.StandardButton.Ok)
                if button is not None:
                    QTest.mouseClick(button, Qt.MouseButton.LeftButton)
                else:
                    active.reject()

        dialog_timer = QTimer()
        dialog_timer.setInterval(10)
        dialog_timer.timeout.connect(respond_to_actual_dialog)
        dialog_timer.start()
        window._attach_pid(oracle["pid"])
        pump_until(lambda: window.probe.pid == oracle["pid"] and not window.probe.pending and
                   bridge.target is not None and bridge.target[0] == oracle["pid"])
        require(abs(bridge.target[1] - created) < .000001 and not bridge.has_session,
                "GUI_SELECTION_DID_NOT_PRESERVE_ACTUAL_OBSERVER_INSTANCE")

        def click(operation, section, *, consent=None, statuses=("COMPLETED",)):
            panel.section.setCurrentIndex(panel.section.findData(section))
            app.processEvents()
            button = panel._action_buttons[operation]
            scroll = window.stack.currentWidget()
            require(isinstance(scroll, QScrollArea), "GUI_ACTION_PAGE_NOT_SCROLLABLE")
            scroll.ensureWidgetVisible(button)
            app.processEvents()
            require(button.isEnabled() and button.isVisible(), "GUI_ACTION_NOT_AVAILABLE_" + operation)
            first_result = len(results)
            dialog_plan.update(operation=operation if consent is not None else None,
                               decision=consent, answered=False)
            QTest.mouseClick(button, Qt.MouseButton.LeftButton)
            if consent is not None:
                require(dialog_plan["answered"], "ACTUAL_GUI_CONFIRMATION_DIALOG_NOT_OBSERVED")
            dialog_plan["operation"] = None
            require(not proof["unexpected_dialogs"], "UNEXPECTED_GUI_DIALOG")
            if consent is False:
                QTest.qWait(100)
                require(len(results) == first_result and not bridge.busy,
                        "CANCELLED_GUI_CONFIRMATION_STARTED_NATIVE_ACTION")
                proof["actions"].append({"operation": operation, "confirmation_cancelled": True,
                                          "native_action_started": False})
                return None
            pump_until(lambda: len(results) > first_result and bridge.worker is None)
            result = results[-1]
            require(result.get("operation") == operation and result.get("status") in statuses,
                    "GUI_NATIVE_ACTION_FAILED_" + operation + ":" +
                    str(result.get("error") or result.get("reason") or result.get("status")))
            require(result.get("target", {}).get("pid") == oracle["pid"] and
                    result["target"]["created_100ns"] == oracle["created_100ns"],
                    "GUI_RESULT_NOT_BOUND_TO_EXACT_NATIVE_TARGET")
            require(result["status"] in panel.status_label.text(), "GUI_STATUS_DID_NOT_DISPLAY_ACTUAL_RESULT")
            proof["actions"].append(journal_metadata(result))
            return result

        modules = click("modules", "modules", statuses=("COMPLETED", "INCOMPLETE_EVIDENCE"))
        require(any(row["base"] <= oracle["function_address"] < row["base"] + row["size"]
                    for row in modules["data"]["rows"]), "GUI_MODULES_MISSING_CONTROLLED_CODE")
        require(panel._tables["modules"].rowCount() > 0, "GUI_MODULE_TABLE_EMPTY")
        require(window.grab().save(str(output / "actual-modules.png"), "PNG"), "GUI_MODULE_SCREENSHOT_FAILED")
        threads = click("threads", "threads", statuses=("COMPLETED", "INCOMPLETE_EVIDENCE"))
        require(any(row["tid"] == oracle["wait_tid"] and row["created_100ns"] == oracle["wait_thread_created_100ns"]
                    for row in threads["data"]["rows"]), "GUI_THREADS_MISSING_EXACT_CONTROLLED_THREAD")
        require(panel._tables["threads"].rowCount() > 0, "GUI_THREAD_TABLE_EMPTY")
        panel.memory_address.setText(hex(oracle["buffer_address"]))
        panel.memory_size.setValue(64)
        read = click("memory_read", "memory")
        require(read["data"]["hex"] == oracle["buffer_hex"], "GUI_MEMORY_READ_DIFFERS_FROM_NATIVE_ORACLE")
        require(any(oracle["buffer_hex"] in panel._tables["memory"].item(row, column).text()
                    for row in range(panel._tables["memory"].rowCount())
                    for column in range(panel._tables["memory"].columnCount())
                    if panel._tables["memory"].item(row, column) is not None),
                "GUI_MEMORY_BYTES_NOT_RENDERED")
        changed = bytes(i ^ 0xA5 for i in range(64)).hex()
        panel.expected_bytes.setText(oracle["buffer_hex"])
        panel.new_bytes.setText(changed)
        click("memory.write", "memory", consent=False)
        require(probe.state()["buffer_hex"] == oracle["buffer_hex"], "GUI_CANCEL_CHANGED_NATIVE_MEMORY")
        written = click("memory.write", "memory", consent=True)
        require(probe.state()["buffer_hex"] == changed and panel.write_id.text() == written["data"]["change_id"],
                "GUI_WRITE_OR_RECORDED_CHANGE_ID_NOT_CONFIRMED")
        click("memory.rollback", "memory", consent=True)
        require(probe.state()["buffer_hex"] == oracle["buffer_hex"], "GUI_ROLLBACK_NOT_CONFIRMED_BY_TARGET")
        click("memory.write", "memory", consent=True)
        require(probe.state()["buffer_hex"] == changed, "GUI_CLOSE_RECOVERY_PRECONDITION_NOT_ESTABLISHED")
        require(len(services) == 1 and services[0][1] != threading.get_ident(), "GUI_CONSTRUCTED_SERVICE_ON_EVENT_THREAD")
        service = services[0][0]
        helper_process = psutil.Process(service.helper_pid)
        proof["helper_pid"] = helper_process.pid
        proof["helper_created"] = helper_process.create_time()
        before_close = probe.state()
        window.close()
        pump_until(lambda: bool(closed) and not bridge.has_session and not window.isVisible(), timeout=50)
        require(closed[-1].get("status") == "COMPLETED" and not proof["unexpected_dialogs"],
                "GUI_CLOSE_DID_NOT_CONFIRM_DIAGNOSTIC_CLEANUP")
        require(not helper_process.is_running(), "GUI_CLOSE_LEFT_DIAGNOSTIC_HELPER_RUNNING")
        require(probe.state()["buffer_hex"] == oracle["buffer_hex"], "GUI_CLOSE_DID_NOT_RESTORE_OWNED_BYTES")
        probe.progress(before_close)
        require(pulse_state["ticks"] >= 2 and pulse_state["max_gap_seconds"] < 2,
                "GUI_EVENT_LOOP_PROGRESS_NOT_CONFIRMED")
        export_path = output / "diagnostic-metadata.jsonl"
        exported = service.export_journal(export_path)
        require(exported.get("status") == "COMPLETED", "GUI_REAL_JOURNAL_EXPORT_FAILED")
        proof["journal"] = verify_action_journal(output / "journal/deep-inspection.sqlite3", export_path,
            results, forbidden_payloads=(oracle["buffer_hex"], changed))
        require(proof["journal"]["cleanup_records"] >= 1, "GUI_HELPER_CLEANUP_NOT_RECORDED")
        proof.update(status="PASS", event_loop=pulse_state, diagnostic_close=journal_metadata(closed[-1]),
                     helper_exit_verified=True, target_survival_verified=True,
                     own_memory_restored_on_close_verified=True, cancelled_confirmation_left_memory_unchanged=True,
                     ordinary_recording_started=False)
    except BaseException as error:
        proof.update(status="FAIL", error=type(error).__name__, reason=str(error)[:1500],
                     failure_traceback=traceback.format_exc(limit=10))
    finally:
        if window is not None:
            try:
                window.close()
                pump_until(lambda: not window.deep_inspector_panel.bridge.has_session and not window.isVisible(), timeout=30)
            except BaseException as error:
                proof.update(status="FAIL", cleanup_error=str(error)[:1000])
        for timer in (pulse, dialog_timer):
            if timer is not None:
                timer.stop()
        if probe is not None:
            try:
                proof["target_cleanup"] = probe.close(kill=proof["status"] != "PASS")
            except BaseException as error:
                proof.update(status="FAIL", target_cleanup_error=str(error)[:1000])
        save(output / "gui-e2e.json", proof)
    print("DEEP_GUI_E2E_" + proof["status"], proof.get("reason", ""), flush=True)
    return 0 if proof["status"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--helper", type=Path)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
