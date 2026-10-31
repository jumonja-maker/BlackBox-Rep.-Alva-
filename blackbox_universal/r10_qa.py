"""Explicit hosted-runner R10 GUI acceptance, including the actual frozen GUI.

Only owned fixture processes are selected. Dialogs are answered through Qt;
only file pickers receive controlled paths. The production elevation broker,
IPC, native operations, observer, Investigation 3 and report workers execute.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import queue
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
from unittest.mock import patch

from PySide6.QtCore import QPoint, Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox, QPushButton, QScrollArea, QWidget

from blackbox_core.deep_journal import journal_metadata
from blackbox_core.optional_jobs import OwnedProcess
from .provenance import source_identity
from .theme import font_coverage


def _require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def _digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _query_elevated_token(pid):
    """Read Windows' real helper token separately from its IPC assertion."""
    import ctypes as C
    from ctypes import wintypes as W
    kernel = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    advapi = C.WinDLL("advapi32", use_last_error=True, winmode=0x800)
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    kernel.OpenProcess.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    kernel.CloseHandle.restype = W.BOOL
    advapi.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
    advapi.OpenProcessToken.restype = W.BOOL
    advapi.GetTokenInformation.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)]
    advapi.GetTokenInformation.restype = W.BOOL
    process, token = kernel.OpenProcess(0x1000, False, pid), W.HANDLE()
    _require(process, "R10_HELPER_PROCESS_QUERY")
    try:
        _require(advapi.OpenProcessToken(process, 8, C.byref(token)), "R10_HELPER_TOKEN_QUERY")
        elevated, needed = W.DWORD(), W.DWORD()
        _require(advapi.GetTokenInformation(token, 20, C.byref(elevated), C.sizeof(elevated), C.byref(needed)),
                 "R10_HELPER_TOKEN_INFORMATION")
        return {"pid": pid, "elevated": bool(elevated.value),
                "source": "INDEPENDENT_OPEN_PROCESS_TOKEN_GET_TOKEN_INFORMATION"}
    finally:
        if token:
            kernel.CloseHandle(token)
        kernel.CloseHandle(process)


class _OwnedFixture:
    """Small independent control oracle for the prebuilt owned C workload."""

    def __init__(self, executable, output):
        output.mkdir(parents=True)
        self.log = (output / "stderr.log").open("wb")
        self.owner = OwnedProcess([str(executable), str(output / "controlled-io.bin")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, detach_console=True)
        self.process = self.owner.process
        self.lines = queue.Queue(maxsize=32)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        try:
            self.ready = self.receive("ready")
            _require(self.ready["pid"] == self.process.pid and self.ready["created_100ns"] > 0,
                     "R10_OWNED_FIXTURE_IDENTITY_REQUIRED")
        except BaseException:
            self.close(False)
            raise

    def _read(self):
        try:
            while True:
                line = self.process.stdout.readline(16385)
                if not line:
                    self.lines.put_nowait(EOFError("R10_FIXTURE_EXITED"))
                    return
                _require(len(line) <= 16384 and line.endswith(b"\n"), "R10_FIXTURE_RESPONSE_BOUND")
                self.lines.put_nowait(json.loads(line))
        except BaseException as error:
            try:
                self.lines.put_nowait(error)
            except queue.Full:
                pass

    def receive(self, kind):
        answer = self.lines.get(timeout=15)
        if isinstance(answer, BaseException):
            raise answer
        _require(type(answer) is dict and answer.get("kind") == kind, "R10_FIXTURE_PROTOCOL")
        return answer

    def command(self, command):
        _require(command in ("state", "stop"), "R10_FIXTURE_COMMAND_SCOPE")
        self.process.stdin.write((command + "\n").encode("ascii"))
        self.process.stdin.flush()
        return self.receive("stopped" if command == "stop" else command)

    def close(self, success):
        try:
            if success:
                state = self.command("stop")
                self.process.wait(timeout=10)
                _require(self.process.returncode == 0, "R10_FIXTURE_GRACEFUL_EXIT")
                _require(state["buffer_hex"] == self.ready["buffer_hex"], "R10_FINAL_MEMORY_RESTORE")
                return {"status": "COMPLETED", "identity": {
                    "pid": state["pid"], "created_100ns": state["created_100ns"]},
                    "memory_restored": True, "exit_code": self.process.returncode}
            return {"status": "FAILURE_CLEANUP"}
        finally:
            self.owner.close(kill=True)
            for stream in (self.process.stdin, self.process.stdout):
                if stream:
                    stream.close()
            self.reader.join(timeout=2)
            self.log.close()


def run_r10_e2e(app, window, output, probe_executable, expected_sha):
    """Return a failure exit unless every required real GUI postcondition holds."""
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    proof = {"status": "RUNNING", "scope": "R10_REAL_QT_TWO_TARGET_ONE_UAC",
        "frozen": bool(getattr(sys, "frozen", False)), "gui_pid": os.getpid(),
        "secure_desktop": "NOT_TESTED", "physical_windows_10_11": "NOT_TESTED",
        "dpi_mode": "QT_SCALE_FACTOR_SIMULATION", "scale": os.environ.get("QT_SCALE_FACTOR", "1"),
        "actions": [], "confirmations": [], "geometry": [], "targets": [], "launches": []}
    fixtures, services, results, closed, graph_results = [], [], [], [], []
    timers = []
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="r10-independent-oracle")
    dialog_plan = {"kind": None, "accept": True, "pid": None, "created": None, "answered": False}
    app.setQuitOnLastWindowClosed(False)
    bridge = window.deep_inspector_panel.bridge
    panel = window.deep_inspector_panel
    graph = window.investigation_graph_panel
    initial_helper = None

    def closure_state():
        # Cached owner state only: diagnostic logging must never take a busy
        # service lock or send another command on a worker-owned IPC channel.
        worker = bridge.worker
        reader = graph.bridge.worker
        service = services[0] if services else None
        helper = service.helper if service is not None else None
        return {"window_visible": window.isVisible(), "pending_close": window._pending_close,
            "deep_close_complete": window._deep_close_complete, "graph_close_pending": window._graph_close_pending,
            "bridge": {"has_session": bridge.has_session, "busy": bridge.busy,
                "closing": bridge._closing, "reset_pending": bridge._reset_pending,
                "cleanup_required": bridge.cleanup_required, "admin_state": bridge.admin_state,
                "worker_kind": worker.command.get("kind") if worker is not None else None,
                "worker_generation": worker.command.get("generation") if worker is not None else None,
                "generation": bridge.generation,
                "worker_running": worker.isRunning() if worker is not None else False,
                "queued_kind": (bridge._queued_command or {}).get("kind"),
                "last_close_result": journal_metadata(bridge._close_result)},
            "graph": {"busy": graph.bridge.busy, "worker_operation": reader.operation if reader is not None else None,
                "closing": graph._closing, "closing_for_window": graph._closing_for_window,
                "queued_records": len(graph._record_queue), "deferred_checkpoint": graph._deferred_checkpoint,
                "deferred_actions": graph._deferred_action_refresh},
            "observer": {"alive": window.probe.alive, "active": window.probe.active,
                "pending": window.probe.pending, "stopping": window.probe.stopping,
                "closing": window.probe.closing, "action_state": window.probe.actions.state,
                "error": window.probe.last_error, "pid": window.probe.pid,
                "pending_operations": list(window.probe._pending.values())[:64],
                "stop_deadline": window.probe._stop_deadline, "last_response": window.probe.last_response,
                "process_state": window.probe.process.state().name,
                "stderr_tail": window.probe._stderr[-2000:]},
            "service": {"helper_pid": helper.pid if helper is not None else None,
                "helper_alive": helper.alive() if helper is not None else False,
                "admin_state": service._admin_state if service is not None else None,
                "owner_retained": service._owner_retained if service is not None else None,
                "cleanup_unconfirmed": service._cleanup_unconfirmed if service is not None else None,
                "interventions_started": service._interventions_started if service is not None else None},
            "close_signals": len(closed), "unexpected_dialogs": proof.get("unexpected_dialogs", [])[-4:]}

    def lifecycle_signal(name, result=None):
        events = proof.setdefault("lifecycle_signals", [])
        if len(events) < 64:
            events.append({"signal": name, "monotonic": time.monotonic(), "result": journal_metadata(result)})

    def log_closure_state():
        if proof.get("phase") != "GUI_CLOSE_HELPER_EXIT_AND_VERIFIED_NATIVE_RESTORE":
            return
        snapshot = closure_state()
        history = proof.setdefault("close_progress", [])
        if len(history) < 80:
            history.append(snapshot)
        print("R10_GUI_CLOSE_STATE " + json.dumps(snapshot, ensure_ascii=False), flush=True)

    def pump(predicate, timeout=50):
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline:
            app.processEvents()
            QTest.qWait(5)
        app.processEvents()
        _require(predicate(), "R10_GUI_DEADLINE:" + str(proof.get("phase")))

    def oracle(fixture):
        future = executor.submit(fixture.command, "state")
        pump(future.done, timeout=20)
        return future.result()

    def record_phase(name):
        proof["phase"] = name
        (output / "progress.json").write_text(json.dumps({"phase": name}), encoding="utf-8")
        print("R10_GUI_PHASE " + name, flush=True)

    def answer_dialog():
        dialog = QApplication.activeModalWidget()
        if dialog is None:
            return
        if not isinstance(dialog, QMessageBox) or dialog_plan["kind"] is None or dialog_plan["answered"]:
            proof.setdefault("unexpected_dialogs", []).append(dialog.windowTitle())
            dialog.reject()
            return
        cancel = dialog.button(QMessageBox.StandardButton.Cancel)
        valid = cancel is not None and dialog.defaultButton() is cancel
        if dialog_plan["pid"] is not None:
            valid = valid and ("PID " + str(dialog_plan["pid"])) in dialog.text()
        if dialog_plan["created"] is not None:
            valid = valid and str(dialog_plan["created"]) in dialog.text()
        proof["confirmations"].append({"kind": dialog_plan["kind"], "target_pid": dialog_plan["pid"],
            "accepted": dialog_plan["accept"], "actual_qt_dialog": True, "cancel_is_default": valid,
            "text_sha256": hashlib.sha256(dialog.text().encode("utf-8")).hexdigest()})
        dialog_plan["answered"] = True
        if not valid or not dialog_plan["accept"]:
            if not valid:
                proof.setdefault("unexpected_dialogs", []).append("CONSENT_IDENTITY_OR_DEFAULT")
            if cancel is not None:
                cancel.click()
            else:
                dialog.reject()
            return
        choices = [button for button in dialog.buttons()
                   if dialog.buttonRole(button) in (QMessageBox.ButtonRole.AcceptRole, QMessageBox.ButtonRole.YesRole)]
        if len(choices) != 1:
            proof.setdefault("unexpected_dialogs", []).append("CONSENT_BUTTON_AMBIGUOUS")
            dialog.reject()
        else:
            QTest.mouseClick(choices[0], Qt.MouseButton.LeftButton)

    def click(widget, *, kind=None, pid=None, created=None, accept=True):
        scroll = window.stack.currentWidget()
        if isinstance(scroll, QScrollArea) and widget is not window.admin_button:
            scroll.ensureWidgetVisible(widget)
        app.processEvents()
        _require(widget.isVisible() and widget.isEnabled(), "R10_GUI_BUTTON_UNAVAILABLE:" + widget.objectName())
        dialog_plan.update(kind=kind, accept=accept, pid=pid, created=created, answered=False)
        QTest.mouseClick(widget, Qt.MouseButton.LeftButton)
        if kind:
            _require(dialog_plan["answered"], "R10_EXPECTED_ACTUAL_CONFIRMATION")
        dialog_plan["kind"] = None
        _require(not proof.get("unexpected_dialogs"), "R10_UNEXPECTED_DIALOG")

    def geometry(state):
        for language in ("RU", "EN"):
            window._set_language(language)
            app.processEvents()
            body = window.findChild(QWidget, "shellBody")
            top = body.mapTo(window.centralWidget(), QPoint()).y()
            button = window.admin_button
            rectangle = button.rect()
            label_width = button.fontMetrics().horizontalAdvance(button.text())
            _require(top <= 145, "R10_TOP_BAR_HEIGHT")
            _require(button.isVisible() and rectangle.width() >= label_width + 12, "R10_ADMIN_TEXT_CLIPPED")
            _require(button.geometry().height() >= button.fontMetrics().height() + 4, "R10_ADMIN_GLYPHS_CLIPPED")
            for sibling in (window.admin_button.parentWidget().findChildren(QWidget, options=Qt.FindChildOption.FindDirectChildrenOnly)):
                if sibling is not button and sibling.isVisible() and sibling.geometry().isValid():
                    _require(not button.geometry().intersects(sibling.geometry()), "R10_ADMIN_OVERLAP:" + sibling.objectName())
            shot = output / ("toolbar-" + state + "-" + language + ".png")
            _require(window.grab().save(str(shot), "PNG"), "R10_SCREENSHOT_WRITE")
            proof["geometry"].append({"language": language, "state": state, "workspace_top_y": top,
                "button": [button.x(), button.y(), button.width(), button.height()],
                "screenshot_sha256": _digest(shot), "text_fits": True})
        window._set_language("EN")

    def action(operation, fixture, *, confirm=False, allow_binding=True):
        panel.section.setCurrentIndex(panel.section.findData("memory"))
        panel.memory_address.setText(hex(fixture.ready["buffer_address"]))
        panel.memory_size.setValue(64)
        first = len(results)
        click(panel._action_buttons[operation], kind=operation if confirm else None, pid=fixture.ready["pid"] if confirm else None)
        pump(lambda: bridge.worker is None and len(results) > first)
        answer = results[-1]
        if allow_binding and answer.get("status") == "CONFIRMATION_REQUIRED":
            _require(answer.get("next_action") == "AUTHORIZE_TARGET_AND_OPERATION_SCOPE" or
                     answer.get("data", {}).get("next_action") == "AUTHORIZE_TARGET_AND_OPERATION_SCOPE",
                     "R10_TARGET_BINDING_REASON_REQUIRED")
            first = len(results)
            click(panel.elevate_button, kind="target_scope", pid=fixture.ready["pid"], created=fixture.ready["created_100ns"])
            pump(lambda: bridge.worker is None and len(results) > first and
                 results[-1].get("operation") == operation, timeout=60)
            answer = results[-1]
        _require(answer.get("operation") == operation and answer.get("status") == "COMPLETED",
                 "R10_NATIVE_GUI_ACTION:" + operation + ":" + str(answer.get("status")) + ":" + str(answer.get("error")))
        _require(answer.get("target", {}).get("pid") == fixture.ready["pid"] and
                 answer["target"]["created_100ns"] == fixture.ready["created_100ns"], "R10_GUI_RESULT_EXACT_FILETIME")
        receipt = answer.get("run_receipt", {})
        _require(receipt.get("contract_version") == 1 and receipt.get("status") == answer["status"] and
                 receipt.get("execution_started") is True and receipt.get("source", {}).get("verified") is True and
                 receipt.get("source", {}).get("helper_pid") == initial_helper["helper_pid"] and
                 receipt.get("target", {}).get("verified") is True and
                 receipt.get("target", {}).get("identity") == answer["target"], "R10_REAL_NATIVE_TOOL_RECEIPT")
        proof["actions"].append(journal_metadata(answer))
        status = services[0].session_status()
        _require(status["helper_identity"] == initial_helper["helper_identity"] and
                 status["session_deadline_monotonic"] == initial_helper["session_deadline_monotonic"],
                 "R10_HELPER_RELAUNCH_OR_LEASE_EXTENSION")
        return answer

    def build_case(sources):
        before = len(graph_results)
        graph.open_case_context(sources)
        click(graph.build_button)
        pump(lambda: any(row[0] == "build" for row in graph_results[before:]) and not graph.bridge.busy, timeout=100)
        built = next(row for row in graph_results[before:] if row[0] == "build")
        _require(graph.case is not None and built[2] == "", "R10_INV3_BUILD:" + built[2])
        return graph.case, graph.index_path

    try:
        _require(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true" and
                 os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "R10_HOSTED_WINDOWS_ONLY")
        proof.update(source_identity(expected_sha))
        _require(proof["source_identity_status"] == "VERIFIED_EXPECTED_HEAD", "R10_EXACT_SOURCE_REQUIRED")
        proof["font_coverage"] = font_coverage(app)
        _require(proof["font_coverage"]["ok"], "R10_RU_EN_GLYPHS")
        executable = Path(probe_executable).resolve(strict=True)
        proof["fixture_sha256"] = _digest(executable)
        for label in ("A", "B"):
            fixture = _OwnedFixture(executable, output / ("target-" + label))
            fixtures.append(fixture)
            proof["targets"].append({"label": label, "pid": fixture.ready["pid"],
                "created_100ns": fixture.ready["created_100ns"]})
        _require(fixtures[0].ready["pid"] != fixtures[1].ready["pid"], "R10_TWO_DISTINCT_TARGETS")
        from blackbox_core.deep_service import InspectorService

        def service_factory():
            service = InspectorService(journal_root=output / "journal")
            original_launch = service.broker.launch

            def production_launch(arguments, *, elevated=False):
                # This is an observer around the real broker, with no substituted result.
                helper = original_launch(arguments, elevated=elevated)
                proof["launches"].append({"elevated": elevated, "pid": helper.pid,
                    "path": "PRODUCTION_SHELLEXECUTEEXW_RUNAS" if elevated else "PRODUCTION_STANDARD_HELPER"})
                return helper

            service.broker.launch = production_launch
            services.append(service)
            return service

        bridge._factory = service_factory
        bridge.result_ready.connect(results.append)
        bridge.closed.connect(closed.append)
        bridge.closed.connect(lambda result: lifecycle_signal("diagnostic.closed", result))
        bridge.recovery_required.connect(lambda result: lifecycle_signal("diagnostic.recovery_required", result))
        graph.closed.connect(lambda: lifecycle_signal("investigation.closed"))
        window.probe.terminated.connect(lambda: lifecycle_signal("observer.terminated"))
        graph.bridge.result_ready.connect(lambda *args: graph_results.append(args))
        dialog_timer = QTimer()
        dialog_timer.setInterval(10)
        dialog_timer.timeout.connect(answer_dialog)
        dialog_timer.start()
        timers.append(dialog_timer)
        close_timer = QTimer()
        close_timer.setInterval(1000)
        close_timer.timeout.connect(log_closure_state)
        close_timer.start()
        timers.append(close_timer)
        window.resize(1330, 850)
        window.showNormal()
        app.processEvents()
        geometry("inactive")
        record_phase("TOP_ADMIN_BUTTON_BEFORE_TARGET")
        _require(bridge.target is None and not bridge.has_session, "R10_ADMIN_MUST_START_WITHOUT_TARGET")
        click(window.admin_button, kind="start_admin", accept=False)
        _require(not services, "R10_CANCEL_STARTED_HELPER")
        click(window.admin_button, kind="start_admin")
        pump(lambda: len(services) == 1 and not bridge.busy and bridge.admin_active, timeout=60)
        initial_helper = services[0].session_status()
        _require(initial_helper.get("elevated_verified") is True and initial_helper.get("helper_identity", {}).get("created_100ns", 0) > 0,
                 "R10_REAL_HELPER_TOKEN_AND_FILETIME")
        _require(initial_helper["target"] is None and len(proof["launches"]) == 1 and proof["launches"][0]["elevated"],
                 "R10_EXACTLY_ONE_UNBOUND_ELEVATED_LAUNCH")
        proof["initial_admin_session"] = initial_helper
        proof["independent_helper_token"] = _query_elevated_token(initial_helper["helper_pid"])
        _require(proof["independent_helper_token"]["elevated"], "R10_HELPER_NOT_ACTUALLY_ELEVATED")
        geometry("active")
        sessions = []
        cases = []
        for number, fixture in enumerate(fixtures):
            record_phase("TARGET_" + str(number) + "_OBSERVE_AND_NATIVE_ACTIONS")
            window._navigate("dashboard")
            window._attach_pid(fixture.ready["pid"])
            pump(lambda: window.probe.pid == fixture.ready["pid"] and not window.probe.pending and
                 not bridge.busy and bridge.target is not None and bridge.target[0] == fixture.ready["pid"])
            if number:
                _require(oracle(fixtures[0])["buffer_hex"] == fixtures[0].ready["buffer_hex"], "R10_SWITCH_DID_NOT_RESTORE_A")
                proof["target_switch_cleanup_independent_readback"] = True
            click(window.start_btn)
            pump(lambda: window.probe.active and window.probe.total_samples >= 2, timeout=35)
            click(window.stop_btn)
            pump(lambda: not window.probe.active and not window.probe.pending and window.probe.session_folder is not None and
                 (Path(window.probe.session_folder) / "report.json").is_file(), timeout=50)
            folder = Path(window.probe.session_folder)
            sessions.append(folder)
            db = sqlite3.connect("file:" + (folder / "session.sqlite3").as_posix() + "?mode=ro", uri=True)
            try:
                _require(db.execute("SELECT count(*) FROM samples").fetchone()[0] >= 2, "R10_OBSERVE_SQLITE_INDEPENDENT_READBACK")
            finally:
                db.close()
            if not panel.isVisible():
                click(window.deep_inspector_toggle)
            read = action("memory_read", fixture)
            _require(read["data"]["hex"] == fixture.ready["buffer_hex"], "R10_GUI_READ_ORACLE")
            changed = bytes(i ^ (0xA5 + number) for i in range(64)).hex()
            panel.expected_bytes.setText(fixture.ready["buffer_hex"])
            panel.new_bytes.setText(changed)
            before = len(results)
            click(panel._action_buttons["memory.write"], kind="memory.write", pid=fixture.ready["pid"], accept=False)
            _require(len(results) == before and oracle(fixture)["buffer_hex"] == fixture.ready["buffer_hex"],
                     "R10_CANCELLED_NATIVE_CONFIRMATION_CHANGED_MEMORY")
            action("memory.write", fixture, confirm=True)
            _require(oracle(fixture)["buffer_hex"] == changed, "R10_NATIVE_WRITE_INDEPENDENT_READBACK")
            action("memory.rollback", fixture, confirm=True)
            _require(oracle(fixture)["buffer_hex"] == fixture.ready["buffer_hex"], "R10_NATIVE_ROLLBACK_INDEPENDENT_READBACK")
            action("memory.write", fixture, confirm=True)
            _require(oracle(fixture)["buffer_hex"] == changed, "R10_CLEANUP_OWNS_PENDING_WRITE")
            sources = [{"source_type": "SESSION", "path": str(folder)},
                       {"source_type": "DEEP_JOURNAL", "path": str(output / "journal/deep-inspection.sqlite3")}]
            cases.append(build_case(sources))
        record_phase("INVESTIGATION3_COMPARE_EXPORT_INDEPENDENT_READBACK")
        first_case, first_index = cases[0]
        second_case, _ = cases[1]
        graph.section.setCurrentIndex(graph.section.findData("recurrences"))
        before = len(graph_results)
        with patch("blackbox_universal.investigation_graph_panel.QFileDialog.getOpenFileName",
                   return_value=(str(first_index), "Investigation index (*.sqlite3)")):
            click(graph.findChild(QPushButton, "invCompareCases"))
        pump(lambda: not graph.bridge.busy and any(row[0] == "compare_cases" for row in graph_results[before:]), timeout=100)
        compared = next(row for row in graph_results[before:] if row[0] == "compare_cases")
        _require(not compared[2], "R10_INV3_COMPARISON:" + compared[2])
        comparison = compared[1]["comparison"]
        export = output / "r10-investigation.json"
        before = len(graph_results)
        with patch("blackbox_universal.investigation_graph_panel.QFileDialog.getSaveFileName",
                   return_value=(str(export), "JSON (*.json)")):
            click(graph.export_button)
        pump(lambda: not graph.bridge.busy and any(row[0] == "export" for row in graph_results[before:]) and export.is_file(), timeout=100)
        exported = json.loads(export.read_text(encoding="utf-8"))
        _require(exported["case_id"] == second_case["case_id"] and exported.get("nodes") and exported.get("sources"),
                 "R10_INV3_EXPORT_READBACK")
        raw = export.read_text(encoding="utf-8")
        _require(all(fixture.ready["buffer_hex"] not in raw for fixture in fixtures), "R10_EXPORT_CONTAINS_PRIVATE_MEMORY")
        proof["investigation"] = {"before_case_id": first_case["case_id"], "after_case_id": second_case["case_id"],
            "comparison": comparison, "export_sha256": _digest(export), "independent_json_readback": True}
        proof["observation_reports"] = [{name: _digest(folder / name) for name in ("session.sqlite3", "report.json", "report.html")} for folder in sessions]
        _require(len(services) == 1 and len(proof["launches"]) == 1, "R10_SECOND_RUNAS_OR_HELPER_LAUNCH")
        proof["final_admin_session"] = services[0].session_status()
        record_phase("GUI_CLOSE_HELPER_EXIT_AND_VERIFIED_NATIVE_RESTORE")
        import psutil
        helper_process = psutil.Process(initial_helper["helper_pid"])
        window.close()
        log_closure_state()
        pump(lambda: closed and not bridge.has_session and not window.isVisible(), timeout=60)
        _require(closed[-1].get("status") == "COMPLETED" and not helper_process.is_running(), "R10_CLOSE_HELPER_EXIT")
        for fixture in fixtures:
            _require(oracle(fixture)["buffer_hex"] == fixture.ready["buffer_hex"], "R10_CLOSE_NATIVE_RESTORE")
        proof["close"] = {"status": "COMPLETED", "helper_exit_verified": True, "both_targets_memory_restored": True,
                          "diagnostic_result": journal_metadata(closed[-1])}
        proof["status"] = "PASS"
    except BaseException as error:
        proof.update(status="FAIL", reason=str(error)[:2000], traceback=traceback.format_exc(limit=12))
        proof["failure_state"] = closure_state()
    finally:
        if window.isVisible() or bridge.has_session:
            try:
                window.close()
                pump(lambda: not bridge.has_session and not window.isVisible(), timeout=45)
            except BaseException as error:
                proof.update(status="FAIL", cleanup_error=str(error)[:1000])
                proof["final_cleanup_state"] = closure_state()
        for timer in timers:
            timer.stop()
        for fixture in fixtures:
            try:
                proof.setdefault("fixture_cleanup", []).append(fixture.close(proof["status"] == "PASS"))
            except BaseException as error:
                proof.update(status="FAIL", fixture_cleanup_error=str(error)[:1000])
        executor.shutdown(wait=True, cancel_futures=True)
        path = output / "r10-gui.json"
        path.write_text(json.dumps(proof, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")
        receipt = {"status": proof["status"], "source_sha": proof.get("actual_source_sha"),
            "frozen": proof["frozen"], "scale": proof["scale"], "receipt_sha256": _digest(path),
            "elevated_launches": sum(launch["elevated"] for launch in proof["launches"]),
            "targets": proof["targets"], "initial_admin_session": proof.get("initial_admin_session"),
            "final_admin_session": proof.get("final_admin_session"), "close": proof.get("close"),
            "reason": proof.get("reason"), "cleanup_error": proof.get("cleanup_error"),
            "failure_state": proof.get("failure_state"), "final_cleanup_state": proof.get("final_cleanup_state"),
            "lifecycle_signals": proof.get("lifecycle_signals"),
            "secure_desktop": "NOT_TESTED"}
        print("R10_GUI_RECEIPT " + json.dumps(receipt, ensure_ascii=False, allow_nan=False), flush=True)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with Path(summary).open("a", encoding="utf-8") as stream:
                stream.write("\n### R10 real GUI/helper receipt\n\n```json\n" + json.dumps(receipt, ensure_ascii=False, indent=2) + "\n```\n")
    return 0 if proof["status"] == "PASS" else 1
