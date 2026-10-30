"""Hosted Windows real Qt acceptance for the Investigation Engine 3 workspace.

Inputs are artifacts produced by qa_inv_native, never a substitute capture.
The source GUI may use the packaged diagnostic helper; that distinction and
unavailable physical Windows / Secure Desktop coverage are persisted explicitly.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
import traceback
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
from tools.qa_inv_common import (assert_sources_unchanged, digest, exact_source,
    graph_facts, require, require_hosted, save, validate_export)


def run(args):
    require_hosted(windows=True)
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    if args.dpi_scale:
        os.environ["QT_SCALE_FACTOR"] = args.dpi_scale
    import psutil
    from PySide6.QtCore import Qt, QTimer, QProcess
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication, QMessageBox, QScrollArea, QPushButton
    from blackbox_core.deep_journal import journal_metadata
    from blackbox_core.deep_service import InspectorService
    from blackbox_universal.decoder_window import DecoderWindow
    from blackbox_universal.theme import set_retro_theme
    from tools.qa_deep_inspection import Probe, build_probe

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    helper = args.diagnostic_helper.resolve(strict=True) if args.diagnostic_helper else None
    evidence_root = args.evidence_root.resolve(strict=True)
    proof = {"status": "RUNNING", "source_sha": exact_source(), "scenario": "H",
        "scope": "SOURCE_GUI_REAL_QT_GRAPH_AND_OWNED_NATIVE_INTERVENTION",
        "gui_form": "PYTHON_SOURCE_NOT_FROZEN_GUI",
        "diagnostic_helper_form": "FROZEN_ONEDIR" if helper else "PYTHON_SOURCE",
        "physical_windows_10_11": "NOT_TESTED", "secure_desktop": "NOT_TESTED",
        "qt_platform": os.environ["QT_QPA_PLATFORM"],
        "requested_dpi_scale": os.environ.get("QT_SCALE_FACTOR", "1"),
        "layout_only": args.layout_only, "confirmations": [], "unexpected_dialogs": [],
        "native_steps": [], "sections": [], "screenshots": []}
    app = window = probe = pulse = dialog_timer = executor = None
    deep_closed, graph_closed, native_results, services = [], [], [], []
    dialog_plan = {"operation": None, "decision": None, "answered": False}
    context_plan = {"pending": False, "answered": False}
    pulse_state = {"ticks": 0, "last": None, "max_gap_seconds": 0.0}
    proof["event_loop"] = pulse_state
    input_hashes = {}
    successful = False

    def phase(name):
        proof["phase"] = name
        save(output / "gui-investigation-qa.json", proof)
        print("INV_GUI_PHASE " + name, flush=True)

    def pump_until(predicate, *, timeout=90):
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline:
            app.processEvents()
            QTest.qWait(5)
        app.processEvents()
        require(predicate(), "INV_GUI_ACTION_OR_CLEANUP_DEADLINE_" + proof.get("phase", "UNKNOWN"))

    def oracle_call(method, *arguments):
        future = executor.submit(method, *arguments)
        pump_until(future.done, timeout=30)
        return future.result()

    def idle():
        panel = window.investigation_graph_panel
        return (panel.bridge.worker is None and window.deep_inspector_panel.bridge.worker is None and
                panel._pending_native is None and not panel._record_queue and
                not panel._deferred_action_refresh and not panel._deferred_checkpoint)

    def reveal(widget):
        scroll = window.stack.currentWidget()
        require(isinstance(scroll, QScrollArea), "INV_WORKSPACE_MUST_REMAIN_IN_SCROLLABLE_OVERVIEW")
        scroll.ensureWidgetVisible(widget)
        app.processEvents()
        require(widget.isVisible(), "INV_GUI_CONTROL_NOT_VISIBLE_" + widget.objectName())

    def click(widget, *, consent=None, operation=None):
        reveal(widget)
        require(widget.isEnabled(), "INV_GUI_CONTROL_DISABLED_" + widget.objectName())
        dialog_plan.update(operation=operation if consent is not None else None,
                           decision=consent, answered=False)
        QTest.mouseClick(widget, Qt.MouseButton.LeftButton)
        if consent is not None:
            require(dialog_plan["answered"], "INV_ACTUAL_CONFIRMATION_NOT_OBSERVED_" + str(operation))
        dialog_plan["operation"] = None
        require(not proof["unexpected_dialogs"], "INV_UNEXPECTED_MODAL_DIALOG")

    def select_section(key):
        panel = window.investigation_graph_panel
        index = panel.section.findData(key)
        require(index >= 0, "INV_SECTION_MISSING_" + key)
        reveal(panel.section)
        panel.section.setFocus()
        QTest.keyClick(panel.section, Qt.Key.Key_Home)
        for _ in range(index):
            QTest.keyClick(panel.section, Qt.Key.Key_Down)
        app.processEvents()
        require(panel.section.currentData() == key and panel.pages.currentIndex() == index,
                "INV_QT_SECTION_NAVIGATION_DID_NOT_SELECT_" + key)

    def choose_node(node):
        panel = window.investigation_graph_panel
        select_section("events")
        index = next(i for i, row in enumerate(panel.case["nodes"]) if row["node_id"] == node["node_id"])
        page = index // panel.nodes_model.page_size
        while panel.nodes_model.offset < page * panel.nodes_model.page_size:
            click(panel.next_button)
        while panel.nodes_model.offset > page * panel.nodes_model.page_size:
            click(panel.previous_button)
        row = index - panel.nodes_model.offset
        table_index = panel.nodes_model.index(row, 0)
        reveal(panel.node_table)
        panel.node_table.scrollTo(table_index)
        app.processEvents()
        QTest.mouseClick(panel.node_table.viewport(), Qt.MouseButton.LeftButton,
                         pos=panel.node_table.visualRect(table_index).center())
        require(panel._selected_node_id == node["node_id"], "INV_ACTUAL_TABLE_NODE_SELECTION_FAILED")
        require(node["source_record_id"] in panel.details.toPlainText(), "INV_SELECTED_SOURCE_REFERENCE_NOT_VISIBLE")

    try:
        phase("READ_ACTUAL_NATIVE_EVIDENCE")
        manifest = json.loads((evidence_root / "native-investigation-qa.json").read_text())
        require(manifest.get("status") == "PASS" and manifest.get("source_sha") == proof["source_sha"],
                "INV_GUI_REQUIRES_PASSED_ACTUAL_NATIVE_EVIDENCE_AT_EXACT_HEAD")
        sources_file = evidence_root / "gui-sources.json"
        supplied = json.loads(sources_file.read_text())
        sources = supplied["sources"]
        for source in sources:
            path = Path(source["path"]).resolve(strict=True)
            input_hashes[str(path)] = digest(path)
        require(any(s["source_type"] == "DEEP_JOURNAL" for s in sources) and
                any(s["source_type"] == "EVENTS_JSONL" for s in sources),
                "INV_GUI_REQUIRES_ACTUAL_SDK_INCIDENT_AND_NATIVE_STACK_SOURCES")
        if helper:
            build_manifest = helper.parent / "_internal/blackbox-build.json"
            require(build_manifest.is_file() and build_manifest.stat().st_size <= 4096,
                    "INV_PACKAGED_HELPER_MANIFEST_MISSING")
            helper_build = json.loads(build_manifest.read_text())
            require(helper_build.get("source_sha") == proof["source_sha"] and
                    helper_build.get("tracked_worktree_clean") is True,
                    "INV_PACKAGED_HELPER_HEAD_MISMATCH")
            proof["diagnostic_helper_build"] = helper_build
            proof["diagnostic_helper_sha256"] = digest(helper)
        app = QApplication.instance() or QApplication([])
        app.setQuitOnLastWindowClosed(False)
        set_retro_theme(app)
        window = DecoderWindow(isolated=True, output_root=output / "sessions", allow_update_check=False)
        window.resize(1330, 850)
        window._set_language("EN")
        window.show()
        app.processEvents()
        deep, panel = window.deep_inspector_panel, window.investigation_graph_panel
        require(not deep.bridge.has_session, "INV_READING_GRAPH_STARTED_DIAGNOSTIC_SESSION")
        require(len(window._nav_buttons) == 6, "INV_EXISTING_SIX_MAIN_PAGES_CHANGED")
        for key, button in window._nav_buttons.items():
            QTest.mouseClick(button, Qt.MouseButton.LeftButton)
            app.processEvents()
            require(button.property("active") is True and window.stack.currentIndex() == window._page_ids[key],
                    "INV_EXISTING_MAIN_PAGE_NOT_REACHABLE_" + key)
        QTest.mouseClick(window._nav_buttons["dashboard"], Qt.MouseButton.LeftButton)
        reveal(window.deep_inspector_toggle)
        QTest.mouseClick(window.deep_inspector_toggle, Qt.MouseButton.LeftButton)
        click(deep._action_buttons["investigate_problem"])
        require(panel.isVisible() and not deep.bridge.has_session, "INV_WORKSPACE_NOT_LAZY")
        panel.bridge.closed.connect(lambda: graph_closed.append(True))
        deep.bridge.closed.connect(deep_closed.append)
        deep.bridge.result_ready.connect(native_results.append)
        panel.open_case_context(sources)

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
        phase("ACTUAL_QT_BUILD_AND_SOURCE_NAVIGATION")
        click(panel.build_button)
        pump_until(lambda: panel.case is not None and panel.bridge.worker is None, timeout=180)
        graph_facts(panel.case)
        proof["graph"] = {"case_id": panel.case["case_id"], "nodes": len(panel.case["nodes"]),
                          "edges": len(panel.case["edges"]), "coverage": panel.case["coverage"]}
        original_case_id = panel.case["case_id"]
        require(panel.nodes_model.rowCount() <= 100 and len(panel.graph.rendered_node_ids) <= 80,
                "INV_GUI_GRAPH_OR_TABLE_NOT_BOUNDED")
        select_section("graph")
        reveal(panel.graph)
        canvas_node = next((item for item in panel.graph.scene().items()
                            if isinstance(item.data(0), str)), None)
        require(canvas_node is not None, "INV_REAL_GRAPH_CANVAS_HAS_NO_SOURCE_NODE")
        panel.graph.ensureVisible(canvas_node)
        app.processEvents()
        QTest.mouseClick(panel.graph.viewport(), Qt.MouseButton.LeftButton,
            pos=panel.graph.mapFromScene(canvas_node.sceneBoundingRect().center()))
        require(panel._selected_node_id == canvas_node.data(0), "INV_GRAPH_CANVAS_CLICK_NOT_BOUND_TO_EVIDENCE")
        proof["graph_canvas_click"] = {"node_id": panel._selected_node_id, "actual_qt_pointer_event": True}
        actual_incident = next((node for node in panel.case["nodes"]
                                if node["observation_type"] == "INCIDENT" and node["source_type"] == "EVENTS_JSONL"), None)
        require(actual_incident is not None, "INV_ACTUAL_APPLICATION_FAILURE_INCIDENT_MISSING")
        choose_node(actual_incident)
        click(panel.related_button)
        pump_until(lambda: panel.bridge.worker is None)
        require(actual_incident["source_identity"] in panel.details.toPlainText(),
                "INV_RELATED_EVIDENCE_LOST_SOURCE_IDENTITY")
        click(panel.thread_button)
        require(panel._selected_node_id == actual_incident["node_id"] and "NOT_ESTABLISHED" in panel.status.text(),
                "INV_APP_INCIDENT_INVENTED_THREAD_IDENTITY_OR_CROSS_SOURCE_JOIN")
        click(panel.stack_button)
        require(panel._selected_node_id == actual_incident["node_id"],
                "INV_APP_INCIDENT_INVENTED_CAUSAL_STACK_LINK")
        proof["incident_route"] = {"incident_node_id": actual_incident["node_id"],
            "record_ref": actual_incident["source_record_id"],
            "source_authority": actual_incident["verification_class"],
            "incident_to_native_thread_or_stack": "NOT_ESTABLISHED_AS_EXPECTED",
            "synthetic_causal_join_used": False}
        stack = next((node for node in panel.case["nodes"] if node["source_type"] == "DEEP_JOURNAL" and
                      node["observation_type"] == "STACK" and node.get("metadata", {}).get("frames")), None)
        require(stack is not None, "INV_ACTUAL_SAVED_PSS_STACK_MISSING")
        choose_node(stack)
        click(panel.thread_button)
        thread_id = panel._selected_node_id
        thread = next(node for node in panel.case["nodes"] if node["node_id"] == thread_id)
        require(thread["observation_type"] == "THREAD" and thread["source_identity"] == stack["source_identity"],
                "INV_SAVED_PSS_STACK_DID_NOT_OPEN_ITS_NATIVE_THREAD")
        click(panel.stack_button)
        require(panel._node()["observation_type"] in ("STACK", "MODULE", "FUNCTION"),
                "INV_SAVED_THREAD_DID_NOT_OPEN_DIRECTLY_RELATED_STACK")
        proof["saved_native_navigation"] = {"thread_node_id": thread_id,
            "stack_node_id": panel._selected_node_id, "relation_to_application_failure": "NOT_ESTABLISHED"}
        hypothesis = next((h for h in panel.case["hypotheses"] if h["category"] == "FILE_OPERATION_ERROR"), None)
        require(hypothesis is not None and hypothesis["root_cause_proven"] is False,
                "INV_ACTUAL_INCIDENT_HYPOTHESIS_MISSING_OR_CAUSALITY_OVERCLAIMED")
        select_section("hypotheses")
        row = next(i for i, item in enumerate(panel._models["hypotheses"].rows)
                   if item["hypothesis_id"] == hypothesis["hypothesis_id"])
        index = panel._models["hypotheses"].index(row, 0)
        reveal(panel.hypothesis_table)
        panel.hypothesis_table.scrollTo(index)
        app.processEvents()
        QTest.mouseClick(panel.hypothesis_table.viewport(), Qt.MouseButton.LeftButton,
                         pos=panel.hypothesis_table.visualRect(index).center())
        require(panel._selected_hypothesis == hypothesis["hypothesis_id"], "INV_HYPOTHESIS_SELECTION_FAILED")
        click(panel.findChild(QPushButton, "invChooseHypothesis"))
        pump_until(lambda: panel.bridge.worker is None)
        require(panel.section.currentData() == "verification" and panel.action_combo.count() > 0,
                "INV_HYPOTHESIS_DID_NOT_OFFER_IMPLEMENTED_DIAGNOSTICS")

        phase("SEVEN_SECTIONS_BILINGUAL_LAYOUT")
        require(panel.section.count() == 7, "INV_SEVEN_WORKSPACE_SECTIONS_REQUIRED")
        proof["device_pixel_ratio"] = window.devicePixelRatioF()
        for language in ("RU", "EN"):
            window._set_language(language)
            for width, height in ((1024, 720), (1600, 1000)):
                window.resize(width, height)
                app.processEvents()
                for section_index in range(panel.section.count()):
                    key = panel.section.itemData(section_index)
                    select_section(key)
                    # Horizontal scrolling would hide labels/buttons at this
                    # viewport size. Vertical scrolling is the intended layout.
                    scroll = window.stack.currentWidget()
                    require(scroll.horizontalScrollBar().maximum() == 0,
                            "INV_WORKSPACE_HORIZONTAL_OVERFLOW_" + key)
                    require(panel.pages.currentWidget().isVisible(), "INV_SECTION_PAGE_HIDDEN_" + key)
                    label = f"{language}-{width}x{height}-{key}.png"
                    require(window.grab().save(str(output / label), "PNG"), "INV_SCREENSHOT_FAILED")
                    proof["screenshots"].append(label)
                    proof["sections"].append({"language": language, "width": width, "height": height, "section": key})
        window.resize(1330, 850)
        window._set_language("EN")
        if args.layout_only:
            require(not deep.bridge.has_session, "INV_LAYOUT_ONLY_STARTED_HELPER")
            assert_sources_unchanged(input_hashes)
            successful = True
        else:
            phase("OWNED_CURRENT_TARGET_AND_EXPLICIT_NEW_MEASUREMENT_CONSENT")
            executable = args.probe.resolve(strict=True) if args.probe else build_probe(output / "build")
            probe = Probe(executable, output / "probe")
            oracle = probe.ready
            proof["target"] = {"pid": oracle["pid"], "created_100ns": oracle["created_100ns"]}
            proof["probe_sha256"] = digest(executable)
            executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="inv-gui-qa-oracle")
            def factory():
                service = InspectorService(journal_root=output / "journal", helper_executable=helper)
                services.append((service, threading.get_ident()))
                return service
            deep.bridge._factory = factory
            created = psutil.Process(oracle["pid"]).create_time()
            window._attach_pid(oracle["pid"])
            pump_until(lambda: window.probe.pid == oracle["pid"] and not window.probe.pending and
                       deep.bridge.target is not None and deep.bridge.target[0] == oracle["pid"])
            require(abs(deep.bridge.target[1] - created) < .000001,
                    "INV_ATTACH_DID_NOT_BIND_CURRENT_OBSERVER_PROCESS_INSTANCE")
            def respond():
                active = QApplication.activeModalWidget()
                if active is None:
                    return
                if active.objectName() == "invContextDialog" and context_plan["pending"] and not context_plan["answered"]:
                    # The actual modal editor and file chooser command run;
                    # only the OS path selection is supplied by the harness.
                    context_plan["answered"] = True
                    try:
                        require(not active.scope.isChecked() and not active.save_button.isEnabled(),
                                "INV_CONTEXT_SCOPE_CONSENT_NOT_EXPLICIT_OR_SAVE_ALREADY_ENABLED")
                        values = {"application_id": "BLACKBOX_INV_GUI_OWNED_PROBE", "version": "CONTROLLED_QA_BUILD",
                            "scenario_id": "INV_GUI_DECLARED_INTERVENTION", "workload_id": "ONE_64_BYTE_WRITE",
                            "source_profile": "USER_DECLARED_QA", "operation_count": "1", "input_bytes": "64"}
                        for key, value in values.items():
                            field = active.fields[key]
                            field.setFocus()
                            QTest.keyClick(field, Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
                            QTest.keyClicks(field, value)
                        if not active.complete.isChecked():
                            QTest.mouseClick(active.complete, Qt.MouseButton.LeftButton)
                        QTest.mouseClick(active.choose_binary, Qt.MouseButton.LeftButton)
                        require(Path(active.binary.text()).resolve(strict=True) == executable.resolve(strict=True),
                                "INV_CONTEXT_ACTUAL_FILE_CHOICE_NOT_RETAINED")
                        QTest.mouseClick(active.scope, Qt.MouseButton.LeftButton)
                        require(active.scope.isChecked() and active.save_button.isEnabled(),
                                "INV_CONTEXT_EXPLICIT_SCOPE_DID_NOT_ENABLE_SAVE")
                        require(active.grab().save(str(output / "actual-context-editor.png"), "PNG"),
                                "INV_CONTEXT_EDITOR_SCREENSHOT_FAILED")
                        proof["context_editor"] = {"actual_qt_dialog": True, "actual_typed_fields": values,
                            "entire_case_consent_default": False, "entire_case_consent_explicitly_selected": True,
                            "selected_real_file": executable.name, "declaration_is_os_evidence": False}
                        QTest.mouseClick(active.save_button, Qt.MouseButton.LeftButton)
                    except BaseException as error:
                        proof["unexpected_dialogs"].append("CONTEXT_EDITOR:" + str(error)[:500])
                        active.reject()
                elif isinstance(active, QMessageBox) and dialog_plan["operation"] and not dialog_plan["answered"]:
                    valid = (re.search(r"\bPID " + str(oracle["pid"]) + r"(?!\d)", active.text()) is not None and
                        active.button(QMessageBox.StandardButton.Yes) is not None and
                        active.button(QMessageBox.StandardButton.Cancel) is not None and
                        active.defaultButton() == active.button(QMessageBox.StandardButton.Cancel))
                    proof["confirmations"].append({"operation": dialog_plan["operation"],
                        "decision": "YES" if dialog_plan["decision"] else "CANCEL", "actual_dialog": True,
                        "exact_pid_and_cancel_default": valid})
                    dialog_plan["answered"] = True
                    if not valid:
                        proof["unexpected_dialogs"].append("INV_CONFIRMATION_TARGET_OR_DEFAULT_CHANGED")
                    button = active.button(QMessageBox.StandardButton.Yes if valid and dialog_plan["decision"]
                                           else QMessageBox.StandardButton.Cancel)
                    if button:
                        QTest.mouseClick(button, Qt.MouseButton.LeftButton)
                    else:
                        active.reject()
                else:
                    proof["unexpected_dialogs"].append(active.windowTitle())
                    active.reject() if hasattr(active, "reject") else active.close()
            dialog_timer = QTimer()
            dialog_timer.setInterval(10)
            dialog_timer.timeout.connect(respond)
            dialog_timer.start()
            select_section("verification")
            click(panel.bind_button, consent=False, operation="BIND_NEW_MEASUREMENTS")
            require(panel._live_identity is None and panel.experiment_case is None and not deep.bridge.has_session,
                    "INV_CANCELLED_BIND_STARTED_NATIVE_EXPERIMENT")
            click(panel.bind_button, consent=True, operation="BIND_NEW_MEASUREMENTS")
            pump_until(lambda: idle() and panel.experiment_case is not None)
            require(panel._live_identity["created_100ns"] == oracle["created_100ns"] and
                    panel.experiment_case.get("origin_case_id") == original_case_id and
                    panel.experiment_case.get("historical_target_relation") == "NOT_ESTABLISHED",
                    "INV_EXPLICIT_NEW_TARGET_DID_NOT_PRESERVE_HISTORICAL_UNCERTAINTY")
            require(panel.case["case_id"] == original_case_id,
                    "INV_LIVE_BIND_OVERWROTE_ORIGINAL_RECORDED_CASE")
            def native_step(widget, operation, *, consent=None):
                count = len(native_results)
                click(widget, consent=consent, operation=operation)
                if consent is False:
                    QTest.qWait(50)
                    require(len(native_results) == count and idle(), "INV_CANCELLED_ACTION_STILL_EXECUTED")
                    return None
                pump_until(lambda: idle() and len(native_results) > count)
                result = native_results[-1]
                require(result.get("operation") == operation and
                        result.get("status") in ("COMPLETED", "INCOMPLETE_EVIDENCE") and
                        result.get("target", {}).get("created_100ns") == oracle["created_100ns"],
                        "INV_GUIDED_NATIVE_STEP_FAILED_" + operation)
                proof["native_steps"].append(journal_metadata(result))
                return result
            phase("REAL_BEFORE_WRITE_AFTER_COMPARE_FROM_QT_CONTROLS")
            before = native_step(panel.before_button, "snapshot")
            action_index = panel.action_combo.findData("memory.write")
            require(action_index >= 0, "INV_IMPLEMENTED_MANUAL_MEMORY_WRITE_NOT_SELECTABLE")
            panel.action_combo.setCurrentIndex(action_index)
            changed = bytes(index ^ 0xA5 for index in range(64)).hex()
            panel.parameters.setPlainText(json.dumps({"address": oracle["buffer_address"],
                "expected_hex": oracle["buffer_hex"], "value_hex": changed}))
            native_step(panel.run_button, "memory.write", consent=False)
            require(oracle_call(probe.state)["buffer_hex"] == oracle["buffer_hex"],
                    "INV_CANCELLED_WRITE_CHANGED_CONTROLLED_NATIVE_BYTES")
            write = native_step(panel.run_button, "memory.write", consent=True)
            require(oracle_call(probe.state)["buffer_hex"] == changed and write["data"].get("change_id"),
                    "INV_GUIDED_WRITE_NOT_VERIFIED_BY_INDEPENDENT_NATIVE_TARGET")
            after = native_step(panel.after_button, "snapshot")
            comparison = native_step(panel.compare_button, "compare")
            require(comparison["data"]["interpretation"] == "OBSERVED_DIFFERENCE_NOT_CAUSAL_PROOF" and
                    panel._experiment["status"] == "INCONCLUSIVE" and
                    panel._experiment["root_cause_proven"] is False,
                    "INV_GUI_COMPARISON_INVENTED_CAUSAL_CONFIRMATION")
            require(panel.experiment_case.get("guided_experiments"), "INV_EXPERIMENT_NOT_DURABLY_ATTACHED_TO_FORK")
            proof["guided_experiment"] = {"origin_case_id": original_case_id,
                "experiment_case_id": panel.experiment_case["case_id"],
                "before_id": before["data"]["snapshot_id"], "after_id": after["data"]["snapshot_id"],
                "comparison_status": panel._experiment["status"], "native_write_independently_verified": True,
                "root_cause_proven": False, "historical_target_relation": "NOT_ESTABLISHED"}
            phase("ACTUAL_EXPORT_BUTTON_AND_NORMAL_CLOSE_RECOVERY")
            export_path = output / "investigation-from-gui.json"
            with patch("blackbox_universal.investigation_graph_panel.QFileDialog.getSaveFileName",
                       return_value=(str(export_path), "JSON (*.json)")):
                click(panel.export_button)
            pump_until(lambda: idle() and export_path.is_file())
            proof["export"] = validate_export(export_path, forbidden=(oracle["buffer_hex"], changed))
            exported = json.loads(export_path.read_text())
            require(exported.get("guided_experiments") and exported.get("origin_case_id") == original_case_id,
                    "INV_GUI_EXPORT_LOST_ORIGINAL_ID_OR_GUIDED_EXPERIMENT")
            phase("ACTUAL_USER_CONTEXT_EDITOR_AND_IMMUTABLE_CHECKPOINT")
            context_parent = panel.experiment_case
            context_parent_id = context_parent["case_id"]
            context_before = json.dumps(context_parent, sort_keys=True)
            context_plan.update(pending=True, answered=False)
            with patch("blackbox_universal.investigation_context_dialog.QFileDialog.getOpenFileName",
                       return_value=(str(executable), "Application (*.exe *.dll)")):
                click(panel.context_button)
            context_plan["pending"] = False
            require(context_plan["answered"], "INV_ACTUAL_CONTEXT_EDITOR_NOT_OBSERVED")
            pump_until(lambda: idle() and panel.case is not None and panel.case["case_id"] != context_parent_id)
            declared = panel.case
            require(declared.get("context_parent_case_id") == context_parent_id and
                    declared.get("context_provenance") == "USER_REPORTED" and
                    declared.get("declared_context_source_binding") == "NOT_ESTABLISHED" and
                    declared["app_identity"]["verification_class"] == "USER_SELECTED_FILE_SHA256" and
                    declared["app_identity"]["sha256"] == digest(executable) and
                    declared["scenario"]["verification_class"] == "USER_REPORTED",
                    "INV_CONTEXT_EDITOR_PROMOTED_DECLARATION_OR_MISIDENTIFIED_SELECTED_FILE")
            require(json.dumps(context_parent, sort_keys=True) == context_before and
                    declared["nodes"] == context_parent["nodes"] and declared["edges"] == context_parent["edges"],
                    "INV_CONTEXT_EDITOR_MODIFIED_ORIGINAL_CASE_OR_RECORDED_OBSERVATIONS")
            context_export = output / "investigation-with-declared-context.json"
            with patch("blackbox_universal.investigation_graph_panel.QFileDialog.getSaveFileName",
                       return_value=(str(context_export), "JSON (*.json)")):
                click(panel.export_button)
            pump_until(lambda: idle() and context_export.is_file())
            proof["context_editor"].update(context_parent_case_id=context_parent_id,
                declared_case_id=declared["case_id"], original_case_unchanged=True,
                historical_process_file_binding="NOT_ESTABLISHED",
                export=validate_export(context_export, forbidden=(oracle["buffer_hex"], changed)))
            require(len(services) == 1 and services[0][1] != threading.get_ident(),
                    "INV_SERVICE_CONSTRUCTED_ON_GUI_THREAD_OR_DUPLICATED")
            helper_process = psutil.Process(services[0][0].helper_pid)
            before_close = oracle_call(probe.state)
            window.close()
            pump_until(lambda: bool(deep_closed) and bool(graph_closed) and not deep.bridge.has_session and
                       not window.isVisible(), timeout=60)
            require(deep_closed[-1].get("status") == "COMPLETED" and not helper_process.is_running(),
                    "INV_CLOSE_LEFT_HELPER_OR_UNCONFIRMED_RECOVERY")
            require(not window.probe.alive and window.probe.process.exitCode() == 0 and
                    window.probe.process.exitStatus() == QProcess.ExitStatus.NormalExit,
                    "INV_OBSERVER_DID_NOT_CLOSE_NORMALLY")
            require(oracle_call(probe.state)["buffer_hex"] == oracle["buffer_hex"],
                    "INV_CLOSE_DID_NOT_RESTORE_WRITTEN_OWNED_BYTES")
            oracle_call(probe.progress, before_close)
            proof["native_close"] = {"diagnostic": journal_metadata(deep_closed[-1]),
                "helper_exit_verified": True, "observer_normal_exit": True,
                "own_memory_restored_verified": True, "target_survival_verified": True}
            assert_sources_unchanged(input_hashes)
            require(pulse_state["ticks"] >= 5 and pulse_state["max_gap_seconds"] < 2,
                    "INV_GUI_EVENT_LOOP_RESPONSIVENESS_NOT_CONFIRMED")
            successful = True
    except BaseException as error:
        proof.update(error=type(error).__name__, reason=str(error)[:1800], traceback=traceback.format_exc(limit=12))
    finally:
        if window is not None:
            try:
                window.close()
                pump_until(lambda: not window.deep_inspector_panel.bridge.has_session and not window.isVisible(), timeout=45)
            except BaseException as error:
                successful = False
                proof["cleanup_error"] = str(error)[:1000]
        for timer in (pulse, dialog_timer):
            if timer is not None:
                timer.stop()
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=True)
        if probe is not None:
            try:
                proof["target_cleanup"] = probe.close(kill=not successful)
                require(not successful or proof["target_cleanup"].get("status") == "COMPLETED",
                        "INV_GUI_OWNED_NATIVE_TARGET_CLEANUP_FAILED")
            except BaseException as error:
                successful = False
                proof["target_cleanup_error"] = str(error)[:1000]
        proof.update(status="PASS" if successful else "FAIL", input_hashes=input_hashes)
        save(output / "gui-investigation-qa.json", proof)
    print("INV_GUI_QA_" + proof["status"], proof.get("reason", ""), flush=True)
    return 0 if successful else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--diagnostic-helper", type=Path)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--dpi-scale", choices=("1", "1.25", "1.5", "2"))
    parser.add_argument("--layout-only", action="store_true")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
