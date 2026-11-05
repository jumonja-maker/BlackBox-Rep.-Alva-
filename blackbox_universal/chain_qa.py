"""Actual source/frozen R60 editor route, executed only on hosted Windows.

Only file-picker answers are scripted. Graph validation, services, persistence,
execution, checkpoint restore and exports use the production Qt/controller path.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import threading
import time
import traceback
from unittest.mock import patch


def run_chain_gui(app, window, output, evidence_root, source_sha):
    from PySide6.QtCore import QBuffer, QIODevice, QPoint, QPointF, Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QScrollArea
    from blackbox_core.chain_qa import require, read_json, save, source_proof, independent_journal
    output, evidence_root = Path(output), Path(evidence_root)
    proof = {"schema": "blackbox.r60.chain-gui-qa/1", "status": "FAIL", "source_sha": source_sha,
             "source_identity": None, "frozen": bool(getattr(__import__("sys"), "frozen", False)),
             "scale": os.environ.get("QT_SCALE_FACTOR", "1"), "dpi_scope": "QT_SCALE_FACTOR_SIMULATION",
             "physical_windows_10_11": "NOT_TESTED", "physical_secure_desktop": "NOT_TESTED", "screenshots": []}
    panel = window.chain_builder_panel

    def pump_until(predicate, code, seconds=40):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            app.processEvents()
            if predicate():
                return
            QTest.qWait(5)
        raise AssertionError(code)

    def background(call):
        answer = {}
        def work():
            try:
                answer["value"] = call()
            except BaseException as error:
                answer["error"] = error
        worker = threading.Thread(target=work, name="chain-gui-independent-readback")
        worker.start()
        pump_until(lambda: not worker.is_alive(), "R60_GUI_INDEPENDENT_READER_TIMEOUT", 60)
        worker.join()
        if "error" in answer:
            raise answer["error"]
        return answer.get("value")

    def idle(seconds=120):
        pump_until(lambda: not panel.bridge.busy, "R60_EDITOR_WORKER_TIMEOUT", seconds)

    def visible(widget):
        ancestor = widget.parentWidget()
        while ancestor is not None:
            if isinstance(ancestor, QScrollArea):
                ancestor.ensureWidgetVisible(widget)
            ancestor = ancestor.parentWidget()
        app.processEvents()

    def click(widget):
        visible(widget)
        require(widget.isEnabled() and widget.isVisible(), "R60_GUI_CONTROL_UNAVAILABLE_" + widget.objectName())
        fired = []
        def received(*_):
            fired.append(True)
        widget.clicked.connect(received)
        try:
            QTest.mouseClick(widget, Qt.MouseButton.LeftButton)
        finally:
            widget.clicked.disconnect(received)
        require(fired, "R60_REAL_QT_CLICK_NOT_DELIVERED_" + widget.objectName())

    def combo(widget, value):
        index = widget.findData(value)
        require(index >= 0, "R60_GUI_COMBO_VALUE_MISSING_" + str(value))
        visible(widget)
        widget.setFocus()
        QTest.keyClick(widget, Qt.Key.Key_Home)
        for _ in range(index):
            QTest.keyClick(widget, Qt.Key.Key_Down)
        require(widget.currentData() == value, "R60_GUI_KEYBOARD_COMBO_NOT_SELECTED")

    def add(tool):
        item = next((panel.palette.item(i) for i in range(panel.palette.count())
                     if panel.palette.item(i).data(Qt.ItemDataRole.UserRole) == tool), None)
        require(item is not None, "R60_EDITOR_TOOL_MISSING_" + tool)
        panel.palette.scrollToItem(item)
        visible(panel.palette)
        QTest.mouseClick(panel.palette.viewport(), Qt.MouseButton.LeftButton,
                         pos=panel.palette.visualItemRect(item).center())
        click(panel.add_button)
        return panel.document["nodes"][-1]["node_id"]

    def connect(first, output_port, second, input_port, *, reject=False):
        combo(panel.source_node, first)
        combo(panel.source_port, output_port)
        combo(panel.target_node, second)
        combo(panel.target_port, input_port)
        before = len(panel.document["edges"])
        visible(panel.connect_button)
        panel.connect_button.setFocus()
        QTest.keyClick(panel.connect_button, Qt.Key.Key_Space)
        idle()
        if reject:
            require(len(panel.document["edges"]) == before and "INCOMPATIBLE_PORT_TYPES" in panel.status.text(),
                    "R60_EDITOR_TYPE_REJECTION_NOT_VISIBLE")
        else:
            require(len(panel.document["edges"]) == before + 1, "R60_EDITOR_EDGE_NOT_COMMITTED_" + panel.status.text())

    def screenshot(language):
        image = window.grab().toImage()
        captured_width, captured_height = image.width(), image.height()
        if image.width() > 1280:
            image = image.scaledToWidth(1280, Qt.TransformationMode.SmoothTransformation)
        buffer = QBuffer()
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        require(image.save(buffer, "PNG", 0), "R60_GUI_SCREENSHOT_ENCODING_FAILED")
        raw = bytes(buffer.data())
        require(0 < len(raw) <= 768 * 1024, "R60_GUI_SCREENSHOT_LOG_BYTE_BUDGET")
        digest = hashlib.sha256(raw).hexdigest()
        label = language + "-" + proof["scale"] + "-" + digest[:12]
        name = label + ".png"
        background(lambda: (output / name).write_bytes(raw))
        encoded = base64.b64encode(raw).decode("ascii")
        chunks = [encoded[index:index + 12000] for index in range(0, len(encoded), 12000)]
        metadata = {"id": label, "file": name, "sha256": digest, "bytes": len(raw),
            "captured_pixels": [captured_width, captured_height], "encoded_pixels": [image.width(), image.height()],
            "chunks": len(chunks), "language": language, "scale": proof["scale"], "source_sha": source_sha,
            "delivery": "PNG_BASE64_IN_CI_LOG_NO_ACTIONS_ARTIFACTS"}
        print("R60_GUI_PNG_BEGIN " + json.dumps(metadata, sort_keys=True), flush=True)
        for index, chunk in enumerate(chunks, 1):
            print("R60_GUI_PNG_CHUNK " + label + " " + str(index) + "/" + str(len(chunks)) + " " + chunk, flush=True)
        print("R60_GUI_PNG_END " + label + " " + digest, flush=True)
        proof["screenshots"].append(metadata)

    try:
        proof["source_identity"] = background(lambda: source_proof(source_sha))
        background(lambda: output.mkdir(parents=True, exist_ok=False))
        require(proof["scale"] in ("1", "1.25", "1.5", "2"), "R60_GUI_SCALE_NOT_IN_MATRIX")
        idle()
        require(panel.catalog and window.stack.count() == 6 and len(window.PAGES) == 6,
                "R60_PRODUCTION_PAGES_OR_CATALOG_MISSING")
        window._navigate("dashboard")
        window.overview_tabs.setCurrentWidget(panel)
        app.processEvents()
        manifest = background(lambda: read_json(evidence_root / "sources.json"))
        first = add("load_source")
        combo(panel._fields["kind"], "TRACE")
        path = panel._fields["path"]
        visible(path)
        path.setFocus()
        QTest.keyClick(path, Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
        QTest.keyClicks(path, str(manifest["trace"]))
        click(panel.apply_button)
        decoder = add("decode_trace")
        waits = add("waits")
        investigation = add("investigate")
        checkpoint = add("CHECKPOINT")
        report = add("export_report")
        # Incomplete imported clocks/stacks must stay partial through derived
        # tools; continuing that branch is an explicit editor policy choice.
        for node_id in (waits, investigation, checkpoint, report):
            panel.select_node(node_id)
            panel.inspector_tabs.setCurrentIndex(0)
            click(panel._fields["_allow_partial"])
            click(panel.apply_button)
        # Real pointer movement followed by keyboard movement changes stored layout.
        item = panel.canvas.items_by_id[first]
        visible(panel.canvas)
        panel.canvas.resetTransform()
        panel.canvas.centerOn(item)
        app.processEvents()
        point = panel.canvas.mapFromScene(item.scenePos() + QPointF(90, 18))
        before = item.pos()
        QTest.mousePress(panel.canvas.viewport(), Qt.MouseButton.LeftButton, pos=point)
        QTest.mouseMove(panel.canvas.viewport(), point + QPoint(35, 20), delay=30)
        QTest.mouseRelease(panel.canvas.viewport(), Qt.MouseButton.LeftButton, pos=point + QPoint(35, 20))
        require(item.pos() != before, "R60_EDITOR_REAL_DRAG_DID_NOT_MOVE_NODE")
        item.setSelected(True)
        panel.canvas.setFocus()
        before_x = item.x()
        QTest.keyClick(panel.canvas, Qt.Key.Key_Right)
        require(item.x() == before_x + 10, "R60_EDITOR_KEYBOARD_MOVE_NOT_PERSISTED")
        proof["canvas"] = {"actual_pointer_drag": True, "keyboard_move": True}
        connect(first, "source", waits, "index", reject=True)
        connect(first, "source", decoder, "trace")
        connect(decoder, "index", waits, "index")
        connect(decoder, "index", investigation, "evidence")
        connect(investigation, "receipt", checkpoint, "after")
        connect(investigation, "case", report, "case")
        connect(checkpoint, "continue", report, "when")
        proof["keyboard_connections"] = len(panel.document["edges"])
        proof["typed_rejection_visible"] = True
        definition_path = str(output / "edited-chain.bbchain.json")
        with patch("blackbox_universal.chain_builder.QFileDialog.getSaveFileName", return_value=(definition_path, "JSON")):
            click(panel.save_button)
            idle()
        before_run = panel.snapshot.get("run_id")
        with patch("blackbox_universal.chain_builder.QFileDialog.getOpenFileName", return_value=(definition_path, "JSON")):
            click(panel.open_button)
            idle()
        require(not window.probe.active and panel.snapshot.get("run_id") == before_run,
                "R60_OPEN_AUTOMATICALLY_EXECUTED_TOOLS")
        profile_path = str(output / "diagnostic.bbprofile.json")
        with patch("blackbox_universal.chain_builder.QFileDialog.getSaveFileName", return_value=(profile_path, "JSON")):
            click(panel.profile_save)
            idle()
        with patch("blackbox_universal.chain_builder.QFileDialog.getOpenFileName", return_value=(profile_path, "JSON")):
            click(panel.profile_open)
            idle()
        require(not window.probe.active and not panel.snapshot.get("run_id"), "R60_PROFILE_OPEN_AUTORUN")
        click(panel.validate_button)
        idle()
        require(panel.validation.get("ready") is True, "R60_EDITOR_PREFLIGHT_FAILED: " + panel.effective.toPlainText()[-2000:])
        for language in ("RU", "EN"):
            window._set_language(language)
            window.overview_tabs.setCurrentWidget(panel)
            panel.inspector_tabs.setCurrentIndex(0)
            panel.select_node(first)
            panel.fit_graph()
            visible(panel.canvas)
            app.processEvents()
            require(panel.canvas.isVisible() and panel.start_button.isEnabled(), "R60_EDITOR_TRANSLATION_HID_CONTROLS")
            screenshot(language)
        proof["passive_open_profile"] = True
        click(panel.start_button)
        idle(240)
        require(panel.snapshot.get("state") == "WAITING_FOR_HUMAN", "R60_MANUAL_CHECKPOINT_NOT_REACHED: " + panel.status.text())
        proof["checkpoint"] = {"run_id": panel.snapshot.get("run_id"), "state": panel.snapshot["state"]}
        click(panel.resume_button)
        idle(240)
        require(panel.snapshot.get("state") in ("COMPLETED", "PARTIAL"), "R60_EDITOR_RESUME_DID_NOT_FINISH: " + panel.status.text())
        require(panel._folder, "R60_EDITOR_SAVED_RUN_FOLDER_MISSING")
        records, journal = background(lambda: independent_journal(panel._folder))
        require(any(event.get("event") == "node.result" and event.get("node_id") == report for event in records),
                "R60_EDITOR_REPORT_TOOL_NOT_ACTUALLY_INVOKED")
        proof.update(run_id=panel.snapshot["run_id"], state=panel.snapshot["state"], journal=journal,
                     actual_result_count=sum(event.get("event") == "node.result" for event in records))
        window._navigate("reports")
        window.chain_history_toggle.setChecked(True)
        idle()
        history = window.chain_history_panel
        selected = next((index for index, row in enumerate(history.rows) if row["run_id"] == panel.snapshot["run_id"]), None)
        require(selected is not None, "R60_REPORTS_HISTORY_MISSING_ACTUAL_RUN")
        history.table.selectRow(selected)
        for format, button in (("json", history.export_json), ("html", history.export_html)):
            destination = str(output / ("history." + format))
            with patch("blackbox_universal.chain_builder.QFileDialog.getSaveFileName", return_value=(destination, format)):
                click(button)
                idle()
            require(background(lambda: Path(destination).is_file()), "R60_GUI_HISTORY_EXPORT_MISSING_" + format)
        proof["history_export_json_html"] = True
        proof["final_source_identity"] = background(lambda: source_proof(source_sha))
        proof["status"] = "PASS"
    except BaseException as error:
        proof.update(status="FAIL", reason=str(error)[:2500], error=type(error).__name__)
        traceback.print_exc(limit=15)
    finally:
        panel.bridge.cancel()
        idle(120)
        window.close()
        pump_until(lambda: not getattr(window.probe, "alive", False) and not panel.bridge.busy
                   and not window.deep_inspector_panel.bridge.has_session, "R60_GUI_OWNERS_NOT_CLOSED", 120)
        app.processEvents()
        background(lambda: save(output / "result.json", proof))
        print("R60_CHAIN_GUI_RECEIPT " + json.dumps(proof, ensure_ascii=True, sort_keys=True), flush=True)
    return proof
