"""Actual source/frozen R60 editor route, executed only on hosted Windows.

Only file-picker answers are scripted. Graph validation, services, persistence,
execution, checkpoint restore and exports use the production Qt/controller path.
"""
from __future__ import annotations

from contextlib import closing
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
import traceback
from unittest.mock import patch


def _gui_phase(phase, **metadata):
    """Bounded routing breadcrumbs; never include entered text or source paths."""
    print("R60_GUI_PHASE " + json.dumps({"phase": phase, **metadata}, ensure_ascii=True,
                                       sort_keys=True), flush=True)


def _assert_visible_hit_point(widget, position):
    """Refuse direct Qt events at points clipped out of the rendered window."""
    from blackbox_core.chain_qa import require
    point = widget.mapToGlobal(position)
    ancestor = widget
    while ancestor is not None:
        mapped = ancestor.mapFromGlobal(point)
        require(ancestor.isVisible() and ancestor.rect().contains(mapped),
                "R60_GUI_POINTER_OUTSIDE_VISIBLE_ANCESTOR_" +
                (ancestor.objectName() or type(ancestor).__name__)[:128] + ":" + json.dumps({
                    "control": widget.objectName()[:128], "point": [position.x(), position.y()],
                    "mapped_point": [mapped.x(), mapped.y()], "ancestor_rect": list(ancestor.rect().getRect())},
                    sort_keys=True))
        ancestor = ancestor.parentWidget()


def _real_button_click(widget):
    """Send a real pointer click to the style's interactive button area.

    A blank checkbox can occupy an entire form row while Qt's hit rectangle
    covers only its indicator. Widget-center clicks can therefore miss it.
    Style coordinates are logical widget coordinates and retain DPI and RTL.
    """
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QCheckBox, QStyle, QStyleOptionButton
    from blackbox_core.chain_qa import require
    control = {"object_name": widget.objectName()[:128], "class": type(widget).__name__[:64],
               "rect": list(widget.rect().getRect()), "geometry": list(widget.geometry().getRect()),
               "enabled": widget.isEnabled(), "visible": widget.isVisible()}
    _gui_phase("CLICK_BEGIN", **control)
    require(widget.isEnabled() and widget.isVisible(), "R60_GUI_CONTROL_UNAVAILABLE_" + widget.objectName())
    checkbox = isinstance(widget, QCheckBox)
    position = widget.rect().center()
    before = widget.checkState() if checkbox else None
    if checkbox:
        option = QStyleOptionButton()
        option.initFrom(widget)
        option.text, option.icon, option.iconSize = widget.text(), widget.icon(), widget.iconSize()
        option.state |= (QStyle.StateFlag.State_NoChange if before == Qt.CheckState.PartiallyChecked else
                         QStyle.StateFlag.State_On if widget.isChecked() else QStyle.StateFlag.State_Off)
        indicator = widget.style().subElementRect(QStyle.SubElement.SE_CheckBoxIndicator, option, widget)
        require(not indicator.isEmpty() and widget.rect().contains(indicator.center()),
                "R60_GUI_CHECKBOX_INDICATOR_UNAVAILABLE_" + widget.objectName())
        position = indicator.center()
    _gui_phase("CLICK_HIT_POINT", object_name=control["object_name"],
               position=[position.x(), position.y()], checkbox=checkbox)
    _assert_visible_hit_point(widget, position)
    fired, toggled = [], []
    def received(*_):
        fired.append(True)
    def changed(*_):
        toggled.append(True)
    widget.clicked.connect(received)
    if checkbox:
        widget.toggled.connect(changed)
    try:
        QTest.mouseClick(widget, Qt.MouseButton.LeftButton, pos=position)
        _gui_phase("CLICK_MOUSE_EVENT_RETURNED", object_name=control["object_name"],
                   clicked_count=len(fired), toggled_count=len(toggled))
    finally:
        widget.clicked.disconnect(received)
        if checkbox:
            widget.toggled.disconnect(changed)
        _gui_phase("CLICK_SIGNALS_DISCONNECTED", object_name=control["object_name"])
    require(fired, "R60_REAL_QT_CLICK_NOT_DELIVERED_" + widget.objectName())
    if checkbox:
        require(widget.checkState() != before and (widget.isTristate() or toggled),
                "R60_REAL_QT_CHECKBOX_NOT_CHANGED_" + widget.objectName())


def run_chain_gui(app, window, output, evidence_root, source_sha, *, failure_guard=None):
    _gui_phase("ENTER")
    from PySide6.QtCore import QBuffer, QIODevice, QPoint, QPointF, QRect, Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QScrollArea
    from blackbox_core.chain_qa import (actual_invocations, file_hash, require, read_json, save,
                                       source_proof, independent_journal)
    output, evidence_root = Path(output), Path(evidence_root)
    proof = {"schema": "blackbox.r60.chain-gui-qa/1", "status": "FAIL", "source_sha": source_sha,
             "source_identity": None, "frozen": bool(getattr(__import__("sys"), "frozen", False)),
             "scale": os.environ.get("QT_SCALE_FACTOR", "1"), "dpi_scope": "QT_SCALE_FACTOR_SIMULATION",
             "physical_windows_10_11": "NOT_TESTED", "physical_secure_desktop": "NOT_TESTED", "screenshots": []}
    panel = window.chain_builder_panel
    _gui_phase("PANEL_REFERENCE_READY")

    def pump_until(predicate, code, seconds=40):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            app.processEvents()
            if predicate():
                return
            # Let the real Python/QThread workers run between Qt event pumps.
            # Keep the original deadline; this is cooperative scheduling, not
            # an extension of any diagnostic or acceptance budget.
            time.sleep(.005)
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
        _gui_phase("CLICK_ENSURE_VISIBLE_BEGIN", object_name=widget.objectName()[:128],
                   class_name=type(widget).__name__[:64])
        visible(widget)
        _real_button_click(widget)

    def type_value(widget, value):
        _gui_phase("TYPE_CONTROL_BEGIN", object_name=widget.objectName()[:128],
                   class_name=type(widget).__name__[:64])
        visible(widget)
        require(widget.isEnabled() and widget.isVisible(), "R60_GUI_VALUE_CONTROL_UNAVAILABLE_" + widget.objectName())
        _assert_visible_hit_point(widget, widget.rect().center())
        widget.setFocus()
        QTest.keyClick(widget, Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
        QTest.keyClicks(widget, str(value))
        _gui_phase("TYPE_CONTROL_FINISHED", object_name=widget.objectName()[:128])

    def combo(widget, value):
        _gui_phase("COMBO_CONTROL_BEGIN", object_name=widget.objectName()[:128],
                   class_name=type(widget).__name__[:64])
        index = widget.findData(value)
        require(index >= 0, "R60_GUI_COMBO_VALUE_MISSING_" + str(value))
        visible(widget)
        _assert_visible_hit_point(widget, widget.rect().center())
        widget.setFocus()
        QTest.keyClick(widget, Qt.Key.Key_Home)
        for _ in range(index):
            QTest.keyClick(widget, Qt.Key.Key_Down)
        require(widget.currentData() == value, "R60_GUI_KEYBOARD_COMBO_NOT_SELECTED")
        _gui_phase("COMBO_CONTROL_FINISHED", object_name=widget.objectName()[:128])

    def add(tool):
        item = next((panel.palette.item(i) for i in range(panel.palette.count())
                     if panel.palette.item(i).data(Qt.ItemDataRole.UserRole) == tool), None)
        require(item is not None, "R60_EDITOR_TOOL_MISSING_" + tool)
        panel.palette.scrollToItem(item)
        visible(panel.palette)
        point = panel.palette.visualItemRect(item).center()
        _assert_visible_hit_point(panel.palette.viewport(), point)
        QTest.mouseClick(panel.palette.viewport(), Qt.MouseButton.LeftButton,
                         pos=point)
        click(panel.add_button)
        return panel.document["nodes"][-1]["node_id"]

    def connect(first, output_port, second, input_port, *, reject=False):
        combo(panel.source_node, first)
        combo(panel.source_port, output_port)
        combo(panel.target_node, second)
        combo(panel.target_port, input_port)
        before = len(panel.document["edges"])
        visible(panel.connect_button)
        _assert_visible_hit_point(panel.connect_button, panel.connect_button.rect().center())
        panel.connect_button.setFocus()
        QTest.keyClick(panel.connect_button, Qt.Key.Key_Space)
        idle()
        if reject:
            require(len(panel.document["edges"]) == before and "INCOMPATIBLE_PORT_TYPES" in panel.status.text(),
                    "R60_EDITOR_TYPE_REJECTION_NOT_VISIBLE")
        else:
            require(len(panel.document["edges"]) == before + 1, "R60_EDITOR_EDGE_NOT_COMMITTED_" + panel.status.text())

    def workspace_geometry(widget):
        full = QRect(widget.mapTo(window, QPoint()), widget.size())
        shown = QRect(full)
        ancestor = widget.parentWidget()
        while ancestor is not None:
            shown = shown.intersected(QRect(ancestor.mapTo(window, QPoint()), ancestor.size()))
            ancestor = ancestor.parentWidget()
        return {"logical_rect": list(full.getRect()), "visible_logical_rect": list(shown.getRect()),
                "fully_visible": widget.isVisible() and shown == full}

    def prepare_workspace_capture():
        # These are the actual page's scroll bars, not an edited/cropped image.
        # Keep the title, controls and workspace together at the top of the page.
        ancestor = panel.parentWidget()
        while ancestor is not None:
            if isinstance(ancestor, QScrollArea):
                ancestor.horizontalScrollBar().setValue(ancestor.horizontalScrollBar().minimum())
                ancestor.verticalScrollBar().setValue(ancestor.verticalScrollBar().minimum())
            ancestor = ancestor.parentWidget()
        app.processEvents()
        controls = {"notice": panel.notice, "start": panel.start_button, "validate": panel.validate_button,
                    "open": panel.open_button, "save": panel.save_button,
                    "canvas": panel.canvas, "inspector": panel.inspector_tabs}
        geometry = {name: workspace_geometry(widget) for name, widget in controls.items()}
        require(all(geometry[name]["fully_visible"] for name in ("notice", "start", "validate", "open", "save")),
                "R60_GUI_WORKSPACE_HEADER_OR_TOOLBAR_CLIPPED:" + json.dumps(geometry, sort_keys=True))
        for name in ("canvas", "inspector"):
            rect = geometry[name]["visible_logical_rect"]
            require(rect[2] >= (300 if name == "canvas" else 240) and rect[3] >= 180,
                    "R60_GUI_WORKSPACE_VIEW_TOO_CLIPPED:" + name + ":" + json.dumps(geometry[name], sort_keys=True))
        return geometry

    def screenshot(language, geometry):
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
            "logical_window_client": [window.width(), window.height()],
            "window_device_pixel_ratio": window.devicePixelRatioF(), "workspace_geometry": geometry,
            "reported_platform_screen_logical_rect": list(window.screen().geometry().getRect()),
            "viewport_scope": "EXPLICIT_LOGICAL_WINDOW_RENDER_NOT_PHYSICAL_DESKTOP_ACCEPTANCE",
            "chunks": len(chunks), "language": language, "scale": proof["scale"], "source_sha": source_sha,
            "delivery": "PNG_BASE64_IN_CI_LOG_NO_ACTIONS_ARTIFACTS"}
        print("R60_GUI_PNG_BEGIN " + json.dumps(metadata, sort_keys=True), flush=True)
        for index, chunk in enumerate(chunks, 1):
            print("R60_GUI_PNG_CHUNK " + label + " " + str(index) + "/" + str(len(chunks)) + " " + chunk, flush=True)
        print("R60_GUI_PNG_END " + label + " " + digest, flush=True)
        proof["screenshots"].append(metadata)

    def verify_recorded_view(records, manifest, identifiers, fixture_pid, original_trace_sha):
        """Independently read the actual UI outputs; never filter source files."""
        from blackbox_core.chain_qa_faults import _persisted_case_scope
        rows = {record["node_id"]: record["data"] for record in records
                if record.get("event") == "node.result"}
        selected = {"pid": fixture_pid}
        trace = rows[identifiers["source"]]["outputs"]["source"][0]
        index = rows[identifiers["decoder"]]["outputs"]["index"][0]
        require(trace["value"].get("selection") == selected and index["value"].get("selection") == selected and
                trace["value"]["sha256"] == original_trace_sha and
                index["value"].get("trace_sha256") == original_trace_sha,
                "R60_GUI_RECORDED_VIEW_LOST_OR_REBOUND_TRACE_SCOPE")
        hashes = {"trace": file_hash(trace["value"]["_path"]), "index": file_hash(index["value"]["_path"])}
        require(hashes["trace"] == original_trace_sha and hashes["index"] == index["value"]["sha256"],
                "R60_GUI_RECORDED_VIEW_SOURCE_HASH_MISMATCH")

        def raw_counts(path):
            before = file_hash(path)
            with closing(sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("PRAGMA trusted_schema=OFF")
                db.execute("PRAGMA cache_size=-4096")
                deadline = time.monotonic() + 30
                db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                summary = json.loads(db.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
                total, target_rows = db.execute(
                    "SELECT count(*),sum(CASE WHEN pid=? THEN 1 ELSE 0 END) FROM events", (fixture_pid,)).fetchone()
                require(summary.get("input_sha256") == original_trace_sha and summary.get("rows") == total and
                        0 < target_rows < total, "R60_GUI_RAW_INDEX_FULL_TRACE_OR_RECORDED_PID_MISSING")
            require(file_hash(path) == before, "R60_GUI_RAW_INDEX_CHANGED_DURING_READBACK")
            return {"rows": total, "target_header_rows": target_rows, "other_header_rows": total - target_rows,
                    "sha256": before, "decode_status": summary.get("status"),
                    "scope": "ALL_STORED_ROWS_WITHOUT_PID_FILTER_NOT_CAPTURE_COMPLETENESS"}

        raw = raw_counts(index["value"]["_path"])
        reference = raw_counts(manifest["index"])
        require(all(raw[key] == reference[key] for key in ("rows", "target_header_rows", "other_header_rows")),
                "R60_GUI_DECODE_FILTERED_THE_ORIGINAL_SYSTEM_TRACE")
        case, case_proof = _persisted_case_scope(rows[identifiers["investigation"]]["outputs"]["case"][0])
        report = rows[identifiers["report"]]["outputs"]["report"][0]
        exported = read_json(report["value"]["_path"], maximum=32 * 1024**2)
        require(file_hash(report["value"]["_path"]) == report["value"]["sha256"],
                "R60_GUI_SELECTED_VIEW_EXPORT_HASH_MISMATCH")
        for result in (case, exported):
            sources = result.get("sources", [])
            require(result.get("case_id") == case["case_id"] and len(sources) == 1 and
                    sources[0].get("source_type") == "TRACE_INDEX" and sources[0].get("selection") == selected and
                    sources[0].get("index_sha256") == hashes["index"] and result.get("root_cause_proven") is False,
                    "R60_GUI_SAVED_CASE_OR_EXPORT_LOST_RECORDED_SOURCE_VIEW")
        wait_artifact = rows[identifiers["waits"]]["outputs"]["report"][0]
        wait_report = read_json(wait_artifact["value"]["_path"])
        require(wait_report.get("filters", {}).get("pid") == fixture_pid and
                wait_report.get("source_trace_sha256") == original_trace_sha and
                wait_report.get("trace_to_session_alignment") == "NOT_ESTABLISHED" and
                file_hash(wait_artifact["value"]["_path"]) == wait_artifact["value"]["sha256"],
                "R60_GUI_WAITS_NOT_APPLIED_TO_EXPLICIT_RECORDED_PID")
        for operation in ("investigation.create", "investigation.export"):
            calls = actual_invocations(records, operation)
            require(len(calls) == 1 and calls[0][0].get("parameters", {}).get("max_result_bytes") == 32 * 1024**2,
                    "R60_GUI_DEFAULT_CASE_RESULT_BUDGET_CHANGED:" + operation)
        require(file_hash(trace["value"]["_path"]) == hashes["trace"] and
                file_hash(index["value"]["_path"]) == hashes["index"],
                "R60_GUI_SELECTED_CASE_READBACK_MODIFIED_SOURCE")
        return {"status": "PASS", "scope": "REAL_EDITOR_SELECTED_RECORDED_SOURCE_VIEW_NOT_LIVE_AUTHORITY",
                "selected_pid": fixture_pid, "selection": selected, "max_result_bytes": 32 * 1024**2,
                "trace_sha256": original_trace_sha, "decoded_index": raw, "original_index": reference,
                "raw_index_rewritten_or_filtered": False, "saved_case": case_proof,
                "case_export_sha256": report["value"]["sha256"], "wait_filters": wait_report["filters"],
                "trace_to_session_alignment": "NOT_ESTABLISHED", "root_cause_proven": False}

    try:
        _gui_phase("REPRESENTATIVE_LOGICAL_VIEWPORT_BEGIN")
        # The offscreen plugin reports a small virtual screen. Its maximized
        # state can force a client size below the product's 1020x690 minimum.
        # Render a normal supported desktop window instead and retain the real
        # Qt/DPI/capture bounds; this establishes no physical monitor coverage.
        window.showNormal()
        window.resize(1600, 1000)
        app.processEvents()
        require(window.width() >= window.minimumWidth() and window.height() >= window.minimumHeight(),
                "R60_GUI_VIEWPORT_BELOW_DECLARED_PRODUCT_MINIMUM")
        proof["viewport"] = {"requested_logical_client": [1600, 1000],
            "actual_logical_client": [window.width(), window.height()],
            "minimum_logical_client": [window.minimumWidth(), window.minimumHeight()],
            "window_geometry_logical": list(window.geometry().getRect()),
            "window_device_pixel_ratio": window.devicePixelRatioF(), "platform": app.platformName(),
            "reported_platform_screen_logical_rect": list(window.screen().geometry().getRect()),
            "reported_platform_screen_device_pixel_ratio": window.screen().devicePixelRatio(),
            "input_scope": "QT_WIDGET_EVENTS_INSIDE_WINDOW_AND_ALL_ANCESTOR_CLIP_RECTS",
            "physical_monitor_and_native_screen_pointer": "NOT_TESTED"}
        _gui_phase("SOURCE_IDENTITY_BEGIN")
        proof["source_identity"] = background(lambda: source_proof(source_sha))
        _gui_phase("OUTPUT_CREATE_BEGIN")
        background(lambda: output.mkdir(parents=True, exist_ok=False))
        require(proof["scale"] in ("1", "1.25", "1.5", "2"), "R60_GUI_SCALE_NOT_IN_MATRIX")
        idle()
        _gui_phase("CATALOG_IDLE")
        require(panel.catalog and window.stack.count() == 6 and len(window.PAGES) == 6,
                "R60_PRODUCTION_PAGES_OR_CATALOG_MISSING")
        window._navigate("dashboard")
        window.overview_tabs.setCurrentWidget(panel)
        app.processEvents()
        _gui_phase("MANIFEST_READ_BEGIN")
        manifest = background(lambda: read_json(evidence_root / "sources.json"))
        fixture_pid = manifest.get("fixture", {}).get("pid")
        require(type(fixture_pid) is int and fixture_pid > 0, "R60_GUI_RECORDED_FIXTURE_PID_MISSING")
        original_trace_sha = background(lambda: file_hash(manifest["trace"]))
        _gui_phase("CONFIGURE_RECORDED_SOURCE_BEGIN")
        first = add("load_source")
        combo(panel._fields["kind"], "TRACE")
        type_value(panel._fields["path"], manifest["trace"])
        # The user explicitly chooses a recorded PID view. Decode still reads
        # the entire system trace; this is not live identity or global rebinding.
        selected, pid_field = panel._fields["selection"].fields["pid"]
        click(selected)
        type_value(pid_field, fixture_pid)
        click(panel.apply_button)
        _gui_phase("CONFIGURE_DECODER_AND_WAITS_BEGIN")
        decoder = add("decode_trace")
        waits = add("waits")
        type_value(panel._fields["pid"], fixture_pid)
        click(panel.apply_button)
        investigation = add("investigate")
        checkpoint = add("CHECKPOINT")
        report = add("export_report")
        _gui_phase("CONFIGURE_PARTIAL_POLICY_BEGIN")
        # Incomplete imported clocks/stacks must stay partial through derived
        # tools; continuing that branch is an explicit editor policy choice.
        for node_id in (waits, investigation, checkpoint, report):
            panel.select_node(node_id)
            panel.inspector_tabs.setCurrentIndex(0)
            click(panel._fields["_allow_partial"])
            click(panel.apply_button)
        _gui_phase("CANVAS_POINTER_BEGIN")
        # Real pointer movement followed by keyboard movement changes stored layout.
        item = panel.canvas.items_by_id[first]
        visible(panel.canvas)
        panel.canvas.resetTransform()
        panel.canvas.centerOn(item)
        app.processEvents()
        point = panel.canvas.mapFromScene(item.scenePos() + QPointF(90, 18))
        _assert_visible_hit_point(panel.canvas.viewport(), point)
        _assert_visible_hit_point(panel.canvas.viewport(), point + QPoint(35, 20))
        before = item.pos()
        QTest.mousePress(panel.canvas.viewport(), Qt.MouseButton.LeftButton, pos=point)
        QTest.mouseMove(panel.canvas.viewport(), point + QPoint(35, 20), delay=30)
        QTest.mouseRelease(panel.canvas.viewport(), Qt.MouseButton.LeftButton, pos=point + QPoint(35, 20))
        require(item.pos() != before, "R60_EDITOR_REAL_DRAG_DID_NOT_MOVE_NODE")
        _gui_phase("CANVAS_POINTER_FINISHED")
        item.setSelected(True)
        panel.canvas.setFocus()
        before_x = item.x()
        QTest.keyClick(panel.canvas, Qt.Key.Key_Right)
        require(item.x() == before_x + 10, "R60_EDITOR_KEYBOARD_MOVE_NOT_PERSISTED")
        proof["canvas"] = {"actual_pointer_drag": True, "keyboard_move": True}
        _gui_phase("CONNECT_TYPED_GRAPH_BEGIN")
        connect(first, "source", waits, "index", reject=True)
        connect(first, "source", decoder, "trace")
        connect(decoder, "index", waits, "index")
        connect(decoder, "index", investigation, "evidence")
        connect(investigation, "receipt", checkpoint, "after")
        connect(investigation, "case", report, "case")
        connect(checkpoint, "continue", report, "when")
        proof["keyboard_connections"] = len(panel.document["edges"])
        proof["typed_rejection_visible"] = True
        _gui_phase("SAVE_REOPEN_DEFINITION_BEGIN")
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
        saved = background(lambda: read_json(definition_path, maximum=1024**2))
        for name, definition in (("saved", saved), ("reopened", panel.document)):
            defined = {node["node_id"]: node for node in definition["nodes"]}
            require(defined[first]["parameters"].get("selection") == {"pid": fixture_pid} and
                    defined[waits]["parameters"].get("pid") == fixture_pid and
                    defined[investigation]["parameters"].get("selection", {}) == {},
                    "R60_GUI_EXPLICIT_RECORDED_SCOPE_NOT_PRESERVED:" + name)
        proof["recorded_scope_saved_and_reopened"] = {"selection": {"pid": fixture_pid},
            "waits_pid": fixture_pid, "global_investigation_selection": {}, "configured_with": "ACTUAL_UI_MOUSE_AND_KEYBOARD"}
        _gui_phase("SAVE_REOPEN_PROFILE_BEGIN")
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
        _gui_phase("PREFLIGHT_READY_SCREENSHOTS_BEGIN")
        for language in ("RU", "EN"):
            window._set_language(language)
            window.overview_tabs.setCurrentWidget(panel)
            panel.inspector_tabs.setCurrentIndex(0)
            panel.select_node(first)
            panel.fit_graph()
            app.processEvents()
            require(panel.canvas.isVisible() and panel.start_button.isEnabled(), "R60_EDITOR_TRANSLATION_HID_CONTROLS")
            reachable = (("start", panel.start_button), ("pause", panel.pause_button),
                         ("stop", panel.cancel_button), ("resume", panel.resume_button),
                         ("canvas", panel.canvas), ("inspector", panel.inspector_tabs),
                         ("apply", panel.apply_button), ("connect", panel.connect_button))
            for _, control in reachable:
                visible(control)
                _assert_visible_hit_point(control, control.rect().center())
            proof.setdefault("workspace_reachability", []).append({"language": language,
                "controls": [name for name, _ in reachable],
                "scope": "ACTUAL_SCROLL_AND_VISIBLE_HIT_POINT_NOT_DISABLED_ACTION_EXECUTION"})
            geometry = prepare_workspace_capture()
            screenshot(language, geometry)
        _gui_phase("SCREENSHOTS_FINISHED_EXECUTION_BEGIN")
        proof["passive_open_profile"] = True
        click(panel.start_button)
        idle(240)
        _gui_phase("INITIAL_EXECUTION_RETURNED")
        require(panel.snapshot.get("state") == "WAITING_FOR_HUMAN", "R60_MANUAL_CHECKPOINT_NOT_REACHED: " + panel.status.text())
        proof["checkpoint"] = {"run_id": panel.snapshot.get("run_id"), "state": panel.snapshot["state"]}
        click(panel.resume_button)
        idle(240)
        _gui_phase("RESUME_RETURNED")
        require(panel.snapshot.get("state") in ("COMPLETED", "PARTIAL"), "R60_EDITOR_RESUME_DID_NOT_FINISH: " + panel.status.text())
        require(panel._folder, "R60_EDITOR_SAVED_RUN_FOLDER_MISSING")
        records, journal = background(lambda: independent_journal(panel._folder))
        _gui_phase("INDEPENDENT_JOURNAL_READ_FINISHED")
        require(any(event.get("event") == "node.result" and event.get("node_id") == report for event in records),
                "R60_EDITOR_REPORT_TOOL_NOT_ACTUALLY_INVOKED")
        identifiers = {"source": first, "decoder": decoder, "waits": waits,
                       "investigation": investigation, "report": report}
        proof["recorded_source_view"] = background(lambda: verify_recorded_view(
            records, manifest, identifiers, fixture_pid, original_trace_sha))
        _gui_phase("RECORDED_SCOPE_READBACK_FINISHED")
        proof.update(run_id=panel.snapshot["run_id"], state=panel.snapshot["state"], journal=journal,
                     actual_result_count=sum(event.get("event") == "node.result" for event in records))
        window._navigate("reports")
        _gui_phase("REPORTS_HISTORY_BEGIN")
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
        if failure_guard is not None:
            failure_guard.apply(proof)
        _gui_phase("ACCEPTANCE_BODY_FINISHED")
    except BaseException as error:
        _gui_phase("PYTHON_EXCEPTION", error_type=type(error).__name__[:64])
        proof.update(status="FAIL", reason=str(error)[:2500], error=type(error).__name__)
        traceback.print_exc(limit=15)
    finally:
        # A latched callback error refuses PASS but never aborts a real owner
        # drain or abandons the background reader used by the harness.
        cleanup_errors = []
        for stage, action in (
            ("FINALIZE_CANCEL_BEGIN", panel.bridge.cancel),
            ("FINALIZE_IDLE_BEGIN", lambda: idle(120)),
            ("FINALIZE_WINDOW_CLOSE_BEGIN", window.close),
            ("FINALIZE_OWNERS_DRAIN_BEGIN", lambda: pump_until(
                lambda: not getattr(window.probe, "alive", False) and not panel.bridge.busy
                    and not window.deep_inspector_panel.bridge.has_session,
                "R60_GUI_OWNERS_NOT_CLOSED", 120)),
            ("FINALIZE_EVENT_DRAIN_BEGIN", app.processEvents)):
            _gui_phase(stage)
            try:
                action()
            except BaseException as error:
                cleanup_errors.append({"stage": stage, "error_type": type(error).__name__[:64]})
        if cleanup_errors:
            proof.update(status="FAIL", finalization_errors=cleanup_errors)
            proof.setdefault("reason", "R60_GUI_FINALIZATION_FAILED")
        if failure_guard is not None:
            failure_guard.apply(proof)
        _gui_phase("FINALIZE_SAVE_RECEIPT_BEGIN")
        background(lambda: save(output / "result.json", proof))
        if failure_guard is not None and failure_guard.failed:
            # The save's event pump can itself deliver a failing callback.
            # All readers have now drained; publish the final FAIL directly.
            failure_guard.apply(proof)
            save(output / "result.json", proof)
        _gui_phase("FINALIZE_RECEIPT_SAVED")
        print("R60_CHAIN_GUI_RECEIPT " + json.dumps(proof, ensure_ascii=True, sort_keys=True), flush=True)
    return proof
