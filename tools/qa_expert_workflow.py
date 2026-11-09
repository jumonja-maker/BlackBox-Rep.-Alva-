"""Hosted-only expert workflow acceptance for the actual source or frozen GUI.

The real recording observes this disposable GUI process through the production
isolated owner. Separately labelled synthetic imported evidence exercises the
finding/event views; it cannot certify Windows sensor behavior or root cause.
PNG files travel as bounded, hash-checked chunks in the existing CI logs.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
SCALES = ("1", "1.25", "1.5", "2")
PAGES = ("dashboard", "processes", "events", "reports", "settings", "decoder")
SECTIONS = ("timeline", "findings", "library", "actions", "technical")
MAX_PNG_BYTES = 768 * 1024


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def hosted_windows():
    require(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("RUNNER_OS") == "Windows", "EXPERT_QA_REQUIRES_GITHUB_HOSTED_WINDOWS")


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=True, allow_nan=False, indent=2), encoding="ascii")
    temporary.replace(path)


def validate_receipt(proof, *, source_sha, frozen, scale):
    """Refuse successful-looking receipts with missing or relabelled evidence."""
    require(re.fullmatch(r"[0-9a-f]{40}", source_sha or ""), "EXPERT_EXPECTED_SHA_INVALID")
    identity = proof.get("source_identity", {})
    require(proof.get("status") == "PASS" and proof.get("source_sha") == source_sha and
            identity.get("actual_source_sha") == source_sha and
            identity.get("source_identity_status") == "VERIFIED_EXPECTED_HEAD" and
            identity.get("tracked_worktree_clean") is True, "EXPERT_RECEIPT_SOURCE_OR_STATUS")
    require(type(proof.get("frozen")) is bool and proof["frozen"] is frozen and
            proof.get("scale") == scale and scale in SCALES, "EXPERT_RECEIPT_FORM_OR_SCALE")
    require(type(proof.get("gui_pid")) is int and proof["gui_pid"] > 0, "EXPERT_RECEIPT_GUI_PID")
    require(proof.get("dpi_scope") == "QT_SCALE_FACTOR_SIMULATION" and
            proof.get("physical_windows_10_11") == "NOT_TESTED" and
            proof.get("secure_desktop") == "NOT_TESTED", "EXPERT_RECEIPT_SCOPE")
    require(proof.get("cleanup", {}).get("owners_closed") is True and
            not proof.get("callback_errors") and not proof.get("unexpected_dialogs"), "EXPERT_RECEIPT_CLEANUP")
    navigation = proof.get("navigation", [])
    require(len(navigation) == 12 and
            {(row.get("language"), row.get("page")) for row in navigation} ==
            {(language, page) for language in ("RU", "EN") for page in PAGES} and
            all(row.get("actual_qt_input") is True for row in navigation), "EXPERT_RECEIPT_NAVIGATION")
    shortcuts = proof.get("shortcuts", [])
    require(len(shortcuts) == 14 and
            {(row.get("language"), row.get("target")) for row in shortcuts} ==
            {(language, page) for language in ("EN", "RU") for page in (*PAGES, "process_search")} and
            all(row.get("actual_qt_input") is True for row in shortcuts), "EXPERT_RECEIPT_SHORTCUTS")
    sections = proof.get("sections", [])
    require(len(sections) == 10 and
            {(row.get("language"), row.get("section")) for row in sections} ==
            {(language, section) for language in ("EN", "RU") for section in SECTIONS} and
            all(row.get("actual_qt_input") is True and row.get("context_unchanged") is True and
                row.get("target_visible_in_viewport") is True for row in sections),
            "EXPERT_RECEIPT_SECTIONS")
    minimum = proof.get("minimum_width", [])
    require(len(minimum) == 2 and {row.get("language") for row in minimum} == {"EN", "RU"},
            "EXPERT_RECEIPT_MINIMUM_WIDTH_LANGUAGES")
    for row in minimum:
        require(row.get("logical_window_client") == [1020, 850] and row.get("actual_qt_resize") is True and
                row.get("expanded_sections") == ["library", "actions", "technical"] and
                type(row.get("viewport_width")) is int and row["viewport_width"] > 0 and
                type(row.get("outer_horizontal_scroll_maximum")) is int and
                row["outer_horizontal_scroll_maximum"] == 0 and
                all(type(row.get(key)) is int and 0 < row[key] <= row["viewport_width"]
                    for key in ("research_panel_width", "library_panel_width")),
                "EXPERT_RECEIPT_MINIMUM_WIDTH_OVERFLOW")
    recordings = proof.get("recordings", [])
    require(len(recordings) == 2 and {row.get("language") for row in recordings} == {"RU", "EN"},
            "EXPERT_RECEIPT_REAL_RECORDINGS")
    for row in recordings:
        require(row.get("scope") == "REAL_GUI_PROCESS_RECORDING" and
                type(row.get("samples")) is int and row["samples"] >= 3 and
                row.get("recorded_pid") == proof.get("gui_pid") and
                row.get("research_helper_pid") != proof.get("gui_pid") and
                type(row.get("research_helper_pid")) is int and row["research_helper_pid"] > 0 and
                row.get("recorded_status") == "COMPLETED" and
                row.get("selected_session_matches") is True and
                row.get("handoff_actual_qt_input") is True and
                row.get("report_html_unknown_preserved") is True and
                row.get("source_files_unchanged_after_review") is True,
                "EXPERT_RECEIPT_REAL_RECORDING_OR_HANDOFF")
        require(set(row.get("files", {})) == {"session.sqlite3", "report.json", "report.html"} and
                all(re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")) and
                    type(item.get("bytes")) is int and item["bytes"] > 0 for item in row["files"].values()),
                "EXPERT_RECEIPT_REPORT_FILES")
        sources = row.get("recorded_sources", {})
        require({"session.sqlite3", "session-v2.sqlite3"} <= set(sources) and
                2 <= len(sources) <= 4 and
                all(re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")) and
                    type(item.get("bytes")) is int and item["bytes"] > 0 for item in sources.values()),
                "EXPERT_RECEIPT_RECORDED_SOURCE_HASHES")
    fixture = proof.get("fixture", {})
    require(fixture.get("scope") == "TEST_ONLY_SYNTHETIC_IMPORTED_EVIDENCE" and
            fixture.get("source_unchanged") is True and
            fixture.get("languages") == ["EN", "RU"] and
            fixture.get("finding_selection_actual_qt_input") is True and
            fixture.get("event_selection_actual_qt_input") is True and
            fixture.get("incident_card_actual_qt_input") is True and
            fixture.get("copy_detail_roundtrip") is True and
            fixture.get("raw_json_roundtrip") is True and
            fixture.get("root_cause") == "UNKNOWN", "EXPERT_RECEIPT_FIXTURE_SCOPE_OR_SELECTION")
    screenshots = proof.get("screenshots", [])
    require(10 <= len(screenshots) <= 16 and len({row.get("id") for row in screenshots}) == len(screenshots),
            "EXPERT_RECEIPT_SCREENSHOT_COUNT")
    for row in screenshots:
        require(row.get("language") in ("RU", "EN") and row.get("scale") == scale and
                row.get("source_sha") == source_sha and row.get("frozen") is frozen and
                type(row.get("bytes")) is int and 0 < row["bytes"] <= MAX_PNG_BYTES and
                re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", "")) and
                row.get("scope") in ("REAL_GUI_PROCESS_RECORDING", "TEST_ONLY_SYNTHETIC_IMPORTED_EVIDENCE"),
                "EXPERT_RECEIPT_SCREENSHOT_IDENTITY")
        if row.get("stage") == "fixture-minimum-width":
            require(row.get("logical_window_client") == [1020, 850], "EXPERT_RECEIPT_MINIMUM_SCREENSHOT_SIZE")
    require({(row.get("language"), row.get("stage"), row.get("scope")) for row in screenshots} >=
            {(language, stage, scope) for language in ("EN", "RU") for stage, scope in (
                ("saved-report", "REAL_GUI_PROCESS_RECORDING"),
                ("fixture-findings", "TEST_ONLY_SYNTHETIC_IMPORTED_EVIDENCE"),
                ("fixture-minimum-width", "TEST_ONLY_SYNTHETIC_IMPORTED_EVIDENCE"),
                ("fixture-incident-card", "TEST_ONLY_SYNTHETIC_IMPORTED_EVIDENCE"),
                ("fixture-events", "TEST_ONLY_SYNTHETIC_IMPORTED_EVIDENCE"))}, "EXPERT_RECEIPT_SCREENSHOT_SCOPE_COVERAGE")
    return proof


def synthetic_recording(folder):
    """A declared import fixture, written by real storage and read by real workers."""
    from blackbox_core.session_v2 import SessionV2Writer, FILENAME
    folder.mkdir(parents=True, exist_ok=False)
    origin = 10**9
    writer = SessionV2Writer(folder, pid=123, created=1.0, name="TEST_ONLY_SYNTHETIC_ROOT", origin_ns=origin)
    try:
        for index in range(1, 9):
            writer.submit("detail", {"time_ns": origin + index * 10**9, "pid": 123, "created": 1.0,
                "cpu_user_s": index * .2, "cpu_system_s": 0.0, "rss_bytes": 32 * 1048576,
                "private_bytes": None, "uss_bytes": 8 * 1048576, "handle_count": 0, "thread_count": 1,
                "read_bytes": index * 4096, "write_bytes": 0, "read_ops": index, "write_ops": 0,
                "children_total": 1, "children_omitted": 0, "threads_omitted": 0,
                "thread_capture_status": "OK", "child_capture_status": "OK",
                "sensor_status": {"children": "OK"},
                "threads": [{"tid": 111, "cpu_user_s": index * .2, "cpu_system_s": 0.0}],
                "children": [{"pid": 456, "created": 2.0, "parent_pid": 123,
                    "name": "TEST_ONLY_SYNTHETIC_CHILD", "cpu_user_s": index * .1, "cpu_system_s": 0.0,
                    "rss_bytes": 4 * 1048576, "private_bytes": None, "handle_count": 0, "thread_count": 1}],
                "requested_interval_ns": 10**9})
        # Hosted full-sync startup can take longer than five seconds. This
        # fixture waits on the original writer; production Stop is unchanged.
        writer.finish("COMPLETED", timeout=60)
    finally:
        if writer.thread.is_alive():
            writer.thread.join(timeout=10)
        require(not writer.thread.is_alive(), "EXPERT_FIXTURE_WRITER_NOT_CLOSED")
    with closing(sqlite3.connect(folder / FILENAME)) as db:
        for second in (2, 5):
            stamp = origin + second * 10**9
            event_id = db.execute("""INSERT INTO events(recorded_ns,observed_ns,instance_id,event_type,
                source_kind,verification_class,timestamp_precision,correlation_key,measurement_status,detail_json)
                VALUES(?,?,1,'UI_UNRESPONSIVE_OBSERVED','WIN32','OS_OBSERVED','TEST_ONLY_SYNTHETIC',
                'TEST_ONLY_SYNTHETIC','SENSOR_TIMEOUT',?)""", (stamp, stamp, json.dumps({
                    "hwnd": 4660, "tid": 111, "timeout_ms": 200, "result": None,
                    "test_only_synthetic": True, "root_cause": "UNKNOWN"}))).lastrowid
            db.execute("""INSERT INTO incidents(trigger_code,start_ns,end_ns,status,primary_event_id,context_json)
                VALUES('UI_TIMEOUT',?,?,'TEST_ONLY_SYNTHETIC',?,?)""", (stamp, stamp + 10**9,
                    event_id, json.dumps({"test_only_synthetic": True, "root_cause": "UNKNOWN"})))
        db.commit()
    return folder / FILENAME


def run_gui(app, window, output, source_sha):
    """Called by app.py so PyInstaller exercises the same actual application."""
    hosted_windows()
    from PySide6.QtCore import QBuffer, QIODevice, QPoint, QRect, QThread, QTimer, Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import (QApplication, QCheckBox, QMessageBox, QPushButton,
                                   QScrollArea, QStyle, QStyleOptionButton)
    from blackbox_universal.provenance import source_identity
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    scale = os.environ.get("QT_SCALE_FACTOR", "1")
    identity = source_identity(source_sha)
    proof = {"schema": "blackbox.expert-workflow-qa/1", "status": "RUNNING", "source_sha": source_sha,
        "source_identity": identity, "frozen": bool(getattr(sys, "frozen", False)), "gui_pid": os.getpid(),
        "scale": scale, "dpi_scope": "QT_SCALE_FACTOR_SIMULATION", "physical_windows_10_11": "NOT_TESTED",
        "secure_desktop": "NOT_TESTED", "navigation": [], "recordings": [], "screenshots": [],
        "sections": [], "shortcuts": [], "minimum_width": [], "callback_errors": [], "unexpected_dialogs": [],
        "cleanup": {"owners_closed": False}}
    old_hook = sys.excepthook
    timer = QTimer()

    def callback_error(kind, value, tb):
        proof["callback_errors"].append("".join(traceback.format_exception(kind, value, tb))[-16000:])

    def phase(name):
        proof["phase"] = name
        save(output / "expert-gui.json", proof)

    def pump(predicate, *, timeout=60, cleanup=False):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            app.processEvents()
            if not cleanup:
                require(not proof["callback_errors"] and not proof["unexpected_dialogs"], "EXPERT_QT_CALLBACK_OR_DIALOG")
            if predicate():
                return
            time.sleep(.005)
        raise AssertionError("EXPERT_GUI_DEADLINE_" + proof.get("phase", "UNKNOWN"))

    def reject_dialogs():
        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, QMessageBox) and widget.isVisible():
                proof["unexpected_dialogs"].append(widget.objectName() or widget.windowTitle())
                widget.reject()

    def reveal(widget):
        current = window.stack.currentWidget()
        if isinstance(current, QScrollArea):
            current.ensureWidgetVisible(widget)
        app.processEvents()
        require(widget.isVisible() and widget.isEnabled(), "EXPERT_VISIBLE_ENABLED_CONTROL_" + widget.objectName())

    def click(widget):
        reveal(widget)
        delivered = []
        receiver = lambda *_: delivered.append(True)
        widget.clicked.connect(receiver)
        try:
            point = widget.rect().center()
            if isinstance(widget, QCheckBox):
                # A checkbox may expand across the layout, while Qt accepts
                # hits only on its indicator/text. Its overall center can be
                # empty space. Click the actual style indicator instead.
                option = QStyleOptionButton()
                option.initFrom(widget)
                option.text = widget.text()
                point = widget.style().subElementRect(
                    QStyle.SubElement.SE_CheckBoxIndicator, option, widget).center()
            require(widget.rect().contains(point), "EXPERT_POINTER_POINT_OUTSIDE_CONTROL")
            QTest.mouseClick(widget, Qt.MouseButton.LeftButton, pos=point)
            app.processEvents()
        finally:
            widget.clicked.disconnect(receiver)
        require(delivered, "EXPERT_REAL_POINTER_DID_NOT_ACTIVATE_" + widget.objectName())

    def navigate(page):
        click(window._nav_buttons[page])
        require(window.stack.currentIndex() == window._page_ids[page] and
                window._nav_buttons[page].property("active") is True, "EXPERT_MAIN_PAGE_NOT_REACHABLE_" + page)

    def select_row(table, row):
        reveal(table)
        index = table.model().index(row, 0)
        table.scrollTo(index)
        app.processEvents()
        QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, pos=table.visualRect(index).center())
        app.processEvents()
        require(table.selectionModel().selectedRows() and
                table.selectionModel().selectedRows()[0].row() == row, "EXPERT_ACTUAL_TABLE_SELECTION_FAILED")

    def screenshot(label, language, scope):
        app.processEvents()
        image = window.grab().toImage()
        captured = [image.width(), image.height()]
        if image.width() > 1280:
            image = image.scaledToWidth(1280, Qt.TransformationMode.SmoothTransformation)
        buffer = QBuffer()
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        require(image.save(buffer, "PNG", 0), "EXPERT_PNG_ENCODING")
        raw = bytes(buffer.data())
        require(0 < len(raw) <= MAX_PNG_BYTES, "EXPERT_PNG_LOG_BYTE_BUDGET")
        sha = hashlib.sha256(raw).hexdigest()
        identifier = label + "-" + language + "-" + scale + "-" + sha[:12]
        (output / (identifier + ".png")).write_bytes(raw)
        proof["screenshots"].append({"id": identifier, "file": identifier + ".png", "sha256": sha,
            "bytes": len(raw), "language": language, "scale": scale, "source_sha": source_sha,
            "stage": label, "frozen": proof["frozen"], "scope": scope, "captured_pixels": captured,
            "encoded_pixels": [image.width(), image.height()],
            "logical_window_client": [window.width(), window.height()],
            "window_device_pixel_ratio": window.devicePixelRatioF(),
            "reported_screen_logical_rect": list(window.screen().geometry().getRect()),
            "viewport_scope": "EXPLICIT_LOGICAL_WINDOW_RENDER_NOT_PHYSICAL_DESKTOP_ACCEPTANCE",
            "delivery": "PNG_BASE64_IN_CI_LOG_NO_ACTIONS_ARTIFACTS"})
        save(output / "expert-gui.json", proof)

    sys.excepthook = callback_error
    timer.timeout.connect(reject_dialogs)
    timer.start(25)
    try:
        require(scale in SCALES and identity.get("source_identity_status") == "VERIFIED_EXPECTED_HEAD",
                "EXPERT_EXACT_SOURCE_AND_SCALE_REQUIRED")
        window.showNormal()
        window.resize(1440, 1000)
        app.processEvents()
        proof["viewport"] = {"logical_client": [window.width(), window.height()],
            "minimum_client": [window.minimumWidth(), window.minimumHeight()], "qt_platform": app.platformName()}
        require(window.width() >= window.minimumWidth() and window.height() >= window.minimumHeight(),
                "EXPERT_SUPPORTED_VIEWPORT_REQUIRED")
        require(tuple(key for key, _ in window.PAGES) == PAGES and window.stack.count() == 6,
                "EXPERT_SIX_PRODUCTION_PAGES_CHANGED")
        pump(lambda: not window.probe.pending and window.probe.alive)
        for language in ("EN", "RU"):
            phase("REAL_RECORDING_" + language)
            window._set_language(language)
            for page in PAGES:
                navigate(page)
                proof["navigation"].append({"language": language, "page": page, "actual_qt_input": True})
            for number, page in enumerate(PAGES, 1):
                navigate("settings" if page == "dashboard" else "dashboard")
                window.activateWindow()
                window.setFocus()
                QTest.keyClick(window, getattr(Qt.Key, "Key_" + str(number)), Qt.KeyboardModifier.ControlModifier)
                app.processEvents()
                require(window.stack.currentIndex() == window._page_ids[page], "EXPERT_ACTUAL_SHORTCUT_FAILED_" + page)
                proof["shortcuts"].append({"language": language, "target": page, "actual_qt_input": True})
            QTest.keyClick(window, Qt.Key.Key_L, Qt.KeyboardModifier.ControlModifier)
            app.processEvents()
            require(window.stack.currentIndex() == window._page_ids["processes"] and window.process_search.hasFocus(),
                    "EXPERT_ACTUAL_SEARCH_SHORTCUT_FAILED")
            proof["shortcuts"].append({"language": language, "target": "process_search", "actual_qt_input": True})
            window._refresh_process_list()
            pump(lambda: not window.probe.pending and any(row["pid"] == os.getpid() for row in window._process_rows))
            reveal(window.process_search)
            window.process_search.setFocus()
            QTest.keyClick(window.process_search, Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
            QTest.keyClicks(window.process_search, str(os.getpid()))
            app.processEvents()
            target_row = next((row for row in range(window.process_table.rowCount()) if
                window.process_table.item(row, 1).data(Qt.ItemDataRole.UserRole) == os.getpid()), None)
            require(target_row is not None, "EXPERT_REAL_DISCOVERED_GUI_PID_MISSING")
            select_row(window.process_table, target_row)
            index = window.process_table.model().index(target_row, 0)
            QTest.mouseDClick(window.process_table.viewport(), Qt.MouseButton.LeftButton,
                             pos=window.process_table.visualRect(index).center())
            pump(lambda: window.probe.pid == os.getpid() and not window.probe.pending)
            require(not window.probe.active and window.probe.session_folder is None,
                    "EXPERT_ATTACH_STARTED_RECORDING")
            require(not window.review_result_button.isEnabled(), "EXPERT_ATTACH_ENABLED_STALE_RESULT_HANDOFF")
            click(window.start_btn)
            pump(lambda: window.probe.active and window.probe.total_samples >= 3, timeout=60)
            require(not window.review_result_button.isEnabled(), "EXPERT_HANDOFF_ENABLED_DURING_RECORDING")
            click(window.stop_btn)
            pump(lambda: not window.probe.active and not window.probe.pending and
                 window.probe.report_result is not None and window._report_state == "saved", timeout=90)
            folder = window.probe.session_folder.resolve(strict=True)
            files = {name: {"sha256": digest(folder / name), "bytes": (folder / name).stat().st_size}
                     for name in ("session.sqlite3", "report.json", "report.html")}
            sources = {path.name: {"sha256": digest(path), "bytes": path.stat().st_size}
                       for path in folder.glob("*.sqlite3")}
            with closing(sqlite3.connect((folder / "session.sqlite3").as_uri() + "?mode=ro", uri=True)) as db:
                recorded_pid, status = db.execute("SELECT pid,exit_code FROM metadata").fetchone()
                samples = db.execute("SELECT count(*) FROM samples").fetchone()[0]
            html = (folder / "report.html").read_text(encoding="utf-8")
            require(recorded_pid == os.getpid() and status == "COMPLETED" and samples >= 3,
                    "EXPERT_REAL_SQLITE_RECORDING_NOT_COMMITTED")
            require("Application root cause not determined" in html, "EXPERT_REPORT_UNKNOWN_CLAIM_CHANGED")
            require(window.stack.currentIndex() == window._page_ids["dashboard"], "EXPERT_STOP_CHANGED_PAGE_WITHOUT_REVIEW")
            # The product owns the explicit post-Stop route; its contract is
            # verified below using actual Qt input, never a private load call.
            click(window.review_result_button)
            pump(lambda: window._interval_worker is None and window._interval_packet is not None and
                 window._interval_packet.get("folder") == str(folder))
            require(window.stack.currentIndex() == window._page_ids["reports"], "EXPERT_HANDOFF_NOT_REPORTS")
            require(str(folder) in window.report_context.text(), "EXPERT_HANDOFF_CONTEXT_NOT_SELECTED_RECORDING")
            require(all(digest(folder / name) == data["sha256"] for name, data in {**files, **sources}.items()),
                    "EXPERT_REVIEW_CHANGED_RECORDED_SOURCES")
            helper_pid = int(window.probe.process.processId())
            proof["recordings"].append({"language": language, "scope": "REAL_GUI_PROCESS_RECORDING",
                "recorded_pid": recorded_pid, "research_helper_pid": helper_pid,
                "recorded_status": status, "samples": samples, "files": files, "recorded_sources": sources,
                "selected_session_matches": window._interval_folder.resolve() == folder,
                "handoff_actual_qt_input": True, "report_html_unknown_preserved": True,
                "source_files_unchanged_after_review": True})
            screenshot("saved-report", language, "REAL_GUI_PROCESS_RECORDING")

        phase("SYNTHETIC_IMPORTED_EVIDENCE")
        fixture_path = synthetic_recording(output / "TEST_ONLY_SYNTHETIC_IMPORTED_EVIDENCE")
        fixture_sha = digest(fixture_path)
        fixture = {"scope": "TEST_ONLY_SYNTHETIC_IMPORTED_EVIDENCE", "sha256": fixture_sha,
            "languages": [], "root_cause": "UNKNOWN", "finding_selection_actual_qt_input": False,
            "event_selection_actual_qt_input": False, "incident_card_actual_qt_input": False,
            "copy_detail_roundtrip": False, "raw_json_roundtrip": False, "source_unchanged": False}
        proof["fixture"] = fixture
        window._load_session_interval(fixture_path.parent)
        pump(lambda: window._interval_worker is None and window._interval_packet is not None and
             window._interval_packet.get("folder") == str(fixture_path.parent))
        for language in ("EN", "RU"):
            window._set_language(language)
            navigate("reports")
            selected_range = tuple(window._interval_packet["interval"]["selected_interval_ns"])
            live_pid = window.probe.pid
            for section in SECTIONS:
                anchor = window.findChild(QPushButton, "expertSection_" + section)
                require(anchor is not None, "EXPERT_SECTION_MISSING_" + section)
                click(anchor)
                target = window._expert_sections[section]
                scroll = window.stack.currentWidget()
                viewport = scroll.viewport()

                def anchor_visible():
                    rect = QRect(target.mapTo(viewport, QPoint()), target.size())
                    return target.isVisible() and not viewport.rect().intersected(rect).isEmpty()

                pump(anchor_visible, timeout=5)
                target_rect = QRect(target.mapTo(viewport, QPoint()), target.size())
                if section == "library":
                    require(window.library_toggle.isChecked() and window.library_panel.isVisible(),
                            "EXPERT_LIBRARY_ANCHOR_NOT_EXPANDED")
                elif section == "actions":
                    require(window.research_toggle.isChecked() and window.research_panel.isVisible(),
                            "EXPERT_ACTION_ANCHOR_NOT_EXPANDED")
                elif section == "technical":
                    require(window.report_technical_toggle.isChecked() and window.report_snapshot_frame.isVisible(),
                            "EXPERT_TECHNICAL_ANCHOR_NOT_EXPANDED")
                require(window.stack.currentIndex() == window._page_ids["reports"] and
                        window._interval_folder == fixture_path.parent and window._interval_process == 1 and
                        tuple(window._interval_packet["interval"]["selected_interval_ns"]) == selected_range and
                        window.probe.pid == live_pid and not window.probe.active and
                        not window.deep_inspector_panel.bridge.has_session,
                        "EXPERT_SECTION_CHANGED_ANALYSIS_SCOPE_OR_LIVE_AUTHORITY_" + section)
                proof["sections"].append({"language": language, "section": section,
                    "actual_qt_input": True, "context_unchanged": True, "target_visible_in_viewport": True,
                    "target_rect_in_viewport": list(target_rect.getRect()),
                    "viewport_rect": list(viewport.rect().getRect())})
            click(window.findChild(QPushButton, "expertSection_findings"))
            phase("FIXTURE_FINDINGS_" + language)
            panel = window.analysis_panel
            click(panel.load)
            pump(lambda: not panel._busy and panel.packet is not None and panel.table.rowCount() >= 2)
            select_row(panel.table, 1)
            require(panel.selection() is not None and panel.selection().get("root_cause") == "UNKNOWN" and
                    panel.selection().get("root_cause_proven") is False and "UNKNOWN" in panel.details.toPlainText(),
                    "EXPERT_FINDING_DETAILS_OR_UNKNOWN_MISSING")
            fixture["finding_selection_actual_qt_input"] = True
            selected_before = panel.selection()
            click(panel.raw)
            require(json.loads(panel.details.toPlainText()) == selected_before, "EXPERT_FINDING_RAW_JSON_MISMATCH")
            click(panel.raw)
            require(panel.selection() == selected_before and "UNKNOWN" in panel.details.toPlainText(),
                    "EXPERT_FINDING_RAW_TOGGLE_LOST_SELECTION")
            fixture["raw_json_roundtrip"] = True
            expected_copy = panel.details.toPlainText()
            click(panel.copy)
            require(QApplication.clipboard().text() == expected_copy, "EXPERT_EXPLICIT_FINDING_COPY_MISMATCH")
            fixture["copy_detail_roundtrip"] = True
            reveal(panel.table)
            screenshot("fixture-findings", language, fixture["scope"])
            phase("MINIMUM_REPORTS_WIDTH_" + language)
            window.resize(1020, 850)
            app.processEvents()
            QTest.qWait(30)
            app.processEvents()
            scroll = window.stack.currentWidget()
            viewport_width = scroll.viewport().width()
            minimum = {"language": language, "logical_window_client": [window.width(), window.height()],
                "actual_qt_resize": True, "viewport_width": viewport_width,
                "outer_horizontal_scroll_maximum": scroll.horizontalScrollBar().maximum(),
                "research_panel_width": window.research_panel.width(),
                "library_panel_width": window.library_panel.width(),
                "expanded_sections": [key for key, toggle, target in (
                    ("library", window.library_toggle, window.library_panel),
                    ("actions", window.research_toggle, window.research_panel),
                    ("technical", window.report_technical_toggle, window.report_snapshot_frame))
                    if toggle.isChecked() and target.isVisible()]}
            proof["minimum_width"].append(minimum)
            click(window.findChild(QPushButton, "expertSection_findings"))
            reveal(panel.table)
            screenshot("fixture-minimum-width", language, fixture["scope"])
            require(minimum["logical_window_client"] == [1020, 850] and
                    minimum["expanded_sections"] == ["library", "actions", "technical"] and
                    minimum["outer_horizontal_scroll_maximum"] == 0 and
                    0 < minimum["research_panel_width"] <= viewport_width and
                    0 < minimum["library_panel_width"] <= viewport_width,
                    "EXPERT_REPORTS_MINIMUM_WIDTH_OVERFLOW_" + json.dumps(minimum, sort_keys=True))
            window.resize(1440, 1000)
            app.processEvents()
            phase("FIXTURE_INCIDENT_CARD_" + language)
            click(panel.card)
            pump(lambda: not panel._busy and panel.card_packet is not None)
            require(panel.card_packet.get("root_cause") == "UNKNOWN" and
                    "UNKNOWN" in panel.details.toPlainText(), "EXPERT_INCIDENT_CARD_UNKNOWN_MISSING")
            click(panel.raw)
            require(json.loads(panel.details.toPlainText()) == panel.card_packet,
                    "EXPERT_COMPLETE_INCIDENT_CARD_RAW_JSON_MISMATCH")
            click(panel.raw)
            fixture["incident_card_actual_qt_input"] = True
            reveal(panel.table)
            screenshot("fixture-incident-card", language, fixture["scope"])
            click(panel.finding)
            require(panel.card_packet is None and panel.selection() == selected_before,
                    "EXPERT_RETURN_TO_FINDING_CHANGED_SELECTION")
            phase("FIXTURE_EVENTS_" + language)
            navigate("events")
            events = window.events_panel
            click(events.load)
            pump(lambda: not events._busy and events.packet is not None and events.table.rowCount() >= 2)
            select_row(events.table, 1)
            require(events.selection() is not None and events.selection().get("verification_class") == "UNVERIFIED_IMPORT" and
                    "UNVERIFIED_IMPORT" in events.details.toPlainText(),
                    "EXPERT_IMPORTED_EVENT_TRUST_LOST")
            fixture["event_selection_actual_qt_input"] = True
            reveal(events.table)
            screenshot("fixture-events", language, fixture["scope"])
            fixture["languages"].append(language)
        fixture["source_unchanged"] = digest(fixture_path) == fixture_sha
        require(fixture["source_unchanged"], "EXPERT_FIXTURE_READER_MODIFIED_SOURCE")
        proof["status"] = "PASS"
    except Exception as exc:
        proof["status"] = "FAIL"
        proof["reason"] = str(exc)
        proof["traceback"] = traceback.format_exc()[-16000:]
    finally:
        phase("CLOSE_OWNERS")
        try:
            window.close()
            pump(lambda: not window.isVisible() and not window.probe.alive and
                 not any(worker.isRunning() or not worker.wait(0) for worker in window.findChildren(QThread)),
                 timeout=90, cleanup=True)
            proof["cleanup"] = {"owners_closed": True, "research_helper_alive": window.probe.alive,
                "running_qthreads": sum(worker.isRunning() for worker in window.findChildren(QThread))}
        except Exception as exc:
            proof["status"] = "FAIL"
            proof["cleanup_error"] = str(exc)
        timer.stop()
        sys.excepthook = old_hook
        proof["phase"] = "FINISHED"
        if proof["callback_errors"] or proof["unexpected_dialogs"]:
            proof["status"] = "FAIL"
        save(output / "expert-gui.json", proof)
    return 0 if proof["status"] == "PASS" else 1


def emit_screenshots(proof, child_output):
    """Retain diagnostic PNGs even when a later workflow assertion failed."""
    rows = proof.get("screenshots", [])
    require(type(rows) is list and len(rows) <= 16, "EXPERT_PNG_COUNT_BUDGET")
    for row in rows:
        require(type(row) is dict and type(row.get("bytes")) is int and
                0 < row["bytes"] <= MAX_PNG_BYTES and
                re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", row.get("id", "")) and
                type(row.get("file")) is str, "EXPERT_PNG_METADATA")
        path = child_output / row["file"]
        require(path.parent == child_output and path.is_file() and not path.is_symlink() and
                path.stat().st_size == row["bytes"] and digest(path) == row["sha256"], "EXPERT_PNG_BYTES_MISMATCH")
        raw = path.read_bytes()
        require(raw.startswith(b"\x89PNG\r\n\x1a\n"), "EXPERT_PNG_SIGNATURE")
        encoded = base64.b64encode(raw).decode("ascii")
        chunks = [encoded[index:index + 12000] for index in range(0, len(encoded), 12000)]
        metadata = {**row, "chunks": len(chunks), "receipt_status": proof.get("status"),
            "actual_source_sha": proof.get("source_identity", {}).get("actual_source_sha"),
            "source_identity_status": proof.get("source_identity", {}).get("source_identity_status")}
        print("EXPERT_GUI_PNG_BEGIN " + json.dumps(metadata, sort_keys=True), flush=True)
        for number, chunk in enumerate(chunks, 1):
            print("EXPERT_GUI_PNG_CHUNK " + row["id"] + " " + str(number) + "/" + str(len(chunks)) + " " + chunk,
                  flush=True)
        print("EXPERT_GUI_PNG_END " + row["id"] + " " + row["sha256"], flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--exe", type=Path)
    args = parser.parse_args()
    hosted_windows()
    if not args.exe:
        sys.path[:0] = [str(ROOT), str(ROOT / "src")]
    from blackbox_universal.provenance import source_identity
    identity = source_identity(args.source_sha)
    require(identity.get("source_identity_status") == "VERIFIED_EXPECTED_HEAD", "EXPERT_LAUNCHER_HEAD_REQUIRED")
    scale = os.environ.get("QT_SCALE_FACTOR", "1")
    require(scale in SCALES, "EXPERT_SCALE_OUTSIDE_MATRIX")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    work = output / "outside-source"
    work.mkdir()
    child_output = output / "gui"
    command = ([str(args.exe.resolve(strict=True))] if args.exe else [sys.executable, str(ROOT / "app.py")])
    command += ["--expert-e2e", str(child_output), "--qa-commit-sha", args.source_sha]
    environment = dict(os.environ)
    environment["QT_QPA_PLATFORM"] = "offscreen"
    if args.exe:
        system = Path(os.environ["SystemRoot"])
        environment["PATH"] = os.pathsep.join((str(system / "System32"), str(system)))
        environment.pop("PYTHONPATH", None)
        environment.pop("PYTHONHOME", None)
    with (output / "child-console.log").open("wb") as log:
        child = subprocess.Popen(command, cwd=work, env=environment, stdout=log, stderr=subprocess.STDOUT,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            child.wait(timeout=360)
        except subprocess.TimeoutExpired:
            import psutil
            descendants = []
            cleanup_errors = []
            try:
                descendants = psutil.Process(child.pid).children(recursive=True)
            except psutil.Error as exc:
                cleanup_errors.append(type(exc).__name__)
            identities = []
            for process in reversed(descendants):
                try:
                    identities.append({"pid": process.pid, "created": process.create_time()})
                    process.kill()
                except psutil.Error as exc:
                    cleanup_errors.append(type(exc).__name__)
            child.kill()
            child.wait(timeout=10)
            _, alive = psutil.wait_procs(descendants, timeout=10)
            failure = {"status": "FAIL", "source_sha": args.source_sha,
                "reason": "EXPERT_ACTUAL_GUI_PROCESS_DEADLINE", "frozen": bool(args.exe), "scale": scale,
                "cleanup": "FORCED_TERMINATION_RESOURCE_FINALIZATION_UNCONFIRMED",
                "launched_gui_pid": child.pid, "descendant_identities": identities,
                "remaining_descendant_pids": [process.pid for process in alive], "cleanup_errors": cleanup_errors}
            save(output / "launcher-timeout.json", failure)
            print("EXPERT_GUI_TIMEOUT " + json.dumps(failure, sort_keys=True), flush=True)
            receipt_path = child_output / "expert-gui.json"
            if receipt_path.is_file() and receipt_path.stat().st_size <= 2 * 1024**2:
                incomplete = json.loads(receipt_path.read_text(encoding="ascii"))
                incomplete["status"] = "FAIL_DEADLINE_FINALIZATION_UNCONFIRMED"
                emit_screenshots(incomplete, child_output)
            raise AssertionError("EXPERT_ACTUAL_GUI_PROCESS_DEADLINE") from None
    receipt_path = child_output / "expert-gui.json"
    if not receipt_path.is_file():
        print("EXPERT_GUI_MISSING_RECEIPT_CONSOLE " +
              (output / "child-console.log").read_bytes()[-16000:].decode("utf-8", "replace"), flush=True)
        error_file = work / "blackbox-qa-error.txt"
        if error_file.is_file():
            print("EXPERT_GUI_EARLY_ERROR " + error_file.read_bytes()[-16000:].decode("utf-8", "replace"), flush=True)
    require(receipt_path.is_file() and receipt_path.stat().st_size <= 2 * 1024**2,
            "EXPERT_ACTUAL_GUI_RECEIPT_MISSING")
    proof = json.loads(receipt_path.read_text(encoding="ascii"))
    if child.returncode or proof.get("status") != "PASS":
        print("EXPERT_GUI_FAILURE " + json.dumps(proof, ensure_ascii=True), flush=True)
        print("EXPERT_GUI_CONSOLE " + (output / "child-console.log").read_bytes()[-16000:].decode("utf-8", "replace"),
              flush=True)
    emit_screenshots(proof, child_output)
    print("EXPERT_GUI_RECEIPT " + json.dumps({**proof, "receipt_sha256": digest(receipt_path)}, sort_keys=True),
          flush=True)
    require(child.returncode == 0, "EXPERT_ACTUAL_GUI_EXIT_FAILURE")
    validate_receipt(proof, source_sha=args.source_sha, frozen=bool(args.exe), scale=scale)


if __name__ == "__main__":
    main()
