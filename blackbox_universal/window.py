"""The BLACK.BOX Universal desktop shell.

Classic desktop window semantics + warm illustrated 90s palette.
The application observes local process metrics and inspects file metadata
without invoking an external diagnostic runtime.
"""
from __future__ import annotations

from datetime import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import psutil
from blackbox_core.contracts import ObserverError
from blackbox_core.report import compare as compare_sessions
from PySide6.QtCore import Qt, QTimer, QThread, Signal, QSettings, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QIcon
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QFrame,
    QGridLayout, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit,
    QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QPushButton,
    QScrollArea, QStackedWidget, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from .monitor import ReadOnlyProbe, available_processes, save_snapshot
from .file_targets import InspectedFile, inspect_file, find_running_executable
from .i18n import translate
from .releases import (Release, NoOfficialRelease, check_latest_release, stage_release,
                       runtime_directory, MAINTENANCE_NAME)
from .shortcuts import create_shortcut
from .theme import COLORS
from .widgets import DesktopMark, MetricCard, SparkleBorder, TrendChart, WindowPanel


def _label(text: str, kind: str = "", wrap: bool = True) -> QLabel:
    item = QLabel(text)
    if kind:
        item.setObjectName(kind)
    item.setWordWrap(wrap)
    return item


def _button(text: str, kind: str = "") -> QPushButton:
    b = QPushButton(text)
    if kind:
        b.setObjectName(kind)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


def _page() -> tuple[QWidget, QVBoxLayout]:
    widget = QWidget()
    widget.setStyleSheet("background: transparent;")
    content = QVBoxLayout(widget)
    content.setContentsMargins(24, 21, 24, 26)
    content.setSpacing(17)
    content.setAlignment(Qt.AlignmentFlag.AlignTop)
    return widget, content


class _UpdateWorker(QThread):
    """All network and ZIP work is outside the Qt GUI event loop."""

    result_ready = Signal(object, str)

    def __init__(self, task: str, parent=None, release: Release | None = None,
                 install: Path | None = None):
        super().__init__(parent)
        self.task = task
        self.release = release
        self.install = install

    def run(self) -> None:
        try:
            if self.task == "check":
                result = check_latest_release()
            elif self.task == "download" and self.release and self.install:
                result = stage_release(self.release, self.install)
            else:
                raise ValueError("INVALID_UPDATE_TASK")
            self.result_ready.emit(result, "")
        except NoOfficialRelease:
            self.result_ready.emit(None, "NO_OFFICIAL_RELEASE")
        except Exception as exc:
            # Do not expose network credentials, private paths or stack traces.
            self.result_ready.emit(None, type(exc).__name__)


class UniversalWindow(QMainWindow):
    PAGES = (
        ("dashboard", "01  OVERVIEW"),
        ("processes", "02  PROCESSES"),
        ("events", "03  EVENT LOG"),
        ("reports", "04  REPORTS"),
        ("settings", "05  SETTINGS"),
    )

    def __init__(self):
        super().__init__()
        self.setWindowTitle("BLACK.BOX Universal | Retro Workstation")
        self.setMinimumSize(1020, 690)
        self.resize(1330, 850)
        self.probe = ReadOnlyProbe()
        self._prefs = QSettings("BlackBox", "BLACK.BOX Universal")
        saved_language = self._prefs.value("language", "EN")
        self.language = saved_language if saved_language in ("RU", "ENG", "EN") else "EN"
        if self.language == "ENG":
            self.language = "EN"
        self._update_worker = None
        self._report_state = "waiting"
        self._available_release = None
        self._maintenance_launching = False
        self._pending_update_stage = None
        icon_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
        icon_file = icon_dir / "assets" / "blackbox.png"
        if icon_file.is_file():
            self.setWindowIcon(QIcon(str(icon_file)))
        self._process_rows: list[dict] = []
        self._selected_file: InspectedFile | None = None
        self._nav_buttons: dict[str, QPushButton] = {}
        self._page_ids: dict[str, int] = {}
        self._build()
        self._refresh_process_list()
        self._update_all()
        self._navigate("dashboard")
        self._set_language(self.language)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)
        if self._prefs.value("check_updates_at_start", True, type=bool):
            QTimer.singleShot(1800, self._automatic_update_check)

    def _build(self) -> None:
        desktop = QWidget()
        desktop.setObjectName("desktop")
        self.setCentralWidget(desktop)
        root = QVBoxLayout(desktop)
        root.setContentsMargins(17, 8, 17, 0)
        root.setSpacing(7)

        banner = QHBoxLayout()
        banner.setSpacing(10)
        icon = DesktopMark()
        banner.addWidget(icon)
        title_col = QVBoxLayout()
        title_col.setSpacing(0)
        title_col.addWidget(_label("BLACK.BOX", "logo", False))
        subtitle = _label("U N I V E R S A L   W O R K S T A T I O N", wrap=False)
        subtitle.setStyleSheet("color: #d7f5d4; font: 700 10px 'Consolas';")
        title_col.addWidget(subtitle)
        banner.addLayout(title_col)
        banner.addStretch()
        banner.addWidget(_label("LOCAL MODE   ●   PRIVATE BY DESIGN",
                                wrap=False))
        root.addLayout(banner)
        root.addWidget(SparkleBorder())

        shell = QFrame()
        shell.setObjectName("shell")
        root.addWidget(shell, 1)
        shell_layout = QVBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)

        chrome = QFrame()
        chrome.setObjectName("topChrome")
        header = QHBoxLayout(chrome)
        header.setContentsMargins(12, 4, 7, 4)
        header.setSpacing(5)
        header.addWidget(_label("▣  BLACK.BOX UNIVERSAL  /  MONITOR.EXE", "chromeTitle", False))
        header.addStretch()
        for glyph, action in (
            ("_", self.showMinimized),
            ("□", self._toggle_maximized),
            ("×", self.close),
        ):
            control = _button(glyph, "windowControl")
            control.clicked.connect(action)
            header.addWidget(control)
        shell_layout.addWidget(chrome)

        toolbar = QFrame()
        toolbar.setObjectName("toolbar")
        tl = QHBoxLayout(toolbar)
        tl.setContentsMargins(11, 4, 12, 4)
        tl.setSpacing(7)
        file_menu = QMenu(self)
        file_menu.addAction("Save snapshot as JSON…", self._export)
        file_menu.addSeparator()
        file_menu.addAction("Quit BLACK.BOX", self.close)
        view_menu = QMenu(self)
        for key, label in self.PAGES:
            view_menu.addAction(label.replace("  ", " · "), lambda checked=False, n=key: self._navigate(n))
        help_menu = QMenu(self)
        help_menu.addAction("About / safety notes", self._about)
        for name, menu in (("FILE", file_menu), ("VIEW", view_menu), ("HELP", help_menu)):
            button = _button(name + "  ▾")
            button.setMenu(menu)
            tl.addWidget(button)
        tl.addStretch()
        self.update_button = _button("↻  CHECK UPDATES", "update")
        self.update_button.setProperty("available", False)
        self.update_button.setToolTip(
            "Checks official GitHub Releases. Only verified newer versions turn green.")
        self.update_button.clicked.connect(self._update_click)
        tl.addWidget(self.update_button)
        self.toolbar_state = _label("●  OBSERVER READY", "signal", False)
        tl.addWidget(self.toolbar_state)
        shell_layout.addWidget(toolbar)

        body = QWidget()
        body.setStyleSheet("background: #fff7e4;")
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)
        shell_layout.addWidget(body, 1)

        sidebar = QFrame()
        sidebar.setObjectName("sideNav")
        sidebar.setFixedWidth(198)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(0, 14, 0, 11)
        side.setSpacing(3)
        brand = _label("  ▧  SYSTEM DISK (C:)", wrap=False)
        brand.setStyleSheet("font: bold 11px 'Consolas'; color: #736b7e; padding: 5px;")
        side.addWidget(brand)
        for key, name in self.PAGES:
            button = _button("   " + name, "nav")
            button.clicked.connect(lambda checked=False, page=key: self._navigate(page))
            button.setProperty("active", False)
            button.setToolTip(name.replace("  ", " · "))
            self._nav_buttons[key] = button
            side.addWidget(button)
        side.addStretch()
        # Compact feedback/language controls in the marked empty sidebar
        # area; no networking until GitHub/email is explicitly opened.
        feedback = QHBoxLayout()
        feedback.setContentsMargins(8, 0, 8, 1)
        feedback.setSpacing(4)
        self.github_button = _button("⌂ GITHUB", "smallLink")
        self.github_button.setToolTip("GitHub repository")
        self.github_button.clicked.connect(self._open_github)
        self.email_button = _button("✉ E-MAIL", "smallLink")
        self.email_button.setToolTip("Send feedback")
        self.email_button.clicked.connect(self._open_email)
        feedback.addWidget(self.github_button)
        feedback.addWidget(self.email_button)
        side.addLayout(feedback)
        languages = QHBoxLayout()
        languages.setContentsMargins(8, 0, 8, 5)
        languages.setSpacing(5)
        self.lang_ru = _button("RU", "smallLink")
        self.lang_en = _button("ENG", "smallLink")
        self.lang_ru.clicked.connect(lambda: self._set_language("RU"))
        self.lang_en.clicked.connect(lambda: self._set_language("EN"))
        languages.addWidget(self.lang_ru)
        languages.addWidget(self.lang_en)
        side.addLayout(languages)
        rule = QFrame()
        rule.setFixedHeight(2)
        rule.setStyleSheet("background: #837789;")
        side.addWidget(rule)
        side.addWidget(_label("    NO CLOUD · NO INJECTION", "caption"))
        side.addWidget(_label("    READ-ONLY · OFFLINE", "caption"))
        body_layout.addWidget(sidebar)

        self.stack = QStackedWidget()
        self.stack.setStyleSheet("background: #fff7e4;")
        body_layout.addWidget(self.stack, 1)
        builders = (
            ("dashboard", self._build_dashboard),
            ("processes", self._build_processes),
            ("events", self._build_events),
            ("reports", self._build_reports),
            ("settings", self._build_settings),
        )
        for key, build in builders:
            self._page_ids[key] = self.stack.addWidget(self._as_scroll(build()))

        taskbar = QFrame()
        taskbar.setObjectName("taskbar")
        tbar = QHBoxLayout(taskbar)
        tbar.setContentsMargins(7, 3, 7, 3)
        tbar.setSpacing(10)
        start = _button("▦  START")
        start_menu = QMenu(self)
        start_menu.addAction("Overview", lambda: self._navigate("dashboard"))
        start_menu.addAction("Choose process", lambda: self._navigate("processes"))
        start_menu.addAction("Save JSON…", self._export)
        start_menu.addSeparator()
        start_menu.addAction("Exit", self.close)
        start.setMenu(start_menu)
        tbar.addWidget(start)
        self.task_active = _label("▣  BLACK.BOX UNIVERSAL", "taskText", False)
        tbar.addWidget(self.task_active)
        tbar.addStretch()
        self.task_privacy = _label("◎  OFFLINE / LOCAL", "taskText", False)
        tbar.addWidget(self.task_privacy)
        self.clock = _label("", "taskText", False)
        tbar.addWidget(self.clock)
        root.addWidget(taskbar)

    def _as_scroll(self, page: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(page)
        return scroll

    def _build_dashboard(self) -> QWidget:
        page, content = _page()
        top = QHBoxLayout()
        top.addStretch()
        self.live_badge = _label("●  NO TARGET SELECTED", "signal", False)
        top.addWidget(self.live_badge)
        content.addLayout(top)

        metrics = QGridLayout()
        metrics.setSpacing(11)
        self.card_cpu = MetricCard("PROCESS CPU", "--", "Current sample", COLORS["coral"])
        self.card_ram = MetricCard("WORKING MEMORY", "--", "Selected process RSS", COLORS["teal"])
        self.card_child = MetricCard("ACTIVE PROCESSES", "--", "Target + visible children", COLORS["lilac"])
        self.card_samples = MetricCard("SAMPLES", "0", "Read-only observations", COLORS["peach"])
        for i, card in enumerate((self.card_cpu, self.card_ram,
                                  self.card_child, self.card_samples)):
            metrics.addWidget(card, 0, i)
        content.addLayout(metrics)

        middle = QHBoxLayout()
        middle.setSpacing(12)
        chart_panel = WindowPanel("Resource telemetry", "REAL SAMPLES")
        self.chart = TrendChart()
        chart_panel.content.addWidget(self.chart)
        middle.addWidget(chart_panel, 7)

        status = WindowPanel("Current session", "TARGET STATUS")
        identity_row = QHBoxLayout()
        identity_row.setSpacing(10)
        identity_left = QVBoxLayout()
        identity_left.setSpacing(7)
        self.target_name = _label("No process selected", "h2", False)
        identity_left.addWidget(self.target_name)
        self.target_pid = _label("Select an application to begin.", "caption")
        identity_left.addWidget(self.target_pid)
        self.state_text = _label("READY TO ATTACH", "signal", False)
        identity_left.addWidget(self.state_text)
        identity_row.addLayout(identity_left, 3)

        # A concise acknowledgement beside the selected PID, not a
        # decorative heading. This is hidden until a real PID is attached.
        self.target_binding = QFrame()
        self.target_binding.setObjectName("targetBinding")
        self.target_binding.setStyleSheet(
            "QFrame#targetBinding { background: #f0ecdb; "
            "border-left: 3px solid #078b84; border-top: 0; "
            "border-right: 0; border-bottom: 0; }")
        binding_layout = QVBoxLayout(self.target_binding)
        binding_layout.setContentsMargins(11, 9, 7, 9)
        binding_layout.setSpacing(5)
        self.target_binding_title = _label("", wrap=False)
        self.target_binding_title.setObjectName("targetBindingTitle")
        self.target_binding_title.setStyleSheet(
            "color: #056c6d; font: 700 11px 'Segoe UI';")
        self.target_binding_detail = _label("", wrap=True)
        self.target_binding_detail.setObjectName("targetBindingDetail")
        self.target_binding_detail.setStyleSheet(
            "color: #605d6d; font: 11px 'Segoe UI';")
        binding_layout.addWidget(self.target_binding_title)
        binding_layout.addWidget(self.target_binding_detail)
        binding_layout.addStretch()
        identity_row.addWidget(self.target_binding, 4)
        status.content.addLayout(identity_row)
        status.content.addStretch()
        select_btn = _button("▣  CHOOSE APPLICATION", "primary")
        select_btn.clicked.connect(lambda: self._navigate("processes"))
        status.content.addWidget(select_btn)
        self.start_btn = _button("▶  START OBSERVING", "accent")
        self.start_btn.clicked.connect(self._start)
        status.content.addWidget(self.start_btn)
        self.stop_btn = _button("■  STOP OBSERVING")
        self.stop_btn.clicked.connect(self._stop)
        status.content.addWidget(self.stop_btn)
        middle.addWidget(status, 4)
        content.addLayout(middle)

        notes = WindowPanel("System messages", "LATEST ACTIVITY")
        self.recent_messages = QPlainTextEdit()
        self.recent_messages.setReadOnly(True)
        self.recent_messages.setMinimumHeight(105)
        self.recent_messages.setMaximumHeight(138)
        notes.content.addWidget(self.recent_messages)
        content.addWidget(notes)
        return page

    def _build_processes(self) -> QWidget:
        page, content = _page()
        head = QHBoxLayout()
        head.addWidget(_label("WINDOWS / PROCESS EXPLORER", "eyebrow", False))
        head.addStretch()
        refresh = _button("↻  REFRESH")
        refresh.clicked.connect(self._refresh_process_list)
        head.addWidget(refresh)
        content.addLayout(head)

        file_row = QHBoxLayout()
        file_row.setSpacing(8)
        self.browse_file_button = _button("▣  SELECT APPLICATION FILE")
        self.browse_file_button.clicked.connect(self._choose_application_file)
        file_row.addWidget(self.browse_file_button)
        self.selected_file_path = QLineEdit()
        self.selected_file_path.setReadOnly(True)
        self.selected_file_path.setPlaceholderText("No application file selected")
        file_row.addWidget(self.selected_file_path, 1)
        content.addLayout(file_row)

        file_actions = QHBoxLayout()
        file_actions.setSpacing(8)
        self.find_file_process_button = _button("◈  FIND RUNNING EXE")
        self.find_file_process_button.setEnabled(False)
        self.find_file_process_button.clicked.connect(self._attach_file_target)
        file_actions.addWidget(self.find_file_process_button)
        self.launch_exe_button = _button("▶  LAUNCH SELECTED EXE")
        self.launch_exe_button.setEnabled(False)
        self.launch_exe_button.clicked.connect(self._launch_file_target)
        file_actions.addWidget(self.launch_exe_button)
        file_actions.addStretch()
        content.addLayout(file_actions)
        self.file_description = _label(
            "Select any file to view its local metadata. Only running EXE files can be attached.",
            "caption")
        content.addWidget(self.file_description)

        self.process_search = QLineEdit()
        self.process_search.setPlaceholderText("Search by process name or PID…")
        self.process_search.setClearButtonEnabled(True)
        self.process_search.textChanged.connect(self._filter_processes)
        content.addWidget(self.process_search)
        self.process_table = QTableWidget(0, 4)
        self.process_table.setHorizontalHeaderLabels(("NAME", "PID", "MEMORY", "STATE"))
        self.process_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)
        for col in (1, 2, 3):
            self.process_table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents)
        self.process_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.process_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.process_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.process_table.setAlternatingRowColors(True)
        self.process_table.verticalHeader().setVisible(False)
        self.process_table.cellDoubleClicked.connect(lambda row, col: self._attach_selected())
        self.process_table.setMinimumHeight(290)
        content.addWidget(self.process_table, 1)
        bottom = QHBoxLayout()
        self.process_count = _label("Scanning processes…", "caption")
        bottom.addWidget(self.process_count)
        bottom.addStretch()
        attach = _button("◈  ATTACH SELECTED PROCESS", "primary")
        attach.clicked.connect(self._attach_selected)
        bottom.addWidget(attach)
        content.addLayout(bottom)
        return page

    def _build_events(self) -> QWidget:
        page, content = _page()
        content.addWidget(_label("WINDOWS / EVENT VIEWER", "eyebrow", False))
        frame = WindowPanel("Session timeline", "LATEST FIRST")
        self.event_table = QTableWidget(0, 3)
        self.event_table.setHorizontalHeaderLabels(("TIME (UTC)", "SIGNAL", "DETAILS"))
        self.event_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents)
        self.event_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents)
        self.event_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch)
        self.event_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.event_table.setAlternatingRowColors(True)
        self.event_table.verticalHeader().setVisible(False)
        self.event_table.setMinimumHeight(370)
        frame.content.addWidget(self.event_table)
        content.addWidget(frame)
        content.addWidget(_label(
            "A disappearing process or high CPU is a clue, not a proven defect.",
            "caption"))
        return page

    def _build_reports(self) -> QWidget:
        page, content = _page()
        h = QHBoxLayout()
        h.addWidget(_label("LOCAL DISK / REPORTS", "eyebrow", False))
        h.addStretch()
        save = _button("▣  SAVE JSON SNAPSHOT", "primary")
        save.clicked.connect(self._export)
        h.addWidget(save)
        content.addLayout(h)
        frame = WindowPanel("Structured observation", "SCHEMA 1")
        self.report_preview = QPlainTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setMinimumHeight(375)
        frame.content.addWidget(self.report_preview)
        content.addWidget(frame)
        self.report_status_label = _label(
            "Local evidence will be saved after Stop.", "caption")
        content.addWidget(self.report_status_label)
        controls = QHBoxLayout()
        self.open_report_button = _button("▣  OPEN HTML REPORT")
        self.open_report_button.clicked.connect(self._open_saved_report)
        controls.addWidget(self.open_report_button)
        self.session_location = _label("No persisted session yet", "caption")
        controls.addWidget(self.session_location, 1)
        compare_button = _button("≍  COMPARE TWO SESSIONS")
        compare_button.clicked.connect(self._compare_sessions)
        controls.addWidget(compare_button)
        content.addLayout(controls)
        content.addWidget(_label(
            "Automatic SQLite, HTML and JSON session reports are saved "
            "when you press STOP. Manual JSON exports are optional. "
            "Inspect process names and PIDs before sharing.", "caption"))
        return page

    def _build_settings(self) -> QWidget:
        page, content = _page()
        content.addWidget(_label("CONTROL PANEL / PREFERENCES", "eyebrow", False))
        setting = WindowPanel("Observation settings", "LOCAL CONFIGURATION")
        setting.content.addWidget(_label("SAMPLE INTERVAL", "cardTitle"))
        self.interval_combo = QComboBox()
        for seconds in (1, 2, 5):
            self.interval_combo.addItem(f"Every {seconds} second" + ("s" if seconds > 1 else ""),
                                        seconds * 1000)
        self.interval_combo.currentIndexChanged.connect(self._change_interval)
        setting.content.addWidget(self.interval_combo)
        setting.content.addWidget(_label(
            "This controls process sampling frequency. Longer intervals reduce "
            "overhead but can miss short-lived activity.", "caption"))
        self.auto_check = QCheckBox("Check GitHub Releases when the app starts")
        self.auto_check.setChecked(self._prefs.value(
            "check_updates_at_start", True, type=bool))
        self.auto_check.toggled.connect(
            lambda value: self._prefs.setValue("check_updates_at_start", value))
        setting.content.addWidget(self.auto_check)
        setting.content.addWidget(_label("PRIVACY & SECURITY", "cardTitle"))
        setting.content.addWidget(_label(
            "• Read-only process counters\n"
            "• No code injection or target manipulation\n"
            "• No automatic upload or account sign-in\n"
            "• Report export only when explicitly requested\n"
            "• No administrator privileges requested by this shell", "caption"))
        content.addWidget(setting)
        about = WindowPanel("About BLACK.BOX", "PREVIEW / v0.3")
        about.content.addWidget(_label(
            "A public-domain-independent desktop shell built from original "
            "PySide6 widgets. Inspired by classic desktop window geometry "
            "and warm retro illustrations, not copied system artwork.", "caption"))
        about.content.addWidget(_label(
            "Diagnostics are produced by the local observer. Deep tracing, "
            "Windows ETW and crash dump analysis are not present in this build.",
            "caption"))
        content.addWidget(about)
        maint = WindowPanel("Portable maintenance", "Managed locally")
        maint.content.addWidget(_label(
            "Updates replace previous application files, keep local logs and "
            "remove old versions. Uninstall removes the portable program "
            "and keeps diagnostic sessions in Documents.", "caption"))
        row = QHBoxLayout()
        self.shortcut_button = _button("▣  CREATE DESKTOP SHORTCUT")
        self.shortcut_button.clicked.connect(self._create_shortcut)
        self.uninstall_button = _button("■  UNINSTALL APPLICATION")
        self.uninstall_button.clicked.connect(self._request_uninstall)
        row.addWidget(self.shortcut_button)
        row.addWidget(self.uninstall_button)
        maint.content.addLayout(row)
        content.addWidget(maint)
        return page

    def _t(self, original: str) -> str:
        return translate(original, self.language)

    def _set_language(self, language: str) -> None:
        if language not in ("EN", "RU"):
            return
        self.language = language
        self._prefs.setValue("language", language)
        # Stable English source strings are kept separately so changing
        # languages never translates already translated text.
        changing = {self.target_name, self.target_pid, self.state_text,
                    self.live_badge, self.toolbar_state, self.clock,
                    self.session_location, self.process_count,
                    self.report_status_label, self.file_description,
                    self.target_binding_title, self.target_binding_detail}
        from PySide6.QtWidgets import QLabel
        for label in self.findChildren(QLabel):
            if label in changing or label.objectName() == "metricValue":
                continue
            original = label.property("bb_english")
            if original is None:
                original = label.text()
                label.setProperty("bb_english", original)
            label.setText(self._t(str(original)))
        for button in self.findChildren(QPushButton):
            if button in (self.update_button, self.lang_ru, self.lang_en):
                continue
            original = button.property("bb_english")
            if original is None:
                original = button.text()
                button.setProperty("bb_english", original)
            button.setText(self._t(str(original)))
            if button in (self.github_button, self.email_button):
                button.setToolTip(self._t(
                    "GitHub repository" if button is self.github_button else "Send feedback"))
        for action in self.findChildren(QAction):
            original = action.property("bb_english")
            if original is None:
                original = action.text()
                action.setProperty("bb_english", original)
            action.setText(self._t(str(original)))
        for table in (self.process_table, self.event_table):
            for i in range(table.columnCount()):
                header = table.horizontalHeaderItem(i)
                if header is None:
                    continue
                original = header.data(Qt.ItemDataRole.UserRole)
                if not original:
                    original = header.text()
                    header.setData(Qt.ItemDataRole.UserRole, original)
                header.setText(self._t(str(original)))
        self.process_search.setPlaceholderText(
            self._t("Search by process name or PID…"))
        self.selected_file_path.setPlaceholderText(
            self._t("No application file selected"))
        self._render_selected_file()
        for i in range(self.interval_combo.count()):
            seconds = self.interval_combo.itemData(i) // 1000
            source = f"Every {seconds} second" + ("s" if seconds > 1 else "")
            self.interval_combo.setItemText(i, self._t(source))
        self.auto_check.setText(
            "Проверять GitHub Releases при запуске" if language == "RU"
            else "Check GitHub Releases when the app starts")
        self.chart.set_language(language)
        self._refresh_report_status()
        self.lang_ru.setProperty("active", language == "RU")
        self.lang_en.setProperty("active", language == "EN")
        for button in (self.lang_ru, self.lang_en):
            button.style().unpolish(button)
            button.style().polish(button)
        self._refresh_update_button()
        self._update_all()
        self._filter_processes(self.process_search.text())
        if self.stack.currentIndex() == self._page_ids["reports"]:
            self._update_report_preview()

    def _open_github(self) -> None:
        QDesktopServices.openUrl(
            QUrl("https://github.com/jumonja-maker/BlackBox-Rep.-Alva-"))

    def _open_email(self) -> None:
        QDesktopServices.openUrl(
            QUrl("mailto:jumonjescu@mail.ru?subject=BLACK.BOX%20Universal%20feedback"))

    def _refresh_update_button(self, state: str = "") -> None:
        if self._available_release:
            text = "✓  UPDATE AVAILABLE"
            self.update_button.setToolTip(
                f"BLACK.BOX Universal {self._available_release.version}")
        elif state == "checking":
            text = "Checking…"
        elif state == "latest":
            text = "✓  UP TO DATE"
        elif state == "no_release":
            text = "ℹ  NO OFFICIAL RELEASE"
        elif state == "error":
            text = "⚠  UPDATE CHECK FAILED"
        else:
            text = "↻  CHECK UPDATES"
        self.update_button.setText(self._t(text))
        self.update_button.setProperty("available", bool(self._available_release))
        self.update_button.style().unpolish(self.update_button)
        self.update_button.style().polish(self.update_button)

    def _automatic_update_check(self) -> None:
        # Never issue hidden HTTP requests while merely constructing a Qt
        # widget in unit tests or while the app is already closing.
        if self.isVisible() and not self._maintenance_launching:
            self._check_updates()

    def _check_updates(self) -> None:
        if self._update_worker is not None:
            return
        self._refresh_update_button("checking")
        self._update_worker = _UpdateWorker("check", self)
        self._update_worker.result_ready.connect(self._update_checked)
        self._update_worker.finished.connect(self._worker_finished)
        self._update_worker.start()

    def _worker_finished(self) -> None:
        # The executable must never close while a QThread remains alive.
        self._update_worker = None
        if self._pending_update_stage is not None:
            folder = self._pending_update_stage
            self._pending_update_stage = None
            self._launch_maintenance("update", staged=folder)

    def _update_checked(self, release: object, error: str) -> None:
        self._available_release = release if isinstance(release, Release) else None
        if error == "NO_OFFICIAL_RELEASE":
            self._refresh_update_button("no_release")
            self.update_button.setToolTip(self._t(
                "No official version is published yet. Development builds are not automatic updates."))
        elif error:
            self._refresh_update_button("error")
            self.update_button.setToolTip(self._t(
                "Could not verify the release. Existing app is unaffected."))
        else:
            self._refresh_update_button("latest")
            if self._available_release is None:
                self.update_button.setToolTip(self._t(
                    "No newer verified official version is available."))

    def _update_click(self) -> None:
        if self._update_worker is not None:
            return
        if self._available_release is None:
            self._check_updates()
            return
        install = runtime_directory()
        if install is None:
            QMessageBox.information(
                self, "Update", self._t(
                    "Updates are available only in the installed portable Windows build."))
            return
        if self.probe.active:
            QMessageBox.warning(
                self, "Update", self._t(
                    "Stop observing and save the session before updating."))
            return
        yes = QMessageBox.question(
            self, "BLACK.BOX Universal",
            self._t("Download and install the verified new version? "
                    "Old application files will be replaced; logs are preserved."),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if yes != QMessageBox.StandardButton.Yes:
            return
        self._refresh_update_button("checking")
        self.update_button.setEnabled(False)
        self._update_worker = _UpdateWorker(
            "download", self, release=self._available_release, install=install)
        self._update_worker.result_ready.connect(self._update_downloaded)
        self._update_worker.finished.connect(self._worker_finished)
        self._update_worker.start()

    def _update_downloaded(self, staged: object, error: str) -> None:
        self.update_button.setEnabled(True)
        if error or not isinstance(staged, Path):
            QMessageBox.warning(
                self, "BLACK.BOX Universal",
                self._t("Update download failed verification. "
                        "Your current application remains unchanged."))
            self._refresh_update_button("error")
            return
        self._pending_update_stage = staged

    def _create_shortcut(self) -> None:
        install = runtime_directory()
        if install is None:
            QMessageBox.information(
                self, "BLACK.BOX Universal",
                self._t("A shortcut can be created from the portable Windows EXE."))
            return
        try:
            path = create_shortcut(install / "BLACK.BOX-Universal.exe")
        except (OSError, ValueError, subprocess.SubprocessError):
            QMessageBox.warning(self, "BLACK.BOX Universal",
                                self._t("Could not create a desktop shortcut."))
            return
        QMessageBox.information(self, "BLACK.BOX Universal",
                                self._t("Desktop shortcut created.") + "\n" + str(path))

    def _request_uninstall(self) -> None:
        install = runtime_directory()
        if install is None:
            QMessageBox.information(
                self, "BLACK.BOX Universal",
                self._t("Uninstall is available only for the portable Windows build."))
            return
        if self.probe.active:
            QMessageBox.warning(
                self, "BLACK.BOX Universal",
                self._t("Stop observing before removing the application."))
            return
        answer = QMessageBox.warning(
            self, "BLACK.BOX Universal",
            self._t("Completely remove this portable application folder? "
                    "Session evidence in Documents is preserved; any logs inside "
                    "the app folder are moved into Documents first."),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if answer == QMessageBox.StandardButton.Yes:
            self._launch_maintenance("uninstall")

    def _launch_maintenance(self, action: str, staged: Path | None = None) -> None:
        install = runtime_directory()
        if install is None:
            return
        scratch = Path(tempfile.mkdtemp(prefix="bb-maintenance-"))
        try:
            helper = scratch / MAINTENANCE_NAME
            shutil.copy2(install / MAINTENANCE_NAME, helper)
            command = [str(helper), action, "--install", str(install),
                       "--wait-pid", str(os.getpid())]
            if staged is not None:
                command += ["--staged", str(staged)]
            kwargs = {"cwd": str(scratch), "close_fds": True}
            if os.name == "nt":
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            subprocess.Popen(command, **kwargs)
        except (OSError, subprocess.SubprocessError):
            shutil.rmtree(scratch, ignore_errors=True)
            if staged is not None:
                shutil.rmtree(staged.parent, ignore_errors=True)
            QMessageBox.warning(self, "BLACK.BOX Universal",
                                self._t("Could not start maintenance. No files were changed."))
            return
        self._maintenance_launching = True
        self.close()

    def _toggle_maximized(self) -> None:
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def _navigate(self, page: str) -> None:
        self.stack.setCurrentIndex(self._page_ids[page])
        for key, button in self._nav_buttons.items():
            button.setProperty("active", key == page)
            button.style().unpolish(button)
            button.style().polish(button)
        # Qt can auto-scroll to whichever child happens to take focus during
        # construction. Always show the top title and full metric cards.
        self.stack.currentWidget().verticalScrollBar().setValue(0)
        if page == "reports":
            self._update_report_preview()
        if page == "events":
            self._update_event_table()

    def _refresh_process_list(self) -> None:
        self._process_rows = available_processes()
        self._filter_processes(self.process_search.text())

    def _filter_processes(self, query: str = "") -> None:
        query = query.strip().casefold()
        visible = [r for r in self._process_rows if
                   query in r["name"].casefold() or query in str(r["pid"])]
        self.process_table.setRowCount(len(visible))
        for row_idx, item in enumerate(visible):
            cells = (item["name"], str(item["pid"]),
                     f'{item["rss_mb"]:.1f} MB' if item["rss_mb"] is not None else "—",
                     item["status"])
            for column, value in enumerate(cells):
                cell = QTableWidgetItem(value)
                if column == 1:
                    cell.setData(Qt.ItemDataRole.UserRole, item["pid"])
                self.process_table.setItem(row_idx, column, cell)
        self.process_count.setText(
            f"{len(visible)} из {len(self._process_rows)} процессов" if self.language == "RU"
            else f"{len(visible)} shown / {len(self._process_rows)} available")

    def _choose_application_file(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(
            self, self._t("Choose an application or another file"), "",
            self._t("Applications and related files (*.exe *.com *.dll *.sys *.msi *.bat *.cmd *.ps1 *.py *.jar);;All files (*)"))
        if not chosen:
            return
        try:
            inspected = inspect_file(chosen)
        except (OSError, ValueError, OverflowError):
            QMessageBox.warning(
                self, "BLACK.BOX Universal", self._t("Cannot read the selected file."))
            return
        self._selected_file = inspected
        self.selected_file_path.setText(str(inspected.path))
        self.selected_file_path.setToolTip(str(inspected.path))
        self.find_file_process_button.setEnabled(inspected.executable_target)
        self.launch_exe_button.setEnabled(
            inspected.executable_target and os.name == "nt")
        self._render_selected_file()

    def _render_selected_file(self) -> None:
        item = self._selected_file
        if item is None:
            self.file_description.setText(self._t(
                "Select any file to view its local metadata. Only running EXE files can be attached."))
            self.file_description.setToolTip("")
            return
        units = f"{item.size_bytes:,} bytes"
        kind = self._t(item.kind)
        architecture = f" · {item.architecture}" if item.architecture else ""
        details = f"{kind}{architecture} · {units} · {item.modified_utc}"
        if item.executable_target:
            note = self._t(
                "EXE ready: find its running process, or explicitly launch it first.")
        else:
            note = self._t(
                "Metadata only: this file is not a runnable Windows EXE target.")
        self.file_description.setText(f"{details}\n{note}")
        self.file_description.setToolTip(
            "SHA-256: " + item.sha256 if item.sha256 else self._t(
                "SHA-256 skipped for files larger than 16 MiB."))

    def _attach_pid(self, pid: int) -> None:
        try:
            self.probe.attach(pid)
        except (psutil.Error, OSError, ValueError, RuntimeError, ObserverError):
            QMessageBox.warning(
                self, self._t("Cannot attach"), self._t(
                    "This process is unavailable or protected. Choose another one."))
            return
        self._update_all()
        self._navigate("dashboard")

    def _attach_file_target(self) -> None:
        item = self._selected_file
        if item is None or not item.executable_target:
            return
        if self.probe.active:
            QMessageBox.information(
                self, "BLACK.BOX Universal", self._t(
                    "Stop observing before choosing another application."))
            return
        matches = find_running_executable(item.path)
        if not matches:
            QMessageBox.information(
                self, "BLACK.BOX Universal", self._t(
                    "This EXE is not running. You can launch it explicitly, or open it yourself and search again."))
            return
        if len(matches) > 1:
            choices = [f"{name} · PID {pid}" for pid, name in matches]
            choice, ok = QInputDialog.getItem(
                self, self._t("Choose running instance"), self._t(
                    "Several instances use this executable:"), choices, 0, False)
            if not ok:
                return
            pid = matches[choices.index(choice)][0]
        else:
            pid = matches[0][0]
        # Recheck the executable identity before attaching: a PID may have
        # vanished or been reused after enumeration.
        try:
            process = psutil.Process(pid)
            if os.path.normcase(os.path.realpath(process.exe())) != (
                    os.path.normcase(os.path.realpath(str(item.path)))):
                raise psutil.NoSuchProcess(pid)
        except (psutil.Error, OSError, ValueError):
            QMessageBox.warning(self, "BLACK.BOX Universal", self._t(
                "The matched process changed or is inaccessible. Search again."))
            return
        self._attach_pid(pid)

    def _launch_file_target(self) -> None:
        item = self._selected_file
        if item is None or not item.executable_target or os.name != "nt":
            return
        if self.probe.active:
            QMessageBox.information(self, "BLACK.BOX Universal", self._t(
                "Stop observing before choosing another application."))
            return
        confirmation = QMessageBox.question(
            self, "BLACK.BOX Universal",
            self._t("Run this EXE on your computer? BLACK.BOX cannot guarantee the file is safe.") +
            "\n\n" + str(item.path),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if confirmation != QMessageBox.StandardButton.Yes:
            return
        try:
            # Never use the shell, scripts, command interpreters, or implicit
            # file association. Revalidate immediately before execution.
            fresh = inspect_file(item.path)
            if not fresh.executable_target or fresh.size_bytes != item.size_bytes or (
                    item.sha256 is not None and fresh.sha256 != item.sha256):
                raise ValueError("SELECTED_FILE_CHANGED")
            process = subprocess.Popen(
                [str(item.path)], cwd=str(item.path.parent), close_fds=True)
        except (OSError, ValueError, subprocess.SubprocessError):
            QMessageBox.warning(self, "BLACK.BOX Universal", self._t(
                "Could not start the selected EXE. No observation was started."))
            return
        self._attach_pid(process.pid)

    def _attach_selected(self) -> None:
        selected = self.process_table.selectedItems()
        if not selected:
            QMessageBox.information(self, "Choose a process",
                                    "Select a row first, then press ATTACH.")
            return
        pid_item = self.process_table.item(selected[0].row(), 1)
        if pid_item is None:
            return
        self._attach_pid(int(pid_item.data(Qt.ItemDataRole.UserRole)))

    def _start(self) -> None:
        try:
            self.probe.start()
        except (psutil.Error, OSError, RuntimeError, ObserverError):
            QMessageBox.warning(self, "Observation",
                                "Choose a running, accessible process first.")
            return
        self._set_report_status("recording")
        self._update_all()

    def _stop(self) -> None:
        self.probe.stop()
        self._set_report_status(
            "saved" if self.probe.report_result is not None else "unavailable")
        self._update_all()

    def _change_interval(self, index: int) -> None:
        if hasattr(self, "_timer"):
            self._timer.setInterval(int(self.interval_combo.itemData(index)))

    def _tick(self) -> None:
        was_active = self.probe.active
        self.probe.tick()
        self._update_all()
        if was_active and not self.probe.active:
            self._set_report_status(
                "saved" if self.probe.report_result is not None else "unavailable")
    
    def _update_all(self) -> None:
        self.clock.setText(datetime.now().strftime("%H:%M"))
        selected = self.probe.pid is not None
        running = self.probe.active
        self.start_btn.setEnabled(selected and not running)
        self.stop_btn.setEnabled(running)
        current = self.probe.last
        self.card_cpu.set_readout(
            f'{current["cpu_pct"]:.1f}%' if self.probe.history and current["cpu_pct"] is not None else "—",
            self._t("Selected root process"))
        self.card_ram.set_readout(
            f'{current["rss_mb"]:.1f} MB' if self.probe.history and current["rss_mb"] is not None else "—",
            self._t("Selected process RSS"))
        self.card_child.set_readout(
            str(current["process_count"]) if self.probe.history and current["process_count"] is not None else "—")
        self.card_samples.set_readout(str(self.probe.total_samples))
        self.chart.set_samples(list(self.probe.history))
        folder = self.probe.session_folder
        self.open_report_button.setEnabled(
            folder is not None and (folder / "report.html").is_file())
        if selected:
            self.target_name.setText(self.probe.name)
            self.target_pid.setText(f"PID {self.probe.pid}  /  local computer")
        else:
            self.target_name.setText(self._t("No process selected"))
            self.target_pid.setText(self._t("Visit PROCESSES to attach."))
        if running:
            status = "●  OBSERVING"
        elif selected:
            status = "●  READY / STOPPED"
        else:
            status = "○  WAITING FOR TARGET"
        self.state_text.setText(self._t(status))
        self._refresh_target_binding(selected, running)
        self.live_badge.setText(self._t(status))
        self.toolbar_state.setText(self._t(status))
        if self.probe.session_folder is not None:
            self.session_location.setText(self._t("Saved in ") + str(self.probe.session_folder))
        else:
            self.session_location.setText(self._t("No persisted session yet"))
        self.recent_messages.setPlainText(
            "\n".join(f'{evt["timestamp_utc"][-8:]}  {evt["code"]}  {evt["detail"]}'
                      for evt in list(self.probe.events)[-5:]) or
            self._t("System ready. Choose a process in the PROCESS EXPLORER."))
        if self.stack.currentIndex() == self._page_ids["events"]:
            self._update_event_table()

    def _refresh_target_binding(self, selected: bool, running: bool) -> None:
        """Explain what is attached without claiming recording before Start."""
        self.target_binding.setVisible(selected)
        if not selected:
            self.target_binding_title.setText("")
            self.target_binding_detail.setText("")
            return
        pid = self.probe.pid
        if running:
            heading = "●  OBSERVING THIS INSTANCE"
            detail = "Recording process" + f" · PID {pid}"
        elif self.probe.session_folder is not None:
            heading = "✓  SESSION FINISHED"
            detail = ("Report saved" if self.probe.report_result is not None
                      else "Observation stopped") + f" · PID {pid}"
        else:
            heading = "✓  PROCESS ATTACHED"
            detail = "Ready to observe" + f" · PID {pid}"
        self.target_binding_title.setText(self._t(heading))
        # Translate the fixed phrase before appending the actual identifier.
        prefix = detail.rsplit(" · PID ", 1)[0]
        self.target_binding_detail.setText(self._t(prefix) + f" · PID {pid}")

    def _update_event_table(self) -> None:
        events = list(reversed(self.probe.events))
        self.event_table.setRowCount(len(events))
        for row, event in enumerate(events):
            for col, value in enumerate((
                event["timestamp_utc"].replace("T", " ")[:19],
                event["code"], event["detail"],
            )):
                self.event_table.setItem(row, col, QTableWidgetItem(value))

    def _update_report_preview(self) -> None:
        if self.probe.pid is None:
            self.report_preview.setPlainText(
                self._t("// No report yet.\n// Choose a process, start observing, "
                        "then return here to inspect real samples."))
            return
        overview = self.probe.snapshot()
        overview["recent_samples"] = overview["recent_samples"][-15:]
        overview["recent_events"] = overview["recent_events"][-15:]
        self.report_preview.setPlainText(
            json.dumps(overview, ensure_ascii=False, indent=2))

    def _open_saved_report(self) -> None:
        folder = self.probe.session_folder
        if folder is None:
            return
        page = folder / "report.html"
        if page.is_file() and not page.is_symlink():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(page)))

    def _compare_sessions(self) -> None:
        first = QFileDialog.getExistingDirectory(self, "Choose first saved session")
        if not first:
            return
        second = QFileDialog.getExistingDirectory(self, "Choose second saved session")
        if not second:
            return
        try:
            result = compare_sessions(Path(first), Path(second))
        except (ObserverError, OSError, ValueError, TypeError):
            QMessageBox.warning(self, "Comparison failed",
                                "These folders do not contain valid BLACK.BOX sessions.")
            return
        self._navigate("reports")
        self.report_preview.setPlainText(json.dumps(
            result, ensure_ascii=False, indent=2))

    def _set_report_status(self, state: str) -> None:
        """Show the state of independently saved local process reports."""
        self._report_state = state
        self._refresh_report_status()

    def _refresh_report_status(self) -> None:
        ru = self.language == "RU"
        messages = {
            "waiting": ("Local report will be saved after Stop.",
                        "После остановки будет сохранён локальный отчёт."),
            "recording": ("Recording process observations…",
                          "Идёт запись наблюдений за процессом…"),
            "saved": ("Local process report saved.",
                      "Локальный отчёт о процессе сохранён."),
            "unavailable": ("Report unavailable; SQLite data may remain.",
                            "Отчёт недоступен; данные SQLite могли сохраниться."),
        }
        pair = messages.get(self._report_state, messages["waiting"])
        self.report_status_label.setText(pair[1] if ru else pair[0])

    def _export(self) -> None:
        if self.probe.pid is None:
            QMessageBox.information(
                self, "No observation to export",
                "Choose a process first. No synthetic results will be generated.")
            return
        suggested = f"blackbox-{self.probe.pid}-snapshot.json"
        name, _ = QFileDialog.getSaveFileName(
            self, "Export local process observations", suggested,
            "JSON files (*.json)")
        if not name:
            return
        try:
            save_snapshot(Path(name), self.probe.snapshot())
        except (OSError, TypeError, ValueError):
            QMessageBox.warning(self, "Export failed",
                                "Could not write the selected JSON file.")
            return
        QMessageBox.information(self, "Snapshot saved",
                                "Local JSON export completed successfully.")
        self._update_report_preview()

    def _about(self) -> None:
        QMessageBox.about(
            self, "BLACK.BOX Universal",
            "BLACK.BOX Universal v0.3.3 — process and file inspection.\n\n"
            "Offline monitoring, human-readable HTML and JSON reports: available.\n"
            "Diagnostics use local operating-system observations.\n"
            "Windows ETW and crash dump collection: NOT IMPLEMENTED.\n\n"
            "No cloud upload, tunneling, process injection or admin escalation.")

    def closeEvent(self, event) -> None:
        if self._update_worker is not None and self._update_worker.isRunning():
            event.ignore()
            QMessageBox.information(
                self, "BLACK.BOX Universal",
                self._t("Finish the current update before closing."))
            return
        self.probe.stop("UI_CLOSED")
        self._timer.stop()
        super().closeEvent(event)
