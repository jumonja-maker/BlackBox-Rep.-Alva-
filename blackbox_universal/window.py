"""The BLACK.BOX Universal desktop shell.

Classic desktop window semantics + warm illustrated 90s palette.
The application observes local process metrics and inspects file metadata
without invoking an external diagnostic runtime.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import psutil
from blackbox_core.actions import ActionError
from blackbox_investigation import InvestigationError
from blackbox_core.contracts import ObserverError
from blackbox_core.report import compare as compare_sessions
from blackbox_core.sampling_health import BusyTickTracker
from PySide6.QtCore import Qt, QTimer, QThread, Signal, QSettings, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QIcon
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QDoubleSpinBox, QSpinBox, QFileDialog, QFrame,
    QGridLayout, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit,
    QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QPushButton,
    QScrollArea, QStackedWidget, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from .monitor import ReadOnlyProbe, available_processes, save_snapshot
from .investigation_worker import InvestigationWorker, session_bounds
from .thread_detail_worker import ThreadDetailWorker
from .base_sample_worker import BaseSampleWorker
from .report_worker import ReportWorker
from .session_interval_worker import SessionIntervalWorker, SessionExportWorker
from .timeline import SessionTimeline
from .process_history_view import RecordedProcessTree
from .investigation_view import title as investigation_title, interval_text as investigation_interval, fact_text as investigation_facts, finding_details, summary_text
from .file_targets import InspectedFile, inspect_file, find_running_executable
from .i18n import translate
from .releases import (Release, NoOfficialRelease, check_latest_release, stage_release,
                       runtime_directory, MAINTENANCE_NAME)
from .shortcuts import create_shortcut
from .maintenance import prepare_external_helper
from .theme import COLORS
from .chrome_icons import ChromeButton
from .widgets import DesktopMark, MetricCard, SparkleBorder, TrendChart, WindowPanel


def _label(text: str, kind: str = "", wrap: bool = True) -> QLabel:
    item = QLabel(text)
    if kind:
        item.setObjectName(kind)
    item.setWordWrap(wrap)
    return item


def _button(text: str, kind: str = "") -> QPushButton:
    b = ChromeButton(text)
    if kind:
        b.setObjectName(kind)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


def _page() -> tuple[QWidget, QVBoxLayout]:
    widget = QWidget()
    widget.setObjectName("pageBody")
    widget.setStyleSheet("QWidget#pageBody { background: transparent; }")
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

    def __init__(self, *, isolated=False, output_root=None, allow_update_check=False):
        super().__init__()
        self.setWindowTitle("BLACK.BOX Universal | Retro Workstation")
        self.setMinimumSize(1020, 690)
        self.resize(1330, 850)
        # The public app entry point uses an isolated owner. The synchronous
        # constructor remains an explicit compatibility API for embedders.
        from .research_bridge import ResearchBridge
        self.probe = ResearchBridge(self,output_root=output_root) if isolated else ReadOnlyProbe(output_root=output_root,background_events=True)
        self._isolated = isolated
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
        self._investigation_worker = None
        self._investigation_retry = None
        self._investigation_html: Path | None = None
        self._investigation_result: dict | None = None
        self._investigation_busy = False
        self._thread_detail_worker: ThreadDetailWorker | None = None
        self._thread_detail_payload = None
        self._thread_detail_state = "default"
        self._base_sample_worker: BaseSampleWorker | None = None
        self._report_worker: ReportWorker | None = None
        self._interval_worker = None
        self._interval_pending = None
        self._interval_packet = None
        self._interval_read_error = False
        self._interval_folder = None
        self._interval_process = 1
        self._interval_export_worker = None
        self._interval_export_result = None
        self._report_error: str | None = None
        self._pending_base_stop: str | None = None
        self._base_sample_error: str | None = None
        self._busy_tick_tracker = BusyTickTracker()
        self._pending_close = False
        icon_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
        icon_file = icon_dir / "assets" / "blackbox.png"
        if icon_file.is_file():
            self.setWindowIcon(QIcon(str(icon_file)))
        self._process_rows: list[dict] = []
        self._selected_file: InspectedFile | None = None
        self._nav_buttons: dict[str, QPushButton] = {}
        self._page_ids: dict[str, int] = {}
        self._build()
        if isolated:
            self.probe.updated.connect(self._research_updated)
            self.probe.terminated.connect(self._research_terminated)
            self.probe.result_ready.connect(self._research_result)
        self._refresh_process_list()
        self._update_all()
        self._navigate("dashboard")
        self._set_language(self.language)
        self._timer = QTimer(self)
        # Production Qt ticks NEVER call the synchronous ReadOnlyProbe.tick().
        self._timer.timeout.connect(self._request_background_sample)
        self._timer.start(1000)
        if allow_update_check and self._prefs.value("check_updates_at_start", True, type=bool):
            QTimer.singleShot(1800, self._automatic_update_check)

    def _build(self) -> None:
        desktop = QWidget()
        desktop.setObjectName("desktop")
        self.setCentralWidget(desktop)
        root = QVBoxLayout(desktop)
        root.setContentsMargins(17, 8, 17, 8)
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
        header.addWidget(_label("BLACK.BOX UNIVERSAL  /  MONITOR.EXE", "chromeTitle", False))
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
        help_menu = QMenu(self)
        help_menu.addAction("About / safety notes", self._about)
        for name, menu in (("FILE", file_menu), ("HELP", help_menu)):
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
        body.setObjectName("shellBody")
        body.setStyleSheet("QWidget#shellBody { background: #fff7e4; }")
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
        brand = _label("  SYSTEM DISK (C:)", wrap=False)
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
        self.stack.setObjectName("pageStack")
        self.stack.setStyleSheet("QStackedWidget#pageStack { background: #fff7e4; }")
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


    def _as_scroll(self, page: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(page)
        return scroll

    def _build_dashboard(self) -> QWidget:
        page, content = _page()
        # Unlike document-like pages, the live graph should use the entire
        # remaining viewport, not remain packed against its top edge.
        content.setAlignment(Qt.AlignmentFlag(0))
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
        self.dashboard_profile=QComboBox()
        self.dashboard_profile.setAccessibleName('Capture profile / Профиль сбора')
        for value in ('STANDARD','DETAILED','INCIDENT_BURST'):self.dashboard_profile.addItem(value,value)
        self.dashboard_profile.setToolTip('Standard / Detailed / Incident Burst · ETW and dumps require separate consent / ETW и дампы включаются отдельно')
        self.dashboard_profile.activated.connect(self._apply_dashboard_profile)
        status.content.addWidget(self.dashboard_profile)
        self.overhead_note=_label('', 'caption');self.overhead_note.hide();status.content.addWidget(self.overhead_note)
        self.start_btn = _button("▶  START OBSERVING", "accent")
        self.start_btn.clicked.connect(self._start)
        status.content.addWidget(self.start_btn)
        self.stop_btn = _button("■  STOP OBSERVING")
        self.stop_btn.clicked.connect(self._stop)
        status.content.addWidget(self.stop_btn)
        self.mark_problem_btn = _button("⚑  MARK PROBLEM")
        self.mark_problem_btn.clicked.connect(self._mark_problem)
        status.content.addWidget(self.mark_problem_btn)
        self.auto_capture_btn = _button("AUTO INCIDENT CAPTURE: OFF")
        self.auto_capture_btn.setObjectName("autoIncidentCapture")
        self.auto_capture_btn.setToolTip(
            "Opt-in: CPU >=85% for 3s or a sampling gap; stores SQLite sample ranges. "
            "No OS hang detection, process tracing, dumps or proven root cause.")
        self.auto_capture_btn.clicked.connect(self._toggle_incident_capture)
        status.content.addWidget(self.auto_capture_btn)
        self.detailed_capture_btn = _button("DETAILED THREADS: OFF")
        self.detailed_capture_btn.setObjectName("detailedCaptureToggle")
        self.detailed_capture_btn.setToolTip(
            "Opt-in bounded background process/threads/children counters. "
            "Stored in independent v2 SQLite sidecar. No stacks or wait chains.")
        self.detailed_capture_btn.clicked.connect(self._toggle_detailed_capture)
        status.content.addWidget(self.detailed_capture_btn)
        self.window_capture_btn = _button("WINDOW TIMEOUT / WCT: OFF")
        self.window_capture_btn.clicked.connect(self._toggle_window_capture)
        status.content.addWidget(self.window_capture_btn)
        self.window_capture_status = _label("Window responsiveness: not recorded","caption")
        self.window_capture_status.setTextFormat(Qt.TextFormat.PlainText)
        status.content.addWidget(self.window_capture_status)
        self.window_selector = QComboBox()
        self.window_selector.setAccessibleName("Target HWND / Окно цели")
        self.window_selector.currentIndexChanged.connect(self._select_target_window)
        status.content.addWidget(self.window_selector)
        action_controls = QGridLayout()
        self.action_prepare_btn = _button("PREPARE ACTION")
        self.action_prepare_btn.clicked.connect(self._prepare_action)
        self.action_begin_btn = _button("BEGIN ACTION")
        self.action_begin_btn.clicked.connect(self._begin_action)
        self.action_end_btn = _button("END ACTION")
        self.action_end_btn.clicked.connect(self._end_action)
        self.action_repeat_btn = _button("REPEAT ACTION")
        self.action_repeat_btn.clicked.connect(self._prepare_action)
        for index, button in enumerate((self.action_prepare_btn, self.action_begin_btn,
                                        self.action_end_btn, self.action_repeat_btn)):
            button.setAccessibleName(button.text())
            action_controls.addWidget(button, index // 2, index % 2)
        status.content.addLayout(action_controls)
        self.action_state_label = _label("Action state: IDLE", "caption")
        status.content.addWidget(self.action_state_label)
        middle.addWidget(status, 4)
        content.addLayout(middle, 1)

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
        # A saved-session TID table on the existing Processes page. The user
        # requests a bounded read through a separate QThread (no GUI disk I/O).
        threads_panel = WindowPanel("Threads of selected PID", "DERIVED / PSUTIL")
        self.thread_detail_status = _label(
            "Record with DETAILED THREADS, then load TID CPU intervals.", "caption")
        threads_panel.content.addWidget(self.thread_detail_status)
        self.thread_detail_refresh = _button("◈  LOAD THREAD CPU")
        self.thread_detail_refresh.setObjectName("loadThreadCpu")
        self.thread_detail_refresh.clicked.connect(self._load_thread_detail)
        threads_panel.content.addWidget(self.thread_detail_refresh)
        self.thread_detail_table = QTableWidget(0, 5)
        self.thread_detail_table.setObjectName("threadCpuTable")
        self.thread_detail_table.setHorizontalHeaderLabels(
            ("TID", "SEGMENT", "MEAN CPU %", "PEAK CPU %", "PAIRS"))
        for col in (0, 1, 2, 3):
            self.thread_detail_table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents)
        self.thread_detail_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch)
        self.thread_detail_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.thread_detail_table.setMinimumHeight(170)
        threads_panel.content.addWidget(self.thread_detail_table)
        content.addWidget(threads_panel)
        history_panel = WindowPanel("Recorded process tree", "PID + BIRTH / READ ONLY")
        self.process_history_table = RecordedProcessTree(self)
        self.process_history_table.itemSelectionChanged.connect(self._history_process_selected)
        history_panel.content.addWidget(self.process_history_table)
        self.process_history_summary=QLabel();self.process_history_summary.setWordWrap(True);history_panel.content.addWidget(self.process_history_summary)
        self.process_history_more = _button("NEXT PROCESS PAGE")
        self.process_history_more.clicked.connect(self._next_process_page)
        self.process_history_more.setEnabled(False)
        history_panel.content.addWidget(self.process_history_more)
        history_panel.content.addWidget(_label(
            "Open a saved interval in Reports. Selecting a historic child does not change the recording target.","caption"))
        content.addWidget(history_panel)
        return page

    def _build_events(self) -> QWidget:
        page, content = _page()
        from .evidence_panels import EvidencePanel
        self.events_panel=EvidencePanel(self,events=True);self.events_panel.range_requested.connect(self._view_evidence_range)
        content.addWidget(self.events_panel)
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
        self.event_table.setMinimumHeight(300)
        frame.content.addWidget(self.event_table)
        content.addWidget(frame)

        findings_panel = WindowPanel("Investigation findings", "OFFLINE EVIDENCE")
        self.event_investigation_table = QTableWidget(0, 3)
        self.event_investigation_table.setObjectName("eventInvestigationFindings")
        self.event_investigation_table.setHorizontalHeaderLabels(("TIME", "FINDING", "EVIDENCE"))
        self.event_investigation_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents)
        self.event_investigation_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents)
        self.event_investigation_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch)
        self.event_investigation_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.event_investigation_table.setMinimumHeight(145)
        self.event_investigation_table.setMaximumHeight(215)
        findings_panel.content.addWidget(self.event_investigation_table)
        content.addWidget(findings_panel)
        timeline_events = WindowPanel("Session event timeline", "PAGED / UNVERIFIED FILE")
        self.session_event_table = QTableWidget(0,4)
        self.session_event_table.setHorizontalHeaderLabels(("TIME ns","CODE","SOURCE","TRUST"))
        self.session_event_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.session_event_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.session_event_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.session_event_table.setMinimumHeight(170)
        self.session_event_table.itemSelectionChanged.connect(self._session_event_selected)
        timeline_events.content.addWidget(self.session_event_table)
        self.session_events_more = _button("NEXT EVENT PAGE")
        self.session_events_more.clicked.connect(self._next_event_page)
        self.session_events_more.setEnabled(False)
        timeline_events.content.addWidget(self.session_events_more)
        content.addWidget(timeline_events)
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
        interval_panel = WindowPanel("Investigation Summary", "FULL SELECTED INTERVAL / READ ONLY")
        interval_actions = QGridLayout()
        self.load_interval_current = _button("LOAD RECORDED SESSION")
        self.load_interval_current.setObjectName("loadRecordedInterval")
        self.load_interval_current.clicked.connect(lambda:self._load_session_interval(self.probe.session_folder))
        interval_actions.addWidget(self.load_interval_current,0,0)
        self.load_interval_saved = _button("OPEN SAVED SESSION…")
        self.load_interval_saved.clicked.connect(self._choose_interval_session)
        interval_actions.addWidget(self.load_interval_saved,0,1)
        self.reset_interval_btn = _button("RESET RANGE / ROOT")
        self.reset_interval_btn.clicked.connect(self._reset_session_interval)
        interval_actions.addWidget(self.reset_interval_btn,1,0)
        self.export_interval_btn = _button("EXPORT SELECTED INTERVAL…")
        self.export_interval_btn.clicked.connect(self._export_session_interval)
        self.export_interval_btn.setEnabled(False)
        interval_actions.addWidget(self.export_interval_btn,1,1)
        interval_panel.content.addLayout(interval_actions)
        self.interval_summary = _label("Open a recorded session to inspect its full interval.","caption")
        self.interval_summary.setTextFormat(Qt.TextFormat.PlainText)
        interval_panel.content.addWidget(self.interval_summary)
        self.session_timeline = SessionTimeline()
        self.session_timeline.range_requested.connect(self._timeline_range_requested)
        interval_panel.content.addWidget(self.session_timeline)
        self.session_event_details=QPlainTextEdit()
        self.session_event_details.setReadOnly(True)
        self.session_event_details.setAccessibleName("Selected event evidence / Данные выбранного события")
        self.session_event_details.setPlaceholderText("Select a saved event to inspect method, status, HWND/TID or WCT nodes. Root cause: UNKNOWN.")
        self.session_event_details.setMaximumHeight(155)
        interval_panel.content.addWidget(self.session_event_details)
        track_controls = QGridLayout()
        for index,key in enumerate((*SessionTimeline.TRACKS,*SessionTimeline.EVENT_TRACKS)):
            toggle = QCheckBox(SessionTimeline.TRACK_LABELS.get(key,key))
            toggle.setChecked(key in self.session_timeline.visible_tracks or key in self.session_timeline.visible_event_tracks)
            toggle.toggled.connect(lambda enabled,k=key:self.session_timeline.set_track(k,enabled))
            track_controls.addWidget(toggle,index//3,index%3)
        interval_panel.content.addLayout(track_controls)
        content.addWidget(interval_panel)
        frame = WindowPanel("Structured observation", "SCHEMA 1")
        self.report_preview = QPlainTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setMinimumHeight(180)
        frame.content.addWidget(self.report_preview)
        technical_toggle = QCheckBox("Technical data (legacy JSON)")
        technical_toggle.toggled.connect(frame.setVisible)
        content.addWidget(technical_toggle)
        content.addWidget(frame)
        frame.setVisible(False)
        self.report_status_label = _label(
            "Local evidence will be saved after Stop.", "caption")
        content.addWidget(self.report_status_label)
        controls = QGridLayout()
        self.open_report_button = _button("▣  OPEN HTML REPORT")
        self.open_report_button.clicked.connect(self._open_saved_report)
        controls.addWidget(self.open_report_button,0,0)
        self.session_location = _label("No persisted session yet", "caption")
        controls.addWidget(self.session_location,1,0,1,2)
        compare_button = _button("≍  COMPARE TWO SESSIONS")
        compare_button.clicked.connect(self._compare_sessions)
        controls.addWidget(compare_button,0,1)
        content.addLayout(controls)

        investigation_actions = QGridLayout()
        self.investigate_current_btn = _button("◈  INVESTIGATE SESSION", "primary")
        self.investigate_current_btn.clicked.connect(
            lambda: self._begin_investigation(choose=False))
        investigation_actions.addWidget(self.investigate_current_btn,0,0)
        self.investigate_saved_btn = _button("▣  INVESTIGATE SAVED…")
        self.investigate_saved_btn.clicked.connect(
            lambda: self._begin_investigation(choose=True))
        investigation_actions.addWidget(self.investigate_saved_btn,0,1)
        self.investigate_interval_btn = _button("◫  INVESTIGATE INTERVAL…")
        self.investigate_interval_btn.setObjectName("investigateInterval")
        self.investigate_interval_btn.clicked.connect(self._select_investigation_interval)
        investigation_actions.addWidget(self.investigate_interval_btn,1,0)
        self.open_investigation_btn = _button("▣  OPEN INVESTIGATION HTML")
        self.open_investigation_btn.setEnabled(False)
        self.open_investigation_btn.clicked.connect(self._open_investigation_html)
        investigation_actions.addWidget(self.open_investigation_btn,1,1)
        content.addLayout(investigation_actions)
        self.investigation_info = _label(
            "Run a separate, read-only analysis of a completed session.", "caption")
        content.addWidget(self.investigation_info)

        investigation_panel = WindowPanel("Investigation results", "SOURCE-LINKED FINDINGS")
        self.investigation_summary = _label(
            "Investigate a completed session to see findings.", "caption")
        investigation_panel.content.addWidget(self.investigation_summary)
        self.investigation_table = QTableWidget(0, 3)
        self.investigation_table.setObjectName("investigationFindings")
        self.investigation_table.setHorizontalHeaderLabels(("TIME", "FINDING", "EVIDENCE"))
        self.investigation_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents)
        self.investigation_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents)
        self.investigation_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch)
        self.investigation_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.investigation_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.investigation_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.investigation_table.setMinimumHeight(155)
        investigation_panel.content.addWidget(self.investigation_table)
        self.investigation_details = QPlainTextEdit()
        self.investigation_details.setObjectName("investigationDetails")
        self.investigation_details.setReadOnly(True)
        self.investigation_details.setMaximumHeight(115)
        self.investigation_details.setPlainText(
            "Selected evidence and its limitations appear here.")
        self.investigation_table.itemSelectionChanged.connect(
            self._show_selected_investigation_finding)
        investigation_panel.content.addWidget(self.investigation_details)
        content.addWidget(investigation_panel)
        content.addWidget(_label(
            "Automatic SQLite, HTML and JSON session reports are saved "
            "when you press STOP. Manual JSON exports are optional. "
            "Inspect process names and PIDs before sharing.", "caption"))
        from .research_panel import ResearchPanel
        self.research_panel = ResearchPanel(self)
        self.research_toggle = _button("ACTION INVESTIGATION / APPLICATION PREPARATION")
        self.research_toggle.setCheckable(True)
        self.research_toggle.toggled.connect(self.research_panel.setVisible)
        self.research_panel.setVisible(False)
        content.insertWidget(1,self.research_toggle)
        content.insertWidget(2,self.research_panel)
        from .library_panel import LibraryPanel
        from .marker_panel import MarkerPanel
        self.marker_panel=MarkerPanel(self);content.addWidget(self.marker_panel)
        from .evidence_panels import EvidencePanel
        self.analysis_panel=EvidencePanel(self);self.analysis_panel.range_requested.connect(self._view_evidence_range)
        content.insertWidget(1,self.analysis_panel)
        self.library_panel=LibraryPanel(self)
        self.library_toggle=_button("SAVED RESEARCH / EXPERIMENT LIBRARY")
        self.library_toggle.setCheckable(True)
        self.library_toggle.toggled.connect(self.library_panel.activated)
        self.library_panel.setVisible(False)
        self.library_panel.open_requested.connect(self._open_library_recording)
        content.insertWidget(1,self.library_toggle)
        content.insertWidget(2,self.library_panel)
        return page

    def _build_settings(self) -> QWidget:
        page, content = _page()
        from .capture_settings import CaptureSettings
        self.capture_settings=CaptureSettings(self);content.addWidget(self.capture_settings)
        from .recovery_panel import RecoveryPanel
        recovery=WindowPanel('Interrupted exports / Прерванные экспорты','LOCAL RECOVERY')
        self.recovery_panel=RecoveryPanel(self);recovery.content.addWidget(self.recovery_panel);content.addWidget(recovery)
        from .measurement_help import MeasurementHelp
        sources=WindowPanel('Measurement definitions / Определения измерений','SENSOR HEALTH')
        self.measurement_help=MeasurementHelp(self);sources.content.addWidget(self.measurement_help);content.addWidget(sources)
        content.addWidget(_label("CONTROL PANEL / PREFERENCES", "eyebrow", False))
        setting = WindowPanel("Observation settings", "LOCAL CONFIGURATION")
        setting.content.addWidget(_label("SAMPLE INTERVAL", "cardTitle"))
        self.interval_combo = QComboBox()
        for seconds in (1, 2, 5):
            self.interval_combo.addItem(f"Every {seconds} second" + ("s" if seconds > 1 else ""),
                                        seconds * 1000)
        self.interval_combo.currentIndexChanged.connect(self._change_interval)
        setting.content.addWidget(self.interval_combo)
        trigger_controls=QGridLayout()
        trigger_controls.addWidget(_label("CPU trigger threshold (% of one logical CPU)"),0,0)
        self.cpu_trigger_threshold=QDoubleSpinBox()
        self.cpu_trigger_threshold.setRange(.1,6400)
        self.cpu_trigger_threshold.setValue(85.)
        trigger_controls.addWidget(self.cpu_trigger_threshold,0,1)
        trigger_controls.addWidget(_label("CPU trigger sustained duration (ms)"),1,0)
        self.cpu_trigger_duration=QSpinBox()
        self.cpu_trigger_duration.setRange(0,60000)
        self.cpu_trigger_duration.setValue(3000)
        trigger_controls.addWidget(self.cpu_trigger_duration,1,1)
        setting.content.addLayout(trigger_controls)
        setting.content.addWidget(_label(
            "This controls process sampling frequency. Longer intervals reduce "
            "overhead but can miss short-lived activity.", "caption"))
        self.auto_check = QCheckBox("Check GitHub Releases when the app starts")
        self.auto_check.setChecked(self._prefs.value(
            "check_updates_at_start", True, type=bool))
        self.auto_check.toggled.connect(
            lambda value: self._prefs.setValue("check_updates_at_start", value))
        setting.content.addWidget(self.auto_check)
        content.addWidget(setting)
        about = WindowPanel("About BLACK.BOX", "v0.4.1")
        about.content.addWidget(_label(
            "A public-domain-independent desktop shell built from original "
            "PySide6 widgets. Inspired by classic desktop window geometry "
            "and warm retro illustrations, not copied system artwork.", "caption"))
        about.content.addWidget(_label(
            "Local diagnostics can include optional Windows/WCT, ETW, runtime "
            "and minidump evidence when available and explicitly requested. "
            "Observed counters do not prove an internal root cause.", "caption"))
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
        if hasattr(self, "research_panel"):
            self.language = language
            self.research_panel.retranslate()
            self.research_toggle.setText("ИССЛЕДОВАНИЕ ДЕЙСТВИЯ / ПОДГОТОВКА ПРОГРАММЫ" if language=="RU"
                                         else "ACTION INVESTIGATION / APPLICATION PREPARATION")
        if language not in ("EN", "RU"):
            return
        self.language = language
        self._prefs.setValue("language", language)
        # Stable English source strings are kept separately so changing
        # languages never translates already translated text.
        changing = {self.target_name, self.target_pid, self.state_text,
                    self.live_badge, self.toolbar_state,
                    self.session_location, self.process_count,
                    self.report_status_label, self.file_description,
                    self.target_binding_title, self.target_binding_detail,
                    self.investigation_info, self.action_state_label}
        changing.add(self.interval_summary)
        changing.add(self.thread_detail_status)
        changing.add(self.window_capture_status)
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
        for checkbox in self.findChildren(QCheckBox):
            original=checkbox.property("bb_english")
            if original is None:
                original=checkbox.text()
                checkbox.setProperty("bb_english",original)
            checkbox.setText(self._t(str(original)))
        for action in self.findChildren(QAction):
            original = action.property("bb_english")
            if original is None:
                original = action.text()
                action.setProperty("bb_english", original)
            action.setText(self._t(str(original)))
        for table in (self.process_table, self.event_table,
                      self.thread_detail_table,
                      self.session_event_table):
            for i in range(table.columnCount()):
                header = table.horizontalHeaderItem(i)
                if header is None:
                    continue
                original = header.data(Qt.ItemDataRole.UserRole)
                if not original:
                    original = header.text()
                    header.setData(Qt.ItemDataRole.UserRole, original)
                header.setText(self._t(str(original)))
        self.process_history_table.set_language(self.language)
        self._render_process_history_summary()
        self._render_thread_detail_status()
        self.process_search.setPlaceholderText(
            self._t("Search by process name or PID…"))
        self.session_event_details.setPlaceholderText(self._t(
            "Select a saved event to inspect method, status, HWND/TID or WCT nodes. Root cause: UNKNOWN."))
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
        self.session_timeline.set_language(language)
        self._render_interval_summary()
        self._refresh_report_status()
        self._refresh_investigation_info()
        self._render_investigation_findings()
        self.lang_ru.setProperty("active", language == "RU")
        self.lang_en.setProperty("active", language == "EN")
        for button in (self.lang_ru, self.lang_en):
            button.style().unpolish(button)
            button.style().polish(button)
        self._refresh_update_button()
        self._update_all()
        self._filter_processes(self.process_search.text())
        if hasattr(self,"research_panel"):
            self.research_panel.retranslate()
            self.research_toggle.setText("ИССЛЕДОВАНИЕ ДЕЙСТВИЯ / ПОДГОТОВКА ПРОГРАММЫ" if language=="RU"
                                         else "ACTION INVESTIGATION / APPLICATION PREPARATION")
        if hasattr(self,"library_panel"):
            self.library_panel.retranslate()
            self.library_toggle.setText("БИБЛИОТЕКА ИССЛЕДОВАНИЙ / ЭКСПЕРИМЕНТОВ" if language=="RU"
                                        else "SAVED RESEARCH / EXPERIMENT LIBRARY")
        if hasattr(self,'capture_settings'):self.capture_settings.retranslate()
        if hasattr(self,'recovery_panel'):self.recovery_panel.retranslate()
        if hasattr(self,'measurement_help'):self.measurement_help.retranslate()
        if hasattr(self,'marker_panel'):self.marker_panel.retranslate()
        if hasattr(self,'analysis_panel'):self.analysis_panel.retranslate()
        if hasattr(self,'events_panel'):self.events_panel.retranslate()
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
        scratch = None
        try:
            helper = prepare_external_helper(install)
            scratch = helper.parent
            command = [str(helper), action, "--install", str(install),
                       "--wait-pid", str(os.getpid())]
            if staged is not None:
                command += ["--staged", str(staged)]
            kwargs = {"cwd": str(scratch), "close_fds": True}
            if os.name == "nt":
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            subprocess.Popen(command, **kwargs)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            if scratch is not None:
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
        if self._isolated:
            self.probe.send("processes")
            return
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
        if self._report_worker is not None or self._pending_base_stop is not None:
            return
        try:
            self.probe.attach(pid)
        except (psutil.Error, OSError, ValueError, RuntimeError, ObserverError):
            QMessageBox.warning(
                self, self._t("Cannot attach"), self._t(
                    "This process is unavailable or protected. Choose another one."))
            return
        self.thread_detail_table.setRowCount(0)
        self._thread_detail_payload = None
        self._thread_detail_state = "default"
        self._render_thread_detail_status()
        self._update_all()
        self._navigate("dashboard")

    def _attach_file_target(self) -> None:
        if self._report_worker is not None or self._pending_base_stop is not None:
            return
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
        if self._report_worker is not None or self._pending_base_stop is not None:
            return
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

    def _apply_dashboard_profile(self,index):
        if not self._isolated or self.probe.active or self.probe.pending:return
        try:self.probe.send('capture_profile',profile=self.dashboard_profile.itemData(index))
        except (ValueError,RuntimeError) as exc:self.recent_messages.appendPlainText(str(exc))

    def _start(self) -> None:
        if self._isolated:
            if self.probe.pending:
                return
            self.probe.start()
            self._set_report_status("recording")
            return
        if (self._base_sample_worker is not None or
                self._pending_base_stop is not None or
                self._report_worker is not None):
            return
        try:
            self.probe.start()
        except (psutil.Error, OSError, RuntimeError, ValueError, ObserverError):
            QMessageBox.warning(self, "Observation",
                                "Choose a running, accessible process first.")
            return
        self._busy_tick_tracker = BusyTickTracker()
        self._set_report_status("recording")
        self._investigation_result = None
        self._investigation_html = None
        self.open_investigation_btn.setEnabled(False)
        self._refresh_investigation_info()
        self._render_investigation_findings()
        self.thread_detail_table.setRowCount(0)
        self._thread_detail_payload = None
        self._thread_detail_state = "default"
        self._render_thread_detail_status()
        self._update_all()

    def _stop(self) -> None:
        if self._isolated:
            if self.probe.active:
                self.probe.stop()
                self._set_report_status("saving")
            return
        if not self.probe.active or self._report_worker is not None:
            return  # idempotent: never overwrite a previously saved report
        # A worker may still hold the independent sample-writing SQLite
        # connection. Do not close the owner store or export a partial report.
        if self._base_sample_worker is not None:
            self._pending_base_stop = "USER_STOPPED"
            self._update_all()
            return
        self._complete_base_stop("USER_STOPPED")

    def _complete_base_stop(self, reason: str) -> None:
        """Close GUI-owned SQLite, then build reports on a separate QThread."""
        if self._report_worker is not None or not self.probe.active:
            return
        self._pending_base_stop = None
        # Stop owns the original SessionStore connection created in Qt.
        # It must NOT be used from ReportWorker (SQLite check_same_thread).
        self.probe.stop(reason, defer_report=True)
        if self.probe.session_folder is None:
            self._set_report_status("unavailable")
            self._update_all()
            return
        worker = ReportWorker(self.probe.session_folder, self)
        self._report_worker = worker
        self._report_error = None
        worker.result_ready.connect(self._report_ready)
        worker.finished.connect(self._report_finished)
        self._set_report_status("saving")
        self._update_all()
        worker.start()

    def _report_ready(self, payload: object, error: str) -> None:
        if error or type(payload) is not dict:
            self._report_error = "REPORT_UNAVAILABLE"
            return
        try:
            self.probe.complete_report(payload, "")
        except (RuntimeError, ValueError, TypeError):
            self._report_error = "REPORT_UNAVAILABLE"

    def _report_finished(self) -> None:
        worker = self._report_worker
        self._report_worker = None
        if worker is not None:
            worker.deleteLater()
        if self._report_error is not None or self.probe.report_result is None:
            self.probe.complete_report(
                None, self._report_error or "REPORT_UNAVAILABLE")
        self._report_error = None
        self._set_report_status(
            "saved" if self.probe.report_result is not None else "unavailable")
        self._update_all()
        if self._pending_close:
            self._pending_close = False
            QTimer.singleShot(0, self.close)

    def _request_background_sample(self) -> None:
        if self._isolated:
            self._update_all()
            return
        if not self.probe.active:
            self._update_all()
            return
        if self._base_sample_worker is not None:
            if self._pending_base_stop is None:
                # Observe a delivered Qt callback that cannot launch a sample.
                # Qt coalesced/blocked callbacks remain UNKNOWN, not counted.
                self._busy_tick_tracker.skipped(
                    time.monotonic_ns(), self._timer.interval())
            return  # bounded backpressure: never accumulate a worker queue
        if self._pending_base_stop is not None:
            return
        core = self.probe._core
        folder = self.probe.session_folder
        if core is None or folder is None:
            self._complete_base_stop("SAMPLE_UNAVAILABLE")
            return
        worker = BaseSampleWorker(
            core, folder, self,
            requested_interval_ms=self._timer.interval())
        worker.session_writer = self.probe._store.v2 if self.probe._store else None
        self._base_sample_worker = worker
        self._base_sample_error = None
        worker.result_ready.connect(self._base_sample_ready)
        worker.finished.connect(self._base_sample_finished)
        worker.start()

    def _base_sample_ready(self, payload: object, error: str) -> None:
        if error:
            self._base_sample_error = error
            return
        if type(payload) is not dict:
            self._base_sample_error = "SAMPLE_UNAVAILABLE"
            return
        if payload.get("folder") != str(self.probe.session_folder):
            self._base_sample_error = "INVALID_DATA"
            return
        try:
            self.probe.accept_background_sample(
                payload["sample"], payload["seq"],
                requested_interval_ms=payload["requested_interval_ms"],
                worker_timing=payload["worker_timing"],
                received_ns=time.monotonic_ns())
        except (ObserverError, ActionError, KeyError, TypeError, ValueError):
            self._base_sample_error = "STORAGE_ERROR"
        self._update_all()

    def _base_sample_finished(self) -> None:
        worker = self._base_sample_worker
        self._base_sample_worker = None
        if worker is not None:
            worker.deleteLater()
        code = self._base_sample_error
        self._base_sample_error = None
        # Persist one bounded gap event per busy episode, before stop/report.
        # A failure cannot be hidden as a successfully completed recording.
        busy_gap = self._busy_tick_tracker.drain()
        if busy_gap is not None:
            try:
                self.probe.record_busy_timer_gap(busy_gap)
            except (ObserverError, ValueError, TypeError):
                code = "STORAGE_ERROR"
        stop_reason = self._pending_base_stop
        if code:
            # Failed samples are preserved as observer_error evidence just as
            # in the former synchronous tick path.
            self.probe.record_background_failure(code)
            self._complete_base_stop(
                code if code in ("PROCESS_EXITED", "PID_REUSED",
                                 "ACCESS_DENIED", "SAMPLE_UNAVAILABLE",
                                 "STORAGE_ERROR") else "SAMPLE_UNAVAILABLE")
        elif stop_reason is not None:
            self._complete_base_stop(stop_reason)
        else:
            self._update_all()
        # ReportWorker owns post-stop report IO; it will honor any
        # deferred window close when its own finished signal is delivered.

    def _change_interval(self, index: int) -> None:
        if hasattr(self, "_timer"):
            self._timer.setInterval(int(self.interval_combo.itemData(index)))
            if self._isolated:
                self.probe.send("interval", milliseconds=int(self.interval_combo.itemData(index)))

    def _load_thread_detail(self) -> None:
        folder = self.probe.session_folder
        if (self._thread_detail_worker is not None or folder is None or
                not (folder / "detail-v2.sqlite3").is_file()):
            return
        self._thread_detail_state = "loading"
        self._render_thread_detail_status()
        self.thread_detail_refresh.setEnabled(False)
        worker = ThreadDetailWorker(folder, self)
        self._thread_detail_worker = worker
        worker.result_ready.connect(self._thread_detail_ready)
        worker.finished.connect(self._thread_detail_finished)
        worker.start()

    def _choose_interval_session(self):
        folder=QFileDialog.getExistingDirectory(self,self._t("Open saved session"))
        if folder:
            self._load_session_interval(Path(folder))

    def _open_library_recording(self,result):
        # Historic selection must never call attach or replace the live target.
        folder=Path(result["folder"])
        self._load_session_interval(folder)
        if result.get("has_research"):
            self.research_panel.folder=folder
            self.research_panel.begin.setValue(0)
            self.research_panel.end.setValue(max(.001,(result["metadata"].get("duration_ms") or 0)/1000))

    def _load_session_interval(self,folder,interval=None,*,instance_id=1,event_cursor=(0,0),process_after=0):
        if folder is None:
            return
        folder=Path(folder)
        if folder!=self._interval_folder:
            self.session_event_details.clear()
            self._thread_detail_payload=None
            self._thread_detail_state="default"
        self._interval_folder=folder
        self._interval_process=instance_id
        args=(folder,interval,instance_id,event_cursor,process_after)
        if self._interval_worker is not None:
            self._interval_pending=args
            self._interval_worker.requestInterruption()
            return
        self._interval_read_error=False
        self.interval_summary.setText(self._t("Reading all selected observations…"))
        self.export_interval_btn.setEnabled(False)
        worker=SessionIntervalWorker(folder,self,interval=interval,instance_id=instance_id,
                                     event_cursor=event_cursor,process_after=process_after)
        self._interval_worker=worker
        worker.result_ready.connect(self._session_interval_ready)
        worker.finished.connect(self._session_interval_finished)
        worker.start()

    def _render_interval_summary(self):
        if self._interval_read_error:
            self.interval_summary.setText(self._t("Selected interval is unavailable; source files were not changed."))
            return
        if self._interval_packet is None:
            if self._interval_worker is None:
                self.interval_summary.setText(self._t("Open a recorded session to inspect its full interval."))
            return
        result=self._interval_packet["interval"]
        coverage=result["coverage"]
        metrics=result["metrics"]
        cpu_peak=metrics["cpu_interval_percent"]["max"]
        rss_peak=metrics["rss_bytes"]["max"]
        cpu_text=f"{cpu_peak:.1f}" if cpu_peak is not None else "UNAVAILABLE"
        rss_text=f"{rss_peak/1048576:.2f}" if rss_peak is not None else "UNAVAILABLE"
        self.interval_summary.setText(self._t("Observed / support / limits")+f"\n{result['series']} · "+
            self._t("{selected}/{total} samples · CPU peak {cpu} % / 1 CPU · RSS peak {rss} MiB").format(
                selected=coverage["selected_samples"],total=coverage["total_samples"],cpu=cpu_text,rss=rss_text)+"\n"+
            self._t("gaps={gaps} · errors={errors} · Root cause: UNKNOWN").format(
                gaps=coverage["spacing_gap_pairs"],errors=coverage["sensor_error_records"])+
            " · UNVERIFIED_IMPORT · "+" / ".join(result["warnings"]))

    def _view_evidence_range(self,folder,start,end):
        self._load_session_interval(Path(folder),(start,end));self._navigate('reports')

    def _session_interval_ready(self,packet,error):
        if self._interval_pending is not None or self._pending_close:
            return
        if error or not isinstance(packet,dict):
            self._interval_packet=None
            self._interval_read_error=True
            self.export_interval_btn.setEnabled(False)
            self._render_interval_summary()
            return
        if packet["folder"]!=str(self._interval_folder):
            return
        self._interval_packet=packet
        self._interval_read_error=False
        result=packet["interval"]
        self._render_interval_summary()
        self.session_timeline.set_interval(result)
        self.export_interval_btn.setEnabled(self._interval_export_worker is None and
            result["metadata"]["recorded_status"] not in (None,"RECORDING"))
        self._thread_detail_ready({"folder":packet["folder"],"analysis":packet["threads"]},"")
        rows=packet["processes"]["rows"]
        self.analysis_panel.apply_interval(packet['folder'],tuple(result['selected_interval_ns']),origin=result['metadata']['monotonic_origin_ns'])
        self.events_panel.apply_interval(packet['folder'],tuple(result['selected_interval_ns']),origin=result['metadata']['monotonic_origin_ns'],processes=rows)
        self.process_history_table.apply_page(packet['processes'],selected_instance=self._interval_process)
        self._render_process_history_summary()
        self.process_history_more.setEnabled(packet["processes"]["has_more"])
        self.session_event_table.blockSignals(True)
        events=packet["events"]["rows"]
        self.session_event_table.setRowCount(len(events))
        for index,event in enumerate(events):
            for column,key in enumerate(("event_time_ns","event_type","source_kind","verification_class")):
                item=QTableWidgetItem(str(event[key]))
                item.setData(Qt.ItemDataRole.UserRole,event.get("observed_ns") or event["recorded_ns"])
                item.setToolTip("Recorded producer class: "+str(event["recorded_verification_class"])+
                                " · writer recorded ns: "+str(event["recorded_ns"]))
                self.session_event_table.setItem(index,column,item)
        self.session_event_table.blockSignals(False)
        self.session_events_more.setEnabled(packet["events"]["has_more"])

    def _session_interval_finished(self):
        worker=self._interval_worker
        self._interval_worker=None
        self.library_panel.selection_changed()
        if worker:
            worker.deleteLater()
        if self._pending_close:
            self._interval_pending=None
            QTimer.singleShot(0,self.close)
            return
        if self._interval_pending is not None:
            folder,interval,instance,event_cursor,process_after=self._interval_pending
            self._interval_pending=None
            self._load_session_interval(folder,interval,instance_id=instance,
                                        event_cursor=event_cursor,process_after=process_after)

    def _timeline_range_requested(self,start,end):
        if self._interval_folder is not None:
            self._load_session_interval(self._interval_folder,None if start is None else (start,end),
                                        instance_id=self._interval_process)

    def _reset_session_interval(self):
        if self._interval_folder:
            self._load_session_interval(self._interval_folder)

    def _history_process_selected(self):
        identity=self.process_history_table.selected_instance()
        if identity is not None and self._interval_folder:
            self._load_session_interval(self._interval_folder,instance_id=identity)

    def _render_process_history_summary(self):
        if self._interval_packet is None:
            return
        packet=self._interval_packet;page=packet['processes']
        tree=packet['interval'].get('process_tree_totals',{})
        ru=self.language=='RU'
        def memory(value):
            return f'{value/1048576:.2f}' if value is not None else ('неизвестно' if ru else 'unknown')
        self.process_history_summary.setText(
            ('На странице / записано экземпляров: ' if ru else 'Page / recorded instances: ')+
            f"{len(page.get('rows',[]))} / {page.get('total_instances','?')} · "+
            ('Контекст предков: ' if ru else 'Ancestor context: ')+str(len(page.get('ancestors',[])))+'\n'+
            ('Пик RSS корня / наблюдаемого дерева: ' if ru else 'Root / observed tree RSS peak: ')+
            memory(tree.get('root_rss_peak_bytes'))+' / '+memory(tree.get('observed_tree_rss_peak_bytes'))+
            (' МиБ. Общая RSS может повторно учитывать общие страницы. Связи PPID предполагаемые.' if ru else
             ' MiB. Summed RSS can count shared pages more than once. PPID links are candidates.')+
            (('\nКонтекст предков ограничен 256 узлами; остальные не загружены.' if ru else
              '\nAncestor context is capped at 256 nodes; remaining ancestors were not loaded.')
             if page.get('ancestor_context_truncated') else ''))

    def _next_process_page(self):
        packet=self._interval_packet
        if packet and packet["processes"]["rows"]:
            after=packet["processes"]["rows"][-1]["instance_id"]
            self._load_session_interval(self._interval_folder,tuple(packet["interval"]["selected_interval_ns"]),
                                        instance_id=self._interval_process,process_after=after)

    def _next_event_page(self):
        packet=self._interval_packet
        if packet and packet["events"].get("next_cursor"):
            self._load_session_interval(self._interval_folder,tuple(packet["interval"]["selected_interval_ns"]),
                instance_id=self._interval_process,event_cursor=packet["events"]["next_cursor"])

    def _session_event_selected(self):
        row=self.session_event_table.currentRow()
        item=self.session_event_table.item(row,0)
        if item and self._interval_packet:
            events=self._interval_packet["events"]["rows"]
            if 0<=row<len(events):
                event=events[row]
                self.session_event_details.setPlainText(json.dumps({
                    "source_file_trust":"UNVERIFIED_IMPORT","root_cause":"UNKNOWN",
                    "recorded_producer_class":event.get("recorded_verification_class"),
                    "source":event.get("source_kind"),"event":event.get("event_type"),
                    "observation_ns":event.get("event_time_ns"),"status":event.get("measurement_status"),
                    "source_clock_resolution_ns":self._interval_packet["interval"]["metadata"].get("monotonic_resolution_ns"),
                    "recorded_evidence":event.get("detail"),
                    "limitations":"Snapshot only; imported claims are not independently authenticated. Correlation is not causation."
                },ensure_ascii=False,indent=2))
            stamp=item.data(Qt.ItemDataRole.UserRole)
            lo,hi=self._interval_packet["interval"]["selected_interval_ns"]
            radius=max(1_000_000_000,(hi-lo)//20)
            self._timeline_range_requested(max(0,stamp-radius),stamp+radius)
            self._navigate("reports")

    def _export_session_interval(self):
        if self._interval_packet is None or self._interval_export_worker is not None:
            return
        dialog=QDialog(self)
        dialog.setWindowTitle(self._t("Export privacy preview"))
        layout=QVBoxLayout(dialog)
        layout.addWidget(_label(self._t(
            "Exports contain measurements and checksums. Choose whether to include process identifiers, user notes or a ZIP. Inspect before sharing.")))
        identifiers=QCheckBox(self._t("Include PID / TID and process name"))
        notes=QCheckBox(self._t("Include user notes"))
        bundle=QCheckBox(self._t("Create ZIP of selected exports"))
        for control in (identifiers,notes,bundle):
            layout.addWidget(control)
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Ok|QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec()!=QDialog.DialogCode.Accepted:
            return
        output=QFileDialog.getExistingDirectory(self,self._t("Choose export folder"))
        if not output:
            return
        result=self._interval_packet["interval"]
        worker=SessionExportWorker(self._interval_folder,Path(output),self,
            interval=tuple(result["selected_interval_ns"]),series=result["series"],
            instance_id=result["instance_id"],include_identifiers=identifiers.isChecked(),
            include_notes=notes.isChecked(),bundle=bundle.isChecked())
        self._interval_export_worker=worker
        self.export_interval_btn.setEnabled(False)
        worker.result_ready.connect(self._session_export_ready)
        worker.finished.connect(self._session_export_finished)
        worker.start()

    def _session_export_ready(self,packet,error):
        self._interval_export_result=packet if not error else {"error":error}
        if error:
            self.interval_summary.setText(error+" · "+self._t("Source files were not changed."))
        else:
            self.interval_summary.setText(self._t("Selected interval exported.")+"\n"+packet["manifest"])

    def _session_export_finished(self):
        worker=self._interval_export_worker
        self._interval_export_worker=None
        if worker:
            worker.deleteLater()
        self.export_interval_btn.setEnabled(self._interval_packet is not None)
        if self._pending_close:
            QTimer.singleShot(0,self.close)

    def _thread_detail_ready(self, payload: object, error: str) -> None:
        if error or type(payload) is not dict:
            self._thread_detail_state="error"
            self._render_thread_detail_status()
            return
        if payload.get("folder") not in (str(self.probe.session_folder),str(self._interval_folder)):
            return
        detail = payload.get("analysis")
        if type(detail) is not dict:
            return
        rows = detail.get("top_threads", [])
        if type(rows) is not list:
            return
        self._thread_detail_payload=payload
        self._thread_detail_state="loaded"
        v2_rows=any("cpu_seconds" in r for r in rows)
        self.thread_detail_table.setColumnCount(7 if v2_rows else 5)
        headers=(("TID","SEGMENT","MEAN CPU %","PEAK CPU %","PAIRS","CPU seconds","OBSERVED %") if v2_rows else
                 ("TID","SEGMENT","MEAN CPU %","PEAK CPU %","PAIRS"))
        self.thread_detail_table.setHorizontalHeaderLabels(tuple(self._t(h) for h in headers))
        for column,header in enumerate(headers):
            self.thread_detail_table.horizontalHeaderItem(column).setData(Qt.ItemDataRole.UserRole,header)
        self.thread_detail_table.setRowCount(len(rows))
        for index, record in enumerate(rows):
            for column, name in enumerate(
                    (("tid", "segment_start_seq", "cpu_percent",
                     "peak_cpu_percent", "observed_pairs","cpu_seconds","observed_presence_percent") if v2_rows else
                     ("tid", "segment_start_seq", "cpu_percent","peak_cpu_percent","observed_pairs"))):
                item = QTableWidgetItem()
                item.setData(Qt.ItemDataRole.DisplayRole, record.get(name))
                item.setToolTip(
                    "PSUTIL / DERIVED; TID reuse between samples cannot be excluded.")
                self.thread_detail_table.setItem(index, column, item)
        self._render_thread_detail_status()

    def _render_thread_detail_status(self):
        # Language changes must not replace the loaded cells or the user's
        # selected TID. Headers are translated from stable English role data.
        messages={"default":"Record with DETAILED THREADS, then load TID CPU intervals.",
                  "loading":"Reading saved thread counters…",
                  "error":"Thread detail is unavailable; source data were not changed."}
        if self._thread_detail_state in messages:
            self.thread_detail_status.setText(self._t(messages[self._thread_detail_state]))
            return
        detail=self._thread_detail_payload["analysis"]
        warnings = ", ".join(detail.get("warnings", []))
        self.thread_detail_status.setText(
            self._t("Thread CPU is derived from adjacent snapshots only.") +
            (" · PID " + str(detail["pid"]) if detail.get("pid") is not None else "") +
            " · " + (self._t("Thread counters were not captured for this process instance.") if
                      detail.get("status")=="THREADS_NOT_OBSERVED_FOR_INSTANCE" else str(detail.get("status"))) +
            ((" · " + warnings) if warnings else ""))

    def _thread_detail_finished(self) -> None:
        self._thread_detail_worker = None
        self.library_panel.selection_changed()
        self._update_all()

    def _tick(self) -> None:
        was_active = self.probe.active
        self.probe.tick()
        self._update_all()
        if was_active and not self.probe.active:
            self._set_report_status(
                "saved" if self.probe.report_result is not None else "unavailable")
    
    def _update_all(self) -> None:
        selected = self.probe.pid is not None
        running = self.probe.active
        stopping = (self._pending_base_stop is not None or
                    self._report_worker is not None or
                    (self._isolated and self.probe.pending))
        self.start_btn.setEnabled(selected and not running and not stopping)
        self.dashboard_profile.setEnabled(self._isolated and not running and not stopping)
        current=getattr(self.probe,'data',{}).get('capture_policy',{}).get('profile','STANDARD')
        self.dashboard_profile.setCurrentIndex(max(0,self.dashboard_profile.findData(current)))
        overhead=getattr(self.probe,'data',{}).get('observer_budget',{})
        self.overhead_note.setVisible(overhead.get('status')=='OBSERVER_USAGE_HIGH')
        self.overhead_note.setText(('Высокая измеренная нагрузка наблюдателя. Частоту можно снизить в настройках.' if self.language=='RU' else 'High sampled observer usage. Lower sampling frequency in Settings.')+
            (' · '+str(overhead.get('interval_ms'))+' ms' if overhead.get('interval_ms') else ''))
        self.overhead_note.setToolTip('Sampled GUI/helper usage; not a measured OFF/ON effect / Нагрузка GUI/helper, не доказанный прирост против OFF')
        self.stop_btn.setEnabled(running and not stopping)
        self.mark_problem_btn.setEnabled(running and not stopping and
                                         self.probe.last_elapsed_ms is not None)
        self.auto_capture_btn.setEnabled(running and not stopping)
        self.cpu_trigger_threshold.setEnabled(self.probe.incident_capture is None)
        self.cpu_trigger_duration.setEnabled(self.probe.incident_capture is None)
        self.detailed_capture_btn.setEnabled(running and not stopping)
        self.window_capture_btn.setEnabled(running and not stopping)
        cap=self.probe.window_capture
        self.window_capture_btn.setText(self._t("WINDOW TIMEOUT / WCT: ON" if cap else "WINDOW TIMEOUT / WCT: OFF"))
        if cap:
            state,windows=cap.snapshot()
            self.window_capture_status.setText(self._t("Window responsiveness")+": "+state)
            entries=[(f"HWND {w['hwnd']} · TID {w['tid']} · "+
                       ("VISIBLE" if w["visible"] else "HIDDEN"),w["hwnd"]) for w in windows]
            current=[(self.window_selector.itemText(i),self.window_selector.itemData(i))
                     for i in range(self.window_selector.count())]
            if [(self._t("Probe up to 4 windows"),None),*entries]!=current:
                selected_hwnd=self.window_selector.currentData()
                self.window_selector.blockSignals(True)
                self.window_selector.clear()
                self.window_selector.addItem(self._t("Probe up to 4 windows"),None)
                for label,hwnd in entries:
                    self.window_selector.addItem(label,hwnd)
                index=self.window_selector.findData(selected_hwnd)
                self.window_selector.setCurrentIndex(max(0,index))
                self.window_selector.blockSignals(False)
        else:
            self.window_capture_status.setText(self._t("Window responsiveness: not recorded"))
        self.window_selector.setEnabled(cap is not None)
        folder_for_threads = self.probe.session_folder
        self.thread_detail_refresh.setEnabled(
            self._thread_detail_worker is None and folder_for_threads is not None
            and (folder_for_threads / "detail-v2.sqlite3").is_file())
        self.detailed_capture_btn.setText(self._t(
            "DETAILED THREADS: ON" if self.probe.detailed_capture is not None
            else "DETAILED THREADS: OFF"))
        self.auto_capture_btn.setText(self._t(
            "AUTO INCIDENT CAPTURE: ON" if self.probe.incident_capture is not None
            else "AUTO INCIDENT CAPTURE: OFF"))
        current_action = self.probe.actions.state
        can_repeat=len(self.probe.actions.completed)<20
        self.action_prepare_btn.setEnabled(running and not stopping and can_repeat and current_action in ("IDLE", "COMPLETED", "ABORTED"))
        self.action_repeat_btn.setEnabled(running and not stopping and can_repeat and current_action == "COMPLETED")
        limit_tip=self._t("Maximum 20 repeats per recording. Start a new recording for another experiment.")
        self.action_prepare_btn.setToolTip(limit_tip)
        self.action_repeat_btn.setToolTip(limit_tip)
        self.action_begin_btn.setEnabled(running and not stopping and self.probe.actions.ready_to_start())
        self.action_end_btn.setEnabled(running and not stopping and current_action == "RUNNING")
        repeat_count = (self.probe.data.get("completed_actions_total",0) if self._isolated
                        else self.probe.actions.completed_total)
        self.action_state_label.setText(
            self._t("Action state") + ": " + current_action +
            (f" · {repeat_count} " + self._t("completed repeats") if repeat_count else ""))
        self.investigate_current_btn.setEnabled(
            not running and not stopping and not self._investigation_busy and
            self.probe.session_folder is not None and
            (self.probe.session_folder / "session.sqlite3").is_file())
        self.investigate_saved_btn.setEnabled(not stopping and not self._investigation_busy)
        self.investigate_interval_btn.setEnabled(not stopping and not self._investigation_busy)
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
            not stopping and folder is not None and (folder / "report.html").is_file())
        if selected:
            self.target_name.setText(self.probe.name)
            self.target_pid.setText(f"PID {self.probe.pid}  /  local computer")
        else:
            self.target_name.setText(self._t("No process selected"))
            self.target_pid.setText(self._t("Visit PROCESSES to attach."))
        if stopping:
            status = "●  FINALIZING SESSION"
        elif running:
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
        if self._report_worker is not None or self._pending_base_stop is not None:
            heading = "●  FINALIZING SESSION"
            detail = "Saving report" + f" · PID {pid}"
        elif running:
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

    def _toggle_detailed_capture(self) -> None:
        if self._report_worker is not None or self._pending_base_stop is not None:
            return
        try:
            self.probe.set_detailed_capture(
                self.probe.detailed_capture is None)
        except (ObserverError, RuntimeError, ValueError, OSError):
            QMessageBox.warning(self, "BLACK.BOX", self._t(
                "Detailed sampling unavailable"))
        self._update_all()

    def _toggle_window_capture(self):
        if self._report_worker is not None or self._pending_base_stop is not None:
            return
        try:
            self.probe.set_window_capture(self.probe.window_capture is None)
        except (ObserverError,RuntimeError,ValueError):
            self.window_capture_status.setText("WINDOW_CAPTURE_UNAVAILABLE")
        self._update_all()

    def _select_target_window(self,index):
        if self.probe.window_capture:
            self.probe.window_capture.selected_hwnd=self.window_selector.itemData(index)

    def _toggle_incident_capture(self) -> None:
        if self._report_worker is not None or self._pending_base_stop is not None:
            return
        try:
            self.probe.set_incident_capture(
                self.probe.incident_capture is None,policy={
                    "threshold":self.cpu_trigger_threshold.value(),
                    "min_duration_ms":self.cpu_trigger_duration.value()})
        except (ObserverError, RuntimeError, ValueError):
            QMessageBox.warning(self, "BLACK.BOX", self._t(
                "Automatic incident capture unavailable"))
        self._update_all()

    def _prepare_action(self) -> None:
        if self._report_worker is not None or self._pending_base_stop is not None:
            return
        try:
            self.probe.prepare_action()
        except (ActionError, ObserverError, OSError):
            QMessageBox.warning(self, "BLACK.BOX", self._t("Action measurement unavailable"))
        self._update_all()

    def _begin_action(self) -> None:
        if self._report_worker is not None or self._pending_base_stop is not None:
            return
        try:
            self.probe.begin_action()
        except (ActionError, ObserverError, OSError):
            QMessageBox.warning(self, "BLACK.BOX", self._t("Action measurement unavailable"))
        self._update_all()

    def _end_action(self) -> None:
        if self._report_worker is not None or self._pending_base_stop is not None:
            return
        try:
            self.probe.finish_action()
        except (ActionError, ObserverError, OSError):
            QMessageBox.warning(self, "BLACK.BOX", self._t("Action measurement unavailable"))
        self._update_all()

    def _mark_problem(self) -> None:
        if self._report_worker is not None or self._pending_base_stop is not None:
            return
        if not self.probe.active or self.probe.last_elapsed_ms is None:
            return
        note, ok = QInputDialog.getText(
            self, self._t("Mark a problem"), self._t(
                "What just went wrong? (optional note)"))
        if not ok:
            return
        try:
            self.probe.mark_problem(note)
        except (RuntimeError, ValueError, ObserverError):
            QMessageBox.warning(self, "BLACK.BOX", self._t(
                "Unable to mark this point. The session was not changed."))
            return
        self._update_all()

    def _select_investigation_interval(self) -> None:
        """Select an arbitrary completed session interval, not merely its tail."""
        if self._investigation_busy or self._investigation_worker is not None:
            return
        folder = self.probe.session_folder if not self.probe.active else None
        if folder is None:
            selected = QFileDialog.getExistingDirectory(
                self, self._t("Choose saved BLACK.BOX session"))
            if not selected:
                return
            folder = Path(selected)
        try:
            earliest, latest, count = session_bounds(folder)
        except InvestigationError:
            QMessageBox.warning(self, "BLACK.BOX", self._t(
                "Session has no valid measurable interval"))
            return
        suggestion = max(earliest, latest - 60_000)
        begin_str, ok = QInputDialog.getText(
            self, self._t("Start of investigation interval"),
            self._t("Start elapsed milliseconds"),
            QLineEdit.EchoMode.Normal, str(suggestion))
        if not ok:
            return
        end_str, ok = QInputDialog.getText(
            self, self._t("End of investigation interval"),
            self._t("End elapsed milliseconds"),
            QLineEdit.EchoMode.Normal, str(latest))
        if not ok:
            return
        if (not begin_str.isascii() or not begin_str.isdecimal() or
                not end_str.isascii() or not end_str.isdecimal() or
                len(begin_str) > 11 or len(end_str) > 11):
            QMessageBox.warning(self, "BLACK.BOX", self._t(
                "Invalid investigation interval"))
            return
        lo, hi = int(begin_str), int(end_str)
        if not earliest <= lo <= hi <= latest:
            QMessageBox.warning(self, "BLACK.BOX", self._t(
                "Invalid investigation interval"))
            return
        self._begin_investigation(folder=folder, interval=(lo, hi))

    def _begin_investigation(
            self, choose: bool = False,
            folder: Path | None = None,
            interval: tuple[int, int] | None = None) -> None:
        if self._investigation_worker is not None or self._investigation_busy:
            return
        if folder is None:
            if choose:
                name = QFileDialog.getExistingDirectory(
                    self, self._t("Choose saved BLACK.BOX session"))
                if not name:
                    return
                folder = Path(name)
            else:
                folder = self.probe.session_folder
        if folder is None or self.probe.active and folder == self.probe.session_folder:
            QMessageBox.information(self, "BLACK.BOX", self._t(
                "Stop the recording or choose a completed saved session."))
            return
        self._investigation_busy = True
        self._investigation_result = None
        self._investigation_html = None
        self.open_investigation_btn.setEnabled(False)
        self._refresh_investigation_info()
        self._render_investigation_findings()
        self._investigation_worker = InvestigationWorker(
            folder, self.language, interval=interval, parent=self)
        self._investigation_worker.result_ready.connect(self._investigation_ready)
        self._investigation_worker.finished.connect(self._investigation_finished)
        self._investigation_worker.start()
        self._update_all()

    def _investigation_ready(self, payload: object, error: str) -> None:
        if error:
            self._investigation_result = {"error": error}
            QMessageBox.warning(self, self._t("Investigation unavailable"),
                                self._t("Analysis could not be completed.") +
                                "\n" + error)
            return
        if type(payload) is not dict:
            return
        if "long_session" in payload:
            lo, hi, total = payload["long_session"]
            question = self._t(
                "This session is long. Analyze only the latest 4096 measurements?") + (
                    f"\n{total} samples · {lo}–{hi} ms")
            if QMessageBox.question(
                    self, "BLACK.BOX", question,
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
                self._investigation_retry = (
                    Path(payload["session"]), (lo, hi))
            return
        report = payload.get("result")
        if type(report) is not dict:
            return
        self._investigation_result = report
        self._investigation_html = Path(payload["html"])
        self.open_investigation_btn.setEnabled(True)
        self._navigate("reports")
        self._render_investigation_findings()
        if Path(payload["session"]) == self.probe.session_folder:
            self.probe.events.append({
                "timestamp_utc": datetime.now().isoformat(timespec="seconds"),
                "code": "INVESTIGATION_READY",
                "detail": f"{len(report.get('findings', []))} findings · local analysis only"})
            self._update_event_table()

    def _investigation_finished(self) -> None:
        self._investigation_worker = None
        self._investigation_busy = False
        self._refresh_investigation_info()
        self._update_all()
        if self._investigation_retry:
            folder, interval = self._investigation_retry
            self._investigation_retry = None
            QTimer.singleShot(0, lambda: self._begin_investigation(
                folder=folder, interval=interval))

    def _refresh_investigation_info(self) -> None:
        if self._investigation_busy:
            status = "Investigating the saved session offline…"
        elif self._investigation_result and "error" in self._investigation_result:
            status = "Investigation failed; original session files are untouched."
        elif self._investigation_result:
            count = len(self._investigation_result.get("findings", []))
            status = self._t("Investigation complete") + f" · {count} " + self._t("findings")
            self.investigation_info.setText(status)
            return
        else:
            status = "Run a separate, read-only analysis of a completed session."
        self.investigation_info.setText(self._t(status))

    def _render_investigation_findings(self) -> None:
        """Keep the separate report and Event Log evidence tables in sync."""
        report = self._investigation_result
        if type(report) is not dict or "error" in report:
            report = None
        findings = report.get("findings", []) if report else []
        if type(findings) is not list:
            findings = []
        self.investigation_summary.setText(summary_text(report, self.language))
        self.investigation_details.setPlainText(self._t(
            "Selected evidence and its limitations appear here."))
        for table in (self.investigation_table, self.event_investigation_table):
            table.setRowCount(min(len(findings), 200))
            headers = ("TIME", "FINDING", "EVIDENCE")
            table.setHorizontalHeaderLabels(tuple(self._t(h) for h in headers))
            for row, finding in enumerate(findings[:200]):
                if type(finding) is not dict:
                    continue
                entries = (
                    investigation_interval(finding),
                    investigation_title(str(finding.get("code", "UNKNOWN")), self.language),
                    investigation_facts(finding, self.language),
                )
                for col, value in enumerate(entries):
                    cell = QTableWidgetItem(value[:280])
                    cell.setToolTip(finding_details(finding, self.language))
                    table.setItem(row, col, cell)
        self.investigation_table.clearSelection()

    def _show_selected_investigation_finding(self) -> None:
        report = self._investigation_result
        if type(report) is not dict:
            return
        row = self.investigation_table.currentRow()
        findings = report.get("findings", [])
        if type(findings) is list and 0 <= row < len(findings):
            finding = findings[row]
            if type(finding) is dict:
                self.investigation_details.setPlainText(
                    finding_details(finding, self.language))

    def _open_investigation_html(self) -> None:
        page = self._investigation_html
        if page and page.is_file() and not page.is_symlink():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(page)))

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
        if self._isolated:
            self.probe.send("compare", before=first, after=second)
            self._navigate("reports")
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
            "saving": ("Saving offline report in background…",
                       "Сохраняется локальный отчёт в фоне…"),
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
        if self._isolated:
            self.probe.send("snapshot_export", destination=name)
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
            "BLACK.BOX Universal v0.3.6 — reliability and visual fixes.\n\n"
            "Offline monitoring, human-readable HTML and JSON reports: available.\n"
            "Diagnostics use local operating-system observations.\n"
            "Research: action episodes, local instrumentation, Windows HWND/WCT, "
            "explicit ETW/minidump capture and portable evidence packages.\n"
            "Source capabilities and access restrictions are reported per session.\n\n"
            "No background cloud upload or hidden process injection.")

    def closeEvent(self, event) -> None:
        if self._isolated and self.probe.alive:
            self._pending_close = True
            self._timer.stop()
            self.probe.shutdown()
            event.ignore()
            return
        if self._interval_export_worker is not None:
            self._pending_close = True
            self._interval_export_worker.requestInterruption()
            event.ignore()
            return
        if self._interval_worker is not None:
            self._pending_close = True
            self._interval_pending = None
            self._interval_worker.requestInterruption()
            event.ignore()
            return
        if self._report_worker is not None:
            self._pending_close = True
            self._timer.stop()
            event.ignore()
            return
        if self._base_sample_worker is not None:
            self._pending_base_stop = "UI_CLOSED"
            self._pending_close = True
            self._timer.stop()
            event.ignore()
            return
        if (self._thread_detail_worker is not None and
                self._thread_detail_worker.isRunning()):
            event.ignore()
            QMessageBox.information(self, "BLACK.BOX", self._t(
                "Thread analysis is finishing; close again after it completes."))
            return
        if self._investigation_worker is not None and self._investigation_worker.isRunning():
            event.ignore()
            QMessageBox.information(
                self, "BLACK.BOX", self._t(
                    "Investigation is finishing; please close the window again afterwards."))
            return
        if self._update_worker is not None and self._update_worker.isRunning():
            event.ignore()
            QMessageBox.information(
                self, "BLACK.BOX Universal",
                self._t("Finish the current update before closing."))
            return
        if self.probe.active:
            self._pending_close = True
            self._timer.stop()
            self._complete_base_stop("UI_CLOSED")
            event.ignore()
            return
        owners=(() if self._isolated else
                (self.probe._pending_windows,self.probe._pending_detailed,self.probe._pending_v2))
        if any(owner is not None and owner.thread is not None and owner.thread.is_alive() for owner in owners):
            self._pending_close=True
            self._timer.stop()
            QTimer.singleShot(50,self.close)
            event.ignore()
            return
        self._timer.stop()
        super().closeEvent(event)

    def _research_updated(self) -> None:
        if self.probe.active:
            self._set_report_status("recording")
        elif self.probe.report_result is not None and self.probe.data.get("research_state") not in ("INCOMPLETE","FINALIZATION_UNCONFIRMED"):
            self._set_report_status("saved")
        elif self.probe.session_folder is not None and not self.probe.pending:
            self._set_report_status("unavailable")
        self._update_all()

    def _research_terminated(self) -> None:
        if self._pending_close:
            self._pending_close = False
            QTimer.singleShot(0, self.close)

    def _research_result(self, op: str, payload: object, error: str) -> None:
        if error:
            return
        if op == "processes" and isinstance(payload, list):
            self._process_rows = payload
            self._filter_processes(self.process_search.text())
        elif op == "compare":
            self.report_preview.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2))
        elif op == "snapshot_export":
            self._refresh_report_status()
