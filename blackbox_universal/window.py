"""The BLACK.BOX Universal desktop shell.

Classic desktop window semantics + warm illustrated 90s palette.
All visible action buttons work. Advanced Alva analysis is intentionally
marked NOT CONNECTED until an upstream integration contract is supplied.
"""
from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path

import psutil
from blackbox_rep_alva.contracts import ObserverError
from blackbox_rep_alva.report import compare as compare_sessions
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QFileDialog, QFrame,
    QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QPushButton,
    QScrollArea, QStackedWidget, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from .monitor import ReadOnlyProbe, available_processes, save_snapshot
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


class UniversalWindow(QMainWindow):
    PAGES = (
        ("dashboard", "01  OVERVIEW"),
        ("processes", "02  PROCESSES"),
        ("events", "03  EVENT LOG"),
        ("reports", "04  REPORTS"),
        ("alva", "05  ALVA LAB"),
        ("settings", "06  SETTINGS"),
    )

    def __init__(self):
        super().__init__()
        self.setWindowTitle("BLACK.BOX Universal + Alva | Retro Workstation")
        self.setMinimumSize(1020, 690)
        self.resize(1330, 850)
        self.probe = ReadOnlyProbe()
        self._process_rows: list[dict] = []
        self._nav_buttons: dict[str, QPushButton] = {}
        self._page_ids: dict[str, int] = {}
        self._build()
        self._refresh_process_list()
        self._update_all()
        self._navigate("dashboard")
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)

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
        rule = QFrame()
        rule.setFixedHeight(2)
        rule.setStyleSheet("background: #837789;")
        side.addWidget(rule)
        side.addWidget(_label("    NO CLOUD · NO INJECTION", "caption"))
        side.addWidget(_label("    ALVA SLOT: PENDING", "caption"))
        body_layout.addWidget(sidebar)

        self.stack = QStackedWidget()
        self.stack.setStyleSheet("background: #fff7e4;")
        body_layout.addWidget(self.stack, 1)
        builders = (
            ("dashboard", self._build_dashboard),
            ("processes", self._build_processes),
            ("events", self._build_events),
            ("reports", self._build_reports),
            ("alva", self._build_alva),
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

    def _heading(self, kicker: str, headline: str, detail: str) -> QVBoxLayout:
        content = QVBoxLayout()
        content.setSpacing(4)
        content.addWidget(_label(kicker, "eyebrow"))
        content.addWidget(_label(headline, "hero"))
        content.addWidget(_label(detail, "caption"))
        return content

    def _build_dashboard(self) -> QWidget:
        page, content = _page()
        top = QHBoxLayout()
        top.addLayout(self._heading("WELCOME TO YOUR WORKSTATION",
                                    "Hello, curious human.",
                                    "An independent window into what your applications are doing."))
        top.addStretch()
        self.live_badge = _label("●  NO TARGET SELECTED", "signal", False)
        top.addWidget(self.live_badge)
        content.addLayout(top)

        metrics = QGridLayout()
        metrics.setSpacing(11)
        self.card_cpu = MetricCard("PROCESS CPU", "--", "Current sample", COLORS["coral"])
        self.card_ram = MetricCard("WORKING MEMORY", "--", "Process tree RSS", COLORS["teal"])
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
        self.target_name = _label("No process selected", "h2")
        status.content.addWidget(self.target_name)
        self.target_pid = _label("Select an application to begin.", "caption")
        status.content.addWidget(self.target_pid)
        self.state_text = _label("READY TO ATTACH", "signal")
        status.content.addWidget(self.state_text)
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
        head.addLayout(self._heading("WINDOWS / PROCESS EXPLORER",
                                     "Choose your application.",
                                     "Attach to a running process without installing an agent inside it."))
        head.addStretch()
        refresh = _button("↻  REFRESH")
        refresh.clicked.connect(self._refresh_process_list)
        head.addWidget(refresh)
        content.addLayout(head)
        notice = QFrame()
        notice.setObjectName("notice")
        notice_body = QHBoxLayout(notice)
        notice_body.addWidget(_label(
            "◎ Read-only mode · No debugging injection · "
            "Some protected processes may be unavailable.", "caption"))
        content.addWidget(notice)
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
        content.addLayout(self._heading("WINDOWS / EVENT VIEWER",
                                        "The little things add up.",
                                        "Chronological local observer events; not internal application traces."))
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
        h.addLayout(self._heading("LOCAL DISK / REPORTS",
                                  "Evidence, not guesses.",
                                  "Inspect the current read-only snapshot. Files stay on your computer."))
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
        controls = QHBoxLayout()
        self.session_location = _label("No persisted session yet", "caption")
        controls.addWidget(self.session_location, 1)
        compare_button = _button("≍  COMPARE TWO SESSIONS")
        compare_button.clicked.connect(self._compare_sessions)
        controls.addWidget(compare_button)
        content.addLayout(controls)
        content.addWidget(_label(
            "Automatic session SQLite, HTML, JSON and offline AI Handoff are saved "
            "when you press STOP. Manual JSON exports are optional. "
            "Inspect process names and PIDs before sharing.", "caption"))
        return page

    def _build_alva(self) -> QWidget:
        page, content = _page()
        content.addLayout(self._heading("PLATFORM / EXTENSION BAY",
                                        "Meet the Alva lab.",
                                        "The interface is ready; the official platform integration is not connected yet."))
        head = WindowPanel("Platform handshake", "NOT CONNECTED")
        row = QHBoxLayout()
        lab_icon = _label("◈", wrap=False)
        lab_icon.setStyleSheet("font: bold 56px 'Consolas'; color: #ec725d;")
        row.addWidget(lab_icon)
        desc = QVBoxLayout()
        desc.addWidget(_label("ALVA PLATFORM", "h2"))
        desc.addWidget(_label(
            "Status: awaiting upstream foundation. "
            "No diagnostic contracts or AI reports are being invented.", "caption"))
        row.addLayout(desc, 1)
        head.content.addLayout(row)
        self.alva_check = _button("◈  CHECK OPTIONAL ALVA PLATFORM")
        self.alva_check.clicked.connect(self._check_alva)
        head.content.addWidget(self.alva_check)
        self.alva_output = QPlainTextEdit()
        self.alva_output.setReadOnly(True)
        self.alva_output.setMinimumHeight(116)
        self.alva_output.setPlainText(
            "Alva is optional. The standalone recorder and AI Handoff work "
            "without it. Use CHECK to inspect an explicitly installed Alva "
            "platform; unverified import is not proof of provenance.")
        head.content.addWidget(self.alva_output)
        content.addWidget(head)
        tiles = QHBoxLayout()
        for heading, description in (
            ("01 / OBSERVE", "Bounded process signals from the local observer."),
            ("02 / VERIFY", "Future scoped Alva contracts and diagnostic evidence."),
            ("03 / HANDOFF", "Optional machine-readable analysis; no cloud required."),
        ):
            card = WindowPanel(heading)
            card.content.addWidget(_label(description, "caption"))
            tiles.addWidget(card, 1)
        content.addLayout(tiles)
        notice = QFrame()
        notice.setObjectName("notice")
        nl = QVBoxLayout(notice)
        nl.setContentsMargins(16, 11, 16, 11)
        nl.addWidget(_label("A SAFE FOUNDATION", "h2"))
        nl.addWidget(_label(
            "This public shell does not bundle the private Alva source, "
            "activate external telemetry, open tunnels or upload reports. "
            "Alva functionality will be added against its official public "
            "interfaces after they are supplied.", "caption"))
        content.addWidget(notice)
        return page

    def _build_settings(self) -> QWidget:
        page, content = _page()
        content.addLayout(self._heading("CONTROL PANEL / PREFERENCES",
                                        "Your machine, your rules.",
                                        "Small decisions that make diagnostics trustworthy."))
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
        setting.content.addWidget(_label("PRIVACY & SECURITY", "cardTitle"))
        setting.content.addWidget(_label(
            "• Read-only process counters\n"
            "• No code injection or target manipulation\n"
            "• No automatic upload or account sign-in\n"
            "• Report export only when explicitly requested\n"
            "• No administrator privileges requested by this shell", "caption"))
        content.addWidget(setting)
        about = WindowPanel("About BLACK.BOX", "PREVIEW / v0.1")
        about.content.addWidget(_label(
            "A public-domain-independent desktop shell built from original "
            "PySide6 widgets. Inspired by classic desktop window geometry "
            "and warm retro illustrations, not copied system artwork.", "caption"))
        about.content.addWidget(_label(
            "Alva adapter: pending official integration basis. Deep tracing, "
            "Windows ETW and crash dump analysis are not present in this build.",
            "caption"))
        content.addWidget(about)
        return page

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
        self.process_count.setText(f"{len(visible)} shown / {len(self._process_rows)} available")

    def _attach_selected(self) -> None:
        selected = self.process_table.selectedItems()
        if not selected:
            QMessageBox.information(self, "Choose a process",
                                    "Select a row first, then press ATTACH.")
            return
        pid_item = self.process_table.item(selected[0].row(), 1)
        if pid_item is None:
            return
        try:
            self.probe.attach(int(pid_item.data(Qt.ItemDataRole.UserRole)))
        except (psutil.Error, OSError, ValueError, RuntimeError, ObserverError):
            QMessageBox.warning(
                self, "Cannot attach",
                "This process is unavailable or protected. Choose another one.")
            return
        self._update_all()
        self._navigate("dashboard")

    def _start(self) -> None:
        try:
            self.probe.start()
        except (psutil.Error, OSError, RuntimeError, ObserverError):
            QMessageBox.warning(self, "Observation",
                                "Choose a running, accessible process first.")
            return
        self._update_all()

    def _stop(self) -> None:
        self.probe.stop()
        self._update_all()

    def _change_interval(self, index: int) -> None:
        if hasattr(self, "_timer"):
            self._timer.setInterval(int(self.interval_combo.itemData(index)))

    def _tick(self) -> None:
        self.probe.tick()
        self._update_all()

    def _update_all(self) -> None:
        self.clock.setText(datetime.now().strftime("%H:%M"))
        selected = self.probe.pid is not None
        running = self.probe.active
        self.start_btn.setEnabled(selected and not running)
        self.stop_btn.setEnabled(running)
        current = self.probe.last
        self.card_cpu.set_readout(
            f'{current["cpu_pct"]:.1f}%' if self.probe.history else "--",
            "Selected root process")
        self.card_ram.set_readout(
            f'{current["rss_mb"]:.1f} MB' if self.probe.history else "--",
            "Tree total / RSS")
        self.card_child.set_readout(
            str(current["process_count"]) if self.probe.history else "--")
        self.card_samples.set_readout(str(len(self.probe.history)))
        self.chart.set_samples(list(self.probe.history))
        if selected:
            self.target_name.setText(self.probe.name)
            self.target_pid.setText(f"PID {self.probe.pid}  /  local computer")
        else:
            self.target_name.setText("No process selected")
            self.target_pid.setText("Visit PROCESSES to attach.")
        if running:
            status = "●  OBSERVING"
        elif selected:
            status = "●  READY / STOPPED"
        else:
            status = "○  WAITING FOR TARGET"
        self.state_text.setText(status)
        self.live_badge.setText(status)
        self.toolbar_state.setText(status)
        if self.probe.session_folder is not None:
            self.session_location.setText("Saved in " + str(self.probe.session_folder))
        else:
            self.session_location.setText("No persisted session yet")
        self.recent_messages.setPlainText(
            "\n".join(f'{evt["timestamp_utc"][-8:]}  {evt["code"]}  {evt["detail"]}'
                      for evt in list(self.probe.events)[-5:]) or
            "System ready. Choose a process in the PROCESS EXPLORER.")
        if self.stack.currentIndex() == self._page_ids["events"]:
            self._update_event_table()

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
                "// No report yet.\n// Choose a process, start observing, "
                "then return here to inspect real samples.")
            return
        overview = self.probe.snapshot()
        overview["recent_samples"] = overview["recent_samples"][-15:]
        overview["recent_events"] = overview["recent_events"][-15:]
        self.report_preview.setPlainText(
            json.dumps(overview, ensure_ascii=False, indent=2))

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

    def _check_alva(self) -> None:
        # Installed private Alva is contacted only on this explicit user action.
        from blackbox_rep_alva.alva_bridge import inspect_platform
        try:
            result = inspect_platform(
                self.probe.session_folder if not self.probe.active else None)
        except (ObserverError, OSError, ValueError, RuntimeError):
            result = {"status": "error", "code": "ALVA_DIAGNOSTICS_FAILED",
                      "provenance_verified": False}
        self.alva_output.setPlainText(
            json.dumps(result, ensure_ascii=False, indent=2))
        if result.get("status") == "invoked":
            self.alva_check.setText("✓  ALVA: SCOPED CALL COMPLETED")
        elif result.get("status") == "api_imported":
            self.alva_check.setText("◈  ALVA: API IMPORTED, NOT VERIFIED")
        else:
            self.alva_check.setText("◈  ALVA: UNAVAILABLE OR UNVERIFIED")

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
            "BLACK.BOX Universal v0.1 — original retro desktop shell.\n\n"
            "Offline process monitoring + SQLite + HTML/JSON + AI Handoff: available.\n"
            "Optional Alva adapter: press CHECK to inspect an installed platform.\n"
            "Windows ETW and crash dump collection: NOT IMPLEMENTED.\n\n"
            "No cloud upload, tunneling, process injection or admin escalation.")

    def closeEvent(self, event) -> None:
        self.probe.stop("UI_CLOSED")
        self._timer.stop()
        super().closeEvent(event)
