"""Offline trace viewer. Decoding is optional and never starts a recording."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
from threading import Event
from uuid import uuid4

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFileDialog, QComboBox, QSpinBox, QLineEdit, QTableWidget, QTableWidgetItem, QHeaderView,
    QPlainTextEdit, QSplitter)

from blackbox_core.decoder_service import capability, decode_file
from blackbox_core.decoder_index import read_index


class DecodeWorker(QThread):
    result_ready = Signal(object, str)

    def __init__(self, source, output, parent=None):
        super().__init__(parent)
        self.source, self.output = source, output
        self.cancel_event = Event()

    def run(self):
        try:
            meta = decode_file(self.source, self.output, cancel=self.cancel_event)
            self.result_ready.emit({"path": str(self.output), "summary": meta}, "")
        except Exception as exc:
            self.result_ready.emit(None, (type(exc).__name__ + ": " + str(exc))[:350])


class DecoderPanel(QWidget):
    idle = Signal()

    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.worker = None
        self.cache = tempfile.TemporaryDirectory(prefix="blackbox-decoder-view-")
        self.index = None
        self.rows = []
        self.cursors = [0]
        self.summary = None
        self.state = "ready"
        self.error = ""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 12, 18, 12)
        self.notice = QLabel()
        self.notice.setWordWrap(True)
        layout.addWidget(self.notice)
        controls = QHBoxLayout()
        self.open_button = QPushButton()
        self.session_button = QPushButton()
        self.cancel_button = QPushButton()
        self.cancel_button.setEnabled(False)
        self.open_button.clicked.connect(lambda: self.choose(False))
        self.session_button.clicked.connect(lambda: self.choose(True))
        self.cancel_button.clicked.connect(self.cancel)
        for button in (self.open_button, self.session_button, self.cancel_button):
            controls.addWidget(button)
        layout.addLayout(controls)
        self.status = QLabel()
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        filters = QHBoxLayout()
        self.mode = QComboBox()
        for key in ("events", "stacks", "gc"):
            self.mode.addItem(key, key)
        self.pid = QSpinBox()
        self.pid.setRange(0, 2147483647)
        self.pid.setPrefix("PID: ")
        self.search = QLineEdit()
        self.search.setMaxLength(120)
        self.search.returnPressed.connect(self.reset_page)
        self.apply_button = QPushButton()
        self.apply_button.clicked.connect(self.reset_page)
        filters.addWidget(self.mode)
        filters.addWidget(self.pid)
        filters.addWidget(self.search, 1)
        filters.addWidget(self.apply_button)
        layout.addLayout(filters)
        split = QSplitter(Qt.Orientation.Vertical)
        self.table = QTableWidget(0, 5)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self.show_details)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setMinimumHeight(100)
        split.addWidget(self.table)
        split.addWidget(self.details)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        layout.addWidget(split, 1)
        paging = QHBoxLayout()
        self.prev_button = QPushButton()
        self.next_button = QPushButton()
        self.export_button = QPushButton()
        self.prev_button.clicked.connect(self.previous)
        self.next_button.clicked.connect(self.next)
        self.export_button.clicked.connect(self.export_index)
        for button in (self.prev_button, self.next_button, self.export_button):
            paging.addWidget(button)
            button.setEnabled(False)
        layout.addLayout(paging)
        self.next_cursor = 0
        self.retranslate()

    def tr2(self, en, ru):
        return ru if self.window.language == "RU" else en

    def retranslate(self):
        self.notice.setText(self.tr2(
            "OFFLINE TRACE DECODER · ETL / EventPipe / BLACK.BOX JSONL. No recording or symbol downloads. "
            "Trace time is not aligned to your session. GC elapsed time is NOT a pause. Imported data is unverified.",
            "ДЕКОДЕР ТРАСС · ETL / EventPipe / JSONL BLACK.BOX. Без записи и загрузки символов. "
            "Время трассы не совмещено с сеансом. Длительность GC — НЕ пауза. Импорт не удостоверяет источник."))
        for button, en, ru in ((self.open_button, "OPEN TRACE…", "ОТКРЫТЬ ТРАССУ…"),
                (self.session_button, "FROM SESSION…", "ИЗ СЕАНСА…"),
                (self.cancel_button, "CANCEL", "ОТМЕНА"),
                (self.apply_button, "APPLY FILTER", "ПРИМЕНИТЬ ФИЛЬТР"),
                (self.prev_button, "PREVIOUS", "НАЗАД"), (self.next_button, "NEXT", "ДАЛЕЕ"),
                (self.export_button, "SAVE INDEX…", "СОХРАНИТЬ ИНДЕКС…")):
            button.setText(self.tr2(en, ru))
        for i, pair in enumerate((("Events", "События"), ("Recorded stacks", "Записанные стеки"),
                                  ("GC / suspension intervals", "GC / интервалы остановки"))):
            self.mode.setItemText(i, self.tr2(*pair))
        self.search.setPlaceholderText(self.tr2("Find provider or event…", "Поиск источника или события…"))
        self.table.setHorizontalHeaderLabels(("#", "ms", "PID", self.tr2("SOURCE", "ИСТОЧНИК"),
                                               self.tr2("EVENT / INTERVAL", "СОБЫТИЕ / ИНТЕРВАЛ")))
        self.render_status()

    def render_status(self):
        if self.state == "decoding":
            text = self.tr2("Decoding in a separate process. Cancel is available.",
                            "Декодирование в отдельном процессе. Можно отменить.")
        elif self.state == "error":
            text = self.tr2("Not decoded: ", "Не расшифровано: ") + self.error
        elif self.summary:
            s = self.summary
            text = self.tr2("Result", "Результат") + f": {s['status']} · {s['rows']} events · {s['events_with_stacks']} stacks · "
            text += f"GC pairs: {s['gc']['gc_pairs']} · errors: {s['events_with_errors']} · bounded: {s['bounded_events']}"
            text += self.tr2(" · capture completeness UNKNOWN", " · полнота записи НЕИЗВЕСТНА")
        else:
            c = capability()
            text = c["engine"] + self.tr2(" · helper ready" if c["helper_present"] else " · helper not built (JSONL available)",
                         " · модуль готов" if c["helper_present"] else " · модуль не собран (JSONL доступен)")
        self.status.setText(text)

    def choose(self, from_session):
        folder = getattr(self.window.probe, "session_folder", None) if from_session else None
        filename, _ = QFileDialog.getOpenFileName(self, self.tr2("Open trace", "Открыть трассу"),
                   str(folder or ""), "Trace files (*.etl *.nettrace *.jsonl)")
        if filename:
            self.start_decode(Path(filename))

    def start_decode(self, source):
        if self.worker is not None:
            return
        if getattr(self.window.probe, "active", False):
            self.state, self.error = "error", "STOP_RECORDING_BEFORE_OFFLINE_DECODE"
            self.render_status()
            return
        output = Path(self.cache.name) / (uuid4().hex + ".sqlite3")
        # Never show an old trace as though it belonged to the new input,
        # including while decoding or after a malformed file fails.
        previous = self.index
        self.index, self.summary, self.rows = None, None, []
        self.cursors, self.next_cursor = [0], 0
        self.table.clearContents()
        self.table.setRowCount(0)
        self.details.clear()
        for button in (self.prev_button, self.next_button, self.export_button):
            button.setEnabled(False)
        if previous is not None:
            previous.unlink(missing_ok=True)
        self.state = "decoding"
        self.open_button.setEnabled(False)
        self.session_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.worker = DecodeWorker(source, output, self)
        self.worker.result_ready.connect(self.received)
        self.worker.finished.connect(self.finished)
        self.render_status()
        self.worker.start()

    def cancel(self):
        if self.worker is not None:
            self.worker.cancel_event.set()

    def received(self, packet, error):
        if error:
            self.state, self.error = "error", error
        else:
            old = self.index
            self.index = Path(packet["path"])
            self.summary = packet["summary"]
            self.state = "decoded"
            if old and old != self.index:
                old.unlink(missing_ok=True)
            self.export_button.setEnabled(True)
            self.reset_page()
        self.render_status()

    def finished(self):
        worker, self.worker = self.worker, None
        if worker is not None:
            worker.deleteLater()
        self.open_button.setEnabled(True)
        self.session_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.idle.emit()

    def reset_page(self):
        self.cursors = [0]
        self.load_page()

    def load_page(self):
        if not self.index:
            return
        try:
            page = read_index(self.index, after=self.cursors[-1], mode=self.mode.currentData(),
                              pid=self.pid.value(), search=self.search.text())
            self.rows = page["rows"]
            self.table.setRowCount(len(self.rows))
            for i, item in enumerate(self.rows):
                row = item["event"]
                cells = (item["index_id"], round(row.get("time_ms", row.get("start_ms", 0)), 4), row["pid"],
                         row.get("provider", "DERIVED"), row.get("name", row.get("kind", "")))
                for col, value in enumerate(cells):
                    self.table.setItem(i, col, QTableWidgetItem(str(value)))
            self.next_cursor = page["next_cursor"]
            self.next_button.setEnabled(page["has_more"])
            self.prev_button.setEnabled(len(self.cursors) > 1)
            self.details.setPlainText(json.dumps(page["summary"], ensure_ascii=False, indent=2))
        except Exception as exc:
            self.state, self.error = "error", type(exc).__name__ + ": " + str(exc)
            self.render_status()

    def previous(self):
        if len(self.cursors) > 1:
            self.cursors.pop()
            self.load_page()

    def next(self):
        self.cursors.append(self.next_cursor)
        self.load_page()

    def show_details(self):
        index = self.table.currentRow()
        if 0 <= index < len(self.rows):
            self.details.setPlainText(json.dumps(self.rows[index]["event"], ensure_ascii=False, indent=2))

    def export_index(self):
        if not self.index:
            return
        name, _ = QFileDialog.getSaveFileName(self, self.tr2("Save decoded index (contains trace data)",
                        "Сохранить индекс (содержит данные трассы)"), "decoded-trace.sqlite3", "SQLite (*.sqlite3)")
        if not name:
            return
        try:
            # Create-new, even when a file dialog offers overwrite confirmation.
            with self.index.open("rb") as source, Path(name).open("xb") as target:
                import shutil
                shutil.copyfileobj(source, target)
        except OSError as exc:
            self.state, self.error = "error", type(exc).__name__ + ": " + str(exc)
            self.render_status()
