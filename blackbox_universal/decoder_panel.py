"""Offline trace viewer. Decoding is optional and never starts a recording."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
from threading import Event
from uuid import uuid4

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton,
    QFileDialog, QComboBox, QSpinBox, QLineEdit, QTableWidget, QTableWidgetItem, QHeaderView,
    QPlainTextEdit, QSplitter)

from blackbox_core.decoder_service import capability, decode_file
from blackbox_core.decoder_limits import failure_details
from blackbox_core.decoder_export import export_index_copy
from blackbox_core.decoder_index import read_index
from blackbox_core.trace_clock_evidence import assess_trace_capture_journal
from blackbox_core.decoder_pdb import review_local_pe_pdb
from blackbox_core.decoder_calltree import export_analysis, parse_calltree_filters
from .decoder_analysis import DecoderAnalysisWorker, CallTreeDialog, DiagnosticReportDialog


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
            self.result_ready.emit({"failure": failure_details(exc)},
                                   (type(exc).__name__ + ": " + str(exc))[:350])


class OpenIndexWorker(QThread):
    result_ready = Signal(object, str)
    kind = "open_index_interval"

    def __init__(self, source, output, arguments, generation, parent=None):
        super().__init__(parent)
        self.source, self.output = source, output
        self.arguments, self.generation = arguments, generation
        self.cancel_event = Event()

    def run(self):
        from .decoder_index_navigation import copy_navigation_index
        try:
            result = copy_navigation_index(self.source, self.output,
                                           cancel_event=self.cancel_event, **self.arguments)
            self.result_ready.emit(result, "")
        except Exception as exc:
            self.result_ready.emit({"failure": failure_details(exc)},
                                   (type(exc).__name__ + ": " + str(exc))[:350])


class DecoderPanel(QWidget):
    idle = Signal()
    index_interval_opened = Signal(object)

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
        self.import_failure = None
        self.clock_review = None  # Manual journal review, scoped to current index.
        self.pdb_review = None  # Independent local file pair, not bound to trace.
        self.analysis_report = None
        self.alignment_report = None
        self._analysis_kind = None
        self._dump_path = None
        self._dump_identity = None
        self._dump_generation = 0
        self._index_navigation_generation = 0
        self._pending_index_navigation = None
        self._navigation_first_page = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 12, 18, 12)
        self.notice = QLabel()
        self.notice.setWordWrap(True)
        layout.addWidget(self.notice)
        controls = QHBoxLayout()
        self.open_button = QPushButton()
        self.session_button = QPushButton()
        self.dump_button = QPushButton()
        self.dump_button.setObjectName("decoderOpenMinidump")
        self.cancel_button = QPushButton()
        self.cancel_button.setEnabled(False)
        self.open_button.clicked.connect(lambda: self.choose(False))
        self.session_button.clicked.connect(lambda: self.choose(True))
        self.dump_button.clicked.connect(self.choose_minidump)
        self.cancel_button.clicked.connect(self.cancel)
        for button in (self.open_button, self.session_button, self.dump_button, self.cancel_button):
            controls.addWidget(button)
        layout.addLayout(controls)
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.dump_memory_notice = QLabel()
        self.dump_memory_notice.setTextFormat(Qt.TextFormat.PlainText)
        self.dump_memory_notice.setWordWrap(True)
        layout.addWidget(self.dump_memory_notice)
        memory_controls = QGridLayout()
        self.dump_address_label = QLabel()
        self.dump_address = QLineEdit()
        self.dump_address.setObjectName("decoderDumpMemoryAddress")
        self.dump_address.setMaxLength(22)
        self.dump_size_label = QLabel()
        self.dump_size = QSpinBox()
        self.dump_size.setObjectName("decoderDumpMemorySize")
        self.dump_size.setRange(1, 4096)
        self.dump_size.setValue(64)
        self.dump_memory_button = QPushButton()
        self.dump_memory_button.setObjectName("decoderReadDumpMemory")
        self.dump_memory_button.clicked.connect(self.read_saved_dump_memory)
        memory_controls.addWidget(self.dump_address_label, 0, 0)
        memory_controls.addWidget(self.dump_address, 0, 1)
        memory_controls.addWidget(self.dump_size_label, 1, 0)
        memory_controls.addWidget(self.dump_size, 1, 1)
        memory_controls.addWidget(self.dump_memory_button, 2, 0, 1, 2)
        layout.addLayout(memory_controls)
        self.dump_memory_view = QPlainTextEdit()
        self.dump_memory_view.setObjectName("decoderPrivateDumpBytes")
        self.dump_memory_view.setReadOnly(True)
        self.dump_memory_view.setMaximumHeight(160)
        self.dump_memory_view.hide()
        layout.addWidget(self.dump_memory_view)
        filters = QHBoxLayout()
        self.mode = QComboBox()
        for key in ("events", "stacks", "gc", "cpu_stacks", "gc_summary", "clock", "modules"):
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
        cpu_filters = QGridLayout()
        self.cpu_scope_label = QLabel()
        self.cpu_time_label = QLabel()
        self.cpu_source = QComboBox()
        self.cpu_source.addItem(".NET", "dotnet")
        self.cpu_source.addItem("Native ETW", "etw")
        self.cpu_instance = QLineEdit()
        self.cpu_tid = QLineEdit()
        self.cpu_start = QLineEdit()
        self.cpu_end = QLineEdit()
        self.cpu_reset = QPushButton()
        self.cpu_reset.clicked.connect(self.reset_cpu_scope)
        cpu_filters.addWidget(self.cpu_scope_label, 0, 0)
        cpu_filters.addWidget(self.cpu_time_label, 1, 0)
        cpu_filters.addWidget(self.cpu_source, 0, 1)
        for field, row, column in ((self.cpu_instance, 0, 2), (self.cpu_tid, 0, 3),
                                   (self.cpu_start, 1, 1), (self.cpu_end, 1, 2)):
            field.setMaxLength(32)
            cpu_filters.addWidget(field, row, column)
            field.textChanged.connect(self._analysis_filter_changed)
        self.cpu_source.currentIndexChanged.connect(self._analysis_filter_changed)
        self.pid.valueChanged.connect(self._analysis_filter_changed)
        cpu_filters.addWidget(self.cpu_reset, 0, 4)
        layout.addLayout(cpu_filters)
        analysis_controls = QGridLayout()
        self.calltree_button = QPushButton()
        self.resolve_tree_button = QPushButton()
        self.resolve_stack_button = QPushButton()
        self.export_analysis_button = QPushButton()
        self.waits_button = QPushButton()
        self.align_session_button = QPushButton()
        self.calltree_button.clicked.connect(self.start_calltree)
        self.resolve_tree_button.clicked.connect(self.choose_calltree_symbols)
        self.resolve_stack_button.clicked.connect(self.choose_stack_symbols)
        self.export_analysis_button.clicked.connect(self.save_analysis)
        self.waits_button.clicked.connect(self.start_wait_analysis)
        self.align_session_button.clicked.connect(self.choose_session_alignment)
        for i, button in enumerate((self.calltree_button, self.resolve_tree_button,
                                    self.resolve_stack_button, self.export_analysis_button,
                                    self.waits_button, self.align_session_button)):
            button.setEnabled(False)
            analysis_controls.addWidget(button, i//2, i%2)
        layout.addLayout(analysis_controls)
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
        self.review_clock_button = QPushButton()
        self.review_pdb_button = QPushButton()
        self.prev_button.clicked.connect(self.previous)
        self.next_button.clicked.connect(self.next)
        self.export_button.clicked.connect(self.export_index)
        self.review_clock_button.clicked.connect(self.review_clock_journal)
        self.review_pdb_button.clicked.connect(self.review_local_pdb)
        for button in (self.prev_button, self.next_button,
                       self.review_clock_button, self.review_pdb_button,
                       self.export_button):
            paging.addWidget(button)
            button.setEnabled(False)
        layout.addLayout(paging)
        self.next_cursor = 0
        self.retranslate()
        self.mode.currentIndexChanged.connect(self.reset_page)
        self.mode.currentIndexChanged.connect(self._dump_mode_changed)

    def tr2(self, en, ru):
        return ru if self.window.language == "RU" else en

    def retranslate(self):
        self.dump_address_label.setText(self.tr2("Saved memory address (0x… or decimal)", "Адрес сохранённой памяти (0x… или десятичный)"))
        self.dump_size_label.setText(self.tr2("Read size, bytes (1–4096)", "Размер чтения, байт (1–4096)"))
        self.dump_memory_button.setText(self.tr2("READ SAVED DUMP MEMORY", "ПРОЧИТАТЬ ПАМЯТЬ СОХРАНЁННОГО ДАМПА"))
        self.dump_memory_button.setAccessibleName(self.dump_memory_button.text())
        self.notice.setText(self.tr2(
            "OFFLINE TRACE DECODER · ETL / EventPipe / BLACK.BOX JSONL; saved minidump metadata. No recording or symbol downloads. "
            "Session time requires checked clock evidence; UTC alone does not establish synchronization. "
            "GC elapsed time is NOT a pause. Imported data is unverified.",
            "ДЕКОДЕР ТРАСС · ETL / EventPipe / JSONL BLACK.BOX; метаданные сохранённых дампов. Без записи и загрузки символов. "
            "Связь с сеансом требует проверки часов; одного UTC недостаточно для синхронизации. "
            "Длительность GC — НЕ пауза. Импорт не удостоверяет источник."))
        for button, en, ru in ((self.open_button, "OPEN TRACE…", "ОТКРЫТЬ ТРАССУ…"),
                (self.session_button, "FROM SESSION…", "ИЗ СЕАНСА…"),
                (self.dump_button, "OPEN DUMP…", "ОТКРЫТЬ ДАМП…"),
                (self.cancel_button, "CANCEL", "ОТМЕНА"),
                (self.apply_button, "APPLY FILTER", "ПРИМЕНИТЬ ФИЛЬТР"),
                (self.prev_button, "PREVIOUS", "НАЗАД"), (self.next_button, "NEXT", "ДАЛЕЕ"),
                (self.export_button, "SAVE INDEX…", "СОХРАНИТЬ ИНДЕКС…"),
                (self.review_clock_button, "CHECK CAPTURE CLOCK…", "ПРОВЕРИТЬ ЧАСЫ ЗАПИСИ…"),
                (self.review_pdb_button, "CHECK LOCAL PDB…", "ПРОВЕРИТЬ ЛОКАЛЬНЫЙ PDB…"),
                (self.calltree_button, "CPU CALL TREE…", "ДЕРЕВО CPU-ВЫБОРОК…"),
                (self.resolve_tree_button, "TREE + LOCAL PDB…", "ДЕРЕВО + ЛОКАЛЬНЫЙ PDB…"),
                (self.resolve_stack_button, "RESOLVE SELECTED STACK…", "ИМЕНА ВЫБРАННОГО СТЕКА…"),
                (self.waits_button, "THREAD WAITS (ETW)…", "ОЖИДАНИЯ ПОТОКОВ (ETW)…"),
                (self.align_session_button, "CORRELATE WITH SESSION…", "СОПОСТАВИТЬ С СЕАНСОМ…"),
                (self.export_analysis_button, "SAVE ANALYSIS…", "СОХРАНИТЬ АНАЛИЗ…")):
            button.setText(self.tr2(en, ru))
        self.cpu_scope_label.setText(self.tr2("CPU / waits:", "CPU / ожидания:"))
        self.cpu_source.setItemText(0, ".NET SampleProfiler")
        self.cpu_source.setItemText(1, self.tr2("Native ETW", "Нативный ETW"))
        self.cpu_source.setAccessibleName(self.tr2("CPU sample source", "Источник CPU-выборок"))
        self.cpu_time_label.setText(self.tr2("Time, ms:", "Время, мс:"))
        self.cpu_reset.setText(self.tr2("RESET", "СБРОС"))
        self.cpu_reset.setToolTip(self.tr2("Clear instance, TID and time filters", "Сбросить экземпляр, TID и интервал"))
        for field, en, ru in (
                (self.cpu_instance, "Instance: all", "Экземпляр: все"),
                (self.cpu_tid, "TID: all", "TID: все"),
                (self.cpu_start, "From ms (inclusive)", "От мс (включительно)"),
                (self.cpu_end, "To ms (exclusive)", "До мс (не включая)")):
            field.setPlaceholderText(self.tr2(en, ru))
            field.setAccessibleName(self.tr2(en, ru))
        scope_help = self.tr2(
            "CPU trees and ETW waits use these filters and the PID above. Blank means all. "
            "Times are trace-relative milliseconds [from, to); use a decimal point.",
            "Эти фильтры и PID выше относятся к дереву CPU и ожиданиям ETW. Пустое поле — все. "
            "Время относительно трассы, мс [от, до); дробная часть через точку.")
        for field in (self.cpu_instance, self.cpu_tid, self.cpu_start, self.cpu_end):
            field.setToolTip(scope_help)
        self.resolve_tree_button.setToolTip(self.tr2(
            "Choose one PE/PDB pair. Only independently matched native frames get derived names; originals are kept.",
            "Выберите пару PE/PDB. Имена добавляются только к соответствующим нативным кадрам; оригиналы сохранены."))
        self.review_pdb_button.setToolTip(self.tr2(
            "Offline GUID/Age check of selected PE and PDB only; imported trace stacks are not symbolized.",
            "Офлайн-проверка GUID/Age выбранных PE и PDB; стеки импортированной трассы не разрешаются."))
        for i, pair in enumerate((("Events", "События"), ("Event-associated stacks", "Стеки событий"),
                                  ("GC / suspension intervals", "GC / интервалы остановки"),
                                  (".NET CPU profiler samples", "Выборки .NET CPU-профилировщика"),
                                  ("GC statistics by generation", "Статистика GC по поколениям"),
                                  ("Trace UTC estimates", "Оценки времени UTC"),
                                   ("Native modules in stacks", "Нативные модули в стеках"))):
            self.mode.setItemText(i, self.tr2(*pair))
        self.search.setPlaceholderText(self.tr2("Find provider or event…", "Поиск источника или события…"))
        self._table_headers()
        self.render_status()

    def _table_headers(self):
        mode = self.mode.currentData()
        unit = ("SAMPLES" if mode == "cpu_stacks" else "PAIRS" if mode == "gc_summary"
                 else "FRAMES" if mode == "modules" else "UTC" if mode == "clock" else "ms")
        self.table.setHorizontalHeaderLabels(("#", unit, "PID", self.tr2("SOURCE", "ИСТОЧНИК"),
                                               self.tr2("EVENT / INTERVAL", "СОБЫТИЕ / ИНТЕРВАЛ")))
        self.table.setColumnWidth(1, 195 if mode == "clock" else 85)

    def render_status(self):
        self._refresh_dump_controls()
        dump_metadata = (self.analysis_report is not None and
                         self.analysis_report.get("schema") == "blackbox.deep-minidump/1")
        self.export_analysis_button.setText(
            self.tr2("SAVE DUMP METADATA…", "СОХРАНИТЬ МЕТАДАННЫЕ ДАМПА…") if dump_metadata else
            self.tr2("SAVE ANALYSIS…", "СОХРАНИТЬ АНАЛИЗ…"))
        if self.state == "analyzing":
            text = self.tr2("Offline analysis; cancel is available. Sources are not modified.",
                            "Офлайн-анализ; можно отменить. Исходные файлы не изменяются.")
        elif self.state == "decoding":
            text = self.tr2("Decoding in a separate process. Cancel is available.",
                            "Декодирование в отдельном процессе. Можно отменить.")
        elif self.state == "error":
            failure_state = (self.import_failure or {}).get("state")
            labels = {"CANCELLED": ("Import cancelled: ", "Импорт отменён: "),
                      "TIMED_OUT": ("Import time limit: ", "Лимит времени импорта: "),
                      "LIMIT_REACHED": ("Import size or memory limit: ", "Лимит размера или памяти: ")}
            text = self.tr2(*labels.get(failure_state, ("Not decoded: ", "Не расшифровано: "))) + self.error
            if self.import_failure:
                text += self.tr2(" Open the original again to retry. No partial result was published.",
                                 " Для повтора откройте исходный файл заново. Частичный результат не опубликован.")
        elif self._analysis_kind in ("minidump", "minidump_memory") and self.analysis_report is not None:
            text = self.tr2("Saved minidump metadata: ", "Метаданные сохранённого дампа: ")
            text += str(self.analysis_report.get("status", "INCOMPLETE_EVIDENCE"))
            text += self.tr2(" · historical state; live process binding NOT_ESTABLISHED",
                             " · прошлое состояние; связь с живым процессом НЕ УСТАНОВЛЕНА")
        elif self.summary:
            s = self.summary
            text = self.tr2("Result", "Результат") + f": {s['status']} · {s['rows']} events · {s['events_with_stacks']} stacks · "
            text += f"GC pairs: {s['gc']['gc_pairs']} · errors: {s['events_with_errors']} · bounded: {s['bounded_events']}"
            profiles = s.get("profiles", {})
            if profiles:
                text += (f" · CPU profiler: {profiles['cpu_profiler_samples_recorded']} recorded, "
                         f"{profiles['cpu_stack_groups_indexed']} stack groups "
                         f"({profiles['cpu_profiler_samples_omitted_from_groups']} ungrouped)")
            clock = s.get("calendar_clock", {})
            if clock:
                alignment = (self.alignment_report.get("status") if self.alignment_report is not None
                             else clock['trace_to_blackbox_session_clock_alignment'])
                text += (f" · UTC projections: {clock['events_with_utc_projection']}/{s['rows']}, "
                         f"offset discrepancies: {clock['relative_vs_utc_offset_disagreements_over_10ms']}, "
                         f"session alignment: {alignment}")
            text += self.tr2(" · capture completeness UNKNOWN; sample counts ≠ CPU%",
                             " · полнота записи НЕИЗВЕСТНА; число выборок ≠ CPU%")
        else:
            c = capability()
            text = c["engine"] + self.tr2(" · helper ready" if c["helper_present"] else " · helper not built (JSONL available)",
                         " · модуль готов" if c["helper_present"] else " · модуль не собран (JSONL доступен)")
        if self.clock_review is not None and self.summary and self.state == "decoded":
            review = self.clock_review
            text += self.tr2(" · CAPTURE CLOCK REVIEW: ", " · ПРОВЕРКА ЧАСОВ ЗАПИСИ: ")
            text += str(review.get("status", "UNKNOWN"))
            text += " · trace/session: NOT_ESTABLISHED"
        if self.alignment_report is not None and self.summary and self.state == "decoded":
            text += self.tr2(" · SESSION CORRELATION: ", " · СВЯЗЬ С СЕАНСОМ: ")
            text += str(self.alignment_report.get("status", "NOT_ESTABLISHED"))
        if self.pdb_review is not None and self.summary and self.state == "decoded":
            text += self.tr2(" · LOCAL PDB: ", " · ЛОКАЛЬНЫЙ PDB: ")
            text += str(self.pdb_review.get("status", "UNKNOWN"))
            text += " · trace module: NOT_ESTABLISHED"
        self.status.setText(text)

    def choose(self, from_session):
        folder = getattr(self.window.probe, "session_folder", None) if from_session else None
        filename, _ = QFileDialog.getOpenFileName(self, self.tr2("Open trace", "Открыть трассу"),
                   str(folder or ""), "Trace files (*.etl *.nettrace *.jsonl)")
        if filename:
            self.start_decode(Path(filename))

    def _remove_cached_index(self, path):
        """Only our private cache owns decoder files; never unlink imports."""
        if path is not None and Path(path).parent.resolve() == Path(self.cache.name).resolve():
            for suffix in ("", "-wal", "-shm", "-journal"):
                Path(str(path) + suffix).unlink(missing_ok=True)

    def open_index_interval(self, index_path, *, expected_trace_sha256=None,
                            expected_index_sha256=None, process_instance=None, pid=None,
                            tid=None, start_ms=None, end_ms=None):
        """Open a private copy and preset recorded-instance analysis filters.

        Opening an interval never binds a live PID or starts a recording. The
        normal event table keeps its ordinary PID/page filter; CPU/wait actions
        use the explicit recorded instance, TID and trace-relative interval.
        """
        if self.worker is not None:
            return False
        if getattr(self.window.probe, "active", False):
            self.state, self.error = "error", "STOP_RECORDING_BEFORE_OFFLINE_ANALYSIS"
            self.render_status()
            return False
        from .decoder_index_navigation import navigation_filters
        try:
            filters = navigation_filters(process_instance=process_instance, pid=pid, tid=tid,
                                         start_ms=start_ms, end_ms=end_ms)
        except (TypeError, ValueError) as exc:
            self.state, self.error = "error", str(exc)
            self.render_status()
            return False
        self._clear_dump_state()
        self._close_calltree()
        self._index_navigation_generation += 1
        self._pending_index_navigation = None
        self._navigation_first_page = None
        previous, self.index = self.index, None
        # A graph may refer to this very cache index. Keep the input until a
        # complete private copy has committed; failed/cancelled navigation must
        # never destroy the previous source either.
        self.summary, self.rows = None, []
        self.analysis_report = self.alignment_report = self.clock_review = self.pdb_review = None
        self._analysis_kind = None
        self.import_failure = None
        self.cursors, self.next_cursor = [0], 0
        self.table.clearContents()
        self.table.setRowCount(0)
        self.details.clear()
        self.reset_cpu_scope()
        for button in (self.open_button, self.session_button, self.dump_button,
                       self.calltree_button, self.resolve_tree_button, self.resolve_stack_button,
                       self.waits_button, self.align_session_button, self.export_analysis_button,
                       self.export_button, self.review_clock_button, self.review_pdb_button,
                       self.prev_button, self.next_button):
            button.setEnabled(False)
        self._enable_cpu_scope(False)
        self.cancel_button.setEnabled(True)
        self.state, self.error = "analyzing", ""
        output = Path(self.cache.name) / (uuid4().hex + ".sqlite3")
        self.worker = OpenIndexWorker(index_path, output,
            {"expected_trace_sha256": expected_trace_sha256,
             "expected_index_sha256": expected_index_sha256, "filters": filters},
            self._index_navigation_generation, self)
        self.worker.previous_index = previous
        self.worker.result_ready.connect(self._index_interval_received)
        self.worker.finished.connect(self.finished)
        self.render_status()
        self.worker.start()
        return True

    def cancel_index_navigation(self):
        if getattr(self.worker, "kind", None) == "open_index_interval":
            self.cancel()

    def _index_interval_received(self, packet, error):
        worker = self.worker
        if (getattr(worker, "kind", None) != "open_index_interval" or
                worker.generation != self._index_navigation_generation or worker.cancel_event.is_set()):
            if packet and packet.get("path"):
                self._remove_cached_index(packet["path"])
            return
        if not error:
            # The first bounded page was read in the worker. Preset its base
            # filter before rendering, without issuing SQLite work on Qt.
            self.mode.blockSignals(True)
            self.mode.setCurrentIndex(self.mode.findData("events"))
            self.mode.blockSignals(False)
            self.pid.setValue(packet["navigation"].get("pid") or 0)
            self.search.clear()
            self._navigation_first_page = packet["initial_page"]
        self.received(packet, error)
        if not error and self.index is not None:
            previous = getattr(worker, "previous_index", None)
            if previous is not None and Path(previous).resolve() != Path(worker.source).resolve():
                self._remove_cached_index(previous)
            scope = packet["navigation"]
            self.pid.setValue(scope.get("pid") or 0)
            self.cpu_source.setCurrentIndex(self.cpu_source.findData(
                "etw" if packet["summary"].get("format") == ".etl" else "dotnet"))
            for key, field in (("process_instance", self.cpu_instance), ("tid", self.cpu_tid),
                               ("start_ms", self.cpu_start), ("end_ms", self.cpu_end)):
                value = scope.get(key)
                field.setText("" if value is None else str(value))
            self._pending_index_navigation = packet
            self.details.setPlainText(self.tr2(
                "Recorded-instance CPU/wait filters selected below. The event table retains its ordinary page/PID filter. Time is trace-relative; relation to a live process is NOT_ESTABLISHED.",
                "Ниже выбраны фильтры CPU/ожиданий записанного экземпляра. Таблица событий сохраняет обычный фильтр страницы/PID. Время задано относительно трассы; связь с живым процессом НЕ УСТАНОВЛЕНА."))

    def start_decode(self, source):
        if self.worker is not None:
            return
        if getattr(self.window.probe, "active", False):
            self.state, self.error = "error", "STOP_RECORDING_BEFORE_OFFLINE_DECODE"
            self.render_status()
            return
        self._clear_dump_state()
        self._index_navigation_generation += 1
        self._pending_index_navigation = None
        self._navigation_first_page = None
        output = Path(self.cache.name) / (uuid4().hex + ".sqlite3")
        # Never show an old trace as though it belonged to the new input,
        # including while decoding or after a malformed file fails.
        previous = self.index
        self.index, self.summary, self.rows = None, None, []
        self.clock_review = None
        self.pdb_review = None
        self.analysis_report = None
        self.alignment_report = None
        self.import_failure = None
        self.reset_cpu_scope()
        for dialog in self.findChildren(CallTreeDialog):
            dialog.close()
        for dialog in self.findChildren(DiagnosticReportDialog):
            dialog.close()
        for button in (self.calltree_button, self.resolve_tree_button, self.resolve_stack_button,
                       self.export_analysis_button, self.waits_button, self.align_session_button):
            button.setEnabled(False)
        self.cursors, self.next_cursor = [0], 0
        self.table.clearContents()
        self.table.setRowCount(0)
        self.details.clear()
        for button in (self.prev_button, self.next_button, self.export_button,
                       self.review_clock_button, self.review_pdb_button):
            button.setEnabled(False)
        if previous is not None:
            self._remove_cached_index(previous)
        self.state = "decoding"
        self.open_button.setEnabled(False)
        self.session_button.setEnabled(False)
        self.dump_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.worker = DecodeWorker(source, output, self)
        self.worker.result_ready.connect(self.received)
        self.worker.finished.connect(self.finished)
        self.render_status()
        self.worker.start()

    def cancel(self):
        if self.worker is not None:
            self.worker.cancel_event.set()
            if getattr(self.worker, "kind", "") == "open_index_interval":
                self._index_navigation_generation += 1
                self._pending_index_navigation = None
                self._navigation_first_page = None
                self._remove_cached_index(self.index)
                self.index, self.summary, self.rows = None, None, []
                self.table.clearContents()
                self.table.setRowCount(0)
                self.details.clear()
                for button in (self.calltree_button, self.resolve_tree_button, self.resolve_stack_button,
                               self.waits_button, self.align_session_button, self.export_analysis_button,
                               self.export_button, self.review_clock_button, self.review_pdb_button,
                               self.prev_button, self.next_button):
                    button.setEnabled(False)
                self.state, self.error = "error", "DECODER_INDEX_NAVIGATION_CANCELLED"
                self.import_failure = {"state": "CANCELLED"}
                self.render_status()
            if getattr(self.worker, "kind", "") == "minidump_memory":
                self._dump_generation += 1
                self.dump_memory_view.clear()
                self.dump_memory_view.hide()
                self.state, self.error = "error", "DUMP_MEMORY_READ_CANCELLED"
                self.render_status()

    def received(self, packet, error):
        self.clock_review = None
        self.pdb_review = None
        self.alignment_report = None
        if error:
            self.state, self.error = "error", error
            self.import_failure = (packet or {}).get("failure")
        else:
            self.import_failure = None
            old = self.index
            self.index = Path(packet["path"])
            self.summary = packet["summary"]
            self.state = "decoded"
            if old and old != self.index:
                self._remove_cached_index(old)
            self.export_button.setEnabled(True)
            self.review_clock_button.setEnabled(True)
            self.review_pdb_button.setEnabled(True)
            self.calltree_button.setEnabled(True)
            self.resolve_tree_button.setEnabled(True)
            self.waits_button.setEnabled(True)
            self.align_session_button.setEnabled(True)
            self.reset_page()
        self.render_status()

    def finished(self):
        worker, self.worker = self.worker, None
        if worker is not None:
            worker.deleteLater()
        self.open_button.setEnabled(True)
        self.session_button.setEnabled(True)
        self.dump_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.export_analysis_button.setEnabled(self.analysis_report is not None)
        if self.index is not None:
            self.calltree_button.setEnabled(True)
            self.resolve_tree_button.setEnabled(True)
            self.waits_button.setEnabled(True)
            self.align_session_button.setEnabled(True)
            self.review_clock_button.setEnabled(True)
            self.review_pdb_button.setEnabled(True)
            self.export_analysis_button.setEnabled(self.analysis_report is not None)
            self._refresh_stack_action()
        self._enable_cpu_scope(True)
        self._refresh_dump_controls()
        self.idle.emit()
        pending, self._pending_index_navigation = self._pending_index_navigation, None
        if (pending is not None and getattr(worker, "kind", None) == "open_index_interval" and
                worker.generation == self._index_navigation_generation):
            self.index_interval_opened.emit(pending)

    def _clear_dump_state(self):
        self._dump_generation += 1
        self._dump_path = None
        self._dump_identity = None
        self.dump_address.clear()
        self.dump_memory_view.clear()
        self.dump_memory_view.hide()
        self._refresh_dump_controls()

    def _dump_mode_changed(self, *_):
        self._clear_dump_state()
        if self.worker is not None and getattr(self.worker, "kind", "") in ("minidump", "minidump_memory"):
            self.worker.cancel_event.set()

    def _refresh_dump_controls(self):
        loaded = self._dump_path is not None and self._dump_identity is not None
        available = self.worker is None and loaded
        for control in (self.dump_memory_notice, self.dump_address_label, self.dump_address,
                        self.dump_size_label, self.dump_size, self.dump_memory_button):
            control.setVisible(loaded)
        for control in (self.dump_address, self.dump_size, self.dump_memory_button):
            control.setEnabled(available)
        if not loaded:
            self.dump_memory_view.hide()
        self.dump_memory_notice.setText(
            (self.tr2("Saved dump: ", "Сохранённый дамп: ") + Path(self._dump_path).name + "\n" if self._dump_path else
             self.tr2("Open a saved dump to read its recorded memory.\n", "Откройте сохранённый дамп для чтения записанной памяти.\n")) +
            self.tr2("Imported historical bytes are displayed only here; SAVE DUMP METADATA excludes them. No live process is required. File consistency checks do not authenticate the dump's origin.",
                     "Импортированные исторические байты показываются только здесь и не входят в СОХРАНЕНИЕ МЕТАДАННЫХ ДАМПА. Живой процесс не требуется. Проверка неизменности файла не удостоверяет происхождение дампа."))

    def read_saved_dump_memory(self):
        if self.worker is not None or self._dump_path is None or self._dump_identity is None:
            return
        self.dump_memory_view.clear()
        self.dump_memory_view.hide()
        try:
            text = self.dump_address.text().strip()
            address = int(text, 16 if text.lower().startswith("0x") else 10)
            size = self.dump_size.value()
            if not 0 <= address < 2**64 or not 1 <= size <= 4096 or address + size > 2**64:
                raise ValueError("INVALID_DUMP_MEMORY_READ")
        except ValueError:
            self.state, self.error = "error", "INVALID_DUMP_MEMORY_ADDRESS_OR_SIZE_1_TO_4096"
            self.render_status()
            return
        self.start_analysis("minidump_memory", {"path": self._dump_path, "expected_identity": self._dump_identity,
                                               "address": address, "size": size})

    def reset_page(self):
        self.cursors = [0]
        self.load_page()

    def load_page(self):
        if not self.index:
            return
        try:
            mode = self.mode.currentData()
            page, self._navigation_first_page = self._navigation_first_page, None
            if page is None:
                page = read_index(self.index, after=self.cursors[-1], mode=mode,
                                  pid=self.pid.value(), search=self.search.text())
            self._table_headers()
            self.rows = page["rows"]
            self.table.setRowCount(len(self.rows))
            # Never carry a selected QTableWidget row across result sets.
            # If selection remains, selecting that same row later emits no
            # change signal and keeps the generic summary instead of details.
            self.table.clearSelection()
            for i, item in enumerate(self.rows):
                row = item["event"]
                if mode == "cpu_stacks":
                    # Only confirmed profiler Thread/Sample events participate;
                    # other event-associated stacks do NOT become CPU weight.
                    frames = row.get("frames") or []
                    first_frame = frames[0] if frames else {}
                    display = first_frame.get("name") or first_frame.get("address") or "UNRESOLVED"
                    cells = (item["index_id"], row["recorded_sample_count"], row["pid"],
                             "SampleProfiler", display)
                elif mode == "gc_summary":
                    gen = row.get("generation")
                    suffix = f" · Gen{gen}" if gen is not None else ""
                    cells = (item["index_id"], row["interval_count"], row["pid"],
                             "CLR", row["kind"] + suffix)
                elif mode == "modules":
                    module = row["module"]
                    cells = (item["index_id"], row["frame_count"], row["pid"],
                             "TRACE MODULE", module["module_name"])
                elif mode == "clock":
                    cells = (item["index_id"], row.get("utc_time_iso", "UNKNOWN"), row["pid"],
                             row.get("provider", "TRACE"), row.get("name", ""))
                else:
                    cells = (item["index_id"], round(row.get("time_ms", row.get("start_ms", 0)), 4),
                             row["pid"], row.get("provider", "DERIVED"),
                             row.get("name", row.get("kind", "")))
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

    def _refresh_stack_action(self):
        index = self.table.currentRow()
        row = self.rows[index]["event"] if 0 <= index < len(self.rows) else {}
        self.resolve_stack_button.setEnabled(self.worker is None and
            bool(self.table.selectionModel().selectedRows()) and
            row.get("type") == "event" and bool(row.get("frames")))

    def show_details(self):
        self._refresh_stack_action()
        index = self.table.currentRow()
        if 0 <= index < len(self.rows):
            row = self.rows[index]["event"]
            detail = row
            if self.alignment_report is not None and row.get("type") == "event":
                from blackbox_core.decoder_alignment import project_event_time
                detail = {"original_event": row,
                          "session_time_projection": project_event_time(self.alignment_report, row)}
            self.details.setPlainText(json.dumps(detail, ensure_ascii=False, indent=2))

    def review_clock_journal(self):
        """Optional, manual review of a matching *.trace.json capture journal."""
        if not self.index or self.worker is not None:
            return
        folder = getattr(self.window.probe, "session_folder", None)
        selected, _ = QFileDialog.getOpenFileName(
            self, self.tr2("Select owned capture journal", "Выберите журнал записи"),
            str(folder or ""), "Capture journals (*.trace.json)")
        if selected:
            self.review_clock_journal_path(Path(selected))

    def review_clock_journal_path(self, journal_path):
        """Structured offline review; a matching hash is NOT clock alignment."""
        if not self.index or self.worker is not None:
            return None
        self.alignment_report = None
        if self._analysis_kind == "alignment":
            self.analysis_report = None
            self.export_analysis_button.setEnabled(False)
        try:
            report = assess_trace_capture_journal(self.index, journal_path)
        except (OSError, ValueError, KeyError, RuntimeError) as exc:
            report = {
                "status": "CLOCK_PROVENANCE_UNAVAILABLE",
                "error": type(exc).__name__,
                "trace_to_blackbox_session_clock_alignment": "NOT_ESTABLISHED",
                "verification_class": "UNVERIFIED_LOCAL_JOURNAL",
            }
        self.table.clearSelection()
        self.details.setPlainText(json.dumps(report, ensure_ascii=False, indent=2))
        self.clock_review = report
        self.render_status()
        return report


    def review_local_pdb(self):
        """User-controlled offline pair review; no PDB names injected into traces."""
        if not self.index or self.worker is not None:
            return
        folder = getattr(self.window.probe, "session_folder", None)
        binary, _ = QFileDialog.getOpenFileName(
            self, self.tr2("Select local PE module", "Выберите локальный PE-модуль"),
            str(folder or ""),
            "PE modules (*.exe *.dll *.sys *.ocx);;All files (*)")
        if not binary:
            return
        pdb, _ = QFileDialog.getOpenFileName(
            self, self.tr2("Select local Windows PDB", "Выберите локальный Windows PDB"),
            str(Path(binary).parent), "PDB (*.pdb);;All files (*)")
        if pdb:
            self.review_local_pdb_paths(Path(binary), Path(pdb))

    def review_local_pdb_paths(self, binary_path, pdb_path):
        """GUID/Age preflight only, never proof of a trace module association."""
        if not self.index or self.worker is not None:
            return None
        try:
            report = review_local_pe_pdb(binary_path, pdb_path)
        except (OSError, ValueError, TypeError, RuntimeError) as exc:
            report = {
                "status": "LOCAL_IDENTITY_UNAVAILABLE",
                "reason": type(exc).__name__,
                "trace_module_identity": "NOT_ESTABLISHED",
                "stack_symbols_resolved": False,
                "symbol_server_contacted": False,
            }
        self.table.clearSelection()
        self.details.setPlainText(json.dumps(report, ensure_ascii=False, indent=2))
        self.pdb_review = report
        self.render_status()
        return report

    def _close_calltree(self):
        dialog = getattr(self, "_calltree_dialog", None)
        if dialog is not None:
            try:
                dialog.close()
            except RuntimeError:
                pass  # WA_DeleteOnClose may already have deleted its C++ object.
            self._calltree_dialog = None
        for report_dialog in self.findChildren(DiagnosticReportDialog):
            report_dialog.close()

    def _analysis_filter_changed(self, *_):
        # Do not export an old tree as though it used newly edited filters.
        if self._analysis_kind in ("calltree", "waits") and self.worker is None:
            self.analysis_report = None
            self.export_analysis_button.setEnabled(False)
            self._close_calltree()
            self.details.clear()

    def _enable_cpu_scope(self, enabled):
        for control in (self.cpu_source, self.cpu_instance, self.cpu_tid,
                        self.cpu_start, self.cpu_end, self.cpu_reset, self.pid):
            control.setEnabled(enabled)

    def reset_cpu_scope(self):
        for field in (self.cpu_instance, self.cpu_tid, self.cpu_start, self.cpu_end):
            field.clear()

    def _calltree_arguments(self):
        return {"index_path": self.index, **parse_calltree_filters(
            source=self.cpu_source.currentData(), pid=self.pid.value(),
            instance_text=self.cpu_instance.text(), tid_text=self.cpu_tid.text(),
            start_text=self.cpu_start.text(), end_text=self.cpu_end.text())}

    def start_calltree(self):
        if self.index is None or self.worker is not None:
            return
        try:
            arguments = self._calltree_arguments()
        except ValueError as exc:
            self.state, self.error = "error", str(exc)
            self.render_status(); return
        self.start_analysis("calltree", arguments)

    def start_wait_analysis(self):
        if self.index is None or self.worker is not None:
            return
        try:
            arguments = self._calltree_arguments()
            arguments.pop("source")
        except ValueError as exc:
            self.state, self.error = "error", str(exc)
            self.render_status()
            return
        self.start_analysis("waits", arguments)

    def choose_session_alignment(self):
        if self.index is None or self.worker is not None:
            return
        folder = str(getattr(self.window.probe, "session_folder", None) or "")
        journal, _ = QFileDialog.getOpenFileName(self,
            self.tr2("Choose capture clock journal", "Выберите журнал часов записи"),
            folder, "Capture journal (*.trace.json)")
        if not journal:
            return
        session, _ = QFileDialog.getOpenFileName(self,
            self.tr2("Choose BLACK.BOX session database", "Выберите базу сеанса BLACK.BOX"),
            str(Path(journal).parent), "Session database (session-v2.sqlite3);;SQLite (*.sqlite3)")
        if session:
            self.start_analysis("alignment", {"index_path": self.index,
                "journal_path": Path(journal), "session_path": Path(session)})

    def choose_calltree_symbols(self):
        if self.index is None or self.worker is not None:
            return
        try:
            arguments = self._calltree_arguments()
        except ValueError as exc:
            self.state, self.error = "error", str(exc)
            self.render_status(); return
        binary, _ = QFileDialog.getOpenFileName(self,
            self.tr2("Choose local PE for CPU tree", "Выберите локальный PE для дерева CPU"),
            "", "PE (*.exe *.dll *.sys);;All files (*)")
        if not binary:
            return
        pdb, _ = QFileDialog.getOpenFileName(self,
            self.tr2("Choose matching Windows PDB", "Выберите соответствующий Windows PDB"),
            str(Path(binary).parent), "PDB (*.pdb)")
        if pdb:
            self.start_analysis("calltree", {**arguments, "binary_path": Path(binary), "pdb_path": Path(pdb)})

    def choose_stack_symbols(self):
        if self.worker is not None:
            return
        index = self.table.currentRow()
        row = self.rows[index]["event"] if 0 <= index < len(self.rows) else {}
        if (not self.table.selectionModel().selectedRows() or
                row.get("type") != "event" or not row.get("frames")):
            return
        binary, _ = QFileDialog.getOpenFileName(self,
            self.tr2("Select local PE for this stack", "Выберите локальный PE для стека"),
            "", "PE (*.exe *.dll *.sys);;All files (*)")
        if not binary:
            return
        pdb, _ = QFileDialog.getOpenFileName(self,
            self.tr2("Select matching local Windows PDB", "Выберите соответствующий Windows PDB"),
            str(Path(binary).parent), "PDB (*.pdb)")
        if pdb:
            self.start_analysis("symbols", {"row": json.loads(json.dumps(row)),
                "binary_path": Path(binary), "pdb_path": Path(pdb),
                "source_trace_sha256": self.summary.get("input_sha256")})

    def choose_minidump(self):
        if self.worker is not None:
            return
        selected, _ = QFileDialog.getOpenFileName(
            self, self.tr2("Open saved minidump", "Открыть сохранённый дамп"),
            "", "Windows minidump (*.dmp *.mdmp);;All files (*)")
        if selected:
            self.start_analysis("minidump", {"path": Path(selected)})

    def start_analysis(self, kind, arguments):
        if self.worker is not None or (self.index is None and kind not in ("minidump", "minidump_memory")):
            return
        if getattr(self.window.probe, "active", False):
            self.state, self.error = "error", "STOP_RECORDING_BEFORE_OFFLINE_ANALYSIS"
            self.render_status(); return
        self._close_calltree()
        if kind == "minidump_memory":
            self._dump_generation += 1
            self.dump_memory_view.clear()
            self.dump_memory_view.hide()
        else:
            self._clear_dump_state()
            self.analysis_report = None
        if kind == "alignment":
            self.alignment_report = None
        self._analysis_kind = kind
        self.state, self.error = "analyzing", ""
        self.import_failure = None
        if kind != "minidump_memory":
            self.details.clear()
        for button in (self.open_button, self.session_button, self.dump_button, self.calltree_button, self.resolve_tree_button,
                       self.resolve_stack_button, self.export_analysis_button,
                       self.review_pdb_button, self.review_clock_button, self.waits_button,
                       self.align_session_button):
            button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self._enable_cpu_scope(False)
        self.worker = DecoderAnalysisWorker(kind, arguments, self)
        self.worker.view_generation = self._dump_generation
        self.worker.result_ready.connect(self.analysis_received)
        self.worker.finished.connect(self.finished)
        self.render_status(); self.worker.start()

    def analysis_received(self, report, error, *, kind=None, generation=None):
        kind = kind or getattr(self.worker, "kind", self._analysis_kind)
        if generation is None:
            generation = getattr(self.worker, "view_generation", None)
        if kind in ("minidump", "minidump_memory") and generation is not None and generation != self._dump_generation:
            self.state = "error"
            if self.error != "DUMP_MEMORY_READ_CANCELLED":
                self.error = "DUMP_SELECTION_CHANGED_DURING_ANALYSIS"
            self.render_status()
            return
        if kind == "minidump_memory":
            if error:
                self.state, self.error = "error", error
                if error == "DUMP_CHANGED_SINCE_METADATA_INSPECTION":
                    self._clear_dump_state()
            else:
                self.state, self.error = "decoded", ""
                self.dump_memory_view.setPlainText(json.dumps(report, ensure_ascii=False, indent=2))
                self.dump_memory_view.show()
            # Sensitive bytes never replace metadata in analysis_report, so
            # ordinary analysis export cannot accidentally disclose this view.
            self.render_status()
            return
        if error:
            self.state, self.error = "error", error
            self.analysis_report = None
        else:
            self.state, self.error = "decoded", ""
            if kind == "minidump":
                report = dict(report)
                self._dump_path = report.pop("_dump_path")
                self._dump_identity = tuple(report.pop("_dump_file_identity"))
            self.analysis_report = report
            self.details.setPlainText(json.dumps(report, ensure_ascii=False, indent=2))
            if self._analysis_kind == "calltree":
                self._calltree_dialog = CallTreeDialog(report, self.window.language, self)
                self._calltree_dialog.show()
            elif self._analysis_kind in ("alignment", "waits", "minidump"):
                if self._analysis_kind == "alignment":
                    self.alignment_report = report
                    self.clock_review = None
                dialog = DiagnosticReportDialog(report, self.window.language, self)
                dialog.show()
        self.render_status()

    def save_analysis(self):
        if self.analysis_report is None or self.worker is not None:
            return
        report = self.analysis_report
        tree = report.get("schema") == "blackbox.cpu-calltree/1"
        dump_metadata = report.get("schema") == "blackbox.deep-minidump/1"
        filters = "JSON (*.json);;Offline flame view (*.html)" if tree else "JSON (*.json)"
        name, chosen = QFileDialog.getSaveFileName(self,
            (self.tr2("Save dump metadata (memory contents excluded)",
                      "Сохранить метаданные дампа (без содержимого памяти)") if dump_metadata else
             self.tr2("Save derived analysis (may contain private data)",
                      "Сохранить производный анализ (может содержать личные данные)")),
            "dump-metadata.json" if dump_metadata else "decoder-analysis.json", filters)
        if not name or self.analysis_report is not report or self.worker is not None:
            return
        try:
            export_analysis(report, Path(name), html=tree and chosen.endswith("(*.html)"))
        except (OSError, ValueError) as exc:
            self.state, self.error = "error", type(exc).__name__
            self.render_status()

    def export_index(self):
        if not self.index:
            return
        name, _ = QFileDialog.getSaveFileName(self, self.tr2("Save decoded index (contains trace data)",
                        "Сохранить индекс (содержит данные трассы)"), "decoded-trace.sqlite3", "SQLite (*.sqlite3)")
        if not name:
            return
        try:
            export_index_copy(self.index, Path(name))
        except (OSError, ValueError) as exc:
            self.state, self.error = "error", type(exc).__name__ + ": " + str(exc)
            self.render_status()
