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
from blackbox_core.decoder_index import read_index
from blackbox_core.trace_clock_evidence import assess_trace_capture_journal
from blackbox_core.decoder_pdb import review_local_pe_pdb
from blackbox_core.decoder_calltree import export_analysis, parse_calltree_filters
from .decoder_analysis import DecoderAnalysisWorker, CallTreeDialog


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
        self.clock_review = None  # Manual journal review, scoped to current index.
        self.pdb_review = None  # Independent local file pair, not bound to trace.
        self.analysis_report = None
        self._analysis_kind = None
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
        self.calltree_button.clicked.connect(self.start_calltree)
        self.resolve_tree_button.clicked.connect(self.choose_calltree_symbols)
        self.resolve_stack_button.clicked.connect(self.choose_stack_symbols)
        self.export_analysis_button.clicked.connect(self.save_analysis)
        for i, button in enumerate((self.calltree_button, self.resolve_tree_button,
                                    self.resolve_stack_button, self.export_analysis_button)):
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

    def tr2(self, en, ru):
        return ru if self.window.language == "RU" else en

    def retranslate(self):
        self.notice.setText(self.tr2(
            "OFFLINE TRACE DECODER · ETL / EventPipe / BLACK.BOX JSONL. No recording or symbol downloads. "
            "Trace time is NOT aligned to your session. UTC is reconstructed by TraceEvent, NOT independently synchronized. "
            "GC elapsed time is NOT a pause. Imported data is unverified.",
            "ДЕКОДЕР ТРАСС · ETL / EventPipe / JSONL BLACK.BOX. Без записи и загрузки символов. "
            "Время НЕ совмещено с сеансом. UTC восстановлено TraceEvent, а НЕ независимо синхронизировано. "
            "Длительность GC — НЕ пауза. Импорт не удостоверяет источник."))
        for button, en, ru in ((self.open_button, "OPEN TRACE…", "ОТКРЫТЬ ТРАССУ…"),
                (self.session_button, "FROM SESSION…", "ИЗ СЕАНСА…"),
                (self.cancel_button, "CANCEL", "ОТМЕНА"),
                (self.apply_button, "APPLY FILTER", "ПРИМЕНИТЬ ФИЛЬТР"),
                (self.prev_button, "PREVIOUS", "НАЗАД"), (self.next_button, "NEXT", "ДАЛЕЕ"),
                (self.export_button, "SAVE INDEX…", "СОХРАНИТЬ ИНДЕКС…"),
                (self.review_clock_button, "CHECK CAPTURE CLOCK…", "ПРОВЕРИТЬ ЧАСЫ ЗАПИСИ…"),
                (self.review_pdb_button, "CHECK LOCAL PDB…", "ПРОВЕРИТЬ ЛОКАЛЬНЫЙ PDB…"),
                (self.calltree_button, "CPU CALL TREE…", "ДЕРЕВО CPU-ВЫБОРОК…"),
                (self.resolve_tree_button, "TREE + LOCAL PDB…", "ДЕРЕВО + ЛОКАЛЬНЫЙ PDB…"),
                (self.resolve_stack_button, "RESOLVE SELECTED STACK…", "ИМЕНА ВЫБРАННОГО СТЕКА…"),
                (self.export_analysis_button, "SAVE ANALYSIS…", "СОХРАНИТЬ АНАЛИЗ…")):
            button.setText(self.tr2(en, ru))
        self.cpu_scope_label.setText(self.tr2("CPU tree:", "Дерево CPU:"))
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
            "Only CPU trees use these filters and the PID above. Blank means all. "
            "Times are trace-relative milliseconds [from, to); use a decimal point.",
            "Эти фильтры и PID выше относятся к дереву CPU. Пустое поле — все. "
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
        if self.state == "analyzing":
            text = self.tr2("Offline analysis; cancel is available. Sources are not modified.",
                            "Офлайн-анализ; можно отменить. Исходные файлы не изменяются.")
        elif self.state == "decoding":
            text = self.tr2("Decoding in a separate process. Cancel is available.",
                            "Декодирование в отдельном процессе. Можно отменить.")
        elif self.state == "error":
            text = self.tr2("Not decoded: ", "Не расшифровано: ") + self.error
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
                text += (f" · UTC projections: {clock['events_with_utc_projection']}/{s['rows']}, "
                         f"offset discrepancies: {clock['relative_vs_utc_offset_disagreements_over_10ms']}, "
                         f"session alignment: {clock['trace_to_blackbox_session_clock_alignment']}")
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
        self.clock_review = None
        self.pdb_review = None
        self.analysis_report = None
        self.reset_cpu_scope()
        for dialog in self.findChildren(CallTreeDialog):
            dialog.close()
        for button in (self.calltree_button, self.resolve_tree_button, self.resolve_stack_button, self.export_analysis_button):
            button.setEnabled(False)
        self.cursors, self.next_cursor = [0], 0
        self.table.clearContents()
        self.table.setRowCount(0)
        self.details.clear()
        for button in (self.prev_button, self.next_button, self.export_button,
                       self.review_clock_button, self.review_pdb_button):
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
        self.clock_review = None
        self.pdb_review = None
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
            self.review_clock_button.setEnabled(True)
            self.review_pdb_button.setEnabled(True)
            self.calltree_button.setEnabled(True)
            self.resolve_tree_button.setEnabled(True)
            self.reset_page()
        self.render_status()

    def finished(self):
        worker, self.worker = self.worker, None
        if worker is not None:
            worker.deleteLater()
        self.open_button.setEnabled(True)
        self.session_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        if self.index is not None:
            self.calltree_button.setEnabled(True)
            self.resolve_tree_button.setEnabled(True)
            self.review_clock_button.setEnabled(True)
            self.review_pdb_button.setEnabled(True)
            self.export_analysis_button.setEnabled(self.analysis_report is not None)
            self._refresh_stack_action()
        self._enable_cpu_scope(True)
        self.idle.emit()

    def reset_page(self):
        self.cursors = [0]
        self.load_page()

    def load_page(self):
        if not self.index:
            return
        try:
            mode = self.mode.currentData()
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
            self.details.setPlainText(json.dumps(self.rows[index]["event"], ensure_ascii=False, indent=2))

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

    def _analysis_filter_changed(self, *_):
        # Do not export an old tree as though it used newly edited filters.
        if self._analysis_kind == "calltree" and self.worker is None:
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

    def start_analysis(self, kind, arguments):
        if self.worker is not None or self.index is None:
            return
        if getattr(self.window.probe, "active", False):
            self.state, self.error = "error", "STOP_RECORDING_BEFORE_OFFLINE_ANALYSIS"
            self.render_status(); return
        self._close_calltree()
        self.analysis_report = None
        self._analysis_kind = kind
        self.state, self.error = "analyzing", ""
        self.details.clear()
        for button in (self.open_button, self.session_button, self.calltree_button, self.resolve_tree_button,
                       self.resolve_stack_button, self.export_analysis_button,
                       self.review_pdb_button, self.review_clock_button):
            button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self._enable_cpu_scope(False)
        self.worker = DecoderAnalysisWorker(kind, arguments, self)
        self.worker.result_ready.connect(self.analysis_received)
        self.worker.finished.connect(self.finished)
        self.render_status(); self.worker.start()

    def analysis_received(self, report, error):
        if error:
            self.state, self.error = "error", error
            self.analysis_report = None
        else:
            self.state, self.error = "decoded", ""
            self.analysis_report = report
            self.details.setPlainText(json.dumps(report, ensure_ascii=False, indent=2))
            if self._analysis_kind == "calltree":
                self._calltree_dialog = CallTreeDialog(report, self.window.language, self)
                self._calltree_dialog.show()
        self.render_status()

    def save_analysis(self):
        if self.analysis_report is None or self.worker is not None:
            return
        tree = self.analysis_report.get("schema") == "blackbox.cpu-calltree/1"
        filters = "JSON (*.json);;Offline flame view (*.html)" if tree else "JSON (*.json)"
        name, chosen = QFileDialog.getSaveFileName(self,
            self.tr2("Save derived analysis (may contain private data)",
                     "Сохранить производный анализ (может содержать личные данные)"),
            "decoder-analysis.json", filters)
        if not name:
            return
        try:
            export_analysis(self.analysis_report, Path(name), html=tree and chosen.endswith("(*.html)"))
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
            # Create-new, even when a file dialog offers overwrite confirmation.
            with self.index.open("rb") as source, Path(name).open("xb") as target:
                import shutil
                shutil.copyfileobj(source, target)
        except OSError as exc:
            self.state, self.error = "error", type(exc).__name__ + ": " + str(exc)
            self.render_status()
