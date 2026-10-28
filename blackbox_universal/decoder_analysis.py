"""Explicit, cancellable offline decoder analysis. No recording or network."""
import json
from html import escape
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QLabel, QTreeWidget,
                              QTreeWidgetItem, QDialogButtonBox, QTableWidget,
                              QTableWidgetItem, QHeaderView, QPlainTextEdit)
from threading import Event

from blackbox_core.decoder_calltree import build_calltree
from blackbox_core.decoder_native_symbols import resolve_event_stack


class DecoderAnalysisWorker(QThread):
    result_ready = Signal(object, str)

    def __init__(self, kind, arguments, parent=None):
        super().__init__(parent)
        self.kind, self.arguments = kind, arguments
        self.cancel_event = Event()

    def run(self):
        try:
            if self.kind == 'calltree':
                result = build_calltree(**self.arguments, cancel=self.cancel_event)
            elif self.kind == 'symbols':
                result = resolve_event_stack(**self.arguments, cancel=self.cancel_event)
            elif self.kind == 'waits':
                from blackbox_core.decoder_waits import build_wait_report
                result = build_wait_report(**self.arguments, cancel=self.cancel_event)
            elif self.kind == 'alignment':
                from blackbox_core.decoder_alignment import assess_session_alignment
                result = assess_session_alignment(**self.arguments, cancel=self.cancel_event)
            elif self.kind == 'minidump':
                from blackbox_core.deep_dump import inspect_dump
                packet = inspect_dump(**self.arguments, cancel_event=self.cancel_event)
                result = {**packet['data'], 'status': packet['status'],
                          'limitations': packet.get('limitations', []),
                          'next_action': packet.get('next_action')}
            else:
                raise ValueError('UNKNOWN_DECODER_ANALYSIS')
            self.result_ready.emit(result, '')
        except Exception as exc:
            # Reason codes only; no private local paths leaked to GUI status.
            reason = str(exc) if isinstance(exc, (ValueError, InterruptedError, TimeoutError)) else type(exc).__name__
            self.result_ready.emit(None, reason[:200])


class DiagnosticReportDialog(QDialog):
    """Human summary plus original derived evidence; imported strings stay plain."""
    def __init__(self, report, language, parent=None):
        super().__init__(parent)
        ru = language == 'RU'
        waits = report.get('schema') == 'blackbox.thread-waits/1'
        dump = report.get('schema') == 'blackbox.deep-minidump/1'
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(('Сохранённый дамп' if ru else 'Saved minidump') if dump else
                            ('Ожидания потоков' if ru else 'Thread waits') if waits else
                            ('Временная связь с сеансом' if ru else 'Session time correlation'))
        self.resize(1000, 640)
        layout = QVBoxLayout(self)
        text = ((
            'Интервалы получены из записанных переключений потоков ETW. '
            'Время ожидания не доказывает владельца блокировки или причину зависания. '
            'Неполные интервалы и потери учитываются отдельно.' if ru else
            'Intervals come from recorded ETW thread switches. Waiting time does not prove '
            'a lock owner or the cause of a hang. Incomplete intervals and losses remain separate.'
        ) if waits else (
            'Сопоставление действует только при выполнении проверенных условий. '
            'Границы погрешности относятся к выбранным часам и файлам, а не к причинности. '
            'Локальные доказательства не удостоверяют происхождение импортированной трассы.' if ru else
            'Correlation applies only under the checked conditions. Uncertainty bounds apply to '
            'the selected clocks and files, not causality. Local evidence does not authenticate an imported trace.'
        ))
        if dump:
            text = ('Модули, сохранённые контексты потоков и области памяти прочитаны из дампа. '
                    'Это прошлое состояние, а не состояние живого процесса. Полный анализ кучи '
                    'и раскрутка сохранённых стеков не выполняются; содержимое памяти в отчёт не входит.' if ru else
                    'Modules, saved thread contexts and memory ranges were read from the dump. '
                    'This is historical state, not a live process. Heap analysis and saved-stack '
                    'unwinding are not performed; memory contents are excluded from this report.')
        width = report.get('uncertainty_width_ns')
        if not waits and report.get('status') == 'BOUNDED_LOCAL_CLOCK_CORRELATION' and type(width) is int and width >= 0:
            if report.get('precision_quality') == 'COARSE_OBSERVATION_INTERVAL_NO_INTERPOLATION':
                text += (f'\nСвязь по порядку измерений, без интерполяции. Ширина интервала события — до {width / 1e6:,.3f} мс; '
                         'у каждого события свои границы. Это не оценка точности физических часов.' if ru else
                         f'\nCorrelation uses observation order without interpolation. An event interval can span up to {width / 1e6:,.3f} ms; '
                         'each event has its own bounds. This does not measure physical clock accuracy.')
            else:
                text += (f'\nШирина интервала смещения QPC: {width / 1e6:,.6f} мс.' if ru else
                         f'\nQPC offset interval width: {width / 1e6:,.6f} ms.')
        notice = QLabel(text + '\n' + str(report.get('status', 'UNKNOWN')))
        notice.setObjectName('diagnosticEvidenceSummary')
        notice.setTextFormat(Qt.TextFormat.PlainText)
        notice.setWordWrap(True)
        layout.addWidget(notice)
        if waits:
            rows = report.get('intervals', [])
            shown = rows[:500]
            count = QLabel((f'Показано {len(shown)} из {len(rows)} интервалов; JSON сохраняет полный результат.' if ru else
                            f'Showing {len(shown)} of {len(rows)} intervals; JSON preserves the full result.'))
            layout.addWidget(count)
            table = QTableWidget(len(shown), 8)
            table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            table.setHorizontalHeaderLabels(['PID', 'TID', 'От, мс', 'До, мс', 'Off-CPU, мс', 'Готов, мс', 'Ожидание', 'Качество'] if ru else
                                            ['PID', 'TID', 'From ms', 'To ms', 'Off-CPU ms', 'Ready ms', 'Wait', 'Quality'])
            table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
            for i, row in enumerate(shown):
                for j, key in enumerate(('pid', 'tid', 'start_ms', 'end_ms', 'off_cpu_ms',
                                          'ready_delay_ms', 'wait_reason', 'quality')):
                    value = row.get(key)
                    cell = QTableWidgetItem('—' if value is None else str(round(value, 6) if type(value) is float else value))
                    cell.setToolTip('<pre>' + escape(str(row.get('explanation', ''))) + '</pre>')
                    table.setItem(i, j, cell)
            layout.addWidget(table, 2)
        evidence = QPlainTextEdit()
        evidence.setReadOnly(True)
        evidence.setPlainText(json.dumps(report, ensure_ascii=False, indent=2))
        layout.addWidget(evidence, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.close)
        layout.addWidget(buttons)


class CallTreeDialog(QDialog):
    def __init__(self, report, language, parent=None):
        super().__init__(parent)
        ru = language == 'RU'
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle('Дерево CPU-выборок' if ru else 'CPU sample call tree')
        self.resize(920, 620)
        layout = QVBoxLayout(self)
        coverage = report['coverage']
        notice = QLabel((
            'Числа — количество записанных выборок, НЕ CPU% и НЕ время. '
            'Отсутствующие и обрезанные стеки показаны явно. ' if ru else
            'Counts are recorded samples, NOT CPU% or time. Missing and clipped stacks remain explicit. '
        ) + json.dumps({"status": report.get("status"), "filters": report["filters"],
                       "coverage": coverage}, ensure_ascii=False))
        notice.setWordWrap(True); layout.addWidget(notice)
        symbols = report.get("symbolization", {})
        if symbols.get("status") == "LOCAL_PAIR_REVIEWED":
            symbol_notice = QLabel((
                "Имена из локального PDB — производные; исходные кадры сохранены. Разрешено: " if ru else
                "Local PDB names are derived; original frames are preserved. Resolved: "
            ) + f'{symbols["frame_occurrences_resolved"]}/{symbols["frame_occurrences_reviewed"]}')
            symbol_notice.setWordWrap(True); layout.addWidget(symbol_notice)
        tree = QTreeWidget(); tree.setColumnCount(3)
        tree.setHeaderLabels(['Кадр / процесс','С потомками','В самом кадре'] if ru else
                            ['Frame / process','Inclusive samples','Self samples'])
        tree.setColumnWidth(0, 620)
        items = {}
        for node in report['nodes']:
            item = QTreeWidgetItem([node['label'],str(node['inclusive_samples']),str(node['self_samples'])])
            # QTreeWidget text is plain text, never render imported symbol names as HTML.
            item.setData(0, Qt.ItemDataRole.UserRole, node['id'])
            if node.get('frame'):
                item.setToolTip(0, "<pre>" + escape(json.dumps({"raw_frame": node['frame'],
                    "derived_symbol": node.get('derived_symbol')}, ensure_ascii=False, indent=2)) + "</pre>")
            if node['parent_id'] is None:tree.addTopLevelItem(item)
            else:items[node['parent_id']].addChild(item)
            items[node['id']] = item
        tree.expandToDepth(1);layout.addWidget(tree)
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.close);layout.addWidget(buttons)
        self.tree=tree
