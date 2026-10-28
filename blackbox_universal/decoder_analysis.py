"""Explicit, cancellable offline decoder analysis. No recording or network."""
import json
from html import escape
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QLabel, QTreeWidget,
                              QTreeWidgetItem, QDialogButtonBox)
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
            else:
                raise ValueError('UNKNOWN_DECODER_ANALYSIS')
            self.result_ready.emit(result, '')
        except Exception as exc:
            # Reason codes only; no private local paths leaked to GUI status.
            reason = str(exc) if isinstance(exc, (ValueError, InterruptedError, TimeoutError)) else type(exc).__name__
            self.result_ready.emit(None, reason[:200])


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
