"""Evidence Graph workspace inside Overview; all native work uses Deep Inspection."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from uuid import uuid4

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPointF, Qt, Signal
from PySide6.QtGui import QColor, QPen, QPolygonF
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QFileDialog, QFormLayout, QGraphicsScene,
    QGraphicsView, QInputDialog, QLabel, QMessageBox,
    QPlainTextEdit, QPushButton, QStackedWidget, QTableView, QVBoxLayout, QWidget,
)

from .action_grid import ActionGrid
from .investigation_graph_bridge import InvestigationGraphBridge


SECTIONS = (
    ("overview", "Problem overview", "Обзор проблемы"),
    ("events", "Related observations", "Связанные события"),
    ("graph", "Evidence graph", "Граф доказательств"),
    ("critical_path", "Critical path", "Критический путь"),
    ("hypotheses", "Hypotheses", "Гипотезы"),
    ("verification", "Verification", "Проверка"),
    ("recurrences", "Recurrences", "Повторения"),
)
RELATION_COLORS = {"EXACT_IDENTITY": "#087b76", "DIRECT_REFERENCE": "#087b76",
    "BOUNDED_TIME_CORRELATION": "#416a9a", "OBSERVED_DEPENDENCY": "#416a9a",
    "TEMPORAL_COINCIDENCE": "#9a6429", "HYPOTHESIS_ONLY": "#9a6429",
    "NOT_ESTABLISHED": "#7b7183", "CONTRADICTED": "#a12a2a"}


def _plain(text=""):
    label = QLabel(text)
    label.setWordWrap(True)
    label.setTextFormat(Qt.TextFormat.PlainText)
    return label


def _value(value, limit=180):
    if value is None:
        return "—"
    if isinstance(value, dict):
        value = {str(k): (v if not isinstance(v, (dict, list)) else "…") for k, v in list(value.items())[:8]}
    elif isinstance(value, list):
        value = value[:8]
    text = json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (dict, list)) else str(value)
    return text[:limit] + ("…" if len(text) > limit else "")


class EvidencePageModel(QAbstractTableModel):
    """Virtualized bounded page over an immutable result, never QTableWidget rows."""
    def __init__(self, columns, parent=None, *, page_size=100):
        super().__init__(parent)
        self.columns, self.rows, self.offset = columns, [], 0
        self.page_size, self.language = page_size, "EN"

    def set_rows(self, rows, *, offset=0):
        self.beginResetModel()
        self.rows = rows if isinstance(rows, list) else []
        self.offset = max(0, min(offset, max(0, len(self.rows) - 1)))
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else min(self.page_size, max(0, len(self.rows) - self.offset))

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.columns)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < self.rowCount():
            return None
        row = self.rows[self.offset + index.row()]
        if role == Qt.ItemDataRole.UserRole:
            return row
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            key = self.columns[index.column()][0]
            if key == "description" and self.language == "RU":
                return _value(row.get("description_ru", row.get(key)))
            return _value(row.get(key))
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.columns[section][2 if self.language == "RU" else 1]
        return super().headerData(section, orientation, role)


class BoundedGraphView(QGraphicsView):
    node_selected = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setScene(QGraphicsScene(self))
        self.setMinimumHeight(230)
        self.setMaximumHeight(380)
        self.setAccessibleName("Evidence graph / Граф доказательств")
        self.rendered_node_ids = []

    def show_graph(self, case, focus=None):
        self.scene().clear()
        nodes, edges = case.get("nodes", []), case.get("edges", [])
        index = {n["node_id"]: n for n in nodes}
        ids = [focus] if focus in index else []
        if ids:
            for edge in edges:
                if focus in (edge.get("from_node"), edge.get("to_node")):
                    ids.extend([edge.get("from_node"), edge.get("to_node")])
        ids.extend(n["node_id"] for n in nodes[:80])
        ids = list(dict.fromkeys(n for n in ids if n in index))[:80]
        self.rendered_node_ids = ids
        positions = {node: QPointF((i % 4) * 230, (i // 4) * 100) for i, node in enumerate(ids)}
        shown_edges = 0
        for edge in edges:
            first, second = edge.get("from_node"), edge.get("to_node")
            if first not in positions or second not in positions or shown_edges >= 160:
                continue
            relation = edge.get("relation_type", "NOT_ESTABLISHED")
            pen = QPen(QColor(RELATION_COLORS.get(relation, "#7b7183")))
            pen.setWidth(2)
            if relation in ("TEMPORAL_COINCIDENCE", "HYPOTHESIS_ONLY", "NOT_ESTABLISHED"):
                pen.setStyle(Qt.PenStyle.DashLine)
            a, b = positions[first] + QPointF(107.5, 35), positions[second] + QPointF(107.5, 35)
            from math import hypot
            length = hypot(b.x() - a.x(), b.y() - a.y())
            if length:
                unit = (b - a) / length
                boundary = min(107.5 / abs(unit.x()) if unit.x() else float("inf"),
                               35 / abs(unit.y()) if unit.y() else float("inf"))
                tip = b - unit * boundary
                side = QPointF(-unit.y(), unit.x()) * 4
                self.scene().addLine(a.x(), a.y(), tip.x(), tip.y(), pen)
                self.scene().addPolygon(QPolygonF([tip, tip - unit * 11 + side, tip - unit * 11 - side]), pen, pen.color())
            label = self.scene().addText(relation)
            label.setDefaultTextColor(pen.color())
            label.setPos((a + b) / 2)
            shown_edges += 1
        for identifier in ids:
            node = index[identifier]
            point = positions[identifier]
            rectangle = self.scene().addRect(point.x(), point.y(), 215, 70,
                QPen(QColor("#554b60")), QColor("#fff7e4"))
            rectangle.setData(0, identifier)
            label = self.scene().addText(_value(node.get("observation_type"), 40) + "\n" +
                _value(node.get("source_record_id"), 27) + "\n" + _value(node.get("completeness_status"), 28))
            label.setPos(point)
            label.setData(0, identifier)
        self.scene().setSceneRect(self.scene().itemsBoundingRect())

    def mousePressEvent(self, event):
        item = self.itemAt(event.pos())
        if item is not None and isinstance(item.data(0), str):
            self.node_selected.emit(item.data(0))
        super().mousePressEvent(event)


class InvestigationGraphPanel(QWidget):
    closed = Signal()
    case_ready = Signal(object)

    def __init__(self, window, deep_panel, *, bridge=None):
        super().__init__(deep_panel)
        self.window, self.deep_panel = window, deep_panel
        self.bridge = bridge or InvestigationGraphBridge(self)
        self.case, self.index_path, self.sources = None, None, []
        self._labels, self._models, self._tables = [], {}, {}
        self._selected_node_id, self._selected_hypothesis = None, None
        self._incident_id, self._selection = None, None
        self._live_identity, self._live_token, self._experiment = None, None, None
        self._pending_native, self._capabilities = None, None
        self._actions, self._group_cases, self._grouping = [], [], None
        self.experiment_case = None
        self._record_queue = []
        self._deferred_action_refresh = False
        self._deferred_checkpoint = False
        self._closing = False
        self._closing_for_window = False
        self._scenario_context, self._app_context = {}, {}
        self._context_scope_sources = None
        self._requires_explicit_sources = False
        self.setObjectName("investigationGraphWorkspace")
        self._build()
        self.bridge.result_ready.connect(self._received)
        self.bridge.busy_changed.connect(self._controls)
        self.bridge.busy_changed.connect(self._read_busy_changed)
        self.bridge.closed.connect(self.closed.emit)
        self.deep_panel.bridge.result_ready.connect(self._diagnostic_result)
        self.deep_panel.bridge.target_changed.connect(self._target_changed)
        self.deep_panel.bridge.busy_changed.connect(self._controls)
        self.retranslate()

    def tr2(self, en, ru):
        return ru if self.window.language == "RU" else en

    def _label(self, widget, en, ru):
        self._labels.append((widget, en, ru))
        widget.setText(self.tr2(en, ru))
        return widget

    def _button(self, layout, name, en, ru, callback):
        button = self._label(QPushButton(), en, ru)
        button.setObjectName(name)
        button.clicked.connect(callback)
        layout.addWidget(button)
        return button

    def _table(self, page, name, columns):
        table = QTableView()
        table.setObjectName(name)
        table.setMinimumHeight(150)
        table.setMaximumHeight(310)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        model = EvidencePageModel(columns, table)
        table.setModel(model)
        table.horizontalHeader().setStretchLastSection(True)
        table.selectionModel().selectionChanged.connect(lambda *_: self._row_selected(table, model))
        page.addWidget(table)
        return table, model

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 10, 0, 0)
        self.heading = self._label(_plain(), "INVESTIGATION ENGINE 3 · Evidence and guided diagnostics",
                                  "ИССЛЕДОВАНИЕ 3 · Доказательства и диагностические проверки")
        layout.addWidget(self.heading)
        self.status = _plain()
        self.status.setObjectName("invStatus")
        layout.addWidget(self.status)
        common = ActionGrid(max_columns=3)
        self.add_source_button = self._button(common, "invAddSource", "Add saved source…", "Добавить источник…", self.choose_source)
        self.build_button = self._button(common, "invBuildGraph", "Build evidence graph", "Построить граф", self.build_case)
        self.open_button = self._button(common, "invOpenCase", "Open investigation…", "Открыть расследование…", self.choose_case)
        self.context_button = self._button(common, "invEditContext", "Declare application / workload context…", "Объявить приложение / контекст нагрузки…", self.edit_context)
        self.cancel_button = self._button(common, "invCancel", "Cancel analysis", "Отменить анализ", self.bridge.cancel)
        self.export_button = self._button(common, "invExport", "Export investigation…", "Сохранить расследование…", self.choose_export)
        self.return_button = self._button(common, "invReturnIncident", "Return to incident", "Вернуться к инциденту", self.return_to_incident)
        layout.addLayout(common)
        self.source_summary = _plain()
        self.source_summary.setObjectName("invSources")
        layout.addWidget(self.source_summary)
        self.section = QComboBox()
        self.section.setObjectName("invSection")
        for key, en, ru in SECTIONS:
            self.section.addItem(self.tr2(en, ru), key)
        layout.addWidget(self.section)
        self.pages = QStackedWidget()
        layout.addWidget(self.pages)
        self.section.currentIndexChanged.connect(self.pages.setCurrentIndex)
        self.overview = _plain()
        overview_page = QVBoxLayout()
        overview_page.addWidget(self.overview)
        sources_table, sources_model = self._table(overview_page, "invSourceTable", [
            ("source_type", "Source", "Источник"), ("source_id", "Identity", "Идентичность"),
            ("source_sha256", "SHA-256", "SHA-256"), ("status", "Coverage", "Полнота")])
        self._tables["sources"], self._models["sources"] = sources_table, sources_model
        self._add_page(overview_page)
        events_page = QVBoxLayout()
        self.node_table, self.nodes_model = self._table(events_page, "invEvidenceTable", [
            ("observation_type", "Observation", "Наблюдение"), ("source_record_id", "Record", "Запись"),
            ("time_domain", "Clock", "Часы"), ("completeness_status", "Coverage", "Полнота")])
        self._models["nodes"], self._tables["nodes"] = self.nodes_model, self.node_table
        paging = ActionGrid(max_columns=3)
        self.previous_button = self._button(paging, "invPrevious", "Previous observations", "Предыдущие наблюдения", lambda: self._page_nodes(-1))
        self.next_button = self._button(paging, "invNext", "Next observations", "Следующие наблюдения", lambda: self._page_nodes(1))
        self.related_button = self._button(paging, "invRelated", "Related evidence", "Связанные доказательства", self.show_related)
        events_page.addLayout(paging)
        self._add_page(events_page)
        graph_page = QVBoxLayout()
        self.graph = BoundedGraphView()
        self.graph.setObjectName("invGraphView")
        self.graph.node_selected.connect(self.select_node)
        graph_page.addWidget(self.graph)
        self.graph_legend = self._label(_plain(),
            "Solid: identity/reference/dependency. Dashed: coincidence, hypothesis or unestablished link. Labels retain the exact relation class. At most 80 nodes and 160 edges are drawn.",
            "Сплошные связи: идентичность, ссылка или зависимость. Пунктир: совпадение, гипотеза или неустановленная связь. Точный класс подписан. Показано не более 80 узлов и 160 связей.")
        graph_page.addWidget(self.graph_legend)
        self.edge_table, edge_model = self._table(graph_page, "invEdgeTable", [
            ("relation_type", "Relation class", "Класс связи"), ("relation", "Relation", "Связь"),
            ("from_node", "From", "От"), ("to_node", "To", "К")])
        self._models["edges"], self._tables["edges"] = edge_model, self.edge_table
        self._add_page(graph_page)
        critical_page = QVBoxLayout()
        self.critical_summary = _plain()
        critical_page.addWidget(self.critical_summary)
        self.critical_view = QGraphicsView(QGraphicsScene(self))
        self.critical_view.setObjectName("invCriticalTimeline")
        self.critical_view.setMinimumHeight(180)
        self.critical_view.setMaximumHeight(320)
        critical_page.addWidget(self.critical_view)
        self.critical_table, critical_model = self._table(critical_page, "invCriticalTable", [
            ("state", "State", "Состояние"), ("thread_identity", "Thread instance", "Экземпляр потока"),
            ("time_domain", "Clock", "Часы"), ("duration_ms", "Duration, ms", "Длительность, мс")])
        self._models["critical"], self._tables["critical"] = critical_model, self.critical_table
        self._add_page(critical_page)
        hypotheses_page = QVBoxLayout()
        self.hypothesis_table, hypothesis_model = self._table(hypotheses_page, "invHypotheses", [
            ("category", "Category", "Категория"), ("description", "Explanation", "Объяснение"),
            ("status", "Status", "Статус")])
        self._models["hypotheses"], self._tables["hypotheses"] = hypothesis_model, self.hypothesis_table
        action = ActionGrid(max_columns=2)
        self._button(action, "invChooseHypothesis", "Review diagnostic actions", "Выбрать диагностическую проверку", self.review_hypothesis)
        self._button(action, "invUserConfirm", "Record my conclusion…", "Записать мой вывод…", self.user_confirm)
        hypotheses_page.addLayout(action)
        self._add_page(hypotheses_page)
        verification_page = QVBoxLayout()
        self.binding_status = _plain()
        self.binding_status.setObjectName("invLiveBinding")
        verification_page.addWidget(self.binding_status)
        actions = ActionGrid(max_columns=3)
        self.bind_button = self._button(actions, "invBindLiveTarget", "Use selected process for NEW measurements", "Выбрать процесс для НОВЫХ измерений", self.bind_live_target)
        self.before_button = self._button(actions, "invCaptureBefore", "1 · Capture BEFORE", "1 · Снять ДО", self.capture_before)
        self.run_button = self._button(actions, "invRunAction", "2 · Confirm chosen action…", "2 · Подтвердить действие…", self.run_action)
        self.after_button = self._button(actions, "invCaptureAfter", "3 · Capture AFTER", "3 · Снять ПОСЛЕ", self.capture_after)
        self.compare_button = self._button(actions, "invCompare", "4 · Compare BEFORE / AFTER", "4 · Сравнить ДО / ПОСЛЕ", self.compare_measurements)
        self.uac_button = self._button(actions, "invRequestPermissions", "Request scoped administrator permission…", "Запросить ограниченные права администратора…", self.deep_panel.request_investigation_elevation)
        self.cancel_native_button = self._button(actions, "invCancelNative", "Cancel chosen diagnostic step", "Отменить диагностический шаг", self.cancel_native_step)
        verification_page.addLayout(actions)
        form = QFormLayout()
        self.action_combo = QComboBox()
        self.action_combo.setObjectName("invActionChoice")
        form.addRow(self._label(_plain(), "Diagnostic action", "Диагностическое действие"), self.action_combo)
        self.parameters = QPlainTextEdit("{}")
        self.parameters.setObjectName("invActionParameters")
        self.parameters.setMaximumHeight(105)
        form.addRow(self._label(_plain(), "Explicit parameters (JSON)", "Явные параметры (JSON)"), self.parameters)
        self.action_note = QPlainTextEdit()
        self.action_note.setObjectName("invActionContract")
        self.action_note.setReadOnly(True)
        self.action_note.setMaximumHeight(180)
        verification_page.addLayout(form)
        verification_page.addWidget(self.action_note)
        self.action_combo.currentIndexChanged.connect(self._action_selected)
        self.verification_status = _plain()
        verification_page.addWidget(self.verification_status)
        self._add_page(verification_page)
        recurrence_page = QVBoxLayout()
        recurrence_actions = ActionGrid(max_columns=2)
        self._button(recurrence_actions, "invGroup", "Find recurrences across saved cases…", "Найти повторения в расследованиях…", self.choose_grouping)
        self._button(recurrence_actions, "invCompareCases", "Compare another version/run…", "Сравнить другую версию/запуск…", self.choose_comparison)
        self._button(recurrence_actions, "invMergeGroups", "Merge groups with reason…", "Объединить группы с причиной…", lambda: self.manual_group("MERGE"))
        self._button(recurrence_actions, "invSplitGroup", "Split group with reason…", "Разделить группу с причиной…", lambda: self.manual_group("SPLIT"))
        recurrence_page.addLayout(recurrence_actions)
        self.recurrence_table, recurrence_model = self._table(recurrence_page, "invRecurrences", [
            ("group_id", "Group", "Группа"), ("status", "Status", "Статус"),
            ("case_ids", "Cases", "Расследования"), ("versions", "Versions", "Версии"),
            ("occurrence_count", "Occurrences", "Повторения"), ("frequency", "Observed frequency", "Наблюдаемая частота")])
        self._models["recurrences"], self._tables["recurrences"] = recurrence_model, self.recurrence_table
        self._add_page(recurrence_page)
        links = ActionGrid(max_columns=3)
        self.thread_button = self._button(links, "invOpenThread", "Show thread evidence", "Показать доказательства потока", self.show_thread)
        self.stack_button = self._button(links, "invOpenStack", "Show stack / module", "Показать стек / модуль", self.show_stack)
        self.module_button = self._button(links, "invOpenModule", "Show module / symbol", "Показать модуль / символ", self.show_module)
        self.decoder_button = self._button(links, "invOpenTraceInterval", "Open recorded interval in Trace Decoder", "Открыть интервал в Trace Decoder", self.open_trace_interval)
        layout.addLayout(links)
        self.details = QPlainTextEdit()
        self.details.setObjectName("invEvidenceDetails")
        self.details.setReadOnly(True)
        self.details.setMaximumHeight(220)
        layout.addWidget(self.details)
        self.footer = self._label(_plain(),
            "Local evidence only. Identity, temporal coincidence and causal hypotheses remain distinct. Missing data is never reconstructed as fact.",
            "Локальные доказательства. Идентичность, временное совпадение и гипотезы причинности различаются. Отсутствующие данные не восстанавливаются как факт.")
        layout.addWidget(self.footer)

    def _add_page(self, contents):
        page = QWidget()
        page.setLayout(contents)
        self.pages.addWidget(page)

    def retranslate(self):
        for widget, en, ru in self._labels:
            widget.setText(self.tr2(en, ru))
        for i, (_, en, ru) in enumerate(SECTIONS):
            self.section.setItemText(i, self.tr2(en, ru))
        for model in self._models.values():
            model.language = self.window.language
            model.headerDataChanged.emit(Qt.Orientation.Horizontal, 0, len(model.columns) - 1)
            if model.rowCount():
                model.dataChanged.emit(model.index(0, 0), model.index(model.rowCount() - 1, model.columnCount() - 1))
        from .deep_inspector_panel import ACTION_LABELS
        for i in range(self.action_combo.count()):
            operation = self.action_combo.itemData(i)
            descriptor = next((a for a in self._actions if a.get("operation") == operation), {})
            en, ru = ACTION_LABELS.get(operation, (operation, operation))
            basis = self.tr2("Manual · ", "Вручную · ") if descriptor.get("selection_basis") == "EXPLICIT_MANUAL_TOOL_NOT_HYPOTHESIS_RECOMMENDATION" else self.tr2("Suggested · ", "Предложено · ")
            self.action_combo.setItemText(i, basis + self.tr2(en, ru) + " · " + str(descriptor.get("availability", "NOT_ESTABLISHED")))
        self._render_summary()
        self._render_binding()
        self._controls()

    def _set_status(self, en, ru):
        self.status.setText(self.tr2(en, ru))

    def open_case_context(self, sources=None, *, incident_id=None, selection=None):
        self.bridge.invalidate()
        self._incident_id, self._selection = incident_id, selection
        if sources is not None:
            self.sources = deepcopy(sources)
            self._context_scope_sources = None
            self._requires_explicit_sources = not bool(self.sources)
        self.show()
        self._render_summary()
        self._controls()

    def choose_source(self):
        choices = [("SESSION", "BLACK.BOX session folder", "Папка сеанса BLACK.BOX"),
            ("TRACE_INDEX", "Trace Decoder index", "Индекс Trace Decoder"),
            ("DEEP_JOURNAL", "Diagnostic action journal", "Журнал диагностических действий"),
            ("INVESTIGATION_V2", "Investigation Engine 2 JSON", "JSON Investigation Engine 2"),
            ("EVENTS_JSONL", "Recorded application events JSONL", "События приложения JSONL"),
            ("DUMP_METADATA", "Saved minidump (metadata only)", "Сохранённый минидамп (только метаданные)")]
        labels = [self.tr2(en, ru) for _, en, ru in choices]
        selected, ok = QInputDialog.getItem(self, "BLACK.BOX", self.tr2("Evidence source", "Источник доказательств"), labels, 0, False)
        if not ok:
            return
        source_type = choices[labels.index(selected)][0]
        if source_type == "SESSION":
            path = QFileDialog.getExistingDirectory(self, selected)
        else:
            filters = "Minidump (*.dmp *.mdmp)" if source_type == "DUMP_METADATA" else "Evidence (*.sqlite3 *.sqlite *.db *.json *.jsonl)"
            path, _ = QFileDialog.getOpenFileName(self, selected, "", filters)
        if path:
            if len(self.sources) >= 16:
                self._set_status("At most 16 source descriptors per case.", "Не более 16 источников в расследовании.")
                return
            self.bridge.invalidate()
            self.sources.append({"source_type": source_type, "path": path})
            self._context_scope_sources = None
            self._render_summary()

    def edit_context(self):
        if self.bridge.busy or self.deep_panel.bridge.busy or self._pending_native or (self.case is None and not self.sources):
            return False
        from .investigation_context_dialog import InvestigationContextDialog
        active = self.experiment_case or self.case or {}
        dialog = InvestigationContextDialog(self, language=self.window.language,
            app_identity=active.get("app_identity") or self._app_context,
            scenario=active.get("scenario") or self._scenario_context)
        generation, selected = self.bridge.generation, self.case
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return False
        if generation != self.bridge.generation or selected is not self.case:
            return False
        path = Path(self.window._investigation_root) / ("context-" + uuid4().hex + ".sqlite3")
        accepted = self.bridge.submit("context", case=self.experiment_case or self.case,
            index_path=str(path), **dialog.arguments())
        if accepted:
            self._set_status("Reading the explicitly selected file and saving user-declared context…",
                             "Чтение явно выбранного файла и сохранение заявленного пользователем контекста…")
        return accepted

    def build_case(self):
        if not self.sources:
            if self._requires_explicit_sources:
                self._set_status("Choose the original saved sources explicitly before rebuilding this investigation.",
                                 "Явно выберите исходные сохранённые источники перед перестроением расследования.")
                return False
            folder = getattr(getattr(self.window, "probe", None), "session_folder", None)
            if folder is not None:
                self.sources = [{"source_type": "SESSION", "path": str(folder)}]
            else:
                self._set_status("Add a saved source or choose a recorded incident.", "Добавьте сохранённый источник или выберите записанный инцидент.")
                return False
        self.bridge.invalidate()
        path = Path(self.window._investigation_root) / ("case-" + uuid4().hex + ".sqlite3")
        declared = self._context_scope_sources == json.dumps(self.sources, sort_keys=True, ensure_ascii=True)
        # A previous consent for NEW measurements cannot establish the target
        # of newly imported historical observations.
        accepted = self.bridge.submit("build", sources=deepcopy(self.sources), target_identity=None,
            selection=self._selection, index_path=str(path),
            scenario=self._scenario_context if declared else None, app_identity=self._app_context if declared else None)
        if accepted:
            self._set_status("Building from saved sources…", "Построение по сохранённым источникам…")
        return accepted

    def choose_case(self):
        path, _ = QFileDialog.getOpenFileName(self, self.tr2("Saved investigation", "Сохранённое расследование"),
                                            str(self.window._investigation_root), "Investigation index (*.sqlite3)")
        if path:
            self.bridge.invalidate()
            self.bridge.submit("open", path=path)

    def load_case(self, case, *, preserve_source_context=False):
        if not preserve_source_context:
            self.sources = []
            self._selection = self._incident_id = None
            self._requires_explicit_sources = True
        self.case = case
        self.experiment_case = None
        self._record_queue.clear()
        self._experiment = None
        self._live_identity = self._live_token = self._pending_native = None
        self._capabilities = None
        self._scenario_context = case.get("scenario") or {}
        self._app_context = case.get("app_identity") or {}
        self._context_scope_sources = None
        self._deferred_action_refresh = self._deferred_checkpoint = False
        self._group_cases = []
        grouping = case.get("issue_grouping")
        self._invalid_saved_grouping = grouping is not None and (
            not isinstance(grouping, dict) or not isinstance(grouping.get("groups"), list) or
            not isinstance(grouping.get("candidates", []), list) or
            any(not isinstance(row, dict) for row in grouping["groups"] + grouping.get("candidates", [])))
        if grouping is None or self._invalid_saved_grouping:
            grouping = None
        self._grouping = grouping
        recurrences = grouping["groups"] + grouping.get("candidates", []) if grouping is not None else case.get("issues", [])
        self._models["recurrences"].set_rows([row for row in recurrences if isinstance(row, dict)] if isinstance(recurrences, list) else [])
        self._selected_node_id = self._selected_hypothesis = None
        self.details.clear()
        self.verification_status.clear()
        self._models["sources"].set_rows(case.get("sources", []))
        self.nodes_model.set_rows(case.get("nodes", []))
        self._models["edges"].set_rows(case.get("edges", []))
        self._models["hypotheses"].set_rows(case.get("hypotheses", []))
        self.graph.show_graph(case)
        self._render_critical(case.get("critical_path", {}))
        self._set_actions(case.get("actions", []))
        self._render_summary()
        self._render_binding()
        self._controls()
        if self._invalid_saved_grouping:
            self._grouping_import_warning()
        self.case_ready.emit(case)

    def _grouping_import_warning(self):
        self._set_status("Malformed imported grouping was ignored. The investigation and its source evidence remain available; rebuild grouping explicitly.",
                         "Некорректные импортированные группы проигнорированы. Расследование и исходные данные доступны; явно постройте группы заново.")

    def _render_summary(self):
        self.source_summary.setText(self.tr2("Saved sources: ", "Сохранённые источники: ") +
            str(len(self.case.get("sources", [])) if self.case else len(self.sources)))
        if not self.case:
            self.overview.setText(self.tr2("Select recorded evidence, then build. No helper or trace starts when this workspace opens.",
                "Выберите записанные данные и постройте граф. Открытие рабочего пространства не запускает helper или трассу."))
            return
        self.overview.setText(self.tr2("Case ", "Расследование ") + str(self.case.get("case_id", "")) +
            self.tr2("\nObservations / links: ", "\nНаблюдения / связи: ") +
            str(len(self.case.get("nodes", []))) + " / " + str(len(self.case.get("edges", []))) +
            "\n" + _value(self.case.get("coverage"), 3000) + "\n" + _value(self.case.get("limitations"), 3000) +
            self.tr2("\nDeclared context: ", "\nЗаявленный контекст: ") +
            _value({"app_identity": self.case.get("app_identity"), "scenario": self.case.get("scenario")}, 1500))

    def _row_selected(self, table, model):
        rows = table.selectionModel().selectedRows()
        if not rows:
            return
        record = model.data(model.index(rows[0].row(), 0), Qt.ItemDataRole.UserRole)
        self._show_details(record)
        if record.get("node_id"):
            self._selected_node_id = record["node_id"]
            self.graph.show_graph(self.case or {}, self._selected_node_id)
        if record.get("hypothesis_id"):
            self._selected_hypothesis = record["hypothesis_id"]
        self._controls()

    def _show_details(self, record):
        text = json.dumps(record, ensure_ascii=False, indent=2, default=str)
        if len(text) > 16000:
            text = text[:16000] + self.tr2(
                "\n[View excerpt truncated. Export the investigation to retain full bounded evidence.]",
                "\n[Показан сокращённый фрагмент. Экспорт расследования сохранит полные данные в установленных пределах.]")
        self.details.setPlainText(text)

    def select_node(self, identifier):
        rows = (self.case or {}).get("nodes", [])
        index = next((i for i, row in enumerate(rows) if row.get("node_id") == identifier), None)
        if index is None:
            return False
        self.nodes_model.set_rows(rows, offset=(index // self.nodes_model.page_size) * self.nodes_model.page_size)
        self.node_table.selectRow(index - self.nodes_model.offset)
        self._selected_node_id = identifier
        self._show_details(rows[index])
        self.graph.show_graph(self.case, identifier)
        self._controls()
        return True

    def _node(self):
        return next((row for row in (self.case or {}).get("nodes", []) if row.get("node_id") == self._selected_node_id), None)

    def _page_nodes(self, direction):
        model = self.nodes_model
        offset = max(0, min(max(0, len(model.rows) - 1), model.offset + direction * model.page_size))
        model.set_rows(model.rows, offset=offset)
        self._controls()

    def show_related(self):
        if self.case and self._selected_node_id:
            return self.bridge.submit("related", case=self.case, node_id=self._selected_node_id, after=0, limit=100)
        return False

    def _linked_node(self, kinds):
        """Follow typed provenance; a shared process never supplies a stack."""
        node = self._node()
        if node is None:
            return None
        if node.get("observation_type") in kinds:
            return node
        reached, frontier = {node["node_id"]}, {node["node_id"]}
        index = {item["node_id"]: item for item in self.case.get("nodes", [])}
        purpose = "thread" if kinds == {"THREAD"} else "stack" if kinds == {"STACK"} else "module"

        def permitted(first, second, edge):
            current, other = index.get(first), index.get(second)
            if current is None or other is None:
                return False
            a, b = current["observation_type"], other["observation_type"]
            relation, relation_type = edge.get("relation"), edge.get("relation_type")
            if purpose == "thread":
                if relation_type == "EXACT_IDENTITY":
                    return relation == "THREAD_EVIDENCE"
                return relation_type == "DIRECT_REFERENCE" and (
                    relation == "THREAD_REFERENCE" and b == "THREAD" or
                    relation in ("THREAD_STACK", "STACK_REFERENCE") and {a, b} == {"STACK", "THREAD"})
            if relation_type != "DIRECT_REFERENCE":
                return False
            if purpose == "stack":
                # Only this observation's stack; never walk another snapshot
                # of the same thread or another thread in the process.
                if first != node["node_id"] or b != "STACK" or a in ("FUNCTION", "MODULE"):
                    return False
                if relation not in ("STACK_REFERENCE", "EVENT_STACK", "THREAD_STACK"):
                    return False
                if a == "THREAD":
                    from blackbox_core.evidence_correlation import thread_identity_key
                    left = thread_identity_key(current.get("thread_identity"), current.get("process_identity"))
                    right = thread_identity_key(other.get("thread_identity"), other.get("process_identity"))
                    if left is not None or right is not None:
                        return left is not None and left == right
                return True
            # Stack frames and their own module are the only symbol route.
            return (
                {a, b} == {"STACK", "FUNCTION"} and relation in ("THREAD_STACK", "EVENT_STACK") or
                {a, b} == {"FUNCTION", "MODULE"} and relation == "FUNCTION_MODULE" or
                {a, b} == {"STACK", "MODULE"} and relation == "MODULE_REFERENCE")

        for _ in range(4):
            following = set()
            for edge in self.case.get("edges", []):
                first, second = edge.get("from_node"), edge.get("to_node")
                if first in frontier and permitted(first, second, edge):
                    following.add(second)
                if second in frontier and permitted(second, first, edge):
                    following.add(first)
            following -= reached
            for identifier in sorted(following)[:200]:
                linked = index.get(identifier)
                if linked and linked.get("observation_type") in kinds:
                    return linked
            reached.update(following)
            frontier = set(sorted(following)[:200])
            if not frontier:
                break
        return None

    def show_thread(self):
        node = self._linked_node({"THREAD"})
        if node:
            self.select_node(node["node_id"])
            self.section.setCurrentIndex(self.section.findData("events"))
        else:
            self._set_status("Thread relation NOT_ESTABLISHED; inspect the source and collect thread identity.",
                             "Связь с потоком NOT_ESTABLISHED; изучите источник и соберите идентичность потока.")

    def show_stack(self):
        node = self._linked_node({"STACK"})
        if node:
            self.select_node(node["node_id"])
            self.section.setCurrentIndex(self.section.findData("graph"))
        else:
            self._set_status("No directly linked saved stack/module. Collect supported stacks or local symbols.",
                             "Нет напрямую связанного сохранённого стека/модуля. Соберите доступные стеки или локальные символы.")

    def show_module(self):
        current = self._node() or {}
        kinds = {"FUNCTION"} if current.get("observation_type") == "MODULE" else {"MODULE"}
        node = self._linked_node(kinds)
        if node:
            self.select_node(node["node_id"])
            self.section.setCurrentIndex(self.section.findData("graph"))
        else:
            self._set_status("Module/symbol relation NOT_ESTABLISHED. Inspect saved frame addresses and verify the matching local PE/PDB.",
                             "Связь с модулем/символом NOT_ESTABLISHED. Изучите сохранённые адреса кадров и проверьте соответствующий локальный PE/PDB.")

    def open_trace_interval(self):
        node = self._node()
        decoder = getattr(self.window, "decoder_panel", None)
        if not node or decoder is None or node.get("source_type") != "TRACE_INDEX":
            self._set_status("Select evidence from a Trace Decoder index.", "Выберите доказательство из индекса Trace Decoder.")
            return False
        path = (self.case or {}).get("_source_paths", {}).get(node["source_identity"])
        if not path:
            self._set_status("Choose and rebuild the original source to verify its identity before navigation.",
                             "Выберите исходный источник и перестройте граф для проверки идентичности перед переходом.")
            return False
        identity, thread = node.get("process_identity") or {}, node.get("thread_identity") or {}
        bounds = node.get("time_bounds") or {}
        metadata = node.get("metadata") or {}
        start = bounds.get("start") if bounds.get("unit") == "ms" else None
        end = bounds.get("end", start) if bounds.get("unit") == "ms" else None
        if start is None:
            start, end = metadata.get("time_ms"), metadata.get("time_ms")
        if start is not None and end is not None and start == end:
            import math
            end = math.nextafter(float(end), math.inf)
        source = next((s for s in self.case.get("sources", []) if s.get("source_id") == node["source_identity"]), {})
        index_hash = source.get("index_sha256")
        if not index_hash and source.get("source_file_count") == 1:
            index_hash = source.get("source_sha256")
        if not index_hash:
            self._set_status("Index file identity is missing. Rebuild from the original Trace Decoder index before navigation.",
                             "Нет идентичности файла индекса. Перестройте граф из исходного индекса Trace Decoder перед переходом.")
            return False
        accepted = decoder.open_index_interval(path, expected_index_sha256=index_hash,
            expected_trace_sha256=source.get("trace_sha256"), process_instance=identity.get("process_instance"),
            pid=identity.get("pid"), tid=thread.get("tid"), start_ms=start, end_ms=end)
        if accepted:
            self.window._navigate("decoder")
        return accepted

    def _render_critical(self, report):
        if not isinstance(report, dict):
            report = {}
        segments = report.get("segments", report.get("intervals", []))
        if not isinstance(segments, list):
            segments = []
        unknowns = report.get("unknowns", [])
        if not isinstance(unknowns, list):
            unknowns = []
        intervals = [item for item in segments if isinstance(item, dict)] + [item for item in unknowns if isinstance(item, dict) and
                                 "start" in item and "end" in item]
        self._models["critical"].set_rows(intervals)
        totals = report.get("totals") or {}
        self.critical_summary.setText(_value(report.get("status", "NOT_ESTABLISHED"), 100) + "\n" +
            self.tr2("Observed states, ms — running: ", "Наблюдаемые состояния, мс — выполнение: ") +
            _value(totals.get("running_ms")) + self.tr2("; blocked: ", "; ожидание: ") +
            _value(totals.get("blocked_ms")) + self.tr2("; ready: ", "; готовность: ") + _value(totals.get("ready_ms")) +
            "\n" + self.tr2("End-to-end completion path is not established. Each clock domain has an independent axis.",
                              "Сквозной путь завершения не установлен. Каждая шкала времени имеет отдельную ось.") +
            "\n" + _value(report.get("limitations", []), 1500))
        scene = self.critical_view.scene()
        scene.clear()
        colors = {"RUNNING": "#10867b", "BLOCKED": "#b46e32", "READY": "#4e79a7", "UNKNOWN": "#8d8491", "INCOMPLETE": "#b34f59"}
        lanes, domains = {}, {}
        shown = []
        from math import isfinite
        for item in intervals[:128]:
            start, end = item.get("start"), item.get("end")
            domain = item.get("time_domain")
            if (type(start) not in (int, float) or type(end) not in (int, float) or
                    not isfinite(start) or not isfinite(end) or end < start or item.get("unit") != "ms" or
                    not isinstance(domain, str)):
                continue
            old = domains.get(domain, (start, end))
            domains[domain] = min(old[0], start), max(old[1], end)
            shown.append(item)
        # Independent labelled domain axes: no cross-clock concatenation,
        # interpolated state or sample-count-to-running-time conversion.
        for item in shown:
            key = (item.get("time_domain"), json.dumps(item.get("thread_identity"),
                   sort_keys=True, ensure_ascii=True, default=str))
            if key not in lanes:
                if len(lanes) >= 32:
                    continue
                lanes[key] = len(lanes)
                thread = item.get("thread_identity") or {}
                if not isinstance(thread, dict):
                    thread = {}
                lo, hi = domains[item.get("time_domain")]
                label = str(item.get("time_domain", ""))[:28] + " · TID " + str(thread.get("tid", thread.get("thread_instance", "?"))) + f" · {lo:g}–{hi:g} ms"
                text = scene.addText(label)
                text.setTextWidth(340)
                text.setPos(0, lanes[key] * 45)
            lane = lanes[key]
            state = item.get("state", "UNKNOWN")
            if not isinstance(state, str) or state not in colors:
                state = "UNKNOWN"
            lo, hi = domains[item.get("time_domain")]
            scale = 800 / max(hi - lo, 0.000001)
            x, width = 360 + (item["start"] - lo) * scale, max(2, (item["end"] - item["start"]) * scale)
            rectangle = scene.addRect(x, lane * 45, width, 28,
                QPen(QColor(colors.get(state, colors["UNKNOWN"]))), QColor(colors.get(state, colors["UNKNOWN"])))
            rectangle.setToolTip(_value(item, 2000))
            label = scene.addText(state)
            label.setDefaultTextColor(QColor("#ffffff"))
            label.setPos(rectangle.rect().x(), lane * 45)
        scene.setSceneRect(scene.itemsBoundingRect())

    def review_hypothesis(self):
        self.section.setCurrentIndex(self.section.findData("verification"))
        if self.case:
            self.bridge.submit("actions", case=self.experiment_case or self.case, hypothesis_id=self._selected_hypothesis,
                               capabilities=self._capabilities, target_identity=self._live_identity)

    def _set_actions(self, actions):
        if isinstance(actions, dict):
            actions = actions.get("actions", [])
        self._actions = actions if isinstance(actions, list) else []
        self.action_combo.blockSignals(True)
        self.action_combo.clear()
        from .deep_inspector_panel import ACTION_LABELS
        for descriptor in self._actions:
            operation = descriptor.get("operation")
            if operation:
                en, ru = ACTION_LABELS.get(operation, (operation, operation))
                basis = self.tr2("Manual · ", "Вручную · ") if descriptor.get("selection_basis") == "EXPLICIT_MANUAL_TOOL_NOT_HYPOTHESIS_RECOMMENDATION" else self.tr2("Suggested · ", "Предложено · ")
                self.action_combo.addItem(basis + self.tr2(en, ru) + " · " + str(descriptor.get("availability", "NOT_ESTABLISHED")), operation)
        self.action_combo.blockSignals(False)
        self._action_selected()

    def _action_selected(self, *_):
        operation = self.action_combo.currentData()
        descriptor = next((a for a in self._actions if a.get("operation") == operation), {})
        self.parameters.setPlainText(json.dumps(descriptor.get("parameters", {}), ensure_ascii=False, indent=2))
        self.action_note.setPlainText(json.dumps({k: descriptor.get(k) for k in
            ("availability", "selection_basis", "reason", "required_parameters", "impact", "required_permissions",
             "timeout_seconds", "confirmation_required", "contract", "limitations")},
            ensure_ascii=False, indent=2, default=str)[:12000])
        self._controls()

    def _live_current(self):
        bridge = self.deep_panel.bridge
        return self._live_identity is not None and self._live_token == (bridge.generation, bridge.target)

    def bind_live_target(self):
        bridge = self.deep_panel.bridge
        if bridge.target is None or bridge.busy or self.bridge.busy or self._pending_native is not None:
            self._set_status("Choose a current process in Overview first.", "Сначала выберите текущий процесс в Overview.")
            return False
        token = (bridge.generation, bridge.target)
        text = self.tr2("Collect NEW measurements from the currently selected process? This does not establish its identity as the process in historical sources.",
                        "Собирать НОВЫЕ измерения выбранного процесса? Это не доказывает, что он совпадает с процессом в исторических источниках.")
        dialog = QMessageBox(QMessageBox.Icon.Question, "BLACK.BOX", text + f"\nPID {bridge.target[0]}",
                             QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, self)
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        dialog.button(QMessageBox.StandardButton.Yes).setText(self.tr2("USE FOR NEW MEASUREMENTS", "ВЫБРАТЬ ДЛЯ НОВЫХ ИЗМЕРЕНИЙ"))
        dialog.button(QMessageBox.StandardButton.Cancel).setText(self.tr2("CANCEL", "ОТМЕНА"))
        if dialog.exec() != QMessageBox.StandardButton.Yes:
            return False
        if token != (bridge.generation, bridge.target):
            return False
        self._live_token = token
        self._pending_native = {"tag": "inv:bind:" + uuid4().hex, "phase": "bind", "token": token}
        return self._dispatch("capabilities", {}, self._pending_native["tag"])

    def _dispatch(self, operation, parameters, tag):
        accepted = self.deep_panel.request_investigation_action(operation, parameters, tag=tag)
        if not accepted:
            self._pending_native = None
        self._controls()
        return accepted

    def _new_experiment(self):
        if self.case is None or self.experiment_case is None or not self._live_current():
            return False
        self._experiment = {"experiment_id": uuid4().hex, "case_id": self.experiment_case["case_id"],
            "hypothesis_id": self._selected_hypothesis, "target_identity": deepcopy(self._live_identity),
            "historical_target_relation": "NOT_ESTABLISHED", "status": "PREPARED_MANUAL",
            "root_cause_proven": False, "records": []}
        return True

    def _run_step(self, phase, operation, parameters):
        if not self._live_current() or self._pending_native or self.deep_panel.bridge.busy or self.bridge.busy:
            return False
        if self._experiment is None:
            return False
        if self._experiment.get("status") in ("RECOVERY_UNCONFIRMED", "EVIDENCE_COMMIT_FAILED", "STOPPED_AT_FAILED_STEP"):
            return False
        tag = "inv:" + self._experiment["experiment_id"] + ":" + phase
        self._pending_native = {"tag": tag, "phase": phase, "token": self._live_token}
        return self._dispatch(operation, parameters, tag)

    def capture_before(self):
        if self.bridge.busy or self.deep_panel.bridge.busy or self._pending_native or \
                (self._experiment or {}).get("status") in ("RECOVERY_UNCONFIRMED", "EVIDENCE_COMMIT_FAILED"):
            return False
        if not self._new_experiment():
            self._set_status("Bind the selected live process for new measurements first.",
                             "Сначала привяжите выбранный живой процесс для новых измерений.")
            return False
        return self._run_step("before", "snapshot", {})

    def _parameters(self):
        text = self.parameters.toPlainText()
        if len(text.encode("utf-8")) > 16384:
            raise ValueError("DIAGNOSTIC_PARAMETERS_BYTE_BUDGET")
        value = json.loads(text)
        if not isinstance(value, dict):
            raise ValueError("DIAGNOSTIC_PARAMETERS_OBJECT_REQUIRED")
        return value

    def run_action(self):
        if not self._experiment or not self._experiment.get("before_id") or self._experiment.get("action_result"):
            return False
        try:
            operation = self.action_combo.currentData()
            if not operation:
                raise ValueError("SELECT_DIAGNOSTIC_ACTION")
            parameters = self._parameters()
            return self._run_step("action", operation, parameters)
        except (ValueError, TypeError) as error:
            self.status.setText(str(error))
            return False

    def capture_after(self):
        if not self._experiment or not self._experiment.get("action_result") or self._experiment.get("after_id"):
            return False
        return self._run_step("after", "snapshot", {})

    def compare_measurements(self):
        experiment = self._experiment or {}
        if not experiment.get("before_id") or not experiment.get("after_id") or experiment.get("comparison"):
            return False
        return self._run_step("compare", "compare", {"before_id": experiment["before_id"], "after_id": experiment["after_id"]})

    def _diagnostic_result(self, result):
        pending = self._pending_native
        if not pending or self._closing:
            return
        if pending["token"] != (self.deep_panel.bridge.generation, self.deep_panel.bridge.target):
            return
        if result.get("request_kind") == "elevate" and pending.get("awaiting_uac"):
            if result.get("status") != "COMPLETED":
                self._pending_native = None
                self._set_status("Permission was not granted; no automatic experiment retry. The recorded case remains available.",
                                 "Права не предоставлены; автоматического повтора эксперимента нет. Записанное расследование доступно.")
                self._controls()
            return
        if result.get("request_tag") != pending["tag"]:
            return
        phase = pending["phase"]
        if result.get("request_kind") == "elevate":
            return
        if result.get("status") == "ADMIN_REQUIRED":
            pending["awaiting_uac"] = True
            self._set_status("Administrator permission is required. Use the existing GRANT ADMINISTRATOR PERMISSION control; cancellation keeps this investigation.",
                             "Требуются права администратора. Используйте штатную кнопку ПРЕДОСТАВИТЬ ПРАВА; отмена сохраняет расследование.")
            self._controls()
            return  # Existing Deep UI owns UAC consent and its exact-target retry.
        self._pending_native = None
        if phase == "bind":
            if result.get("status") == "COMPLETED" and result.get("target", {}).get("created_100ns"):
                self._live_identity = deepcopy(result["target"])
                self._capabilities = result.get("data")
                self._experiment = None
                self._render_binding()
                if self.case:
                    self.bridge.submit("fork", case=self.case, target_identity=self._live_identity)
        elif self._experiment:
            from blackbox_core.deep_journal import journal_metadata
            record = journal_metadata(result)
            self._experiment["records"].append({"phase": phase, "result": record})
            success = result.get("status") in ("COMPLETED", "INCOMPLETE_EVIDENCE")
            data = result.get("data") or {}
            if phase in ("before", "after") and success and data.get("snapshot_id"):
                self._experiment[phase + "_id"] = data["snapshot_id"]
            elif phase == "action":
                self._experiment["action_result"] = record
            elif phase == "compare" and success:
                self._experiment["comparison"] = record
                self._experiment["status"] = "INCONCLUSIVE"
                self._set_status("Comparison recorded. A change after intervention alone does not establish causation.",
                                 "Сравнение сохранено. Одно изменение после воздействия не доказывает причинность.")
            if result.get("status") == "RECOVERY_UNCONFIRMED":
                self._experiment["status"] = "RECOVERY_UNCONFIRMED"
            elif not success:
                self._experiment["status"] = "STOPPED_AT_FAILED_STEP"
                self._set_status("Step did not complete. Review its result; capture a NEW BEFORE to start another explicit experiment.",
                                 "Шаг не завершён. Проверьте результат; для нового явного эксперимента снимите НОВОЕ ДО.")
            self.verification_status.setText(_value(self._experiment, 5000))
            self._record_queue.append({**record, "experiment_id": self._experiment["experiment_id"],
                "hypothesis_id": self._experiment.get("hypothesis_id"), "phase": phase.upper()})
            self._flush_records()
        self._controls()

    def _flush_records(self):
        if self.bridge.busy or self._closing or not self._record_queue or self.experiment_case is None:
            return
        record = self._record_queue.pop(0)
        path = Path(self.window._investigation_root) / ("checkpoint-" + uuid4().hex + ".sqlite3")
        self.bridge.submit("record_experiment", case=self.experiment_case, record=record, index_path=str(path))

    def _read_busy_changed(self, busy):
        if not busy and self._closing_for_window:
            self._closing_for_window = self._closing = False
            self._controls()
            self.closed.emit()
            return
        if busy or self._closing:
            return
        if self._record_queue:
            self._flush_records()
        elif self._deferred_checkpoint:
            self._deferred_checkpoint = False
            self._checkpoint_metadata()
        elif self._deferred_action_refresh and self.case is not None:
            self._deferred_action_refresh = False
            self.bridge.submit("actions", case=self.experiment_case or self.case,
                hypothesis_id=self._selected_hypothesis, capabilities=self._capabilities,
                target_identity=self._live_identity)

    def _checkpoint_metadata(self):
        if self.bridge.busy or self.case is None:
            return False
        path = Path(self.window._investigation_root) / ("metadata-" + uuid4().hex + ".sqlite3")
        return self.bridge.submit("save_case", case=self.experiment_case or self.case,
            index_path=str(path), experiment=self.experiment_case is not None)

    def cancel_native_step(self):
        if self.deep_panel.bridge.busy:
            self.deep_panel.bridge.cancel()
        elif self._pending_native and self._pending_native.get("awaiting_uac"):
            self._pending_native = None
            self._set_status("Pending permission request cancelled. No diagnostic action was retried.",
                             "Ожидание прав отменено. Диагностическое действие не повторялось.")
        self._controls()

    def _render_binding(self):
        self.binding_status.setText(self.tr2("New measurements target: ", "Цель новых измерений: ") +
            (_value(self._live_identity, 600) if self._live_current() else self.tr2("not bound", "не привязана")) +
            "\n" + self.tr2("Historical association: NOT_ESTABLISHED unless separately supported by sources.",
                              "Связь с исторической целью: NOT_ESTABLISHED без отдельного подтверждения источниками."))

    def _target_changed(self):
        self.bridge.invalidate()
        self._live_identity = self._live_token = self._pending_native = self._experiment = None
        self._capabilities = None
        self._record_queue.clear()
        self._deferred_action_refresh = False
        self._deferred_checkpoint = False
        self._set_actions((self.case or {}).get("actions", []))
        self._render_binding()
        self._set_status("Live target changed; previous consent/results cannot apply. Saved case remains read-only.",
                         "Живая цель изменена; прежнее согласие и результаты неприменимы. Сохранённое расследование доступно для чтения.")
        self._controls()

    def user_confirm(self):
        if self.case is None or self._selected_hypothesis is None or self.bridge.busy:
            return
        reason, ok = QInputDialog.getText(self, "BLACK.BOX", self.tr2(
            "Your conclusion and basis (user assertion, not engine proof)", "Ваш вывод и основание (мнение пользователя, не доказательство движка)"))
        if ok and reason.strip():
            active = self.experiment_case or self.case
            active.setdefault("user_annotations", []).append({"hypothesis_id": self._selected_hypothesis,
                "status": "USER_CONFIRMED", "reason": reason[:2000], "verification_class": "USER_REPORTED"})
            self._checkpoint_metadata()
            self._set_status("User conclusion recorded separately from observed facts.", "Вывод пользователя записан отдельно от наблюдаемых фактов.")

    def choose_export(self):
        if self.case is None:
            return
        path, selected = QFileDialog.getSaveFileName(self, self.tr2("Export investigation", "Экспорт расследования"),
            "BLACKBOX-Investigation.json", "JSON (*.json);;HTML (*.html)")
        if path:
            self.export_to(path, format="html" if "HTML" in selected or path.lower().endswith(".html") else "json")

    def export_to(self, path, *, format="json"):
        if self.case is None:
            return False
        return self.bridge.submit("export", case=self.experiment_case or self.case, destination=str(path), format=format)

    def choose_comparison(self):
        if self.case is None:
            return
        path, _ = QFileDialog.getOpenFileName(self, self.tr2("Comparable saved investigation", "Сопоставимое расследование"),
            str(self.window._investigation_root), "Investigation index (*.sqlite3)")
        if path:
            self.bridge.submit("compare_cases", case=self.case, other_path=path)

    def choose_grouping(self):
        if self.case is None:
            return
        paths, _ = QFileDialog.getOpenFileNames(self, self.tr2("Saved investigations", "Сохранённые расследования"),
            str(self.window._investigation_root), "Investigation index (*.sqlite3)")
        if paths:
            self.bridge.submit("group", case=self.case, other_paths=paths[:32])

    def manual_group(self, action):
        if not self._grouping:
            return
        selected_case, selected_grouping = self.case, self._grouping
        group_text, ok = QInputDialog.getText(self, "BLACK.BOX", self.tr2("Group IDs, comma separated", "Идентификаторы групп через запятую"))
        if not ok:
            return
        cases_text = ""
        if action == "SPLIT":
            cases_text, ok = QInputDialog.getText(self, "BLACK.BOX", self.tr2("Case IDs for split, comma separated", "Идентификаторы расследований для разделения через запятую"))
            if not ok:
                return
        reason, ok = QInputDialog.getText(self, "BLACK.BOX", self.tr2("Reason (required)", "Причина (обязательна)"))
        if not ok or not reason.strip():
            return
        if self.case is not selected_case or self._grouping is not selected_grouping:
            self._set_status("Investigation changed while choosing groups. Review this case and start the edit again.",
                             "Расследование изменилось во время выбора групп. Проверьте это дело и начните изменение заново.")
            return
        self.bridge.submit("group_change", groups=selected_grouping, action=action,
            group_ids=[x.strip() for x in group_text.split(",") if x.strip()][:32],
            case_ids=[x.strip() for x in cases_text.split(",") if x.strip()][:64] if action == "SPLIT" else None,
            reason=reason[:2000])

    def return_to_incident(self):
        if self._incident_id is None:
            self._set_status("Original incident context is unavailable. Choose its original saved source to locate it.",
                             "Контекст исходного инцидента отсутствует. Выберите его исходный сохранённый источник.")
            return False
        self.window._navigate("reports")
        panel = getattr(self.window, "analysis_panel", None)
        if panel is not None:
            rows = (getattr(panel, "packet", None) or {}).get("findings", [])
            for index, row in enumerate(rows):
                if self._incident_id is not None and row.get("detail", {}).get("incident_id") == self._incident_id:
                    panel.table.selectRow(index)
                    break
            scroll = self.window.stack.currentWidget()
            if hasattr(scroll, "ensureWidgetVisible"):
                scroll.ensureWidgetVisible(panel)

    def _received(self, operation, packet, error, generation):
        if generation != self.bridge.generation or self._closing:
            return
        if error:
            self.status.setText(self.tr2("Investigation could not complete: ", "Расследование не завершено: ") + error)
            if operation == "record_experiment" and self._experiment is not None:
                self._experiment["status"] = "EVIDENCE_COMMIT_FAILED"
                self._record_queue.clear()
            return
        if not isinstance(packet, dict):
            return
        if operation in ("build", "open"):
            self.index_path = packet.get("index_path")
            self.load_case(packet["case"], preserve_source_context=operation == "build")
            if self._invalid_saved_grouping:
                self._grouping_import_warning()
            else:
                self._set_status("Evidence graph ready; inspect source identities and gaps.", "Граф готов; проверяйте идентичности источников и разрывы.")
        elif operation == "context":
            context = packet["context"]
            if "case" in packet:
                self.index_path = packet["index_path"]
                self.load_case(packet["case"], preserve_source_context=True)
            else:
                self._app_context, self._scenario_context = context["app_identity"], context["scenario"]
                self._context_scope_sources = json.dumps(self.sources, sort_keys=True, ensure_ascii=True)
            self._set_status("Context saved as USER_REPORTED. File SHA-256 does not establish historical process binding; comparisons remain conditional.",
                             "Контекст сохранён как USER_REPORTED. SHA-256 файла не устанавливает связь с историческим процессом; сравнения остаются условными.")
        elif operation == "actions":
            self._set_actions(packet.get("actions", []))
        elif operation == "fork":
            self.experiment_case = packet["experiment_case"]
            self._deferred_action_refresh = True
        elif operation == "record_experiment":
            self.experiment_case = packet["experiment_case"]
            self.index_path = packet.get("index_path", self.index_path)
        elif operation == "save_case":
            if "experiment_case" in packet:
                self.experiment_case = packet["experiment_case"]
            else:
                self.case = packet["case"]
            self.index_path = packet.get("index_path", self.index_path)
        elif operation == "related":
            self._show_details(packet["related"])
        elif operation in ("group", "group_change"):
            self._grouping = packet.get("grouping")
            self._group_cases = packet.get("cases", self._group_cases)
            value = self._grouping if isinstance(self._grouping, list) else (self._grouping or {}).get("groups", [])
            if isinstance(self._grouping, dict):
                value = value + self._grouping.get("candidates", [])
            self._models["recurrences"].set_rows(value)
            if self.case:
                (self.experiment_case or self.case)["issue_grouping"] = self._grouping
                self._deferred_checkpoint = True
        elif operation == "compare_cases":
            self._show_details(packet["comparison"])
            (self.experiment_case or self.case)["version_comparison"] = packet["comparison"]
            self._deferred_checkpoint = True
        elif operation == "export":
            self._set_status("Investigation export saved with provenance and limitations.", "Экспорт расследования сохранён с происхождением и ограничениями.")
        self._controls()

    def _controls(self, *_):
        if not hasattr(self, "run_button"):
            return
        busy = self.bridge.busy
        native_busy = self.deep_panel.bridge.busy
        active = self.case is not None and not busy and not self._record_queue and not self._closing
        can_change_case = not busy and not native_busy and self._pending_native is None and not self._closing
        self.build_button.setEnabled(can_change_case)
        self.add_source_button.setEnabled(can_change_case)
        self.open_button.setEnabled(can_change_case)
        self.context_button.setEnabled(can_change_case and bool(self.case is not None or self.sources))
        self.cancel_button.setEnabled(busy)
        self.export_button.setEnabled(active)
        self.return_button.setEnabled(active and self._incident_id is not None)
        self.bind_button.setEnabled(active and not native_busy and self._pending_native is None and self.deep_panel.bridge.target is not None)
        ready = active and self._live_current() and not native_busy and self._pending_native is None
        experiment = self._experiment or {}
        if experiment.get("status") in ("RECOVERY_UNCONFIRMED", "EVIDENCE_COMMIT_FAILED"):
            ready = False
        self.before_button.setEnabled(ready)
        phase_ready = ready and experiment.get("status") != "STOPPED_AT_FAILED_STEP"
        from blackbox_core.deep_contracts import DEEP_ACTIONS
        descriptor = next((a for a in self._actions if a.get("operation") == self.action_combo.currentData()), {})
        action_implemented = self.action_combo.currentData() in DEEP_ACTIONS and descriptor.get("availability") != "UNAVAILABLE"
        self.run_button.setEnabled(phase_ready and action_implemented and bool(experiment.get("before_id")) and not experiment.get("action_result"))
        self.after_button.setEnabled(phase_ready and bool(experiment.get("action_result")) and not experiment.get("after_id") and experiment.get("status") != "RECOVERY_UNCONFIRMED")
        self.compare_button.setEnabled(phase_ready and bool(experiment.get("before_id")) and bool(experiment.get("after_id")) and not experiment.get("comparison"))
        self.uac_button.setEnabled(not native_busy and bool((self._pending_native or {}).get("awaiting_uac")))
        self.cancel_native_button.setEnabled(native_busy or self._pending_native is not None)
        self.previous_button.setEnabled(active and self.nodes_model.offset > 0)
        self.next_button.setEnabled(active and self.nodes_model.offset + self.nodes_model.page_size < len(self.nodes_model.rows))
        for button in (self.related_button, self.thread_button, self.stack_button, self.module_button, self.decoder_button):
            button.setEnabled(active and self._selected_node_id is not None)

    def shutdown(self):
        self._closing = True
        self.bridge.shutdown()

    def cancel_for_window_close(self):
        """Wait for this reader, while permitting recovery to keep the UI open.

        Native cleanup can refuse to close the owner. It must remain possible
        to inspect/export the historical case after that result.
        """
        self._closing_for_window = self._closing = True
        self._pending_native = self._live_identity = self._live_token = None
        self._experiment = None
        self._record_queue.clear()
        self._deferred_action_refresh = self._deferred_checkpoint = False
        self.bridge.invalidate()
        if not self.bridge.busy:
            self._read_busy_changed(False)
        self._controls()
