"""User controlled diagnostic graph editor inside the existing Overview page."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from uuid import uuid4

from PySide6.QtCore import Qt, QPointF, QRectF, QMimeData, Signal, QTimer
from PySide6.QtGui import (QBrush, QColor, QDrag, QKeySequence, QPainter,
                          QPainterPath, QPen, QShortcut)
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog,
    QFormLayout, QGraphicsEllipseItem, QGraphicsItem, QGraphicsObject,
    QGraphicsPathItem, QGraphicsScene, QGraphicsView, QGridLayout, QHBoxLayout,
    QLabel, QLineEdit, QListWidget, QListWidgetItem, QPlainTextEdit, QPushButton,
    QScrollArea, QSpinBox, QSplitter, QTabWidget, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget, QStackedWidget,
)

from .action_grid import ActionGrid
from .chain_bridge import ChainBuilderBridge


TOOL_NAMES = {
    "process_select": ("Confirm process", "Подтвердить процесс"),
    "load_source": ("Open saved source", "Открыть сохранённый источник"),
    "observe": ("Record observation", "Записать наблюдение"),
    "decode_trace": ("Decode saved trace", "Декодировать сохранённую трассу"),
    "load_graph": ("Open Evidence Graph", "Открыть граф доказательств"),
    "investigate": ("Investigation 3", "Расследование 3"),
    "critical_path": ("Critical path", "Критический путь"),
    "waits": ("Wait analysis", "Анализ ожиданий"),
    "file_io": ("File I/O analysis", "Анализ файлового I/O"),
    "disk_io": ("Disk I/O analysis", "Анализ дискового I/O"),
    "crash": ("Saved crash/dump", "Сохранённый сбой/дамп"),
    "incident": ("Saved incident", "Сохранённый инцидент"),
    "compare": ("Compare investigations", "Сравнить исследования"),
    "export_report": ("Export report", "Экспорт отчёта"),
    "session_finalize": ("Finalize owned diagnostic session", "Завершить свою диагностическую сессию"),
    "CONDITION": ("Receipt condition", "Условие по результату"),
    "JOIN": ("Join evidence", "Объединить доказательства"),
    "CHECKPOINT": ("Manual checkpoint", "Ручная контрольная точка"),
}
STATE_NAMES = {
    "QUEUED": ("Queued", "В очереди"), "RUNNING": ("Running", "Выполняется"),
    "COMPLETED": ("Completed", "Завершено"), "PARTIAL": ("Partial", "Частично"),
    "FAILED": ("Failed", "Ошибка"), "CANCELLED": ("Cancelled", "Отменено"),
    "WAITING_FOR_HUMAN": ("Waiting for you", "Ожидает решения"),
    "RECOVERY_UNCONFIRMED": ("Cleanup unconfirmed", "Очистка не подтверждена"),
    "SKIPPED": ("Inactive branch", "Неактивная ветвь"),
}
COLORS = {"COMPLETED": "#087b76", "RUNNING": "#416a9a", "WAITING_FOR_HUMAN": "#9a6429",
          "PARTIAL": "#9a6429", "FAILED": "#a12a2a", "RECOVERY_UNCONFIRMED": "#a12a2a"}
MIME = "application/x-blackbox-workflow-tool"
PARAMETER_LABELS = {
    "pid": ("Process ID (blank: current selection)", "PID процесса (пусто: текущий выбор)"),
    "kind": ("Saved source type", "Тип сохранённого источника"), "path": ("Source path", "Путь к источнику"),
    "selection": ("Selected evidence interval", "Выбранный интервал доказательств"),
    "scenario": ("Declared scenario context", "Заявленный контекст сценария"),
    "parameters": ("Action parameters", "Параметры действия"),
    "duration_seconds": ("Duration, seconds", "Длительность, секунды"),
    "policy": ("Capture policy overrides", "Переопределения политики записи"),
    "incident_id": ("Saved incident ID", "ID сохранённого инцидента"),
    "pre_seconds": ("Prehistory, seconds", "Предыстория, секунды"),
    "post_seconds": ("After event, seconds", "После события, секунды"),
    "image_path": ("Local image file", "Локальный файл образа"), "pdb_path": ("Local PDB", "Локальный PDB"),
    "pe_path": ("Local PE image", "Локальный PE-образ"), "format": ("Report format", "Формат отчёта"),
    "status": ("Required receipt status", "Проверяемый статус RunReceipt"),
    "profile": ("Recording profile", "Профиль записи"),
    "address": ("Address (decimal or 0x…)", "Адрес (десятичный или 0x…)"),
    "size": ("Read size, bytes", "Размер чтения, байт"),
    "thread_created_100ns": ("Thread creation FILETIME", "Время создания потока FILETIME"),
    "tid": ("Thread ID", "ID потока"), "process_instance": ("Recorded instance", "Записанный экземпляр"),
    "start_ms": ("Start, ms", "Начало, мс"), "end_ms": ("End, ms", "Конец, мс"),
    "start_ns": ("Start, ns", "Начало, нс"), "end_ns": ("End, ns", "Конец, нс"),
    "max_session_mb": ("Session soft limit, MiB", "Мягкий лимит сеанса, MiB"),
    "max_trace_mb": ("Trace budget, MiB", "Бюджет трассы, MiB"),
    "windows_enabled": ("Observe windows", "Наблюдать окна"),
    "incident_enabled": ("Capture incidents", "Собирать инциденты"),
    "adaptive_throttle": ("Adaptive sampling", "Адаптация частоты измерений"),
    "incident": ("Incident limits", "Лимиты инцидентов"),
    "full": ("Extended dump", "Расширенный дамп"), "hash_files": ("Hash module files", "Хешировать файлы модулей"),
    "change_id": ("Recorded change ID", "ID выполненного изменения"),
    "breakpoint_id": ("Breakpoint ID", "ID точки останова"), "module_base": ("Module base", "База модуля"),
    "scenario_id": ("Scenario ID", "ID сценария"), "scenario_version": ("Scenario version", "Версия сценария"),
    "workload_id": ("Workload ID", "ID нагрузки"), "input_id": ("Input ID", "ID входных данных"),
    "app_version": ("Application version", "Версия приложения"), "description": ("Description", "Описание"),
    "detail_interval_ms": ("Detail interval, ms", "Интервал подробных измерений, мс"),
    "thread_limit": ("Thread limit", "Предел потоков"), "child_limit": ("Child process limit", "Предел дочерних процессов"),
    "top_threads": ("Top thread count", "Число наиболее активных потоков"),
    "burst_seconds": ("Burst duration, s", "Длительность усиленного сбора, с"),
    "burst_interval_ms": ("Burst interval, ms", "Интервал усиленного сбора, мс"),
    "session_seconds": ("Session duration, s", "Длительность сеанса, с"),
    "pre_ms": ("Prehistory, ms", "Предыстория, мс"), "post_ms": ("After event, ms", "После события, мс"),
    "max_incidents": ("Incident limit", "Предел инцидентов"),
    "max_buffer_samples": ("Buffered sample limit", "Предел измерений в буфере"),
    "max_buffer_bytes": ("Buffer budget, bytes", "Бюджет буфера, байт"),
    "threshold": ("Trigger threshold", "Порог срабатывания"),
    "min_duration_ms": ("Minimum trigger duration, ms", "Минимальная длительность срабатывания, мс"),
    "before_id": ("Before snapshot ID", "ID снимка до"), "after_id": ("After snapshot ID", "ID снимка после"),
    "condition": ("Predicate", "Условие"), "mode": ("Join policy", "Политика объединения"),
    "allow_partial": ("Allow incomplete branches", "Допускать неполные ветви"),
    "message": ("Checkpoint message", "Сообщение контрольной точки"),
}


def _object_schema(tool, key):
    """Typed presentation for existing bounded service parameter objects."""
    integer = lambda **values: {"type": "integer", **values}
    text = lambda **values: {"type": "string", **values}
    if key == "selection":
        return {name: integer(min=0, max=2**63 - 1) for name in
                ("start_ns", "end_ns", "start_ms", "end_ms", "process_instance", "pid", "tid")}
    if key == "scenario":
        return {name: text() for name in ("scenario_id", "scenario_version", "workload_id", "input_id", "app_version", "description")}
    if key == "policy":
        return {"profile": text(choices=["STANDARD", "DETAILED", "INCIDENT_BURST"]),
                "detail_interval_ms": integer(min=500, max=30000), "thread_limit": integer(min=1, max=1024),
                "child_limit": integer(min=1, max=256), "top_threads": integer(min=1, max=256),
                "burst_seconds": integer(min=1, max=60), "burst_interval_ms": integer(min=500, max=5000),
                "session_seconds": integer(min=0, max=604800), "max_session_mb": integer(min=16, max=1048576),
                "max_trace_mb": integer(min=1, max=1024), "windows_enabled": {"type": "boolean"},
                "incident_enabled": {"type": "boolean"}, "adaptive_throttle": {"type": "boolean"},
                "incident": {"type": "object", "fields": {
                    "pre_ms": integer(min=0, max=300000), "post_ms": integer(min=0, max=60000),
                    "max_incidents": integer(min=1, max=1000), "max_buffer_samples": integer(min=1, max=100000),
                    "max_buffer_bytes": integer(min=1024, max=67108864),
                    "threshold": {"type": "number", "min": 0, "max": 100000},
                    "min_duration_ms": integer(min=0, max=60000)}}}
    if key != "parameters":
        return {}
    operation = tool.removeprefix("deep.")
    thread = {"tid": integer(min=1, max=0xFFFFFFFF), "thread_created_100ns": integer(min=1, max=2**64 - 1)}
    address = {"address": integer(min=1, max=2**64 - 1)}
    if operation in ("thread.suspend", "thread.resume", "debug.context", "debug.step"):
        return thread
    if operation == "thread_stacks":
        return {**thread, "pdb_path": text(), "module_base": integer(min=1, max=2**64 - 1)}
    if operation == "modules":
        return {"hash_files": {"type": "boolean"}}
    if operation == "memory_read":
        return {**address, "size": integer(min=1, max=65536)}
    if operation == "memory.write":
        return {}  # Fresh address and bytes are requested by the runtime dialog.
    if operation == "memory.rollback":
        return {"change_id": text()}
    if operation == "debug.breakpoint.add":
        return address
    if operation in ("debug.breakpoint.disable", "debug.breakpoint.remove"):
        return {"breakpoint_id": text()}
    if operation == "dump":
        return {"full": {"type": "boolean"}}
    if operation == "profile.etw":
        return {"duration_seconds": integer(min=1, max=30),
                "profile": text(choices=["BLACKBOX.Deep.Light"])}
    if operation in ("dump_inspect", "dump_read_memory"):
        return {"path": text(), **({**address, "size": integer(min=1, max=4096)} if operation == "dump_read_memory" else {})}
    if operation == "symbols_verify":
        return {"pe_path": text(), "pdb_path": text()}
    if operation == "trace_evidence":
        return {"path": text(), "process_instance": integer(min=1),
                "start_ms": {"type": "number", "min": 0}, "end_ms": {"type": "number", "min": 0}}
    if operation == "compare":
        return {"before_id": text(), "after_id": text()}
    return {}


class ObjectParameterEditor(QWidget):
    """Optional typed fields; nested configuration never becomes a JSON string."""
    def __init__(self, schema, value, parent=None, *, language="EN"):
        super().__init__(parent)
        self.original = deepcopy(value) if isinstance(value, dict) else {}
        self.fields = {}
        form = QFormLayout(self)
        form.setContentsMargins(0, 0, 0, 0)
        for key, spec in schema.items():
            label = PARAMETER_LABELS.get(key, (key, key))[1 if language == "RU" else 0]
            enabled = QCheckBox(label)
            enabled.setChecked(key in self.original)
            current = self.original.get(key)
            kind = spec.get("type", "string")
            if kind == "object":
                widget = ObjectParameterEditor(spec.get("fields", {}), current, self, language=language)
            elif spec.get("choices"):
                widget = QComboBox()
                for choice in spec["choices"]:
                    widget.addItem(str(choice), choice)
                selected = widget.findData(current)
                if selected >= 0:
                    widget.setCurrentIndex(selected)
            elif kind == "boolean":
                widget = QCheckBox()
                widget.setChecked(bool(current))
            elif kind == "integer" and spec.get("max", 2147483647) <= 2147483647:
                widget = QSpinBox()
                widget.setRange(spec.get("min", 0), spec.get("max", 2147483647))
                if current is not None:
                    widget.setValue(current)
            elif kind == "number":
                widget = QDoubleSpinBox()
                widget.setRange(spec.get("min", 0), spec.get("max", 21600))
                if current is not None:
                    widget.setValue(current)
            else:
                widget = QLineEdit("" if current is None else str(current))
                widget.setMaxLength(8192)
                widget.setProperty("integer64", kind == "integer")
            widget.setEnabled(enabled.isChecked())
            enabled.toggled.connect(widget.setEnabled)
            widget.setObjectName("chainObject_" + key)
            self.fields[key] = (enabled, widget)
            form.addRow(enabled, widget)
        if not schema:
            label = QLabel("Нет сохраняемых параметров" if language == "RU" else "No saved parameters")
            label.setWordWrap(True)
            form.addRow(label)

    def value(self):
        result = deepcopy(self.original)
        for key, (enabled, widget) in self.fields.items():
            if not enabled.isChecked():
                result.pop(key, None)
                continue
            if isinstance(widget, ObjectParameterEditor):
                result[key] = widget.value()
            elif isinstance(widget, QComboBox):
                result[key] = widget.currentData()
            elif isinstance(widget, QCheckBox):
                result[key] = widget.isChecked()
            elif isinstance(widget, (QSpinBox, QDoubleSpinBox)):
                result[key] = widget.value()
            elif widget.property("integer64"):
                result[key] = int(widget.text(), 0)
            else:
                result[key] = widget.text().strip()
        return result


class OptionalParameterEditor(QWidget):
    """Keep an omitted numeric/boolean filter distinct from an explicit zero."""
    def __init__(self, field, present, parent=None, *, language="EN"):
        super().__init__(parent)
        self.field = field
        self.enabled = QCheckBox("Указать" if language == "RU" else "Set value")
        self.enabled.setChecked(present)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.enabled)
        layout.addWidget(field, 1)
        field.setEnabled(present)
        self.enabled.toggled.connect(field.setEnabled)


class ConditionParameterEditor(QWidget):
    """Typed bounded predicates over actual receipt/artifact metadata."""
    def __init__(self, condition, parent=None, *, language="EN"):
        super().__init__(parent)
        self.language, self.rows = language, []
        self.original = deepcopy(condition) if isinstance(condition, dict) else {"status": "COMPLETED"}
        self.touched, self._loading = False, True
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.combination = QComboBox()
        for labels, key in ((("Single predicate", "Одно условие"), "single"),
                            (("AND", "И (AND)"), "all"), (("OR", "ИЛИ (OR)"), "any")):
            label = labels[1 if language == "RU" else 0]
            self.combination.addItem(label, key)
        self.combination.currentIndexChanged.connect(self._changed)
        self.layout.addWidget(self.combination)
        original = self.original
        combination = "all" if "all" in original else "any" if "any" in original else "single"
        self.combination.setCurrentIndex(self.combination.findData(combination))
        clauses = original.get(combination, [original]) if combination != "single" else [original]
        for clause in clauses[:8]:
            self.add_clause(clause)
        self.add_button = QPushButton("Добавить условие (до 8)" if language == "RU" else "Add condition (up to 8)")
        self.add_button.clicked.connect(lambda: self.add_clause())
        self.layout.addWidget(self.add_button)
        self.note = QLabel("Отсутствующие данные дают UNKNOWN. Выполняется только подтверждённая ветвь." if language == "RU" else
                           "Missing data stays UNKNOWN. Only the established branch becomes active.")
        self.note.setWordWrap(True)
        self.layout.addWidget(self.note)
        self._loading = False

    def _changed(self, *_):
        if not self._loading:
            self.touched = True

    def add_clause(self, condition=None):
        if len(self.rows) >= 8:
            return
        condition = condition if isinstance(condition, dict) else {"status": "COMPLETED"}
        area = QWidget(self)
        form = QFormLayout(area)
        field = QComboBox()
        field.setEditable(True)
        for key in ("status", "execution_started", "cleanup.confirmed", "coverage.evidence_completeness", "coverage.row_count", "value.metric"):
            field.addItem(key, key)
        path = condition.get("field", "status")
        if "has_evidence" in condition:
            path = "has_evidence"
        elif "sufficient" in condition:
            path = "sufficient"
        field.setCurrentText(path)
        operator = QComboBox()
        for key in ("EQ", "NE", "GT", "GE", "LT", "LE", "EXISTS"):
            operator.addItem(key, key)
        operator.setCurrentIndex(max(0, operator.findData(condition.get("op", "EQ"))))
        expected = condition.get("value", condition.get("status", condition.get("has_evidence", condition.get("sufficient", "COMPLETED"))))
        kind = "boolean" if type(expected) is bool else "integer" if type(expected) is int else "number" if type(expected) is float else "null" if expected is None else "string"
        value_type = QComboBox()
        for name, labels in (("string", ("Text", "Текст")), ("integer", ("Integer", "Целое число")),
                             ("number", ("Number", "Число")), ("boolean", ("Boolean", "Логическое")),
                             ("null", ("Null", "Не задано"))):
            label = labels[1 if self.language == "RU" else 0]
            value_type.addItem(label, name)
        value_type.setCurrentIndex(value_type.findData(kind))
        raw = QLineEdit("" if expected is None else str(expected))
        raw.setMaxLength(8192)
        boolean = QComboBox()
        boolean.addItem("Да" if self.language == "RU" else "True", True)
        boolean.addItem("Нет" if self.language == "RU" else "False", False)
        boolean.setCurrentIndex(0 if expected is True else 1)
        values = QStackedWidget()
        values.addWidget(raw)
        values.addWidget(boolean)
        values.setCurrentIndex(1 if kind == "boolean" else 0)
        value_type.currentIndexChanged.connect(lambda _: values.setCurrentIndex(1 if value_type.currentData() == "boolean" else 0))
        form.addRow("Поле" if self.language == "RU" else "Field", field)
        form.addRow("Оператор" if self.language == "RU" else "Operator", operator)
        form.addRow("Тип значения" if self.language == "RU" else "Value type", value_type)
        form.addRow("Значение" if self.language == "RU" else "Value", values)
        remove = QPushButton("Удалить условие" if self.language == "RU" else "Remove condition")
        form.addRow(remove)
        row = {"area": area, "field": field, "operator": operator, "type": value_type, "raw": raw, "boolean": boolean}
        self.rows.append(row)
        self.layout.insertWidget(len(self.rows), area)
        def delete():
            if len(self.rows) > 1:
                self.rows.remove(row)
                self.layout.removeWidget(area)
                area.deleteLater()
                self._changed()
        remove.clicked.connect(delete)
        for widget in (field, operator, value_type, boolean):
            widget.currentIndexChanged.connect(self._changed)
        field.editTextChanged.connect(self._changed)
        raw.textChanged.connect(self._changed)
        self._changed()

    def draft(self):
        return {"touched": self.touched, "combination": self.combination.currentData(), "rows": [
            {"field": row["field"].currentText(), "operator": row["operator"].currentData(),
             "type": row["type"].currentData(), "raw": row["raw"].text(), "boolean": row["boolean"].currentData()}
            for row in self.rows]}

    def restore_draft(self, draft):
        self._loading = True
        while len(self.rows) < len(draft["rows"]):
            self.add_clause()
        for row, values in zip(self.rows, draft["rows"]):
            row["field"].setCurrentText(values["field"])
            row["operator"].setCurrentIndex(row["operator"].findData(values["operator"]))
            row["type"].setCurrentIndex(row["type"].findData(values["type"]))
            row["raw"].setText(values["raw"])
            row["boolean"].setCurrentIndex(row["boolean"].findData(values["boolean"]))
        self.combination.setCurrentIndex(self.combination.findData(draft["combination"]))
        self._loading = False
        self.touched = draft["touched"]

    def value(self):
        if not self.touched:
            return deepcopy(self.original)
        clauses = []
        for row in self.rows:
            path, operator, kind = row["field"].currentText().strip(), row["operator"].currentData(), row["type"].currentData()
            if kind == "boolean":
                value = row["boolean"].currentData()
            elif kind == "integer":
                value = int(row["raw"].text(), 0)
            elif kind == "number":
                value = float(row["raw"].text())
            else:
                value = None if kind == "null" else row["raw"].text()
            if path in ("has_evidence", "sufficient"):
                if type(value) is not bool:
                    raise ValueError("BOOLEAN_CONDITION_VALUE_REQUIRED")
                if operator not in ("EQ", "NE"):
                    raise ValueError("BOOLEAN_EVIDENCE_CONDITION_REQUIRES_EQ_OR_NE")
                clauses.append({path: not value if operator == "NE" else value})
            else:
                clauses.append({"field": path, "op": operator, **({} if operator == "EXISTS" else {"value": value})})
        mode = self.combination.currentData()
        if mode == "single":
            if len(clauses) != 1:
                raise ValueError("CHOOSE_AND_OR_FOR_MULTIPLE_CONDITIONS")
            return clauses[0]
        return {mode: clauses}


class ToolPalette(QListWidget):
    def startDrag(self, supported):
        item = self.currentItem()
        if item is None:
            return
        mime = QMimeData()
        mime.setData(MIME, item.data(Qt.ItemDataRole.UserRole).encode("utf-8"))
        drag = QDrag(self)
        drag.setMimeData(mime)
        drag.exec(Qt.DropAction.CopyAction)


class WorkflowNodeItem(QGraphicsObject):
    def __init__(self, canvas, node, ports):
        super().__init__()
        self.canvas, self.node, self.ports = canvas, node, ports
        self.node_id = node["node_id"]
        self.state = ""
        self.width = 280
        self.height = max(112, 73 + 24 * max(len(ports["inputs"]), len(ports["outputs"])))
        self.setFlags(QGraphicsItem.GraphicsItemFlag.ItemIsMovable |
                      QGraphicsItem.GraphicsItemFlag.ItemIsSelectable |
                      QGraphicsItem.GraphicsItemFlag.ItemIsFocusable |
                      QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setData(0, self.node_id)
        self.setPos(*node.get("position", (0, 0)))
        self.setToolTip(node.get("title") or node.get("tool_id") or node["kind"])
        for side in ("inputs", "outputs"):
            for row, (name, spec) in enumerate(ports[side].items()):
                port = QGraphicsEllipseItem(-6, -6, 12, 12, self)
                port.setPos(0 if side == "inputs" else self.width, 72 + row * 24)
                port.setBrush(QColor("#416a9a" if side == "inputs" else "#087b76"))
                port.setPen(QPen(QColor("#554b60"), 1))
                port.setData(0, (self.node_id, side, name))
                port.setToolTip(name + " · " + " | ".join(spec["types"]))

    def boundingRect(self):
        return QRectF(-8, -3, self.width + 16, self.height + 6)

    def paint(self, painter, option, widget=None):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(QColor("#fff7e4"))
        painter.setPen(QPen(QColor("#416a9a" if self.isSelected() else COLORS.get(self.state, "#554b60")),
                            3 if self.isSelected() else 2))
        painter.drawRoundedRect(QRectF(0, 0, self.width, self.height), 6, 6)
        painter.setPen(QColor("#332c39"))
        title = self.node.get("title") or self.canvas.tool_name(self.node.get("tool_id") or self.node["kind"])
        painter.drawText(QRectF(10, 7, 260, 22), Qt.AlignmentFlag.AlignLeft, title[:42])
        painter.drawText(QRectF(10, 29, 260, 18), Qt.AlignmentFlag.AlignLeft,
                         (self.node.get("tool_id") or self.node["kind"])[:42])
        if self.state:
            painter.drawText(QRectF(10, 48, 260, 18), Qt.AlignmentFlag.AlignLeft, self.canvas.state_name(self.state))
        for side in ("inputs", "outputs"):
            for row, (name, spec) in enumerate(self.ports[side].items()):
                text = name + " · " + "/".join(spec["types"])
                painter.drawText(QRectF(10 if side == "inputs" else 150, 65 + row * 24, 120, 20),
                    Qt.AlignmentFlag.AlignLeft if side == "inputs" else Qt.AlignmentFlag.AlignRight, text[:19])

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            self.canvas.update_edges()
        return super().itemChange(change, value)

    def port_position(self, side, name):
        names = list(self.ports[side])
        return self.scenePos() + QPointF(0 if side == "inputs" else self.width, 72 + names.index(name) * 24)


class WorkflowCanvas(QGraphicsView):
    node_selected = Signal(str)
    positions_changed = Signal(object)
    connection_requested = Signal(object)
    delete_requested = Signal(object, object)
    tool_dropped = Signal(str, object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setScene(QGraphicsScene(self))
        self.setObjectName("chainCanvas")
        self.setAccessibleName("Workflow nodes and typed ports / Узлы цепочки и типизированные порты")
        self.setMinimumSize(350, 340)
        self.setAcceptDrops(True)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.items_by_id, self.edge_items = {}, {}
        self.edges, self.language, self.pending_port = [], "EN", None
        self.editable = True
        self._drag_start = {}
        self.scene().selectionChanged.connect(self._selected)

    def tool_name(self, tool):
        pair = TOOL_NAMES.get(tool)
        if pair is None and tool.startswith("deep."):
            from .deep_inspector_panel import ACTION_LABELS
            pair = ACTION_LABELS.get(tool.removeprefix("deep."))
        pair = pair or (tool, tool)
        return pair[1 if self.language == "RU" else 0]

    def state_name(self, state):
        return STATE_NAMES.get(state, (state, state))[1 if self.language == "RU" else 0]

    def set_graph(self, document, catalog, controls):
        selected = self.selected_node_ids()
        self.scene().blockSignals(True)
        self.scene().clear()
        self.items_by_id, self.edge_items = {}, {}
        self.edges = deepcopy(document["edges"])
        for node in document["nodes"]:
            kind = node.get("kind", "TOOL")
            descriptor = catalog.get(node.get("tool_id"), {}) if kind in ("TOOL", "REPEAT") else controls.get(kind, {})
            ports = {"inputs": dict(descriptor.get("inputs", {})), "outputs": dict(descriptor.get("outputs", {}))}
            if node.get("tool_id") == "load_source" and node.get("parameters", {}).get("kind"):
                ports["outputs"]["source"] = {"types": [node["parameters"]["kind"]], "required": True, "many": False}
            ports["inputs"]["when"] = {"types": ["BOOLEAN"], "required": False, "many": False}
            item = WorkflowNodeItem(self, node, ports)
            item.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, self.editable)
            self.items_by_id[node["node_id"]] = item
            self.scene().addItem(item)
            item.setSelected(node["node_id"] in selected)
        for edge in self.edges:
            item = QGraphicsPathItem()
            item.setPen(QPen(QColor("#736b7e"), 2))
            item.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
            item.setData(0, ("edge", edge["edge_id"]))
            item.setZValue(-1)
            self.scene().addItem(item)
            self.edge_items[edge["edge_id"]] = item
        self.scene().blockSignals(False)
        self.update_edges()

    def update_edges(self):
        for edge in self.edges:
            first, second = self.items_by_id.get(edge["source_node"]), self.items_by_id.get(edge["target_node"])
            if first is None or second is None or edge["edge_id"] not in self.edge_items:
                continue
            try:
                start = first.port_position("outputs", edge["source_port"])
                end = second.port_position("inputs", edge["target_port"])
            except ValueError:
                continue
            path = QPainterPath(start)
            offset = max(65, abs(end.x() - start.x()) / 2)
            path.cubicTo(start + QPointF(offset, 0), end - QPointF(offset, 0), end)
            self.edge_items[edge["edge_id"]].setPath(path)
        self.scene().setSceneRect(self.scene().itemsBoundingRect().adjusted(-100, -80, 100, 80))

    def selected_node_ids(self):
        return [item.node_id for item in self.scene().selectedItems() if isinstance(item, WorkflowNodeItem)]

    def _selected(self):
        selected = self.selected_node_ids()
        if selected:
            self.node_selected.emit(selected[0])

    def port_at(self, position):
        item = self.itemAt(position)
        while item is not None:
            data = item.data(0)
            if isinstance(data, (tuple, list)) and len(data) == 3:
                return data
            item = item.parentItem()
        return None

    def mousePressEvent(self, event):
        self._drag_start = {key: item.pos() for key, item in self.items_by_id.items()}
        port = self.port_at(event.pos())
        if port and self.editable:
            self.pending_port = port
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        if self.pending_port is not None:
            target, first = self.port_at(event.pos()), self.pending_port
            self.pending_port = None
            if target and target != first:
                if first[1] == "inputs":
                    first, target = target, first
                if first[1] == "outputs" and target[1] == "inputs":
                    self.connection_requested.emit({"source_node": first[0], "source_port": first[2],
                        "target_node": target[0], "target_port": target[2]})
            event.accept()
            return
        super().mouseReleaseEvent(event)
        moved = {key: [item.x(), item.y()] for key, item in self.items_by_id.items()
                 if self._drag_start.get(key) != item.pos()}
        if moved and self.editable:
            self.positions_changed.emit(moved)

    def zoom(self, multiplier):
        scale = self.transform().m11()
        requested = max(.15, min(3.5, scale * multiplier))
        self.scale(requested / scale, requested / scale)

    def wheelEvent(self, event):
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            self.zoom(1.15 if event.angleDelta().y() > 0 else 1 / 1.15)
            event.accept()
        else:
            super().wheelEvent(event)

    def keyPressEvent(self, event):
        key = event.key()
        if key in (Qt.Key.Key_Plus, Qt.Key.Key_Equal, Qt.Key.Key_Minus):
            self.zoom(1 / 1.15 if key == Qt.Key.Key_Minus else 1.15)
        elif key == Qt.Key.Key_Escape:
            self.pending_port = None
            self.scene().clearSelection()
        elif key == Qt.Key.Key_Delete and self.editable:
            edges = [item.data(0)[1] for item in self.scene().selectedItems()
                     if isinstance(item.data(0), (tuple, list)) and item.data(0)[0] == "edge"]
            self.delete_requested.emit(self.selected_node_ids(), edges)
        elif key in (Qt.Key.Key_Left, Qt.Key.Key_Right, Qt.Key.Key_Up, Qt.Key.Key_Down) and self.editable:
            delta = {Qt.Key.Key_Left: (-10, 0), Qt.Key.Key_Right: (10, 0),
                     Qt.Key.Key_Up: (0, -10), Qt.Key.Key_Down: (0, 10)}[key]
            moved = {}
            for identifier in self.selected_node_ids():
                item = self.items_by_id[identifier]
                item.setPos(item.pos() + QPointF(*delta))
                moved[identifier] = [item.x(), item.y()]
            if moved:
                self.positions_changed.emit(moved)
        else:
            super().keyPressEvent(event)
            return
        event.accept()

    def dragEnterEvent(self, event):
        if self.editable and event.mimeData().hasFormat(MIME):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        self.dragEnterEvent(event)

    def dropEvent(self, event):
        if self.editable and event.mimeData().hasFormat(MIME):
            tool = bytes(event.mimeData().data(MIME)).decode("utf-8")[:128]
            point = self.mapToScene(event.position().toPoint())
            self.tool_dropped.emit(tool, [point.x(), point.y()])
            event.acceptProposedAction()


class ChainBuilderPanel(QWidget):
    history_changed = Signal()

    def __init__(self, window, root, *, bridge=None):
        super().__init__(window)
        self.window, self.root = window, Path(root)
        self.bridge = bridge or ChainBuilderBridge(window, root)
        self.catalog, self.controls, self.snapshot, self.validation = {}, {}, {}, {}
        self._labels, self._fields, self._selected = [], {}, None
        self._folder, self._loading, self._run_active = None, False, False
        self._human_pending = False
        self.document = {"schema": "blackbox.workflow-definition/1", "schema_version": 1,
            "workflow_id": uuid4().hex, "title": "My diagnostic chain", "revision": 1,
            "description": "", "mode": "USER_CONTROLLED", "nodes": [], "edges": [],
            "profile": {"profile_id": "application", "overrides": {}},
            "budget": {"seconds": 1800, "max_workers": 2, "max_owned_resources": 8, "max_output_bytes": 1024**3}}
        self.setObjectName("chainBuilder")
        self._build()
        self.bridge.result_ready.connect(self._received)
        self.bridge.snapshot_changed.connect(self._snapshot)
        self.bridge.busy_changed.connect(self._busy)
        self.bridge.human_required.connect(self._human)
        self.retranslate()
        QTimer.singleShot(0, lambda: self.bridge.submit("catalog"))

    def tr2(self, en, ru):
        return ru if self.window.language == "RU" else en

    def _text(self, widget, en, ru):
        self._labels.append((widget, en, ru))
        widget.setText(self.tr2(en, ru))
        return widget

    def _button(self, name, en, ru, callback):
        button = self._text(QPushButton(), en, ru)
        button.setObjectName(name)
        button.clicked.connect(callback)
        return button

    def _build(self):
        layout = QVBoxLayout(self)
        self.notice = self._text(QLabel(),
            "Build a diagnostic chain. Opening, preview and validation never run tools. Interventions require fresh confirmation.",
            "Создайте диагностическую цепочку. Открытие, предпросмотр и проверка не запускают инструменты. Вмешательства требуют нового подтверждения.")
        self.notice.setWordWrap(True)
        layout.addWidget(self.notice)
        header = QFormLayout()
        self.title = QLineEdit(self.document["title"])
        self.title.setMaxLength(256)
        self.title.setObjectName("chainTitle")
        self.title.editingFinished.connect(self._title_changed)
        title_label = self._text(QLabel(), "Chain name", "Название цепочки")
        header.addRow(title_label, self.title)
        self.profile = QComboBox()
        self.profile.setEditable(True)
        for key in ("windows", "application", "case"):
            self.profile.addItem(key, key)
        self.profile.setCurrentIndex(1)
        self.profile.currentIndexChanged.connect(self._profile_changed)
        self.profile.lineEdit().editingFinished.connect(self._profile_changed)
        header.addRow(self._text(QLabel(), "Profile", "Профиль"), self.profile)
        self.profile_parent = QComboBox()
        self.profile_parent.addItem("—", "")
        for key in ("windows", "application", "case"):
            self.profile_parent.addItem(key, key)
        self.profile_parent.currentIndexChanged.connect(self._profile_changed)
        header.addRow(self._text(QLabel(), "Inherit from", "Наследовать от"), self.profile_parent)
        layout.addLayout(header)
        actions = ActionGrid()
        self.open_button = self._button("chainOpen", "Open chain…", "Открыть цепочку…", self.open_definition)
        self.save_button = self._button("chainSave", "Save chain…", "Сохранить цепочку…", self.save_definition)
        self.profile_save = self._button("chainSaveProfile", "Save profile…", "Сохранить профиль…", lambda: self.profile_file("save_profile"))
        self.profile_open = self._button("chainOpenProfile", "Open profile…", "Открыть профиль…", lambda: self.profile_file("open_profile"))
        self.validate_button = self._button("chainValidate", "Validate / preview", "Проверить / предпросмотр", self.validate)
        self.start_button = self._button("chainStart", "Start", "Запустить", self.start)
        self.pause_button = self._button("chainPause", "Pause at safe boundary", "Пауза на безопасной границе", self.bridge.pause)
        self.cancel_button = self._button("chainCancel", "Stop owned operations", "Остановить свои операции", self.bridge.cancel)
        self.resume_button = self._button("chainResume", "Continue / resume", "Продолжить", self.resume)
        self.grant_button = self._button("chainGrantPermission", "Request scoped permission…", "Запросить ограниченные права…", self.bridge.grant_permission)
        for button in (self.open_button, self.save_button, self.profile_open, self.profile_save, self.validate_button,
                       self.start_button, self.pause_button, self.cancel_button, self.resume_button, self.grant_button):
            actions.addWidget(button)
        layout.addLayout(actions)
        self.status = QLabel()
        self.status.setObjectName("chainStatus")
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.status)
        split = QSplitter(Qt.Orientation.Horizontal)
        palette_area, palette_layout = QWidget(), QVBoxLayout()
        palette_area.setLayout(palette_layout)
        self.palette = ToolPalette()
        self.palette.setObjectName("chainTools")
        self.palette.setAccessibleName("Available tools / Доступные инструменты")
        self.palette.setDragEnabled(True)
        self.palette.itemDoubleClicked.connect(lambda _: self.add_selected_tool())
        palette_layout.addWidget(self.palette)
        self.add_button = self._button("chainAddNode", "Add selected tool", "Добавить инструмент", self.add_selected_tool)
        self.add_repeat = self._button("chainAddRepeat", "Add bounded repeat", "Добавить ограниченный повтор", lambda: self.add_selected_tool(repeat=True))
        self.choose_process = self._button("chainChooseProcess", "Choose process…", "Выбрать процесс…", lambda: self.window._navigate("processes"))
        for button in (self.add_button, self.add_repeat, self.choose_process):
            palette_layout.addWidget(button)
        split.addWidget(palette_area)
        self.canvas = WorkflowCanvas()
        self.canvas.node_selected.connect(self.select_node)
        self.canvas.positions_changed.connect(self._positions_changed)
        self.canvas.connection_requested.connect(self.connect_ports)
        self.canvas.delete_requested.connect(self.delete_nodes)
        self.canvas.tool_dropped.connect(self.add_tool)
        split.addWidget(self.canvas)
        inspector = QWidget()
        inspector_layout = QVBoxLayout(inspector)
        self.inspector_tabs = QTabWidget()
        self.parameter_page = QWidget()
        self.parameter_form = QFormLayout(self.parameter_page)
        parameter_scroll = QScrollArea()
        parameter_scroll.setWidgetResizable(True)
        parameter_scroll.setWidget(self.parameter_page)
        self.inspector_tabs.addTab(parameter_scroll, "Parameters")
        self.effective = QPlainTextEdit()
        self.effective.setReadOnly(True)
        self.effective.setObjectName("chainEffectiveProfile")
        self.inspector_tabs.addTab(self.effective, "Preview")
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setObjectName("chainNodeDetails")
        self.inspector_tabs.addTab(self.details, "Details")
        inspector_layout.addWidget(self.inspector_tabs)
        self.apply_button = self._button("chainApplyParameters", "Apply node parameters", "Применить параметры узла", self.apply_parameters)
        self.delete_button = self._button("chainDeleteNode", "Delete selection", "Удалить выбранное", lambda: self.delete_nodes(self.canvas.selected_node_ids(), []))
        inspector_layout.addWidget(self.apply_button)
        inspector_layout.addWidget(self.delete_button)
        split.addWidget(inspector)
        split.setSizes([180, 540, 300])
        layout.addWidget(split)
        connection = QGridLayout()
        self.source_node, self.target_node = QComboBox(), QComboBox()
        self.source_port, self.target_port = QComboBox(), QComboBox()
        for name, widget in (("chainSourceNode", self.source_node), ("chainTargetNode", self.target_node),
                             ("chainSourcePort", self.source_port), ("chainTargetPort", self.target_port)):
            widget.setObjectName(name)
            widget.setAccessibleName(name)
            widget.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
            widget.setMinimumContentsLength(6)
        self.source_node.currentIndexChanged.connect(self._connection_ports)
        self.target_node.currentIndexChanged.connect(self._connection_ports)
        connection.addWidget(self._text(QLabel(), "From output", "Из выхода"), 0, 0)
        connection.addWidget(self.source_node, 0, 1)
        connection.addWidget(self.source_port, 0, 2)
        connection.addWidget(self._text(QLabel(), "To input", "Во вход"), 1, 0)
        connection.addWidget(self.target_node, 1, 1)
        connection.addWidget(self.target_port, 1, 2)
        self.connect_button = self._button("chainConnect", "Connect compatible ports", "Соединить совместимые порты", self.connect_from_controls)
        connection.addWidget(self.connect_button, 0, 3, 2, 1)
        layout.addLayout(connection)
        zoom = QHBoxLayout()
        for name, en, ru, callback in (("chainZoomOut", "−", "−", lambda: self.canvas.zoom(1 / 1.15)),
                ("chainZoomIn", "+", "+", lambda: self.canvas.zoom(1.15)),
                ("chainFit", "Fit graph", "Весь граф", self.fit_graph),
                ("chainActualSize", "100%", "100%", self.canvas.resetTransform)):
            zoom.addWidget(self._button(name, en, ru, callback))
        self.budget_seconds = QDoubleSpinBox()
        self.budget_seconds.setRange(.01, 21600)
        self.budget_seconds.setValue(1800)
        self.budget_seconds.valueChanged.connect(self._budget_changed)
        zoom.addWidget(self._text(QLabel(), "Total budget, s", "Общий бюджет, с"))
        zoom.addWidget(self.budget_seconds)
        self.parallel = QSpinBox()
        self.parallel.setRange(1, 4)
        self.parallel.setValue(2)
        self.parallel.valueChanged.connect(self._budget_changed)
        zoom.addWidget(self._text(QLabel(), "Read-only workers", "Read-only исполнители"))
        zoom.addWidget(self.parallel)
        layout.addLayout(zoom)
        # Scope/profile overrides have ordinary typed controls, not a JSON editor.
        overrides = QGridLayout()
        self.allowed_tools = QListWidget()
        self.allowed_tools.setMaximumHeight(110)
        self.allowed_tools.itemChanged.connect(self._overrides_changed)
        self.override_tools = self._text(QCheckBox(), "Override allowed tools", "Переопределить допустимые инструменты")
        self.override_tools.toggled.connect(self._overrides_changed)
        self.profile_seconds = QDoubleSpinBox()
        self.profile_seconds.setRange(.01, 21600)
        self.profile_seconds.setValue(1800)
        self.profile_seconds.valueChanged.connect(self._overrides_changed)
        self.override_seconds = self._text(QCheckBox(), "Override profile budget, s", "Переопределить бюджет профиля, с")
        self.override_seconds.toggled.connect(self._overrides_changed)
        self.allow_effectful = self._text(QCheckBox(), "Plan effectful tools (fresh confirmation remains required)",
            "Допустить вмешательства в плане (новое подтверждение обязательно)")
        self.allow_effectful.toggled.connect(self._overrides_changed)
        self.source_ids = QLineEdit()
        self.source_ids.setObjectName("chainProfileSourceIds")
        self.source_ids.setMaxLength(8192)
        self.source_ids.setToolTip(self.tr2(
            "Use the saved source's exact SHA-256 shown in node outputs. Sessions use their aggregate fingerprint. "
            "This does not select or authorize a live PID/creation FILETIME.",
            "Укажите точный SHA-256 сохранённого источника из выходов узла. Для сеанса используется совокупный хеш. "
            "Это не выбирает и не разрешает живой PID/FILETIME создания."))
        self.source_ids.editingFinished.connect(self._overrides_changed)
        self.allowed_nodes = QListWidget()
        self.allowed_nodes.setMaximumHeight(100)
        self.allowed_nodes.itemChanged.connect(self._overrides_changed)
        self.override_nodes = self._text(QCheckBox(), "Restrict allowed branches / nodes", "Ограничить допустимые ветви / узлы")
        self.override_nodes.toggled.connect(self._overrides_changed)
        overrides.addWidget(self.override_tools, 0, 0)
        overrides.addWidget(self.allowed_tools, 1, 0, 2, 1)
        overrides.addWidget(self.override_seconds, 0, 1)
        overrides.addWidget(self.profile_seconds, 1, 1)
        overrides.addWidget(self.allow_effectful, 2, 1)
        overrides.addWidget(self._text(QLabel(), "Allowed source SHA-256 IDs (comma separated; blank inherits)",
            "Допустимые SHA-256 источников (через запятую; пусто — наследование)"), 3, 0)
        overrides.addWidget(self.source_ids, 4, 0)
        overrides.addWidget(self.override_nodes, 3, 1)
        overrides.addWidget(self.allowed_nodes, 4, 1)
        layout.addLayout(overrides)
        self._shortcuts = []
        for sequence, callback in ((QKeySequence.StandardKey.Save, self.save_definition),
                                   (QKeySequence.StandardKey.Open, self.open_definition)):
            shortcut = QShortcut(QKeySequence(sequence), self)
            shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
            shortcut.activated.connect(callback)
            self._shortcuts.append(shortcut)

    def _mark_changed(self):
        self.document["revision"] += 1
        self.validation = {}
        self.status.setText(self.tr2("Changed. Validate before starting.", "Изменено. Проверьте перед запуском."))

    def _title_changed(self):
        if not self._loading and self.title.text().strip():
            self.document["title"] = self.title.text().strip()
            self._mark_changed()

    def _profile_changed(self):
        if self._loading:
            return
        profile = self.document["profile"]
        selected = self.profile.currentData()
        if self.profile.currentText() != self.profile.itemText(self.profile.currentIndex()):
            selected = self.profile.currentText().strip()
        profile["profile_id"] = selected or self.profile.currentText().strip()
        parent = self.profile_parent.currentData()
        if parent:
            profile["inherits"] = parent
        else:
            profile.pop("inherits", None)
        self._mark_changed()

    def _budget_changed(self):
        if self._loading:
            return
        self.document["budget"].update(seconds=self.budget_seconds.value(), max_workers=self.parallel.value())
        self._mark_changed()

    def _overrides_changed(self, *_):
        if self._loading:
            return
        overrides = self.document["profile"].setdefault("overrides", {})
        if self.override_tools.isChecked():
            overrides["allowed_tools"] = [self.allowed_tools.item(i).data(Qt.ItemDataRole.UserRole)
                for i in range(self.allowed_tools.count()) if self.allowed_tools.item(i).checkState() == Qt.CheckState.Checked]
        else:
            overrides.pop("allowed_tools", None)
        if self.override_seconds.isChecked():
            overrides["max_seconds"] = self.profile_seconds.value()
        else:
            overrides.pop("max_seconds", None)
        overrides["allow_effectful"] = self.allow_effectful.isChecked()
        source_ids = [value.strip() for value in self.source_ids.text().split(",") if value.strip()]
        if source_ids:
            overrides["source_ids"] = source_ids
        else:
            overrides.pop("source_ids", None)
        if self.override_nodes.isChecked():
            overrides["allowed_node_ids"] = [self.allowed_nodes.item(i).data(Qt.ItemDataRole.UserRole)
                for i in range(self.allowed_nodes.count()) if self.allowed_nodes.item(i).checkState() == Qt.CheckState.Checked]
        else:
            overrides.pop("allowed_node_ids", None)
        self._mark_changed()

    def _render(self):
        self.canvas.set_graph(self.document, self.catalog, self.controls)
        records = self.snapshot.get("nodes", [])
        if isinstance(records, dict):
            records = [dict(value, node_id=key) for key, value in records.items()]
        for record in records:
            item = self.canvas.items_by_id.get(record.get("node_id"))
            if item is not None:
                item.state = record.get("state", record.get("status", "UNKNOWN"))
        self.allowed_nodes.blockSignals(True)
        self.allowed_nodes.clear()
        allowed = self.document["profile"].get("overrides", {}).get("allowed_node_ids")
        for node in self.document["nodes"]:
            item = QListWidgetItem(node.get("title") or self.canvas.tool_name(node.get("tool_id") or node["kind"]))
            item.setData(Qt.ItemDataRole.UserRole, node["node_id"])
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if allowed is None or node["node_id"] in allowed else Qt.CheckState.Unchecked)
            self.allowed_nodes.addItem(item)
        self.allowed_nodes.blockSignals(False)
        for box in (self.source_node, self.target_node):
            selected = box.currentData()
            box.blockSignals(True)
            box.clear()
            for node in self.document["nodes"]:
                box.addItem(node.get("title") or self.canvas.tool_name(node.get("tool_id") or node["kind"]), node["node_id"])
            index = box.findData(selected)
            if index >= 0:
                box.setCurrentIndex(index)
            box.blockSignals(False)
        self._connection_ports()

    def _connection_ports(self, *_):
        for node_box, port_box, side in ((self.source_node, self.source_port, "outputs"),
                                         (self.target_node, self.target_port, "inputs")):
            current = port_box.currentData()
            port_box.clear()
            item = self.canvas.items_by_id.get(node_box.currentData())
            if item is not None:
                for name, spec in item.ports[side].items():
                    port_box.addItem(name + " · " + "/".join(spec["types"]), name)
                index = port_box.findData(current)
                if index >= 0:
                    port_box.setCurrentIndex(index)

    def add_selected_tool(self, *, repeat=False):
        item = self.palette.currentItem()
        if item is not None:
            self.add_tool(item.data(Qt.ItemDataRole.UserRole), None, repeat=repeat)

    def add_tool(self, tool, position=None, *, repeat=False):
        if self.bridge.busy or tool not in self.catalog and tool not in self.controls:
            return
        if len(self.document["nodes"]) >= 256:
            self.status.setText(self.tr2("The graph limit is 256 nodes.", "Предел графа — 256 узлов."))
            return
        descriptor = self.catalog.get(tool, {})
        parameters = {key: deepcopy(spec["default"]) for key, spec in descriptor.get("parameters", {}).items()
                      if "default" in spec}
        kind = ("REPEAT" if repeat else "TOOL") if tool in self.catalog else tool
        limits = descriptor.get("descriptor", {}).get("budgets", {})
        seconds = min(180, limits.get("max_operation_seconds", 180), limits.get("default_timeout_seconds", 180))
        node = {"node_id": "node_" + uuid4().hex[:12], "tool_id": tool if tool in self.catalog else "",
            "kind": kind, "title": "", "parameters": parameters, "budget_seconds": seconds,
            "required": True, "repeat_count": 2 if repeat and tool in self.catalog else 1,
            "allow_partial_inputs": False,
            "repeat_interval_seconds": 0,
            "position": position or [40 + len(self.document["nodes"]) % 3 * 330, 40 + len(self.document["nodes"]) // 3 * 180]}
        self.document["nodes"].append(node)
        self._mark_changed()
        self._render()
        item = self.canvas.items_by_id[node["node_id"]]
        item.setSelected(True)
        self.canvas.ensureVisible(item)
        self.select_node(node["node_id"])

    def _positions_changed(self, positions):
        for node in self.document["nodes"]:
            if node["node_id"] in positions:
                node["position"] = positions[node["node_id"]]
        self._mark_changed()

    def delete_nodes(self, node_ids, edge_ids):
        if self.bridge.busy:
            return
        self.document["nodes"] = [n for n in self.document["nodes"] if n["node_id"] not in node_ids]
        self.document["edges"] = [e for e in self.document["edges"] if e["edge_id"] not in edge_ids
                                  and e["source_node"] not in node_ids and e["target_node"] not in node_ids]
        self._selected = None
        self._mark_changed()
        self._render()
        self.select_node("")

    def connect_from_controls(self):
        self.connect_ports({"source_node": self.source_node.currentData(), "source_port": self.source_port.currentData(),
            "target_node": self.target_node.currentData(), "target_port": self.target_port.currentData()})

    def connect_ports(self, edge):
        if self.bridge.busy or not all(edge.values()):
            return
        edge = dict(edge, edge_id="edge_" + uuid4().hex[:12])
        self.bridge.submit("connect", definition=self.document, edge=edge)

    def _form_row(self, key, label, widget):
        widget.setObjectName("chainParam_" + key)
        widget.setAccessibleName(label)
        self._fields[key] = widget
        self.parameter_form.addRow(label, widget)

    def select_node(self, node_id):
        self._selected = node_id
        while self.parameter_form.rowCount():
            self.parameter_form.removeRow(0)
        self._fields = {}
        node = next((n for n in self.document["nodes"] if n["node_id"] == node_id), None)
        if node is None:
            return
        title = QLineEdit(node.get("title", ""))
        title.setMaxLength(256)
        self._form_row("_title", self.tr2("Node name", "Название узла"), title)
        budget = QDoubleSpinBox()
        budget.setRange(.01, 21600)
        budget.setValue(node.get("budget_seconds", 60))
        self._form_row("_budget", self.tr2("Budget, s", "Бюджет, с"), budget)
        required = QCheckBox()
        required.setChecked(node.get("required", True))
        self._form_row("_required", self.tr2("Required branch", "Обязательная ветвь"), required)
        partial = QCheckBox()
        partial.setChecked(node.get("allow_partial_inputs", False))
        partial.setToolTip(self.tr2("Continue with incomplete upstream evidence; derived results remain partial.",
            "Продолжить с неполными входными свидетельствами; производные результаты останутся частичными."))
        self._form_row("_allow_partial", self.tr2("Accept partial evidence", "Принимать неполные свидетельства"), partial)
        parameters = node.get("parameters", {})
        descriptor = self.catalog.get(node.get("tool_id"), {})
        specs = descriptor.get("parameters", {})
        if node["kind"] == "CONDITION":
            specs = {"condition": {"type": "condition", "default": {"status": "COMPLETED"}}}
        elif node["kind"] == "JOIN":
            specs = {"mode": {"type": "choice", "choices": ["ALL_REQUIRED", "ALLOW_PARTIAL"], "default": "ALL_REQUIRED"},
                     "allow_partial": {"type": "boolean", "default": False}}
        elif node["kind"] == "CHECKPOINT":
            specs = {"message": {"type": "string", "default": ""}}
        for key, spec in specs.items():
            # Runtime effect payload belongs to the original fresh R10 dialog.
            if key in ("expected_hex", "value_hex", "confirmed", "authorization", "token"):
                continue
            value = parameters.get(key, spec.get("default"))
            if node["kind"] == "CONDITION" and key == "condition" and "condition" not in parameters and parameters:
                value = parameters
            choices, kind = spec.get("choices"), spec.get("type", "str")
            if kind == "condition":
                widget = ConditionParameterEditor(value, self.parameter_page, language=self.window.language)
            elif kind == "object":
                widget = ObjectParameterEditor(_object_schema(node.get("tool_id", ""), key), value, self.parameter_page,
                                               language=self.window.language)
            elif choices:
                widget = QComboBox()
                for choice in choices:
                    widget.addItem(str(choice), choice)
                index = widget.findData(value)
                if index >= 0:
                    widget.setCurrentIndex(index)
            elif kind in ("int", "integer") and spec.get("max", 2147483647) <= 2147483647:
                widget = QSpinBox()
                widget.setRange(max(-2147483647, int(spec.get("min", 0))), min(2147483647, int(spec.get("max", 2147483647))))
                if value is not None:
                    widget.setValue(int(value))
            elif kind in ("float", "number"):
                widget = QDoubleSpinBox()
                widget.setRange(float(spec.get("min", 0)), float(spec.get("max", 21600)))
                if value is not None:
                    widget.setValue(float(value))
            elif kind in ("bool", "boolean"):
                widget = QCheckBox()
                widget.setChecked(bool(value))
            else:
                widget = QLineEdit("" if value is None else str(value))
                widget.setMaxLength(8192)
                widget.setProperty("parameter_type", kind)
                widget.setProperty("integer64", kind in ("int", "integer"))
            if (not spec.get("required", False) and "default" not in spec
                    and isinstance(widget, (QSpinBox, QDoubleSpinBox, QCheckBox, QComboBox))):
                widget = OptionalParameterEditor(widget, key in parameters, self.parameter_page,
                                                  language=self.window.language)
            label = spec.get("label_ru") if self.window.language == "RU" else spec.get("label")
            label = str(label or spec.get("label") or PARAMETER_LABELS.get(key, (key, key))[1 if self.window.language == "RU" else 0])
            self._form_row(key, label, widget)
            if key in ("path", "destination", "pdb_path", "pe_path", "index_path"):
                button = QPushButton(self.tr2("Choose file/folder…", "Выбрать файл/папку…"))
                button.setObjectName("chainBrowse_" + key)
                button.clicked.connect(lambda checked=False, field=widget, name=key: self._browse_parameter(field, name))
                self.parameter_form.addRow(button)
        if node["kind"] == "REPEAT":
            count = QSpinBox()
            count.setRange(1, 4096)
            count.setValue(node["repeat_count"])
            interval = QDoubleSpinBox()
            interval.setRange(0, 3600)
            interval.setValue(node.get("repeat_interval_seconds", 0))
            self._form_row("_repeat", self.tr2("Maximum repetitions", "Максимум повторов"), count)
            self._form_row("_interval", self.tr2("Interval, s", "Интервал, с"), interval)
        if node.get("tool_id") == "deep.memory.write":
            label = QLabel(self.tr2("Memory bytes are requested fresh at execution and never saved in this graph.",
                                   "Байты памяти вводятся заново при выполнении и не сохраняются в схеме."))
            label.setWordWrap(True)
            self.parameter_form.addRow(label)
        self._show_node_details(node)
        self.apply_button.setEnabled(not self.bridge.busy)

    def _browse_parameter(self, field, name):
        node = next((n for n in self.document["nodes"] if n["node_id"] == self._selected), {})
        is_session = node.get("parameters", {}).get("kind") == "SESSION"
        if is_session:
            path = QFileDialog.getExistingDirectory(self, self.tr2("Saved session", "Сохранённый сеанс"))
        elif name == "destination":
            path, _ = QFileDialog.getSaveFileName(self, self.tr2("New output file", "Новый выходной файл"))
        else:
            path, _ = QFileDialog.getOpenFileName(self, self.tr2("Saved source", "Сохранённый источник"))
        if path:
            field.setText(path)

    def apply_parameters(self):
        if self.bridge.busy:
            return
        node = next((n for n in self.document["nodes"] if n["node_id"] == self._selected), None)
        if node is None:
            return
        parameters = {}
        for key, widget in self._fields.items():
            if key.startswith("_"):
                continue
            if isinstance(widget, OptionalParameterEditor):
                if not widget.enabled.isChecked():
                    continue
                widget = widget.field
            if isinstance(widget, (ObjectParameterEditor, ConditionParameterEditor)):
                try:
                    value = widget.value()
                except ValueError as error:
                    self.status.setText(self.tr2("Check the typed parameter: ", "Проверьте типизированный параметр: ")
                                        + str(error)[:300])
                    return
            elif isinstance(widget, QComboBox):
                value = widget.currentData()
            elif isinstance(widget, QCheckBox):
                value = widget.isChecked()
            elif isinstance(widget, (QSpinBox, QDoubleSpinBox)):
                value = widget.value()
            else:
                value = widget.text().strip()
                if value == "":
                    continue
                if widget.property("integer64"):
                    try:
                        value = int(value, 0)
                    except ValueError:
                        self.status.setText(self.tr2("Check the numeric parameter values.", "Проверьте числовые параметры."))
                        return
            parameters[key] = value
        node.update(title=self._fields["_title"].text(), budget_seconds=self._fields["_budget"].value(),
                    required=self._fields["_required"].isChecked(),
                    allow_partial_inputs=self._fields["_allow_partial"].isChecked(), parameters=parameters)
        if "_repeat" in self._fields:
            node.update(repeat_count=self._fields["_repeat"].value(), repeat_interval_seconds=self._fields["_interval"].value())
        self._mark_changed()
        self._render()
        self.select_node(node["node_id"])

    def validate(self):
        self.bridge.submit("validate", definition=self.document)

    def start(self):
        self._human_pending = False
        self.bridge.submit("start", definition=self.document, root=str(self.root))

    def resume(self):
        if self.bridge.continue_human():
            return
        if self._folder:
            self.bridge.submit("resume", definition=self.document, folder=self._folder)

    def open_definition(self):
        path, _ = QFileDialog.getOpenFileName(self, self.tr2("Open chain", "Открыть цепочку"), "", "BLACK.BOX workflow (*.bbchain.json)")
        if path:
            self.bridge.submit("open", path=path)

    def save_definition(self):
        path, _ = QFileDialog.getSaveFileName(self, self.tr2("Save new chain file", "Сохранить новый файл цепочки"), "", "BLACK.BOX workflow (*.bbchain.json)")
        if path:
            if not path.endswith(".bbchain.json"):
                path += ".bbchain.json"
            self.bridge.submit("save", definition=self.document, path=path)

    def profile_file(self, operation):
        chooser = QFileDialog.getSaveFileName if operation == "save_profile" else QFileDialog.getOpenFileName
        path, _ = chooser(self, self.tr2("Diagnostic profile", "Диагностический профиль"), "", "BLACK.BOX profile (*.bbprofile.json)")
        if path:
            if operation == "save_profile" and not path.endswith(".bbprofile.json"):
                path += ".bbprofile.json"
            self.bridge.submit(operation, definition=self.document, path=path)

    def open_run(self, folder):
        if self.bridge.submit("open_run", path=folder):
            self.window._navigate("dashboard")
            if hasattr(self.window, "overview_tabs"):
                self.window.overview_tabs.setCurrentWidget(self)

    def fit_graph(self):
        self.canvas.fitInView(self.canvas.scene().itemsBoundingRect().adjusted(-30, -30, 30, 30), Qt.AspectRatioMode.KeepAspectRatio)

    def _busy(self, busy):
        self._run_active = bool(busy and self.bridge.worker is not None and
                                self.bridge.worker.operation in ("start", "resume", "cancel_saved_run"))
        self.canvas.editable = not busy
        for item in self.canvas.items_by_id.values():
            item.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, not busy)
        for widget in (self.open_button, self.save_button, self.validate_button, self.start_button, self.profile,
                       self.profile_parent, self.profile_open, self.profile_save, self.add_button, self.add_repeat,
                       self.apply_button, self.delete_button, self.connect_button, self.title, self.parameter_page,
                       self.override_tools, self.allowed_tools, self.override_seconds, self.profile_seconds,
                       self.budget_seconds, self.parallel, self.allow_effectful, self.source_ids,
                       self.override_nodes, self.allowed_nodes):
            widget.setEnabled(not busy)
        self.pause_button.setEnabled(self._run_active)
        self.cancel_button.setEnabled(self._run_active or self.bridge._paused_run is not None)
        self.resume_button.setEnabled(self._human_pending or not busy and self.snapshot.get("state") == "WAITING_FOR_HUMAN")
        if not busy:
            self.history_changed.emit()

    def _human(self, packet):
        self._human_pending = packet.get("state") == "WAITING_FOR_HUMAN"
        self.grant_button.setEnabled(bool(packet.get("grant_permission")))
        self.resume_button.setEnabled(self._human_pending)
        if packet.get("reason") == "CHOOSE_PROCESS_THEN_CONTINUE":
            identity = packet["target"]
            self.status.setText(self.tr2("Select PID {pid} on Processes, return here and press Continue.",
                "Выберите PID {pid} на странице Процессы, вернитесь сюда и нажмите Продолжить.").format(pid=identity["pid"]))
        else:
            self.status.setText(self.canvas.state_name(packet.get("state", "WAITING_FOR_HUMAN")) + " · " + str(packet.get("reason", packet.get("operation", ""))))

    def _snapshot(self, snapshot):
        self.snapshot = snapshot
        self._folder = snapshot.get("folder") or snapshot.get("output_folder") or self._folder
        state = snapshot.get("state", "UNKNOWN")
        self.status.setText(self.canvas.state_name(state) + " · " + str(snapshot.get("run_id", "")))
        rows = snapshot.get("nodes", [])
        if isinstance(rows, dict):
            rows = [dict(value, node_id=key) for key, value in rows.items()]
        for row in rows:
            item = self.canvas.items_by_id.get(row.get("node_id"))
            if item is not None:
                item.state = row.get("state", row.get("status", "UNKNOWN"))
                item.update()
        if self._selected:
            node = next((n for n in self.document["nodes"] if n["node_id"] == self._selected), None)
            if node:
                self._show_node_details(node)
        self.resume_button.setEnabled(self._human_pending or state == "WAITING_FOR_HUMAN" and not self.bridge.busy)

    def _show_node_details(self, node):
        spec = self.catalog.get(node.get("tool_id"), {})
        lines = [self.tr2("Node", "Узел") + ": " + node["node_id"],
                 self.tr2("Tool", "Инструмент") + ": " + (node.get("tool_id") or node["kind"]),
                 self.tr2("Inputs", "Входы") + ": " + "; ".join(k + " " + "/".join(v["types"]) for k, v in spec.get("inputs", {}).items()),
                 self.tr2("Outputs", "Выходы") + ": " + "; ".join(k + " " + "/".join(v["types"]) for k, v in spec.get("outputs", {}).items()),
                 self.tr2("Rights", "Права") + ": " + str(spec.get("descriptor", {}).get("required_rights", "—")),
                 self.tr2("Effects", "Воздействие") + ": " + str(spec.get("descriptor", {}).get("effects", "—")),
                 self.tr2("Exclusive resources", "Эксклюзивные ресурсы") + ": " + ", ".join(spec.get("resources", []))]
        if not spec.get("available", True):
            lines.append(self.tr2("Unavailable", "Недоступно") + ": " + str(spec.get("unavailable_reason")))
        rows = self.snapshot.get("nodes", [])
        if isinstance(rows, dict):
            rows = [dict(value, node_id=key) for key, value in rows.items()]
        record = next((r for r in rows if r.get("node_id") == node["node_id"]), None)
        if record:
            for key, en, ru in (("state", "State", "Состояние"), ("component_status", "Component status", "Статус компонента"),
                    ("reason_code", "Reason", "Причина"), ("outputs", "Actual outputs / sources / coverage", "Фактические выходы / источники / полнота"),
                    ("run_receipt", "RunReceipt", "RunReceipt"), ("cleanup", "Cleanup", "Очистка"),
                    ("upstream", "Upstream receipts", "Входящие результаты"), ("downstream", "Downstream receipts", "Последующие результаты")):
                if key in record:
                    lines.append("\n" + self.tr2(en, ru) + ":\n" + json.dumps(record[key], ensure_ascii=False, indent=2, default=str)[:18000])
        self.details.setPlainText("\n".join(lines))

    def _received(self, operation, result, error):
        if error:
            self.status.setText(self.tr2("Operation failed: ", "Операция не завершена: ") + error)
            return
        if operation == "catalog":
            self.catalog, self.controls = result["tools"], result["controls"]
            self._populate_palette()
        elif operation in ("open", "open_run", "connect", "open_profile"):
            self.document = result["definition"]
            self._load_controls()
            self._render()
            if operation == "connect":
                self._mark_changed()
            if operation == "open_run":
                self._folder = result["folder"]
                self._snapshot(result["snapshot"])
            elif operation == "open":
                self.snapshot, self._folder = {}, None
                self.status.setText(self.tr2("Opened. No tools were started.", "Открыто. Инструменты не запускались."))
        if isinstance(result, dict) and "validation" in result:
            self.validation = result["validation"]
            self._show_validation()
        if operation in ("save", "save_profile"):
            self.status.setText(self.tr2("Saved to a new file.", "Сохранено в новый файл."))
        self._busy(self.bridge.busy)

    def _load_controls(self):
        self._loading = True
        self.title.setText(self.document["title"])
        profile, budget = self.document["profile"], self.document["budget"]
        profile_id = profile.get("profile_id", "application")
        if self.profile.findData(profile_id) < 0:
            self.profile.addItem(profile_id, profile_id)
        self.profile.setCurrentIndex(self.profile.findData(profile_id))
        self.profile_parent.setCurrentIndex(max(0, self.profile_parent.findData(profile.get("inherits", ""))))
        self.budget_seconds.setValue(budget.get("seconds", 1800))
        self.parallel.setValue(budget.get("max_workers", 2))
        overrides = profile.get("overrides", {})
        self.override_tools.setChecked("allowed_tools" in overrides)
        self.override_seconds.setChecked("max_seconds" in overrides)
        self.profile_seconds.setValue(overrides.get("max_seconds", 1800))
        self.allow_effectful.setChecked(bool(overrides.get("allow_effectful", False)))
        self.source_ids.setText(", ".join(overrides.get("source_ids", [])))
        self.override_nodes.setChecked("allowed_node_ids" in overrides)
        allowed = overrides.get("allowed_tools", list(self.catalog))
        for index in range(self.allowed_tools.count()):
            item = self.allowed_tools.item(index)
            item.setCheckState(Qt.CheckState.Checked if item.data(Qt.ItemDataRole.UserRole) in allowed else Qt.CheckState.Unchecked)
        self._loading = False

    def _show_validation(self):
        value = self.validation
        lines = [self.tr2("Ready", "Готово") + ": " + str(bool(value.get("ready"))),
                 self.tr2("Preview only. No diagnostic operation was executed.", "Только предпросмотр. Диагностические операции не выполнялись.")]
        for key, en, ru in (("errors", "Errors", "Ошибки"), ("warnings", "Limits / warnings", "Ограничения / замечания"),
                ("declared_budgets", "Declared maximum budgets (not measured time)", "Заявленные максимальные бюджеты (не измеренное время)"),
                ("required_rights", "Required rights", "Требуемые права"), ("resources", "Resources", "Ресурсы"),
                ("effective_profile", "Effective profile and overrides", "Итоговый профиль и переопределения")):
            lines.append("\n" + self.tr2(en, ru) + ":\n" + json.dumps(value.get(key, []), ensure_ascii=False, indent=2, default=str))
        self.effective.setPlainText("\n".join(lines))
        self.inspector_tabs.setCurrentIndex(1)
        self.status.setText(self.tr2("Ready to start explicitly.", "Готово к явному запуску.") if value.get("ready") else
                            self.tr2("Validation found issues. Edit and check again.", "Проверка выявила ошибки. Исправьте и проверьте снова."))

    def _populate_palette(self):
        self._loading = True
        selected = self.palette.currentItem().data(Qt.ItemDataRole.UserRole) if self.palette.currentItem() else None
        self.palette.clear()
        self.allowed_tools.clear()
        for tool in (*self.catalog, *self.controls):
            descriptor = self.catalog.get(tool, {})
            label = self.canvas.tool_name(tool)
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, tool)
            item.setToolTip(tool + ("\n" + str(descriptor.get("unavailable_reason")) if not descriptor.get("available", True) else ""))
            if not descriptor.get("available", True):
                item.setForeground(QColor("#736b7e"))
            self.palette.addItem(item)
            if tool == selected:
                self.palette.setCurrentItem(item)
            if tool in self.catalog:
                allowed = QListWidgetItem(label)
                allowed.setData(Qt.ItemDataRole.UserRole, tool)
                allowed.setFlags(allowed.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                allowed.setCheckState(Qt.CheckState.Checked)
                self.allowed_tools.addItem(allowed)
        self._loading = False
        self._load_controls()
        self._render()

    def retranslate(self):
        def capture(widget):
            if isinstance(widget, OptionalParameterEditor):
                return (widget.enabled.isChecked(), capture(widget.field))
            if isinstance(widget, ConditionParameterEditor):
                return widget.draft()
            if isinstance(widget, ObjectParameterEditor):
                return {key: (enabled.isChecked(), capture(field)) for key, (enabled, field) in widget.fields.items()}
            if isinstance(widget, QLineEdit):
                return widget.text()
            if isinstance(widget, QComboBox):
                return widget.currentData()
            if isinstance(widget, QCheckBox):
                return widget.isChecked()
            return widget.value()
        def restore(widget, value):
            if isinstance(widget, OptionalParameterEditor):
                widget.enabled.setChecked(value[0])
                restore(widget.field, value[1])
                return
            if isinstance(widget, ConditionParameterEditor):
                widget.restore_draft(value)
                return
            if isinstance(widget, ObjectParameterEditor):
                for key, (enabled, field) in widget.fields.items():
                    if key in value:
                        enabled.setChecked(value[key][0])
                        restore(field, value[key][1])
            elif isinstance(widget, QLineEdit):
                widget.setText(value)
            elif isinstance(widget, QComboBox):
                widget.setCurrentIndex(max(0, widget.findData(value)))
            elif isinstance(widget, QCheckBox):
                widget.setChecked(value)
            else:
                widget.setValue(value)
        drafts = {key: capture(widget) for key, widget in self._fields.items()}
        for widget, en, ru in self._labels:
            # Dynamic parameter rows are deleted when selecting another node.
            try:
                widget.setText(self.tr2(en, ru))
                widget.setAccessibleName(widget.text())
            except RuntimeError:
                pass
        self.canvas.language = self.window.language
        self.source_ids.setToolTip(self.tr2(
            "Use the saved source's exact SHA-256 shown in node outputs. Sessions use their aggregate fingerprint. "
            "This does not select or authorize a live PID/creation FILETIME.",
            "Укажите точный SHA-256 сохранённого источника из выходов узла. Для сеанса используется совокупный хеш. "
            "Это не выбирает и не разрешает живой PID/FILETIME создания."))
        for index, pair in enumerate((("All Windows", "Вся Windows"), ("Selected application", "Выбранное приложение"),
                                      ("Specific investigation", "Конкретное расследование"))):
            self.profile.setItemText(index, self.tr2(*pair))
            self.profile_parent.setItemText(index + 1, self.tr2(*pair))
        for index, pair in enumerate((("Parameters", "Параметры"), ("Preview", "Предпросмотр"), ("Details", "Подробности"))):
            self.inspector_tabs.setTabText(index, self.tr2(*pair))
        if self.catalog:
            self._populate_palette()
        if self._selected:
            self.select_node(self._selected)
            for key, widget in self._fields.items():
                if key in drafts:
                    restore(widget, drafts[key])
        if self.validation:
            self._show_validation()
        self._busy(self.bridge.busy)
        self.grant_button.setEnabled(bool(self.bridge._native and self.bridge._native.get("awaiting_uac")))


class ChainHistoryPanel(QWidget):
    """Passive Reports route. Loading a past run never starts or resumes it."""
    def __init__(self, window, builder):
        super().__init__(window)
        self.window, self.builder, self.bridge = window, builder, builder.bridge
        self.rows, self._labels = [], []
        layout = QVBoxLayout(self)
        self.title = QLabel()
        self.title.setWordWrap(True)
        layout.addWidget(self.title)
        controls = ActionGrid()
        self.refresh = QPushButton()
        self.refresh.setObjectName("chainHistoryRefresh")
        self.refresh.clicked.connect(lambda: self.bridge.submit("history", root=str(builder.root)))
        self.open = QPushButton()
        self.open.setObjectName("chainHistoryOpen")
        self.open.clicked.connect(self.open_selected)
        self.export_json = QPushButton()
        self.export_json.setObjectName("chainHistoryExportJSON")
        self.export_json.clicked.connect(lambda: self.export_selected("json"))
        self.export_html = QPushButton()
        self.export_html.setObjectName("chainHistoryExportHTML")
        self.export_html.clicked.connect(lambda: self.export_selected("html"))
        for widget in (self.refresh, self.open, self.export_json, self.export_html):
            controls.addWidget(widget)
        layout.addLayout(controls)
        self.table = QTableWidget(0, 3)
        self.table.setObjectName("chainRunHistory")
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setMaximumHeight(220)
        self.table.cellDoubleClicked.connect(lambda *_: self.open_selected())
        layout.addWidget(self.table)
        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.status)
        self.bridge.result_ready.connect(self._received)
        self.bridge.busy_changed.connect(self._busy)
        self.retranslate()

    def selected(self):
        row = self.table.currentRow()
        return self.rows[row] if 0 <= row < len(self.rows) else None

    def open_selected(self):
        row = self.selected()
        if row:
            self.builder.open_run(row["folder"])

    def export_selected(self, format):
        row = self.selected()
        if row is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, self.builder.tr2("Export workflow history", "Экспорт истории цепочки"), "",
                                             ("JSON (*.json)" if format == "json" else "HTML (*.html)"))
        if path:
            self.bridge.submit("export", folder=row["folder"], path=path, format=format)

    def _busy(self, busy):
        for widget in (self.refresh, self.open, self.export_json, self.export_html):
            widget.setEnabled(not busy)

    def _received(self, operation, result, error):
        if operation not in ("history", "export"):
            return
        if error:
            self.status.setText(error)
            return
        if operation == "history":
            self.rows = result
            self.table.setRowCount(len(result))
            for index, row in enumerate(result):
                for column, value in enumerate((row["title"], row["run_id"], self.builder.canvas.state_name(row["state"]))):
                    self.table.setItem(index, column, QTableWidgetItem(str(value)))
            self.status.setText(self.builder.tr2("Open history to inspect it; continuation is a separate action.",
                                                "Открытие показывает историю; продолжение запускается отдельным действием."))
        else:
            self.status.setText(self.builder.tr2("Export completed with independent read-back.", "Экспорт завершён с независимым повторным чтением."))

    def retranslate(self):
        tr = self.builder.tr2
        self.title.setText(tr("Diagnostic chain history · saved runs and their actual cleanup", "История диагностических цепочек · сохранённые запуски и фактическая очистка"))
        for widget, en, ru in ((self.refresh, "Refresh chain history", "Обновить историю цепочек"),
                (self.open, "Open selected run", "Открыть выбранный запуск"),
                (self.export_json, "Export JSON…", "Экспорт JSON…"), (self.export_html, "Export HTML…", "Экспорт HTML…")):
            widget.setText(tr(en, ru))
            widget.setAccessibleName(widget.text())
        self.table.setHorizontalHeaderLabels([tr("Chain", "Цепочка"), "Run ID", tr("State", "Состояние")])
