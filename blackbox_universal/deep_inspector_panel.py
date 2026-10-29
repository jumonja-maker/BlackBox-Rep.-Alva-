"""Explicit deep inspection and controlled actions inside the existing Overview."""
from __future__ import annotations

import json
import hashlib
import math
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QFormLayout,
    QHeaderView, QInputDialog, QLabel, QLineEdit, QMessageBox,
    QPlainTextEdit, QPushButton, QSpinBox, QStackedWidget, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from .action_grid import ActionGrid
from .deep_inspector_bridge import DeepInspectorBridge


SECTIONS = (
    ("processes", "Processes", "Процессы"),
    ("modules", "Modules", "Модули"),
    ("threads", "Threads", "Потоки"),
    ("handles", "Handles", "Дескрипторы"),
    ("memory", "Memory", "Память"),
    ("network", "Network", "Сеть"),
    ("disk", "Disk", "Диск"),
    ("debug", "Debug", "Отладка"),
    ("timeline", "Timeline", "История действий"),
)

ACTION_LABELS = {
    "processes": ("Refresh process tree", "Обновить дерево процессов"),
    "modules": ("Inspect loaded modules", "Исследовать загруженные модули"),
    "threads": ("Inspect threads", "Исследовать потоки"),
    "thread_stacks": ("Capture current thread stacks…", "Снять текущие стеки потоков…"),
    "wait_chains": ("Inspect wait chains", "Исследовать цепочки ожиданий"),
    "handles": ("Inspect handles", "Исследовать дескрипторы"),
    "memory_map": ("Inspect address space", "Исследовать адресное пространство"),
    "memory_read": ("Read selected memory", "Прочитать выбранный участок памяти"),
    "memory.write": ("Write selected bytes…", "Изменить выбранные байты…"),
    "memory.rollback": ("Attempt verified restore…", "Попытаться восстановить с проверкой…"),
    "network": ("Inspect TCP / UDP connections", "Исследовать соединения TCP / UDP"),
    "disk": ("Inspect process I/O and files", "Исследовать I/O процесса и файлы"),
    "debug.attach": ("Attach debugger…", "Подключить отладчик…"),
    "debug.pause": ("Pause execution…", "Приостановить выполнение…"),
    "debug.continue": ("Continue execution…", "Продолжить выполнение…"),
    "debug.step": ("Single step…", "Выполнить один шаг…"),
    "debug.context": ("Read stopped thread context", "Прочитать контекст остановленного потока"),
    "debug.detach": ("Detach debugger…", "Отключить отладчик…"),
    "debug.breakpoints": ("Show breakpoints", "Показать точки останова"),
    "debug.breakpoint.add": ("Add breakpoint…", "Установить точку останова…"),
    "debug.breakpoint.disable": ("Disable breakpoint…", "Отключить точку останова…"),
    "debug.breakpoint.remove": ("Remove breakpoint…", "Удалить точку останова…"),
    "thread.suspend": ("Suspend selected thread…", "Приостановить выбранный поток…"),
    "thread.resume": ("Release own thread suspension…", "Снять собственную приостановку потока…"),
    "timeline": ("Read action journal", "Показать журнал действий"),
    "snapshot": ("Capture state", "Снять состояние"),
    "compare": ("Compare before / after", "Сравнить до / после"),
    "dump": ("Create diagnostic dump…", "Создать диагностический дамп…"),
    "trace_evidence": ("Read historical trace evidence…", "Прочитать данные сохранённой трассы…"),
    "dump_inspect": ("Inspect saved dump…", "Исследовать сохранённый дамп…"),
    "dump_read_memory": ("Read memory from saved dump…", "Прочитать память из сохранённого дампа…"),
    "symbols_verify": ("Verify local PE / PDB…", "Проверить локальные PE / PDB…"),
    "profile.etw": ("Record system-wide ETW…", "Записать системную ETW-трассу…"),
}

STATUS_TEXT = {
    "AVAILABLE": ("Available", "Доступно"),
    "ADMIN_REQUIRED": ("Additional Windows permissions can be requested", "Можно запросить дополнительные права Windows"),
    "UAC_CANCELLED": ("UAC was cancelled; ordinary observation remains available", "UAC отменён; обычное наблюдение доступно"),
    "ACCESS_DENIED": ("Windows denied this operation", "Windows отказала в выполнении операции"),
    "PROTECTED_PROCESS": ("Windows process protection restricts this operation", "Операцию ограничивает защита процесса Windows"),
    "PROCESS_CHANGED": ("The selected process ended or was replaced; select it again", "Выбранный процесс завершён или заменён; выберите его заново"),
    "ALREADY_DEBUGGED": ("Another debugger is already attached", "Уже подключён другой отладчик"),
    "OPERATION_FAILED": ("The operation failed; inspect the reported error", "Технический отказ; изучите указанную ошибку"),
    "INCOMPLETE_EVIDENCE": ("Evidence is incomplete; review limitations", "Данные неполны; ознакомьтесь с ограничениями"),
    "COMPLETED": ("Completed", "Завершено"),
    "RECOVERY_UNCONFIRMED": ("Recovery is not confirmed; check the target before further actions", "Восстановление не подтверждено; проверьте цель перед дальнейшими действиями"),
    "CANCELLED": ("Cancelled", "Отменено"),
    "TIMED_OUT": ("The operation exceeded its time limit", "Превышено ограничение времени операции"),
    "UNSUPPORTED_PLATFORM": ("This operation requires Windows", "Для этой операции требуется Windows"),
    "SESSION_EXPIRED": ("The diagnostic session expired; start a new scoped session", "Срок диагностической сессии истёк; начните новую ограниченную сессию"),
    "CONFIRMATION_REQUIRED": ("Explicit confirmation is required", "Требуется явное подтверждение"),
}

FIELD_LABELS = {
    "field": ("Field", "Поле"), "value": ("Value", "Значение"),
    "name": ("Name", "Имя"), "path": ("Path", "Путь"),
    "pid": ("PID", "PID"), "ppid": ("Parent PID", "PID родителя"),
    "tid": ("TID", "TID"), "owner": ("Owner", "Владелец"),
    "command_line": ("Command line", "Командная строка"),
    "identity": ("Process instance", "Экземпляр процесса"),
    "created_100ns": ("Creation FILETIME", "Время создания FILETIME"),
    "thread_created_100ns": ("Thread creation FILETIME", "Создание потока FILETIME"),
    "base": ("Base address", "Базовый адрес"), "address": ("Address", "Адрес"),
    "size": ("Size, bytes", "Размер, байт"), "protection": ("Protection", "Защита"),
    "state": ("State", "Состояние"), "status": ("Status", "Статус"),
    "type": ("Type", "Тип"), "type_name": ("Region type", "Тип региона"),
    "state_name": ("Region state", "Состояние региона"),
    "file_version": ("File version", "Версия файла"), "sha256": ("SHA-256", "SHA-256"),
    "base_priority": ("Base priority", "Базовый приоритет"),
    "operation": ("Operation", "Операция"), "impact": ("Impact", "Воздействие"),
    "required_rights": ("Required rights", "Необходимые права"),
    "next_action": ("Next action", "Следующее действие"),
    "source": ("Source", "Источник"), "reason": ("Reason", "Причина"),
    "family": ("Address family", "Семейство адресов"), "protocol": ("Protocol", "Протокол"),
    "local": ("Local address", "Локальный адрес"), "remote": ("Remote address", "Удалённый адрес"),
    "process_instance": ("Recorded instance", "Записанный экземпляр"),
    "observed_tree_depth": ("Observed tree depth", "Глубина наблюдаемого дерева"),
    "allocation_base": ("Allocation base", "База выделения"),
    "allocation_protection": ("Allocation protection", "Защита выделения"),
    "mapped_file_path": ("Backing file (NT path)", "Связанный файл (NT-путь)"),
    "mapped_file_status": ("File association status", "Статус связи с файлом"),
    "association_kind": ("Region association", "Принадлежность региона"),
    "image_name": ("Backing image name", "Имя связанного образа"),
    "mapped_file_source": ("File association source", "Источник связи с файлом"),
    "mapped_file_winerror": ("File query WinError", "WinError запроса файла"),
    "handle": ("Handle", "Дескриптор"), "type_index": ("Object type index", "Индекс типа объекта"),
    "granted_access": ("Granted access mask", "Маска полученного доступа"),
    "attributes": ("Attributes", "Атрибуты"), "name_status": ("Name lookup status", "Статус получения имени"),
    "kernel_time_100ns": ("Kernel time, 100 ns", "Время ядра, 100 нс"),
    "user_time_100ns": ("User time, 100 ns", "Пользовательское время, 100 нс"),
    "captured_100ns": ("Capture FILETIME", "Время снятия FILETIME"),
    "frames": ("Stack frames", "Кадры стека"), "context": ("Thread context", "Контекст потока"),
    "kind": ("Observation type", "Тип наблюдения"),
    "observed_suspend_count": ("Observed suspend count", "Наблюдаемый счётчик приостановки"),
    "owned_suspension_count": ("Own suspensions", "Собственные приостановки"),
    "historical_etw_stack": ("Historical ETW stack", "Исторический стек ETW"),
    "bytes_sent": ("Sent bytes", "Передано байт"), "bytes_received": ("Received bytes", "Получено байт"),
    "event_name": ("Recorded event", "Записанное событие"), "event_id": ("Event ordinal", "Номер события"),
    "trace_relative_ms": ("Trace time, ms", "Время трассы, мс"),
    "event_transfer_bytes": ("Event transfer, bytes", "Объём события, байт"),
    "latency_ms": ("Reported duration, ms", "Заявленная длительность, мс"),
    "latency_status": ("Duration evidence", "Основание длительности"),
    "trace_interval_start_ms": ("Derived interval start, ms", "Вычисленное начало интервала, мс"),
    "trace_interval_end_ms": ("Interval end, ms", "Конец интервала, мс"),
    "fields": ("Recorded fields", "Записанные поля"),
    "typed_observation": ("Typed observation", "Типизированное наблюдение"),
    "frame_address": ("Selected frame PC", "PC выбранного кадра"),
    "image_base": ("Recorded image base", "Записанная база образа"),
    "image_size": ("Image size", "Размер образа"),
    "module_name": ("Module name", "Имя модуля"),
    "snapshot_pe": ("Captured PE identity", "Идентичность снятого PE"),
    "snapshot_binding": ("Snapshot binding", "Привязка к снимку"),
    "inspection_scope": ("Observation scope", "Область наблюдения"),
}


def _plain_label():
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    return label


class OverviewInspectorPanel(QWidget):
    closed = Signal(object)
    recovery_required = Signal(object)

    def __init__(self, window, *, bridge=None):
        super().__init__(window)
        self.window = window
        self.setObjectName("deepInspectionPanel")
        self.bridge = bridge or DeepInspectorBridge(self)
        self._labels = []
        self._action_buttons = {}
        self._tables = {}
        self._section_results = {}
        self._last_result = None
        self._last_request = None
        self._pending_retry = None
        self._before_id = None
        self._after_id = None
        self._target_name = ""
        self._row_details = None
        self._trace_request = None
        self._section_trace_requests = {}
        self._dump_path = None
        self._captured_trace = None
        self._debug_state = "IDLE"
        self._stack_context = None
        self._request_section = "processes"
        self._build()
        self.bridge.result_ready.connect(self._receive)
        self.bridge.busy_changed.connect(self._refresh_controls)
        self.bridge.target_changed.connect(self._target_changed)
        self.bridge.idle.connect(self._idle)
        self.bridge.closed.connect(self.closed.emit)
        self.bridge.recovery_required.connect(self.recovery_required.emit)
        self.retranslate()

    def tr2(self, en, ru):
        return ru if self.window.language == "RU" else en

    def _translated(self, widget, en, ru):
        self._labels.append((widget, en, ru))
        widget.setText(self.tr2(en, ru))
        return widget

    def _button(self, layout, key, en, ru, callback):
        button = self._translated(QPushButton(), en, ru)
        button.setObjectName("deep_" + key.replace(".", "_"))
        button.clicked.connect(callback)
        layout.addWidget(button)
        self._action_buttons[key] = button
        return button

    def _action(self, layout, operation, *, parameters=None):
        en, ru = ACTION_LABELS[operation]
        return self._button(layout, operation, en, ru,
                            lambda: self._request(operation, parameters))

    def _field(self, layout, key, en, ru, *, value=""):
        field = QLineEdit(value)
        field.setObjectName("deepField_" + key)
        field.setMaximumWidth(500)
        label = self._translated(_plain_label(), en, ru)
        layout.addRow(label, field)
        return field

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.target_label = _plain_label()
        self.mode_label = self._translated(_plain_label(),
            "OBSERVE · INSPECT · INTERVENE — actions run only after your request.",
            "OBSERVE · INSPECT · INTERVENE — действия выполняются только по вашему запросу.")
        layout.addWidget(self.target_label)
        layout.addWidget(self.mode_label)
        self.status_label = _plain_label()
        self.status_label.setObjectName("deepInspectionStatus")
        self.admin_label = _plain_label()
        self.admin_label.setObjectName("deepAdminStatus")
        layout.addWidget(self.status_label)
        layout.addWidget(self.admin_label)
        common = ActionGrid(max_columns=3)
        self._button(common, "capabilities", "Check available operations", "Проверить доступные операции", self._capabilities)
        self._button(common, "before", "Capture BEFORE", "Снять ДО", lambda: self._request("snapshot", tag="before"))
        self._button(common, "after", "Capture AFTER", "Снять ПОСЛЕ", lambda: self._request("snapshot", tag="after"))
        self._action(common, "compare", parameters=lambda: {"before_id": self._before_id, "after_id": self._after_id})
        self.cancel_button = self._button(common, "cancel", "Cancel operation", "Отменить операцию", self.bridge.cancel)
        self.end_admin_button = self._button(common, "end_admin", "End administrator session", "Завершить сеанс администратора", self.bridge.end_admin)
        self._button(common, "retry_cleanup", "Retry diagnostic cleanup", "Повторить завершение диагностики", self.bridge.retry_cleanup)
        self._button(common, "profiling", "Profiling / EventPipe / ETW…", "Профилирование / EventPipe / ETW…", self._open_profiling)
        layout.addLayout(common)
        self.elevate_button = QPushButton()
        self._translated(self.elevate_button, "REQUEST ADMINISTRATOR PERMISSION…", "ЗАПРОСИТЬ ПРАВА АДМИНИСТРАТОРА…")
        self.elevate_button.setObjectName("deepRequestElevation")
        self.elevate_button.clicked.connect(self._elevate)
        self.elevate_button.hide()
        layout.addWidget(self.elevate_button)
        self.section = QComboBox()
        self.section.setObjectName("deepInspectionSection")
        for key, en, ru in SECTIONS:
            self.section.addItem(self.tr2(en, ru), key)
        self.section.setAccessibleName("Deep inspection section / Раздел глубокого исследования")
        layout.addWidget(self.section)
        self.pages = QStackedWidget()
        self.pages.setObjectName("deepInspectionSections")
        layout.addWidget(self.pages)
        for key, en, ru in SECTIONS:
            page = QWidget()
            page_layout = QVBoxLayout(page)
            page_layout.setContentsMargins(0, 0, 0, 0)
            actions = ActionGrid(max_columns=2)
            page_layout.addLayout(actions)
            self._build_section(key, page_layout, actions)
            table = QTableWidget(0, 2)
            table.setObjectName("deepTable_" + key)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            table.horizontalHeader().setStretchLastSection(True)
            table.setMinimumHeight(180)
            table.setMaximumHeight(350)
            table.itemSelectionChanged.connect(lambda section=key: self._select_row(section))
            page_layout.addWidget(table)
            self._tables[key] = table
            if key == "threads":
                self._build_stack_frames(page_layout)
            self.pages.addWidget(page)
        self.section.currentIndexChanged.connect(self.pages.setCurrentIndex)
        self.section.currentIndexChanged.connect(self._section_changed)
        self.summary = _plain_label()
        self.summary.setObjectName("deepResultSummary")
        layout.addWidget(self.summary)
        self.details_toggle = self._translated(QCheckBox(), "Show source fields and technical details", "Показать поля источника и технические сведения")
        self.details = QPlainTextEdit()
        self.details.setObjectName("deepResultDetails")
        self.details.setReadOnly(True)
        self.details.setMinimumHeight(160)
        self.details.setMaximumHeight(280)
        self.details.hide()
        self.details_toggle.toggled.connect(self.details.setVisible)
        layout.addWidget(self.details_toggle)
        layout.addWidget(self.details)
        self.privacy = self._translated(_plain_label(),
            "Memory and dump contents stay local and are excluded from the ordinary action-journal export. Historical trace events do not establish a link to a live process by PID alone.",
            "Содержимое памяти и дампов остаётся локальным и не входит в обычный экспорт журнала действий. Один PID не доказывает связь событий старой трассы с живым процессом.")
        layout.addWidget(self.privacy)

    def _build_stack_frames(self, layout):
        self.stack_source_label = _plain_label()
        self.stack_source_label.setObjectName("deepStackSource")
        layout.addWidget(self.stack_source_label)
        self.stack_frames = QTableWidget(0, 7)
        self.stack_frames.setObjectName("deepStackFrames")
        self.stack_frames.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.stack_frames.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.stack_frames.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.stack_frames.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.stack_frames.horizontalHeader().setStretchLastSection(True)
        self.stack_frames.setMinimumHeight(160)
        self.stack_frames.setMaximumHeight(280)
        self.stack_frames.itemSelectionChanged.connect(self._select_stack_frame)
        layout.addWidget(self.stack_frames)
        actions = ActionGrid(max_columns=1)
        self._button(actions, "stack_frame_module", "Open selected frame's module", "Открыть модуль выбранного кадра", self._open_stack_module)
        layout.addLayout(actions)

    def _clear_stack_frames(self):
        self._stack_context = None
        self.stack_frames.blockSignals(True)
        self.stack_frames.setRowCount(0)
        self.stack_frames.blockSignals(False)
        self.stack_source_label.setText(self.tr2(
            "Select a captured thread or historical event to inspect its stack frames.",
            "Выберите снятый поток или историческое событие для просмотра кадров стека."))

    @staticmethod
    def _address_text(value):
        return hex(value) if type(value) is int and 0 <= value < 2**64 else str(value) if value is not None else "—"

    def _show_stack_frames(self, row):
        self._clear_stack_frames()
        frames = row.get("frames")
        if not isinstance(frames, list):
            return
        historical = row.get("source") == "HISTORICAL_TRACE"
        current = (row.get("kind") == "LIVE_PSS_THREAD_CONTEXT" and row.get("historical_etw_stack") is False
                   and type(row.get("tid")) is int and row["tid"] > 0
                   and type(row.get("created_100ns")) is int and row["created_100ns"] > 0)
        if not historical and not current:
            return
        self._stack_context = {"generation": self.bridge.generation,
                               "kind": "HISTORICAL_TRACE" if historical else "CURRENT_PSS_CAPTURE",
                               "tid": row.get("tid"), "thread_created_100ns": None if historical else row.get("created_100ns"),
                               "captured_100ns": row.get("captured_100ns"),
                               "pid": row.get("pid") if historical else self.bridge.target[0] if self.bridge.target else None,
                               "process_instance": row.get("process_instance") if historical else None,
                               "time_ms": row.get("time_ms") if historical else None,
                               "unwind_completeness": row.get("unwind_completeness", "NOT_PROVEN")}
        target = self._section_results.get("threads", {}).get("target")
        if not historical and isinstance(target, dict):
            self._stack_context["process_identity"] = dict(target)
        label = self.tr2("Historical trace stack — live thread association NOT_ESTABLISHED",
                         "Исторический стек трассы — связь с живым потоком НЕ УСТАНОВЛЕНА") if historical else self.tr2(
                         "Current thread stack captured with PSS — completeness NOT_PROVEN",
                         "Текущий стек потока, снятый PSS — полнота НЕ ДОКАЗАНА")
        label += f"\nTID {row.get('tid', '—')}"
        if historical:
            label += self.tr2(" · recorded instance ", " · записанный экземпляр ") + str(row.get("process_instance", "—"))
            label += f" · {row.get('time_ms', '—')} " + self.tr2("ms", "мс")
        else:
            label += " · FILETIME " + str(row.get("created_100ns", "—"))
            label += self.tr2(" · capture ", " · снято ") + str(row.get("captured_100ns", "—"))
        shown = min(len(frames), 128)
        omitted = max(0, len(frames) - shown) + max(0, int(row.get("frames_omitted", 0)))
        label += self.tr2("\nDisplayed frames: ", "\nПоказано кадров: ") + f"{shown}"
        if omitted:
            label += self.tr2(" · omitted: ", " · пропущено: ") + str(omitted)
        self.stack_source_label.setText(label)
        self.stack_frames.blockSignals(True)
        self.stack_frames.setRowCount(shown)
        for number, frame in enumerate(frames[:shown]):
            if not isinstance(frame, dict):
                frame = {"address": None}
            module = frame.get("module")
            module_name = module.get("module_name") if isinstance(module, dict) else module
            symbol = frame.get("symbol") if isinstance(frame.get("symbol"), dict) else {}
            name = frame.get("name") if historical else symbol.get("name")
            location = symbol.get("source_location")
            source = "HISTORICAL_TRACE_UNVERIFIED" if historical else frame.get("symbol_binding", "PSS_RAW_ADDRESS")
            values = (number, self._address_text(frame.get("address")), module_name,
                      self._address_text(frame.get("rva")), name, location, source)
            for column, value in enumerate(values):
                text = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value) if value is not None else "—"
                item = QTableWidgetItem(text[:2000])
                item.setData(Qt.ItemDataRole.UserRole, frame)
                self.stack_frames.setItem(number, column, item)
        self.stack_frames.blockSignals(False)

    def _selected_stack_frame(self):
        if (self._stack_context is None or self._stack_context.get("generation") != self.bridge.generation):
            return None
        item = self.stack_frames.item(self.stack_frames.currentRow(), 0)
        frame = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return frame if isinstance(frame, dict) else None

    def _select_stack_frame(self):
        frame = self._selected_stack_frame()
        if frame is None:
            self._refresh_controls()
            return
        self.details.setPlainText(self._technical_text({"stack_context": self._stack_context, "frame": frame}))
        if self._stack_context["kind"] == "CURRENT_PSS_CAPTURE":
            address = frame.get("address")
            if type(address) is int and 0 < address < 2**64:
                self.memory_address.setText(hex(address))
                self.breakpoint_address.setText(hex(address))
            base = frame.get("module_base")
            if type(base) is int and 0 < base < 2**64:
                self.stack_module_base.setText(hex(base))
            else:
                self.stack_module_base.clear()
        else:
            for field in (self.memory_address, self.breakpoint_address, self.stack_module_base):
                field.clear()
        self._refresh_controls()

    def _stack_module(self):
        frame = self._selected_stack_frame()
        if frame is None:
            return None
        if self._stack_context["kind"] == "HISTORICAL_TRACE":
            from blackbox_core.decoder_modules import validate_module_frame
            try:
                module = validate_module_frame(self._stack_context, frame)
            except (ValueError, TypeError, KeyError):
                return None
            if module is not None:
                return dict(module, inspection_scope="HISTORICAL_TRACE_MODULE", frame_address=frame.get("address"))
            return None
        module = frame.get("module_identity")
        if (isinstance(module, dict) and module.get("source") == "SAME_PSS_CAPTURE"
                and module.get("snapshot_binding") == "PSS_CLONE_PE_IDENTITY_AND_LAYOUT_MATCH"
                and module.get("base") == frame.get("module_base")
                and isinstance(module.get("snapshot_pe"), dict)
                and type(module.get("base")) is int and type(module.get("size")) is int
                and type(frame.get("address")) is int
                and 0 < module["base"] <= frame["address"] < module["base"] + module["size"] <= 2**64
                and frame.get("rva") == frame["address"] - module["base"]
                and module["snapshot_pe"].get("image_size") == module["size"]):
            return dict(module, inspection_scope="CURRENT_PSS_CAPTURE", frame_address=frame["address"])
        return None

    def _open_stack_module(self):
        module = self._stack_module()
        if module is None:
            return
        result = {"operation": "frame_module", "status": "INCOMPLETE_EVIDENCE",
                  "source": self._stack_context["kind"],
                  "data": {"rows": [module], "stack_context": dict(self._stack_context)},
                  "limitations": [self.tr2(
                      "Module identity belongs to the selected stack capture; this is not a fresh module inventory.",
                      "Идентичность модуля относится к выбранному снятию стека; это не новая инвентаризация модулей.")]}
        self._section_results["modules"] = result
        self.section.setCurrentIndex(self.section.findData("modules"))
        self._tables["modules"].selectRow(0)

    def _build_section(self, key, layout, actions):
        if key == "processes":
            self._action(actions, "processes")
        elif key == "modules":
            self.module_hashes = self._translated(QCheckBox(), "Compute local module SHA-256", "Вычислять SHA-256 локальных модулей")
            layout.addWidget(self.module_hashes)
            self._action(actions, "modules", parameters=lambda: {"hash_files": self.module_hashes.isChecked()})
            self._button(actions, "symbols_verify", *ACTION_LABELS["symbols_verify"], self._symbols)
            self._button(actions, "module_decoder", "Open Trace Decoder", "Открыть декодер трасс", self._open_decoder)
        elif key == "threads":
            for operation in ("threads", "thread_stacks", "wait_chains"):
                self._action(actions, operation, parameters=self._stack_parameters if operation == "thread_stacks" else None)
            fields = QFormLayout()
            self.thread_tid = self._field(fields, "thread_tid", "Selected TID", "Выбранный TID")
            self.thread_created = self._field(fields, "thread_created", "Thread creation FILETIME", "Время создания потока FILETIME")
            self.stack_module_base = self._field(fields, "stack_module_base", "Optional module base for PDB", "Необязательная база модуля для PDB")
            self.stack_pdb = self._field(fields, "stack_pdb", "Optional local PDB path", "Необязательный путь локального PDB")
            layout.addLayout(fields)
            self._button(actions, "stack_pdb", "Choose local stack PDB…", "Выбрать локальный PDB для стека…", self._choose_stack_pdb)
            self._action(actions, "thread.suspend", parameters=lambda: self._thread_parameters(required=True))
            self._action(actions, "thread.resume", parameters=lambda: self._thread_parameters(required=True))
            self._button(actions, "historical_threads", "Read historical stacks / waits…", "Прочитать исторические стеки / ожидания…", self._trace)
        elif key == "handles":
            self._action(actions, "handles")
        elif key == "memory":
            self._action(actions, "memory_map")
            fields = QFormLayout()
            self.memory_address = self._field(fields, "address", "Address (0x… or decimal)", "Адрес (0x… или десятичный)")
            self.memory_size = QSpinBox()
            self.memory_size.setRange(1, 65536)
            self.memory_size.setValue(256)
            size_label = self._translated(_plain_label(), "Read size, bytes", "Размер чтения, байт")
            fields.addRow(size_label, self.memory_size)
            self.expected_bytes = self._field(fields, "expected", "Expected original bytes (hex, up to 4096 bytes)", "Ожидаемые исходные байты (hex, до 4096 байт)")
            self.new_bytes = self._field(fields, "replacement", "Replacement bytes (hex, up to 4096 bytes)", "Новые байты (hex, до 4096 байт)")
            self.expected_bytes.setMaxLength(131072)
            self.new_bytes.setMaxLength(131072)
            self.write_id = self._field(fields, "write_id", "Recorded write ID to restore", "Идентификатор записи для восстановления")
            layout.addLayout(fields)
            self._action(actions, "memory_read", parameters=self._memory_read_parameters)
            self._action(actions, "memory.write", parameters=self._memory_write_parameters)
            self._action(actions, "memory.rollback", parameters=lambda: {"change_id": self._required(self.write_id)})
            self._button(actions, "dump", *ACTION_LABELS["dump"], self._dump)
            self._button(actions, "dump_inspect", *ACTION_LABELS["dump_inspect"], self._inspect_dump)
            self._button(actions, "dump_read_memory", *ACTION_LABELS["dump_read_memory"], self._read_dump_memory)
        elif key == "network":
            self._action(actions, "network")
            self._button(actions, "historical_network", "Read recorded network events…", "Прочитать записанные сетевые события…", self._trace)
            self._button(actions, "historical_network_interval", "Open selected trace interval", "Открыть выбранный интервал трассы", self._open_trace_interval)
        elif key == "disk":
            self._action(actions, "disk")
            self._button(actions, "historical_disk", "Read recorded file operations…", "Прочитать записанные файловые операции…", self._trace)
            self._button(actions, "historical_disk_interval", "Open selected trace interval", "Открыть выбранный интервал трассы", self._open_trace_interval)
        elif key == "debug":
            self.debug_state_label = _plain_label()
            self.debug_state_label.setText(self.tr2("DEBUG: ", "ОТЛАДКА: ") + self._debug_state)
            layout.addWidget(self.debug_state_label)
            for operation in ("debug.attach", "debug.pause", "debug.continue", "debug.detach", "debug.breakpoints"):
                self._action(actions, operation)
            fields = QFormLayout()
            self.debug_tid = self._field(fields, "debug_tid", "Stopped TID", "Остановленный TID")
            self.debug_created = self._field(fields, "debug_created", "Thread creation FILETIME", "Время создания потока FILETIME")
            self.breakpoint_address = self._field(fields, "breakpoint_address", "Breakpoint address", "Адрес точки останова")
            self.breakpoint_id = self._field(fields, "breakpoint_id", "Breakpoint ID", "Идентификатор точки останова")
            layout.addLayout(fields)
            self._action(actions, "debug.context", parameters=self._debug_thread_parameters)
            self._action(actions, "debug.step", parameters=self._debug_thread_parameters)
            self._action(actions, "debug.breakpoint.add", parameters=lambda: {"address": self._integer(self.breakpoint_address)})
            for operation in ("debug.breakpoint.disable", "debug.breakpoint.remove"):
                self._action(actions, operation, parameters=lambda: {"breakpoint_id": self._required(self.breakpoint_id)})
        elif key == "timeline":
            self._action(actions, "timeline")
            self._button(actions, "export", "Export action journal…", "Сохранить журнал действий…", self._export)
            self._button(actions, "trace_evidence", *ACTION_LABELS["trace_evidence"], self._trace)
            fields = QFormLayout()
            self.profile_seconds = QSpinBox()
            self.profile_seconds.setRange(1, 30)
            self.profile_seconds.setValue(5)
            seconds_label = self._translated(_plain_label(), "ETW duration, seconds", "Длительность ETW, секунд")
            fields.addRow(seconds_label, self.profile_seconds)
            self.profile_kind = QComboBox()
            self.profile_kind.addItem("BLACKBOX Deep: CPU / File / Disk / TCP / UDP", "BLACKBOX.Deep.Light")
            profile_label = self._translated(_plain_label(), "Recording profile", "Профиль записи")
            fields.addRow(profile_label, self.profile_kind)
            layout.addLayout(fields)
            self._button(actions, "profile.etw", *ACTION_LABELS["profile.etw"], self._record_etw)
            self._button(actions, "captured_trace", "Open captured trace in Decoder", "Открыть записанную трассу в декодере", self._open_captured_trace)

    @staticmethod
    def _required(field):
        text = field.text().strip()
        if not text:
            field.setFocus()
            raise ValueError("REQUIRED_FIELD_EMPTY")
        return text

    @classmethod
    def _integer(cls, field):
        text = cls._required(field)
        try:
            value = int(text, 16 if text.lower().startswith("0x") else 10)
        except ValueError:
            raise ValueError("INVALID_ADDRESS_OR_ID") from None
        if not 0 < value < 2**64:
            raise ValueError("INVALID_ADDRESS_OR_ID")
        return value

    def _thread_parameters(self, *, required=False):
        if not required and not self.thread_tid.text().strip():
            return {}
        return {"tid": self._integer(self.thread_tid), "thread_created_100ns": self._integer(self.thread_created)}

    def _stack_parameters(self):
        parameters = self._thread_parameters()
        if self.stack_pdb.text().strip():
            parameters.update(pdb_path=self.stack_pdb.text().strip(), module_base=self._integer(self.stack_module_base))
        return parameters

    def _choose_stack_pdb(self):
        interaction = self._interaction_token()
        path, _ = QFileDialog.getOpenFileName(self, self.tr2("Local stack PDB", "Локальный PDB для стека"), "", "PDB (*.pdb)")
        if path and self._interaction_current(interaction):
            self.stack_pdb.setText(path)

    def _debug_thread_parameters(self):
        if not self.debug_tid.text().strip():
            return {}
        parameters = {"tid": self._integer(self.debug_tid)}
        if self.debug_created.text().strip():
            parameters["thread_created_100ns"] = self._integer(self.debug_created)
        return parameters

    def _memory_read_parameters(self):
        return {"address": self._integer(self.memory_address), "size": self.memory_size.value()}

    def _memory_write_parameters(self):
        expected = bytes.fromhex(self._required(self.expected_bytes))
        replacement = bytes.fromhex(self._required(self.new_bytes))
        if not expected or len(expected) != len(replacement):
            raise ValueError("MEMORY_BYTES_MUST_HAVE_EQUAL_BOUNDED_LENGTH")
        if len(expected) > 4096:
            raise ValueError("MEMORY_WRITE_LIMIT_4096_BYTES")
        return {"address": self._integer(self.memory_address), "expected_hex": expected.hex(), "value_hex": replacement.hex()}

    def _interaction_token(self):
        """Bind modal choices to the selected instance before Qt re-enters."""
        return self.bridge.generation, self.bridge.target

    def _interaction_current(self, token):
        if token == self._interaction_token() and token[1] is not None:
            return True
        self.status_label.setText(self.tr2(
            "CANCELLED · The selected process changed while choosing or confirming the action. Review the new target and start the action again.",
            "CANCELLED · Выбранный процесс изменился во время выбора или подтверждения действия. Проверьте новую цель и начните действие заново."))
        return False

    def _request(self, operation, parameters=None, *, tag=""):
        interaction = self._interaction_token()
        try:
            if not self._interaction_current(interaction):
                return False
            if callable(parameters):
                parameters = parameters()
            parameters = parameters or {}
            from blackbox_core.deep_contracts import DEEP_ACTIONS
            spec = DEEP_ACTIONS[operation]
            confirmed = not spec.confirmation_required or self._confirm(operation, parameters)
            if not confirmed:
                return False
            if not self._interaction_current(interaction):
                return False
            accepted = self.bridge.submit(operation, parameters, confirmed=confirmed,
                                          tag=tag, timeout_seconds=spec.timeout_seconds)
            if accepted:
                self._request_section = self.section.currentData()
                self._last_request = {"operation": operation, "parameters": dict(parameters), "tag": tag,
                                      "confirmed": confirmed, "timeout_seconds": spec.timeout_seconds,
                                      "interaction": interaction}
                self.elevate_button.hide()
            return accepted
        except (ValueError, TypeError, KeyError) as exc:
            self.status_label.setText(self.tr2("Check the selected address, identity and input values: ", "Проверьте выбранный адрес, идентичность и значения: ") + str(exc))
            return False

    def _confirm(self, operation, parameters):
        en, ru = ACTION_LABELS.get(operation, (operation, operation))
        target = self.bridge.target
        identity = f"{self._target_name} · PID {target[0]}" if target else "—"
        risk = self.tr2(
            "This diagnostic action may pause or change the application. Recovery is attempted and verified where possible; a complete rollback cannot be guaranteed.",
            "Диагностическое действие может приостановить или изменить программу. Восстановление выполняется и проверяется там, где это возможно; полный откат не гарантируется.")
        if operation == "dump":
            risk = self.tr2("The dump may contain passwords and documents and may briefly pause the application. It is saved only to the selected file.",
                           "Дамп может содержать пароли и документы; его снятие может кратковременно приостановить программу. Он сохраняется только в выбранный файл.")
        elif operation == "profile.etw":
            risk = self.tr2(
                "WPR records a SYSTEM-WIDE ETW trace, including other processes. Recording adds measurement overhead and can contain sensitive data. It stops automatically after the selected duration and is excluded from ordinary journal export. An existing WPR recording will not be stopped to make room for this capture.",
                "WPR записывает СИСТЕМНУЮ ETW-трассу, включая другие процессы. Запись создаёт нагрузку и может содержать чувствительные данные. Она автоматически завершится по выбранной длительности и не войдёт в обычный экспорт журнала. Уже идущая запись WPR не будет остановлена ради этого действия.")
        text = f"{self.tr2(en, ru)}\n{identity}\n\n{risk}"
        if parameters:
            preview = dict(parameters)
            for key in ("expected_hex", "value_hex"):
                if key in preview:
                    payload = bytes.fromhex(preview[key])
                    preview[key] = {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
                                    "first_64_bytes": payload[:64].hex()}
            text += "\n\n" + json.dumps(preview, ensure_ascii=False, indent=2)[:6000]
        dialog = QMessageBox(QMessageBox.Icon.Warning, "BLACK.BOX", text,
                             QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, self)
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.button(QMessageBox.StandardButton.Yes).setText(self.tr2("CONFIRM", "ПОДТВЕРДИТЬ"))
        dialog.button(QMessageBox.StandardButton.Cancel).setText(self.tr2("CANCEL", "ОТМЕНА"))
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        return dialog.exec() == QMessageBox.StandardButton.Yes

    def _elevate(self):
        interaction = self._interaction_token()
        request = self._last_request
        if not request or self.bridge.busy:
            return
        if (request.get("interaction") != interaction or not self._interaction_current(interaction)):
            return
        operation = request["operation"]
        operations = [operation]
        if operation.startswith("debug."):
            operations = [name for name in ACTION_LABELS if name.startswith("debug.")]
        elif operation == "memory.write":
            operations = ["memory.write", "memory.rollback", "memory_read"]
        elif operation == "thread.suspend":
            operations = ["thread.suspend", "thread.resume"]
        labels = [self.tr2(*ACTION_LABELS.get(name, (name, name))) for name in operations]
        text = self.tr2(
            "Windows administrator permission is required for the requested diagnostic operation. BLACK.BOX will open the system UAC prompt and authorize only this process and the operations listed below. Each intervention still requires confirmation.",
            "Для запрошенного диагностического действия необходимы дополнительные права Windows. BLACK.BOX вызовет системное окно UAC и разрешит работу только с этим процессом и перечисленными операциями. Каждое вмешательство по-прежнему требует подтверждения.")
        text += f"\n\n{self._target_name} · PID {self.bridge.target[0]}\n" + "\n".join(labels)
        dialog = QMessageBox(QMessageBox.Icon.Warning,
                             self.tr2("BLACK.BOX — Administrator permission", "BLACK.BOX — Права администратора"),
                             text, QMessageBox.StandardButton.Cancel, self)
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.button(QMessageBox.StandardButton.Cancel).setText(self.tr2("CANCEL", "ОТМЕНА"))
        grant = dialog.addButton(self.tr2("GRANT ADMINISTRATOR PERMISSION", "ПРЕДОСТАВИТЬ ПРАВА АДМИНИСТРАТОРА"), QMessageBox.ButtonRole.AcceptRole)
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        dialog.exec()
        if dialog.clickedButton() is grant:
            if not self._interaction_current(interaction):
                return
            self._pending_retry = dict(request)
            if not self.bridge.elevate(operations):
                self._pending_retry = None

    def _dump(self):
        interaction = self._interaction_token()
        choices = [self.tr2("Minidump", "Минидамп"), self.tr2("Extended dump with memory", "Расширенный дамп с памятью")]
        selected, ok = QInputDialog.getItem(self, "BLACK.BOX", self.tr2("Dump type", "Тип дампа"), choices, 0, False)
        if not ok:
            return
        if not self._interaction_current(interaction):
            return
        path, _ = QFileDialog.getSaveFileName(self, self.tr2("New diagnostic dump", "Новый диагностический дамп"), "BLACKBOX-Diagnostic.dmp", "Dump (*.dmp)")
        if path and self._interaction_current(interaction):
            self._request("dump", {"destination": path, "full": selected == choices[1], "max_bytes": 1024 * 1024 * 1024})

    def _record_etw(self):
        interaction = self._interaction_token()
        path, _ = QFileDialog.getSaveFileName(
            self, self.tr2("New system-wide ETW recording", "Новая системная запись ETW"),
            "BLACKBOX-Diagnostic.etl", "ETW (*.etl)")
        if path and self._interaction_current(interaction):
            self._request("profile.etw", {
                "duration_seconds": self.profile_seconds.value(),
                "profile": self.profile_kind.currentData(),
                "destination": path,
                "systemwide_confirmed": True,
            })

    def _inspect_dump(self):
        interaction = self._interaction_token()
        path, _ = QFileDialog.getOpenFileName(self, self.tr2("Saved diagnostic dump", "Сохранённый диагностический дамп"), "", "Dump (*.dmp)")
        if path and self._interaction_current(interaction):
            self._dump_path = path
            self._request("dump_inspect", {"path": path})

    def _read_dump_memory(self):
        interaction = self._interaction_token()
        path = self._dump_path
        if not path:
            path, _ = QFileDialog.getOpenFileName(self, self.tr2("Saved diagnostic dump", "Сохранённый диагностический дамп"), "", "Dump (*.dmp)")
        if path and self._interaction_current(interaction):
            self._dump_path = path
            self._request("dump_read_memory", lambda: self._saved_memory_parameters(path))

    def _saved_memory_parameters(self, path):
        parameters = self._memory_read_parameters()
        if parameters["size"] > 4096:
            raise ValueError("SAVED_DUMP_READ_LIMIT_4096_BYTES")
        return dict(parameters, path=path)

    def _symbols(self):
        interaction = self._interaction_token()
        pe, _ = QFileDialog.getOpenFileName(self, self.tr2("Local module PE", "Локальный PE модуля"), "", "PE (*.exe *.dll)")
        if not pe:
            return
        if not self._interaction_current(interaction):
            return
        pdb, _ = QFileDialog.getOpenFileName(self, self.tr2("Local PDB", "Локальный PDB"), "", "PDB (*.pdb)")
        if pdb and self._interaction_current(interaction):
            self._request("symbols_verify", {"pe_path": pe, "pdb_path": pdb})

    def _trace(self):
        interaction = self._interaction_token()
        path, _ = QFileDialog.getOpenFileName(self, self.tr2("Trace Decoder index", "Индекс Trace Decoder"), "", "SQLite (*.sqlite3 *.sqlite *.db)")
        if not path:
            return
        if not self._interaction_current(interaction):
            return
        # First list the actual trace instances; never substitute the live PID
        # for a recorded lifetime identifier.
        self._trace_request = {"index_path": path, "limit": 200}
        self._request("trace_evidence", self._trace_request)

    def _choose_trace_instance(self, data):
        interaction = self._interaction_token()
        candidates = data.get("candidate_instances")
        if (not isinstance(candidates, list) or not candidates or self._trace_request is None
                or self._trace_request.get("process_instance") is not None):
            return
        trace_request = dict(self._trace_request)
        choices = [self.tr2("Instance ", "Экземпляр ") +
                   f"{row.get('process_instance', '?')} · PID {row.get('pid', '?')} · "
                   f"{row.get('first_ms', '?')}–{row.get('last_ms', '?')} " + self.tr2("ms", "мс")
                   if isinstance(row, dict) else str(row) for row in candidates[:100]]
        selected, ok = QInputDialog.getItem(self, "BLACK.BOX", self.tr2(
            "Select a recorded instance. Matching PID alone does not prove this is the live target.",
            "Выберите записанный экземпляр. Совпадение PID не доказывает связь с живой целью."), choices, 0, False)
        if not ok:
            return
        if not self._interaction_current(interaction) or self._trace_request != trace_request:
            return
        row = candidates[choices.index(selected)]
        instance = row.get("process_instance", row.get("instance_id", row.get("id"))) if isinstance(row, dict) else row
        if instance is None:
            return
        self._trace_request = dict(trace_request, process_instance=instance)
        self._request("trace_evidence", self._trace_request)

    def _trace_interval_parameters(self):
        section = self.section.currentData()
        context = self._section_trace_requests.get(section)
        if section not in ("network", "disk") or not context:
            return None
        table = self._tables[section]
        item = table.item(table.currentRow(), 0)
        row = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if not isinstance(row, dict) or row.get("process_instance") != context.get("process_instance"):
            return None
        end = row.get("trace_relative_ms")
        start = row.get("trace_interval_start_ms", end)
        if (type(start) not in (float, int) or type(end) not in (float, int)
                or not math.isfinite(start) or not math.isfinite(end) or start > end):
            return None
        # Queries use a half-open interval. Include the completion event without
        # inventing an observed start or a unit conversion for untyped events.
        end_exclusive = math.nextafter(float(end), math.inf)
        if not math.isfinite(end_exclusive):
            return None
        parameters = dict(context, start_ms=start, end_ms=end_exclusive)
        tid = row.get("tid")
        if type(tid) is int and 0 < tid < 2**32:
            parameters["tid"] = tid
        return parameters

    def _open_trace_interval(self):
        parameters = self._trace_interval_parameters()
        if parameters is None:
            return
        self._trace_request = parameters
        self.section.setCurrentIndex(self.section.findData("timeline"))
        self._request("trace_evidence", parameters)

    def _export(self):
        interaction = self._interaction_token()
        path, _ = QFileDialog.getSaveFileName(self, self.tr2("Export action journal", "Сохранить журнал действий"), "BLACKBOX-Diagnostic-Journal.json", "JSON (*.json)")
        if path and self._interaction_current(interaction):
            self._request_section = self.section.currentData()
            self.bridge.export(path)

    def _capabilities(self):
        self._request_section = self.section.currentData()
        self.bridge.capabilities()

    def _open_decoder(self):
        panel = getattr(self.window, "decoder_panel", None)
        if panel is None:
            self.status_label.setText(self.tr2("Trace Decoder is available in the production six-page application.", "Trace Decoder доступен в основной программе с шестью страницами."))
            return
        # Opening the decoder does not assign a live instance to an old trace.
        self.window._navigate("decoder")

    def _open_captured_trace(self):
        panel = getattr(self.window, "decoder_panel", None)
        if panel is None or self._captured_trace is None:
            return
        self.window._navigate("decoder")
        panel.start_decode(Path(self._captured_trace))

    def _open_profiling(self):
        panel = getattr(self.window, "research_panel", None)
        toggle = getattr(self.window, "research_toggle", None)
        if panel is None or toggle is None:
            self.status_label.setText(self.tr2("Profiling controls are available in the full application.", "Управление профилированием доступно в полной программе."))
            return
        self.window._navigate("reports")
        toggle.setChecked(True)
        scroll = self.window.stack.currentWidget()
        if hasattr(scroll, "ensureWidgetVisible"):
            scroll.ensureWidgetVisible(panel)

    def set_target(self, pid, created, name=""):
        self._target_name = str(name or "")
        self.bridge.set_target(pid, created)
        self._render_target()

    def _target_changed(self):
        self._before_id = self._after_id = None
        self._pending_retry = self._last_request = None
        self._last_result = None
        self._trace_request = None
        self._section_trace_requests.clear()
        self._dump_path = None
        self._captured_trace = None
        self._section_results.clear()
        self._clear_stack_frames()
        self._row_details = None
        self.elevate_button.hide()
        for table in self._tables.values():
            table.setRowCount(0)
        for field in (self.thread_tid, self.thread_created, self.debug_tid, self.debug_created,
                      self.memory_address, self.expected_bytes, self.new_bytes, self.write_id,
                      self.breakpoint_address, self.breakpoint_id, self.stack_module_base, self.stack_pdb):
            field.clear()
        self._debug_state = "IDLE"
        self.debug_state_label.setText(self.tr2("DEBUG: ", "ОТЛАДКА: ") + self._debug_state)
        self.details.clear()
        self.summary.clear()
        self.status_label.clear()
        self._refresh_controls()

    def _render_target(self):
        target = self.bridge.target
        self.target_label.setText((self.tr2("Selected instance: ", "Выбранный экземпляр: ") +
                                   f"{self._target_name} · PID {target[0]} · {target[1]}") if target else
                                  self.tr2("Select an application in Overview or Processes.", "Выберите программу на странице обзора или процессов."))
        self._refresh_controls()

    def _render_operation_status(self, result):
        status = str(result.get("status", "OPERATION_FAILED"))
        message = self.tr2(*STATUS_TEXT.get(status, (status, status)))
        error = result.get("error") or result.get("reason")
        if result.get("winerror") is not None:
            error = (str(error) + " · " if error else "") + "WinError " + str(result["winerror"])
        self.status_label.setText(f"{status} · {message}" + ("\n" + str(error)[:1000] if error else ""))
        self.status_label.setStyleSheet("color: #a12020; font-weight: bold;" if status == "RECOVERY_UNCONFIRMED" else "")

    def _receive(self, result):
        if (result.get("generation", self.bridge.generation) != self.bridge.generation
                and result.get("request_kind") != "close"):
            return
        self._last_result = result
        status = str(result.get("status", "OPERATION_FAILED"))
        self._render_operation_status(result)
        data = result.get("data") or {}
        if isinstance(data, dict):
            if result.get("operation") == "profile.etw":
                self._captured_trace = None
                if (status == "COMPLETED" and data.get("saved_verified") is True
                        and isinstance(data.get("destination"), str) and data.get("trace_bytes", 0) > 0):
                    self._captured_trace = data["destination"]
            snapshot_id = data.get("snapshot_id")
            if snapshot_id and result.get("request_tag") == "before":
                self._before_id = snapshot_id
            elif snapshot_id and result.get("request_tag") == "after":
                self._after_id = snapshot_id
            for key, field in (("change_id", self.write_id), ("breakpoint_id", self.breakpoint_id)):
                if data.get(key) is not None:
                    field.setText(str(data[key]))
            if data.get("state") is not None:
                self._debug_state = str(data["state"])
                self.debug_state_label.setText(self.tr2("DEBUG: ", "ОТЛАДКА: ") + self._debug_state)
            tid = data.get("stopped_tid", data.get("tid"))
            if tid is not None:
                self.debug_tid.setText(str(tid))
                self.debug_created.setText(str(data.get("thread_created_100ns") or ""))
        if result.get("request_kind") == "elevate":
            if status != "COMPLETED":
                self._pending_retry = None
        elif result.get("request_kind") != "close":
            section = self._request_section
            self._section_trace_requests.pop(section, None)
            if (result.get("operation") == "trace_evidence" and isinstance(data, dict)
                    and (self._last_request or {}).get("operation") == "trace_evidence"):
                digest = data.get("source_trace_sha256")
                selection = data.get("trace_selection", {})
                if (isinstance(digest, str) and len(digest) == 64
                        and all(char in "0123456789abcdefABCDEF" for char in digest)
                        and type(selection.get("process_instance")) is int):
                    self._section_trace_requests[section] = dict(
                        self._last_request["parameters"],
                        process_instance=selection["process_instance"],
                        expected_source_trace_sha256=digest)
            self._section_results[section] = result
            self._show_result(section, result)
            if section != self.section.currentData():
                self._section_changed()
        self.elevate_button.setVisible(status == "ADMIN_REQUIRED" and self._last_request is not None)
        self._refresh_controls()

    def _idle(self):
        request = self._pending_retry
        if request and self._last_result and self._last_result.get("request_kind") == "elevate":
            self._pending_retry = None
            if self._last_result.get("status") == "COMPLETED":
                if not self._interaction_current(request.get("interaction")):
                    return
                self.bridge.submit(request["operation"], request["parameters"],
                                   confirmed=request["confirmed"], tag=request["tag"],
                                   timeout_seconds=request["timeout_seconds"])
                return
        result = self._last_result or {}
        if result.get("operation") == "trace_evidence" and isinstance(result.get("data"), dict):
            self._choose_trace_instance(result["data"])
        self._refresh_controls()

    @staticmethod
    def _rows(data):
        if isinstance(data, list):
            return [row if isinstance(row, dict) else {"value": row} for row in data]
        if not isinstance(data, dict):
            return [{"value": data}]
        for key in ("rows", "events", "processes", "modules", "threads", "handles", "regions", "connections", "entries", "operations", "breakpoints", "frames", "candidate_instances"):
            if isinstance(data.get(key), list) and data[key]:
                return [row if isinstance(row, dict) else {"value": row} for row in data[key]]
        return [{"field": key, "value": value} for key, value in data.items()]

    def _technical_text(self, value):
        text = json.dumps(value, ensure_ascii=False, indent=2)
        if len(text) > 100000:
            text = text[:100000] + self.tr2(
                "\n… DISPLAY TRUNCATED: select a smaller range to inspect the remaining fields.",
                "\n… ПОКАЗ СОКРАЩЁН: выберите меньший диапазон для просмотра остальных полей.")
        return text

    @staticmethod
    def _process_tree_rows(rows):
        """Bounded presentation of observed PPID links, not proven lifetimes."""
        by_pid = {row["pid"]: row for row in rows if isinstance(row.get("pid"), int)}
        children = {}
        for pid, row in by_pid.items():
            children.setdefault(row.get("ppid"), []).append(pid)
        roots = [pid for pid, row in by_pid.items() if row.get("ppid") not in by_pid or row.get("ppid") == pid]
        visited, rendered = set(), []
        for root in [*roots, *by_pid]:
            stack = [(root, 0)]
            while stack:
                pid, depth = stack.pop()
                if pid in visited:
                    continue
                visited.add(pid)
                row = dict(by_pid[pid])
                if row.get("name"):
                    row["name"] = "  " * min(depth, 32) + str(row["name"])
                row["observed_tree_depth"] = depth
                rendered.append(row)
                stack.extend((child, min(depth + 1, 32)) for child in reversed(children.get(pid, [])) if child != pid)
        rendered.extend(row for row in rows if not isinstance(row.get("pid"), int))
        return rendered

    def _show_result(self, section, result):
        if section == "threads":
            self._clear_stack_frames()
        rows = self._rows(result.get("data"))
        if result.get("operation") == "processes":
            rows = self._process_tree_rows(rows)
        elif result.get("operation") == "trace_evidence" and isinstance(result.get("data"), dict):
            data = result["data"]
            if section in ("network", "disk") and data.get("trace_selection", {}).get("process_instance") is not None:
                rows = [row for row in data.get("io_events", []) if row.get("category") == section]
            elif data.get("trace_selection", {}).get("process_instance") is None:
                rows = data.get("candidate_instances", [])
        columns = []
        if result.get("operation") == "trace_evidence" and section in ("network", "disk"):
            preferred = ("event_name", "trace_relative_ms", "pid", "tid", "event_transfer_bytes",
                         "latency_ms", "trace_interval_start_ms", "trace_interval_end_ms",
                         "latency_status", "typed_observation", "fields", "process_instance")
            columns = [key for key in preferred if any(key in row for row in rows[:500])]
        elif result.get("operation") == "memory_map" and section == "memory":
            preferred = ("base", "size", "type_name", "state_name", "protection", "allocation_base",
                         "mapped_file_path", "mapped_file_status", "association_kind", "image_name",
                         "mapped_file_winerror", "mapped_file_source")
            columns = [key for key in preferred if any(key in row for row in rows[:500])]
        for row in rows[:500]:
            for key in row:
                if section == "threads" and key in ("frames", "context"):
                    continue
                if key not in columns and len(columns) < 12:
                    columns.append(key)
        columns = columns or ["field", "value"]
        table = self._tables[section]
        table.blockSignals(True)
        table.clear()
        table.setColumnCount(len(columns))
        table.setHorizontalHeaderLabels([self.tr2(*FIELD_LABELS.get(key, (key, key))) for key in columns])
        table.setRowCount(min(500, len(rows)))
        for i, row in enumerate(rows[:500]):
            for j, key in enumerate(columns):
                value = row.get(key)
                text = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value if value is not None else "—")
                item = QTableWidgetItem(text[:2000] + ("…" if len(text) > 2000 else ""))
                item.setData(Qt.ItemDataRole.UserRole, row)
                table.setItem(i, j, item)
        table.blockSignals(False)
        limitations = result.get("limitations") or []
        text = self.tr2("Displayed rows: ", "Показано строк: ") + f"{min(len(rows), 500)} / {len(rows)}"
        if limitations:
            text += "\n" + "\n".join(str(item) for item in limitations)[:4000]
        if result.get("operation") == "trace_evidence" and isinstance(result.get("data"), dict):
            selected = result["data"].get("trace_selection", {})
            if selected.get("start_ms") is not None or selected.get("end_ms") is not None:
                text += self.tr2("\nRecorded interval, ms: ", "\nЗаписанный интервал, мс: ")
                text += f"[{selected.get('start_ms', '—')}, {selected.get('end_ms', '—')})"
                text += f" · PID {selected.get('pid', '—')} · TID {selected.get('tid', '—')}"
                text += self.tr2(" · recorded instance ", " · записанный экземпляр ") + str(selected.get("process_instance", "—"))
                text += self.tr2("\nHistorical filter only; association with the live process remains unestablished.",
                                 "\nЭто фильтр исторических событий; связь с живым процессом по-прежнему не установлена.")
        if result.get("next_action"):
            text += "\n" + self.tr2("Next action: ", "Следующее действие: ") + str(result["next_action"])
        self.summary.setText(text)
        self.details.setPlainText(self._technical_text(result))

    def _select_row(self, section):
        table = self._tables[section]
        item = table.item(table.currentRow(), 0)
        if item is None:
            return
        row = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(row, dict):
            return
        self._row_details = row
        self.details.setPlainText(self._technical_text(row))
        historical = (row.get("source") == "HISTORICAL_TRACE" or
                      row.get("inspection_scope") == "HISTORICAL_TRACE_MODULE" or
                      self._section_results.get(section, {}).get("operation") == "trace_evidence")
        if section == "threads":
            self._show_stack_frames(row)
        tid = row.get("tid", row.get("thread_id"))
        created = row.get("thread_created_100ns", row.get("created_100ns"))
        if tid is not None and not historical:
            self.thread_tid.setText(str(tid))
            self.debug_tid.setText(str(tid))
            self.thread_created.setText(str(created) if created is not None else "")
            self.debug_created.setText(str(created) if created is not None else "")
        elif historical:
            for field in (self.thread_tid, self.thread_created, self.debug_tid, self.debug_created):
                field.clear()
        address = row.get("frame_address", row.get("base_address", row.get("address", row.get("base"))))
        if isinstance(address, int) and address > 0 and not historical:
            self.memory_address.setText(hex(address))
            self.breakpoint_address.setText(hex(address))
            if section == "modules":
                base = row.get("base", address)
                if type(base) is int and base > 0:
                    self.stack_module_base.setText(hex(base))
        if row.get("breakpoint_id") is not None and not historical:
            self.breakpoint_id.setText(str(row["breakpoint_id"]))
        self._refresh_controls()

    def _section_changed(self):
        section = self.section.currentData()
        result = self._section_results.get(section)
        if result is not None:
            self._show_result(section, result)
        else:
            self.summary.clear()
            self.details.clear()
        self._refresh_controls()

    def _refresh_controls(self, *_):
        available = self.bridge.target is not None and not self.bridge.busy
        for key, button in self._action_buttons.items():
            button.setEnabled(available)
        cleanup_required = bool(getattr(self.bridge, "cleanup_required", False))
        self.cancel_button.setEnabled(self.bridge.busy and not cleanup_required)
        self._action_buttons["retry_cleanup"].setEnabled(cleanup_required and getattr(self.bridge, "worker", None) is None)
        self.end_admin_button.setEnabled(available and self.bridge.admin_active)
        self._action_buttons["compare"].setEnabled(available and self._before_id is not None and self._after_id is not None)
        self._action_buttons["captured_trace"].setEnabled(available and self._captured_trace is not None)
        self._action_buttons["stack_frame_module"].setEnabled(available and self._stack_module() is not None)
        interval_available = available and self._trace_interval_parameters() is not None
        for key in ("historical_network_interval", "historical_disk_interval"):
            self._action_buttons[key].setEnabled(interval_available)
        self.elevate_button.setEnabled(available)
        checked = getattr(self.bridge, "admin_checked_at", "")
        self.admin_label.setText(("ADMIN: ACTIVE · " + self.tr2("last checked ", "проверено в ") + checked)
                                if self.bridge.admin_active else self.tr2("ADMIN: INACTIVE", "ADMIN: INACTIVE · сеанс администратора не активен"))

    def retranslate(self):
        for widget, en, ru in self._labels:
            widget.setText(self.tr2(en, ru))
            if isinstance(widget, QPushButton):
                widget.setAccessibleName(widget.text())
        for index, (_, en, ru) in enumerate(SECTIONS):
            self.section.setItemText(index, self.tr2(en, ru))
        self.stack_frames.setHorizontalHeaderLabels([
            self.tr2("Frame", "Кадр"), "PC", self.tr2("Module", "Модуль"), "RVA",
            self.tr2("Function / recorded name", "Функция / записанное имя"),
            self.tr2("Source location", "Строка исходников"), self.tr2("Evidence source", "Источник данных")])
        if self._stack_context is None:
            self._clear_stack_frames()
        self._render_target()
        self.debug_state_label.setText(self.tr2("DEBUG: ", "ОТЛАДКА: ") + self._debug_state)
        if self._last_result:
            self._render_operation_status(self._last_result)
        self._section_changed()

    def shutdown(self):
        self.bridge.shutdown()
