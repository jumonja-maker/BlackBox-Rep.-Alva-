"""Explicit deep inspection and controlled actions inside the existing Overview."""
from __future__ import annotations

import json
import hashlib

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
}


def _plain_label():
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    return label


class OverviewInspectorPanel(QWidget):
    closed = Signal(object)

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
        self._dump_path = None
        self._request_section = "processes"
        self._build()
        self.bridge.result_ready.connect(self._receive)
        self.bridge.busy_changed.connect(self._refresh_controls)
        self.bridge.target_changed.connect(self._target_changed)
        self.bridge.idle.connect(self._idle)
        self.bridge.closed.connect(self.closed.emit)
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
            self.expected_bytes = self._field(fields, "expected", "Expected original bytes (hex)", "Ожидаемые исходные байты (hex)")
            self.new_bytes = self._field(fields, "replacement", "Replacement bytes (hex)", "Новые байты (hex)")
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
        elif key == "disk":
            self._action(actions, "disk")
            self._button(actions, "historical_disk", "Read recorded file operations…", "Прочитать записанные файловые операции…", self._trace)
        elif key == "debug":
            self.debug_state_label = _plain_label()
            self.debug_state_label.setText("DEBUG: IDLE")
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
        path, _ = QFileDialog.getOpenFileName(self, self.tr2("Local stack PDB", "Локальный PDB для стека"), "", "PDB (*.pdb)")
        if path:
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
        if not expected or len(expected) != len(replacement) or len(expected) > 65536:
            raise ValueError("MEMORY_BYTES_MUST_HAVE_EQUAL_BOUNDED_LENGTH")
        return {"address": self._integer(self.memory_address), "expected_hex": expected.hex(), "value_hex": replacement.hex()}

    def _request(self, operation, parameters=None, *, tag=""):
        try:
            if callable(parameters):
                parameters = parameters()
            parameters = parameters or {}
            from blackbox_core.deep_contracts import DEEP_ACTIONS
            spec = DEEP_ACTIONS[operation]
            confirmed = not spec.confirmation_required or self._confirm(operation, parameters)
            if not confirmed:
                return False
            accepted = self.bridge.submit(operation, parameters, confirmed=confirmed,
                                          tag=tag, timeout_seconds=spec.timeout_seconds)
            if accepted:
                self._request_section = self.section.currentData()
                self._last_request = {"operation": operation, "parameters": dict(parameters), "tag": tag,
                                      "confirmed": confirmed, "timeout_seconds": spec.timeout_seconds}
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
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        return dialog.exec() == QMessageBox.StandardButton.Yes

    def _elevate(self):
        request = self._last_request
        if not request or self.bridge.busy:
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
        grant = dialog.addButton(self.tr2("GRANT ADMINISTRATOR PERMISSION", "ПРЕДОСТАВИТЬ ПРАВА АДМИНИСТРАТОРА"), QMessageBox.ButtonRole.AcceptRole)
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        dialog.exec()
        if dialog.clickedButton() is grant:
            self._pending_retry = dict(request)
            if not self.bridge.elevate(operations):
                self._pending_retry = None

    def _dump(self):
        choices = [self.tr2("Minidump", "Минидамп"), self.tr2("Extended dump with memory", "Расширенный дамп с памятью")]
        selected, ok = QInputDialog.getItem(self, "BLACK.BOX", self.tr2("Dump type", "Тип дампа"), choices, 0, False)
        if not ok:
            return
        path, _ = QFileDialog.getSaveFileName(self, self.tr2("New diagnostic dump", "Новый диагностический дамп"), "BLACKBOX-Diagnostic.dmp", "Dump (*.dmp)")
        if path:
            self._request("dump", {"destination": path, "full": selected == choices[1], "max_bytes": 1024 * 1024 * 1024})

    def _inspect_dump(self):
        path, _ = QFileDialog.getOpenFileName(self, self.tr2("Saved diagnostic dump", "Сохранённый диагностический дамп"), "", "Dump (*.dmp)")
        if path:
            self._dump_path = path
            self._request("dump_inspect", {"path": path})

    def _read_dump_memory(self):
        path = self._dump_path
        if not path:
            path, _ = QFileDialog.getOpenFileName(self, self.tr2("Saved diagnostic dump", "Сохранённый диагностический дамп"), "", "Dump (*.dmp)")
        if path:
            self._dump_path = path
            self._request("dump_read_memory", lambda: dict(self._memory_read_parameters(), path=path))

    def _symbols(self):
        pe, _ = QFileDialog.getOpenFileName(self, self.tr2("Local module PE", "Локальный PE модуля"), "", "PE (*.exe *.dll)")
        if not pe:
            return
        pdb, _ = QFileDialog.getOpenFileName(self, self.tr2("Local PDB", "Локальный PDB"), "", "PDB (*.pdb)")
        if pdb:
            self._request("symbols_verify", {"pe_path": pe, "pdb_path": pdb})

    def _trace(self):
        path, _ = QFileDialog.getOpenFileName(self, self.tr2("Trace Decoder index", "Индекс Trace Decoder"), "", "SQLite (*.sqlite3 *.sqlite *.db)")
        if not path:
            return
        # First list the actual trace instances; never substitute the live PID
        # for a recorded lifetime identifier.
        self._trace_request = {"index_path": path, "limit": 200}
        self._request("trace_evidence", self._trace_request)

    def _choose_trace_instance(self, data):
        candidates = data.get("candidate_instances")
        if (not isinstance(candidates, list) or not candidates or self._trace_request is None
                or self._trace_request.get("process_instance") is not None):
            return
        choices = [f"Instance {row.get('process_instance', '?')} · PID {row.get('pid', '?')} · "
                   f"{row.get('first_ms', '?')}–{row.get('last_ms', '?')} ms"
                   if isinstance(row, dict) else str(row) for row in candidates[:100]]
        selected, ok = QInputDialog.getItem(self, "BLACK.BOX", self.tr2(
            "Select a recorded instance. Matching PID alone does not prove this is the live target.",
            "Выберите записанный экземпляр. Совпадение PID не доказывает связь с живой целью."), choices, 0, False)
        if not ok:
            return
        row = candidates[choices.index(selected)]
        instance = row.get("process_instance", row.get("instance_id", row.get("id"))) if isinstance(row, dict) else row
        if instance is None:
            return
        self._trace_request = dict(self._trace_request, process_instance=instance)
        self._request("trace_evidence", self._trace_request)

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(self, self.tr2("Export action journal", "Сохранить журнал действий"), "BLACKBOX-Diagnostic-Journal.json", "JSON (*.json)")
        if path:
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
        self._dump_path = None
        self._section_results.clear()
        self._row_details = None
        self.elevate_button.hide()
        for table in self._tables.values():
            table.setRowCount(0)
        for field in (self.thread_tid, self.thread_created, self.debug_tid, self.debug_created,
                      self.memory_address, self.expected_bytes, self.new_bytes, self.write_id,
                      self.breakpoint_address, self.breakpoint_id, self.stack_module_base, self.stack_pdb):
            field.clear()
        self.debug_state_label.setText("DEBUG: IDLE")
        self.details.clear()
        self.summary.clear()
        self.status_label.clear()
        self._refresh_controls()

    def _render_target(self):
        target = self.bridge.target
        self.target_label.setText((self.tr2("Selected instance: ", "Выбранный экземпляр: ") +
                                   f"{self._target_name} · PID {target[0]} · {target[1]}") if target else
                                  self.tr2("Select an application in Overview or Processes.", "Выберите программу в Overview или на странице процессов."))
        self._refresh_controls()

    def _receive(self, result):
        self._last_result = result
        status = str(result.get("status", "OPERATION_FAILED"))
        message = self.tr2(*STATUS_TEXT.get(status, (status, status)))
        error = result.get("error") or result.get("reason")
        if result.get("winerror") is not None:
            error = (str(error) + " · " if error else "") + "WinError " + str(result["winerror"])
        self.status_label.setText(f"{status} · {message}" + ("\n" + str(error)[:1000] if error else ""))
        self.status_label.setStyleSheet("color: #a12020; font-weight: bold;" if status == "RECOVERY_UNCONFIRMED" else "")
        data = result.get("data") or {}
        if isinstance(data, dict):
            snapshot_id = data.get("snapshot_id")
            if snapshot_id and result.get("request_tag") == "before":
                self._before_id = snapshot_id
            elif snapshot_id and result.get("request_tag") == "after":
                self._after_id = snapshot_id
            for key, field in (("change_id", self.write_id), ("breakpoint_id", self.breakpoint_id)):
                if data.get(key) is not None:
                    field.setText(str(data[key]))
            if data.get("state") is not None:
                self.debug_state_label.setText("DEBUG: " + str(data["state"]))
            tid = data.get("stopped_tid", data.get("tid"))
            if tid is not None:
                self.debug_tid.setText(str(tid))
                self.debug_created.setText(str(data.get("thread_created_100ns") or ""))
        if result.get("request_kind") == "elevate":
            if status != "COMPLETED":
                self._pending_retry = None
        elif result.get("request_kind") != "close":
            section = self._request_section
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
        for row in rows[:500]:
            for key in row:
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
                item = QTableWidgetItem(text[:2000])
                item.setData(Qt.ItemDataRole.UserRole, row)
                table.setItem(i, j, item)
        table.blockSignals(False)
        limitations = result.get("limitations") or []
        text = self.tr2("Displayed rows: ", "Показано строк: ") + f"{min(len(rows), 500)} / {len(rows)}"
        if limitations:
            text += "\n" + "\n".join(str(item) for item in limitations)[:4000]
        if result.get("next_action"):
            text += "\n" + self.tr2("Next action: ", "Следующее действие: ") + str(result["next_action"])
        self.summary.setText(text)
        self.details.setPlainText(json.dumps(result, ensure_ascii=False, indent=2)[:100000])

    def _select_row(self, section):
        table = self._tables[section]
        item = table.item(table.currentRow(), 0)
        if item is None:
            return
        row = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(row, dict):
            return
        self._row_details = row
        self.details.setPlainText(json.dumps(row, ensure_ascii=False, indent=2)[:100000])
        tid = row.get("tid", row.get("thread_id"))
        created = row.get("thread_created_100ns", row.get("created_100ns"))
        if tid is not None:
            self.thread_tid.setText(str(tid))
            self.debug_tid.setText(str(tid))
            self.thread_created.setText(str(created) if created is not None else "")
            self.debug_created.setText(str(created) if created is not None else "")
        address = row.get("base_address", row.get("address", row.get("base")))
        if isinstance(address, int) and address > 0:
            self.memory_address.setText(hex(address))
            self.breakpoint_address.setText(hex(address))
            if section == "modules":
                self.stack_module_base.setText(hex(address))
        if row.get("breakpoint_id") is not None:
            self.breakpoint_id.setText(str(row["breakpoint_id"]))

    def _section_changed(self):
        section = self.section.currentData()
        result = self._section_results.get(section)
        if result is not None:
            self._show_result(section, result)
        else:
            self.summary.clear()
            self.details.clear()

    def _refresh_controls(self, *_):
        available = self.bridge.target is not None and not self.bridge.busy
        for key, button in self._action_buttons.items():
            button.setEnabled(available)
        self.cancel_button.setEnabled(self.bridge.busy)
        self.end_admin_button.setEnabled(available and self.bridge.admin_active)
        self._action_buttons["compare"].setEnabled(available and self._before_id is not None and self._after_id is not None)
        self.elevate_button.setEnabled(available)
        checked = getattr(self.bridge, "admin_checked_at", "")
        self.admin_label.setText(("ADMIN: ACTIVE · " + self.tr2("last checked ", "проверено в ") + checked)
                                if self.bridge.admin_active else "ADMIN: INACTIVE")

    def retranslate(self):
        for widget, en, ru in self._labels:
            widget.setText(self.tr2(en, ru))
            if isinstance(widget, QPushButton):
                widget.setAccessibleName(widget.text())
        for index, (_, en, ru) in enumerate(SECTIONS):
            self.section.setItemText(index, self.tr2(en, ru))
        self._render_target()
        if self._last_result:
            status = str(self._last_result.get("status", "OPERATION_FAILED"))
            self.status_label.setText(status + " · " + self.tr2(*STATUS_TEXT.get(status, (status, status))))
        self._section_changed()

    def shutdown(self):
        self.bridge.shutdown()
