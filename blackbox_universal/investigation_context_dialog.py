"""Explicit declarations for whole-case comparison context, RU/EN."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout)


class InvestigationContextDialog(QDialog):
    def __init__(self, parent, *, language="EN", app_identity=None, scenario=None):
        super().__init__(parent)
        self.setObjectName("invContextDialog")
        self.setWindowTitle("BLACK.BOX · " + ("Контекст расследования" if language == "RU" else "Investigation context"))
        self.setMinimumWidth(550)
        self.tr2 = lambda en, ru: ru if language == "RU" else en
        self.fields = {}
        layout = QVBoxLayout(self)
        note = QLabel(self.tr2(
            "The application identity and workload are YOUR declaration for every source in this case. A selected file's hash proves its bytes; its association with the historical process remains NOT_ESTABLISHED. Conditional comparisons never prove a cause or a fix.",
            "Приложение и нагрузка — ВАША декларация для всех источников этого расследования. Хеш выбранного файла доказывает его байты; связь с историческим процессом остаётся NOT_ESTABLISHED. Условное сравнение не доказывает причину или исправление."))
        note.setTextFormat(Qt.TextFormat.PlainText)
        note.setWordWrap(True)
        layout.addWidget(note)
        form = QFormLayout()
        app_identity, scenario = app_identity or {}, scenario or {}
        for key, en, ru, maximum, value in (
            ("application_id", "Application ID", "Идентификатор приложения", 256, app_identity.get("application_id", "")),
            ("version", "Declared application version", "Заявленная версия приложения", 128, app_identity.get("version", "")),
            ("scenario_id", "Scenario ID", "Идентификатор сценария", 256, scenario.get("scenario_id", "")),
            ("workload_id", "Workload ID", "Идентификатор нагрузки", 256, scenario.get("workload_id", "")),
            ("source_profile", "Capture profile ID", "Идентификатор профиля записи", 256, scenario.get("source_profile", "")),
            ("operation_count", "Declared operation count", "Заявленное число операций", 19, scenario.get("operation_count", "")),
            ("input_bytes", "Declared input bytes", "Заявленный объём входа, байт", 19, scenario.get("input_bytes", "")),
        ):
            field = QLineEdit(str(value))
            field.setObjectName("invContext_" + key)
            field.setMaxLength(maximum)
            self.fields[key] = field
            form.addRow(self.tr2(en, ru), field)
        self.complete = QCheckBox(self.tr2("I declare the workload complete", "Я заявляю, что нагрузка завершена"))
        self.complete.setObjectName("invContextComplete")
        self.complete.setChecked(scenario.get("complete") is True)
        form.addRow(self.complete)
        self.binary = QLineEdit()
        self.binary.setObjectName("invContextBinaryPath")
        self.binary.setReadOnly(True)
        binary_row = QHBoxLayout()
        binary_row.addWidget(self.binary)
        self.choose_binary = QPushButton(self.tr2("Choose binary…", "Выбрать файл приложения…"))
        self.choose_binary.setObjectName("invContextChooseBinary")
        self.choose_binary.clicked.connect(self._binary)
        binary_row.addWidget(self.choose_binary)
        form.addRow(self.tr2("Application file (optional SHA-256)", "Файл приложения (необязательный SHA-256)"), binary_row)
        self.import_path = QLineEdit()
        self.import_path.setObjectName("invContextImportPath")
        self.import_path.setReadOnly(True)
        import_row = QHBoxLayout()
        import_row.addWidget(self.import_path)
        self.choose_json = QPushButton(self.tr2("Use metadata JSON…", "Использовать JSON контекста…"))
        self.choose_json.setObjectName("invContextChooseJson")
        self.choose_json.clicked.connect(self._json)
        import_row.addWidget(self.choose_json)
        form.addRow(self.tr2("JSON overrides typed fields", "JSON заменяет введённые поля"), import_row)
        layout.addLayout(form)
        scope_text = self.tr2("I declare this context for ALL sources in this case", "Я объявляю этот контекст для ВСЕХ источников расследования")
        self.scope = QCheckBox(scope_text)
        self.scope.setObjectName("invContextEntireCaseConsent")
        layout.addWidget(self.scope)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        self.save_button = self.buttons.button(QDialogButtonBox.StandardButton.Save)
        self.save_button.setObjectName("invContextSave")
        self.save_button.setText(self.tr2("DECLARE AND SAVE", "ОБЪЯВИТЬ И СОХРАНИТЬ"))
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(self.tr2("CANCEL", "ОТМЕНА"))
        self.save_button.setEnabled(False)
        self.scope.toggled.connect(self.save_button.setEnabled)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    def _binary(self):
        path, _ = QFileDialog.getOpenFileName(self, self.tr2("Application binary", "Файл приложения"), "", "Application (*.exe *.dll);;All files (*)")
        if path:
            self.binary.setText(path)

    def _json(self):
        path, _ = QFileDialog.getOpenFileName(self, self.tr2("Declared context JSON", "JSON заявленного контекста"), "", "Context (*.json)")
        if path:
            self.import_path.setText(path)

    def arguments(self):
        return {"app_fields": {key: self.fields[key].text().strip() for key in ("application_id", "version")},
                "scenario_fields": {**{key: self.fields[key].text().strip() for key in (
                    "scenario_id", "workload_id", "source_profile", "operation_count", "input_bytes")},
                    "complete": self.complete.isChecked()},
                "binary_path": self.binary.text() or None, "context_path": self.import_path.text() or None,
                "scope_confirmed": self.scope.isChecked()}
