"""Small explicit preparation wizard; control receipt is verified live."""
from __future__ import annotations
from pathlib import Path
from PySide6.QtCore import Qt,QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QDialog,QVBoxLayout,QLabel,QComboBox,QPushButton,
                              QPlainTextEdit,QDialogButtonBox)


class PreparationDialog(QDialog):
    def __init__(self,panel):
        super().__init__(panel);self.panel=panel;self.bridge=panel.bridge
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose,True)
        self.setWindowTitle(panel.tr("Prepare my application","Подготовить мою программу"))
        self.resize(740,560);self.folder=None;self.packet=None;self.target=self.bridge.pid
        self._identity=self.identity();self._prepared_scope=None;self._requests={};self._legacy={}
        self._correlated=hasattr(self.bridge,'command_result')
        layout=QVBoxLayout(self)
        layout.addWidget(QLabel(panel.tr("1. Choose the application's runtime; detection is advisory.",
            "1. Выберите среду программы. Автоматическое определение служит подсказкой.")))
        self.runtime=QComboBox();self.runtime.addItems(("JSONL / Other","Python",".NET / C#","Windows C++","Electron / Node"))
        layout.addWidget(self.runtime)
        self.generate=QPushButton(panel.tr("2. Generate the local connection files","2. Подготовить файлы подключения"))
        self.generate.clicked.connect(self.generate_client);layout.addWidget(self.generate)
        self.instructions=QPlainTextEdit();self.instructions.setReadOnly(True);layout.addWidget(self.instructions)
        self.instructions.setPlainText(panel.tr("Start recording, generate files, then send blackbox.ready from the selected application.",
            "Начните запись, подготовьте файлы и отправьте blackbox.ready из выбранной программы. Сбор данных остаётся локальным."))
        self.open_folder=QPushButton(panel.tr("Open generated files","Открыть подготовленные файлы"));self.open_folder.setEnabled(False)
        self.open_folder.clicked.connect(self.open_files);layout.addWidget(self.open_folder)
        self.verification=QLabel();self.verification.setWordWrap(True);layout.addWidget(self.verification)
        close=QDialogButtonBox(QDialogButtonBox.StandardButton.Close);close.rejected.connect(self.close);layout.addWidget(close)
        self.runtime.currentIndexChanged.connect(self.render)
        if self._correlated:self.bridge.command_result.connect(self.command_received)
        else:self.bridge.result_ready.connect(self.receive)
        self.bridge.updated.connect(self.refresh)
        self.refresh()
        if self.bridge.pid:self.send("inspect")

    def identity(self):
        return self.bridge.pid,getattr(self.bridge,'data',{}).get('pid_creation_time')

    def scope(self):
        folder=getattr(self.bridge,'session_folder',None)
        return self.identity(),str(folder) if folder is not None else None

    def send(self,op):
        scope=self.scope()
        if not self._correlated and op in self._legacy:return
        self._legacy[op]=scope
        try:
            ident=self.bridge.send(op)
        except (OSError,RuntimeError,ValueError) as exc:
            self._legacy.pop(op,None)
            from .research_messages import explain
            self.instructions.setPlainText(explain(str(exc),self.panel.window.language));return
        if self._correlated:
            self._legacy.pop(op,None);self._requests[ident]=(op,scope)

    def generate_client(self):
        if not self.bridge.active or self.bridge.pending or self.identity()!=self._identity:return
        self.packet=self.folder=self._prepared_scope=None;self.open_folder.setEnabled(False)
        self.send('prepare_client')

    def command_received(self,ident,op,result,error):
        request=self._requests.pop(ident,None)
        if request is not None and request[0]==op:self.receive(op,result,error,scope=request[1])

    def receive(self,op,result,error,*,scope=None):
        if op not in ("inspect","prepare_client"):return
        if scope is None:scope=self._legacy.pop(op,None)
        if scope is None or scope[0]!=self.identity() or (op=='prepare_client' and scope!=self.scope()):return
        if error:
            from .research_messages import explain
            self.instructions.setPlainText(explain(error,self.panel.window.language));return
        if not isinstance(result,dict):
            self.instructions.setPlainText('PREPARATION_RESULT_UNAVAILABLE');return
        if op=="inspect":
            candidates=result.get("runtime_candidates",[])
            index=1 if "python" in candidates else 2 if "dotnet" in candidates else 4 if "electron" in candidates else 0
            self.runtime.setCurrentIndex(index)
        else:
            self.packet=result;self.folder=Path(result["folder"]);self._prepared_scope=scope
            self.open_folder.setEnabled(True);self.render();self.refresh()

    def render(self):
        if not self.packet:return
        ru=self.panel.window.language=="RU"
        steps={
          0:("Append schema1 JSONL events to the configured path. Preserve source clock identity and use a stable operation_id for paired boundaries.",
             "Добавьте события JSONL по схеме из подготовленных клиентов. Сохраняйте обозначение часов и одинаковый operation_id у начала и конца операции."),
          1:("Copy blackbox_event_client.py and blackbox-config.json to your project. Adapt example.py to your real operation.",
             "Скопируйте blackbox_event_client.py и blackbox-config.json в проект. Разместите свою операцию внутри блока из example.py."),
          2:("Include BlackBoxEvents.cs in a Windows .NET 6+ project. Construct BlackBoxEvents(configPath), then call Emit(\"blackbox.ready\").",
             "Добавьте BlackBoxEvents.cs в Windows-проект .NET 6+. Создайте BlackBoxEvents(configPath) и вызовите Emit(\"blackbox.ready\")."),
          3:("Include BlackBoxEvents.hpp in a C++17 Windows project. Supply path/token from the configuration; call emit(\"blackbox.ready\"). Keep matching EXE/PDB files for native names.",
             "Подключите BlackBoxEvents.hpp в Windows-проект C++17. Передайте path/token из конфигурации и вызовите emit(\"blackbox.ready\"). Для имён native-функций сохраните соответствующие EXE/PDB."),
          4:("Require blackbox-events.cjs and construct BlackBoxEvents(configPath). Emit blackbox.ready. For optional Chromium traces, call the explicit contentTracing methods after app.whenReady().",
             "Подключите blackbox-events.cjs и создайте BlackBoxEvents(configPath). Отправьте blackbox.ready. Дополнительную трассировку Chromium включайте через методы contentTracing после app.whenReady()."),
        }
        text=steps[self.runtime.currentIndex()][1 if ru else 0]
        text+="\n\n"+("Папка: " if ru else "Folder: ")+str(self.folder)
        text+="\n\n"+("Событие должно поступить из PID " if ru else "The control event must arrive from PID ")+str(self.target)
        text+="\n\n"+("Подтверждение означает получение события приложения в этом сеансе. Подлинность события операционной системой не удостоверяется." if ru
                           else "Verification means an application event was received in this session; it is not OS attestation.")
        self.instructions.setPlainText(text)

    def refresh(self):
        matches=self.identity()==self._identity
        current=self._prepared_scope is not None and self._prepared_scope==self.scope()
        if self._prepared_scope is not None and not current:
            self.packet=self.folder=self._prepared_scope=None;self.open_folder.setEnabled(False)
            self.instructions.setPlainText(self.panel.tr('Process or recording changed; generate files for the selected recording.',
                'Процесс или запись изменились; подготовьте файлы для выбранной записи.'))
        self.generate.setEnabled(self.bridge.active and not self.bridge.pending and matches)
        ready=bool(current and self.bridge.data.get("app_ready") and matches)
        self.verification.setText(self.panel.tr("3. Control event received in this session.","3. Проверочное событие получено в текущем сеансе.") if ready else
            self.panel.tr("3. Waiting for blackbox.ready from the selected application.","3. Ожидается blackbox.ready из выбранной программы."))

    def open_files(self):
        if self.folder and self._prepared_scope==self.scope():QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.folder)))
