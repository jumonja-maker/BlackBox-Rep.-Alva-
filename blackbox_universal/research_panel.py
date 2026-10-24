"""Action-centred evidence controls inside the existing Reports page."""
from __future__ import annotations
import ctypes
from html import escape
import json
import math
import os
from pathlib import Path
import subprocess
import sys

from PySide6.QtCore import Qt,Signal
from PySide6.QtGui import QColor,QPainter,QPen
from PySide6.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QGridLayout,QLabel,QPushButton,
    QLineEdit,QSpinBox,QDoubleSpinBox,QFileDialog,QPlainTextEdit,QTableWidget,QTableWidgetItem,
    QHeaderView,QMessageBox,QCheckBox,QDialog,QDialogButtonBox)


class EvidenceTimeline(QWidget):
    interval_selected=Signal(int,int)
    def __init__(self,parent=None):
        super().__init__(parent);self.setMinimumHeight(100)
        self.rows=[];self.start=0;self.end=1000;self.anchor=None
        self.setToolTip("Drag: select interval · Wheel: zoom / Перетащите: интервал · Колесо: масштаб")
    def set_data(self,result):
        normal=result.get("normalised_interval")
        origin=normal.get("metadata",{}).get("monotonic_origin_ns") if isinstance(normal,dict) else None
        points=normal.get("timeline",{}).get("tracks",{}).get("cpu_interval_percent") if isinstance(normal,dict) else None
        if type(origin) is int and isinstance(points,list):
            self.rows=[{"elapsed_ms":(p["time_ns"]-origin)/1e6,"cpu_percent":p["value"],
                "segment":p["segment"]} for p in points]
        else:self.rows=result.get("chart",[])
        self.start,self.end=result["range_ms"];self.update()
    def _time(self,x):return int(self.start+max(0,min(1,x/max(1,self.width())))*(self.end-self.start))
    def paintEvent(self,event):
        painter=QPainter(self);painter.fillRect(self.rect(),QColor("#f0ecdb"))
        segments=self.curve_segments()
        high=max([value for segment in segments for _,value in segment]+[100.0])
        painter.setPen(QPen(QColor("#078b84"),2))
        for segment in segments:
            previous=None
            for stamp,value in segment:
                x=int((stamp-self.start)/max(1,self.end-self.start)*self.width())
                y=int(self.height()-20-value/high*(self.height()-30))
                if previous:painter.drawLine(previous[0],previous[1],x,y)
                else:painter.drawPoint(x,y)
                previous=(x,y)
        painter.setPen(QColor("#363344"))
        painter.drawText(8,self.height()-4,f"{self.start/1000:.2f} — {self.end/1000:.2f} s · CPU 0–{high:.1f}%")
    def curve_segments(self):
        segments=[];current=[];identity=None
        for row in self.rows:
            value=row.get("cpu_percent");stamp=row.get("elapsed_ms");group=row.get("segment")
            valid=(type(value) in (int,float) and math.isfinite(value) and value>=0 and
                type(stamp) in (int,float) and math.isfinite(stamp))
            if not valid or current and group!=identity:
                if current:segments.append(current);current=[]
            if valid:current.append((stamp,float(value)));identity=group
        if current:segments.append(current)
        return segments

    def mousePressEvent(self,event):self.anchor=self._time(event.position().x())
    def mouseReleaseEvent(self,event):
        if self.anchor is not None:
            a,b=sorted((self.anchor,self._time(event.position().x())))
            if b-a>=1:self.interval_selected.emit(a,b)
        self.anchor=None
    def wheelEvent(self,event):
        center=self._time(event.position().x());factor=.5 if event.angleDelta().y()>0 else 2
        width=max(100,int((self.end-self.start)*factor));a=max(0,center-width//2)
        self.interval_selected.emit(a,a+width);event.accept()


class ResearchPanel(QWidget):
    def __init__(self,window):
        super().__init__(window);self.window=window;self.bridge=window.probe
        self._labels=[];self.result=None;self._comparison_result=None
        layout=QVBoxLayout(self);layout.setContentsMargins(0,0,0,0)
        self.status=QLabel();self.status.setWordWrap(True);layout.addWidget(self.status)
        context=QGridLayout()
        self.scenario=QLineEdit();self.workload=QLineEdit();self.version=QLineEdit()
        for i,(field,en,ru) in enumerate(((self.scenario,"Scenario","Сценарий"),(self.workload,"Workload / input identity","Нагрузка / идентификатор входных данных"),(self.version,"Target version","Версия программы"))):
            label=QLabel();self._labels.append((label,en,ru));context.addWidget(label,i,0);context.addWidget(field,i,1)
        self.budget=QSpinBox();self.budget.setRange(16,1048576);self.budget.setValue(1024);self.budget.setSuffix(" MiB")
        label=QLabel();self._labels.append((label,"Session disk budget","Бюджет записи на диске"));context.addWidget(label,3,0);context.addWidget(self.budget,3,1)
        self.warmups=QSpinBox();self.warmups.setRange(0,10000)
        label=QLabel();self._labels.append((label,"Warm-up repetitions to exclude","Исключить разогревочные повторы"));context.addWidget(label,4,0);context.addWidget(self.warmups,4,1)
        layout.addLayout(context)
        buttons=QGridLayout();self.buttons=[];self.by_action={}
        entries=(("Context / capabilities","Контекст / доступность",self.inspect),
            ("Apply context","Применить контекст",self.configure),
            ("Prepare my application","Подготовить мою программу",self.prepare),
            ("Verify native PDB…","Проверить native PDB…",self.symbols),
            ("Inspect dump stacks…","Разобрать стеки дампа…",self.inspect_dump),
            ("Windows snapshot","Снимок Windows / WCT",self.native),
            ("ETW recording","Запись ETW",self.etw),
            ("EventPipe 10 s","EventPipe 10 с",lambda:self.send("eventpipe",seconds=10)),
            ("Capture minidump","Снять минидамп",self.dump),
            ("Administrator mode…","Режим администратора…",self.elevate),
            ("Export investigation…","Сохранить исследование…",self.export),
            ("Compare investigations…","Сравнить исследования…",self.compare),
            ("Verify package…","Проверить пакет…",self.verify),
            ("Recover interrupted session…","Восстановить прерванный сеанс…",self.recover),
            ("Open saved session…","Открыть сохранённый сеанс…",self.open_session))
        for i,(en,ru,callback) in enumerate(entries):
            b=QPushButton();b.clicked.connect(callback);buttons.addWidget(b,i//2,i%2)
            self._labels.append((b,en,ru));self.buttons.append(b)
            self.by_action[en]=b
        layout.addLayout(buttons)
        self.sensitive=QCheckBox();self._labels.append((self.sensitive,"Include raw traces, dumps and source fields in export","Включать исходные трассы, дампы и поля источников"));layout.addWidget(self.sensitive)
        interval=QHBoxLayout();self.begin=QDoubleSpinBox();self.end=QDoubleSpinBox()
        for box in (self.begin,self.end):box.setRange(0,31*24*3600);box.setDecimals(3);box.setSuffix(" s");interval.addWidget(box)
        self.end.setValue(60)
        self.load=QPushButton();self._labels.append((self.load,"Load interval","Показать интервал"));self.load.clicked.connect(self.load_interval);interval.addWidget(self.load)
        layout.addLayout(interval)
        paging=QHBoxLayout();self.previous=QPushButton();self.next=QPushButton()
        self._labels.extend(((self.previous,"Previous events","Предыдущие события"),(self.next,"Next events","Следующие события")))
        self.previous.clicked.connect(lambda:self.page(True));self.next.clicked.connect(lambda:self.page(False))
        paging.addWidget(self.previous);paging.addWidget(self.next);layout.addLayout(paging)
        self.page_data={}
        self.timeline=EvidenceTimeline();self.timeline.interval_selected.connect(self.select_interval);layout.addWidget(self.timeline)
        self.table=QTableWidget(0,4);self.table.setHorizontalHeaderLabels(("ms","SOURCE","QUALITY","EVENT"))
        self.table.horizontalHeader().setSectionResizeMode(3,QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setMinimumHeight(180);self.table.itemSelectionChanged.connect(self.show_evidence);layout.addWidget(self.table)
        self.machine_fields=QCheckBox();self._labels.append((self.machine_fields,"Show technical JSON for comparison","Показать технический JSON сравнения"))
        self.machine_fields.toggled.connect(self._render_comparison);layout.addWidget(self.machine_fields)
        self.details=QPlainTextEdit();self.details.setReadOnly(True);self.details.setMinimumHeight(150);layout.addWidget(self.details)
        self.folder=None
        self.preparation_dialog=None
        if hasattr(self.bridge,"result_ready"):
            self.bridge.result_ready.connect(self.receive)
            self.bridge.updated.connect(self.refresh)
        else:
            self.setEnabled(False)
        self.retranslate();self.refresh()

    def tr(self,en,ru):return ru if self.window.language=="RU" else en
    def retranslate(self):
        for widget,en,ru in self._labels:widget.setText(self.tr(en,ru))
        self.table.setHorizontalHeaderLabels(("ms",self.tr("SOURCE","ИСТОЧНИК"),self.tr("QUALITY","КАЧЕСТВО"),self.tr("EVENT","СОБЫТИЕ")))
        self._render_comparison()
    def refresh(self):
        data=getattr(self.bridge,"data",{})
        mode=data.get("capabilities",{}).get("privilege",{}).get("mode","UNKNOWN")
        mode_text={"STANDARD":self.tr("Standard user","Обычные права"),
                   "ADMINISTRATOR":self.tr("Administrator","Администратор")}.get(mode,self.tr("Checking…","Проверяем…"))
        ready=self.tr("Control event received","Проверочное событие получено") if data.get("app_ready") else self.tr("Waiting for application event","Ожидается событие приложения")
        jobs=data.get("optional_jobs",{})
        busy=jobs.get("current_op")
        progress=(self.tr(" · Diagnostic: "," · Диагностика: ")+str(busy)+
            self.tr(" · queued "," · в очереди ")+str(jobs.get("queued",0))) if busy else ""
        self.status.setText(mode_text+" · "+ready+progress+" · "+(self.bridge.last_error or ""))
        caps=data.get("capabilities",{})
        for name,key in (("Windows snapshot","hwnd"),("ETW recording","etw_wpr"),
                         ("EventPipe 10 s","dotnet_trace"),("Capture minidump","minidump")):
            status=caps.get(key,"UNKNOWN")
            self.by_action[name].setEnabled(status not in ("UNSUPPORTED_PLATFORM","TOOL_UNAVAILABLE"))
            self.by_action[name].setToolTip(status)
        self.status.setToolTip(json.dumps(data.get("sensor_health",{}),ensure_ascii=False,indent=2))
    def send(self,op,**args):
        try:return self.bridge.send(op,**args)
        except (RuntimeError,ValueError) as exc:self.details.setPlainText(str(exc))
    def configure(self):
        self.send("configure",scenario=self.scenario.text(),workload=self.workload.text(),target_version=self.version.text(),budget_mb=self.budget.value(),warmup_count=self.warmups.value())
    def inspect(self):self.send("inspect")
    def prepare(self):
        if self.preparation_dialog is not None:
            self.preparation_dialog.raise_();return
        from .preparation_dialog import PreparationDialog
        self.preparation_dialog=PreparationDialog(self)
        self.preparation_dialog.destroyed.connect(lambda:setattr(self,"preparation_dialog",None))
        self.preparation_dialog.show()
    def symbols(self):
        pdb,_=QFileDialog.getOpenFileName(self,self.tr("Matching native PDB","Подходящий native PDB"),"","PDB (*.pdb)")
        if pdb:self.send("symbols",pdb=pdb)
    def inspect_dump(self):
        dump,_=QFileDialog.getOpenFileName(self,self.tr("Process dump","Дамп процесса"),"","Dump (*.dmp)")
        if not dump:return
        symbols=QFileDialog.getExistingDirectory(self,self.tr("Local symbols (Cancel: none)","Локальные символы (Отмена: без них)"))
        self.send("inspect_dump",dump=dump,symbols=symbols or None)
    def native(self):self.send("native",enabled=not self.bridge.data.get("native_enabled",False))
    def etw(self):
        on=not self.bridge.data.get("wpr_active",False)
        if on and QMessageBox.question(self,"BLACK.BOX",self.tr(
                "Record a system-wide ETW trace for up to 30 seconds? It may include other processes and changes measurement overhead. Recording stops automatically.",
                "Записать системную ETW-трассу до 30 секунд? Она может содержать данные других процессов и влиять на измерения. Остановка выполняется автоматически."))!=QMessageBox.StandardButton.Yes:return
        self.send("wpr",enabled=on)
    def dump(self):
        if QMessageBox.question(self,"BLACK.BOX",self.tr(
                "Capture a minidump? It contains process memory and may briefly pause the selected application.",
                "Снять минидамп? Он содержит память процесса и может кратковременно приостановить выбранную программу."))==QMessageBox.StandardButton.Yes:
            self.send("dump",full=False)
    def export(self):
        destination,_=QFileDialog.getSaveFileName(self,self.tr("Save investigation","Сохранить исследование"),"BLACKBOX-Investigation.zip","ZIP (*.zip)")
        if destination:self.send("export",folder=str(self.folder) if self.folder else None,destination=destination,include_sensitive=self.sensitive.isChecked())
    def compare(self):
        first=QFileDialog.getExistingDirectory(self,self.tr("Before session","Сеанс до"))
        if not first:return
        second=QFileDialog.getExistingDirectory(self,self.tr("After session","Сеанс после"))
        if second:self.send("compare",before=first,after=second)
    def verify(self):
        path,_=QFileDialog.getOpenFileName(self,self.tr("Verify investigation","Проверить исследование"),"","ZIP (*.zip)")
        if path:self.send("verify",path=path)
    def recover(self):
        path=QFileDialog.getExistingDirectory(self,self.tr("Interrupted session","Прерванный сеанс"))
        if not path:return
        destination=QFileDialog.getExistingDirectory(self,self.tr("Recovery parent directory","Каталог для восстановления"))
        if destination:
            from uuid import uuid4
            self.send("recover",folder=path,destination=str(Path(destination)/("recovered-"+uuid4().hex[:8])))
    def open_session(self):
        path=QFileDialog.getExistingDirectory(self,self.tr("Open research session","Открыть исследование"))
        if path:self.folder=Path(path);self.load_interval()
    def load_interval(self):
        self.send("episode",folder=str(self.folder) if self.folder else None,start_ms=int(self.begin.value()*1000),end_ms=int(self.end.value()*1000))
    def select_interval(self,start,end):
        self.begin.setValue(start/1000);self.end.setValue(end/1000);self.load_interval()
    def show_evidence(self):
        selected=self.table.selectedItems()
        if selected:
            r=self.table.item(selected[0].row(),0).data(Qt.ItemDataRole.UserRole)
            self.details.setPlainText(json.dumps(r,ensure_ascii=False,indent=2))
    def page(self,backward):
        if not self.page_data:return
        cursor={"before_id":self.page_data.get("first_id")} if backward else {"after_id":self.page_data.get("next_id",0)}
        if cursor.get("before_id")==1:return
        self.send("evidence_page",folder=str(self.folder) if self.folder else None,
            start_ms=int(self.begin.value()*1000),end_ms=int(self.end.value()*1000),**cursor)
    def render_page(self,page):
        self.page_data=page;rows=page["rows"];self.table.setRowCount(len(rows))
        for i,r in enumerate(rows):
            for j,key in enumerate(("elapsed_ms","source","quality","kind")):
                item=QTableWidgetItem(str(r[key]));item.setData(Qt.ItemDataRole.UserRole,r);self.table.setItem(i,j,item)
    def receive(self,op,result,error):
        if error:
            from .research_messages import explain
            self.details.setPlainText(explain(error,self.window.language));return
        if op=="episode" and type(result) is dict:
            self.result=result;self.timeline.set_data(result);self.render_page(result["evidence"])
            self.details.setPlainText(json.dumps({"facts":result["facts"],"limitations":result["limitations"],
                "more_evidence_available":result["evidence"]["has_more"]},ensure_ascii=False,indent=2))
        elif op=="compare" and type(result) is dict:
            self._comparison_result=result;self._render_comparison()
        elif op=="evidence_page" and type(result) is dict:self.render_page(result)
        elif op=="prepare_client" and type(result) is dict:
            self.details.setPlainText(result["instructions"]+"\n\n"+result["folder"])
        elif op not in ("attach","start","prepare","begin","end","mark","interval","detailed","incidents","stop","quit","processes"):
            self.details.setPlainText(json.dumps(result,ensure_ascii=False,indent=2))
    def _render_comparison(self):
        if self._comparison_result is None:return
        if self.machine_fields.isChecked():text=json.dumps(self._comparison_result,ensure_ascii=False,indent=2)
        else:
            from .experiment_view import comparison_text
            text=comparison_text(self._comparison_result,self.window.language)
        self.details.setPlainText(text)

    def elevate(self):
        if os.name!="nt":self.details.setPlainText("UNSUPPORTED_PLATFORM");return
        if self.bridge.active or self.bridge.pending:
            self.details.setPlainText(self.tr("Stop recording first.","Сначала остановите запись."));return
        args=[] if getattr(sys,"frozen",False) else [str(Path(__file__).resolve().parent.parent/"app.py")]
        if self.bridge.pid:args.extend(["--attach-pid",str(self.bridge.pid)])
        shell=ctypes.WinDLL("shell32",use_last_error=True)
        shell.ShellExecuteW.argtypes=[ctypes.c_void_p,ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_int]
        shell.ShellExecuteW.restype=ctypes.c_void_p
        result=shell.ShellExecuteW(None,"runas",sys.executable,subprocess.list2cmdline(args),None,1)
        self.details.setPlainText(self.tr("Elevated instance requested; original evidence retained.","Запрошен отдельный запуск с повышенными правами; исходные данные сохранены.") if result and result>32 else self.tr("Elevation declined or unavailable.","Повышение прав отменено или недоступно."))
