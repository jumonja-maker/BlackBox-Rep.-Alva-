"""Human metric definitions and bounded health; visible Settings only."""
from html import escape
from PySide6.QtWidgets import QWidget,QVBoxLayout,QPushButton,QTableWidget,QTableWidgetItem,QHeaderView,QDialog,QTextBrowser
class MeasurementHelp(QWidget):
 def __init__(self,window):
  super().__init__(window);self.window=window;self._key=None;box=QVBoxLayout(self);self.button=QPushButton();self.button.clicked.connect(self.help);box.addWidget(self.button)
  self.table=QTableWidget(0,6);self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers);self.table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch);self.table.setMaximumHeight(220);box.addWidget(self.table)
  if hasattr(window.probe,'updated'):window.probe.updated.connect(self.refresh)
  self.retranslate()
 def retranslate(self):
  self.button.setText('Определения, формулы и ограничения метрик' if self.window.language=='RU' else 'Metric definitions, formulas and limitations')
  self.table.setHorizontalHeaderLabels(('ДАТЧИК','SOURCE','СОСТОЯНИЕ','ПРАВА','ПОСЛ. / P95 ms','ОШИБКИ / БЮДЖЕТ') if self.window.language=='RU' else ('SENSOR','SOURCE','STATUS','PERMISSIONS','LAST / P95 ms','ERRORS / OVERRUNS'))
 def showEvent(self,event):super().showEvent(event);self._key=None;self.refresh()
 def refresh(self):
  if not self.isVisible():return
  rows=getattr(self.window.probe,'data',{}).get('sensor_health',{});key=tuple((k,r.get('samples'),r.get('failures'),r.get('status')) for k,r in rows.items())
  if key==self._key:return
  self._key=key;self.table.setRowCount(len(rows))
  for i,(name,r) in enumerate(rows.items()):
   values=(name,r['source'],r['status'],r.get('permissions'),str(r.get('sample_ms'))+' / '+str(r.get('latency_p95_ms')),str(r['failures'])+' / '+str(r['overruns']))
   for j,value in enumerate(values):
    item=QTableWidgetItem(str(value));item.setToolTip(str(r.get('limitations'))+'\n'+str(r.get('source_error') or r.get('error') or ''));self.table.setItem(i,j,item)
 def help(self):
  from blackbox_core.metric_help import definitions
  dialog=QDialog(self);dialog.resize(800,650);dialog.setWindowTitle(self.button.text());box=QVBoxLayout(dialog);browser=QTextBrowser();browser.setOpenExternalLinks(False);box.addWidget(browser)
  rows=[]
  rows.append('<h2>'+('Доступность источников' if self.window.language=='RU' else 'Source capabilities')+'</h2>')
  for item in getattr(self.window.probe,'data',{}).get('capability_inventory',[]):
   rows.append('<p>'+escape(str(item.get('capability_id'))+' · '+str(item.get('source_id'))+' · '+str(item.get('availability'))+' · '+str(item.get('accuracy_notes')))+'</p>')
  for r in definitions()['metrics']:rows.append('<h3>'+escape(r['metric'])+'</h3><p>'+escape(r['source']+' · '+r['unit'])+'</p><p>'+escape(r['explanation_ru' if self.window.language=='RU' else 'explanation_en'])+'</p>')
  browser.setHtml(''.join(rows));dialog.exec()

