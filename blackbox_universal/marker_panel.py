"""Explicit USER markers on Reports, acknowledged only after durable commit."""
from PySide6.QtWidgets import QWidget,QVBoxLayout,QHBoxLayout,QLineEdit,QComboBox,QPushButton,QLabel
from .action_grid import ActionGrid
class MarkerPanel(QWidget):
 def __init__(self,window):
  super().__init__(window);self.window=window;self.bridge=window.probe;layout=QVBoxLayout(self);self.buttons=[];self.labels=[]
  self.name=QLineEdit();self.name.setMaxLength(128);self.note=QLineEdit();self.note.setMaxLength(2048)
  layout.addWidget(self.name);layout.addWidget(self.note);self.stages=QComboBox();layout.addWidget(self.stages)
  row=ActionGrid(max_columns=4);self.action_grid=row
  for kind,en,ru in (('STAGE_BEGIN','Begin stage','Начать этап'),('STAGE_END','End stage','Завершить этап'),('COMMENT','Comment','Комментарий'),('PROBLEM','Problem','Проблема')):
   b=QPushButton();b.clicked.connect(lambda checked=False,k=kind:self.send(k));self.labels.append((b,en,ru));row.addWidget(b);self.buttons.append((kind,b))
  layout.addLayout(row);self.status=QLabel();self.status.setWordWrap(True);layout.addWidget(self.status)
  if hasattr(self.bridge,'result_ready'):self.bridge.result_ready.connect(self.receive);self.bridge.updated.connect(self.refresh)
  else:self.setEnabled(False)
  self.retranslate()
 def retranslate(self):
  self.action_grid.invalidate()
  ru=self.window.language=='RU'
  for b,en,text in self.labels:b.setText(text if ru else en)
  self.name.setPlaceholderText('Название этапа' if ru else 'Stage name');self.note.setPlaceholderText('Заметка пользователя' if ru else 'User note')
 def refresh(self):
  rows=self.bridge.snapshot().get('active_stages',[]);selected=self.stages.currentData()
  current=[self.stages.itemData(i) for i in range(self.stages.count())]
  if current!=[r['stage_id'] for r in rows]:
   self.stages.clear()
   for r in rows:self.stages.addItem(r['name'],r['stage_id'])
   self.stages.setCurrentIndex(max(0,self.stages.findData(selected)))
  for kind,b in self.buttons:b.setEnabled(self.bridge.active and not self.bridge.pending and (kind!='STAGE_END' or bool(rows)))
 def send(self,kind):
  try:self.bridge.send('user_marker',kind=kind,name=self.name.text(),note=self.note.text(),stage_id=self.stages.currentData())
  except (RuntimeError,ValueError) as exc:self.status.setText(str(exc))
 def receive(self,op,result,error):
  if op=='user_marker':self.status.setText(error or 'USER_DECLARED · research.sqlite3:evidence:'+str(result['evidence_id']))

