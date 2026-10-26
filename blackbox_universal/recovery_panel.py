"""Explicit inspection/confirmation of interrupted exports via isolated operations."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget,QVBoxLayout,QGridLayout,QLabel,QComboBox,QPushButton,QPlainTextEdit,QFileDialog,QMessageBox
class RecoveryPanel(QWidget):
 def __init__(self,window):
  super().__init__(window);self.window=window;self.bridge=window.probe;self.folder=None;self.rows=[];self.busy=False;self.labels=[]
  box=QVBoxLayout(self);self.note=QLabel();self.note.setWordWrap(True);box.addWidget(self.note)
  self.choose=QPushButton();self.finish=QPushButton();self.discard=QPushButton();grid=QGridLayout()
  for i,(w,en,ru,fn) in enumerate(((self.choose,'Inspect export folder…','Проверить папку экспорта…',self.inspect),
    (self.finish,'Finish selected export…','Завершить выбранный экспорт…',lambda:self.recover('FINISH')),
    (self.discard,'Discard verified temporary files…','Удалить проверенные временные файлы…',lambda:self.recover('DISCARD')))):
   self.labels.append((w,en,ru));w.clicked.connect(fn);grid.addWidget(w,i//2,i%2)
  box.addLayout(grid);self.selection=QComboBox();self.selection.currentIndexChanged.connect(self.controls);box.addWidget(self.selection)
  self.detail=QPlainTextEdit();self.detail.setReadOnly(True);self.detail.setMaximumHeight(130);box.addWidget(self.detail)
  self.status=QLabel();self.status.setWordWrap(True);box.addWidget(self.status)
  if hasattr(self.bridge,'result_ready'):self.bridge.result_ready.connect(self.receive)
  else:self.setEnabled(False)
  self.retranslate();self.controls()
 def tr(self,en,ru):return ru if self.window.language=='RU' else en
 def retranslate(self):
  for w,en,ru in self.labels:w.setText(self.tr(en,ru))
  self.note.setText(self.tr('Interrupted exports are retained locally. Recovery/delete requires confirmation; original recordings are not edited.',
   'Прерванные экспорты сохраняются локально. Продолжение/удаление требует подтверждения; исходные записи не редактируются.'))
 def controls(self,*_):
  i=self.selection.currentIndex();row=self.rows[i] if 0<=i<len(self.rows) else None
  allowed=bool(row and row.get('owner_active') is False and row.get('state')!='INVALID_RETAINED' and not self.busy)
  self.choose.setEnabled(not self.busy);self.finish.setEnabled(allowed and row.get('can_finish',False));self.discard.setEnabled(allowed)
  if row:self.detail.setPlainText(row['journal']+'\n'+str(row['state'])+'\n'+self.tr('Owner active: ','Владелец активен: ')+str(row.get('owner_active')))
 def send(self,op,**args):
  try:self.bridge.send(op,**args);self.busy=True;self.controls()
  except (ValueError,RuntimeError) as exc:self.status.setText(str(exc))
 def inspect(self):
  folder=QFileDialog.getExistingDirectory(self,self.tr('Export folder','Папка экспорта'))
  if folder:self.folder=folder;self.send('export_recovery_scan',folder=folder)
 def recover(self,action):
  i=self.selection.currentIndex()
  if self.busy or not 0<=i<len(self.rows):return
  row=self.rows[i]
  if row.get('owner_active') is not False:return
  text=self.tr('Finish publication without overwriting existing files?' if action=='FINISH' else 'Permanently remove only verified partial files of this export?',
   'Завершить публикацию без перезаписи существующих файлов?' if action=='FINISH' else 'Безвозвратно удалить только проверенные временные файлы этого экспорта?')
  confirm=QMessageBox(self);confirm.setWindowTitle(self.tr('Confirm export recovery','Подтвердить восстановление экспорта'))
  confirm.setTextFormat(Qt.TextFormat.PlainText);confirm.setText(text+'\n'+row['journal']);confirm.setStandardButtons(QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No);confirm.setDefaultButton(QMessageBox.StandardButton.No)
  if confirm.exec()==QMessageBox.StandardButton.Yes:self.send('export_recover',journal=row['journal'],action=action,confirmed=True)
 def receive(self,op,result,error):
  if op not in ('export_recovery_scan','export_recover') or not self.busy:return
  self.busy=False
  if error:
   from .research_messages import explain
   self.status.setText(explain(error,self.window.language))
  elif op=='export_recover':self.status.setText(result['status']);self.send('export_recovery_scan',folder=self.folder)
  else:
   self.rows=result['rows'];self.selection.blockSignals(True);self.selection.clear()
   for row in self.rows:self.selection.addItem(row['journal'].rsplit('/',1)[-1]+' · '+str(row['state']))
   self.selection.blockSignals(False);self.status.setText(self.tr('Journals: ','Журналов: ')+str(len(self.rows)))
  self.controls()

