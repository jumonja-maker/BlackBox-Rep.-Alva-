"""Human-first investigation and unified event controls, no SQLite on Qt."""
import json
from pathlib import Path
from PySide6.QtCore import Qt,Signal,QTimer
from PySide6.QtWidgets import QWidget,QVBoxLayout,QHBoxLayout,QGridLayout,QPushButton,QLabel,QComboBox,QLineEdit,QDoubleSpinBox,QTableWidget,QTableWidgetItem,QHeaderView,QPlainTextEdit,QCheckBox,QFileDialog
from blackbox_core.investigation_v2 import QUESTIONS,SORTS
from blackbox_core.event_stream import SOURCES,SEVERITIES
class EvidencePanel(QWidget):
 range_requested=Signal(str,object,object)
 def __init__(self,window,*,events=False):
  super().__init__(window);self.window=window;self.bridge=window.probe;self.events=events
  self.op='events_query' if events else 'investigation';self.folder=None;self.interval=None;self.origin=0
  self.packet=None;self.card_packet=None;self._generation=0;self._busy=False;self._dirty=False
  self._cursor=None;self._history=[];self._next=None;self._more=False;self.labels=[]
  box=QVBoxLayout(self);row=QHBoxLayout();self.load=QPushButton();self.open=QPushButton()
  for b,en,ru,fn in ((self.load,'Load events' if events else 'Investigate selected interval','Показать события' if events else 'Расследовать выбранный интервал',self.refresh),
    (self.open,'Open recording…','Открыть запись…',self.choose)):
   self.label(b,en,ru);b.clicked.connect(fn);row.addWidget(b)
  box.addLayout(row);filters=QGridLayout();self.question=QComboBox();self.sort=QComboBox();self.source=QComboBox();self.severity=QComboBox();self.target=QComboBox()
  for v in QUESTIONS:self.question.addItem(v,v)
  for v in SORTS:self.sort.addItem(v,v)
  for v in SOURCES:self.source.addItem(v,v)
  for v in SEVERITIES:self.severity.addItem(v,v)
  self.target.addItem('ALL',0)
  for i,w in enumerate((self.source,self.severity,self.target) if events else (self.question,self.sort)):
   filters.addWidget(w,0,i);w.activated.connect(self.refresh)
  self.start=QDoubleSpinBox();self.end=QDoubleSpinBox()
  for w in (self.start,self.end):w.setRange(0,604800);w.setDecimals(3);w.setSuffix(' s');w.editingFinished.connect(self.refresh)
  self.end.setValue(3600);self.search=QLineEdit();self.search.setMaxLength(256)
  self.timer=QTimer(self);self.timer.setSingleShot(True);self.timer.setInterval(300);self.timer.timeout.connect(self.refresh);self.search.textChanged.connect(lambda:self.timer.start())
  if events:filters.addWidget(self.start,1,0);filters.addWidget(self.end,1,1);filters.addWidget(self.search,2,0,1,3)
  box.addLayout(filters);self.summaries=[]
  if not events:
   for en,ru in (('What was observed','Что наблюдалось'),('Supporting measurements','Подтверждающие измерения'),('What cannot be established','Что нельзя установить')):
    title=QLabel();self.label(title,en,ru);box.addWidget(title);label=QLabel('—');label.setWordWrap(True);label.setTextFormat(Qt.TextFormat.PlainText);box.addWidget(label);self.summaries.append(label)
  self.table=QTableWidget(0,4);self.table.setObjectName('unifiedEvents' if events else 'investigation2Findings')
  self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers);self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows);self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
  self.table.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch);self.table.setMinimumHeight(170)
  self.table.itemSelectionChanged.connect(self.selected);box.addWidget(self.table)
  row=QGridLayout();self.previous=QPushButton();self.next=QPushButton();self.card=QPushButton();self.navigate=QPushButton()
  for i,(b,en,ru,fn) in enumerate(((self.previous,'Previous page','Предыдущая страница',self.back),(self.next,'Next page','Следующая страница',self.forward),
    (self.card,'Incident card','Карточка инцидента',self.open_card),(self.navigate,'Show interval','Показать интервал',self.show_interval))):
   self.label(b,en,ru);b.clicked.connect(fn);row.addWidget(b,i//2,i%2)
  if events:self.card.hide()
  box.addLayout(row);self.raw=QCheckBox();self.label(self.raw,'Technical data','Технические данные');self.raw.toggled.connect(self.render_detail);box.addWidget(self.raw)
  self.details=QPlainTextEdit();self.details.setReadOnly(True);self.details.setMaximumHeight(240);box.addWidget(self.details)
  self.status=QLabel();self.status.setWordWrap(True);box.addWidget(self.status)
  if hasattr(self.bridge,'result_ready'):self.bridge.result_ready.connect(self.receive)
  else:self.setEnabled(False)
  self.retranslate();self.controls()
 def tr(self,en,ru):return ru if self.window.language=='RU' else en
 def label(self,w,en,ru):self.labels.append((w,en,ru));w.setText(self.tr(en,ru))
 def retranslate(self):
  for w,en,ru in self.labels:w.setText(self.tr(en,ru))
  self.table.setHorizontalHeaderLabels((self.tr('Time (s)','Время (с)'),self.tr('Code','Код'),self.tr('Source / class','Источник / класс'),self.tr('Severity','Уровень')))
  self.search.setPlaceholderText(self.tr('Literal event code or note…','Код события или текст заметки…'))
  if self.packet:self.render()
 def apply_interval(self,folder,interval,*,origin=None,processes=()):
  folder=Path(folder);changed=(folder,interval)!=(self.folder,self.interval);self.folder=folder;self.interval=interval
  if origin is not None:self.origin=origin
  if changed:
   self._generation+=1;self.packet=None;self.card_packet=None;self.table.setRowCount(0);self._cursor=None;self._history=[];self._more=False;self.details.clear()
   if interval:self.start.setValue(max(0,(interval[0]-self.origin)/1e9));self.end.setValue(max(0,(interval[1]-self.origin)/1e9))
   if self._busy:self._dirty=True
  selected=self.target.currentData();ids=[self.target.itemData(i) for i in range(self.target.count())]
  if ids!=[0]+[r['instance_id'] for r in processes]:
   self.target.clear();self.target.addItem('ALL',0)
   for r in processes:self.target.addItem(f"PID {r['pid']} · {r['creation_time']}",r['instance_id'])
   self.target.setCurrentIndex(max(0,self.target.findData(selected)))
  self.controls()
 def choose(self):
  folder=QFileDialog.getExistingDirectory(self,self.tr('Recording folder','Папка записи'))
  if folder:self.apply_interval(folder,None);self.refresh()
 def refresh(self,*_):
  self.timer.stop();self._generation+=1;self._cursor=None;self._history=[];self._more=False;self.load_page()
 def load_page(self):
  if self._busy:self._dirty=True;return
  folder=self.folder or self.bridge.session_folder
  if not folder:return
  args={'folder':str(folder),'after':self._cursor,'request_key':self._generation}
  if self.events:args.update(limit=100,source=self.source.currentData(),severity=self.severity.currentData(),instance_id=self.target.currentData() or 0,
    search=self.search.text(),start_ms=int(self.start.value()*1000),end_ms=int(self.end.value()*1000))
  else:
   args.update(limit=50,question=self.question.currentData(),sort_order=self.sort.currentData())
   if self.interval:args.update(start_ns=self.interval[0],end_ns=self.interval[1])
  try:self.bridge.send(self.op,**args);self._busy=True;self._dirty=False;self.controls()
  except (RuntimeError,ValueError) as exc:self.status.setText(str(exc))
 def back(self):
  if self._history and not self._busy:self._cursor=self._history.pop();self.load_page()
 def forward(self):
  if self._more and not self._busy:self._history.append(self._cursor);self._cursor=self._next;self.load_page()
 def selection(self):
  selected=self.table.selectionModel().selectedRows();index=selected[0].row() if selected else -1
  rows=self.packet.get('rows' if self.events else 'findings',[]) if self.packet else []
  return rows[index] if 0<=index<len(rows) else None
 def controls(self):
  selected=self.selection();self.load.setEnabled(not self._busy);self.previous.setEnabled(bool(self._history) and not self._busy)
  self.next.setEnabled(self._more and not self._busy);self.navigate.setEnabled(selected is not None and not self._busy)
  self.card.setEnabled(bool(selected and selected.get('detail',{}).get('incident_id')) and not self._busy)
 def selected(self):self.card_packet=None;self.render_detail();self.controls()
 def render_detail(self):
  row=self.card_packet or self.selection()
  if not row:self.details.clear();return
  if self.raw.isChecked():text=json.dumps(row,ensure_ascii=False,indent=2)
  elif self.card_packet:
   text=self.tr('Incident observations; root cause UNKNOWN.','Наблюдения инцидента; причина UNKNOWN.')+'\n'
   text+='\n'.join(name+': '+r['status']+' · '+str(r.get('values')) for name,r in row.get('snapshots',{}).items())
   text+='\n'+self.tr('Post-context complete: ','Контекст после полный: ')+str(row.get('post_context_complete'))
   text+='\n'+', '.join(row.get('next_actions',[]))
  elif self.events:text=row['code']+'\n'+row['source']+' · UNVERIFIED_IMPORT\n'+json.dumps(row['detail'],ensure_ascii=False,indent=2)
  else:text=row['code']+' · '+row['confidence_class']+'\n'+self.tr('Facts: ','Факты: ')+json.dumps(row['facts'],ensure_ascii=False,indent=2)+'\n'+self.tr('Alternatives: ','Альтернативы: ')+', '.join(row['alternative_explanations'])+'\n'+self.tr('Limitations: ','Ограничения: ')+', '.join(row['limitations'])+'\nRoot cause: UNKNOWN.'
  self.details.setPlainText(text)
 def open_card(self):
  row=self.selection()
  if not row:return
  try:self.bridge.send('incident_card',folder=str(self.folder or self.bridge.session_folder),incident_id=row['detail']['incident_id']);self._busy=True;self.controls()
  except (ValueError,RuntimeError) as exc:self.status.setText(str(exc))
 def show_interval(self):
  row=self.selection()
  if row:
   lo=row['time_ns']-2*10**9 if self.events else row['start_ns']-60*10**9
   hi=row['time_ns']+2*10**9 if self.events else (row['end_ns'] or row['start_ns'])+20*10**9
   self.range_requested.emit(str(self.folder or self.bridge.session_folder),max(0,lo),hi)
 def render(self):
  p=self.packet;rows=p['rows' if self.events else 'findings'];self.origin=p['monotonic_origin_ns'] if self.events else p['metadata']['monotonic_origin_ns']
  self.table.blockSignals(True);self.table.setRowCount(len(rows))
  for i,row in enumerate(rows):
   stamp=row['time_ns'] if self.events else row['start_ns']
   for j,value in enumerate((f'{(stamp-self.origin)/1e9:.3f}',row['code'],row['source'] if self.events else row['confidence_class'],row['severity'])):self.table.setItem(i,j,QTableWidgetItem(str(value)))
  self.table.clearSelection();self.table.blockSignals(False);self._more=p['has_more'];self._next=p['next_cursor']
  total=p['total_matching' if self.events else 'findings_total'];self.status.setText(self.tr('Shown / matching: ','Показано / найдено: ')+f'{len(rows)} / {total} · UNVERIFIED_IMPORT')
  if not self.events:
   cov=p['coverage'];metrics=p['summary']['support']['metrics'];self.summaries[0].setText(self.tr('Samples / findings: ','Измерений / находок: ')+f"{cov['selected_samples']} / {total}")
   self.summaries[1].setText(self.tr('Observed CPU peak (% of one CPU), RSS peak (bytes): ','Наблюдавшийся пик CPU (% одного CPU), RSS (байт): ')+str(metrics['cpu_interval_percent']['max'])+' / '+str(metrics['rss_bytes']['max'])+self.tr('; gaps: ','; разрывы: ')+str(cov['spacing_gap_pairs']))
   self.summaries[2].setText(self.tr('Root cause, memory leak and between-sample activity are not established. Imported source claims are not authenticated.',
    'Причина, утечка памяти и активность между опросами не установлены. Заявления источника в импортированном файле не удостоверяют его подлинность.'))
   io=p.get('application_io_latency',{})
   if io.get('groups'):
    self.summaries[1].setText(self.summaries[1].text()+' · '+self.tr('App-reported I/O median / p95 (ns): ','I/O со слов приложения, медиана / p95 (нс): ')+
     '; '.join(r['io_kind']+': '+str(r['median'])+' / '+str(r['p95']) for r in io['groups']))
  self.controls()
 def receive(self,op,result,error):
  if op not in ((self.op,'incident_card') if not self.events else (self.op,)) or not self._busy:return
  self._busy=False
  if error:
   from .research_messages import explain
   self.status.setText(explain(error,self.window.language))
  elif op=='incident_card':self.card_packet=result;self.render_detail()
  elif result.get('request_key')==self._generation:self.packet=result;self.card_packet=None;self.render()
  else:self._dirty=True
  self.controls()
  if self._dirty:QTimer.singleShot(0,self.load_page)

