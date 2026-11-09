"""Human-first investigation and unified event controls, no SQLite on Qt."""
from pathlib import Path
from PySide6.QtCore import Qt,Signal,QTimer
from PySide6.QtWidgets import QApplication,QWidget,QVBoxLayout,QHBoxLayout,QGridLayout,QPushButton,QLabel,QComboBox,QLineEdit,QDoubleSpinBox,QTableWidget,QTableWidgetItem,QHeaderView,QPlainTextEdit,QCheckBox,QFileDialog
from blackbox_core.investigation_v2 import QUESTIONS,SORTS
from blackbox_core.event_stream import SOURCES,SEVERITIES
from .evidence_presentation import detail_text,label as evidence_label,raw_json,time_text,title as evidence_title
class EvidencePanel(QWidget):
 range_requested=Signal(str,object,object)
 investigate_requested=Signal(object)
 def __init__(self,window,*,events=False):
  super().__init__(window);self.window=window;self.bridge=window.probe;self.events=events
  self.op='events_query' if events else 'investigation';self.folder=None;self.interval=None;self.origin=None
  self.packet=None;self.card_packet=None;self._generation=0;self._busy=False;self._dirty=False
  self._active_op=None;self._active_generation=None;self._card_request=None;self._selected_key=None
  self.instance_id=None if events else 1;self._query_instance_id=None;self._packet_instance_id=None
  self._suppress_reload=False;self._awaiting_interval=False
  self._cursor=None;self._history=[];self._next=None;self._more=False;self.labels=[]
  box=QVBoxLayout(self);row=QHBoxLayout();self.load=QPushButton();self.open=QPushButton()
  for b,en,ru,fn in ((self.load,'Load events' if events else 'Investigate selected interval','Показать события' if events else 'Расследовать выбранный интервал',self.refresh),
    (self.open,'Open recording…','Открыть запись…',self.choose)):
   self.label(b,en,ru);b.clicked.connect(fn);row.addWidget(b)
  box.addLayout(row);self.source_context=QLabel();self.source_context.setObjectName('evidenceSourceContext')
  self.source_context.setWordWrap(True);self.source_context.setTextFormat(Qt.TextFormat.PlainText)
  self.source_context.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse);box.addWidget(self.source_context)
  filters=QGridLayout();self.question=QComboBox(self);self.sort=QComboBox(self);self.source=QComboBox(self);self.severity=QComboBox(self);self.target=QComboBox(self)
  for v in QUESTIONS:self.question.addItem(v,v)
  for v in SORTS:self.sort.addItem(v,v)
  for v in SOURCES:self.source.addItem(v,v)
  for v in SEVERITIES:self.severity.addItem(v,v)
  self.target.addItem('ALL',0)
  filter_specs=((self.source,'Source group','Группа источника'),(self.severity,'Severity','Уровень'),(self.target,'Process instance','Экземпляр процесса')) if events else ((self.question,'Finding group','Группа находок'),(self.sort,'Order','Порядок'))
  for i,(w,en,ru) in enumerate(filter_specs):
   caption=QLabel();self.label(caption,en,ru);caption.setBuddy(w);filters.addWidget(caption,0,i)
   filters.addWidget(w,1,i);w.activated.connect(self.refresh)
  self.start=QDoubleSpinBox(self);self.end=QDoubleSpinBox(self)
  for w in (self.start,self.end):w.setRange(0,604800);w.setDecimals(3);w.setSuffix(' s');w.editingFinished.connect(self.refresh)
  self.end.setValue(3600);self.search=QLineEdit(self);self.search.setMaxLength(256)
  # Both modes retain the shared control API. Controls outside this mode's
  # layout still need a Qt owner, and explicit hiding preserves their old UI.
  for w in ((self.question,self.sort) if events else (self.source,self.severity,self.target,self.start,self.end,self.search)):w.hide()
  self.timer=QTimer(self);self.timer.setSingleShot(True);self.timer.setInterval(300);self.timer.timeout.connect(self.refresh);self.search.textChanged.connect(lambda:self.timer.start())
  if events:
   for i,(w,en,ru) in enumerate(((self.start,'Start from recording origin (s)','Начало (с от начала отсчёта)'),(self.end,'End from recording origin (s)','Конец (с от начала отсчёта)'))):
    caption=QLabel();self.label(caption,en,ru);caption.setBuddy(w);filters.addWidget(caption,2,i);filters.addWidget(w,3,i)
   filters.addWidget(self.search,4,0,1,3)
  box.addLayout(filters);self.summaries=[]
  if not events:
   for en,ru in (('What was observed','Что наблюдалось'),('Supporting measurements','Подтверждающие измерения'),('What cannot be established','Что нельзя установить')):
    title=QLabel();self.label(title,en,ru);box.addWidget(title);label=QLabel('—');label.setWordWrap(True);label.setTextFormat(Qt.TextFormat.PlainText);box.addWidget(label);self.summaries.append(label)
  self.table=QTableWidget(0,4);self.table.setObjectName('unifiedEvents' if events else 'investigation2Findings')
  self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers);self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows);self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
  self.table.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch);self.table.setMinimumHeight(170)
  for column in (0,2,3):self.table.horizontalHeader().setSectionResizeMode(column,QHeaderView.ResizeMode.ResizeToContents)
  self.table.itemSelectionChanged.connect(self.selected);box.addWidget(self.table)
  self.table.itemDoubleClicked.connect(lambda *_:self.show_interval())
  row=QGridLayout();self.previous=QPushButton();self.next=QPushButton();self.card=QPushButton();self.navigate=QPushButton()
  for i,(b,en,ru,fn) in enumerate(((self.previous,'Previous page','Предыдущая страница',self.back),(self.next,'Next page','Следующая страница',self.forward),
    (self.card,'Incident card','Карточка инцидента',self.open_card),(self.navigate,'Show interval','Показать интервал',self.show_interval))):
   self.label(b,en,ru);b.clicked.connect(fn);row.addWidget(b,i//2,i%2)
  if events:self.card.hide()
  self.investigate=QPushButton();self.investigate.setObjectName('investigateSelectedProblem')
  self.label(self.investigate,'INVESTIGATE PROBLEM','ИССЛЕДОВАТЬ ПРОБЛЕМУ');self.investigate.clicked.connect(self.open_investigation)
  row.addWidget(self.investigate,2,0,1,2)
  self.finding=QPushButton();self.label(self.finding,'Back to finding','Вернуться к находке');self.finding.clicked.connect(self.close_card);row.addWidget(self.finding,3,0)
  self.copy=QPushButton();self.label(self.copy,'Copy displayed details','Копировать показанные сведения');self.copy.clicked.connect(self.copy_detail);row.addWidget(self.copy,3,1)
  if events:self.finding.hide()
  box.addLayout(row);self.raw=QCheckBox();self.raw.setObjectName('evidenceRawJson');self.label(self.raw,'Raw JSON — complete selected record','JSON — полная выбранная запись');self.raw.toggled.connect(self.render_detail);box.addWidget(self.raw)
  self.details=QPlainTextEdit();self.details.setReadOnly(True);self.details.setMaximumHeight(240);box.addWidget(self.details)
  self.status=QLabel();self.status.setWordWrap(True);box.addWidget(self.status)
  if hasattr(self.bridge,'result_ready'):self.bridge.result_ready.connect(self.receive)
  else:self.setEnabled(False)
  self.retranslate();self.controls()
 def tr(self,en,ru):return ru if self.window.language=='RU' else en
 def label(self,w,en,ru):self.labels.append((w,en,ru));w.setText(self.tr(en,ru))
 def retranslate(self):
  for w,en,ru in self.labels:w.setText(self.tr(en,ru))
  for combo,labels in ((self.question,{'ALL':('All findings','Все находки'),'CPU':('CPU','Нагрузка CPU'),'UI':('UI response','Отклик интерфейса'),'MEMORY':('Memory / handles','Память / дескрипторы'),'IO':('I/O','Ввод-вывод'),'COVERAGE':('Coverage','Полнота наблюдений')}),
    (self.sort,{'TIME_ASC':('Earliest first','Сначала ранние'),'TIME_DESC':('Latest first','Сначала поздние'),'SEVERITY':('Severity first','Сначала важные')})):
   for i in range(combo.count()):
    en,ru=labels[combo.itemData(i)];combo.setItemText(i,self.tr(en,ru))
  for combo in (self.source,self.severity):
   for i in range(combo.count()):
    code=combo.itemData(i);combo.setItemText(i,evidence_label(code,self.window.language));combo.setItemData(i,str(code),Qt.ItemDataRole.ToolTipRole)
  self.target.setItemText(0,self.tr('All process instances','Все экземпляры процессов'))
  self.table.setHorizontalHeaderLabels((self.tr('Recording time (s)','Время записи (с)'),self.tr('Event' if self.events else 'Finding','Событие' if self.events else 'Находка'),self.tr('Source group' if self.events else 'Evidence class','Группа источника' if self.events else 'Класс свидетельства'),self.tr('Severity','Уровень')))
  self.table.setToolTip(self.tr('Select a row for facts, sources and limitations. Double-click to show its interval. Original codes are in tooltips and Raw JSON.',
   'Выберите строку для просмотра фактов, источников и ограничений. Двойной щелчок покажет интервал. Исходные коды — в подсказках и JSON.'))
  self.details.setPlaceholderText(self.tr('Load a recording to see findings and their evidence.','Откройте запись, чтобы увидеть находки и их свидетельства.'))
  self.search.setPlaceholderText(self.tr('Literal event code or note…','Код события или текст заметки…'))
  self.render_source_context()
  if self._awaiting_interval:self.status.setText(self.tr('Waiting for recording context…','Ожидание контекста записи…'))
  if self.packet:self.render()
 def render_source_context(self):
  folder=str(self.folder) if self.folder is not None else self.tr('not selected','не выбрана')
  interval=self.packet.get('selected_interval_ns') if self.packet else self.interval
  if isinstance(interval,(tuple,list)) and len(interval)==2 and all(type(value) is int for value in interval):
   selected=time_text({'start_ns':interval[0],'end_ns':interval[1]},self.origin,self.window.language)
  else:selected=self.tr('not loaded / unknown','не загружен / неизвестен')
  scope=self._packet_instance_id if self.packet else (self.target.currentData() if self.events else self.instance_id)
  if self.events and scope==0:scope_text=self.tr('All process instances','Все экземпляры процессов')
  elif type(scope) is int:scope_text=self.tr('Recorded instance ID ','ID записанного экземпляра ')+str(scope)
  else:scope_text=self.tr('not loaded / unknown','не загружен / неизвестен')
  text=self.tr('Recording: ','Запись: ')+folder+'\n'+self.tr('Selected range: ','Выбранный интервал: ')+selected+'\n'+
   self.tr('Event process scope: ' if self.events else 'Counter/thread scope: ','Процессы событий: ' if self.events else 'Процесс счётчиков и потоков: ')+scope_text
  if not self.events:text+='\n'+self.tr('Incidents, markers and source errors retain their source scope.','Инциденты, маркеры и ошибки источников сохраняют область своего источника.')
  self.source_context.setText(text)
 def clear_evidence(self):
  self.packet=None;self.card_packet=None;self._selected_key=None;self._card_request=None;self._packet_instance_id=None
  self.table.blockSignals(True);self.table.setRowCount(0);self.table.blockSignals(False)
  self._cursor=None;self._history=[];self._next=None;self._more=False;self.details.clear();self.status.clear()
  for summary in self.summaries:summary.setText('—')
 def invalidate_interval(self,folder):
  """Forget source-bound evidence without starting or reviving a query.

  An already-running operation keeps its busy lifecycle until its response is
  drained. Its old packet and any scheduled reload cannot repopulate this view.
  """
  self.timer.stop();self._generation+=1;self._suppress_reload=True;self._dirty=False;self._awaiting_interval=True
  self.folder=Path(folder) if folder is not None else None;self.interval=None;self.origin=None;self.instance_id=None;self._query_instance_id=None
  self.clear_evidence();self.target.clear();self.target.addItem(self.tr('All process instances','Все экземпляры процессов'),0)
  self.start.setValue(0);self.end.setValue(3600);self.render_source_context()
  self.status.setText(self.tr('Waiting for recording context…','Ожидание контекста записи…'));self.controls()
 def apply_interval(self,folder,interval,*,origin=None,processes=(),instance_id=1):
  """Bind a recording; instance_id scopes findings, while events use target."""
  if type(instance_id) is not int or not 1<=instance_id<2**63:raise ValueError('INVALID_PROCESS_INSTANCE')
  scope=None if self.events else instance_id
  folder=Path(folder);folder_changed=folder!=self.folder;changed=(folder,interval,scope)!=(self.folder,self.interval,self.instance_id)
  self.folder=folder;self.interval=interval;self.instance_id=scope;self._awaiting_interval=False
  if folder_changed:self.origin=None
  if origin is not None:self.origin=origin
  if changed:
   self._generation+=1;self.clear_evidence()
   if interval and type(self.origin) is int:self.start.setValue(max(0,(interval[0]-self.origin)/1e9));self.end.setValue(max(0,(interval[1]-self.origin)/1e9))
   if self._busy and not self._suppress_reload:self._dirty=True
  elif self._suppress_reload:self.status.clear()
  selected=self.target.currentData();ids=[self.target.itemData(i) for i in range(self.target.count())]
  if ids!=[0]+[r['instance_id'] for r in processes]:
   self.target.clear();self.target.addItem(self.tr('All process instances','Все экземпляры процессов'),0)
   for r in processes:self.target.addItem(f"PID {r['pid']} · {r['creation_time']}",r['instance_id'])
   self.target.setCurrentIndex(max(0,self.target.findData(selected)))
  self.render_source_context();self.controls()
 def choose(self):
  folder=QFileDialog.getExistingDirectory(self,self.tr('Recording folder','Папка записи'))
  if folder:self.apply_interval(folder,None);self.refresh()
 def refresh(self,*_):
  self.timer.stop();self._suppress_reload=False;self._awaiting_interval=False;self._generation+=1;self._cursor=None;self._history=[];self._more=False;self.load_page()
 def load_page(self):
  if self._suppress_reload:return
  if self._busy:self._dirty=True;return
  folder=self.folder or self.bridge.session_folder
  if not folder:return
  if not self.events and self.instance_id is None:
   self._awaiting_interval=True;self.status.setText(self.tr('Waiting for recording context…','Ожидание контекста записи…'));return
  self.folder=Path(folder);self.render_source_context()
  args={'folder':str(folder),'after':self._cursor,'request_key':self._generation}
  if self.events:args.update(limit=100,source=self.source.currentData(),severity=self.severity.currentData(),instance_id=self.target.currentData() or 0,
    search=self.search.text(),start_ms=int(self.start.value()*1000),end_ms=int(self.end.value()*1000))
  else:
   args.update(limit=50,question=self.question.currentData(),sort_order=self.sort.currentData(),instance_id=self.instance_id)
   if self.interval:args.update(start_ns=self.interval[0],end_ns=self.interval[1])
  try:
   self.bridge.send(self.op,**args);self._query_instance_id=args['instance_id'];self._busy=True;self._active_op=self.op;self._active_generation=self._generation;self._dirty=False
   self.status.setText(self.tr('Loading evidence…','Загрузка свидетельств…'));self.controls()
  except (RuntimeError,ValueError) as exc:self.status.setText(str(exc))
 def back(self):
  if self._history and not self._busy:self._cursor=self._history.pop();self.load_page()
 def forward(self):
  if self._more and not self._busy:self._history.append(self._cursor);self._cursor=self._next;self.load_page()
 def selection(self):
  selected=self.table.selectionModel().selectedRows();index=selected[0].row() if selected else -1
  rows=self.packet.get('rows' if self.events else 'findings',[]) if self.packet else []
  return rows[index] if 0<=index<len(rows) else None
 def row_key(self,row):
  if not row:return None
  if self.events:return (row.get('evidence_ref'),row.get('time_ns'),row.get('rank'),row.get('id'))
  return row.get('finding_id') or (row.get('code'),row.get('start_ns'),row.get('end_ns'))
 def incident_id(self,row):
  detail=row.get('detail') if row else None
  return detail.get('incident_id') if isinstance(detail,dict) else None
 def controls(self):
  selected=self.selection();self.load.setEnabled(not self._busy);self.previous.setEnabled(bool(self._history) and not self._busy)
  has_time=selected is not None and type(selected.get('time_ns' if self.events else 'start_ns')) is int
  self.next.setEnabled(self._more and not self._busy);self.navigate.setEnabled(has_time and not self._busy)
  self.card.setEnabled(bool(self.incident_id(selected)) and not self._busy)
  self.investigate.setEnabled(has_time and not self._busy);self.finding.setEnabled(self.card_packet is not None);self.copy.setEnabled(bool(self.details.toPlainText()))
 def open_investigation(self):
  row=self.selection();folder=self.folder or self.bridge.session_folder
  if row is None or folder is None:return
  lo=row.get('time_ns') if self.events else row.get('start_ns');hi=row.get('time_ns') if self.events else row.get('end_ns') or lo
  selection={'start_ns':lo,'end_ns':hi} if type(lo) is int and type(hi) is int else None
  source={'source_type':'SESSION','path':str(folder)}
  if selection:source['selection']=selection
  self.investigate_requested.emit({'sources':[source],'incident_id':self.incident_id(row),'selection':selection})
 def selected(self):self._selected_key=self.row_key(self.selection());self.card_packet=None;self.render_detail();self.controls()
 def close_card(self):self.card_packet=None;self.render_detail();self.controls()
 def copy_detail(self):
  if self.details.toPlainText():QApplication.clipboard().setText(self.details.toPlainText())
 def render_detail(self):
  row=self.card_packet if self.card_packet is not None else self.selection()
  if row is None:self.details.clear();return
  text=raw_json(row) if self.raw.isChecked() else detail_text(row,self.window.language,origin=self.origin,events=self.events,card=self.card_packet is not None)
  self.details.setPlainText(text)
 def open_card(self):
  row=self.selection()
  if not row or not self.incident_id(row) or self._busy:return
  try:
   folder=str(self.folder or self.bridge.session_folder)
   self.bridge.send('incident_card',folder=folder,incident_id=self.incident_id(row));self._busy=True;self._active_op='incident_card'
   self._card_request=(self._generation,folder,self.row_key(row));self.controls()
  except (ValueError,RuntimeError) as exc:self.status.setText(str(exc))
 def show_interval(self):
  row=self.selection()
  if row and not self._busy and type(row.get('time_ns' if self.events else 'start_ns')) is int:
   lo=row['time_ns']-2*10**9 if self.events else row['start_ns']-60*10**9
   hi=row['time_ns']+2*10**9 if self.events else (row['end_ns'] or row['start_ns'])+20*10**9
   self.range_requested.emit(str(self.folder or self.bridge.session_folder),max(0,lo),hi)
 def render(self):
  p=self.packet;rows=p['rows' if self.events else 'findings'];self.origin=p['monotonic_origin_ns'] if self.events else p['metadata']['monotonic_origin_ns']
  self.render_source_context()
  selected=self._selected_key;self.table.blockSignals(True);self.table.setRowCount(len(rows))
  for i,row in enumerate(rows):
   stamp=row.get('time_ns' if self.events else 'start_ns');time=f'{(stamp-self.origin)/1e9:.3f}' if type(stamp) is int and type(self.origin) is int else '—'
   raw_values=(stamp,row['code'],row['source'] if self.events else row['confidence_class'],row['severity'])
   values=(time,evidence_title(row['code'],self.window.language),evidence_label(raw_values[2],self.window.language),evidence_label(row['severity'],self.window.language))
   for j,value in enumerate(values):
    item=QTableWidgetItem(str(value));item.setToolTip(str(raw_values[j]));self.table.setItem(i,j,item)
  self.table.clearSelection()
  selected_index=next((i for i,row in enumerate(rows) if self.row_key(row)==selected),0 if rows else -1)
  if selected_index>=0:self.table.selectRow(selected_index)
  self._selected_key=self.row_key(rows[selected_index]) if selected_index>=0 else None
  self.table.blockSignals(False);self._more=p['has_more'];self._next=p['next_cursor'];self.render_detail()
  total=p['total_matching' if self.events else 'findings_total'];self.status.setText(self.tr('Page ','Страница ')+str(len(self._history)+1)+self.tr(' · shown / matching: ',' · показано / найдено: ')+f'{len(rows)} / {total} · '+evidence_label(p.get('source_trust',p.get('file_trust','UNKNOWN')),self.window.language))
  if not self.events:
   cov=p['coverage'];metrics=p['summary']['support']['metrics'];self.summaries[0].setText(self.tr('Samples / findings: ','Измерений / находок: ')+f"{cov['selected_samples']} / {total}")
   cpu,rss=metrics['cpu_interval_percent']['max'],metrics['rss_bytes']['max'];unknown=self.tr('not observed','не наблюдалось')
   self.summaries[1].setText(self.tr('Observed CPU peak: ','Наблюдавшийся пик CPU: ')+(f'{cpu:.2f}%'+self.tr(' of one CPU',' одного CPU') if cpu is not None else unknown)+
    self.tr(' · RSS peak: ',' · Пик RSS: ')+(f'{rss/1048576:.2f} MiB' if rss is not None else unknown)+self.tr(' · gaps: ',' · разрывы: ')+str(cov['spacing_gap_pairs']))
   self.summaries[2].setText(self.tr('Root cause, memory leak and between-sample activity are not established. Imported source claims are not authenticated.',
    'Причина, утечка памяти и активность между опросами не установлены. Заявления источника в импортированном файле не удостоверяют его подлинность.'))
   io=p.get('application_io_latency',{})
   if io.get('groups'):
    self.summaries[1].setText(self.summaries[1].text()+' · '+self.tr('App-reported I/O median / p95 (ns): ','I/O со слов приложения, медиана / p95 (нс): ')+
     '; '.join(r['io_kind']+': '+str(r['median'])+' / '+str(r['p95']) for r in io['groups']))
  self.controls()
 def receive(self,op,result,error):
  if op not in ((self.op,'incident_card') if not self.events else (self.op,)) or not self._busy or op!=self._active_op:return
  self._busy=False;self._active_op=None
  current_card=(self._generation,str(self.folder or self.bridge.session_folder),self.row_key(self.selection()))
  stale_card=op=='incident_card' and self._card_request!=current_card
  stale_query=op==self.op and self._active_generation!=self._generation
  if self._suppress_reload:self._dirty=False
  elif stale_card or stale_query:
   if stale_query:self._dirty=True
  elif error:
   from .research_messages import explain
   self.status.setText(explain(error,self.window.language))
  elif op=='incident_card':self.card_packet=result;self.render_detail()
  elif result.get('request_key')==self._generation:self.packet=result;self._packet_instance_id=self._query_instance_id;self.card_packet=None;self.render()
  else:self._dirty=True
  self.controls()
  if self._dirty:QTimer.singleShot(0,self.load_page)

