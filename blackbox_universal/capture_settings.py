"""Profile settings are commands to the isolated owner, never on-paint I/O."""
from PySide6.QtWidgets import QWidget,QVBoxLayout,QFormLayout,QComboBox,QSpinBox,QDoubleSpinBox,QCheckBox,QPushButton,QLabel
from blackbox_core.capture_policy import DEFAULT,validate_policy,TRIGGERS
FIELDS={
 'detail_interval_ms':('Detail interval, ms','Интервал подробной записи, мс',500,30000),
 'thread_limit':('Thread capture limit','Лимит опроса потоков',1,1024),
 'child_limit':('Child capture limit','Лимит опроса потомков',1,256),
 'top_threads':('Top thread rows','Строк потоков в отчёте',1,256),
 'burst_seconds':('Incident Burst TTL, s','Срок Incident Burst, с',1,60),
 'burst_interval_ms':('Burst interval, ms','Интервал Burst, мс',500,5000),
 'session_seconds':('Session limit, s (0: off)','Срок записи, с (0: выкл.)',0,604800),
 'max_session_mb':('Session soft limit, MiB','Мягкий лимит записи, MiB',16,1048576),
 'max_trace_mb':('Trace soft limit, MiB','Мягкий лимит трассы, MiB',1,1024)}
INCIDENT={
 'threshold':('CPU threshold (% of one CPU)','Порог CPU (% одного CPU)',.1,6400.),
 'min_duration_ms':('CPU sustained duration, ms','Длительность превышения CPU, мс',0,3600000),
 'gap_ms':('Sampling gap threshold, ms','Порог разрыва опроса, мс',1,3600000),
 'pre_ms':('Pre-context, ms','Контекст до, мс',0,300000),
 'post_ms':('Post-context, ms','Контекст после, мс',0,60000),
 'cooldown_ms':('Cooldown, ms','Пауза между инцидентами, мс',0,3600000),
 'max_incidents':('Incident limit','Лимит инцидентов',1,1000),
 'memory_growth_bytes':('Memory growth, bytes','Рост памяти, байт',0,2147483647),
 'handle_growth':('Handle growth','Рост дескрипторов',0,1048576),
 'growth_window_ms':('Growth window, ms','Окно роста, мс',0,60000),
 'io_rate_bytes_s':('I/O threshold, bytes/s','Порог I/O, байт/с',0,2147483647)}
class CaptureSettings(QWidget):
 def __init__(self,window):
  super().__init__(window);self.window=window;self.bridge=window.probe;self.labels=[];self.boxes={};self.triggers={}
  layout=QVBoxLayout(self);self.profile=QComboBox()
  for value in ('STANDARD','DETAILED','INCIDENT_BURST'):self.profile.addItem(value,value)
  layout.addWidget(self.profile);self.note=QLabel();self.note.setWordWrap(True);layout.addWidget(self.note)
  toggle=QPushButton();self.labels.append((toggle,'Profile limits and trigger policies','Лимиты профиля и политики инцидентов'))
  toggle.setCheckable(True);layout.addWidget(toggle);self.form_widget=QWidget();form=QFormLayout(self.form_widget)
  for prefix,fields in (('',FIELDS),('incident.',INCIDENT)):
   for key,(en,ru,lo,hi) in fields.items():
    box=QDoubleSpinBox() if key=='threshold' else QSpinBox();box.setRange(lo,hi);box.setValue(DEFAULT['incident'][key] if prefix else DEFAULT[key])
    label=QLabel();label.setWordWrap(True);self.labels.append((label,en,ru));form.addRow(label,box);self.boxes[prefix+key]=box
  self.windows=QCheckBox();self.incidents=QCheckBox();self.gaps=QCheckBox();self.adaptive=QCheckBox();self.adaptive.setChecked(True);self.reference=QComboBox()
  self.reference.addItems(('ABSOLUTE','BASELINE_DELTA'))
  for w,en,ru in ((self.windows,'Observe Windows responsiveness / WCT','Наблюдать отзывчивость Windows / WCT'),(self.incidents,'Enable incident detection','Включить обнаружение инцидентов'),(self.gaps,'Create incidents for sampling gaps','Создавать инциденты разрывов опроса')):
   self.labels.append((w,en,ru));form.addRow(w)
  form.addRow('CPU reference',self.reference)
  self.labels.append((self.adaptive,'Reduce sampling frequency on sustained observer usage','Снижать частоту при длительной нагрузке наблюдателя'));form.addRow(self.adaptive)
  for trigger in TRIGGERS:
   box=QCheckBox(trigger);box.setChecked(trigger in DEFAULT['incident']['enabled_triggers']);self.triggers[trigger]=box;form.addRow(box)
  layout.addWidget(self.form_widget);self.form_widget.hide();toggle.toggled.connect(self.form_widget.setVisible)
  self.apply=QPushButton();self.labels.append((self.apply,'Apply before recording','Применить до начала записи'));self.apply.clicked.connect(self.commit);layout.addWidget(self.apply)
  self.status=QLabel();self.status.setWordWrap(True);layout.addWidget(self.status)
  if hasattr(self.bridge,'result_ready'):self.bridge.result_ready.connect(self.receive);self.bridge.updated.connect(self.refresh)
  else:self.setEnabled(False)
  self.retranslate()
 def tr(self,en,ru):return ru if self.window.language=='RU' else en
 def retranslate(self):
  for w,en,ru in self.labels:w.setText(self.tr(en,ru))
  self.note.setText(self.tr('Standard: base counters. Detailed: extra thread/child/memory queries. Burst: bounded detail after an incident. Profiles do not start ETW or dumps. Actual overhead requires a benchmark.',
   'Standard: базовые счётчики. Detailed: дополнительные запросы потоков, потомков и памяти. Burst: подробная запись на ограниченное время после инцидента. Профили не запускают ETW и дампы. Нагрузку нужно измерять.'))
 def values(self):
  p={};incident={}
  for key,box in self.boxes.items():
   if key.startswith('incident.'):incident[key.split('.')[1]]=box.value()
   else:p[key]=box.value()
  incident.update(enabled_triggers=[k for k,w in self.triggers.items() if w.isChecked()],cpu_reference=self.reference.currentText(),gap_incidents=self.gaps.isChecked())
  p.update(profile=self.profile.currentData(),windows_enabled=self.windows.isChecked(),incident_enabled=self.incidents.isChecked(),adaptive_throttle=self.adaptive.isChecked(),incident=incident)
  return validate_policy(p)
 def commit(self):
  try:self.bridge.send('capture_policy',policy=self.values())
  except (ValueError,RuntimeError) as exc:
   from .research_messages import explain
   self.status.setText(explain(str(exc),self.window.language))
 def refresh(self):self.apply.setEnabled(not self.bridge.active and not self.bridge.pending);self.form_widget.setEnabled(not self.bridge.active);self.profile.setEnabled(not self.bridge.active)
 def receive(self,op,result,error):
  if op!='capture_policy':return
  if error:self.status.setText(error);return
  self.status.setText(self.tr('Policy applied. ETW and dumps remain explicit.','Политика применена. ETW и дампы запускаются отдельно.'))
  p=result['policy'];self.profile.setCurrentIndex(self.profile.findData(p['profile']))
  for key,box in self.boxes.items():box.setValue(p['incident'][key.split('.')[1]] if key.startswith('incident.') else p[key])
  self.windows.setChecked(p['windows_enabled']);self.incidents.setChecked(p['incident_enabled']);self.gaps.setChecked(p['incident']['gap_incidents'])
  self.adaptive.setChecked(p['adaptive_throttle'])
  self.reference.setCurrentText(p['incident']['cpu_reference'])
  for key,box in self.triggers.items():box.setChecked(key in p['incident']['enabled_triggers'])

