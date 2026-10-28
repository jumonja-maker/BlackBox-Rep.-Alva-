"""All findings streamed to JSON/CSV/HTML, with external SQLite sorting."""
from contextlib import closing
import csv,json,sqlite3,time
from html import escape
from .session_view import SessionView
from .investigation_v2 import _selected_series,finding_streams,research_tail,LIMITATIONS
from .package_privacy import redact
from .owned_unlink import remove_entry
from .csv_safety import csv_safe
def privacy(value,identifiers,notes):
 if isinstance(value,dict):return {k:privacy(v,identifiers,notes) for k,v in value.items() if
  (identifiers or k not in ('pid','tid','hwnd','creation_time','pid_creation_time','instance_id')) and
  k not in ('attributes','context') and (notes or k not in ('note','comment','name'))}
 if isinstance(value,list):return [privacy(v,identifiers,notes) for v in value]
 return value
def write_findings(folder,tx,prefix,*,interval=None,series=None,instance_id=1,include_identifiers=False,include_notes=False,cancel=None):
 def check():
  if cancel is not None and cancel():raise InterruptedError('EXPORT_CANCELLED')
 spool=tx.reserve(prefix+'.sort.sqlite3');json_path=tx.reserve(prefix+'.findings.json');csv_path=tx.reserve(prefix+'.findings.csv');html_path=tx.reserve(prefix+'.findings.html')
 stats={'deadline':time.monotonic()+60,'derived_triggers_not_emitted':0,'derived_trigger_limit_reached':False};count=0
 with SessionView.open(folder,cancel=cancel) as view,closing(sqlite3.connect(spool)) as db:
  db.execute('PRAGMA cache_size=-2048');db.execute('CREATE TABLE finding(stamp INTEGER,uid TEXT,data TEXT)')
  series=series or _selected_series(view,instance_id)
  start,end=interval or (None,None)
  if end is None:
   end=max(view._range(start,None,series,instance_id)[1],research_tail(folder) or 0)
  report=view.interval(start,end,series=series,instance_id=instance_id,buckets=32)
  lo,hi=report['selected_interval_ns'];coverage=report['coverage']
  for row in finding_streams(view,folder,lo,hi,series=series,instance_id=instance_id,coverage=coverage,stats=stats):
   if count%128==0:check()
   # Consent covers user statements only. Imported application attributes and
   # notes on non-user evidence never become visible through this checkbox.
   user_notes=include_notes and row['confidence_class']=='USER_REPORTED'
   row=privacy(redact(row,include_notes=user_notes),include_identifiers,user_notes)
   db.execute('INSERT INTO finding VALUES(?,?,?)',(row['start_ns'],row['finding_id'],json.dumps(row,ensure_ascii=False,allow_nan=False)));count+=1
  db.execute('CREATE INDEX ix_finding_order ON finding(stamp,uid)');db.commit()
  with json_path.open('w',encoding='utf-8') as js,csv_path.open('w',encoding='utf-8-sig',newline='') as cs,html_path.open('w',encoding='utf-8') as ht:
   js.write('{"schema_version":2,"engine":"BLACKBOX_INVESTIGATION_2","file_trust":"UNVERIFIED_IMPORT","root_cause":"UNKNOWN","findings":[')
   writer=csv.writer(cs);writer.writerow(('finding_id','start_monotonic_ns','end_monotonic_ns','code','severity','class','sources','coverage'))
   ht.write('<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>BLACK.BOX findings</title><style>body{font:15px system-ui;max-width:1100px;margin:2em auto}pre{white-space:pre-wrap;overflow-wrap:anywhere}article{border-top:1px solid #aaa;padding:1em}</style><h1>Находки / Findings</h1><h2>Что наблюдалось / Observed</h2><p>'+str(count)+' findings; '+str(coverage['selected_samples'])+' samples.</p><h2>Подтверждающие данные / Supporting measurements</h2><pre>'+escape(json.dumps(coverage,ensure_ascii=False,indent=2))+'</pre><h2>Что установить нельзя / Cannot establish</h2><p>Root cause: UNKNOWN. '+escape(', '.join(LIMITATIONS))+'</p>')
   for ordinal,(_,uid,raw) in enumerate(db.execute('SELECT stamp,uid,data FROM finding ORDER BY stamp,uid')):
    if ordinal%128==0:check()
    row=json.loads(raw);js.write((',' if ordinal else '')+raw)
    writer.writerow([csv_safe(v) for v in (uid,row['start_ns'],row['end_ns'],row['code'],row['severity'],row['confidence_class'],json.dumps(row['sources']),json.dumps(row['coverage']))])
    ht.write('<article id="finding-'+uid+'"><h3>'+escape(row['code'])+'</h3><p>'+escape(row['confidence_class'])+'</p><h4>Факты / Facts</h4><pre>'+escape(json.dumps(row['facts'],ensure_ascii=False,indent=2))+'</pre><h4>Гипотезы / Candidates</h4><pre>'+escape(json.dumps(row['hypotheses'],ensure_ascii=False,indent=2))+'</pre><p>'+escape(', '.join(row['alternative_explanations']))+'</p><p>'+escape(', '.join(row['limitations']))+'</p><details><summary>Технические данные / Technical data</summary><pre>'+escape(raw)+'</pre></details></article>')
   limits={k:v for k,v in stats.items() if k!='deadline'}
   js.write('],"findings_total":'+str(count)+',"analysis_limits":'+json.dumps(limits)+',"causal_link_proven":false}')
   ht.write('<p>Analysis limits: '+escape(json.dumps(limits))+'</p>')
 own=next(r['identity'] for r in tx.data['cleanup_inventory'] if r['relative']==spool.name)
 remove_entry(tx.stage,spool.name,own,tx.data['stage_identity'])
 return {'count':count,'files':{p.name:p for p in (json_path,csv_path,html_path)},'json_file':json_path.name,'html_file':html_path.name,
  'pagination_truncation':False,'analysis_limits':limits,'ordering':'START_MONOTONIC_NS_AND_FINDING_ID'}

