"""Indexed read-only event merge, literal filters and bounded keyset pages."""
import json,re,time
from pathlib import Path
from .session_view import SessionView,SessionReadError
from .session_v2 import safe_path
SOURCES=('ALL','USER','WIN32','WCT','ETW','EVENTPIPE','APP','OBSERVER')
SEVERITIES=('ALL','INFO','WARNING','ERROR')
def _source_sql(value):
 return "CASE WHEN "+value+" IN ('USER','USER_MARKER') THEN 'USER' WHEN "+value+" IN ('WIN32','WIN32_HWND','WIN32_APPLICATION_EVENTLOG') THEN 'WIN32' WHEN "+value+" IN ('WCT','WIN32_WCT') THEN 'WCT' WHEN "+value+" LIKE 'ETW%' THEN 'ETW' WHEN "+value+" LIKE 'EVENTPIPE%' THEN 'EVENTPIPE' WHEN "+value+" IN ('APPLICATION_EVENT','APP_INSTRUMENTATION') THEN 'APP' ELSE 'OBSERVER' END"
def _union(view,folder):
 deadline=time.monotonic()+25;view.db.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
 research=safe_path(Path(folder)/'research.sqlite3');attached=False
 if research.is_file():
  view.db.execute('ATTACH DATABASE ? AS research_read',(research.resolve().as_uri()+'?mode=ro',));attached=True
 if view.is_v2:
  mirror="AND CASE WHEN json_valid(detail_json) THEN coalesce(json_extract(detail_json,'$.kind'),'') ELSE '' END!='research_evidence_ref'" if attached else ''
  sql="SELECT coalesce(observed_ns,recorded_ns) AS time_ns,0 AS rank,event_id AS id,"+_source_sql('source_kind')+" AS source,event_type AS code,measurement_status AS status,instance_id,substr(detail_json,1,16385) AS detail_json,length(detail_json) AS detail_size,'session-v2.sqlite3:events:'||event_id AS evidence_ref FROM main.events WHERE 1=1 "+mirror
  sql+=" UNION ALL SELECT monotonic_ns,1,error_id,'OBSERVER',code,'UNAVAILABLE',NULL,'{}',2,'session-v2.sqlite3:sensor_errors:'||error_id FROM main.sensor_errors"
 else:
  # Legacy events without an actual timestamp stay in the legacy event view.
  origin=view.metadata['monotonic_origin_ns']
  clock="coalesce(json_extract(data,'$.timestamp_monotonic_ns'),"+str(origin)+"+json_extract(data,'$.elapsed_ms')*1000000)"
  sql="SELECT "+clock+" AS time_ns,0 AS rank,seq AS id,'OBSERVER' AS source,coalesce(json_extract(data,'$.code'),json_extract(data,'$.event'),json_extract(data,'$.kind'),'LEGACY_EVENT') AS code,'RECORDED_LEGACY' AS status,1 AS instance_id,substr(data,1,16385) AS detail_json,length(data) AS detail_size,'session.sqlite3:events:'||seq AS evidence_ref FROM main.events WHERE json_valid(data) AND "+clock+" IS NOT NULL"
 if attached:
  sql+=" UNION ALL SELECT monotonic_ns,2,id,"+_source_sql('source')+",kind,quality,1,substr(data,1,16385),length(data),'research.sqlite3:evidence:'||id FROM research_read.evidence WHERE source!='BLACKBOX_LEGACY' AND CASE WHEN json_valid(data) THEN json_type(data,'$.legacy_event_seq') IS NULL ELSE 1 END"
 severity="CASE WHEN upper(code||' '||status) LIKE '%ERROR%' OR upper(code||' '||status) LIKE '%FAIL%' THEN 'ERROR' WHEN upper(code||' '||status) LIKE '%TIMEOUT%' OR upper(code||' '||status) LIKE '%DENIED%' OR upper(code||' '||status) LIKE '%UNAVAILABLE%' OR upper(code||' '||status) LIKE '%GAP%' OR upper(code||' '||status) LIKE '%UNRESPONSIVE%' THEN 'WARNING' ELSE 'INFO' END"
 return "SELECT *,("+severity+") AS severity FROM ("+sql+")"
def event_page(folder,*,start_ns=0,end_ns=2**63-1,after=None,limit=100,source='ALL',severity='ALL',instance_id=0,search='',start_ms=None,end_ms=None):
 if (type(limit) is not int or not 1<=limit<=200 or source not in SOURCES or severity not in SEVERITIES or
  type(instance_id) is not int or instance_id<0 or type(search) is not str or len(search)>256):raise SessionReadError('INVALID_EVENT_FILTER')
 if after is not None and (type(after) not in (tuple,list) or len(after)!=3 or any(type(n) is not int or n<0 or n>=2**63 for n in after)):raise SessionReadError('INVALID_EVENT_CURSOR')
 with SessionView.open(folder) as view:
  origin=view.metadata['monotonic_origin_ns']
  if start_ms is not None:
   if type(start_ms) is not int or not 0<=start_ms<=604800000:raise SessionReadError('INVALID_EVENT_FILTER')
   start_ns=origin+start_ms*1000000
  if end_ms is not None:
   if type(end_ms) is not int or not 0<=end_ms<=604800000:raise SessionReadError('INVALID_EVENT_FILTER')
   end_ns=origin+end_ms*1000000
  if type(start_ns) is not int or type(end_ns) is not int or not 0<=start_ns<=end_ns<2**63:raise SessionReadError('INVALID_EVENT_FILTER')
  sql=_union(view,folder);clauses=['time_ns BETWEEN ? AND ?'];args=[start_ns,end_ns]
  if source!='ALL':clauses.append('source=?');args.append(source)
  if severity!='ALL':clauses.append('severity=?');args.append(severity)
  if instance_id:clauses.append('instance_id=?');args.append(instance_id)
  if search:
   # SQLite LIKE only folds ASCII. Use literal Unicode casefold matching so
   # Cyrillic provider names and events are searchable; user %/_ are text,
   # never implicit wildcard patterns or SQL statements.
   view.db.create_function('bb_contains_literal',2,
    lambda hay,term:int(str(term) in str(hay or '').casefold()),deterministic=True)
   clauses.append("bb_contains_literal(code||' '||detail_json,?)=1")
   args.append(search.casefold())
  query='SELECT * FROM ('+sql+') WHERE '+' AND '.join(clauses)
  count=view.db.execute('SELECT count(*) FROM ('+query+')',args).fetchone()[0]
  cursor_clause=' AND (time_ns,rank,id)>(?,?,?)' if after is not None else ''
  rows=view.db.execute(query+cursor_clause+' ORDER BY time_ns,rank,id LIMIT ?',(*args,*(after or ()),limit+1)).fetchall()
  page=[]
  for raw in rows[:limit]:
   row=dict(raw);text=row.pop('detail_json');size=row.pop('detail_size')
   try:row['detail']=json.loads(text) if size<=16384 else {'status':'IMPORTED_EVENT_SIZE_LIMIT'}
   except ValueError:row['detail']={'status':'INVALID_IMPORTED_EVENT'}
   row['verification_class']='UNVERIFIED_IMPORT';page.append(row)
  return {'schema_version':2,'rows':page,'has_more':len(rows)>limit,'total_matching':count,
   'next_cursor':[page[-1][k] for k in ('time_ns','rank','id')] if page else None,'monotonic_origin_ns':origin,
   'selected_interval_ns':[start_ns,end_ns],'source_trust':'UNVERIFIED_IMPORT',
   'timestamp_limitations':['LEGACY_EVENTS_WITHOUT_TIME_REMAIN_IN_LEGACY_VIEW'] if not view.is_v2 else []}
def event_tracks(view,start,end,*,folder=None,buckets=128):
 if type(buckets) is not int or not 1<=buckets<=512:raise SessionReadError('INVALID_EVENT_BUCKETS')
 if folder is None:
  # SessionView has no mutable target relationship; caller supplies source.
  return {'status':'SOURCE_FOLDER_REQUIRED','tracks':{},'buckets':buckets}
 sql=_union(view,folder)
 group="CASE WHEN source='USER' AND upper(code) LIKE '%ACTION%' THEN 'ACTIONS' WHEN source='USER' THEN 'USER' WHEN code LIKE '%INCIDENT%' OR code LIKE 'UI_%' THEN 'INCIDENTS' WHEN source='WIN32' THEN 'WINDOW' WHEN source='WCT' THEN 'WCT' WHEN source IN ('ETW','EVENTPIPE') THEN 'TRACE' ELSE 'OBSERVER' END"
 query="SELECT "+group+" AS track,min(?,max(0,(time_ns-?)*?/max(1,?))) AS bucket,count(*) AS count,min(time_ns) AS first_ns,max(time_ns) AS last_ns,min(code) AS code_example_alphabetical FROM ("+sql+") WHERE time_ns BETWEEN ? AND ? GROUP BY track,bucket ORDER BY track,bucket"
 rows=view.db.execute(query,(buckets-1,start,buckets,max(1,end-start),start,end));tracks={}
 for raw in rows:
  row=dict(raw);name=row.pop('track');tracks.setdefault(name,[]).append(row)
 return {'status':'ALL_MATCHING_EVENTS_BUCKETED','tracks':tracks,'buckets':buckets,'method':'COUNT_FIRST_LAST_PER_BUCKET'}

