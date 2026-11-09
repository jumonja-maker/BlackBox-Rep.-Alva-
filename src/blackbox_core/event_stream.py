"""Indexed read-only event merge, literal filters and bounded keyset pages."""
import json,time
from pathlib import Path
from .session_view import SessionView,SessionReadError
from .session_v2 import safe_path
SOURCES=('ALL','USER','WIN32','WCT','ETW','EVENTPIPE','APP','OBSERVER')
SEVERITIES=('ALL','INFO','WARNING','ERROR')
MAX_EVENT_SCALAR_CHARS=512
MAX_EVENT_SCALAR_BYTES=2048
MAX_EVENT_DETAIL_BYTES=16384
MAX_EVENT_PAGE_BYTES=2*1024*1024


def _detail_pairs(pairs):
 result={}
 for key,value in pairs:
  if key in result:raise ValueError('DUPLICATE_EVENT_DETAIL_KEY')
  result[key]=value
 return result


def _parse_event_detail(text,size,kind):
 if type(size) is not int or size<0:
  raise SessionReadError('INVALID_IMPORTED_EVENT')
 if size>MAX_EVENT_DETAIL_BYTES:raise SessionReadError('IMPORTED_EVENT_SIZE_LIMIT')
 if kind!='text' or type(text) is not str:raise SessionReadError('INVALID_IMPORTED_EVENT')
 try:
  if len(text)>size:raise ValueError('EVENT_DETAIL_SIZE_MISMATCH')
  if len(text.encode('utf-8'))!=size:raise ValueError('EVENT_DETAIL_SIZE_MISMATCH')
  value=json.loads(text,object_pairs_hook=_detail_pairs,
   parse_constant=lambda value:(_ for _ in ()).throw(ValueError('NONFINITE_EVENT_DETAIL')))
  pending=[(value,0)];nodes=0
  while pending:
   item,depth=pending.pop();nodes+=1
   if depth>32 or nodes>8192:raise ValueError('EVENT_DETAIL_STRUCTURE_LIMIT')
   if type(item) is float and not (-float('inf')<item<float('inf')):
    raise ValueError('NONFINITE_EVENT_DETAIL')
   children=item.values() if type(item) is dict else item if type(item) is list else ()
   if len(pending)+len(children)>8192:raise ValueError('EVENT_DETAIL_STRUCTURE_LIMIT')
   pending.extend((child,depth+1) for child in children)
  return value
 except (ValueError,TypeError,RecursionError,OverflowError) as error:
  raise SessionReadError('INVALID_IMPORTED_EVENT') from error


def _event_detail(text,size,kind):
 try:
  return _parse_event_detail(text,size,kind)
 except SessionReadError as error:
  if str(error)=='IMPORTED_EVENT_SIZE_LIMIT':
   return {'status':'IMPORTED_EVENT_SIZE_LIMIT','recorded_size_bytes':size,
           'detail_limit_bytes':MAX_EVENT_DETAIL_BYTES}
  if kind!='text':return {'status':'INVALID_IMPORTED_EVENT','reason':'DETAIL_NOT_TEXT'}
  return {'status':'INVALID_IMPORTED_EVENT','reason':'INVALID_OR_UNSUPPORTED_JSON_DETAIL'}


def _validate_event_rows(view,sql):
 # Validate before range/filter counting: a malformed clock or source cannot
 # establish that a row lies outside the requested evidence scope. Only
 # bounded scalar prefixes cross the SQLite/Python boundary.
 invalid="""typeof(time_ns)!='integer' OR time_ns<0 OR
 typeof(rank)!='integer' OR rank NOT BETWEEN 0 AND 2 OR
 typeof(id)!='integer' OR id<=0 OR
 (instance_id IS NOT NULL AND (typeof(instance_id)!='integer' OR instance_id<=0)) OR
 code_type!='text' OR status_type!='text' OR source_type!='text' OR
 code_nul>0 OR status_nul>0 OR source_nul>0 OR
 code_bytes>? OR status_bytes>? OR source_bytes>? OR
 code_chars>? OR status_chars>? OR source_chars>?"""
 if view.db.execute('SELECT 1 FROM ('+sql+') WHERE '+invalid+' LIMIT 1',
  (MAX_EVENT_SCALAR_BYTES,)*3+(MAX_EVENT_SCALAR_CHARS,)*3).fetchone() is not None:
  raise SessionReadError('INVALID_OR_UNSUPPORTED_IMPORTED_EVENT_SCALAR')


def _source_sql(value):
 return "CASE WHEN "+value+" IN ('USER','USER_MARKER') THEN 'USER' WHEN "+value+" IN ('WIN32','WIN32_HWND','WIN32_APPLICATION_EVENTLOG') THEN 'WIN32' WHEN "+value+" IN ('WCT','WIN32_WCT') THEN 'WCT' WHEN "+value+" LIKE 'ETW%' THEN 'ETW' WHEN "+value+" LIKE 'EVENTPIPE%' THEN 'EVENTPIPE' WHEN "+value+" IN ('APPLICATION_EVENT','APP_INSTRUMENTATION') THEN 'APP' ELSE 'OBSERVER' END"
def _union(view,folder):
 deadline=time.monotonic()+25;view.db.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
 research=safe_path(Path(folder)/'research.sqlite3');attached=False
 if research.is_file():
  view.db.execute('ATTACH DATABASE ? AS research_read',(research.resolve().as_uri()+'?mode=ro',));attached=True
 if view.is_v2:
  mirror="AND CASE WHEN json_valid(detail_json) THEN coalesce(json_extract(detail_json,'$.kind'),'') ELSE '' END!='research_evidence_ref'" if attached else ''
  sql="SELECT coalesce(observed_ns,recorded_ns) AS time_ns,0 AS rank,event_id AS id,source_kind AS original_source,event_type AS code,measurement_status AS status,instance_id,substr(detail_json,1,16385) AS detail_json,length(CAST(detail_json AS BLOB)) AS detail_size,typeof(detail_json) AS detail_type,'session-v2.sqlite3:events:'||event_id AS evidence_ref FROM main.events WHERE 1=1 "+mirror
  sql+=" UNION ALL SELECT monotonic_ns,1,error_id,'OBSERVER',code,'UNAVAILABLE',NULL,'{}',2,'text','session-v2.sqlite3:sensor_errors:'||error_id FROM main.sensor_errors"
 else:
  # Legacy events without an actual timestamp stay in the legacy event view.
  origin=view.metadata['monotonic_origin_ns']
  clock="coalesce(json_extract(data,'$.timestamp_monotonic_ns'),"+str(origin)+"+json_extract(data,'$.elapsed_ms')*1000000)"
  sql="SELECT "+clock+" AS time_ns,0 AS rank,seq AS id,'OBSERVER' AS original_source,coalesce(json_extract(data,'$.code'),json_extract(data,'$.event'),json_extract(data,'$.kind'),'LEGACY_EVENT') AS code,'RECORDED_LEGACY' AS status,1 AS instance_id,substr(data,1,16385) AS detail_json,length(CAST(data AS BLOB)) AS detail_size,typeof(data) AS detail_type,'session.sqlite3:events:'||seq AS evidence_ref FROM main.events WHERE json_valid(data) AND "+clock+" IS NOT NULL"
 if attached:
  sql+=" UNION ALL SELECT monotonic_ns,2,id,source,kind,quality,1,substr(data,1,16385),length(CAST(data AS BLOB)),typeof(data),'research.sqlite3:evidence:'||id FROM research_read.evidence WHERE source!='BLACKBOX_LEGACY' AND CASE WHEN json_valid(data) THEN json_type(data,'$.legacy_event_seq') IS NULL ELSE 1 END"
 # Original lengths/types are SQL scalars. Returning prefixes rather than the
 # complete imported code/status prevents a 200-row page amplifying large
 # forged scalar fields before the worker's response-size guard can run.
 scalar="SELECT time_ns,rank,id,"+_source_sql('original_source')+" AS source,"+\
  "substr(code,1,513) AS code,substr(status,1,513) AS status,instance_id,"+\
  "detail_json,detail_size,detail_type,substr(evidence_ref,1,128) AS evidence_ref,"+\
  "typeof(code) AS code_type,typeof(status) AS status_type,typeof(original_source) AS source_type,"+\
  "instr(code,char(0)) AS code_nul,instr(status,char(0)) AS status_nul,instr(original_source,char(0)) AS source_nul,"+\
  "length(CAST(code AS BLOB)) AS code_bytes,length(CAST(status AS BLOB)) AS status_bytes,"+\
  "length(CAST(original_source AS BLOB)) AS source_bytes,length(code) AS code_chars,"+\
  "length(status) AS status_chars,length(original_source) AS source_chars FROM ("+sql+")"
 severity="CASE WHEN upper(code||' '||status) LIKE '%ERROR%' OR upper(code||' '||status) LIKE '%FAIL%' THEN 'ERROR' WHEN upper(code||' '||status) LIKE '%TIMEOUT%' OR upper(code||' '||status) LIKE '%DENIED%' OR upper(code||' '||status) LIKE '%UNAVAILABLE%' OR upper(code||' '||status) LIKE '%GAP%' OR upper(code||' '||status) LIKE '%UNRESPONSIVE%' THEN 'WARNING' ELSE 'INFO' END"
 return "SELECT *,("+severity+") AS severity FROM ("+scalar+")"
def event_page(folder,*,start_ns=0,end_ns=2**63-1,after=None,limit=100,source='ALL',severity='ALL',instance_id=0,search='',start_ms=None,end_ms=None):
 if (type(limit) is not int or not 1<=limit<=200 or source not in SOURCES or severity not in SEVERITIES or
  type(instance_id) is not int or not 0<=instance_id<2**63 or type(search) is not str or len(search)>256):raise SessionReadError('INVALID_EVENT_FILTER')
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
  sql=_union(view,folder);_validate_event_rows(view,sql)
  clauses=['time_ns BETWEEN ? AND ?'];args=[start_ns,end_ns]
  if source!='ALL':clauses.append('source=?');args.append(source)
  if severity!='ALL':clauses.append('severity=?');args.append(severity)
  if instance_id:clauses.append('instance_id=?');args.append(instance_id)
  if search:
   # The complete retained detail is searchable. An oversized detail cannot
   # truthfully be declared a non-match from its bounded prefix.
   if view.db.execute('SELECT 1 FROM ('+sql+') WHERE '+' AND '.join(clauses)+
    " AND (detail_type!='text' OR detail_size>?) LIMIT 1",(*args,MAX_EVENT_DETAIL_BYTES)).fetchone():
    raise SessionReadError('IMPORTED_EVENT_DETAIL_SEARCH_UNSUPPORTED')
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
  rows=view.db.execute(query+cursor_clause+' ORDER BY time_ns,rank,id LIMIT ?',(*args,*(after or ()),limit+1))
  page=[];page_bytes=0;has_more=False;page_limit_reason=None
  for raw in rows:
   if len(page)==limit:has_more=True;break
   row={name:raw[name] for name in ('time_ns','rank','id','source','code','status','instance_id','evidence_ref','severity')}
   row['detail']=_event_detail(raw['detail_json'],raw['detail_size'],raw['detail_type'])
   row['verification_class']='UNVERIFIED_IMPORT'
   encoded_size=len(json.dumps(row,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode('ascii'))+1
   if page_bytes+encoded_size>MAX_EVENT_PAGE_BYTES:
    if not page:raise SessionReadError('IMPORTED_EVENT_ROW_RESPONSE_SIZE_LIMIT')
    has_more=True;page_limit_reason='SERIALIZED_PAGE_BYTE_LIMIT';break
   page.append(row);page_bytes+=encoded_size
  return {'schema_version':2,'rows':page,'has_more':has_more,'total_matching':count,
   'next_cursor':[page[-1][k] for k in ('time_ns','rank','id')] if page else None,'monotonic_origin_ns':origin,
   'selected_interval_ns':[start_ns,end_ns],'source_trust':'UNVERIFIED_IMPORT',
   'page_limit_reason':page_limit_reason,'serialized_rows_bytes':page_bytes,
   'page_byte_limit':MAX_EVENT_PAGE_BYTES,
   'timestamp_limitations':['LEGACY_EVENTS_WITHOUT_TIME_REMAIN_IN_LEGACY_VIEW'] if not view.is_v2 else []}
def event_tracks(view,start,end,*,folder=None,buckets=128):
 if type(buckets) is not int or not 1<=buckets<=512:raise SessionReadError('INVALID_EVENT_BUCKETS')
 if type(start) is not int or type(end) is not int or not 0<=start<=end<2**63:raise SessionReadError('INVALID_EVENT_FILTER')
 if folder is None:
  # SessionView has no mutable target relationship; caller supplies source.
  return {'status':'SOURCE_FOLDER_REQUIRED','tracks':{},'buckets':buckets}
 sql=_union(view,folder);_validate_event_rows(view,sql)
 group="CASE WHEN source='USER' AND upper(code) LIKE '%ACTION%' THEN 'ACTIONS' WHEN source='USER' THEN 'USER' WHEN code LIKE '%INCIDENT%' OR code LIKE 'UI_%' THEN 'INCIDENTS' WHEN source='WIN32' THEN 'WINDOW' WHEN source='WCT' THEN 'WCT' WHEN source IN ('ETW','EVENTPIPE') THEN 'TRACE' ELSE 'OBSERVER' END"
 query="SELECT "+group+" AS track,min(?,max(0,(time_ns-?)*?/max(1,?))) AS bucket,count(*) AS count,min(time_ns) AS first_ns,max(time_ns) AS last_ns,min(code) AS code_example_alphabetical FROM ("+sql+") WHERE time_ns BETWEEN ? AND ? GROUP BY track,bucket ORDER BY track,bucket"
 rows=view.db.execute(query,(buckets-1,start,buckets,max(1,end-start),start,end));tracks={}
 for raw in rows:
  row=dict(raw);name=row.pop('track');tracks.setdefault(name,[]).append(row)
 return {'status':'ALL_MATCHING_EVENTS_BUCKETED','tracks':tracks,'buckets':buckets,'method':'COUNT_FIRST_LAST_PER_BUCKET'}

