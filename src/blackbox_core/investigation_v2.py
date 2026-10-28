"""Read-only investigation of a whole chosen interval; all claims retain provenance."""
from contextlib import closing
import hashlib,heapq,json,re,time
from pathlib import Path
from .session_view import SessionView,SessionReadError
from .session_v2 import safe_path
from .casebook import readonly
from .incidents import IncidentCapture
QUESTIONS=('ALL','CPU','UI','MEMORY','IO','COVERAGE')
SORTS=('TIME_ASC','TIME_DESC','SEVERITY')
LIMITATIONS=['COUNTERS_DO_NOT_ESTABLISH_ROOT_CAUSE','SOURCE_FILE_NOT_AUTHENTICATED','BETWEEN_SAMPLE_ACTIVITY_UNKNOWN','TID_REUSE_CANNOT_BE_EXCLUDED']
def _selected_series(view,instance_id):
 return 'DETAILED' if view.is_v2 and view.bounds('DETAILED',instance_id)[2] else 'STANDARD' if instance_id==1 else 'CHILD'
def _finding(code,start,end,*,ref,facts,category='OBSERVED',severity='INFO',coverage=None,extra=None):
 uid=hashlib.sha256((ref+'|'+code+'|'+str(start)+'|'+str(end)).encode()).hexdigest()[:32]
 group='CPU' if 'CPU' in code else 'MEMORY' if any(x in code for x in ('RSS','PRIVATE','HANDLE')) else 'UI' if any(x in code for x in ('UI_','WCT')) else 'IO' if 'IO_' in code else 'COVERAGE'
 alternatives={'CPU':['EXPECTED_WORKLOAD','BACKGROUND_WORK','OBSERVER_EFFECT'],'MEMORY':['RETAINED_CACHE','DELAYED_GC','DIFFERENT_WORKLOAD'],'UI':['LONG_UI_HANDLER','LOCK_OR_EXTERNAL_WAIT','SCHEDULING_DELAY'],'IO':['EXPECTED_TRANSFER','BUFFERING','OTHER_PROCESS_WORK']}
 return {'finding_id':uid,'schema_version':2,'code':code,'severity':severity,'start_ns':start,'end_ns':end,
  'facts':facts,'confidence_class':category,'hypotheses':[{'code':'INSPECT_COINCIDENT_WORK_AND_SOURCE_COVERAGE','class':'CANDIDATE'}],
  'alternative_explanations':alternatives.get(group,['SOURCE_FAILURE_OR_COLLECTION_LIMIT']),'limitations':list(LIMITATIONS),
  'sources':[{'evidence_ref':ref,'verification_class':'UNVERIFIED_IMPORT'}],'coverage':coverage or {},'group':group,
  'root_cause':'UNKNOWN','root_cause_proven':False,'source_trust':'UNVERIFIED_IMPORT','detail':extra or {}}
def _persisted_findings(view,start,end,coverage):
 if not view.is_v2:return
 for r in view.db.execute('SELECT incident_id,trigger_code,start_ns,end_ns,status,primary_event_id,substr(context_json,1,16385) AS detail FROM incidents WHERE start_ns<=? AND coalesce(end_ns,?)>=? ORDER BY start_ns,incident_id',(end,end,start)):
  try:detail=json.loads(r['detail']) if len(r['detail'])<=16384 else {'status':'IMPORTED_INCIDENT_SIZE_LIMIT'}
  except ValueError:detail={'status':'INVALID_IMPORTED_INCIDENT'}
  yield _finding('INCIDENT_'+r['trigger_code'],r['start_ns'],r['end_ns'],ref='session-v2.sqlite3:incidents:'+str(r['incident_id']),
   facts=[{'code':'RECORDED_INCIDENT','status':r['status'],'primary_event_id':r['primary_event_id']}],
   category='OBSERVED' if r['trigger_code']=='UI_TIMEOUT' else 'DERIVED',severity='WARNING',coverage=coverage,
   extra={'incident_id':r['incident_id'],'context':detail})
 for r in view.db.execute('SELECT error_id,monotonic_ns,sensor_id,code,win32_code FROM sensor_errors WHERE monotonic_ns BETWEEN ? AND ?',(start,end)):
  yield _finding('SENSOR_UNAVAILABLE',r['monotonic_ns'],r['monotonic_ns'],ref='session-v2.sqlite3:sensor_errors:'+str(r['error_id']),facts=[dict(r)],category='UNAVAILABLE',severity='WARNING',coverage=coverage)
def _counter_findings(view,start,end,series,instance_id,coverage,stats):
 detector=IncidentCapture(max_incidents=1000,post_ms=0,gap_incidents=True);origin=view.metadata['monotonic_origin_ns'];previous=None
 for ordinal,row in enumerate(view.reader.iter_samples(start,end,series=series,instance_id=instance_id)):
  if ordinal%128==0 and time.monotonic()>stats['deadline']:raise SessionReadError('INVESTIGATION_INTERVAL_BUDGET')
  # CPU is computed from comparable adjacent cumulative pairs by the reader's
  # interval contract. A legacy CPU value remains only a recorded counter.
  cpu=row.get('cpu_percent')
  if previous and view.is_v2:
   dt=row['time_ns']-previous['time_ns'];interval=row.get('requested_interval_ns') or 0
   values=[(previous.get(k),row.get(k)) for k in ('cpu_user_s','cpu_system_s')]
   continuous=dt>0 and row['series_seq']==previous['series_seq']+1 and (not interval or dt<=max(2*interval,interval+500000000))
   cpu=100*sum(b-a for a,b in values)/(dt/1e9) if continuous and all(a is not None and b is not None and b>=a for a,b in values) else None
  previous=row
  events=detector.observe(elapsed_ms=max(0,(row['time_ns']-origin)//1000000),sample_seq=ordinal+1,
   cpu_percent=cpu,rss_bytes=row.get('rss_bytes'),private_bytes=row.get('private_bytes'),
   handle_count=row.get('handle_count'),read_bytes=row.get('read_bytes'),write_bytes=row.get('write_bytes'))
  for event in events:
   if event['code']=='AUTO_INCIDENT_STARTED':
    yield _finding('DERIVED_'+event['trigger_code'],row['time_ns'],row['time_ns'],
     ref='samples:'+series+':'+str(row.get('sample_id',row.get('seq',ordinal+1))),facts=[event['trigger_detail']],category='DERIVED',severity='WARNING',coverage=coverage)
   elif event['code']=='SAMPLING_GAP_OBSERVED':
    yield _finding('OBSERVATION_GAP',origin+event['start_ms']*1000000,row['time_ns'],ref='samples:'+series+':'+str(ordinal+1),facts=[event],category='DERIVED',severity='WARNING',coverage=coverage)
 stats['derived_triggers_not_emitted']=detector.dropped_triggers
 stats['derived_trigger_limit_reached']=detector.dropped_triggers>0

def _action_findings(view,start,end,coverage):
 if not view.is_v2:return
 from .experiment_metrics import measure_interval
 for row in view.db.execute("SELECT * FROM action_intervals WHERE state='COMPLETED' AND start_ns<=? AND end_ns>=? ORDER BY start_ns,action_id",(end,start)):
  if row['start_ns'] is None or row['end_ns'] is None or row['end_ns']<row['start_ns']:continue
  lo=max(start,row['start_ns']);hi=min(end,row['end_ns'])
  resources=measure_interval(view,lo,hi,series='STANDARD');detail=measure_interval(view,lo,hi,series='DETAILED')
  item=_finding('ACTION_RESOURCE_COINCIDENCE',lo,hi,ref='session-v2.sqlite3:action_intervals:'+row['action_id'],
   facts=[{'code':'RESOURCES_INSIDE_USER_ACTION_INTERVAL','resources':resources,'detailed_resources':detail}],
   category='DERIVED',coverage=coverage,extra={'action_id':row['action_id'],'experiment_id':row['experiment_id'],'action_boundary_source':row['verification_class'],
    'partial_action_interval':lo!=row['start_ns'] or hi!=row['end_ns'],'timing_uncertainty':'USER_COMMAND_BOUNDARIES_NOT_OS_ACTION_EXECUTION','causal_claim':False})
  item['hypotheses']=[{'code':'INSTRUMENT_VOLUNTARY_ACTION_STAGES','class':'CANDIDATE','recommendation_type':'NEXT_MEASUREMENT'}]
  item['alternative_explanations']=['EXPECTED_WORK','BACKGROUND_WORK','UNOBSERVED_ACTIVITY_BETWEEN_SAMPLES']
  item['limitations']+=['TEMPORAL_COINCIDENCE_NOT_CAUSATION','NO_BOUNDARY_EXTRAPOLATION']
  yield item
def _research_findings(folder,start,end,coverage):
 path=safe_path(Path(folder)/'research.sqlite3')
 if not path.is_file():return
 with closing(readonly(path)) as db:
  deadline=time.monotonic()+25;db.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
  for r in db.execute("SELECT id,monotonic_ns,kind,source,substr(data,1,8193) AS detail FROM evidence WHERE monotonic_ns BETWEEN ? AND ? AND (source='USER_MARKER' OR (kind='user_problem' AND source IN ('USER','BLACKBOX_LEGACY')) OR kind IN ('application.source_failed','observer.operation_failed')) ORDER BY monotonic_ns,id",(start,end)):
   try:detail=json.loads(r['detail']) if len(r['detail'])<=8192 else {'status':'IMPORTED_EVENT_SIZE_LIMIT'}
   except ValueError:detail={'status':'INVALID_IMPORTED_EVENT'}
   user=r['source']=='USER_MARKER' or (r['kind']=='user_problem' and r['source'] in ('USER','BLACKBOX_LEGACY'))
   yield _finding(r['kind'],r['monotonic_ns'],r['monotonic_ns'],ref='research.sqlite3:evidence:'+str(r['id']),
    facts=[{'code':'USER_STATEMENT' if user else 'SOURCE_STATUS','values':detail}],category='USER_REPORTED' if user else 'UNAVAILABLE',coverage=coverage)
def finding_streams(view,folder,start,end,*,series,instance_id,coverage,stats):
 """One finding inventory for paged investigation and complete exports.

 Callers own filtering, ordering and their resource/cancellation budgets. The
 underlying generators remain streaming; no whole-history list is materialized.
 """
 yield from _persisted_findings(view,start,end,coverage)
 yield from _counter_findings(view,start,end,series,instance_id,coverage,stats)
 yield from _research_findings(folder,start,end,coverage)
 if instance_id==1:
  yield from _action_findings(view,start,end,coverage)

def research_tail(folder):
 path=safe_path(Path(folder)/'research.sqlite3')
 if not path.is_file():return None
 with closing(readonly(path)) as db:
  value=db.execute('SELECT max(monotonic_ns) FROM evidence').fetchone()[0]
  return value if type(value) is int and 0<=value<2**63 else None
def investigate(folder,*,start_ns=None,end_ns=None,instance_id=1,after=None,limit=50,question='ALL',sort_order='TIME_ASC'):
 if type(limit) is not int or not 1<=limit<=100 or question not in QUESTIONS or sort_order not in SORTS:raise SessionReadError('INVALID_FINDINGS_QUERY')
 length=3 if sort_order=='SEVERITY' else 2
 if after is not None and (type(after) not in (list,tuple) or len(after)!=length or any(type(x) is not int or not -2**63<x<2**63 for x in after[:-1]) or type(after[-1]) is not str or not re.fullmatch('[0-9a-f]{32}',after[-1])):raise SessionReadError('INVALID_FINDINGS_QUERY')
 def key(row):
  if sort_order=='TIME_DESC':return (-row['start_ns'],row['finding_id'])
  if sort_order=='SEVERITY':return (-{'ERROR':3,'WARNING':2,'INFO':1}.get(row['severity'],0),row['start_ns'],row['finding_id'])
  return (row['start_ns'],row['finding_id'])
 stats={'deadline':time.monotonic()+25,'derived_triggers_not_emitted':0,'derived_trigger_limit_reached':False}
 with SessionView.open(folder) as view:
  series=_selected_series(view,instance_id)
  if end_ns is None:
   tail=research_tail(folder);end_ns=max(view._range(start_ns,None,series,instance_id)[1],tail or 0)
  report=view.interval(start_ns,end_ns,series=series,instance_id=instance_id,buckets=128)
  lo,hi=report['selected_interval_ns'];coverage=report['coverage'];total=0
  def rows():
   nonlocal total
   for item in finding_streams(view,folder,lo,hi,series=series,instance_id=instance_id,coverage=coverage,stats=stats):
    if question!='ALL' and item['group']!=question:continue
    total+=1
    if total%128==0 and time.monotonic()>stats['deadline']:raise SessionReadError('INVESTIGATION_INTERVAL_BUDGET')
    if after is None or key(item)>tuple(after):yield item
  from .capture_policy import recorded_top_threads
  found=heapq.nsmallest(limit+1,rows(),key=key);page=found[:limit];threads=view.thread_summary(lo,hi,instance_id=instance_id,top_n=recorded_top_threads(folder))
  from .instrumentation_analysis import io_latency_statistics
  io=io_latency_statistics(folder,start_ns=lo,end_ns=hi)
  return {'schema_version':2,'engine':'BLACKBOX_INVESTIGATION_2','metadata':view.metadata,'selected_interval_ns':[lo,hi],
   'summary':{'observed':{'samples':coverage['selected_samples'],'findings_matching':total,'series':series},
    'support':{'metrics':report['metrics'],'coverage':coverage,'thread_status':threads['status']},
    'cannot_establish':['INTERNAL_ROOT_CAUSE','LEAK_WITHOUT_OBJECT_ANALYSIS','AUTHENTICITY_OF_IMPORTED_SOURCE']},
   'application_io_latency':io,'interval':report,'thread_analysis':threads,'coverage':coverage,'findings':page,'findings_total':total,'has_more':len(found)>limit,
   'next_cursor':list(key(page[-1])) if page else None,'sort_order':sort_order,
   'analysis_limits':{k:v for k,v in stats.items() if k!='deadline'},'file_trust':'UNVERIFIED_IMPORT','root_cause':'UNKNOWN','root_cause_proven':False,'limitations':LIMITATIONS}
def _snapshot(view,stamp,series):
 if not view.is_v2:return {'status':'LEGACY_LIMITED_DATA'}
 row=view.db.execute('SELECT * FROM samples WHERE instance_id=1 AND series=? AND monotonic_ns<=? ORDER BY monotonic_ns DESC,sample_id DESC LIMIT 1',(series,stamp)).fetchone()
 if row is None:return {'status':'NOT_OBSERVED'}
 if stamp-row['monotonic_ns']>max(2*row['requested_interval_ns'],row['requested_interval_ns']+500000000):return {'status':'SAMPLED_GAP','nearest_observed_ns':row['monotonic_ns']}
 return {'status':'OBSERVED_NEAR_BOUNDARY_NOT_INTERPOLATED','observed_ns':row['monotonic_ns'],'offset_ns':stamp-row['monotonic_ns'],
  'values':{k:row[k] for k in ('rss_bytes','private_bytes','uss_bytes','handle_count','thread_count','cpu_user_s','cpu_system_s','read_bytes','write_bytes')}}
def incident_card(folder,incident_id,*,pre_seconds=60,post_seconds=20,top_n=None):
 if top_n is None:
  from .capture_policy import recorded_top_threads
  top_n=recorded_top_threads(folder)
 if type(incident_id) is not int or incident_id<1 or type(pre_seconds) is not int or not 0<=pre_seconds<=300 or type(post_seconds) is not int or not 0<=post_seconds<=60:raise SessionReadError('INVALID_INCIDENT_CARD')
 with SessionView.open(folder) as view:
  if not view.is_v2:return {'status':'LEGACY_LIMITED_DATA','root_cause':'UNKNOWN','schema_version':2}
  raw=view.db.execute('SELECT * FROM incidents WHERE incident_id=?',(incident_id,)).fetchone()
  if raw is None:raise SessionReadError('INCIDENT_NOT_FOUND')
  item=dict(raw);text=item.pop('context_json')
  if len(text)>16384:raise SessionReadError('IMPORTED_INCIDENT_SIZE_LIMIT')
  item['context']=json.loads(text);series=_selected_series(view,1);first,last,count=view.bounds(series)
  if not count:return {'status':'NO_RESOURCE_SAMPLES','incident':item,'root_cause':'UNKNOWN','schema_version':2}
  trigger=item['start_ns'];ended=item['end_ns'] if item['end_ns'] is not None else min(last,trigger)
  lo=max(first,trigger-pre_seconds*10**9);hi=min(last,max(trigger,ended)+post_seconds*10**9)
  if hi<lo:lo=hi=max(first,min(last,trigger))
  begin=max(lo,min(hi,trigger));end=max(lo,min(hi,ended))
  from .event_stream import event_page
  from .process_tree import resource_tree_page,tree_totals
  children=resource_tree_page(view,lo,hi,limit=100);children['totals']=tree_totals(view,lo,hi)
  return {'schema_version':2,'status':'OBSERVATION_ONLY','incident':item,'range_ns':[lo,hi],
   'snapshots':{'before':_snapshot(view,begin,series),'at_end':_snapshot(view,end,series),'post':_snapshot(view,hi,series)},
   'resources':{'before':view.interval(lo,begin,series=series,buckets=32),'inside':view.interval(begin,end,series=series,buckets=32),'after':view.interval(end,hi,series=series,buckets=32)},
   'threads':view.thread_summary(lo,hi,top_n=top_n),'process_tree':children,
   'events':event_page(folder,start_ns=lo,end_ns=hi,limit=50),
   'native_windows':event_page(folder,start_ns=lo,end_ns=hi,source='WIN32',limit=32),
   'wct':event_page(folder,start_ns=lo,end_ns=hi,source='WCT',limit=16),
   'trace_evidence':event_page(folder,start_ns=lo,end_ns=hi,source='ETW',limit=16),
   'runtime_evidence':event_page(folder,start_ns=lo,end_ns=hi,source='EVENTPIPE',limit=16),
   'capabilities':view.metadata.get('capabilities',[]),'post_context_complete':item['end_ns'] is not None and last>=ended+post_seconds*10**9,
   'next_actions':['INSPECT_AVAILABLE_WCT','REPEAT_EQUIVALENT_WORKLOAD','ADD_VOLUNTARY_STAGE_EVENTS'],
   'hypotheses':[{'code':'INSPECT_COINCIDENT_WORK_OR_WAITS','class':'CANDIDATE'}],'limitations':LIMITATIONS+['PRE_POST_MAY_BE_PARTIAL'],
   'source_trust':'UNVERIFIED_IMPORT','root_cause':'UNKNOWN','root_cause_proven':False}

