"""Bounded user-selected policies. Standard never starts opt-in collectors."""
from copy import deepcopy
TRIGGERS=('CPU_SUSTAINED','PRIVATE_GROWTH','RSS_GROWTH','HANDLE_GROWTH','IO_BURST','UI_TIMEOUT','PROCESS_EXIT_OBSERVED','SAMPLING_GAP')
DEFAULT={'schema_version':1,'profile':'STANDARD','detail_interval_ms':2000,'thread_limit':256,
 'child_limit':256,'top_threads':32,'burst_seconds':20,'burst_interval_ms':500,'session_seconds':0,
 'max_session_mb':1024,'max_trace_mb':256,'windows_enabled':False,'incident_enabled':False,
 'incident':{'threshold':85.,'min_duration_ms':3000,'gap_ms':5500,'pre_ms':60000,'post_ms':20000,
 'cooldown_ms':30000,'max_incidents':20,'memory_growth_bytes':32*1024**2,'handle_growth':128,
 'growth_window_ms':10000,'io_rate_bytes_s':64*1024**2,'gap_incidents':False,
 'enabled_triggers':list(TRIGGERS[:-1]),'cpu_reference':'ABSOLUTE'}}
def validate_policy(value=None):
 result=deepcopy(DEFAULT)
 if value is None:return result
 if type(value) is not dict or set(value)-set(DEFAULT):raise ValueError('INVALID_CAPTURE_POLICY')
 for key,item in value.items():
  if key=='incident':
   if type(item) is not dict or set(item)-set(DEFAULT['incident']):raise ValueError('INVALID_INCIDENT_POLICY')
   result['incident'].update(item)
  else:result[key]=item
 if type(result['schema_version']) is not int or result['schema_version']!=1 or result['profile'] not in ('STANDARD','DETAILED','INCIDENT_BURST'):raise ValueError('INVALID_CAPTURE_PROFILE')
 limits={'detail_interval_ms':(500,30000),'thread_limit':(1,1024),'child_limit':(1,256),'top_threads':(1,256),
 'burst_seconds':(1,60),'burst_interval_ms':(500,5000),'session_seconds':(0,604800),
 'max_session_mb':(16,1024*1024),'max_trace_mb':(1,1024)}
 for key,(lo,hi) in limits.items():
  if type(result[key]) is not int or not lo<=result[key]<=hi:raise ValueError('INVALID_CAPTURE_LIMIT_'+key.upper())
 if result['top_threads']>result['thread_limit']:raise ValueError('TOP_THREADS_EXCEEDS_CAPTURE_LIMIT')
 if any(type(result[k]) is not bool for k in ('windows_enabled','incident_enabled')):raise ValueError('INVALID_CAPTURE_POLICY')
 from .incidents import IncidentCapture
 IncidentCapture(**result['incident'])
 return result
def profile_description(value):
 p=validate_policy(value)
 return {'profile':p['profile'],'starts_etw':False,'starts_dump':False,'requires_administrator':False,
 'overhead':'EXTRA_THREAD_CHILD_MEMORY_QUERIES' if p['profile']=='DETAILED' else 'BOUNDED_DETAIL_ON_INCIDENT' if p['profile']=='INCIDENT_BURST' else 'BASE_PROCESS_COUNTERS',
 'estimate_not_benchmark':True,'burst_limit_seconds':p['burst_seconds']}

def recorded_top_threads(folder):
 """Use this recording's preference, never the current live target's policy."""
 from pathlib import Path
 from contextlib import closing
 from .casebook import readonly
 import json,sqlite3
 path=Path(folder)/'research.sqlite3'
 if not path.is_file():return DEFAULT['top_threads']
 try:
  with closing(readonly(path)) as db:
   row=db.execute("SELECT substr(data,1,65537) FROM context WHERE key='experiment'").fetchone()
  if not row or len(row[0])>65536:return DEFAULT['top_threads']
  n=json.loads(row[0]).get('capture_policy',{}).get('top_threads',DEFAULT['top_threads'])
  return n if type(n) is int and 1<=n<=256 else DEFAULT['top_threads']
 except (OSError,ValueError,TypeError,AttributeError,sqlite3.Error):return DEFAULT['top_threads']

