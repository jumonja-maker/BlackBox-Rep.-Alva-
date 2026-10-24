"""Read-only local Application event log. No WER settings or target mutation.

Execution.ProcessID is the logger, never silently treated as the crashed PID.
Only named target PID payload fields and a bounded UTC interval are matched.
"""
from __future__ import annotations
from datetime import datetime,timezone
import os,time,xml.etree.ElementTree as ET

NS={'e':'http://schemas.microsoft.com/win/2004/08/events/event'}
PROVIDERS={'Application Error':{1000},'Windows Error Reporting':{1001},'.NET Runtime':{1026}}
PID_NAMES=('ProcessId','ProcessID','FaultingProcessId','FaultingProcessID')
def utc_ns(value):
 if not isinstance(value,str) or len(value)>64:raise ValueError('INVALID_EVENT_UTC')
 parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
 if parsed.tzinfo is None:raise ValueError('EVENT_UTC_TIMEZONE_REQUIRED')
 delta=parsed.astimezone(timezone.utc)-datetime(1970,1,1,tzinfo=timezone.utc)
 return (delta.days*86400+delta.seconds)*10**9+delta.microseconds*1000
def parse_event(xml,*,pid,start_utc_ns,end_utc_ns):
 if not isinstance(xml,str) or len(xml)>262144 or '<!DOCTYPE' in xml.upper() or '<!ENTITY' in xml.upper():raise ValueError('UNSAFE_EVENT_XML')
 root=ET.fromstring(xml);system=root.find('e:System',NS)
 if system is None:return None
 provider=system.find('e:Provider',NS);name=provider.get('Name','') if provider is not None else ''
 try:event_id=int(system.findtext('e:EventID','',NS))
 except ValueError:return None
 if event_id not in PROVIDERS.get(name,set()):return None
 node=system.find('e:TimeCreated',NS)
 if node is None:return None
 stamp=utc_ns(node.get('SystemTime'))
 if not start_utc_ns<=stamp<=end_utc_ns:return None
 data={}
 for field in root.findall('e:EventData/e:Data',NS):
  key=field.get('Name','')
  if key in PID_NAMES:data[key]=(field.text or '')[:40]
 matched=[]
 for key,value in data.items():
  try:actual=int(value,16 if value.lower().startswith('0x') else 10)
  except ValueError:continue
  if actual==pid:matched.append(key)
 if not matched:return None
 # Raw message/path/module/username/stack payloads are deliberately not kept.
 return {'source':'WIN32_APPLICATION_EVENTLOG','provider':name,'event_id':event_id,
  'record_id':system.findtext('e:EventRecordID','',NS)[:32],'event_utc_ns':stamp,'target_pid':pid,
  'target_match_fields':matched,'match_quality':'NAMED_PID_AND_UTC_WINDOW_BIRTH_NOT_ATTESTED',
  'timestamp_precision':'RENDERED_UTC_PARSED_TO_DATETIME_MICROSECONDS',
  'classification':'OS_RECORDED_FAILURE_EVENT_NOT_INTERNAL_ROOT_CAUSE','root_cause':'UNKNOWN'}

def query(pid,created,*,end_utc_ns=None,max_events=200):
 if type(pid) is not int or pid<=0 or type(created) not in (int,float) or created<=0 or type(max_events) is not int or not 1<=max_events<=200:raise ValueError('INVALID_CRASH_QUERY')
 end=time.time_ns() if end_utc_ns is None else end_utc_ns
 if type(end) is not int or not 0<end<=time.time_ns()+10**9:raise ValueError('INVALID_CRASH_QUERY')
 start=max(int(created*10**9),end-86400*10**9)
 if start>end:raise ValueError('INVALID_CRASH_QUERY_INTERVAL')
 base={'source':'WIN32_APPLICATION_EVENTLOG','status':'UNSUPPORTED_PLATFORM','events':[],'window_utc_ns':[start,end],
  'target':{'pid':pid,'created':created},'loss_count':None,'capture_complete':False,
  'limitations':['NO_MATCH_IS_NOT_NO_CRASH','EVENTLOG_CAN_BE_DELAYED_DISABLED_OR_INACCESSIBLE','PID_REUSE_WITHIN_WINDOW_NOT_INDEPENDENTLY_EXCLUDED',
   'EXECUTION_PID_IS_LOGGER_NOT_FAULTING_TARGET','NO_RAW_MESSAGES_PATHS_OR_WER_CHANGES']}
 if os.name!='nt':return base
 import ctypes as C
 from ctypes import wintypes as W
 api=C.WinDLL('wevtapi.dll',use_last_error=True,winmode=0x800)
 api.EvtQuery.argtypes=[W.HANDLE,W.LPCWSTR,W.LPCWSTR,W.DWORD];api.EvtQuery.restype=W.HANDLE
 api.EvtNext.argtypes=[W.HANDLE,W.DWORD,C.POINTER(W.HANDLE),W.DWORD,W.DWORD,C.POINTER(W.DWORD)];api.EvtNext.restype=W.BOOL
 api.EvtRender.argtypes=[W.HANDLE,W.HANDLE,W.DWORD,W.DWORD,C.c_void_p,C.POINTER(W.DWORD),C.POINTER(W.DWORD)];api.EvtRender.restype=W.BOOL
 api.EvtClose.argtypes=[W.HANDLE];api.EvtClose.restype=W.BOOL
 def iso(ns):return datetime.fromtimestamp(ns/10**9,timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
 xpath="*[System[(EventID=1000 or EventID=1001 or EventID=1026) and TimeCreated[@SystemTime>='"+iso(start)+"' and @SystemTime<='"+iso(end)+"']]]"
 handle=api.EvtQuery(None,'Application',xpath,0x1|0x200)
 if not handle:return {**base,'status':'ACCESS_DENIED' if C.get_last_error()==5 else 'QUERY_FAILED','win32_error':C.get_last_error()}
 rows=[];scanned=0;invalid=0;status='NO_MATCH_OBSERVED';deadline=time.monotonic()+5
 try:
  while scanned<2000 and len(rows)<max_events and time.monotonic()<deadline:
   events=(W.HANDLE*16)();got=W.DWORD()
   if not api.EvtNext(handle,16,events,200,0,C.byref(got)):
    code=C.get_last_error()
    if code!=259:status='TIMEOUT' if code==1460 else 'QUERY_INCOMPLETE'
    break
   try:
    for i in range(got.value):
     scanned+=1;needed=W.DWORD();props=W.DWORD();api.EvtRender(None,events[i],1,0,None,C.byref(needed),C.byref(props))
     if needed.value<=0 or needed.value>524288:invalid+=1;continue
     buffer=C.create_unicode_buffer((needed.value+1)//2)
     if not api.EvtRender(None,events[i],1,C.sizeof(buffer),buffer,C.byref(needed),C.byref(props)):invalid+=1;continue
     try:row=parse_event(buffer.value,pid=pid,start_utc_ns=start,end_utc_ns=end)
     except (ValueError,ET.ParseError):invalid+=1;continue
     if row and len(rows)<max_events:rows.append(row)
   finally:
    for i in range(got.value):api.EvtClose(events[i])
  else:status='TRUNCATED'
 finally:api.EvtClose(handle)
 if rows and status=='NO_MATCH_OBSERVED':status='MATCHING_OS_EVENTS'
 return {**base,'status':status,'events':rows,'scanned_events':scanned,'invalid_events':invalid,
  'query_completed':status in ('NO_MATCH_OBSERVED','MATCHING_OS_EVENTS'),'capture_complete':False}
