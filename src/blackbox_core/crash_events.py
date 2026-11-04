"""Read-only local Application event log. No WER settings or target mutation.

Execution.ProcessID is the logger, never silently treated as the crashed PID.
Only named target PID payload fields and a bounded UTC interval are matched.
"""
from __future__ import annotations
from datetime import datetime,timezone
import hashlib,math,os,re,time,xml.etree.ElementTree as ET

NS={'e':'http://schemas.microsoft.com/win/2004/08/events/event'}
PROVIDERS={'Application Error':{1000},'Windows Error Reporting':{1001},'.NET Runtime':{1026}}
PID_NAMES=('ProcessId','ProcessID','FaultingProcessId','FaultingProcessID')
CREATION_NAMES=('ProcessCreationTime','ProcessStartTime','FaultingProcessCreationTime')

def _payload_integer(value,*,hex_default=False):
 if not isinstance(value,str) or len(value)>40:return None
 try:answer=int(value,16 if value.lower().startswith('0x') or hex_default else 10)
 except ValueError:return None
 return answer if 0<=answer<2**64 else None

def _basename(value):
 return str(value or '').replace('\\','/').rsplit('/',1)[-1][:512]

def _version(value):
 return value if isinstance(value,str) and len(value)<=64 and re.fullmatch(r'[0-9]{1,10}(?:\.[0-9]{1,10}){1,3}',value) else None
def utc_ns(value):
 if not isinstance(value,str) or len(value)>64:raise ValueError('INVALID_EVENT_UTC')
 parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
 if parsed.tzinfo is None:raise ValueError('EVENT_UTC_TIMEZONE_REQUIRED')
 delta=parsed.astimezone(timezone.utc)-datetime(1970,1,1,tzinfo=timezone.utc)
 return (delta.days*86400+delta.seconds)*10**9+delta.microseconds*1000

def parse_wer_candidate(xml,*,image_name,start_utc_ns,end_utc_ns):
 """WER report metadata without a target PID is only an image/time candidate."""
 if not isinstance(image_name,str) or not image_name or len(image_name)>1024:raise ValueError('INVALID_WER_IMAGE_NAME')
 if type(start_utc_ns) is not int or type(end_utc_ns) is not int or not 0<=start_utc_ns<=end_utc_ns:raise ValueError('INVALID_EVENT_WINDOW')
 if not isinstance(xml,str) or len(xml)>262144 or '<!DOCTYPE' in xml.upper() or '<!ENTITY' in xml.upper():raise ValueError('UNSAFE_EVENT_XML')
 root=ET.fromstring(xml);system=root.find('e:System',NS)
 if system is None:return None
 provider=system.find('e:Provider',NS)
 if provider is None or provider.get('Name')!='Windows Error Reporting' or system.findtext('e:EventID','',NS)!='1001':return None
 node=system.find('e:TimeCreated',NS)
 if node is None:return None
 stamp=utc_ns(node.get('SystemTime'))
 if not start_utc_ns<=stamp<=end_utc_ns:return None
 values={}
 for field in root.findall('e:EventData/e:Data',NS):
  key=field.get('Name','')
  if key in ('AppName','P1','EventName','ReportId','ReportID'):
   if key in values:return None
   values[key]=(field.text or '')[:1024]
 name=_basename(values.get('AppName') or values.get('P1'))
 if values.get('AppName') and values.get('P1') and _basename(values['AppName']).casefold()!=_basename(values['P1']).casefold():return None
 if not name or name.casefold()!=_basename(image_name).casefold():return None
 event_name=values.get('EventName','')
 if event_name not in ('APPCRASH','BEX','BEX64','CLR20r3','MoAppCrash','AppHangB1','AppHangXProcB1'):return None
 report_id=values.get('ReportId') or values.get('ReportID')
 if report_id and not re.fullmatch(r'[0-9a-fA-F{}-]{32,38}',report_id):report_id=None
 encoded=xml.encode('utf-8');digest=hashlib.sha256(encoded).hexdigest()
 return {'source':'WIN32_APPLICATION_EVENTLOG','provider':'Windows Error Reporting','event_id':1001,
  'record_id':system.findtext('e:EventRecordID','',NS)[:32],'event_utc_ns':stamp,
  'source_id':'sha256:'+digest,'source_sha256':digest,'source_size_bytes':len(encoded),
  'source_type':'RENDERED_WINDOWS_EVENT_XML_UTF8','verification_class':'UNVERIFIED_IMPORT',
  'application':{'name':name},'wer_event_name':event_name,'report_id':report_id,
  'target_pid':None,'process_instance_binding':'NOT_ESTABLISHED_IMAGE_AND_TIME_CANDIDATE_ONLY',
  'classification':'UNATTRIBUTED_WER_REPORT_CANDIDATE_NOT_TARGET_CRASH_PROOF','root_cause':'UNKNOWN'}
def parse_event(xml,*,pid,start_utc_ns,end_utc_ns,expected_created_100ns=None):
 if type(pid) is not int or not 0<pid<=0xFFFFFFFF:raise ValueError('INVALID_EVENT_TARGET_PID')
 if type(start_utc_ns) is not int or type(end_utc_ns) is not int or not 0<=start_utc_ns<=end_utc_ns:raise ValueError('INVALID_EVENT_WINDOW')
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
  if key in PID_NAMES+CREATION_NAMES+('AppName','AppVersion','ModuleName','ModuleVersion',
                                    'ExceptionCode','FaultingOffset','FaultingThreadId'):
   if key in data:return None
   data[key]=(field.text or '')[:1024]
 matched=[key for key in PID_NAMES if key in data]
 named_pids=[_payload_integer(data[key]) for key in matched]
 if (not named_pids or any(value is None or not 0<value<=0xFFFFFFFF for value in named_pids)
     or len(set(named_pids))!=1 or named_pids[0]!=pid):return None
 creation=[_payload_integer(data.get(k)) for k in CREATION_NAMES if k in data]
 creation=[n for n in creation if n]
 if len(set(creation))>1:return None
 recorded_creation=creation[0] if creation else None
 if recorded_creation is not None and (recorded_creation-116444736000000000)*100>stamp+999:return None
 if expected_created_100ns is not None:
  if type(expected_created_100ns) is not int or not 0<expected_created_100ns<2**64:raise ValueError('INVALID_EVENT_TARGET_FILETIME')
  if recorded_creation is not None and recorded_creation!=expected_created_100ns:return None
 bound=recorded_creation is not None and expected_created_100ns==recorded_creation
 execution=system.find('e:Execution',NS)
 logger_pid=_payload_integer(execution.get('ProcessID')) if execution is not None else None
 encoded=xml.encode('utf-8')
 digest=hashlib.sha256(encoded).hexdigest()
 # Raw message/path/module/username/stack payloads are deliberately not kept.
 return {'source':'WIN32_APPLICATION_EVENTLOG','provider':name,'event_id':event_id,
  'source_id':'sha256:'+digest,'source_sha256':digest,'source_size_bytes':len(encoded),
  'source_type':'RENDERED_WINDOWS_EVENT_XML_UTF8','verification_class':'UNVERIFIED_IMPORT',
  'record_id':system.findtext('e:EventRecordID','',NS)[:32],'event_utc_ns':stamp,'target_pid':pid,
  'target_match_fields':matched,'match_quality':'NAMED_PID_AND_RECORDED_CREATION_FILETIME' if bound else 'NAMED_PID_AND_UTC_WINDOW_BIRTH_NOT_ATTESTED',
  'logger_pid':logger_pid,'recorded_creation_100ns':recorded_creation,
  'process_instance_binding':'MATCHED_RECORDED_CREATION_FILETIME' if bound else 'BIRTH_NOT_ATTESTED',
  'application':{'name':_basename(data.get('AppName')),'version':_version(data.get('AppVersion'))},
  'faulting_module':{'name':_basename(data.get('ModuleName')),'version':_version(data.get('ModuleVersion'))},
  'exception_code':_payload_integer(data.get('ExceptionCode'),hex_default=True),
  'faulting_offset':_payload_integer(data.get('FaultingOffset'),hex_default=True),
  'faulting_tid':_payload_integer(data.get('FaultingThreadId')),
  'timestamp_precision':'RENDERED_UTC_PARSED_TO_DATETIME_MICROSECONDS',
  'classification':'OS_RECORDED_FAILURE_EVENT_NOT_INTERNAL_ROOT_CAUSE','root_cause':'UNKNOWN'}

def query(pid,created,*,end_utc_ns=None,max_events=200,expected_created_100ns=None,
          cancel_event=None,deadline=None,image_name=None):
 if type(pid) is not int or not 0<pid<=0xFFFFFFFF or type(created) not in (int,float) or not 0<created<2**63 or type(max_events) is not int or not 1<=max_events<=200:raise ValueError('INVALID_CRASH_QUERY')
 end=time.time_ns() if end_utc_ns is None else end_utc_ns
 if type(end) is not int or not 0<end<=time.time_ns()+10**9:raise ValueError('INVALID_CRASH_QUERY')
 if expected_created_100ns is not None and (type(expected_created_100ns) is not int or not 0<expected_created_100ns<2**64):raise ValueError('INVALID_EVENT_TARGET_FILETIME')
 if deadline is not None and (type(deadline) not in (int,float) or not math.isfinite(deadline) or deadline<=0):raise ValueError('INVALID_CRASH_DEADLINE')
 if image_name is not None and (not isinstance(image_name,str) or not 1<=len(image_name)<=1024):raise ValueError('INVALID_WER_IMAGE_NAME')
 start=max(int(created*10**9),end-86400*10**9)
 if start>end:raise ValueError('INVALID_CRASH_QUERY_INTERVAL')
 base={'source':'WIN32_APPLICATION_EVENTLOG','status':'UNSUPPORTED_PLATFORM','events':[],'wer_candidates':[],'window_utc_ns':[start,end],
  'target':{'pid':pid,'created':created},'loss_count':None,'capture_complete':False,
  'limitations':['NO_MATCH_IS_NOT_NO_CRASH','EVENTLOG_CAN_BE_DELAYED_DISABLED_OR_INACCESSIBLE','PID_REUSE_WITHIN_WINDOW_NOT_INDEPENDENTLY_EXCLUDED',
   'EXECUTION_PID_IS_LOGGER_NOT_FAULTING_TARGET','NO_RAW_MESSAGES_PATHS_OR_WER_CHANGES']}
 if cancel_event is not None and cancel_event.is_set():return {**base,'status':'CANCELLED'}
 if deadline is not None and time.monotonic()>=deadline:return {**base,'status':'TIMED_OUT'}
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
 rows=[];candidates=[];candidate_omissions=0;scanned=0;invalid=0;status='NO_MATCH_OBSERVED';deadline=min(time.monotonic()+5,deadline) if deadline is not None else time.monotonic()+5
 close_errors=0
 try:
  while scanned<2000 and len(rows)<max_events and time.monotonic()<deadline:
   if cancel_event is not None and cancel_event.is_set():status='CANCELLED';break
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
     try:row=parse_event(buffer.value,pid=pid,start_utc_ns=start,end_utc_ns=end,expected_created_100ns=expected_created_100ns)
     except (ValueError,ET.ParseError):invalid+=1;continue
     if row and len(rows)<max_events:
      row['verification_class']='LOCAL_OS_EVENTLOG_READ'
      rows.append(row)
     elif image_name:
      try:candidate=parse_wer_candidate(buffer.value,image_name=image_name,start_utc_ns=start,end_utc_ns=end)
      except (ValueError,ET.ParseError):invalid+=1;continue
      if candidate:
       candidate['verification_class']='LOCAL_OS_EVENTLOG_READ'
       if len(candidates)<20:candidates.append(candidate)
       else:candidate_omissions+=1
   finally:
    for i in range(got.value):
     if not api.EvtClose(events[i]):close_errors+=1
  else:status='TRUNCATED'
 finally:
  if not api.EvtClose(handle):close_errors+=1
 if rows and status=='NO_MATCH_OBSERVED':status='MATCHING_OS_EVENTS'
 if close_errors:status='RECOVERY_UNCONFIRMED'
 return {**base,'status':status,'events':rows,'wer_candidates':candidates,'wer_candidates_omitted':candidate_omissions,'scanned_events':scanned,'invalid_events':invalid,
  'query_completed':status in ('NO_MATCH_OBSERVED','MATCHING_OS_EVENTS'),'capture_complete':False,
  'cleanup':{'status':'RECOVERY_UNCONFIRMED' if close_errors else 'COMPLETED','close_failures':close_errors}}
