"""Explicit offline ETL best-effort decode via Windows' own tracerpt.

Event headers identify their emitter, not necessarily a causal/faulting target.
No symbols/downloads, decoded stack guesses, or invented event-loss numbers.
"""
from __future__ import annotations
import hashlib,os,subprocess,tempfile,time,xml.etree.ElementTree as ET
from pathlib import Path
from .session_v2 import safe_path
from .optional_jobs import OwnedProcess
NS={'e':'http://schemas.microsoft.com/win/2004/08/events/event'}
def file_hash(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1024**2),b''):h.update(block)
 return h.hexdigest()
def parse_xml(path,*,target_pid,max_rows=500):
 if type(target_pid) is not int or target_pid<=0 or type(max_rows) is not int or not 1<=max_rows<=500:raise ValueError('INVALID_TRACE_DECODE_POLICY')
 path=safe_path(path)
 if path.stat().st_size>32*1024**2:raise ValueError('TRACE_DECODE_XML_BUDGET')
 # Reject declarations over the complete bounded file, including UTF-16 output.
 with path.open('rb') as f:
  tail=b''
  for chunk in iter(lambda:f.read(65536),b''):
   check=(tail+chunk).replace(b'\x00',b'').upper()
   if b'<!DOCTYPE' in check or b'<!ENTITY' in check:raise ValueError('UNSAFE_TRACE_XML')
   tail=chunk[-64:]
 rows=[];scanned=0;recognized=0;matched=0;providers={};deadline=time.monotonic()+10
 iterator=ET.iterparse(path,events=('start','end'));_,root=next(iterator)
 for event,node in iterator:
  if event!='end' or node.tag.split('}')[-1]!='Event':continue
  scanned+=1
  if scanned%128==0 and time.monotonic()>deadline:raise TimeoutError('TRACE_DECODE_PARSE_TIMEOUT')
  system=node.find('e:System',NS)
  if system is None:system=node.find('System')
  if system is not None:
   def child(name):
    value=system.find('e:'+name,NS)
    return value if value is not None else system.find(name)
   execution=child('Execution');provider=child('Provider');eid=child('EventID');stamp=child('TimeCreated')
   if provider is not None and eid is not None and (eid.text or '').strip() and stamp is not None:recognized+=1
   try:emitter=int(execution.get('ProcessID','')) if execution is not None else None
   except ValueError:emitter=None
   if emitter==target_pid:
    matched+=1;name=(provider.get('Name') or provider.get('Guid') or 'UNKNOWN_PROVIDER')[:128] if provider is not None else 'UNKNOWN_PROVIDER'
    if name in providers or len(providers)<128:providers[name]=providers.get(name,0)+1
    if len(rows)<max_rows:rows.append({'source':'ETW_TRACERPT','provider':name,'event_id':(eid.text or '')[:32] if eid is not None else None,
     'emitter_pid':emitter,'thread_id':execution.get('ThreadID','')[:32],
     'timestamp_utc':stamp.get('SystemTime','')[:80] if stamp is not None else None,
     'scope':'TARGET_EMITTER_PID_NOT_CAUSAL_ATTRIBUTION','verification_class':'UNVERIFIED_IMPORT'})
  node.clear();root.clear()
 return {'rows':rows,'scanned_events':scanned,'recognized_header_events':recognized,'matching_emitter_events':matched,'rows_omitted':max(0,matched-len(rows)),
  'provider_counts':providers,'event_payloads_retained':False,'decoded_scope':'EVENT_HEADERS_ONLY_NOT_STACKS_OR_GC_PAYLOADS'}

def decode(path,*,target_pid):
 base={'source':'ETW_TRACERPT','status':'UNSUPPORTED_PLATFORM','decoded':False,'lost_events':None,
  'root_cause':'UNKNOWN','limitations':['IMPORTED_ETL_NOT_AUTHENTICATED','HEADER_PID_IDENTIFIES_EMITTER',
   'NO_ETL_CLOCK_ALIGNMENT_TO_SESSION_ASSUMED','LOSS_COUNT_UNKNOWN','NO_GC_OR_DISK_LATENCY_INFERRED_FROM_HEADERS']}
 if os.name!='nt':return base
 path=safe_path(path)
 if path.suffix.lower()!='.etl' or not path.is_file() or not 0<path.stat().st_size<=256*1024**2:raise ValueError('INVALID_ETL_OR_INPUT_SIZE_LIMIT')
 tool=Path(os.environ.get('SystemRoot','C:/Windows'))/'System32'/'tracerpt.exe'
 if not tool.is_file():return {**base,'status':'TOOL_UNAVAILABLE'}
 before=file_hash(path);owner=None
 with tempfile.TemporaryDirectory(prefix='blackbox-tracerpt-') as tmp:
  directory=Path(tmp);output=directory/'events.xml';log=directory/'tool.log'
  try:
   with log.open('xb') as stream:
    owner=OwnedProcess([str(tool),str(path),'-o',str(output),'-of','XML','-lr','-y'],stdout=stream,stderr=stream)
    deadline=time.monotonic()+25
    while owner.process.poll() is None:
     if time.monotonic()>deadline:raise TimeoutError('TRACE_DECODE_TOOL_TIMEOUT')
     if (output.exists() and output.stat().st_size>32*1024**2) or log.stat().st_size>1024**2:raise ValueError('TRACE_DECODE_OUTPUT_BUDGET')
     time.sleep(.05)
   if owner.process.returncode!=0 or not output.is_file():return {**base,'status':'TOOL_DECODE_FAILED','exit_code':owner.process.returncode}
   if file_hash(path)!=before:raise ValueError('TRACE_INPUT_CHANGED_DURING_DECODE')
   result=parse_xml(output,target_pid=target_pid)
   return {**base,**result,'status':'HEADER_EVENTS_DECODED' if result['recognized_header_events'] else 'NO_RECOGNIZED_EVENTS',
    'decoded':bool(result['recognized_header_events']),'input_sha256':before,'decoder':{'name':'tracerpt.exe','sha256':file_hash(tool),'source':'WINDOWS_SYSTEM32_TOOL'},'decoded_xml_bytes':output.stat().st_size}
  finally:
   if owner:owner.close(kill=True)
