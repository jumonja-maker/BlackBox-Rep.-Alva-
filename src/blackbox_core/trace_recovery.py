"""Explicit recovery in an owned recording, including orphaned writers.

Live journal owner/guardian identity is checked separately; never global WPR.
"""
import hashlib,os,re,time
from pathlib import Path
from .library_files import checked,read_json,atomic_json
def alive(data,prefix):
 import psutil
 pid=data.get(prefix+'_pid');created=data.get(prefix+'_created')
 if type(pid) is not int or pid<=0:return False
 try:
  actual=psutil.Process(pid).create_time()
  # An old journal with no birth time cannot prove that an existing PID is
  # unrelated. Be conservative; never stop it just because metadata is old.
  return abs(actual-created)<.000001 if type(created) in (int,float) and created>0 else True
 except psutil.NoSuchProcess:return False
 except psutil.AccessDenied:return True
def folder_for(catalog,entry_id):
 row=catalog.entry(entry_id)
 if row['origin']!='LOCAL_APP_MARKED' or row['state'] in ('TRASH','MOVING_TO_TRASH','RESTORING','PURGING','PURGE_PARTIAL','PURGED'):raise ValueError('TRACE_RECOVERY_REQUIRES_OWNED_RECORDING')
 folder=catalog._folder(row);catalog._marker(folder,row);return folder
def scan(catalog,entry_id):
 artifacts=checked(folder_for(catalog,entry_id)/'artifacts');rows=[]
 if artifacts.is_dir():
  for path in artifacts.glob('*.trace.json'):
   if len(rows)>=100:break
   try:
    data=read_json(path,65536);valid=bool(re.fullmatch(r'(BLACKBOX|EVENTPIPE)_[0-9a-f]{32}\.trace\.json',path.name))
    active=alive(data,'owner') or alive(data,'guardian')
    rows.append({'journal':path.name,'state':data.get('state'),'owner_active':active,'eligible':valid and not active and data.get('state') not in ('COMPLETED','FAILED','RECOVERED_NAMED_CANCEL','RECOVERED_OWNED_TOOL_STOP'),'source':data.get('source','NOT_STARTED'),'recording_id':entry_id})
   except (OSError,ValueError):rows.append({'journal':path.name,'state':'INVALID_RETAINED','eligible':False})
 return {'rows':rows,'automatic_cleanup':False,'files_deleted':False}
def recover(catalog,entry_id,journal,*,confirmed=False):
 if confirmed is not True:raise ValueError('TRACE_RECOVERY_CONFIRMATION_REQUIRED')
 if not re.fullmatch(r'(BLACKBOX|EVENTPIPE)_[0-9a-f]{32}\.trace\.json',str(journal)):raise ValueError('INVALID_TRACE_JOURNAL')
 folder=checked(folder_for(catalog,entry_id)/'artifacts');path=checked(folder/journal);data=read_json(path,65536)
 if alive(data,'owner') or alive(data,'guardian'):raise ValueError('TRACE_OWNER_STILL_ACTIVE')
 if data.get('state') in ('COMPLETED','FAILED','RECOVERED_NAMED_CANCEL','RECOVERED_OWNED_TOOL_STOP'):raise ValueError('TRACE_ALREADY_FINALIZED')
 if data.get('consent')!='EXPLICIT_USER_COMMAND':raise ValueError('TRACE_CONSENT_NOT_RECORDED')
 if journal.startswith('BLACKBOX_'):
  instance=journal.removesuffix('.trace.json')
  if data.get('instance')!=instance:raise ValueError('INVALID_OWNED_TRACE_INSTANCE')
  from .windows_research import WprCapture
  cap=WprCapture(folder);cap.instance=instance;cap.active=True;cap.cancel();status='RECOVERED_NAMED_CANCEL'
 else:
  uid=journal.removeprefix('EVENTPIPE_').removesuffix('.trace.json')
  if data.get('uid')!=uid:raise ValueError('INVALID_EVENTPIPE_JOURNAL')
  if alive(data,'collector'):
   import psutil
   process=psutil.Process(data['collector_pid']);args=process.cmdline();expected=str(folder/('eventpipe-'+uid+'.nettrace'))
   try:
    output=args[args.index('--output')+1];target=args[args.index('--process-id')+1]
   except (ValueError,IndexError):raise ValueError('TRACE_COLLECTOR_IDENTITY_UNCONFIRMED') from None
   if os.path.normcase(os.path.normpath(output))!=os.path.normcase(os.path.normpath(expected)) or target!=str(data['target']['pid']):raise ValueError('TRACE_COLLECTOR_IDENTITY_UNCONFIRMED')
   h=hashlib.sha256()
   with Path(process.exe()).open('rb') as f:
    for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
   if h.hexdigest()!=data.get('tool',{}).get('sha256'):raise ValueError('TRACE_COLLECTOR_IDENTITY_UNCONFIRMED')
   if not alive(data,'collector'):raise ValueError('TRACE_COLLECTOR_IDENTITY_UNCONFIRMED')
   process.terminate()
   try:process.wait(timeout=3)
   except psutil.TimeoutExpired:process.kill();process.wait(timeout=2)
  status='RECOVERED_OWNED_TOOL_STOP'
 data.update(state=status,recovered_utc_ns=time.time_ns(),recovery_consent='EXPLICIT_USER_COMMAND',capture_complete=False,lost_events=None)
 atomic_json(path,data)
 return {'status':status,'journal':journal,'recording_id':entry_id,'files_deleted':False,'target_terminated':False,'capture_complete':False,'lost_events':None}

