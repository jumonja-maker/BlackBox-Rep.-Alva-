"""Explicit recovery in an owned recording, including orphaned writers.

Live journal owner/guardian identity is checked separately; never global WPR.
"""
import hashlib,math,os,re,time
from pathlib import Path
from .library_files import checked,read_json,atomic_json
from .trace_cleanup import terminal_cleanup_proven
def _birth(value):
 try:return type(value) in (int,float) and value>0 and math.isfinite(value)
 except OverflowError:return False
def journal_identity(path):
 from .chain_io import fingerprint_file
 return fingerprint_file(path,max_bytes=65536,deadline=time.monotonic()+5)
def alive(data,prefix):
 import psutil
 pid=data.get(prefix+'_pid');created=data.get(prefix+'_created')
 if type(pid) is not int or pid<=0:return False
 try:
  actual=psutil.Process(pid).create_time()
  # An old journal with no birth time cannot prove that an existing PID is
  # unrelated. Be conservative; never stop it just because metadata is old.
  return abs(actual-created)<.000001 if _birth(actual) and _birth(created) else True
 except psutil.NoSuchProcess:return False
 except psutil.AccessDenied:return True
def folder_for(catalog,entry_id):
 row=catalog.entry(entry_id)
 if row['origin']!='LOCAL_APP_MARKED' or row['state'] in ('TRASH','MOVING_TO_TRASH','RESTORING','PURGING','PURGE_PARTIAL','PURGED'):raise ValueError('TRACE_RECOVERY_REQUIRES_OWNED_RECORDING')
 folder=catalog._folder(row);catalog._marker(folder,row);return folder
def _owned_context(context,entry_id,path,data):
 """An owner-injected job binding, corroborated by the actual worker parent.

 User operation args never enter this channel. This permits an explicit
 recovery of the helper's inactive old recording without pretending its
 still-live PID is an abandoned owner.
 """
 import psutil
 if type(context) is not dict:raise ValueError('TRACE_OWNER_STILL_ACTIVE')
 owner=context.get('owner',{});source=context.get('source')
 trace_id=data.get('instance') if path.name.startswith('BLACKBOX_') else data.get('uid')
 if (type(owner) is not dict or type(owner.get('pid')) is not int or
  owner['pid']!=os.getppid() or not _birth(owner.get('created')) or
  data.get('owner_pid')!=owner['pid'] or not _birth(data.get('owner_created')) or
  abs(data['owner_created']-owner['created'])>=.000001 or
  context.get('entry_id')!=entry_id or context.get('folder')!=str(path.parent.parent) or
  context.get('journal')!=path.name or context.get('trace_id')!=trace_id or
  type(context.get('command_id')) is not str or not context['command_id']):
  raise ValueError('TRACE_RECOVERY_OWNER_BINDING_MISMATCH')
 try:actual=psutil.Process(owner['pid']).create_time()
 except psutil.Error:raise ValueError('TRACE_RECOVERY_OWNER_BINDING_MISMATCH') from None
 if not _birth(actual) or abs(actual-owner['created'])>=.000001:
  raise ValueError('TRACE_RECOVERY_OWNER_BINDING_MISMATCH')
 if source!=journal_identity(path):raise ValueError('TRACE_RECOVERY_SOURCE_CHANGED')
 return context
def _finalized(data,*,journal=None):
 return terminal_cleanup_proven(data,journal=journal)
def scan(catalog,entry_id,*,_owned=()):
 artifacts=checked(folder_for(catalog,entry_id)/'artifacts');rows=[]
 if artifacts.is_dir():
  for path in artifacts.glob('*.trace.json'):
   if len(rows)>=100:break
   try:
    data=read_json(path,65536);valid=bool(re.fullmatch(r'(BLACKBOX|EVENTPIPE)_[0-9a-f]{32}\.trace\.json',path.name))
    owner_active=alive(data,'owner');guardian_active=alive(data,'guardian');owned=False
    if owner_active and not guardian_active:
     for context in _owned:
      if type(context) is not dict or context.get('journal')!=path.name:continue
      try:_owned_context(context,entry_id,path,data);owned=True
      except (OSError,ValueError):pass
    rows.append({'journal':path.name,'state':data.get('state'),'owner_active':owner_active or guardian_active,
     'eligible':valid and not guardian_active and (not owner_active or owned) and not _finalized(data,journal=path.name),
     'source':data.get('source','NOT_STARTED'),'recording_id':entry_id,
     'recovery_scope':'EXPLICIT_INACTIVE_OWNING_HELPER' if owned else 'ABANDONED_OWNER_ONLY'})
   except (OSError,ValueError):rows.append({'journal':path.name,'state':'INVALID_RETAINED','eligible':False})
 return {'rows':rows,'automatic_cleanup':False,'files_deleted':False}
def recover(catalog,entry_id,journal,*,confirmed=False,_owned=None):
 if confirmed is not True:raise ValueError('TRACE_RECOVERY_CONFIRMATION_REQUIRED')
 if not re.fullmatch(r'(BLACKBOX|EVENTPIPE)_[0-9a-f]{32}\.trace\.json',str(journal)):raise ValueError('INVALID_TRACE_JOURNAL')
 folder=checked(folder_for(catalog,entry_id)/'artifacts');path=checked(folder/journal);data=read_json(path,65536)
 if alive(data,'guardian'):raise ValueError('TRACE_OWNER_STILL_ACTIVE')
 binding=_owned_context(_owned,entry_id,path,data) if _owned is not None else None
 if alive(data,'owner') and binding is None:raise ValueError('TRACE_OWNER_STILL_ACTIVE')
 if _finalized(data,journal=path.name):raise ValueError('TRACE_ALREADY_FINALIZED')
 if data.get('consent')!='EXPLICIT_USER_COMMAND':raise ValueError('TRACE_CONSENT_NOT_RECORDED')
 if journal.startswith('BLACKBOX_'):
  instance=journal.removesuffix('.trace.json')
  if data.get('instance')!=instance or data.get('uid') is not None:raise ValueError('INVALID_OWNED_TRACE_INSTANCE')
  from .windows_research import WprCapture,WprCommandError,WPR_NO_ACTIVE_PROFILES
  cap=WprCapture(folder);cap.instance=instance;cap.active=True
  observation='NAMED_CANCEL_CONFIRMED';absence_code=None
  try:cap.cancel()
  except WprCommandError as exc:
   # Microsoft documents 0xC5583000 for no profiles in the addressed
   # instance. Accept only the actual numeric result of THIS exact Cancel;
   # localized output, another command, or any other error proves nothing.
   code=exc.wpr_returncode
   if (type(code) is not int or not -(2**31)<=code<2**32 or
    code & 0xffffffff!=WPR_NO_ACTIVE_PROFILES or exc.wpr_arguments!=('-cancel',) or
    exc.wpr_instance!=instance):raise
   cap.active=False;observation='NAMED_INSTANCE_ABSENT_CONFIRMED';absence_code=code & 0xffffffff
  if cap.active is not False:raise ValueError('TRACE_NAMED_CANCEL_UNCONFIRMED')
  status='RECOVERED_NAMED_CANCEL'
 else:
  uid=journal.removeprefix('EVENTPIPE_').removesuffix('.trace.json')
  if data.get('uid')!=uid or data.get('instance') is not None:raise ValueError('INVALID_EVENTPIPE_JOURNAL')
  if type(data.get('collector_pid')) is not int or data['collector_pid']<=0 or not _birth(data.get('collector_created')):
   raise ValueError('TRACE_COLLECTOR_IDENTITY_UNCONFIRMED')
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
 cleanup={'confirmed':True,'scope':'EXPLICIT_EXACT_NAMED_RECOVERY','trace_id':data.get('instance',data.get('uid'))}
 if journal.startswith('BLACKBOX_'):
  cleanup['observation']=observation
  if absence_code is not None:cleanup['wpr_returncode']=absence_code
 data.update(state=status,recovered_utc_ns=time.time_ns(),recovery_consent='EXPLICIT_USER_COMMAND',capture_complete=False,lost_events=None,resource_cleanup=cleanup)
 atomic_json(path,data)
 result={'status':status,'journal':journal,'recording_id':entry_id,'files_deleted':False,'target_terminated':False,'capture_complete':False,'lost_events':None,'resource_cleanup':cleanup}
 if binding is not None:result.update(owner_binding=binding,source_after=journal_identity(path))
 return result

