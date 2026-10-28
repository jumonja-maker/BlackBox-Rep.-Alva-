"""Opt-in GC EventPipe with bounded guardian, lease, journal and tool provenance."""
import hashlib,os,shutil,subprocess,sys,time
from pathlib import Path
from threading import Thread,Event
from uuid import uuid4
from .trace_owner import _read,_write
from .session_v2 import safe_path
from .trace_clock_evidence import capture_trace_clock_bracket
PROFILES=('gc-collect','gc-verbose')
# dotnet-trace may need extra time to attach and to write its rundown.
# Finite tool budgets, NOT a change to user-selected capture duration.
EVENTPIPE_STARTUP_GRACE_S=12
EVENTPIPE_FINALIZE_GRACE_S=8


def eventpipe_collection_deadline_seconds(seconds):
 if type(seconds) is not int or not 1 <= seconds <= 60:
  raise ValueError('INVALID_EVENTPIPE_POLICY')
 return seconds + EVENTPIPE_STARTUP_GRACE_S


def eventpipe_capture_confirmed(rc, size, forced_termination):
 """Never certify a forced or incomplete trace as successfully collected."""
 return rc == 0 and size > 0 and not forced_termination


def runtime_capability(pid):
 from .preparation import inspect_target
 data=inspect_target(pid);runtime='dotnet' in data['runtime_candidates'];tool=shutil.which('dotnet-trace')
 return {'source':'EVENTPIPE_DOTNET_TRACE','status':'TOOL_UNAVAILABLE' if not tool else
  'RUNTIME_CANDIDATE_REQUIRES_TOOL_HANDSHAKE' if runtime else 'RUNTIME_NOT_SUPPORTED' if data['detection_status']=='OBSERVED_MODULE_NAMES_NOT_PROOF_OF_PRIMARY_RUNTIME' else 'RUNTIME_UNCONFIRMED',
  'target_pid':pid,'created':data['created'],'runtime_candidate':runtime,'runtime_detection':data['detection_status'],
  'tool_available':bool(tool),'requires_optin':True,'permissions':'TARGET_DIAGNOSTIC_PORT_ACCESS',
  'supported_os':['Windows','Linux','Darwin'],'profiles':list(PROFILES),'decoded':False,'lost_events':None}
def same_target(data):
 import psutil
 try:return abs(psutil.Process(data['target']['pid']).create_time()-data['target']['created'])<.000001
 except psutil.Error:return False
def run(journal):
 import psutil
 from .research_worker import _streams
 from .optional_jobs import OwnedProcess
 path=safe_path(journal);data=_read(path);uid=data['uid'];policy=data['policy']
 if (not isinstance(uid,str) or len(uid)!=32 or any(c not in '0123456789abcdef' for c in uid) or path.name!='EVENTPIPE_'+uid+'.trace.json'
  or type(policy['seconds']) is not int or not 1<=policy['seconds']<=60 or policy['profile'] not in PROFILES
  or type(policy['max_bytes']) is not int or not 1024**2<=policy['max_bytes']<=1024**3):raise ValueError('INVALID_EVENTPIPE_POLICY')
 inp,_=_streams();lease=Event()
 def read_lease():inp.readline(64);lease.set()
 Thread(target=read_lease,name='blackbox-eventpipe-lease',daemon=True).start()
 capture=path.parent/('eventpipe-'+uid+'.nettrace');log=path.parent/('eventpipe-'+uid+'.log');owner=None
 data.update(state='STARTING',guardian_pid=os.getpid(),guardian_created=psutil.Process().create_time(),source='EVENTPIPE_DOTNET_TRACE',decoded=False,lost_events=None)
 _write(path,data)
 try:
  tool=shutil.which('dotnet-trace')
  if not tool:raise OSError('DOTNET_TRACE_TOOL_UNAVAILABLE')
  if not same_target(data):raise ValueError('TARGET_INSTANCE_CHANGED')
  data['capability']=runtime_capability(data['target']['pid'])
  if data['capability']['status']=='RUNTIME_NOT_SUPPORTED':raise ValueError('RUNTIME_NOT_SUPPORTED')
  h=hashlib.sha256()
  with Path(tool).open('rb') as f:
   for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
  data['tool']={'name':Path(tool).name,'sha256':h.hexdigest(),'bundled':False,'authenticity':'LOCAL_TOOL_NOT_INDEPENDENTLY_ATTESTED'}
  _write(path,data)
  with log.open('xb') as stream:
   minutes,seconds=divmod(policy['seconds'],60)
   args=[tool,'collect','--process-id',str(data['target']['pid']),'--duration',f'00:00:{minutes:02}:{seconds:02}',
    '--profile',policy['profile'],'--buffersize','16','--format','NetTrace','--output',str(capture)]
   # Record brackets around launcher activity; they do NOT mark the exact
   # first/last EventPipe event nor authenticate session-v2 clock alignment.
   data['clock_anchors']={'before_tool_spawn':capture_trace_clock_bracket()}
   owner=OwnedProcess(args,stdin=subprocess.PIPE,stdout=stream,stderr=stream,env={**os.environ,'DOTNET_CLI_TELEMETRY_OPTOUT':'1'})
   data['clock_anchors']['after_tool_spawn']=capture_trace_clock_bracket()
   data.update(state='RECORDING',collector_pid=owner.process.pid,collector_created=psutil.Process(owner.process.pid).create_time());_write(path,data)
   deadline=time.monotonic()+eventpipe_collection_deadline_seconds(policy['seconds']);reason=None;forced_termination=False
   while owner.process.poll() is None:
    if lease.wait(.1):reason='LEASE_EOF_OR_EXPLICIT_STOP';break
    if time.monotonic()>=deadline:reason='TTL_EXPIRED';break
    if not same_target(data):reason='TARGET_INSTANCE_ENDED';break
    if (capture.exists() and capture.stat().st_size>=policy['max_bytes']) or log.stat().st_size>=1024**2:reason='OUTPUT_BUDGET';break
   if reason and owner.process.poll() is None:
    try:owner.process.stdin.write(b'\n');owner.process.stdin.flush()
    except (OSError,ValueError):pass
    try:owner.process.wait(timeout=EVENTPIPE_FINALIZE_GRACE_S)
    except subprocess.TimeoutExpired:
     forced_termination=True
     owner.close(kill=True)
   rc=owner.process.poll();size=capture.stat().st_size if capture.is_file() else 0
   data['clock_anchors']['after_tool_exit']=capture_trace_clock_bracket()
   if owner.process.stdin:owner.process.stdin.close()
  success=eventpipe_capture_confirmed(rc,size,forced_termination)
  # An independently computed local trace digest can later be compared to
  # decoder-index.input_sha256. The journal itself is NOT authenticated.
  captured_sha256=None
  if success:
   digest=hashlib.sha256()
   with capture.open('rb') as recorded:
    for block in iter(lambda:recorded.read(1024*1024),b''):digest.update(block)
   captured_sha256=digest.hexdigest()
  data.update(state='COMPLETED' if success else 'FAILED',stop_reason=reason or 'TOOL_COMPLETED',
   result={'source':'EVENTPIPE_DOTNET_TRACE','status':'TOOL_CAPTURED_UNDECODED' if success else 'INCOMPLETE_OR_UNSUPPORTED',
    'exit_code':rc,'bytes':size,'path':capture.name,'sha256':captured_sha256,
    'profile':policy['profile'],'decoded':False,'lost_events':None,
    'stop_completion_status':'FORCED_TERMINATION_AFTER_BOUNDED_GRACE' if forced_termination else 'TOOL_EXIT_OBSERVED',
    'handshake_status':'TOOL_SUCCESS_NONEMPTY_OUTPUT_NOT_INDEPENDENTLY_ATTESTED' if success else 'NOT_CONFIRMED',
    'size_policy':'POLLED_SOFT_LIMIT_NOT_FILESYSTEM_QUOTA'})
 except BaseException as exc:data.update(state='FAILED',error=(type(exc).__name__+': '+str(exc))[:512])
 finally:
  if owner:owner.close(kill=True)
  data['ended_ns']=time.monotonic_ns()
  if isinstance(data.get('clock_anchors'),dict):
   data['clock_anchors']['guardian_finally']=capture_trace_clock_bracket()
  _write(path,data)
 return 0 if data['state']=='COMPLETED' else 1
class DotnetTrace:
 def __init__(self,folder,pid,seconds=10,*,tool=None,profile='gc-collect',max_bytes=256*1024**2,session_path=None):
  import psutil
  if tool is not None:raise ValueError('CUSTOM_EVENTPIPE_EXECUTABLE_NOT_ALLOWED')
  if type(seconds) is not int or not 1<=seconds<=60 or profile not in PROFILES or type(max_bytes) is not int or not 1024**2<=max_bytes<=1024**3:raise ValueError('INVALID_EVENTPIPE_POLICY')
  if not shutil.which('dotnet-trace'):raise OSError('DOTNET_TRACE_TOOL_UNAVAILABLE')
  self.folder=safe_path(folder);self.uid=uuid4().hex;self.path=self.folder/('EVENTPIPE_'+self.uid+'.trace.json');self.process=None;self.reported=False
  self.data={'schema_version':1,'uid':self.uid,'state':'RESERVED','consent':'EXPLICIT_USER_COMMAND',
   'owner_pid':os.getpid(),'owner_created':psutil.Process().create_time(),'target':{'pid':pid,'created':psutil.Process(pid).create_time()},
   'policy':{'seconds':seconds,'max_bytes':max_bytes,'profile':profile},'decoded':False,'lost_events':None}
  from .decoder_alignment import capture_session_binding
  self.data['session_clock_binding']=capture_session_binding(
   session_path if session_path is not None else self.folder.parent/'session-v2.sqlite3')
 def start(self):
  if self.process is not None:raise ValueError('TRACE_ALREADY_STARTED')
  if self.path.exists() or self.path.is_symlink():raise ValueError('TRACE_JOURNAL_EXISTS')
  with self.path.open('xb'):pass
  _write(self.path,self.data)
  args=[sys.executable,'--runtime-owner',str(self.path)] if getattr(sys,'frozen',False) else [sys.executable,'-m','blackbox_core.runtime_trace',str(self.path)]
  try:self.process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
  except BaseException as exc:
   self.data.update(state='FAILED',error=type(exc).__name__);_write(self.path,self.data);raise
  return {'source':'EVENTPIPE_DOTNET_TRACE','status':'START_REQUESTED','journal':self.path.name,
   'target_pid':self.data['target']['pid'],'duration_seconds':self.data['policy']['seconds'],'profile':self.data['policy']['profile'],'decoded':False,'lost_events':None}
 def poll(self):
  if self.process is None or self.process.poll() is None or self.reported:return None
  self.reported=True;process=self.process;rc=process.returncode
  if process.stdin is not None:process.stdin.close()
  self.process=None
  try:self.data=_read(self.path)
  except (OSError,ValueError):return {'source':'EVENTPIPE_DOTNET_TRACE','status':'JOURNAL_UNAVAILABLE','decoded':False,'lost_events':None}
  state=self.data.get('state','UNKNOWN')
  if state not in ('COMPLETED','FAILED'):state='GUARDIAN_EXITED_UNCONFIRMED'
  return {'source':'EVENTPIPE_DOTNET_TRACE','status':state,'journal':self.path.name,'exit_code':rc,'details':self.data,'decoded':False,'lost_events':None}
 def stop(self):
  if self.process is None:return None
  if self.process.stdin is not None:self.process.stdin.close();self.process.stdin=None
  try:self.process.wait(timeout=8)
  except subprocess.TimeoutExpired:return {'source':'EVENTPIPE_DOTNET_TRACE','status':'GUARDIAN_CLEANUP_PENDING','journal':self.path.name,'decoded':False,'lost_events':None}
  return self.poll()
if __name__=='__main__':raise SystemExit(run(sys.argv[1]))

