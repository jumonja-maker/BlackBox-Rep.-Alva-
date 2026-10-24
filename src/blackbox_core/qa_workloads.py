"""Explicit, local QA stands with real OS resources; never production telemetry.

The supplied directory is a disposable fixture directory. Only fixture-owned
threads, handles, child processes and files are changed. No network or injector.
"""
from __future__ import annotations
import argparse,hashlib,json,os,subprocess,sys,threading,time
from pathlib import Path
from .library_files import atomic_json

MODES=('cpu','threads','children','memory','handles','io','longrun')

def write(path,data):
 # Heartbeat/control status is atomic but is not a disk-durability benchmark.
 atomic_json(path,data,durable=False)

def run(mode,directory,*,count=2,seconds=60):
 if mode not in MODES or type(count) is not int or not 1<=count<=1024 or not 0<seconds<=86400:raise ValueError('INVALID_QA_WORKLOAD')
 if mode=='children' and count>100:raise ValueError('QA_CHILD_LIMIT_100')
 if mode=='threads' and count>512:raise ValueError('QA_THREAD_LIMIT_512')
 if mode=='cpu' and count>min(64,max(2,os.cpu_count() or 1)):raise ValueError('QA_CPU_THREAD_LIMIT')
 root=Path(directory);root.mkdir(parents=True,exist_ok=True)
 if any(root.iterdir()):raise ValueError('QA_WORKLOAD_DIRECTORY_MUST_BE_EMPTY')
 import psutil
 process=psutil.Process();stop=threading.Event();threads=[];children=[];handles=[];held=[];enabled=[];tids=[]
 info={'schema_version':1,'fixture':'REAL_OS_QA_ONLY','mode':mode,'pid':process.pid,'created':process.create_time(),
  'requested_count':count,'thread_ids':tids,'ttl_seconds':seconds,'memory_step_bytes':32*1024**2,
  'resource_semantics':'REAL_TARGET_COUNTERS_NOT_SYNTHETIC_SAMPLES'}
 deadline=time.monotonic()+seconds;last_command=None;sequence=0;stream=None
 def worker(active):
  tids.append(threading.get_native_id())
  while not stop.is_set():
   if mode=='cpu' and active.is_set():hashlib.pbkdf2_hmac('sha256',b'BLACKBOX-FIX-01',b'public-fixture-salt',10000)
   else:stop.wait(.02)
 def allocate():
  block=bytearray(32*1024**2)
  for offset in range(0,len(block),4096):block[offset]=1
  held.append(block)
 def new_handle():
  if os.name=='nt':
   import ctypes as C
   k=C.WinDLL('kernel32',use_last_error=True);k.CreateEventW.argtypes=[C.c_void_p,C.c_int,C.c_int,C.c_wchar_p];k.CreateEventW.restype=C.c_void_p
   h=k.CreateEventW(None,False,False,None)
   if not h:raise C.WinError(C.get_last_error())
   return h
  return os.open(os.devnull,os.O_RDONLY)
 def close_handle(h):
  if os.name=='nt':
   import ctypes as C
   k=C.WinDLL('kernel32',use_last_error=True);k.CloseHandle.argtypes=[C.c_void_p];k.CloseHandle.restype=C.c_int
   if not k.CloseHandle(h):raise C.WinError(C.get_last_error())
  else:os.close(h)
 def state(ack=None,error=None):
  write(root/'state.json',{'seq':sequence,'ack':ack,'error':error,'monotonic_ns':time.monotonic_ns(),
   'threads_started':len(tids),'cpu_enabled':sum(e.is_set() for e in enabled),
   'children_alive':sum(p.poll() is None for p in children),'held_memory_bytes':len(held)*32*1024**2,
   'owned_handles':len(handles),'handle_semantics':'WIN32_HANDLES' if os.name=='nt' else 'POSIX_FILE_DESCRIPTORS'})
 try:
  if mode in ('cpu','threads'):
   for _ in range(count):
    active=threading.Event();active.set();enabled.append(active)
    t=threading.Thread(target=worker,args=(active,));t.start();threads.append(t)
   until=time.monotonic()+10
   while len(tids)<count and time.monotonic()<until:time.sleep(.01)
   if len(tids)!=count:raise RuntimeError('QA_THREADS_NOT_READY')
  elif mode=='children':
   for _ in range(count):children.append(subprocess.Popen([sys.executable,'-S','-c',f'import time;time.sleep({seconds+20!r})'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
   until=time.monotonic()+10
   while len(process.children())<count and time.monotonic()<until:time.sleep(.01)
   if len(process.children())<count:raise RuntimeError('QA_CHILDREN_NOT_READY')
  elif mode=='memory':allocate()
  elif mode=='handles':
   for _ in range(count):handles.append(new_handle())
  elif mode=='io':stream=(root/'io.bin').open('x+b')
  state();write(root/'ready.json',info)
  last_state=time.monotonic()
  while time.monotonic()<deadline and not (root/'stop.request').exists():
   command=root/'command.json'
   if command.is_file():
    try:
     data=json.loads(command.read_text());cid=data['id']
     if cid!=last_command:
      last_command=cid;sequence+=1;op=data['op']
      if mode=='cpu' and op=='SET_CPU_COUNT':
       n=data['count']
       if type(n) is not int or not 0<=n<=count:raise ValueError('INVALID_CPU_COUNT')
       for i,e in enumerate(enabled):e.set() if i<n else e.clear()
      elif mode=='memory' and op=='ALLOCATE_32_MIB':
       if len(held)>=8:raise ValueError('QA_MEMORY_LIMIT_256_MIB')
       allocate()
      elif mode=='memory' and op=='RELEASE_HALF':del held[:(len(held)+1)//2]
      elif mode=='memory' and op=='RELEASE_ALL':held.clear()
      elif mode=='handles' and op=='CLOSE_HALF':
       for _ in range((len(handles)+1)//2):close_handle(handles.pop())
      else:raise ValueError('UNSUPPORTED_QA_COMMAND')
      state(cid)
    except (OSError,ValueError,KeyError,TypeError) as exc:state(last_command,type(exc).__name__+': '+str(exc)[:160])
   if stream:
    stream.seek(0);stream.write(b'x'*(1024**2));stream.flush();stream.seek(0);stream.read(1024**2)
   if time.monotonic()-last_state>=1:state(last_command);last_state=time.monotonic()
   stop.wait(.05)
 finally:
  stop.set()
  for t in threads:t.join(timeout=2)
  for p in children:
   if p.poll() is None:p.terminate()
  for p in children:
   try:p.wait(timeout=5)
   except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
  for h in handles:close_handle(h)
  if stream:stream.close();(root/'io.bin').unlink()
  held.clear()
 return 0

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=MODES);p.add_argument('directory',type=Path)
 p.add_argument('--count',type=int,default=2);p.add_argument('--seconds',type=float,default=60)
 a=p.parse_args(argv);return run(a.mode,a.directory,count=a.count,seconds=a.seconds)
if __name__=='__main__':raise SystemExit(main())
