"""Explicit real GUI OFF/ON benchmark and wall-clock endurance harness.

Short runs are functional checks, never substitutes for 8h/1h or physical QA.
No target mutation, automatic ETW/dump, downloads, or telemetry generation.
"""
from __future__ import annotations
import argparse,csv,json,os,platform,statistics,time
from pathlib import Path
import psutil

def quantiles(values):
 values=sorted(v for v in values if type(v) in (int,float));n=len(values)
 def q(p):
  if not n:return None
  at=(n-1)*p;lo=int(at);hi=min(lo+1,n-1);return values[lo]+(values[hi]-values[lo])*(at-lo)
 return {'n':n,'median':q(.5),'p95':q(.95),'minimum':q(0),'maximum':q(1),'small_sample':n<20}

def write(path,data):
 temp=path.with_suffix('.writing');temp.write_text(json.dumps(data,ensure_ascii=False,indent=2,allow_nan=False),encoding='utf-8');os.replace(temp,path)

def counters(process):
 try:
  with process.oneshot():
   cpu=process.cpu_times();return {'identity':(process.pid,process.create_time()),'cpu':cpu.user+cpu.system,'rss':process.memory_info().rss}
 except (psutil.Error,OSError):return None

def measurement(target):
 root=psutil.Process();excluded={target.pid}
 try:excluded.update(p.pid for p in target.children(recursive=True))
 except psutil.Error:pass
 processes=[root]
 try:processes+=root.children(recursive=True)
 except psutil.Error:pass
 observer={}
 for p in processes:
  if p.pid in excluded:continue
  row=counters(p)
  if row:observer[row['identity']]=row
 return {'at_ns':time.monotonic_ns(),'target':counters(target),'observer':observer}

def pair(a,b,cpus):
 dt=(b['at_ns']-a['at_ns'])/1e9
 if dt<=0:raise ValueError('QA_CLOCK_NOT_INCREASING')
 shared=a['observer'].keys()&b['observer'].keys();values=[b['observer'][i]['cpu']-a['observer'][i]['cpu'] for i in shared]
 valid=[v for v in values if v>=0];ta,tb=a['target'],b['target']
 target_cpu=(tb['cpu']-ta['cpu']) if ta and tb and ta['identity']==tb['identity'] and tb['cpu']>=ta['cpu'] else None
 return {'duration_s':dt,'observer_cpu_machine_pp':100*sum(valid)/dt/cpus if valid else None,
  'target_cpu_machine_pp':100*target_cpu/dt/cpus if target_cpu is not None else None,
  'observer_rss_bytes':sum(r['rss'] for r in b['observer'].values()) if b['observer'] else None,
  'target_rss_bytes':tb['rss'] if tb else None,'observer_instances':len(b['observer']),
  'observer_missing_or_new_instances':len(a['observer'].keys()^b['observer'].keys())}

def run(mode,pid,output,*,phase_seconds=60,warmup_seconds=10,sample_seconds=.5,profile='STANDARD',duration_seconds=None,expected_sha=None):
 if mode not in ('benchmark','endurance') or type(pid) is not int or pid<=0:raise ValueError('INVALID_PRODUCTION_QA')
 if not .25<=phase_seconds<=3600 or not 0<=warmup_seconds<=300 or not .1<=sample_seconds<=10:raise ValueError('INVALID_QA_TIMING')
 if profile not in ('STANDARD','DETAILED'):raise ValueError('INVALID_ENDURANCE_PROFILE')
 duration=duration_seconds if duration_seconds is not None else (28800 if profile=='STANDARD' else 3600)
 if mode=='endurance' and not .25<=duration<=86400:raise ValueError('INVALID_ENDURANCE_DURATION')
 from blackbox_core.session_v2 import safe_path
 output=safe_path(output)
 output.mkdir(parents=True,exist_ok=True)
 if any(output.iterdir()):raise ValueError('QA_OUTPUT_MUST_BE_EMPTY')
 target=psutil.Process(pid);created=target.create_time();cpus=psutil.cpu_count() or 1
 if pid==psutil.Process().pid or pid in {p.pid for p in psutil.Process().parents()}:raise ValueError('QA_TARGET_CONTAINS_OBSERVER_USE_INDEPENDENT_TARGET')
 from PySide6.QtWidgets import QApplication
 from .window import UniversalWindow
 from .provenance import source_identity
 app=QApplication.instance() or QApplication([]);app.setQuitOnLastWindowClosed(False)
 window=UniversalWindow(isolated=True,output_root=output/'sessions',allow_update_check=False);window.show();bridge=window.probe
 started=time.monotonic_ns();rows=[];phases=[]
 result={'schema_version':1,'mode':mode,'state':'RUNNING','source':source_identity(expected_sha),
  'machine':{'os':platform.platform(),'machine':platform.machine(),'processor':platform.processor(),
   'logical_cpus':cpus,'physical_cpus':psutil.cpu_count(logical=False),'ram_bytes':psutil.virtual_memory().total,
   'python':platform.python_version(),'psutil':psutil.__version__,'qt_platform':os.environ.get('QT_QPA_PLATFORM','desktop')},
  'target':{'pid':pid,'created':created},'phase_seconds':phase_seconds,'warmup_seconds':warmup_seconds,'sample_seconds':sample_seconds,
  'limitations':['OBSERVER_INCLUDES_GUI_OWNED_HELPERS_AND_MEASUREMENT_LOOP','RSS_TREE_SUM_CAN_DOUBLE_COUNT_SHARED_PAGES',
   'EXITED_HELPER_CPU_BETWEEN_SAMPLES_UNKNOWN','OFF_INCLUDES_IDLE_GUI_AND_SESSION_HELPER','SHORT_RUN_IS_NOT_ENDURANCE_OR_PHYSICAL_WINDOWS_QA'],
  'phases':phases,'acceptance':'NOT_ACCEPTED'}
 def pump(seconds):
  until=time.monotonic()+seconds
  while time.monotonic()<until:app.processEvents();time.sleep(min(.01,max(0,until-time.monotonic())))
 def wait(predicate,seconds=20):
  until=time.monotonic()+seconds
  while not predicate() and time.monotonic()<until:pump(.01)
  if not predicate():raise TimeoutError('QA_REAL_GUI_COMMAND_TIMEOUT: '+str(bridge.last_error))
 try:
  bridge.attach(pid);wait(lambda:bridge.pid==pid and not bridge.pending)
  with (output/'samples.csv').open('x',newline='',encoding='utf-8') as stream:
   fields=['phase','at_ns','duration_s','observer_cpu_machine_pp','target_cpu_machine_pp','observer_rss_bytes','target_rss_bytes','observer_instances','observer_missing_or_new_instances']
   writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader()
   plan=[('OFF_1',phase_seconds),('STANDARD',phase_seconds),('OFF_2',phase_seconds),('DETAILED',phase_seconds),('OFF_3',phase_seconds)] if mode=='benchmark' else [(profile,duration)]
   for phase,seconds in plan:
    if phase in ('STANDARD','DETAILED'):
     bridge.send('capture_policy',policy={'profile':phase});wait(lambda:not bridge.pending)
     if bridge.last_error:raise RuntimeError(bridge.last_error)
     window._start();wait(lambda:bridge.active and not bridge.pending)
    pump(warmup_seconds);begin=time.monotonic_ns();deadline=time.monotonic()+seconds;previous=measurement(target);phase_rows=[];last_progress=0
    while time.monotonic()<deadline:
     pump(min(sample_seconds,max(.001,deadline-time.monotonic())))
     if abs(target.create_time()-created)>1e-6:raise RuntimeError('QA_TARGET_INSTANCE_CHANGED')
     if phase in ('STANDARD','DETAILED') and not bridge.active:raise RuntimeError('QA_RECORDING_STOPPED_EARLY: '+str(bridge.last_error))
     current=measurement(target);row={'phase':phase,'at_ns':current['at_ns'],**pair(previous,current,cpus)};writer.writerow(row);phase_rows.append(row);previous=current
     # Endurance retains samples in CSV, not an unbounded Python list.
     if len(phase_rows)>7200:phase_rows.pop(0)
     if time.monotonic()-last_progress>=5:
      stream.flush();write(output/'progress.json',{'state':'RUNNING','phase':phase,'actual_phase_seconds':(time.monotonic_ns()-begin)/1e9,'recorded_samples':bridge.total_samples,'session':str(bridge.session_folder or ''),'sensor_health':bridge.data.get('sensor_health',{})});last_progress=time.monotonic()
    elapsed=(time.monotonic_ns()-begin)/1e9
    item={'phase':phase,'actual_seconds':elapsed,'requested_seconds':seconds,'summary_window_limit':7200,
     'metrics':{key:quantiles([r[key] for r in phase_rows]) for key in ('observer_cpu_machine_pp','target_cpu_machine_pp','observer_rss_bytes','target_rss_bytes')},
     'session':str(bridge.session_folder) if phase in ('STANDARD','DETAILED') else None}
    if phase in ('STANDARD','DETAILED'):
     window._stop();wait(lambda:not bridge.active and not bridge.pending,90)
     item['recorded_samples']=bridge.total_samples;item['recording_state']=bridge.session_state
    phases.append(item);write(output/'result.json',result)
   if mode=='benchmark':
    off=[p['metrics']['observer_cpu_machine_pp']['median'] for p in phases if p['phase'].startswith('OFF')]
    observed_off=[v for v in off if v is not None]
    baseline=statistics.median(observed_off) if observed_off else None;result['budget_comparison']={}
    for p in phases:
     if p['phase'] not in ('STANDARD','DETAILED'):continue
     value=p['metrics']['observer_cpu_machine_pp']['median'];delta=value-baseline if value is not None and baseline is not None else None;budget=1 if p['phase']=='STANDARD' else 3
     result['budget_comparison'][p['phase']]={'observer_delta_machine_pp':delta,'target_budget_pp':budget,'over_budget':delta>budget if delta is not None else None,
      'interpretation':'SHORT_FUNCTIONAL_ONLY' if phase_seconds<60 else 'MEASURED_ON_RECORDED_MACHINE_NOT_UNIVERSAL_GUARANTEE'}
   else:
    required=28800 if profile=='STANDARD' else 3600
    result['endurance_duration_met']=phases[0]['actual_seconds']>=required
    result['required_seconds']=required;result['short_run']=duration<required
   result['state']='COMPLETED';return result
 except BaseException as exc:
  result.update(state='FAILED',error=type(exc).__name__+': '+str(exc)[:500]);raise
 finally:
  result['actual_total_seconds']=(time.monotonic_ns()-started)/1e9
  write(output/'result.json',result)
  window.close()
  until=time.monotonic()+95
  while bridge.alive and time.monotonic()<until:pump(.02)
  if bridge.alive:raise RuntimeError('QA_GUI_HELPER_NOT_CLOSED')
  window.deleteLater();app.processEvents()

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('benchmark','endurance'));p.add_argument('--pid',type=int,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--phase-seconds',type=float,default=60);p.add_argument('--warmup-seconds',type=float,default=10);p.add_argument('--sample-seconds',type=float,default=.5)
 p.add_argument('--profile',choices=('STANDARD','DETAILED'),default='STANDARD');p.add_argument('--duration-seconds',type=float);p.add_argument('--expected-sha')
 a=p.parse_args(argv);run(a.mode,a.pid,a.output,phase_seconds=a.phase_seconds,warmup_seconds=a.warmup_seconds,sample_seconds=a.sample_seconds,profile=a.profile,duration_seconds=a.duration_seconds,expected_sha=a.expected_sha);return 0
if __name__=='__main__':raise SystemExit(main())
