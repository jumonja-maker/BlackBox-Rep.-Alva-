"""Real short GUI harness; explicitly no endurance/performance acceptance."""
import json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from blackbox_universal.production_qa import pair,quantiles
class ProductionQaTests(unittest.TestCase):
 def test_process_cohort_uses_only_same_instances_and_machine_cpu_scale(self):
  a={'at_ns':10**9,'observer':{(1,1):{'cpu':1},(2,1):{'cpu':9}},'target':{'identity':(3,1),'cpu':1}}
  b={'at_ns':2*10**9,'observer':{(1,1):{'cpu':1.2,'rss':100},(2,2):{'cpu':10,'rss':200}},'target':{'identity':(3,1),'cpu':2,'rss':100}}
  r=pair(a,b,2);self.assertAlmostEqual(r['observer_cpu_machine_pp'],10)
  self.assertEqual(r['target_cpu_machine_pp'],50);self.assertEqual(r['observer_missing_or_new_instances'],2)
  self.assertEqual(quantiles([])['median'],None);self.assertEqual(quantiles([1,2,3])['median'],2)
 def invoke(self,mode,temp):
  output=Path(temp)/mode
  pidfile=Path(temp)/'target.json'
  target=subprocess.Popen([sys.executable,'-c','import psutil,time,sys;from pathlib import Path;Path(sys.argv[1]).write_text(str(psutil.Process().pid));time.sleep(55)',str(pidfile)])
  import time
  deadline=time.monotonic()+5
  while not pidfile.exists() and time.monotonic()<deadline:time.sleep(.01)
  self.assertTrue(pidfile.is_file());pid=pidfile.read_text()
  args=[sys.executable,'-m','blackbox_universal.production_qa',mode,'--pid',pid,'--output',str(output),
   '--phase-seconds','.4','--warmup-seconds','0','--sample-seconds','.1','--duration-seconds','.4']
  env={**os.environ,'QT_QPA_PLATFORM':'offscreen','XDG_CONFIG_HOME':str(Path(temp)/'config')}
  try:done=subprocess.run(args,env=env,capture_output=True,text=True,timeout=50)
  finally:
   target.terminate();target.wait(timeout=5)
  self.assertEqual(done.returncode,0,done.stderr[-4000:]);return output,json.loads((output/'result.json').read_text())
 def test_real_off_on_gui_benchmark_retains_both_target_and_observer_measurements(self):
  with tempfile.TemporaryDirectory() as temp:
   output,r=self.invoke('benchmark',temp);self.assertEqual(r['state'],'COMPLETED')
   self.assertEqual([p['phase'] for p in r['phases']],['OFF_1','STANDARD','OFF_2','DETAILED','OFF_3'])
   self.assertEqual(r['budget_comparison']['STANDARD']['interpretation'],'SHORT_FUNCTIONAL_ONLY')
   self.assertEqual(r['acceptance'],'NOT_ACCEPTED');self.assertGreater((output/'samples.csv').stat().st_size,100)
   self.assertGreater(r['phases'][1]['recorded_samples'],0)
   self.assertGreater(r['phases'][0]['metrics']['observer_cpu_machine_pp']['n'],0)
 def test_short_real_recording_is_never_certified_as_eight_hours(self):
  with tempfile.TemporaryDirectory() as temp:
   _,r=self.invoke('endurance',temp);self.assertEqual(r['state'],'COMPLETED')
   self.assertTrue(r['short_run']);self.assertFalse(r['endurance_duration_met'])
   self.assertEqual(r['required_seconds'],28800);self.assertGreaterEqual(r['phases'][0]['actual_seconds'],.4)
if __name__=='__main__':unittest.main()
