"""Actual 300 OS threads/100 descendants, explicitly separate from DTO tests."""
import json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
import psutil
from blackbox_core.detailed_capture import sample_process

class RealScaleTests(unittest.TestCase):
 def launch(self,mode,count,root):
  child=subprocess.Popen([sys.executable,'-m','blackbox_core.qa_workloads',mode,str(root),'--count',str(count),'--seconds','40'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  self.addCleanup(lambda:self.finish(child,root))
  deadline=time.monotonic()+25
  while not (root/'ready.json').is_file() and child.poll() is None and time.monotonic()<deadline:time.sleep(.02)
  if not (root/'ready.json').is_file():
   child.terminate();_,err=child.communicate(timeout=5);self.fail('REAL_FIXTURE_START_FAILED: '+err.decode(errors='replace')[-2000:])
  info=json.loads((root/'ready.json').read_text());return child,info
 @staticmethod
 def finish(child,root):
  if child.poll() is None:
   if root.exists():(root/'stop.request').touch()
   try:child.wait(timeout=10)
   except subprocess.TimeoutExpired:child.terminate();child.wait(timeout=5)
  if child.stderr:child.stderr.close()
 def command(self,root,op,**extra):
  cid=str(time.monotonic_ns());p=root/'command.writing';p.write_text(json.dumps({'id':cid,'op':op,**extra}));os.replace(p,root/'command.json')
  deadline=time.monotonic()+5
  while time.monotonic()<deadline:
   state=json.loads((root/'state.json').read_text())
   if state.get('ack')==cid:
    self.assertIsNone(state['error']);return state
   time.sleep(.02)
  self.fail('REAL_FIXTURE_COMMAND_TIMEOUT')
 def test_300_real_threads_default_truncation_and_explicit_larger_capture(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp)/'threads';child,info=self.launch('threads',300,root)
   try:
    limited=sample_process(info['pid'],info['created']);full=sample_process(info['pid'],info['created'],thread_limit=512)
    self.assertGreaterEqual(limited['thread_count'],301);self.assertEqual(len(limited['threads']),256)
    self.assertGreaterEqual(limited['threads_omitted'],45);self.assertGreaterEqual(len(full['threads']),301)
    self.assertEqual(full['threads_omitted'],0)
   finally:self.finish(child,root)
 def test_100_real_children_are_distinct_instances_and_bounded(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp)/'children';child,info=self.launch('children',100,root)
   try:
    limited=sample_process(info['pid'],info['created'],child_limit=20);full=sample_process(info['pid'],info['created'],child_limit=100)
    self.assertEqual(limited['children_total'],100);self.assertEqual(limited['children_omitted'],80)
    self.assertEqual(len(full['children']),100);self.assertEqual(len({(c['pid'],c['created']) for c in full['children']}),100)
   finally:self.finish(child,root)
 def test_two_native_cpu_workers_and_switch_to_one_then_zero(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp)/'cpu';child,info=self.launch('cpu',2,root)
   try:
    before=sample_process(info['pid'],info['created']);time.sleep(.35);after=sample_process(info['pid'],info['created'])
    a={r['tid']:r['cpu_user_s']+r['cpu_system_s'] for r in before['threads']}
    deltas=[r['cpu_user_s']+r['cpu_system_s']-a[r['tid']] for r in after['threads'] if r['tid'] in a]
    self.assertGreaterEqual(sum(d>0 for d in deltas),2)
    self.assertEqual(self.command(root,'SET_CPU_COUNT',count=1)['cpu_enabled'],1)
    self.assertEqual(self.command(root,'SET_CPU_COUNT',count=0)['cpu_enabled'],0)
   finally:self.finish(child,root)
 def test_memory_steps_and_release_keep_real_counter_semantics(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp)/'memory';child,info=self.launch('memory',1,root)
   try:
    before=psutil.Process(info['pid']).memory_info().rss
    state=self.command(root,'ALLOCATE_32_MIB');after=psutil.Process(info['pid']).memory_info().rss
    self.assertEqual(state['held_memory_bytes'],64*1024**2);self.assertGreater(after-before,16*1024**2)
    self.assertEqual(self.command(root,'RELEASE_ALL')['held_memory_bytes'],0)
   finally:self.finish(child,root)

if __name__=='__main__':unittest.main()
