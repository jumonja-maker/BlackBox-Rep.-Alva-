"""Real SDK records and strict negative native-recovery boundaries.

Mocks below verify refusal/ownership contracts; they do not certify ETW/GC.
"""
from contextlib import closing
import json,os,sqlite3,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import psutil
from blackbox_core.instrumentation import EventWriter,EventTail
from blackbox_core.instrumentation_analysis import io_latency_statistics
from blackbox_core.casebook import CaseBook
from blackbox_core.runtime_trace import DotnetTrace,runtime_capability
from blackbox_core.trace_recovery import recover,scan

class SdkLatencyTests(unittest.TestCase):
 def test_real_nested_sdk_records_keep_links_latency_and_target_exception(self):
  with tempfile.TemporaryDirectory() as temp:
   p=Path(temp)/'events.jsonl';w=EventWriter(p,'a'*32)
   with w.stage('save') as stage:
    with w.io_operation('WRITE',byte_count=4096,parent_id=stage):time.sleep(.002)
    with self.assertRaisesRegex(RuntimeError,'target'):
     with w.io_operation('FLUSH',parent_id=stage):raise RuntimeError('target')
   rows=EventTail(p,'a'*32,os.getpid()).poll();ends=[r for r in rows if r['kind']=='io.operation.end']
   self.assertEqual([r['attributes']['status'] for r in ends],['COMPLETED','ERROR'])
   self.assertGreater(ends[0]['attributes']['latency_ns'],0)
   self.assertEqual(ends[0]['attributes']['latency_clock'],'PYTHON_PERF_COUNTER_NS')
   self.assertTrue(all(r['parent_id']==stage for r in ends))
   self.assertEqual(rows[-1]['kind'],'stage.end');self.assertEqual(rows[-1]['attributes']['status'],'COMPLETED')
 def test_quantiles_are_only_valid_app_reports_not_bytes_or_device_facts(self):
  with tempfile.TemporaryDirectory() as temp:
   folder=Path(temp);b=CaseBook(folder,os.getpid(),psutil.Process().create_time(),{})
   try:
    for n in range(1,101):
     b.put('io.operation.end',{'operation_id':str(n),'attributes':{'latency_ns':n,'io_kind':'READ','status':'COMPLETED'}},source='APPLICATION_EVENT')
    b.put('io.operation.end',{'operation_id':'error','attributes':{'latency_ns':99999,'io_kind':'READ','status':'ERROR'}},source='APPLICATION_EVENT')
    b.put('io.operation.end',{'operation_id':'bad','attributes':{'latency_ns':-1,'io_kind':'READ','status':'COMPLETED'}},source='APPLICATION_EVENT')
    b.put('io.operation.end',{'operation_id':'counter','attributes':{'read_bytes':100000}},source='APPLICATION_EVENT')
    r=io_latency_statistics(folder);g=r['groups'][0]
    self.assertEqual((g['completed_events'],g['error_events']),(100,1))
    self.assertEqual(g['median'],50.5);self.assertAlmostEqual(g['p95'],95.05)
    self.assertEqual(r['invalid_events'],2);self.assertIsNone(r['lost_events'])
    self.assertEqual(r['source'],'APPLICATION_EVENT_UNAUTHENTICATED')
    self.assertEqual(io_latency_statistics(folder,start_ns=time.monotonic_ns()+10**9)['status'],'NOT_OBSERVED')
   finally:b.db.close()
 def test_absent_source_does_not_invent_latency(self):
  with tempfile.TemporaryDirectory() as temp:self.assertEqual(io_latency_statistics(temp)['groups'],[])

class RuntimeBoundaryTests(unittest.TestCase):
 def test_missing_tool_is_explicit_and_never_downloads(self):
  with patch('blackbox_core.runtime_trace.shutil.which',return_value=None):
   self.assertEqual(runtime_capability(os.getpid())['status'],'TOOL_UNAVAILABLE')
   with tempfile.TemporaryDirectory() as temp:
    with self.assertRaisesRegex(OSError,'TOOL_UNAVAILABLE'):DotnetTrace(temp,os.getpid())
    self.assertEqual(list(Path(temp).iterdir()),[])
 def test_custom_executable_and_invalid_policy_refused(self):
  with tempfile.TemporaryDirectory() as temp:
   for kwargs in ({'tool':'anything'},{'seconds':0},{'seconds':61},{'seconds':True},{'profile':'cpu-sampling'},{'max_bytes':1}):
    with self.assertRaises(ValueError):DotnetTrace(temp,os.getpid(),**kwargs)
 def test_launch_failure_leaves_honest_failed_journal(self):
  with tempfile.TemporaryDirectory() as temp,patch('blackbox_core.runtime_trace.shutil.which',return_value='TEST_ONLY'):
   trace=DotnetTrace(temp,os.getpid(),seconds=60)
   with patch('blackbox_core.runtime_trace.subprocess.Popen',side_effect=OSError('TEST_ONLY_START_FAILURE')):
    with self.assertRaises(OSError):trace.start()
   data=json.loads(trace.path.read_text());self.assertEqual(data['state'],'FAILED')
   self.assertFalse(data['decoded']);self.assertIsNone(data['lost_events'])
 def test_guardian_journal_failure_releases_pipe_and_does_not_invent_success(self):
  with tempfile.TemporaryDirectory() as temp,patch('blackbox_core.runtime_trace.shutil.which',return_value='TEST_ONLY'):
   trace=DotnetTrace(temp,os.getpid())
   class Process:
    returncode=1
    def __init__(self):self.stdin=open(Path(temp)/'pipe','wb')
    def poll(self):return 1
   p=Process();trace.process=p
   self.assertEqual(trace.poll()['status'],'JOURNAL_UNAVAILABLE')
   self.assertTrue(p.stdin.closed);self.assertIsNone(trace.process)

class RecoveryBoundaries(unittest.TestCase):
 def fixture(self,root,data):
  folder=Path(root);a=folder/'artifacts';a.mkdir();name='BLACKBOX_'+'a'*32+'.trace.json'
  (a/name).write_text(json.dumps(data))
  class Catalog:
   def entry(self,e):return {'origin':'LOCAL_APP_MARKED','state':'ORPHANED'}
   def _folder(self,r):return folder
   def _marker(self,*a):pass
  return Catalog(),name
 def test_no_consent_or_live_owner_cannot_cancel_any_capture(self):
  with tempfile.TemporaryDirectory() as temp:
   data={'state':'RECORDING','instance':'BLACKBOX_'+'a'*32,'consent':'EXPLICIT_USER_COMMAND','owner_pid':os.getpid(),'owner_created':psutil.Process().create_time()}
   c,name=self.fixture(temp,data)
   self.assertFalse(scan(c,'test')['rows'][0]['eligible'])
   with self.assertRaisesRegex(ValueError,'CONFIRMATION'):recover(c,'test',name)
   with patch('blackbox_core.windows_research.WprCapture.cancel') as cancel:
    with self.assertRaisesRegex(ValueError,'OWNER_STILL_ACTIVE'):recover(c,'test',name,confirmed=True)
    cancel.assert_not_called()
 def test_recovery_uses_only_exact_named_instance_and_preserves_artifacts(self):
  with tempfile.TemporaryDirectory() as temp:
   data={'state':'RECORDING','instance':'BLACKBOX_'+'a'*32,'consent':'EXPLICIT_USER_COMMAND','owner_pid':0,'guardian_pid':0}
   c,name=self.fixture(temp,data);raw=Path(temp)/'artifacts'/'private.etl';raw.write_bytes(b'KEEP')
   names=[]
   with patch('blackbox_core.windows_research.WprCapture.cancel',lambda cap:names.append(cap.instance)):
    r=recover(c,'test',name,confirmed=True)
   self.assertEqual(names,[data['instance']]);self.assertFalse(r['capture_complete'])
   self.assertEqual(raw.read_bytes(),b'KEEP');self.assertIsNone(r['lost_events'])
   self.assertFalse(scan(c,'test')['rows'][0]['eligible'])
 def test_mismatched_journal_or_path_never_reaches_wpr(self):
  with tempfile.TemporaryDirectory() as temp:
   c,name=self.fixture(temp,{'state':'RECORDING','instance':'foreign','consent':'EXPLICIT_USER_COMMAND'})
   with patch('blackbox_core.windows_research.WprCapture.cancel') as cancel:
    for name in (name,'../else.trace.json','BLACKBOX_foreign.trace.json'):
     with self.assertRaises(ValueError):recover(c,'test',name,confirmed=True)
    cancel.assert_not_called()

if __name__=='__main__':unittest.main()
