"""Actual recorder integration; injected TTL boundaries are TEST ONLY."""
from contextlib import closing
import json,os,sqlite3,tempfile,time,unittest
from types import SimpleNamespace
from unittest.mock import patch
from blackbox_core.research_worker import ResearchSession
from blackbox_core.capture_policy import validate_policy
class ProfileMarkerTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.s=ResearchSession(self.temp.name);self.s.command({'op':'attach','args':{'pid':os.getpid()}})
 def tearDown(self):self.s.stop();self.temp.cleanup()
 def wait(self,predicate):
  end=time.monotonic()+5
  while not predicate() and time.monotonic()<end:time.sleep(.01)
  self.assertTrue(predicate())
 def test_profiles_validate_and_standard_never_starts_traces(self):
  for value in ({'profile':'fake'},{'burst_seconds':61},{'windows_enabled':1},{'incident':{'enabled_triggers':['fake']}},{'thread_limit':0}):
   with self.assertRaises(ValueError):validate_policy(value)
  self.s.command({'op':'start'});self.s.tick();self.assertIsNone(self.s.probe.detailed_capture);self.assertIsNone(self.s.wpr);self.assertIsNone(self.s.runtime_trace)
 def test_detailed_reenable_keeps_existing_rows_and_sample_sequence(self):
  s=self.s;s.command({'op':'capture_policy','args':{'policy':{'profile':'DETAILED','detail_interval_ms':500}}});s.command({'op':'start'})
  self.wait(lambda:s.probe.detailed_capture.samples>=1);path=s.probe.detailed_capture.path
  s.command({'op':'detailed','args':{'enabled':False}})
  with closing(sqlite3.connect(path)) as db:rows=db.execute('SELECT * FROM process_samples ORDER BY seq').fetchall()
  s.command({'op':'detailed','args':{'enabled':True}});self.wait(lambda:s.probe.detailed_capture.samples>len(rows));s.stop()
  with closing(sqlite3.connect(path)) as db:after=db.execute('SELECT * FROM process_samples ORDER BY seq').fetchall()
  self.assertEqual(after[:len(rows)],rows);self.assertGreater(len(after),len(rows))
 def test_stage_commit_user_class_and_actual_issue_time(self):
  s=self.s;s.command({'op':'start'});s.tick();issued=time.monotonic_ns()
  begin=s.command({'op':'user_marker','issued_ns':issued,'args':{'kind':'STAGE_BEGIN','name':'test stage'}})
  end=s.command({'op':'user_marker','args':{'kind':'STAGE_END','stage_id':begin['stage_id']}})
  self.assertEqual(begin['timestamp_monotonic_ns'],issued);self.assertGreaterEqual(end['duration_ns'],0)
  with patch.object(s.book,'put',side_effect=OSError('TEST_ONLY_FULL_DISK')):
   with self.assertRaises(OSError):s.command({'op':'user_marker','args':{'kind':'STAGE_BEGIN','name':'failed'}})
  self.assertEqual(s.markers.snapshot(),[]);s.stop()
  with closing(sqlite3.connect(s.probe.session_folder/'session-v2.sqlite3')) as db:
   self.assertEqual(db.execute("SELECT source_kind,verification_class FROM events WHERE event_type='user.stage_begin'").fetchone(),('USER','USER_DECLARED'))
 def test_stop_with_trace_does_not_mirror_into_closed_primary_store(self):
  s=self.s;s.command({'op':'start'});s.tick();s.wpr=SimpleNamespace(active=False,stop=lambda:{'status':'COMPLETED'})
  s.stop();self.assertEqual(s.research_state,'COMPLETED')
 def test_burst_has_real_short_ttl_can_resume_and_never_starts_traces(self):
  s=self.s;s.command({'op':'capture_policy','args':{'policy':{'profile':'INCIDENT_BURST','burst_seconds':1}}});s.command({'op':'start'});s.tick()
  self.assertIsNone(s.probe.detailed_capture)
  for _ in range(2):
   # TEST ONLY injected trigger boundary; real elapsed TTL and recorder writes.
   s.probe.incident_events.append({'code':'AUTO_INCIDENT_STARTED','trigger_code':'TEST_ONLY_TRIGGER'})
   s._maybe_burst();self.wait(lambda:s.probe.detailed_capture.samples>0)
   time.sleep(1.02);s._policy_tick();self.assertIsNone(s.probe.detailed_capture)
  self.assertIsNone(s.wpr);self.assertIsNone(s.runtime_trace)
 def test_actual_logical_size_limit_stops_and_keeps_all_recorded_files(self):
  from pathlib import Path
  s=self.s;s.command({'op':'capture_policy','args':{'policy':{'max_session_mb':16}}});s.command({'op':'start'});s.tick()
  path=s.probe.session_folder/'TEST_ONLY_LOGICAL_BYTES.bin'
  with path.open('wb') as f:f.truncate(17*1024**2)
  s._health();self.assertFalse(s.probe.active);self.assertEqual(s.research_state,'STORAGE_LIMIT_REACHED')
  self.assertEqual(path.stat().st_size,17*1024**2);self.assertTrue((s.probe.session_folder/'session-v2.sqlite3').is_file())
 def test_real_time_limit_keeps_completed_observations(self):
  s=self.s;s.command({'op':'capture_policy','args':{'policy':{'session_seconds':1}}});s.command({'op':'start'});s.tick();time.sleep(1.02);s.tick()
  self.assertEqual(s.research_state,'TIME_LIMIT_REACHED');self.assertFalse(s.probe.active)
if __name__=='__main__':unittest.main()

