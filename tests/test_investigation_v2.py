"""Synthetic 513-incident contract and actual read-only source queries."""
from contextlib import closing
import hashlib,json,sqlite3,tempfile,unittest
from pathlib import Path
from blackbox_core.session_v2 import SessionV2Writer,FILENAME
from blackbox_core.session_view import SessionView
from blackbox_core.investigation_v2 import investigate,incident_card
from blackbox_core.event_stream import event_page,event_tracks
ORIGIN=10**9
def observation(n):
 return {'time_ns':ORIGIN+n*10**9,'pid':123,'created':1.,'cpu_user_s':n*.1,'cpu_system_s':0.,
 'rss_bytes':100,'private_bytes':200,'uss_bytes':50,'handle_count':10,'thread_count':1,'read_bytes':n*100,
 'write_bytes':0,'read_ops':n,'write_ops':0,'children_total':0,'children_omitted':0,'threads_omitted':0,
 'thread_capture_status':'OK','child_capture_status':'OK','sensor_status':{'children':'OK'},
 'threads':[{'tid':1,'cpu_user_s':n*.1,'cpu_system_s':0.}],'children':[],'requested_interval_ns':10**9}
class Investigation2Tests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.folder=Path(self.temp.name);w=SessionV2Writer(self.folder,pid=123,created=1.,name='TEST_ONLY',origin_ns=ORIGIN)
  for n in range(1,9):w.submit('detail',observation(n))
  w.finish('COMPLETED')
 def tearDown(self):self.temp.cleanup()
 def incidents(self,count):
  with closing(sqlite3.connect(self.folder/FILENAME)) as db:
   for n in range(count):
    stamp=ORIGIN+(n%7+1)*10**9
    eid=db.execute("INSERT INTO events(recorded_ns,observed_ns,instance_id,event_type,source_kind,verification_class,timestamp_precision,correlation_key,measurement_status,detail_json) VALUES(?,?,1,'UI_UNRESPONSIVE_OBSERVED','WIN32','OS_OBSERVED','TEST_ONLY','TEST_ONLY','SENSOR_TIMEOUT','{}')",(stamp,stamp)).lastrowid
    db.execute("INSERT INTO incidents(trigger_code,start_ns,end_ns,status,primary_event_id,context_json) VALUES('UI_TIMEOUT',?,?,'TEST_ONLY',?,'{}')",(stamp,stamp+10**9,eid))
   db.commit()
 def test_every_513_incident_is_accessible_and_original_hash_unchanged(self):
  self.incidents(513);path=self.folder/FILENAME;before=hashlib.sha256(path.read_bytes()).hexdigest();seen=set();cursor=None
  while True:
   page=investigate(self.folder,after=cursor,limit=50);self.assertEqual(page['findings_total'],513)
   for row in page['findings']:self.assertNotIn(row['finding_id'],seen);seen.add(row['finding_id'])
   if not page['has_more']:break
   cursor=page['next_cursor']
  self.assertEqual(len(seen),513);self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),before)
 def test_card_has_distinct_memory_and_actual_partial_post(self):
  self.incidents(1);card=incident_card(self.folder,1)
  self.assertFalse(card['post_context_complete']);self.assertEqual(card['root_cause'],'UNKNOWN')
  self.assertEqual(card['snapshots']['before']['values']['private_bytes'],200)
  self.assertEqual(card['snapshots']['before']['values']['uss_bytes'],50)
 def test_event_filters_cursor_and_whole_interval_tracks(self):
  self.incidents(207);a=event_page(self.folder,source='WIN32',severity='WARNING',limit=100)
  b=event_page(self.folder,source='WIN32',severity='WARNING',after=a['next_cursor'],limit=100)
  self.assertEqual(a['total_matching'],207);self.assertFalse(set(r['evidence_ref'] for r in a['rows']) & set(r['evidence_ref'] for r in b['rows']))
  self.assertTrue(all(r['verification_class']=='UNVERIFIED_IMPORT' for r in a['rows']))
  with SessionView.open(self.folder) as view:
   tracks=event_tracks(view,ORIGIN,ORIGIN+10*10**9,folder=self.folder)
   self.assertEqual(sum(r['count'] for r in tracks['tracks']['INCIDENTS']),207)
  self.assertEqual(event_page(self.folder,search='100%_literal')['total_matching'],0)
 def test_sorting_and_invalid_arguments(self):
  self.incidents(9);p=investigate(self.folder,sort_order='TIME_DESC')
  self.assertEqual([r['start_ns'] for r in p['findings']],sorted((r['start_ns'] for r in p['findings']),reverse=True))
  for kwargs in ({'source':'FAKE'},{'limit':201},{'after':[0,1]},{'start_ms':-1}):
   with self.assertRaises(ValueError):event_page(self.folder,**kwargs)
  with self.assertRaises(ValueError):incident_card(self.folder,999)
 def test_unknown_coverage_and_stable_memory_are_not_leak_proof(self):
  result=investigate(self.folder);self.assertIsNone(result['coverage']['exact_missed_samples'])
  self.assertFalse(result['root_cause_proven']);self.assertFalse(any('LEAK' in r['code'] for r in result['findings']))
 def test_action_resource_coincidence_is_not_causation_and_uses_recorded_top_n(self):
  from blackbox_core.casebook import CaseBook
  b=CaseBook(self.folder,123,1.,{'capture_policy':{'top_threads':1}});b.db.close()
  with closing(sqlite3.connect(self.folder/FILENAME)) as db:
   db.execute("INSERT INTO action_intervals VALUES('a','e','COMPLETED',?,?,?,?,'USER_DECLARED')",(ORIGIN,ORIGIN+10**9,ORIGIN+5*10**9,ORIGIN+6*10**9));db.commit()
  result=investigate(self.folder);row=next(r for r in result['findings'] if r['code']=='ACTION_RESOURCE_COINCIDENCE')
  self.assertFalse(row['detail']['causal_claim']);self.assertEqual(row['detail']['action_boundary_source'],'USER_DECLARED')
  self.assertIn('TEMPORAL_COINCIDENCE_NOT_CAUSATION',row['limitations'])
  self.assertEqual(result['thread_analysis']['top_n'],1)
if __name__=='__main__':unittest.main()

