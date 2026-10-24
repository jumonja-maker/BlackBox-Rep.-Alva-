"""Integrated read-only reports and recording ownership, not endurance proof."""
from contextlib import closing
import csv,json,os,sqlite3,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from blackbox_core.research_worker import ResearchSession
from blackbox_core.session_v2 import SessionV2Writer
from blackbox_core.session_view import SessionView
from blackbox_core.process_tree import resource_tree_page,tree_totals
from blackbox_core.interval_report import export_interval
from blackbox_core.findings_export import csv_safe
from test_investigation_v2 import observation,ORIGIN
class CompletedWorkflowTests(unittest.TestCase):
 def test_resource_tree_uses_actual_linked_cohorts_not_sum_of_peaks(self):
  with tempfile.TemporaryDirectory() as temp:
   folder=Path(temp);w=SessionV2Writer(folder,pid=123,created=1.,name='TEST_ONLY',origin_ns=ORIGIN)
   for n,memory in enumerate(((20,30),(40,10)),1):
    row=observation(n);row['children_total']=2
    row['children']=[{'pid':200+i,'created':2.+i,'parent_pid':123,'name':'TEST_ONLY_CHILD','cpu_user_s':float(n),'cpu_system_s':0.,'rss_bytes':value,'thread_count':1} for i,value in enumerate(memory)]
    w.submit('detail',row)
   w.finish('COMPLETED')
   with SessionView.open(folder) as view:
    page=resource_tree_page(view,ORIGIN,ORIGIN+4*10**9);total=tree_totals(view,ORIGIN,ORIGIN+4*10**9)
    self.assertEqual(page['total_instances'],3);self.assertEqual(total['observed_tree_rss_peak_bytes'],150)
    self.assertEqual(page['rows'][1]['resources']['cpu_seconds'],1.)
    self.assertEqual(page['rows'][1]['parent_instance_candidate'],1);self.assertFalse(total['sums_individual_peaks'])
 def test_all_513_findings_are_exported_and_no_sort_database_is_published(self):
  from test_investigation_v2 import Investigation2Tests
  fixture=Investigation2Tests();fixture.setUp()
  try:
   fixture.incidents(513)
   with tempfile.TemporaryDirectory() as temp:
    out=Path(temp);r=export_interval(fixture.folder,out,prefix='all',bundle=True)
    data=json.loads((out/'all.findings.json').read_text());self.assertEqual(len(data['findings']),513)
    self.assertEqual(data['findings_total'],513)
    with (out/'all.findings.csv').open(encoding='utf-8-sig') as f:self.assertEqual(len(list(csv.reader(f)))-1,513)
    self.assertFalse(any(p.suffix=='.sqlite3' or p.name.startswith('.bb-export-') for p in out.iterdir()))
    self.assertFalse(r['report']['findings_export']['pagination_truncation'])
  finally:fixture.tearDown()
 def test_csv_formula_prefixes_and_whitespace_are_data(self):
  for value in ('=cmd',' +SUM(1)','\t=1','\r-1','@value'):self.assertTrue(csv_safe(value).startswith("'"))
 def test_primary_stop_can_finalize_open_user_stage_without_closed_store_write(self):
  with tempfile.TemporaryDirectory() as temp:
   s=ResearchSession(temp);s.command({'op':'attach','args':{'pid':os.getpid()}});s.command({'op':'start'});s.tick()
   s.command({'op':'user_marker','args':{'kind':'STAGE_BEGIN','name':'TEST_ONLY_EXIT_BOUNDARY'}})
   s.probe.stop('PROCESS_EXITED');s.stop('PROCESS_EXITED')
   self.assertEqual(s.research_state,'PROCESS_EXITED')
   with closing(sqlite3.connect(s.probe.session_folder/'research.sqlite3')) as db:self.assertEqual(db.execute("SELECT count(*) FROM evidence WHERE kind='user.stage_aborted'").fetchone()[0],1)
 def test_setup_failure_releases_book_and_allows_clean_retry(self):
  with tempfile.TemporaryDirectory() as temp:
   s=ResearchSession(temp);s.command({'op':'attach','args':{'pid':os.getpid()}})
   with patch.object(s,'_start_registry',side_effect=OSError('TEST_ONLY_SETUP_ERROR')):
    with self.assertRaises(OSError):s.command({'op':'start'})
   first=s.probe.session_folder;self.assertIsNone(s.book);self.assertFalse(s.probe.active)
   s.command({'op':'start'});s.tick();self.assertNotEqual(first,s.probe.session_folder);s.stop()
 def test_every_sensor_exposes_full_capability_and_bounded_health(self):
  with tempfile.TemporaryDirectory() as temp:
   s=ResearchSession(temp);s.command({'op':'attach','args':{'pid':os.getpid()}});s.command({'op':'start'});s.tick()
   try:
    for row in s.sensors.health().values():
     self.assertTrue({'permissions','requires_optin','supported_os','accuracy','limitations','unavailable_reason','latency_p95_ms'}<=set(row))
     self.assertLessEqual(row['latency_window_count'],128)
   finally:s.stop()
if __name__=='__main__':unittest.main()

