from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from types import SimpleNamespace
from blackbox_core.experiment_metrics import measure_interval,resource_statistics,compare_resources

class IntervalMetricTests(unittest.TestCase):
    def view(self,rows):
        db=sqlite3.connect(':memory:');self.addCleanup(db.close)
        db.execute('CREATE TABLE events(event_type TEXT,source_kind TEXT,measurement_status TEXT,observed_ns INTEGER,recorded_ns INTEGER)')
        return SimpleNamespace(db=db,reader=SimpleNamespace(iter_samples=lambda *a,**k:iter(rows)))
    def row(self,n,**kwargs):
        return {'series_seq':n+1,'time_ns':n*10**9,'requested_interval_ns':10**9,
            'cpu_user_s':n*.5,'cpu_system_s':n*.1,'rss_bytes':100+n*10,'private_bytes':None,
            'handle_count':None,'read_bytes':n*20,'write_bytes':n*10,**kwargs}
    def test_integrates_actual_dt_pairs_without_double_counting(self):
        view=self.view([self.row(n) for n in range(3)])
        r=measure_interval(view,0,2*10**9,series='STANDARD')
        self.assertAlmostEqual(r['metrics']['cpu_seconds'],1.2)
        self.assertEqual(r['metrics']['read_bytes'],40);self.assertEqual(r['covered_fraction']['cpu_seconds'],1)
        self.assertIsNone(r['metrics']['private_peak_bytes']);self.assertIsNone(r['metrics']['ui_timeouts'])
    def test_gap_and_counter_reset_are_not_integrated(self):
        view=self.view([self.row(0),self.row(1,read_bytes=0),self.row(5,read_bytes=9999)])
        r=measure_interval(view,0,5*10**9,series='STANDARD')
        self.assertEqual(r['gaps'],1);self.assertEqual(r['metrics']['read_bytes'],0)
        self.assertAlmostEqual(r['metrics']['cpu_seconds'],.6)
    def test_single_available_memory_value_does_not_create_zero_delta(self):
        r=measure_interval(self.view([self.row(0),self.row(1,rss_bytes=None)]),0,10**9,series='STANDARD')
        self.assertIsNone(r['metrics']['rss_delta_bytes']);self.assertEqual(r['metrics']['rss_peak_bytes'],100)
    def test_short_unobserved_action_is_not_zero_cpu(self):
        r=measure_interval(self.view([self.row(0)]),0,10**6,series='STANDARD')
        self.assertIsNone(r['metrics']['cpu_seconds']);self.assertEqual(r['pair_count']['cpu_seconds'],0)
    def test_zero_reference_has_no_invented_percent_gain(self):
        a={'metrics':{'read_bytes':{'median':0,'observed_repeats':2}}}
        b={'metrics':{'read_bytes':{'median':10,'observed_repeats':2}}}
        r=compare_resources(a,b)['read_bytes'];self.assertEqual(r['absolute_delta'],10);self.assertIsNone(r['percent_delta'])

class RealActionResourceTests(unittest.TestCase):
    def test_real_recorded_action_has_linked_resource_statistics(self):
        from blackbox_core.research_worker import ResearchSession
        with tempfile.TemporaryDirectory() as tmp:
            s=ResearchSession(tmp);s.command({'op':'attach','args':{'pid':os.getpid()}});s.command({'op':'start'})
            try:
                s.probe.actions.cool_down_ms=0
                s.command({'op':'prepare','args':{'baseline_ms':0}});s.command({'op':'begin'})
                for _ in range(3):
                    sum(i*i for i in range(10000));s.tick();time.sleep(.02)
                s.command({'op':'end'});s.tick();s.stop()
                r=resource_statistics(s.probe.session_folder)
                self.assertEqual(r['repeats'],1);self.assertEqual(r['metrics']['cpu_seconds']['observed_repeats'],1)
                self.assertGreaterEqual(r['metrics']['cpu_seconds']['median'],0)
                self.assertIsNone(r['metrics']['private_peak_bytes']['median'])
                self.assertFalse(r['runs_preview'][0]['boundary_extrapolation'])
                from blackbox_core.casebook import export_case
                import zipfile,json
                dest=Path(tmp)/'action.zip';export_case(s.probe.session_folder,dest)
                with zipfile.ZipFile(dest) as archive:
                    report=json.loads(archive.read('report.json'))
                    self.assertEqual(report['resource_statistics']['repeats'],1)
                    self.assertIn('Resources per action',archive.read('report.html').decode())
                self.assertEqual(resource_statistics(s.probe.session_folder,warmup_count=1)['repeats'],0)
            finally:s.stop()
