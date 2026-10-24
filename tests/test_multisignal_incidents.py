import unittest
from blackbox_core.incidents import IncidentCapture

class MultiSignalTests(unittest.TestCase):
    def detector(self,**kwargs):return IncidentCapture(min_duration_ms=999999,post_ms=0,cooldown_ms=0,growth_window_ms=2000,**kwargs)
    def test_rss_growth_has_actual_pair_and_unknown_cause(self):
        d=self.detector(memory_growth_bytes=100)
        self.assertEqual(d.observe(elapsed_ms=0,sample_seq=1,cpu_percent=None,rss_bytes=100),[])
        d.observe(elapsed_ms=1000,sample_seq=2,cpu_percent=None,rss_bytes=180)
        rows=d.observe(elapsed_ms=2200,sample_seq=3,cpu_percent=None,rss_bytes=230)
        self.assertEqual(rows[0]['trigger_code'],'RSS_GROWTH')
        self.assertEqual(rows[0]['trigger_detail']['delta'],130)
        self.assertEqual(rows[-1]['root_cause'],'UNKNOWN');self.assertIn('context_refs',rows[-1])
    def test_denied_private_or_handles_never_trigger_zero_growth(self):
        d=self.detector(memory_growth_bytes=1,handle_growth=1)
        for n in range(10):
            rows=d.observe(elapsed_ms=n*1000,sample_seq=n+1,cpu_percent=None,private_bytes=None,handle_count=None)
            self.assertEqual(rows,[])
    def test_counter_reset_and_gap_do_not_become_io_burst(self):
        d=self.detector(io_rate_bytes_s=100)
        d.observe(elapsed_ms=0,sample_seq=1,cpu_percent=None,read_bytes=10000,write_bytes=0)
        self.assertEqual(d.observe(elapsed_ms=1000,sample_seq=2,cpu_percent=None,read_bytes=1,write_bytes=0),[])
        rows=d.observe(elapsed_ms=10000,sample_seq=3,cpu_percent=None,read_bytes=99999,write_bytes=0)
        self.assertEqual([r['code'] for r in rows],['SAMPLING_GAP_OBSERVED'])
    def test_io_burst_is_throughput_not_latency(self):
        d=self.detector(io_rate_bytes_s=100)
        d.observe(elapsed_ms=0,sample_seq=1,cpu_percent=0,read_bytes=0,write_bytes=0)
        r=d.observe(elapsed_ms=2000,sample_seq=2,cpu_percent=0,read_bytes=200,write_bytes=200)[0]
        self.assertEqual(r['trigger_code'],'IO_BURST');self.assertEqual(r['trigger_detail']['observed_bytes_s'],200)
        self.assertEqual(r['trigger_detail']['interpretation'],'THROUGHPUT_NOT_IO_LATENCY')
    def test_exit_is_not_called_a_crash_and_post_is_not_fabricated(self):
        d=self.detector();r=d.process_exited(elapsed_ms=1234,sample_seq=2)
        self.assertEqual(r[-1]['status'],'NO_POST_TARGET_EXITED');self.assertIsNone(r[0]['trigger_detail']['exit_code'])
        self.assertFalse(r[-1]['proven_root_cause'])
    def test_nan_and_infinite_thresholds_refused(self):
        for value in (float('nan'),float('inf')):
            with self.assertRaises(ValueError):IncidentCapture(threshold=value)
