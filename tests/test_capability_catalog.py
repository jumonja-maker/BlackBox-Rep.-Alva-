import os,tempfile,unittest
from unittest.mock import patch
from blackbox_core.capability_catalog import inventory
from blackbox_core.research_worker import ResearchSession
class CapabilityCatalogTests(unittest.TestCase):
 def test_fixed_future_contract_never_substitutes_machine_totals_or_starts_tools(self):
  with patch('subprocess.Popen',side_effect=AssertionError('DETECTION_MUST_NOT_START_CAPTURE')):
   rows=inventory({'hwnd':'UNSUPPORTED_PLATFORM','wct':'UNSUPPORTED_PLATFORM','minidump':'UNSUPPORTED_PLATFORM','etw_wpr':'TOOL_UNAVAILABLE','dotnet_trace':'TOOL_UNAVAILABLE'})
  self.assertEqual(len({r['capability_id'] for r in rows}),13)
  for r in rows:
   self.assertIn('source_id',r);self.assertIn('privilege_level',r);self.assertIn('accuracy_notes',r);self.assertIn('failure_reason',r)
   self.assertFalse(r['detector_starts_capture'])
  for r in rows[-3:]:
   self.assertEqual(r['availability'],'FUTURE_NOT_IMPLEMENTED');self.assertFalse(r['system_total_fallback']);self.assertIsNone(r['value'])
 def test_real_registry_exposes_all_provider_boundaries_without_automatic_deep_capture(self):
  with tempfile.TemporaryDirectory() as temp:
   s=ResearchSession(temp);s.command({'op':'attach','args':{'pid':os.getpid()}});s.command({'op':'start'});s.tick()
   try:
    health=s.snapshot()['sensor_health']
    self.assertTrue({'threads','memory','process_tree','wct','etw','runtime','dump','crash_events'}<=health.keys())
    self.assertEqual(health['dump']['status'],'NOT_REQUESTED');self.assertIsNone(s.wpr);self.assertIsNone(s.runtime_trace)
    self.assertEqual(health['threads']['status'],'DISABLED')
   finally:s.stop()
if __name__=='__main__':unittest.main()
