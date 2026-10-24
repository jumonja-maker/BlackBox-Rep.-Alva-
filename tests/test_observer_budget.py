"""Injected budget inputs test policy, never masquerade as hardware benchmark."""
import os,tempfile,unittest
from blackbox_core.observer_budget import ObserverBudget
from blackbox_core.research_worker import ResearchSession
class ObserverBudgetTests(unittest.TestCase):
 def test_single_peak_missing_source_and_machine_scale_never_prove_overhead_effect(self):
  b=ObserverBudget();self.assertFalse(b.observe(100,100,cores=100,profile='STANDARD',frontend_expected=True,now=0))
  self.assertEqual(b.latest['machine_cpu_pp'],2);self.assertFalse(b.latest['baseline_off_measured'])
  self.assertFalse(b.observe(100,None,cores=100,profile='STANDARD',frontend_expected=True,now=1));self.assertEqual(b.latest['status'],'NOT_OBSERVED')
  for n in range(2,5):alert=b.observe(400,0,cores=100,profile='STANDARD',frontend_expected=True,now=n)
  self.assertTrue(alert);self.assertFalse(b.observe(400,0,cores=100,profile='STANDARD',now=5))
  self.assertFalse(b.latest['total_observer_effect_proven'])
 def test_actual_owner_reduces_frequency_keeps_recording_and_marks_changed_configuration(self):
  with tempfile.TemporaryDirectory() as temp:
   s=ResearchSession(temp);s.command({'op':'attach','args':{'pid':os.getpid()}});s.command({'op':'start'});s.tick()
   try:
    for _ in range(3):s._observe_overhead(400,None,cores=1)
    self.assertEqual(s.interval_ms,2000);self.assertTrue(s.probe.active);self.assertTrue(s._configuration_changed)
    self.assertTrue(s.observer_budget.latest['frequency_reduced']);self.assertIsNone(s.wpr);self.assertIsNone(s.runtime_trace)
   finally:s.stop()
 def test_explicit_disabled_policy_warns_without_changing_requested_frequency(self):
  with tempfile.TemporaryDirectory() as temp:
   s=ResearchSession(temp);s.capture_policy['adaptive_throttle']=False
   for _ in range(3):s._observe_overhead(400,None,cores=1)
   self.assertEqual(s.interval_ms,1000);self.assertEqual(s.observer_budget.latest['status'],'OBSERVER_USAGE_HIGH')
   self.assertFalse(s.observer_budget.latest['frequency_reduced'])
if __name__=='__main__':unittest.main()
