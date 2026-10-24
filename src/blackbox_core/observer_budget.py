"""Conservative warning from sampled observer usage, not an OFF/ON benchmark."""
import math,time
class ObserverBudget:
 def __init__(self):self.high=0;self.last_warning=None;self.latest={'status':'NOT_OBSERVED'}
 def observe(self,helper_cpu,frontend_cpu,*,cores,profile,frontend_expected=False,now=None):
  now=time.monotonic() if now is None else now
  values=[helper_cpu]+([frontend_cpu] if frontend_expected else [])
  if any(type(v) not in (int,float) or not math.isfinite(v) or v<0 for v in values) or not cores:
   self.high=0;self.latest={'status':'NOT_OBSERVED'};return False
  usage=sum(values)/cores;budget=3 if profile=='DETAILED' else 1
  self.high=self.high+1 if usage>budget else 0
  self.latest={'status':'OBSERVER_USAGE_HIGH' if self.high>=3 else 'SAMPLED_OBSERVER_USAGE',
   'machine_cpu_pp':usage,'advisory_budget_pp':budget,'consecutive_high_windows':self.high,
   'scope':'GUI_AND_PRIMARY_HELPER_ONLY_OTHER_COLLECTOR_CPU_NOT_INCLUDED' if frontend_expected else 'PRIMARY_HELPER_ONLY',
   'baseline_off_measured':False,'total_observer_effect_proven':False}
  alert=self.high>=3 and (self.last_warning is None or now-self.last_warning>=30)
  if alert:self.last_warning=now
  return alert
