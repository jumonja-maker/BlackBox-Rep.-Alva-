import unittest
from blackbox_core.sensors import Capability, CallbackSensor, SensorRegistry

class RegistryTests(unittest.TestCase):
    def test_failure_backs_off_without_disabling_other_sensor(self):
        now=[10.0];calls=[]
        registry=SensorRegistry(('broken','good'),clock=lambda:now[0])
        def broken(deadline):calls.append(deadline);raise PermissionError('ACCESS_DENIED')
        registry.register(CallbackSensor(Capability('broken','TEST','AVAILABLE'),broken))
        registry.register(CallbackSensor(Capability('good','TEST','AVAILABLE'),lambda d:{'status':'OK','value':0}))
        registry.start({});self.assertIsNone(registry.sample('broken'))
        self.assertEqual(registry.sample('good')['value'],0)
        self.assertIsNone(registry.sample('broken'));self.assertEqual(len(calls),1)
        state=registry.health()['broken'];self.assertEqual(state['status'],'BACKOFF')
        self.assertIsNone(state['heartbeat_age_ms']);self.assertEqual(state['failures'],1)
        now[0]+=1;registry.sample('broken');self.assertEqual(len(calls),2)
        self.assertEqual(registry.health()['broken']['retry_after_ms'],2000)
    def test_unavailable_is_not_zero_and_registry_is_fixed(self):
        r=SensorRegistry(('source',));r.register(CallbackSensor(Capability('source','TEST','UNSUPPORTED_PLATFORM'),lambda d:{'status':'UNSUPPORTED_PLATFORM'}))
        with self.assertRaises(ValueError):r.register(CallbackSensor(Capability('evil','X','AVAILABLE'),lambda d:{}))
        r.start({});self.assertEqual(r.sample('source')['status'],'UNSUPPORTED_PLATFORM')
        with self.assertRaises(ValueError):r.register(CallbackSensor(Capability('source','X','AVAILABLE'),lambda d:{}))
        r.stop();self.assertEqual(r.health()['source']['status'],'STOPPED')
    def test_soft_budget_overrun_is_reported_without_false_hard_timeout(self):
        now=[0.0];r=SensorRegistry(('s',),clock=lambda:now[0])
        def collect(d):now[0]=2;return {'status':'OK'}
        r.register(CallbackSensor(Capability('s','TEST','AVAILABLE'),collect));r.start({});r.sample('s',budget_s=.1)
        self.assertEqual(r.health()['s']['overruns'],1)
        self.assertEqual(r.health()['s']['deadline_kind'],'COOPERATIVE_BUDGET')
