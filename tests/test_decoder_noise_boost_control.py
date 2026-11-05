"""Typed policy/failure contracts only; actual Windows behavior needs the pilot."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from tools.qa_noise_boost_control import requested_policy,validate_cached_control,validate_live_control,fully_differing_boost_controls,validate_controlled_native_boost_pair,SCOPE


class NativeNoiseBoostControlTests(unittest.TestCase):
    def test_experiment_requires_actual_different_flags_in_both_pairs(self):
        inherited=[{'disabled_before_count':0,'disabled_after_count':0} for _ in range(2)]
        disabled=[{'disabled_before_count':0,'disabled_after_count':16} for _ in range(2)]
        self.assertTrue(fully_differing_boost_controls(inherited,disabled))
        for changed in ([{'disabled_before_count':16,'disabled_after_count':16}]*2,
                        [disabled[0],{'disabled_before_count':16,'disabled_after_count':16}],
                        [disabled[0]],
                        [{'disabled_before_count':False,'disabled_after_count':16}]*2):
            with self.subTest(changed=changed):self.assertFalse(fully_differing_boost_controls(inherited,changed))
        self.assertFalse(fully_differing_boost_controls(disabled,disabled))

    def receipt(self, policy='INHERITED'):
        return {'thread_boost_policy':policy,'thread_boost_observation_scope':SCOPE,
            'workers':[{'tid':100+i,'boost_disabled_before':False,'boost_disabled_after':policy=='DISABLED',
                'relative_priority_before':0,'relative_priority_after':0,'boost_control_verified':True}
                for i in range(16)]}

    def observation(self, ready):
        return {'status':'OBSERVED','process_identity_verified_before':True,'process_identity_verified_after':True,
            'errors':[],'query_handles_opened':16,'query_handles_closed':16,'query_handles_closed_verified':True,
            'retained_query_handles_after':0,'threads':[{'tid':w['tid'],'status':'OBSERVED','base_priority':6,
                'priority':6,'priority_boost_disabled':w['boost_disabled_after']} for w in ready['workers']]}

    def test_optional_request_keeps_legacy_absence_and_rejects_non_native_or_unknown_modes(self):
        self.assertIsNone(requested_policy({'implementation':'NATIVE_WIN32'}))
        for mode in ('INHERITED','DISABLED'):
            self.assertEqual(requested_policy({'implementation':'NATIVE_WIN32','thread_boost_policy':mode}),mode)
        for implementation,mode in [('PYTHON_CTYPES_WIN32','DISABLED'),('NATIVE_WIN32',True),
                                    ('NATIVE_WIN32',None),('NATIVE_WIN32','disabled'),('NATIVE_WIN32','UNKNOWN')]:
            with self.subTest(implementation=implementation,mode=mode),self.assertRaises(AssertionError):
                requested_policy({'implementation':implementation,'thread_boost_policy':mode})

    def test_cached_flags_use_real_bool_and_keep_every_relative_priority_unchanged(self):
        for mode in ('INHERITED','DISABLED'):
            result=validate_cached_control(self.receipt(mode),mode)
            self.assertEqual(result['worker_count'],16)
            self.assertEqual(result['disabled_after_count'],16 if mode=='DISABLED' else 0)
            self.assertEqual(result['scope'],SCOPE)
        for field,value in [('boost_disabled_before',0),('boost_disabled_after','true'),
                            ('boost_disabled_after',False),('boost_control_verified',False),
                            ('relative_priority_before',None),('relative_priority_after',1),
                            ('relative_priority_after',True)]:
            with self.subTest(field=field,value=value),self.assertRaises(AssertionError):
                broken=self.receipt('DISABLED');broken['workers'][0][field]=value
                validate_cached_control(broken,'DISABLED')

    def test_unknown_partial_or_duplicate_workers_never_establish_a_control(self):
        for kind in ('missing','duplicate','policy','scope'):
            with self.subTest(kind=kind),self.assertRaises(AssertionError):
                receipt=self.receipt('DISABLED')
                if kind=='missing':receipt['workers'].pop()
                elif kind=='duplicate':receipt['workers'][1]['tid']=receipt['workers'][0]['tid']
                elif kind=='policy':receipt['thread_boost_policy']='INHERITED'
                else:receipt['thread_boost_observation_scope']='CONTINUOUS'
                validate_cached_control(receipt,'DISABLED')

    def test_live_independent_flags_and_checked_query_close_are_mandatory(self):
        ready=self.receipt('DISABLED');observed=self.observation(ready)
        verified=validate_live_control(observed,ready,'DISABLED')
        self.assertEqual(verified['status'],'VERIFIED_LIVE_OWNED_WORKER_QUERY_AFTER_READY')
        self.assertEqual(verified['workers'][0]['base_priority'],6)
        self.assertEqual(ready['workers'][0]['relative_priority_after'],0)
        for field,value in [('query_handles_closed_verified',False),('retained_query_handles_after',1),
                            ('query_handles_closed',15),('query_handles_closed',16.0),
                            ('query_handles_opened',16.0),('retained_query_handles_after',False),
                            ('process_identity_verified_after',False),('errors',['UNKNOWN'])]:
            with self.subTest(field=field),self.assertRaises(AssertionError):
                validate_live_control({**observed,field:value},ready,'DISABLED')
        for field,value in [('priority_boost_disabled',False),('priority_boost_disabled',1),('base_priority',True),
                            ('base_priority',None),('base_priority',32),('priority',True),
                            ('status','UNKNOWN'),('tid',999)]:
            with self.subTest(worker_field=field),self.assertRaises(AssertionError):
                bad=deepcopy(observed);bad['threads'][0][field]=value
                validate_live_control(bad,ready,'DISABLED')

    def test_invalid_owner_request_fails_before_file_or_process_creation(self):
        from tools.qa_decoder_budget_diagnostic import NoiseOwner
        from pathlib import Path
        with patch('pathlib.Path.open') as opened,patch('tools.qa_decoder_apps.OwnedProcess') as child:
            with self.assertRaisesRegex(AssertionError,'NOISE_THREAD_BOOST_REQUEST_INVALID'):
                NoiseOwner(Path('must-not-create'),{'implementation':'NATIVE_WIN32','expected_native_handles':32,
                                                   'thread_boost_policy':'UNKNOWN'})
            opened.assert_not_called();child.assert_not_called()

    def controlled_case(self):
        ready=self.receipt('DISABLED');cached=validate_cached_control(ready,'DISABLED')
        live=validate_live_control(self.observation(ready),ready,'DISABLED')
        return {'native_thread_boost_control':{'requested':'DISABLED','ready':cached,
                'oracle':deepcopy(cached),'live_ready':live}}

    def test_controlled_pair_adds_attestation_without_claiming_legacy_equivalence(self):
        decision=validate_controlled_native_boost_pair(self.controlled_case(),self.controlled_case())
        self.assertEqual(decision['status'],'CONTROLLED_NATIVE_BASELINE_ATTESTED')
        self.assertIs(decision['legacy_inherited_condition_equivalent'],False)
        self.assertEqual(decision['historical_deadline_cause'],'NOT_ESTABLISHED')

    def test_controlled_pair_rejects_wrong_mode_partial_flags_or_uncertain_query_cleanup(self):
        for kind in ('mode','cached','cached_type','oracle','live_flag','live_count','close','retained'):
            with self.subTest(kind=kind),self.assertRaises(AssertionError):
                case=self.controlled_case();control=case['native_thread_boost_control']
                if kind=='mode':control['requested']='INHERITED'
                elif kind=='cached':control['ready']['disabled_after_count']=15
                elif kind=='cached_type':
                    control['ready']['worker_count']=16.0;control['oracle']['worker_count']=16.0
                elif kind=='oracle':control['oracle']['policy']='INHERITED'
                elif kind=='live_flag':control['live_ready']['workers'][0]['priority_boost_disabled']=False
                elif kind=='live_count':control['live_ready']['workers'].pop()
                elif kind=='close':control['live_ready']['query_handles_closed_verified']=False
                else:control['live_ready']['retained_query_handles_after']=1
                validate_controlled_native_boost_pair(self.controlled_case(),case)


if __name__=='__main__':unittest.main()
