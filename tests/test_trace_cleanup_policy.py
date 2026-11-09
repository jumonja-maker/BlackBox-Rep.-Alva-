"""Recorded cleanup consistency is separate from live owner authority."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackbox_core.trace_cleanup import terminal_cleanup_proven
from blackbox_core.trace_recovery import recover
from blackbox_core.windows_research import WprCapture,WprCommandError,WPR_NO_ACTIVE_PROFILES


class TraceCleanupPolicyTests(unittest.TestCase):
    def journal(self,kind='WPR',state='FAILED'):
        data={'state':state,'consent':'EXPLICIT_USER_COMMAND','capture_complete':False}
        if kind=='WPR':
            data['instance']='BLACKBOX_'+'a'*32
            data['resource_cleanup']={'confirmed':True,'scope':'EXACT_NAMED_WPR_INSTANCE','instance':data['instance']}
        else:
            data['uid']='b'*32
            data['resource_cleanup']={'confirmed':True,'scope':'EXACT_OWNED_EVENTPIPE_PROCESS_BOUNDARY','uid':data['uid']}
        return data

    def test_failed_artifact_and_completed_capture_both_require_the_exact_cleanup_scope(self):
        for kind in ('WPR','EVENTPIPE'):
            for state in ('COMPLETED','FAILED'):
                with self.subTest(kind=kind,state=state):
                    data=self.journal(kind,state)
                    self.assertTrue(terminal_cleanup_proven(data))
                    data['resource_cleanup']['scope']='UNRELATED_BOUNDARY'
                    self.assertFalse(terminal_cleanup_proven(data))

    def test_foreign_identity_or_filename_and_contradictory_cleanup_remain_unknown(self):
        for kind in ('WPR','EVENTPIPE'):
            for variant in ('identity','basename','false','bool','error','nonterminal','scope'):
                with self.subTest(kind=kind,variant=variant):
                    data=self.journal(kind);name=None
                    if variant=='identity':data['resource_cleanup']['instance' if kind=='WPR' else 'uid']='foreign'
                    elif variant=='basename':name='BLACKBOX_'+'f'*32+'.trace.json'
                    elif variant=='false':data['resource_cleanup']['confirmed']=False
                    elif variant=='bool':data['resource_cleanup']['confirmed']=1
                    elif variant=='error':data['cleanup_error']='UNKNOWN_ORIGINAL_CLOSE'
                    elif variant=='nonterminal':data['state']='CLEANUP_REQUIRED'
                    else:data['resource_cleanup']['scope']='EXPLICIT_EXACT_NAMED_RECOVERY'
                    self.assertFalse(terminal_cleanup_proven(data,journal=name))

    def test_legacy_labels_do_not_become_cleanup_but_the_separate_named_cancel_ack_can(self):
        for kind in ('WPR','EVENTPIPE'):
            for state in ('COMPLETED','FAILED','RECOVERED_NAMED_CANCEL','RECOVERED_OWNED_TOOL_STOP'):
                data=self.journal(kind,state);data.pop('resource_cleanup')
                self.assertFalse(terminal_cleanup_proven(data),(kind,state))
        data=self.journal();data.pop('resource_cleanup');data['cleanup']='NAMED_CANCEL_CONFIRMED'
        self.assertTrue(terminal_cleanup_proven(data))
        data['resource_cleanup']={'confirmed':False,'scope':'EXACT_NAMED_WPR_INSTANCE','instance':data['instance']}
        self.assertFalse(terminal_cleanup_proven(data),'New explicit uncertainty overrides legacy ACK')

    def test_explicit_recovery_proof_preserves_historical_failure_but_requires_exact_consent_and_kind(self):
        for kind in ('WPR','EVENTPIPE'):
            data=self.journal(kind,'RECOVERED_NAMED_CANCEL' if kind=='WPR' else 'RECOVERED_OWNED_TOOL_STOP')
            data.update(recovery_consent='EXPLICIT_USER_COMMAND',recovered_utc_ns=0,
                cleanup_error='HISTORICAL_FAILURE_BEFORE_EXPLICIT_RECOVERY')
            data['resource_cleanup']={'confirmed':True,'scope':'EXPLICIT_EXACT_NAMED_RECOVERY',
                'trace_id':data.get('instance',data.get('uid'))}
            self.assertTrue(terminal_cleanup_proven(data))
            for field,value in (('recovery_consent',None),('recovered_utc_ns',True),
                                ('state','RECOVERED_OWNED_TOOL_STOP' if kind=='WPR' else 'RECOVERED_NAMED_CANCEL')):
                changed=deepcopy(data);changed[field]=value
                self.assertFalse(terminal_cleanup_proven(changed),(kind,field))


class NamedAbsenceRecoveryTests(unittest.TestCase):
    def fixture(self,root):
        folder=Path(root);artifacts=folder/'artifacts';artifacts.mkdir()
        instance='BLACKBOX_'+'c'*32;name=instance+'.trace.json'
        path=artifacts/name
        # Legacy COMPLETED is unknown until the explicit exact native action.
        path.write_text(json.dumps({'instance':instance,'state':'COMPLETED',
            'consent':'EXPLICIT_USER_COMMAND','owner_pid':0,'guardian_pid':0}))
        class Catalog:
            def entry(self,entry_id):return {'origin':'LOCAL_APP_MARKED','state':'COMPLETED'}
            def _folder(self,row):return folder
            def _marker(self,*args):pass
        return Catalog(),instance,path

    def test_actual_scoped_numeric_no_active_hresult_can_confirm_an_absent_named_instance(self):
        for code in (WPR_NO_ACTIVE_PROFILES,WPR_NO_ACTIVE_PROFILES-(1<<32)):
            with self.subTest(code=code),tempfile.TemporaryDirectory() as temp:
                catalog,instance,path=self.fixture(temp)
                def absent(cap):
                    raise WprCommandError(code,'Localized text is irrelevant',arguments=['-cancel'],instance=cap.instance)
                with patch.object(WprCapture,'cancel',absent):
                    result=recover(catalog,'entry',path.name,confirmed=True)
                self.assertEqual(result['resource_cleanup']['observation'],'NAMED_INSTANCE_ABSENT_CONFIRMED')
                self.assertEqual(result['resource_cleanup']['wpr_returncode'],WPR_NO_ACTIVE_PROFILES)
                self.assertTrue(terminal_cleanup_proven(json.loads(path.read_text()),journal=path.name))
                self.assertFalse(result['capture_complete'])

    def test_wrong_code_command_instance_or_text_cannot_be_used_as_absence_proof(self):
        for variant in ('wrong-code','wrong-command','wrong-instance','text-only','bool-code'):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory() as temp:
                catalog,instance,path=self.fixture(temp);before=path.read_bytes()
                error=(OSError('WPR_COMMAND_FAILED_3310891008: There are no trace profiles running.')
                       if variant=='text-only' else WprCommandError(
                           5 if variant=='wrong-code' else True if variant=='bool-code' else WPR_NO_ACTIVE_PROFILES,
                           '0xc5583000 There are no trace profiles running.',
                           arguments=['-status'] if variant=='wrong-command' else ['-cancel'],
                           instance='BLACKBOX_'+'f'*32 if variant=='wrong-instance' else instance))
                with patch.object(WprCapture,'cancel',side_effect=error):
                    with self.assertRaises(OSError):recover(catalog,'entry',path.name,confirmed=True)
                self.assertEqual(path.read_bytes(),before)

    def test_numeric_error_is_taken_from_real_process_result_and_exact_last_instance_argument(self):
        with tempfile.TemporaryDirectory() as temp:
            capture=WprCapture(temp);capture.tool='TEST_ONLY_TOOL'
            with patch('blackbox_core.windows_research.subprocess.Popen') as launch:
                process=launch.return_value;process.returncode=WPR_NO_ACTIVE_PROFILES
                with self.assertRaises(WprCommandError) as failure:capture._run(['-cancel'])
            self.assertEqual(failure.exception.wpr_returncode,WPR_NO_ACTIVE_PROFILES)
            self.assertEqual(failure.exception.wpr_arguments,('-cancel',))
            self.assertEqual(launch.call_args.args[0],['TEST_ONLY_TOOL','-cancel','-instancename',capture.instance])


if __name__=='__main__':unittest.main()
