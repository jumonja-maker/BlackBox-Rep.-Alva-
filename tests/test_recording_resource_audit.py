"""Recording admission and explicit recovery proof, not native acceptance.

Real recorder files and worker-parent identity are used below. Native Stop
ACKs/failures are explicit controlled fixtures and never certify WPR/EventPipe.
"""
from copy import deepcopy
from contextlib import nullcontext
import io
import json
import os
from pathlib import Path
import tempfile
from threading import Event
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import psutil
from blackbox_core.library_catalog import LibraryCatalog
from blackbox_core.contracts import ObserverError
from blackbox_core.probe import PsutilProbe
from blackbox_core.research_worker import ResearchSession
from blackbox_core.runtime_trace import DotnetTrace, run as run_eventpipe
from blackbox_core.trace_owner import TraceSupervisor, _read, run
from blackbox_core.trace_recovery import alive, journal_identity, recover, scan


class DeadGuardian:
    stdin=None
    returncode=1
    def poll(self):return self.returncode
    def wait(self,timeout=None):return self.returncode


class RecordingResourceAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.session=ResearchSession(self.root)
        self.session.command({'op':'attach','args':{'pid':os.getpid()}})
        self.addCleanup(self.session.stop)

    def record(self):
        self.session.command({'op':'start'});self.session.tick()
        return self.session.probe.session_folder

    def retained(self,kind='wpr'):
        folder=self.record()
        artifacts=folder/'artifacts';artifacts.mkdir(exist_ok=True)
        if kind=='wpr':
            trace=TraceSupervisor(artifacts);self.session.wpr=trace
        else:
            with patch('blackbox_core.runtime_trace.shutil.which',return_value='TEST_ONLY'):
                trace=DotnetTrace(artifacts,os.getpid())
            self.session.runtime_trace=trace
        trace._cleanup_confirmed=False
        trace.data.update(state='RECORDING',guardian_pid=0)
        trace.path.write_text(json.dumps(trace.data),encoding='utf-8')
        trace.process=DeadGuardian();trace.poll()
        self.session.stop()
        return trace

    def test_duplicate_start_preserves_actual_recording_book_markers_and_owners(self):
        folder=self.record();s=self.session
        # No native source starts here. These opaque owners prove Start must
        # return before replacing any current recording context.
        owners=(object(),object());s.wpr,s.runtime_trace=owners
        book,markers,origin=s.book,s.markers,s.probe._recording_origin_ns
        try:
            with patch.object(s.probe,'start',side_effect=AssertionError('duplicate base Start')):
                self.assertEqual(s.command({'op':'start'}),{'folder':str(folder)})
            self.assertIs(s.book,book);self.assertIs(s.markers,markers)
            self.assertIs(s.wpr,owners[0]);self.assertIs(s.runtime_trace,owners[1])
            self.assertEqual(s.probe._recording_origin_ns,origin)
            self.assertEqual(s.probe.total_samples,1)
            self.assertTrue(s.probe.active)
        finally:s.wpr=None;s.runtime_trace=None

    def test_dead_unknown_guardian_blocks_start_and_attach_without_rebinding(self):
        for kind in ('wpr','eventpipe'):
            with self.subTest(kind=kind):
                trace=self.retained(kind);s=self.session;folder=s.probe.session_folder
                self.assertFalse(trace.cleanup_confirmed())
                self.assertTrue(s.stop()['cleanup_required'])
                with patch.object(s.probe,'start') as start,patch.object(s.probe,'attach') as attach:
                    for command in ({'op':'start'},{'op':'attach','args':{'pid':os.getpid()}}):
                        with self.assertRaisesRegex(ValueError,'RECORDING_RESOURCE_CLEANUP_UNCONFIRMED'):
                            s.command(command)
                    start.assert_not_called();attach.assert_not_called()
                self.assertEqual(s.probe.session_folder,folder)
                self.assertTrue(any(trace is owner for owner in (s.wpr,s.runtime_trace)))
                s.wpr=None;s.runtime_trace=None

    def test_pending_base_writer_blocks_new_recording_before_context_reset(self):
        self.record();s=self.session;s.stop();markers=s.markers
        pending=SimpleNamespace(thread=SimpleNamespace(is_alive=lambda:True))
        s.probe._pending_v2=pending
        try:
            with self.assertRaisesRegex(ValueError,'RECORDING_RESOURCE_CLEANUP_UNCONFIRMED'):
                s.command({'op':'start'})
            self.assertIs(s.markers,markers);self.assertIs(s.probe._pending_v2,pending)
        finally:s.probe._pending_v2=None

    def test_trace_restart_cannot_replace_an_unknown_owner_during_active_base_recording(self):
        folder=self.record();s=self.session;artifacts=folder/'artifacts';artifacts.mkdir(exist_ok=True)
        wpr=TraceSupervisor(artifacts);wpr._cleanup_confirmed=False;wpr.process=DeadGuardian()
        with patch('blackbox_core.runtime_trace.shutil.which',return_value='TEST_ONLY'):
            eventpipe=DotnetTrace(artifacts,os.getpid())
        eventpipe._cleanup_confirmed=False
        s.wpr=wpr;s.runtime_trace=eventpipe
        with patch('blackbox_core.research_worker.TraceSupervisor') as new_wpr,\
             patch('blackbox_core.research_worker.DotnetTrace') as new_eventpipe:
            for command in ({'op':'wpr','args':{'enabled':True}},{'op':'eventpipe'}):
                with self.assertRaisesRegex(ValueError,'RECORDING_RESOURCE_CLEANUP_UNCONFIRMED'):
                    s.command(command)
            new_wpr.assert_not_called();new_eventpipe.assert_not_called()
        self.assertIs(s.wpr,wpr);self.assertIs(s.runtime_trace,eventpipe)
        self.assertTrue(s.probe.active);self.assertEqual(s.probe.session_folder,folder)

    def recovery_request(self,trace):
        s=self.session;row=LibraryCatalog(self.root).query()['rows'][0]
        command={'id':'owned-recovery','op':'library_trace_recover','args':{
            'entry_id':row['entry_id'],'journal':trace.path.name,'confirmed':True,
            '_owned_trace_recovery':{'FORGED_USER_ARGUMENT':'IGNORED'}}}
        with patch.object(s.jobs,'submit') as submit:s.submit_optional(command)
        return command,submit.call_args.args[1],row['entry_id']

    @staticmethod
    def confirmed_cancel(cap):cap.active=False

    def test_explicit_owned_recovery_requires_actual_parent_and_matching_job_receipt(self):
        trace=self.retained();s=self.session
        command,packet,entry_id=self.recovery_request(trace)
        binding=packet['_owned_trace_recovery']
        self.assertEqual(binding['command_id'],command['id'])
        self.assertNotIn('FORGED_USER_ARGUMENT',binding)
        catalog=LibraryCatalog(self.root)
        self.assertEqual(catalog.entry(entry_id)['state'],'FINALIZATION_UNCONFIRMED')
        # In production this code executes in the existing optional worker;
        # only its OS parent PID is simulated. Birth-time lookup remains real.
        with patch('blackbox_core.trace_recovery.os.getppid',return_value=os.getpid()):
            review=scan(catalog,entry_id,_owned=[binding])
            self.assertTrue(review['rows'][0]['eligible'])
            self.assertTrue(review['rows'][0]['owner_active'])
            with patch('blackbox_core.windows_research.WprCapture.cancel',self.confirmed_cancel):
                value=recover(catalog,entry_id,trace.path.name,confirmed=True,_owned=binding)
        self.assertFalse(trace.cleanup_confirmed(),'Journal RECOVERED is not a parent cleanup ACK')
        receipt={'command':command,'result':value,'error':None}
        with patch.object(s.jobs,'poll',return_value=[receipt]):s.poll_optional()
        self.assertTrue(trace.cleanup_confirmed())
        self.assertFalse(s.stop()['cleanup_required'])
        self.assertEqual(catalog.entry(entry_id)['state'],'INCOMPLETE')
        folder=s.probe.session_folder
        s.command({'op':'start'})
        self.assertNotEqual(s.probe.session_folder,folder)
        self.assertTrue(s.probe.active)
        self.assertIsNone(s.wpr)
        self.assertFalse(value['capture_complete']);self.assertIsNone(value['lost_events'])

    def test_foreign_or_changed_recovery_proof_never_releases_retained_owner(self):
        trace=self.retained();s=self.session
        command,packet,entry_id=self.recovery_request(trace);binding=packet['_owned_trace_recovery']
        catalog=LibraryCatalog(self.root);original=trace.path.read_bytes()
        with patch('blackbox_core.windows_research.WprCapture.cancel') as cancel:
            with self.assertRaisesRegex(ValueError,'OWNER_BINDING_MISMATCH'):
                recover(catalog,entry_id,trace.path.name,confirmed=True,_owned=binding)
            for field,value in (('command_id','other-job'),('folder',str(self.root/'foreign')),
                                ('trace_id','BLACKBOX_'+'f'*32)):
                changed=deepcopy(binding);changed[field]=value
                if field=='command_id':continue  # Echo is checked by the actual parent below.
                with patch('blackbox_core.trace_recovery.os.getppid',return_value=os.getpid()):
                    with self.assertRaisesRegex(ValueError,'OWNER_BINDING_MISMATCH'):
                        recover(catalog,entry_id,trace.path.name,confirmed=True,_owned=changed)
            trace.path.write_bytes(original+b' ')
            with patch('blackbox_core.trace_recovery.os.getppid',return_value=os.getpid()):
                with self.assertRaisesRegex(ValueError,'SOURCE_CHANGED'):
                    recover(catalog,entry_id,trace.path.name,confirmed=True,_owned=binding)
            cancel.assert_not_called()
        trace.path.write_bytes(original)
        for change in ('job','source','cleanup'):
            s._trace_recovery_requests[command['id']]=(trace,binding)
            proof={'owner_binding':deepcopy(binding),'recording_id':entry_id,
                'journal':trace.path.name,'status':'RECOVERED_NAMED_CANCEL',
                'resource_cleanup':{'confirmed':True,'trace_id':trace.instance},
                'source_after':journal_identity(trace.path)}
            if change=='job':proof['owner_binding']['command_id']='foreign'
            elif change=='source':proof['source_after']['sha256']='0'*64
            else:proof['resource_cleanup']=None
            result={'command':command,'result':proof,'error':None}
            with patch.object(s.jobs,'poll',return_value=[result]):s.poll_optional()
            self.assertEqual(result['error'],'TRACE_RECOVERY_ACKNOWLEDGEMENT_MISMATCH')
            self.assertFalse(trace.cleanup_confirmed())

    def test_cancelling_recovery_forgets_its_private_acknowledgement_binding(self):
        trace=self.retained();command,_,_=self.recovery_request(trace)
        result={'command':command,'result':None,'error':'OPTIONAL_OPERATION_CANCELLED_RESULT_UNCONFIRMED'}
        with patch.object(self.session.jobs,'cancel',return_value=[result]):self.session.cancel_optional()
        self.assertEqual(self.session._trace_recovery_requests,{})
        self.assertFalse(trace.cleanup_confirmed())

    def test_live_actual_guardian_cannot_use_the_inactive_owner_exception(self):
        trace=self.retained();trace.process=SimpleNamespace(poll=lambda:None)
        try:
            command,packet,_=self.recovery_request(trace)
            self.assertNotIn('_owned_trace_recovery',packet)
            self.assertNotIn(command['id'],self.session._trace_recovery_requests)
        finally:trace.process=DeadGuardian()


class TerminalResourceProofTests(unittest.TestCase):
    def test_eventpipe_guardian_finally_journals_an_actual_original_owner_close_failure(self):
        from blackbox_core.optional_jobs import OwnedProcessCleanupUnconfirmed
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);tool=root/'TEST_ONLY_TOOL';tool.write_bytes(b'TEST ONLY NOT EXECUTABLE')
            with patch('blackbox_core.runtime_trace.shutil.which',return_value=str(tool)):
                trace=DotnetTrace(root,os.getpid())
            trace.path.write_text(json.dumps(trace.data))
            owner=Mock();owner.process.pid=os.getpid();owner.process.poll.return_value=0
            owner.close.side_effect=OwnedProcessCleanupUnconfirmed(owner,'TEST_ONLY_FINAL_CLOSE_FAILURE')
            with patch('blackbox_core.research_worker._streams',return_value=(io.StringIO(''),io.StringIO())),\
                 patch('blackbox_core.runtime_trace.shutil.which',return_value=str(tool)),\
                 patch('blackbox_core.runtime_trace.runtime_capability',return_value={'status':'TEST_ONLY_CANDIDATE'}),\
                 patch('blackbox_core.optional_jobs.OwnedProcess',return_value=owner):
                self.assertEqual(run_eventpipe(trace.path),1)
            owner.close.assert_called_once_with(kill=True)
            data=_read(trace.path)
            self.assertEqual(data['state'],'CLEANUP_REQUIRED')
            self.assertFalse(data['resource_cleanup']['confirmed'])
            self.assertIn('TEST_ONLY_FINAL_CLOSE_FAILURE',data['cleanup_error'])

    def test_eventpipe_guardian_distinguishes_no_tool_from_unconfirmed_owned_cleanup(self):
        from blackbox_core.optional_jobs import OwnedProcessCleanupUnconfirmed
        for unknown in (False,True):
            with self.subTest(cleanup_unknown=unknown),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);tool=root/'TEST_ONLY_TOOL';tool.write_bytes(b'TEST ONLY NOT EXECUTABLE')
                with patch('blackbox_core.runtime_trace.shutil.which',return_value=str(tool)):
                    trace=DotnetTrace(root,os.getpid())
                trace.path.write_text(json.dumps(trace.data))
                owner=Mock();owner.close.side_effect=OwnedProcessCleanupUnconfirmed(owner,'TEST_ONLY_CLOSE_FAILURE')
                with patch('blackbox_core.research_worker._streams',return_value=(io.StringIO(''),io.StringIO())),\
                     patch('blackbox_core.runtime_trace.shutil.which',return_value=str(tool) if unknown else None),\
                     patch('blackbox_core.runtime_trace.runtime_capability',return_value={'status':'TEST_ONLY_CANDIDATE'}),\
                     patch('blackbox_core.optional_jobs.OwnedProcess',side_effect=OwnedProcessCleanupUnconfirmed(owner,'TEST_ONLY_START_FAILURE')) as launch:
                    self.assertEqual(run_eventpipe(trace.path),1)
                data=_read(trace.path)
                self.assertEqual(data['resource_cleanup']['confirmed'],not unknown)
                self.assertEqual(data['state'],'CLEANUP_REQUIRED' if unknown else 'FAILED')
                owner.close.assert_not_called()  # No automatic retry of a failed original cleanup.
                if not unknown:launch.assert_not_called()

    def test_wpr_failed_artifact_can_have_confirmed_stop_but_failed_cancel_cannot(self):
        class Capture:
            tool=None
            fail_cancel=False
            def __init__(self,folder,**kwargs):self.active=False
            def start(self):self.active=True;return {'status':'TEST_ONLY_STARTED'}
            def stop(self):
                if not self.fail_cancel:self.active=False
                raise OSError('TEST_ONLY_ARTIFACT_FAILURE')
            def cancel(self):raise OSError('TEST_ONLY_CANCEL_UNCONFIRMED')
        for unknown in (False,True):
            with self.subTest(cleanup_unknown=unknown),tempfile.TemporaryDirectory() as temp:
                trace=TraceSupervisor(temp,seconds=1);trace.path.write_text(json.dumps(trace.data))
                Capture.fail_cancel=unknown;lease=Event();lease.set()
                self.assertEqual(run(trace.path,capture_factory=Capture,lease_lost=lease),1)
                data=_read(trace.path)
                self.assertEqual(data['resource_cleanup']['confirmed'],not unknown)
                self.assertEqual(data['state'],'CLEANUP_REQUIRED' if unknown else 'FAILED')
                trace.process=DeadGuardian();trace._cleanup_confirmed=False
                result=trace.poll()
                self.assertEqual(trace.cleanup_confirmed(),not unknown)
                self.assertEqual(trace.stop(),result)

    def test_eventpipe_terminal_receipt_is_cached_and_foreign_uid_is_unconfirmed(self):
        with tempfile.TemporaryDirectory() as temp,patch('blackbox_core.runtime_trace.shutil.which',return_value='TEST_ONLY'):
            trace=DotnetTrace(temp,os.getpid());trace._cleanup_confirmed=False
            trace.data.update(state='FAILED',resource_cleanup={'confirmed':True,
                'scope':'EXACT_OWNED_EVENTPIPE_PROCESS_BOUNDARY','uid':trace.uid})
            trace.path.write_text(json.dumps(trace.data));trace.process=DeadGuardian()
            result=trace.poll();self.assertEqual(result['status'],'FAILED')
            self.assertTrue(trace.cleanup_confirmed());self.assertEqual(trace.stop(),result)
            self.assertIsNone(trace.poll())
            trace.reported=False;trace.process=DeadGuardian();trace.data['uid']='f'*32
            trace.path.write_text(json.dumps(trace.data))
            self.assertEqual(trace.poll()['status'],'JOURNAL_UNAVAILABLE')
            self.assertFalse(trace.cleanup_confirmed())

    def test_nonfinite_observed_birth_cannot_prove_an_owner_absent(self):
        data={'owner_pid':os.getpid(),'owner_created':psutil.Process().create_time()}
        for value in (float('nan'),float('inf'),None,True,0,-1,10**1000):
            with self.subTest(value=repr(value)),patch('psutil.Process') as process:
                process.return_value.create_time.return_value=value
                self.assertTrue(alive(data,'owner'))

    def test_broken_dead_guardian_lease_does_not_hide_its_terminal_cleanup_receipt(self):
        class BrokenLease:
            closed=False
            def close(self):self.closed=True;raise BrokenPipeError('TEST_ONLY_DEAD_GUARDIAN')
        with tempfile.TemporaryDirectory() as temp:
            trace=TraceSupervisor(temp);trace._cleanup_confirmed=False
            trace.data.update(state='FAILED',resource_cleanup={'confirmed':True,
                'scope':'EXACT_NAMED_WPR_INSTANCE','instance':trace.instance})
            trace.path.write_text(json.dumps(trace.data))
            trace.process=DeadGuardian();trace.process.stdin=BrokenLease()
            result=trace.poll()
            self.assertEqual(result['status'],'FAILED');self.assertTrue(trace.cleanup_confirmed())
            self.assertIsNone(trace.process.stdin);self.assertEqual(trace.stop(),result)


class RecordingIdentityBoundaryTests(unittest.TestCase):
    invalid=(float('nan'),float('inf'),None,True,0,-1,10**1000)

    def test_invalid_initial_birth_never_primes_sampling(self):
        for value in self.invalid:
            with self.subTest(value=repr(value)),patch('psutil.Process') as process:
                process.return_value.create_time.return_value=value
                with self.assertRaises(ObserverError) as error:PsutilProbe(os.getpid())
                self.assertEqual((error.exception.code,error.exception.stage),('PID_REUSED','attach'))
                process.return_value.cpu_percent.assert_not_called()

    def test_invalid_expected_or_observed_birth_cannot_sample_counters(self):
        for expected_invalid in (False,True):
            for value in self.invalid:
                with self.subTest(expected_invalid=expected_invalid,value=repr(value)):
                    probe=PsutilProbe.__new__(PsutilProbe);probe.psutil=psutil;probe.process=Mock()
                    probe.created=value if expected_invalid else 1.0
                    probe.process.create_time.return_value=1.0 if expected_invalid else value
                    probe.last_observation=None
                    with self.assertRaises(ObserverError) as error:probe.sample()
                    self.assertEqual(error.exception.code,'PID_REUSED')
                    probe.process.oneshot.assert_not_called();probe.process.memory_info.assert_not_called()
                    self.assertIsNone(probe.last_observation)

    def test_invalid_birth_cannot_enter_explicit_native_capture(self):
        for expected_invalid in (False,True):
            for value in self.invalid:
                with self.subTest(expected_invalid=expected_invalid,value=repr(value)):
                    session=ResearchSession.__new__(ResearchSession)
                    session.probe=SimpleNamespace(pid=os.getpid(),_core=SimpleNamespace(
                        created=value if expected_invalid else 1.0))
                    with patch('psutil.Process') as process,\
                         patch('blackbox_core.research_worker.window_observations') as windows,\
                         patch('blackbox_core.research_worker.enable_debug_privilege') as privilege,\
                         patch('blackbox_core.research_worker.wait_chain') as wct:
                        process.return_value.create_time.return_value=1.0 if expected_invalid else value
                        with self.assertRaisesRegex(ValueError,'TARGET_INSTANCE_CHANGED'):session.capture_native()
                        windows.assert_not_called();privilege.assert_not_called();wct.assert_not_called()
                        if expected_invalid:process.assert_not_called()

    def test_invalid_fresh_birth_after_counter_reads_never_publishes_the_sample(self):
        for value in self.invalid:
            with self.subTest(value=repr(value)):
                probe=PsutilProbe.__new__(PsutilProbe);probe.psutil=psutil;probe.process=Mock()
                probe.created=1.0;probe.pid=os.getpid();probe.last_observation=None
                p=probe.process;p.create_time.return_value=1.0;p.oneshot.side_effect=nullcontext
                p.memory_info.return_value=SimpleNamespace(rss=10)
                p.cpu_percent.return_value=0.0;p.cpu_times.return_value=SimpleNamespace(user=1.0,system=0.0)
                p.num_threads.return_value=1;p.children.return_value=[];p.io_counters.return_value=None
                with patch('psutil.Process') as fresh:
                    fresh.return_value.create_time.return_value=value
                    with self.assertRaises(ObserverError) as error:probe.sample()
                self.assertEqual(error.exception.code,'PID_REUSED')
                self.assertIsNone(probe.last_observation)


if __name__=='__main__':unittest.main()
