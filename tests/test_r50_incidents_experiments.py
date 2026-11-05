"""R50 contracts and real recording read-back; executed on hosted CI only.

The deterministic counter/identity cases below are contract tests, not native
Windows workload evidence. The separate wave harness owns native acceptance.
"""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from blackbox_core.incidents import IncidentCapture
from blackbox_core.experiments import assess_comparability, capture_run_identity
from blackbox_core.casebook import context, evidence_page, export_comparison, load_comparison


class PrehistoryContractTests(unittest.TestCase):
    def detector(self,**kw):
        return IncidentCapture(threshold=80,min_duration_ms=0,post_ms=0,cooldown_ms=0,
            enabled_triggers=['MANUAL_PROBLEM'],**kw)

    def test_byte_and_row_limits_preserve_explicit_truncation(self):
        capture=self.detector(pre_ms=60000,max_buffer_samples=3,max_buffer_bytes=4096)
        for seq in range(1,40):
            capture.observe(elapsed_ms=seq*100,sample_seq=seq,cpu_percent=0,
                rss_bytes=seq,detail_ref='source:'+str(seq))
        cov=capture.coverage()
        self.assertLessEqual(cov['retained_samples'],3)
        self.assertLessEqual(cov['accounted_buffer_bytes'],4096)
        self.assertGreater(cov['capacity_evictions'],0)
        rows=capture.trigger('MANUAL_PROBLEM',elapsed_ms=4000,sample_seq=39,
            evidence_ref='research.sqlite3:evidence:40',verification='USER_DECLARED')
        self.assertEqual(rows[-1]['capture_coverage']['coverage_state'],'INCOMPLETE')
        self.assertEqual(rows[-1]['source'],'USER_MARKER')
        self.assertFalse(rows[-1]['proven_root_cause'])
        self.assertFalse(rows[-1]['capture_coverage']['buffer_at_completion']['raw_recording_deleted'])

    def test_arbitrary_reference_objects_cannot_escape_memory_budget(self):
        capture=self.detector()
        for value in ({'large':'x'*10000},'x'*513,True):
            with self.assertRaises(ValueError):
                capture.observe(elapsed_ms=0,sample_seq=1,cpu_percent=0,detail_ref=value)
        self.assertEqual(capture.coverage()['observed_samples'],0)

    def test_unretained_sample_is_not_fabricated_prehistory(self):
        capture=self.detector(max_buffer_bytes=1024)
        capture.observe(elapsed_ms=0,sample_seq=1,cpu_percent=0)
        self.assertEqual(capture.coverage()['retained_samples'],0)
        self.assertEqual(capture.coverage()['samples_not_retained'],1)
        rows=capture.trigger('MANUAL_PROBLEM',elapsed_ms=1,sample_seq=1,
            evidence_ref='research.sqlite3:evidence:1',verification='USER_DECLARED')
        self.assertEqual(rows[0]['pre_observed_count'],0)
        self.assertFalse(rows[0]['capture_coverage']['prehistory_complete'])

    def test_sequence_loss_and_incomplete_stop_stay_incomplete(self):
        capture=IncidentCapture(min_duration_ms=0,pre_ms=1000,post_ms=2000)
        capture.observe(elapsed_ms=0,sample_seq=1,cpu_percent=0)
        capture.observe(elapsed_ms=1000,sample_seq=2,cpu_percent=95)
        rows=capture.observe(elapsed_ms=2000,sample_seq=4,cpu_percent=95)
        self.assertTrue(rows[0]['sequence_gap'])
        stopped=capture.stop(elapsed_ms=2000,sample_seq=4)[0]
        self.assertEqual(stopped['status'],'INCOMPLETE_RECORDING_STOPPED')
        self.assertEqual(stopped['capture_coverage']['coverage_state'],'INCOMPLETE')
        self.assertTrue(stopped['capture_coverage']['sampling_gap_during_post'])

    def test_application_crash_marker_never_becomes_os_proof(self):
        capture=IncidentCapture(post_ms=0,enabled_triggers=['APP_CRASH_MARKER'])
        capture.observe(elapsed_ms=0,sample_seq=1,cpu_percent=0)
        rows=capture.trigger('APP_CRASH_MARKER',elapsed_ms=1,sample_seq=1,
            evidence_ref='research.sqlite3:evidence:2',verification='APP_SUPPLIED_UNAUTHENTICATED')
        self.assertEqual(rows[0]['source'],'APPLICATION_EVENT')
        self.assertIn('NOT_OS_CRASH_PROOF',rows[0]['trigger_detail']['interpretation'])
        with self.assertRaises(ValueError):
            capture.trigger('CRASH_OBSERVED',elapsed_ms=2,sample_seq=1,
                evidence_ref='eventlog:3',verification='USER_DECLARED')

    def test_one_observation_cpu_rss_io_pulse_keeps_exact_completed_context(self):
        capture=IncidentCapture(threshold=20,min_duration_ms=0,growth_window_ms=1000,
            memory_growth_bytes=8*1024**2,io_rate_bytes_s=1024,pre_ms=60000,
            post_ms=2000,cooldown_ms=1000,max_buffer_samples=16,max_buffer_bytes=8192,
            enabled_triggers=['CPU_SUSTAINED','RSS_GROWTH','IO_BURST'])
        capture.observe(elapsed_ms=0,sample_seq=1,cpu_percent=0,
            rss_bytes=32*1024**2,read_bytes=0,write_bytes=0)
        started=capture.observe(elapsed_ms=1000,sample_seq=2,cpu_percent=100,
            rss_bytes=96*1024**2,read_bytes=0,write_bytes=1024**2)
        self.assertEqual([row['code'] for row in started],['AUTO_INCIDENT_STARTED'])
        self.assertEqual(started[0]['trigger_code'],'CPU_SUSTAINED')
        # The step has ended: none of the three signals qualifies again.
        self.assertEqual(capture.observe(elapsed_ms=2000,sample_seq=3,cpu_percent=0,
            rss_bytes=96*1024**2,read_bytes=0,write_bytes=1024**2),[])
        completed=capture.observe(elapsed_ms=3000,sample_seq=4,cpu_percent=0,
            rss_bytes=96*1024**2,read_bytes=0,write_bytes=1024**2)
        self.assertEqual([row['code'] for row in completed],['AUTO_INCIDENT_COMPLETED'])
        incident=completed[0]
        self.assertEqual(incident['trigger_code'],'CPU_SUSTAINED')
        self.assertEqual(incident['trigger_detail']['observed_percent'],100)
        self.assertEqual(incident['secondary_signals'],{
            'RSS_GROWTH':{'metric':'rss_bytes','delta':64*1024**2,'threshold':8*1024**2,
                'first_seq':1,'observed_window_ms':1000,
                'interpretation':'GROWTH_OBSERVED_NOT_A_PROVEN_LEAK'},
            'IO_BURST':{'observed_bytes_s':1024**2,'threshold_bytes_s':1024,
                'observed_window_ms':1000,'interpretation':'THROUGHPUT_NOT_IO_LATENCY'}})
        self.assertEqual(incident['source'],'BLACKBOX_EXTERNAL_COUNTERS')
        self.assertEqual(incident['context_refs']['base_samples'],'session.sqlite3:samples:1..4')
        self.assertEqual(incident['trigger_sample_seq'],2)
        self.assertEqual(incident['status'],'CAPTURED')
        self.assertTrue(incident['capture_coverage']['post_complete'])
        self.assertEqual(incident['capture_coverage']['coverage_state'],'INCOMPLETE')
        self.assertEqual(incident['root_cause'],'UNKNOWN')
        self.assertFalse(incident['proven_root_cause'])
        self.assertEqual(capture.coverage()['incidents_completed'],1)
        self.assertFalse(capture.coverage()['active'])

    def test_immediate_pulse_keeps_only_enabled_observed_secondary_signals(self):
        capture=IncidentCapture(threshold=20,min_duration_ms=0,growth_window_ms=1000,
            memory_growth_bytes=8*1024**2,io_rate_bytes_s=1024,post_ms=0,
            enabled_triggers=['CPU_SUSTAINED','RSS_GROWTH'])
        capture.observe(elapsed_ms=0,sample_seq=1,cpu_percent=0,
            rss_bytes=32*1024**2,read_bytes=0,write_bytes=0)
        rows=capture.observe(elapsed_ms=1000,sample_seq=2,cpu_percent=100,
            rss_bytes=96*1024**2,read_bytes=0,write_bytes=1024**2)
        self.assertEqual([row['code'] for row in rows],
            ['AUTO_INCIDENT_STARTED','AUTO_INCIDENT_COMPLETED'])
        self.assertEqual(rows[-1]['trigger_code'],'CPU_SUSTAINED')
        self.assertEqual(set(rows[-1]['secondary_signals']),{'RSS_GROWTH'})
        self.assertEqual(rows[-1]['secondary_signals']['RSS_GROWTH']['first_seq'],1)
        self.assertEqual(rows[-1]['last_sample_seq'],2)
        self.assertEqual(capture.coverage()['incidents_completed'],1)
        self.assertFalse(capture.coverage()['active'])


def recorded_context(pid=123,created=100,image='a'*64):
    return {'state':'COMPLETED','capture_health':{'recording_resources_closed':True},
        'experiment':{'scenario':'owned workload','scenario_version':'1','workload':'input-sha',
            'target_version':'1','profile':'STANDARD','interval_ms':1000,'origin_monotonic_ns':1000,
            'run_identity':{'run_id':uuid4().hex,'identity_status':'OS_OBSERVED_EXACT_FILETIME',
                'process_identity':{'pid':pid,'created_100ns':created},
                'image':{'source_sha256':image,'source_size_bytes':10,'content_integrity':'HASHED_STABLE_FILE'},
                'clock_domain':{'source':'BLACKBOX_LOCAL_MONOTONIC_NS'}}}}


def resource_contract():
    return {'metrics':{key:{'median':0,'missing_repeats':0,'minimum_observed_fraction':1}
        for key in ('cpu_seconds','rss_peak_bytes','read_bytes','write_bytes')}}


class RepeatContractTests(unittest.TestCase):
    def compare(self,a,b,**kw):
        return assess_comparability(a,b,before_resources=resource_contract(),
            after_resources=resource_contract(),before_repeats=2,after_repeats=2,**kw)

    def test_distinct_instances_repeat_same_build_without_merging_identity(self):
        a=recorded_context();b=recorded_context(pid=456,created=200)
        result=self.compare(a,b)
        self.assertEqual(result['status'],'COMPARABLE')
        self.assertEqual(result['process_relation'],'DISTINCT_EXACT_INSTANCES')
        self.assertFalse(result['identity_merge_performed'])
        self.assertEqual(result['run_contexts']['before']['process_identity']['pid'],123)
        self.assertEqual(result['run_contexts']['after']['process_identity']['pid'],456)
        self.assertFalse(result['causal_link_proven'])
        self.assertEqual(result['file_trust'],'UNVERIFIED_IMPORT')

    def test_known_version_and_image_changes_are_not_comparable(self):
        for field in ('image','version'):
            b=recorded_context()
            if field=='image':b['experiment']['run_identity']['image']['source_sha256']='b'*64
            else:b['experiment']['target_version']='different'
            self.assertEqual(self.compare(recorded_context(),b)['status'],'NOT_COMPARABLE')

    def test_same_pid_with_another_creation_is_kept_as_distinct_instance(self):
        result=self.compare(recorded_context(pid=123,created=100),recorded_context(pid=123,created=101))
        self.assertEqual(result['process_relation'],'DISTINCT_EXACT_INSTANCES')
        self.assertFalse(result['identity_merge_performed'])

    def test_one_recording_is_not_counted_as_an_independent_before_after_pair(self):
        item=recorded_context()
        result=self.compare(item,deepcopy(item))
        self.assertEqual(result['status'],'NOT_COMPARABLE')
        self.assertIn('same_recording_reused',result['context_mismatches'])

    def test_missing_identity_clock_cleanup_and_loss_are_inconclusive(self):
        for field in ('identity','clock','cleanup','retention'):
            b=recorded_context()
            if field=='identity':b['experiment']['run_identity']['identity_status']='NOT_ESTABLISHED'
            if field=='clock':b['experiment']['run_identity']['clock_domain']={}
            if field=='cleanup':b['capture_health']['recording_resources_closed']=False
            if field=='retention':b['capture_health']['incident_coverage']={'dropped_triggers':1}
            self.assertEqual(self.compare(recorded_context(),b)['status'],'INCONCLUSIVE',field)

    def test_missing_sensor_is_not_compared_as_zero(self):
        resources=resource_contract();resources['metrics']['read_bytes']['median']=None
        result=assess_comparability(recorded_context(),recorded_context(),
            before_resources=resource_contract(),after_resources=resources,before_repeats=2,after_repeats=2)
        self.assertEqual(result['status'],'INCONCLUSIVE')
        self.assertIn('after.sensor_coverage.read_bytes',result['unknowns'])

    def test_workload_mismatch_takes_priority_over_partial_data(self):
        b=recorded_context();b['capture_health']['recording_resources_closed']=False
        result=self.compare(recorded_context(),b,context_mismatches=['workload'])
        self.assertEqual(result['status'],'NOT_COMPARABLE')


class ActualRecordingReadbackTests(unittest.TestCase):
    def recording(self,root):
        from blackbox_core.research_worker import ResearchSession
        session=ResearchSession(root)
        session.command({'op':'attach','args':{'pid':os.getpid()}})
        session.command({'op':'configure','args':{'scenario':'R50 own process','scenario_version':'1',
            'workload':'same bounded input','target_version':'1'}})
        session.command({'op':'capture_policy','args':{'policy':{'incident_enabled':True,
            'incident':{'enabled_triggers':['MANUAL_PROBLEM'],'post_ms':0}}}})
        session.command({'op':'start'})
        try:
            session.tick()
            session.command({'op':'mark','args':{'note':'owned QA marker'}})
            session.probe.actions.cool_down_ms=0
            for _ in range(2):
                session.command({'op':'prepare','args':{'baseline_ms':0}})
                session.command({'op':'begin'})
                for _ in range(3):session.tick();time.sleep(.02)
                session.command({'op':'end'});session.tick()
        finally:session.stop()
        return session.probe.session_folder

    def test_actual_recording_links_run_and_manual_incident_with_safe_export(self):
        with tempfile.TemporaryDirectory() as root:
            first=self.recording(root);second=self.recording(root)
            metadata=context(first)
            self.assertEqual(len(metadata['experiment']['run_identity']['run_id']),32)
            if os.name=='nt':
                self.assertEqual(metadata['experiment']['run_identity']['identity_status'],'OS_OBSERVED_EXACT_FILETIME')
            rows=evidence_page(first,limit=500)['rows']
            manual=[r for r in rows if r['data'].get('event',{}).get('trigger_code')=='MANUAL_PROBLEM']
            self.assertGreaterEqual(len(manual),2)
            source=first/'session.sqlite3';before=sha256(source.read_bytes()).hexdigest()
            for format in ('json','html'):
                destination=Path(root)/('comparison.'+format)
                receipt=export_comparison(first,second,destination,format=format)
                self.assertTrue(receipt['readback_verified'])
                self.assertEqual(sha256(destination.read_bytes()).hexdigest(),receipt['sha256'])
                self.assertEqual(receipt['run_receipt']['operation'],'research.export_comparison')
                self.assertTrue(receipt['run_receipt']['source']['verified'])
                self.assertEqual(receipt['run_receipt']['source']['producer_authentication'],'NOT_ESTABLISHED')
                self.assertFalse(receipt['run_receipt']['target']['verified'])
                self.assertTrue(receipt['run_receipt']['cleanup']['confirmed'])
                before_files=next(row['files'] for row in receipt['source_identities'] if row['role']=='before')
                self.assertEqual(before_files['session.sqlite3']['source_sha256'],before)
                loaded=load_comparison(destination)
                self.assertFalse(loaded['comparison']['causal_link_proven'])
                comparison_receipt=loaded['comparison']['run_receipt']
                self.assertEqual(comparison_receipt['operation'],'research.compare')
                self.assertFalse(comparison_receipt['source']['verified'])
                self.assertTrue(comparison_receipt['cleanup']['confirmed'])
                if format=='json':
                    independent=json.loads(destination.read_text())
                    self.assertEqual(independent['comparison']['comparison_status'],loaded['comparison']['comparison_status'])
                original=destination.read_bytes()
                with self.assertRaises(FileExistsError):export_comparison(first,second,destination,format=format)
                self.assertEqual(destination.read_bytes(),original)
            self.assertEqual(sha256(source.read_bytes()).hexdigest(),before)

    def test_malformed_import_cannot_send_strings_or_nan_to_gui_metrics(self):
        from blackbox_core.casebook import compare_cases
        with tempfile.TemporaryDirectory() as root:
            first=self.recording(root);second=self.recording(root)
            result=compare_cases(first,second)
            for bad in ('not a number',float('nan')):
                value=deepcopy(result);value['resource_comparison']['cpu_seconds']['before_median']=bad
                path=Path(root)/'bad.json'
                path.write_text(json.dumps({'schema':'blackbox.experiment-comparison.v1','comparison':value}))
                with self.assertRaises(ValueError):load_comparison(path)
            malformed=deepcopy(result)
            malformed['duration_comparison']['before_variability']={'iqr':1}
            path.write_text(json.dumps({'schema':'blackbox.experiment-comparison.v1','comparison':malformed}))
            with self.assertRaises(ValueError):load_comparison(path)

    def test_publication_replacement_keeps_foreign_file_and_no_success_receipt(self):
        from blackbox_core.export_recovery import ExportTransaction
        original_publish=ExportTransaction.publish
        with tempfile.TemporaryDirectory() as root:
            first=self.recording(root);second=self.recording(root)
            for mode in ('mutated-bytes','replaced-identity'):
                target=Path(root)/(mode+'.json');foreign=[]
                def replace_after_publish(tx):
                    original_publish(tx)
                    content=target.read_bytes()
                    if mode=='mutated-bytes':
                        content=b'x'*len(content);target.write_bytes(content)
                    else:
                        alternate=Path(root)/'foreign-correct-content.json'
                        alternate.write_bytes(content);os.replace(alternate,target)
                    foreign.append(content)
                with patch.object(ExportTransaction,'publish',replace_after_publish):
                    with self.assertRaises(ValueError) as raised:export_comparison(first,second,target)
                self.assertTrue(raised.exception.publication_unconfirmed)
                self.assertEqual(raised.exception.run_receipt['status'],'RECOVERY_UNCONFIRMED')
                self.assertEqual(target.read_bytes(),foreign[0])

    def test_identity_capture_budget_validation_does_not_lookup_invalid_pid(self):
        for budget in (0,-1,True,float('nan')):
            with self.assertRaises(ValueError):capture_run_identity(os.getpid(),timeout_seconds=budget)
