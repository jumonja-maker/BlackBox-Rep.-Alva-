"""Portable QA protocol/profile/download boundaries, not native Windows evidence."""
from contextlib import closing, nullcontext, redirect_stdout
from pathlib import Path
import hashlib
import io
import json
import os
import sqlite3
import stat
import struct
import tempfile
import time
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile

from tools.qa_decoder_apps import (decode_trace, etw_observations, installed, native_pe_identity, observe_native_output,
                                   native_output_path, observed_module_encoding,
                                   observed_process_image, safe_extract, monitored_run, seven_zip, workload_log_snapshot)
from tools.qa_decoder_budget_diagnostic import (PAIRS, parse_args, validate_noise_oracle,
    NoiseOwner, BudgetCapture,
    SEVENZIP_CAPABILITIES, validate_comparison, validate_original_source, validate_positive,
    validate_progress, validate_rejection, validate_workload_activity, validate_case_contract,
    validate_output_observation, seal_and_remove_large_evidence, collect_bounded_case_facts,
    validate_workload_budget, noise_policy, validate_noise_policy, validate_native_timing, workload_activity)
from tools.qa_decoder_budget_diagnostic import native_attribution
from tools.qa_schedule_capture import profile_definition
from tools.qa_decoder_noise_fixture import (_close_owner_with_checked_handles,
    _compiler_worker_environment, _require_compiler_policy, _configured_compiler_environment,
    _stop_completed_compiler_job)


class WorkloadFailureObservationProtocolTests(unittest.TestCase):
    """Fake owners/sensors/clocks exercise receipts, never real Windows load."""
    def invoke_deadline(self, root, *, fresh_code=None, diagnostics_fail=False, cleanup_fail=False, rss_budget_fail=False,
                        timeout_override=None, sleep_advance=31):
        log = root / 'private-child.log'; now = [0.0]; polls = [None, None, fresh_code]
        events = []; before_cleanup = []
        process = SimpleNamespace(pid=123, poll=lambda: polls.pop(0))
        def wait(**kwargs):
            raise AssertionError('UNEXPECTED_WAIT_AFTER_DEADLINE')
        process.wait = wait
        def close(**kwargs):
            events.append(('close', kwargs))
            receipt = root / 'workload-failure.json'
            before_cleanup.append(json.loads(receipt.read_text()) if receipt.exists() else None)
            if cleanup_fail:
                raise OSError('/private/cleanup')
        def owned(*args, **kwargs):
            kwargs['stdout'].write(b'PRIVATE_CHILD_LOG_PAYLOAD')
            return SimpleNamespace(process=process, close=close)
        identity = {'observed_image': '/private/executable', 'owned_image_matches_requested': True,
            'image_identity_source': 'OWNED_WINDOWS_PROCESS_HANDLE', 'creation_time_filetime_ticks': '134000000000000000',
            'cpu_user_seconds_held_handle': 2.75, 'cpu_kernel_seconds_held_handle': .65,
            'exit_time_filetime_ticks': '0'}
        identities = [identity, OSError('/private/held-handle')] if diagnostics_fail else [identity, identity]
        sensor = SimpleNamespace(oneshot=nullcontext, cpu_times=lambda: SimpleNamespace(user=2.5, system=.5),
            memory_info=lambda: SimpleNamespace(rss=2 * 1024**3 if rss_budget_fail else 4 * 1024**2), num_threads=lambda: 3,
            io_counters=lambda: SimpleNamespace(write_bytes=1024, read_bytes=2048))
        fake_psutil = SimpleNamespace(Process=lambda pid: sensor, NoSuchProcess=type('FakeNoSuchProcess', (Exception,), {}))
        def sleep(seconds):
            self.assertEqual(seconds, .025)
            now[0] += sleep_advance
        buffer = io.StringIO()
        expected_reason = 'APP_WORKLOAD_RSS_BUDGET' if rss_budget_fail else 'APP_WORKLOAD_DEADLINE'
        run_options = {'timeout': timeout_override} if timeout_override is not None else {}
        with patch.dict('sys.modules', {'psutil': fake_psutil}), \
                patch('tools.qa_decoder_apps.OwnedProcess', side_effect=owned), \
                patch('tools.qa_decoder_apps.owned_process_identity', side_effect=identities), \
                patch('tools.qa_decoder_apps.time.monotonic', side_effect=lambda: now[0]), \
                patch('tools.qa_decoder_apps.time.sleep', side_effect=sleep), redirect_stdout(buffer):
            if diagnostics_fail:
                with patch('tools.qa_decoder_apps.write_json', side_effect=OSError('/private/write')), \
                        patch('tools.qa_decoder_apps.workload_log_snapshot', side_effect=OSError('/private/hash')):
                    with self.assertRaisesRegex(AssertionError, '^' + expected_reason + '$') as caught:
                        monitored_run(['/private/executable', 'PRIVATE_ARG'], log, role='COMPRESS', cycle=1, **run_options)
            else:
                with self.assertRaisesRegex(AssertionError, '^' + expected_reason + '$') as caught:
                    monitored_run(['/private/executable', 'PRIVATE_ARG'], log, role='COMPRESS', cycle=1, **run_options)
        self.assertEqual(events, [('close', {'kill': True})])
        return caught.exception.workload_failure, before_cleanup[0], buffer.getvalue()

    def test_actual_failure_state_and_partial_counters_are_saved_before_forced_cleanup(self):
        for code in (None, 0):
            with self.subTest(fresh_code=code), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); facts, saved, stdout = self.invoke_deadline(root, fresh_code=code)
                self.assertEqual(saved, facts)
                self.assertEqual(facts['reason_code'], 'APP_WORKLOAD_DEADLINE')
                self.assertEqual(facts['configured_timeout_seconds'], 30)
                self.assertEqual(facts['elapsed_monitor_seconds'], 31)
                self.assertEqual(facts['deadline_check_elapsed_monitor_seconds'], 31)
                self.assertEqual(facts['last_resource_sample_begin_elapsed_monitor_seconds'], 0)
                self.assertEqual(facts['resource_samples_observed'], 1)
                self.assertEqual(facts['last_loop_poll_state'], 'RUNNING')
                self.assertEqual(facts['process_state_before_cleanup'], 'RUNNING' if code is None else 'EXITED')
                self.assertEqual(facts['poll_exit_code_before_cleanup'], 'NOT_ESTABLISHED' if code is None else 0)
                self.assertEqual((facts['role'], facts['cycle'], facts['phase']), ('COMPRESS', 1, 'DEADLINE_CHECK'))
                self.assertEqual((facts['cpu_user_seconds_observed'], facts['cpu_kernel_seconds_observed']), (2.5, .5))
                self.assertEqual((facts['cpu_user_seconds_held_handle'], facts['cpu_kernel_seconds_held_handle']), (2.75, .65))
                self.assertEqual(facts['peak_rss_observed'], 4 * 1024**2)
                self.assertEqual((facts['max_threads_observed'], facts['write_bytes_observed'], facts['read_bytes_observed']), (3, 1024, 2048))
                self.assertTrue(facts['owned_image_matches_requested'])
                self.assertEqual(facts['creation_time_filetime_ticks'], '134000000000000000')
                self.assertEqual(facts['log']['sha256'], hashlib.sha256(b'PRIVATE_CHILD_LOG_PAYLOAD').hexdigest())
                self.assertEqual(facts['log']['observation'], 'BOUNDED_STABLE_SNAPSHOT_NOT_FINAL_LOG')
                for private in ('PRIVATE_', '/private/', str(root)):
                    self.assertNotIn(private, json.dumps(facts) + stdout)
                proof = {'reason_code': 'APP_WORKLOAD_DEADLINE'}
                collect_bounded_case_facts(proof, root, root / 'absent-helper', {})
                self.assertEqual(proof['small_facts']['workload_failure'], facts)
                self.assertEqual(proof['reason_code'], 'APP_WORKLOAD_DEADLINE')

    def test_diagnostic_and_cleanup_failures_do_not_replace_primary_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            facts, saved, stdout = self.invoke_deadline(Path(tmp), diagnostics_fail=True, cleanup_fail=True)
            self.assertIsNone(saved)
            self.assertEqual(facts['reason_code'], 'APP_WORKLOAD_DEADLINE')
            self.assertEqual(facts['held_counters_observation'], 'NOT_ESTABLISHED')
            self.assertEqual(facts['cpu_user_seconds_held_handle'], 'NOT_ESTABLISHED')
            for name in ('held_identity_observation_error', 'log_observation_error', 'cleanup_error'):
                self.assertEqual(facts[name], 'REDACTED_UNSTRUCTURED')
            self.assertIn('APP_WORKLOAD_FAILURE_WRITE_FAILED', stdout)
            self.assertNotIn('/private/', json.dumps(facts) + stdout)

    def test_native_budget_still_rejects_live_process_after_sixty_seconds(self):
        with tempfile.TemporaryDirectory() as tmp:
            facts, saved, _ = self.invoke_deadline(Path(tmp), timeout_override=60, sleep_advance=61)
            self.assertEqual(saved, facts)
            self.assertEqual(facts['configured_timeout_seconds'], 60)
            self.assertEqual(facts['elapsed_monitor_seconds'], 61)
            self.assertEqual(facts['reason_code'], 'APP_WORKLOAD_DEADLINE')
            self.assertEqual(facts['process_state_before_cleanup'], 'RUNNING')

    def test_revised_native_budget_still_rejects_live_process_after_ninety_seconds(self):
        with tempfile.TemporaryDirectory() as tmp:
            facts, saved, _ = self.invoke_deadline(Path(tmp), timeout_override=90, sleep_advance=91)
            self.assertEqual(saved, facts)
            self.assertEqual(facts['configured_timeout_seconds'], 90)
            self.assertEqual(facts['elapsed_monitor_seconds'], 91)
            self.assertEqual(facts['reason_code'], 'APP_WORKLOAD_DEADLINE')
            self.assertEqual(facts['process_state_before_cleanup'], 'RUNNING')

    def test_returned_process_proof_records_native_budget_and_observed_duration_after_thirty_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); now = [0.]; polls = [None, 0]; events = []
            process = SimpleNamespace(pid=123, poll=lambda: polls.pop(0))
            def wait(**kwargs):
                events.append(('wait', kwargs)); return 0
            process.wait = wait
            owner = SimpleNamespace(process=process, close=lambda **kwargs: events.append(('close', kwargs)))
            sensor = SimpleNamespace(oneshot=nullcontext, cpu_times=lambda: SimpleNamespace(user=1., system=.5),
                memory_info=lambda: SimpleNamespace(rss=1024), num_threads=lambda: 2,
                io_counters=lambda: SimpleNamespace(read_bytes=1024, write_bytes=512))
            fake_psutil = SimpleNamespace(Process=lambda pid: sensor, NoSuchProcess=type('FakeNoSuchProcess', (Exception,), {}))
            def sleep(seconds):
                self.assertEqual(seconds, .025); now[0] += 31
            with patch.dict('sys.modules', {'psutil': fake_psutil}), \
                    patch('tools.qa_decoder_apps.OwnedProcess', return_value=owner), \
                    patch('tools.qa_decoder_apps.owned_process_identity', return_value={'owned_image_matches_requested': True}), \
                    patch('tools.qa_decoder_apps.time.monotonic', side_effect=lambda: now[0]), \
                    patch('tools.qa_decoder_apps.time.sleep', side_effect=sleep):
                proof = monitored_run(['fake.exe'], root / 'child.log', timeout=60, role='COMPRESS', cycle=0)
            self.assertEqual(events, [('wait', {'timeout': 5}), ('close', {'kill': True})])
            self.assertEqual(proof['exit_code'], 0)
            self.assertEqual(proof['configured_timeout_seconds'], 60)
            self.assertEqual(proof['elapsed_monitor_seconds'], 31)
            self.assertEqual(proof['monitor_duration_scope'], 'OBSERVED_MONITOR_DURATION_NOT_HARD_OS_DEADLINE')
            self.assertFalse((root / 'workload-failure.json').exists())

    def test_mid_sample_rss_failure_preserves_queried_metrics_and_marks_unqueried_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            facts, saved, _ = self.invoke_deadline(Path(tmp), rss_budget_fail=True)
            self.assertEqual(saved, facts)
            self.assertEqual(facts['reason_code'], 'APP_WORKLOAD_RSS_BUDGET')
            self.assertEqual(facts['phase'], 'RESOURCE_SAMPLE')
            self.assertEqual(facts['resource_samples_observed'], 0)
            self.assertEqual(facts['peak_rss_observed'], 2 * 1024**3)
            self.assertEqual(facts['cpu_seconds_observed'], 3.)
            for name in ('max_threads_observed', 'write_bytes_observed', 'read_bytes_observed'):
                self.assertEqual(facts[name], 'NOT_ESTABLISHED')

    def test_log_snapshot_never_reads_more_than_limit_and_rejects_growth_or_replacement(self):
        def info(*, size=3, inode=22, modified=10):
            return SimpleNamespace(st_dev=1, st_ino=inode, st_size=size, st_mtime_ns=modified,
                                   st_ctime_ns=10, st_mode=stat.S_IFREG)
        cases = [('stable', info(), info(), info(), info()),
                 ('growth', info(), info(), info(size=4), info(size=4)),
                 ('same_size_write', info(), info(), info(modified=11), info(modified=11)),
                 ('replacement', info(), info(inode=23), info(inode=23), info(inode=23)),
                 ('oversize', info(size=4 * 1024**2 + 1), info(), info(), info())]
        for name, expected, before, after, current in cases:
            with self.subTest(case=name):
                reads = []
                def read(limit):
                    reads.append(limit)
                    return b'abc'
                source = SimpleNamespace(fileno=lambda: 20, read=read)
                with patch('tools.qa_decoder_apps.os.fstat', side_effect=[expected, before, after]), \
                        patch('pathlib.Path.open', return_value=nullcontext(source)), \
                        patch('pathlib.Path.stat', return_value=current):
                    if name == 'stable':
                        facts = workload_log_snapshot(Path('private.log'), SimpleNamespace(fileno=lambda: 10))
                        self.assertEqual(facts['sha256'], hashlib.sha256(b'abc').hexdigest())
                        self.assertEqual(facts['observation'], 'BOUNDED_STABLE_SNAPSHOT_NOT_FINAL_LOG')
                    else:
                        with self.assertRaisesRegex(AssertionError, 'APP_WORKLOAD_LOG_SNAPSHOT_'):
                            workload_log_snapshot(Path('private.log'), SimpleNamespace(fileno=lambda: 10))
                self.assertEqual(reads, [4 * 1024**2 + 1] if name not in ('replacement', 'oversize') else [])

    def test_seven_zip_persists_partial_work_before_failed_extraction_and_cancel(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); binary = root / 'private-7z.exe'; binary.write_bytes(b'fixture')
            failure = AssertionError('APP_WORKLOAD_DEADLINE'); calls = []; saved_before_cancel = []
            capture = SimpleNamespace(active=True)
            def cancel():
                saved_before_cancel.append(json.loads((root / 'workload-oracle.json').read_text()))
                capture.active = False
            capture.cancel = cancel
            def run(args, log, **kwargs):
                calls.append(kwargs)
                if kwargs['role'] == 'EXTRACT':
                    raise failure
                return {'pid': 123, 'exit_code': 0, 'owned_image_matches_requested': True}
            with patch('tools.qa_decoder_apps.installed', return_value=binary), \
                    patch('tools.qa_decoder_apps.native_pe_identity', return_value={'code_kind': 'NATIVE_PE_NO_CLR_COM_DESCRIPTOR'}), \
                    patch('tools.qa_decoder_apps.binary_identity', return_value={'sha256': 'a' * 64}), \
                    patch('tools.qa_decoder_apps.start_schedule', return_value=capture), \
                    patch('tools.qa_decoder_apps.monitored_run', side_effect=run):
                with self.assertRaises(AssertionError) as caught:
                    seven_zip(root, root / 'unused-helper')
            self.assertIs(caught.exception, failure)
            self.assertEqual(calls, [{'role': 'COMPRESS', 'cycle': 0}, {'role': 'EXTRACT', 'cycle': 0}])
            oracle = saved_before_cancel[0]
            self.assertEqual(oracle['status'], 'INCOMPLETE_WORKLOAD_FAILURE')
            self.assertEqual(oracle['roundtrips_verified'], 0)
            self.assertEqual(oracle['input_bytes'], 8 * 1024**2)
            self.assertEqual(oracle['input_sha256'], hashlib.sha256((root / 'input.bin').read_bytes()).hexdigest())
            self.assertEqual(oracle['workloads'][0]['pid'], 123)
            self.assertEqual(oracle['workload_policy'], 'ORDINARY_30')
            self.assertEqual(oracle['requested_process_timeout_seconds'], 30)

    def test_seven_zip_native_policy_forwards_ninety_to_both_roles_and_records_partial_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); binary = root / 'fake.exe'; binary.write_bytes(b'fixture')
            capture = SimpleNamespace(active=False); failure = AssertionError('APP_WORKLOAD_DEADLINE')
            completed = {'pid': 123, 'configured_timeout_seconds': 90, 'elapsed_monitor_seconds': 31,
                         'exit_code': 0, 'role': 'COMPRESS', 'cycle': 0}
            with patch('tools.qa_decoder_apps.installed', return_value=binary), \
                    patch('tools.qa_decoder_apps.native_pe_identity', return_value={}), \
                    patch('tools.qa_decoder_apps.binary_identity', return_value={'sha256': 'a' * 64}), \
                    patch('tools.qa_decoder_apps.start_schedule', return_value=capture), \
                    patch('tools.qa_decoder_apps.monitored_run', side_effect=[completed, failure]) as run:
                with self.assertRaises(AssertionError) as caught:
                    seven_zip(root, root / 'unused', workload_policy='CONTROLLED_NATIVE_90')
            self.assertIs(caught.exception, failure)
            self.assertEqual([call.kwargs for call in run.call_args_list], [
                {'role': 'COMPRESS', 'cycle': 0, 'timeout': 90}, {'role': 'EXTRACT', 'cycle': 0, 'timeout': 90}])
            oracle = json.loads((root / 'workload-oracle.json').read_text())
            self.assertEqual(oracle['workload_policy'], 'CONTROLLED_NATIVE_90')
            self.assertEqual(oracle['requested_process_timeout_seconds'], 90)
            self.assertEqual(oracle['workloads'][0]['elapsed_monitor_seconds'], 31)
            self.assertEqual(oracle['status'], 'INCOMPLETE_WORKLOAD_FAILURE')

    def test_unknown_and_boolean_workload_policies_are_rejected_before_source_or_capture_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'must-not-be-created'
            with patch('tools.qa_decoder_apps.installed') as installed_app, \
                    patch('tools.qa_decoder_apps.start_schedule') as capture:
                for policy in ('UNKNOWN', 'CONTROLLED_NATIVE_61', True, False, 60, None):
                    with self.subTest(policy=policy), self.assertRaisesRegex(AssertionError, 'UNKNOWN_FIXED_QA_WORKLOAD_POLICY'):
                        seven_zip(output, output / 'unused', workload_policy=policy)
                installed_app.assert_not_called(); capture.assert_not_called()
            self.assertFalse(output.exists())


class ProducerNoisePolicyProtocolTests(unittest.TestCase):
    """Portable receipt/clock faults only; native execution remains a CI gate."""
    def ready(self, implementation):
        native = implementation == 'NATIVE_WIN32'
        return {'schema': 'blackbox.scheduler-noise/1', 'status': 'READY', 'pid': 123,
            'created_100ns': '1000', 'source_sha256': 'a' * 64, 'executable_sha256': 'b' * 64,
            'implementation': implementation, 'expected_native_handles': 32 if native else 16,
            'ttl_seconds': 210 if native else 70, 'progress_limit': 841 if native else 281,
            'begin_qpc': 0, 'qpc_frequency_hz': 1000,
            'workers': [{'tid': 100 + i, 'created_100ns': str(2000 + i)} for i in range(16)]}

    def progress(self, ready, sequence):
        return {**{key: ready[key] for key in ('pid', 'created_100ns', 'source_sha256', 'executable_sha256',
            'implementation', 'expected_native_handles', 'ttl_seconds', 'progress_limit', 'qpc_frequency_hz')},
            'schema': 'blackbox.scheduler-noise-progress/1', 'sequence': sequence,
            'sample_begin_qpc': sequence * 10, 'sample_end_qpc': sequence * 10 + 1, 'qpc': sequence * 10 + 1,
            'workers': [{'tid': 100 + i, 'handoffs': sequence} for i in range(16)], 'total_handoffs': 16 * sequence}

    def test_native_extended_receipts_work_but_python_and_legacy_limits_stay_strict(self):
        ready = self.ready('NATIVE_WIN32'); progress = self.progress(ready, 300)
        validate_progress(progress, ready, implementation='NATIVE_WIN32')
        with self.assertRaisesRegex(AssertionError, 'PROGRESS_IDENTITY_OR_COUNTS'):
            validate_progress(progress, ready)  # Legacy utility calls retain the 281 ceiling.
        for implementation, sequence in (('NATIVE_WIN32', 842), ('PYTHON_CTYPES_WIN32', 282)):
            source = self.ready(implementation)
            with self.subTest(implementation=implementation), self.assertRaisesRegex(AssertionError, 'PROGRESS_IDENTITY_OR_COUNTS'):
                validate_progress(self.progress(source, sequence), source, implementation=implementation)
        for change in ({'ttl_seconds': 70}, {'ttl_seconds': 210.0}, {'ttl_seconds': True},
                       {'progress_limit': 281}, {'progress_limit': 841.0}, {'implementation': 'PYTHON_CTYPES_WIN32'}):
            with self.subTest(change=change), self.assertRaisesRegex(AssertionError, 'ACTUAL_POLICY_MISMATCH'):
                validate_progress({**progress, **change}, ready, implementation='NATIVE_WIN32')
        oracle = {**ControlledBudgetProtocolTests().oracle(), 'implementation': 'NATIVE_WIN32',
                  'ttl_seconds': 210, 'progress_limit': 841, 'native_handles_created': 32, 'native_handles_closed': 32}
        validate_noise_oracle(oracle, 123, '1000', expected_handles=32, implementation='NATIVE_WIN32')
        for change in ({'ttl_seconds': 70}, {'progress_limit': 841.0}):
            with self.subTest(oracle=change), self.assertRaisesRegex(AssertionError, 'ACTUAL_POLICY_MISMATCH'):
                validate_noise_oracle({**oracle, **change}, 123, '1000', expected_handles=32, implementation='NATIVE_WIN32')

    def test_workload_activity_consumes_native_over_281_files_without_relaxing_python(self):
        paths = [Path(f'progress-{i:04d}.json') for i in range(1, 301)]
        for implementation in ('NATIVE_WIN32', 'PYTHON_CTYPES_WIN32'):
            with self.subTest(implementation=implementation):
                ready = self.ready(implementation)
                noise = NoiseOwner(SimpleNamespace(glob=lambda pattern: paths), {
                    'implementation': implementation, 'expected_native_handles': ready['expected_native_handles']})
                noise.ready = ready
                def read(path):
                    return self.progress(ready, int(path.stem.split('-')[1]))
                with patch('tools.qa_decoder_budget_diagnostic.read_json', side_effect=read) as reader, \
                        patch('tools.qa_decoder_apps.file_hash', return_value='c' * 64):
                    if implementation == 'NATIVE_WIN32':
                        result = workload_activity(noise, {'begin_qpc': 5, 'end_qpc': 3010, 'qpc_frequency_hz': 1000})
                        self.assertEqual(result['threads_with_positive_handoff_delta'], 16)
                        self.assertEqual(result['handoffs_between_receipts'], 16 * 299)
                        self.assertEqual(reader.call_count, 300)
                    else:
                        with self.assertRaisesRegex(AssertionError, 'PROGRESS_FILE_BUDGET'):
                            workload_activity(noise, {'begin_qpc': 5, 'end_qpc': 3010, 'qpc_frequency_hz': 1000})
                        reader.assert_not_called()

    def test_native_prelude_accepts_extended_progress_and_failure_facts_survive_abort(self):
        paths = [Path(f'progress-{i:04d}.json') for i in range(1, 301)]
        for implementation in ('NATIVE_WIN32', 'PYTHON_CTYPES_WIN32'):
            with self.subTest(implementation=implementation):
                ready = self.ready(implementation)
                noise = NoiseOwner(SimpleNamespace(glob=lambda pattern: paths), {
                    'implementation': implementation, 'expected_native_handles': ready['expected_native_handles']})
                noise.ready = ready
                noise.owner = SimpleNamespace(process=SimpleNamespace(poll=lambda: None), close=lambda **kwargs: None)
                def read_progress(path, *, phase_context):
                    phase_context.update(receipt_bytes=123, receipt_sha256='c' * 64,
                        snapshot_scope='ONE_READONLY_HANDLE_BYTES_JSON_SIZE_SHA_NO_REOPEN')
                    return self.progress(ready, 300)
                with patch('tools.qa_decoder_budget_diagnostic.time.monotonic', return_value=0.), \
                        patch('tools.qa_decoder_budget_diagnostic.read_json', side_effect=read_progress), \
                        patch('tools.qa_decoder_apps.file_hash', return_value='c' * 64), \
                        patch('pathlib.Path.stat', return_value=SimpleNamespace(st_size=123)):
                    if implementation == 'NATIVE_WIN32':
                        noise.await_handoffs(4800, 100)
                        self.assertEqual(noise.prelude['status'], 'COMPLETED')
                        self.assertEqual(noise.prelude['sequence'], 300)
                        self.assertEqual(noise.prelude['observed_handoffs'], 4800)
                    else:
                        with self.assertRaisesRegex(AssertionError, 'PROGRESS_FILE_BUDGET'):
                            noise.await_handoffs(4800, 100)
                        self.assertEqual(noise.prelude['status'], 'FAILED')
                saved = dict(noise.prelude)
                noise.owner.process.poll = lambda: 1
                noise.abort()
                self.assertEqual(noise.prelude, saved)
                self.assertEqual(noise.cleanup['status'], 'FORCED_OR_UNCONFIRMED_NOT_ACCEPTED')

    def test_native_qos_accepts_exact_boundaries_and_rejects_one_tick_or_malformed_clock(self):
        ready = {'begin_qpc': 100, 'qpc_frequency_hz': 1000}
        clock = {'begin_qpc': 90100, 'end_qpc': 185100, 'qpc_frequency_hz': 1000}
        facts = validate_native_timing(ready, clock, complete=True)
        self.assertEqual((facts['ready_to_work_begin_seconds'], facts['whole_workload_seconds']), (90, 95))
        self.assertEqual(facts['status'], 'WITHIN_LIMITS')
        for source, value in ((ready, {**clock, 'begin_qpc': 90101}),
                              (ready, {**clock, 'end_qpc': 185101}),
                              ({**ready, 'qpc_frequency_hz': 1000.0}, clock),
                              (ready, {**clock, 'qpc_frequency_hz': True}),
                              (ready, {**clock, 'end_qpc': 2**63}),
                              (ready, {**clock, 'qpc_frequency_hz': 2**64})):
            rejected = {}
            with self.subTest(ready=source, clock=value), self.assertRaisesRegex(AssertionError, 'NATIVE_QOS_'):
                validate_native_timing(source, value, complete=True, facts=rejected)
            self.assertNotEqual(rejected['status'], 'WITHIN_LIMITS')


class BudgetCaptureOrderProtocolTests(unittest.TestCase):
    """Fault-injected protocol ordering only, not WPR or native evidence."""
    def capture(self, *, noise_error=None, stop_error=None, cancel_error=None):
        events = []; clock = {'begin_qpc': 100}; captures = []; lifecycle = {'secondary_errors': []}
        cleanup = {'status': 'RECORDING', 'cleanup_required': True}
        noise = SimpleNamespace(owner=object(), cleanup={'status': 'NOT_ESTABLISHED'},
            producer={'implementation': 'PYTHON_CTYPES_WIN32'}, policy=noise_policy('PYTHON_CTYPES_WIN32'))
        def stop_noise():
            events.append(('noise_stop', clock.get('end_qpc')))
            if noise_error is not None:
                raise noise_error
            noise.cleanup = {'status': 'COMPLETED'}
        noise.stop = stop_noise
        actual = SimpleNamespace(active=True)
        result = {'path': 'owned.etl'}
        def stop_wpr():
            events.append(('wpr_stop', clock.get('end_qpc')))
            if stop_error is not None:
                raise stop_error
            actual.active = False
            return result
        def cancel_wpr():
            events.append(('wpr_cancel',))
            if cancel_error is not None:
                raise cancel_error
            actual.active = False
        def end_counter():
            events.append(('workload_end',))
            return 200
        actual.stop = stop_wpr; actual.cancel = cancel_wpr
        capture = BudgetCapture(actual, noise, clock, cleanup, captures, end_counter, lifecycle)
        return capture, events, captures, result

    def test_same_workload_boundary_then_orderly_noise_then_real_capture_stop(self):
        capture, events, captures, result = self.capture()
        self.assertIs(capture.stop(), result)
        self.assertEqual(events, [('workload_end',), ('noise_stop', 200), ('wpr_stop', 200)])
        self.assertEqual(captures, [result])
        self.assertEqual(capture.cleanup, {'status': 'STOPPED', 'cleanup_required': False})
        self.assertEqual(capture.noise.cleanup['status'], 'COMPLETED')
        capture.cancel()
        self.assertEqual(len(events), 3)

    def test_noise_failure_still_stops_wpr_and_cannot_retry_normal_noise_stop(self):
        failure = AssertionError('NOISE_EXIT_NOT_CONFIRMED')
        capture, events, captures, result = self.capture(noise_error=failure)
        with self.assertRaises(AssertionError) as caught:
            capture.stop()
        self.assertIs(caught.exception, failure)
        self.assertEqual(events, [('workload_end',), ('noise_stop', 200), ('wpr_stop', 200)])
        self.assertEqual(captures, [result])
        self.assertEqual(capture.cleanup['status'], 'STOPPED')
        self.assertEqual(capture.noise.cleanup['status'], 'NOT_ESTABLISHED')
        with self.assertRaises(AssertionError) as repeated:
            capture.cancel()
        self.assertIs(repeated.exception, failure)
        self.assertEqual(len(events), 3)

    def test_noise_first_failure_survives_wpr_stop_and_finally_cancel_failures(self):
        failure = AssertionError('NOISE_EXIT_NOT_CONFIRMED')
        capture, events, captures, _ = self.capture(noise_error=failure,
            stop_error=RuntimeError('WPR_STOP_FAILED'), cancel_error=OSError('WPR_CANCEL_FAILED'))
        with self.assertRaises(AssertionError) as caught:
            try:
                capture.stop()
            finally:
                if capture.active:
                    capture.cancel()
        self.assertIs(caught.exception, failure)
        self.assertEqual(events, [('workload_end',), ('noise_stop', 200), ('wpr_stop', 200), ('wpr_cancel',)])
        self.assertEqual(captures, [])
        self.assertEqual(capture.cleanup, {'status': 'UNCONFIRMED', 'cleanup_required': True})
        self.assertEqual(capture.lifecycle['primary_error']['reason_code'], 'NOISE_EXIT_NOT_CONFIRMED')
        self.assertEqual([item['phase'] for item in capture.lifecycle['secondary_errors']], ['WPR_STOP', 'WPR_CANCEL'])
        self.assertEqual(capture.noise.cleanup['status'], 'NOT_ESTABLISHED')

    def test_wpr_failure_is_not_replaced_and_completed_noise_is_not_stopped_again(self):
        failure = RuntimeError('WPR_STOP_FAILED')
        capture, events, captures, _ = self.capture(stop_error=failure)
        with self.assertRaises(RuntimeError) as caught:
            try:
                capture.stop()
            finally:
                if capture.active:
                    capture.cancel()
        self.assertIs(caught.exception, failure)
        self.assertEqual(events, [('workload_end',), ('noise_stop', 200), ('wpr_stop', 200), ('wpr_cancel',)])
        self.assertEqual(capture.noise.cleanup['status'], 'COMPLETED')
        self.assertEqual(capture.cleanup, {'status': 'CANCELLED', 'cleanup_required': False})
        self.assertEqual(captures, [])

    def test_existing_application_failure_survives_cancel_and_noise_failure(self):
        failure = ValueError('APP_WORKLOAD_FAILED')
        capture, events, captures, _ = self.capture(noise_error=RuntimeError('NOISE_STOP_FAILED'),
            cancel_error=OSError('WPR_CANCEL_FAILED'))
        with self.assertRaises(ValueError) as caught:
            try:
                raise failure
            finally:
                if capture.active:
                    capture.cancel()
        self.assertIs(caught.exception, failure)
        self.assertEqual(events, [('noise_stop', None), ('wpr_cancel',)])
        self.assertEqual(capture.lifecycle['primary_error']['phase'], 'APPLICATION')
        self.assertEqual([item['phase'] for item in capture.lifecycle['secondary_errors']], ['NOISE_STOP', 'WPR_CANCEL'])
        self.assertTrue(capture.cleanup['cleanup_required'])
        self.assertEqual(captures, [])

    def test_cancel_still_attempts_wpr_after_first_noise_failure_without_retrying_noise(self):
        failure = AssertionError('NOISE_EXIT_NOT_CONFIRMED')
        capture, events, captures, _ = self.capture(noise_error=failure)
        with self.assertRaises(AssertionError) as caught:
            capture.cancel()
        self.assertIs(caught.exception, failure)
        self.assertEqual(events, [('noise_stop', None), ('wpr_cancel',)])
        self.assertEqual(capture.cleanup, {'status': 'CANCELLED', 'cleanup_required': False})
        self.assertEqual(capture.noise.cleanup['status'], 'NOT_ESTABLISHED')
        self.assertEqual(captures, [])
        with self.assertRaises(AssertionError) as repeated:
            capture.cancel()
        self.assertIs(repeated.exception, failure)
        self.assertEqual(events, [('noise_stop', None), ('wpr_cancel',)])

    def test_native_qos_rejection_preserves_first_error_and_still_stops_noise_and_capture(self):
        for begin, end, reason, wpr_error in ((20100, 115101, 'NATIVE_QOS_WORKLOAD_EXCEEDED', None),
                (90101, 185101, 'NATIVE_QOS_READY_TO_WORK_EXCEEDED', RuntimeError('WPR_STOP_FAILED'))):
            with self.subTest(reason=reason):
                capture, events, _, _ = self.capture(stop_error=wpr_error)
                capture.noise.producer = {'implementation': 'NATIVE_WIN32'}
                capture.noise.policy = noise_policy('NATIVE_WIN32')
                capture.noise.ready = {'begin_qpc': 100, 'qpc_frequency_hz': 1000}
                capture.clock.update(begin_qpc=begin, qpc_frequency_hz=1000)
                capture.end_counter = lambda: end
                with self.assertRaisesRegex(AssertionError, '^' + reason + '$') as caught:
                    try:
                        capture.stop()
                    finally:
                        if capture.active:
                            capture.cancel()
                self.assertIs(capture.first_error, caught.exception)
                self.assertEqual(capture.lifecycle['primary_error']['phase'], 'NATIVE_TIMING')
                self.assertEqual(capture.lifecycle['native_timing']['status'], 'REJECTED')
                self.assertEqual(events[:2], [('noise_stop', end), ('wpr_stop', end)])
                self.assertEqual(sum(item[0] == 'noise_stop' for item in events), 1)
                self.assertEqual(capture.noise.cleanup['status'], 'COMPLETED')
                self.assertFalse(capture.cleanup['cleanup_required'])
                self.assertEqual(capture.cleanup['status'], 'CANCELLED' if wpr_error else 'STOPPED')

    def scheduler_capture(self, *, noise_error=None, final_code=None):
        capture, events, _, _ = self.capture(noise_error=noise_error)
        ticks = iter(range(100, 120))
        capture.end_counter = lambda: next(ticks)
        capture.clock['qpc_frequency_hz'] = 1000
        target = SimpleNamespace(process=SimpleNamespace(pid=501, poll=lambda: final_code))
        capture.noise.owner = SimpleNamespace(process=SimpleNamespace(pid=502))
        capture.noise.identity = {'creation_time_filetime_ticks': '200'}
        capture.noise.ready = {'pid': 502, 'created_100ns': '200', 'workers': [
            {'tid': 1000 + i, 'created_100ns': str(300 + i)} for i in range(16)]}
        failure = {'pid': 501, 'creation_time_filetime_ticks': '100',
            'owned_image_matches_requested': True, 'image_identity_source': 'OWNED_WINDOWS_PROCESS_HANDLE',
            'private': 'PRIVATE_PAYLOAD /private/path'}
        return capture, target, failure, events

    def test_failure_callback_observes_two_owned_snapshots_before_noise_stop_without_accepting_completion(self):
        for code in (None, 0):
            with self.subTest(final_poll=code):
                capture, target, failure, events = self.scheduler_capture(final_code=code)
                primary = AssertionError('APP_WORKLOAD_DEADLINE'); results = []; buffer = io.StringIO()
                def observe(process, created, thread_births=None):
                    events.append(('observe', process.pid))
                    return {'status': 'OBSERVED', 'pid': process.pid, 'observation_scope': 'PROTOCOL_FIXTURE_ONLY'}
                with patch('tools.qa_decoder_apps.observe_owned_thread_priorities', side_effect=observe) as helper, \
                        redirect_stdout(buffer):
                    with self.assertRaises(AssertionError) as caught:
                        try:
                            raise primary
                        except AssertionError:
                            results.append(capture.observe_workload_failure(target, failure))
                            raise
                self.assertIs(caught.exception, primary)
                self.assertIs(capture.first_error, primary)
                result = results[0]
                self.assertIs(capture.lifecycle['failure_scheduler_observation'], result)
                self.assertEqual(helper.call_args_list[0].args, (target.process, '100'))
                self.assertEqual(helper.call_args_list[1].args, (capture.noise.owner.process, '200'))
                self.assertEqual(helper.call_args_list[1].kwargs, {'thread_births': {
                    1000 + i: str(300 + i) for i in range(16)}})
                self.assertEqual(events, [('observe', 501), ('observe', 502), ('noise_stop', None)])
                self.assertEqual(result['scope'], 'OBSERVATIONS_ONLY_NOT_STATE_WAIT_OR_CAUSE')
                self.assertEqual(result['workload_status'], 'INCOMPLETE_GUARD_FAILURE_BOUNDARY')
                self.assertEqual(result['failure_boundary_qpc'], 100)
                self.assertLess(result['target_end_qpc'], result['noise_begin_qpc'])
                self.assertLess(result['snapshots_end_qpc'], result['after_noise_stop_poll_begin_qpc'])
                self.assertNotIn('end_qpc', capture.clock)
                after = result['target_after_noise_stop']
                self.assertEqual(after['state'], 'RUNNING' if code is None else 'EXITED')
                self.assertEqual(after['exit_code'], 'NOT_ESTABLISHED' if code is None else 0)
                self.assertEqual(after['scope'], 'AFTER_NOISE_STOP_BEFORE_TARGET_CLEANUP')
                self.assertIs(capture.observe_workload_failure(target, failure), result)
                self.assertEqual(helper.call_count, 2)
                self.assertIn('CONTROLLED_SCHEDULER_FAILURE_FACTS', buffer.getvalue())
                self.assertNotIn('PRIVATE_', json.dumps(result) + buffer.getvalue())
                self.assertNotIn('/private/', json.dumps(result) + buffer.getvalue())
                with self.assertRaises(AssertionError) as cancelled:
                    capture.cancel()
                self.assertIs(cancelled.exception, primary)
                self.assertEqual(events[-1], ('wpr_cancel',))
                self.assertEqual(sum(item[0] == 'noise_stop' for item in events), 1)

    def test_failure_callback_query_clock_and_noise_errors_remain_secondary_unknown_observations(self):
        capture, target, failure, _ = self.scheduler_capture(noise_error=RuntimeError('NOISE_STOP_FAILED'))
        ticks = iter(range(101, 120)); count = [0]
        def clock():
            count[0] += 1
            if count[0] == 1:
                raise OSError('/private/clock')
            return next(ticks)
        capture.end_counter = clock; capture.clock['qpc_frequency_hz'] = 'PRIVATE_FREQUENCY'
        primary = AssertionError('APP_WORKLOAD_DEADLINE'); results = []
        target.process.poll = lambda: (_ for _ in ()).throw(OSError('/private/poll'))
        with patch('tools.qa_decoder_apps.observe_owned_thread_priorities', side_effect=OSError('/private/query')), \
                redirect_stdout(io.StringIO()):
            with self.assertRaises(AssertionError) as caught:
                try:
                    raise primary
                except AssertionError:
                    results.append(capture.observe_workload_failure(target, failure))
                    raise
        self.assertIs(caught.exception, primary)
        self.assertIs(capture.first_error, primary)
        result = results[0]
        self.assertEqual(result['qpc_frequency_hz'], 'NOT_ESTABLISHED')
        self.assertEqual(result['failure_boundary_qpc'], 'NOT_ESTABLISHED')
        self.assertEqual(result['target']['status'], 'UNKNOWN')
        self.assertEqual(result['noise']['status'], 'UNKNOWN')
        self.assertEqual(result['target_after_noise_stop']['state'], 'UNKNOWN')
        self.assertEqual(capture.lifecycle['secondary_errors'][0]['phase'], 'NOISE_STOP')
        self.assertNotIn('/private/', json.dumps(result))
        self.assertNotIn('PRIVATE_', json.dumps(result))

    def test_failure_callback_never_queries_malformed_or_duplicate_noise_thread_identities(self):
        for change in ({'tid': 'PRIVATE_PATH'}, {'tid': 1001}, {'created_100ns': '/private/birth'}):
            with self.subTest(change=change):
                capture, target, failure, _ = self.scheduler_capture()
                capture.noise.ready['workers'][0].update(change)
                primary = AssertionError('APP_WORKLOAD_DEADLINE'); results = []
                with patch('tools.qa_decoder_apps.observe_owned_thread_priorities', return_value={'status': 'OBSERVED'}) as helper, \
                        redirect_stdout(io.StringIO()):
                    with self.assertRaises(AssertionError) as caught:
                        try:
                            raise primary
                        except AssertionError:
                            results.append(capture.observe_workload_failure(target, failure))
                            raise
                self.assertIs(caught.exception, primary)
                self.assertEqual(helper.call_count, 1)
                self.assertEqual(results[0]['noise']['status'], 'UNKNOWN')
                self.assertEqual(results[0]['noise']['reason_code'], 'FAILURE_NOISE_THREAD_IDENTITIES_NOT_ESTABLISHED')
                self.assertNotIn('PRIVATE_', json.dumps(results[0]))


class NoiseStopObservationProtocolTests(unittest.TestCase):
    """Literal receipts and fake processes are protocol tests, not native proof."""
    def noise(self, root, code=17):
        output = root / 'noise'; output.mkdir()
        noise = NoiseOwner(output, {'implementation': 'NATIVE_WIN32', 'expected_native_handles': 32})
        calls = []
        def wait(*, timeout):
            calls.append(('wait', timeout, (output / 'stop.request').is_file()))
            return code
        noise.owner = SimpleNamespace(process=SimpleNamespace(wait=wait, poll=lambda: code),
                                      close=lambda **kwargs: calls.append(('close', kwargs)))
        noise.ready = {'begin_qpc': 100, 'qpc_frequency_hz': 10000000}
        noise.log = io.BytesIO()
        return noise, calls

    def test_nonzero_exit_preserves_actual_bounded_oracle_before_unchanged_failure_and_abort(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); noise, calls = self.noise(root)
            oracle = {'schema': 'blackbox.scheduler-noise/1', 'status': 'FAILED',
                'pid': 123, 'created_100ns': '134000000000000000', 'pairs': 8,
                'qpc_frequency_hz': 10000000, 'begin_qpc': 100, 'end_qpc': 170,
                'stop_requested': True, 'all_threads_joined': False, 'cleanup_required': True,
                'native_handles_created': 32, 'native_handles_closed': 31,
                'event_handles_created': 16, 'event_handles_closed': 16,
                'thread_handles_created': 16, 'thread_handles_closed': 15,
                'errors': ['NATIVE_NOISE_THREAD_JOIN_FAILED', 'PRIVATE_ERROR /private/path'],
                'secret': 'PRIVATE_PAYLOAD', 'workers': [{'tid': 1000 + i, 'handoffs': i + 1,
                    'created_100ns': str(134000000000000001 + i), 'begin_qpc': 90, 'end_qpc': 160,
                    'private': 'PRIVATE_WORKER_PAYLOAD'} for i in range(16)]}
            (noise.output / 'oracle.json').write_text(json.dumps(oracle), encoding='utf-8')
            (root / 'noise.log').write_bytes(b'PRIVATE_LOG_PAYLOAD')
            with patch('tools.qa_decoder_budget_diagnostic.kernel_api', return_value=object()), \
                    patch('tools.qa_decoder_budget_diagnostic.counter', side_effect=[10000000, 150, 151]):
                with self.assertRaisesRegex(AssertionError, '^NOISE_EXIT_NOT_CONFIRMED$'):
                    noise.stop()
            self.assertEqual(calls, [('wait', 8, True)])
            observation = noise.stop_observation
            self.assertEqual(observation['child_exit_code'], 17)
            self.assertEqual(observation['child_exit_before_stop_request'], 17)
            self.assertTrue(observation['parent_stop_requested'])
            self.assertEqual(observation['parent_stop_request_begin_qpc'], 150)
            self.assertEqual(observation['parent_stop_request_end_qpc'], 151)
            self.assertEqual(observation['child_ready'], {'begin_qpc': 100, 'qpc_frequency_hz': 10000000})
            projected = observation['child_oracle']
            for name in ('status', 'stop_requested', 'all_threads_joined', 'cleanup_required',
                         'native_handles_created', 'native_handles_closed', 'event_handles_closed',
                         'thread_handles_closed', 'begin_qpc', 'end_qpc'):
                self.assertEqual(projected[name], oracle[name])
            self.assertEqual(projected['workers'][15]['handoffs'], 16)
            self.assertEqual(projected['errors'], ['NATIVE_NOISE_THREAD_JOIN_FAILED', 'NOT_ESTABLISHED'])
            self.assertIn('UNVALIDATED', projected['acceptance_scope'])
            self.assertEqual(observation['child_log']['sha256'], hashlib.sha256(b'PRIVATE_LOG_PAYLOAD').hexdigest())
            for private in ('PRIVATE_', str(root)):
                self.assertNotIn(private, json.dumps(observation))
            saved = json.dumps(observation, sort_keys=True)
            self.assertEqual(noise.cleanup['status'], 'NOT_ESTABLISHED')
            noise.abort()
            self.assertEqual(noise.cleanup['status'], 'FORCED_OR_UNCONFIRMED_NOT_ACCEPTED')
            self.assertTrue(noise.cleanup['cleanup_required'])
            self.assertEqual(json.dumps(noise.stop_observation, sort_keys=True), saved)
            self.assertEqual(calls[-1], ('close', {'kill': True}))

    def test_missing_or_malformed_child_oracle_never_masks_nonzero_exit(self):
        for content in (None, '{private malformed JSON', json.dumps(['PRIVATE_PAYLOAD'])):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); noise, calls = self.noise(root, 23)
                if content is not None:
                    (noise.output / 'oracle.json').write_text(content, encoding='utf-8')
                with patch('tools.qa_decoder_budget_diagnostic.kernel_api', side_effect=RuntimeError('/private/clock')):
                    with self.assertRaisesRegex(AssertionError, '^NOISE_EXIT_NOT_CONFIRMED$'):
                        noise.stop()
                observation = noise.stop_observation
                self.assertEqual(observation['child_exit_code'], 23)
                self.assertEqual(observation['child_oracle'], 'NOT_ESTABLISHED')
                self.assertIn('oracle_read_error', observation)
                self.assertEqual(observation['parent_clock_error'], 'REDACTED_UNSTRUCTURED')
                self.assertNotIn('/private', json.dumps(observation))
                self.assertNotIn('PRIVATE_PAYLOAD', json.dumps(observation))
                self.assertEqual(calls, [('wait', 8, True)])


class CheckedOwnerCloseProtocolTests(unittest.TestCase):
    """Fake owner/kernel fault fixtures only: no native process or handle evidence."""
    class Owner:
        def __init__(self, native_result=73, owner_error=None):
            self.job = 101
            self._closed = False
            self.registered = True
            self.unregister_calls = 0
            self.close_calls = []
            self.events = []
            self.received_native_result = None
            self.owner_error = owner_error

            class Kernel:
                pass
            self.kernel = Kernel()
            def native_close(handle):
                self.events.append(('native_close', handle))
                return native_result
            self.kernel.CloseHandle = native_close

        def close(self, *, kill=False):
            self.close_calls.append(kill)
            self.events.append(('owner_close', kill))
            # Model the existing owner, which advances its state after the
            # call. A FALSE must interrupt it before these assignments.
            self.received_native_result = self.kernel.CloseHandle(self.job)
            self.job = None
            self._closed = True
            # Model the normal cleanup hook required by the future R20 owner.
            self.registered = False
            self.unregister_calls += 1
            self.events.append(('normal_unregister',))
            if self.owner_error is not None:
                raise self.owner_error

    def test_delegates_to_owner_close_and_keeps_normal_cleanup_hook_and_native_result(self):
        owner = self.Owner()
        original_close = owner.kernel.CloseHandle
        _close_owner_with_checked_handles(owner)
        self.assertEqual(owner.close_calls, [False])
        self.assertEqual(owner.events, [('owner_close', False), ('native_close', 101), ('normal_unregister',)])
        self.assertEqual(owner.received_native_result, 73)
        self.assertEqual(owner.unregister_calls, 1)
        self.assertFalse(owner.registered)
        self.assertIsNone(owner.job)
        self.assertTrue(owner._closed)
        self.assertIs(owner.kernel.CloseHandle, original_close)

    def test_native_false_interrupts_owner_before_job_state_or_registry_is_cleared(self):
        owner = self.Owner(native_result=0)
        original_close = owner.kernel.CloseHandle
        with self.assertRaisesRegex(AssertionError, 'NATIVE_NOISE_COMPILER_JOB_CLOSE_FAILED'):
            _close_owner_with_checked_handles(owner)
        self.assertEqual(owner.close_calls, [False])
        self.assertEqual(owner.events, [('owner_close', False), ('native_close', 101)])
        self.assertEqual(owner.job, 101)
        self.assertFalse(owner._closed)
        self.assertTrue(owner.registered)
        self.assertEqual(owner.unregister_calls, 0)
        self.assertIs(owner.kernel.CloseHandle, original_close)

    def test_owner_exception_is_preserved_and_wrapper_is_restored(self):
        failure = RuntimeError('OWNER_CLEANUP_HOOK_FAILED')
        owner = self.Owner(owner_error=failure)
        original_close = owner.kernel.CloseHandle
        with self.assertRaises(RuntimeError) as caught:
            _close_owner_with_checked_handles(owner)
        self.assertIs(caught.exception, failure)
        self.assertEqual(owner.close_calls, [False])
        self.assertEqual(owner.unregister_calls, 1)
        self.assertIs(owner.kernel.CloseHandle, original_close)


class PlannedCompilerJobStopProtocolTests(unittest.TestCase):
    """Pure fake Job/query/clock fixtures, never evidence of Windows cleanup."""
    def owner(self, *, worker_exit=0, job=101, termination_result=1):
        owner = CheckedOwnerCloseProtocolTests.Owner()
        owner.job = job
        owner.process = SimpleNamespace(poll=lambda: worker_exit)
        owner.termination_calls = []
        owner.query_calls = []
        owner.observations = []
        def terminate(handle, code):
            owner.termination_calls.append((handle, code))
            owner.events.append(('terminate', handle, code))
            return termination_result
        owner.kernel.TerminateJobObject = terminate
        return owner

    def invoke(self, owner, responses, *, build_deadline=90):
        responses = list(responses)
        clock = [0.0]
        def now():
            clock[0] += .125
            return clock[0]
        def query(kernel, handle):
            self.assertIs(kernel, owner.kernel)
            owner.query_calls.append(handle)
            if len(owner.query_calls) > 32:
                raise RuntimeError('PURE_PROTOCOL_QUERY_BOUND')
            ok, active, error = responses[0]
            if len(responses) > 1:
                responses.pop(0)
            owner.events.append(('query', ok, active))
            return ok, SimpleNamespace(active_processes=active), error
        def snapshot(actual_owner, phase, observations):
            self.assertIs(actual_owner, owner)
            actual_owner._noise_diagnostic_handles = []
            observations.append({'phase': phase})
            owner.events.append(('snapshot', phase))
        with patch('tools.qa_decoder_noise_fixture._compiler_snapshot', side_effect=snapshot), \
                patch('tools.qa_decoder_noise_fixture._job_accounting', side_effect=query), \
                patch('tools.qa_decoder_noise_fixture.time.monotonic', side_effect=now), \
                patch('tools.qa_decoder_noise_fixture.time.sleep'):
            return _stop_completed_compiler_job(owner, build_deadline=build_deadline,
                                                observations=owner.observations)

    def assert_owner_still_owns_handles(self, owner, expected_job=101):
        self.assertEqual(owner.job, expected_job)
        self.assertFalse(owner._closed)
        self.assertTrue(owner.registered)
        self.assertEqual(owner.close_calls, [])
        self.assertEqual(owner.unregister_calls, 0)

    def test_live_nonzero_or_missing_job_cannot_be_stopped_as_successful_compilation(self):
        for worker_exit, job in ((None, 101), (1, 101), (0, None)):
            with self.subTest(worker_exit=worker_exit, job=job):
                owner = self.owner(worker_exit=worker_exit, job=job)
                with self.assertRaises(AssertionError) as caught:
                    self.invoke(owner, [(True, 0, 0)])
                self.assertEqual(caught.exception.compiler_planned_shutdown['status'], 'FAILED')
                self.assertEqual(owner.termination_calls, [])
                self.assertEqual(owner.query_calls, [])
                self.assertEqual(owner.observations, [])
                self.assert_owner_still_owns_handles(owner, job)

    def test_active_job_is_terminated_then_observed_empty_without_closing_owner(self):
        owner = self.owner()
        receipt = self.invoke(owner, [(True, 2, 0), (True, 1, 0), (True, 0, 0)])
        self.assertEqual(receipt['status'], 'COMPLETED')
        self.assertEqual(receipt['method'], 'PLANNED_OWNED_SDK_BACKGROUND_SHUTDOWN_AFTER_SUCCESSFUL_COMPILATION')
        self.assertTrue(receipt['termination_requested'])
        self.assertTrue(receipt['termination_succeeded'])
        self.assertEqual(receipt['active_job_processes_before_stop'], 2)
        self.assertEqual(receipt['active_job_processes_after_stop'], 0)
        self.assertFalse(receipt['natural_background_exit_claimed'])
        self.assertEqual(owner.termination_calls, [(101, 1)])
        self.assertTrue(all(handle == 101 for handle in owner.query_calls))
        self.assertLess(owner.events.index(('terminate', 101, 1)), owner.events.index(('query', True, 0)))
        self.assert_owner_still_owns_handles(owner)

    def test_already_empty_job_needs_no_termination_and_retains_its_owner(self):
        owner = self.owner()
        receipt = self.invoke(owner, [(True, 0, 0)])
        self.assertEqual(receipt['status'], 'COMPLETED')
        self.assertFalse(receipt['termination_requested'])
        self.assertIsNone(receipt['termination_succeeded'])
        self.assertEqual(owner.termination_calls, [])
        self.assertEqual(receipt['active_job_processes_after_stop'], 0)
        self.assert_owner_still_owns_handles(owner)

    def test_failed_termination_query_still_active_or_expired_deadline_cannot_pass(self):
        cases = [
            ('termination_false', 0, [(True, 2, 0)], 90),
            ('initial_query_failed', 1, [(False, 0, 5)], 90),
            ('query_failed_after_termination', 1, [(True, 2, 0), (False, 0, 5)], 90),
            ('still_active', 1, [(True, 2, 0)], 90),
            ('already_expired', 1, [(True, 0, 0)], 0),
        ]
        for label, termination_result, responses, deadline in cases:
            with self.subTest(fixture=label):
                owner = self.owner(termination_result=termination_result)
                with self.assertRaises(AssertionError) as caught:
                    self.invoke(owner, responses, build_deadline=deadline)
                receipt = caught.exception.compiler_planned_shutdown
                self.assertEqual(receipt['status'], 'FAILED')
                self.assertFalse(receipt['natural_background_exit_claimed'])
                self.assertNotEqual(receipt['active_job_processes_after_stop'], 0)
                self.assert_owner_still_owns_handles(owner)


class CompilerEnvironmentPolicyProtocolTests(unittest.TestCase):
    """Literal fake mappings only: no ambient environment or Windows evidence."""
    def test_normalizes_only_two_casefold_keys_without_mutating_or_filtering_parent_mapping(self):
        inherited = {
            'VSCMD_SKIP_SENDTELEMETRY': '0', 'vscmd_skip_sendtelemetry': 'false',
            'VCToolsTelemetryOptOut': '0', 'VCTOOLSTELEMETRYOPTOUT': 'false',
            'HTTP_PROXY': 'http://proxy.invalid:8080', 'NO_PROXY': 'example.invalid,localhost',
            'BB_FAKE_CREDENTIAL': 'LITERAL_TEST_VALUE_NOT_A_SECRET',
            'SSL_CERT_FILE': 'C:/fixtures/ca.pem', 'REQUESTS_CA_BUNDLE': 'C:/fixtures/ca-bundle.pem',
            'BB_FAKE_CA_GUARD': 'KEEP_LITERAL_CA_GUARD', 'EMPTY_UNRELATED': '',
            'Unrelated_miXeD': 'MiXeD-Value', 'VSCMD_SKIP_SENDTELEMETRY_extra': 'keep-suffix',
            'PrefixVCToolsTelemetryOptOut': 'keep-prefix', 'VCToolsTelemetryOptOut.Suffix': 'keep-dot-suffix',
        }
        before = dict(inherited)
        normalized = _compiler_worker_environment(inherited)
        policy = {'vscmd_skip_sendtelemetry', 'vctoolstelemetryoptout'}
        expected = {key: value for key, value in inherited.items() if key.casefold() not in policy}
        expected.update(VSCMD_SKIP_SENDTELEMETRY='1', VCToolsTelemetryOptOut='1')
        self.assertEqual(normalized, expected)
        self.assertEqual(_compiler_worker_environment(MappingProxyType(inherited)), expected)
        self.assertEqual(inherited, before)
        self.assertIsNot(normalized, inherited)
        for canonical in ('VSCMD_SKIP_SENDTELEMETRY', 'VCToolsTelemetryOptOut'):
            self.assertEqual([key for key in normalized if key.casefold() == canonical.casefold()], [canonical])
        _require_compiler_policy(normalized)

    def test_validator_accepts_one_exact_value_for_each_case_insensitive_key_without_mutation(self):
        for policy in ({'VSCMD_SKIP_SENDTELEMETRY': '1', 'VCToolsTelemetryOptOut': '1'},
                       {'vscmd_skip_sendtelemetry': '1', 'vctoolstelemetryoptout': '1'},
                       {'VsCmD_SkIp_SeNdTeLeMeTrY': '1', 'VcToOlStElEmEtRyOpToUt': '1'}):
            with self.subTest(keys=tuple(policy)):
                before = dict(policy)
                _require_compiler_policy(policy)
                self.assertEqual(policy, before)

    def test_validator_rejects_missing_conflicting_duplicate_and_near_match_policy(self):
        base = {'VSCMD_SKIP_SENDTELEMETRY': '1', 'VCToolsTelemetryOptOut': '1'}
        invalid = [{}, {'VSCMD_SKIP_SENDTELEMETRY': '1'}, {'VCToolsTelemetryOptOut': '1'},
            {**base, 'vscmd_skip_sendtelemetry': '1'},
            {**base, 'VCTOOLSTELEMETRYOPTOUT': '0'},
            {'VSCMD_SKIP_SENDTELEMETRY': '1', 'VCToolsTelemetryOptOut_typo': '1'}]
        for key in base:
            for value in ('0', 'true', '', ' 1', '1 '):
                invalid.append({**base, key: value})
        for number, environment in enumerate(invalid):
            with self.subTest(fixture=number):
                before = dict(environment)
                with self.assertRaisesRegex(AssertionError, 'NATIVE_NOISE_COMPILER_OPT_OUT_POLICY_UNCONFIRMED'):
                    _require_compiler_policy(environment)
                self.assertEqual(environment, before)

    def test_sdk_setup_updates_survive_reapplying_and_strictly_checking_fixed_policy(self):
        # Entirely literal SDK-return fixtures, never actual vcvars/compiler
        # execution or inspection of the host's environment.
        parent = {'Path': 'C:/fixtures/original-bin', 'VSCMD_SKIP_SENDTELEMETRY': '1',
            'VCToolsTelemetryOptOut': '1', 'HTTP_PROXY': 'http://proxy.invalid:8080',
            'BB_FAKE_CREDENTIAL': 'LITERAL_TEST_VALUE_NOT_A_SECRET',
            'SSL_CERT_FILE': 'C:/fixtures/ca.pem', 'BB_FAKE_CA_GUARD': 'KEEP_LITERAL_GUARD'}
        original_parent = dict(parent)
        sdk = {**parent, 'Path': 'C:/fixtures/SDK/bin;C:/fixtures/original-bin',
            'INCLUDE': 'C:/fixtures/SDK/include', 'LIB': 'C:/fixtures/SDK/lib',
            'VCToolsTelemetryOptOut': '0', 'vctoolstelemetryoptout': 'sdk-changed'}
        del sdk['VSCMD_SKIP_SENDTELEMETRY']  # Model a consumed setup-only flag.
        original_sdk = dict(sdk)
        with self.assertRaisesRegex(AssertionError, 'NATIVE_NOISE_COMPILER_OPT_OUT_POLICY_UNCONFIRMED'):
            _require_compiler_policy(sdk)
        compiler = 'C:/fixtures/SDK/bin/cl.exe'
        output = Path('SDK_SETUP_PROTOCOL_FIXTURE')
        with patch('tools.qa_decoder_noise_fixture.compiler_environment',
                   return_value=(compiler, MappingProxyType(sdk))) as setup, \
                patch('tools.qa_decoder_noise_fixture._require_compiler_policy',
                      wraps=_require_compiler_policy) as validator:
            actual_compiler, configured = _configured_compiler_environment(output)
        setup.assert_called_once_with(output)
        validator.assert_called_once_with(configured)
        self.assertIs(validator.call_args[0][0], configured)
        self.assertIs(actual_compiler, compiler)
        expected = {key: value for key, value in sdk.items()
                    if key.casefold() not in ('vscmd_skip_sendtelemetry', 'vctoolstelemetryoptout')}
        expected.update(VSCMD_SKIP_SENDTELEMETRY='1', VCToolsTelemetryOptOut='1')
        self.assertEqual(configured, expected)
        self.assertEqual(sdk, original_sdk)
        self.assertEqual(parent, original_parent)
        failure = AssertionError('NATIVE_NOISE_COMPILER_OPT_OUT_POLICY_UNCONFIRMED')
        with patch('tools.qa_decoder_noise_fixture.compiler_environment', return_value=(compiler, sdk)), \
                patch('tools.qa_decoder_noise_fixture._require_compiler_policy', side_effect=failure) as validator:
            with self.assertRaises(AssertionError) as caught:
                _configured_compiler_environment(output)
        self.assertIs(caught.exception, failure)
        validator.assert_called_once()


class ControlledBudgetProtocolTests(unittest.TestCase):
    """Protocol fixtures only; real rejection additionally requires hosted ETW."""
    def oracle(self):
        return {'schema': 'blackbox.scheduler-noise/1', 'status': 'COMPLETED', 'pid': 123,
            'created_100ns': '1000', 'pairs': PAIRS, 'stop_requested': True,
            'all_threads_joined': True, 'native_handles_created': 2 * PAIRS,
            'native_handles_closed': 2 * PAIRS, 'cleanup_required': False, 'errors': [],
            'qpc_frequency_hz': 10000000, 'workers': [
                {'tid': 100 + n, 'created_100ns': str(2000 + n), 'handoffs': 100,
                 'begin_qpc': 10, 'end_qpc': 1000} for n in range(2 * PAIRS)]}

    def test_noise_receipt_needs_every_join_handle_handoff_and_exact_process(self):
        validate_noise_oracle(self.oracle(), 123, '1000')
        for field, value in (('pid', 124), ('created_100ns', '1001'), ('all_threads_joined', False),
                             ('native_handles_closed', 2 * PAIRS - 1), ('stop_requested', False),
                             ('cleanup_required', True), ('errors', ['OWNED_EXIT_UNCONFIRMED'])):
            with self.subTest(field=field):
                oracle = self.oracle(); oracle[field] = value
                with self.assertRaises(AssertionError):
                    validate_noise_oracle(oracle, 123, '1000')
        oracle = self.oracle(); oracle['workers'][0]['handoffs'] = 0
        with self.assertRaisesRegex(AssertionError, 'REAL_HANDOFFS'):
            validate_noise_oracle(oracle, 123, '1000')

    def test_expected_prefix_alone_is_not_a_native_reproduction(self):
        meta = {'status': 'TRUNCATED', 'rows': 250000, 'input_sha256': 'a' * 64,
                'import_completeness': 'BOUNDED_PREFIX'}
        native = {'switch_rows': 12000, 'ready_rows': 12000, 'noise_tids_observed': 16,
                  'qpc_frequency_matches': True}
        validate_rejection(meta, 'a' * 64, native)
        for field, value in (('switch_rows', 0), ('ready_rows', 0),
                             ('noise_tids_observed', 0), ('qpc_frequency_matches', False)):
            with self.subTest(field=field), self.assertRaisesRegex(AssertionError, 'NATIVE_NOISE'):
                validate_rejection(meta, 'a' * 64, {**native, field: value})
        with self.assertRaisesRegex(AssertionError, 'NATIVE_NOISE'):
            validate_rejection(meta, 'a' * 64, {**native, 'switch_rows': 1, 'ready_rows': 1})
        for change in ({'status': 'DECODED'}, {'rows': 0}, {'input_sha256': 'b' * 64},
                       {'import_completeness': 'ALL_EMITTED_RECORDS'}):
            with self.subTest(change=change), self.assertRaisesRegex(AssertionError, 'REPRODUCTION_NOT_ESTABLISHED'):
                validate_rejection({**meta, **change}, 'a' * 64, native)

    def test_noise_child_cannot_take_parent_helper_or_source_arguments(self):
        self.assertTrue(parse_args(['--noise-child', '--output', 'own-noise-root']).noise_child)
        for arguments in (['--output', 'root'], ['--noise-child', '--output', 'root', '--helper', 'decoder'],
                          ['--noise-child', '--output', 'root', '--source-sha', 'a' * 40]):
            with self.subTest(arguments=arguments), redirect_stdout(io.StringIO()), \
                    patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit) as error:
                parse_args(arguments)
            self.assertEqual(error.exception.code, 2)

    def test_negative_prefix_still_requires_original_predecode_hash_and_size(self):
        diagnostic = {'schema': 'blackbox.decoder-app-trace-diagnostic/1',
            'source_sha256': 'a' * 64, 'source_bytes': 100, 'metadata_input_sha256_matches': True}
        self.assertEqual(validate_original_source(diagnostic, 'a' * 64, 100), {
            'source_sha256': 'a' * 64, 'source_bytes': 100, 'metadata_input_sha256_matches': True})
        for change in ({'source_sha256': 'b' * 64}, {'source_bytes': 101}, {'source_bytes': 100.0},
                       {'metadata_input_sha256_matches': False}):
            with self.subTest(change=change), self.assertRaisesRegex(AssertionError, 'ORIGINAL_SOURCE_CHANGED'):
                validate_original_source({**diagnostic, **change}, 'a' * 64, 100)

    def test_positive_case_requires_complete_decode_and_all_original_capabilities(self):
        result = {'status': 'PASS', 'capabilities': {key: 'PASS' for key in SEVENZIP_CAPABILITIES}}
        meta = {'status': 'DECODED', 'rows': 120, 'import_completeness': 'ALL_EMITTED_RECORDS'}
        validate_positive(result, meta)
        for capability in SEVENZIP_CAPABILITIES:
            with self.subTest(capability=capability), self.assertRaisesRegex(AssertionError, 'COMPLETE_ACCEPTANCE'):
                validate_positive({**result, 'capabilities': {**result['capabilities'], capability: 'FAIL_NOT_OBSERVED'}}, meta)
        with self.assertRaisesRegex(AssertionError, 'COMPLETE_ACCEPTANCE'):
            validate_positive(result, {**meta, 'status': 'TRUNCATED'})
        with self.assertRaisesRegex(AssertionError, 'COMPLETE_ACCEPTANCE'):
            validate_positive({'status': 'PASS', 'capabilities': {}}, meta)

    def test_progress_requires_exact_child_identity_and_monotonic_real_counters(self):
        ready = {**self.oracle(), 'source_sha256': 'c' * 64, 'begin_qpc': 10}
        progress = {'schema': 'blackbox.scheduler-noise-progress/1', 'pid': 123, 'created_100ns': '1000',
            'source_sha256': 'c' * 64, 'qpc_frequency_hz': 10000000, 'sequence': 1, 'qpc': 20,
            'sample_begin_qpc': 19, 'sample_end_qpc': 20,
            'workers': [{'tid': 100 + n, 'handoffs': 100} for n in range(2 * PAIRS)], 'total_handoffs': 1600}
        validate_progress(progress, ready)
        validate_progress(progress, ready, progress)  # Polling the same immutable receipt is idempotent.
        for change in ({'pid': 124}, {'created_100ns': '1001'}, {'source_sha256': 'd' * 64},
                       {'qpc_frequency_hz': 1000}, {'qpc_frequency_hz': True}, {'sequence': 10000},
                       {'total_handoffs': 1599}, {'sample_begin_qpc': 21}, {'sample_end_qpc': 19},
                       {'sample_begin_qpc': 19.0}):
            with self.subTest(change=change), self.assertRaisesRegex(AssertionError, 'PROGRESS_IDENTITY'):
                validate_progress({**progress, **change}, ready)
        regressed = json.loads(json.dumps(progress))
        regressed['sequence'] = 2; regressed['qpc'] = 30
        regressed['sample_begin_qpc'] = 29; regressed['sample_end_qpc'] = 30
        regressed['workers'][0]['handoffs'] -= 1
        regressed['workers'][1]['handoffs'] += 1
        with self.assertRaisesRegex(AssertionError, 'PROGRESS_REGRESSED'):
            validate_progress(regressed, ready, progress)
        with self.assertRaisesRegex(AssertionError, 'SAMPLE_OVERLAP'):
            validate_progress({**progress, 'sequence': 2, 'sample_begin_qpc': 19}, ready, progress)

    def test_ab_admission_refuses_less_noise_fewer_roundtrips_or_source_changes(self):
        budget = {'workload_policy': 'CONTROLLED_NATIVE_90', 'requested_process_timeout_seconds': 90,
            'requested_minimum_roundtrips': 1, 'roundtrips_verified': 2,
            'workloads': [{'pid': 100 + n, 'role': 'COMPRESS' if n % 2 == 0 else 'EXTRACT', 'cycle': n // 2,
                'configured_timeout_seconds': 90, 'elapsed_monitor_seconds': 31 if n % 2 == 0 else .5,
                'exit_code': 0} for n in range(4)]}
        common = {'input_sha256': 'a' * 64, 'input_bytes': 8 * 1024**2, 'application_sha256': 'b' * 64,
            'native_image': {'code_kind': 'NATIVE_PE_NO_CLR_COM_DESCRIPTOR'}, 'helper_sha256': 'c' * 64,
            'script_hashes': {'driver': 'd' * 64},
            'actual_native_module_encoding': 'PER_EVENT_MODULES_V1',
            'requested_workload_policy': 'CONTROLLED_NATIVE_90', 'requested_process_timeout_seconds': 90,
            'requested_minimum_roundtrips': 1, 'requested_minimum_prelude_seconds': 0,
            'workload_budget': budget,
            'requested_noise_policy': {'implementation': 'NATIVE_WIN32', 'ttl_seconds': 210,
                                       'progress_limit': 841, 'owner_seconds': 225},
            'noise_policy_receipts': {phase: {'implementation': 'NATIVE_WIN32', 'ttl_seconds': 210, 'progress_limit': 841}
                                      for phase in ('ready', 'oracle')},
            'native_timing': {'ready_qpc': 0, 'work_begin_qpc': 10000, 'work_end_qpc': 74000, 'qpc_frequency_hz': 1000},
            'noise_producer': {'implementation': 'NATIVE_WIN32', 'source_sha256': '3' * 64,
                               'executable_sha256': '4' * 64, 'expected_native_handles': 32},
            'source_identity': {'actual_source_sha': 'e' * 40, 'source_tree_sha': 'f' * 40},
            'noise_cleanup': {'status': 'COMPLETED'}, 'capture_cleanup': {'status': 'STOPPED'},
            'noise_workload_coverage': {'all_16_threads_bracket': True, 'threads_with_positive_handoff_delta': 16},
            'roundtrips_verified': 2}
        first = {**common, 'status': 'EXPECTED_NATIVE_BUDGET_NEGATIVE', 'noise_handoffs': 10000,
            'prelude': {'target_handoffs': 0, 'requested_minimum_seconds': 0, 'wait_seconds': 0, 'status': 'NOT_REQUIRED'},
            'capture_profile': {'name': 'schedule', 'xml_sha256': '1' * 64}}
        second = {**common, 'status': 'COMPLETE_7ZIP_ACCEPTANCE', 'noise_handoffs': 20000,
            'requested_minimum_roundtrips': 2,
            'workload_budget': {**budget, 'requested_minimum_roundtrips': 2},
            'capture_profile': {'name': 'cpu_file', 'xml_sha256': '2' * 64},
            'prelude': {'target_handoffs': 10000, 'observed_handoffs': 11000,
                        'requested_minimum_seconds': 0, 'wait_seconds': 1, 'status': 'COMPLETED'}}
        validate_comparison(first, second)
        for change in ({'noise_handoffs': 9999}, {'roundtrips_verified': 1}, {'application_sha256': '0' * 64},
                       {'noise_workload_coverage': {'all_16_threads_bracket': False}},
                       {'prelude': {**second['prelude'], 'wait_seconds': 66}},
                       {'requested_workload_policy': 'ORDINARY_30'}, {'requested_process_timeout_seconds': 30},
                       {'requested_noise_policy': {**common['requested_noise_policy'], 'ttl_seconds': 210.0}},
                       {'requested_noise_policy': {**common['requested_noise_policy'], 'owner_seconds': 225.0}},
                       {'requested_noise_policy': {**common['requested_noise_policy'], 'progress_limit': 841.0}},
                       {'requested_noise_policy': {**common['requested_noise_policy'], 'extra': 'PRIVATE_PATH'}},
                       {'noise_policy_receipts': {**common['noise_policy_receipts'],
                            'oracle': {**common['noise_policy_receipts']['oracle'], 'progress_limit': 841.0}}},
                       {'native_timing': {**common['native_timing'], 'work_end_qpc': 106000}},
                       {'workload_budget': {**budget, 'requested_minimum_roundtrips': 2,
                            'workloads': [budget['workloads'][0],
                            {**budget['workloads'][1], 'configured_timeout_seconds': 30}, *budget['workloads'][2:]]}}):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                validate_comparison(first, {**second, **change})

    def test_workload_policy_requires_actual_budget_and_duration_of_every_returned_process(self):
        workload = {'workload_policy': 'CONTROLLED_NATIVE_90', 'requested_process_timeout_seconds': 90,
            'requested_minimum_roundtrips': 1, 'roundtrips_verified': 1,
            'workloads': [{'pid': 100 + n, 'role': 'COMPRESS' if n == 0 else 'EXTRACT', 'cycle': 0,
                'configured_timeout_seconds': 90, 'elapsed_monitor_seconds': 31 if n == 0 else .5,
                'exit_code': 0} for n in range(2)]}
        observed = validate_workload_budget(workload, 'CONTROLLED_NATIVE_90')
        self.assertEqual(observed['workloads'][0]['elapsed_monitor_seconds'], 31)
        self.assertEqual(observed['monitor_duration_scope'], 'OBSERVED_MONITOR_DURATION_NOT_HARD_OS_DEADLINE')
        for change in ({'configured_timeout_seconds': 30}, {'configured_timeout_seconds': 90.0},
                       {'elapsed_monitor_seconds': None}, {'elapsed_monitor_seconds': float('nan')},
                       {'pid': 'PRIVATE_PATH'}, {'pid': True}, {'pid': 0}, {'pid': 2**32},
                       {'exit_code': False},
                       {'exit_code': 1}, {'role': 'COMPRESS'}, {'cycle': 1}):
            bad = {**workload, 'workloads': [workload['workloads'][0], {**workload['workloads'][1], **change}]}
            with self.subTest(change=change), self.assertRaisesRegex(AssertionError, 'WORKLOAD_BUDGET_NOT_OBSERVED'):
                validate_workload_budget(bad, 'CONTROLLED_NATIVE_90')

    def test_each_noise_thread_must_make_real_handoffs_inside_workload_interval(self):
        first = {'sequence': 1, 'qpc': 20, 'sample_begin_qpc': 19, 'sample_end_qpc': 20,
                 'qpc_frequency_hz': 10000000,
                 'workers': [{'tid': 100 + n, 'handoffs': 100} for n in range(16)]}
        last = {'sequence': 2, 'qpc': 30, 'sample_begin_qpc': 29, 'sample_end_qpc': 30,
                'qpc_frequency_hz': 10000000,
                'workers': [{'tid': 100 + n, 'handoffs': 101} for n in range(16)]}
        clock = {'begin_qpc': 10, 'end_qpc': 40, 'qpc_frequency_hz': 10000000}
        self.assertEqual(validate_workload_activity(first, last, clock)['threads_with_positive_handoff_delta'], 16)
        with self.assertRaisesRegex(AssertionError, 'ALL_THREADS_ACTIVE'):
            validate_workload_activity(first, {**last, 'qpc': 50, 'sample_end_qpc': 50}, clock)
        for start, end in (({**first, 'sample_begin_qpc': 9}, last),
                           (first, {**last, 'sample_end_qpc': 41}),
                           ({**first, 'sample_begin_qpc': 10}, last),
                           (first, {**last, 'sample_end_qpc': 40})):
            # The former single qpc point is still inside [10, 40]. The
            # counter-copy interval crosses the boundary and must be rejected.
            with self.subTest(start=start['sample_begin_qpc'], end=end['sample_end_qpc']), \
                    self.assertRaisesRegex(AssertionError, 'ALL_THREADS_ACTIVE'):
                validate_workload_activity(start, end, clock)
        last['workers'][0]['handoffs'] = 100
        with self.assertRaisesRegex(AssertionError, 'ALL_THREADS_ACTIVE'):
            validate_workload_activity(first, last, clock)

    def test_negative_contracts_require_real_observer_footer_and_distinct_limits(self):
        meta = {'status': 'TRUNCATED', 'rows': 250000, 'input_sha256': 'a' * 64,
                'import_completeness': 'BOUNDED_PREFIX'}
        native = {'switch_rows': 12000, 'ready_rows': 12000, 'noise_tids_observed': 16,
                  'qpc_frequency_matches': True}
        output = {'status': 'OBSERVED', 'helper_exit_code': 0, 'output_bytes': 100,
                  'output_sha256': 'b' * 64, 'footer': {'status': 'TRUNCATED', 'rows': 250000}}
        value = {'schema': 'blackbox.native-output-observation/1', 'processes': [output]}
        self.assertEqual(validate_output_observation(value, meta), output)
        self.assertEqual(validate_case_contract('ROW_BUDGET_NEGATIVE', True, None, meta, 'a' * 64, native, output),
                         'EXPECTED_ROW_BUDGET_NEGATIVE')
        self.assertEqual(validate_case_contract('NATIVE_BUDGET_NEGATIVE', True, None, meta, 'a' * 64, native, output),
                         'EXPECTED_NATIVE_BUDGET_NEGATIVE')
        with self.assertRaisesRegex(AssertionError, 'OUTPUT_LIMIT_NOT_REACHED'):
            validate_case_contract('OUTPUT_BUDGET_NEGATIVE', True, None, meta, 'a' * 64, native, output)
        byte_meta = {**meta, 'rows': 139635}
        byte_output = {**output, 'output_bytes': 384 * 1024**2 + 100,
                       'footer': {'status': 'TRUNCATED', 'rows': 139635}}
        self.assertEqual(validate_case_contract('OUTPUT_BUDGET_NEGATIVE', True, None, byte_meta,
            'a' * 64, native, byte_output), 'EXPECTED_OUTPUT_BUDGET_NEGATIVE')
        with self.assertRaisesRegex(AssertionError, 'NATIVE_ROW_LIMIT_NOT_REACHED'):
            validate_case_contract('NATIVE_BUDGET_NEGATIVE', True, None, byte_meta, 'a' * 64, native, byte_output)
        with self.assertRaisesRegex(AssertionError, 'REJECTION_NOT_OBSERVED'):
            validate_case_contract('OUTPUT_BUDGET_NEGATIVE', False, None, byte_meta, 'a' * 64, native, byte_output)
        with self.assertRaisesRegex(AssertionError, 'OBSERVATION_UNCONFIRMED'):
            validate_output_observation({'schema': value['schema'], 'processes': [{**output, 'helper_exit_code': 1}]}, meta)
        with self.assertRaisesRegex(AssertionError, 'OBSERVATION_UNCONFIRMED'):
            validate_output_observation(value, byte_meta)


class NativeOutputAndRetentionProtocolTests(unittest.TestCase):
    """Only file/protocol fixtures; actual decoder/Windows evidence comes from CI."""
    def test_observer_accepts_only_default_or_exact_explicit_inline_argv(self):
        self.assertEqual(native_output_path(['helper.exe', 'input.etl', 'decoded.jsonl']), Path('decoded.jsonl'))
        self.assertEqual(native_output_path(['helper.exe', 'input.etl', 'decoded.jsonl', '--inline-modules']),
                         Path('decoded.jsonl'))
        for argv in (['helper.exe', 'input.etl'], ['helper.exe', 'input.etl', 'decoded.jsonl', '--other'],
                     ['helper.exe', 'input.etl', 'decoded.jsonl', '--INLINE-MODULES'],
                     ['helper.exe', 'input.etl', 'decoded.jsonl', '--inline-modules', 'extra']):
            with self.subTest(arity=len(argv), last=argv[-1]):
                self.assertIsNone(native_output_path(argv))

    def test_partial_failure_facts_preserve_primary_error_and_exclude_paths_payload_and_args(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); work = root / '7zip'; work.mkdir()
            helper = root / 'helper.exe'; helper.write_bytes(b'explicit non-executable hash fixture')
            (work / 'input.bin').write_bytes(b'explicit input fixture')
            (work / 'decoder-summary.json').write_text(json.dumps({'status': 'TRUNCATED', 'rows': 5,
                'input_sha256': 'a' * 64, 'payload': 'PRIVATE_PAYLOAD', 'path': str(root)}), encoding='utf-8')
            (work / 'workload-oracle.json').write_text(json.dumps({'input_sha256': 'b' * 64, 'input_bytes': 8,
                'roundtrips_verified': 1, 'application': {'sha256': 'c' * 64, 'path': str(helper)},
                'workloads': [{'pid': 123, 'creation_time_filetime_ticks': '1000', 'exit_code': 0,
                    'owned_image_matches_requested': True, 'args': ['PRIVATE_ARG'], 'observed_image': str(helper)}]}),
                encoding='utf-8')
            proof = {'status': 'REPRODUCTION_NOT_ESTABLISHED', 'reason_code': 'ORIGINAL_OBSERVER_FAILURE'}
            collect_bounded_case_facts(proof, work, helper, {'begin_qpc': 10, 'qpc_frequency_hz': 10000000})
            self.assertEqual(proof['reason_code'], 'ORIGINAL_OBSERVER_FAILURE')
            self.assertEqual(proof['small_facts']['summary']['rows'], 5)
            self.assertEqual(proof['small_facts']['workload']['owned_processes'][0]['creation_time_filetime_ticks'], '1000')
            self.assertEqual(proof['small_facts']['workload_qpc_bounds']['end_qpc'], 'NOT_ESTABLISHED')
            self.assertEqual(proof['small_facts']['actual_input_file']['bytes'], len(b'explicit input fixture'))
            for private in (str(root), str(helper), 'PRIVATE_PAYLOAD', 'PRIVATE_ARG'):
                self.assertNotIn(private, json.dumps(proof))
            missing = {'reason_code': 'ORIGINAL_CAPTURE_FAILURE'}
            collect_bounded_case_facts(missing, root / 'absent', helper, {})
            self.assertEqual(missing['reason_code'], 'ORIGINAL_CAPTURE_FAILURE')
            self.assertEqual(missing['small_facts']['summary'], 'NOT_ESTABLISHED')
            self.assertIn('workload', missing['fact_errors'])

    def test_observer_measures_actual_file_bytes_hash_and_footer_without_payload_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'private-output.jsonl'
            payload = (b'{"type":"header","secret":"PRIVATE_PAYLOAD"}\n' +
                json.dumps({'type': 'footer', 'protocol': 'blackbox.trace-event/1',
                            'status': 'TRUNCATED', 'rows': 5}).encode() + b'\n')
            path.write_bytes(payload)
            observed = observe_native_output(path)
            self.assertEqual(observed['status'], 'OBSERVED')
            self.assertEqual(observed['output_bytes'], len(payload))
            self.assertEqual(observed['output_sha256'], hashlib.sha256(payload).hexdigest())
            self.assertNotIn('PRIVATE_PAYLOAD', json.dumps(observed))
            self.assertNotIn(str(path), json.dumps(observed))
            path.write_bytes(b'no completion footer\n')
            broken = observe_native_output(path)
            self.assertEqual(broken['status'], 'UNCONFIRMED')
            self.assertEqual(broken['output_bytes'], path.stat().st_size)
            self.assertIn('observation_error_code', broken)

    def test_only_hashed_owned_large_files_are_removed_after_verified_seal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); work = root / '7zip'; work.mkdir()
            source = work / 'trace-owned.etl'; index = work / 'decoded.sqlite3'
            source.write_bytes(b'explicit ETL file fixture'); index.write_bytes(b'explicit index file fixture')
            original = work / 'input.bin'; original.write_bytes(b'preserved QA input')
            proof = {'status': 'REPRODUCTION_NOT_ESTABLISHED', 'noise_cleanup': {'status': 'COMPLETED'},
                'capture_cleanup': {'status': 'STOPPED'}, 'native_output': {'helper_exit_code': 0},
                'evidence': {name: {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                                    'bytes': path.stat().st_size} for name, path in (('etl', source), ('index', index))}}
            seal_and_remove_large_evidence(root, work, source, index, proof)
            self.assertFalse(source.exists()); self.assertFalse(index.exists())
            self.assertEqual(original.read_bytes(), b'preserved QA input')
            self.assertTrue((root / 'case-sealed.json').is_file())
            self.assertEqual(proof['evidence_retention']['status'], 'OWNED_QA_EVIDENCE_HASHED_THEN_REMOVED')
            self.assertEqual(proof['evidence_retention']['removed'], ['etl', 'index'])

    def test_unconfirmed_resources_cannot_delete_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / 'trace.etl'; index = root / 'decoded.sqlite3'
            source.write_bytes(b'keep'); index.write_bytes(b'keep')
            with self.assertRaisesRegex(AssertionError, 'RESOURCE_CLEANUP_UNCONFIRMED'):
                seal_and_remove_large_evidence(root, root, source, index, {
                    'noise_cleanup': {'status': 'UNCONFIRMED'}, 'capture_cleanup': {'status': 'STOPPED'},
                    'native_output': {'helper_exit_code': 0}})
            self.assertTrue(source.is_file()); self.assertTrue(index.is_file())

    def test_wrong_hash_cannot_delete_owned_or_other_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); work = root / '7zip'; work.mkdir()
            source = work / 'trace.etl'; index = work / 'decoded.sqlite3'; outside = root / 'user-input.etl'
            for path in (source, index, outside):
                path.write_bytes(b'preserve on unconfirmed hash')
            proof = {'noise_cleanup': {'status': 'COMPLETED'}, 'capture_cleanup': {'status': 'STOPPED'},
                'native_output': {'helper_exit_code': 0}, 'evidence': {
                    name: {'sha256': '0' * 64, 'bytes': path.stat().st_size}
                    for name, path in (('etl', source), ('index', index))}}
            with self.assertRaisesRegex(AssertionError, 'HASH_CHANGED'):
                seal_and_remove_large_evidence(root, work, source, index, proof)
            for path in (source, index, outside):
                self.assertTrue(path.is_file())


class IndexAttributionProtocolTests(unittest.TestCase):
    """Stored-row fixtures exercise scopes and ambiguity, never native capture."""
    def test_stack_counts_are_partitioned_and_bytes_explicitly_derived(self):
        frame = {'name': 'PRIVATE_FRAME_Ж'}
        rows = [{'pid': 11, 'process_instance': 1, 'frames': [frame]},
                {'pid': 22, 'process_instance': 2, 'frames': [frame, frame]},
                {'pid': -1, 'process_instance': None, 'frames': []}]
        with tempfile.TemporaryDirectory() as tmp:
            index = Path(tmp) / 'index.sqlite3'
            with closing(sqlite3.connect(index)) as db:
                db.execute('CREATE TABLE events(data TEXT)')
                db.executemany('INSERT INTO events VALUES(?)', [(json.dumps(row),) for row in rows])
                db.commit()
            result = native_attribution(index, {'rows': 3, 'engine': {'trace_counter_frequency_hz': 10}},
                {'pid': 22, 'qpc_frequency_hz': 10, 'workers': []}, time.monotonic() + 5, [11])
            stats = result['stack_attribution']; groups = stats['groups']
            self.assertEqual(groups['target_application']['frames'], 1)
            self.assertEqual(groups['owned_noise']['frames'], 2)
            self.assertEqual(groups['unattributed']['rows'], 1)
            self.assertIn('NOT_ACTUAL_NATIVE_JSONL', stats['byte_scope'])
            self.assertGreater(groups['target_application']['derived_index_frame_json_bytes'], 0)
            self.assertNotIn('PRIVATE_FRAME', json.dumps(stats))
            with closing(sqlite3.connect(index)) as db:
                db.execute('INSERT INTO events VALUES(?)', (json.dumps({**rows[0], 'process_instance': 3}),))
                db.commit()
            reused = native_attribution(index, {'rows': 4, 'engine': {'trace_counter_frequency_hz': 10}},
                {'pid': 22, 'qpc_frequency_hz': 10, 'workers': []}, time.monotonic() + 5, [11])
            self.assertIn(11, reused['stack_attribution']['ambiguous_known_pids'])
            self.assertEqual(reused['stack_attribution']['groups']['target_application']['rows'], 0)


class FixedQaProfileTests(unittest.TestCase):
    def test_cpu_file_profile_preserves_native_oracle_sources_and_buffer_limits(self):
        tools = Path(__file__).resolve().parents[1] / 'tools'
        schedule = ET.parse(tools / profile_definition('schedule')[0]).getroot()
        focused = ET.parse(tools / profile_definition('cpu_file')[0]).getroot()
        keywords = lambda root: {item.attrib['Value'] for item in root.findall('.//SystemProvider/Keywords/Keyword')}
        expected = {'ProcessThread', 'Loader', 'SampledProfile', 'FileIO', 'FileIOInit', 'DiskIO', 'DiskIOInit'}
        self.assertEqual(keywords(focused), expected)
        self.assertEqual(keywords(schedule), expected | {'CSwitch', 'ReadyThread'})
        for root in (schedule, focused):
            self.assertEqual([item.attrib['Value'] for item in root.findall('.//Stacks/Stack')], ['SampledProfile'])
            self.assertEqual(root.find('.//SystemCollector/BufferSize').attrib['Value'], '128')
            self.assertEqual(root.find('.//SystemCollector/Buffers').attrib['Value'], '256')
            self.assertEqual(root.find('.//Profile').attrib['LoggingMode'], 'Memory')

    def test_fixed_profile_map_rejects_untrusted_wpr_expressions_and_non_string_values(self):
        for value in ('CPU.Verbose', 'schedule!OtherProfile', '../cpu_file', '', None, True, []):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'UNKNOWN_FIXED_QA_CAPTURE_PROFILE'):
                profile_definition(value)


class ApplicationTraceDiagnosticTests(unittest.TestCase):
    def exercise_decode(self, *, status="DECODED", rows=12, metadata_hash=None,
                        changed_source=False, expected_failure=None, hostile_counts=False,
                        native_module_encoding=None):
        # This is an explicit metadata-handling regression. decode_file is
        # mocked; actual ETW/EventPipe and third-party workloads remain CI gates.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "PRIVATE_PATH_MUST_NOT_APPEAR_IN_LOGS.etl"
            original = b"explicit trace-metadata fixture, not actual ETW"
            source.write_bytes(original)
            digest = hashlib.sha256(original).hexdigest()
            output = root / "7zip"
            output.mkdir()
            summary_path = root / "isolated-job-summary.txt"
            meta = {"status": status, "rows": rows,
                "input_sha256": digest if metadata_hash is None else metadata_hash,
                "import_completeness": "BOUNDED_PREFIX" if status == "TRUNCATED" else "ALL_EMITTED_RECORDS",
                "decoder_reported_lost_events": None, "events_with_stacks": 7,
                "events_with_errors": 0, "bounded_events": 1,
                "reliability": {"event_limit": 250000},
                "engine": {"protocol": "blackbox.trace-event/1"},
                "profiles": {"private_note": "PRIVATE_METADATA_MUST_NOT_APPEAR_IN_LOGS"}}
            if native_module_encoding is not None:
                meta['engine']['frame_module_encoding'] = native_module_encoding
            if hostile_counts:
                meta.update(events_with_stacks="PRIVATE_COUNTER_MUST_NOT_APPEAR_IN_LOGS",
                            events_with_errors=True, bounded_events=2**100)
                meta["reliability"] = {"event_limit": -1}

            def decoded(*args, **kwargs):
                if changed_source:
                    source.write_bytes(b"different original source bytes")
                return meta

            terminal = io.StringIO()
            helper = root / "decoder-helper.exe"
            result = None
            options = {'native_module_encoding': native_module_encoding} if native_module_encoding is not None else {}
            with patch("tools.qa_decoder_apps.decode_file", side_effect=decoded) as decoder, \
                    patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary_path)}), \
                    redirect_stdout(terminal):
                if expected_failure:
                    with self.assertRaisesRegex(AssertionError, expected_failure):
                        decode_trace(source, output, helper, **options)
                else:
                    result = decode_trace(source, output, helper, **options)
            decoder.assert_called_once_with(source, output / "decoded.sqlite3", timeout=90, **options)
            self.assertEqual(json.loads((output / "decoder-summary.json").read_text(encoding="utf-8")), meta)
            diagnostic = json.loads((output / "decoder-diagnostic.json").read_text(encoding="utf-8"))
            logged = terminal.getvalue()
            self.assertTrue(logged.startswith("THIRD_PARTY_DECODER_TRACE_DETAIL "))
            self.assertEqual(json.loads(logged.split(" ", 1)[1]), diagnostic)
            summary = summary_path.read_text(encoding="utf-8")
            self.assertEqual(json.loads(summary.split("Third-party trace decode ", 1)[1]), diagnostic)
            for private in (str(source), str(root), "PRIVATE_PATH", "PRIVATE_METADATA", "PRIVATE_COUNTER"):
                self.assertNotIn(private, logged + summary + json.dumps(diagnostic))
            self.assertEqual(diagnostic["source_sha256"], digest)
            self.assertEqual(diagnostic["source_bytes"], len(original))
            self.assertEqual(diagnostic["decoder_status"], status)
            self.assertEqual(diagnostic["rows"], rows)
            return result, meta, diagnostic

    def test_complete_trace_keeps_full_metadata_and_emits_safe_diagnostic(self):
        result, meta, diagnostic = self.exercise_decode(hostile_counts=True)
        self.assertIs(result[1], meta)
        self.assertTrue(diagnostic["metadata_input_sha256_matches"])
        self.assertEqual(diagnostic["application"], "7-Zip")
        self.assertEqual(diagnostic["source_format"], ".etl")
        for field in ("events_with_stacks", "events_with_errors", "bounded_events", "event_limit"):
            self.assertIsNone(diagnostic[field])

    def test_explicit_native_transport_is_forwarded_and_reported_without_changing_default_kwargs(self):
        for encoding in ('INLINE_V1', 'PER_EVENT_MODULES_V1'):
            with self.subTest(encoding=encoding):
                _, _, diagnostic = self.exercise_decode(native_module_encoding=encoding)
                self.assertEqual(diagnostic['requested_native_module_encoding'], encoding)
                self.assertEqual(diagnostic['actual_native_module_encoding'], encoding)
        _, _, default = self.exercise_decode()
        self.assertEqual(default['requested_native_module_encoding'], 'DEFAULT')
        self.assertEqual(observed_module_encoding({'engine': {}}), 'INLINE_V1')

    def test_truncated_trace_remains_failure_and_saves_actual_prefix_metadata(self):
        _, _, diagnostic = self.exercise_decode(status="TRUNCATED", rows=250000,
            expected_failure="APP_TRACE_NOT_COMPLETELY_DECODED")
        self.assertEqual(diagnostic["import_completeness"], "BOUNDED_PREFIX")
        self.assertEqual(diagnostic["event_limit"], 250000)

    def test_zero_decoded_rows_remain_failure_with_saved_diagnostic(self):
        self.exercise_decode(rows=0, expected_failure="APP_TRACE_NOT_COMPLETELY_DECODED")

    def test_metadata_hash_mismatch_remains_failure(self):
        _, _, diagnostic = self.exercise_decode(metadata_hash="f" * 64,
            expected_failure="APP_TRACE_HASH_CHANGED")
        self.assertFalse(diagnostic["metadata_input_sha256_matches"])

    def test_changed_original_still_fails_and_reports_original_hash_and_size(self):
        self.exercise_decode(changed_source=True, expected_failure="APP_TRACE_HASH_CHANGED")


class ApplicationImageIdentityTests(unittest.TestCase):
    def test_explicit_application_precedes_path_shim_and_owns_observed_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            native = root / "program-files-7z.exe"
            shim = root / "chocolatey-7z.exe"
            native.write_bytes(b"native-file-identity-fixture")
            shim.write_bytes(b"launcher-file-identity-fixture")
            with patch("tools.qa_decoder_apps.shutil.which", return_value=str(shim)):
                self.assertEqual(installed("7z", [native]), native.resolve())
            with self.assertRaisesRegex(AssertionError, "OWNED_PROCESS_IMAGE_MISMATCH"):
                observed_process_image(shim, native)
            self.assertEqual(observed_process_image(native, native), str(native.resolve()))

    def pe_header_fixture(self, *, magic=0x20B, managed=False, dll=False):
        # Explicit binary-format fixture only; never executed and never
        # presented as acceptance of an actual Windows application.
        directory_at = 112 if magic == 0x20B else 96
        optional_size = directory_at + 16 * 8
        data = bytearray(128 + 24 + optional_size)
        data[:2] = b"MZ"; struct.pack_into("<I", data, 60, 128)
        data[128:132] = b"PE\0\0"
        struct.pack_into("<H", data, 132, 0x8664 if magic == 0x20B else 0x14C)
        struct.pack_into("<HH", data, 148, optional_size, 0x2002 if dll else 0x2)
        struct.pack_into("<H", data, 152, magic)
        struct.pack_into("<I", data, 152 + directory_at - 4, 16)
        if managed:
            struct.pack_into("<II", data, 152 + directory_at + 14 * 8, 0x2000, 72)
        return data

    def test_clr_launcher_cannot_certify_native_application_for_either_pe_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "image.exe"
            for magic in (0x10B, 0x20B):
                with self.subTest(magic=magic):
                    binary.write_bytes(self.pe_header_fixture(magic=magic, managed=True))
                    with self.assertRaisesRegex(AssertionError, "CLR_LAUNCHER_OR_MANAGED_IMAGE_REJECTED"):
                        native_pe_identity(binary)
                    binary.write_bytes(self.pe_header_fixture(magic=magic))
                    proof = native_pe_identity(binary)
                    self.assertEqual(proof["code_kind"], "NATIVE_PE_NO_CLR_COM_DESCRIPTOR")
                    self.assertEqual(proof["clr_com_descriptor_bytes"], 0)

    def test_truncated_header_and_dll_do_not_count_as_native_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "image.exe"
            for data in (b"MZ", self.pe_header_fixture()[:-1], self.pe_header_fixture(dll=True)):
                with self.subTest(length=len(data)):
                    binary.write_bytes(data)
                    with self.assertRaises(AssertionError):
                        native_pe_identity(binary)


class ApplicationLifetimeEvidenceTests(unittest.TestCase):
    def observations(self, rows, pids):
        # Explicit protocol fixture: this exercises acceptance proof handling,
        # not Windows ETW capture or third-party application execution.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "observations.sqlite3"
            with closing(sqlite3.connect(path)) as db:
                db.execute("CREATE TABLE events(data TEXT NOT NULL)")
                db.executemany("INSERT INTO events VALUES (?)",
                               [(json.dumps(row),) for row in rows])
                db.commit()
            return etw_observations(path, pids)

    def test_absent_or_missing_pid_identity_is_not_lifetime_evidence(self):
        for rows in ([], [{"pid": 10}], [{"pid": 10, "process_instance": 1}]):
            with self.subTest(rows=rows):
                observed = self.observations(rows, [10, 20])
                self.assertFalse(observed["pid_reuse_ambiguous"])
                self.assertFalse(observed["pid_lifetimes_confirmed"])
        self.assertFalse(self.observations([], [])["pid_lifetimes_confirmed"])

    def test_each_owned_pid_needs_one_unique_observed_lifetime(self):
        rows = [{"pid": 10, "process_instance": 0},
                {"pid": 20, "process_instance": 1},
                {"pid": 20, "process_instance": 1}]
        self.assertTrue(self.observations(rows, [10, 20])["pid_lifetimes_confirmed"])
        rows.append({"pid": 10, "process_instance": 2})
        observed = self.observations(rows, [10, 20])
        self.assertTrue(observed["pid_reuse_ambiguous"])
        self.assertFalse(observed["pid_lifetimes_confirmed"])


class ApplicationArchiveBoundaryTests(unittest.TestCase):
    def archive(self, root, entries):
        path = root / "app.zip"
        with zipfile.ZipFile(path, "w") as z:
            for name, value in entries:
                z.writestr(name, value)
        return path

    def test_complete_validation_precedes_any_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = self.archive(root, [("notepad++.exe", b"owned-fixture"),
                                          ("../outside", b"not allowed")])
            with self.assertRaisesRegex(AssertionError, "UNSAFE_APP_ARCHIVE"):
                safe_extract(archive, root / "output")
            self.assertFalse((root / "output").exists())
            self.assertFalse((root / "outside").exists())

    def test_windows_case_collision_and_file_directory_conflict_rejected(self):
        for entries in [[("App.exe", b"a"), ("app.exe", b"b")],
                        [("assets", b"a"), ("assets/one", b"b")]]:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with self.assertRaises(AssertionError):
                    safe_extract(self.archive(root, entries), root / "output")
                self.assertFalse((root / "output").exists())

    def test_link_member_rejected_without_writing_earlier_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            symlink = zipfile.ZipInfo("link")
            symlink.create_system = 3
            symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive = self.archive(root, [("notepad++.exe", b"owned-fixture"),
                                          (symlink, "../../escape")])
            with self.assertRaisesRegex(AssertionError, "UNSAFE_APP_ARCHIVE"):
                safe_extract(archive, root / "output")
            self.assertFalse((root / "output").exists())

    def test_fixed_payload_retains_runtime_and_omits_active_updater_plugins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = self.archive(root, [("notepad++.exe", b"owned-fixture"),
                                          ("localization/english.xml", b"text"),
                                          ("updater/gup.exe", b"not executed"),
                                          ("plugins/Plugin.dll", b"not executed")])
            safe_extract(archive, root / "output")
            self.assertEqual((root / "output/notepad++.exe").read_bytes(), b"owned-fixture")
            self.assertEqual((root / "output/localization/english.xml").read_bytes(), b"text")
            self.assertFalse((root / "output/updater").exists())
            self.assertFalse((root / "output/plugins").exists())


class OwnedThreadPriorityDiagnosticProtocolTests(unittest.TestCase):
    """Fake WinAPI/layout/owner contracts only; never native scheduler evidence."""
    class Kernel:
        def __init__(self, *, close_ok=True, close_raises=False, owner_ok=True, change_thread_birth=False,
                     change_process_birth=False, affinity_ok=True):
            self.close_ok = close_ok; self.close_raises = close_raises; self.owner_ok = owner_ok
            self.change_thread_birth = change_thread_birth; self.change_process_birth = change_process_birth
            self.affinity_ok = affinity_ok; self.opened = []; self.closed = []; self.times = {}; self.process_reads = 0
            self.counter = 1000

        def QueryPerformanceFrequency(self, output): output._obj.value = 10000000; return 1
        def QueryPerformanceCounter(self, output): self.counter += 10; output._obj.value = self.counter; return 1
        def GetProcessId(self, handle): return 123
        def WaitForSingleObject(self, handle, milliseconds):
            if milliseconds != 0: raise AssertionError('PROTOCOL_MUST_NOT_WAIT')
            return 258
        def GetProcessTimes(self, handle, created, exited, kernel, user):
            self.process_reads += 1
            created._obj.dwLowDateTime = 101 if self.change_process_birth and self.process_reads >= 3 else 100
            kernel._obj.dwLowDateTime = 30 + self.process_reads
            user._obj.dwLowDateTime = 0  # An actual queried zero must remain known.
            return 1
        def GetPriorityClass(self, handle): return 0x20
        def GetProcessPriorityBoost(self, handle, output): output._obj.value = 0; return 1
        def GetProcessAffinityMask(self, handle, process_mask, system_mask):
            process_mask._obj.value = 3; system_mask._obj.value = 15
            return int(self.affinity_ok)
        def OpenThread(self, access, inherit, tid):
            if access != 0x100040 or inherit: raise AssertionError('PROTOCOL_QUERY_RIGHTS_ONLY')
            self.opened.append(tid); return 1000 + tid
        def GetThreadId(self, handle): return handle - 1000
        def GetProcessIdOfThread(self, handle): return 123 if self.owner_ok else 124
        def GetThreadTimes(self, handle, created, exited, kernel, user):
            self.times[handle] = self.times.get(handle, 0) + 1
            created._obj.dwLowDateTime = handle - 900 + int(self.change_thread_birth and self.times[handle] > 1)
            return 1
        def GetThreadPriorityBoost(self, handle, output): output._obj.value = 0; return 1
        def CloseHandle(self, handle):
            self.closed.append(handle)
            if self.close_raises: raise OSError('PRIVATE_CLOSE_PATH')
            return int(self.close_ok)

    def observe(self, *, kernel=None, ntstatus=0, returned=48, thread_births='DEFAULT',
                expected='100', retained=None, enumeration=None, budget_expired=False,
                native_pid=123, native_priority=10):
        from tools import qa_decoder_apps as apps
        kernel = kernel or self.Kernel(); queries = []
        process = SimpleNamespace(pid=123, _handle=77)
        retained = [] if retained is None else retained
        def query(handle, information_class, output, size, length):
            self.assertEqual((information_class, size), (0, 48))
            queries.append(handle)
            data = output._obj
            data.client_id.process = native_pid; data.client_id.thread = handle - 1000
            data.teb = 0x7fffdeadbeef; data.affinity = 0xa5  # Never public pointer/mask values.
            data.priority = native_priority; data.base_priority = 8
            length._obj.value = returned
            return ntstatus
        native = SimpleNamespace(NtQueryInformationThread=query)
        if thread_births == 'DEFAULT': thread_births = {10: '110', 11: '111'}
        fake_psutil = SimpleNamespace(Process=lambda pid: SimpleNamespace(threads=lambda: enumeration))
        clock = iter((0., 3.)) if budget_expired else None
        with patch.object(apps, '_priority_native_api', return_value=(kernel, native)), \
                patch.object(apps, '_retained_priority_query_handles', retained), \
                patch.object(apps.time, 'monotonic', side_effect=(lambda: next(clock)) if clock else lambda: 0.), \
                patch.object(apps.os, 'cpu_count', return_value=2), \
                patch.dict('sys.modules', {'psutil': fake_psutil}):
            result = apps.observe_owned_thread_priorities(process, expected, thread_births)
        return result, kernel, queries, retained, process

    def test_actual_layout_and_identity_checked_priorities_cpu_and_capacity_have_no_pointer_fields(self):
        from tools import qa_decoder_apps as apps
        self.assertEqual(apps.C.sizeof(apps._PriorityFileTime), 8)
        self.assertEqual(apps.C.sizeof(apps._ThreadBasicPriorityInformation), 48)
        self.assertEqual(apps._ThreadBasicPriorityInformation.priority.offset, 40)
        self.assertEqual(apps._ThreadBasicPriorityInformation.base_priority.offset, 44)
        result, kernel, queries, _, _ = self.observe()
        self.assertEqual(result['status'], 'OBSERVED')
        self.assertTrue(result['process_identity_verified_before'])
        self.assertTrue(result['process_identity_verified_after'])
        self.assertEqual(result['priority_class'], 'NORMAL')
        self.assertFalse(result['priority_boost_disabled'])
        self.assertEqual(result['runtime_reported_logical_processors'], 2)
        self.assertEqual(result['affinity']['process_mask_bit_count'], 2)
        self.assertEqual(result['affinity']['system_mask_bit_count'], 4)
        self.assertEqual(result['process_cpu']['user_100ns'], 0)
        self.assertEqual(result['process_cpu']['kernel_100ns'], 33)
        self.assertLess(result['process_cpu']['sample_begin_qpc'], result['process_cpu']['sample_end_qpc'])
        self.assertEqual(queries, [1010, 1011]); self.assertEqual(kernel.closed, queries)
        self.assertEqual((result['query_handles_opened'], result['query_handles_closed']), (2, 2))
        self.assertTrue(result['query_handles_closed_verified'])
        for row in result['threads']:
            self.assertEqual((row['priority'], row['base_priority']), (10, 8))
            self.assertFalse(row['priority_boost_disabled'])
            self.assertLess(row['sample_begin_qpc'], row['sample_end_qpc'])
        encoded = json.dumps(result)
        for private in ('7fffdeadbeef', str(0x7fffdeadbeef), 'teb', 'thread_state', 'PRIVATE_PATH'):
            self.assertNotIn(private, encoded)

    def test_ntstatus_length_thread_and_process_identity_fail_closed_and_close_opened_handles(self):
        cases = ({'ntstatus': -1073741821}, {'returned': 47}, {'expected': '99'},
                 {'native_pid': 124}, {'native_priority': 32},
                 {'kernel': self.Kernel(owner_ok=False)}, {'kernel': self.Kernel(change_thread_birth=True)},
                 {'kernel': self.Kernel(change_process_birth=True)}, {'budget_expired': True})
        for options in cases:
            with self.subTest(options=options):
                result, kernel, _, _, _ = self.observe(**options)
                self.assertEqual(result['status'], 'NOT_ESTABLISHED')
                self.assertTrue(result['errors'])
                self.assertEqual(len(kernel.opened), len(kernel.closed))
                self.assertTrue(result['query_handles_closed_verified'])

    def test_target_enumeration_and_explicit_known_threads_are_bounded_before_thread_open(self):
        result, kernel, _, _, _ = self.observe(thread_births=None,
            enumeration=[SimpleNamespace(id=10), SimpleNamespace(id=11)])
        self.assertEqual(result['status'], 'OBSERVED'); self.assertEqual(kernel.opened, [10, 11])
        for births, entries in (({n: '110' for n in range(1, 34)}, None),
                                (None, [SimpleNamespace(id=n) for n in range(1, 34)]),
                                ({True: '110'}, None), ({10: 'PRIVATE_PATH'}, None)):
            with self.subTest(explicit=births is not None):
                result, kernel, _, _, _ = self.observe(thread_births=births, enumeration=entries)
                self.assertEqual(result['status'], 'NOT_ESTABLISHED')
                self.assertEqual(kernel.opened, [])
                self.assertNotIn('PRIVATE_PATH', json.dumps(result))

    def test_failed_close_retains_real_query_capability_and_retention_cap_blocks_new_open(self):
        for kernel in (self.Kernel(close_ok=False), self.Kernel(close_raises=True)):
            with self.subTest(close_raises=kernel.close_raises):
                result, kernel, _, retained, process = self.observe(kernel=kernel, thread_births={10: '110'})
                self.assertEqual(result['status'], 'NOT_ESTABLISHED')
                self.assertFalse(result['query_handles_closed_verified']); self.assertTrue(result['cleanup_required'])
                self.assertEqual(retained, [(kernel, 1010, process)])
                self.assertEqual((result['query_handles_opened'], result['query_handles_closed']), (1, 0))
                self.assertNotIn('PRIVATE_CLOSE_PATH', json.dumps(result))
        existing = [object() for _ in range(128)]
        blocked, kernel, _, retained, _ = self.observe(retained=existing)
        self.assertEqual(blocked['status'], 'NOT_ESTABLISHED'); self.assertEqual(kernel.opened, [])
        self.assertEqual(len(retained), 128)

    def test_optional_affinity_failure_and_unsupported_native_api_stay_explicit(self):
        from tools import qa_decoder_apps as apps
        result, _, _, _, _ = self.observe(kernel=self.Kernel(affinity_ok=False))
        self.assertEqual(result['affinity']['status'], 'NOT_ESTABLISHED')
        for failure, code in ((AssertionError('PRIORITY_UNSUPPORTED_NATIVE_ABI'), 'PRIORITY_UNSUPPORTED_NATIVE_ABI'),
                              (RuntimeError('PRIORITY_PRIVATE_TOKEN'), 'PRIORITY_QUERY_UNAVAILABLE')):
            with patch.object(apps, '_priority_native_api', side_effect=failure):
                unavailable = apps.observe_owned_thread_priorities(SimpleNamespace(pid=123, _handle=77), '100')
            self.assertEqual(unavailable['status'], 'NOT_ESTABLISHED')
            self.assertEqual(unavailable['errors'], [code])
            self.assertEqual(unavailable['threads'], []); self.assertEqual(unavailable['query_handles_opened'], 0)

    def test_observer_runs_in_original_exception_before_owned_cleanup_and_cannot_replace_it(self):
        import sys
        from contextlib import nullcontext, redirect_stdout
        from tools import qa_decoder_apps as apps
        with tempfile.TemporaryDirectory() as tmp:
            now = [0.]; events = []; observed = []
            process = SimpleNamespace(pid=123, poll=lambda: None)
            owner = SimpleNamespace(process=process, close=lambda **kwargs: events.append('cleanup'))
            sensor = SimpleNamespace(oneshot=nullcontext, cpu_times=lambda: SimpleNamespace(user=0., system=0.),
                memory_info=lambda: SimpleNamespace(rss=1024), num_threads=lambda: 1,
                io_counters=lambda: SimpleNamespace(read_bytes=0, write_bytes=0))
            psutil = SimpleNamespace(Process=lambda pid: sensor, NoSuchProcess=type('NoSuchProcess', (Exception,), {}))
            def observer(actual_owner, failure):
                self.assertIs(actual_owner, owner); self.assertEqual(failure['reason_code'], 'APP_WORKLOAD_DEADLINE')
                events.append('observer'); observed.append(sys.exc_info()[1])
                raise RuntimeError('PRIVATE_PATH must not replace primary')
            def sleep(seconds): now[0] += 31
            output = io.StringIO()
            with patch.dict('sys.modules', {'psutil': psutil}), \
                    patch.object(apps, 'OwnedProcess', return_value=owner), \
                    patch.object(apps, 'owned_process_identity', return_value={'creation_time_filetime_ticks': '100'}), \
                    patch.object(apps.time, 'monotonic', side_effect=lambda: now[0]), \
                    patch.object(apps.time, 'sleep', side_effect=sleep), redirect_stdout(output):
                with self.assertRaisesRegex(AssertionError, '^APP_WORKLOAD_DEADLINE$') as caught:
                    apps.monitored_run(['fixture.exe'], Path(tmp) / 'child.log', failure_observer=observer)
            self.assertIs(observed[0], caught.exception); self.assertEqual(events, ['observer', 'cleanup'])
            self.assertNotIn('PRIVATE_PATH', output.getvalue())

    def test_noncallable_observer_is_denied_before_process_or_log_creation(self):
        from tools import qa_decoder_apps as apps
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'must-not-exist.log'
            with patch.object(apps, 'OwnedProcess') as owner:
                with self.assertRaisesRegex(AssertionError, 'INVALID_WORKLOAD_FAILURE_OBSERVER'):
                    apps.monitored_run(['fixture.exe'], log, failure_observer=object())
                owner.assert_not_called()
            self.assertFalse(log.exists())

    def test_seven_zip_forwards_only_present_bound_observer_to_both_owned_roles(self):
        from tools import qa_decoder_apps as apps
        for with_observer in (False, True):
            with self.subTest(with_observer=with_observer), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); binary = root / 'fixture.exe'; binary.write_bytes(b'not-native-unit-fixture')
                capture = SimpleNamespace(active=False)
                callback = lambda owner, failure: None
                if with_observer:
                    capture.observe_workload_failure = callback
                failure = AssertionError('APP_WORKLOAD_DEADLINE')
                with patch.object(apps, 'installed', return_value=binary), \
                        patch.object(apps, 'native_pe_identity', return_value={}), \
                        patch.object(apps, 'binary_identity', return_value={'sha256': 'a' * 64}), \
                        patch.object(apps, 'start_schedule', return_value=capture), \
                        patch.object(apps, 'monitored_run', side_effect=[{'pid': 123}, failure]) as run:
                    with self.assertRaises(AssertionError) as caught:
                        apps.seven_zip(root, root / 'unused-helper')
                self.assertIs(caught.exception, failure)
                for number, call in enumerate(run.call_args_list):
                    expected = {'role': 'COMPRESS' if number == 0 else 'EXTRACT', 'cycle': 0}
                    if with_observer:
                        expected['failure_observer'] = callback
                    self.assertEqual(call.kwargs, expected)  # Ordinary timeout remains omitted/default30.
                self.assertEqual(run.call_count, 2)


class PreparedNativeBuildProtocolTests(unittest.TestCase):
    """Literal files/fake compiler results test reuse boundaries, never native acceptance."""
    head = 'a' * 40

    def fixture(self, root, *, edit_build=None):
        from contextlib import contextmanager, ExitStack
        from tools import qa_decoder_noise_fixture as fixture
        @contextmanager
        def active():
            identity = {'requested_head_sha': self.head, 'workflow_event_sha': 'b' * 40,
                'actual_source_sha': self.head, 'source_tree_sha': 'c' * 40, 'tracked_worktree_clean': True,
                'identity_source': 'ACTUAL_GIT_CHECKOUT', 'source_identity_status': 'VERIFIED_EXPECTED_HEAD'}
            for name in (*fixture._CRITICAL_SCRIPTS, 'tools/fixtures/DecoderBudgetProbe/noise.c'):
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('literal protocol source: ' + name, encoding='utf-8')
            github_output = root / 'step-output.txt'; github_output.write_bytes(b'')
            output = root / 'decoder-budget-diagnostic' / 'native-build'
            state = {'now': 0., 'calls': 0}
            native = {'format': 'PE32_PLUS', 'machine': '0x8664', 'clr_com_descriptor_rva': 0,
                'clr_com_descriptor_bytes': 0, 'code_kind': 'NATIVE_PE_NO_CLR_COM_DESCRIPTOR'}
            def build(folder, head):
                self.assertEqual(head, self.head); state['calls'] += 1
                folder.mkdir(parents=True, exist_ok=False)
                for name in ('noise.obj', 'noise-identity.h', 'compiler-request.json', 'compiler.log'):
                    (folder / name).write_bytes(b'PROTOCOL_FIXTURE_ONLY')
                executable = folder / 'scheduler-noise.exe'; executable.write_bytes(b'MZ PROTOCOL_FIXTURE_ONLY')
                pdb_path = folder / 'scheduler-noise.pdb'
                pdb_path.write_bytes(b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00' + b'\x00' * 32)
                digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
                source_hash = digest(root / 'tools/fixtures/DecoderBudgetProbe/noise.c')
                pdb = {'container': 'MSF7', 'bytes': pdb_path.stat().st_size, 'sha256': digest(pdb_path),
                    'verification_scope': 'CONTAINER_SIGNATURE_SIZE_AND_SHA256_ONLY'}
                value = {'schema': 'blackbox.native-noise-build/1', 'status': 'PASS', 'executable': str(executable),
                    'source_sha256': source_hash, 'executable_sha256': digest(executable), 'implementation': 'NATIVE_WIN32',
                    'expected_native_handles': 32, 'event_handles': 16, 'thread_handles': 16,
                    'source_identity': dict(identity), 'native_image': dict(native), 'native_pdb': pdb,
                    'cleanup': {'status': 'COMPLETED', 'process_exit_code': 0, 'process_created': True,
                        'active_job_processes_before_close': 0, 'job_handle_closed_verified': True,
                        'diagnostic_query_handles_closed_verified': True, 'cleanup_required': False,
                        'observed_job_processes': 3, 'scope': 'COMPILER_LEADER_EXIT_AND_OWNED_JOB_OBJECT'},
                    'compiler_job_observations': [{'phase': 'EMPTY_BEFORE_CLOSE', 'query_handles_closed_verified': True,
                        'accounting': {'status': 'OBSERVED', 'active_processes': 0, 'total_processes': 3}}],
                    'compiler_opt_out_policy': {'request_status': 'FIXED_ENVIRONMENT_REQUESTED',
                        'worker_verification_status': 'WORKER_AND_COMPILER_ENVIRONMENT_VERIFIED'},
                    'compiler_planned_shutdown': {'status': 'COMPLETED',
                        'method': 'PLANNED_OWNED_SDK_BACKGROUND_SHUTDOWN_AFTER_SUCCESSFUL_COMPILATION',
                        'active_job_processes_before_stop': 0, 'active_job_processes_after_stop': 0,
                        'termination_requested': False, 'termination_succeeded': None, 'natural_background_exit_claimed': False,
                        'last_job_query_winerror': 0},
                    'completed_output_proof': {'status': 'VERIFIED_BEFORE_PLANNED_STOP', 'post_shutdown_revalidated': True,
                        'source_sha256': source_hash, 'executable_sha256': digest(executable), 'native_image': dict(native),
                        'native_pdb': pdb}, 'compiler_job_assignment_verified_before_go': True}
                if edit_build:
                    edit_build(value)
                fixture.save(folder / 'build.json', value)
                state['now'] = 9.25
                return value
            with ExitStack() as stack:
                stack.enter_context(patch.object(fixture, 'ROOT', root))
                stack.enter_context(patch.object(fixture, 'source_identity', return_value=identity))
                stack.enter_context(patch.object(fixture, 'require_hosted_windows'))
                stack.enter_context(patch.object(fixture, 'native_pe_identity', return_value=native))
                stack.enter_context(patch.object(fixture, 'build_native_noise', side_effect=build))
                stack.enter_context(patch.object(fixture.time, 'monotonic', side_effect=lambda: state['now']))
                stack.enter_context(patch.dict(os.environ, {'GITHUB_REPOSITORY': 'literal/repository', 'GITHUB_RUN_ID': '123',
                    'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_JOB': 'portable', 'GITHUB_OUTPUT': str(github_output)}))
                stack.enter_context(redirect_stdout(io.StringIO()))
                yield fixture, output, state, identity, github_output
        return active()

    def prepare(self, fixture, output, github_output):
        fixture.prepare_native_noise(output, self.head)
        digest = hashlib.sha256((output / 'prepared-build.json').read_bytes()).hexdigest()
        self.assertEqual(github_output.read_text(), 'manifest_sha256=' + digest + '\n')
        return digest

    def test_same_job_build_once_revalidated_files_and_runner_output_anchor(self):
        with tempfile.TemporaryDirectory() as tmp, self.fixture(Path(tmp)) as (fixture, output, state, _, github_output):
            anchor = self.prepare(fixture, output, github_output)
            with patch.object(fixture, 'build_native_noise', side_effect=AssertionError('NO_COMPILE_FALLBACK')):
                loaded = fixture.load_prepared_native_noise(output, self.head, expected_manifest_sha256=anchor)
            self.assertEqual(state['calls'], 1)
            self.assertEqual(loaded['prepared_build_elapsed_seconds'], 9.25)
            facts = loaded['prepared_validation']
            self.assertEqual(facts['status'], 'VERIFIED_SAME_JOB_BUILD_FILES')
            self.assertEqual(facts['expected_manifest_sha256'], anchor)
            self.assertEqual(facts['ci_context'], {'repository': 'literal/repository', 'run_id': '123', 'run_attempt': '1', 'job_key': 'portable'})
            self.assertEqual(set(facts['critical_physical_sha256']), set(fixture._CRITICAL_SCRIPTS))
            self.assertNotIn(str(Path(tmp)), json.dumps(facts))

    def test_context_source_physical_script_and_artifact_changes_reject_reuse(self):
        for change in ('run', 'attempt', 'job', 'repository', 'head', 'tree', 'source', 'script', 'exe', 'pdb', 'receipt'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp, self.fixture(Path(tmp)) as (fixture, output, _, identity, github_output):
                anchor = self.prepare(fixture, output, github_output)
                keys = {'run': 'GITHUB_RUN_ID', 'attempt': 'GITHUB_RUN_ATTEMPT', 'job': 'GITHUB_JOB', 'repository': 'GITHUB_REPOSITORY'}
                environment = {keys[change]: 'other/repository' if change == 'repository' else 'other' if change == 'job' else '2'} if change in keys else {}
                if change == 'tree':
                    identity['source_tree_sha'] = 'd' * 40
                paths = {'source': Path(tmp) / 'tools/fixtures/DecoderBudgetProbe/noise.c',
                    'script': Path(tmp) / fixture._CRITICAL_SCRIPTS[0], 'exe': output / 'scheduler-noise.exe',
                    'pdb': output / 'scheduler-noise.pdb', 'receipt': output / 'build.json'}
                if change in paths:
                    with paths[change].open('ab') as stream:
                        stream.write(b'CHANGED')
                with patch.dict(os.environ, environment), self.assertRaises(AssertionError):
                    fixture.load_prepared_native_noise(output, 'e' * 40 if change == 'head' else self.head,
                                                      expected_manifest_sha256=anchor)

    def test_external_anchor_rejects_valid_elapsed_change_even_with_recomputed_inner_digest(self):
        with tempfile.TemporaryDirectory() as tmp, self.fixture(Path(tmp)) as (fixture, output, _, _, github_output):
            anchor = self.prepare(fixture, output, github_output)
            seal_path = output / 'prepared-build.json'; seal = json.loads(seal_path.read_text())
            seal['payload']['prepared_build_elapsed_seconds'] = 8.5
            seal['payload_sha256'] = hashlib.sha256(fixture._canonical(seal['payload'])).hexdigest()
            seal_path.write_bytes(fixture._canonical(seal))
            with self.assertRaisesRegex(AssertionError, 'EXTERNAL_ANCHOR_MISMATCH'):
                fixture.load_prepared_native_noise(output, self.head, expected_manifest_sha256=anchor)
            for invalid in ('', 'F' * 64, None):
                with self.subTest(anchor=invalid), self.assertRaises(AssertionError):
                    fixture.load_prepared_native_noise(output, self.head, expected_manifest_sha256=invalid)
            with self.assertRaises(TypeError):
                fixture.load_prepared_native_noise(output, self.head)

    def test_elapsed_types_nonfinite_duplicate_keys_and_failed_build_proof_are_rejected(self):
        for elapsed in (0, -1, 90.001, True, '9.25', float('nan'), float('inf')):
            with self.subTest(elapsed=elapsed), tempfile.TemporaryDirectory() as tmp, self.fixture(Path(tmp)) as (fixture, output, _, _, github_output):
                self.prepare(fixture, output, github_output)
                path = output / 'prepared-build.json'; seal = json.loads(path.read_text())
                seal['payload']['prepared_build_elapsed_seconds'] = elapsed
                canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
                seal['payload_sha256'] = hashlib.sha256(canonical(seal['payload'])).hexdigest()
                path.write_bytes(canonical(seal)); anchor = hashlib.sha256(path.read_bytes()).hexdigest()
                with self.assertRaises(AssertionError):
                    fixture.load_prepared_native_noise(output, self.head, expected_manifest_sha256=anchor)
        for bad in ('duplicate', 'forced', 'no_close', 'postproof', 'worker'):
            def edit(value):
                if bad == 'forced': value['cleanup']['status'] = 'FORCED_CLOSED'
                if bad == 'no_close': value['cleanup']['job_handle_closed_verified'] = False
                if bad == 'postproof': value['completed_output_proof']['post_shutdown_revalidated'] = False
                if bad == 'worker': value['cleanup']['process_exit_code'] = 1
            with self.subTest(proof=bad), tempfile.TemporaryDirectory() as tmp, self.fixture(Path(tmp), edit_build=edit) as (fixture, output, _, _, github_output):
                if bad != 'duplicate':
                    with self.assertRaises(AssertionError):
                        fixture.prepare_native_noise(output, self.head)
                    self.assertFalse((output / 'prepared-build.json').exists())
                    self.assertEqual(github_output.read_bytes(), b'')
                else:
                    self.prepare(fixture, output, github_output)
                    path = output / 'prepared-build.json'; raw = path.read_bytes().replace(b'{', b'{"schema":"DUPLICATE",', 1)
                    path.write_bytes(raw)
                    with self.assertRaisesRegex(AssertionError, 'DUPLICATE_KEY'):
                        fixture.load_prepared_native_noise(output, self.head, expected_manifest_sha256=hashlib.sha256(raw).hexdigest())

    def test_hardlinks_reparse_and_source_or_seal_change_during_load_are_rejected(self):
        for change in ('hardlink', 'reparse', 'source_during', 'seal_during'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp, self.fixture(Path(tmp)) as (fixture, output, _, _, github_output):
                anchor = self.prepare(fixture, output, github_output)
                if change == 'hardlink':
                    os.link(output / 'scheduler-noise.exe', Path(tmp) / 'second-link.exe')
                original_stat = Path.lstat; original_snapshot = fixture._prepared_snapshot; calls = [0]
                def lstat(path, *args, **kwargs):
                    info = original_stat(path, *args, **kwargs)
                    return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400) if change == 'reparse' and path == output else info
                def snapshot(*args):
                    result = original_snapshot(*args); calls[0] += 1
                    if calls[0] == 1 and change == 'source_during':
                        with (Path(tmp) / fixture._CRITICAL_SCRIPTS[0]).open('ab') as stream: stream.write(b'CHANGED')
                    if calls[0] == 1 and change == 'seal_during':
                        with (output / 'prepared-build.json').open('ab') as stream: stream.write(b' ')
                    return result
                with patch('pathlib.Path.lstat', lstat), patch.object(fixture, '_prepared_snapshot', side_effect=snapshot), self.assertRaises(AssertionError):
                    fixture.load_prepared_native_noise(output, self.head, expected_manifest_sha256=anchor)

    def test_driver_prepared_only_root_is_fresh_no_clobber_and_budget_debits_duration(self):
        from tools.qa_decoder_budget_diagnostic import diagnostic_output_root, prepared_budget_deadline
        with tempfile.TemporaryDirectory() as tmp, patch('tools.qa_decoder_budget_diagnostic.ROOT', Path(tmp)):
            root = Path(tmp) / 'diagnostic'; build = root / 'native-build'; build.mkdir(parents=True)
            self.assertEqual(diagnostic_output_root(root, prepared=True), root.resolve())
            original_stat = Path.lstat
            def lstat(path, *args, **kwargs):
                info = original_stat(path, *args, **kwargs)
                return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400) if path == Path(tmp) else info
            with patch('pathlib.Path.lstat', lstat), self.assertRaises(AssertionError):
                diagnostic_output_root(root, prepared=True)
            with tempfile.TemporaryDirectory() as outside:
                with self.assertRaises(AssertionError): diagnostic_output_root(Path(outside), prepared=True)
                self.assertEqual(list(Path(outside).iterdir()), [])
            for name in ('native-schedule', 'budget-diagnostic.json'):
                sibling = root / name; sibling.write_bytes(b'KEEP')
                with self.assertRaises(AssertionError): diagnostic_output_root(root, prepared=True)
                self.assertEqual(sibling.read_bytes(), b'KEEP'); sibling.unlink()
            with self.assertRaises(AssertionError): diagnostic_output_root(root, prepared=1)
            wrong_root = Path(tmp) / 'not-directory'; wrong_root.write_bytes(b'KEEP')
            with self.assertRaises(AssertionError): diagnostic_output_root(wrong_root, prepared=True)
            self.assertEqual(wrong_root.read_bytes(), b'KEEP')
            build.rmdir(); build.write_bytes(b'KEEP')
            with self.assertRaises(AssertionError): diagnostic_output_root(root, prepared=True)
            self.assertEqual(build.read_bytes(), b'KEEP')
        self.assertEqual(prepared_budget_deadline(10, 9.25), 660.75)
        for bad in (0, -1, True, float('nan'), float('inf'), 90.01):
            with self.subTest(elapsed=bad), self.assertRaises(AssertionError): prepared_budget_deadline(10, bad)

    def test_final_prepared_recheck_rejects_changed_valid_elapsed_hash_status_missing_and_types(self):
        from tools.qa_decoder_budget_diagnostic import validate_prepared_recheck
        initial = {'prepared_build_elapsed_seconds': 9.25, 'prepared_validation': {
            'schema': 'blackbox.native-noise-prepared-validation/1', 'status': 'VERIFIED_SAME_JOB_BUILD_FILES',
            'source_sha': self.head, 'source_tree_sha': 'c' * 40, 'prepared_receipt_sha256': 'd' * 64}}
        final = json.loads(json.dumps(initial))
        self.assertEqual(validate_prepared_recheck(initial, final), initial['prepared_validation'])
        for change in ('elapsed', 'hash', 'status', 'missing', 'type', 'bool_elapsed', 'nonfinite'):
            with self.subTest(change=change):
                changed = json.loads(json.dumps(initial))
                if change == 'elapsed': changed['prepared_build_elapsed_seconds'] = 8.5
                if change == 'hash': changed['prepared_validation']['prepared_receipt_sha256'] = 'e' * 64
                if change == 'status': changed['prepared_validation']['status'] = 'NOT_ESTABLISHED'
                if change == 'missing': del changed['prepared_validation']
                if change == 'type': changed['prepared_validation'] = []
                if change == 'bool_elapsed': changed['prepared_build_elapsed_seconds'] = True
                if change == 'nonfinite': changed['prepared_validation']['extra'] = float('nan')
                with self.assertRaises((AssertionError, ValueError)):
                    validate_prepared_recheck(initial, changed)

    def test_prepared_modes_require_anchor_and_missing_seal_never_compiles(self):
        from tools.qa_decoder_budget_diagnostic import parse_args
        invalid = [['--noise-child', '--output', 'literal', '--prepared-native-build'],
            ['--output', 'literal', '--helper', 'helper.exe', '--source-sha', self.head, '--prepared-native-build'],
            ['--output', 'literal', '--helper', 'helper.exe', '--source-sha', self.head, '--prepared-build-sha256', 'a' * 64]]
        from contextlib import redirect_stderr
        for arguments in invalid:
            with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): parse_args(arguments)
        with tempfile.TemporaryDirectory() as tmp, self.fixture(Path(tmp)) as (fixture, output, state, _, _):
            output.mkdir(parents=True)
            with self.assertRaises(AssertionError):
                fixture.load_prepared_native_noise(output, self.head, expected_manifest_sha256='a' * 64)
            self.assertEqual(state['calls'], 0)


class ControlledMinimumStimulusProtocolTests(unittest.TestCase):
    """Fake clocks, files and role receipts test control flow, not Windows evidence."""

    def invoke_seven_zip(self, root, *, minimum=None, cycle_seconds=5, fail_extract=False):
        binary = root / 'protocol-only.exe'; binary.write_bytes(b'not an executable')
        now = [0.0]; calls = []; capture = SimpleNamespace(active=False)
        failure = AssertionError('APP_WORKLOAD_DEADLINE')
        def run(argv, log, **kwargs):
            calls.append((list(argv), dict(kwargs)))
            now[0] += cycle_seconds / 2
            if kwargs['role'] == 'EXTRACT':
                if fail_extract:
                    raise failure
                destination = Path(argv[4][2:]); destination.mkdir()
                (destination / 'input.bin').write_bytes((root / 'input.bin').read_bytes())
            return {'pid': 100 + len(calls), 'exit_code': 0, 'owned_image_matches_requested': True,
                    'cpu_seconds_observed': 1}
        options = {} if minimum is None else {'minimum_roundtrips': minimum}
        observations = {'cpu_samples': 1, 'cpu_samples_with_stacks': 1, 'file_events': 1,
                        'thread_events': 1, 'pid_lifetimes_confirmed': True}
        with patch('tools.qa_decoder_apps.installed', return_value=binary), \
                patch('tools.qa_decoder_apps.native_pe_identity', return_value={}), \
                patch('tools.qa_decoder_apps.binary_identity', return_value={'sha256': 'a' * 64}), \
                patch('tools.qa_decoder_apps.random.Random', return_value=SimpleNamespace(
                    randbytes=lambda count: b'explicit protocol input')) as rng, \
                patch('tools.qa_decoder_apps.start_schedule', return_value=capture), \
                patch('tools.qa_decoder_apps.monitored_run', side_effect=run), \
                patch('tools.qa_decoder_apps.finish_schedule', return_value={'observations': observations}) as finish, \
                patch('tools.qa_decoder_apps.time.monotonic', side_effect=lambda: now[0]):
            if fail_extract:
                with self.assertRaises(AssertionError) as caught:
                    seven_zip(root, root / 'unused-helper', **options)
                self.assertIs(caught.exception, failure); finish.assert_not_called()
                result = None
            else:
                result = seven_zip(root, root / 'unused-helper', **options)
            rng.assert_called_once_with(20261028)
        return result, json.loads((root / 'workload-oracle.json').read_text()), calls

    def test_completed_roundtrip_minimum_overrides_early_four_second_break_but_not_maximum(self):
        for minimum, seconds, expected in ((None, 5, 1), (2, 5, 2), (3, 5, 3), (1, 1, 3)):
            with self.subTest(minimum=minimum, cycle_seconds=seconds), tempfile.TemporaryDirectory() as tmp:
                result, oracle, calls = self.invoke_seven_zip(Path(tmp), minimum=minimum, cycle_seconds=seconds)
                requested = 1 if minimum is None else minimum
                self.assertEqual(oracle['requested_minimum_roundtrips'], requested)
                self.assertEqual(oracle['roundtrips_verified'], expected)
                self.assertEqual(result['oracle']['requested_minimum_roundtrips'], requested)
                self.assertEqual(result['oracle']['roundtrips_verified'], expected)
                self.assertEqual(len(calls), 2 * expected)
                for number, (argv, kwargs) in enumerate(calls):
                    self.assertEqual(kwargs, {'role': 'COMPRESS' if number % 2 == 0 else 'EXTRACT', 'cycle': number // 2})
                    if number % 2 == 0:
                        self.assertEqual(argv[1:8], ['a', '-t7z', '-mx=7', '-mmt=2', '-bd', '-y', str(Path(tmp) / f'roundtrip-{number // 2}.7z')])
                self.assertEqual(oracle['requested_process_timeout_seconds'], 30)

    def test_failed_roundtrip_retains_requested_minimum_without_claiming_completed_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, oracle, calls = self.invoke_seven_zip(Path(tmp), minimum=2, fail_extract=True)
            self.assertIsNone(result); self.assertEqual(len(calls), 2)
            self.assertEqual(oracle['requested_minimum_roundtrips'], 2)
            self.assertEqual(oracle['roundtrips_verified'], 0)
            self.assertEqual(oracle['status'], 'INCOMPLETE_WORKLOAD_FAILURE')
            self.assertEqual(oracle['failure_reason_code'], 'APP_WORKLOAD_DEADLINE')

    def test_invalid_minima_fail_before_application_or_case_source_resource_work(self):
        from tools import qa_decoder_budget_diagnostic as driver
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'must-not-exist'
            with patch('tools.qa_decoder_apps.installed') as installed_app, \
                    patch('tools.qa_decoder_apps.start_schedule') as capture, \
                    patch.object(driver, 'source_identity') as identity:
                for minimum in (True, False, 0, -1, 4, 2.0, '2', None):
                    with self.subTest(minimum=minimum), self.assertRaisesRegex(AssertionError, 'INVALID_QA_MINIMUM_ROUNDTRIPS'):
                        seven_zip(output, output / 'unused', minimum_roundtrips=minimum)
                    with self.subTest(case_minimum=minimum), self.assertRaisesRegex(AssertionError, 'INVALID_QA_MINIMUM_ROUNDTRIPS'):
                        driver.run_case(output, output / 'unused', 'a' * 40, 100, 'schedule', {},
                            'ROW_BUDGET_NEGATIVE', minimum_roundtrips=minimum)
                for minimum in (True, -1, 0, 9, 10.0, 11, None):
                    with self.subTest(prelude_minimum=minimum), self.assertRaisesRegex(AssertionError, 'INVALID_CONTROLLED_STIMULUS_REQUEST'):
                        driver.run_case(output, output / 'unused', 'a' * 40, 100, 'cpu_file',
                            {'implementation': 'PYTHON_CTYPES_WIN32'}, 'OUTPUT_BUDGET_NEGATIVE',
                            minimum_prelude_seconds=minimum)
                installed_app.assert_not_called(); capture.assert_not_called(); identity.assert_not_called()
            self.assertFalse(output.exists())

    def invoke_prelude(self, *, target=16, minimum=10, whole_deadline=100, hash_advance=0, implementation='PYTHON_CTYPES_WIN32'):
        templates = ProducerNoisePolicyProtocolTests(); ready = templates.ready(implementation)
        path = Path('progress-0001.json'); now = [0.0]; read_times = []
        noise = NoiseOwner(SimpleNamespace(glob=lambda pattern: [path]), {
            'implementation': implementation, 'expected_native_handles': ready['expected_native_handles']})
        noise.ready = ready
        noise.owner = SimpleNamespace(process=SimpleNamespace(poll=lambda: None))
        def read(unused, **options):
            read_times.append(now[0])
            now[0] += hash_advance  # Cost of acquiring/validating one complete snapshot.
            options['phase_context'].update(receipt_bytes=123, receipt_sha256='c' * 64,
                snapshot_scope='ONE_READONLY_HANDLE_BYTES_JSON_SIZE_SHA_NO_REOPEN')
            return templates.progress(ready, int(now[0]) + 1)
        def sleep(seconds):
            self.assertEqual(seconds, .02)
            self.assertLess(now[0], 80, 'fake-clock guard prevents protocol-test hangs')
            now[0] += 1
        def hashed(unused):
            return 'c' * 64
        with patch('tools.qa_decoder_budget_diagnostic.time.monotonic', side_effect=lambda: now[0]), \
                patch('tools.qa_decoder_budget_diagnostic.time.sleep', side_effect=sleep), \
                patch('tools.qa_decoder_budget_diagnostic.read_json', side_effect=read), \
                patch('tools.qa_decoder_apps.file_hash', side_effect=hashed), \
                patch('pathlib.Path.stat', return_value=SimpleNamespace(st_size=123)):
            failure = None
            try:
                noise.await_handoffs(target, whole_deadline, minimum_seconds=minimum)
            except AssertionError as error:
                failure = error
        return noise.prelude, read_times, failure

    def test_early_target_cannot_complete_python_prelude_before_ten_seconds_and_native_stays_zero(self):
        prelude, reads, failure = self.invoke_prelude()
        self.assertIsNone(failure); self.assertEqual(prelude['status'], 'COMPLETED')
        self.assertEqual(prelude['requested_minimum_seconds'], 10)
        self.assertEqual(prelude['wait_seconds'], 10)
        self.assertEqual(reads, list(range(11)))
        self.assertGreaterEqual(prelude['observed_handoffs'], 16)
        native, reads, failure = self.invoke_prelude(minimum=0, implementation='NATIVE_WIN32')
        self.assertIsNone(failure); self.assertEqual(native['status'], 'COMPLETED')
        self.assertEqual(native['requested_minimum_seconds'], 0)
        self.assertEqual(native['wait_seconds'], 0); self.assertEqual(reads, [0])

    def test_minimum_cannot_replace_handoff_target_or_existing_deadlines_including_slow_receipt(self):
        for options, expected_wait in (({'target': 10000}, 15), ({'whole_deadline': 8}, 8), ({'hash_advance': 16}, 16)):
            with self.subTest(options=options):
                prelude, reads, failure = self.invoke_prelude(**options)
                self.assertIsInstance(failure, AssertionError)
                self.assertEqual(str(failure), 'COMPARABLE_NOISE_PRELUDE_NOT_ESTABLISHED')
                self.assertEqual(prelude['status'], 'FAILED')
                self.assertEqual(prelude['wait_seconds'], expected_wait)
                self.assertTrue(reads)
        noise = NoiseOwner(SimpleNamespace(glob=lambda pattern: self.fail('invalid minimum read files')), {
            'implementation': 'NATIVE_WIN32', 'expected_native_handles': 32})
        with patch('tools.qa_decoder_budget_diagnostic.time.monotonic') as clock:
            for minimum in (True, -1, 10, 10.0, 11):
                with self.subTest(native_minimum=minimum), self.assertRaisesRegex(AssertionError, 'INVALID_NOISE_PRELUDE_REQUEST'):
                    noise.await_handoffs(16, 100, minimum_seconds=minimum)
            clock.assert_not_called()

    def comparison_pair(self, *, positive):
        implementation = 'NATIVE_WIN32' if positive else 'PYTHON_CTYPES_WIN32'
        policy = 'CONTROLLED_NATIVE_90' if positive else 'ORDINARY_30'; seconds = 90 if positive else 30
        actual_noise_policy = noise_policy(implementation)
        budget = {'workload_policy': policy, 'requested_process_timeout_seconds': seconds,
            'requested_minimum_roundtrips': 1, 'roundtrips_verified': 2,
            'workloads': [{'pid': 100 + n, 'role': 'COMPRESS' if n % 2 == 0 else 'EXTRACT', 'cycle': n // 2,
                'configured_timeout_seconds': seconds, 'elapsed_monitor_seconds': 1, 'exit_code': 0} for n in range(4)]}
        common = {'input_sha256': 'a' * 64, 'input_bytes': 8 * 1024**2, 'application_sha256': 'b' * 64,
            'native_image': {'code_kind': 'NATIVE_PE_NO_CLR_COM_DESCRIPTOR'}, 'helper_sha256': 'c' * 64,
            'script_hashes': {'driver': 'd' * 64}, 'actual_native_module_encoding': 'PER_EVENT_MODULES_V1',
            'requested_workload_policy': policy, 'requested_process_timeout_seconds': seconds,
            'requested_minimum_roundtrips': 1, 'requested_minimum_prelude_seconds': 0,
            'workload_budget': budget, 'requested_noise_policy': actual_noise_policy,
            'noise_policy_receipts': {phase: {key: actual_noise_policy[key] for key in ('implementation', 'ttl_seconds', 'progress_limit')}
                                      for phase in ('ready', 'oracle')},
            'native_timing': {'ready_qpc': 0, 'work_begin_qpc': 10000, 'work_end_qpc': 74000, 'qpc_frequency_hz': 1000},
            'noise_producer': {'implementation': implementation, 'source_sha256': '3' * 64},
            'source_identity': {'actual_source_sha': 'e' * 40, 'source_tree_sha': 'f' * 40},
            'noise_cleanup': {'status': 'COMPLETED'}, 'capture_cleanup': {'status': 'STOPPED'},
            'noise_workload_coverage': {'all_16_threads_bracket': True, 'threads_with_positive_handoff_delta': 16},
            'roundtrips_verified': 2}
        first = {**common, 'status': 'EXPECTED_NATIVE_BUDGET_NEGATIVE' if positive else 'EXPECTED_ROW_BUDGET_NEGATIVE',
            'noise_handoffs': 10000, 'capture_profile': {'name': 'schedule', 'xml_sha256': '1' * 64},
            'prelude': {'target_handoffs': 0, 'requested_minimum_seconds': 0, 'wait_seconds': 0, 'status': 'NOT_REQUIRED'}}
        second = {**common, 'status': 'COMPLETE_7ZIP_ACCEPTANCE' if positive else 'EXPECTED_OUTPUT_BUDGET_NEGATIVE',
            'noise_handoffs': 20000, 'capture_profile': {'name': 'cpu_file', 'xml_sha256': '2' * 64},
            'requested_minimum_roundtrips': 2, 'requested_minimum_prelude_seconds': 0 if positive else 10,
            'workload_budget': {**budget, 'requested_minimum_roundtrips': 2},
            'actual_native_module_encoding': 'PER_EVENT_MODULES_V1' if positive else 'INLINE_V1',
            'prelude': {'target_handoffs': 10000, 'observed_handoffs': 11000, 'requested_minimum_seconds': 0 if positive else 10,
                        'wait_seconds': 1 if positive else 10, 'status': 'COMPLETED'}}
        return first, second

    def test_comparison_binds_exact_requests_observed_counts_and_python_only_ten_second_wait(self):
        for positive in (False, True):
            first, second = self.comparison_pair(positive=positive)
            observed = validate_comparison(first, second, positive=positive)
            self.assertEqual(observed['second_requested_minimum_roundtrips'], 2)
            self.assertEqual(observed['second_minimum_prelude_seconds'], 0 if positive else 10)
            for change in ({'requested_minimum_roundtrips': True}, {'requested_minimum_roundtrips': 1},
                           {'roundtrips_verified': 3}, {'requested_minimum_prelude_seconds': 10 if positive else 0},
                           {'prelude': {**second['prelude'], 'requested_minimum_seconds': True}},
                           {'prelude': {**second['prelude'], 'wait_seconds': 66 if positive else 16}},
                           {'prelude': {**second['prelude'], 'observed_handoffs': 9999}},
                           {'prelude': {**second['prelude'], 'status': 'FAILED'}},
                           {'workload_budget': {**second['workload_budget'], 'roundtrips_verified': 3}}):
                with self.subTest(positive=positive, change=change), self.assertRaises(AssertionError):
                    validate_comparison(first, {**second, **change}, positive=positive)
            if not positive:
                with self.assertRaises(AssertionError):
                    validate_comparison(first, {**second, 'prelude': {**second['prelude'], 'wait_seconds': 9.999}}, positive=False)
        native = {'qpc_frequency_matches': True}
        complete = {'status': 'DECODED', 'rows': 154022, 'import_completeness': 'ALL_EMITTED_RECORDS'}
        with self.assertRaisesRegex(AssertionError, 'REJECTION_NOT_OBSERVED'):
            validate_case_contract('OUTPUT_BUDGET_NEGATIVE', False, None, complete, 'a' * 64, native,
                {'output_bytes': 362820931})
        for capability in SEVENZIP_CAPABILITIES:
            result = {'status': 'PASS', 'capabilities': {key: 'PASS' for key in SEVENZIP_CAPABILITIES}}
            result['capabilities'][capability] = 'FAIL_NOT_OBSERVED'
            with self.subTest(capability=capability), self.assertRaisesRegex(AssertionError, 'COMPLETE_ACCEPTANCE'):
                validate_case_contract('COMPLETE_NATIVE_7ZIP', False, result, complete, 'a' * 64, native, {})

    def test_driver_forwards_each_first_actual_count_and_only_python_b_minimum_prelude(self):
        from tools import qa_decoder_budget_diagnostic as driver
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); helper = root / 'protocol-helper.exe'; helper.write_bytes(b'not an executable')
            native = {'implementation': 'NATIVE_WIN32'}
            cases = [{'status': 'EXPECTED_ROW_BUDGET_NEGATIVE', 'noise_handoffs': 10000, 'roundtrips_verified': 2},
                     {'status': 'EXPECTED_OUTPUT_BUDGET_NEGATIVE'},
                     {'status': 'EXPECTED_NATIVE_BUDGET_NEGATIVE', 'noise_handoffs': 20000, 'roundtrips_verified': 3},
                     {'status': 'COMPLETE_7ZIP_ACCEPTANCE'}]
            args = SimpleNamespace(output=root / 'output', helper=helper, source_sha='a' * 40,
                                   prepared_native_build=False, prepared_build_sha256=None)
            with patch.object(driver, 'require_hosted_windows'), \
                    patch('tools.qa_decoder_noise_fixture.build_native_noise', return_value=native) as builder, \
                    patch.object(driver, 'run_case', side_effect=cases) as run, \
                    patch.object(driver, 'validate_comparison', return_value={'protocol_only': True}), \
                    patch('tools.qa_decoder_apps.file_hash', return_value='b' * 64), \
                    patch('tools.qa_decoder_apps.write_json'), \
                    patch.object(driver.time, 'monotonic', return_value=0), \
                    patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': ''}), redirect_stdout(io.StringIO()):
                self.assertEqual(driver.run_diagnostic(args), 0)  # Fake protocol flow only, not native acceptance.
            builder.assert_called_once_with(args.output.resolve() / 'native-build', args.source_sha)
            self.assertEqual(run.call_count, 4)
            self.assertEqual(run.call_args_list[0].kwargs, {})
            self.assertEqual(run.call_args_list[2].kwargs, {})
            self.assertEqual(run.call_args_list[1].args[-1], 10000)
            self.assertEqual(run.call_args_list[1].kwargs, {'native_module_encoding': 'INLINE_V1',
                'minimum_roundtrips': 2, 'minimum_prelude_seconds': 10})
            self.assertEqual(run.call_args_list[3].args[-1], 20000)
            self.assertEqual(run.call_args_list[3].kwargs, {'native_module_encoding': None,
                'minimum_roundtrips': 3, 'minimum_prelude_seconds': 0})

    def test_case_forwards_requested_count_to_real_workload_entry_and_retains_failure(self):
        from tools import qa_decoder_budget_diagnostic as driver
        for implementation, minimum, prelude in (('PYTHON_CTYPES_WIN32', 2, 10), ('NATIVE_WIN32', 3, 0)):
            with self.subTest(implementation=implementation), tempfile.TemporaryDirectory() as tmp:
                producer = {'implementation': implementation, 'source_sha256': 'a' * 64,
                    'executable_sha256': 'b' * 64, 'expected_native_handles': 16 if prelude else 32}
                options = {'minimum_roundtrips': minimum}
                if prelude:
                    options['native_module_encoding'] = 'INLINE_V1'
                else:
                    options['workload_policy'] = 'CONTROLLED_NATIVE_90'
                output = Path(tmp) / 'case'; sentinel = AssertionError('PROTOCOL_WORKLOAD_ENTRY_FAILURE')
                with patch.object(driver, 'source_identity', return_value={'source_identity_status': 'VERIFIED_EXPECTED_HEAD'}), \
                        patch.object(driver, 'kernel_api', return_value=object()), \
                        patch.object(driver, 'counter', return_value=1000), \
                        patch.object(driver.NoiseOwner, 'start') as start, \
                        patch.object(driver, 'collect_bounded_case_facts'), \
                        patch.object(driver, 'collect_noise_stop_observation'), \
                        patch('tools.qa_decoder_apps.seven_zip', side_effect=sentinel) as workload, \
                        redirect_stdout(io.StringIO()):
                    proof = driver.run_case(output, Path(tmp) / 'unused-helper', 'a' * 40, 100, 'cpu_file', producer,
                        'OUTPUT_BUDGET_NEGATIVE' if prelude else 'COMPLETE_NATIVE_7ZIP', 10000,
                        native_module_encoding='INLINE_V1' if prelude else None,
                        minimum_roundtrips=minimum, minimum_prelude_seconds=prelude)
                workload.assert_called_once_with(output / '7zip', Path(tmp) / 'unused-helper', profile='cpu_file', **options)
                start.assert_not_called()
                self.assertEqual(proof['status'], 'REPRODUCTION_NOT_ESTABLISHED')
                self.assertEqual(proof['reason_code'], 'PROTOCOL_WORKLOAD_ENTRY_FAILURE')
                self.assertEqual(proof['requested_minimum_roundtrips'], minimum)
                self.assertEqual(proof['requested_minimum_prelude_seconds'], prelude)


class PreludeFailureAndBudgetCompositionTests(unittest.TestCase):
    """Fault/clock fixtures only; all real acceptance still runs in Windows CI."""

    def test_native_prelude_has_its_finite_preparation_window_and_python_stays_fifteen(self):
        helper = ControlledMinimumStimulusProtocolTests()
        prelude, _, error = helper.invoke_prelude(
            target=640, minimum=0, implementation='NATIVE_WIN32')
        self.assertIsNone(error)
        self.assertEqual(prelude['wait_seconds'], 39)
        self.assertEqual(prelude['maximum_wait_seconds'], 65)
        native, _, error = helper.invoke_prelude(
            target=100000, minimum=0, implementation='NATIVE_WIN32')
        self.assertIsInstance(error, AssertionError)
        self.assertEqual(native['wait_seconds'], 65)
        python, _, error = helper.invoke_prelude(target=100000, minimum=10)
        self.assertIsInstance(error, AssertionError)
        self.assertEqual(python['wait_seconds'], 15)

    def test_prelude_retains_original_os_error_and_numeric_phase_without_private_text(self):
        from tools import qa_decoder_budget_diagnostic as driver
        ready = ProducerNoisePolicyProtocolTests().ready('NATIVE_WIN32')
        for phase in ('RECEIPT_STAT', 'RECEIPT_READ'):
            with self.subTest(phase=phase):
                failure = PermissionError(13, 'PRIVATE_USER_PATH_MUST_NOT_BE_EXPORTED')
                failure.winerror = 32
                noise = NoiseOwner(SimpleNamespace(glob=lambda pattern: [Path('progress-0013.json')]),
                    {'implementation': 'NATIVE_WIN32', 'expected_native_handles': 32})
                noise.ready = ready
                noise.owner = SimpleNamespace(process=SimpleNamespace(poll=lambda: None))
                def fail_read(path, *, phase_context):
                    phase_context['phase'] = phase
                    raise failure
                with patch.object(driver.time, 'monotonic', return_value=0), \
                        patch.object(driver, 'read_json', side_effect=fail_read), \
                        patch('tools.qa_decoder_apps.file_hash') as hashed:
                    with self.assertRaises(PermissionError) as caught:
                        noise.await_handoffs(1000, 100)
                self.assertIs(caught.exception, failure)
                fact = noise.prelude['failure']
                self.assertEqual((fact['phase'], fact['error_type'], fact['winerror'], fact['errno']),
                                 (phase, 'PermissionError', 32, 13))
                self.assertEqual(fact['receipt_leaf'], 'progress-0013.json')
                self.assertNotIn('PRIVATE_USER_PATH', json.dumps(fact))
                self.assertEqual(noise.prelude['status'], 'FAILED')
                hashed.assert_not_called()

    def test_factory_prelude_failure_normally_stops_noise_before_wpr_and_keeps_primary(self):
        from tools import qa_decoder_budget_diagnostic as driver
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); order = []; caught = []
            failure = PermissionError(13, 'PRIVATE_PRELUDE_PATH')
            failure.winerror = 5
            actual = SimpleNamespace(active=True, qa_profile='cpu_file', profile_entry='fixed',
                                     profile_path=root / 'profile.wprp')
            def cancel():
                order.append('wpr_cancel'); actual.active = False
            actual.cancel = cancel
            def start(noise):
                noise.owner = SimpleNamespace(process=SimpleNamespace(poll=lambda: None))
            def stop(noise):
                order.append('noise_stop')
                noise.oracle = {'workers': [{'handoffs': 1} for _ in range(16)]}  # Protocol fixture only.
                noise.cleanup = {'status': 'COMPLETED'}
            def workload(output, helper, **options):
                try:
                    driver.apps.start_schedule(output, profile='cpu_file')
                except BaseException as error:
                    caught.append(error)
                    raise
            producer = {'implementation': 'PYTHON_CTYPES_WIN32', 'source_sha256': 'a' * 64,
                        'executable_sha256': 'b' * 64, 'expected_native_handles': 16}
            with patch.object(driver, 'source_identity', return_value={'source_identity_status': 'VERIFIED_EXPECTED_HEAD'}), \
                    patch.object(driver, 'kernel_api', return_value=object()), \
                    patch.object(driver, 'counter', return_value=1000), \
                    patch('tools.qa_decoder_apps.start_schedule', return_value=actual), \
                    patch('tools.qa_decoder_apps.seven_zip', side_effect=workload), \
                    patch('tools.qa_decoder_apps.file_hash', return_value='c' * 64), \
                    patch.object(driver.NoiseOwner, 'start', autospec=True, side_effect=start), \
                    patch.object(driver.NoiseOwner, 'await_handoffs', side_effect=failure), \
                    patch.object(driver.NoiseOwner, 'stop', autospec=True, side_effect=stop), \
                    patch.object(driver.NoiseOwner, 'abort') as abort, \
                    patch.object(driver, 'collect_bounded_case_facts'), \
                    patch.object(driver, 'collect_noise_stop_observation'), redirect_stdout(io.StringIO()):
                proof = driver.run_case(root / 'case', root / 'helper.exe', 'a' * 40, 100,
                    'cpu_file', producer, 'OUTPUT_BUDGET_NEGATIVE', 1000,
                    native_module_encoding='INLINE_V1', minimum_prelude_seconds=10)
            self.assertEqual(order, ['noise_stop', 'wpr_cancel'])
            self.assertEqual(len(caught), 1); self.assertIs(caught[0], failure)
            self.assertEqual(proof['status'], 'REPRODUCTION_NOT_ESTABLISHED')
            self.assertEqual(proof['capture_cleanup'], {'status': 'CANCELLED', 'cleanup_required': False})
            self.assertEqual(proof['noise_cleanup']['status'], 'COMPLETED')
            self.assertEqual(proof['capture_lifecycle']['primary_error']['phase'], 'NOISE_START_OR_PRELUDE')
            self.assertEqual(proof['capture_lifecycle']['primary_error']['winerror'], 5)
            abort.assert_not_called()


class NativePositiveCapturePreparationTests(unittest.TestCase):
    """Order/failure protocol fixtures; never substitute for real native A/B."""
    def invoke(self, *, role='native_positive', fault=None):
        from tools import qa_decoder_budget_diagnostic as driver
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); order=[]; caught=[]
            failure=PermissionError(13, 'PROTOCOL_PREPARATION_FAILURE'); failure.winerror=5
            boundary=AssertionError('PROTOCOL_AFTER_FACTORY')
            native=role!='python_byte'; profile='schedule' if role=='native_row' else 'cpu_file'
            expectation={'native_positive':'COMPLETE_NATIVE_7ZIP', 'native_row':'NATIVE_BUDGET_NEGATIVE',
                         'python_byte':'OUTPUT_BUDGET_NEGATIVE'}[role]
            actual=SimpleNamespace(active=False,qa_profile=profile,profile_entry='fixed',profile_path=root/'profile.wprp')
            def cancel():
                order.append('wpr_cancel'); actual.active=False
            actual.cancel=cancel
            def original(folder, **options):
                order.append('wpr_start')
                if fault=='wpr': raise failure
                actual.active=True
                return actual
            def start(noise):
                order.append('noise_start')
                noise.owner=SimpleNamespace(process=SimpleNamespace(poll=lambda:None))
                noise.ready={'qpc_frequency_hz':1000,'begin_qpc':900}
            def prelude(noise, target, deadline, **options):
                order.append('prelude')
                self.assertEqual(target,1000); self.assertEqual(options['minimum_seconds'],0 if native else 10)
                if fault=='prelude': raise failure
                noise.prelude={'status':'COMPLETED','target_handoffs':target,'observed_handoffs':2000}
            def stop(noise):
                order.append('noise_stop')
                noise.oracle={'workers':[{'handoffs':1} for _ in range(16)]}
                noise.cleanup={'status':'COMPLETED'}
            def workload(output, helper, **options):
                capture=None
                try:
                    capture=driver.apps.start_schedule(output,profile=profile)
                    order.append('workload_begin')
                    raise boundary  # Stop after proving factory ordering; no fake acceptance.
                except BaseException as error:
                    caught.append(error)
                    raise
                finally:
                    if capture is not None: capture.cancel()
            producer={'implementation':'NATIVE_WIN32' if native else 'PYTHON_CTYPES_WIN32',
                      'source_sha256':'a'*64,'executable_sha256':'b'*64,'expected_native_handles':32 if native else 16}
            with patch.object(driver,'source_identity',return_value={'source_identity_status':'VERIFIED_EXPECTED_HEAD'}), \
                    patch.object(driver,'kernel_api',return_value=object()), \
                    patch.object(driver,'counter',return_value=1000), \
                    patch.object(driver.time,'monotonic',return_value=0), \
                    patch('tools.qa_decoder_apps.start_schedule',side_effect=original) as factory, \
                    patch('tools.qa_decoder_apps.seven_zip',side_effect=workload), \
                    patch('tools.qa_decoder_apps.file_hash',return_value='c'*64), \
                    patch.object(driver.NoiseOwner,'start',autospec=True,side_effect=start), \
                    patch.object(driver.NoiseOwner,'await_handoffs',autospec=True,side_effect=prelude), \
                    patch.object(driver.NoiseOwner,'stop',autospec=True,side_effect=stop), \
                    patch.object(driver.NoiseOwner,'abort') as abort, \
                    patch.object(driver,'collect_bounded_case_facts'), \
                    patch.object(driver,'collect_noise_stop_observation'),redirect_stdout(io.StringIO()):
                proof=driver.run_case(root/'case',root/'helper.exe','a'*40,100,profile,producer,expectation,
                    0 if role=='native_row' else 1000, minimum_prelude_seconds=0 if native else 10,
                    native_module_encoding=None if native else 'INLINE_V1')
            abort.assert_not_called()
            self.assertEqual(proof['status'],'REPRODUCTION_NOT_ESTABLISHED')
            return proof,order,caught,failure,boundary,factory.call_count

    def test_native_positive_prepares_then_starts_capture_before_workload(self):
        proof,order,caught,_,boundary,count=self.invoke()
        self.assertEqual(order,['noise_start','prelude','wpr_start','workload_begin','noise_stop','wpr_cancel'])
        self.assertEqual(caught,[boundary]);self.assertEqual(count,1)
        lifecycle=proof['capture_lifecycle']
        self.assertEqual(lifecycle['prelude_capture_scope'],'NATIVE_POSITIVE_PREPARATION_BEFORE_WPR')
        self.assertLessEqual(lifecycle['prelude_completed_qpc'],lifecycle['capture_start_request_qpc'])
        self.assertLessEqual(lifecycle['capture_start_complete_qpc'],proof['noise_workload_qpc_bounds']['begin_qpc'])
        self.assertEqual(proof['capture_cleanup'],{'status':'CANCELLED','cleanup_required':False})

    def test_native_positive_prelude_failure_never_starts_wpr_and_normally_stops_noise(self):
        proof,order,caught,failure,_,count=self.invoke(fault='prelude')
        self.assertEqual(order,['noise_start','prelude','noise_stop']);self.assertEqual(count,0)
        self.assertEqual(len(caught),1);self.assertIs(caught[0],failure)
        self.assertEqual(proof['capture_cleanup'],{'status':'NOT_STARTED','cleanup_required':False})
        self.assertEqual(proof['capture_lifecycle']['primary_error']['phase'],'NOISE_START_OR_PRELUDE')

    def test_native_positive_wpr_start_failure_keeps_primary_and_noise_cleanup(self):
        proof,order,caught,failure,_,count=self.invoke(fault='wpr')
        self.assertEqual(order,['noise_start','prelude','wpr_start','noise_stop']);self.assertEqual(count,1)
        self.assertEqual(len(caught),1);self.assertIs(caught[0],failure)
        self.assertEqual(proof['capture_lifecycle']['primary_error']['phase'],'WPR_START')
        self.assertTrue(proof['capture_cleanup']['cleanup_required'])
        self.assertEqual(proof['noise_cleanup']['status'],'COMPLETED')

    def test_python_byte_prelude_stays_recorded_and_native_row_order_stays_unchanged(self):
        for role,expected in [('python_byte',['wpr_start','noise_start','prelude','workload_begin','noise_stop','wpr_cancel']),
                              ('native_row',['wpr_start','noise_start','workload_begin','noise_stop','wpr_cancel'])]:
            with self.subTest(role=role):
                proof,order,_,_,_,_=self.invoke(role=role)
                self.assertEqual(order,expected)
                self.assertEqual(proof['capture_lifecycle']['prelude_capture_scope'],'PRELUDE_RECORDED_WITHIN_WPR')


class OwnedGuiQueueProtocolTests(unittest.TestCase):
    """Fake User32 contract tests, not evidence of a real responsive window."""
    def user(self, *, pid=77, tid=88, post_success=True, query_success=True):
        class Function:
            def __init__(self, call): self.call = call
            def __call__(self, *args): return self.call(*args)
        calls = []
        def identity(hwnd, pointer):
            calls.append(('identity', hwnd)); pointer._obj.value = pid
            return tid
        def post(*args):
            calls.append(('post', *args)); return int(post_success)
        def query(*args):
            calls.append(('query', *args[:6])); args[-1]._obj.value = 12
            return int(query_success)
        return SimpleNamespace(GetWindowThreadProcessId=Function(identity),
            PostMessageW=Function(post), SendMessageTimeoutW=Function(query)), calls

    def test_only_fixed_pointer_free_actions_are_queued_once_after_each_ownership_check(self):
        from tools import qa_decoder_apps as apps
        user, calls = self.user()
        with patch.object(apps.C, 'WinDLL', return_value=user, create=True), \
                patch.object(apps.C, 'set_last_error', create=True):
            for message, first, second, phase in ((2160, 12, 12, 'SELECT_END'),
                    (0x102, 65, 0, 'APPEND_CHARACTER'), (0x111, 41006, 0, 'SAVE_DOCUMENT'),
                    (0x10, 0, 0, 'CLOSE_WINDOW')):
                apps.post_owned(77, 101, message, first, second, expected_tid=88, phase=phase)
        self.assertEqual([row[0] for row in calls], ['identity', 'post'] * 4)
        self.assertEqual([row[2] for row in calls if row[0] == 'post'], [2160, 0x102, 0x111, 0x10])
        for message, first, second in ((0x102, 65, 1), (2160, 12, 13), (0x111, 1, 0), (0x10, 1, 0), (9999, 0, 0)):
            with patch.object(apps.C, 'WinDLL', create=True) as library, \
                    self.assertRaisesRegex(AssertionError, 'UNSUPPORTED_GUI_ACTION'):
                apps.post_owned(77, 101, message, first, second, expected_tid=88, phase='SAVE_DOCUMENT')
            library.assert_not_called()

    def test_ownership_and_queue_tid_changes_reject_before_posting(self):
        from tools import qa_decoder_apps as apps
        for pid, tid, reason in ((78, 88, 'OWNERSHIP_CHANGED'), (77, 89, 'GUI_THREAD_CHANGED'), (77, 0, 'OWNERSHIP_CHANGED')):
            user, calls = self.user(pid=pid, tid=tid)
            with patch.object(apps.C, 'WinDLL', return_value=user, create=True), \
                    self.assertRaisesRegex(AssertionError, reason):
                apps.post_owned(77, 101, 0x10, expected_tid=88, phase='CLOSE_WINDOW')
            self.assertFalse(any(row[0] == 'post' for row in calls))

    def test_failed_query_keeps_five_hundred_ms_and_safe_phase_error_facts(self):
        from tools import qa_decoder_apps as apps
        user, calls = self.user(query_success=False); printed = io.StringIO()
        with patch.object(apps.C, 'WinDLL', return_value=user, create=True), \
                patch.object(apps.C, 'set_last_error', create=True), \
                patch.object(apps.C, 'get_last_error', return_value=1460, create=True), redirect_stdout(printed), \
                self.assertRaisesRegex(AssertionError, 'OWNED_GUI_MESSAGE_FAILED_1460_VERIFY_DOCUMENT_LENGTH'):
            apps.send_owned(77, 101, 2006, phase='VERIFY_DOCUMENT_LENGTH')
        fact = json.loads(printed.getvalue().split('THIRD_PARTY_DECODER_GUI_FAILURE_FACTS ', 1)[1])
        self.assertEqual((fact['phase'], fact['message_code'], fact['winerror']), ('VERIFY_DOCUMENT_LENGTH', 2006, 1460))
        self.assertEqual((fact['configured_timeout_ms'], fact['window_tid_at_query']), (500, 88))
        self.assertEqual([row[-2:] for row in calls if row[0] == 'query'], [(34, 500)])

    def test_readiness_retries_only_readonly_timeout_and_other_failures_keep_identity(self):
        from tools import qa_decoder_apps as apps
        owner = SimpleNamespace(process=SimpleNamespace(pid=77, poll=lambda: None)); now = [0.0]
        def advance(seconds): now[0] += seconds
        timeout = AssertionError('OWNED_GUI_MESSAGE_FAILED_1460_VERIFY_DOCUMENT_LENGTH')
        with patch.object(apps.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(apps.time, 'sleep', side_effect=advance), \
                patch.object(apps, 'send_owned', side_effect=[timeout, 4, 12]) as probe, \
                patch.object(apps, 'post_owned') as action:
            self.assertEqual(apps.await_owned_length(owner, 101, 12, 1, 'VERIFY_DOCUMENT_LENGTH'), 12)
        self.assertEqual(probe.call_count, 3); action.assert_not_called()
        failure = AssertionError('NOTEPAD_WINDOW_OWNERSHIP_CHANGED')
        with patch.object(apps.time, 'monotonic', return_value=0), \
                patch.object(apps, 'send_owned', side_effect=failure) as probe, \
                patch.object(apps.time, 'sleep') as sleep, self.assertRaises(AssertionError) as caught:
            apps.await_owned_length(owner, 101, 12, 1, 'VERIFY_DOCUMENT_LENGTH')
        self.assertIs(caught.exception, failure); probe.assert_called_once(); sleep.assert_not_called()
        with patch.object(apps.time, 'monotonic', side_effect=[0, 2]), \
                patch.object(apps, 'send_owned', return_value=12), \
                self.assertRaisesRegex(AssertionError, 'DOCUMENT_READY_NOT_ESTABLISHED'):
            apps.await_owned_length(owner, 101, 12, 1, 'VERIFY_DOCUMENT_LENGTH')


class ImmutableReceiptSnapshotTests(unittest.TestCase):
    """Private-file contracts; fake kernel faults are not native workload proof."""
    def test_actual_private_file_bytes_json_hash_and_size_are_one_snapshot(self):
        from tools import qa_decoder_budget_diagnostic as driver
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'progress-0001.json'
            raw = b'{"counter":1}\r\n'; path.write_bytes(raw); context = {}
            self.assertEqual(driver.read_json(path, phase_context=context), {'counter': 1})
            self.assertEqual(context['receipt_bytes'], len(raw))
            self.assertEqual(context['receipt_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(context['snapshot_scope'], 'ONE_READONLY_HANDLE_BYTES_JSON_SIZE_SHA_NO_REOPEN')
            self.assertFalse(driver._RETAINED_RECEIPT_HANDLES)
            path.unlink()  # File lifecycle check; checked CloseHandle is the Windows close proof.
            self.assertFalse(path.exists())

    def test_oversize_and_malformed_private_files_still_fail_without_retained_handles(self):
        from tools import qa_decoder_budget_diagnostic as driver
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'progress-0001.json'; path.write_bytes(b'{"counter":1}')
            with self.assertRaisesRegex(AssertionError, 'DIAGNOSTIC_RECEIPT_SIZE'):
                driver.read_json(path, limit=2)
            path.write_bytes(b'{')
            with self.assertRaises(json.JSONDecodeError): driver.read_json(path)
            self.assertFalse(driver._RETAINED_RECEIPT_HANDLES)
            path.unlink()

    def kernel(self, driver, raw, *, read_ok=True, close_ok=True, close_raises=False, changed=False, attributes=32):
        class Function:
            def __init__(self, call): self.call = call
            def __call__(self, *args): return self.call(*args)
        calls = []; infos = [0]
        def create(*args): calls.append(('open', *args)); return 51
        def info(handle, pointer):
            infos[0] += 1; row = pointer._obj
            row.attributes=attributes; row.links=1; row.volume=7; row.index_low=9
            row.size_high=0; row.size_low=len(raw); row.created.dwLowDateTime=10
            row.written.dwLowDateTime=20 + int(changed and infos[0] > 1)
            row.accessed.dwLowDateTime=infos[0]  # Reading may legitimately change access time.
            calls.append(('info', handle)); return 1
        def read(handle, buffer, size, count, overlapped):
            calls.append(('read', handle, size)); driver.C.memmove(buffer, raw, len(raw))
            count._obj.value=len(raw); return int(read_ok)
        def close(handle):
            calls.append(('close', handle))
            if close_raises: raise RuntimeError('PRIVATE_KERNEL_CLOSE_FAILURE')
            return int(close_ok)
        return SimpleNamespace(CreateFileW=Function(create), GetFileType=Function(lambda handle: 1),
            GetFileInformationByHandle=Function(info), ReadFile=Function(read), CloseHandle=Function(close)), calls

    def invoke_windows(self, **options):
        from tools import qa_decoder_budget_diagnostic as driver
        raw=b'{"counter":1}\r\n'; kernel,calls=self.kernel(driver,raw,**options)
        def winerror(code):
            failure=PermissionError(13, 'PRIVATE_KERNEL_PATH_WITHHELD'); failure.winerror=code
            return failure
        retained=[]; context={}; result=None; error=None
        with patch.object(driver.C,'WinDLL',return_value=kernel,create=True), \
                patch.object(driver.C,'get_last_error',return_value=32,create=True), \
                patch.object(driver.C,'WinError',side_effect=winerror,create=True), \
                patch.object(driver,'_RETAINED_RECEIPT_HANDLES',retained):
            try: result=driver._windows_receipt_bytes(Path('progress-0001.json'),32768,context)
            except BaseException as failure: error=failure
        return driver,raw,result,error,retained,context,calls

    def test_win32_open_requests_readonly_access_and_all_sharing_with_checked_close(self):
        driver,raw,result,error,retained,context,calls=self.invoke_windows()
        self.assertIsNone(error); self.assertEqual(result,raw); self.assertEqual(retained,[])
        self.assertEqual(driver.C.sizeof(driver.ReceiptFileInfo),52)
        opened=calls[0]
        self.assertEqual((opened[2],opened[3],opened[5],opened[6]),(0x80000000,7,3,0x00200000))
        self.assertEqual([row[0] for row in calls],['open','info','read','info','close'])
        self.assertEqual(calls[-1],('close',51))

    def test_win32_read_change_reparse_and_close_failures_never_become_success(self):
        for options in ({'read_ok':False},{'changed':True},{'attributes':0x400},{'close_ok':False},{'close_raises':True}):
            with self.subTest(options=options):
                _,_,result,error,retained,context,calls=self.invoke_windows(**options)
                self.assertIsNone(result); self.assertIsNotNone(error)
                self.assertEqual(sum(row[0]=='close' for row in calls),1)
                self.assertEqual(len(retained),int(options.get('close_ok') is False or options.get('close_raises') is True))
        for options in ({'close_ok':False},{'close_raises':True}):
            with self.subTest(primary_read_failure=True,options=options):
                _,_,result,error,retained,context,calls=self.invoke_windows(read_ok=False,**options)
                self.assertIsInstance(error,PermissionError); self.assertEqual(error.winerror,32)
                self.assertEqual(len(retained),1)
                self.assertTrue(any('RECEIPT_HANDLE_CLOSE_UNCONFIRMED' in note for note in error.__notes__))


if __name__ == "__main__":
    unittest.main()
