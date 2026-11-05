"""Portable QA protocol/profile/download boundaries, not native Windows evidence."""
from contextlib import closing, redirect_stdout
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
                                   observed_process_image, safe_extract)
from tools.qa_decoder_budget_diagnostic import (PAIRS, parse_args, validate_noise_oracle,
    SEVENZIP_CAPABILITIES, validate_comparison, validate_original_source, validate_positive,
    validate_progress, validate_rejection, validate_workload_activity, validate_case_contract,
    validate_output_observation, seal_and_remove_large_evidence, collect_bounded_case_facts)
from tools.qa_decoder_budget_diagnostic import native_attribution
from tools.qa_schedule_capture import profile_definition
from tools.qa_decoder_noise_fixture import (_close_owner_with_checked_handles,
    _compiler_worker_environment, _require_compiler_policy, _configured_compiler_environment,
    _stop_completed_compiler_job)


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
        common = {'input_sha256': 'a' * 64, 'input_bytes': 8 * 1024**2, 'application_sha256': 'b' * 64,
            'native_image': {'code_kind': 'NATIVE_PE_NO_CLR_COM_DESCRIPTOR'}, 'helper_sha256': 'c' * 64,
            'script_hashes': {'driver': 'd' * 64},
            'actual_native_module_encoding': 'PER_EVENT_MODULES_V1',
            'noise_producer': {'implementation': 'NATIVE_WIN32', 'source_sha256': '3' * 64,
                               'executable_sha256': '4' * 64, 'expected_native_handles': 32},
            'source_identity': {'actual_source_sha': 'e' * 40, 'source_tree_sha': 'f' * 40},
            'noise_cleanup': {'status': 'COMPLETED'}, 'capture_cleanup': {'status': 'STOPPED'},
            'noise_workload_coverage': {'all_16_threads_bracket': True, 'threads_with_positive_handoff_delta': 16},
            'roundtrips_verified': 2}
        first = {**common, 'status': 'EXPECTED_NATIVE_BUDGET_NEGATIVE', 'noise_handoffs': 10000,
            'capture_profile': {'name': 'schedule', 'xml_sha256': '1' * 64}}
        second = {**common, 'status': 'COMPLETE_7ZIP_ACCEPTANCE', 'noise_handoffs': 20000,
            'capture_profile': {'name': 'cpu_file', 'xml_sha256': '2' * 64},
            'prelude': {'target_handoffs': 10000, 'observed_handoffs': 11000, 'wait_seconds': 1}}
        validate_comparison(first, second)
        for change in ({'noise_handoffs': 9999}, {'roundtrips_verified': 1}, {'application_sha256': '0' * 64},
                       {'noise_workload_coverage': {'all_16_threads_bracket': False}},
                       {'prelude': {**second['prelude'], 'wait_seconds': 16}}):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                validate_comparison(first, {**second, **change})

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


if __name__ == "__main__":
    unittest.main()
