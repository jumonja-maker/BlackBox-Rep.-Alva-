"""Synthetic log-projection contracts; these are not endurance/native evidence."""
from copy import deepcopy
import json
import unittest

from tools.qa_wave02_endurance import artifactless_profile_facts


def observed_result(profile='INCIDENT_BURST'):
    return {'profile': profile, 'status': 'PASS',
        'saved': {
            'database_finalization': {'database_count': 4, 'integrity_ok_databases': 4,
                'nonempty_wal_files': 0, 'schema1_exit_code': 'COMPLETED', 'schema2_status': 'CLOSED',
                'schema2_exit_code': 'COMPLETED', 'schema2_writer_dropped_commands': 0,
                'research_state': 'COMPLETED', 'recording_resources_closed': True, 'finalization_error_count': 0},
            'schema2_standard_samples': 1802, 'schema2_detail_samples': 122,
            'incident_count': 71, 'burst_starts': 12, 'burst_ttl_stops': 12, 'manual_incident_refs': 60,
            'recorded_peak_cpu_one_cpu_percent': 102.5, 'recorded_rss_range_bytes': 40 * 1024**2,
            'recorded_write_bytes_delta': 1024 * 1024,
            'detail_threads': {'owner_count': 12, 'live_thread_count': 0, 'error_count': 0},
            'trigger_coverage': None if profile == 'STANDARD' else {
                'observed_codes': ['CPU_SUSTAINED', 'IO_BURST', 'MANUAL_PROBLEM', 'RSS_GROWTH'],
                'incomplete_prehistory_count': 2}},
        'recorder_cleanup': {'recording_resources_closed': True, 'optional_jobs_cleanup_required': False,
            'pending_owned_process_owners': 0, 'writer_thread_alive': False, 'journal_thread_alive': False},
        'stop': {'state': 'COMPLETED', 'base_recording_state': 'COMPLETED', 'cleanup_required': False, 'errors': []},
        'target_cleanup': {'status': 'COMPLETED', 'exit_code': 0,
                           'oracle': {'cleanup_complete': True}}}


class ArtifactlessEnduranceReceiptTests(unittest.TestCase):
    def test_observed_sql_measurements_and_cleanup_facts_survive_without_acceptance_claim(self):
        source = observed_result()
        before = deepcopy(source)
        result = artifactless_profile_facts(source)
        self.assertEqual(result['status'], 'OBSERVED_FIXED_FACTS')
        self.assertEqual(result['unavailable_fields'], [])
        self.assertEqual(result['saved_measurements']['schema2_standard_samples'], 1802)
        self.assertEqual(result['saved_measurements']['recorded_write_bytes_delta'], 1024 * 1024)
        self.assertEqual(result['database_finalization']['schema2_status'], 'CLOSED')
        self.assertFalse(result['recorder_cleanup']['writer_thread_alive'])
        self.assertTrue(result['target_cleanup']['native_oracle_cleanup_complete'])
        self.assertEqual(result['trigger_coverage']['incomplete_prehistory_count'], 2)
        self.assertNotIn('endurance_acceptance', result)
        self.assertEqual(source, before)

    def test_private_paths_payloads_errors_and_arbitrary_keys_never_enter_job_log_projection(self):
        source = observed_result()
        secret = 'PRIVATE_FILE_PATH_PAYLOAD_ENVIRONMENT_OR_MEMORY_MUST_NOT_APPEAR'
        source.update(session=secret, minute_samples=[secret], private_payload={'value': secret})
        source['saved']['database_finalization']['private_metadata'] = secret
        source['saved']['detail_threads']['thread_object'] = secret
        source['recorder_cleanup']['private_handle'] = secret
        source['stop']['errors'] = [secret]
        source['target_cleanup']['oracle'].update(path=secret, command=secret, memory=secret)
        result = artifactless_profile_facts(source)
        text = json.dumps(result, allow_nan=False)
        self.assertNotIn(secret, text)
        self.assertEqual(result['stop']['error_count'], 1)
        self.assertLess(len(text.encode('utf-8')), 8192)

    def test_bool_negative_nonfinite_and_oversized_measurements_stay_unavailable(self):
        for value in (True, -1, float('nan'), float('inf'), 2**10000, 'PRIVATE_BAD_COUNTER', []):
            source = observed_result()
            source['saved']['recorded_rss_range_bytes'] = value
            source['saved']['incident_count'] = value
            with self.subTest(type=type(value).__name__):
                result = artifactless_profile_facts(source)
                self.assertEqual(result['status'], 'NOT_ESTABLISHED')
                self.assertIsNone(result['saved_measurements']['recorded_rss_range_bytes'])
                self.assertIsNone(result['saved_measurements']['incident_count'])
                self.assertIn('incident_count', result['unavailable_fields'])
                self.assertNotIn('PRIVATE_BAD_COUNTER', json.dumps(result, allow_nan=False))

    def test_missing_child_facts_never_become_successful_cleanup_or_zero_counters(self):
        for source in ({'status': 'PASS'}, None, [], {'saved': None, 'stop': []}):
            with self.subTest(type=type(source).__name__):
                result = artifactless_profile_facts(source)
                self.assertEqual(result['status'], 'NOT_ESTABLISHED')
                self.assertIsNone(result['saved_measurements']['incident_count'])
                self.assertIsNone(result['recorder_cleanup']['recording_resources_closed'])
                self.assertIsNone(result['target_cleanup']['native_oracle_cleanup_complete'])
                self.assertEqual(result['stop']['state'], 'NOT_ESTABLISHED')

    def test_observed_failure_values_are_retained_as_facts_without_being_renamed_pass(self):
        source = observed_result()
        source['status'] = 'FAIL'
        source['recorder_cleanup']['writer_thread_alive'] = True
        source['stop']['cleanup_required'] = True
        source['target_cleanup']['oracle']['cleanup_complete'] = False
        result = artifactless_profile_facts(source)
        self.assertTrue(result['recorder_cleanup']['writer_thread_alive'])
        self.assertTrue(result['stop']['cleanup_required'])
        self.assertFalse(result['target_cleanup']['native_oracle_cleanup_complete'])
        self.assertNotEqual(result['status'], 'PASS')

    def test_standard_trigger_scope_is_not_requested_and_invalid_incident_codes_are_not_echoed(self):
        result = artifactless_profile_facts(observed_result('STANDARD'))
        self.assertEqual(result['status'], 'OBSERVED_FIXED_FACTS')
        self.assertEqual(result['trigger_coverage'], {'status': 'NOT_REQUESTED_FOR_STANDARD'})
        for codes in (None, ['CPU_SUSTAINED'] * 2, ['PRIVATE_PROVIDER_OR_PATH'], [True], list(range(8))):
            source = observed_result()
            source['saved']['trigger_coverage']['observed_codes'] = codes
            with self.subTest(codes=repr(codes)):
                result = artifactless_profile_facts(source)
                self.assertEqual(result['status'], 'NOT_ESTABLISHED')
                self.assertIsNone(result['trigger_coverage']['observed_codes'])
                self.assertNotIn('PRIVATE_PROVIDER_OR_PATH', json.dumps(result, allow_nan=False))


if __name__ == '__main__':
    unittest.main()
