"""Hosted progress/read and log-projection contracts; not one-hour acceptance."""
from contextlib import closing, contextmanager
from copy import deepcopy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from tools import qa_wave02_endurance as endurance
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


class OwnedProgressReadTests(unittest.TestCase):
    def fixture(self, root):
        folder = root / 'sessions' / 'actual-sqlite-fixture'
        folder.mkdir(parents=True)
        with closing(sqlite3.connect(folder / 'session.sqlite3')) as db:
            db.execute('CREATE TABLE samples(seq INTEGER PRIMARY KEY,elapsed_ms INTEGER NOT NULL)')
            db.execute('INSERT INTO samples VALUES(1,0)')
            db.commit()
        packet = {'source_sha': 'a' * 40, 'profile': 'STANDARD', 'pid': 123,
                  'session': str(folder), 'sample_count': 1, 'status': 'RUNNING'}
        path = root / 'progress.json'
        path.write_text(json.dumps(packet), encoding='utf-8')
        watch = {'root': root, 'count': 1, 'last_advance': 100., 'launched': 0.,
                 'session': str(folder), 'complete': False, 'span_seconds': 0.}
        return path, folder, packet, watch

    def poll(self, watch, now):
        return endurance.poll_owned_progress(watch, profile='STANDARD', pid=123,
                                             source_sha='a' * 40, now=now)

    def advance(self, folder):
        with closing(sqlite3.connect(folder / 'session.sqlite3')) as db:
            db.execute('INSERT INTO samples VALUES(2,1000)')
            db.commit()

    def test_denied_snapshot_does_not_ack_advance_and_next_read_uses_actual_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, folder, packet, watch = self.fixture(Path(temporary))
            before = hashlib.sha256(path.read_bytes()).hexdigest()
            prior = deepcopy(watch)
            self.advance(folder)
            # Cross-platform policy injection only; the Windows case below
            # separately establishes an actual OS sharing denial.
            denied = PermissionError(13, 'CONTROLLED_PROGRESS_READ_DENIAL')
            with patch.object(Path, 'read_text', side_effect=denied):
                self.assertIsNone(self.poll(watch, 110.))
            self.assertEqual(watch, prior)
            current = self.poll(watch, 115.)
            self.assertEqual(current['count'], 2)
            self.assertEqual(watch['last_advance'], 115.)
            self.assertEqual(watch['span_seconds'], 1.)
            self.assertEqual(json.loads(path.read_text())['sample_count'], 1)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
            # A readable unchanged heartbeat is not persisted advancement.
            self.poll(watch, 125.)
            self.assertEqual(watch['last_advance'], 115.)

    def test_persistent_denial_expires_original_progress_watchdog_and_retains_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, folder, packet, watch = self.fixture(Path(temporary))
            prior = deepcopy(watch)
            before = path.read_bytes()
            denied = PermissionError(13, 'CONTROLLED_PERSISTENT_PROGRESS_DENIAL')
            with patch.object(Path, 'read_text', side_effect=denied):
                for now in (105., 110., 120., 130.):
                    self.assertIsNone(self.poll(watch, now))
                    self.assertEqual(watch, prior)
                with self.assertRaisesRegex(AssertionError, 'PERSISTED_PROGRESS_FROZEN_STANDARD') as failure:
                    self.poll(watch, 130.001)
            self.assertIs(failure.exception.__cause__, denied)
            self.assertEqual(watch, prior)
            self.assertEqual(path.read_bytes(), before)
            self.assertTrue((folder / 'session.sqlite3').is_file())
            # Even new rows after the deadline cannot revive an expired watch.
            self.advance(folder)
            with self.assertRaisesRegex(AssertionError, 'PERSISTED_PROGRESS_FROZEN_STANDARD'):
                self.poll(watch, 131.)
            self.assertEqual(watch, prior)

    def test_missing_snapshot_uses_startup_or_persisted_deadline_without_resetting_either(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            watch = {'root': root, 'count': 0, 'last_advance': 0., 'launched': 0.,
                     'session': None, 'complete': False}
            prior = deepcopy(watch)
            for now in (5., 60., 90.):
                self.assertIsNone(self.poll(watch, now))
            with self.assertRaisesRegex(AssertionError, 'CHILD_NOT_STARTED_STANDARD') as failure:
                self.poll(watch, 90.001)
            self.assertIsInstance(failure.exception.__cause__, FileNotFoundError)
            self.assertEqual(watch, prior)
            watch.update(count=1, last_advance=100., session='already-verified')
            prior = deepcopy(watch)
            self.assertIsNone(self.poll(watch, 110.))
            with self.assertRaisesRegex(AssertionError, 'PERSISTED_PROGRESS_FROZEN_STANDARD'):
                self.poll(watch, 130.001)
            self.assertEqual(watch, prior)

    def test_invalid_snapshot_and_database_or_final_receipt_denial_are_not_retried(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, folder, packet, watch = self.fixture(Path(temporary))
            prior = deepcopy(watch)
            for contents, reason in (('{', 'Expecting'), ('x' * 8193, 'JSON_BUDGET'),
                                     (json.dumps(dict(packet, source_sha='b' * 40)), 'IDENTITY_MISMATCH')):
                with self.subTest(reason=reason):
                    path.write_text(contents, encoding='utf-8')
                    with self.assertRaisesRegex((ValueError, AssertionError), reason):
                        self.poll(watch, 110.)
                    self.assertEqual(watch, prior)
            path.write_text(json.dumps(packet), encoding='utf-8')
            denied = PermissionError(13, 'DATABASE_OR_FINAL_EVIDENCE_DENIAL')
            with patch.object(endurance, 'actual_progress', side_effect=denied):
                with self.assertRaises(PermissionError) as failure:
                    self.poll(watch, 110.)
            self.assertIs(failure.exception, denied)
            self.assertEqual(watch, prior)
            with patch.object(Path, 'read_text', side_effect=denied):
                with self.assertRaises(PermissionError):
                    endurance.read_json(path)

    @contextmanager
    def deny_windows_read(self, path):
        from ctypes import wintypes as W
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, ctypes.c_void_p,
                                      W.DWORD, W.DWORD, W.HANDLE]
        kernel.CreateFileW.restype = W.HANDLE
        kernel.CloseHandle.argtypes = [W.HANDLE]
        kernel.CloseHandle.restype = W.BOOL
        handle = kernel.CreateFileW(str(path), 0x80000000, 0, None, 3, 0, None)
        self.assertNotIn(handle, (None, ctypes.c_void_p(-1).value))
        try:
            # Prove the actual owned file is unreadable before exercising the
            # progress poll. Never replace native denial with synthetic PASS.
            with self.assertRaises(PermissionError):
                path.read_bytes()
            yield
        finally:
            self.assertTrue(kernel.CloseHandle(handle), 'Actual owned deny-read handle close must be acknowledged')

    @unittest.skipUnless(os.name == 'nt', 'Actual Windows owned-file share-denial case')
    def test_actual_windows_read_denial_recovers_without_modifying_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, folder, packet, watch = self.fixture(Path(temporary))
            before = path.read_bytes()
            prior = deepcopy(watch)
            with self.deny_windows_read(path):
                self.advance(folder)
                self.assertIsNone(self.poll(watch, 110.))
                self.assertEqual(watch, prior)
            self.assertEqual(self.poll(watch, 115.)['count'], 2)
            self.assertEqual(watch['last_advance'], 115.)
            self.assertEqual(path.read_bytes(), before)

    @unittest.skipUnless(os.name == 'nt', 'Actual Windows persistent share-denial watchdog case')
    def test_actual_windows_persistent_denial_cannot_refresh_progress_watchdog(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, folder, packet, watch = self.fixture(Path(temporary))
            before = path.read_bytes()
            prior = deepcopy(watch)
            with self.deny_windows_read(path):
                for now in (110., 120., 130.):
                    self.assertIsNone(self.poll(watch, now))
                with self.assertRaisesRegex(AssertionError, 'PERSISTED_PROGRESS_FROZEN_STANDARD') as failure:
                    self.poll(watch, 130.001)
                self.assertIsInstance(failure.exception.__cause__, PermissionError)
                self.assertEqual(watch, prior)
            self.assertEqual(path.read_bytes(), before)
            self.assertTrue((folder / 'session.sqlite3').is_file())


if __name__ == '__main__':
    unittest.main()
