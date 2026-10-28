"""Audit regressions: literal profile search and truthful guardian termination."""
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from unittest.mock import patch
import tempfile
import unittest

from blackbox_core.decoder_index import read_index
from blackbox_core.trace_owner import TraceSupervisor, _read
from test_decoder_calltree import stack_row
from test_decoder_modules import write_index


class ProfileSearchAudit(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_unicode_is_searched_in_decoded_frame_values_only(self):
        path, _ = write_index(self.root, [stack_row(1, 'Пример.Класс.Метод')])
        before = path.read_bytes()
        for text in ('Пример', 'Метод', '0x1000'):
            with self.subTest(text=text):
                self.assertEqual(len(read_index(path, mode='cpu_stacks', search=text)['rows']), 1)
        for text in ('name', 'address', '\\u041f', 'stack_status'):
            with self.subTest(text=text):
                self.assertEqual(read_index(path, mode='cpu_stacks', search=text)['rows'], [])
        self.assertEqual(path.read_bytes(), before)

    def test_percent_underscore_and_backslash_are_literal_and_keyset_is_stable(self):
        rows = [stack_row(1, r'100%_literal\name'), stack_row(2, '10000literalXname'),
                stack_row(3, r'100%_literal\name', instance=9)]
        path, _ = write_index(self.root, rows)
        first = read_index(path, mode='cpu_stacks', search='%_literal\\', limit=1)
        self.assertEqual(len(first['rows']), 1); self.assertTrue(first['has_more'])
        second = read_index(path, mode='cpu_stacks', search='%_literal\\',
                            limit=1, after=first['next_cursor'])
        self.assertEqual(len(second['rows']), 1); self.assertFalse(second['has_more'])
        self.assertGreater(second['next_cursor'], first['next_cursor'])
        self.assertEqual(read_index(path, mode='cpu_stacks', search='%', pid=123)['rows'], [])

    def test_previous_profile_schema_is_read_without_migration(self):
        from contextlib import closing
        path, _ = write_index(self.root, [stack_row(1, 'Пример.Метод')])
        with closing(sqlite3.connect(path)) as db: db.execute('PRAGMA user_version=2')
        before = path.read_bytes()
        self.assertEqual(len(read_index(path, mode='cpu_stacks', search='Метод')['rows']), 1)
        self.assertEqual(path.read_bytes(), before)


class GuardianTerminalAudit(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def supervisor(self):
        # These journal/termination regressions do not test process birth-time
        # collection. Keep that unrelated native dependency deterministic; the
        # child process and its exit status below remain real.
        with patch('psutil.Process') as process:
            process.return_value.create_time.return_value = 1.0
            return TraceSupervisor(self.root)

    def guardian(self, state='RECORDING', code=7):
        trace = self.supervisor()
        trace.data.update(state=state, source='ETW_WPR')
        trace.path.write_text(json.dumps(trace.data), encoding='utf-8')
        trace.process = subprocess.Popen([sys.executable, '-c', f'import sys;sys.exit({code})'],
                                         stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
        self.addCleanup(self.cleanup, trace)
        trace.process.wait(timeout=10)
        return trace

    @staticmethod
    def cleanup(trace):
        if trace.process.poll() is None: trace.process.kill(); trace.process.wait(5)
        if trace.process.stdin is not None: trace.process.stdin.close()

    def test_dead_guardian_cannot_report_recording_and_stop_preserves_result(self):
        trace = self.guardian()
        before = trace.path.read_bytes()
        result = trace.poll()
        self.assertEqual(result['status'], 'CLEANUP_REQUIRED')
        self.assertEqual(result['reason'], 'GUARDIAN_EXITED_WITHOUT_FINAL_STATE')
        self.assertEqual(result['last_journal_state'], 'RECORDING')
        self.assertEqual(result['exit_code'], 7)
        self.assertIsNone(result['lost_events'])
        self.assertIsNone(trace.poll())
        self.assertEqual(trace.stop(), result)
        self.assertEqual(trace.path.read_bytes(), before, 'Explicit recovery owns journal mutation')

    def test_dead_guardian_after_starting_or_stopping_is_unconfirmed(self):
        for state in ('RESERVED', 'STARTING', 'STOPPING'):
            with self.subTest(state=state):
                trace = self.guardian(state, 0)
                self.assertEqual(trace.stop()['status'], 'CLEANUP_REQUIRED')
                self.assertEqual(_read(trace.path)['state'], state)

    def test_forced_owned_child_exit_does_not_claim_capture_stopped(self):
        trace = self.supervisor()
        trace.data.update(state='RECORDING')
        trace.path.write_text(json.dumps(trace.data))
        original = trace.path.read_bytes()
        trace.process = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(30)'],
                                         stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
        self.addCleanup(self.cleanup, trace)
        trace.process.terminate(); trace.process.wait(timeout=10)
        result = trace.poll()
        self.assertEqual(result['status'], 'CLEANUP_REQUIRED')
        self.assertEqual(result['reason'], 'GUARDIAN_EXITED_WITHOUT_FINAL_STATE')
        self.assertFalse(trace.active)
        self.assertIsNone(trace.process.stdin)
        self.assertEqual(trace.path.read_bytes(), original)
        self.assertEqual(trace.stop(), result)

    def test_process_exit_is_observed_before_final_journal_is_read(self):
        trace = self.supervisor()
        trace.data.update(state='RECORDING')
        trace.path.write_text(json.dumps(trace.data))
        class CompletingProcess:
            stdin = None
            def poll(self):
                final = dict(trace.data, state='COMPLETED')
                trace.path.write_text(json.dumps(final))
                return 0
        trace.process = CompletingProcess()
        self.assertEqual(trace.poll()['status'], 'COMPLETED')

    def test_terminal_completion_requires_matching_successful_process_exit(self):
        trace = self.guardian('COMPLETED', 7)
        result = trace.poll()
        self.assertEqual(result['status'], 'CLEANUP_REQUIRED')
        self.assertEqual(result['reason'], 'GUARDIAN_ABNORMAL_EXIT')

    def test_valid_terminal_result_is_consumed_once_and_cached_for_stop(self):
        for state, code in [('COMPLETED', 0), ('FAILED', 1), ('CLEANUP_REQUIRED', 1)]:
            with self.subTest(state=state):
                trace = self.guardian(state, code)
                result = trace.poll()
                self.assertEqual(result['status'], state)
                self.assertEqual(trace.stop(), result)

    def test_dead_guardian_with_corrupt_or_foreign_journal_keeps_recovery_uncertain(self):
        for data in ('invalid json', '[]', '{"instance":"OTHER","state":"COMPLETED"}'):
            with self.subTest(data=data):
                trace = self.guardian()
                trace.path.write_text(data)
                result = trace.poll()
                self.assertEqual(result['status'], 'CLEANUP_REQUIRED')
                self.assertEqual(result['reason'], 'JOURNAL_UNAVAILABLE')
                self.assertEqual(trace.stop(), result)
