"""Independent-format fixtures, not replacement Windows/endurance evidence."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
from html import escape
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from blackbox_universal import wave02_comparison_oracles as oracle


def protocol_id(kind, *parts):
    # Fixture follows the recorded graph-v3 ID wire format, without importing
    # BLACK.BOX stable_id, a product export writer or an import reader.
    return hashlib.sha256(json.dumps(['3.0.0', kind, *parts], ensure_ascii=True,
        separators=(',', ':'), sort_keys=True).encode('ascii')).hexdigest()


class ComparisonExportOracleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.folders = {}
        self.runs = {}
        for role, pid, run_id in (('before', 101, 'a' * 32), ('after', 102, 'b' * 32)):
            folder = self.root / role
            folder.mkdir()
            run = {'schema_version': 1, 'run_id': run_id,
                'process_identity': {'pid': pid, 'created_100ns': 123456 + pid},
                'identity_status': 'OS_OBSERVED_EXACT_FILETIME',
                'image': {'source_sha256': 'c' * 64, 'source_size_bytes': 123,
                          'content_integrity': 'HASHED_STABLE_FILE'},
                'clock_domain': {'source': 'BLACKBOX_LOCAL_MONOTONIC_NS',
                                 'cross_run_alignment': 'NOT_ESTABLISHED'}}
            for name in ('session.sqlite3', 'session-v2.sqlite3'):
                with sqlite3.connect(folder / name) as db:
                    db.execute('CREATE TABLE fixture(value TEXT)')
                    db.execute('INSERT INTO fixture VALUES (?)', (role,))
                db.close()
            with sqlite3.connect(folder / 'research.sqlite3') as db:
                db.execute('CREATE TABLE context(key TEXT PRIMARY KEY,data TEXT)')
                db.executemany('INSERT INTO context VALUES (?,?)', [
                    ('state', json.dumps('COMPLETED')),
                    ('capture_health', json.dumps({'recording_resources_closed': True, 'finalization_errors': []})),
                    ('environment', json.dumps({'platform': 'EXPLICIT_UNIT_FIXTURE'})),
                    ('capabilities', json.dumps({'privilege': 'EXPLICIT_UNIT_FIXTURE'})),
                    ('experiment', json.dumps({'run_identity': run, 'warmup_count': 0,
                        'scenario': 'owned recorded workload', 'workload': 'input-v1',
                        'scenario_version': '1', 'target_version': 'fixture-v1',
                        'profile': 'INCIDENT_BURST', 'interval_ms': 500, 'origin_monotonic_ns': 1000,
                        'capture_policy': {'profile': 'INCIDENT_BURST', 'incident_enabled': True}}))])
                db.execute('CREATE TABLE action_runs(action_id TEXT)')
                db.executemany('INSERT INTO action_runs VALUES (?)', [('action-1',), ('action-2',)])
            db.close()
            self.folders[role], self.runs[role] = folder, run

    def payload(self, *, second_call=False):
        start = datetime(2026, 11, 5, 7, 0, int(second_call), tzinfo=timezone.utc)
        call_id = ('e' if second_call else 'd') * 32
        limits = {'timeout_seconds': 30, 'scope': 'EXISTING_COMPONENT_BUDGET'}
        call = {'run_id': call_id, 'operation': 'research.compare', 'contract_version': 1,
            'started_at_utc': start.isoformat(), 'deadline_utc': (start + timedelta(seconds=30)).isoformat(),
            'started_monotonic_ns': 1000 + int(second_call) * 10**9,
            'deadline_monotonic_ns': 1000 + int(second_call) * 10**9 + 30 * 10**9,
            'target': None, 'parameters': {}, 'clock_scope': 'CALLING_PROCESS_MONOTONIC_NS',
            'sources': [{'source_type': 'RESEARCH_SESSION', 'role': role,
                         'producer_authentication': 'NOT_ESTABLISHED'} for role in ('before', 'after')],
            'permissions': {'level_at_request': 'READ_ONLY_LOCAL_EVIDENCE',
                'confirmation_required': False, 'authorization': {
                    'redacted': 'SENSITIVE_PAYLOAD',
                    'serialized_bytes': len(b'"NO_HELPER_OR_NATIVE_INTERVENTION_AUTHORITY"'),
                    'sha256': hashlib.sha256(b'"NO_HELPER_OR_NATIVE_INTERVENTION_AUTHORITY"').hexdigest()}},
            'limits': limits}
        file_sources, receipt_sources = {}, []
        for role, folder in self.folders.items():
            file_sources[role] = {}
            for name in ('session.sqlite3', 'session-v2.sqlite3', 'research.sqlite3'):
                data = (folder / name).read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                file_sources[role][name] = {'source_id': protocol_id('recording-file', name, digest, len(data)),
                    'source_sha256': digest, 'source_size_bytes': len(data),
                    'producer_authentication': 'NOT_ESTABLISHED'}
            receipt_sources.append({'source_type': 'RESEARCH_INDEX', 'role': role,
                'filename': 'research.sqlite3', 'recording_run_id': self.runs[role]['run_id'],
                'source_id': protocol_id('recording-run', self.runs[role]['run_id']), 'source_sha256': None,
                'source_size_bytes': (folder / 'research.sqlite3').stat().st_size,
                'producer_authentication': 'NOT_ESTABLISHED'})
        receipt = {'run_id': call_id, 'operation': 'research.compare', 'contract_version': 1,
            'tool_id': 'blackbox.research.compare', 'status': 'COMPLETED', 'execution_started': True,
            'started_at_utc': start.isoformat(), 'ended_at_utc': (start + timedelta(milliseconds=1)).isoformat(),
            'duration_ns': 100000 + int(second_call), 'limits': limits,
            'source': {'name': 'LOCAL_EVIDENCE_COMPONENT', 'verified': False,
                'verification_scope': 'BYTE_CONSISTENCY_ONLY_NOT_PRODUCER_AUTHENTICATION',
                'producer_authentication': 'NOT_ESTABLISHED', 'sources': receipt_sources},
            'target': {'identity': None, 'verified': False, 'scope': 'RECORDED_IDENTITY_NOT_LIVE_BINDING'},
            'cleanup': {'status': 'COMPLETED', 'confirmed': True,
                        'scope': 'READ_ONLY_COMPARISON_HANDLES_CLOSED_NO_NATIVE_OWNER'},
            'coverage': {'completeness': 'UNKNOWN', 'scope': 'RECORDED_COMPARISON',
                         'comparison_status': 'COMPARABLE'},
            'effects': 'READ_ONLY_SOURCE; CREATE_NEW_RESULT_ONLY', 'result_references': [], 'limitations': []}
        return {'schema': 'blackbox.experiment-comparison.v1', 'source_trust': 'UNVERIFIED_IMPORT',
            'causal_link_proven': False, 'privacy': 'METADATA_ONLY_NO_MEMORY_OR_DUMP_BYTES',
            'sources': file_sources, 'comparison': {'schema_version': 2, 'comparison': 'OBSERVATION_ONLY',
                'comparison_status': 'COMPARABLE', 'source_trust': 'UNVERIFIED_IMPORT',
                'speedup_proven': False, 'causal_link_proven': False, 'comparable_context': True,
                'comparability': {'status': 'COMPARABLE', 'identity_merge_performed': False,
                    'process_relation': 'DISTINCT_EXACT_INSTANCES',
                    'cross_run_clock_alignment': 'NOT_ESTABLISHED', 'file_trust': 'UNVERIFIED_IMPORT',
                    'speedup_proven': False, 'causal_link_proven': False, 'run_contexts': deepcopy(self.runs)},
                'experiments': {'before': {'repeats': 2}, 'after': {'repeats': 2}},
                'metrics': {'note': 'Русский <&> "текст"', 'counter': 0},
                'run_context': call, 'run_receipt': receipt,
                'tool_descriptor': {'tool_id': 'blackbox.research.compare', 'version': 1,
                                    'operations': ['research.compare'], 'effects': 'NO_NATIVE_INTERVENTION'}}}

    def write(self, value, *, format='json', text=None):
        path = self.root / ('comparison.' + format)
        if text is None:
            text = json.dumps(value, ensure_ascii=False, allow_nan=False)
            if format == 'html':
                text = ('<!doctype html><html><pre>Human summary, not metadata</pre>'
                        '<h2>Recorded metadata</h2><pre id="blackbox-comparison-data">' +
                        escape(text) + '</pre></html>')
        path.write_text(text, encoding='utf-8')
        return path

    def read(self, value, *, format='json', reference=None, text=None):
        return oracle.read_comparison_export(self.write(value, format=format, text=text), format=format,
            before=self.folders['before'], after=self.folders['after'], json_reference=reference)

    def test_distinct_valid_call_receipts_keep_all_recorded_sources_and_public_metadata(self):
        reference, first = self.read(self.payload())
        parsed, second = self.read(self.payload(second_call=True), format='html', reference=reference)
        self.assertNotEqual(parsed['comparison']['run_receipt']['run_id'],
                            reference['comparison']['run_receipt']['run_id'])
        self.assertNotEqual(parsed['comparison']['run_context']['started_monotonic_ns'],
                            reference['comparison']['run_context']['started_monotonic_ns'])
        self.assertTrue(second['semantic_readback_verified'])
        self.assertTrue(second['html_matches_json'])
        self.assertTrue(second['stable_receipt_verified'])
        self.assertFalse(first['stable_receipt_verified'])
        self.assertEqual(second['source_file_count'], 6)
        self.assertEqual(second['before_run_id'], self.runs['before']['run_id'])
        self.assertNotIn('path', second)

    def test_altered_source_role_hash_size_or_inventory_cannot_pass(self):
        changes = (
            lambda q: q['sources']['before']['research.sqlite3'].update(source_sha256='f' * 64),
            lambda q: q['sources']['after']['session-v2.sqlite3'].update(source_size_bytes=1),
            lambda q: q['sources']['before'].pop('session.sqlite3'),
            lambda q: q['sources'].update(before=q['sources']['after']),
            lambda q: q['comparison']['comparability']['run_contexts']['before']['process_identity'].update(pid=999),
            lambda q: q['comparison']['run_receipt']['source']['sources'][0].update(recording_run_id='f' * 32),
        )
        for change in changes:
            with self.subTest(change=change):
                value = self.payload()
                change(value)
                with self.assertRaisesRegex(AssertionError, 'WAVE02_COMPARISON_ORACLE_'):
                    self.read(value)

    def test_unknown_cause_clock_cleanup_and_fabricated_trust_are_rejected(self):
        for change in (
            lambda q: q.update(causal_link_proven=True),
            lambda q: q['comparison'].update(speedup_proven=True),
            lambda q: q['comparison']['comparability'].update(cross_run_clock_alignment='ESTABLISHED'),
            lambda q: q['comparison']['run_receipt']['source'].update(verified=True),
            lambda q: q['comparison']['run_receipt']['cleanup'].update(confirmed=False),
        ):
            with self.subTest(change=change):
                value = self.payload()
                change(value)
                with self.assertRaisesRegex(AssertionError, 'WAVE02_COMPARISON_ORACLE_'):
                    self.read(value)

    def test_comparable_requires_actual_recorded_equal_configuration_and_valid_instance(self):
        folder = self.folders['after']
        with sqlite3.connect(folder / 'research.sqlite3') as db:
            original = json.loads(db.execute("SELECT data FROM context WHERE key='experiment'").fetchone()[0])
        db.close()
        changes = (
            lambda exp: exp.pop('workload'),
            lambda exp: exp.pop('capture_policy'),
            lambda exp: exp.update(workload='different-input'),
            lambda exp: exp.update(profile='STANDARD'),
            lambda exp: exp.update(interval_ms=1000),
            lambda exp: exp['run_identity']['process_identity'].update(pid=0),
            lambda exp: exp['run_identity']['process_identity'].update(created_100ns=0),
            lambda exp: exp['run_identity']['image'].update(source_sha256='not-a-digest'),
            lambda exp: exp['run_identity']['clock_domain'].update(source='UNKNOWN'),
        )
        for change in changes:
            with self.subTest(change=change):
                experiment = deepcopy(original)
                change(experiment)
                with sqlite3.connect(folder / 'research.sqlite3') as db:
                    db.execute("UPDATE context SET data=? WHERE key='experiment'", (json.dumps(experiment),))
                db.close()
                # Export-like metadata is consistent with the actual modified
                # source identity/hash. Its positive status must still fail.
                self.runs['after'] = experiment['run_identity']
                with self.assertRaisesRegex(AssertionError, 'WAVE02_COMPARISON_ORACLE_RECORDED_'):
                    self.read(self.payload())

    def test_context_receipt_binding_and_real_call_time_bounds_are_required(self):
        for change in (
            lambda q: q['comparison']['run_receipt'].update(run_id='f' * 32),
            lambda q: q['comparison']['run_context'].update(operation='another.operation'),
            lambda q: q['comparison']['run_context'].update(started_monotonic_ns=1000.0),
            lambda q: q['comparison']['run_context'].update(deadline_monotonic_ns=2000),
            lambda q: q['comparison']['run_receipt'].update(ended_at_utc='2026-11-05T06:59:00+00:00'),
            lambda q: q['comparison']['run_receipt'].update(duration_ns=31 * 10**9),
        ):
            with self.subTest(change=change):
                value = self.payload()
                change(value)
                with self.assertRaisesRegex(AssertionError, 'WAVE02_COMPARISON_ORACLE_'):
                    self.read(value)

    def test_stable_context_permissions_limits_sources_and_target_are_not_normalized_away(self):
        reference, _ = self.read(self.payload())
        for change in (
            lambda q: q['comparison']['run_context']['permissions'].update(confirmation_required=True),
            lambda q: q['comparison']['run_context']['limits'].update(timeout_seconds=31),
            lambda q: q['comparison']['run_context'].update(sources=[]),
            lambda q: q['comparison']['run_context'].update(target={'pid': 1}),
            lambda q: q['comparison']['run_context'].update(parameters={'unexpected': True}),
            lambda q: q['comparison']['run_context'].update(extra_stable_field='substituted'),
        ):
            with self.subTest(change=change):
                value = self.payload(second_call=True)
                change(value)
                with self.assertRaisesRegex(AssertionError, 'WAVE02_COMPARISON_ORACLE_'):
                    self.read(value, format='html', reference=reference)

    def test_a_cached_same_call_receipt_is_not_two_actual_comparison_calls(self):
        reference, _ = self.read(self.payload())
        with self.assertRaisesRegex(AssertionError, 'SEPARATE_COMPARE_CALLS_REQUIRED'):
            self.read(deepcopy(reference), format='html', reference=reference)

    def test_all_other_receipt_fields_are_compared_across_separate_calls(self):
        reference, _ = self.read(self.payload())
        value = self.payload(second_call=True)
        value['comparison']['run_receipt']['limitations'] = ['SUBSTITUTED_STABLE_FIELD']
        with self.assertRaisesRegex(AssertionError, 'STABLE_RECEIPT_CHANGED'):
            self.read(value, format='html', reference=reference)

    def test_arbitrary_public_metadata_scalar_types_cannot_change_between_formats(self):
        reference, _ = self.read(self.payload())
        value = self.payload(second_call=True)
        value['comparison']['metrics']['counter'] = False
        with self.assertRaisesRegex(AssertionError, 'HTML_JSON_METADATA_DIFFER'):
            self.read(value, format='html', reference=reference)

    def test_unique_closed_plain_html_metadata_is_required(self):
        reference, _ = self.read(self.payload())
        value = self.payload(second_call=True)
        original = self.write(value, format='html').read_text(encoding='utf-8')
        for text in (
            original.replace('id="blackbox-comparison-data"', 'id="other"'),
            original.replace('</pre></html>', '</html>'),
            original.replace('data">', 'data"><span>'),
            original.replace('</html>', '<pre id="blackbox-comparison-data">{}</pre></html>'),
            original.replace('</html>', '<script>unexpected()</script></html>'),
        ):
            with self.subTest(text=text[-100:]):
                with self.assertRaisesRegex(AssertionError, 'WAVE02_COMPARISON_ORACLE_HTML_'):
                    self.read(value, format='html', reference=reference, text=text)

    def test_duplicate_keys_nan_invalid_utf8_and_export_byte_limit_fail(self):
        value = self.payload()
        text = json.dumps(value)
        for changed in (text.replace('"privacy":', '"privacy":"wrong", "privacy":', 1),
                        text.replace('"counter": 0', '"counter": NaN')):
            with self.assertRaisesRegex(AssertionError, 'WAVE02_EXPORT_ORACLE_'):
                self.read(value, text=changed)
        path = self.write(value)
        with patch.object(oracle, 'MAX_EXPORT_BYTES', 32):
            with self.assertRaisesRegex(AssertionError, 'FILE_TYPE_OR_SIZE'):
                oracle.read_comparison_export(path, format='json', **self.folders)
        path.write_bytes(b'\xff')
        with self.assertRaisesRegex(AssertionError, 'INVALID_UTF8_OR_JSON'):
            oracle.read_comparison_export(path, format='json', **self.folders)

    def test_real_recording_bytes_changed_during_parse_reject_old_successful_metadata(self):
        value = self.payload()
        parse = oracle._parse
        def mutate(data, format):
            answer = parse(data, format)
            with (self.folders['before'] / 'session.sqlite3').open('ab') as stream:
                stream.write(b'explicit-owned-fixture-fault')
            return answer
        with patch.object(oracle, '_parse', side_effect=mutate):
            with self.assertRaisesRegex(AssertionError, 'EXPORT_OR_RECORDING_CHANGED'):
                self.read(value)


if __name__ == '__main__':
    unittest.main()
