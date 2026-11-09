"""QA-oracle regressions; these format fixtures are not Windows evidence."""
from copy import deepcopy
import hashlib
from html import escape
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackbox_universal import wave02_export_oracles as oracle


def graph_fixture():
    source = {'source_id': 'source-1', 'source_type': 'EVENTS_JSONL',
        'source_sha256': 'a' * 64, 'source_size_bytes': 123, 'source_file_count': 1,
        'content_manifest': [{'role': '0', 'sha256': 'a' * 64, 'size_bytes': 123}],
        'selection': {}, 'verification_class': 'UNVERIFIED_IMPORT',
        'provenance': {'producer_authentication': 'NOT_ESTABLISHED'}}
    node = {'node_id': 'node-1', 'observation_type': 'ERROR', 'source_identity': 'source-1',
        'source_type': 'EVENTS_JSONL', 'source_sha256': 'a' * 64, 'source_record_id': 'line:1',
        'time_domain': 'UNVERIFIED_APPLICATION_CLOCK', 'time_bounds': None,
        'process_identity': {'kind': 'LIVE_PROCESS', 'pid': 123, 'created_100ns': 456},
        'thread_identity': None, 'verification_class': 'UNVERIFIED_IMPORT',
        'completeness_status': 'UNKNOWN', 'metadata': {'note': 'Русский <&> "текст" &notit;'}}
    return {'schema': 'blackbox.investigation-graph/1', 'algorithm_version': '3.0.0',
        'case_id': 'actual-case-identity', 'graph_version': 1, 'target_identity': None,
        'source_ids': ['source-1'], 'sources': [source], 'nodes': [node],
        'edges': [{'edge_id': 'edge-1', 'from_node': 'node-1', 'to_node': 'node-1',
                   'relation_type': 'TEMPORAL_COINCIDENCE'}],
        'root_cause': 'UNKNOWN', 'root_cause_proven': False, 'file_trust': 'UNVERIFIED_IMPORT',
        'coverage': {'evidence_completeness': 'UNKNOWN_CAPTURE_COMPLETENESS'},
        'critical_path': {'schema': 'blackbox.critical-path/1', 'status': 'NOT_ESTABLISHED',
            'end_to_end_established': False, 'segments': [], 'dependencies': [], 'path': []},
        'hypotheses': [{'hypothesis_id': 'hypothesis-1', 'root_cause_proven': False}],
        'run_receipt': {'contract_version': 1, 'run_id': 'real-e2e-run-id',
            'operation': 'investigation.create', 'status': 'COMPLETED', 'execution_started': True,
            'source': {'verified': True, 'producer_authentication': 'NOT_ESTABLISHED'},
            'target': {'identity': None, 'verified': False, 'scope': 'RECORDED_IDENTITY_NOT_LIVE_BINDING'},
            'cleanup': {'confirmed': True, 'scope': 'NORMALIZATION_SOURCE_READ_HANDLES'}}}


def graph_html(value):
    # Deliberately authored directly from the documented format, without any
    # BLACK.BOX writer/reader/redactor/validator. Earlier <pre> is not metadata.
    return ('<!doctype html><html><body><h2>Human summary</h2><pre>not JSON</pre>'
            '<h2>Source-linked investigation</h2><pre>' +
            escape(json.dumps(value, ensure_ascii=False, allow_nan=False)) + '</pre></body></html>')


class GraphExportOracleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.expected = graph_fixture()

    def read_json(self, value=None, *, raw=None):
        path = self.root / 'case.json'
        path.write_text(json.dumps(self.expected if value is None else value,
                                   ensure_ascii=False) if raw is None else raw, encoding='utf-8')
        return oracle.read_graph_export(path, format='json', expected_case=self.expected)

    def read_html(self, text=None, *, reference=None):
        path = self.root / 'case.html'
        path.write_text(graph_html(self.expected) if text is None else text, encoding='utf-8')
        return oracle.read_graph_export(path, format='html', expected_case=self.expected,
            json_reference=self.expected if reference is None else reference)

    def test_real_files_preserve_unicode_escaped_text_and_all_recorded_identities(self):
        parsed, first = self.read_json()
        html_value, second = self.read_html(reference=parsed)
        self.assertEqual(parsed, html_value)
        self.assertEqual(parsed, self.expected)
        self.assertTrue(second['semantic_readback_verified'])
        self.assertTrue(second['html_matches_json'])
        self.assertTrue(second['export_bytes_unchanged'])
        self.assertFalse(first['html_matches_json'])
        path = self.root / 'case.html'
        self.assertEqual(second['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(second['bytes'], path.stat().st_size)
        self.assertEqual(second['producer_authentication'], 'NOT_ESTABLISHED')
        self.assertNotIn('path', second)

    def native_target_export_fixture(self):
        # A raw native case contains a real-process private image path. This
        # export-like fixture is authored explicitly, without a product redactor.
        raw = {'pid': 123, 'created_100ns': 456, 'image_path': r'C:\Users\private\owned-native.exe',
               'image_sha256': 'e' * 64}
        self.expected['target_identity'] = deepcopy(raw)
        self.expected['run_receipt']['target']['identity'] = deepcopy(raw)
        self.expected['nodes'][0]['process_identity'].update(image_path=raw['image_path'])
        public = deepcopy(self.expected)
        public['target_identity']['image_path'] = '[PATH_OR_URL_OMITTED:explicit-fixture]'
        public['run_receipt']['target']['identity']['image_path'] = '[PATH_OR_URL_OMITTED:explicit-fixture]'
        public['nodes'][0]['process_identity']['image_path'] = '[PATH_OR_URL_OMITTED:explicit-fixture]'
        return public

    def test_native_private_target_paths_may_be_omitted_without_changing_public_identity(self):
        public = self.native_target_export_fixture()
        parsed, _ = self.read_json(public)
        html_value, receipt = self.read_html(graph_html(public), reference=parsed)
        self.assertEqual(parsed, html_value)
        self.assertTrue(receipt['semantic_readback_verified'])
        self.assertNotEqual(parsed['target_identity']['image_path'], self.expected['target_identity']['image_path'])

    def test_target_and_receipt_pid_birth_and_image_hash_still_cannot_change(self):
        public = self.native_target_export_fixture()
        for route in ('target_identity', 'receipt_identity'):
            for field, wrong in (('pid', 124), ('created_100ns', 457), ('image_sha256', 'f' * 64),
                                 ('pid', 123.0), ('created_100ns', 456.0)):
                with self.subTest(route=route, field=field):
                    changed = deepcopy(public)
                    identity = (changed['target_identity'] if route == 'target_identity'
                                else changed['run_receipt']['target']['identity'])
                    identity[field] = wrong
                    with self.assertRaisesRegex(AssertionError, 'RECORDED_IDENTITIES_CHANGED'):
                        self.read_json(changed)

    def test_matching_json_html_cannot_change_identity_scalar_types(self):
        self.expected['nodes'][0]['process_identity']['exact'] = False
        for field, wrong in (('pid', 123.0), ('created_100ns', 456.0), ('exact', 0)):
            with self.subTest(field=field):
                changed = deepcopy(self.expected)
                changed['nodes'][0]['process_identity'][field] = wrong
                with self.assertRaisesRegex(AssertionError, 'RECORDED_IDENTITIES_CHANGED'):
                    self.read_json(changed)
                with self.assertRaisesRegex(AssertionError, 'RECORDED_IDENTITIES_CHANGED'):
                    self.read_html(graph_html(changed), reference=changed)

    def test_application_producer_and_recorded_session_creation_scopes_are_preserved(self):
        for prefix, field, recorded, wrong in (
            ('APP', 'producer_id', 'recorded-producer-1', 'another-producer'),
            ('SESSION', 'creation_time', 1700000000.125, 1700000000.25),
        ):
            self.expected = graph_fixture()
            process = {'kind': prefix + '_PROCESS', 'pid': 123, 'source_id': 'source-1',
                       'exact': False, field: recorded}
            if prefix == 'SESSION':
                process['instance_id'] = 1
            self.expected['nodes'][0].update(process_identity=process,
                thread_identity={**process, 'kind': prefix + '_THREAD', 'tid': 789})
            parsed, _ = self.read_json()
            self.read_html(reference=parsed)
            for identity_name in ('process_identity', 'thread_identity'):
                with self.subTest(kind=prefix, identity=identity_name):
                    changed = deepcopy(self.expected)
                    changed['nodes'][0][identity_name][field] = wrong
                    with self.assertRaisesRegex(AssertionError, 'RECORDED_IDENTITIES_CHANGED'):
                        self.read_json(changed)

    def test_matching_exports_cannot_change_recorded_clock_coverage_or_receipt_scalar_types(self):
        self.expected['nodes'][0]['time_bounds'] = {'start': 100, 'end': 200, 'unit': 'ns'}
        self.expected['sources'][0]['coverage'] = {'complete': False, 'samples': 1}
        self.expected['critical_path']['totals'] = {'observed_ms': 1}
        changes = (
            lambda q: q['nodes'][0]['time_bounds'].update(start=100.0),
            lambda q: q['sources'][0]['coverage'].update(complete=0),
            lambda q: q['sources'][0]['coverage'].update(samples=True),
            lambda q: q['critical_path']['totals'].update(observed_ms=True),
            lambda q: q['run_receipt']['target'].update(verified=0),
        )
        parsed, _ = self.read_json()
        self.read_html(reference=parsed)
        for change in changes:
            with self.subTest(change=change):
                changed = deepcopy(self.expected)
                change(changed)
                with self.assertRaisesRegex(AssertionError, 'RECORDED_IDENTITIES_CHANGED'):
                    self.read_json(changed)
                with self.assertRaisesRegex(AssertionError, 'RECORDED_IDENTITIES_CHANGED'):
                    self.read_html(graph_html(changed), reference=changed)

    def test_source_hash_role_size_and_process_birth_changes_are_detected(self):
        changes = (
            lambda q: q['sources'][0].update(source_sha256='b' * 64),
            lambda q: q['sources'][0]['content_manifest'][0].update(sha256='b' * 64),
            lambda q: q['sources'][0]['content_manifest'][0].update(role='replaced-role'),
            lambda q: q['sources'][0].update(source_size_bytes=124),
            lambda q: q['nodes'][0]['process_identity'].update(created_100ns=457),
            lambda q: q['nodes'][0].update(time_domain='ANOTHER_CLOCK'),
            lambda q: q['nodes'][0].update(source_record_id='line:2'),
            lambda q: q['edges'][0].update(relation_type='EXACT_IDENTITY'),
            lambda q: q.update(case_id='another-case'),
        )
        for change in changes:
            with self.subTest(change=change):
                altered = deepcopy(self.expected)
                change(altered)
                with self.assertRaisesRegex(AssertionError, 'WAVE02_EXPORT_ORACLE_'):
                    self.read_json(altered)

    def test_compound_source_keeps_each_role_hash_and_size_in_both_formats(self):
        source = self.expected['sources'][0]
        digest = hashlib.sha256(json.dumps([['local_image', 'c' * 64], ['trace_index', 'a' * 64]],
            separators=(',', ':')).encode('ascii')).hexdigest()
        source.update(source_file_count=2, source_size_bytes=323,
            source_sha256=digest,
            content_manifest=[{'role': 'local_image', 'sha256': 'c' * 64, 'size_bytes': 200},
                              {'role': 'trace_index', 'sha256': 'a' * 64, 'size_bytes': 123}])
        self.expected['nodes'][0]['source_sha256'] = digest
        parsed, _ = self.read_json()
        _, receipt = self.read_html(reference=parsed)
        self.assertTrue(receipt['semantic_readback_verified'])
        changed = deepcopy(self.expected)
        changed['sources'][0]['content_manifest'][0]['sha256'] = 'd' * 64
        with self.assertRaisesRegex(AssertionError, 'RECORDED_IDENTITIES_CHANGED'):
            self.read_json(changed)

    def test_missing_duplicate_and_dangling_graph_ids_fail(self):
        changes = (
            lambda q: q['sources'].append(deepcopy(q['sources'][0])),
            lambda q: q['nodes'].append(deepcopy(q['nodes'][0])),
            lambda q: q['edges'].append(deepcopy(q['edges'][0])),
            lambda q: q['nodes'][0].update(node_id='changed-node'),
            lambda q: q['edges'][0].update(edge_id='changed-edge'),
            lambda q: q['edges'][0].update(to_node='absent-node'),
            lambda q: q.update(source_ids=[]),
        )
        for change in changes:
            with self.subTest(change=change):
                altered = deepcopy(self.expected)
                change(altered)
                with self.assertRaisesRegex(AssertionError, 'WAVE02_EXPORT_ORACLE_'):
                    self.read_json(altered)

    def test_receipt_unknown_cleanup_or_claimed_proof_cannot_pass(self):
        changes = (
            lambda q: q.update(root_cause='PROVEN'),
            lambda q: q.update(root_cause_proven=True),
            lambda q: q.update(file_trust='VERIFIED'),
            lambda q: q['hypotheses'][0].update(root_cause_proven=True),
            lambda q: q['run_receipt'].update(operation='investigation.export'),
            lambda q: q['run_receipt'].update(status='RECOVERY_UNCONFIRMED'),
            lambda q: q['run_receipt']['cleanup'].update(confirmed=False),
            lambda q: q['run_receipt']['source'].update(verified=False),
            lambda q: q['sources'][0]['provenance'].update(producer_authentication='ESTABLISHED'),
            lambda q: q['run_receipt'].update(run_id='different-operation'),
        )
        for change in changes:
            with self.subTest(change=change):
                altered = deepcopy(self.expected)
                change(altered)
                with self.assertRaisesRegex(AssertionError, 'WAVE02_EXPORT_ORACLE_'):
                    self.read_json(altered)

    def test_html_metadata_must_equal_json_beyond_identity_projection(self):
        changed = deepcopy(self.expected)
        changed['nodes'][0]['metadata']['note'] = 'lost or substituted public metadata'
        with self.assertRaisesRegex(AssertionError, 'HTML_JSON_METADATA_DIFFER'):
            self.read_html(graph_html(changed))

    def test_html_cannot_change_boolean_or_number_types_in_arbitrary_public_metadata(self):
        for recorded, substituted in ((0, False), (1, 1.0)):
            with self.subTest(recorded=recorded, substituted=substituted):
                self.expected['nodes'][0]['metadata']['counter'] = recorded
                reference, _ = self.read_json()
                changed = deepcopy(reference)
                changed['nodes'][0]['metadata']['counter'] = substituted
                with self.assertRaisesRegex(AssertionError, 'HTML_JSON_METADATA_DIFFER'):
                    self.read_html(graph_html(changed), reference=reference)

    def test_consistent_json_html_cannot_claim_an_established_critical_path(self):
        for field, wrong in (('status', 'ESTABLISHED'), ('end_to_end_established', True),
                             ('root_cause_proven', True)):
            with self.subTest(field=field):
                changed = deepcopy(self.expected)
                changed['critical_path'][field] = wrong
                # Matching HTML and JSON is insufficient: neither may acquire
                # an established path/root-cause claim absent from real E2E.
                with self.assertRaisesRegex(AssertionError, 'CRITICAL_PATH_CAUSE_OR_SCHEMA'):
                    self.read_json(changed)
                with self.assertRaisesRegex(AssertionError, 'CRITICAL_PATH_CAUSE_OR_SCHEMA'):
                    self.read_html(graph_html(changed), reference=changed)

    def test_critical_path_segments_and_dependencies_remain_bound_to_graph_ids(self):
        node = self.expected['nodes'][0]
        node.update(observation_type='WAIT_INTERVAL')
        self.expected['critical_path'].update(status='PARTIAL', path=['segment-1'], segments=[{
            'segment_id': 'segment-1', 'node_id': 'node-1', 'source_identity': 'source-1',
            'time_domain': node['time_domain'], 'thread_identity': None,
            'start': 1, 'end': 3, 'unit': 'ms', 'state': 'INCOMPLETE', 'duration_ms': None,
            'source_event_ids': [1, 2]}])
        parsed, _ = self.read_json()
        self.read_html(reference=parsed)
        for change in (
            lambda q: q['critical_path']['segments'][0].update(node_id='absent-node'),
            lambda q: q['critical_path']['segments'][0].update(source_identity='absent-source'),
            lambda q: q['critical_path']['segments'][0].update(time_domain='another-clock'),
            lambda q: q['critical_path']['dependencies'].append({
                'from_segment': 'segment-1', 'to_segment': 'absent-segment', 'evidence_ref': 'edge-1'}),
            lambda q: q['critical_path'].update(path=['absent-segment']),
        ):
            with self.subTest(change=change):
                changed = deepcopy(self.expected)
                change(changed)
                with self.assertRaisesRegex(AssertionError, 'CRITICAL_PATH_'):
                    self.read_json(changed)

    def test_html_requires_unique_final_plain_closed_metadata_block(self):
        text = graph_html(self.expected)
        malformed = (
            text.replace('Source-linked investigation', 'Wrong section'),
            text.replace('<h2>Source-linked investigation</h2>', ''),
            text.replace('</pre></body>', '</body>'),
            text.replace('<pre>{', '<pre><span>{'),
            text.replace('<pre>{', '<pre><!-- comment -->{'),
            text.replace('<pre>{', '<pre id="another-block">{'),
            text.replace('</body>', '<h2>Source-linked investigation</h2><pre>{}</pre></body>'),
            text.replace('</body>', '<pre>{}</pre></body>'),
            text.replace('</body>', '<script>unexpected()</script></body>'),
        )
        for raw in malformed:
            with self.subTest(raw=raw[-90:]):
                with self.assertRaisesRegex(AssertionError, 'WAVE02_EXPORT_ORACLE_HTML_'):
                    self.read_html(raw)

    def test_duplicate_json_keys_nonfinite_and_invalid_utf8_fail(self):
        raw = json.dumps(self.expected)
        for altered in (
            raw.replace('"case_id":', '"case_id":"other", "case_id":', 1),
            raw.replace('"graph_version": 1', '"graph_version": NaN'),
            raw.replace('"graph_version": 1', '"graph_version": Infinity'),
            raw.replace('"graph_version": 1', '"graph_version": 1e999'),
            '{"incomplete":',
        ):
            with self.subTest(raw=altered[:80]):
                with self.assertRaisesRegex(AssertionError, 'WAVE02_EXPORT_ORACLE_'):
                    self.read_json(raw=altered)
        path = self.root / 'invalid.json'
        path.write_bytes(b'\xff')
        with self.assertRaisesRegex(AssertionError, 'INVALID_UTF8_OR_JSON'):
            oracle.read_graph_export(path, format='json', expected_case=self.expected)

    def test_oversize_or_nonregular_file_is_rejected_before_json_parsing(self):
        path = self.root / 'bounded.json'
        path.write_bytes(b'x' * 33)
        with patch.object(oracle, 'MAX_GRAPH_EXPORT_BYTES', 32):
            with self.assertRaisesRegex(AssertionError, 'FILE_TYPE_OR_SIZE'):
                oracle.read_graph_export(path, format='json', expected_case=self.expected)
        with self.assertRaisesRegex(AssertionError, 'FILE_TYPE_OR_SIZE'):
            oracle.read_graph_export(self.root, format='json', expected_case=self.expected)

    def test_actual_file_change_during_parse_invalidates_successful_old_metadata(self):
        path = self.root / 'changing.json'
        path.write_text(json.dumps(self.expected), encoding='utf-8')
        parse = oracle._parse_graph

        def change_owned_file(data, format):
            value = parse(data, format)
            path.write_bytes(data.replace(b'actual-case-identity', b'changed-case-identit'))
            return value

        with patch.object(oracle, '_parse_graph', side_effect=change_owned_file):
            with self.assertRaisesRegex(AssertionError, 'FILE_CHANGED'):
                oracle.read_graph_export(path, format='json', expected_case=self.expected)

    def test_html_without_independently_read_json_reference_is_rejected(self):
        path = self.root / 'case.html'
        path.write_text(graph_html(self.expected), encoding='utf-8')
        with self.assertRaisesRegex(AssertionError, 'HTML_REQUIRES_JSON_REFERENCE'):
            oracle.read_graph_export(path, format='html', expected_case=self.expected)


if __name__ == '__main__':
    unittest.main()
