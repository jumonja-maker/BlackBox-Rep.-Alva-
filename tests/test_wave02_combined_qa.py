"""Fixtures for the independent combined SQLite oracle, not native evidence."""
from copy import deepcopy
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from tools.qa_wave02_combined import _write_failure_receipt, verify_saved_combined


class CombinedSavedEvidenceOracleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / 'fixture.sqlite3'
        self.case = {'schema': 'blackbox.investigation-graph/1', 'case_id': 'fixture-case',
                     'sources': [{'source_id': 'recorded-source', 'source_type': 'SESSION',
                                  'content_manifest': [{'role': 'session_main',
                                      'sha256': '1' * 64, 'size_bytes': 13}]}],
                     'nodes': [{'node_id': 'node-a', 'source_identity': 'recorded-source',
                                'metadata': {'counter': 0}},
                               {'node_id': 'node-b', 'source_identity': 'recorded-source'}],
                     'edges': [{'edge_id': 'edge-a', 'from_node': 'node-a', 'to_node': 'node-b'}]}
        self.write_index()

    def write_index(self):
        raw = json.dumps(self.case, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('PRAGMA application_id=0x42424933')
            db.execute('PRAGMA user_version=1')
            db.executescript('''
                CREATE TABLE investigation(case_id TEXT, schema TEXT, content_json TEXT, content_sha256 TEXT);
                CREATE TABLE nodes(ordinal INTEGER PRIMARY KEY, node_id TEXT, record_json TEXT);
                CREATE TABLE edges(ordinal INTEGER PRIMARY KEY, edge_id TEXT, from_node TEXT,
                                   to_node TEXT, record_json TEXT);
            ''')
            db.execute('INSERT INTO investigation VALUES(?,?,?,?)',
                       (self.case['case_id'], self.case['schema'], raw,
                        hashlib.sha256(raw.encode('ascii')).hexdigest()))
            for ordinal, node in enumerate(self.case['nodes'], 1):
                db.execute('INSERT INTO nodes VALUES(?,?,?)',
                           (ordinal, node['node_id'], json.dumps(node)))
            for ordinal, edge in enumerate(self.case['edges'], 1):
                db.execute('INSERT INTO edges VALUES(?,?,?,?,?)',
                           (ordinal, edge['edge_id'], edge['from_node'], edge['to_node'], json.dumps(edge)))

    def mutate(self, command, values=()):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(command, values)

    def test_reads_content_manifests_and_individual_rows_without_changing_source(self):
        before = self.path.read_bytes()
        receipt = verify_saved_combined(self.path, self.case)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(receipt['source_count'], 1)
        self.assertEqual(receipt['node_count'], 2)
        self.assertEqual(receipt['edge_count'], 1)
        self.assertTrue(receipt['source_manifests_and_graph_rows_verified'])
        self.assertTrue(receipt['readonly_connection_closed'])

    def test_rejects_a_valid_database_with_substituted_node_record(self):
        changed = deepcopy(self.case['nodes'][0])
        changed['metadata']['counter'] = 5
        self.mutate('UPDATE nodes SET record_json=? WHERE node_id=?',
                    (json.dumps(changed), 'node-a'))
        with self.assertRaisesRegex(AssertionError, 'SQLITE_GRAPH_ROW_DIFFER'):
            verify_saved_combined(self.path, self.case)

    def test_rejects_missing_persisted_node(self):
        self.mutate('DELETE FROM nodes WHERE node_id=?', ('node-b',))
        with self.assertRaisesRegex(AssertionError, 'SQLITE_GRAPH_ROW_COUNT'):
            verify_saved_combined(self.path, self.case)

    def test_rejects_additional_persisted_node(self):
        extra = {'node_id': 'extra', 'source_identity': 'recorded-source'}
        self.mutate('INSERT INTO nodes VALUES(?,?,?)', (3, 'extra', json.dumps(extra)))
        with self.assertRaisesRegex(AssertionError, 'SQLITE_GRAPH_ROW_DIFFER'):
            verify_saved_combined(self.path, self.case)

    def test_rejects_content_hash_that_does_not_describe_recorded_json(self):
        self.mutate('UPDATE investigation SET content_sha256=?', ('0' * 64,))
        with self.assertRaisesRegex(AssertionError, 'SQLITE_CONTENT_BINDING'):
            verify_saved_combined(self.path, self.case)

    def test_rejects_changed_source_manifest_even_if_graph_ids_survive(self):
        changed = deepcopy(self.case)
        changed['sources'][0]['content_manifest'][0]['sha256'] = '2' * 64
        with self.assertRaisesRegex(AssertionError, 'SQLITE_EXPORT_METADATA_DIFFER'):
            verify_saved_combined(self.path, changed)

    def test_rejects_boolean_for_integer_metadata(self):
        changed = deepcopy(self.case)
        changed['nodes'][0]['metadata']['counter'] = False
        with self.assertRaisesRegex(AssertionError, 'SQLITE_EXPORT_METADATA_DIFFER'):
            verify_saved_combined(self.path, changed)

    def test_rejects_changed_persisted_navigation_endpoint(self):
        self.mutate('UPDATE edges SET to_node=? WHERE edge_id=?', ('unrecorded', 'edge-a'))
        with self.assertRaisesRegex(AssertionError, 'SQLITE_EDGE_ENDPOINT_DIFFER'):
            verify_saved_combined(self.path, self.case)

    def test_rejects_wrong_case_and_schema(self):
        self.mutate('UPDATE investigation SET schema=?', ('wrong-schema',))
        with self.assertRaisesRegex(AssertionError, 'SQLITE_CONTENT_BINDING'):
            verify_saved_combined(self.path, self.case)

    def test_rejects_nonempty_active_wal_before_readback(self):
        sidecar = Path(str(self.path) + '-wal')
        sidecar.write_bytes(b'explicit fixture, not OS disk damage')
        with self.assertRaisesRegex(AssertionError, 'SOURCE_ACTIVE_SIDECAR'):
            verify_saved_combined(self.path, self.case)

    def test_late_failure_receipt_cannot_inherit_pass(self):
        saved = []
        error = OSError('explicit late receipt fingerprint fixture')
        failure = _write_failure_receipt(lambda path, value: saved.append((path, value)),
                                        self.path, {'status': 'PASS', 'case_id': 'fixture-case',
                                                    'public_receipt': {'status': 'PASS'}}, error)
        self.assertEqual(failure['status'], 'FAIL')
        self.assertEqual(failure['public_receipt']['status'], 'FAIL')
        self.assertEqual(saved[0][1]['status'], 'FAIL')
        self.assertEqual(saved[0][1]['case_id'], 'fixture-case')
        self.assertEqual(saved[0][1]['error'], 'OSError')

    def test_secondary_receipt_io_failure_preserves_original_cause(self):
        original = OSError('explicit original fixture')
        def cannot_save(_path, _value):
            raise PermissionError('explicit secondary fixture')
        failure = _write_failure_receipt(cannot_save, self.path, {'status': 'PASS'}, original)
        self.assertEqual(failure['status'], 'FAIL')
        self.assertEqual(str(original), 'explicit original fixture')
        self.assertIn('COMBINED_FAILURE_RECEIPT_WRITE_UNCONFIRMED:PermissionError', original.__notes__)


if __name__ == '__main__':
    unittest.main()
