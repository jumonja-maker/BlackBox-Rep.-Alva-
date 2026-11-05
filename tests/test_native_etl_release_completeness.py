"""Ensure busy Windows ETW acceptance never disguises a bounded prefix as complete.

Real Windows CPU.Verbose sampling / PDB / symbol integration runs separately
in the existing hosted Windows source and release workflows; these tests
exercise only fail-closed metadata contracts.
"""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from tools.qa_decoder_patch import (
    NATIVE_QA_CAPTURE_SECONDS,
    require_complete_native_etl,
    compare_native_prefix, native_index_diagnostics, strict_typed_event,
)

SOURCE = "a" * 64
FULL = {
    "schema": "blackbox.decoder-index/4",
    "status": "DECODED",
    "import_completeness": "ALL_EMITTED_RECORDS",
    "input_sha256": SOURCE,
    "rows": 50_000,
    "decoder_reported_lost_events": 0,
}


class BoundedRealNativeCapturePolicyTests(unittest.TestCase):
    def test_real_wpr_capture_is_bounded_without_disabling_stacks(self):
        self.assertEqual(NATIVE_QA_CAPTURE_SECONDS, 2)

    def test_lossless_fully_emitted_source_is_accepted(self):
        self.assertIsNone(require_complete_native_etl(dict(FULL), SOURCE))

    def test_truncated_384mib_jsonl_prefix_is_never_full(self):
        altered = dict(FULL, status="TRUNCATED", import_completeness="BOUNDED_PREFIX",
                       rows=124881)
        with self.assertRaisesRegex(AssertionError, "NATIVE_ETL_DECODE_FAILED"):
            require_complete_native_etl(altered, SOURCE)

    def test_metadata_claims_fullness_even_with_prefix_denied(self):
        for meta in (
            {**FULL, "status": "DECODED", "import_completeness": "BOUNDED_PREFIX"},
            {**FULL, "status": "TRUNCATED", "import_completeness": "ALL_EMITTED_RECORDS"},
            {**FULL, "status": "FAILED"},
            None,
        ):
            with self.subTest(meta=meta):
                with self.assertRaisesRegex(
                        AssertionError, "NATIVE_ETL_(DECODE_FAILED|RESULT_MISSING)"):
                    require_complete_native_etl(meta, SOURCE)

    def test_wrong_source_hash_is_denied(self):
        with self.assertRaisesRegex(AssertionError, "NATIVE_ETL_SOURCE_HASH_MISMATCH"):
            require_complete_native_etl({**FULL, "input_sha256": "b" * 64}, SOURCE)

    def test_missing_or_nonzero_source_decoder_loss_is_denied(self):
        for lost in (1, 100, None):
            with self.subTest(lost=lost):
                with self.assertRaisesRegex(
                        AssertionError, "NATIVE_ETL_DECODER_REPORTED_LOST_EVENTS"):
                    require_complete_native_etl({**FULL, "decoder_reported_lost_events": lost},
                                                SOURCE)


class NativeReferenceProtocolTests(unittest.TestCase):
    """SQLite/JSON protocol fixtures only; real ETL dual-import remains a CI gate."""
    def index(self, root, name, rows):
        path = root / name
        with closing(sqlite3.connect(path)) as db:
            db.execute('CREATE TABLE events(id INTEGER PRIMARY KEY,data TEXT NOT NULL)')
            db.executemany('INSERT INTO events VALUES(?,?)',
                [(number, json.dumps(row, allow_nan=False)) for number, row in enumerate(rows, 1)])
            db.commit()
        return path

    def event(self, number, value=1):
        return {'ordinal': number, 'source_index': str(number + 10), 'pid': 42,
                'process_instance': 1, 'frames': [], 'payload': {'value': value, 'known_null': None}}

    def test_truncated_secondary_matches_every_emitted_row_without_claiming_its_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); first = self.event(1)
            compact = self.index(root, 'compact.sqlite3', [first, self.event(2)])
            legacy = self.index(root, 'legacy.sqlite3', [dict(reversed(list(first.items())))])
            result = compare_native_prefix(compact, legacy, {**FULL, 'rows': 2},
                {**FULL, 'rows': 1, 'status': 'TRUNCATED', 'import_completeness': 'BOUNDED_PREFIX'}, SOURCE, seconds=5)
            self.assertEqual(result['matched_prefix_rows'], 1)
            self.assertEqual(result['compact_full_rows'], 2)
            self.assertEqual(result['comparison_scope'], 'EMITTED_LEGACY_PREFIX_ONLY')
            self.assertEqual(result['legacy_unemitted_tail'], 'NOT_COMPARED_NOT_CLAIMED')

    def test_complete_secondary_cannot_be_shorter_and_primary_prefix_can_never_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            compact = self.index(root, 'compact.sqlite3', [self.event(1), self.event(2)])
            legacy = self.index(root, 'legacy.sqlite3', [self.event(1)])
            with self.assertRaisesRegex(AssertionError, 'FULL_REFERENCE_ROW_COUNTS_DIFFER'):
                compare_native_prefix(compact, legacy, {**FULL, 'rows': 2}, {**FULL, 'rows': 1}, SOURCE, seconds=5)
            with self.assertRaisesRegex(AssertionError, 'NATIVE_ETL_DECODE_FAILED'):
                compare_native_prefix(compact, legacy, {**FULL, 'rows': 2, 'status': 'TRUNCATED',
                    'import_completeness': 'BOUNDED_PREFIX'}, {**FULL, 'rows': 1}, SOURCE, seconds=5)

    def test_full_reference_rejects_numeric_type_changes_false_and_lost_null_fields(self):
        for label, changed in (('float', self.event(1, 1.0)), ('bool', self.event(1, True)),
                               ('missing_null', {**self.event(1), 'payload': {'value': 1}})):
            with self.subTest(fixture=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                compact = self.index(root, 'compact.sqlite3', [self.event(1)])
                legacy = self.index(root, 'legacy.sqlite3', [changed])
                with self.assertRaisesRegex(AssertionError, 'PUBLIC_EVENT_MISMATCH'):
                    compare_native_prefix(compact, legacy, {**FULL, 'rows': 1}, {**FULL, 'rows': 1}, SOURCE, seconds=5)
        with self.assertRaisesRegex(AssertionError, 'DUPLICATE_JSON_KEY'):
            strict_typed_event('{"ordinal":1,"ordinal":1}')
        with self.assertRaisesRegex(AssertionError, 'NONFINITE_JSON'):
            strict_typed_event('{"value":NaN}')

    def test_derived_group_bytes_dedup_are_bounded_and_never_print_frames(self):
        frame = {'address': '0x1', 'name': 'PRIVATE_FRAME_NAME', 'module': {'name': 'PRIVATE_MODULE'}}
        other_frame = {**frame, 'address': '0x2'}
        rows = [{**self.event(1), 'frames': [frame, frame]},
                {**self.event(2), 'frames': [frame, other_frame]}, {**self.event(3), 'pid': -1}]
        with tempfile.TemporaryDirectory() as tmp:
            index = self.index(Path(tmp), 'index.sqlite3', rows)
            result = native_index_diagnostics(index, 42, max_unique=1, seconds=5)
            owned = result['groups']['owned_native_fixture']
            self.assertEqual(owned['frame_occurrences'], 4)
            self.assertEqual(owned['module_occurrences'], 4)
            self.assertEqual(owned['distinct_lower_bound']['frames'], 1)
            self.assertIn('frames', owned['distinct_capped'])
            self.assertEqual(result['groups']['unattributed']['rows'], 1)
            self.assertIn('NOT_NATIVE_UTF8', result['byte_scope'])
            self.assertNotIn('PRIVATE_FRAME', json.dumps(result))
            self.assertNotIn('PRIVATE_MODULE', json.dumps(result))


if __name__ == "__main__":
    unittest.main()
