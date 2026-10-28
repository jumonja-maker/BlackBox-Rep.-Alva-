"""Independent PR25 review: real exported bytes from synthetic local evidence.

Only the transaction's process creation-time observation is stubbed in the
synthetic fixture. The redactor, SQLite backup, reports and ZIP are production.
"""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from blackbox_core.casebook import export_case
from blackbox_core.package_privacy import redact, redact_copies
from test_audit_findings_20261028 import fixture, source_hashes


class IndependentPrivacyReview(unittest.TestCase):
    def test_embedded_absolute_paths_with_spaces_hide_the_complete_value(self):
        examples = (
            r'Could not open C:\Users\Alice Smith\BB_REVIEW_PRIVATE.txt',
            'Cannot read /home/alice smith/BB_REVIEW_PRIVATE.txt; retry later',
            r'Error at \\server\Private Share\BB_REVIEW_PRIVATE.txt',
            'GET https://private.invalid/BB_REVIEW_PRIVATE?q=x failed',
            'Open "C:\\Users\\Alice Smith\\BB_REVIEW_PRIVATE.txt" now',
        )
        for value in examples:
            with self.subTest(value=value):
                result = redact({'kind': value, 'nested': {value: value}})
                self.assertNotIn('BB_REVIEW_PRIVATE', json.dumps(result))
                self.assertNotIn('Smith', json.dumps(result))
                self.assertNotIn('smith', json.dumps(result))
                self.assertTrue(result['kind'].startswith('[PATH_OR_URL_OMITTED:'))
        self.assertEqual(redact({'kind': 'plain diagnostic 42'}),
                         {'kind': 'plain diagnostic 42'})

    def test_long_non_path_text_does_not_require_quadratic_uri_search(self):
        value='a'*(128*1024)
        self.assertEqual(redact({'code':value}), {'code':value})

    def test_sqlite_prefix_lookalike_trigger_is_rejected_before_any_update(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'detail-v2.sqlite3'
            with closing(sqlite3.connect(path)) as db:
                db.executescript("CREATE TABLE visible(code TEXT); "
                    "CREATE TABLE touched(code TEXT); "
                    "CREATE TRIGGER sqliteXhidden AFTER UPDATE ON visible BEGIN "
                    "INSERT INTO touched VALUES ('executed'); END;")
                db.execute('INSERT INTO visible VALUES (?)', ('/tmp/private',));db.commit()
            with self.assertRaisesRegex(ValueError,'UNSUPPORTED_SHARE_COPY_SCHEMA'):
                redact_copies(temp)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM touched').fetchone()[0],0)

    def test_sqlite_prefix_lookalike_is_a_user_table_not_internal_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'detail-v2.sqlite3'
            with closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE sqliteXextra(code TEXT)')
                db.execute('INSERT INTO sqliteXextra VALUES (?)',
                           (r'Cannot open C:\Private User\BB_LOOKALIKE_PRIVATE.txt',))
                db.commit()
            redact_copies(temp)
            with closing(sqlite3.connect(path)) as db:
                value = db.execute('SELECT code FROM sqliteXextra').fetchone()[0]
                self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertNotIn('BB_LOOKALIKE_PRIVATE', value)
            self.assertNotIn(b'BB_LOOKALIKE_PRIVATE', path.read_bytes())

    def test_exported_zip_hides_embedded_path_and_preserves_original_databases(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root/'session'; source.mkdir()
            fixture(source)
            message = r'Cannot open C:\Private User\BB_ZIP_PRIVATE.txt'
            with closing(sqlite3.connect(source/'research.sqlite3')) as db:
                db.execute('UPDATE evidence SET kind=?,data=? WHERE id=1',
                           (message, json.dumps({message: message})))
                db.commit()
            with closing(sqlite3.connect(source/'session-v2.sqlite3')) as db:
                db.execute('UPDATE events SET event_type=?', (message,))
                db.commit()
            before = source_hashes(source)
            with patch('psutil.Process') as owner:
                owner.return_value.create_time.return_value = 1.
                result = export_case(source, root/'share.zip')
            expected = {'research.sqlite3', 'session-v2.sqlite3',
                        'evidence.csv', 'report.json', 'report.html'}
            with zipfile.ZipFile(root/'share.zip') as archive:
                self.assertTrue(expected <= set(archive.namelist()))
                for member in archive.namelist():
                    self.assertNotIn(b'BB_ZIP_PRIVATE', archive.read(member), member)
                    self.assertNotIn(b'Private User', archive.read(member), member)
            self.assertEqual(before, source_hashes(source))
            self.assertEqual(result['manifest']['privacy']['known_paths_urls'], 'REDACTED')
            self.assertFalse(result['manifest']['privacy']['universal_secret_detection'])
            # Consent is separate: the explicit sensitive export retains bytes.
            with patch('psutil.Process') as owner:
                owner.return_value.create_time.return_value = 1.
                export_case(source, root/'sensitive.zip', include_sensitive=True)
            with zipfile.ZipFile(root/'sensitive.zip') as archive:
                self.assertIn(b'BB_ZIP_PRIVATE', archive.read('research.sqlite3'))
            self.assertEqual(before, source_hashes(source))

    def test_copy_tokens_preserve_equal_references_and_distinct_messages(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'detail-v2.sqlite3'
            messages = [r'Cannot read C:\Private User\BB_ID_A.txt',
                        r'Cannot read C:\Private User\BB_ID_B.txt']
            with closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE parent(id TEXT PRIMARY KEY, data_json TEXT)')
                db.execute('CREATE TABLE child(id INTEGER PRIMARY KEY, reference TEXT REFERENCES parent(id))')
                for i, message in enumerate(messages):
                    db.execute('INSERT INTO parent VALUES (?,?)',
                               (message, json.dumps({'reference': message})))
                    db.execute('INSERT INTO child VALUES (?,?)', (i, message))
                db.commit()
            redact_copies(temp)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])
                rows = db.execute('SELECT id,data_json FROM parent').fetchall()
                self.assertEqual(len({r[0] for r in rows}), 2)
                for identity, data in rows:
                    self.assertEqual(identity, json.loads(data)['reference'])
            self.assertNotIn(b'BB_ID_', path.read_bytes())


if __name__ == '__main__':
    unittest.main()
