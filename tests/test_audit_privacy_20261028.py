"""BB-02/07: actual share exports and bounded copy-only redaction."""
from contextlib import closing
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import zipfile

from blackbox_core.casebook import export_case
from blackbox_core.package_privacy import redact, redact_copies
from blackbox_core.research_worker import ResearchSession


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AuditPrivacyTests(unittest.TestCase):
    def test_share_scalar_paths_are_redacted_in_every_derived_member_and_originals_unchanged(self):
        sentinels = (r'C:\private\BB_PRIV_PATH_a241.txt', '/home/private/BB_POSIX_a241.txt',
                     'https://internal.invalid/BB_URL_a241')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); session = ResearchSession(root/'sessions')
            session.command({'op':'attach','args':{'pid':os.getpid()}})
            session.command({'op':'start'})
            session.book.put(sentinels[0], {'copy':sentinels[0]}, source=sentinels[1], quality=sentinels[2])
            session.tick(); session.stop(); folder = session.probe.session_folder
            with closing(sqlite3.connect(folder/'session-v2.sqlite3')) as db:
                db.execute('UPDATE events SET event_type=?,source_kind=?,measurement_status=?', sentinels)
                db.commit()
            original = {p.name:sha(p) for p in folder.glob('*.sqlite3')}
            result = export_case(folder, root/'share.zip')
            with zipfile.ZipFile(root/'share.zip') as archive:
                self.assertTrue({'evidence.csv','report.json','report.html','research.sqlite3','session-v2.sqlite3'} <= set(archive.namelist()))
                for name in archive.namelist():
                    data = archive.read(name)
                    for text in ('BB_PRIV_PATH_a241','BB_POSIX_a241','BB_URL_a241'):
                        self.assertNotIn(text.encode(), data, (name,text))
            self.assertEqual(original,{p.name:sha(p) for p in folder.glob('*.sqlite3')})
            self.assertFalse(result['manifest']['privacy']['universal_secret_detection'])
            export_case(folder,root/'sensitive.zip',include_sensitive=True)
            with zipfile.ZipFile(root/'sensitive.zip') as archive:
                self.assertIn(b'BB_PRIV_PATH_a241',archive.read('research.sqlite3'))
                self.assertIn(b'BB_URL_a241',archive.read('session-v2.sqlite3'))

    def test_csv_prefixes_share_the_safe_parsed_cell_policy(self):
        values=[' =1+1','\n=1+1','\t@SUM(A1)','\r-2','  +2','plain','x=1+1']
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); session=ResearchSession(root/'sessions')
            session.command({'op':'attach','args':{'pid':os.getpid()}});session.command({'op':'start'})
            for value in values:session.book.put(value,{},source='APPLICATION_EVENT')
            session.tick();session.stop()
            export_case(session.probe.session_folder,root/'case.zip')
            with zipfile.ZipFile(root/'case.zip') as archive:
                rows=list(csv.DictReader(io.StringIO(archive.read('evidence.csv').decode('utf-8-sig'))))
            kinds={r['kind'] for r in rows}
            for v in values[:5]:self.assertIn("'"+v,kinds)
            self.assertIn('plain',kinds);self.assertIn('x=1+1',kinds)

    def test_copy_redaction_covers_detail_text_numeric_text_and_json_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'detail-v2.sqlite3'
            with closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE sensor_errors(seq INTEGER PRIMARY KEY, code TEXT, value INTEGER, extra_json TEXT)')
                db.execute('INSERT INTO sensor_errors VALUES (1,?,?,?)',('/tmp/BB_DETAIL_PRIVATE',r'C:\BB_NUMBER_PRIVATE',json.dumps({'https://private.invalid/BB_KEY_PRIVATE':{'safe':'/etc/BB_JSON_PRIVATE'}})))
                db.commit()
            redact_copies(tmp)
            with closing(sqlite3.connect(path)) as db:
                row=db.execute('SELECT code,value,extra_json FROM sensor_errors').fetchone()
                self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
            for value in row:
                self.assertNotIn('BB_',value)
            json.loads(row[2])

    def test_export_copy_keeps_distinct_path_ids_and_foreign_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'session-v2.sqlite3'
            with closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE experiments(experiment_id TEXT PRIMARY KEY, profile_json TEXT)')
                db.execute('CREATE TABLE experiment_runs(action_id TEXT PRIMARY KEY, experiment_id TEXT REFERENCES experiments)')
                for i in range(2):
                    value='/home/user/BB_PRIVATE_ID_'+str(i)
                    db.execute('INSERT INTO experiments VALUES (?,?)',(value,json.dumps({'reference':value})))
                    db.execute('INSERT INTO experiment_runs VALUES (?,?)',('action'+str(i),value))
                db.commit()
            redact_copies(tmp)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])
                rows=db.execute('SELECT experiment_id,profile_json FROM experiments').fetchall()
                self.assertEqual(len({r[0] for r in rows}),2)
                for ident,raw in rows:
                    self.assertEqual(json.loads(raw)['reference'],ident)
                    self.assertNotIn('BB_PRIVATE',ident)

    def test_raw_omitted_artifact_name_does_not_escape_default_share_policy(self):
        if os.name=='nt':self.skipTest('Fixture uses a Windows-looking filename only legal on POSIX')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);session=ResearchSession(root/'sessions')
            session.command({'op':'attach','args':{'pid':os.getpid()}});session.command({'op':'start'})
            session.tick();session.stop();folder=session.probe.session_folder
            artifacts=folder/'artifacts';artifacts.mkdir(exist_ok=True)
            artifact=artifacts/r'C:\private\BB_OMITTED_NAME_a241.bin';artifact.write_bytes(b'raw data not shared')
            export_case(folder,root/'case.zip')
            with zipfile.ZipFile(root/'case.zip') as archive:
                self.assertNotIn(b'BB_OMITTED_NAME_a241',archive.read('manifest.json'))
            self.assertEqual(artifact.read_bytes(),b'raw data not shared')

    def test_nonregular_schema_refuses_before_running_triggers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'detail-v2.sqlite3'
            with closing(sqlite3.connect(path)) as db:
                db.executescript("CREATE TABLE sensor_errors(code TEXT); INSERT INTO sensor_errors VALUES ('/tmp/BB_TRIGGER_PRIVATE'); CREATE TABLE touched(value TEXT); CREATE TRIGGER touch AFTER UPDATE ON sensor_errors BEGIN INSERT INTO touched VALUES ('ran'); END;")
            with self.assertRaisesRegex(ValueError,'UNSUPPORTED_SHARE_COPY_SCHEMA'):redact_copies(tmp)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM touched').fetchone()[0],0)

    def test_full_path_fields_with_spaces_do_not_leave_private_basename(self):
        result=redact({'kind':r'C:\Users\Private User\BB_PRIVATE_BASENAME.txt',
                       'source':'/home/private user/BB_POSIX_BASENAME.txt'})
        text=json.dumps(result)
        self.assertNotIn('BB_PRIVATE_BASENAME',text)
        self.assertNotIn('BB_POSIX_BASENAME',text)

    def test_private_scalar_columns_use_same_default_policy_as_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'detail-v2.sqlite3'
            with closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE sensor_errors(note TEXT, attributes TEXT, code TEXT)')
                db.execute('INSERT INTO sensor_errors VALUES (?,?,?)',('BB_PRIVATE_NOTE','BB_PRIVATE_ATTRIBUTES','OBSERVED'))
                db.commit()
            redact_copies(tmp)
            with closing(sqlite3.connect(path)) as db:row=db.execute('SELECT * FROM sensor_errors').fetchone()
            self.assertNotIn('BB_PRIVATE',json.dumps(row))
            self.assertEqual(row[-1],'OBSERVED')
            self.assertEqual(json.loads(row[1])['privacy'],'APPLICATION_ATTRIBUTES_OMITTED_BY_DEFAULT')

    def _assert_generated_copy_refused(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'detail-v2.sqlite3'
            with closing(sqlite3.connect(path)) as db:
                db.execute("CREATE TABLE sensor_errors(id INTEGER PRIMARY KEY, generated TEXT GENERATED ALWAYS AS('constant') "+mode+", code TEXT)")
                db.execute('INSERT INTO sensor_errors(id,code) VALUES (1,?)',('/home/private/GENERATED_LEAK_SENTINEL',))
                db.commit()
            with self.assertRaisesRegex(ValueError,'UNSUPPORTED_SHARE_COPY_SCHEMA'):
                redact_copies(tmp)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('SELECT id,generated,code FROM sensor_errors').fetchone(),
                                 (1,'constant','/home/private/GENERATED_LEAK_SENTINEL'))

    def test_stored_generated_column_cannot_hide_a_following_sensitive_field(self):
        self._assert_generated_copy_refused('STORED')

    def test_virtual_generated_column_cannot_hide_a_following_sensitive_field(self):
        self._assert_generated_copy_refused('VIRTUAL')

    def test_private_index_schema_cannot_escape_redacted_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'detail-v2.sqlite3'
            with closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE sensor_errors(code TEXT)')
                db.execute('CREATE INDEX "C:\\private\\BB_INDEX_SCHEMA_LEAK" ON sensor_errors(code)')
                db.commit()
            with self.assertRaisesRegex(ValueError,'UNSUPPORTED_SHARE_COPY_SCHEMA'):
                redact_copies(tmp)

    def test_explicit_note_opt_in_does_not_admit_attributes_or_known_paths(self):
        value={'note':'useful note','comment':'useful comment','attributes':{'secret':'BB_SECRET'},
               'facts':[{'note':'refer /tmp/BB_NOTE_PRIVATE'}]}
        default=redact(value)
        allowed=redact(value,include_notes=True)
        self.assertNotIn('useful',json.dumps(default))
        self.assertEqual(allowed['note'],'useful note');self.assertEqual(allowed['comment'],'useful comment')
        self.assertNotIn('BB_SECRET',json.dumps(allowed));self.assertNotIn('BB_NOTE_PRIVATE',json.dumps(allowed))


if __name__=='__main__':unittest.main()
