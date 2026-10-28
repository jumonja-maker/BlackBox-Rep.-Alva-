"""Audit BB-05/06: exact finding coverage and scoped notes consent.

All evidence files are local synthetic SQLite, not authenticated observations.
"""
from contextlib import closing
import csv
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from blackbox_core.casebook import CaseBook
from blackbox_core.investigation_v2 import investigate
from blackbox_core.interval_report import export_interval
from blackbox_core.session_v2 import SessionV2Writer, FILENAME
from test_investigation_v2 import observation, ORIGIN

NOTE = 'EXPLICIT_USER_NOTE_AUDIT_28'
LEGACY_NOTE = 'EXPLICIT_LEGACY_NOTE_AUDIT_28'
ATTRIBUTE = 'ARBITRARY_APPLICATION_ATTRIBUTE_AUDIT_28'
SOURCE_NOTE = 'NONUSER_SOURCE_NOTE_AUDIT_28'


def fixture(folder, *, actions=1):
    writer = SessionV2Writer(folder, pid=123, created=1., name='SYNTHETIC_ONLY', origin_ns=ORIGIN)
    for n in range(1, 9):
        writer.submit('base', observation(n))
        if n in (2, 6): writer.submit('detail', observation(n))
    writer.submit('event', {'kind':'user_problem', 'note':LEGACY_NOTE,
        'attributes':{'note':ATTRIBUTE}, 'source':'USER',
        'timestamp_monotonic_ns':ORIGIN+4*10**9, '_recorded_ns':ORIGIN+4*10**9})
    writer.finish('COMPLETED')
    book = CaseBook(folder, 123, 1., {'origin_monotonic_ns': ORIGIN})
    stamp = ORIGIN + 4 * 10**9
    book.put('user.comment', {'kind':'COMMENT', 'note':NOTE,
        'attributes':{'note':ATTRIBUTE}, 'command_line':ATTRIBUTE},
        source='USER_MARKER', quality='USER_DECLARED', at_ns=stamp)
    book.put('user_problem', {'legacy_event_seq':1,
        'event':{'kind':'user_problem', 'note':LEGACY_NOTE, 'source':'USER',
                 'attributes':{'comment':ATTRIBUTE}}},
        source='USER', quality='USER_REPORTED', at_ns=stamp)
    book.put('application.source_failed', {'note':SOURCE_NOTE,
        'attributes':{'note':ATTRIBUTE}}, source='APPLICATION_EVENT', at_ns=stamp)
    book.close()
    with closing(sqlite3.connect(folder/FILENAME)) as db:
        for n in range(actions):
            db.execute("INSERT INTO action_intervals VALUES(?, 'experiment', 'COMPLETED', ?, ?, ?, ?, 'USER_DECLARED')",
                ('action-'+str(n), ORIGIN, ORIGIN+2*10**9, ORIGIN+5*10**9, ORIGIN+6*10**9))
        db.commit()


def source_hashes(folder):
    return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.glob('*.sqlite3')}


def all_ui_findings(folder, **kwargs):
    rows=[]; cursor=None
    while True:
        page=investigate(folder, after=cursor, limit=50, **kwargs)
        rows.extend(page['findings'])
        if not page['has_more']: return rows
        cursor=page['next_cursor']


class FindingsAuditRegressions(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.folder=self.root/'source'; self.folder.mkdir()
        self.output=self.root/'output'; self.output.mkdir()
    def tearDown(self): self.temp.cleanup()

    def exported(self, prefix, **kwargs):
        # This fixture tests exported synthetic data, not OS ownership. Isolate
        # only the transaction owner's creation-time observation; mounted /proc
        # in some runners is not in Python's PID namespace. File identities,
        # source reads, transaction writes and publication remain production.
        with patch('psutil.Process') as owner:
            owner.return_value.create_time.return_value=1.
            result=export_interval(self.folder, self.output, prefix=prefix, **kwargs)
        data=json.loads((self.output/(prefix+'.findings.json')).read_text())
        return result, data

    def test_action_findings_have_same_ids_in_ui_json_csv_and_html(self):
        fixture(self.folder)
        before=source_hashes(self.folder)
        ui=all_ui_findings(self.folder)
        result,data=self.exported('all')
        expected={r['finding_id'] for r in ui}
        self.assertTrue(any(r['code']=='ACTION_RESOURCE_COINCIDENCE' for r in ui))
        self.assertEqual(expected, {r['finding_id'] for r in data['findings']})
        with (self.output/'all.findings.csv').open(encoding='utf-8-sig', newline='') as stream:
            self.assertEqual(expected, {r['finding_id'] for r in csv.DictReader(stream)})
        html=(self.output/'all.findings.html').read_text()
        for uid in expected: self.assertIn('finding-'+uid, html)
        self.assertFalse(result['report']['findings_export']['pagination_truncation'])
        self.assertEqual(before, source_hashes(self.folder))

    def test_more_than_one_ui_page_has_complete_action_export(self):
        fixture(self.folder, actions=65)
        ui=all_ui_findings(self.folder)
        _,data=self.exported('many')
        self.assertGreater(len(ui),50)
        self.assertEqual(len(ui),data['findings_total'])
        self.assertEqual({r['finding_id'] for r in ui},{r['finding_id'] for r in data['findings']})

    def test_explicit_note_consent_preserves_marker_and_legacy_notes_only(self):
        fixture(self.folder)
        before=source_hashes(self.folder)
        result,data=self.exported('consented', include_notes=True)
        encoded=json.dumps(data,ensure_ascii=False)
        self.assertIn(NOTE,encoded)
        self.assertIn(LEGACY_NOTE,encoded)
        self.assertNotIn(ATTRIBUTE,encoded)
        self.assertNotIn(SOURCE_NOTE,encoded)
        self.assertTrue(result['report']['privacy']['user_notes_included'])
        html=(self.output/'consented.findings.html').read_text()
        self.assertIn(NOTE,html); self.assertIn(LEGACY_NOTE,html)
        event_text=(self.output/'consented.events.jsonl').read_text()
        self.assertIn(LEGACY_NOTE,event_text); self.assertNotIn(ATTRIBUTE,event_text)
        self.assertEqual(before,source_hashes(self.folder))

    def test_default_notes_remain_omitted_in_every_export_file(self):
        fixture(self.folder)
        result,_=self.exported('default', include_notes=False, bundle=True)
        for name in result['files']:
            path=Path(name)
            if path.suffix=='.zip': continue
            text=path.read_text(encoding='utf-8-sig')
            for private in (NOTE,LEGACY_NOTE,ATTRIBUTE,SOURCE_NOTE): self.assertNotIn(private,text)

    def test_selected_standard_series_is_used_by_finding_coverage(self):
        fixture(self.folder)
        result,data=self.exported('standard', series='STANDARD')
        count=result['report']['coverage']['selected_samples']
        self.assertEqual(count,8)
        self.assertTrue(data['findings'])
        for row in data['findings']: self.assertEqual(row['coverage']['selected_samples'],count)

    def test_marker_after_last_sample_is_in_full_default_export(self):
        fixture(self.folder)
        book_path=self.folder/'research.sqlite3'
        with closing(sqlite3.connect(book_path)) as db:
            db.execute("UPDATE evidence SET monotonic_ns=? WHERE kind='user.comment'",(ORIGIN+10*10**9,))
            db.commit()
        ui=all_ui_findings(self.folder)
        _,data=self.exported('tail',include_notes=True)
        self.assertEqual({r['finding_id'] for r in ui},{r['finding_id'] for r in data['findings']})
        self.assertIn(NOTE,json.dumps(data))

    def test_interval_events_default_policy_redacts_scalar_paths(self):
        fixture(self.folder)
        private_path=r'C:\Users\AuditPrivate28\secret.txt'
        with closing(sqlite3.connect(self.folder/FILENAME)) as db:
            db.execute("INSERT INTO events(recorded_ns,observed_ns,instance_id,event_type,source_kind,verification_class,timestamp_precision,correlation_key,measurement_status,detail_json) VALUES(?,?,1,?,'APPLICATION_EVENT','USER_DECLARED','TEST_ONLY',?,'OK','{}')",
                (ORIGIN+4*10**9,ORIGIN+4*10**9,private_path,private_path))
            db.commit()
        result,_=self.exported('scalar')
        # JSON escaping can hide literal slashes: inspect decoded documents.
        exported=[json.loads(line) for line in (self.output/'scalar.events.jsonl').read_text().splitlines()]
        self.assertNotIn('AuditPrivate28',json.dumps(exported))
        self.assertEqual(len(exported),2)

    def test_export_never_overwrites_previous_report_or_changes_source(self):
        fixture(self.folder)
        self.exported('existing')
        before={p.name:p.read_bytes() for p in self.output.iterdir()}
        source=source_hashes(self.folder)
        with self.assertRaises(FileExistsError): self.exported('existing')
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.output.iterdir()})
        self.assertEqual(source,source_hashes(self.folder))

    def test_cancelled_export_cleans_only_its_staging(self):
        fixture(self.folder)
        keep=self.output/'KEEP.txt'; keep.write_text('unrelated file')
        before=source_hashes(self.folder)
        with self.assertRaises((InterruptedError,ValueError)):
            self.exported('cancelled',cancel=lambda:True)
        self.assertEqual([p.name for p in self.output.iterdir()],['KEEP.txt'])
        self.assertEqual(keep.read_text(),'unrelated file')
        self.assertEqual(before,source_hashes(self.folder))

    def test_same_explicit_interval_produces_same_action_ids(self):
        fixture(self.folder)
        start,end=ORIGIN+3*10**9,ORIGIN+4*10**9
        ui=all_ui_findings(self.folder,start_ns=start,end_ns=end)
        _,data=self.exported('clipped',interval=(start,end))
        self.assertEqual({r['finding_id'] for r in ui},{r['finding_id'] for r in data['findings']})
        action=next(r for r in data['findings'] if r['code']=='ACTION_RESOURCE_COINCIDENCE')
        self.assertTrue(action['detail']['partial_action_interval'])


if __name__=='__main__': unittest.main()
