"""Real recorder/optional operation integration; local fixtures are TEST ONLY."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from blackbox_core.research_worker import ResearchSession
from blackbox_core.library_catalog import LibraryCatalog,MARKER
from blackbox_core.operation_worker import execute
from blackbox_core.casebook import compare_cases,_hash


class LibraryWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.session=ResearchSession(self.root)
        self.session.command({'op':'attach','args':{'pid':os.getpid()}})
    def tearDown(self):self.session.stop();self.temp.cleanup()
    def record(self,version='1'):
        s=self.session;s.command({'op':'configure','args':{'scenario':'Library QA','scenario_version':version,'workload':'same-input'}})
        s.command({'op':'start'});s.tick();folder=s.probe.session_folder;s.stop();return folder
    def test_local_comment_lives_only_in_index_and_share_export_preserves_originals(self):
        folder=self.record();catalog=LibraryCatalog(self.root);row=catalog.query()['rows'][0]
        original={p.name:_hash(p) for p in folder.glob('*.sqlite3')};note='PRIVATE_LOCAL_COMMENT_<script>test</script>'
        catalog.annotate(row['entry_id'],note)
        with patch('blackbox_core.library_catalog.recording_metadata',side_effect=AssertionError('query must not scan source')):
            self.assertEqual(catalog.query()['rows'][0]['local_note'],note)
        with self.assertRaises(ValueError):catalog.annotate(row['entry_id'],'x'*2049)
        self.assertEqual(catalog.entry(row['entry_id'])['local_note'],note)
        out=self.root/'share';out.mkdir();result=execute({'op':'library_export','args':{'entry_id':row['entry_id'],'output':str(out)},'library_root':str(self.root)})
        import zipfile
        with zipfile.ZipFile(result['path']) as package:
            self.assertFalse(any(note.encode() in package.read(name) for name in package.namelist()))
        self.assertEqual(original,{p.name:_hash(p) for p in folder.glob('*.sqlite3')})
    def test_lifecycle_index_is_not_part_of_sampling_and_repeated_stop_is_idempotent(self):
        s=self.session;s.command({'op':'start'});catalog=LibraryCatalog(self.root)
        rows=catalog.query()['rows'];self.assertEqual(len(rows),1);self.assertEqual(rows[0]['state'],'RECORDING')
        with self.assertRaises(ValueError):catalog.plan_trash([rows[0]['entry_id']])
        with patch.object(LibraryCatalog,'record_owned',side_effect=AssertionError('must not run per sample')):
            for _ in range(3):s.tick()
        s.stop();row=catalog.entry(rows[0]['entry_id']);self.assertEqual(row['state'],'COMPLETED');self.assertEqual(row['samples'],3)
        marker=s.probe.session_folder/MARKER;before=marker.read_bytes();s.stop();self.assertEqual(marker.read_bytes(),before)
        self.assertEqual(json.loads(before)['lifecycle'],'FINALIZED');self.assertIsNone(s.library_error)
    def test_optional_index_failure_does_not_interrupt_primary_recording(self):
        with patch.object(LibraryCatalog,'record_owned',side_effect=OSError('fixture full disk')):
            s=self.session;s.command({'op':'start'});s.tick()
            self.assertTrue(s.probe.active);self.assertEqual(s.probe.total_samples,1)
            self.assertEqual(s.snapshot()['library_health']['status'],'INDEX_ERROR')
            s.stop();self.assertEqual(s.research_state,'COMPLETED')
        with closing(sqlite3.connect(s.probe.session_folder/'session.sqlite3')) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM samples').fetchone()[0],1)
    def test_pending_native_owner_prevents_finalized_marker_and_cleanup(self):
        self.session.command({'op':'start'});self.session.tick()
        self.session.probe._pending_windows=SimpleNamespace(thread=SimpleNamespace(is_alive=lambda:True))
        self.session.stop();catalog=LibraryCatalog(self.root);row=catalog.query()['rows'][0]
        self.assertEqual(row['state'],'FINALIZATION_UNCONFIRMED');self.assertFalse(row['trash_eligible'])
        self.assertEqual(json.loads((Path(row['folder'])/MARKER).read_text())['lifecycle'],'ACTIVE')
        with self.assertRaises(ValueError):catalog.plan_trash([row['entry_id']])
        self.session.probe._pending_windows=None
    def test_open_compare_and_trash_use_indexed_ids_and_preserve_sources(self):
        first=self.record('1');second=self.record('2');catalog=LibraryCatalog(self.root)
        rows=catalog.query()['rows'];ids={r['folder_name']:r['entry_id'] for r in rows}
        digest=_hash(first/'session.sqlite3');base={'library_root':str(self.root)}
        opened=execute({**base,'op':'library_open','args':{'entry_id':ids[first.name]}})
        self.assertEqual(opened['folder'],str(first));self.assertTrue(opened['has_research'])
        comparison=execute({**base,'op':'library_compare','args':{'before_id':ids[first.name],'after_id':ids[second.name]}})
        self.assertIn('scenario_version',comparison['comparison']['context_mismatches'])
        self.assertFalse(comparison['comparison']['comparable_context']);self.assertEqual(_hash(first/'session.sqlite3'),digest)
        with self.assertRaisesRegex(ValueError,'SELECT_TWO'):
            execute({**base,'op':'library_compare','args':{'before_id':ids[first.name],'after_id':ids[first.name]}})
        with self.assertRaises(ValueError):execute({**base,'op':'library_open','args':{'entry_id':'../../elsewhere'}})
        result=execute({**base,'op':'library_query','args':{'request_key':91,'library_root':str(self.root/'ignored')}})
        self.assertEqual(result['request_key'],91);self.assertEqual(len(result['rows']),2)
        self.assertFalse((self.root/'ignored').exists())
    def test_disposable_operation_queries_real_index_without_sampler_connection(self):
        self.record();s=self.session
        s.submit_optional({'op':'library_query','id':'actual-library-child','args':{'request_key':5}})
        end=time.monotonic()+10;result=[]
        try:
            while not result and time.monotonic()<end:result=s.poll_optional();time.sleep(.01)
            self.assertTrue(result);self.assertIsNone(result[0]['error']);self.assertEqual(len(result[0]['result']['rows']),1)
            self.assertNotEqual(result[0]['pid'],os.getpid());self.assertEqual(result[0]['result']['request_key'],5)
        finally:s.jobs.cancel()
    def test_legacy_scenario_version_is_a_warning_not_silent_claim(self):
        first=self.record('');second=self.record('');result=compare_cases(first,second)
        self.assertIn('scenario_version_not_recorded',result['context_warnings'])


if __name__=='__main__':unittest.main()
