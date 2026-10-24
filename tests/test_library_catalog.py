"""Local library behavior and adversarial boundaries; fixtures are TEST ONLY."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
from uuid import uuid4
from blackbox_core.library_catalog import LibraryCatalog,recording_metadata,MARKER,TRASH
from blackbox_core.library_files import tree_summary,move_no_replace,atomic_json
from blackbox_core.storage import SessionStore
from blackbox_core.casebook import CaseBook,_hash
from blackbox_core.contracts import Sample

class LibraryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'library';self.root.mkdir()
        self.catalog=LibraryCatalog(self.root)
    def tearDown(self):self.temp.cleanup()
    def recording(self,*,root=None,finalized=True,scenario='Поиск',version='1.0',age_days=0):
        root=root or self.root;root.mkdir(exist_ok=True)
        store=SessionStore(root,123,started_with='TEST_ONLY_FIXTURE')
        store.write_sample(Sample(0,100,None,1,0,0,0))
        folder=store.folder;book=CaseBook(folder,123,1.,{'scenario':scenario,'target_version':version,'profile':'STANDARD','interval_ms':2000})
        book.close('COMPLETED' if finalized else 'RECORDING')
        store.finish('COMPLETED' if finalized else 'INTERRUPTED');store.close()
        meta=recording_metadata(folder);meta['started_ns']-=int(age_days*86400*1e9)
        if root==self.root:entry=self.catalog.record_owned(folder,meta,finalized=finalized)
        else:entry=self.catalog.register(folder)
        return folder,entry
    def test_empty_query_and_default_policy_have_no_automatic_deletion(self):
        self.assertEqual(self.catalog.query()['rows'],[])
        self.assertFalse(self.catalog.policy()['automatic_deletion'])
        self.assertFalse((self.root/'blackbox-library.sqlite3').exists())
    def test_indexed_search_paging_and_counts_do_not_walk_recordings(self):
        _,first=self.recording(scenario='Тест Ёж',version='v2')
        with closing(self.catalog._connect(write=True)) as db:
            columns=[r[1] for r in db.execute('PRAGMA table_info(entries)')]
            for n in range(120):
                row=dict(first);row['entry_id']=uuid4().hex;row['locator']='LOCAL:session-'+uuid4().hex
                row['folder_name']=row['locator'][6:];row['started_ns']+=n+1
                db.execute('INSERT INTO entries('+','.join(columns)+') VALUES('+','.join('?' for _ in columns)+')',tuple(row.get(c) for c in columns))
            db.commit()
        ids=[];cursor=None
        with patch('blackbox_core.library_catalog.os.scandir',side_effect=AssertionError('query must not scan folders')):
            while True:
                result=self.catalog.query(search='ёж',after=cursor,limit=17)
                ids.extend(r['entry_id'] for r in result['rows']);cursor=result['next_cursor']
                if not result['has_more']:break
        self.assertEqual(len(ids),121);self.assertEqual(len(ids),len(set(ids)))
        self.assertFalse(result['disk_scan'])
    def test_literal_percent_underscore_and_sql_text_are_search_data(self):
        self.recording(scenario="100%_literal ' OR 1=1 --")
        self.assertEqual(len(self.catalog.query(search='%_literal')['rows']),1)
        self.assertEqual(self.catalog.query(search='nonexistent%')['rows'],[])
    def test_external_recording_remains_readonly_and_cannot_enter_trash(self):
        folder,row=self.recording(root=Path(self.temp.name)/'external')
        digest=_hash(folder/'session.sqlite3')
        self.assertEqual(row['origin'],'USER_SELECTED_UNVERIFIED')
        with self.assertRaisesRegex(ValueError,'ACTIVE_OR_EXTERNAL'):self.catalog.plan_trash([row['entry_id']])
        self.assertEqual(_hash(folder/'session.sqlite3'),digest)
    def test_active_or_unconfirmed_recording_is_never_a_cleanup_candidate(self):
        _,row=self.recording(finalized=False)
        with self.assertRaises(ValueError):self.catalog.plan_trash([row['entry_id']])
        self.catalog.policy({'days':1,'max_bytes':1})
        self.assertEqual(self.catalog.retention_preview()['candidates'],[])
    def test_confirmed_trash_and_restore_preserve_every_original_byte(self):
        folder,row=self.recording();(folder/'owned-note.bin').write_bytes(b'actual original bytes')
        before=_hash(folder/'session.sqlite3');plan=self.catalog.plan_trash([row['entry_id']])
        self.assertTrue(folder.is_dir());result=self.catalog.apply_trash(plan['confirmation_token'])
        self.assertEqual(result['results'][0]['status'],'MOVED_TO_TRASH');self.assertEqual(result['bytes_freed'],0)
        trashed=self.catalog.entry(row['entry_id']);self.assertEqual(trashed['state'],'TRASH')
        self.assertEqual((Path(trashed['folder'])/'owned-note.bin').read_bytes(),b'actual original bytes')
        restored=self.catalog.restore(row['entry_id']);self.assertEqual(restored['status'],'RESTORED')
        self.assertEqual(_hash(folder/'session.sqlite3'),before)
    def test_confirmation_is_single_use_and_changes_require_new_review(self):
        folder,row=self.recording();plan=self.catalog.plan_trash([row['entry_id']])
        (folder/'new.txt').write_text('added after preview')
        with self.assertRaisesRegex(ValueError,'CHANGED'):self.catalog.apply_trash(plan['confirmation_token'])
        self.assertTrue(folder.is_dir());fresh=self.catalog.plan_trash([row['entry_id']])
        self.catalog.apply_trash(fresh['confirmation_token'])
        with self.assertRaisesRegex(ValueError,'EXPIRED_OR_USED'):self.catalog.apply_trash(fresh['confirmation_token'])
    def test_restore_refuses_existing_destination_without_overwrite(self):
        folder,row=self.recording();self.catalog.apply_trash(self.catalog.plan_trash([row['entry_id']])['confirmation_token'])
        folder.mkdir();(folder/'keep').write_text('do not overwrite')
        with self.assertRaises(FileExistsError):self.catalog.restore(row['entry_id'])
        self.assertEqual((folder/'keep').read_text(),'do not overwrite');self.assertEqual(self.catalog.entry(row['entry_id'])['state'],'TRASH')
    def test_retention_is_preview_only_and_counts_unknown_sizes(self):
        folder,row=self.recording(age_days=20)
        self.catalog.policy({'days':7,'max_bytes':1})
        result=self.catalog.retention_preview()
        self.assertEqual(len(result['candidates']),1);self.assertEqual(result['bytes_freed'],0);self.assertTrue(folder.exists())
        with self.assertRaisesRegex(ValueError,'AUTOMATIC'):self.catalog.policy({'days':7,'max_bytes':1,'automatic_deletion':True})
        for limit in (-1,0,1000):
            with self.assertRaises(ValueError):self.catalog.retention_preview(limit=limit)
    def test_external_sizes_do_not_create_local_retention_candidates(self):
        folder,row=self.recording();size=row['size_bytes']
        external,_=self.recording(root=Path(self.temp.name)/'external')
        (external/'large.bin').write_bytes(b'x'*(size*2));self.catalog.register(external)
        self.catalog.policy({'days':0,'max_bytes':size+1})
        result=self.catalog.retention_preview();self.assertEqual(result['candidates'],[])
        self.assertEqual(result['known_live_bytes'],size)
    def test_second_instance_cannot_claim_an_entry_already_being_moved(self):
        folder,row=self.recording();plan=self.catalog.plan_trash([row['entry_id']])
        second=LibraryCatalog(self.root);original=second._trash_root
        def another_claim(create=False):
            trash=original(create=create)
            with closing(second._connect(write=True)) as db:
                db.execute("UPDATE entries SET state='MOVING_TO_TRASH',previous_state='COMPLETED',trash_name=? WHERE entry_id=?",('f'*32,row['entry_id']));db.commit()
            return trash
        with patch.object(second,'_trash_root',side_effect=another_claim):result=second.apply_trash(plan['confirmation_token'])
        self.assertEqual(result['results'][0]['status'],'MOVE_UNCONFIRMED');self.assertTrue(folder.exists())
        self.assertEqual(self.catalog.entry(row['entry_id'])['trash_name'],'f'*32)
    def test_plan_expiry_and_bounded_consent_queue(self):
        folder,row=self.recording();plan=self.catalog.plan_trash([row['entry_id']])
        with closing(self.catalog._connect(write=True)) as db:
            db.execute('UPDATE plans SET expires_ns=0');db.commit()
        with self.assertRaisesRegex(ValueError,'EXPIRED_OR_USED'):self.catalog.apply_trash(plan['confirmation_token'])
        self.assertTrue(folder.is_dir())
        # Test-only outstanding plan rows: never wait five real minutes.
        with closing(self.catalog._connect(write=True)) as db:
            for i in range(128):db.execute('INSERT INTO plans VALUES(?,?,?,?,0)',(str(i),time.time_ns(),time.time_ns()+10**12,'{}'))
            db.commit()
        with self.assertRaisesRegex(ValueError,'QUEUE_FULL'):self.catalog.plan_trash([row['entry_id']])
    def test_invalid_marker_or_path_change_cannot_authorize_move(self):
        folder,row=self.recording();data=json.loads((folder/MARKER).read_text());data['root_id']=uuid4().hex
        atomic_json(folder/MARKER,data)
        with self.assertRaisesRegex(ValueError,'NOT_MARKED'):self.catalog.plan_trash([row['entry_id']])
        self.assertTrue(folder.exists())
    def test_pending_etw_guardian_prevents_trash(self):
        folder,row=self.recording();art=folder/'artifacts';art.mkdir()
        (art/('BLACKBOX_'+uuid4().hex+'.trace.json')).write_text('{"state":"RECORDING"}')
        with self.assertRaisesRegex(ValueError,'TRACE_STILL_ACTIVE'):self.catalog.plan_trash([row['entry_id']])
    def test_scan_is_explicit_bounded_and_legacy_does_not_become_app_owned(self):
        for _ in range(3):
            store=SessionStore(self.root,123,'TEST_ONLY_LEGACY');store.finish('COMPLETED');store.close()
        self.assertEqual(self.catalog.query()['rows'],[])
        first=self.catalog.scan(limit=2);self.assertTrue(first['has_more']);self.assertEqual(first['added'],2)
        second=self.catalog.scan(after=first['cursor'],limit=2);self.assertFalse(second['has_more'])
        rows=self.catalog.query()['rows'];self.assertEqual(len(rows),3)
        self.assertTrue(all(r['origin']=='USER_SELECTED_UNVERIFIED' for r in rows))
    def test_index_database_collision_is_rejected_without_modification(self):
        path=self.root/'blackbox-library.sqlite3'
        db=sqlite3.connect(path);db.execute('CREATE TABLE important(data)');db.execute("INSERT INTO important VALUES('keep')");db.commit();db.close()
        before=_hash(path)
        with self.assertRaisesRegex(ValueError,'WRONG_DATABASE'):self.catalog.policy({'days':1,'max_bytes':0})
        self.assertEqual(_hash(path),before)
    def test_reconcile_interrupted_move_uses_both_locations_without_deleting(self):
        folder,row=self.recording();plan=self.catalog.plan_trash([row['entry_id']]);self.catalog.apply_trash(plan['confirmation_token'])
        with closing(self.catalog._connect(write=True)) as db:
            db.execute("UPDATE entries SET state='MOVING_TO_TRASH' WHERE entry_id=?",(row['entry_id'],));db.commit()
        result=self.catalog.reconcile();self.assertEqual(result['results'][0]['state'],'TRASH')
        self.catalog.restore(row['entry_id']);self.assertTrue(folder.is_dir())
    def test_atomic_move_refuses_destination(self):
        source=self.root/'source';dest=self.root/'dest';source.mkdir();dest.mkdir()
        (dest/'keep').write_text('untouched')
        with self.assertRaises(FileExistsError):move_no_replace(source,dest)
        self.assertEqual((dest/'keep').read_text(),'untouched')
    def test_symlink_is_not_followed_or_moved(self):
        folder,row=self.recording();outside=Path(self.temp.name)/'keep';outside.mkdir();(outside/'data').write_text('keep')
        try:(folder/'link').symlink_to(outside,target_is_directory=True)
        except (OSError,NotImplementedError):self.skipTest('symlink creation not available for this token')
        with self.assertRaises(ValueError):self.catalog.plan_trash([row['entry_id']])
        self.assertEqual((outside/'data').read_text(),'keep')

if __name__=='__main__':unittest.main()
