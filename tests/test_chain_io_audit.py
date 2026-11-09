"""Source-set and cancellation regressions for workflow file references."""
from copy import deepcopy
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from blackbox_core.chain_contracts import WorkflowError
from blackbox_core.chain_io import fingerprint_file, make_file_artifact, verify_artifact


class WorkflowSourceBoundaryAuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)

    def session(self,name):
        folder=self.root/name
        folder.mkdir()
        # Byte-consistency fixtures only; these are not captured SQLite data.
        (folder/'session.sqlite3').write_bytes(b'TEST_ONLY_LEGACY_SOURCE')
        return folder

    def test_added_database_cannot_silently_change_a_previously_bound_session_source(self):
        for added in ('session-v2.sqlite3','research.sqlite3'):
            with self.subTest(added=added):
                folder=self.session(added+'-fixture')
                artifact=make_file_artifact('SESSION',folder)
                original=deepcopy(artifact.to_dict())
                verify_artifact(artifact)
                (folder/added).write_bytes(b'TEST_ONLY_NEW_SOURCE_WITH_DIFFERENT_READER_PRIORITY')
                with self.assertRaisesRegex(WorkflowError,'WORKFLOW_SESSION_DATABASE_SET_CHANGED'):
                    verify_artifact(artifact)
                self.assertEqual(artifact.to_dict(),original)
                self.assertEqual((folder/'session.sqlite3').read_bytes(),b'TEST_ONLY_LEGACY_SOURCE')

    def test_session_database_set_change_during_initial_hashing_is_refused(self):
        folder=self.session('initial-source')
        def changed_source(path,**options):
            result=fingerprint_file(path,**options)
            (folder/'session-v2.sqlite3').write_bytes(b'TEST_ONLY_LATE_ADDED_SOURCE')
            return result
        with patch('blackbox_core.chain_io.fingerprint_file',side_effect=changed_source):
            with self.assertRaisesRegex(WorkflowError,'WORKFLOW_SESSION_DATABASE_SET_CHANGED'):
                make_file_artifact('SESSION',folder)

    def test_file_and_session_fingerprints_observe_explicit_cancel_and_deadline(self):
        path=self.root/'source.json'
        path.write_text('{"fixture":"read policy only"}',encoding='utf-8')
        folder=self.session('cancelled-session')
        cancel=threading.Event();cancel.set()
        for kind,source in (('REPORT',path),('SESSION',folder)):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(InterruptedError,'WORKFLOW_CANCELLED'):
                    make_file_artifact(kind,source,cancel=cancel)
                with self.assertRaisesRegex(TimeoutError,'WORKFLOW_DEADLINE'):
                    make_file_artifact(kind,source,deadline=0)

    def test_cancel_after_one_database_hash_stops_session_reference_construction(self):
        folder=self.session('cancel-between-databases')
        (folder/'research.sqlite3').write_bytes(b'TEST_ONLY_RESEARCH_SOURCE')
        cancel=threading.Event();read=[]
        def cancel_after_hash(path,**options):
            result=fingerprint_file(path,**options)
            read.append(Path(path).name)
            cancel.set()
            return result
        with patch('blackbox_core.chain_io.fingerprint_file',side_effect=cancel_after_hash):
            with self.assertRaisesRegex(InterruptedError,'WORKFLOW_CANCELLED'):
                make_file_artifact('SESSION',folder,cancel=cancel)
        self.assertEqual(len(read),1)
