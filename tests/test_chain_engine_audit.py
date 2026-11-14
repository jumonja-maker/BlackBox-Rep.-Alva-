"""Durable scheduler admission and exact live-owner boundary regressions.

All executors are explicit local test fixtures, never native acceptance claims.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from blackbox_core import chain_engine
from blackbox_core.chain_contracts import PortSpec, WorkflowError
from blackbox_core.chain_engine import WorkflowEngine
from blackbox_core.chain_store import WorkflowRunStore
from test_chain_engine import adapter, edge, node_records, outcome, workflow


class WorkflowAdmissionAuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)

    def history_bytes(self,store):
        return {str(path.relative_to(store.folder)):hashlib.sha256(path.read_bytes()).hexdigest()
                for path in Path(store.folder).rglob('*') if path.is_file()}

    @staticmethod
    def head(store):
        events=store.read_events()
        return events[-1]['sequence'],events[-1]['record_sha256']

    def fixture(self,definition=None):
        calls=[];cleanup=[]
        def execute(ctx,inputs,parameters):
            calls.append(ctx.node_id)
            return outcome(ctx)
        def finish(ctx):
            cleanup.append(ctx.run_id)
            return {'status':'COMPLETED','cleanup':{'confirmed':True,'status':'CONFIRMED',
                'scope':'TEST_ONLY_RUNTIME_BOUNDARY'}}
        catalog={'read':adapter('read',execute),
            'consume':adapter('consume',execute,inputs={'input':PortSpec(('REPORT',))})}
        definition=definition or workflow([{'node_id':'read','tool_id':'read'}])
        store=WorkflowRunStore.create(self.root/'runs',definition)
        runtime=SimpleNamespace(finish_run=finish)
        return definition,catalog,store,runtime,calls,cleanup

    def test_stale_engine_cannot_replay_completed_history_with_shared_or_separate_facade(self):
        for separate in (False,True):
            with self.subTest(separate_facade=separate):
                definition,catalog,store,runtime,calls,cleanup=self.fixture()
                first=WorkflowEngine(definition,catalog=catalog,store=store,runtime=runtime)
                other_store=WorkflowRunStore.open(store.folder) if separate else store
                stale=WorkflowEngine(definition,catalog=catalog,store=other_store,runtime=runtime)
                self.assertEqual(first.run()['state'],'COMPLETED')
                before,head=self.history_bytes(store),self.head(store)
                with self.assertRaisesRegex(WorkflowError,'WORKFLOW_HISTORY_ADVANCED'):
                    stale.run()
                self.assertEqual(calls,['read'])
                self.assertEqual(cleanup,[store.run_id])
                self.assertEqual(self.head(store),head)
                self.assertEqual(self.history_bytes(store),before)
                self.assertEqual(store.load_state()['state'],'COMPLETED')

    def test_constructor_after_completion_requires_restore_without_replaying_or_cleaning(self):
        definition,catalog,store,runtime,calls,cleanup=self.fixture()
        first=WorkflowEngine(definition,catalog=catalog,store=store,runtime=runtime)
        self.assertEqual(first.run()['state'],'COMPLETED')
        before=self.history_bytes(store)
        with self.assertRaisesRegex(WorkflowError,'WORKFLOW_HISTORY_ADVANCED'):
            WorkflowEngine(definition,catalog=catalog,store=WorkflowRunStore.open(store.folder),runtime=runtime)
        restored=WorkflowEngine.restore(WorkflowRunStore.open(store.folder),catalog=catalog,runtime=runtime)
        self.assertEqual(restored.resume()['state'],'COMPLETED')
        self.assertEqual(calls,['read'])
        self.assertEqual(cleanup,[store.run_id])
        self.assertEqual(self.history_bytes(store),before)

    def checkpoint_definition(self):
        return workflow([{'node_id':'saved','tool_id':'read'},
            {'node_id':'checkpoint','kind':'CHECKPOINT','budget_seconds':1},
            {'node_id':'after','tool_id':'consume'}],[
                edge('saved','checkpoint',port='receipt',target='after'),
                edge('saved','after'),edge('checkpoint','after',port='continue',target='when')])

    def test_two_restored_checkpoint_snapshots_cannot_both_dispatch_the_same_downstream_node(self):
        definition,catalog,store,runtime,calls,cleanup=self.fixture(self.checkpoint_definition())
        paused=WorkflowEngine(definition,catalog=catalog,store=store,runtime=runtime).run()
        self.assertEqual(paused['state'],'WAITING_FOR_HUMAN')
        first=WorkflowEngine.restore(WorkflowRunStore.open(store.folder),catalog=catalog,runtime=runtime)
        stale=WorkflowEngine.restore(WorkflowRunStore.open(store.folder),catalog=catalog,runtime=runtime)
        self.assertEqual(first.resume()['state'],'COMPLETED')
        before,head=self.history_bytes(store),self.head(store)
        with self.assertRaisesRegex(WorkflowError,'WORKFLOW_HISTORY_ADVANCED'):
            stale.resume()
        self.assertEqual(calls,['saved','after'])
        self.assertEqual(cleanup,[store.run_id])
        self.assertEqual(self.head(store),head)
        self.assertEqual(self.history_bytes(store),before)
        self.assertEqual(len(node_records(store.load_state())['after']['attempts']),1)

    def test_restore_hydrates_one_captured_snapshot_and_refuses_a_later_advanced_head(self):
        definition,catalog,store,runtime,calls,cleanup=self.fixture()
        original=store.read_events
        def advancing_read():
            captured=original()
            store.append('run.state',data={'state':'WAITING_FOR_HUMAN'})
            return captured
        with patch.object(store,'read_events',side_effect=advancing_read) as read:
            restored=WorkflowEngine.restore(store,catalog=catalog,runtime=runtime)
            self.assertEqual(read.call_count,1)
        before,head=self.history_bytes(store),self.head(store)
        with self.assertRaisesRegex(WorkflowError,'WORKFLOW_HISTORY_ADVANCED'):
            restored.resume()
        self.assertEqual(calls,[])
        self.assertEqual(cleanup,[])
        self.assertEqual(self.head(store),head)
        self.assertEqual(self.history_bytes(store),before)

    def test_same_store_concurrent_engine_is_refused_before_dispatch_or_cleanup(self):
        entered,release=threading.Event(),threading.Event()
        calls=[];cleanup=[];results=[];errors=[]
        def execute(ctx,inputs,parameters):
            calls.append(ctx.node_id);entered.set()
            if not release.wait(5):raise RuntimeError('TEST_ONLY_FIXTURE_RELEASE_TIMEOUT')
            return outcome(ctx)
        def finish(ctx):
            cleanup.append(ctx.run_id)
            return {'status':'COMPLETED','cleanup':{'confirmed':True,'status':'CONFIRMED'}}
        definition=workflow([{'node_id':'read','tool_id':'read'}])
        catalog={'read':adapter('read',execute)}
        store=WorkflowRunStore.create(self.root/'runs',definition)
        runtime=SimpleNamespace(finish_run=finish)
        first=WorkflowEngine(definition,catalog=catalog,store=store,runtime=runtime)
        other=WorkflowEngine(definition,catalog=catalog,store=store,runtime=runtime)
        def drive():
            try:results.append(first.run())
            except BaseException as error:errors.append(error)
        thread=threading.Thread(target=drive,name='TEST_ONLY_CHAIN_ADMISSION',daemon=True)
        thread.start()
        try:
            self.assertTrue(entered.wait(3))
            before,head=self.history_bytes(store),self.head(store)
            with self.assertRaisesRegex(WorkflowError,'WORKFLOW_RUN_ALREADY_DRIVING'):
                other.run()
            self.assertEqual(calls,['read'])
            self.assertEqual(cleanup,[])
            self.assertEqual(self.head(store),head)
            self.assertEqual(self.history_bytes(store),before)
        finally:
            release.set();thread.join(timeout=8)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors,[])
        self.assertEqual(results[0]['state'],'COMPLETED')
        with self.assertRaisesRegex(WorkflowError,'WORKFLOW_HISTORY_ADVANCED'):
            other.run()

    def test_copied_run_id_cannot_adopt_or_release_another_engines_uncertain_lease(self):
        calls=[];foreign_cleanup=[]
        def execute(ctx,inputs,parameters):
            calls.append(ctx.run_id)
            return outcome(ctx,cleanup=False)
        definition=workflow([{'node_id':'read','tool_id':'read'}])
        catalog={'read':adapter('read',execute,resources=('TEST_ONLY_EXACT_OWNER_RESOURCE',))}
        with patch.object(chain_engine,'_LEASES',{}):
            original_store=WorkflowRunStore.create(self.root/'original',definition,run_id='copied-id-fixture')
            original=WorkflowEngine(definition,catalog=catalog,store=original_store)
            result=original.run()
            self.assertEqual(result['state'],'RECOVERY_UNCONFIRMED')
            original_lease=dict(chain_engine._LEASES['TEST_ONLY_EXACT_OWNER_RESOURCE'])
            copied=WorkflowRunStore.create(self.root/'other-root',definition,run_id=original_store.run_id)
            runtime=SimpleNamespace(finish_run=lambda ctx:foreign_cleanup.append(ctx.run_id))
            foreign=WorkflowEngine(definition,catalog=catalog,store=copied,runtime=runtime)
            before=self.history_bytes(original_store)
            with self.assertRaisesRegex(WorkflowError,'WORKFLOW_RUN_OWNER_CAPABILITY_MISMATCH'):
                foreign.run()
            self.assertEqual(calls,[original_store.run_id])
            self.assertEqual(foreign_cleanup,[])
            self.assertEqual(chain_engine._LEASES['TEST_ONLY_EXACT_OWNER_RESOURCE'],original_lease)
            self.assertEqual(self.history_bytes(original_store),before)
            self.assertNotIn('capability',json.dumps(result))
            self.assertNotIn('capability',json.dumps(original_store.read_events()))

    def test_invalid_observed_writer_birth_never_proves_a_live_history_owner_gone(self):
        import psutil
        definition,catalog,store,runtime,calls,cleanup=self.fixture()
        store.acquire_writer()
        self.addCleanup(store.release_writer)
        other=WorkflowRunStore.open(store.folder)
        created=psutil.Process().create_time()
        before=self.history_bytes(store)
        for invalid in (float('nan'),float('inf'),None,False,0,-1,10**1000):
            with self.subTest(observed_birth=invalid):
                def observed(pid=None):
                    self.assertIn(pid,(None,os.getpid()))
                    return SimpleNamespace(create_time=lambda:created if pid is None else invalid)
                with patch('psutil.Process',side_effect=observed):
                    with self.assertRaisesRegex(WorkflowError,'WORKFLOW_WRITER_OWNERSHIP_UNCONFIRMED'):
                        other.acquire_writer()
                    with self.assertRaisesRegex(WorkflowError,'WORKFLOW_WRITER_OWNERSHIP_UNCONFIRMED'):
                        other._other_history_writer_live(time.monotonic()+5)
                self.assertEqual(self.history_bytes(store),before)
                self.assertIsNotNone(store._writer_nonce)
