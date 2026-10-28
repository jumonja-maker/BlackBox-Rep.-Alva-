"""BB-01: optional library failures must never terminate primary recording."""
from contextlib import closing
import json
import os
from pathlib import Path
import queue
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from blackbox_core.casebook import context
from blackbox_core.research_worker import ResearchSession


class Helper:
    """Real JSON-lines recorder process, observing only this test's own PID."""
    def __init__(self, root):
        code = 'from blackbox_core.research_worker import main; import sys; raise SystemExit(main(sys.argv[1]))'
        self.process = subprocess.Popen([sys.executable, '-u', '-c', code, str(root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding='utf-8')
        self.lines = queue.Queue(); self.last = None; self.serial = 0
        def read():
            for line in self.process.stdout:
                try: self.lines.put(json.loads(line))
                except ValueError: self.lines.put({'invalid':line})
            self.lines.put({'eof':True})
        self.reader = threading.Thread(target=read, daemon=True); self.reader.start()
        self.wait(lambda row:row.get('type') == 'snapshot')

    def wait(self, predicate, timeout=15):
        until = time.monotonic()+timeout
        while time.monotonic() < until:
            try: row = self.lines.get(timeout=max(.01, until-time.monotonic()))
            except queue.Empty: break
            if row.get('type') == 'snapshot': self.last = row['snapshot']
            if predicate(row): return row
            if row.get('eof'): raise AssertionError('Recorder helper exited unexpectedly')
        raise AssertionError('Recorder helper did not complete the expected protocol operation')

    def call(self, op, args=None):
        self.serial += 1; identity = str(self.serial)
        self.process.stdin.write(json.dumps({'id':identity,'op':op,'args':args or {}})+'\n')
        self.process.stdin.flush()
        reply = self.wait(lambda row:row.get('type') == 'result' and row.get('id') == identity)
        if reply.get('error'): raise AssertionError(reply)
        return reply.get('result')

    def close(self):
        try:
            if self.process.poll() is None: self.call('quit')
        finally:
            if self.process.poll() is None:
                try: self.process.wait(10)
                except subprocess.TimeoutExpired: self.process.kill(); self.process.wait(5)
            self.reader.join(3)
            self.process.stdin.close(); self.process.stdout.close(); self.process.stderr.close()


def _coherent_process_namespace():
    # A few hosted sandboxes virtualize os.getpid() without mounting matching
    # procfs. Such a PID can identify an unrelated host process. Do not turn
    # that environment into fake native-capture evidence or probe that PID.
    return not sys.platform.startswith('linux') or Path('/proc/self').resolve().name == str(os.getpid())


@unittest.skipUnless(_coherent_process_namespace(),
    'CONTROLLED_PROCESS_NAMESPACE_UNAVAILABLE: os.getpid and /proc/self differ')
class CaptureIndexFailureTests(unittest.TestCase):
    def test_real_helper_keeps_sampling_with_corrupt_optional_index_and_closes_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); index = root/'blackbox-library.sqlite3'
            index.write_bytes(b'TEST_ONLY_CORRUPT_SQLITE_INDEX')
            helper = Helper(root)
            try:
                helper.call('attach', {'pid':os.getpid()})
                helper.call('interval', {'milliseconds':100})
                folder = Path(helper.call('start')['folder'])
                helper.call('user_marker', {'kind':'STAGE_BEGIN','name':'Capture index fault'})
                snapshot = helper.wait(lambda row:row.get('type') == 'snapshot' and
                    (row['snapshot'].get('sample_count',0) >= 3 or
                     row['snapshot'].get('research_state') != 'RECORDING'))['snapshot']
                self.assertEqual(snapshot['research_state'], 'RECORDING', snapshot.get('last_error'))
                self.assertTrue(snapshot['observation_active_at_export'])
                self.assertGreaterEqual(snapshot['sample_count'], 3)
                stopped = helper.call('stop')
                self.assertEqual(stopped['state'], 'COMPLETED', stopped)
            finally: helper.close()
            self.assertEqual(index.read_bytes(), b'TEST_ONLY_CORRUPT_SQLITE_INDEX')
            with closing(sqlite3.connect(folder/'session.sqlite3')) as db:
                count = db.execute('SELECT count(*) FROM samples').fetchone()[0]
                self.assertGreaterEqual(count, 3)
                self.assertEqual(db.execute('SELECT exit_code FROM metadata').fetchone()[0], 'COMPLETED')
            with closing(sqlite3.connect(folder/'session-v2.sqlite3')) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM samples').fetchone()[0], count)
                self.assertEqual(db.execute("SELECT source_kind,verification_class FROM events WHERE event_type='user.stage_aborted'").fetchone(), ('USER','USER_DECLARED'))
            with closing(sqlite3.connect(folder/'research.sqlite3')) as db:
                health = [json.loads(row[0]) for row in db.execute("SELECT data FROM evidence WHERE kind='observer.health'")]
                self.assertTrue(health)
                self.assertEqual(health[0]['library_budget']['status'], 'INDEX_UNAVAILABLE')
                self.assertEqual(db.execute("SELECT count(*) FROM evidence WHERE kind='user.stage_aborted'").fetchone()[0], 1)

    def session(self, root):
        session = ResearchSession(root)
        session.command({'op':'attach','args':{'pid':os.getpid()}})
        session.command({'op':'start'})
        return session

    def test_real_exclusive_index_lock_does_not_stop_or_delay_primary_tick_unboundedly(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = self.session(tmp)
            try:
                with closing(sqlite3.connect(Path(tmp)/'blackbox-library.sqlite3')) as locked:
                    locked.execute('BEGIN EXCLUSIVE')
                    session.last_health = time.monotonic()-6
                    tick = time.monotonic(); session.tick()
                    self.assertLess(time.monotonic()-tick, 3)
                    self.assertTrue(session.probe.active)
                    self.assertEqual(session._library_budget['status'], 'INDEX_UNAVAILABLE')
                    locked.rollback()
                # Expire relative to this clock's origin. Zero does not expire a
                # 60-second cache on a recently booted Linux CI VM.
                session._library_budget_at = time.monotonic()-61
                session.last_health = time.monotonic()-6
                session.tick()
                self.assertEqual(session.probe.total_samples, 2)
                self.assertNotEqual(session._library_budget.get('status'), 'INDEX_UNAVAILABLE')
            finally: session.stop()
            self.assertEqual(session.research_state, 'COMPLETED')

    def test_user_stage_sqlite_finalization_failure_still_closes_primary_stores_honestly(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = self.session(tmp)
            try:
                session.tick()
                session.command({'op':'user_marker','args':{'kind':'STAGE_BEGIN','name':'Faulted stage'}})
                with patch.object(session.markers, 'close', side_effect=sqlite3.OperationalError('TEST_ONLY_STAGE_STORAGE_ERROR')):
                    result = session.stop()
                self.assertEqual(result['state'], 'INCOMPLETE')
                self.assertTrue(any(error.startswith('USER_STAGES_FINALIZATION_UNCONFIRMED:') for error in result['errors']))
                self.assertIsNone(session.book)
                self.assertIsNone(session.probe._store)
                self.assertFalse(session.probe.active)
                self.assertEqual(context(session.probe.session_folder)['state'], 'INCOMPLETE')
                with closing(sqlite3.connect(session.probe.session_folder/'session.sqlite3')) as db:
                    self.assertEqual(db.execute('SELECT count(*) FROM samples').fetchone()[0], 1)
                with closing(sqlite3.connect(session.probe.session_folder/'session-v2.sqlite3')) as db:
                    self.assertEqual(db.execute('SELECT count(*) FROM samples').fetchone()[0], 1)
            finally: session.stop()

    def test_optional_budget_is_cached_and_does_not_run_per_sample(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = self.session(tmp)
            try:
                from blackbox_core.library_catalog import LibraryCatalog
                with patch.object(LibraryCatalog, 'storage_budget', side_effect=sqlite3.DatabaseError('TEST_ONLY_BAD_INDEX')) as budget:
                    session.last_health = time.monotonic()-6
                    session.tick()
                    for _ in range(3): session.last_health = time.monotonic()-6; session.tick()
                    self.assertEqual(budget.call_count, 1)
                    self.assertEqual(session.probe.total_samples, 4)
                    self.assertTrue(session.probe.active)
                self.assertEqual(session._library_budget, {'status':'INDEX_UNAVAILABLE'})
            finally: session.stop()


class CaptureHandlerContractTests(unittest.TestCase):
    """Portable failure contracts with an explicit, non-native probe boundary."""
    def make_session(self, folder):
        probe = SimpleNamespace(output_root=folder, session_folder=folder,
            active=True, _store=object(), report_result={}, last_error=None,
            session_state='RECORDING', _pending_detailed=None,
            _pending_windows=None, _pending_v2=None)
        def stop(reason, **_kwargs):
            probe.active=False; probe._store=None; probe.session_state='COMPLETED'
        probe.stop=stop
        import psutil
        with patch('blackbox_universal.monitor.ReadOnlyProbe', return_value=probe), \
                patch('psutil.Process', side_effect=psutil.NoSuchProcess(os.getpid())):
            session=ResearchSession(folder)
        session._observer=session._frontend=None
        session.book=Mock()
        return session

    def test_sqlite_optional_budget_error_reaches_unavailable_and_keeps_recording(self):
        with tempfile.TemporaryDirectory() as tmp:
            session=self.make_session(Path(tmp))
            from blackbox_core.library_catalog import LibraryCatalog
            try:
                with patch.object(LibraryCatalog,'storage_budget',side_effect=sqlite3.DatabaseError('TEST_ONLY_INDEX_FAULT')) as budget:
                    session._health(); session._health()
                self.assertEqual(session._library_budget, {'status':'INDEX_UNAVAILABLE'})
                self.assertEqual(budget.call_count,1)
                self.assertTrue(session.probe.active)
                health=session.book.put.call_args_list[-1]
                self.assertEqual(health.args[0],'observer.health')
                self.assertEqual(health.args[1]['library_budget']['status'],'INDEX_UNAVAILABLE')
            finally: session.book=None; session.probe.active=False; session.jobs.cancel()

    def test_budget_retry_expiration_is_relative_even_before_one_minute_uptime(self):
        with tempfile.TemporaryDirectory() as tmp:
            session=self.make_session(Path(tmp))
            from blackbox_core.library_catalog import LibraryCatalog
            session._library_budget={'status':'INDEX_UNAVAILABLE'}
            session._library_budget_at=9.
            healthy={'policy':{'max_bytes':0},'known_bytes':0,'unknown_entries':0}
            try:
                with patch('blackbox_core.research_worker.time.monotonic',return_value=10.), \
                        patch.object(LibraryCatalog,'storage_budget',return_value=healthy) as budget:
                    session._health()
                    budget.assert_not_called()
                    self.assertEqual(session._library_budget['status'],'INDEX_UNAVAILABLE')
                    session._library_budget_at=10.-61
                    session._health()
                    budget.assert_called_once()
                    self.assertEqual(session._library_budget,healthy)
                    self.assertEqual(session._library_budget_at,10.)
                    self.assertTrue(session.probe.active)
            finally: session.book=None; session.probe.active=False; session.jobs.cancel()

    def test_sqlite_stage_failure_finalizes_as_incomplete_and_releases_primary_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            session=self.make_session(Path(tmp)); book=session.book
            with patch.object(session.markers,'close',side_effect=sqlite3.OperationalError('TEST_ONLY_STAGE_FAULT')):
                result=session.stop()
            self.assertEqual(result['state'],'INCOMPLETE')
            self.assertTrue(result['errors'][0].startswith('USER_STAGES_FINALIZATION_UNCONFIRMED:'))
            self.assertIsNone(session.book)
            self.assertIsNone(session.probe._store)
            self.assertFalse(session.probe.active)
            book.sync_legacy.assert_called_once_with(drain=True)
            book.close.assert_called_once_with('INCOMPLETE')


if __name__ == '__main__': unittest.main()
