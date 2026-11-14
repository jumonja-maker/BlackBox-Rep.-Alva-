"""Hosted-only Qt/protocol contracts; no synthetic result is native evidence."""
import io
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtCore import QObject, QProcess
from PySide6.QtWidgets import QApplication, QWidget
from blackbox_universal.investigation_graph_panel import InvestigationGraphPanel
from blackbox_universal.research_bridge import ResearchBridge
from test_inv_gui import DeepPanelDouble, ReaderDouble, fixture_case


class IntegrityGuiContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = QWidget(); self.window.language = 'EN'
        self.deep = DeepPanelDouble(self.window); self.reader = ReaderDouble()
        self.panel = InvestigationGraphPanel(self.window, self.deep, bridge=self.reader)

    def tearDown(self):
        self.panel.shutdown(); self.window.close(); self.window.deleteLater()
        self.app.processEvents()

    def test_integrity_view_explains_actual_recorded_receipt_without_authenticating_import(self):
        case = fixture_case()
        case['sources'] = [{'source_type':'SYNTHETIC', 'source_id':'s', 'source_size_bytes':13,
                            'source_sha256':'a'*64, 'verification_class':'UNVERIFIED_IMPORT',
                            'coverage':{'capture_status':'TRUNCATED'}}]
        case['coverage']['evidence_completeness'] = 'INCOMPLETE_EVIDENCE'
        case['run_receipt'] = {'run_id':'synthetic-r20-run', 'operation':'investigation.create',
            'status':'COMPLETED', 'source':{'verification_scope':'BYTE_CONSISTENCY_ONLY_NOT_PRODUCER_AUTHENTICATION',
                                         'producer_authentication':'NOT_ESTABLISHED'},
            'cleanup':{'confirmed':False}}
        self.panel.load_case(case)
        self.panel.section.setCurrentIndex(self.panel.section.findData('integrity'))
        self.assertEqual(self.panel._models['integrity'].rowCount(), 1)
        self.assertIn('INCOMPLETE_EVIDENCE', self.panel.integrity_summary.text())
        self.assertIn('synthetic-r20-run', self.panel.integrity_receipt.toPlainText())
        self.assertIn('NOT_ESTABLISHED', self.panel.integrity_receipt.toPlainText())
        self.window.language = 'RU'; self.panel.retranslate()
        self.assertIn('Запуск:', self.panel.integrity_receipt.toPlainText())
        self.assertEqual(self.reader.calls, []); self.assertEqual(self.deep.calls, [])

    def test_imported_cleanup_claim_never_authorizes_a_live_cleanup(self):
        case = fixture_case()
        case['run_receipt'] = {'cleanup':{'owner_retained':True}, 'status':'RECOVERY_UNCONFIRMED'}
        with patch('blackbox_core.optional_jobs.OwnedProcess.pending_cleanup', return_value=[]):
            self.panel.load_case(case)
            self.assertFalse(self.panel.retry_owned_button.isEnabled())
            self.assertFalse(self.panel.retry_owned_cleanup())
        self.assertEqual(self.reader.calls, [])


class ResearchQuitContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def bridge(self, payload, *, ident='quit-1'):
        value = ResearchBridge.__new__(ResearchBridge); QObject.__init__(value)
        value.process = Mock()
        value.process.state.return_value = QProcess.ProcessState.Running
        value.process.readAllStandardOutput.return_value = (json.dumps({
            'type':'result','id':ident,'op':'quit','result':payload,'error':None})+'\n').encode()
        value._pending = {'quit-1':'quit'}; value._queue=[]; value._buffer=bytearray()
        value.closing=True; value.last_response=0; value._stop_deadline=1; value.last_error=None
        return value

    def test_cleanup_refusal_keeps_transport_open_for_explicit_retry(self):
        owner = self.bridge({'cleanup_required':True})
        owner._read()
        owner.process.closeWriteChannel.assert_not_called()
        owner.process.kill.assert_not_called()
        self.assertFalse(owner.closing)
        self.assertEqual(owner.last_error, 'RESEARCH_RESOURCE_CLEANUP_UNCONFIRMED')

    def test_matching_confirmed_quit_ack_closes_stdin(self):
        owner = self.bridge({'cleanup_required':False})
        owner._read(); owner.process.closeWriteChannel.assert_called_once_with()
        self.assertTrue(owner.closing)

    def test_unmatched_quit_cannot_close_transport(self):
        owner = self.bridge({'cleanup_required':False}, ident='foreign-id')
        owner._read(); owner.process.closeWriteChannel.assert_not_called()

    def test_shutdown_flush_does_not_close_before_ack(self):
        owner = self.bridge({'cleanup_required':False})
        owner._flush(); owner.process.closeWriteChannel.assert_not_called()

    def test_unresponsive_stop_is_uncertain_and_does_not_kill_owner(self):
        owner = self.bridge({'cleanup_required':True})
        with patch('blackbox_universal.research_bridge.time.monotonic', return_value=10):
            owner._check_deadline()
        owner.process.kill.assert_not_called()
        self.assertFalse(owner.closing)
        self.assertEqual(owner.last_error, 'HELPER_STOP_TIMEOUT_PARTIAL_SESSION_RETAINED')

    def run_worker_contract(self, outcomes):
        from blackbox_core import research_worker
        seen=[]
        class FakeJobs:
            busy=True
            def cancel(self):return []
        class FakeSession:
            def __init__(self, _root):
                self.jobs=FakeJobs(); self.probe=SimpleNamespace(active=False); self.book=None
            def snapshot(self):return {'optional_jobs':{'cleanup_required':self.jobs.busy}}
            def poll_optional(self):return []
            def cancel_optional(self):return self.jobs.cancel()
            def command(self, command):
                seen.append(command['id'])
                pending=outcomes[min(len(seen)-1,len(outcomes)-1)]
                self.jobs.busy=pending
                return {'cleanup_required':pending,'state':'INCOMPLETE' if pending else 'COMPLETED'}
            def stop(self, _reason):return None
            def _recording_resources_closed(self):return not self.jobs.busy
        commands=''.join(json.dumps({'id':'q'+str(i),'op':'quit'})+'\n' for i in range(len(outcomes)))
        output=io.StringIO()
        with patch.object(research_worker,'ResearchSession',FakeSession), \
             patch.object(research_worker,'_streams',return_value=(io.StringIO(commands),output)):
            code=research_worker.main()
        return code,seen,output.getvalue()

    def test_worker_rejects_first_quit_then_accepts_explicit_cleanup_retry(self):
        code,seen,output=self.run_worker_contract([True,False])
        self.assertEqual(code,0); self.assertEqual(seen,['q0','q1'])
        self.assertIn('"cleanup_required":true',output)

    def test_eof_with_unconfirmed_resources_returns_nonzero(self):
        code,seen,_output=self.run_worker_contract([True])
        self.assertEqual(code,3); self.assertEqual(seen,['q0','eof'])
