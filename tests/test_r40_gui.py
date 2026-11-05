"""Hosted Qt contracts; synthetic rows/mocks are not native crash evidence."""
from copy import deepcopy
from pathlib import Path
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QWidget
from blackbox_universal.investigation_graph_bridge import InvestigationGraphWorker
from blackbox_universal.investigation_graph_panel import InvestigationGraphPanel
from blackbox_universal.research_panel import ResearchPanel
from test_inv_gui import DeepPanelDouble, ReaderDouble, fixture_case


def crash_case(count=1):
    case = fixture_case()
    node = case['nodes'][1]
    node['source_sha256'] = 'a' * 64
    reference = {'node_id':node['node_id'], 'source_id':node['source_identity'],
                 'source_record_id':node['source_record_id'], 'source_sha256':node['source_sha256']}
    event = {**reference, 'provider':'Windows Error Reporting', 'event_id':1001,
        'classification':'UNATTRIBUTED_WER_REPORT_CANDIDATE_NOT_TARGET_CRASH_PROOF',
        'exception_code':None, 'target_pid':None, 'recorded_creation_100ns':None}
    frame = {**reference, 'tid':7, 'ordinal':1, 'address':4096,
        'recorded_symbol':'FixtureCaller', 'origin':'DBGHELP_UNWOUND_CALLER',
        'recorded_source_file':'fixture.c', 'recorded_source_line':23,
        'recorded_symbol_status':'VERIFIED_LOCAL_PDB', 'recorded_source_status':'PDB_RECORDED_LINE'}
    case['crash_investigation'] = {'schema':'blackbox.crash-investigation/1',
        'status':'INCOMPLETE_EVIDENCE', 'root_cause':'UNKNOWN',
        'summary':{'failure_events':count, 'saved_dumps':0, 'threads':0, 'frames':1},
        'events':[deepcopy(event) for _ in range(count)], 'dumps':[], 'modules':[], 'threads':[], 'frames':[frame],
        'coverage':{'source_completeness':'NOT_PROVEN'}, 'limitations':['SYNTHETIC_GUI_CONTRACT_ONLY']}
    return case


class CrashGuiContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = QWidget(); self.window.language = 'EN'
        self.window._investigation_root = Path('SYNTHETIC_GUI_ONLY')
        self.deep, self.reader = DeepPanelDouble(self.window), ReaderDouble()
        self.panel = InvestigationGraphPanel(self.window, self.deep, bridge=self.reader)

    def tearDown(self):
        self.panel.shutdown(); self.window.close(); self.window.deleteLater()
        self.app.processEvents()

    def select_crash(self, case=None):
        self.panel.load_case(case or crash_case())
        self.panel.section.setCurrentIndex(self.panel.section.findData('crash'))
        self.panel._tables['crash'].selectRow(0)

    def test_unattributed_wer_and_unknown_cause_are_visible_without_native_action(self):
        self.select_crash()
        row = self.panel._models['crash'].rows[0]
        self.assertIn('Unattributed WER candidate', row['evidence_status'])
        self.assertIsNone(row['target_pid'])
        self.assertIn('Cause: UNKNOWN', self.panel.crash_report.toPlainText())
        self.assertIn('Incomplete evidence', self.panel.crash_summary.text())
        self.assertEqual(self.reader.calls, []); self.assertEqual(self.deep.calls, [])
        self.assertFalse(self.panel.retry_offline_dump_button.isEnabled())

    def test_source_link_requires_same_node_record_and_source_hash(self):
        self.select_crash()
        self.assertTrue(self.panel.open_crash_evidence())
        self.assertEqual(self.panel._selected_node_id, 'n1')
        self.assertEqual(self.panel.section.currentData(), 'graph')
        value = crash_case(); value['crash_investigation']['events'][0]['source_sha256'] = 'b' * 64
        self.select_crash(value)
        self.assertFalse(self.panel.crash_graph_button.isEnabled())
        self.assertFalse(self.panel.open_crash_evidence())
        value['crash_investigation']['events'][0]['node_id'] = 'missing'
        self.select_crash(value)
        self.assertFalse(self.panel.open_crash_evidence())

    def test_stack_view_preserves_native_origin_and_recorded_line_status(self):
        self.select_crash()
        self.panel.crash_kind.setCurrentIndex(self.panel.crash_kind.findData('frames'))
        row = self.panel._models['crash'].rows[0]
        self.assertIn('FixtureCaller', row['description'])
        self.assertIn('fixture.c:23', row['description'])
        self.assertIn('DBGHELP_UNWOUND_CALLER', row['evidence_status'])
        self.assertIn('PDB_RECORDED_LINE', row['evidence_status'])
        self.assertEqual(row['address'], 4096)
        self.assertEqual(self.reader.calls, [])

    def test_dump_only_case_opens_a_nonempty_kind_without_inventing_failure_event(self):
        value = crash_case(); value['crash_investigation']['events'] = []
        value['crash_investigation']['dumps'] = [{**value['crash_investigation']['frames'][0],
            'file':'own.dmp','architecture':'x64','exception_stream_recorded':True,'exception_code':0xC0000005}]
        self.select_crash(value)
        self.assertEqual(self.panel.crash_kind.currentData(),'dumps')
        self.assertEqual(self.panel._models['crash'].rowCount(),1)
        self.assertIn('own.dmp',self.panel._models['crash'].rows[0]['description'])
        self.assertEqual(self.panel.case['crash_investigation']['events'],[])

    def test_pages_are_bounded_and_language_change_explains_evidence_scope(self):
        self.select_crash(crash_case(130))
        model = self.panel._models['crash']
        self.assertEqual(model.rowCount(),100)
        self.panel.crash_next_button.click()
        self.assertEqual((model.offset, model.rowCount()), (100,30))
        self.assertFalse(self.panel.crash_next_button.isEnabled())
        self.window.language = 'RU'; self.panel.retranslate()
        self.assertIn('Причина: UNKNOWN',self.panel.crash_report.toPlainText())
        self.assertIn('Непривязанный кандидат WER',model.rows[0]['evidence_status'])
        self.assertEqual(model.headerData(0,Qt.Orientation.Horizontal), 'Тип')

    def test_legacy_case_clears_previous_projection_and_does_not_import_cleanup_owner(self):
        self.select_crash()
        value = fixture_case(); value['offline_owner_retained'] = True
        self.panel.load_case(value)
        self.assertEqual(self.panel._models['crash'].rowCount(),0)
        self.assertIn('not recorded',self.panel.crash_summary.text())
        self.assertFalse(self.panel.retry_offline_dump_cleanup())
        self.assertEqual(self.reader.calls, [])

    def test_saved_dump_build_has_explicit_pe_pdb_and_no_live_identity_before_target(self):
        self.deep.bridge.target = None
        self.assertTrue(self.panel.open_saved_dump('saved.dmp',image_path='chosen.exe',pdb_path='chosen.pdb'))
        operation, args = self.reader.calls[-1]
        self.assertEqual(operation,'build')
        self.assertEqual(args['sources'],[{'source_type':'DUMP_METADATA','path':'saved.dmp',
            'image_path':'chosen.exe','pdb_path':'chosen.pdb'}])
        self.assertIsNone(args['target_identity'])
        self.assertEqual(self.deep.calls, [])
        self.assertEqual(self.deep.elevation_calls,0)
        self.assertEqual(self.panel.section.currentData(),'crash')
        self.assertFalse(self.panel.open_saved_dump('other.dmp',pdb_path='orphan.pdb'))

    def test_cancelled_pe_selection_does_not_build_or_retry_inspection(self):
        with patch('blackbox_universal.investigation_graph_panel.QFileDialog.getOpenFileName',
                   side_effect=[('saved.dmp',''),('','')]), \
             patch('blackbox_universal.investigation_graph_panel.QInputDialog.getItem',
                   side_effect=lambda _parent,_title,_label,items,*args:(items[1],True)):
            self.assertFalse(self.panel.choose_saved_dump())
        self.assertEqual(self.reader.calls,[])
        self.assertIsNone(self.panel._offline_dump_path)

    def test_offline_cleanup_dispatch_has_no_action_replay_or_helper_state_change(self):
        self.deep.bridge.target = None
        self.deep.bridge.cleanup_required = True
        self.deep.bridge.admin_active = True
        self.panel.open_saved_dump('selected.dmp',image_path='selected.exe')
        self.reader.calls.clear()
        self.assertTrue(self.panel.retry_offline_dump_cleanup())
        self.assertEqual(self.reader.calls,[('cleanup_offline_dump',{'path':'selected.dmp'})])
        self.assertTrue(self.deep.bridge.cleanup_required)
        self.assertTrue(self.deep.bridge.admin_active)
        self.assertEqual(self.deep.calls,[])
        result = {'status':'RECOVERY_UNCONFIRMED','data':{'offline_owner_retained':True,
            'resource_owner':'SAVED_DBGHELP_SESSION','cleanup_confirmed':False}}
        self.panel._received('cleanup_offline_dump',{'offline_cleanup':result},'',self.reader.generation)
        self.assertIn('RECOVERY_UNCONFIRMED',self.panel.status.text())
        self.assertIn('SAVED_DBGHELP_SESSION',self.panel.details.toPlainText())

    def test_worker_cleanup_calls_only_real_scoped_entrypoint(self):
        worker = InvestigationGraphWorker('cleanup_offline_dump',{'path':'selected.dmp'},0,api=SimpleNamespace())
        received=[];worker.result_ready.connect(lambda *args:received.append(args))
        result={'status':'COMPLETED','data':{'had_retained_owner':False,'cleanup_confirmed':True}}
        with patch('blackbox_core.deep_dump.inspect_dump',return_value=result) as inspect:
            worker.run()
        inspect.assert_called_once_with('selected.dmp',retry_cleanup=True,cancel_event=worker.cancel_event)
        self.assertEqual(received[0][1],{'offline_cleanup':result})
        self.assertEqual(received[0][2],'')

    def test_research_default_and_optional_cdb_are_distinct(self):
        deep=SimpleNamespace(_inspect_dump=Mock(return_value=True))
        toggle=SimpleNamespace(setChecked=Mock())
        context=SimpleNamespace(window=SimpleNamespace(deep_inspector_panel=deep,deep_inspector_toggle=toggle),
            details=SimpleNamespace(setPlainText=Mock()),tr=lambda en,ru:en,send=Mock())
        self.assertTrue(ResearchPanel.inspect_dump(context))
        deep._inspect_dump.assert_called_once_with(); context.send.assert_not_called()
        with patch('blackbox_universal.research_panel.QFileDialog.getOpenFileName',return_value=('saved.dmp','')), \
             patch('blackbox_universal.research_panel.QFileDialog.getExistingDirectory',return_value='symbols'):
            ResearchPanel.inspect_dump_cdb(context)
        context.send.assert_called_once_with('inspect_dump',dump='saved.dmp',symbols='symbols')

    def test_worker_preserves_scoped_native_recovery_failure_without_claiming_cleanup(self):
        error = RuntimeError('SCOPED_SYMBOL_CLEANUP_FAILED')
        error.code = 'SCOPED_SYMBOL_CLEANUP_FAILED'
        error.status = 'RECOVERY_UNCONFIRMED'
        error.offline_owner_retained = True
        error.resource_owner = 'SAVED_DBGHELP_SESSION'
        worker = InvestigationGraphWorker('cleanup_offline_dump',{'path':'selected.dmp'},0,api=SimpleNamespace())
        received=[];worker.result_ready.connect(lambda *args:received.append(args))
        with patch('blackbox_core.deep_dump.inspect_dump',side_effect=error):
            worker.run()
        self.assertIsNone(received[0][1])
        self.assertIn('RECOVERY_UNCONFIRMED [SAVED_DBGHELP_SESSION]',received[0][2])
        self.assertIn('SCOPED_SYMBOL_CLEANUP_FAILED',received[0][2])
