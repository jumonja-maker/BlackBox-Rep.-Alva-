"""Hosted Qt contracts for the delay view; synthetic cases are not native proof."""
from copy import deepcopy
import os
import unittest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QWidget
from blackbox_universal.investigation_graph_panel import InvestigationGraphPanel
from test_inv_gui import DeepPanelDouble, ReaderDouble, fixture_case


def delay_case(*, source='n1', segment_source='n1', count=1):
    value = fixture_case()
    value['critical_path'] = {'status':'PARTIAL', 'segments':[{
        'segment_id':'segment-1', 'node_id':segment_source, 'state':'BLOCKED',
        'start':10., 'end':20., 'duration_ms':10., 'unit':'ms',
        'time_domain':'SYNTHETIC_CLOCK', 'thread_identity':{'tid':7}}]}
    finding = {'finding_id':'finding-1', 'category':'FILE_IO_ERROR', 'status':'SOURCE_REPORTED',
        'description':'Recorded file error', 'description_ru':'Записанная ошибка файла',
        'source_nodes':[source], 'critical_path_segments':['segment-1'],
        'details':{'ntstatus':0xC0000043, 'win32_error':5, 'elapsed_ms':3.,
                   'lock_owner':'NOT_ESTABLISHED'}, 'root_cause_proven':False}
    value['delay_investigation'] = {'schema':'blackbox.delay-investigation/1',
        'status':'PARTIAL_EVIDENCE', 'root_cause':'UNKNOWN',
        'findings':[{**deepcopy(finding), 'finding_id':'finding-'+str(i)} for i in range(count)],
        'coverage':{'findings_represented':count,'findings_omitted_budget':0},
        'limitations':['SYNTHETIC_GUI_CONTRACT_ONLY']}
    return value


class DelayGuiContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = QWidget(); self.window.language = 'EN'
        self.deep, self.reader = DeepPanelDouble(self.window), ReaderDouble()
        self.panel = InvestigationGraphPanel(self.window, self.deep, bridge=self.reader)

    def tearDown(self):
        self.panel.shutdown(); self.window.close(); self.window.deleteLater()
        self.app.processEvents()

    def select_delay(self, case=None):
        self.panel.load_case(case or delay_case())
        self.panel.section.setCurrentIndex(self.panel.section.findData('delays'))
        self.panel._tables['delays'].selectRow(0)

    def test_view_keeps_raw_error_namespaces_and_unknown_cause(self):
        self.select_delay()
        row = self.panel._models['delays'].rows[0]
        self.assertIn('NTSTATUS 0xC0000043', row['error_codes'])
        self.assertIn('Win32 5', row['error_codes'])
        self.assertEqual(row['details']['ntstatus'], 0xC0000043)
        self.assertIn('UNKNOWN', self.panel.delay_report.toPlainText())
        self.assertIn('Partial evidence', self.panel.delay_summary.text())
        self.assertEqual(row['snapshot_owner'], 'NOT_ESTABLISHED')
        self.assertEqual(self.reader.calls, []); self.assertEqual(self.deep.calls, [])

    def test_source_button_navigates_only_the_referenced_existing_node(self):
        self.select_delay()
        self.assertTrue(self.panel.delay_graph_button.isEnabled())
        self.assertTrue(self.panel.open_delay_evidence())
        self.assertEqual(self.panel._selected_node_id, 'n1')
        self.assertEqual(self.panel.section.currentData(), 'graph')
        self.assertEqual(self.reader.calls, []); self.assertEqual(self.deep.calls, [])

    def test_critical_path_navigation_requires_both_segment_and_source_node(self):
        self.select_delay()
        self.assertTrue(self.panel.delay_critical_button.isEnabled())
        self.assertTrue(self.panel.open_delay_critical())
        self.assertEqual(self.panel.section.currentData(), 'critical_path')
        self.assertEqual(self.panel.critical_table.selectionModel().selectedRows()[0].row(), 0)
        self.select_delay(delay_case(segment_source='n2'))
        self.assertFalse(self.panel.delay_critical_button.isEnabled())
        self.assertFalse(self.panel.open_delay_critical())
        self.assertEqual(self.panel.section.currentData(), 'delays')

    def test_dangling_imported_reference_does_not_guess_from_pid_or_time(self):
        self.select_delay(delay_case(source='missing'))
        self.assertFalse(self.panel.delay_graph_button.isEnabled())
        self.assertFalse(self.panel.open_delay_evidence())
        self.assertFalse(self.panel.open_delay_critical())
        self.assertIsNone(self.panel._selected_node_id)

    def test_bounded_pages_reach_tail_without_repeating_the_first_page(self):
        self.select_delay(delay_case(count=130))
        model = self.panel._models['delays']
        self.assertEqual(model.rowCount(),100)
        self.panel.delay_next_button.click()
        self.assertEqual(model.offset,100); self.assertEqual(model.rowCount(),30)
        self.assertFalse(self.panel.delay_next_button.isEnabled())
        self.assertTrue(self.panel.delay_previous_button.isEnabled())
        self.panel.delay_previous_button.click()
        self.assertEqual(model.offset,0)

    def test_language_switch_uses_recorded_russian_description_and_explanation(self):
        self.select_delay()
        self.window.language='RU'; self.panel.retranslate()
        model=self.panel._models['delays']
        self.assertEqual(model.data(model.index(0,1),Qt.ItemDataRole.DisplayRole),'Записанная ошибка файла')
        self.assertIn('Причина: UNKNOWN',self.panel.delay_report.toPlainText())
        self.assertIn('Неполные данные',self.panel.delay_summary.text())

    def test_loading_legacy_case_clears_previous_delay_rows(self):
        self.select_delay()
        self.panel.load_case(fixture_case())
        self.assertEqual(self.panel._models['delays'].rowCount(),0)
        self.assertFalse(self.panel.delay_graph_button.isEnabled())
        self.assertFalse(self.panel.delay_critical_button.isEnabled())
        self.assertIn('not recorded',self.panel.delay_summary.text())

    def test_ready_waker_is_not_displayed_as_a_windows_lock_owner(self):
        case=delay_case()
        row=case['delay_investigation']['findings'][0]
        row['category']='READY_DELAY'
        row['details']={'ready_delay_ms':2.,'waker_thread':{'pid':99,'tid':100},
                        'lock_owner':'NOT_ESTABLISHED'}
        self.select_delay(case)
        self.assertEqual(self.panel._models['delays'].rows[0]['snapshot_owner'],'NOT_ESTABLISHED')
