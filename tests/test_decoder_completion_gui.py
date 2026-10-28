"""Actual Qt worker lifecycle and derived-report identity; synthetic input only."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtWidgets import QApplication, QTableWidget, QLabel
from blackbox_core.decoder_index import build_index, PROTOCOL, read_index
from blackbox_universal.decoder_window import DecoderWindow
from blackbox_universal.decoder_analysis import DiagnosticReportDialog
from blackbox_universal.theme import set_retro_theme


class DecoderCompletionGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        set_retro_theme(cls.app)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.window = DecoderWindow(output_root=self.root, allow_update_check=False)
        self.window._timer.stop(); self.window.show(); self.app.processEvents()
        self.panel = self.window.decoder_panel

    def wait_idle(self):
        end = time.monotonic() + 10
        while self.panel.worker is not None and time.monotonic() < end:
            self.app.processEvents(); time.sleep(.005)
        self.assertIsNone(self.panel.worker)

    def tearDown(self):
        from qt_test_support import close_and_drain
        self.panel.cancel(); self.wait_idle()
        close_and_drain(self.window, self.app)
        self.temp.cleanup()

    def load_waits(self):
        from test_decoder_waits import switch, ready, A, B
        rows = [switch(1, 10.), ready(2, 20.), switch(3, 30., B, A, state=1)]
        source, index = self.root/'scheduler.jsonl', self.root/'scheduler.sqlite3'
        objects = [dict(type='header', protocol=PROTOCOL, input_sha256='a'*64), *rows,
                   dict(type='footer', protocol=PROTOCOL, rows=3, status='DECODED',
                        decoder_reported_lost_events=0)]
        source.write_text(''.join(json.dumps(x)+'\n' for x in objects), encoding='utf-8')
        summary = build_index(source, index, input_sha256='a'*64, format_name='.etl')
        self.panel.received({'path': str(index), 'summary': summary}, '')
        return index

    def test_wait_report_filters_and_gui_keep_original_index(self):
        index = self.load_waits(); digest = hashlib.sha256(index.read_bytes()).hexdigest()
        self.panel.pid.setValue(42)
        self.panel.cpu_tid.setText('8')
        for lang in ('RU', 'EN'):
            self.window._set_language(lang)
            self.assertTrue(self.panel.waits_button.text())
            self.assertTrue(self.panel.align_session_button.text())
        self.panel.waits_button.click()
        self.assertFalse(self.panel.waits_button.isEnabled())
        self.assertTrue(self.panel.cancel_button.isEnabled())
        self.wait_idle()
        self.assertEqual(self.panel.analysis_report['status'], 'OBSERVED_INTERVALS')
        self.assertEqual(self.panel.analysis_report['intervals'][0]['off_cpu_ms'], 20.)
        dialog, = self.panel.findChildren(DiagnosticReportDialog)
        self.assertEqual(dialog.findChild(QTableWidget).rowCount(), 1)
        self.assertTrue(self.panel.export_analysis_button.isEnabled())
        self.assertEqual(hashlib.sha256(index.read_bytes()).hexdigest(), digest)
        self.panel.cpu_tid.setText('9')
        self.assertIsNone(self.panel.analysis_report)
        self.assertFalse(self.panel.export_analysis_button.isEnabled())

    def test_alignment_uses_explicit_pair_and_projects_selected_event(self):
        from test_decoder_alignment import fixture
        index, journal, session, _ = fixture(self.root)
        self.panel.received({'path': str(index), 'summary': read_index(index)['summary']}, '')
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (index, journal, session)}
        with patch('blackbox_universal.decoder_panel.QFileDialog.getOpenFileName',
                   side_effect=[(str(journal), ''), (str(session), '')]):
            self.panel.align_session_button.click(); self.wait_idle()
        self.assertEqual(self.panel.alignment_report['status'], 'BOUNDED_LOCAL_CLOCK_CORRELATION')
        self.panel.table.selectRow(0); self.app.processEvents()
        shown = json.loads(self.panel.details.toPlainText())
        self.assertIn('session_relative_lower_ns', shown['session_time_projection'])
        for path, digest in before.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        self.panel.start_decode(self.root/'absent.jsonl')
        self.assertIsNone(self.panel.alignment_report)
        self.wait_idle()
        self.assertFalse(self.panel.align_session_button.isEnabled())

    def test_new_wait_worker_cancels_and_restores_controls(self):
        self.load_waits()
        def blocked(*args, cancel, **kwargs):
            self.assertTrue(cancel.wait(5))
            raise InterruptedError('WAIT_ANALYSIS_CANCELLED')
        with patch('blackbox_core.decoder_waits.build_wait_report', side_effect=blocked):
            self.panel.start_wait_analysis()
            self.panel.cancel_button.click(); self.wait_idle()
        self.assertIn('WAIT_ANALYSIS_CANCELLED', self.panel.error)
        self.assertIsNone(self.panel.analysis_report)
        self.assertTrue(self.panel.open_button.isEnabled())
        self.assertTrue(self.panel.waits_button.isEnabled())
        self.assertFalse(self.panel.export_analysis_button.isEnabled())

    def test_gettickcount_alignment_exposes_coarse_uncertainty_in_summary(self):
        from test_decoder_alignment import fixture, use_gettickcount_clock
        from blackbox_core.decoder_alignment import ORDER_MODEL
        index, journal, session, data = fixture(self.root)
        use_gettickcount_clock(journal, session, data)
        self.window._set_language('RU')
        self.panel.received({'path': str(index), 'summary': read_index(index)['summary']}, '')
        self.panel.start_analysis('alignment', {'index_path': index,
            'journal_path': journal, 'session_path': session})
        self.wait_idle()
        self.assertEqual(self.panel.alignment_report['clock_model'], ORDER_MODEL)
        dialog, = self.panel.findChildren(DiagnosticReportDialog)
        text = dialog.findChild(QLabel, 'diagnosticEvidenceSummary').text()
        self.assertIn('без интерполяции', text)
        self.assertIn('у каждого события свои границы', text)
        self.panel.table.selectRow(0); self.app.processEvents()
        projection = json.loads(self.panel.details.toPlainText())['session_time_projection']
        self.assertEqual(projection['clock_model'], ORDER_MODEL)
        self.assertGreater(projection['uncertainty_width_ns'], 500_000_000)

    def test_cancelled_import_offers_retry_without_stale_evidence(self):
        def blocked(*args, cancel, **kwargs):
            self.assertTrue(cancel.wait(5))
            raise InterruptedError('DECODER_CANCELLED')
        with patch('blackbox_universal.decoder_panel.decode_file', side_effect=blocked):
            self.panel.start_decode(self.root/'fixture.jsonl')
            self.panel.cancel_button.click(); self.wait_idle()
        self.assertEqual(self.panel.import_failure['state'], 'CANCELLED')
        self.assertIsNone(self.panel.index)
        self.assertFalse(self.panel.export_button.isEnabled())
        self.assertTrue(self.panel.open_button.isEnabled())
        self.assertIn('DECODER_CANCELLED', self.panel.status.text())
