"""Audit UI contracts with real helper commands and nested Qt event loops."""
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtCore import QCoreApplication, QEvent, QSettings, QTimer
from PySide6.QtWidgets import QApplication, QMessageBox
from blackbox_core.storage import SessionStore
from blackbox_universal.decoder_window import DecoderWindow
from blackbox_universal.investigation_worker import InvestigationWorker
from qt_test_support import close_and_drain


class AuditUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.settings = QSettings(str(self.root / 'prefs.ini'), QSettings.Format.IniFormat)
        self.pref_patch = patch('blackbox_universal.window.QSettings', return_value=self.settings)
        self.pref_patch.start()
        self.window = None

    def tearDown(self):
        try:
            if self.window is not None:
                close_and_drain(self.window, self.app, timeout=20)
                self.window.deleteLater()
                QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        finally:
            self.pref_patch.stop()
            self.temp.cleanup()

    def drain(self, predicate, seconds=15):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.app.processEvents()
            if predicate(): return True
            time.sleep(.005)
        return predicate()

    def make_window(self, *, isolated=False):
        self.window = DecoderWindow(isolated=isolated, output_root=self.root,
                                    allow_update_check=False)
        self.window._timer.stop()
        return self.window

    def start_recording(self):
        w = self.make_window(isolated=True)
        w.probe.attach(os.getpid())
        self.assertTrue(self.drain(lambda: w.probe.pid == os.getpid() and not w.probe.pending))
        w._start()
        self.assertTrue(self.drain(lambda: w.probe.active and not w.probe.pending and w.probe.total_samples > 0))
        return w

    def session(self, count):
        store = SessionStore(self.root, os.getpid())
        folder = store.folder
        # A genuine schema-1 session, populated transactionally for bounded QA.
        store.db.executemany('INSERT INTO samples VALUES (?,?,?,?,?,?,?,?)',
            [(i + 1, i, 1000000 + i, 0.0, 1, i, i, 0) for i in range(count)])
        store.db.commit()
        store.finish('COMPLETED'); store.close()
        return folder

    def test_verify_pending_keeps_stop_enabled_and_real_click_stops(self):
        w = self.start_recording()
        archive = self.root / 'own.zip'; archive.write_bytes(b'not a valid ZIP')
        with patch('blackbox_universal.research_panel.QFileDialog.getOpenFileName',
                   return_value=(str(archive), 'ZIP')):
            w.research_panel.verify()
        self.assertIn('verify', w.probe._pending.values())
        self.assertTrue(w.stop_btn.isEnabled(), 'Optional verify must not disable Stop')
        with patch.object(w.probe, 'send', wraps=w.probe.send) as send:
            w.stop_btn.click()
            self.assertIn('stop', w.probe._pending.values())
            self.assertFalse(w.stop_btn.isEnabled())
            w._stop()  # A second delivered UI callback cannot enqueue another stop.
            self.assertEqual(sum(call.args[0] == 'stop' for call in send.call_args_list), 1)
        self.assertTrue(self.drain(lambda: not w.probe.active and not w.probe.pending))
        with closing(sqlite3.connect(w.probe.session_folder / 'session.sqlite3')) as db:
            self.assertEqual(db.execute('SELECT exit_code FROM metadata').fetchone()[0], 'COMPLETED')

    def test_export_pending_keeps_stop_enabled(self):
        w = self.start_recording()
        with patch('blackbox_universal.research_panel.QFileDialog.getSaveFileName',
                   return_value=(str(self.root / 'share.zip'), 'ZIP')):
            w.research_panel.export()
        self.assertIn('export', w.probe._pending.values())
        self.assertTrue(w.stop_btn.isEnabled())
        w.stop_btn.click()
        self.assertTrue(self.drain(lambda: not w.probe.active and not w.probe.pending))

    def investigate(self, *, modal, consent):
        w = self.make_window()
        folder = self.session(4097)
        observations = []
        def question(parent, title, text, buttons, default):
            if modal:
                dialog = QMessageBox(parent)
                dialog.setStandardButtons(buttons)
                deadline = time.monotonic() + 5
                def answer():
                    if w._investigation_worker is not None and time.monotonic() < deadline:
                        QTimer.singleShot(10, answer)
                        return
                    observations.append(w._investigation_worker is None)
                    dialog.done(int(consent))
                QTimer.singleShot(250, answer)
                return dialog.exec()  # Actual nested Qt loop delivers worker.finished.
            observations.append(w._investigation_worker is None)
            return consent
        with patch('blackbox_universal.window.QMessageBox.question', side_effect=question), \
             patch.object(w, '_begin_investigation', wraps=w._begin_investigation) as begin:
            w._begin_investigation(folder=folder)
            self.assertTrue(self.drain(lambda: bool(observations)))
            self.assertEqual(observations, [modal])
            if consent == QMessageBox.StandardButton.Yes:
                self.assertTrue(self.drain(lambda: w._investigation_result is not None and
                                           w._investigation_worker is None, seconds=20))
                self.assertEqual(begin.call_count, 2, 'Consent must restart exactly once')
                self.assertTrue(w.open_investigation_btn.isEnabled())
                self.assertEqual(len(list(folder.glob('investigation-*.html'))), 1)
                self.assertEqual(len(list(folder.glob('investigation-*.json'))), 1)
                self.assertEqual(w._investigation_result['coverage']['selected_samples'], 4096)
            else:
                self.assertTrue(self.drain(lambda: w._investigation_worker is None))
                self.assertEqual(begin.call_count, 1)
                self.assertEqual(list(folder.glob('investigation-*')), [])
                self.assertIsNone(w._investigation_result)
            self.assertIsNone(w._investigation_retry)

    def test_modal_consent_after_finished_restarts_real_long_session_once(self):
        self.investigate(modal=True, consent=QMessageBox.StandardButton.Yes)

    def test_immediate_consent_before_finished_restarts_real_long_session_once(self):
        self.investigate(modal=False, consent=QMessageBox.StandardButton.Yes)

    def test_modal_decline_does_not_analyze_or_export(self):
        self.investigate(modal=True, consent=QMessageBox.StandardButton.No)

    def test_completed_investigation_does_not_accumulate_qthread_children(self):
        w = self.make_window()
        folder = self.session(2)
        for _ in range(3):
            w._begin_investigation(folder=folder)
            self.assertTrue(self.drain(lambda: w._investigation_worker is None))
            QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
            self.assertEqual(w.findChildren(InvestigationWorker), [],
                             'Finished worker QObjects must not accumulate until window close')


if __name__ == '__main__': unittest.main()
