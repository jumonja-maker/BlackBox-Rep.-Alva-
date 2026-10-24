"""Exercise the actual production isolated GUI, including slow SQLite IO."""
from __future__ import annotations
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
import sys
import traceback
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM","offscreen")
from PySide6.QtCore import QTimer,QCoreApplication,QEvent,QItemSelectionModel
from PySide6.QtWidgets import QApplication,QDialog,QMessageBox
from blackbox_universal.window import UniversalWindow


class IsolatedGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app=QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)
    def drain(self,condition,seconds=10):
        end=time.monotonic()+seconds
        while not condition() and time.monotonic()<end:
            self.app.processEvents();time.sleep(.005)
        return condition()
    def setUp(self):
        self.callback_errors=[];self.previous_hook=sys.excepthook
        sys.excepthook=lambda kind,value,tb:self.callback_errors.append("".join(traceback.format_exception(kind,value,tb)))
        self.temp=tempfile.TemporaryDirectory()
        self.window=UniversalWindow(isolated=True,output_root=Path(self.temp.name),allow_update_check=False)
        self.window._timer.stop()
        self.window.probe.attach(os.getpid())
        self.assertTrue(self.drain(lambda:self.window.probe.pid==os.getpid() and not self.window.probe.pending),
                        self.window.probe.last_error)
    def tearDown(self):
        try:
            self.window.close()
            self.assertTrue(self.drain(lambda:not self.window.probe.alive,seconds=15))
            self.window.deleteLater();self.app.processEvents();self.temp.cleanup()
            self.assertEqual(self.callback_errors,[],"Qt callback exception must fail GUI acceptance")
        finally:sys.excepthook=self.previous_hook
    def start_recording(self):
        self.window._start()
        self.assertTrue(self.drain(lambda:self.window.probe.active and self.window.probe.total_samples>=1 and not self.window.probe.pending))
    def test_sqlite_wait_does_not_block_gui_or_advance_uncommitted_action(self):
        self.start_recording();bridge=self.window.probe
        db=sqlite3.connect(bridge.session_folder/"session.sqlite3",timeout=3)
        pulses=[];timer=QTimer();timer.setInterval(5);timer.timeout.connect(lambda:pulses.append(1));timer.start()
        try:
            db.execute("BEGIN IMMEDIATE")
            bridge.prepare_action(baseline_ms=0)
            end=time.monotonic()+.25
            while time.monotonic()<end:self.app.processEvents();time.sleep(.003)
            self.assertGreater(len(pulses),10)
            self.assertTrue(bridge.pending);self.assertEqual(bridge.actions.state,"IDLE")
            self.window._navigate("events");self.assertEqual(self.window.stack.currentIndex(),2)
        finally:db.rollback();db.close();timer.stop()
        self.assertTrue(self.drain(lambda:bridge.actions.state in ("ARMED","BASELINE") and not bridge.pending))
    def test_close_finalizes_owned_helper_and_keeps_evidence(self):
        self.start_recording();folder=self.window.probe.session_folder
        self.window.close()
        self.assertTrue(self.drain(lambda:not self.window.probe.alive))
        with closing(sqlite3.connect(folder/"session.sqlite3")) as db:
            row=db.execute("SELECT exit_code FROM metadata").fetchone()
        self.assertEqual(row[0],"INTERRUPTED")
        self.assertTrue((folder/"research.sqlite3").is_file())
    def test_bilingual_controls_keep_five_pages(self):
        self.assertEqual(self.window.stack.count(),5)
        self.window._set_language("RU")
        self.assertEqual(self.window.research_panel.load.text(),"Показать интервал")
        self.window._set_language("EN")
        self.assertEqual(self.window.research_panel.load.text(),"Load interval")
        self.assertEqual(self.window.library_panel.open_button.text(),"Open selected")
    def test_permanent_trash_deletion_is_really_confirmed_in_ui(self):
        self.start_recording();w=self.window;b=w.probe;folder=b.session_folder
        w._stop();self.assertTrue(self.drain(lambda:not b.active and not b.pending))
        p=w.library_panel;p.refresh();self.assertTrue(self.drain(lambda:bool(p.rows) and not p._busy))
        row=next(r for r in p.rows if r['folder']==str(folder))
        with patch.object(p,'confirm_plan',side_effect=lambda plan:p.send('library_apply_trash',confirmation_token=plan['confirmation_token'])):
            p.send('library_plan_trash',entry_ids=[row['entry_id']]);self.assertTrue(self.drain(lambda:not p._busy))
        p.filter.setCurrentIndex(p.filter.findData('TRASH'));self.assertTrue(self.drain(lambda:not p._busy and any(r['state']=='TRASH' for r in p.rows)))
        index=next(i for i,r in enumerate(p.rows) if r['entry_id']==row['entry_id']);payload=Path(p.rows[index]['folder']);p.table.selectRow(index)
        self.assertTrue(self.drain(lambda:p.purge_button.isEnabled()))
        with patch('blackbox_universal.library_panel.QMessageBox.exec',return_value=QMessageBox.StandardButton.No):
            p.purge_button.click();self.assertTrue(self.drain(lambda:not p._busy))
        self.assertTrue(payload.exists())
        with patch('blackbox_universal.library_panel.QMessageBox.exec',return_value=QMessageBox.StandardButton.Yes):
            p.purge_button.click();self.assertTrue(self.drain(lambda:not p._busy and not payload.exists()))

    def test_new_user_markers_analysis_and_event_filters_use_real_isolated_owner(self):
        self.start_recording();w=self.window;b=w.probe
        w.marker_panel.name.setText('real GUI stage');w.marker_panel.send('STAGE_BEGIN')
        self.assertTrue(self.drain(lambda:bool(b.snapshot().get('active_stages')) and not b.pending))
        w.marker_panel.send('STAGE_END')
        self.assertTrue(self.drain(lambda:not b.snapshot().get('active_stages') and not b.pending))
        first=b.total_samples
        self.assertTrue(self.drain(lambda:b.total_samples>first,seconds=4))
        w._stop();self.assertTrue(self.drain(lambda:not b.active and not b.pending))
        w._load_session_interval(b.session_folder)
        self.assertTrue(self.drain(lambda:w._interval_worker is None and w.analysis_panel.folder==b.session_folder))
        w.analysis_panel.load.click()
        self.assertTrue(self.drain(lambda:w.analysis_panel.packet is not None and not w.analysis_panel._busy))
        self.assertTrue(any(r['confidence_class']=='USER_REPORTED' for r in w.analysis_panel.packet['findings']))
        w.events_panel.source.setCurrentIndex(w.events_panel.source.findData('USER'));w.events_panel.refresh()
        self.assertTrue(self.drain(lambda:w.events_panel.packet is not None and not w.events_panel._busy))
        self.assertTrue(all(r['source']=='USER' for r in w.events_panel.packet['rows']))
        self.assertGreater(w.events_panel.packet['total_matching'],0)

    def test_preparation_wizard_requires_actual_control_event(self):
        self.start_recording();panel=self.window.research_panel;panel.prepare()
        dialog=panel.preparation_dialog
        self.assertTrue(self.drain(lambda:not self.window.probe.pending))
        self.assertFalse(self.window.probe.data.get("app_ready"))
        dialog.generate.click()
        self.assertTrue(self.drain(lambda:dialog.packet is not None))
        from blackbox_core.instrumentation import EventWriter
        writer=EventWriter(dialog.packet["event_path"],dialog.packet["token"])
        self.assertTrue(writer.emit("blackbox.ready"))
        self.assertTrue(self.drain(lambda:self.window.probe.data.get("app_ready")))
        self.assertIn("received",dialog.verification.text())
        dialog.close();QCoreApplication.sendPostedEvents(None,QEvent.Type.DeferredDelete)
        self.assertIsNone(panel.preparation_dialog)
    def test_reports_fit_minimum_window_width_in_russian(self):
        self.window._set_language("RU");self.window._navigate("reports")
        self.window.research_toggle.setChecked(True);self.window.resize(1020,850);self.window.show()
        self.app.processEvents()
        self.assertLessEqual(self.window.research_panel.width(),self.window.stack.currentWidget().viewport().width())
        self.window.library_toggle.setChecked(True);self.window.library_panel.storage_toggle.setChecked(True)
        self.app.processEvents()
        self.assertLessEqual(self.window.library_panel.width(),self.window.stack.currentWidget().viewport().width())

    def saved_recording(self,version):
        bridge=self.window.probe
        bridge.send('configure',scenario='GUI library',scenario_version=version,workload='same input',target_version=version)
        self.assertTrue(self.drain(lambda:not bridge.pending));self.start_recording()
        folder=bridge.session_folder;self.window.stop_btn.click()
        self.assertTrue(self.drain(lambda:not bridge.pending and not bridge.active))
        return folder
    def select_library_rows(self,*indexes):
        table=self.window.library_panel.table;table.clearSelection()
        flags=QItemSelectionModel.SelectionFlag.Select|QItemSelectionModel.SelectionFlag.Rows
        for index in indexes:table.selectionModel().select(table.model().index(index,0),flags)
    def test_index_search_discards_stale_pages_and_does_not_poll_sample_updates(self):
        self.saved_recording('1');panel=self.window.library_panel;bridge=self.window.probe
        with patch.object(bridge,'send',wraps=bridge.send) as send:
            for _ in range(5):bridge.updated.emit();self.window._update_all()
            self.assertFalse(any(c.args[0].startswith('library_') for c in send.call_args_list))
            panel.refresh();panel.search.setText('absent');panel.refresh();panel.search.setText('GUI library');panel.refresh()
            self.assertTrue(self.drain(lambda:not bridge.pending and not panel._page_pending and not panel._query_dirty))
            self.assertEqual(len(panel.rows),1);self.assertEqual(panel.rows[0]['scenario'],'GUI library')
            self.assertEqual(panel.selected(),[]);self.assertFalse(panel.open_button.isEnabled())
            self.assertLessEqual(sum(c.args[0]=='library_query' for c in send.call_args_list),3)
    def test_library_open_and_compare_use_real_isolated_operations_without_target_rebind(self):
        first=self.saved_recording('1');self.saved_recording('2')
        panel=self.window.library_panel;bridge=self.window.probe;pid=bridge.pid
        self.window.library_toggle.setChecked(True)
        self.assertTrue(self.drain(lambda:len(panel.rows)==2 and not bridge.pending))
        self.select_library_rows(1);panel.open_button.click()
        self.assertTrue(self.drain(lambda:self.window._interval_packet is not None and not bridge.pending))
        self.assertEqual(self.window._interval_folder,first);self.assertEqual(bridge.pid,pid)
        comparisons=[];panel.comparison_ready.connect(comparisons.append);self.select_library_rows(0,1)
        with patch.object(QDialog,'exec',return_value=QDialog.DialogCode.Accepted):panel.compare_button.click()
        self.assertTrue(self.drain(lambda:bool(comparisons) and not bridge.pending))
        self.assertIn('scenario_version',comparisons[0]['context_mismatches']);self.assertEqual(bridge.pid,pid)
        self.assertEqual(self.window.stack.count(),5)
    def test_library_review_cancel_and_confirmed_trash_restore_preserve_evidence(self):
        from blackbox_core.casebook import _hash
        from blackbox_core.library_catalog import LibraryCatalog
        folder=self.saved_recording('1');digest=_hash(folder/'session.sqlite3')
        panel=self.window.library_panel;bridge=self.window.probe;panel.refresh()
        self.assertTrue(self.drain(lambda:len(panel.rows)==1 and not bridge.pending))
        self.select_library_rows(0)
        with patch.object(QMessageBox,'exec',return_value=QMessageBox.StandardButton.No):
            panel.trash_button.click();self.assertTrue(self.drain(lambda:not bridge.pending and not panel._busy))
        self.assertTrue(folder.is_dir());self.assertEqual(_hash(folder/'session.sqlite3'),digest)
        self.select_library_rows(0)
        with patch.object(QMessageBox,'exec',return_value=QMessageBox.StandardButton.Yes):
            panel.trash_button.click();self.assertTrue(self.drain(lambda:not bridge.pending and not panel._busy))
        self.assertFalse(folder.exists());self.assertEqual(LibraryCatalog(Path(self.temp.name)).query(state='TRASH')['rows'][0]['state'],'TRASH')
        panel.filter.setCurrentIndex(panel.filter.findData('TRASH'))
        self.assertTrue(self.drain(lambda:len(panel.rows)==1 and not bridge.pending))
        self.select_library_rows(0);panel.restore_button.click()
        self.assertTrue(self.drain(lambda:folder.is_dir() and not bridge.pending))
        self.assertEqual(_hash(folder/'session.sqlite3'),digest)
    def test_upstream_window_controls_and_policy_reach_isolated_owner(self):
        self.start_recording();bridge=self.window.probe
        self.window.cpu_trigger_threshold.setValue(12.5);self.window.cpu_trigger_duration.setValue(333)
        self.window.auto_capture_btn.click()
        self.assertTrue(self.drain(lambda:bridge.data.get("incident_policy")=={"threshold":12.5,"min_duration_ms":333} and not bridge.pending))
        self.window.window_capture_btn.click()
        self.assertTrue(self.drain(lambda:bridge.window_capture is not None and not bridge.pending))
        self.assertIsInstance(bridge.window_capture.snapshot()[0],str)
        self.window.window_capture_btn.click()
        self.assertTrue(self.drain(lambda:bridge.window_capture is None and not bridge.pending))


if __name__=="__main__":unittest.main()
