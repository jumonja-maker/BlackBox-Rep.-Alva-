"""Exercise the actual production isolated GUI, including slow SQLite IO."""
from __future__ import annotations
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

os.environ.setdefault("QT_QPA_PLATFORM","offscreen")
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication
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
        self.temp=tempfile.TemporaryDirectory()
        self.window=UniversalWindow(isolated=True,output_root=Path(self.temp.name))
        self.window._timer.stop()
        self.window.probe.attach(os.getpid())
        self.assertTrue(self.drain(lambda:self.window.probe.pid==os.getpid() and not self.window.probe.pending),
                        self.window.probe.last_error)
    def tearDown(self):
        self.window.close()
        self.assertTrue(self.drain(lambda:not self.window.probe.alive,seconds=15))
        self.window.deleteLater();self.app.processEvents();self.temp.cleanup()
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
        with sqlite3.connect(folder/"session.sqlite3") as db:
            row=db.execute("SELECT exit_code FROM metadata").fetchone()
        self.assertEqual(row[0],"INTERRUPTED")
        self.assertTrue((folder/"research.sqlite3").is_file())
    def test_bilingual_controls_keep_five_pages(self):
        self.assertEqual(self.window.stack.count(),5)
        self.window._set_language("RU")
        self.assertEqual(self.window.research_panel.load.text(),"Показать интервал")
        self.window._set_language("EN")
        self.assertEqual(self.window.research_panel.load.text(),"Load interval")


if __name__=="__main__":unittest.main()
