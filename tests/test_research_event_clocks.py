from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from blackbox_core.contracts import ObserverError
from blackbox_core.research_worker import ResearchSession

class ActualEventClockTests(unittest.TestCase):
    def test_delayed_marker_retains_gui_issue_time_and_separate_receive_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            s=ResearchSession(tmp);s.command({'op':'attach','args':{'pid':os.getpid()}});s.command({'op':'start'});s.tick()
            try:
                issued=time.monotonic_ns();time.sleep(.06)
                s.command({'op':'mark','issued_ns':issued,'args':{'note':'delayed marker'}})
            finally:s.stop()
            with closing(sqlite3.connect(s.probe.session_folder/'session.sqlite3')) as db:
                rows=[json.loads(r[0]) for r in db.execute('SELECT data FROM events')]
            marker=next(r for r in rows if r.get('kind')=='user_problem')
            self.assertEqual(marker['timestamp_monotonic_ns'],issued)
            self.assertGreaterEqual(marker['observer_received_monotonic_ns']-issued,40_000_000)
            self.assertEqual(marker['command_clock_origin'],'GUI_ISSUED')
    def test_invalid_or_missing_issue_time_cannot_reuse_previous_latency(self):
        s=ResearchSession()
        s.command({'op':'status','issued_ns':time.monotonic_ns()})
        self.assertIsNotNone(s.command_latency_ms)
        s.command({'op':'status'});self.assertIsNone(s.command_latency_ms)
        for invalid in (True,'clock',time.monotonic_ns()+10**12):
            with self.assertRaisesRegex(ValueError,'INVALID_COMMAND_ISSUE_TIME'):
                s.command({'op':'status','issued_ns':invalid})
            self.assertIsNone(s.command_latency_ms)

    def test_committed_detail_count_is_retained_after_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            s=ResearchSession(tmp);s.command({'op':'attach','args':{'pid':os.getpid()}});s.command({'op':'start'})
            s.command({'op':'detailed','args':{'enabled':True}})
            try:
                end=time.monotonic()+5
                while s.probe.detailed_capture.samples<1 and time.monotonic()<end:time.sleep(.01)
                before=s.snapshot()['detail_sample_count'];self.assertGreaterEqual(before,1)
            finally:s.stop()
            after=s.snapshot();self.assertGreaterEqual(after['detail_sample_count'],before)
            self.assertFalse(after['detail_enabled'])

    def test_exit_during_first_tick_finalizes_before_optional_health(self):
        # The target may disappear between attach/start and its first sample
        # on a busy Windows machine. ReadOnlyProbe.tick then closes its
        # SessionStore immediately; the research CaseBook must not mirror a
        # later health record into that closed SQLite connection.
        with tempfile.TemporaryDirectory() as tmp:
            session = ResearchSession(tmp)
            session.command({'op': 'attach', 'args': {'pid': os.getpid()}})
            session.command({'op': 'start'})
            session.command({'op': 'incidents', 'args': {'enabled': True}})
            folder = session.probe.session_folder
            try:
                with patch.object(session.probe._core, 'sample',
                                  side_effect=ObserverError('PROCESS_EXITED', 'sample')):
                    session.tick()
                self.assertFalse(session.probe.active)
                self.assertIsNone(session.book)
                self.assertIsNone(session.probe._store)
                self.assertEqual(session.probe.session_state, 'PROCESS_EXITED')
                self.assertEqual(session.research_state, 'INCOMPLETE')
                # Finalizing twice must not reopen or write into the session.
                session.stop()
                with closing(sqlite3.connect(folder / 'session.sqlite3')) as db:
                    self.assertEqual(
                        db.execute('SELECT exit_code FROM metadata').fetchone()[0],
                        'PROCESS_EXITED')
            finally:
                session.stop()

    def test_actual_exit_is_timestamped_when_observed_not_at_last_sample(self):
        target=subprocess.Popen([sys.executable,'-u','-c','import os,time;print(os.getpid(),flush=True);time.sleep(1)'],stdout=subprocess.PIPE,text=True)
        try:
            pid=int(target.stdout.readline())
            with tempfile.TemporaryDirectory() as tmp:
                s=ResearchSession(tmp);s.command({'op':'attach','args':{'pid':pid}});s.command({'op':'start'})
                s.command({'op':'incidents','args':{'enabled':True}});s.tick();previous=s.probe.last_elapsed_ms
                target.wait(timeout=5);time.sleep(.05);s.tick();s.stop()
                with closing(sqlite3.connect(s.probe.session_folder/'session.sqlite3')) as db:
                    rows=[json.loads(r[0]) for r in db.execute('SELECT data FROM events')]
                marker=next(r for r in rows if r.get('code')=='AUTO_INCIDENT_STARTED' and r.get('trigger_code')=='PROCESS_EXIT_OBSERVED')
                self.assertGreater(marker['elapsed_ms']-previous,100)
                end=next(r for r in rows if r.get('code')=='AUTO_INCIDENT_COMPLETED' and r.get('trigger_code')=='PROCESS_EXIT_OBSERVED')
                self.assertEqual(end['observed_post_ms'],0);self.assertIsNone(marker['trigger_detail']['exit_code'])
        finally:
            target.stdout.close()
            if target.poll() is None:target.terminate();target.wait(timeout=5)
