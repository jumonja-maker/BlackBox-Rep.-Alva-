from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from blackbox_core.research_worker import ResearchSession

class IsolatedOwnerCadenceTests(unittest.TestCase):
    def test_real_owner_delay_is_persisted_without_fictional_lost_os_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            s=ResearchSession(tmp);s.command({'op':'attach','args':{'pid':os.getpid()}})
            s.command({'op':'interval','args':{'milliseconds':100}});s.command({'op':'start'})
            try:s.tick();time.sleep(.7);s.tick()
            finally:s.stop()
            with closing(sqlite3.connect(s.probe.session_folder/'session.sqlite3')) as db:
                events=[json.loads(r[0]) for r in db.execute('SELECT data FROM events')]
            gaps=[r for r in events if r.get('code')=='EXTENDED_MONOTONIC_SAMPLE_SPACING']
            self.assertEqual(len(gaps),1);self.assertGreaterEqual(gaps[0]['observed_spacing_ms'],650)
            self.assertIsNone(gaps[0]['missing_sample_count']);self.assertFalse(gaps[0]['root_cause_proven'])
