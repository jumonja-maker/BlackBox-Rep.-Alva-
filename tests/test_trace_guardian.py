import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from blackbox_core.trace_owner import TraceSupervisor,run,_read

class TraceGuardianTests(unittest.TestCase):
    def test_real_guardian_failure_is_journalled_without_affecting_recorder(self):
        if os.name=='nt':self.skipTest('Non-Windows source-unavailable case')
        with tempfile.TemporaryDirectory() as tmp:
            trace=TraceSupervisor(tmp,seconds=1);trace.start();result=trace.stop()
            self.assertEqual(result['status'],'FAILED');self.assertFalse(trace.active)
            data=_read(trace.path);self.assertIn('WPR_TOOL_UNAVAILABLE',data['error'])
            self.assertEqual(data['instance'],trace.instance);self.assertIsNone(data['lost_events'])
    def test_guardian_stops_its_named_capture_after_eof_and_records_hash(self):
        captures=[]
        class FakeCapture:
            def __init__(self,folder):self.folder=Path(folder);self.active=False;self.tool=None;captures.append(self)
            def start(self):self.active=True;return {'status':'RECORDING'}
            def stop(self):
                self.active=False;p=self.folder/'fixture.etl';p.write_bytes(b'explicit synthetic trace fixture')
                return {'status':'CAPTURED','path':p.name,'bytes':p.stat().st_size}
            def cancel(self):self.active=False
        with tempfile.TemporaryDirectory() as tmp:
            trace=TraceSupervisor(tmp,seconds=1)
            trace.path.write_text(json.dumps(trace.data))
            with patch('blackbox_core.windows_research.WprCapture',FakeCapture),patch('blackbox_core.research_worker._streams',return_value=(io.StringIO(''),io.StringIO())):
                self.assertEqual(run(trace.path),0)
            data=_read(trace.path);self.assertEqual(data['state'],'COMPLETED')
            self.assertEqual(data['stop_reason'],'LEASE_EOF_OR_EXPLICIT_STOP');self.assertFalse(captures[0].active)
            self.assertEqual(len(data['result']['sha256']),64)
    def test_ttl_and_size_policy_cannot_be_unbounded(self):
        for seconds in (0,61,True):
            with self.assertRaises(ValueError):TraceSupervisor('.',seconds=seconds)
        with self.assertRaises(ValueError):TraceSupervisor('.',max_output_bytes=1)
    def test_invalid_named_instance_cannot_cancel_another_profiler(self):
        with tempfile.TemporaryDirectory() as tmp:
            trace=TraceSupervisor(tmp);trace.data['instance']='OtherProfiler';trace.path.write_text(json.dumps(trace.data))
            with patch('blackbox_core.research_worker._streams',return_value=(io.StringIO(''),io.StringIO())):
                with self.assertRaisesRegex(ValueError,'INSTANCE'):run(trace.path)
