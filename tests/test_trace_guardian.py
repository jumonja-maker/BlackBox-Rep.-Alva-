import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from blackbox_core.trace_owner import TraceSupervisor,run,_read

class TraceGuardianTests(unittest.TestCase):
    def test_native_stack_profile_is_explicit_allowlisted_and_default_is_unchanged(self):
        from blackbox_core.windows_research import WprCapture
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(TraceSupervisor(tmp).data['policy']['profile'], 'GeneralProfile.Light')
            for profile in ('GeneralProfile.Light', 'CPU.Verbose'):
                with patch('blackbox_core.windows_research.wpr_tool', return_value='wpr.exe'):
                    capture = WprCapture(tmp, profile=profile)
                with patch.object(capture, '_run') as command:
                    result = capture.start()
                    command.assert_called_once_with(['-start', profile])
                    self.assertEqual(result['profile'], profile)
                    capture.active = False
            for invalid in ('OtherProfile', '../untrusted.wprp!X', 'CPU -filemode', True, None):
                with self.subTest(profile=invalid):
                    with self.assertRaisesRegex(ValueError, 'INVALID_WPR_PROFILE'):
                        TraceSupervisor(tmp, profile=invalid)
                    with self.assertRaisesRegex(ValueError, 'INVALID_WPR_PROFILE'):
                        WprCapture(tmp, profile=invalid)
            trace = TraceSupervisor(tmp)
            trace.data['policy']['profile'] = 'untrusted.wprp!X'
            trace.path.write_text(json.dumps(trace.data))
            with patch('blackbox_core.research_worker._streams', return_value=(io.StringIO(''), io.StringIO())):
                with self.assertRaisesRegex(ValueError, 'INVALID_WPR_PROFILE'):
                    run(trace.path)

    def test_eventpipe_deadline_is_bounded_and_forced_exit_never_succeeds(self):
        from blackbox_core.runtime_trace import (
            eventpipe_collection_deadline_seconds, eventpipe_capture_confirmed,
            EVENTPIPE_FINALIZE_GRACE_S,
        )
        self.assertEqual(eventpipe_collection_deadline_seconds(2), 14)
        self.assertLessEqual(
            eventpipe_collection_deadline_seconds(60) + EVENTPIPE_FINALIZE_GRACE_S, 80)
        for invalid in (0, 61, True, "2"):
            with self.subTest(seconds=invalid):
                with self.assertRaisesRegex(ValueError, "INVALID_EVENTPIPE_POLICY"):
                    eventpipe_collection_deadline_seconds(invalid)
        self.assertTrue(eventpipe_capture_confirmed(0, 4096, False))
        self.assertFalse(eventpipe_capture_confirmed(0, 4096, True))
        self.assertFalse(eventpipe_capture_confirmed(1, 4096, False))
        self.assertFalse(eventpipe_capture_confirmed(0, 0, False))
        self.assertFalse(eventpipe_capture_confirmed(None, 4096, False))


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
            def __init__(self,folder,*,profile="GeneralProfile.Light"):self.folder=Path(folder);self.profile=profile;self.active=False;self.tool=None;captures.append(self)
            def start(self):self.active=True;return {'status':'RECORDING'}
            def stop(self):
                self.active=False;p=self.folder/'fixture.etl';p.write_bytes(b'explicit synthetic trace fixture')
                return {'status':'CAPTURED','path':p.name,'bytes':p.stat().st_size}
            def cancel(self):self.active=False
        with tempfile.TemporaryDirectory() as tmp:
            trace=TraceSupervisor(tmp,seconds=1,profile='CPU.Verbose')
            trace.path.write_text(json.dumps(trace.data))
            with patch('blackbox_core.windows_research.WprCapture',FakeCapture),patch('blackbox_core.research_worker._streams',return_value=(io.StringIO(''),io.StringIO())):
                self.assertEqual(run(trace.path),0)
            data=_read(trace.path);self.assertEqual(data['state'],'COMPLETED')
            self.assertEqual(captures[0].profile,'CPU.Verbose')
            self.assertEqual(data['stop_reason'],'LEASE_EOF_OR_EXPLICIT_STOP');self.assertFalse(captures[0].active)
            self.assertEqual(len(data['result']['sha256']),64)
            # The journal carries brackets from the owning capture guardian,
            # never a derived claim of cross-session clock synchronization.
            anchors=data['clock_anchors']
            for name in ('before_tool_start','after_tool_start',
                         'before_tool_stop','after_tool_stop','guardian_finally'):
                self.assertIn(name,anchors)
                self.assertEqual(anchors[name]['trace_to_session_alignment'],
                                 'NOT_ESTABLISHED')
            self.assertEqual(anchors['before_tool_start']['schema'],
                             'blackbox.trace-clock-bracket/1')
    def test_ttl_and_size_policy_cannot_be_unbounded(self):
        for seconds in (0,61,True):
            with self.assertRaises(ValueError):TraceSupervisor('.',seconds=seconds)
        with self.assertRaises(ValueError):TraceSupervisor('.',max_output_bytes=1)
    def test_invalid_named_instance_cannot_cancel_another_profiler(self):
        with tempfile.TemporaryDirectory() as tmp:
            trace=TraceSupervisor(tmp);trace.data['instance']='OtherProfiler';trace.path.write_text(json.dumps(trace.data))
            with patch('blackbox_core.research_worker._streams',return_value=(io.StringIO(''),io.StringIO())):
                with self.assertRaisesRegex(ValueError,'INSTANCE'):run(trace.path)
