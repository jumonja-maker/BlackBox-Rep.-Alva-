"""Strict XML attribution and native query, separated from synthetic evidence."""
import json,os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import psutil
from blackbox_core.crash_events import parse_event,query,utc_ns
from blackbox_core.trace_decode import parse_xml,decode

def xml(pid,*,payload=True,provider='Application Error',eid=1000):
 data=f'<EventData><Data Name="ProcessId">0x{pid:x}</Data><Data Name="AppPath">PRIVATE_PATH</Data></EventData>' if payload else ''
 return f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="{provider}"/><EventID>{eid}</EventID><TimeCreated SystemTime="2026-10-24T12:00:00.1234567Z"/><Execution ProcessID="{pid}" ThreadID="5"/><EventRecordID>42</EventRecordID></System>{data}</Event>'

class CrashEvidenceTests(unittest.TestCase):
 def test_named_fault_pid_is_required_execution_pid_alone_is_not_a_crash_match(self):
  args={'pid':123,'start_utc_ns':0,'end_utc_ns':2**63-1}
  self.assertIsNone(parse_event(xml(123,payload=False),**args))
  self.assertIsNone(parse_event(xml(124),**args))
  row=parse_event(xml(123),**args);self.assertEqual(row['event_id'],1000)
  self.assertEqual(row['target_match_fields'],['ProcessId']);self.assertEqual(row['root_cause'],'UNKNOWN')
  self.assertNotIn('PRIVATE_PATH',json.dumps(row))
 def test_unrelated_provider_time_and_xml_declarations_are_not_accepted(self):
  args={'pid':123,'start_utc_ns':0,'end_utc_ns':2**63-1}
  self.assertIsNone(parse_event(xml(123,provider='OTHER'),**args))
  self.assertIsNone(parse_event(xml(123),**{**args,'end_utc_ns':1}))
  with self.assertRaises(ValueError):parse_event('<!DOCTYPE Event>'+xml(123),**args)
  with self.assertRaises(ValueError):utc_ns('2026-10-24T12:00:00')
  self.assertEqual(utc_ns('1970-01-01T00:00:00.000001Z'),1000)
 def test_unavailable_source_does_not_invent_no_crash_confirmation(self):
  if os.name=='nt':self.skipTest('portable unavailability case')
  result=query(os.getpid(),psutil.Process().create_time());self.assertEqual(result['status'],'UNSUPPORTED_PLATFORM')
  self.assertFalse(result['capture_complete']);self.assertIsNone(result['loss_count'])
 @unittest.skipUnless(os.name=='nt','Actual Windows Event Log API')
 def test_actual_bounded_local_eventlog_query_has_honest_status(self):
  r=query(os.getpid(),psutil.Process().create_time(),max_events=2)
  self.assertIn(r['status'],('NO_MATCH_OBSERVED','MATCHING_OS_EVENTS','TRUNCATED','TIMEOUT','ACCESS_DENIED'))
  self.assertFalse(r['capture_complete']);self.assertIsNone(r['loss_count'])

class EtlDecodeContractTests(unittest.TestCase):
 @unittest.skipUnless(os.name=='nt','Actual Windows ETW/tracerpt integration')
 def test_real_owned_etl_is_independently_decoded_to_actual_target_header_events(self):
  import importlib.util
  from blackbox_core.windows_research import privilege
  if privilege()['mode']!='ADMINISTRATOR':self.skipTest('ETW fixture requires administrator token')
  source=Path(__file__).resolve().parents[1]/'tools'/'fixtures'/'etl_header_fixture.py'
  spec=importlib.util.spec_from_file_location('bb_real_etl_fixture',source);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  with tempfile.TemporaryDirectory() as temp:
   path=Path(temp)/'owned-real.etl';fixture=module.capture(path);self.assertGreater(path.stat().st_size,0)
   r=decode(path,target_pid=fixture['pid']);self.assertEqual(r['status'],'HEADER_EVENTS_DECODED',r)
   self.assertGreaterEqual(r['matching_emitter_events'],12,r)
   self.assertTrue(any(row['event_id']=='7' for row in r['rows']),r)
   self.assertEqual(fixture['events_lost_reported_by_owned_session'],0)
   # Fixture counters are independently observed; generic imported ETL decoder
   # does not claim the same loss coverage from an opaque source file.
   self.assertIsNone(r['lost_events']);self.assertEqual(r['decoded_scope'],'EVENT_HEADERS_ONLY_NOT_STACKS_OR_GC_PAYLOADS')
 def test_full_bounded_header_scan_retains_preview_count_not_invented_loss(self):
  with tempfile.TemporaryDirectory() as temp:
   p=Path(temp)/'SYNTHETIC-not-real-etl.xml';p.write_text('<Events>'+xml(123)*601+xml(456)*10+'</Events>')
   r=parse_xml(p,target_pid=123,max_rows=20)
   self.assertEqual(r['scanned_events'],611);self.assertEqual(r['recognized_header_events'],611)
   self.assertEqual(r['matching_emitter_events'],601);self.assertEqual(len(r['rows']),20);self.assertEqual(r['rows_omitted'],581)
   self.assertEqual(r['rows'][0]['scope'],'TARGET_EMITTER_PID_NOT_CAUSAL_ATTRIBUTION');self.assertFalse(r['event_payloads_retained'])
   self.assertNotIn('PRIVATE_PATH',json.dumps(r))
 def test_utf16_entity_declaration_and_invalid_budgets_are_refused(self):
  with tempfile.TemporaryDirectory() as temp:
   p=Path(temp)/'attack.xml';p.write_bytes(('<!DOCTYPE Events [<!ENTITY x "bad">]><Events/>').encode('utf-16'))
   with self.assertRaisesRegex(ValueError,'UNSAFE'):parse_xml(p,target_pid=123)
   with self.assertRaises(ValueError):parse_xml(p,target_pid=123,max_rows=501)
 def test_opaque_file_is_never_called_decoded_on_non_windows(self):
  if os.name=='nt':self.skipTest('portable unavailability case')
  r=decode('opaque.etl',target_pid=123);self.assertFalse(r['decoded']);self.assertIsNone(r['lost_events'])
 def test_large_optional_decode_result_cannot_overflow_primary_evidence_or_stop_base(self):
  from blackbox_core.research_worker import ResearchSession
  from blackbox_core.casebook import evidence_page
  with tempfile.TemporaryDirectory() as temp:
   s=ResearchSession(temp);s.command({'op':'attach','args':{'pid':os.getpid()}});s.command({'op':'start'});s.tick()
   try:
    value={'status':'HEADER_EVENTS_DECODED','rows':[{'provider':'SYNTHETIC_CONTRACT_ONLY','event_id':str(i)} for i in range(500)],'supplemental_artifact':'test-only.json'}
    with patch.object(s.jobs,'poll',return_value=[{'command':{'op':'decode_trace'},'result':value,'error':None}]):s.poll_optional()
    self.assertTrue(s.probe.active)
    row=next(r for r in evidence_page(s.probe.session_folder)['rows'] if r['kind']=='trace.decoded')
    self.assertEqual(row['data']['items_omitted_from_evidence_preview'],484);self.assertEqual(len(row['data']['rows']),16)
   finally:s.stop()
if __name__=='__main__':unittest.main()
