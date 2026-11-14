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
 def test_xml_node_depth_and_deadline_limits_do_not_depend_on_event_headers(self):
  with tempfile.TemporaryDirectory() as temp:
   p=Path(temp)/'TEST_ONLY_NON_EVENT_XML.xml'
   p.write_text('<Noise>'+('<Unused/>'*10000)+'</Noise>')
   with patch('blackbox_core.trace_decode.MAX_XML_NODES',256):
    with self.assertRaisesRegex(ValueError,'XML_NODE_BUDGET'):parse_xml(p,target_pid=123)
   p.write_text('<Noise>'*65+'</Noise>'*65)
   with self.assertRaisesRegex(ValueError,'XML_DEPTH_BUDGET'):parse_xml(p,target_pid=123)
   p.write_text('<Noise>'+('<Unused/>'*20)+'</Noise>')
   calls=[]
   def clock():
    calls.append(None)
    return 0 if len(calls)<5 else 11
   with patch('blackbox_core.trace_decode.time.monotonic',side_effect=clock):
    with self.assertRaisesRegex(TimeoutError,'PARSE_TIMEOUT'):parse_xml(p,target_pid=123)
 def test_irrelevant_xml_and_event_payload_do_not_remove_actual_system_headers(self):
  with tempfile.TemporaryDirectory() as temp:
   p=Path(temp)/'TEST_ONLY_MIXED_XML.xml'
   p.write_text('<Events>'+('<Unused><Child/></Unused>'*500)+xml(123)+
    ('<Unused/>'*500)+xml(456)+xml(123)+'</Events>')
   result=parse_xml(p,target_pid=123,max_rows=1)
   self.assertEqual(result['scanned_events'],3)
   self.assertEqual(result['recognized_header_events'],3)
   self.assertEqual(result['matching_emitter_events'],2)
   self.assertEqual(result['rows_omitted'],1)
   self.assertEqual(result['rows'][0]['event_id'],'1000')
   self.assertEqual(result['rows'][0]['thread_id'],'5')
   self.assertNotIn('PRIVATE_PATH',json.dumps(result))
 def test_unconfirmed_tracerpt_close_retains_staging_until_explicit_owner_cleanup(self):
  from types import SimpleNamespace
  from blackbox_core.optional_jobs import OwnedProcessCleanupUnconfirmed
  class RetainedOwner:
   def __init__(self):
    self.process=SimpleNamespace(returncode=0,poll=lambda:0)
    self.cleanup_required=False;self.resources=[];self.allow_cleanup=False
   def close(self,*,kill):
    if self.allow_cleanup:
     for resource in self.resources:resource.cleanup()
     self.cleanup_required=False
     return
    self.cleanup_required=True
    raise OwnedProcessCleanupUnconfirmed(self,'TEST_ONLY_STOP_UNCONFIRMED')
   def retain_cleanup_resource(self,resource):self.resources.append(resource)
  owner=RetainedOwner()
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);source=root/'TEST_ONLY_INPUT.etl';source.write_bytes(b'TEST_ONLY_NOT_REAL_ETL')
   tool=root/'System32'/'tracerpt.exe';tool.parent.mkdir();tool.write_bytes(b'TEST_ONLY_NOT_EXECUTABLE')
   def launch(command,**unused):
    Path(command[3]).write_text('<Events>'+xml(123)+'</Events>')
    return owner
   try:
    with patch('blackbox_core.trace_decode.os',SimpleNamespace(name='nt',environ={'SystemRoot':str(root)})),\
     patch('blackbox_core.trace_decode.OwnedProcess',side_effect=launch):
     with self.assertRaisesRegex(OwnedProcessCleanupUnconfirmed,'TEST_ONLY_STOP_UNCONFIRMED'):
      decode(source,target_pid=123)
    self.assertEqual(len(owner.resources),1)
    stage=Path(owner.resources[0].name)
    self.assertTrue((stage/'events.xml').is_file())
    self.assertTrue((stage/'tool.log').is_file())
    self.assertEqual(source.read_bytes(),b'TEST_ONLY_NOT_REAL_ETL')
   finally:
    owner.allow_cleanup=True;owner.close(kill=True)
   self.assertFalse(stage.exists())
   self.assertFalse(owner.cleanup_required)
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
