"""Delay interpretation format controls, distinct from hosted native fixtures."""
from copy import deepcopy
import threading
import unittest

from blackbox_core.critical_path import analyze_critical_path
from blackbox_core.delay_investigation import analyze_delay, validate_delay_report, render_delay_html
from blackbox_core.evidence_graph import build_graph, validate_case
from blackbox_core.hypothesis_engine import generate_hypotheses
from blackbox_core.investigation_graph_contracts import InvestigationError, InvestigationBudget, evidence_node


TRACE="a"*64
PROCESS={"kind":"TRACE_PROCESS","trace_sha256":TRACE,"pid":42,"process_instance":2}
THREAD={**PROCESS,"kind":"TRACE_THREAD","tid":8,"thread_instance":3}


def source(*,loss=0,kind="TRACE_INDEX"):
    value=dict(source_id="source",source_type=kind,source_sha256="b"*64)
    if kind=="TRACE_INDEX":value.update(trace_input_sha256=TRACE,decoded_status="DECODED",
        decoder_reported_lost_events=loss,scan_complete=True,out_of_order_events=False,
        event_sequence_gaps=0,scheduler_complete=False)
    return value


def node(record,kind,metadata,*,src=None,start=10.,end=30.,process=PROCESS,thread=THREAD,unit="ms",domain=None):
    return evidence_node(src or source(),record,kind,metadata=metadata,process_identity=process,
        thread_identity=thread,time_domain=domain or "TRACE_RELATIVE:"+TRACE,
        time_bounds={"start":start,"end":end,"unit":unit,"uncertainty":None})


def case(*nodes,src=None,coverage=None):
    value=build_graph({"sources":[src or source(kind=nodes[0]["source_type"] if nodes else "TRACE_INDEX")],"nodes":list(nodes),"coverage":coverage or {},"limitations":[]})
    value["critical_path"]=analyze_critical_path(value)
    return value


def wait(record="wait",**changes):
    metadata=dict(quality="OBSERVED_SWITCH_PAIR",off_cpu_ms=20.,blocked_ms=10.,ready_delay_ms=10.,
        source_event_ids=[1,2,3],ready_time_ms=20.,waker_thread={"pid":999,"tid":888},waker_is_lock_owner="NOT_ESTABLISHED")
    metadata.update(changes)
    return node(record,"WAIT_INTERVAL",metadata)


def snapshot(*,lock_type=3,owned=6,status="OK",truncated=False):
    return dict(operation="wait_chains",source="WIN32_WCT",status=status,truncated=truncated,cycle_reported=False,nodes=[
        {"object_type":8,"object_status":3,"pid":42,"tid":8},
        {"object_type":lock_type,"object_status":owned},
        {"object_type":8,"object_status":3,"pid":42,"tid":9}])


def wct_node(**changes):
    process={"kind":"LIVE_PROCESS","pid":42,"created_100ns":133000000000000000}
    thread={**process,"kind":"LIVE_THREAD","tid":8,"thread_created_100ns":133000000000001000}
    return node("wct","WAIT_INTERVAL",snapshot(**changes),src=source(kind="DEEP_JOURNAL"),
        process=process,thread=thread,start=10,end=10,unit="ns",domain="NATIVE_CAPTURE:source")


class DelayInvestigationContracts(unittest.TestCase):
    def test_scheduler_blocked_and_ready_keep_source_nodes_and_never_assign_waker_as_owner(self):
        value=case(wait());report=analyze_delay(value)
        self.assertEqual({r["category"] for r in report["findings"]},{"SCHEDULER_WAIT","READY_DELAY"})
        for finding in report["findings"]:
            self.assertEqual(finding["details"]["lock_owner"],"NOT_ESTABLISHED")
            self.assertEqual(finding["source_nodes"],[value["nodes"][0]["node_id"]])
            self.assertFalse(finding["root_cause_proven"])
            self.assertEqual(finding["source_authenticity"],"UNVERIFIED_IMPORT")
        self.assertEqual(report["root_cause"],"UNKNOWN")

    def test_lost_trace_cannot_reuse_cached_exact_duration_or_ready_split(self):
        src=source(loss=3);value=case(wait(),src=src)
        # Raw cached metadata still claims a pair; the source's explicit loss wins.
        report=analyze_delay(value)
        self.assertEqual(report["status"],"PARTIAL_EVIDENCE")
        self.assertEqual([r["category"] for r in report["findings"]],["SCHEDULER_WAIT"])
        self.assertIsNone(report["findings"][0]["details"]["off_cpu_ms"])

    def test_missing_ready_boundary_preserves_offcpu_but_does_not_invent_blocked_time(self):
        report=analyze_delay(case(wait(blocked_ms=None,ready_delay_ms=None)))
        finding,=report["findings"]
        self.assertEqual(finding["details"]["off_cpu_ms"],20.)
        self.assertIsNone(finding["details"]["blocked_ms"]);self.assertIsNone(finding["details"]["ready_delay_ms"])

    def test_contradictory_overlapping_scheduler_intervals_do_not_display_numeric_success(self):
        second=wait("overlap")
        second["time_bounds"].update(start=15.,end=35.)
        report=analyze_delay(case(wait(),second))
        waits=[r for r in report["findings"] if r["category"]=="SCHEDULER_WAIT"]
        self.assertTrue(all(r["status"]=="INCOMPLETE_EVIDENCE" and r["details"]["off_cpu_ms"] is None for r in waits))

    def test_windows_wct_owned_mutex_edge_reports_snapshot_owner_without_exact_lifetime(self):
        value=case(wct_node())
        report=analyze_delay(value);finding,=report["findings"]
        self.assertEqual(finding["category"],"WCT_CHAIN")
        owner,=finding["details"]["reported_owners"]
        self.assertEqual((owner["pid"],owner["tid"]),(42,9))
        self.assertFalse(owner["exact_instance"])
        self.assertEqual(owner["scope"],"THIS_WINDOWS_WCT_SNAPSHOT_ONLY")
        self.assertEqual(finding["details"]["persistent_owner"],"NOT_ESTABLISHED")
        self.assertIsNone(finding["details"]["wait_duration_ms"])

    def test_sendmessage_recipient_unowned_object_and_incomplete_wct_do_not_become_lock_owner(self):
        for changes in ({"lock_type":2},{"owned":7},{"status":"ACCESS_DENIED"},{"truncated":True}):
            with self.subTest(changes=changes):
                finding,=analyze_delay(case(wct_node(**changes)))["findings"]
                self.assertEqual(finding["details"]["reported_owners"],[])
                self.assertEqual(finding["details"]["lock_owner_status"],"NOT_ESTABLISHED")

    def test_actual_native_ui_observation_code_is_visible_and_generates_existing_hypothesis(self):
        n=node("ui","ANNOTATION",{"code":"UI_UNRESPONSIVE_OBSERVED","fields":{
            "window":{"pid":42,"tid":8,"hwnd":123},"consecutive_timeouts":2,
            "check":{"status":"SENSOR_TIMEOUT"},"onset_exact":False}})
        value=case(n);finding,=analyze_delay(value)["findings"]
        self.assertEqual(finding["category"],"UI_FREEZE")
        self.assertIsNone(finding["details"]["continuous_freeze_duration_ms"])
        self.assertEqual(finding["details"]["window"]["tid"],8)
        self.assertTrue(any(h["category"]=="UI_UNRESPONSIVE" for h in generate_hypotheses(value)))

    def test_network_packet_metadata_does_not_establish_failure_or_root_cause(self):
        finding,=analyze_delay(case(node("net","NETWORK_OPERATION",{"io_observation":{
            "kind":"network","protocol":"TCP","operation":"send","transferred_bytes":512,
            "source_address":"127.0.0.1","destination_address":"127.0.0.1"}})))["findings"]
        self.assertEqual(finding["details"]["packet_contents"],"NOT_COLLECTED")
        self.assertEqual(finding["details"]["network_cause_of_delay"],"NOT_ESTABLISHED")

    def test_generic_error_code_without_win32_provenance_is_not_converted_to_win32(self):
        finding,=analyze_delay(case(node("file","FILE_OPERATION",{"status":"ERROR","error_code":5,
            "error_code_basis":"RECORDED_SOURCE_STATEMENT_NOT_ETW_INFERENCE"})))["findings"]
        self.assertEqual(finding["category"],"FILE_IO_ERROR")
        self.assertIsNone(finding["details"]["win32_error"])
        self.assertEqual(finding["details"]["error_code"],5)

    def test_error_priority_is_bounded_without_silently_hiding_omission(self):
        nodes=[node("net:"+str(i),"NETWORK_OPERATION",{}) for i in range(10)]
        error=node("file","FILE_OPERATION",{"win32_code":32,"status":"ERROR"})
        report=analyze_delay(case(*nodes,error),max_findings=1)
        self.assertEqual(report["findings"][0]["category"],"FILE_IO_ERROR")
        self.assertEqual(report["coverage"]["findings_omitted_budget"],10)
        self.assertEqual(report["status"],"PARTIAL_EVIDENCE")

    def test_imported_owner_cause_identity_and_dangling_refs_are_rejected(self):
        value=case(wct_node());report=analyze_delay(value)
        indexed={n["node_id"]:n for n in value["nodes"]}
        bad=deepcopy(report);bad["findings"][0]["details"]["reported_owners"][0]["pid"]=999
        with self.assertRaisesRegex(InvestigationError,"LOCK_OWNER"):validate_delay_report(bad,nodes=indexed)
        bad=deepcopy(report);bad["root_cause_proven"]=True
        with self.assertRaises(InvestigationError):validate_delay_report(bad,nodes=indexed)
        bad=deepcopy(report);bad["findings"][0]["source_nodes"]=["nonexistent"]
        with self.assertRaises(InvestigationError):validate_delay_report(bad,nodes=indexed)
        bad=deepcopy(report);bad["findings"][0]["process_identity"]={**PROCESS,"process_instance":99}
        with self.assertRaisesRegex(InvestigationError,"BINDING"):validate_delay_report(bad,nodes=indexed)
        bad=deepcopy(report);bad["findings"][0]["critical_path_segments"]=["missing-segment"]
        with self.assertRaisesRegex(InvestigationError,"CRITICAL_PATH"):validate_delay_report(bad,nodes=indexed,critical_segments=set())
        value["delay_investigation"]=deepcopy(report);value["delay_investigation"]["root_cause"]="PROVEN"
        with self.assertRaises(InvestigationError):validate_case(value)

    def test_arbitrary_trace_or_application_wct_shaped_payload_is_not_windows_ownership_proof(self):
        forged=node("fake","ANNOTATION",{"code":"WCT_SNAPSHOT","wct":snapshot()})
        self.assertEqual(analyze_delay(case(forged))["findings"],[])

    def test_html_descriptions_are_escaped_and_not_executable(self):
        report=analyze_delay(case(node("ui","ANNOTATION",{"code":"UI_TIMEOUT"})))
        report["findings"][0]["description"]="<script>alert(1)</script>"
        output=render_delay_html(report)
        self.assertIn("&lt;script&gt;",output);self.assertNotIn("<script>",output)

    def test_cancelled_projection_returns_no_model(self):
        stop=threading.Event();stop.set()
        with self.assertRaises(InterruptedError):analyze_delay(case(wait()),budget=InvestigationBudget(cancel_event=stop))
