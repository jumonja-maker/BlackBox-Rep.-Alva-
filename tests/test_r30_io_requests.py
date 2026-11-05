"""Format/negative-control fixtures; real Windows FileIO acceptance is separate."""
from copy import deepcopy
from contextlib import closing
import hashlib
import gc
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
import weakref
from unittest.mock import patch

from blackbox_core.decoder_cpu import ETW_PROVIDER_GUID
from blackbox_core.decoder_index import PROTOCOL, build_index
from blackbox_core.decoder_io import build_file_io_report, build_disk_io_report, validate_io_observation
from blackbox_core.investigation_v3 import create_investigation, export_investigation, load_investigation


def identity(pid=42, tid=8, instance=2, thread=3, start=0., end=1000.):
    return dict(pid=pid, tid=tid, process_instance=instance, thread_instance=thread,
                start_ms=start, end_ms=end, attribution="TRACELOG_THREAD_LIFETIME")


def token(value, kind="request"):
    return hashlib.sha256(("blackbox.file-io/1:"+kind+":"+format(value,"x")).encode("ascii")).hexdigest() if value else None


def row(ordinal, moment, name, opcode, value, *, thread=None, payload=None):
    thread = deepcopy(thread or identity())
    return dict(type="event", ordinal=ordinal, time_ms=moment,
        pid=thread["pid"], tid=thread["tid"], process_instance=thread["process_instance"],
        provider="Windows Kernel", provider_guid=ETW_PROVIDER_GUID, name=name,
        event_id=65535, opcode=opcode, version=3, payload=payload or {}, frames=[],
        semantic=None, errors=[], io_observation=value)


def file_start(ordinal=1, moment=10., *, request=1, thread=None, operation="create"):
    thread = deepcopy(thread or identity())
    opcode, name = {"create":(64,"Create"),"read":(67,"Read"),"write":(68,"Write")}[operation]
    value = dict(schema="blackbox.trace-io/1", source="ETW_KERNEL_FILE_IO",
        parser="TRACEEVENT_FILE_IO_CREATE" if operation=="create" else "TRACEEVENT_FILE_IO_READ_WRITE",
        kind="file", phase="start", operation=operation, request_key=token(request),
        file_object_key=token(2,"file-object"), file_name=r"C:\private-fixture\locked.bin", name_status="RECORDED",
        requested_bytes=4096 if operation in ("read","write") else None,
        offset=0 if operation in ("read","write") else None, ntstatus=None,
        status_domain="NOT_REPORTED_IN_START_EVENT", event_thread=thread,
        key_basis="HASHED_KERNEL_REQUEST_TOKEN_SCOPED_TO_SOURCE_TRACE", transferred_bytes=None)
    return row(ordinal,moment,"FileIO/"+name,opcode,value,thread=thread,
        payload={"IrpPtr":request,"FileObject":2,"FileName":value["file_name"]})


def file_end(ordinal=2, moment=30., *, request=1, ntstatus=0xC0000043, thread=None):
    thread = deepcopy(thread or identity(pid=4,tid=99,instance=4,thread=5))
    value=dict(schema="blackbox.trace-io/1",source="ETW_KERNEL_FILE_IO",parser="TRACEEVENT_FILE_IO_OP_END",
        kind="file",phase="end",operation="operation_end",request_key=token(request),file_object_key=None,
        file_name=None,name_status="UNAVAILABLE",requested_bytes=None,offset=None,ntstatus=ntstatus,
        status_domain="NTSTATUS",event_thread=thread,key_basis="HASHED_KERNEL_REQUEST_TOKEN_SCOPED_TO_SOURCE_TRACE",
        transferred_bytes=None)
    return row(ordinal,moment,"FileIO/OperationEnd",76,value,thread=thread,
        payload={"IrpPtr":request,"NtStatus":ntstatus if ntstatus < 2**31 else ntstatus-2**32})


def disk_start(ordinal=1,moment=10.,*,request=1,thread=None):
    thread=deepcopy(thread or identity())
    value=dict(schema="blackbox.trace-io/1",source="ETW_KERNEL_DISK_REQUEST",parser="TRACEEVENT_DISK_IO_INIT",
        kind="disk_request",operation="write",request_key=token(request,"disk-request"),event_thread=thread)
    return row(ordinal,moment,"DiskIO/WriteInit",13,value,thread=thread,payload={"Irp":request})


def disk_end(ordinal=2,moment=30.,*,request=1,legacy=False):
    thread=identity(pid=4,tid=99,instance=4,thread=5)
    value=dict(schema="blackbox.trace-io/1",source="ETW_KERNEL_DISK_IO",parser="TRACEEVENT_DISK_IO",
        kind="disk",operation="write",transferred_bytes=4096,elapsed_ms=5.,response_qpc_ticks=5,
        counter_frequency_hz=1000,duration_basis="COMPLETION_EVENT_REPORTED_QPC_DURATION",
        start_boundary_observed=False,device_busy_time_established=False)
    if not legacy:value.update(request_key=token(request,"disk-request"),disk_number=0,event_thread=thread)
    return row(ordinal,moment,"DiskIO/Write",11,value,thread=thread,
        payload={"Irp":request,"TransferSize":4096,"HighResResponseTime":5})


class _IndexFixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.number=0

    def index(self,rows,*,loss=0,status="DECODED"):
        self.number+=1
        source=self.root/f"events-{self.number}.jsonl";target=self.root/f"index-{self.number}.sqlite3"
        records=[dict(type="header",protocol=PROTOCOL,input_sha256="a"*64,trace_counter_frequency_hz=1000),*rows,
            dict(type="footer",protocol=PROTOCOL,status=status,rows=len(rows),decoder_reported_lost_events=loss)]
        source.write_text("".join(json.dumps(value)+"\n" for value in records))
        build_index(source,target,input_sha256="a"*64,format_name=".etl")
        return target

    def assert_unrelated_payload_not_retained(self, build, rows):
        # The source is ordinary valid JSON. Tracking only changes the decoded
        # irrelevant mapping into a weak-referenceable mapping with equal data;
        # production event validation still runs. This tests lifetime, not RSS.
        from blackbox_core.decoder_index import validate_event as real_validate
        class TrackedMapping(dict):
            pass
        rows[0]["payload"]["irrelevant"]={"padding":"x"*(128*1024)}
        path=self.index(rows);refs=[];checked=[];real_loads=json.loads
        def tracked_loads(raw,*args,**kwargs):
            value=real_loads(raw,*args,**kwargs)
            if type(value) is dict and value.get("type")=="event" and value.get("ordinal")==1:
                marker=TrackedMapping(value["payload"]["irrelevant"])
                value["payload"]["irrelevant"]=marker
                refs.append(weakref.ref(marker))
            return value
        def inspect_second(value,ordinal):
            if ordinal==2:
                gc.collect()
                self.assertEqual(len(refs),1)
                self.assertIsNone(refs[0](),"Pending request retained an unrelated event payload")
                checked.append(True)
            return real_validate(value,ordinal)
        # Install plain functions: a MagicMock call history would itself retain
        # the first full row and invalidate this reference-lifetime oracle.
        with patch("json.loads",new=tracked_loads),patch("blackbox_core.decoder_index.validate_event",new=inspect_second):
            result=build(path)
        self.assertEqual(checked,[True])
        self.assertLess(result["coverage"]["pending_metadata_peak_bytes"],16*1024)
        self.assertEqual(result["coverage"]["pending_byte_measurement"],"ENCODED_COMPACT_BOUNDARY_METADATA_NOT_PROCESS_RSS")


class FileIoRequestContracts(_IndexFixture):
    def test_pending_file_request_releases_unrelated_large_source_payload_before_completion(self):
        self.assert_unrelated_payload_not_retained(build_file_io_report,[file_start(),file_end()])

    def test_pending_file_metadata_byte_budget_is_enforced_without_mutating_source(self):
        path=self.index([file_start(),file_end()]);before=path.read_bytes()
        with patch("blackbox_core.decoder_io.MAX_IO_PENDING_METADATA_BYTES",1),self.assertRaisesRegex(ValueError,"METADATA_BYTE_BUDGET"):
            build_file_io_report(path)
        self.assertEqual(path.read_bytes(),before)

    def test_ntstatus_and_request_duration_belong_to_exact_issuer_not_completion_pid(self):
        path=self.index([file_start(),file_end()]);before=hashlib.sha256(path.read_bytes()).hexdigest()
        report=build_file_io_report(path,pid=42,process_instance=2,tid=8)
        operation,=report["operations"]
        self.assertEqual(report["status"],"OBSERVED_OPERATIONS")
        self.assertEqual((operation["pid"],operation["process_instance"],operation["tid"],operation["thread_instance"]),(42,2,8,3))
        self.assertEqual(operation["completion_thread"]["pid"],4)
        self.assertEqual((operation["elapsed_ms"],operation["ntstatus"],operation["status_name"]),(20.,0xC0000043,"STATUS_SHARING_VIOLATION"))
        self.assertIsNone(operation["win32_error"])
        self.assertEqual(operation["source_event_ids"],[1,2])
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),before)

    def test_access_denied_raw_status_is_not_silently_relabelled_as_win32_five(self):
        operation,=build_file_io_report(self.index([file_start(),file_end(ntstatus=0xC0000022)]))["operations"]
        self.assertEqual(operation["status_name"],"STATUS_ACCESS_DENIED")
        self.assertEqual(operation["ntstatus"],0xC0000022)
        self.assertIsNone(operation["win32_error"])

    def test_pointer_reuse_after_complete_request_creates_distinct_operation_ids(self):
        rows=[file_start(),file_end(),file_start(3,40.),file_end(4,50.,ntstatus=0)]
        result=build_file_io_report(self.index(rows))["operations"]
        self.assertEqual(len(result),2)
        self.assertNotEqual(result[0]["operation_id"],result[1]["operation_id"])
        self.assertEqual([value["ntstatus"] for value in result],[0xC0000043,0])

    def test_duplicate_start_without_boundary_withholds_status_and_duration(self):
        rows=[file_start(),file_start(2,20.,thread=identity(instance=99,thread=7)),file_end(3,30.)]
        report=build_file_io_report(self.index(rows))
        self.assertEqual(report["status"],"PARTIAL_EVIDENCE")
        self.assertEqual(report["coverage"]["duplicate_request_starts"],1)
        self.assertTrue(all(value["elapsed_ms"] is None and value["ntstatus"] is None for value in report["operations"]))

    def test_pid_reuse_does_not_transfer_a_request_to_the_new_trace_process_instance(self):
        end=file_end(thread=identity(pid=42,tid=8,instance=99,thread=100,start=20.))
        path=self.index([file_start(),end])
        self.assertEqual(build_file_io_report(path,pid=42,process_instance=99)["operations"],[])
        operation,=build_file_io_report(path,pid=42,process_instance=2)["operations"]
        self.assertEqual(operation["process_instance"],2)

    def test_loss_unknown_truncation_and_positive_loss_do_not_prove_error_attribution(self):
        for loss,status in ((None,"DECODED"),(4,"DECODED"),(0,"TRUNCATED")):
            with self.subTest(loss=loss,status=status):
                report=build_file_io_report(self.index([file_start(),file_end()],loss=loss,status=status))
                operation,=report["operations"]
                self.assertEqual(report["status"],"PARTIAL_EVIDENCE")
                self.assertIsNone(operation["elapsed_ms"]);self.assertIsNone(operation["ntstatus"])
                self.assertEqual(operation["observed_completion_ntstatus"],0xC0000043)
                self.assertEqual(operation["status_attribution"],"NOT_ESTABLISHED")

    def test_unknown_issuing_lifetime_never_uses_pid_tid_as_exact_identity(self):
        thread=identity();thread.update(process_instance=None,thread_instance=None,start_ms=None,end_ms=None,attribution="UNRESOLVED_THREAD")
        operation,=build_file_io_report(self.index([file_start(thread=thread),file_end()]))["operations"]
        self.assertIsNone(operation["process_instance"]);self.assertIsNone(operation["elapsed_ms"])
        self.assertEqual(operation["quality"],"UNRESOLVED_ISSUING_THREAD")

    def test_missing_completion_is_visible_censored_and_not_success(self):
        report=build_file_io_report(self.index([file_start()]))
        operation,=report["operations"]
        self.assertEqual(report["coverage"]["right_censored_requests"],1)
        self.assertEqual(operation["quality"],"RIGHT_CENSORED_REQUEST")
        self.assertIsNone(operation["ntstatus"]);self.assertIsNone(operation["elapsed_ms"])

    def test_unmatched_completion_is_not_attributed_to_header_process(self):
        report=build_file_io_report(self.index([file_end(1)]),pid=4)
        self.assertEqual(report["operations"],[])
        self.assertEqual(report["coverage"]["unmatched_completions"],1)

    def test_order_reversal_invalidates_earlier_emitted_intervals(self):
        rows=[file_start(),file_end(),file_start(3,5.,request=2)]
        report=build_file_io_report(self.index(rows))
        self.assertEqual(report["coverage"]["out_of_order_events"],1)
        self.assertTrue(all(value["elapsed_ms"] is None and value["ntstatus"] is None for value in report["operations"]))

    def test_legacy_file_rows_require_redecode_not_payload_name_inference(self):
        start=file_start();end=file_end()
        del start["io_observation"];del end["io_observation"]
        report=build_file_io_report(self.index([start,end]))
        self.assertEqual(report["status"],"REDECODE_REQUIRED");self.assertEqual(report["operations"],[])

    def test_clipped_window_and_result_budget_remain_explicit(self):
        path=self.index([file_start(),file_end(),file_start(3,40.,request=2),file_end(4,50.,request=2)])
        clipped=build_file_io_report(path,start_ms=15.,end_ms=25.)["operations"][0]
        self.assertEqual((clipped["start_ms"],clipped["end_ms"]),(15.,25.))
        self.assertIsNone(clipped["elapsed_ms"])
        limited=build_file_io_report(path,max_operations=1)
        self.assertEqual(len(limited["operations"]),1);self.assertEqual(limited["coverage"]["operations_omitted_budget"],1)

    def test_wrong_parser_header_pointer_or_status_is_rejected(self):
        for field,value in (("parser","TRACEEVENT_DISK_IO"),("request_key","b"*64),("phase","end"),("requested_bytes",True)):
            item=file_start();item["io_observation"][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):validate_io_observation(item)
        item=file_end();item["io_observation"]["ntstatus"]=5
        with self.assertRaises(ValueError):validate_io_observation(item)

    def test_cancel_and_deadline_do_not_mutate_index(self):
        path=self.index([file_start(),file_end()]);before=path.read_bytes()
        stop=threading.Event();stop.set()
        with self.assertRaises(InterruptedError):build_file_io_report(path,cancel=stop)
        with patch("time.monotonic",side_effect=[0.,100.]),self.assertRaises(TimeoutError):build_file_io_report(path)
        self.assertEqual(path.read_bytes(),before)

    def test_investigation_graph_delay_export_and_independent_readback_preserve_source(self):
        path=self.index([file_start(),file_end()]);before=path.read_bytes()
        destination=self.root/"investigation.sqlite3"
        case=create_investigation([{"source_type":"TRACE_INDEX","path":str(path),"selection":{"pid":42,"process_instance":2}}],index_path=destination)
        paired=[n for n in case["nodes"] if n["metadata"].get("file_io_pair")]
        self.assertEqual(len(paired),1);self.assertEqual(paired[0]["thread_identity"]["thread_instance"],3)
        findings=[f for f in case["delay_investigation"]["findings"] if f["category"]=="FILE_IO_ERROR"]
        self.assertEqual(len(findings),1);self.assertEqual(findings[0]["details"]["ntstatus"],0xC0000043)
        self.assertIn(paired[0]["node_id"],findings[0]["source_nodes"])
        target=self.root/"report.json";web=self.root/"report.html"
        export_investigation(case,target);export_investigation(case,web,format="html")
        saved=json.loads(target.read_text())
        self.assertEqual(saved["delay_investigation"]["root_cause"],"UNKNOWN")
        self.assertNotIn("private-fixture",target.read_text())
        self.assertIn("Delays and I/O",web.read_text())
        reread=load_investigation(destination)
        self.assertEqual([f["finding_id"] for f in reread["delay_investigation"]["findings"]],
                         [f["finding_id"] for f in case["delay_investigation"]["findings"]])
        with self.assertRaises(FileExistsError):export_investigation(case,target)
        self.assertEqual(path.read_bytes(),before)


class DiskIoRequestContracts(_IndexFixture):
    def test_unknown_header_pid_without_instance_preserves_separate_typed_completion_lifetime(self):
        end=disk_end()
        end["pid"]=-1
        end["process_instance"]=None
        validate_io_observation(end)
        report=build_disk_io_report(self.index([disk_start(),end]),pid=42,process_instance=2)
        operation,=report["requests"]
        self.assertEqual(report["status"],"OBSERVED_REQUESTS")
        self.assertEqual((operation["pid"],operation["process_instance"],operation["tid"]),(42,2,8))
        self.assertEqual(operation["elapsed_ms"],20.)
        self.assertEqual((operation["completion_thread"]["pid"],operation["completion_thread"]["process_instance"]),(4,4))
        self.assertEqual(end["io_observation"]["event_thread"]["pid"],4)
        self.assertEqual(end["pid"],-1)
        self.assertIsNone(end["process_instance"])

    def test_indexed_unknown_header_process_cannot_replace_known_thread_process_instance(self):
        end=disk_end(1)
        end["pid"]=-1
        end["process_instance"]=2
        with self.assertRaisesRegex(ValueError,"DISK_EVENT_THREAD_CONFLICT"):
            validate_io_observation(end)

    def test_identity_conflict_reports_only_bounded_numeric_identity_metadata(self):
        for row_field in ("pid", "tid", "process_instance"):
            with self.subTest(row_field=row_field):
                item=disk_end(1)
                item[row_field]+=1
                item["source_index"]="7"
                item["payload"]["secret"]="DO_NOT_REPORT_PAYLOAD"
                with self.assertRaisesRegex(ValueError,"DISK_EVENT_THREAD_CONFLICT") as raised:
                    validate_io_observation(item)
                message=str(raised.exception)
                self.assertIn("role=COMPLETION_EVENT_HEADER",message)
                self.assertIn("source_index=7",message)
                self.assertIn("typed_tid=99",message)
                self.assertNotIn("DO_NOT_REPORT_PAYLOAD",message)
                self.assertNotIn("Irp",message)
                self.assertLess(len(message),700)

    def test_identity_diagnostics_do_not_echo_arbitrary_source_index_text(self):
        item=disk_start()
        item["process_instance"]+=1
        item["source_index"]="PRIVATE"*10000
        with self.assertRaisesRegex(ValueError,"DISK_EVENT_THREAD_CONFLICT") as raised:
            validate_io_observation(item)
        message=str(raised.exception)
        self.assertIn("role=REQUEST_INIT_EVENT_HEADER",message)
        self.assertIn("source_index=UNAVAILABLE",message)
        self.assertNotIn("PRIVATE",message)
        self.assertLess(len(message),700)

    def test_pending_disk_request_releases_unrelated_large_source_payload_before_completion(self):
        self.assert_unrelated_payload_not_retained(build_disk_io_report,[disk_start(),disk_end()])

    def test_pending_disk_metadata_byte_budget_is_enforced_without_mutating_source(self):
        path=self.index([disk_start(),disk_end()]);before=path.read_bytes()
        with patch("blackbox_core.decoder_io.MAX_IO_PENDING_METADATA_BYTES",1),self.assertRaisesRegex(ValueError,"METADATA_BYTE_BUDGET"):
            build_disk_io_report(path)
        self.assertEqual(path.read_bytes(),before)

    def test_disk_request_span_and_reported_counter_are_separate_without_invented_queue_split(self):
        result=build_disk_io_report(self.index([disk_start(),disk_end()]),pid=42)
        operation,=result["requests"]
        self.assertEqual(result["status"],"OBSERVED_REQUESTS")
        self.assertEqual((operation["elapsed_ms"],operation["reported_response_ms"]),(20.,5.))
        self.assertEqual(operation["process_instance"],2)
        self.assertIsNone(operation["queue_delay_ms"]);self.assertIsNone(operation["device_service_ms"])

    def test_observed_request_concurrency_is_a_filtered_lower_bound_not_hardware_queue_depth(self):
        rows=[disk_start(),disk_start(2,15.,request=2),disk_end(3,30.),disk_end(4,35.,request=2)]
        report=build_disk_io_report(self.index(rows))
        self.assertEqual([r["observed_outstanding_requests_at_start_lower_bound"] for r in report["requests"]],[0,1])
        self.assertTrue(all(r["outstanding_count_scope"]=="MATCHED_FILTERED_REQUESTS_NOT_HARDWARE_QUEUE_DEPTH" for r in report["requests"]))

    def test_legacy_completion_does_not_acquire_a_fabricated_start(self):
        result=build_disk_io_report(self.index([disk_end(1,legacy=True)]))
        self.assertEqual(result["requests"],[])
        self.assertEqual(result["coverage"]["legacy_completion_only_events"],1)

    def test_disk_loss_or_duplicate_request_withholds_span_and_concurrency(self):
        for rows,loss in (([disk_start(),disk_end()],2),
                          ([disk_start(),disk_start(2,15.),disk_end(3,30.)],0)):
            report=build_disk_io_report(self.index(rows,loss=loss))
            self.assertEqual(report["status"],"PARTIAL_EVIDENCE")
            self.assertTrue(all(r["elapsed_ms"] is None and r["observed_outstanding_requests_at_start_lower_bound"] is None for r in report["requests"]))

    def test_disk_source_frequency_mismatch_is_refused(self):
        path=self.index([disk_start(),disk_end()])
        with closing(sqlite3.connect(path)) as db:
            metadata=json.loads(db.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
            metadata["engine"]["trace_counter_frequency_hz"]=2000
            db.execute("UPDATE metadata SET value=? WHERE key='summary'",(json.dumps(metadata),))
            db.commit()
        with self.assertRaisesRegex(ValueError,"FREQUENCY_MISMATCH"):build_disk_io_report(path)
