"""R40 format/negative contracts; actual native crash/unwind has a separate CI fixture."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from blackbox_core.crash_events import parse_event, parse_wer_candidate, query
from blackbox_core.deep_dump import inspect_dump, unwind_dump
from blackbox_core.crash_investigation import project_crash_evidence, validate_crash_report
from blackbox_core.investigation_graph_contracts import InvestigationError
from blackbox_core.investigation_v3 import create_investigation, export_investigation, load_investigation
from blackbox_core.evidence_graph import validate_case
from blackbox_core.investigation_graph_contracts import canonical_json
from blackbox_core.deep_contracts import ActionRequest, ProcessIdentity
from blackbox_core.deep_service import InspectorService
from test_deep_dump import dump_bytes


def crash_dump(*, exception_code=0xC0000005, thread_flags=0, context_size=256):
    """Synthetic MDMP fields, deliberately different thread/exception contexts."""
    data = dump_bytes(unused_streams=3)
    context = bytearray(context_size)
    if context_size >= 256:
        struct.pack_into("<I", context, 48, 0x100001)
        struct.pack_into("<Q", context, 248, 0x140000124)
        struct.pack_into("<Q", context, 152, 0x70000080)
        struct.pack_into("<Q", context, 160, 0x700000A0)
    context_rva = len(data)
    data.extend(context)
    exception = bytearray(168)
    struct.pack_into("<I", exception, 0, 77)
    struct.pack_into("<IIQQII", exception, 8, exception_code, 0, 0, 0x140000124, 0, 0)
    struct.pack_into("<II", exception, 160, len(context), context_rva)
    offset = len(data)
    data.extend(exception)
    struct.pack_into("<III", data, 32 + 5 * 12, 6, len(exception), offset)
    thread_info = struct.pack("<III", 12, 64, 1) + struct.pack(
        "<IIIIQQQQQQ", 77, thread_flags, 0, 0, 134382769877915962, 0, 1, 1, 0x140000100, 1)
    offset = len(data)
    data.extend(thread_info)
    struct.pack_into("<III", data, 32 + 6 * 12, 17, len(thread_info), offset)
    return data


def event_xml(*, birth="0x1dc4c918af3c41a", pid=123, logger=567):
    return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><Provider Name="Application Error"/><EventID>1000</EventID>'
        '<TimeCreated SystemTime="2026-11-04T14:00:00Z"/>'
        f'<Execution ProcessID="{logger}"/><EventRecordID>42</EventRecordID></System>'
        f'<EventData><Data Name="ProcessId">{pid}</Data>'
        f'<Data Name="ProcessCreationTime">{birth}</Data>'
        '<Data Name="AppName">C:\\private-user\\probe.exe</Data>'
        '<Data Name="AppVersion">1.2.3.4</Data>'
        '<Data Name="ModuleName">C:\\private-user\\fault.dll</Data>'
        '<Data Name="ModuleVersion">1.2.0.0</Data>'
        '<Data Name="ExceptionCode">c0000005</Data>'
        '<Data Name="FaultingOffset">0000000000000124</Data>'
        '<Data Name="UnrelatedSecret">NEVER_EXPORT_THIS_PAYLOAD</Data>'
        '</EventData></Event>')


class R40DumpContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "fixture.dmp"

    def test_exception_hash_exact_saved_thread_time_and_private_payload(self):
        raw = crash_dump()
        self.path.write_bytes(raw)
        answer = inspect_dump(self.path)
        value = answer["data"]
        self.assertEqual(value["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(value["source_id"], "sha256:" + value["sha256"])
        self.assertEqual(value["source_size_bytes"], len(raw))
        self.assertEqual(value["verification_class"], "UNVERIFIED_IMPORT")
        self.assertEqual(value["exception"]["code"], 0xC0000005)
        self.assertEqual(value["exception"]["tid"], 77)
        thread = value["threads"][0]
        self.assertEqual(thread["recorded_creation_100ns"], 134382769877915962)
        self.assertEqual(thread["context"]["rip"], 0x140000124)
        self.assertEqual(thread["context_source"], "SAVED_EXCEPTION_CONTEXT")
        self.assertEqual(thread["frames"][0]["method"], "CAPTURED_CONTROL_CONTEXT_PC_ONLY")
        self.assertFalse(thread["frames"][0]["unwind_confirmed"])
        self.assertEqual(value["live_process_binding"], "NOT_ESTABLISHED")
        self.assertNotIn("deadbeef", json.dumps(answer))
        self.assertEqual(self.path.read_bytes(), raw)

    def test_normal_dump_is_not_promoted_to_recorded_crash(self):
        self.path.write_bytes(dump_bytes())
        data = inspect_dump(self.path)["data"]
        self.assertIsNone(data["exception"])
        self.assertIsNone(data["threads"][0]["recorded_creation_100ns"])
        self.assertEqual(data["threads"][0]["context_source"], "SAVED_THREAD_CONTEXT")

    def test_thread_info_invalid_flag_does_not_attest_creation(self):
        self.path.write_bytes(crash_dump(thread_flags=8))
        self.assertIsNone(inspect_dump(self.path)["data"]["threads"][0]["recorded_creation_100ns"])

    def test_corrupt_exception_and_thread_info_fail_closed(self):
        raw = crash_dump()
        offset, = struct.unpack_from("<I", raw, 32 + 5 * 12 + 8)
        struct.pack_into("<I", raw, offset + 32, 16)
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "EXCEPTION"):
            inspect_dump(self.path)
        raw = crash_dump()
        offset, = struct.unpack_from("<I", raw, 32 + 6 * 12 + 8)
        struct.pack_into("<I", raw, offset + 4, 2**32 - 1)
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "THREAD_INFO"):
            inspect_dump(self.path)

    def test_cancel_deadline_and_invalid_unwind_options_do_not_mutate(self):
        raw = crash_dump()
        self.path.write_bytes(raw)
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(InterruptedError):
            inspect_dump(self.path, cancel_event=cancel)
        with self.assertRaises(TimeoutError):
            inspect_dump(self.path, deadline=time.monotonic() - 1)
        with self.assertRaisesRegex(ValueError, "LOCAL_IMAGE"):
            inspect_dump(self.path, pdb_path="untrusted.pdb")
        with self.assertRaisesRegex(ValueError, "FRAME_BUDGET"):
            inspect_dump(self.path, image_path="untrusted.exe", max_frames=129)
        self.assertEqual(self.path.read_bytes(), raw)

    @unittest.skipIf(os.name == "nt", "Non-Windows refusal is not native unwind evidence")
    def test_nonwindows_unwind_never_simulates_dbghelp_success(self):
        self.path.write_bytes(crash_dump())
        answer = unwind_dump(self.path, "not-loaded.exe")
        self.assertEqual(answer["status"], "UNSUPPORTED_PLATFORM")
        self.assertEqual(answer["data"]["frames"], [])

    @unittest.skipUnless(os.name == "nt", "Actual Windows local-image identity refusal")
    def test_unmatched_local_image_cannot_supply_dump_unwind_metadata(self):
        raw = crash_dump()
        self.path.write_bytes(raw)
        with self.assertRaises(ValueError):
            unwind_dump(self.path, sys.executable)
        self.assertEqual(self.path.read_bytes(), raw)

    def test_metadata_and_unwind_cannot_silently_come_from_different_dumps(self):
        raw = crash_dump()
        self.path.write_bytes(raw)
        # Fault injection only, not native success: another pass reports B.
        foreign = {"status": "INCOMPLETE_EVIDENCE", "data": {
            "source_sha256": "b" * 64, "source_id": "sha256:" + "b" * 64, "threads": []}}
        with patch("blackbox_core.deep_dump.unwind_dump", return_value=foreign):
            with self.assertRaisesRegex(ValueError, "BETWEEN_METADATA_AND_UNWIND"):
                inspect_dump(self.path, image_path="explicit-own-image.exe")
        self.assertEqual(self.path.read_bytes(), raw)

    def test_existing_investigation_dump_route_export_readback_preserves_metadata_only(self):
        raw = crash_dump()
        self.path.write_bytes(raw)
        case = create_investigation([{"source_type": "DUMP_METADATA", "path": str(self.path)}],
                                    index_path=self.root / "case.sqlite3")
        projected = project_crash_evidence(case)
        self.assertEqual(case["crash_investigation"], projected)
        self.assertEqual(projected["summary"]["saved_dumps"], 1)
        self.assertEqual(projected["summary"]["recorded_exceptions"], 1)
        self.assertEqual(projected["summary"]["unwound_callers"], 0)
        self.assertEqual(projected["root_cause"], "UNKNOWN")
        self.assertFalse(projected["privacy"]["memory_contents_included"])
        self.assertEqual(projected["modules"][0]["name"], "native-probe.exe")
        for format in ("json", "html"):
            destination = self.root / ("report." + format)
            export_investigation(case, destination, format=format)
            if format == "json":
                loaded = json.loads(destination.read_text())
                validate_case(loaded)
                self.assertEqual(loaded["crash_investigation"]["summary"], projected["summary"])
                self.assertEqual(project_crash_evidence(loaded)["summary"], projected["summary"])
            data = destination.read_text()
            if format == "html":
                self.assertIn("Crash evidence / Сведения об аварии", data)
            self.assertNotIn("private-user", data)
            self.assertNotIn("deadbeef", data)
            with self.assertRaises(FileExistsError):
                export_investigation(case, destination, format=format)
        self.assertEqual(self.path.read_bytes(), raw)
        self.assertEqual(project_crash_evidence(load_investigation(self.root / "case.sqlite3"))["summary"],
                         projected["summary"])

    def test_explicit_pe_pdb_roles_and_native_cleanup_are_in_the_real_creation_receipt(self):
        self.path.write_bytes(crash_dump())
        image, pdb = self.root / "selected.exe", self.root / "selected.pdb"
        image.write_bytes(b"CONTRACT_SELECTED_IMAGE_NOT_NATIVE_EXECUTABLE")
        pdb.write_bytes(b"CONTRACT_SELECTED_PDB_NOT_NATIVE_SYMBOL_PROOF")
        # Native success is not simulated as acceptance: this isolates the
        # real normalizer/facade/store plumbing and role-hash receipt boundary.
        report = inspect_dump(self.path)
        report["data"].update(stack_unwind_status="INCOMPLETE_EVIDENCE", cleanup={
            "status": "COMPLETED", "confirmed": True, "offline_owner_retained": False,
            "resource_owner": "SAVED_DBGHELP_SESSION"})
        with patch("blackbox_core.deep_dump.inspect_dump", return_value=report) as inspection:
            case = create_investigation([{"source_type": "DUMP_METADATA", "path": str(self.path),
                                         "image_path": str(image), "pdb_path": str(pdb)}])
        options = inspection.call_args.kwargs
        self.assertEqual(options["image_path"], str(image))
        self.assertEqual(options["pdb_path"], str(pdb))
        self.assertNotIn("max_frames", options)
        source = case["sources"][0]
        manifest = {item["role"]: item["sha256"] for item in source["content_manifest"]}
        self.assertEqual(manifest, {role: hashlib.sha256(path.read_bytes()).hexdigest()
            for role, path in (("minidump", self.path), ("local_image", image), ("local_pdb", pdb))})
        self.assertEqual(source["source_file_count"], 3)
        self.assertTrue(source["native_resources_started"])
        self.assertEqual(source["native_resource_cleanup"]["resource_owner"], "SAVED_DBGHELP_SESSION")
        cleanup = case["run_receipt"]["cleanup"]
        self.assertTrue(cleanup["confirmed"])
        self.assertEqual(cleanup["scope"], "NORMALIZATION_SOURCE_READ_HANDLES_AND_OFFLINE_UNWIND")

        def mutate_image(*args, **kwargs):
            image.write_bytes(b"MUTATED_DURING_CONTRACT_INSPECTION")
            return report
        with patch("blackbox_core.deep_dump.inspect_dump", side_effect=mutate_image):
            with self.assertRaisesRegex(InvestigationError, "SOURCE_CHANGED"):
                create_investigation([{"source_type": "DUMP_METADATA", "path": str(self.path),
                                       "image_path": str(image), "pdb_path": str(pdb)}])

    def test_source_hash_must_agree_with_actual_dump_inspection_pass(self):
        self.path.write_bytes(crash_dump())
        report = inspect_dump(self.path)
        report["data"]["sha256"] = "e" * 64
        with patch("blackbox_core.deep_dump.inspect_dump", return_value=report):
            with self.assertRaisesRegex(InvestigationError, "BETWEEN_HASH_AND_DUMP_INSPECTION"):
                create_investigation([{"source_type": "DUMP_METADATA", "path": str(self.path)}])

    def test_native_recovery_failure_stays_uncertain_at_the_facade_boundary(self):
        from blackbox_core.deep_native import NativeError
        self.path.write_bytes(crash_dump())
        image = self.root / "selected.exe"
        image.write_bytes(b"CONTRACT_ONLY_NOT_NATIVE")
        failure = NativeError("RECOVERY_UNCONFIRMED", "CONTRACT_INJECTED_SYMCLEANUP_FAILURE")
        failure.offline_owner_retained = True
        failure.resource_owner = "SAVED_DBGHELP_SESSION"
        with patch("blackbox_core.deep_dump.inspect_dump", side_effect=failure):
            with self.assertRaises(NativeError) as caught:
                create_investigation([{"source_type": "DUMP_METADATA", "path": str(self.path),
                                       "image_path": str(image)}])
        self.assertEqual(caught.exception.run_receipt["status"], "RECOVERY_UNCONFIRMED")
        self.assertFalse(caught.exception.run_receipt["cleanup"]["confirmed"])
        self.assertTrue(caught.exception.offline_owner_retained)

    def test_readback_recomputes_a_structurally_valid_saved_view_without_source_reopening(self):
        self.path.write_bytes(crash_dump())
        index = self.root / "recompute.sqlite3"
        case = create_investigation([{"source_type": "DUMP_METADATA", "path": str(self.path)}], index_path=index)
        expected = case["crash_investigation"]["summary"]
        # Re-signed imported JSON is integrity-consistent, not authenticated.
        # The reader must derive the view from recorded nodes, not trust it.
        with closing(sqlite3.connect(index)) as db:
            row = json.loads(db.execute("SELECT content_json FROM investigation").fetchone()[0])
            saved = row["crash_investigation"]
            saved.update(status="NOT_COLLECTED", events=[], dumps=[], modules=[], threads=[], frames=[])
            saved["summary"] = {key: 0 for key in saved["summary"]}
            validate_case(row)
            raw = canonical_json(row)
            db.execute("UPDATE investigation SET content_json=?,content_sha256=?",
                       (raw, hashlib.sha256(raw.encode("ascii")).hexdigest()))
            db.commit()
        before = index.read_bytes()
        self.path.unlink()
        with patch("blackbox_core.deep_dump.inspect_dump", side_effect=AssertionError("SOURCE_REOPENED")):
            loaded = load_investigation(index)
        self.assertEqual(loaded["crash_investigation"]["summary"], expected)
        self.assertEqual(index.read_bytes(), before)

    def test_legacy_absent_projection_exports_without_adding_a_false_saved_view(self):
        self.path.write_bytes(crash_dump())
        case = create_investigation([{"source_type": "DUMP_METADATA", "path": str(self.path)}])
        case.pop("crash_investigation")
        for format in ("json", "html"):
            destination = self.root / ("legacy." + format)
            export_investigation(case, destination, format=format)
            self.assertNotIn("crash_investigation", destination.read_text())
        self.assertNotIn("crash_investigation", case)

    def test_historical_pid_does_not_bind_a_new_live_instance(self):
        self.path.write_bytes(crash_dump())
        case = create_investigation([{"source_type": "DUMP_METADATA", "path": str(self.path)}],
            target_identity={"pid": 4321, "created_100ns": 134382769877915963, "image_path": ""})
        view = project_crash_evidence(case)
        self.assertEqual(view["dumps"][0]["recorded_pid"], 4321)
        self.assertEqual(view["dumps"][0]["live_process_binding"], "NOT_ESTABLISHED")
        self.assertEqual(view["dumps"][0]["process_instance_binding"], "NOT_ESTABLISHED_FROM_IMPORTED_SOURCE")
        self.assertEqual(view["root_cause"], "UNKNOWN")

    def test_saved_crash_projection_rejects_payload_and_dangling_authority_claims(self):
        self.path.write_bytes(crash_dump())
        case = create_investigation([{"source_type": "DUMP_METADATA", "path": str(self.path)}])
        clean = project_crash_evidence(case)
        for mutate in (
            lambda value: value["privacy"].update(memory_contents_included=True),
            lambda value: value["dumps"][0].update(node_id="f" * 64),
            lambda value: value["coverage"].update(memory_bytes="PRIVATE_HEX"),
            lambda value: value["summary"].update(root_cause_proven=1),
            lambda value: value["dumps"][0].update(live_process_binding="MATCHED")):
            forged = json.loads(json.dumps(clean))
            mutate(forged)
            with self.assertRaises(InvestigationError):
                validate_crash_report(forged, nodes=case["nodes"])

    def test_saved_query_rows_keep_utc_clock_and_wer_candidates_unattributed(self):
        event = parse_event(event_xml(), pid=123, start_utc_ns=0, end_utc_ns=2**63-1)
        candidate = {**event, "provider": "Windows Error Reporting", "event_id": 1001,
                     "target_pid": 123, "process_instance_binding": "MATCHED_RECORDED_CREATION_FILETIME",
                     "wer_event_name": "APPCRASH"}
        row = {"schema_version": 1, "pid": 123, "tid": 77, "seq": 1,
               "source_ns": 1, "source_clock": "SYNTHETIC_FORMAT_ONLY_MONOTONIC",
               "token": "SYNTHETIC_FORMAT_ONLY",
               "kind": "crash.system_events", "attributes": {
                   "status": "MATCHING_OS_EVENTS", "events": [event], "wer_candidates": [candidate],
                   "memory_bytes": "PRIVATE_MARKER_MUST_NOT_LEAK"}}
        path = self.root / "format-only.jsonl"
        path.write_text(json.dumps(row) + "\n")
        case = create_investigation([{"source_type": "EVENTS_JSONL", "path": str(path)}])
        view = project_crash_evidence(case)
        self.assertEqual(view["summary"]["failure_events"], 2)
        self.assertEqual(view["summary"]["unattributed_wer_candidates"], 1)
        self.assertEqual(view["events"][0]["event_utc_ns"], event["event_utc_ns"])
        self.assertTrue(view["events"][0]["event_time_domain"].startswith("EVENTLOG_UTC:"))
        self.assertFalse(view["events"][0]["observer_receipt_is_event_time"])
        self.assertIsNone(view["events"][1]["target_pid"])
        self.assertEqual(view["events"][1]["recorded_process_binding"],
                         "NOT_ESTABLISHED_IMAGE_AND_TIME_CANDIDATE_ONLY")
        self.assertNotIn("PRIVATE_MARKER_MUST_NOT_LEAK", json.dumps(view))


class R40EventLogContracts(unittest.TestCase):
    def test_invalid_or_conflicting_recorded_birth_aliases_cannot_grant_exact_identity(self):
        birth = int("1dc4c918af3c41a", 16)
        for first, second in (("INVALID", str(birth)), ("0", str(birth)),
                              (str(birth), "INVALID"), (str(birth), "0")):
            xml = event_xml(birth=first).replace("</EventData>",
                '<Data Name="FaultingProcessCreationTime">' + second + '</Data></EventData>')
            row = parse_event(xml, pid=123, start_utc_ns=0, end_utc_ns=2**63-1,
                              expected_created_100ns=birth)
            self.assertEqual(row["process_instance_binding"], "BIRTH_NOT_ATTESTED")
            self.assertIsNone(row["recorded_creation_100ns"])
        contradictory = event_xml().replace("</EventData>",
            '<Data Name="FaultingProcessCreationTime">' + str(birth + 1) + '</Data></EventData>')
        self.assertIsNone(parse_event(contradictory, pid=123, start_utc_ns=0, end_utc_ns=2**63-1,
                                    expected_created_100ns=birth))

    def test_creation_exactly_matches_and_logger_is_not_faulting_pid(self):
        birth = int("1dc4c918af3c41a", 16)
        answer = parse_event(event_xml(), pid=123, start_utc_ns=0, end_utc_ns=2**63-1,
                             expected_created_100ns=birth)
        self.assertEqual(answer["target_pid"], 123)
        self.assertEqual(answer["logger_pid"], 567)
        self.assertEqual(answer["process_instance_binding"], "MATCHED_RECORDED_CREATION_FILETIME")
        self.assertEqual(answer["exception_code"], 0xC0000005)
        self.assertEqual(answer["faulting_offset"], 0x124)
        self.assertEqual(answer["application"]["name"], "probe.exe")
        self.assertEqual(answer["verification_class"], "UNVERIFIED_IMPORT")
        self.assertEqual(answer["root_cause"], "UNKNOWN")
        self.assertEqual(answer["source_sha256"], hashlib.sha256(event_xml().encode()).hexdigest())
        serialized = json.dumps(answer)
        self.assertNotIn("private-user", serialized)
        self.assertNotIn("NEVER_EXPORT_THIS_PAYLOAD", serialized)

    def test_pid_reuse_and_malformed_birth_cannot_create_exact_binding(self):
        args = dict(pid=123, start_utc_ns=0, end_utc_ns=2**63-1,
                    expected_created_100ns=int("1dc4c918af3c41a", 16))
        self.assertIsNone(parse_event(event_xml(birth="1"), **args))
        answer = parse_event(event_xml(birth="INVALID"), **args)
        self.assertEqual(answer["process_instance_binding"], "BIRTH_NOT_ATTESTED")
        self.assertIsNone(parse_event(event_xml(pid=124), **args))
        self.assertIsNone(parse_event(event_xml(logger=123).replace('Name="ProcessId"', 'Name="LoggerOnly"'), **args))

    def test_only_named_fault_pid_fields_can_match_not_thread_offset_or_birth(self):
        args = dict(pid=123, start_utc_ns=0, end_utc_ns=2**63-1)
        variants = [event_xml(pid=456).replace('</EventData>', '<Data Name="FaultingThreadId">123</Data></EventData>'),
                    event_xml(pid=456).replace('0000000000000124', '123'),
                    event_xml(pid=456, birth="123")]
        for xml in variants:
            self.assertIsNone(parse_event(xml, **args))
        conflicting = event_xml().replace('</EventData>', '<Data Name="FaultingProcessId">456</Data></EventData>')
        self.assertIsNone(parse_event(conflicting, **args))

    def test_query_cancel_and_expired_budget_keep_incomplete_status(self):
        cancel = threading.Event()
        cancel.set()
        answer = query(123, 1, cancel_event=cancel)
        self.assertEqual(answer["status"], "CANCELLED")
        self.assertFalse(answer["capture_complete"])
        answer = query(123, 1, deadline=time.monotonic() - 1)
        self.assertEqual(answer["status"], "TIMED_OUT")

    def test_wer_without_faulting_pid_remains_unattributed(self):
        xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><Provider Name="Windows Error Reporting"/><EventID>1001</EventID>'
            '<TimeCreated SystemTime="2026-11-04T14:00:00Z"/><Execution ProcessID="123"/>'
            '<EventRecordID>43</EventRecordID></System><EventData>'
            '<Data Name="EventName">APPCRASH</Data><Data Name="P1">C:\\private-user\\probe.exe</Data>'
            '<Data Name="ReportId">{12345678-1234-1234-1234-123456789abc}</Data>'
            '<Data Name="Secret">NEVER_SHARE_WER_PAYLOAD</Data></EventData></Event>')
        args = dict(start_utc_ns=0, end_utc_ns=2**63-1)
        self.assertIsNone(parse_event(xml, pid=123, **args))
        row = parse_wer_candidate(xml, image_name="probe.exe", **args)
        self.assertIsNone(row["target_pid"])
        self.assertEqual(row["process_instance_binding"], "NOT_ESTABLISHED_IMAGE_AND_TIME_CANDIDATE_ONLY")
        self.assertEqual(row["verification_class"], "UNVERIFIED_IMPORT")
        self.assertEqual(row["root_cause"], "UNKNOWN")
        self.assertNotIn("private-user", json.dumps(row))
        self.assertNotIn("NEVER_SHARE_WER_PAYLOAD", json.dumps(row))
        self.assertIsNone(parse_wer_candidate(xml, image_name="other.exe", **args))
        self.assertIsNone(parse_wer_candidate(xml, image_name="probe.exe", **{**args, "end_utc_ns": 1}))
        forged = xml.replace('</EventData>', '<Data Name="AppName">other.exe</Data></EventData>')
        self.assertIsNone(parse_wer_candidate(forged, image_name="other.exe", **args))


class R40OfflineCleanupContracts(unittest.TestCase):
    """Injected cleanup outcomes are contracts, not observed Windows failures."""
    def owner(self, cleanup_answers, *, close_answer=True):
        history = []
        answers = iter(cleanup_answers)
        def cleanup(handle):
            history.append(("sym", handle))
            return next(answers)
        def images_close():
            history.append(("images", None))
        def event_close(handle):
            history.append(("event", handle))
            return close_answer
        return {"handle": 1234, "initialized": True, "cleanup": cleanup,
                "images": SimpleNamespace(close=images_close),
                "kernel": SimpleNamespace(close=event_close)}, history

    def test_failed_symbol_cleanup_retains_capability_and_explicit_retry_releases_in_order(self):
        from blackbox_core import deep_native_stacks as stacks
        owner, history = self.owner([False, True])
        self.assertIn("NOT_CONFIRMED", stacks._release_saved_unwind_owner(owner))
        self.assertEqual(history, [("sym", 1234)])
        self.assertTrue(owner["initialized"])
        with patch.object(stacks, "_SAVED_UNWIND_OWNER", owner):
            answer = stacks.retry_saved_unwind_cleanup()
            self.assertEqual(answer["status"], "COMPLETED")
            self.assertFalse(answer["data"]["offline_owner_retained"])
            self.assertIsNone(stacks._SAVED_UNWIND_OWNER)
        self.assertEqual(history, [("sym", 1234), ("sym", 1234), ("images", None), ("event", 1234)])

    def test_unconfirmed_owner_blocks_new_unwind_without_reopening_a_dump(self):
        from blackbox_core import deep_native_stacks as stacks
        from blackbox_core.deep_native import NativeError
        owner, history = self.owner([False])
        with patch.object(stacks, "_SAVED_UNWIND_OWNER", owner):
            with self.assertRaises(NativeError) as error:
                stacks.unwind_saved_contexts([], lambda *_: b"", [], "MUST_NOT_OPEN_MISSING_FILE.exe")
            self.assertEqual(error.exception.status, "RECOVERY_UNCONFIRMED")
            self.assertTrue(error.exception.offline_owner_retained)
        self.assertEqual(history, [])

    def test_failed_handle_close_is_never_retried_by_recycled_numeric_value(self):
        from blackbox_core import deep_native_stacks as stacks
        owner, history = self.owner([True], close_answer=False)
        self.assertIn("RESTART_REQUIRED", stacks._release_saved_unwind_owner(owner))
        before = list(history)
        with patch.object(stacks, "_SAVED_UNWIND_OWNER", owner):
            answer = stacks.retry_saved_unwind_cleanup()
            self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
            self.assertIs(stacks._SAVED_UNWIND_OWNER, owner)
        self.assertEqual(history, before)

    def test_existing_dump_inspect_explicit_cleanup_does_not_replay_inspection(self):
        from blackbox_core import deep_native_stacks as stacks
        owner, history = self.owner([True])
        with patch.object(stacks, "_SAVED_UNWIND_OWNER", owner):
            answer = inspect_dump("MUST_NOT_OPEN_MISSING_DUMP.dmp", retry_cleanup=True)
        self.assertEqual(answer["status"], "COMPLETED")
        self.assertFalse(answer["data"]["offline_owner_retained"])
        self.assertTrue(answer["data"]["had_retained_owner"])
        self.assertEqual(history, [("sym", 1234), ("images", None), ("event", 1234)])


class R40ServiceOwnerIsolation(unittest.TestCase):
    """Real coordinator/journal with fake authority; no native elevation claim."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = InspectorService(Path(self.temp.name))
        self.target = ProcessIdentity(123, 134382769877915962, "controlled.exe")
        self.helper = SimpleNamespace(pid=456, alive=lambda: True)
        self.service.helper = self.helper
        self.service._helper_identity = ProcessIdentity(456, 134382769877915963, "helper.exe")
        self.service._admin_session_managed = True
        self.service._permission = "ADMINISTRATOR"
        self.service._elevated_verified = True
        self.service._admin_state = "ACTIVE"
        self.service._expires = time.monotonic() + 60
        self.service._target = self.target

    def tearDown(self):
        self.service.helper = None
        self.temp.cleanup()

    def request(self):
        return ActionRequest("dump_inspect", self.target,
                             {"path": "owned.dmp", "retry_cleanup": True})

    def test_offline_failure_and_retry_do_not_poison_admin_helper_authority(self):
        failure = {"status": "RECOVERY_UNCONFIRMED", "data": {
            "offline_owner_retained": True, "resource_owner": "SAVED_DBGHELP_SESSION"},
            "error": "INJECTED_OFFLINE_SYM_CLEANUP_FAILURE"}
        with patch.object(self.service, "_local", return_value=failure):
            answer = self.service.execute(self.request())
        self.assertEqual(answer["status"], "RECOVERY_UNCONFIRMED")
        self.assertEqual(answer["run_receipt"]["status"], "RECOVERY_UNCONFIRMED")
        self.assertFalse(self.service._owner_retained)
        self.assertFalse(self.service._cleanup_unconfirmed)
        self.assertTrue(self.service.admin_active)
        success = {"status": "COMPLETED", "data": {
            "offline_owner_retained": False, "resource_owner": "SAVED_DBGHELP_SESSION"}}
        with patch.object(self.service, "_local", return_value=success):
            answer = self.service.execute(self.request())
        self.assertEqual(answer["status"], "COMPLETED")
        self.assertIs(self.service.helper, self.helper)
        self.assertTrue(self.service.admin_active)

    def test_successful_offline_cleanup_does_not_clear_real_helper_uncertainty(self):
        self.service._owner_retained = self.service._cleanup_unconfirmed = True
        self.service._admin_state = "CLEANUP_REQUIRED"
        success = {"status": "COMPLETED", "data": {
            "offline_owner_retained": False, "resource_owner": "SAVED_DBGHELP_SESSION"}}
        with patch.object(self.service, "_local", return_value=success):
            answer = self.service.execute(self.request())
        self.assertEqual(answer["status"], "COMPLETED")
        self.assertTrue(self.service._owner_retained)
        self.assertTrue(self.service._cleanup_unconfirmed)
        self.assertEqual(self.service.session_status()["state"], "CLEANUP_REQUIRED")
        self.assertFalse(self.service.admin_active)


if __name__ == "__main__":
    unittest.main()
