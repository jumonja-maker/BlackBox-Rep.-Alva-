"""Source contracts. Fixtures here are synthetic, never native acceptance.

Executed exclusively by the hosted Investigation Engine 3 workflow.
"""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
from threading import Event
import unittest
from unittest.mock import patch

from blackbox_core import evidence_normalization as normal
from blackbox_core.deep_journal import EvidenceJournal
from blackbox_core.decoder_index import PROTOCOL, build_index
from blackbox_core.investigation_graph_contracts import InvestigationBudget
from blackbox_core.session_v2 import SessionV2Writer


class NormalizationContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def sdk(self, *, count=2, complete=True, extra=None):
        rows = []
        for index in range(1, count + 1):
            rows.append({"schema_version": 1, "token": "SECRET_TOKEN_MUST_NOT_ESCAPE", "pid": 123, "tid": 7,
                "seq": index, "kind": "io.operation.begin" if index % 2 else "io.operation.end",
                "source_clock": "PYTHON_PERF_COUNTER_NS", "source_ns": 1000 + index * 100,
                "operation_id": "operation-" + str((index + 1) // 2), "parent_id": None, "client_dropped": 0,
                "attributes": {"io_kind": "WRITE", **({"status": "ERROR", "error_code": 5,
                    "private_secret": "PRIVATE_SENTINEL", "value_hex": "deadc0de"} if not index % 2 else {}),
                    **(extra or {})}})
        if complete:
            rows.append({**rows[-1], "seq": count + 1, "kind": "blackbox.completed", "source_ns": 2000,
                         "operation_id": None, "attributes": {"status": "COMPLETED", "expected_operations": count // 2}})
        path = self.root / "app.jsonl"
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        return path, rows

    def trace(self, *, rows=4, lost=0):
        events = [{"type": "event", "ordinal": n, "time_ms": n * 10, "pid": 123, "tid": 7,
                   "process_instance": 4, "provider": "CONTRACT_FIXTURE", "name": "FileIO/Write",
                   "payload": {"FileName": r"C:\Users\private\controlled.bin"}, "frames": []}
                  for n in range(1, rows + 1)]
        source = self.root / "trace.jsonl"
        records = [{"type": "header", "protocol": PROTOCOL, "input_sha256": "a" * 64}, *events,
                   {"type": "footer", "protocol": PROTOCOL, "rows": rows,
                    "status": "DECODED", "decoder_reported_lost_events": lost}]
        source.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
        target = self.root / "trace.sqlite3"
        build_index(source, target, input_sha256="a" * 64, format_name=".etl")
        return target

    def test_content_identity_survives_rename_and_source_is_unchanged(self):
        path, _ = self.sdk()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        first = normal.normalize_sources([{"source_type": "EVENTS_JSONL", "path": str(path)}])
        renamed = self.root / "renamed-source.jsonl"
        shutil.copyfile(path, renamed)
        second = normal.normalize_sources([{"source_type": "EVENTS_JSONL", "path": str(renamed)}])
        self.assertEqual(first["sources"], second["sources"])
        self.assertEqual(first["nodes"], second["nodes"])
        self.assertNotEqual(first["_source_paths"], second["_source_paths"])
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        self.assertTrue(first["sources"][0]["application_events_complete"])

    def test_sdk_error_stays_a_source_statement_and_private_values_are_removed(self):
        path, _ = self.sdk()
        result = normal.normalize_sources([{"source_type": "EVENTS_JSONL", "path": path}])
        serialized = json.dumps({k: value for k, value in result.items() if not k.startswith("_")})
        for secret in ("SECRET_TOKEN_MUST_NOT_ESCAPE", "PRIVATE_SENTINEL", "deadc0de"):
            self.assertNotIn(secret, serialized)
        error = next(node for node in result["nodes"] if node["metadata"].get("status") == "ERROR")
        self.assertEqual(error["metadata"]["error_code"], 5)
        self.assertEqual(error["metadata"]["error_code_basis"], "RECORDED_SOURCE_STATEMENT_NOT_ETW_INFERENCE")
        self.assertEqual(error["verification_class"], "UNVERIFIED_IMPORT")
        self.assertEqual(error["process_identity"]["kind"], "APP_PROCESS")
        self.assertFalse(error["process_identity"]["exact"])

    def test_sdk_io_classification_requires_explicit_name_boundaries(self):
        examples = {"profileio.failed": "ERROR", "getcpu.failed": "ERROR",
            "app.profileio.operation.end": "ERROR", "FileIO/Read": "FILE_OPERATION",
            "app.io.operation.end": "FILE_OPERATION", "IO.OPERATION": "FILE_OPERATION",
            "TcpIp/Send": "NETWORK_OPERATION", "UdpIp/Send": "NETWORK_OPERATION",
            "network.error": "NETWORK_OPERATION", "app_tcp_send": "NETWORK_OPERATION",
            "app/udp/receive": "NETWORK_OPERATION"}
        for kind, expected in examples.items():
            with self.subTest(kind=kind):
                path, rows = self.sdk(complete=False)
                row = {**rows[0], "kind": kind, "attributes": {"status": "ERROR", "error_code": 5}}
                path.write_text(json.dumps(row) + "\n", encoding="utf-8")
                result = normal.normalize_sources([{"source_type": "EVENTS_JSONL", "path": path}])
                self.assertEqual(len(result["nodes"]), 1)
                self.assertEqual(result["nodes"][0]["observation_type"], expected)

    def test_eof_alone_missing_loss_counter_and_missing_sequence_never_mean_complete(self):
        path, rows = self.sdk(complete=False)
        spec = [{"source_type": "EVENTS_JSONL", "path": path}]
        self.assertFalse(normal.normalize_sources(spec)["sources"][0]["application_events_complete"])
        path, rows = self.sdk()
        rows[0].pop("client_dropped")
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        source = normal.normalize_sources(spec)["sources"][0]
        self.assertIsNone(source["application_client_dropped_total"])
        self.assertFalse(source["application_events_complete"])
        path, rows = self.sdk(count=4)
        rows.pop(1)
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        self.assertGreater(normal.normalize_sources(spec)["sources"][0]["application_sequence_gaps"], 0)

    def test_replayed_sequence_bad_error_type_and_partial_line_are_rejected(self):
        path, rows = self.sdk()
        rows[1]["seq"] = rows[0]["seq"]
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        with self.assertRaisesRegex(ValueError, "REPLAYED"):
            normal.normalize_sources([{"source_type": "EVENTS_JSONL", "path": path}])
        path, _ = self.sdk(extra={"error_code": True})
        with self.assertRaisesRegex(ValueError, "ERROR_CODE"):
            normal.normalize_sources([{"source_type": "EVENTS_JSONL", "path": path}])
        path.write_text('{"schema_version":1}')
        with self.assertRaisesRegex(ValueError, "PARTIAL"):
            normal.normalize_sources([{"source_type": "EVENTS_JSONL", "path": path}])

    def test_source_byte_budget_and_event_pass_limit_are_explicit(self):
        path, _ = self.sdk(count=10)
        result = normal.normalize_sources([{"source_type": "EVENTS_JSONL", "path": path}],
                                          budget=InvestigationBudget(max_events=3))
        self.assertEqual(result["coverage"]["events_examined"], 3)
        self.assertTrue(result["coverage"]["has_more"])
        self.assertTrue(result["coverage"]["events_omitted_is_lower_bound"])
        self.assertFalse(result["sources"][0]["scan_complete"])
        self.assertTrue(result["coverage"]["next_cursor"])
        with self.assertRaisesRegex(ValueError, "SOURCE_FILE_BUDGET"):
            normal.normalize_sources([{"source_type": "EVENTS_JSONL", "path": path}],
                                     budget=InvestigationBudget(max_source_bytes=1024))

    def test_pre_cancelled_operation_never_reads_source(self):
        cancelled = Event()
        cancelled.set()
        with patch.object(normal, "_hash_file") as reader, self.assertRaises(InterruptedError):
            normal.normalize_sources([{"source_type": "EVENTS_JSONL", "path": self.root / "missing"}],
                                      budget=InvestigationBudget(cancel_event=cancelled))
        reader.assert_not_called()

    def test_trace_filter_preserves_trace_local_identity_and_unknown_file_status(self):
        path = self.trace()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        result = normal.normalize_sources([{"source_type": "TRACE_INDEX", "path": path,
                                            "selection": {"pid": 123, "process_instance": 4}}])
        file_node = next(node for node in result["nodes"] if node["observation_type"] == "FILE_OPERATION")
        self.assertEqual(file_node["process_identity"], {"kind": "TRACE_PROCESS", "trace_sha256": "a" * 64,
                                                       "process_instance": 4, "pid": 123})
        self.assertNotIn("status", file_node["metadata"])
        self.assertNotIn("error_code", file_node["metadata"])
        self.assertNotIn("private", json.dumps(file_node["metadata"]))
        self.assertEqual(result["sources"][0]["trace_input_sha256"], "a" * 64)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_trace_cursor_and_unknown_loss_do_not_claim_complete_scheduling(self):
        path = self.trace(rows=6, lost=None)
        with patch("blackbox_core.decoder_waits.build_wait_report") as wait_reader:
            result = normal.normalize_sources([{"source_type": "TRACE_INDEX", "path": path}],
                                              budget=InvestigationBudget(max_events=2))
        wait_reader.assert_not_called()
        source = result["sources"][0]
        self.assertIsNone(source["decoder_reported_lost_events"])
        self.assertFalse(source["scheduler_complete"])
        cursor = result["coverage"]["next_cursor"][0]
        self.assertEqual(cursor["after"], 2)
        continued = normal.normalize_sources([{"source_type": "TRACE_INDEX", "path": path, "after": 2}])
        event_ids = {node["source_record_id"] for node in continued["nodes"]}
        self.assertIn("events:3", event_ids)
        self.assertNotIn("events:1", event_ids)

    def test_sqlite_views_cannot_masquerade_as_events_and_wal_is_refused(self):
        path = self.trace()
        with closing(sqlite3.connect(path)) as db:
            db.execute("ALTER TABLE events RENAME TO actual_events")
            db.execute("CREATE VIEW events AS SELECT * FROM actual_events")
        with self.assertRaisesRegex(ValueError, "TABLE"):
            normal.normalize_sources([{"source_type": "TRACE_INDEX", "path": path}])
        Path(str(path) + "-wal").write_bytes(b"ACTIVE_COMMITTED_WAL")
        with self.assertRaisesRegex(ValueError, "WAL_ACTIVE"):
            normal.normalize_sources([{"source_type": "TRACE_INDEX", "path": path}])

    def test_changed_input_is_refused_before_any_result_is_returned(self):
        path, _ = self.sdk()
        original = normal._StableSource.verify
        def changed(stable):
            path.write_text(path.read_text() + "\n")
            return original(stable)
        with patch.object(normal._StableSource, "verify", changed), self.assertRaisesRegex(ValueError, "SOURCE_CHANGED"):
            normal.normalize_sources([{"source_type": "EVENTS_JSONL", "path": path}])

    def test_deep_journal_chain_identity_redaction_and_snapshot_refs(self):
        journal = EvidenceJournal(self.root / "journal")
        target = {"pid": 123, "created_100ns": 987654321, "image_path": r"C:\private\fixture.exe"}
        journal.append({"operation_id": "one:requested", "action_id": "one", "phase": "REQUESTED",
                        "operation": "memory.write", "target": target, "source": "BLACKBOX_DIAGNOSTIC_ACTION_ENGINE"})
        journal.append({"operation_id": "one:result", "action_id": "one", "phase": "RESULT",
                        "operation": "memory.write", "target": target, "status": "COMPLETED",
                        "source": "NATIVE_MEMORY", "data": {"expected_hex": "aabbccdd"}})
        result = normal.normalize_sources([{"source_type": "DEEP_JOURNAL", "path": journal.path}])
        action = next(node for node in result["nodes"] if node["metadata"].get("phase") == "RESULT")
        self.assertEqual(action["process_identity"], {"kind": "LIVE_PROCESS", "pid": 123, "created_100ns": 987654321})
        self.assertIn("actions:one:requested", action["metadata"]["record_refs"])
        self.assertNotIn("aabbccdd", json.dumps({key: value for key, value in result.items() if not key.startswith("_")}))
        self.assertTrue(result["sources"][0]["selected_prefix_complete"])
        with closing(sqlite3.connect(journal.path)) as db:
            changed = db.execute("UPDATE actions SET record_json='{}' WHERE sequence=1")
            self.assertEqual(changed.rowcount, 1)
            db.commit()
        with self.assertRaisesRegex(ValueError, "HASH_CHAIN"):
            normal.normalize_sources([{"source_type": "DEEP_JOURNAL", "path": journal.path}])

    def test_native_stack_expands_actual_snapshot_identity_and_rva(self):
        journal = EvidenceJournal(self.root / "journal")
        target = {"pid": 123, "created_100ns": 987654321}
        module = {"base": 4096, "size": 8192, "name": "fixture.exe", "path": r"C:\private\fixture.exe",
                  "snapshot_binding": "PSS_CLONE_PE_IDENTITY_AND_LAYOUT_MATCH",
                  "snapshot_pe": {"guid": "aabbccdd-0000-1111-2222-334455667788", "age": 1, "machine": 34404,
                                  "image_size": 8192, "image_timestamp": 100}}
        journal.append({"operation_id": "stack:result", "action_id": "stack", "phase": "RESULT",
                        "operation": "thread_stacks", "target": target, "status": "COMPLETED",
                        "data": {"rows": [{"tid": 7, "created_100ns": 12345,
                            "frames": [{"address": 4100, "rva": 4, "module_identity": module}]}]}})
        result = normal.normalize_sources([{"source_type": "DEEP_JOURNAL", "path": journal.path}])
        types = {node["observation_type"] for node in result["nodes"]}
        self.assertTrue({"PROCESS", "THREAD", "STACK", "MODULE", "FUNCTION"} <= types)
        thread = next(node for node in result["nodes"] if node["observation_type"] == "THREAD")
        self.assertEqual(thread["thread_identity"]["thread_created_100ns"], 12345)
        function = next(node for node in result["nodes"] if node["observation_type"] == "FUNCTION")
        self.assertEqual(function["metadata"]["rva"], 4)

    def test_session_float_creation_and_sampled_tid_remain_non_native(self):
        folder = self.root / "session"
        folder.mkdir()
        writer = SessionV2Writer(folder, pid=123, created=1., name="FIXTURE_ONLY", origin_ns=1_000_000_000)
        writer.submit("detail", {"time_ns": 2_000_000_000, "pid": 123, "created": 1.,
            "cpu_user_s": 1., "cpu_system_s": 0., "rss_bytes": 100, "thread_count": 1,
            "read_bytes": 0, "write_bytes": 0, "children_total": 0, "children_omitted": 0, "threads_omitted": 0,
            "thread_capture_status": "OK", "child_capture_status": "OK", "sensor_status": {"children": "OK"},
            "threads": [{"tid": 7, "cpu_user_s": 1., "cpu_system_s": 0.}], "children": [], "requested_interval_ns": 1_000_000_000})
        writer.finish("COMPLETED")
        result = normal.normalize_sources([{"source_type": "SESSION", "path": folder}])
        process = next(node for node in result["nodes"] if node["observation_type"] == "PROCESS")
        self.assertEqual(process["process_identity"]["kind"], "SESSION_PROCESS")
        self.assertFalse(process["process_identity"]["exact"])
        self.assertNotIn("created_100ns", process["process_identity"])

    def test_old_investigation_report_and_future_registry_contract_are_explicit(self):
        path = self.root / "old.json"
        path.write_text(json.dumps({"schema_version": 2, "engine": "BLACKBOX_INVESTIGATION_2",
            "findings": [{"finding_id": "old-1", "code": "CPU_WARNING", "start_ns": 1, "end_ns": 2}],
            "findings_total": 1, "has_more": False}))
        result = normal.normalize_sources([{"source_type": "INVESTIGATION_V2", "path": path}])
        self.assertTrue(result["sources"][0]["legacy_engine_preserved"])
        self.assertEqual(result["nodes"][0]["verification_class"], "UNVERIFIED_IMPORT")
        self.assertFalse(normal.registry_source_contract()["collector"])
        self.assertEqual(normal.registry_source_contract()["status"], "NOT_IMPLEMENTED")

    def test_publication_receipt_rechecks_bytes_and_rejects_imported_receipts(self):
        path, _ = self.sdk()
        result = normal.normalize_sources([{"source_type": "EVENTS_JSONL", "path": path}])
        self.assertEqual(normal.revalidate_sources(result)["status"], "UNCHANGED")
        path.write_text(path.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "SOURCE_CHANGED"):
            normal.revalidate_sources(result)
        with self.assertRaisesRegex(ValueError, "REVALIDATION_RECEIPT"):
            normal.revalidate_sources({"_source_receipts": ({"path": str(path)},)})

    def test_source_change_or_wal_during_final_hash_is_refused(self):
        path, _ = self.sdk()
        result = normal.normalize_sources([{"source_type": "EVENTS_JSONL", "path": path}])
        original = normal._hash_file
        def changed_after_hash(source_path, budget):
            digest = original(source_path, budget)
            source_path.write_bytes(source_path.read_bytes() + b"\n")
            return digest
        with patch.object(normal, "_hash_file", changed_after_hash), self.assertRaisesRegex(ValueError, "SOURCE_CHANGED"):
            normal.revalidate_sources(result)
        path, _ = self.sdk()
        result = normal.normalize_sources([{"source_type": "EVENTS_JSONL", "path": path}])
        def wal_after_hash(source_path, budget):
            digest = original(source_path, budget)
            Path(str(source_path) + "-wal").write_bytes(b"NEW_ACTIVE_WAL")
            return digest
        with patch.object(normal, "_hash_file", wal_after_hash), self.assertRaisesRegex(ValueError, "WAL_ACTIVE"):
            normal.revalidate_sources(result)

    def test_trace_summary_scalars_are_validated_before_use(self):
        path = self.trace()
        with closing(sqlite3.connect(path)) as db:
            summary = json.loads(db.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
            summary.pop("input_sha256")
            db.execute("UPDATE metadata SET value=? WHERE key='summary'", (json.dumps(summary),))
            db.commit()
        # The existing decoder rejects this metadata before adapter projection.
        with self.assertRaisesRegex(ValueError, "^INVALID_INDEX_SUMMARY$"):
            normal.normalize_sources([{"source_type": "TRACE_INDEX", "path": path}])

    def test_untyped_middle_switch_withholds_running_completeness(self):
        from copy import deepcopy
        from blackbox_core.critical_path import analyze_critical_path
        from blackbox_core.decoder_waits import SCHEDULE_SCHEMA
        from blackbox_core.evidence_graph import build_graph
        first = {"pid": 123, "tid": 7, "process_instance": 4, "thread_instance": 9,
                 "start_ms": 0., "end_ms": 1000., "attribution": "TRACELOG_THREAD_LIFETIME"}
        other = {**first, "pid": 124, "tid": 8, "process_instance": 5, "thread_instance": 10}
        rows = []
        for ordinal, old, new in ((1, other, first), (2, first, other), (3, first, other)):
            row = {"type": "event", "ordinal": ordinal, "time_ms": ordinal * 10.,
                "pid": new["pid"], "tid": new["tid"], "process_instance": new["process_instance"],
                "provider": "Windows Kernel", "provider_guid": "9e814aad-3204-11d2-9a82-006008a86939",
                "name": "Thread/CSwitch", "event_id": 65535, "opcode": 36, "version": 2,
                "payload": {}, "frames": [], "semantic": None, "errors": [],
                "thread_schedule": {"schema": SCHEDULE_SCHEMA, "source": "ETW_KERNEL_SCHEDULER",
                    "parser": "TRACEEVENT_CSWITCH", "kind": "switch", "processor_index": 0,
                    "old_thread": deepcopy(old), "new_thread": deepcopy(new), "old_state_code": 5,
                    "old_state": "Wait", "wait_reason_code": 4, "wait_reason": "DelayExecution", "wait_mode": 0}}
            if ordinal == 2:
                row.pop("thread_schedule")
            rows.append(row)
        stream, path = self.root / "mixed.jsonl", self.root / "mixed.sqlite3"
        stream.write_text("".join(json.dumps(row) + "\n" for row in [
            {"type": "header", "protocol": PROTOCOL, "input_sha256": "b" * 64}, *rows,
            {"type": "footer", "protocol": PROTOCOL, "status": "DECODED", "rows": 3,
             "decoder_reported_lost_events": 0}]))
        build_index(stream, path, input_sha256="b" * 64, format_name=".etl")
        result = normal.normalize_sources([{"source_type": "TRACE_INDEX", "path": path}])
        source = result["sources"][0]
        self.assertEqual(source["wait_coverage"]["missing_typed_classification"], 1)
        self.assertFalse(source["scheduler_complete"])
        self.assertFalse(any(segment["state"] == "RUNNING" for segment in analyze_critical_path(build_graph(result))["segments"]))

    def test_duplicate_deep_alias_never_changes_another_nodes_action_refs(self):
        journal = EvidenceJournal(self.root / "deep-alias")
        journal.append({"operation_id": "stack:result", "action_id": "stack", "phase": "RESULT",
            "operation": "threads", "target": {"pid": 123, "created_100ns": 987654321},
            "data": {"rows": [{"tid": 7, "created_100ns": 12345}]}})
        source = {"source_type": "DEEP_JOURNAL", "path": journal.path}
        once = normal.normalize_sources([source])
        twice = normal.normalize_sources([source, source])
        self.assertEqual(once["nodes"], twice["nodes"])
        self.assertEqual(once["coverage"], twice["coverage"])

    def test_colocated_research_file_does_not_inherit_session_clock(self):
        from blackbox_core.casebook import CaseBook
        folder = self.root / "mixed-session"
        folder.mkdir()
        writer = SessionV2Writer(folder, pid=123, created=1., name="SYNTHETIC_CLOCK_SCOPE", origin_ns=1_000_000_000)
        writer.finish("COMPLETED")
        book = CaseBook(folder, 123, 1., {"origin_monotonic_ns": 1234})
        try:
            book.put("user_problem", {"message": "SYNTHETIC_UNRELATED_CLOCK"}, source="USER_MARKER")
        finally:
            book.db.close()
        result = normal.normalize_sources([{"source_type": "SESSION", "path": folder}])
        process = next(node for node in result["nodes"] if node["observation_type"] == "PROCESS")
        research = next(node for node in result["nodes"] if node["source_record_id"].startswith("evidence:"))
        self.assertNotEqual(process["time_domain"], research["time_domain"])
        self.assertTrue(research["time_domain"].startswith("RESEARCH_MONOTONIC:"))
        self.assertEqual(result["sources"][0]["research_session_clock_alignment"], "NOT_ESTABLISHED")

    def test_session_reader_is_pinned_and_optional_source_appearance_is_refused(self):
        from blackbox_core.session_view import SchemaV1Reader
        folder = self.root / "legacy-race"
        folder.mkdir()
        with closing(sqlite3.connect(folder / "session.sqlite3")) as db:
            db.executescript("""
                CREATE TABLE metadata(schema_version INTEGER, session_id TEXT, pid INTEGER,
                    started_utc TEXT, ended_utc TEXT, exit_code TEXT, probe TEXT);
                CREATE TABLE samples(seq INTEGER PRIMARY KEY,elapsed_ms INTEGER,rss_bytes INTEGER,
                    cpu_percent REAL,num_threads INTEGER,read_bytes INTEGER,write_bytes INTEGER,children_count INTEGER);
                INSERT INTO metadata VALUES(1,'SYNTHETIC_LEGACY',123,'2026-01-01',NULL,'COMPLETED','FIXTURE');
                INSERT INTO samples VALUES(1,0,100,1.,1,0,0,0);
            """)
        second = self.root / "valid-v2"
        second.mkdir()
        writer = SessionV2Writer(second, pid=456, created=2., name="UNHASHED_NEW_SOURCE", origin_ns=1_000_000_000)
        writer.finish("COMPLETED")
        opened = []
        def late_v2(path, **kwargs):
            opened.append(path.name)
            shutil.copyfile(second / "session-v2.sqlite3", folder / "session-v2.sqlite3")
            return SchemaV1Reader(path, **kwargs)
        with patch("blackbox_core.session_view.SchemaV1Reader", side_effect=late_v2):
            with self.assertRaisesRegex(ValueError, "^SOURCE_CHANGED$"):
                normal.normalize_sources([{"source_type": "SESSION", "path": folder}])
        self.assertEqual(opened, ["session.sqlite3"])
        (folder / "session-v2.sqlite3").unlink()
        normalized = normal.normalize_sources([{"source_type": "SESSION", "path": folder}])
        (folder / "research.sqlite3").write_bytes(b"NEW_OPTIONAL_SOURCE")
        with self.assertRaisesRegex(ValueError, "^SOURCE_CHANGED$"):
            normal.revalidate_sources(normalized)


if __name__ == "__main__":
    unittest.main()
