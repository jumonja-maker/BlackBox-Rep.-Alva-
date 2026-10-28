"""Synthetic offline contracts; real Windows acceptance is a separate CI job."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
from threading import Event
import time
import unittest

from blackbox_core.decoder_index import PROTOCOL, build_index
from blackbox_core.deep_trace import build_trace_evidence, verify_local_symbols, KERNEL_GUID


TARGET = {"pid": 123, "created_100ns": 133_000_000_000_000_000, "image_path": "C:\\fixture.exe"}


def row(ordinal, instance=1, *, provider="Synthetic", name="Event", payload=None, frames=None):
    return {"type": "event", "ordinal": ordinal, "time_ms": float(ordinal),
            "pid": 123, "tid": 7, "process_instance": instance,
            "provider": provider, "name": name, "payload": payload or {}, "frames": frames or []}


class DeepHistoricalTraceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def index(self, rows, *, loss=0, status="DECODED"):
        source = self.root / "events.jsonl"
        output = self.root / "index.sqlite3"
        records = [{"type": "header", "protocol": PROTOCOL, "input_sha256": "a" * 64}, *rows,
            {"type": "footer", "protocol": PROTOCOL, "status": status, "rows": len(rows),
             "decoder_reported_lost_events": loss}]
        source.write_text("".join(json.dumps(x) + "\n" for x in records), encoding="utf-8")
        build_index(source, output, input_sha256="a" * 64, format_name=".etl")
        return output

    def test_pid_matching_never_automatically_attaches_historical_events(self):
        p = self.index([row(1)])
        result = build_trace_evidence(p, TARGET)
        self.assertEqual(result["status"], "INCOMPLETE_EVIDENCE")
        self.assertEqual(result["next_action"], "SELECT_TRACE_PROCESS_INSTANCE")
        self.assertEqual(result["data"]["events"], [])
        self.assertEqual(result["data"]["candidate_instances"][0]["process_instance"], 1)
        self.assertEqual(result["data"]["live_target_relation"], "NOT_ESTABLISHED")

    def test_same_pid_different_trace_instances_never_mix(self):
        p = self.index([row(1, 1), row(2, 2), row(3, 1)])
        result = build_trace_evidence(p, TARGET, process_instance=1)
        self.assertEqual([r["ordinal"] for r in result["data"]["events"]], [1, 3])
        self.assertEqual(len(result["data"]["candidate_instances"]), 2)
        self.assertEqual(result["data"]["live_target_relation"], "NOT_ESTABLISHED")

    def test_missing_process_lifetime_not_recovered_from_pid(self):
        p = self.index([row(1, None), row(2, 2)])
        result = build_trace_evidence(p, TARGET, process_instance=2)
        self.assertEqual(result["data"]["coverage"]["events_without_instance"], 1)
        self.assertEqual([r["ordinal"] for r in result["data"]["events"]], [2])

    def test_historical_stack_remains_original_and_index_read_only(self):
        frames = [{"name": "RecordedFunction", "address": "0x1234"}]
        p = self.index([row(1, frames=frames)])
        before = hashlib.sha256(p.read_bytes()).hexdigest()
        result = build_trace_evidence(p, TARGET, process_instance=1)
        event = result["data"]["events"][0]
        self.assertEqual(event["frames"], frames)
        self.assertEqual(event["source"], "HISTORICAL_TRACE")
        self.assertEqual(event["live_thread_relation"], "NOT_ESTABLISHED")
        self.assertEqual(before, hashlib.sha256(p.read_bytes()).hexdigest())

    def test_filters_and_row_budget_preserve_omitted_counts(self):
        p = self.index([row(i) for i in range(1, 11)])
        result = build_trace_evidence(p, TARGET, process_instance=1, tid=7,
                                      start_ms=3, end_ms=8, limit=2)
        self.assertEqual([r["ordinal"] for r in result["data"]["events"]], [3, 4])
        self.assertEqual(result["data"]["coverage"]["selected_events"], 5)
        self.assertEqual(result["data"]["coverage"]["omitted_events"], 3)

    def test_spoofed_network_name_not_projected_without_kernel_guid(self):
        p = self.index([row(1, name="TcpIp/Send", payload={"size": 123})])
        result = build_trace_evidence(p, TARGET, process_instance=1)
        self.assertEqual(result["data"]["io_events"], [])

    def test_network_and_disk_fields_do_not_invent_latency_packets_or_totals(self):
        a = row(1, name="TcpIp/Send", payload={"size": 123, "saddr": "127.0.0.1", "sport": 8080})
        b = row(2, name="DiskIO/Read", payload={"TransferSize": 4096, "HighResResponseTime": 1234})
        for item in (a, b):
            item["provider_guid"] = KERNEL_GUID
        p = self.index([a, b])
        result = build_trace_evidence(p, TARGET, process_instance=1)
        net, disk = result["data"]["io_events"]
        self.assertEqual(net["recorded_size_fields"], {"size": 123})
        self.assertIsNone(net["transfer_total_bytes"])
        self.assertEqual(net["packet_contents"], "NOT_COLLECTED")
        self.assertEqual(disk["recorded_timing_fields"], {"HighResResponseTime": 1234})
        self.assertIsNone(disk["latency_ms"])
        self.assertEqual(disk["physical_disk_activity"], "NOT_ESTABLISHED")

    def test_unknown_loss_and_truncation_remain_explicit(self):
        p = self.index([row(1)], loss=None, status="TRUNCATED")
        result = build_trace_evidence(p, TARGET, process_instance=1)
        self.assertIn("CAPTURE_LOSS_UNKNOWN_OR_IMPORT_INCOMPLETE", result["limitations"])
        self.assertIsNone(result["data"]["capture_complete"])

    def test_cancel_and_deadline_prevent_read(self):
        p = self.index([row(1)])
        cancel = Event(); cancel.set()
        with self.assertRaises(InterruptedError):
            build_trace_evidence(p, TARGET, cancel_event=cancel)
        with self.assertRaises(TimeoutError):
            build_trace_evidence(p, TARGET, deadline=time.monotonic() - 1)

    def test_untrusted_view_cannot_masquerade_as_index_table(self):
        p = self.index([row(1)])
        with closing(sqlite3.connect(p)) as db:
            db.execute("ALTER TABLE events RENAME TO old_events")
            db.execute("CREATE VIEW events AS SELECT * FROM old_events")
            db.commit()
        with self.assertRaisesRegex(ValueError, "TABLES"):
            build_trace_evidence(p, TARGET, process_instance=1)

    def test_rejects_pid_only_target_and_boolean_instance(self):
        with self.assertRaises(ValueError):
            build_trace_evidence(self.root / "missing", {"pid": 123})
        with self.assertRaises(ValueError):
            build_trace_evidence(self.root / "missing", TARGET, process_instance=True)

    def test_local_symbol_failure_does_not_claim_match(self):
        result = verify_local_symbols(self.root / "missing.exe", self.root / "missing.pdb")
        self.assertEqual(result["status"], "INCOMPLETE_EVIDENCE")
        self.assertEqual(result["data"]["live_module_binding"], "NOT_ESTABLISHED")
        self.assertIsNone(result["data"]["symbol"])

    def test_local_symbol_cancel_and_invalid_rva(self):
        cancel = Event(); cancel.set()
        with self.assertRaises(InterruptedError):
            verify_local_symbols("missing.exe", "missing.pdb", cancel_event=cancel)
        with self.assertRaises(ValueError):
            verify_local_symbols("missing.exe", "missing.pdb", rva=True)
