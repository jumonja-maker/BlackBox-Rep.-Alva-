"""Typed I/O schema fixtures; no claim of native capture acceptance here."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from blackbox_core.decoder_index import PROTOCOL, build_index, read_index
from blackbox_core.decoder_io import IO_SCHEMA, validate_io_observation
from blackbox_core.deep_trace import KERNEL_GUID, build_trace_evidence


def disk_event():
    return {"type": "event", "ordinal": 1, "time_ms": 10.0, "pid": 123, "tid": 7,
        "process_instance": 1, "provider": "Windows Kernel", "provider_guid": KERNEL_GUID,
        "name": "DiskIO/Read", "event_id": 65535, "opcode": 10, "version": 3,
        "payload": {"TransferSize": 4096, "HighResResponseTime": 25000}, "frames": [],
        "io_observation": {"schema": IO_SCHEMA, "source": "ETW_KERNEL_DISK_IO",
            "parser": "TRACEEVENT_DISK_IO", "kind": "disk", "operation": "read",
            "transferred_bytes": 4096, "elapsed_ms": 2.5, "response_qpc_ticks": 25000,
            "counter_frequency_hz": 10000000,
            "duration_basis": "COMPLETION_EVENT_REPORTED_QPC_DURATION",
            "start_boundary_observed": False, "device_busy_time_established": False}}


def network_event(*, ipv6=False, udp=False):
    family = "UdpIp" if udp else "TcpIp"
    return {"type": "event", "ordinal": 1, "time_ms": 10.0, "pid": 123, "tid": 7,
        "process_instance": 1, "provider": "Windows Kernel", "provider_guid": KERNEL_GUID,
        "name": family + "/Send" + ("IPV6" if ipv6 else ""), "event_id": 65535,
        "opcode": 26 if ipv6 else 10, "version": 2,
        "payload": {"size": 123, "sport": 10001, "dport": 10002}, "frames": [],
        "io_observation": {"schema": IO_SCHEMA, "source": "ETW_KERNEL_NETWORK",
            "parser": "TRACEEVENT_UpdIpV6TraceData" if udp and ipv6 else
                      "TRACEEVENT_TcpIpV6SendTraceData" if ipv6 else
                      "TRACEEVENT_UdpIpTraceData" if udp else "TRACEEVENT_TcpIpSendTraceData",
            "kind": "network", "protocol": "UDP" if udp else "TCP", "operation": "send",
            "family": "IPv6" if ipv6 else "IPv4", "transferred_bytes": 123,
            "source_address": "::1" if ipv6 else "127.0.0.1",
            "destination_address": "::1" if ipv6 else "127.0.0.1",
            "source_port": 10001, "destination_port": 10002, "address_status": "DECODED",
            "byte_count_scope": "THIS_RECORDED_KERNEL_EVENT_NOT_PROCESS_OR_LINK_TOTAL",
            "packet_contents": "NOT_COLLECTED"}}


class DeepTypedIoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def index(self, row, *, frequency=10000000):
        source = self.root / "typed.jsonl"
        output = self.root / "typed.sqlite3"
        header = {"type": "header", "protocol": PROTOCOL, "input_sha256": "a" * 64,
                  "trace_counter_frequency_hz": frequency}
        footer = {"type": "footer", "protocol": PROTOCOL, "status": "DECODED", "rows": 1,
                  "decoder_reported_lost_events": 0}
        source.write_text("".join(json.dumps(x) + "\n" for x in (header, row, footer)), encoding="utf-8")
        build_index(source, output, input_sha256="a" * 64, format_name=".etl")
        return output

    def test_valid_disk_reports_observed_duration_not_invented_start_or_device_busy_time(self):
        p = self.index(disk_event())
        saved = read_index(p)["rows"][0]["event"]["io_observation"]
        self.assertEqual(saved["elapsed_ms"], 2.5)
        report = build_trace_evidence(p, {"pid": 123, "created_100ns": 133000000000000000},
                                      process_instance=1)
        io, = report["data"]["io_events"]
        self.assertEqual(io["latency_ms"], 2.5)
        self.assertEqual(io["trace_interval_start_ms"], 7.5)
        self.assertEqual(io["event_transfer_bytes"], 4096)
        self.assertFalse(io["start_boundary_observed"])
        self.assertFalse(io["typed_observation"]["device_busy_time_established"])
        self.assertIsNone(io["transfer_total_bytes"])

    def test_zero_duration_is_recorded_value_and_not_missing_interval_fill(self):
        row = disk_event()
        row["payload"]["HighResResponseTime"] = 0
        row["io_observation"].update(elapsed_ms=0.0, response_qpc_ticks=0)
        self.assertEqual(validate_io_observation(row)["elapsed_ms"], 0)

    def test_duration_cannot_conflict_with_qpc_ticks(self):
        row = disk_event(); row["io_observation"]["elapsed_ms"] = 25
        with self.assertRaisesRegex(ValueError, "TYPED_IO"):
            validate_io_observation(row)

    def test_duration_cannot_use_another_source_frequency(self):
        with self.assertRaisesRegex(ValueError, "FREQUENCY"):
            self.index(disk_event(), frequency=1000)

    def test_disk_provider_opcode_version_payload_and_boolean_fields_fail_closed(self):
        for where, key, value in (("row", "provider_guid", "00000000-0000-0000-0000-000000000000"),
                ("row", "opcode", 11), ("row", "version", 0), ("payload", "TransferSize", 7),
                ("io", "transferred_bytes", True), ("io", "elapsed_ms", float("nan")),
                ("io", "start_boundary_observed", True)):
            row = disk_event()
            subject = row if where == "row" else row["payload"] if where == "payload" else row["io_observation"]
            subject[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validate_io_observation(row)

    def test_tcp_udp_ipv4_ipv6_preserve_per_event_bytes(self):
        for ipv6 in (False, True):
            for udp in (False, True):
                row = network_event(ipv6=ipv6, udp=udp)
                result = validate_io_observation(row)
                self.assertEqual(result["transferred_bytes"], 123)
                self.assertEqual(result["packet_contents"], "NOT_COLLECTED")
                self.assertNotIn("latency_ms", result)

    def test_network_address_family_and_port_are_validated(self):
        for key, value in (("source_address", "::1"), ("source_port", 65536),
                           ("transferred_bytes", -1), ("operation", "receive")):
            row = network_event(); row["io_observation"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_io_observation(row)

    def test_network_parser_cannot_claim_another_protocol_family_or_operation(self):
        for ipv6, udp, parser in (
                (True, True, "TRACEEVENT_TcpIpV6SendTraceData"),
                (True, True, "TRACEEVENT_UdpIpTraceData"),
                (False, False, "TRACEEVENT_TcpIpTraceData"),
                (True, False, "TRACEEVENT_TcpIpV6TraceData")):
            row = network_event(ipv6=ipv6, udp=udp)
            row["io_observation"]["parser"] = parser
            with self.subTest(parser=parser), self.assertRaises(ValueError):
                validate_io_observation(row)

    def test_udp_ipv6_public_addresses_do_not_require_generic_payload_fields(self):
        row = network_event(ipv6=True, udp=True)
        self.assertNotIn("saddr", row["payload"])
        self.assertNotIn("daddr", row["payload"])
        saved = read_index(self.index(row))["rows"][0]["event"]["io_observation"]
        self.assertEqual(saved["parser"], "TRACEEVENT_UpdIpV6TraceData")
        self.assertEqual((saved["source_address"], saved["destination_address"]), ("::1", "::1"))

    def test_unconfirmed_ipv6_version_is_not_promoted_to_typed_observation(self):
        row = network_event(ipv6=True, udp=True)
        row["version"] = 1
        with self.assertRaises(ValueError):
            validate_io_observation(row)

    def test_missing_address_remains_explicitly_partial(self):
        row = network_event()
        row["io_observation"].update(source_address=None, address_status="INCOMPLETE_EVIDENCE")
        self.assertIsNone(validate_io_observation(row)["source_address"])

    def test_missing_typed_projection_does_not_promote_payload_count(self):
        row = network_event(); del row["io_observation"]
        self.assertIsNone(validate_io_observation(row))

    def test_unknown_typed_kind_and_extra_fields_are_rejected(self):
        row = disk_event(); row["io_observation"]["kind"] = "arbitrary"
        with self.assertRaises(ValueError):
            validate_io_observation(row)
        row = deepcopy(disk_event()); row["io_observation"]["claims_complete"] = True
        with self.assertRaises(ValueError):
            validate_io_observation(row)
