"""QA-validator format fixtures, never substitutes for actual Windows ETL."""
from copy import deepcopy
import unittest

from tools.qa_deep_trace_io import KERNEL, analyze_events


ORACLE = {"pid": 123, "io_tid": 71, "created_100ns": 133000000000000000,
          "tcp4_port": 10001, "tcp6_port": 10002, "udp4_port": 10003, "udp6_port": 10004}
FILE = r"D:\controlled QA\probe\controlled-io.bin"
IMAGE = r"D:\controlled QA\build\deep-probe.exe"


def event(name, *, payload=None, tid=71):
    return {"ordinal": 1, "pid": 123, "tid": tid, "process_instance": 4,
            "provider_guid": KERNEL, "event_id": 65535, "name": name,
            "opcode": 0, "version": 2, "payload": payload or {}, "frames": []}


def fixture(*, network=True):
    rows = [event("Process/DCStop", payload={"ImageFileName": "deep-probe.exe"}, tid=-1),
            event("Thread/DCStop"),
            event("FileIO/Write", payload={"FileName": FILE, "FileKey": 1234, "IoSize": 4096})]
    disk = event("DiskIO/Write", payload={"FileName": FILE, "FileKey": 1234,
                                            "TransferSize": 4096, "ElapsedTimeMSec": 2.5})
    disk.update(opcode=11, version=3)
    disk["io_observation"] = {"schema": "blackbox.trace-io/1", "source": "ETW_KERNEL_DISK_IO",
        "parser": "TRACEEVENT_DISK_IO", "kind": "disk", "operation": "write",
        "transferred_bytes": 4096, "elapsed_ms": 2.5, "response_qpc_ticks": 25000,
        "counter_frequency_hz": 10000000,
        "duration_basis": "COMPLETION_EVENT_REPORTED_QPC_DURATION",
        "start_boundary_observed": False, "device_busy_time_established": False}
    rows.append(disk)
    if network:
        for protocol in ("TCP", "UDP"):
            for version in (4, 6):
                family = "TcpIp" if protocol == "TCP" else "UdpIp"
                address = "::1" if version == 6 else "127.0.0.1"
                key = protocol.lower() + str(version) + "_port"
                row = event(family + "/Send" + ("IPV6" if version == 6 else ""),
                            payload={"size": 1, "sport": ORACLE[key], "dport": ORACLE[key]})
                row.update(opcode=26 if version == 6 else 10, version=2)
                row["io_observation"] = {"schema": "blackbox.trace-io/1", "source": "ETW_KERNEL_NETWORK",
                    "parser": "TRACEEVENT_UpdIpV6TraceData" if protocol == "UDP" and version == 6 else
                              "TRACEEVENT_TcpIpV6SendTraceData" if version == 6 else
                              "TRACEEVENT_UdpIpTraceData" if protocol == "UDP" else "TRACEEVENT_TcpIpSendTraceData",
                    "kind": "network", "protocol": protocol, "operation": "send", "family": "IPv" + str(version),
                    "transferred_bytes": 1, "source_address": address, "destination_address": address,
                    "source_port": ORACLE[key], "destination_port": ORACLE[key], "address_status": "DECODED",
                    "byte_count_scope": "THIS_RECORDED_KERNEL_EVENT_NOT_PROCESS_OR_LINK_TOTAL",
                    "packet_contents": "NOT_COLLECTED"}
                rows.append(row)
    return rows


class DeepTraceIoAcceptanceContracts(unittest.TestCase):
    def analyze(self, rows, *, frequency=10000000):
        return analyze_events(lambda: iter(rows), ORACLE,
                              {"trace_counter_frequency_hz": frequency},
                              target_image=IMAGE, known_file=FILE)

    def test_independent_units_endpoint_and_file_oracles_agree(self):
        result = self.analyze(fixture())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["disk"]["known_file_events"], 1)
        self.assertEqual(result["disk"]["examples"][0]["elapsed_ms"], 2.5)
        self.assertTrue(all(endpoint["status"] == "OBSERVED"
                            for endpoint in result["network"].values()))
        self.assertEqual(result["generic_live_creation_time_from_trace"], "NOT_ESTABLISHED")
        self.assertEqual(result["physical_device_busy_time"], "NOT_ESTABLISHED")

    def test_same_pid_with_another_trace_instance_is_rejected(self):
        rows = fixture()
        reused = deepcopy(rows[0])
        reused["process_instance"] = 5
        rows.append(reused)
        with self.assertRaisesRegex(AssertionError, "INSTANCE_MISSING_OR_AMBIGUOUS"):
            self.analyze(rows)

    def test_pid_header_and_correct_filename_do_not_replace_lifecycle_evidence(self):
        rows = fixture()[1:]
        with self.assertRaisesRegex(AssertionError, "PROCESS_LIFECYCLE"):
            self.analyze(rows)

    def test_known_file_from_wrong_issuing_thread_is_not_accepted(self):
        rows = fixture()
        rows[2]["tid"] = ORACLE["io_tid"] + 1
        with self.assertRaisesRegex(AssertionError, "KNOWN_FILE_IO_AND_ISSUING_THREAD"):
            self.analyze(rows)

    def test_matching_file_name_under_another_directory_is_not_same_object(self):
        rows = fixture()
        rows[2]["payload"]["FileName"] = r"D:\other\controlled-io.bin"
        with self.assertRaisesRegex(AssertionError, "KNOWN_FILE_IO_AND_ISSUING_THREAD"):
            self.analyze(rows)

    def test_correct_duration_cannot_use_frequency_from_another_trace(self):
        with self.assertRaisesRegex(ValueError, "FREQUENCY_MISMATCH"):
            self.analyze(fixture(), frequency=1000)

    def test_supported_actual_disk_event_requires_positive_typed_projection(self):
        rows = fixture()
        del rows[3]["io_observation"]
        with self.assertRaisesRegex(AssertionError, "DISK_EVENT_MISSING_TYPED_PROJECTION"):
            self.analyze(rows)

    def test_unrecorded_network_families_are_not_synthetic_passes(self):
        with self.assertRaisesRegex(AssertionError, "ACTUAL_TYPED_TCP_ENDPOINT_POSITIVE_CASE_REQUIRED"):
            self.analyze(fixture(network=False))

    def test_one_protocol_positive_does_not_replace_other_protocol(self):
        rows = fixture()[:6]  # TCP v4/v6 only, no UDP.
        with self.assertRaisesRegex(AssertionError, "ACTUAL_TYPED_UDP_ENDPOINT_POSITIVE_CASE_REQUIRED"):
            self.analyze(rows)

    def test_individual_missing_families_remain_explicit(self):
        rows = fixture()
        result = self.analyze(rows[:4] + [rows[4], rows[6]])  # TCP/UDP IPv4 only.
        for key in ("tcp6_port", "udp6_port"):
            endpoint = result["network"][key]
            self.assertEqual(endpoint["status"], "NOT_COLLECTED")
            self.assertEqual(endpoint["matched_events"], 0)
            self.assertEqual(endpoint["latency"], "NOT_ESTABLISHED_BY_NETWORK_METADATA")

    def test_udp_ipv6_fixture_cannot_masquerade_as_tcp_parser(self):
        rows = fixture()
        rows[-1]["io_observation"]["parser"] = "TRACEEVENT_TcpIpV6SendTraceData"
        with self.assertRaisesRegex(ValueError, "TYPED_IO"):
            self.analyze(rows)

    def test_unconfirmed_ipv6_layout_is_not_a_supported_positive_case(self):
        rows = fixture()
        rows = rows[:4] + [rows[4], rows[6]]
        row = event("UdpIp/SendIPV6", payload={"size": 1})
        row.update(opcode=26, version=1)
        rows.append(row)
        result = self.analyze(rows)
        self.assertEqual(result["network"]["udp6_port"]["status"], "NOT_COLLECTED")

    def test_recorded_target_family_must_match_known_native_port(self):
        rows = fixture()
        row = rows[4]
        row["payload"].update(sport=10050, dport=10051)
        row["io_observation"].update(source_port=10050, destination_port=10051)
        with self.assertRaisesRegex(AssertionError, "FIXTURE_NETWORK_PORT_MISMATCH"):
            self.analyze(rows)

    def test_file_activity_does_not_imply_specific_disk_completion_association(self):
        rows = fixture()
        rows[3].update(pid=999, tid=88, process_instance=50)
        result = self.analyze(rows)
        self.assertEqual(result["disk"]["typed_events"], 1)
        self.assertEqual(result["disk"]["fixture_thread_status"], "NOT_COLLECTED")
        self.assertEqual(result["disk"]["known_file_status"], "NOT_COLLECTED")


if __name__ == "__main__":
    unittest.main()
