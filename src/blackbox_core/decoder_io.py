"""Typed kernel disk/network projections; never classify by payload names alone."""
from __future__ import annotations

import ipaddress
import math

from .decoder_cpu import ETW_PROVIDER_GUID

IO_SCHEMA = "blackbox.trace-io/1"
_NETWORK_PARSERS = {
    "TRACEEVENT_TcpIpTraceData": ("TCP", "IPv4", {"receive"}),
    "TRACEEVENT_TcpIpSendTraceData": ("TCP", "IPv4", {"send"}),
    "TRACEEVENT_TcpIpV6TraceData": ("TCP", "IPv6", {"receive"}),
    "TRACEEVENT_TcpIpV6SendTraceData": ("TCP", "IPv6", {"send"}),
    "TRACEEVENT_UdpIpTraceData": ("UDP", "IPv4", {"send", "receive"}),
    # The spelling is the actual public type in pinned TraceEvent 4.0.0.
    "TRACEEVENT_UpdIpV6TraceData": ("UDP", "IPv6", {"send", "receive"}),
}


def _int(value, minimum=0, maximum=2**63 - 1):
    return type(value) is int and minimum <= value <= maximum


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value < 1e15


def _require(value):
    if not value:
        raise ValueError("INVALID_TYPED_IO_CONTRACT")


def validate_io_observation(row):
    """Validate optional new fields while retaining older trace-index support."""
    value = row.get("io_observation")
    if value is None:
        return None
    _require(type(value) is dict and value.get("schema") == IO_SCHEMA and
             row.get("provider_guid") == ETW_PROVIDER_GUID and
             type(row.get("event_id")) is int and row["event_id"] == 65535 and
             _int(row.get("opcode"), 0, 255) and _int(row.get("version"), 0, 255))
    if value.get("kind") == "disk":
        _require(set(value) == {"schema", "source", "parser", "kind", "operation", "transferred_bytes",
             "elapsed_ms", "response_qpc_ticks", "counter_frequency_hz", "duration_basis",
             "start_boundary_observed", "device_busy_time_established"})
        _require(value["source"] == "ETW_KERNEL_DISK_IO" and value["parser"] == "TRACEEVENT_DISK_IO" and
                 row["opcode"] in (10, 11) and row["version"] in (2, 3) and
                 value["operation"] == ("read" if row["opcode"] == 10 else "write") and
                 row.get("name") == ("DiskIO/Read" if row["opcode"] == 10 else "DiskIO/Write") and
                 _int(value["transferred_bytes"], 0, 2**32 - 1) and _number(value["elapsed_ms"]) and
                 _int(value["response_qpc_ticks"]) and _int(value["counter_frequency_hz"], 1, 10**12) and
                 value["duration_basis"] == "COMPLETION_EVENT_REPORTED_QPC_DURATION" and
                 value["start_boundary_observed"] is False and value["device_busy_time_established"] is False)
        expected = value["response_qpc_ticks"] * 1000 / value["counter_frequency_hz"]
        _require(abs(value["elapsed_ms"] - expected) <= max(0.000001, expected * 1e-10))
        for key, actual in (("TransferSize", value["transferred_bytes"]),
                            ("HighResResponseTime", value["response_qpc_ticks"])):
            if key in row["payload"]:
                _require(type(row["payload"][key]) is int and row["payload"][key] == actual)
    elif value.get("kind") == "network":
        _require(set(value) == {"schema", "source", "parser", "kind", "protocol", "operation", "family",
            "transferred_bytes", "source_address", "destination_address", "source_port", "destination_port",
            "address_status", "byte_count_scope", "packet_contents"})
        _require(value["source"] == "ETW_KERNEL_NETWORK" and value["parser"] in _NETWORK_PARSERS and
                 value["protocol"] in ("TCP", "UDP") and row["opcode"] in (10, 11, 26, 27) and
                 row["version"] in (1, 2) and
                 value["operation"] == ("send" if row["opcode"] in (10, 26) else "receive") and
                 value["family"] == ("IPv4" if row["opcode"] < 26 else "IPv6") and
                 _int(value["transferred_bytes"], 0, 2**32 - 1) and
                 _int(value["source_port"], 0, 65535) and _int(value["destination_port"], 0, 65535) and
                 value["byte_count_scope"] == "THIS_RECORDED_KERNEL_EVENT_NOT_PROCESS_OR_LINK_TOTAL" and
                 value["packet_contents"] == "NOT_COLLECTED")
        protocol, address_family, operations = _NETWORK_PARSERS[value["parser"]]
        _require(value["protocol"] == protocol and value["family"] == address_family and
                 value["operation"] in operations and
                 (address_family != "IPv6" or row["version"] == 2))
        family = "TcpIp" if value["protocol"] == "TCP" else "UdpIp"
        action = "Send" if value["operation"] == "send" else "Recv"
        suffix = "IPV6" if value["family"] == "IPv6" else ""
        # KernelTraceEventParser names IPv4 events without an explicit suffix.
        _require(row.get("name") == f"{family}/{action}{suffix}")
        present = True
        for key in ("source_address", "destination_address"):
            address = value[key]
            if address is None:
                present = False
                continue
            _require(type(address) is str and 1 <= len(address) <= 128)
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                raise ValueError("INVALID_TYPED_IO_ADDRESS") from None
            _require(parsed.version == (4 if value["family"] == "IPv4" else 6))
        _require(value["address_status"] == ("DECODED" if present else "INCOMPLETE_EVIDENCE"))
        for key, actual in (("size", value["transferred_bytes"]),
                            ("sport", value["source_port"]), ("dport", value["destination_port"])):
            if key in row["payload"]:
                _require(type(row["payload"][key]) is int and row["payload"][key] == actual)
    else:
        raise ValueError("INVALID_TYPED_IO_KIND")
    return value


def validate_io_clock(row, engine_header):
    """A disk event's unit conversion must agree with its source trace header."""
    value = row.get("io_observation")
    if value is None or value.get("kind") != "disk":
        return
    frequency = engine_header.get("trace_counter_frequency_hz") if type(engine_header) is dict else None
    if not _int(frequency, 1, 10**12) or frequency != value["counter_frequency_hz"]:
        raise ValueError("TYPED_DISK_IO_SOURCE_FREQUENCY_MISMATCH")
