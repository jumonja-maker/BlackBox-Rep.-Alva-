"""Validate real BB-DEEP-001 ETL I/O using the packaged offline decoder.

The controlled fixture's retained process handle and before/after identity are
external QA evidence. TraceEvent ProcessIndex is only a trace-local identity;
this tool never treats it as a creation FILETIME or proves general live joins.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import ipaddress
import json
import math
import ntpath
import os
from pathlib import Path
import sqlite3
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from blackbox_core.decoder_io import validate_io_clock, validate_io_observation
from tools.qa_deep_inspection import file_hash, require, require_hosted_windows, save

KERNEL = "9e814aad-3204-11d2-9a82-006008a86939"
MAX_EVENTS = 250000


def windows_path(value):
    if not isinstance(value, str):
        return ""
    if value.startswith("\\??\\"):
        value = value[4:]
    return ntpath.normcase(ntpath.normpath(value))


def analyze_events(row_source, oracle, engine, *, target_image, known_file):
    """Bounded streaming analysis; fixture-format unit tests are not native proof."""
    pid, io_tid = oracle["pid"], oracle["io_tid"]
    instances, process_images, thread_instances, file_instances = set(), set(), set(), set()
    file_keys = set()
    known_file_count = 0

    def scan():
        for count, row in enumerate(row_source(), 1):
            require(count <= MAX_EVENTS, "QA_IO_EVENT_BUDGET_EXCEEDED")
            yield row

    for row in scan():
        if row.get("provider_guid") != KERNEL or row.get("pid") != pid:
            continue
        instance = row.get("process_instance")
        if type(instance) is not int or instance < 0:
            continue
        instances.add(instance)
        payload, name = row.get("payload", {}), row.get("name", "")
        if name in ("Process/Start", "Process/DCStart", "Process/DCStop"):
            image = payload.get("ImageFileName", "")
            if ntpath.basename(windows_path(image)) == ntpath.basename(windows_path(target_image)):
                process_images.add(instance)
        if name in ("Thread/Start", "Thread/DCStart", "Thread/DCStop") and row.get("tid") == io_tid:
            thread_instances.add(instance)
        if (name in ("FileIO/Read", "FileIO/Write") and row.get("tid") == io_tid and
                windows_path(payload.get("FileName")) == windows_path(known_file)):
            file_instances.add(instance)
            known_file_count += 1
            key = payload.get("FileKey")
            if type(key) is int and key > 0:
                file_keys.add(key)
    require(len(instances) == 1, "CONTROLLED_TRACE_PROCESS_INSTANCE_MISSING_OR_AMBIGUOUS")
    instance = next(iter(instances))
    require(instance in process_images, "TRACE_PROCESS_LIFECYCLE_IMAGE_EVIDENCE_REQUIRED")
    require(instance in thread_instances, "TRACE_ISSUING_THREAD_LIFECYCLE_EVIDENCE_REQUIRED")
    require(instance in file_instances and known_file_count > 0,
            "KNOWN_FILE_IO_AND_ISSUING_THREAD_NOT_OBSERVED")

    disk = {"eligible_events": 0, "typed_events": 0, "positive_transfer_events": 0,
            "fixture_thread_events": 0, "known_file_events": 0, "examples": []}
    endpoints = {key: {"protocol": protocol, "family": family, "known_port": oracle[key],
                       "source_family_events": 0, "fixture_family_events": 0,
                       "matched_events": 0, "observed_transfer_bytes": 0}
                 for key, protocol, family in (("tcp4_port", "TCP", "IPv4"),
                    ("tcp6_port", "TCP", "IPv6"), ("udp4_port", "UDP", "IPv4"),
                    ("udp6_port", "UDP", "IPv6"))}
    for row in scan():
        if row.get("provider_guid") != KERNEL:
            continue
        name, payload = row.get("name", ""), row.get("payload", {})
        typed = validate_io_observation(row)
        if name in ("DiskIO/Read", "DiskIO/Write") and row.get("version") in (2, 3):
            disk["eligible_events"] += 1
            require(typed is not None and typed["kind"] == "disk",
                    "REAL_SUPPORTED_DISK_EVENT_MISSING_TYPED_PROJECTION")
            validate_io_clock(row, engine)
            ticks, frequency = typed["response_qpc_ticks"], typed["counter_frequency_hz"]
            independently_converted = 1000 * ticks / frequency
            require(math.isclose(independently_converted, typed["elapsed_ms"], abs_tol=0.000001,
                                 rel_tol=1e-10), "REAL_DISK_QPC_DURATION_CONVERSION_MISMATCH")
            require(payload.get("TransferSize") == typed["transferred_bytes"],
                    "REAL_DISK_TRANSFER_SIZE_MISMATCH")
            if "ElapsedTimeMSec" in payload:
                require(math.isclose(payload["ElapsedTimeMSec"], typed["elapsed_ms"],
                                     abs_tol=0.000001, rel_tol=1e-10),
                        "REAL_DISK_NATIVE_ELAPSED_TIME_MISMATCH")
            disk["typed_events"] += 1
            disk["positive_transfer_events"] += typed["transferred_bytes"] > 0
            own_thread = (row.get("pid") == pid and row.get("process_instance") == instance and
                          row.get("tid") == io_tid)
            own_file = own_thread and (windows_path(payload.get("FileName")) == windows_path(known_file) or
                                        payload.get("FileKey") in file_keys)
            disk["fixture_thread_events"] += own_thread
            disk["known_file_events"] += own_file
            if len(disk["examples"]) < 4:
                disk["examples"].append({"ordinal": row.get("ordinal"), "operation": typed["operation"],
                    "transferred_bytes": typed["transferred_bytes"], "elapsed_ms": typed["elapsed_ms"],
                    "response_qpc_ticks": ticks, "counter_frequency_hz": frequency,
                    "fixture_issuing_thread": own_thread, "known_file_bound": own_file})
        if (name.startswith(("TcpIp/", "UdpIp/")) and row.get("opcode") in (10, 11, 26, 27)
                and row.get("version") in (1, 2) and
                (row["opcode"] < 26 or row["version"] == 2)):
            require(typed is not None and typed["kind"] == "network",
                    "REAL_SUPPORTED_NETWORK_EVENT_MISSING_TYPED_PROJECTION")
            key = ("tcp" if typed["protocol"] == "TCP" else "udp") + \
                  ("4_port" if typed["family"] == "IPv4" else "6_port")
            endpoint = endpoints[key]
            endpoint["source_family_events"] += 1
            if row.get("pid") != pid or row.get("process_instance") != instance:
                continue
            endpoint["fixture_family_events"] += 1
            if endpoint["known_port"] not in (typed["source_port"], typed["destination_port"]):
                continue
            require(typed["address_status"] == "DECODED" and
                    all(ipaddress.ip_address(typed[field]).is_loopback
                        for field in ("source_address", "destination_address")),
                    "CONTROLLED_NETWORK_ENDPOINT_NOT_LOOPBACK")
            require(typed["transferred_bytes"] > 0 and typed["packet_contents"] == "NOT_COLLECTED",
                    "CONTROLLED_NETWORK_TRANSFER_METADATA_INVALID")
            endpoint["matched_events"] += 1
            endpoint["observed_transfer_bytes"] += typed["transferred_bytes"]
    require(disk["typed_events"] > 0 and disk["positive_transfer_events"] > 0,
            "ACTUAL_TYPED_DISK_TRANSFER_AND_DURATION_POSITIVE_CASE_REQUIRED")
    for endpoint in endpoints.values():
        if endpoint["fixture_family_events"]:
            require(endpoint["matched_events"] > 0, "RECORDED_FIXTURE_NETWORK_PORT_MISMATCH")
        endpoint["status"] = "OBSERVED" if endpoint["matched_events"] else "NOT_COLLECTED"
        endpoint["latency"] = "NOT_ESTABLISHED_BY_NETWORK_METADATA"
        endpoint["byte_count_scope"] = "SUM_OF_MATCHED_RECORDED_EVENTS_NOT_UNIQUE_LINK_BYTES"
    disk["fixture_thread_status"] = "OBSERVED" if disk["fixture_thread_events"] else "NOT_COLLECTED"
    disk["known_file_status"] = "OBSERVED" if disk["known_file_events"] else "NOT_COLLECTED"
    return {"status": "PASS", "trace_process_instance": instance, "pid": pid, "io_tid": io_tid,
            "known_file_read_write_events": known_file_count, "disk": disk, "network": endpoints,
            "identity_basis": "OWNED_LIVE_FIXTURE_CONTINUITY_PLUS_TRACE_LIFECYCLE_IMAGE_THREAD_AND_FILE",
            "generic_live_creation_time_from_trace": "NOT_ESTABLISHED",
            "capture_completeness": "NOT_ESTABLISHED", "physical_device_busy_time": "NOT_ESTABLISHED",
            "network_policy_limit": "UNOBSERVED_PROTOCOL_FAMILIES_REMAIN_NOT_COLLECTED",
            "packet_contents": "NOT_COLLECTED", "root_cause": "NOT_ESTABLISHED"}


def run(args):
    require_hosted_windows()
    from blackbox_core.decoder_service import decode_file
    qa = args.qa_root.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"status": "FAIL", "source_sha": os.environ.get("GITHUB_SHA"),
              "scope": "REAL_PROFILE_ETL_DECODED_BY_PACKAGED_HELPER"}
    try:
        require(len(report["source_sha"] or "") == 40 and
                all(c in "0123456789abcdef" for c in report["source_sha"]), "EXACT_SOURCE_SHA_REQUIRED")
        acceptance = json.loads((qa / "acceptance.json").read_text(encoding="utf-8"))
        oracle = json.loads((qa / "probe/oracle.json").read_text(encoding="utf-8"))
        profile = acceptance["profiling"]
        require(acceptance["source_sha"] == report["source_sha"] and acceptance["status"] == "PASS" and
                profile["capture_status"] == "COMPLETED" and profile["native_capture_executed"] is True,
                "EXACT_SOURCE_SUCCESSFUL_NATIVE_PROFILE_REQUIRED")
        target = profile["target_instance"]
        require(target["pid"] == oracle["pid"] and target["created_100ns"] == oracle["created_100ns"] and
                all(profile[phase]["pid"] == target["pid"] and
                    profile[phase]["created_100ns"] == target["created_100ns"]
                    for phase in ("workload_before", "workload_after")),
                "PROFILE_TARGET_CONTINUITY_NOT_CONFIRMED")
        require(all(profile["workload_after"][field] > profile["workload_before"][field]
                    for field in ("heartbeat", "io_cycles", "network_cycles")),
                "PROFILE_CONTROLLED_WORKLOAD_DID_NOT_PROGRESS")
        trace = qa / "profile-controlled.etl"
        require(0 < trace.stat().st_size <= 256 * 1024 * 1024, "REAL_PROFILE_TRACE_SIZE_BUDGET")
        digest = file_hash(trace)
        require(digest == profile["sha256"] and trace.stat().st_size == profile["bytes"],
                "PROFILE_TRACE_IDENTITY_MISMATCH")
        helper = args.helper.resolve(strict=True)
        package_manifest = helper.parent.parent / "_internal/blackbox-build.json"
        provenance = json.loads(package_manifest.read_text(encoding="utf-8"))
        require(provenance.get("source_sha") == report["source_sha"] and
                provenance.get("tracked_worktree_clean") is True,
                "PACKAGED_DECODER_SOURCE_PROVENANCE_MISMATCH")
        index = output / "decoded.sqlite3"
        with patch("blackbox_core.decoder_service.helper_path", return_value=helper):
            meta = decode_file(trace, index, timeout=180)
        require(meta["status"] == "DECODED" and 0 < meta["rows"] <= MAX_EVENTS and
                meta["input_sha256"] == digest, "REAL_PROFILE_NOT_COMPLETELY_DECODED_WITHIN_BUDGET")
        with closing(sqlite3.connect(index.as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("PRAGMA query_only=ON")
            require(db.execute("PRAGMA integrity_check").fetchone() == ("ok",), "PROFILE_INDEX_CORRUPTED")

            def records():
                for raw, in db.execute("SELECT data FROM events ORDER BY id"):
                    require(len(raw) <= 1536 * 1024, "PROFILE_INDEX_ROW_BUDGET")
                    yield json.loads(raw)

            report["observations"] = analyze_events(records, oracle, meta["engine"],
                target_image=target["image_path"], known_file=str(qa / "probe/controlled-io.bin"))
        require(file_hash(trace) == digest, "ORIGINAL_PROFILE_CHANGED_DURING_DECODE")
        report.update(status="PASS", trace_sha256=digest, trace_bytes=trace.stat().st_size,
                      decoder_sha256=file_hash(helper), index_sha256=file_hash(index),
                      decoded_rows=meta["rows"], original_unchanged=True,
                      decoder_reported_lost_events=meta.get("decoder_reported_lost_events"))
    except BaseException as error:
        report.update(error=type(error).__name__, reason=str(error)[:1500])
    finally:
        save(output / "typed-io-acceptance.json", report)
    print("DEEP_TYPED_IO_" + report["status"], report.get("reason", ""), flush=True)
    return 0 if report["status"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qa-root", required=True, type=Path)
    parser.add_argument("--helper", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
