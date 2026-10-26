"""Real EventPipe and Windows ETL decode. No fake events certify the engine."""
from __future__ import annotations
import argparse
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from unittest.mock import patch
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from blackbox_core.decoder_service import decode_file
from blackbox_core.decoder_index import read_index, file_hash


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--helper", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    helper = options.helper.resolve(strict=True)
    output = options.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    fixture = ROOT / "tools/decoder-fixture/DecoderFixture.csproj"
    subprocess.run(["dotnet", "build", str(fixture), "-c", "Release", "-o", str(output / "fixture")],
                   check=True, timeout=180)
    trace = output / "fixture.nettrace"
    env = {**os.environ, "DOTNET_EnableEventPipe": "1", "DOTNET_EventPipeOutputPath": str(trace),
           "DOTNET_EventPipeCircularMB": "10", "DOTNET_EventPipeOutputStreaming": "1",
           "DOTNET_EventPipeConfig": "Microsoft-Windows-DotNETRuntime:0x19:5,BlackBox-Decoder-QA:0xFFFFFFFFFFFFFFFF:5,Microsoft-DotNETCore-SampleProfiler:0x0:5"}
    fixture_run = subprocess.run(["dotnet", str(output / "fixture/DecoderFixture.dll")], env=env,
                                capture_output=True, text=True, check=True, timeout=60)
    require(trace.is_file() and trace.stat().st_size > 0, "REAL_NETTRACE_NOT_RECORDED")
    digest = file_hash(trace)
    index = output / "eventpipe.sqlite3"
    with patch("blackbox_core.decoder_service.helper_path", return_value=helper):
        meta = decode_file(trace, index)
    require(meta["status"] == "DECODED", "REAL_NETTRACE_NOT_COMPLETELY_PARSED")
    require(meta["gc"]["gc_pairs"] >= 12, "REAL_GC_PAIRS_MISSING")
    require(meta["events_with_stacks"] > 0, "REAL_RECORDED_STACKS_MISSING")
    require(file_hash(trace) == digest, "INPUT_TRACE_WAS_MODIFIED")
    with closing(sqlite3.connect(index)) as db:
        markers = [json.loads(row[0]) for row in db.execute(
            "SELECT data FROM events WHERE provider='BlackBox-Decoder-QA'")]
    markers = [row for row in markers if row["payload"].get("label") == "BLACKBOX_REAL_EVENTPIPE_FIXTURE"]
    require({row["payload"].get("ordinal") for row in markers} == set(range(12)), "REAL_CUSTOM_PAYLOAD_INCOMPLETE")
    report = {"eventpipe": meta, "real_fixture_stdout": fixture_run.stdout,
              "input_sha256_before_and_after": digest, "result": "RUNNING"}
    if os.name == "nt":
        require(os.environ.get("GITHUB_ACTIONS") == "true", "ETW_QA_ONLY_ON_DISPOSABLE_RUNNER")
        spec = importlib.util.spec_from_file_location("bb_owned_etl_fixture", ROOT / "tools/fixtures/etl_header_fixture.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        etl = output / "owned.etl"
        proof = module.capture(etl)
        etl_index = output / "etl.sqlite3"
        with patch("blackbox_core.decoder_service.helper_path", return_value=helper):
            report["etl"] = decode_file(etl, etl_index)
        guid = str(UUID(bytes_le=bytes.fromhex(proof["provider_guid_bytes_le"])))
        with closing(sqlite3.connect(etl_index)) as db:
            events = [json.loads(row[0]) for row in db.execute("SELECT data FROM events WHERE pid=?", (proof["pid"],))]
        require(len([row for row in events if row.get("provider_guid") == guid and row.get("event_id") == 7]) == 12,
                "REAL_ETW_EVENTS_MISSING")
        report["etw_fixture"] = proof
    # Wrong-format input cannot get a fake success footer/index.
    bad = output / "broken.nettrace"
    bad.write_bytes(b"NOT_A_REAL_TRACE")
    with patch("blackbox_core.decoder_service.helper_path", return_value=helper):
        try: decode_file(bad, output / "invalid.sqlite3", timeout=30)
        except (OSError, ValueError): pass
        else: raise AssertionError("INVALID_TRACE_WAS_ACCEPTED")
    require(not (output / "invalid.sqlite3").exists(), "FAILED_INDEX_PUBLISHED")
    report["result"] = "PASS"
    (output / "decoder-qa.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("REAL_TRACEEVENT_DECODER_QA_PASS")


if __name__ == "__main__":
    main()
