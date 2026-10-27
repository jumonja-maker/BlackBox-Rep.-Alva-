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


def real_owned_eventpipe_qa(helper, output):
    """Real opt-in dotnet-trace guardian, independent decoder and journal review.

    Runs only on a disposable Windows CI worker with a pinned diagnostic tool.
    The result never establishes trace/session clock synchronization.
    """
    import shutil
    import time
    from blackbox_core.runtime_trace import DotnetTrace
    from blackbox_core.trace_clock_evidence import assess_trace_capture_journal

    require(shutil.which("dotnet-trace") is not None,
            "REAL_EVENTPIPE_GUARDIAN_QA_TOOL_NOT_INSTALLED")
    work = output / "owned-eventpipe"
    work.mkdir()
    managed = work / "managed"
    managed.mkdir()
    shutil.copyfile(ROOT / "tools/fixtures/ManagedRuntimeProbe/Program.cs",
                    managed / "Program.cs")
    (managed / "Probe.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
        '<OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework>'
        '</PropertyGroup></Project>', encoding="utf-8")
    (managed / "NuGet.Config").write_text(
        '<configuration><packageSources><clear /></packageSources></configuration>',
        encoding="utf-8")
    build = subprocess.run(
        ["dotnet", "build", "Probe.csproj", "-c", "Release", "-o", "out",
         "--verbosity", "quiet"], cwd=managed, capture_output=True,
        text=True, timeout=120)
    require(build.returncode == 0,
            "REAL_EVENTPIPE_QA_FIXTURE_BUILD_FAILED: " + (build.stdout + build.stderr)[-2000:])
    state = work / "state"
    state.mkdir()
    process = subprocess.Popen(
        ["dotnet", str(managed / "out/Probe.dll"), str(state), "30"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    trace = None
    try:
        deadline = time.monotonic() + 10
        while (not (state / "ready.json").exists() and process.poll() is None
               and time.monotonic() < deadline):
            time.sleep(.03)
        require((state / "ready.json").is_file() and process.poll() is None,
                "REAL_EVENTPIPE_QA_TARGET_NEVER_READY")
        target = json.loads((state / "ready.json").read_text(encoding="utf-8"))
        require(target.get("fixture") == "FIX-09_REAL_MANAGED_RUNTIME" and
                target.get("pid") == process.pid, "REAL_EVENTPIPE_QA_TARGET_ID_MISMATCH")
        captures = work / "captures"
        captures.mkdir()
        trace = DotnetTrace(captures, process.pid, seconds=2, profile="gc-collect")
        trace.start()
        deadline = time.monotonic() + 25
        captured = None
        while captured is None and time.monotonic() < deadline:
            captured = trace.poll()
            if captured is None:
                time.sleep(.05)
        require(captured is not None and captured.get("status") == "COMPLETED",
                "REAL_EVENTPIPE_GUARDIAN_DID_NOT_COMPLETE: " + repr(captured))
        require(process.poll() is None, "REAL_EVENTPIPE_QA_TARGET_EXITED_DURING_CAPTURE")
        journal = captures / captured["journal"]
        details = captured["details"]
        trace_file = captures / details["result"]["path"]
        require(trace_file.suffix == ".nettrace" and trace_file.is_file(),
                "REAL_EVENTPIPE_QA_NETTRACE_MISSING")
        digest = file_hash(trace_file)
        require(details["result"]["sha256"] == digest,
                "REAL_EVENTPIPE_QA_JOURNAL_DIGEST_MISMATCH")
        index = work / "eventpipe-index.sqlite3"
        with patch("blackbox_core.decoder_service.helper_path", return_value=helper):
            meta = decode_file(trace_file, index)
        require(meta["status"] == "DECODED" and meta["rows"] > 0 and
                meta["input_sha256"] == digest,
                "REAL_EVENTPIPE_QA_DECODE_OR_HASH_FAILED")
        review = assess_trace_capture_journal(index, journal)
        require(review["status"] == "HASH_MATCHED_QPC_BRACKETS_UNVERIFIED" and
                review["trace_to_blackbox_session_clock_alignment"] == "NOT_ESTABLISHED" and
                len(review["checked_clock_stages"]) == 3,
                "REAL_EVENTPIPE_QA_CLOCK_REVIEW_FAILED: " + repr(review))
        require(file_hash(trace_file) == digest, "REAL_EVENTPIPE_QA_INPUT_CHANGED")
        return {"status": "PASS_HASH_LINKED_CLOCK_UNVERIFIED", "sha256": digest,
                "decoded_rows": meta["rows"], "clock_review": review,
                "capture_complete": "UNKNOWN", "cross_session_alignment": "NOT_ESTABLISHED"}
    finally:
        if trace is not None:
            trace.stop()
        if process.poll() is None:
            (state / "stop.request").touch()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def real_owned_wpr_decoder_qa(helper, output):
    """Real WPR guardian ETL -> decoder -> digest and QPC journal review.

    The independent Windows shell job still tests TTL. A missing WPR tool or
    privilege is explicitly NOT_AVAILABLE, never a false ETL pass.
    """
    import time
    from blackbox_core.trace_owner import TraceSupervisor, _read
    from blackbox_core.trace_clock_evidence import assess_trace_capture_journal
    from blackbox_core.windows_research import privilege, wpr_tool

    if privilege().get("mode") != "ADMINISTRATOR" or not wpr_tool():
        return {"status": "NOT_AVAILABLE_NO_WPR_OR_ADMIN",
                "capture_complete": "UNKNOWN", "cross_session_alignment": "NOT_ESTABLISHED"}
    work = output / "owned-wpr"
    work.mkdir()
    trace = TraceSupervisor(work, seconds=2, max_output_bytes=256 * 1024 ** 2,
                            target={"pid": os.getpid(), "purpose": "OWNED_CI_QPC_QA"})
    try:
        trace.start()
        deadline = time.monotonic() + 25
        status = "RESERVED"
        while time.monotonic() < deadline:
            status = _read(trace.path).get("state")
            if status == "RECORDING":
                break
            require(trace.active, "REAL_WPR_QA_GUARDIAN_EXITED: " + status)
            time.sleep(.05)
        require(status == "RECORDING", "REAL_WPR_QA_NEVER_RECORDED")
        end = time.monotonic() + .3
        while time.monotonic() < end:
            sum(i * i for i in range(10000))
        trace.process.wait(timeout=85)  # Named capture TTL, never a global stop.
        captured = trace.poll()
        details = _read(trace.path)
        require(details.get("state") == "COMPLETED" and
                details.get("stop_reason") == "TTL_EXPIRED",
                "REAL_WPR_QA_TTL_NOT_CONFIRMED: " + repr(details.get("state")))
        source = work / details["result"]["path"]
        require(source.is_file() and source.suffix == ".etl" and
                0 < source.stat().st_size <= 256 * 1024 ** 2,
                "REAL_WPR_QA_ETL_NOT_WITHIN_DECODER_BUDGET")
        digest = file_hash(source)
        require(details["result"]["sha256"] == digest,
                "REAL_WPR_QA_JOURNAL_HASH_MISMATCH")
        index = work / "wpr-index.sqlite3"
        with patch("blackbox_core.decoder_service.helper_path", return_value=helper):
            meta = decode_file(source, index)
        require(meta["status"] == "DECODED" and meta["rows"] > 0 and
                meta["input_sha256"] == digest,
                "REAL_WPR_QA_ETL_DECODE_OR_HASH_FAILED")
        review = assess_trace_capture_journal(index, trace.path)
        require(review["status"] == "HASH_MATCHED_QPC_BRACKETS_UNVERIFIED" and
                review["trace_to_blackbox_session_clock_alignment"] == "NOT_ESTABLISHED" and
                len(review["checked_clock_stages"]) == 4,
                "REAL_WPR_QA_CLOCK_REVIEW_FAILED: " + repr(review))
        require(file_hash(source) == digest, "REAL_WPR_QA_INPUT_CHANGED")
        return {"status": "PASS_HASH_LINKED_CLOCK_UNVERIFIED", "sha256": digest,
                "decoded_rows": meta["rows"], "clock_review": review,
                "capture_complete": "UNKNOWN", "cross_session_alignment": "NOT_ESTABLISHED",
                "guardian_status": captured.get("status") if captured else "UNKNOWN"}
    finally:
        if trace.active:
            trace.stop()


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
    # GC allocation event stacks are NOT sampled CPU stacks. Require actual
    # Microsoft-DotNETCore-SampleProfiler Thread/Sample and reconcile counts.
    profiles = meta.get("profiles", {})
    require(profiles.get("cpu_profiler_samples_recorded", 0) > 0,
            "REAL_CPU_PROFILER_SAMPLES_MISSING")
    require(profiles.get("cpu_stack_groups_indexed", 0) > 0,
            "REAL_CPU_STACK_PROFILE_MISSING")
    require(profiles["cpu_profiler_samples_with_stacks"] > 0,
            "REAL_CPU_STACK_FRAMES_MISSING")
    require(profiles["gc_summary_groups"] > 0, "REAL_GC_AGGREGATES_MISSING")
    require(profiles["cpu_sample_interval_and_cpu_percent"] == "NOT_ESTABLISHED",
            "CPU_SAMPLE_COUNT_MISLABELLED_AS_CPU_TIME")
    sample_page = read_index(index, mode="cpu_stacks", limit=1)
    require(sample_page["rows"] and
            sample_page["rows"][0]["event"]["recorded_sample_count"] > 0,
            "REAL_CPU_STACK_GROUP_UNREADABLE")
    gc_page = read_index(index, mode="gc_summary")
    require(any(r["event"]["kind"] == "GC_ELAPSED_NOT_PAUSE" and
                r["event"]["is_application_pause"] is False
                for r in gc_page["rows"]), "REAL_GC_ELAPSED_NOT_PAUSE_MISSING")
    # Actual TraceEvent timestamps: both a relative trace timestamp and a
    # QPC-derived DateTime UTC projection must survive the native helper.
    # This does NOT independently attest the UTC clock or align another session.
    clock = meta["calendar_clock"]
    require(clock["events_with_utc_projection"] > 0,
            "REAL_TRACEEVENT_CALENDAR_CLOCK_MISSING")
    require(clock["events_with_utc_projection"] +
            clock["events_without_utc_projection"] == meta["rows"],
            "REAL_TRACEEVENT_CLOCK_COVERAGE_MISMATCH")
    require(clock["trace_to_blackbox_session_clock_alignment"] == "NOT_ESTABLISHED",
            "TRACEEVENT_CALENDAR_CLOCK_MISREPRESENTED_AS_SESSION_ALIGNMENT")
    clock_page = read_index(index, mode="clock", limit=1)
    require(len(clock_page["rows"]) == 1, "REAL_UTC_MODE_EMPTY")
    clock_event = clock_page["rows"][0]["event"]
    require(clock_event["utc_time_ns"] > 1_000_000_000_000_000_000 and
            clock_event["utc_time_iso"].endswith("Z") and
            clock_event["utc_projection_quality"] == "TRACEEVENT_DERIVED_UTC_UNVERIFIED",
            "REAL_UTC_PROJECTION_INVALID")
    require(isinstance(clock_event.get("source_ticks"), str),
            "REAL_TRACE_SOURCE_TICKS_MISSING")
    require(file_hash(trace) == digest, "INPUT_TRACE_WAS_MODIFIED")
    with closing(sqlite3.connect(index)) as db:
        observed_profiler = db.execute(
            "SELECT count(*) FROM events WHERE provider='Microsoft-DotNETCore-SampleProfiler' "
            "AND name='Thread/Sample'").fetchone()[0]
        grouped_profiler = db.execute(
            "SELECT coalesce(sum(sample_count),0) FROM stack_profiles").fetchone()[0]
        paired_gc_intervals = db.execute(
            "SELECT coalesce(sum(interval_count),0) FROM gc_profiles "
            "WHERE kind='GC_ELAPSED_NOT_PAUSE'").fetchone()[0]
        require(observed_profiler == profiles["cpu_profiler_samples_recorded"],
                "REAL_CPU_PROFILER_INPUT_COUNT_MISMATCH")
        require(grouped_profiler + profiles["cpu_profiler_samples_omitted_from_groups"] ==
                profiles["cpu_profiler_samples_with_stacks"],
                "REAL_CPU_PROFILER_GROUP_COVERAGE_MISMATCH")
        require(paired_gc_intervals == meta["gc"]["gc_pairs"],
                "REAL_GC_PAIR_AGGREGATE_MISMATCH")
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
        report["owned_eventpipe"] = real_owned_eventpipe_qa(helper, output)
        report["owned_wpr"] = real_owned_wpr_decoder_qa(helper, output)
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
