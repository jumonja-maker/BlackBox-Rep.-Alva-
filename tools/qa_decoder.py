"""Real EventPipe and Windows ETL decode. No fake events certify the engine."""
from __future__ import annotations
import argparse
import copy
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from threading import Event
import time
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


def require_bounded_trace_qpc(review, meta, stages):
    """Numbers inside guardian bounds are weak evidence, NEVER clock alignment."""
    clock = meta.get("calendar_clock", {})
    seen = clock.get("source_counter_events_observed")
    missing = clock.get("source_counter_events_missing")
    require(type(seen) is int and seen > 0 and type(missing) is int and
            seen + missing == meta["rows"], "REAL_TRACE_QPC_COUNTER_COVERAGE_INVALID")
    require(review.get("status") == "HASH_MATCHED_QPC_BRACKETS_UNVERIFIED" and
            review.get("trace_qpc_range_quality") in (
                "NUMERIC_RANGE_WITHIN_CAPTURE_BRACKETS_UNVERIFIED",
                "PARTIAL_COUNTER_RANGE_WITHIN_BRACKETS_UNVERIFIED") and
            review.get("trace_qpc_counter_events_observed") == seen and
            len(review.get("checked_clock_stages", [])) == stages,
            "REAL_TRACE_QPC_CAPTURE_WINDOW_MISMATCH: " + repr(review))
    require(review.get("trace_to_blackbox_session_clock_alignment") == "NOT_ESTABLISHED",
            "TRACE_QPC_RANGE_IS_NOT_SESSION_CLOCK_ALIGNMENT")


def start_clock_session(folder, pid):
    """A real session writer and real native clock probe, no clock overrides."""
    import psutil
    import time
    from blackbox_core.session_v2 import SessionV2Writer
    folder.mkdir()
    writer = SessionV2Writer(folder, pid=pid, created=psutil.Process(pid).create_time(),
                             name="OWNED_CLOCK_ACCEPTANCE", origin_ns=time.monotonic_ns())
    require(writer._ready.wait(5) and not writer.failure, "REAL_SESSION_CLOCK_WRITER_NOT_READY")
    return writer


def require_real_session_alignment(index, journal, session_path, output):
    """Real same-session correlation plus deliberately invalid evidence copies."""
    from blackbox_core.decoder_alignment import ALIGNED, assess_session_alignment, project_event_time
    result = assess_session_alignment(index, journal, session_path)
    require(result.get("status") == ALIGNED,
            "REAL_SESSION_CLOCK_NOT_CORRELATED: " + repr(result))
    first = read_index(index, limit=1)["rows"][0]["event"]
    projection = project_event_time(result, first)
    require(projection.get("status") == ALIGNED and
            projection["session_relative_lower_ns"] <= projection["session_relative_upper_ns"] and
            projection["uncertainty_width_ns"] <= 10_000_000 and
            not result["utc_used_for_mapping"], "REAL_EVENT_CLOCK_INTERVAL_INVALID")
    original = json.loads(journal.read_text(encoding="utf-8"))
    changed = copy.deepcopy(original)
    for anchor in changed["clock_anchors"].values():
        if "clock_identity" in anchor:
            anchor["clock_identity"]["boot_id"] = "00000000-0000-0000-0000-000000000001"
    bad_boot = output / "negative-changed-boot.trace.json"
    bad_boot.write_text(json.dumps(changed), encoding="utf-8")
    boot_result = assess_session_alignment(index, bad_boot, session_path)
    require(boot_result.get("status") == "NOT_ESTABLISHED" and
            boot_result.get("reason") == "BOOT_ID_MISMATCH", "CHANGED_BOOT_WAS_CORRELATED")
    changed = copy.deepcopy(original)
    for anchor in changed["clock_anchors"].values():
        if "qpc_frequency_hz" in anchor:
            anchor["qpc_frequency_hz"] *= 2
    bad_frequency = output / "negative-changed-frequency.trace.json"
    bad_frequency.write_text(json.dumps(changed), encoding="utf-8")
    frequency_result = assess_session_alignment(index, bad_frequency, session_path)
    require(frequency_result.get("status") == "NOT_ESTABLISHED", "CHANGED_FREQUENCY_WAS_CORRELATED")
    other = start_clock_session(output / "negative-other-session", os.getpid())
    other.finish("COMPLETED")
    session_result = assess_session_alignment(index, journal, other.path)
    require(session_result.get("reason") == "CAPTURE_SESSION_BINDING_MISMATCH_OR_ABSENT",
            "DIFFERENT_SESSION_WAS_CORRELATED")
    proof = {"status": "PASS_REAL_BOUNDED_LOCAL_CLOCK_CORRELATION",
             "alignment": result, "first_event_projection": projection,
             "negative_evidence_copy_checks": {"different_boot": boot_result,
                 "different_frequency": frequency_result, "different_session": session_result},
             "capture_complete": "UNKNOWN", "evidence_authenticity": "LOCAL_NOT_CRYPTOGRAPHICALLY_ATTESTED"}
    (output / "session-alignment-qa.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")
    return proof


def real_native_failure_qa(helper, traces, output):
    """Damage copies of actually recorded traces, cancel a real helper, retry.

    Timing-independent cancellation is requested immediately after the native
    process is spawned. The process itself, decode supervisor and cleanup are
    real; no fake helper or simulated ETW API is substituted.
    """
    from blackbox_core.decoder_limits import failure_details
    from blackbox_core.optional_jobs import OwnedProcess

    root = output / "native-reliability"
    root.mkdir()
    report = {"status": "RUNNING", "platform": sys.platform,
              "damage_source": "COPIES_OF_SUCCESSFULLY_DECODED_REAL_CAPTURES", "traces": []}

    def save():
        (root / "native-failure-qa.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    save()
    for source, successful_meta in traces:
        work = root / source.suffix.lstrip(".")
        work.mkdir()
        digest = file_hash(source)
        original_bytes = source.stat().st_size
        require(original_bytes > 128 and successful_meta["status"] == "DECODED",
                "DAMAGE_QA_REQUIRES_REAL_NONEMPTY_GOOD_TRACE")
        evidence = {"source_name": source.name, "source_sha256": digest,
                    "source_bytes": original_bytes, "cases": []}
        report["traces"].append(evidence)
        for variant in ("zeroed-real-header", "truncated-real-prefix"):
            damaged = work / (variant + source.suffix)
            if variant == "zeroed-real-header":
                shutil.copyfile(source, damaged)
                with damaged.open("r+b") as stream:
                    stream.write(b"\0" * 64)
                damage = {"operation": "OVERWRITE_FIRST_64_BYTES_OF_REAL_COPY_WITH_ZERO",
                          "original_bytes_retained_after_offset": 64}
            else:
                with source.open("rb") as original, damaged.open("xb") as stream:
                    stream.write(original.read(64))
                damage = {"operation": "KEEP_FIRST_64_BYTES_OF_REAL_TRACE", "retained_bytes": 64}
            destination = work / (variant + ".sqlite3")
            damaged_sha = file_hash(damaged)
            item = {"case": variant, "input_name": damaged.name,
                    "input_sha256": damaged_sha, "input_bytes": damaged.stat().st_size,
                    "damage": damage, "status": "RUNNING"}
            evidence["cases"].append(item)
            save()
            start = time.monotonic()
            with patch("blackbox_core.decoder_service.helper_path", return_value=helper):
                try:
                    result = decode_file(damaged, destination, timeout=20)
                except (OSError, ValueError, MemoryError) as exc:
                    item.update(status="CONTROLLED_FAILURE", failure=failure_details(exc),
                                published_index=destination.exists())
                    save()
                    require(not destination.exists(), "DAMAGED_NATIVE_TRACE_PUBLISHED_FAILED_INDEX")
                else:
                    item.update(status="CONTROLLED_PARTIAL" if result.get("status") == "TRUNCATED"
                                else "UNCLASSIFIED_ACCEPTED_DAMAGED_TRACE",
                                decoder_status=result.get("status"), rows=result.get("rows"),
                                capture_complete=result.get("capture_complete"),
                                published_index=destination.exists())
                    save()
                    # A clearly invalid header cannot receive a successful index.
                    # A truncated trace may be kept only as explicitly partial.
                    require(variant != "zeroed-real-header" and result.get("status") == "TRUNCATED"
                            and result.get("capture_complete") is None,
                            "DAMAGED_NATIVE_TRACE_NOT_EXPLICITLY_REJECTED_OR_PARTIAL: " + repr(item))
            item["duration_seconds"] = time.monotonic() - start
            require(file_hash(damaged) == damaged_sha, "DAMAGED_INPUT_COPY_WAS_MODIFIED")
            require(not list(work.glob(".decoder-building-*")), "DAMAGED_INDEX_SCRATCH_LEAKED")
            save()

        # Request cancellation at a deterministic observation boundary *after*
        # a genuine native helper exists, rather than before any work starts.
        cancel, owners, scratch = Event(), [], []

        def start_then_cancel(args, **kwargs):
            owner = OwnedProcess(args, **kwargs)
            owners.append(owner)
            scratch.append(Path(args[1]).parent)
            cancel.set()
            return owner

        destination = work / "cancelled.sqlite3"
        started = time.monotonic()
        cancelled = {"case": "cancel-after-real-helper-spawn", "status": "RUNNING"}
        evidence["cases"].append(cancelled)
        save()
        with patch("blackbox_core.decoder_service.helper_path", return_value=helper), \
             patch("blackbox_core.optional_jobs.OwnedProcess", side_effect=start_then_cancel):
            try:
                decode_file(source, destination, cancel=cancel, timeout=20)
            except InterruptedError as exc:
                cancelled.update(status="CANCELLED", failure=failure_details(exc))
            else:
                raise AssertionError("REAL_NATIVE_HELPER_CANCEL_IGNORED")
        cancelled.update(duration_seconds=time.monotonic()-started,
                         actual_helper_pids=[owner.process.pid for owner in owners],
                         helper_exit_codes=[owner.process.poll() for owner in owners],
                         private_scratch_removed=all(not p.exists() for p in scratch),
                         published_index=destination.exists())
        save()
        require(len(owners) == 1 and owners[0].process.poll() is not None and
                cancelled["private_scratch_removed"] and not destination.exists() and
                not list(work.glob(".decoder-building-*")), "CANCELLED_NATIVE_HELPER_OR_INDEX_LEAKED")
        with patch("blackbox_core.decoder_service.helper_path", return_value=helper):
            recovery = decode_file(source, work / "fresh-retry.sqlite3")
        require(recovery["status"] == "DECODED" and recovery["input_sha256"] == digest and
                recovery["rows"] == successful_meta["rows"], "NATIVE_FRESH_RETRY_DID_NOT_RECOVER")
        require(file_hash(source) == digest, "GOOD_NATIVE_TRACE_CHANGED_BY_FAILURE_QA")
        evidence.update(source_sha256_after=file_hash(source),
                        recovery={"status": recovery["status"], "rows": recovery["rows"],
                                  "partial_index_reused": False})
        save()
    report["status"] = "PASS_REAL_NATIVE_DAMAGE_CANCEL_RETRY"
    save()
    return report


def real_owned_eventpipe_qa(helper, output):
    """Real opt-in dotnet-trace guardian, independent decoder and journal review.

    Runs only on a disposable Windows CI worker with a pinned diagnostic tool.
    Adds bounded same-session QPC correlation, never UTC/cryptographic attestation.
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
        ["dotnet", str(managed / "out/Probe.dll"), str(state), "50"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    trace = None
    session_writer = None
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
        session_writer = start_clock_session(work / "session", process.pid)
        trace = DotnetTrace(captures, process.pid, seconds=2, profile="gc-collect",
                            session_path=session_writer.path)
        trace.start()
        deadline = time.monotonic() + 40
        captured = None
        while captured is None and time.monotonic() < deadline:
            captured = trace.poll()
            if captured is None:
                time.sleep(.05)
        if captured is None or captured.get("status") != "COMPLETED":
            # Fail closed. Show bounded collector diagnostics only on failure.
            log_path = next(captures.glob("eventpipe-*.log"), None)
            tail = (log_path.read_text(encoding="utf-8", errors="replace")[-1600:]
                    if log_path and log_path.is_file() else "COLLECTOR_LOG_UNAVAILABLE")
            raise AssertionError("REAL_EVENTPIPE_GUARDIAN_DID_NOT_COMPLETE: " +
                                 repr(captured) + "; tool_log_tail=" + repr(tail))
        require(process.poll() is None, "REAL_EVENTPIPE_QA_TARGET_EXITED_DURING_CAPTURE")
        journal = captures / captured["journal"]
        details = captured["details"]
        trace_file = captures / details["result"]["path"]
        require(trace_file.suffix == ".nettrace" and trace_file.is_file(),
                "REAL_EVENTPIPE_QA_NETTRACE_MISSING")
        digest = file_hash(trace_file)
        require(details["result"]["sha256"] == digest,
                "REAL_EVENTPIPE_QA_JOURNAL_DIGEST_MISMATCH")
        require(details["result"].get("stop_completion_status") == "TOOL_EXIT_OBSERVED",
                "REAL_EVENTPIPE_QA_TOOL_EXIT_NOT_CONFIRMED")
        index = work / "eventpipe-index.sqlite3"
        with patch("blackbox_core.decoder_service.helper_path", return_value=helper):
            meta = decode_file(trace_file, index)
        require(meta["status"] == "DECODED" and meta["rows"] > 0 and
                meta["input_sha256"] == digest,
                "REAL_EVENTPIPE_QA_DECODE_OR_HASH_FAILED")
        review = assess_trace_capture_journal(index, journal)
        require_bounded_trace_qpc(review, meta, 3)
        session_writer.finish("COMPLETED")
        alignment = require_real_session_alignment(index, journal, session_writer.path, work)
        require(file_hash(trace_file) == digest, "REAL_EVENTPIPE_QA_INPUT_CHANGED")
        return {"status": "PASS_HASH_LINKED_CLOCK_UNVERIFIED", "sha256": digest,
                "decoded_rows": meta["rows"], "clock_review": review,
                "capture_complete": "UNKNOWN", "cross_session_alignment": "NOT_ESTABLISHED",
                "same_session_alignment": alignment}
    finally:
        if trace is not None:
            trace.stop()
        if session_writer is not None:
            session_writer.finish("COMPLETED")
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
    session_writer = start_clock_session(work / "session", os.getpid())
    trace = TraceSupervisor(work, seconds=2, max_output_bytes=256 * 1024 ** 2,
                            target={"pid": os.getpid(), "purpose": "OWNED_CI_QPC_QA"},
                            session_path=session_writer.path)
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
        require_bounded_trace_qpc(review, meta, 4)
        session_writer.finish("COMPLETED")
        alignment = require_real_session_alignment(index, trace.path, session_writer.path, work)
        require(file_hash(source) == digest, "REAL_WPR_QA_INPUT_CHANGED")
        return {"status": "PASS_HASH_LINKED_CLOCK_UNVERIFIED", "sha256": digest,
                "decoded_rows": meta["rows"], "clock_review": review,
                "capture_complete": "UNKNOWN", "cross_session_alignment": "NOT_ESTABLISHED",
                "same_session_alignment": alignment,
                "guardian_status": captured.get("status") if captured else "UNKNOWN"}
    finally:
        if trace.active:
            trace.stop()
        session_writer.finish("COMPLETED")


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
    reliability_traces = [(trace, meta)]
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
        reliability_traces.append((etl, report["etl"]))
        report["owned_eventpipe"] = real_owned_eventpipe_qa(helper, output)
        report["owned_wpr"] = real_owned_wpr_decoder_qa(helper, output)
    report["native_failure_acceptance"] = real_native_failure_qa(helper, reliability_traces, output)
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
