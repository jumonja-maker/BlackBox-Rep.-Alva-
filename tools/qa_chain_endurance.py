"""Actual 5h30 R60 scheduler lifecycle on standard GitHub-hosted Windows.

Two production engines own the actual work: 331 real closed-ETL reads at
60-second intervals and a long OBSERVE adapter owning ResearchSession. The QA
controller only drives the native workload and inspects progress; it never ticks
or stops the successful recorder outside its adapter. An expected cancellation
ends OBSERVE after both independently persisted spans reach 5h30. This does not
replace the existing two one-hour profiles or turn CANCELLED into COMPLETED.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from blackbox_core.chain_qa import (actual_invocations, definition, file_hash, independent_journal,
                                    link, require, save, source_proof)
from tools.qa_wave02_endurance import (
    MAX_OUTPUT_BYTES, MAX_RSS, MAX_RSS_GROWTH, MAX_SESSION_BYTES, NativeController,
    actual_progress, command, directory_bytes, inspect_live, policy, verify_saved,
)
from tools.qa_wave02_fixture import WaveProbe, build

REQUESTED_SECONDS = 19800
ITERATIONS = 331
INTERVAL_SECONDS = 60
MAX_ACTIVE_SECONDS = 20400


def output_bytes(root):
    """Bound the new invocation folders without changing old recording guards."""
    total = directories = files_seen = 0
    for parent, children, files in os.walk(root, followlinks=False):
        directories += 1
        require(directories <= 12000, "R60_ENDURANCE_INVOCATION_DIRECTORY_BUDGET")
        for name in children + files:
            require(not (Path(parent) / name).is_symlink(), "R60_ENDURANCE_OUTPUT_SYMLINK")
        for name in files:
            files_seen += 1
            require(files_seen <= 5000, "R60_ENDURANCE_OUTPUT_FILE_BUDGET")
            try:
                total += (Path(parent) / name).stat().st_size
            except FileNotFoundError:
                pass  # An owned SQLite writer may close its transient WAL.
    return total


def verify_engine_history(records, trace_sha256):
    invocations = actual_invocations(records, "workflow.load_source")
    require(len(invocations) == ITERATIONS, "R60_ENDURANCE_ALL_ACTUAL_INVOCATIONS_REQUIRED")
    starts = [context["started_monotonic_ns"] for context, _receipt in invocations]
    intervals_ns = [second - first for first, second in zip(starts, starts[1:])]
    span = (starts[-1] - starts[0]) / 10**9
    require(span >= REQUESTED_SECONDS and all(second > first for first, second in zip(starts, starts[1:])),
            "R60_ENDURANCE_PERSISTED_INVOCATION_SPAN_TOO_SHORT")
    require(all(interval >= INTERVAL_SECONDS * 1_000_000_000 for interval in intervals_ns),
            "R60_ENDURANCE_PERSISTED_INVOCATION_CADENCE_TOO_SHORT")
    require(all(receipt["status"] == "COMPLETED" and receipt["execution_started"] is True and
                receipt["cleanup"]["confirmed"] is True for _context, receipt in invocations),
            "R60_ENDURANCE_REAL_RECEIPT_OR_CLEANUP_FAILED")
    results = [event["data"] for event in records if event.get("event") == "node.result" and
               event.get("node_id") == "repeat-etl-read"]
    intents = [event["data"] for event in records if event.get("event") == "node.intent" and
               event.get("node_id") == "repeat-etl-read"]
    require(len(results) == len(intents) == ITERATIONS and
            len({row["node_run_id"] for row in results}) == ITERATIONS and
            len({row["iteration"] for row in results}) == ITERATIONS and
            {row["node_run_id"] for row in results} == {row["node_run_id"] for row in intents},
            "R60_ENDURANCE_INTENT_RESULT_ITERATION_BINDING")
    for row in results:
        output = row["outputs"].get("source")
        require(row["state"] == "COMPLETED" and type(output) is list and len(output) == 1 and
                output[0]["kind"] == "TRACE" and output[0]["value"].get("sha256") == trace_sha256,
                "R60_ENDURANCE_ACTUAL_SOURCE_FINGERPRINT_MISSING")
    return {"requested_seconds": REQUESTED_SECONDS, "actual_invocations": len(invocations),
            "persisted_first_context_monotonic_ns": starts[0], "persisted_last_context_monotonic_ns": starts[-1],
            "persisted_invocation_span_seconds": span, "source_sha256": trace_sha256,
            "requested_interval_seconds": INTERVAL_SECONDS,
            "persisted_minimum_interval_seconds": min(intervals_ns) / 10**9,
            "persisted_maximum_interval_seconds": max(intervals_ns) / 10**9,
            "all_actual_intervals_at_least_requested": True,
            "intent_result_binding_verified": True, "all_actual_cleanup_acknowledgements": True,
            "scope": "ACTUAL_EXISTING_FILE_ADAPTER_CALLS_NOT_COLLECTOR_OR_JOB_UPTIME"}


def verify_observe_history(snapshot, records, repeat_records, cancel_requested_ns, expected_identity):
    """Independent persisted proof of a long production adapter and its stop.

    The requested graph is intentionally CANCELLED after the real 5h30 work.
    That product state remains CANCELLED even though this acceptance scenario
    passes and the underlying recording writer closed normally.
    """
    require(snapshot["state"] == "CANCELLED" and snapshot["cleanup"].get("confirmed") is True,
            "R60_ENDURANCE_LONG_OBSERVE_FALSE_COMPLETION_OR_UNKNOWN_CLEANUP")
    rows = {row["node_id"]: row for row in snapshot["nodes"]}
    observed, selected = rows["long-observe"], rows["long-observe-target"]
    require(selected["state"] == "COMPLETED" and
            all(selected["outputs"]["process"][0]["value"]["identity"][key] == value
                for key, value in expected_identity.items()),
            "R60_ENDURANCE_LONG_OBSERVE_PERSISTED_TARGET_MISMATCH")
    results = [event["data"] for event in records if event.get("event") == "node.result" and
               event.get("node_id") == "long-observe"]
    intents = [event["data"] for event in records if event.get("event") == "node.intent" and
               event.get("node_id") == "long-observe"]
    invocations = actual_invocations(records, "workflow.observe")
    require(len(results) == len(intents) == len(invocations) == 1 and
            results[0]["node_run_id"] == intents[0]["node_run_id"] == observed["node_run_id"],
            "R60_ENDURANCE_LONG_OBSERVE_MISSING_OR_REPLAYED_ACTUAL_CALL")
    context, receipt = invocations[0]
    cleanup = results[0]["cleanup"]
    stopped = cleanup.get("stop_result", {})
    require(results[0]["state"] == observed["state"] == "CANCELLED" and
            results[0]["component_status"] == receipt["status"] == "CANCELLED" and
            results[0]["execution_started"] is receipt["execution_started"] is True and
            cleanup.get("confirmed") is True and receipt["cleanup"].get("confirmed") is True and
            stopped.get("cleanup_required") is False and not stopped.get("errors") and
            stopped.get("state") == stopped.get("base_recording_state") == "COMPLETED",
            "R60_ENDURANCE_LONG_OBSERVE_ACTUAL_CANCELLATION_OR_STOP_ACK_MISSING")
    start_ns, end_ns = context["started_monotonic_ns"], results[0]["ended_monotonic_ns"]
    repeats = actual_invocations(repeat_records, "workflow.load_source")
    first_read, last_read = repeats[0][0]["started_monotonic_ns"], repeats[-1][0]["started_monotonic_ns"]
    require(type(cancel_requested_ns) is int and type(end_ns) is int and
            start_ns <= first_read <= last_read <= cancel_requested_ns <= end_ns and
            end_ns - start_ns >= REQUESTED_SECONDS * 10**9 and
            type(receipt.get("duration_ns")) is int and receipt["duration_ns"] >= REQUESTED_SECONDS * 10**9,
            "R60_ENDURANCE_REPEAT_NOT_WITHIN_PERSISTED_LONG_OBSERVE_INVOCATION")
    output = results[0]["outputs"].get("session", [])
    require(type(output) is list and len(output) == 1 and output[0]["kind"] == "SESSION" and
            output[0]["value"].get("recording_state") == "CANCELLED" and
            len(output[0]["value"].get("files", [])) == 3,
            "R60_ENDURANCE_LONG_OBSERVE_RESULT_REFERENCE_MISSING")
    return {"workflow_state": "CANCELLED", "node_state": "CANCELLED", "receipt_status": receipt["status"],
        "expected_workflow_state": "CANCELLED", "expected_cancellation_scenario": True,
        "actual_invocations": 1, "run_id": snapshot["run_id"], "node_run_id": observed["node_run_id"],
        "context_started_monotonic_ns": start_ns, "result_ended_monotonic_ns": end_ns,
        "actual_invocation_span_seconds": (end_ns - start_ns) / 10**9,
        "receipt_duration_ns": receipt["duration_ns"], "cancel_requested_monotonic_ns": cancel_requested_ns,
        "first_repeat_started_monotonic_ns": first_read, "last_repeat_started_monotonic_ns": last_read,
        "all_repeat_calls_within_observe": True, "target_identity": expected_identity,
        "cleanup": cleanup, "engine_cleanup": snapshot["cleanup"],
        "recording_source_sha256": output[0]["value"]["sha256"],
        "scope": "ACTUAL_LONG_RUNNING_PRODUCTION_OBSERVE_ADAPTER_NOT_EXTERNAL_TICKING"}


def run(args):
    identity = source_proof(args.source_sha)
    from blackbox_core.chain_adapters import ChainRuntime, build_catalog
    from blackbox_core.chain_engine import WorkflowEngine
    from blackbox_core.chain_store import WorkflowRunStore
    from blackbox_core.deep_native import capture_identity
    from blackbox_core.optional_jobs import OwnedProcess
    from blackbox_core.research_worker import ResearchSession
    from tools.qa_schedule_capture import OwnedScheduleCapture
    import psutil

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    proof = {"schema": "blackbox.r60.endurance-qa/1", "status": "FAIL", "source_sha": args.source_sha,
        "source_identity": identity, "requested_seconds": REQUESTED_SECONDS,
        "scope": "TWO_PRODUCTION_ENGINES_REAL_REPEAT_AND_LONG_OBSERVE_ADAPTER_OWNERSHIP",
        "physical_windows_10_11": "NOT_TESTED", "physical_secure_desktop": "NOT_TESTED",
        "gui_endurance": "NOT_TESTED", "eight_hour_acceptance": False,
        "sampler_or_recorder_limits_changed": False, "actions_artifacts": False}
    fixture = capture = session = controller = engine = engine_thread = None
    observe_engine = observe_thread = observe_store = None
    engine_result, engine_errors, observe_result, observe_errors, created_sessions = [], [], [], [], []
    writer = journal = None
    maxima = {"writer_queue_depth": 0, "event_queue_depth": 0, "ring_accounted_bytes": 0,
              "ring_samples": 0, "self_rss_bytes": 0, "self_threads": 0,
              "recording_bytes": 0, "output_bytes": 0}
    try:
        executable = args.probe.resolve(strict=True) if args.probe else build(output / "build", args.source_sha)
        executable_hash = file_hash(executable)
        fixture = WaveProbe(executable, output / "target")
        target = capture_identity(fixture.process.pid)
        expected = {"pid": target.pid, "created_100ns": target.created_100ns}
        require(expected == {key: fixture.ready[key] for key in expected}, "R60_ENDURANCE_EXACT_NATIVE_IDENTITY")
        capture_root = output / "initial-capture"
        capture_root.mkdir()
        capture = OwnedScheduleCapture(capture_root)
        proof["capture_start"] = capture.start()
        file_done = fixture.command("file", "file_done")
        require(file_done["ok"] is True and file_done["acl_restored"] is True,
                "R60_ENDURANCE_ACTUAL_FILE_OR_ACL_CLEANUP")
        fixture.send("burst")
        begun = fixture.receive("burst_begin", timeout=10)
        done = fixture.receive("burst_done", timeout=20)
        require(all(row.get("pid") == target.pid and row.get("created_100ns") == target.created_100ns
                    for row in (begun, done)) and
                done["worker_threads"] == 4 and done["worker_exit_verified"] is True and
                done["allocated_bytes"] == 64 * 1024**2 and done["io_bytes"] > 0 and
                done["start_qpc"] == begun["start_qpc"] and
                done["end_qpc"] - begun["start_qpc"] >= fixture.ready["qpc_frequency"] * 6,
                "R60_ENDURANCE_INITIAL_REAL_WORKLOAD")
        captured = capture.stop()
        require(captured["status"] == "CAPTURED" and not capture.active,
                "R60_ENDURANCE_INITIAL_CAPTURE_CLEANUP_UNCONFIRMED")
        proof["capture_stop"] = captured
        trace = capture_root / captured["path"]
        trace_hash = file_hash(trace)
        require(0 < trace.stat().st_size <= 256 * 1024**2, "R60_ENDURANCE_INITIAL_ETL_BUDGET")
        capture = None
        def research_factory(output_root=None):
            # This factory runs inside the production OBSERVE adapter. Only
            # metadata is configured here; attach/start/tick/stop remain owned
            # by _direct_observe throughout the actual 5h30 recording.
            actual = ResearchSession(output_root)
            command(actual, "configure", scenario="BB-R60-5H30-SCHEDULER-LIFECYCLE", scenario_version="1",
                workload="owned-six-second-cpu-memory-file-burst-every-300s-v1", target_version=executable_hash)
            created_sessions.append(actual)
            return actual
        runtime = ChainRuntime(output_root=output / "recordings", research_factory=research_factory)
        observe_workflow = definition([
            {"node_id": "long-observe-target", "tool_id": "process_select", "budget_seconds": 5,
             "parameters": {"pid": target.pid}},
            {"node_id": "long-observe", "tool_id": "observe", "budget_seconds": 21540,
             "parameters": {"duration_seconds": 21500, "policy": policy("STANDARD")}}], [
                link("long-observe-target", "process", "long-observe", "process")],
            identity="5h30-owned-observe", seconds=21600, workers=1)
        observe_store = WorkflowRunStore.create(output / "observe-runs", observe_workflow)
        observe_engine = WorkflowEngine(observe_workflow, catalog=build_catalog(runtime),
                                       store=observe_store, runtime=runtime)
        def execute_observe():
            try:
                observe_result.append(observe_engine.run())
            except BaseException as error:
                observe_errors.append(error)
        observe_thread = threading.Thread(target=execute_observe,
                                          name="r60-long-observe-engine", daemon=True)
        observe_thread.start()
        setup_deadline = time.monotonic() + 30
        while True:
            require(not observe_errors, "R60_ENDURANCE_OBSERVE_START_EXCEPTION: " +
                    (str(observe_errors[0])[:500] if observe_errors else ""))
            require(observe_thread.is_alive(), "R60_ENDURANCE_OBSERVE_ENDED_BEFORE_ACTUAL_RECORDING")
            session = runtime.research
            if session is not None and session.probe.active and session.probe.total_samples >= 1:
                break
            require(time.monotonic() < setup_deadline, "R60_ENDURANCE_OBSERVE_ADAPTER_DID_NOT_START")
            threading.Event().wait(.05)
        folder = Path(session.probe.session_folder).resolve(strict=True)
        require(len(created_sessions) == 1 and session is created_sessions[0] and
                session.interval_ms == 1000 and session.context["run_identity"]["process_identity"] == expected,
                "R60_ENDURANCE_SAMPLER_CADENCE_OR_IDENTITY_CHANGED")
        writer, journal = session.probe._store.v2, session.probe._store._journal
        inspect_live(session, [], maxima)
        proof["observe_run_id"] = observe_store.run_id
        workflow = definition([{"node_id": "repeat-etl-read", "kind": "REPEAT", "tool_id": "load_source",
            "parameters": {"kind": "TRACE", "path": str(trace)}, "repeat_count": ITERATIONS,
            "repeat_interval_seconds": INTERVAL_SECONDS, "budget_seconds": 5}], [],
            identity="5h30-lifecycle", seconds=21600, workers=2)
        store = WorkflowRunStore.create(output / "runs", workflow)
        engine = WorkflowEngine(workflow, catalog=build_catalog(), store=store)
        def execute():
            try:
                engine_result.append(engine.run())
            except BaseException as error:
                engine_errors.append(error)
        engine_thread = threading.Thread(target=execute, name="r60-actual-endurance-engine", daemon=True)
        # Its own adapter has already published the first recorder sample.
        # Starting REPEAT now places every read within the long OBSERVE call.
        engine_thread.start()
        controller = NativeController(fixture)
        me = psutil.Process()
        started = time.monotonic()
        next_check, next_log, next_burst, next_state = started, started, started + 10, started + 45
        sampled_rss_baseline = None
        state_checks, minute_count = 0, 0
        cpu_start = me.cpu_times()
        while True:
            now = time.monotonic()
            require(now - started <= MAX_ACTIVE_SECONDS, "R60_ENDURANCE_COMPOSITIONAL_WATCHDOG")
            require(fixture.process.poll() is None, "R60_ENDURANCE_OWNED_TARGET_EXITED")
            require(not engine_errors, "R60_ENDURANCE_ENGINE_EXCEPTION: " +
                    (str(engine_errors[0])[:500] if engine_errors else ""))
            require(not observe_errors and observe_thread.is_alive() and not observe_result,
                    "R60_ENDURANCE_LONG_OBSERVE_ENDED_BEFORE_EXPECTED_CANCELLATION")
            controller.poll()
            if now >= next_burst and engine_thread.is_alive() and controller.thread is None:
                controller.start()
                next_burst = now + 300
            if now >= next_state and controller.thread is None:
                actual = fixture.command("state")
                require(actual["pid"] == target.pid and actual["created_100ns"] == target.created_100ns,
                        "R60_ENDURANCE_NATIVE_ORACLE_IDENTITY_CHANGED")
                state_checks += 1
                next_state = now + 60
            if now >= next_check:
                inspect_live(session, [], maxima)
                require(1000 <= session.interval_ms <= 5000,
                        "R60_ENDURANCE_UNEXPECTED_PRODUCTION_SAMPLER_CADENCE")
                progress = actual_progress(folder)
                rss = me.memory_info().rss
                maxima["self_rss_bytes"] = max(maxima["self_rss_bytes"], rss)
                maxima["self_threads"] = max(maxima["self_threads"], me.num_threads())
                maxima["recording_bytes"] = max(maxima["recording_bytes"], directory_bytes(folder))
                maxima["output_bytes"] = max(maxima["output_bytes"], output_bytes(output))
                if now - started >= 120 and sampled_rss_baseline is None:
                    sampled_rss_baseline = rss
                require(rss <= MAX_RSS and (sampled_rss_baseline is None or
                        rss - sampled_rss_baseline <= MAX_RSS_GROWTH) and
                        maxima["recording_bytes"] <= MAX_SESSION_BYTES and
                        maxima["output_bytes"] <= MAX_OUTPUT_BYTES + 256 * 1024**2,
                        "R60_ENDURANCE_MEASURED_RESOURCE_GUARD")
                if not engine_thread.is_alive():
                    require(len(engine_result) == 1 and engine_result[0]["state"] == "COMPLETED",
                            "R60_ENDURANCE_ENGINE_FINISHED_WITHOUT_ALL_INVOCATIONS")
                    if progress["span_seconds"] >= REQUESTED_SECONDS and controller.thread is None:
                        break
                next_check = now + 5
            if now >= next_log:
                minute_count += 1
                require(minute_count <= 345, "R60_ENDURANCE_PROGRESS_LOG_BUDGET")
                print("R60_ENDURANCE_PROGRESS " + json.dumps({"source_sha": args.source_sha,
                    "elapsed_seconds": round(now - started, 3), "recorded_samples": session.probe.total_samples,
                    "engine_state": engine.snapshot()["state"],
                    "observe_engine_state": observe_engine.snapshot()["state"],
                    "native_bursts": controller.completed,
                    "state_checks": state_checks, "rss_bytes": me.memory_info().rss}, sort_keys=True), flush=True)
                next_log = now + 60
            threading.Event().wait(.2)
        engine_thread.join(timeout=5)
        controller.join()
        require(not engine_thread.is_alive() and controller.completed >= REQUESTED_SECONDS // 300 and
                state_checks >= 300, "R60_ENDURANCE_REAL_WORKLOAD_COVERAGE")
        records, journal_proof = independent_journal(store.folder)
        proof["engine"] = verify_engine_history(records, trace_hash)
        proof["engine_journal"] = journal_proof
        require(observe_thread.is_alive() and not observe_result and not observe_errors,
                "R60_ENDURANCE_LONG_OBSERVE_NOT_RUNNING_AT_EXPECTED_STOP")
        cancel_requested_ns = time.monotonic_ns()
        observe_engine.request_cancel()
        observe_thread.join(timeout=30)
        require(not observe_thread.is_alive() and not observe_errors and len(observe_result) == 1,
                "R60_ENDURANCE_LONG_OBSERVE_CANCEL_NOT_ACKNOWLEDGED")
        observe_snapshot = observe_result[0]
        observe_records, observe_journal_proof = independent_journal(observe_store.folder)
        observed = verify_observe_history(observe_snapshot, observe_records, records,
                                         cancel_requested_ns, expected)
        stopped = observed["cleanup"]["stop_result"]
        require(session._recording_resources_closed() and session.book is None and not session.probe.active and
                not writer.thread.is_alive() and (journal is None or not journal._worker.is_alive()) and
                not OwnedProcess.pending_cleanup(), "R60_ENDURANCE_RECORDER_ACTUAL_OWNERS_NOT_CLOSED")
        proof["observe_engine"] = observed
        proof["observe_engine_journal"] = observe_journal_proof
        proof["recording"] = verify_saved(folder, "STANDARD", REQUESTED_SECONDS, expected, executable_hash, [])
        proof["recorder_cleanup"] = {"stop": stopped, "writer_thread_alive": writer.thread.is_alive(),
            "journal_thread_alive": bool(journal is not None and journal._worker.is_alive()),
            "recording_resources_closed": session._recording_resources_closed(),
            "stop_owner": "PRODUCTION_OBSERVE_ADAPTER_AFTER_EXPLICIT_ENGINE_CANCELLATION",
            "workflow_state": observe_snapshot["state"], "expected_workflow_state": "CANCELLED"}
        proof["target_cleanup"] = fixture.close()
        fixture = None
        require(proof["target_cleanup"]["status"] == "COMPLETED" and not OwnedProcess.pending_cleanup() and
                file_hash(trace) == trace_hash and file_hash(executable) == executable_hash,
                "R60_ENDURANCE_TARGET_OWNER_OR_ORIGINAL_SOURCE_CHANGED")
        cpu_end = me.cpu_times()
        proof.update(status="PASS", maxima=maxima, actual_native_bursts=controller.completed,
            native_burst_io_bytes=controller.total_io_bytes, native_state_checks=state_checks,
            measured_active_seconds=time.monotonic() - started,
            observer_cpu_seconds=cpu_end.user + cpu_end.system - cpu_start.user - cpu_start.system,
            final_source_identity=source_proof(args.source_sha), original_sources_unchanged=True,
            worker_thread_closed=True, observe_engine_thread_closed=not observe_thread.is_alive(),
            external_recorder_start_tick_stop_calls=0,
            tick_timing="NOT_EXTERNALLY_INTERCEPTED; PRODUCTION_ADAPTER_OWNS_SAMPLING",
            pending_owned_process_owners=0)
    except BaseException as error:
        proof.update(status="FAIL", error=type(error).__name__, reason=str(error)[:2000])
        traceback.print_exc(limit=12)
    finally:
        cleanup_errors = []
        if engine is not None and engine_thread is not None and engine_thread.is_alive():
            engine.request_cancel()
            engine_thread.join(timeout=10)
            if engine_thread.is_alive():
                cleanup_errors.append("ENGINE_WORKER_CLEANUP_UNCONFIRMED")
        if observe_engine is not None and observe_thread is not None and observe_thread.is_alive():
            observe_engine.request_cancel()
            observe_thread.join(timeout=30)
            if observe_thread.is_alive():
                cleanup_errors.append("LONG_OBSERVE_ENGINE_CLEANUP_UNCONFIRMED")
        if controller is not None:
            try:
                controller.join()
            except BaseException as error:
                cleanup_errors.append("NATIVE_CONTROLLER:" + type(error).__name__)
        if session is None and created_sessions:
            session = created_sessions[0]
        if session is not None and (session.book is not None or session.probe.active):
            if observe_thread is not None and observe_thread.is_alive():
                # The production owner remains reachable. Never issue a second
                # stop concurrently against its thread-affine SQLite objects.
                cleanup_errors.append("RECORDING_RETAINED_BY_LIVE_PRODUCTION_OBSERVE_OWNER")
            else:
                try:
                    proof["failure_stop"] = session.stop("R60_QA_FAILURE")
                except BaseException as error:
                    cleanup_errors.append("RESEARCH_STOP:" + type(error).__name__)
        if capture is not None and capture.active:
            try:
                capture.cancel()
            except BaseException as error:
                cleanup_errors.append("CAPTURE_CANCEL:" + type(error).__name__)
        if fixture is not None:
            try:
                proof["failure_target_cleanup"] = fixture.close(kill=True)
            except BaseException as error:
                cleanup_errors.append("TARGET_CLOSE:" + type(error).__name__)
        if session is not None and (not session._recording_resources_closed() or
                session.jobs.health().get("cleanup_required")):
            cleanup_errors.append("RECORDING_OWNER_CLEANUP_UNCONFIRMED")
        if cleanup_errors:
            proof.update(status="FAIL", cleanup_errors=cleanup_errors)
        save(output / "result.json", proof)
        print("R60_ENDURANCE_RECEIPT " + json.dumps({**proof,
            "result_sha256": file_hash(output / "result.json")}, sort_keys=True), flush=True)
    return 0 if proof["status"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--probe", type=Path)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
