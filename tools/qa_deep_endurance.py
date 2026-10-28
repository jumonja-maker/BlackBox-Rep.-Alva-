"""Continuous BB-DEEP-001 + existing GUI recording on GitHub-hosted Windows.

A requested 19,800 seconds is 5h30m, never an eight-hour certification. The job
needs a 360 minute deadline to leave room for setup, cleanup and artifacts.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from tools.qa_deep_inspection import Probe, build_probe, file_hash, require, require_hosted_windows, save


def verify_samples(path: Path, minimum_seconds: float) -> dict:
    digest = file_hash(path)
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        require(db.execute("PRAGMA integrity_check").fetchone() == ("ok",),
                "ENDURANCE_OBSERVATION_DATABASE_CORRUPTED")
        count, first, last, min_seq, max_seq = db.execute(
            "SELECT COUNT(*),MIN(elapsed),MAX(elapsed),MIN(seq),MAX(seq) FROM samples").fetchone()
        require(count >= 2 and min_seq == 1 and max_seq == count and
                last - first >= minimum_seconds,
                "ENDURANCE_COMPLETE_MEASURED_INTERVAL_NOT_CONFIRMED")
        regressions = db.execute("""
            SELECT COUNT(*) FROM (
              SELECT heartbeat,io_cycles,network_cycles,
                     LAG(heartbeat) OVER(ORDER BY seq) old_heartbeat,
                     LAG(io_cycles) OVER(ORDER BY seq) old_io,
                     LAG(network_cycles) OVER(ORDER BY seq) old_network
              FROM samples
            ) WHERE heartbeat <= old_heartbeat OR io_cycles <= old_io OR network_cycles <= old_network
        """).fetchone()[0]
        require(regressions == 0, "CONTINUOUS_NATIVE_WORKLOAD_PROGRESS_NOT_CONFIRMED")
        rss = db.execute("SELECT MAX(qa_rss),MAX(target_rss),MAX(helper_rss) FROM samples").fetchone()
        helpers = db.execute("SELECT COUNT(DISTINCT helper_pid) FROM samples WHERE helper_pid>0").fetchone()[0]
    require(file_hash(path) == digest, "READ_ONLY_ENDURANCE_VERIFICATION_CHANGED_DATABASE")
    return {"status": "PASS", "count": count, "first_seconds": first,
            "last_seconds": last, "observed_span_seconds": last - first,
            "max_qa_rss": rss[0], "max_target_rss": rss[1], "max_helper_rss": rss[2],
            "observed_helper_instances": helpers, "nonprogress_intervals": regressions,
            "sha256": digest, "rss_measurement": "SAMPLED_PROCESS_WORKING_SET_NOT_HARD_LIMIT"}


def run(args: argparse.Namespace) -> int:
    require_hosted_windows()
    from blackbox_core.deep_contracts import ActionRequest
    from blackbox_core.deep_service import InspectorService
    from blackbox_core.optional_jobs import OwnedProcess
    from tools.qa_github_endurance import _evidence as verify_observer
    import psutil

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source_sha = os.environ.get("GITHUB_SHA", "")
    require(len(source_sha) == 40 and all(c in "0123456789abcdef" for c in source_sha),
            "EXACT_GITHUB_SOURCE_SHA_REQUIRED")
    proof = {"status": "RUNNING", "source_sha": source_sha,
             "requested_seconds": args.duration_seconds,
             "scope": "CONTINUOUS_NATIVE_WORKLOAD_WITH_PRODUCTION_GUI_RECORDING_AND_DEEP_ACTIONS",
             "runner_environment": os.environ.get("RUNNER_ENVIRONMENT"),
             "eight_hour_continuous_acceptance": False,
             "physical_windows_10_11": "NOT_TESTED",
             "uac_secure_desktop": "NOT_TESTED",
             "helper_sessions": []}
    probe = observer = service = db = observer_log = action_log = None
    successful = False
    try:
        executable = args.probe.resolve(strict=True) if args.probe else build_probe(output / "build")
        helper = args.helper.resolve(strict=True) if args.helper else None
        probe = Probe(executable, output / "probe")
        proof["probe_sha256"] = file_hash(executable)
        proof["target_identity"] = {"pid": probe.ready["pid"], "created_100ns": probe.ready["created_100ns"]}
        observer_root = output / "observer"
        observer_root.mkdir()
        observer_log = (observer_root / "production-qa.log").open("wb")
        observer = OwnedProcess([sys.executable, "-u", "-m", "blackbox_universal.production_qa",
                                 "endurance", "--pid", str(probe.process.pid),
                                 "--output", str(observer_root / "run"), "--profile", "STANDARD",
                                 "--duration-seconds", str(args.duration_seconds),
                                 "--expected-sha", source_sha], stdout=observer_log,
                                stderr=subprocess.STDOUT, detach_console=True)
        db_path = output / "deep-observations.sqlite3"
        db = sqlite3.connect(db_path)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("""CREATE TABLE samples(
          seq INTEGER PRIMARY KEY, elapsed REAL NOT NULL, heartbeat INTEGER NOT NULL,
          io_cycles INTEGER NOT NULL, network_cycles INTEGER NOT NULL,
          qa_rss INTEGER NOT NULL, target_rss INTEGER NOT NULL,
          helper_pid INTEGER, helper_rss INTEGER)""")
        action_log = (output / "deep-actions.jsonl").open("x", encoding="utf-8")
        start = time.monotonic()
        last_deep = last_renewal = last_write = last_log = float("-inf")
        last_record = None
        first_sample_elapsed = None
        sequence = action_count = renewals = 0
        target_process = psutil.Process(probe.process.pid)
        qa_process = psutil.Process()

        def action(operation: str, parameters: dict | None = None, *, confirmed: bool = False) -> dict:
            nonlocal action_count
            result = service.execute(ActionRequest(operation, identity, parameters or {}, confirmed,
                                                   timeout_seconds=25))
            require(result.get("status") in ("COMPLETED", "INCOMPLETE_EVIDENCE"),
                    "ENDURANCE_ACTION_FAILED_" + operation + ":" + str(result.get("error"))[:300])
            # The regular log contains metadata only. The fixed test buffer is not exported here.
            action_log.write(json.dumps({"elapsed": time.monotonic() - start, "operation": operation,
                                         "operation_id": result.get("operation_id"),
                                         "status": result["status"], "limitations": result.get("limitations", [])},
                                        allow_nan=False) + "\n")
            action_log.flush()
            action_count += 1
            return result

        while True:
            elapsed = time.monotonic() - start
            require(elapsed <= args.duration_seconds + 720,
                    "ENDURANCE_WATCHDOG_DEADLINE_EXCEEDED")
            require(probe.process.poll() is None, "CONTINUOUS_NATIVE_TARGET_EXITED")
            if service is None or elapsed - last_renewal >= 240:
                if service is not None:
                    closed = service.close()
                    proof["helper_sessions"][-1]["cleanup"] = closed
                    require(closed.get("status") == "COMPLETED", "ENDURANCE_HELPER_CLEANUP_UNCONFIRMED")
                renewals += 1
                service = InspectorService(journal_root=output / "journals" / f"session-{renewals:04d}",
                                           helper_executable=helper)
                identity = service.identity(probe.process.pid)
                require(identity.created_100ns == probe.ready["created_100ns"],
                        "ENDURANCE_TARGET_INSTANCE_CHANGED")
                last_renewal = elapsed
                proof["helper_sessions"].append({"session": renewals, "start_seconds": elapsed})
            if elapsed - last_deep >= 30:
                action("snapshot")
                read = action("memory_read", {"address": probe.ready["buffer_address"], "length": 64})
                require(read["data"].get("hex") == probe.ready["buffer_hex"],
                        "ENDURANCE_KNOWN_MEMORY_CHANGED_UNEXPECTEDLY")
                proof["helper_sessions"][-1]["helper_pid"] = service.helper_pid
                last_deep = elapsed
            if elapsed - last_write >= 120:
                changed = bytes((i ^ 0xA5) for i in range(64)).hex()
                wrote = action("memory.write", {"address": probe.ready["buffer_address"],
                                                "expected_hex": probe.ready["buffer_hex"],
                                                "value_hex": changed}, confirmed=True)
                require(probe.state()["buffer_hex"] == changed, "ENDURANCE_WRITE_READBACK_FAILED")
                action("memory.rollback", {"change_id": wrote["data"]["change_id"]}, confirmed=True)
                require(probe.state()["buffer_hex"] == probe.ready["buffer_hex"],
                        "ENDURANCE_ROLLBACK_READBACK_FAILED")
                last_write = elapsed

            state = probe.state()
            if last_record is not None:
                state = probe.progress(last_record)
            last_record = state
            helper_pid = service.helper_pid
            helper_rss = psutil.Process(helper_pid).memory_info().rss if helper_pid else None
            sequence += 1
            sample_elapsed = time.monotonic() - start
            if first_sample_elapsed is None:
                first_sample_elapsed = sample_elapsed
            db.execute("INSERT INTO samples VALUES(?,?,?,?,?,?,?,?,?)",
                       (sequence, sample_elapsed, state["heartbeat"], state["io_cycles"],
                        state["network_cycles"], qa_process.memory_info().rss,
                        target_process.memory_info().rss, helper_pid, helper_rss))
            db.commit()
            if elapsed - last_log >= 60:
                progress = {"status": "RUNNING", "elapsed_seconds": elapsed,
                            "requested_seconds": args.duration_seconds, "samples": sequence,
                            "deep_actions": action_count, "helper_sessions": renewals,
                            "target_heartbeat": state["heartbeat"], "file_cycles": state["io_cycles"],
                            "network_cycles": state["network_cycles"]}
                save(output / "progress.json", progress)
                print("DEEP_ENDURANCE_PROGRESS " + json.dumps(progress), flush=True)
                last_log = elapsed
            if observer.process.poll() is not None:
                require(observer.process.returncode == 0, "PRODUCTION_GUI_ENDURANCE_FAILED")
                # Keep a real target observation covering the requested interval,
                # including any production-harness startup offset.
                if sample_elapsed - first_sample_elapsed >= args.duration_seconds:
                    break
            threading.Event().wait(5)

        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        db.close()
        db = None
        action_log.close()
        action_log = None
        proof["observer"] = verify_observer(observer_root, "STANDARD", args.duration_seconds, source_sha)
        proof["observations"] = verify_samples(db_path, args.duration_seconds)
        proof["actual_seconds"] = time.monotonic() - start
        proof["deep_action_count"] = action_count
        proof["full_330_minutes_completed"] = bool(args.duration_seconds == 19800 and
                                                  proof["observations"]["observed_span_seconds"] >= 19800 and
                                                  proof["observer"]["actual_seconds"] >= 19800)
        successful = True
    except BaseException as error:
        proof.update(status="FAIL", error=type(error).__name__, reason=str(error)[:1500])
    finally:
        for obj, label in ((service, "diagnostic_helper_cleanup"), (observer, "observer_cleanup"),
                           (probe, "target_cleanup")):
            if obj is not None:
                try:
                    if label == "observer_cleanup":
                        obj.close(kill=not successful)
                        cleanup = {"exit_code": obj.process.poll()}
                    elif label == "target_cleanup":
                        cleanup = obj.close(kill=not successful)
                    else:
                        cleanup = obj.close()
                    proof[label] = cleanup
                    if label == "diagnostic_helper_cleanup":
                        require(cleanup.get("status") == "COMPLETED", "ENDURANCE_FINAL_HELPER_CLEANUP_UNCONFIRMED")
                except BaseException as error:
                    successful = False
                    proof[label] = {"status": "FAILED", "reason": str(error)[:1000]}
        for stream in (db, observer_log, action_log):
            if stream is not None:
                stream.close()
        proof["status"] = "PASS" if successful else "FAIL"
        save(output / "endurance.json", proof)
    print("DEEP_ENDURANCE_" + proof["status"], flush=True)
    return 0 if successful else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration-seconds", type=int, default=19800)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--helper", type=Path)
    args = parser.parse_args()
    if not 30 <= args.duration_seconds <= 19800:
        parser.error("duration must be between 30 and 19800 seconds")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
