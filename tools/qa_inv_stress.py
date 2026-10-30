"""250k synthetic-source graph stress on hosted runners, separate from native QA."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
from tools.qa_inv_common import digest, exact_source, graph_facts, require, require_hosted, save

RSS_LIMIT = 512 * 1024**2
PRIVATE_PATTERN = ".blackbox-investigation-*"


def write_fixture(path, rows):
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for sequence in range(1, rows + 1):
            stream.write(json.dumps({"schema_version": 1, "pid": 123, "tid": 456,
                "token": "SYNTHETIC_QA_PUBLIC_PRODUCER_TOKEN", "seq": sequence,
                "source_clock": "SYNTHETIC_QA_NOT_CAPTURE", "source_ns": sequence * 1000000,
                "kind": "io.operation.begin" if sequence % 2 else "io.operation.end",
                "operation_id": "synthetic-operation-" + str((sequence + 1) // 2),
                "parent_id": None, "client_dropped": 0,
                "attributes": {"io_kind": "READ", "status": "COMPLETED",
                    "error_code": 0, "byte_count": 4096, "note": "SYNTHETIC_FORMAT_STRESS_ONLY"}},
                separators=(",", ":")) + "\n")


def worker(source, target, mode, output):
    from blackbox_core.investigation_v3 import create_investigation
    from blackbox_core.investigation_graph_store import query_graph

    require_hosted()
    cancellation = threading.Event()
    requested = {"value": False}
    timer = None
    if mode == "cancel":
        def request():
            requested["value"] = True
            cancellation.set()
        timer = threading.Timer(.2, request)
        timer.start()
    started = time.monotonic()
    result = {"mode": mode, "fixture_scope": "SYNTHETIC_FORMAT_STRESS_NOT_WINDOWS_CAPTURE"}
    try:
        case = create_investigation([{"source_type": "EVENTS_JSONL", "path": str(source)}],
            budget={"max_events": 250000, "max_nodes": 256, "max_edges": 512,
                    "timeout_seconds": 1 if mode == "deadline" else 300},
            cancel_event=cancellation, index_path=target)
        graph_facts(case)
        page = query_graph(target, limit=25,
            budget={"max_nodes": 256, "max_edges": 512, "timeout_seconds": 30})
        result.update(outcome="COMPLETED", case_id=case["case_id"], coverage=case["coverage"],
            node_ids=sorted(node["node_id"] for node in case["nodes"]),
            nodes=len(case["nodes"]), edges=len(case["edges"]), index_bytes=target.stat().st_size,
            first_page_records=len(page["records"]), page_total=page["total"])
    except Exception as error:
        result.update(outcome=type(error).__name__, reason=str(error)[:1600])
    finally:
        if timer is not None:
            timer.cancel()
            timer.join(timeout=1)
        result.update(elapsed_seconds=time.monotonic() - started,
            cancellation_requested=requested["value"], destination_exists=target.exists(),
            leftover_private_indexes=[p.name for p in target.parent.glob(PRIVATE_PATTERN)])
        save(output, result)


def validate_case(result, *, expected_rows=None, expected_outcome="COMPLETED"):
    require(result.get("outcome") == expected_outcome, "GRAPH_STRESS_UNEXPECTED_OUTCOME_" + str(result))
    require(not result.get("leftover_private_indexes"), "GRAPH_STRESS_PRIVATE_INDEX_LEFTOVER")
    if expected_outcome == "COMPLETED":
        coverage = result.get("coverage", {})
        require(result.get("destination_exists") is True and
                coverage.get("events_examined") == expected_rows and
                result.get("nodes", 0) <= 256 and result.get("edges", 0) <= 512,
                "GRAPH_STRESS_DID_NOT_EXAMINE_FULL_SOURCE_WITH_BOUNDED_GRAPH")
        require(result.get("index_bytes", RSS_LIMIT) <= 128 * 1024**2 and
                0 < result.get("first_page_records", 0) <= 25,
                "GRAPH_STRESS_INDEX_OR_PAGE_NOT_BOUNDED")
        if expected_rows > 256:
            require(coverage.get("nodes_omitted", 0) > 0 and coverage.get("has_more") is True,
                    "GRAPH_STRESS_DISPLAY_OMISSIONS_NOT_DISCLOSED")
    else:
        require(result.get("destination_exists") is False, "FAILED_GRAPH_BUILD_PUBLISHED_FINAL_INDEX")


def measured(source, target, mode, output):
    import psutil
    before = digest(source)
    result_path = output / (target.parent.name + "-" + mode + ".json")
    command = [sys.executable, str(Path(__file__).resolve()), "--worker", mode,
               "--source", str(source), "--target", str(target), "--result", str(result_path)]
    started, peak = time.monotonic(), 0
    with (output / (target.parent.name + "-" + mode + ".log")).open("wb") as log:
        child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        process = psutil.Process(child.pid)
        try:
            while child.poll() is None:
                try:
                    peak = max(peak, process.memory_info().rss)
                except psutil.NoSuchProcess:
                    pass
                require(peak <= RSS_LIMIT, "GRAPH_STRESS_WORKER_RSS_EXCEEDED_512_MIB")
                require(time.monotonic() - started <= 360, "GRAPH_STRESS_WORKER_WALL_DEADLINE")
                time.sleep(.02)
            require(child.returncode == 0, "GRAPH_STRESS_WORKER_EXIT_" + str(child.returncode))
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=10)
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result.update(peak_rss_bytes=peak, parent_elapsed_seconds=time.monotonic() - started,
                  source_sha256_before=before, source_sha256_after=digest(source), source_bytes=source.stat().st_size)
    require(result["source_sha256_after"] == before, "GRAPH_STRESS_CHANGED_SOURCE")
    save(result_path, result)
    return result


def run(output, rows):
    require_hosted()
    output.mkdir(parents=True, exist_ok=False)
    report = {"status": "RUNNING", "source_sha": exact_source(), "event_count": rows,
              "scope": "SYNTHETIC_SDK_SCHEMA_STRESS_OF_ACTUAL_INVESTIGATION_GRAPH_BUILDER",
              "native_capture": False, "rss_limit_bytes": RSS_LIMIT, "cases": {}}
    try:
        with tempfile.TemporaryDirectory(prefix="blackbox-inv-stress-") as raw:
            root = Path(raw)
            small, large = root / "small.jsonl", root / "large.jsonl"
            write_fixture(small, min(10000, rows))
            write_fixture(large, rows)
            for label, source, expected in (("small", small, min(10000, rows)), ("large", large, rows)):
                folder = root / label
                folder.mkdir()
                result = measured(source, folder / "case.sqlite3", "normal", output)
                validate_case(result, expected_rows=expected)
                report["cases"][label] = result
            require(report["cases"]["large"]["peak_rss_bytes"] <=
                    report["cases"]["small"]["peak_rss_bytes"] + 128 * 1024**2,
                    "GRAPH_STRESS_RSS_GROWS_WITH_DISCARDED_SOURCE_RECORDS")
            folder = root / "cancel-retry"
            folder.mkdir()
            result = measured(large, folder / "case.sqlite3", "cancel", output)
            validate_case(result, expected_outcome="InterruptedError")
            require(result.get("cancellation_requested") is True, "GRAPH_STRESS_CANCEL_WAS_NOT_REQUESTED")
            report["cases"]["cancel"] = result
            result = measured(large, folder / "case.sqlite3", "normal", output)
            validate_case(result, expected_rows=rows)
            report["cases"]["retry"] = result
            require(result["case_id"] == report["cases"]["large"]["case_id"] and
                    result["node_ids"] == report["cases"]["large"]["node_ids"],
                    "GRAPH_REBUILD_NOT_DETERMINISTIC")
            moved = root / "renamed-identical-source.jsonl"
            shutil.copyfile(large, moved)
            folder = root / "relocated"
            folder.mkdir()
            result = measured(moved, folder / "case.sqlite3", "normal", output)
            validate_case(result, expected_rows=rows)
            require(result["case_id"] == report["cases"]["large"]["case_id"] and
                    result["node_ids"] == report["cases"]["large"]["node_ids"],
                    "GRAPH_IDS_DEPEND_ON_SOURCE_FILENAME")
            report["cases"]["relocated"] = result
            corrupted = root / "partial.jsonl"
            write_fixture(corrupted, 1000)
            with corrupted.open("ab") as stream:
                stream.write(b'{"unfinished":')
            folder = root / "corrupt"
            folder.mkdir()
            result = measured(corrupted, folder / "case.sqlite3", "normal", output)
            validate_case(result, expected_outcome="InvestigationError")
            report["cases"]["corrupt"] = result
            folder = root / "deadline"
            folder.mkdir()
            result = measured(large, folder / "case.sqlite3", "deadline", output)
            require(result["outcome"] in ("TimeoutError", "COMPLETED"), "GRAPH_DEADLINE_UNEXPECTED_RESULT")
            validate_case(result, expected_rows=rows, expected_outcome=result["outcome"])
            report["cases"]["deadline"] = result
        report.update(status="PASS", source_integrity_preserved=True,
                      limitations=["SYNTHETIC_FORMAT_STRESS_NOT_REAL_ETW_CAPTURE",
                                   "RSS_IS_SAMPLED_WORKING_SET_NOT_A_HARD_ALLOCATOR_LIMIT",
                                   "NOT_LONG_DURATION_OR_PHYSICAL_WINDOWS_ACCEPTANCE"])
    except BaseException as error:
        report.update(status="FAIL", error=type(error).__name__, reason=str(error)[:1800])
    save(output / "graph-stress-qa.json", report)
    print("INV_GRAPH_STRESS_" + report["status"], flush=True)
    return 0 if report["status"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--rows", type=int, default=250000)
    parser.add_argument("--worker", choices=("normal", "cancel", "deadline"))
    parser.add_argument("--source", type=Path)
    parser.add_argument("--target", type=Path)
    parser.add_argument("--result", type=Path)
    args = parser.parse_args()
    require_hosted()
    if args.worker:
        worker(args.source, args.target, args.worker, args.result)
        return 0
    require(args.output is not None and 1000 <= args.rows <= 250000, "GRAPH_STRESS_ARGUMENTS_INVALID")
    return run(args.output.resolve(), args.rows)


if __name__ == "__main__":
    raise SystemExit(main())
