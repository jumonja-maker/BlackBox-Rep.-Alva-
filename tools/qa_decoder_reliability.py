"""Owned synthetic JSONL stress/failure QA; does not impersonate native ETW QA.

Each measured import runs in a separate process. Parent measures actual RSS;
fixtures/outputs are disposable, sources are hashed before and after every case.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from threading import Event, Thread
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blackbox_core.decoder_index import MAX_EVENTS, read_index
from blackbox_core.decoder_service import decode_file


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024**2), b""):
            value.update(chunk)
    return value.hexdigest()


def fixture(path, rows):
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for number in range(1, rows + 1):
            stream.write(json.dumps({"schema_version": 1, "pid": 123, "tid": 456,
                "seq": number, "source_clock": "SYNTHETIC_QA_NOT_CAPTURE",
                "source_ns": number * 1000000, "kind": "qa.reliability",
                "detail": "x" * 96}, separators=(",", ":")) + "\n")


def worker(source, target, mode, result_file):
    cancel = Event()
    monitor = None
    if mode == "cancel":
        def request_cancel():
            until = time.monotonic() + 30
            while time.monotonic() < until and not cancel.is_set():
                if list(target.parent.glob(".decoder-building-*")):
                    time.sleep(.05)
                    cancel.set()
                    return
                time.sleep(.005)
            cancel.set()
        monitor = Thread(target=request_cancel, daemon=True)
        monitor.start()
    started = time.monotonic()
    result = {}
    try:
        summary = decode_file(source, target, cancel=cancel, timeout=1 if mode == "deadline" else 180)
        page = read_index(target, limit=1)
        result = {"outcome": "DECODED", "rows": summary["rows"], "status": summary["status"],
                  "capture_complete": summary["capture_complete"],
                  "input_sha256": summary["input_sha256"],
                  "first_page_rows": len(page["rows"]), "index_bytes": target.stat().st_size}
    except Exception as error:
        result = {"outcome": type(error).__name__, "reason": str(error)[:512]}
    finally:
        cancel.set()
        if monitor is not None:
            monitor.join(timeout=1)
        result.update(elapsed_seconds=time.monotonic() - started,
                      destination_exists=target.exists(),
                      leftover_private_indexes=[p.name for p in target.parent.glob(".decoder-building-*")])
        result_file.write_text(json.dumps(result, indent=2), encoding="utf-8")


def measured(source, target, mode, evidence):
    import psutil
    before = digest(source)
    result_file = evidence / (target.parent.name + "-" + mode + ".json")
    command = [sys.executable, str(Path(__file__).resolve()), "--worker", mode,
               "--source", str(source), "--target", str(target), "--result", str(result_file)]
    started = time.monotonic()
    peak = 0
    with (evidence / (target.parent.name + "-" + mode + ".log")).open("wb") as log:
        child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        process = psutil.Process(child.pid)
        try:
            while child.poll() is None:
                try:
                    peak = max(peak, process.memory_info().rss)
                except psutil.NoSuchProcess:
                    pass
                if peak > 512 * 1024**2:
                    raise RuntimeError("QA_IMPORT_RSS_EXCEEDED_512_MIB")
                if time.monotonic() - started > 180:
                    raise TimeoutError("QA_IMPORT_EXCEEDED_180_SECONDS")
                time.sleep(.01)
            if child.returncode != 0:
                raise RuntimeError("QA_WORKER_EXIT_" + str(child.returncode))
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=10)
    result = json.loads(result_file.read_text(encoding="utf-8"))
    result.update(peak_rss_bytes=peak, parent_wall_seconds=time.monotonic() - started,
                  source_sha256_before=before, source_sha256_after=digest(source),
                  source_bytes=source.stat().st_size)
    assert result["source_sha256_after"] == before, "Source changed"
    assert not result["leftover_private_indexes"], "Partial index left after terminal outcome"
    result_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def run(output, rows):
    output.mkdir(parents=True, exist_ok=False)
    results = {}
    with tempfile.TemporaryDirectory(prefix="blackbox-reliability-qa-") as raw:
        root = Path(raw)
        small = root / "small.jsonl"
        large = root / "large.jsonl"
        fixture(small, min(10000, rows))
        fixture(large, rows)
        for label, source in (("small", small), ("large", large)):
            folder = root / label
            folder.mkdir()
            result = measured(source, folder / "index.sqlite3", "normal", output)
            assert result["outcome"] == "DECODED" and result["status"] == "DECODED", result
            assert result["rows"] == (min(10000, rows) if label == "small" else rows)
            assert result["capture_complete"] is None
            results[label] = result
        assert results["large"]["peak_rss_bytes"] <= results["small"]["peak_rss_bytes"] + 128 * 1024**2

        retry = root / "cancel-retry"
        retry.mkdir()
        cancelled = measured(large, retry / "index.sqlite3", "cancel", output)
        assert cancelled["outcome"] == "InterruptedError" and not cancelled["destination_exists"], cancelled
        results["cancel"] = cancelled
        results["retry"] = measured(large, retry / "index.sqlite3", "normal", output)
        assert results["retry"]["outcome"] == "DECODED" and results["retry"]["rows"] == rows

        corrupt = root / "corrupt.jsonl"
        with large.open("rb") as source, corrupt.open("wb") as dest:
            # Read/write chunks; the QA generator itself must not load the trace.
            for chunk in iter(lambda: source.read(1024**2), b""):
                dest.write(chunk)
            dest.write(b'{"unterminated":')
        folder = root / "corrupt"
        folder.mkdir()
        broken = measured(corrupt, folder / "index.sqlite3", "normal", output)
        assert broken["outcome"] == "ValueError" and not broken["destination_exists"], broken
        results["corrupt"] = broken

        # A one-second budget includes all phases. At the full supported event
        # cap this is a measurable deadline check; a very fast runner may finish
        # legitimately, in which case the artifact explicitly says so.
        folder = root / "deadline"
        folder.mkdir()
        deadline = measured(large, folder / "index.sqlite3", "deadline", output)
        assert deadline["outcome"] in ("TimeoutError", "DECODED"), deadline
        if deadline["outcome"] == "TimeoutError":
            assert not deadline["destination_exists"]
        results["deadline"] = deadline
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=no"],
                                    cwd=ROOT, text=True).strip()
    final = {"schema": "blackbox.decoder-reliability-qa/1", "result": "PASS", "source_sha": sha,
             "tracked_worktree_clean": not bool(dirty),
             "source_identity_status": "CLEAN_CHECKOUT" if not dirty else "LOCAL_UNCOMMITTED_CHANGES",
             "platform": sys.platform, "python": sys.version, "synthetic_jsonl_only": True,
             "event_count": rows, "source_integrity_preserved": True,
             "rss_policy_bytes": 512 * 1024**2, "rss_growth_policy_bytes": 128 * 1024**2,
             "cases": results,
             "limitations": ["NOT_NATIVE_ETW_OR_EVENTPIPE_ACCEPTANCE", "NOT_LONG_DURATION_ENDURANCE",
                             "NO_PARTIAL_INDEX_RESUME", "NOT_PROOF_ALL_CORRUPT_FILES_ARE_HANDLED"]}
    (output / "reliability-qa.json").write_text(json.dumps(final, indent=2), encoding="utf-8")
    print(json.dumps({"result": "PASS", "rows": rows,
                      "large_peak_rss_bytes": results["large"]["peak_rss_bytes"],
                      "large_elapsed_seconds": results["large"]["elapsed_seconds"],
                      "deadline_outcome": results["deadline"]["outcome"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--rows", type=int, default=250000)
    parser.add_argument("--worker", choices=("normal", "cancel", "deadline"))
    parser.add_argument("--source", type=Path)
    parser.add_argument("--target", type=Path)
    parser.add_argument("--result", type=Path)
    args = parser.parse_args()
    if args.worker:
        worker(args.source, args.target, args.worker, args.result)
    else:
        if args.output is None or not 1000 <= args.rows <= MAX_EVENTS:
            parser.error("--output and --rows between 1000 and MAX_EVENTS are required")
        run(args.output, args.rows)


if __name__ == "__main__":
    main()
