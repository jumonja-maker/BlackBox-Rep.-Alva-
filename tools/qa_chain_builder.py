"""Prepare actual hosted fixtures and invoke the same R60 source/frozen QA CLI."""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from blackbox_core.chain_qa import file_hash, read_json, require, source_proof


def _guard_stamp(path):
    try:
        value = path.stat()
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    except OSError:
        return None


def _fresh_guard_failure(path, *, pid, source_sha, started_ns, previous_stamp):
    """Read only bounded, fresh metadata bound to this actual returned child.

    A stale/missing file or absent process receipt is not a startup diagnosis.
    No exception text, command line, source paths or payloads are transported.
    """
    try:
        stamp = _guard_stamp(path)
        if stamp is None:
            return {"status": "NOT_PRESENT_OR_UNREADABLE"}
        if stamp == previous_stamp:
            return {"status": "UNCHANGED_PREVIOUS_FILE_NOT_CURRENT_CHILD"}
        value = read_json(path, maximum=32768)
        first = value.get("first", {})
        frames = first.get("frames") if type(first) is dict else None
        recorded = value.get("first_recorded_monotonic_ns")
        valid = (type(pid) is int and pid > 0 and value.get("pid") == pid and
            value.get("source_sha") == source_sha and
            value.get("scope") == "CHAIN_QA_PYTHON_FAILURE_METADATA_ONLY" and
            type(value.get("count")) is int and 1 <= value["count"] <= 1_000_000 and
            type(recorded) is int and started_ns <= recorded <= time.monotonic_ns() and
            type(first) is dict and type(first.get("error_type")) is str and
            0 < len(first["error_type"]) <= 64 and type(frames) is list and len(frames) <= 12)
        if not valid:
            return {"status": "NOT_BOUND_TO_CURRENT_CHILD"}
        safe_frames = []
        for frame in frames:
            valid = (type(frame) is dict and type(frame.get("file")) is str and
                0 < len(frame["file"]) <= 128 and not any(char in frame["file"] for char in ("/", "\\")) and
                type(frame.get("function")) is str and len(frame["function"]) <= 96 and
                type(frame.get("line")) is int and 0 <= frame["line"] <= 2**31 - 1)
            if not valid:
                return {"status": "INVALID_BOUNDED_GUARD_METADATA"}
            safe_frames.append({key: frame[key] for key in ("file", "function", "line")})
        require(_guard_stamp(path) == stamp, "R60_GUARD_METADATA_CHANGED_DURING_READBACK")
        return {"status": "BOUND_CURRENT_CHILD_METADATA", "pid": pid, "source_sha": source_sha,
            "count": value["count"], "first_recorded_monotonic_ns": recorded,
            "first": {"error_type": first["error_type"], "frames": safe_frames}}
    except Exception as error:
        return {"status": "READBACK_UNCONFIRMED", "error_type": type(error).__name__[:64]}


def _medium_child_diagnostic(child, *, source_sha, frozen, guard_path, started_ns, previous_stamp):
    def integrity(key):
        value = child.get(key)
        if type(value) is not dict:
            return None
        return {field: value.get(field) for field in ("sid", "rid", "level", "source")}
    code = child.get("exit_code")
    return {"source_sha": source_sha, "frozen": frozen, "pid": child.get("pid"),
        "exit_code": code, "windows_status_hex": "0x%08x" % (code & 0xffffffff) if type(code) is int else None,
        "medium_integrity_requested": child.get("medium_integrity_requested"),
        "token_integrity": integrity("token_integrity"), "child_token_integrity": integrity("child_token_integrity"),
        "creation_flags": child.get("creation_flags"), "job_assigned_before_resume": child.get("job_assigned_before_resume"),
        "parent_token_unchanged": child.get("parent_token_unchanged"),
        "guard": _fresh_guard_failure(guard_path, pid=child.get("pid"), source_sha=source_sha,
            started_ns=started_ns, previous_stamp=previous_stamp),
        "scope": "ACTUAL_MEDIUM_CHILD_EXIT_AND_FRESH_PYTHON_METADATA_NOT_ROOT_CAUSE"}


def verify_gui_screenshots(proof, folder, *, emit=False):
    rows = proof.get("screenshots")
    require(type(rows) is list and len(rows) == 2 and {row.get("language") for row in rows} == {"RU", "EN"},
            "R60_RU_EN_SCREENSHOT_PROOF_REQUIRED")
    for row in rows:
        name = row["file"]
        require(type(name) is str and Path(name).name == name and name.endswith(".png"),
                "R60_SCREENSHOT_NAME_REFUSED")
        path = Path(folder) / name
        require(not path.is_symlink() and 0 < path.stat().st_size <= 768 * 1024 and
                path.stat().st_size == row["bytes"] and file_hash(path) == row["sha256"],
                "R60_SCREENSHOT_HASH_OR_BYTE_BUDGET")
        if emit:
            encoded = base64.b64encode(path.read_bytes()).decode("ascii")
            chunks = [encoded[index:index + 12000] for index in range(0, len(encoded), 12000)]
            require(len(chunks) == row["chunks"], "R60_SCREENSHOT_CHUNK_COUNT")
            print("R60_GUI_PNG_BEGIN " + json.dumps(row, sort_keys=True), flush=True)
            for index, chunk in enumerate(chunks, 1):
                print("R60_GUI_PNG_CHUNK " + row["id"] + " " + str(index) + "/" + str(len(chunks)) + " " + chunk,
                      flush=True)
            print("R60_GUI_PNG_END " + row["id"] + " " + row["sha256"], flush=True)


def run(args):
    source_proof(args.source_sha)
    evidence = args.evidence_root
    if evidence is None:
        require(args.exe is None and args.decoder is not None, "R60_REAL_DECODER_EVIDENCE_REQUIRED")
        from tools.qa_wave02 import run as prepare_actual_evidence
        evidence = args.output.with_name(args.output.name + "-actual-wave02")
        prepare_actual_evidence(argparse.Namespace(output=evidence, decoder=args.decoder,
            source_sha=args.source_sha, probe=args.probe, diagnostic_helper=args.diagnostic_helper, container="full"))
    executable = [str(args.exe.resolve(strict=True))] if args.exe else [sys.executable, "-X", "faulthandler", str(ROOT / "app.py")]
    command = executable + ["--chain-e2e", str(args.output.resolve()), "--chain-evidence",
        str(evidence.resolve(strict=True)), "--qa-commit-sha", args.source_sha]
    if args.gui_only:
        command.append("--chain-gui-only")
    if args.standard_token:
        require(not args.gui_only, "R60_STANDARD_REQUIRES_ACTUAL_CORE_CHAIN")
        command.append("--chain-standard-token")
        from tools.qa_decoder_standard_token import restricted_child, restricted_interpreter
        guard_path = ROOT / "blackbox-chain-qa-error.json"
        previous_stamp, started_ns = _guard_stamp(guard_path), time.monotonic_ns()
        try:
            if not args.exe:
                command[0] = str(restricted_interpreter(sys.executable))
            child = restricted_child(command, cwd=ROOT, timeout_seconds=1200, medium_integrity=True)
        except BaseException as error:
            print("R60_CHAIN_STANDARD_TOKEN_DIAGNOSTIC " + json.dumps({"source_sha": args.source_sha,
                "frozen": bool(args.exe), "pid": None, "exit_code": None, "windows_status_hex": None,
                "status": "CHILD_RESULT_NOT_RETURNED", "error_type": type(error).__name__[:64],
                "winerror": getattr(error, "winerror", None) if type(getattr(error, "winerror", None)) is int else None,
                "scope": "NO_CHILD_EXIT_OR_TOKEN_RESULT_AVAILABLE"}, sort_keys=True), flush=True)
            raise
        print("R60_CHAIN_STANDARD_TOKEN_DIAGNOSTIC " + json.dumps(_medium_child_diagnostic(child,
            source_sha=args.source_sha, frozen=bool(args.exe), guard_path=guard_path,
            started_ns=started_ns, previous_stamp=previous_stamp), sort_keys=True), flush=True)
        require(child["exit_code"] == 0 and child["child_token_integrity"]["sid"] == "S-1-16-8192",
                "R60_ACTUAL_CHAIN_MEDIUM_TOKEN_PROCESS_FAILED")
        print("R60_CHAIN_STANDARD_TOKEN_CHILD " + json.dumps(child, sort_keys=True), flush=True)
    else:
        completed = subprocess.run(command, timeout=1200, check=False)
        print("R60_CHAIN_CHILD_EXIT " + json.dumps({"source_sha": args.source_sha, "frozen": bool(args.exe),
            "gui_only": args.gui_only, "returncode": completed.returncode,
            "windows_status_hex": "0x%08x" % (completed.returncode & 0xffffffff)}, sort_keys=True), flush=True)
        require(completed.returncode == 0, "R60_SOURCE_OR_FROZEN_CHAIN_PROCESS_FAILED: " + str(completed.returncode))
    result = read_json(args.output / "result.json")
    require(result.get("status") == "PASS" and result.get("frozen") is bool(args.exe) and
            result.get("source_sha") == args.source_sha, "R60_CHAIN_PROOF_INCOMPLETE")
    if not args.gui_only and (args.exe or args.standard_token):
        # Windowed/restricted children may have no console. Retain the actual
        # persisted native and negative-flow proof in this artifactless job;
        # a file hash or a short PASS summary alone cannot expose its scope.
        print("R60_CHAIN_NATIVE_RECEIPT " + json.dumps({**result,
            "result_sha256": file_hash(args.output / "result.json")}, sort_keys=True), flush=True)
    if args.standard_token:
        require(result.get("standard_token") is True and result["live"]["own_token"]["elevated"] is False,
                "R60_STANDARD_CHAIN_TOKEN_PROOF_MISSING")
    gui = read_json(args.output / "gui" / "result.json")
    require(gui.get("status") == "PASS", "R60_ACTUAL_EDITOR_QA_INCOMPLETE")
    verify_gui_screenshots(gui, args.output / "gui", emit=bool(args.exe))
    print("R60_CHAIN_ACCEPTANCE_RECEIPT " + json.dumps({"status": "PASS", "source_sha": args.source_sha,
        "frozen": bool(args.exe), "exe_sha256": file_hash(args.exe) if args.exe else None,
        "result_sha256": file_hash(args.output / "result.json"), "gui_result_sha256": file_hash(args.output / "gui" / "result.json"),
        "scope": "GUI_ONLY" if args.gui_only else "CORE_NATIVE_AND_GUI",
        "node_count": result.get("node_count"), "journal": result.get("journal"),
        "actual_invocation_counts": result.get("actual_invocation_counts"), "gui": gui}, sort_keys=True), flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--decoder", type=Path)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--diagnostic-helper", type=Path)
    parser.add_argument("--exe", type=Path)
    parser.add_argument("--gui-only", action="store_true")
    parser.add_argument("--standard-token", action="store_true")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
