"""Prepare actual hosted fixtures and invoke the same R60 source/frozen QA CLI."""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from blackbox_core.chain_qa import file_hash, read_json, require, source_proof


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
    executable = [str(args.exe.resolve(strict=True))] if args.exe else [sys.executable, str(ROOT / "app.py")]
    command = executable + ["--chain-e2e", str(args.output.resolve()), "--chain-evidence",
        str(evidence.resolve(strict=True)), "--qa-commit-sha", args.source_sha]
    if args.gui_only:
        command.append("--chain-gui-only")
    if args.standard_token:
        require(not args.gui_only, "R60_STANDARD_REQUIRES_ACTUAL_CORE_CHAIN")
        command.append("--chain-standard-token")
        from tools.qa_decoder_standard_token import restricted_child, restricted_interpreter
        if not args.exe:
            command[0] = str(restricted_interpreter(sys.executable))
        child = restricted_child(command, cwd=ROOT, timeout_seconds=1200, medium_integrity=True)
        require(child["exit_code"] == 0 and child["child_token_integrity"]["sid"] == "S-1-16-8192",
                "R60_ACTUAL_CHAIN_MEDIUM_TOKEN_PROCESS_FAILED")
        print("R60_CHAIN_STANDARD_TOKEN_CHILD " + json.dumps(child, sort_keys=True), flush=True)
    else:
        completed = subprocess.run(command, timeout=1200, check=False)
        require(completed.returncode == 0, "R60_SOURCE_OR_FROZEN_CHAIN_PROCESS_FAILED")
    result = read_json(args.output / "result.json")
    require(result.get("status") == "PASS" and result.get("frozen") is bool(args.exe) and
            result.get("source_sha") == args.source_sha, "R60_CHAIN_PROOF_INCOMPLETE")
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
