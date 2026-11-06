"""Prepare actual hosted fixtures and invoke the same R60 source/frozen QA CLI."""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from blackbox_core.chain_qa import file_hash, read_json, require, save, source_proof


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


def _standard_token_precondition(value, pid):
    """Project only typed scalar token facts, never arbitrary failure strings."""
    def scalars(mapping, keys):
        mapping = mapping if type(mapping) is dict else {}
        return {key: item if item is None or type(item) is bool or
                type(item) is int and 0 <= item <= 2**63 - 1 else None
                for key in keys for item in (mapping.get(key),)}
    value = value if type(value) is dict else {}
    own = value.get("own_token", {})
    mode = value.get("privilege", {})
    mode = mode if type(mode) is dict else {}
    result = {"status": value.get("status") if value.get("status") in ("COLLECTING", "OBSERVED") else "NOT_ESTABLISHED",
        "own_token": scalars(own, ("pid", "elevated", "elevation_type")),
        "privilege": {"mode": mode.get("mode") if mode.get("mode") in ("STANDARD", "ADMINISTRATOR") else None,
                      **scalars(mode, ("windows",))},
        "gate_conditions": scalars(value.get("gate_conditions"), ("privilege_standard", "raw_token_elevation_false"))}
    facts = value.get("current_token_facts", {})
    if (type(facts) is not dict or facts.get("schema") != "blackbox.r60.current-token-facts/1" or
            facts.get("pid") != pid):
        result["current_token_facts"] = {"status": "NOT_BOUND_OR_NOT_COLLECTED"}
        return result
    token = facts.get("process_token", {})
    token = token if type(token) is dict else {}
    integrity = token.get("integrity", {})
    integrity = integrity if type(integrity) is dict else {}
    sid = integrity.get("sid")
    privileges = token.get("privileges")
    projected = None
    if type(privileges) is list and len(privileges) <= 256:
        projected = []
        for item in privileges:
            if (type(item) is not dict or type(item.get("name")) is not str or
                    re.fullmatch(r"Se[A-Za-z0-9]{1,64}Privilege", item["name"]) is None):
                projected = None
                break
            projected.append({"name": item["name"], **scalars(item,
                ("attributes", "enabled", "enabled_by_default", "removed"))})
    result["current_token_facts"] = {"status": "OBSERVED_SCALAR_PROJECTION", "pid": pid,
        **scalars(facts, ("effective_administrators_member",)),
        "process_token": {**scalars(token, ("elevation_raw", "elevated", "elevation_type", "has_restrictions_raw")),
            "integrity": {"sid": sid if type(sid) is str and re.fullmatch(r"S-1-16-[0-9]{1,10}", sid) else None,
                          **scalars(integrity, ("rid", "attributes"))},
            "administrators_group": scalars(token.get("administrators_group"), ("present", "attributes", "enabled", "deny_only")),
            "privileges": projected, "is_token_restricted": scalars(token.get("is_token_restricted"), ("available", "value"))},
        "cleanup": scalars(facts.get("cleanup"), ("confirmed",))}
    return result


def _medium_result_diagnostic(path, child, *, source_sha, frozen, started_ns):
    try:
        before = _guard_stamp(path)
        if before is None:
            return {"status": "RESULT_NOT_PRESENT_OR_UNREADABLE"}
        value = read_json(path, maximum=4 * 1024**2)
        started = value.get("started_monotonic_ns")
        require(value.get("schema") == "blackbox.r60.chain-native-qa/1" and
                value.get("pid") == child.get("pid") and value.get("source_sha") == source_sha and
                value.get("frozen") is frozen and value.get("standard_token") is True and
                type(started) is int and started_ns <= started <= time.monotonic_ns(),
                "R60_MEDIUM_RESULT_NOT_BOUND_TO_CURRENT_CHILD")
        precondition = value.get("standard_token_precondition", {})
        require(type(precondition) is dict and (not precondition or
                precondition.get("schema") == "blackbox.r60.standard-token-precondition/1" and
                precondition.get("pid") == child["pid"] and precondition.get("source_sha") == source_sha),
                "R60_MEDIUM_PRECONDITION_NOT_BOUND_TO_CURRENT_CHILD")
        require(_guard_stamp(path) == before, "R60_MEDIUM_RESULT_CHANGED_DURING_READBACK")
        return {"status": "BOUND_CURRENT_CHILD_RESULT", "pid": child["pid"], "source_sha": source_sha,
            "result_status": value.get("status") if value.get("status") in ("PASS", "FAIL") else "UNKNOWN",
            "node_count": value.get("node_count") if type(value.get("node_count")) is int else None,
            "standard_token_precondition": _standard_token_precondition(precondition, child["pid"]),
            "scope": "ACTUAL_FAILED_OR_SUCCESSFUL_MEDIUM_QA_PRECONDITION_FACTS_NOT_RELAXED_AUTHORIZATION"}
    except Exception as error:
        return {"status": "RESULT_READBACK_UNCONFIRMED", "error_type": type(error).__name__[:64]}


def _diagnose_windowed_bootstrap(args, interpreter, launch):
    """Two owned bootstrap controls, never an application/native-query retry."""
    output = args.output.resolve().with_name(args.output.name + "-bootstrap")
    output.mkdir(parents=True, exist_ok=False)
    interpreter = Path(interpreter).resolve(strict=True)
    original_hash = file_hash(interpreter)
    with_marker, without_marker = output / "with-option.entered", output / "without-option.entered"
    with_metadata, without_metadata = output / "with-option.json", output / "without-option.json"
    # Identical script and cwd in both commands. Only -X faulthandler differs.
    # sys is already a builtin runtime module: no stdlib filesystem import
    # precedes this first exclusive marker write.
    script = "\n".join((
        "open(" + repr(str(with_marker)) + " if 'faulthandler' in __import__('sys')._xoptions else " +
            repr(str(without_marker)) + ", 'xb').write(b'ENTRY_REACHED\\n')",
        "import sys, os, json, faulthandler",
        "enabled_option = 'faulthandler' in sys._xoptions",
        "metadata = {'schema': 'blackbox.r60.windowed-bootstrap/1', 'pid': os.getpid(), " +
            "'source_sha': " + repr(args.source_sha) + ", 'option_present': enabled_option, " +
            "'stderr_is_none': sys.stderr is None, 'faulthandler_enabled': faulthandler.is_enabled(), " +
            "'version': list(sys.version_info[:3])}",
        "with open(" + repr(str(with_metadata)) + " if enabled_option else " + repr(str(without_metadata)) +
            ", 'x', encoding='ascii') as stream:",
        "    json.dump(metadata, stream, ensure_ascii=True, sort_keys=True)",
    ))
    cases, child_receipts = [], []
    for option in (True, False):
        command = [str(interpreter)] + (["-X", "faulthandler"] if option else []) + ["-c", script]
        try:
            child = launch(command, cwd=ROOT, timeout_seconds=30, medium_integrity=True)
        except BaseException as error:
            print("R60_MEDIUM_BOOTSTRAP_CASE " + json.dumps({"option_present": option,
                "source_sha": args.source_sha, "status": "CHILD_RESULT_NOT_RETURNED", "pid": None,
                "exit_code": None, "error_type": type(error).__name__[:64],
                "scope": "BOOTSTRAP_DIAGNOSTIC_NOT_APPLICATION_ACCEPTANCE"}, sort_keys=True), flush=True)
            raise
        marker = with_marker if option else without_marker
        metadata_path = with_metadata if option else without_metadata
        code = child.get("exit_code")
        observed = {"option_present": option, "source_sha": args.source_sha, "pid": child.get("pid"),
            "exit_code": code, "windows_status_hex": "0x%08x" % (code & 0xffffffff) if type(code) is int else None,
            "token_integrity": child.get("token_integrity"), "child_token_integrity": child.get("child_token_integrity"),
            "medium_integrity_requested": child.get("medium_integrity_requested"),
            "job_assigned_before_resume": child.get("job_assigned_before_resume"),
            "parent_token_unchanged": child.get("parent_token_unchanged"),
            "first_statement_marker_present": marker.is_file() and not marker.is_symlink(),
            "bootstrap_metadata": None, "scope": "BOOTSTRAP_DIAGNOSTIC_NOT_APPLICATION_ACCEPTANCE"}
        # Retain the real process exit/token facts before any readback refuses
        # an unreadable, missing, malformed or mismatched bootstrap result.
        print("R60_MEDIUM_BOOTSTRAP_CASE " + json.dumps(observed, sort_keys=True), flush=True)
        require(child.get("token_integrity", {}).get("sid") == "S-1-16-8192" and
                child.get("child_token_integrity", {}).get("sid") == "S-1-16-8192" and
                child.get("medium_integrity_requested") is True and
                child.get("job_assigned_before_resume") is True and child.get("parent_token_unchanged") is True,
                "R60_BOOTSTRAP_ACTUAL_MEDIUM_TOKEN_OR_JOB_PROOF_MISSING")
        if marker.exists():
            require(not marker.is_symlink() and marker.is_file() and marker.stat().st_size == 14 and
                    marker.read_bytes() == b"ENTRY_REACHED\n",
                    "R60_BOOTSTRAP_FIRST_STATEMENT_MARKER_INVALID")
        if metadata_path.exists():
            metadata = read_json(metadata_path, maximum=8192)
            require(set(metadata) == {"schema", "pid", "source_sha", "option_present", "stderr_is_none",
                                      "faulthandler_enabled", "version"} and
                    metadata["schema"] == "blackbox.r60.windowed-bootstrap/1" and
                    metadata["pid"] == child["pid"] and metadata["source_sha"] == args.source_sha and
                    metadata["option_present"] is option and type(metadata["stderr_is_none"]) is bool and
                    type(metadata["faulthandler_enabled"]) is bool and type(metadata["version"]) is list and
                    len(metadata["version"]) == 3 and all(type(value) is int and 0 <= value <= 65535
                                                       for value in metadata["version"]) and
                    observed["first_statement_marker_present"], "R60_BOOTSTRAP_METADATA_NOT_BOUND_TO_ACTUAL_CHILD")
            observed["bootstrap_metadata"] = metadata
        print("R60_MEDIUM_BOOTSTRAP_READBACK " + json.dumps(observed, sort_keys=True), flush=True)
        require(file_hash(interpreter) == original_hash, "R60_BOOTSTRAP_INTERPRETER_CHANGED")
        cases.append(observed)
        child_receipts.append(child)
    first, second = cases
    baseline = second["bootstrap_metadata"] or {}
    dacl_policy = [row.get("qa_default_dacl_adjustment", {}) for row in child_receipts]
    policy_equal = (all(type(row.get("after")) is dict and row.get("child_readback") == row["after"]
                        for row in dacl_policy) and dacl_policy[0]["after"] == dacl_policy[1]["after"])
    require(policy_equal, "R60_BOOTSTRAP_EPHEMERAL_TOKEN_DACL_POLICY_CHANGED")
    supported = (first["exit_code"] == 1 and not first["first_statement_marker_present"] and
        first["bootstrap_metadata"] is None and second["exit_code"] == 0 and
        second["first_statement_marker_present"] and baseline.get("stderr_is_none") is True and
        baseline.get("faulthandler_enabled") is False)
    proof = {"status": "OBSERVED", "scope": "BOOTSTRAP_DIAGNOSTIC_NOT_APPLICATION_ACCEPTANCE",
        "source_sha": args.source_sha, "interpreter_sha256": original_hash, "cases": cases,
        "same_interpreter_script_and_cwd": True, "same_medium_token_default_dacl_policy": policy_equal,
        "separate_owned_ephemeral_tokens": True, "hypothesis_supported": supported,
        "application_or_native_query_retried": False, "application_acceptance_established": False}
    save(output / "result.json", proof)
    print("R60_MEDIUM_BOOTSTRAP_DIAGNOSTIC " + json.dumps({**proof,
        "result_sha256": file_hash(output / "result.json")}, sort_keys=True), flush=True)
    return proof


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
    diagnose_bootstrap = getattr(args, "diagnose_windowed_bootstrap", False)
    require(not diagnose_bootstrap or args.standard_token and not args.exe and not args.gui_only,
            "R60_BOOTSTRAP_DIAGNOSIS_REQUIRES_SOURCE_MEDIUM_ONLY")
    evidence = args.evidence_root
    if evidence is None:
        require(args.exe is None and args.decoder is not None, "R60_REAL_DECODER_EVIDENCE_REQUIRED")
        from tools.qa_wave02 import run as prepare_actual_evidence
        evidence = args.output.with_name(args.output.name + "-actual-wave02")
        prepare_actual_evidence(argparse.Namespace(output=evidence, decoder=args.decoder,
            source_sha=args.source_sha, probe=args.probe, diagnostic_helper=args.diagnostic_helper, container="full"))
    # pythonw has no guaranteed stderr descriptor before application startup.
    # Keep console diagnostics on console Python; windowed source and packaged
    # EXE use their explicit QA guard, without a console-only startup option.
    executable = ([str(args.exe.resolve(strict=True))] if args.exe else
        [sys.executable] + ([] if args.standard_token else ["-X", "faulthandler"]) + [str(ROOT / "app.py")])
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
                if diagnose_bootstrap:
                    _diagnose_windowed_bootstrap(args, command[0], restricted_child)
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
        print("R60_CHAIN_STANDARD_TOKEN_RESULT " + json.dumps(_medium_result_diagnostic(args.output / "result.json", child,
            source_sha=args.source_sha, frozen=bool(args.exe), started_ns=started_ns), sort_keys=True), flush=True)
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
    parser.add_argument("--diagnose-windowed-bootstrap", action="store_true",
                        help="Run two separate controlled Medium pythonw startup diagnostics before the single app launch")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
