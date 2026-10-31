"""Launch source or actual frozen R10 GUI, then independently verify its receipt.

The frozen child runs outside the source tree with Python absent from PATH.
No executable, screenshot or evidence file is transferred between runners.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--exe", type=Path)
    args = parser.parse_args()
    require(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "R10_HOSTED_WINDOWS_REQUIRED")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    command = [str(args.exe.resolve(strict=True))] if args.exe else [sys.executable, str(ROOT / "app.py")]
    command += ["--r10-e2e", str(output), "--r10-probe", str(args.probe.resolve(strict=True)),
                "--qa-commit-sha", args.source_sha]
    environment = dict(os.environ)
    environment["QT_QPA_PLATFORM"] = "offscreen"
    if args.exe:
        environment["PATH"] = os.pathsep.join([str(Path(os.environ["SystemRoot"]) / "System32"), os.environ["SystemRoot"]])
        environment.pop("PYTHONPATH", None)
        environment.pop("PYTHONHOME", None)
    receipt = {"status": "FAIL", "source_sha": args.source_sha, "frozen": bool(args.exe),
               "physical_uac_secure_desktop": "NOT_TESTED"}
    try:
        completed = subprocess.run(command, cwd=output if args.exe else ROOT, env=environment,
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
        (output / "gui-process.log").write_text((completed.stdout + completed.stderr)[-96000:], encoding="utf-8")
        proof_path = output / "r10-gui.json"
        require(proof_path.is_file() and proof_path.stat().st_size <= 2 * 1024 * 1024, "R10_GUI_RECEIPT_REQUIRED")
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        if completed.returncode != 0 or proof.get("status") != "PASS":
            failure = {key: proof.get(key) for key in ("status", "phase", "scale", "reason", "traceback",
                "cleanup_error", "failure_state", "final_cleanup_state", "close_progress", "unexpected_dialogs", "lifecycle_signals")}
            print("R10_GUI_CHILD_FAILURE_RECEIPT " + json.dumps(failure, ensure_ascii=False), flush=True)
        require(completed.returncode == 0 and proof.get("status") == "PASS",
                "R10_GUI_FAILURE:" + str(proof.get("phase")) + ":" + str(proof.get("reason")))
        require(proof.get("actual_source_sha") == args.source_sha and
                proof.get("source_identity_status") == "VERIFIED_EXPECTED_HEAD", "R10_GUI_EXACT_SHA_REQUIRED")
        require(proof.get("frozen") is bool(args.exe), "R10_GUI_FORM_MISMATCH")
        require(len(proof["launches"]) == 1 and proof["launches"][0]["elevated"] is True and
                proof["launches"][0]["path"] == "PRODUCTION_SHELLEXECUTEEXW_RUNAS", "R10_GUI_ONE_REAL_RUNAS_REQUIRED")
        first, last = proof["initial_admin_session"], proof["final_admin_session"]
        require(first["elevated_verified"] is True and first["permission_level"] == "ADMINISTRATOR" and
                first["helper_identity"]["created_100ns"] > 0 and first["helper_pid"] != proof["gui_pid"],
                "R10_GUI_REAL_HELPER_TOKEN_IDENTITY_REQUIRED")
        require(proof.get("independent_helper_token", {}).get("elevated") is True and
                proof["independent_helper_token"]["pid"] == first["helper_pid"], "R10_INDEPENDENT_HELPER_TOKEN_REQUIRED")
        require(first["helper_identity"] == last["helper_identity"] and
                first["session_deadline_monotonic"] == last["session_deadline_monotonic"], "R10_GUI_HELPER_OR_DEADLINE_CHANGED")
        require(len(proof["targets"]) == 2 and proof["targets"][0]["pid"] != proof["targets"][1]["pid"] and
                proof["target_switch_cleanup_independent_readback"] is True, "R10_GUI_TWO_TARGET_CLEANUP_REQUIRED")
        require(proof["close"]["helper_exit_verified"] is True and proof["close"]["both_targets_memory_restored"] is True,
                "R10_GUI_CLOSE_POSTCONDITIONS_REQUIRED")
        require(len(proof["geometry"]) == 4 and all(row["text_fits"] for row in proof["geometry"]), "R10_GUI_RU_EN_GEOMETRY_REQUIRED")
        require(proof["investigation"]["independent_json_readback"] is True, "R10_INV3_READBACK_REQUIRED")
        receipt.update(status="PASS", receipt_sha256=digest(proof_path), helper_identity=first["helper_identity"],
            helper_token_authority=first["helper_token_authority"], elevated_launches=1, targets=proof["targets"],
            independent_helper_token=proof["independent_helper_token"],
            source_identity_status=proof["source_identity_status"], scale=proof["scale"],
            cleanup=proof["close"], export_sha256=proof["investigation"]["export_sha256"],
            actions=len(proof["actions"]), confirmations=len(proof["confirmations"]), screenshots=len(proof["geometry"]))
        if args.exe:
            receipt.update(gui_exe_sha256=digest(args.exe.resolve()),
                diagnostic_exe_sha256=digest(args.exe.resolve().parent / "diagnostic/BLACK.BOX-Diagnostic.exe"),
                no_python_on_child_path=True, outside_source_working_directory=True)
    except BaseException as error:
        receipt.update(reason=str(error)[:2000], traceback=traceback.format_exc(limit=6))
        for name in ("progress.json", "blackbox-qa-error.txt"):
            path = output / name
            if path.is_file():
                print("R10_GUI_FAILURE_DETAIL " + name + " " + path.read_text(encoding="utf-8")[-6000:], flush=True)
    (output / "r10-gui-launch.json").write_text(json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8")
    print("R10_GUI_LAUNCH_RECEIPT " + json.dumps(receipt, ensure_ascii=False), flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as stream:
            stream.write("\n### R10 independent GUI acceptance\n\n```json\n" + json.dumps(receipt, indent=2, ensure_ascii=False) + "\n```\n")
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
