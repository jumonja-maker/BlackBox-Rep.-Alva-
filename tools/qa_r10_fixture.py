"""Build the existing owned R10 Windows workload on a hosted runner only.

The executable is shared by native, source-Qt and frozen-Qt acceptance.  Its
stdin/stdout oracle is independent of the diagnostic helper being tested.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from tools.qa_deep_inspection import build_probe, file_hash, require, require_hosted_windows, save


def build(output: Path, source_sha: str) -> dict:
    require_hosted_windows()
    require(bool(re.fullmatch(r"[0-9a-f]{40}", source_sha)), "EXACT_SOURCE_SHA_REQUIRED")
    from blackbox_universal.provenance import source_identity
    identity = source_identity(source_sha)
    require(identity.get("source_identity_status") == "VERIFIED_EXPECTED_HEAD",
            "R10_FIXTURE_ACTUAL_CHECKOUT_IDENTITY_MISMATCH")
    executable = build_probe(output.resolve())
    receipt = {"status": "PASS", "schema": "blackbox.r10.fixture.v1",
               "source_sha": source_sha, "executable": str(executable),
               "source_identity": identity,
               "sha256": file_hash(executable),
               "source": "EXISTING_COMPILED_OWNED_DEEP_INSPECTION_PROBE",
               "oracle": "INDEPENDENT_NATIVE_PROCESS_STDIN_STDOUT_JSON",
               "physical_interactive_uac": "NOT_TESTED"}
    save(output / "r10-fixture.json", receipt)
    print("R10_FIXTURE_RECEIPT " + json.dumps(receipt, sort_keys=True), flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as stream:
            stream.write("\nR10 owned native fixture: PASS; source `" + source_sha +
                         "`; EXE SHA-256 `" + receipt["sha256"] + "`.\n")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    build(args.output, args.source_sha)


if __name__ == "__main__":
    main()
