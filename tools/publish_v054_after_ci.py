"""Publish v0.5.4 from the exact owner-approved R00 recovery merge after green main CI.

GitHub Actions Artifacts are never used. The genuine portable ZIP and checksum
are uploaded directly to GitHub Releases only from their verified Windows runner.
Existing tags and releases are never replaced.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from blackbox_universal import __version__
from tools.publish_verified_draft import api, preflight, publish, require
from tools.release_gate import VERSION, verify_archive

TAG = "v0.5.4"
CI_NAME = "BLACK.BOX Universal - independent Windows build and release"
REPOSITORY = "jumonja-maker/BlackBox-Rep.-Alva-"
INVESTIGATION_MERGE_SHA = "864fce95dc4b6f19dd0c2950d1fecce5a9b6feb0"
APPROVED_REPAIR_BRANCH = "fix/r00-v054-main-qa-recovery-20261031"


def approved_release_source(client, repo: str, sha: str, run: dict) -> dict:
    """Independently verify merged PR #27 followed by one exact approved fix PR.

    The new source *must* be a two-parent GitHub merge commit based directly
    on the original owner-approved PR #27 merge, never a future unrelated push.
    """
    require(repo == REPOSITORY, "UNEXPECTED_RELEASE_REPOSITORY")
    require(bool(re.fullmatch(r"[a-f0-9]{40}", sha)), "INVALID_SOURCE_SHA")
    require(isinstance(run, dict) and run.get("conclusion") == "success" and
            run.get("event") == "push" and run.get("name") == CI_NAME and
            run.get("head_branch") == "main" and
            run.get("head_sha") == sha and
            (run.get("head_repository") or {}).get("full_name") == repo,
            "GREEN_EXACT_MAIN_QA_REQUIRED")
    current = client(f"repos/{repo}/git/ref/heads/main")
    require(current.get("object", {}).get("sha") == sha, "MAIN_MOVED")
    investigation = client(f"repos/{repo}/pulls/27")
    require(investigation.get("merged") is True and
            investigation.get("merge_commit_sha") == INVESTIGATION_MERGE_SHA,
            "PR27_MERGE_NOT_VERIFIED")
    pulls = client(f"repos/{repo}/pulls?state=closed&per_page=100")
    require(isinstance(pulls, list), "INVALID_RECOVERY_PR_LIST")
    qualified = [
        pr for pr in pulls
        if pr.get("merged_at") and pr.get("merge_commit_sha") == sha
        and (pr.get("head") or {}).get("ref") == APPROVED_REPAIR_BRANCH
        and (pr.get("base") or {}).get("ref") == "main"
    ]
    require(len(qualified) == 1, "OWNER_APPROVED_RECOVERY_MERGE_MISSING")
    commit = client(f"repos/{repo}/git/commits/{sha}")
    parents = commit.get("parents")
    require(isinstance(parents, list) and len(parents) == 2 and
            parents[0].get("sha") == INVESTIGATION_MERGE_SHA and
            parents[1].get("sha") == qualified[0]["head"]["sha"],
            "RECOVERY_MERGE_ANCESTRY_MISMATCH")
    return {"main_sha": sha, "original_pr": 27,
            "recovery_pr": qualified[0].get("number"),
            "recovery_head": qualified[0]["head"]["sha"],
            "upstream_ci_run": run.get("id")}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--authorize-only", action="store_true")
    args = parser.parse_args()
    repo = os.getenv("GITHUB_REPOSITORY", "")
    sha = os.getenv("GITHUB_SHA", "")
    require(os.getenv("GITHUB_ACTIONS") == "true" and
            os.getenv("GITHUB_EVENT_NAME") == "workflow_run" and
            os.getenv("GITHUB_REF") == "refs/heads/main",
            "EXACT_WORKFLOW_RUN_REQUIRED")
    require(__version__ == VERSION == "0.5.4", "RELEASE_VERSION_MISMATCH")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    run = event.get("workflow_run", {})
    verified = approved_release_source(api, repo, sha, run)
    checked_out = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True).strip()
    require(checked_out == sha, "CHECKED_OUT_SOURCE_SHA_MISMATCH")
    preflight(api, repo, sha, TAG)
    if args.authorize_only:
        require(args.archive is None, "UNEXPECTED_AUTHORIZATION_ARCHIVE")
        output = os.environ.get("GITHUB_OUTPUT")
        require(bool(output), "GITHUB_OUTPUT_MISSING")
        with open(output, "a", encoding="utf-8") as stream:
            stream.write("approved=true\n")
        print("EXACT_OWNER_APPROVED_RELEASE_SOURCE", json.dumps(verified, sort_keys=True))
        return
    archive = args.archive
    require(archive is not None and archive.name == "BLACK.BOX-Universal-Windows.zip"
            and archive.is_file(), "RELEASE_ARCHIVE_MISSING")
    sidecar = Path(str(archive) + ".sha256")
    require(sidecar.is_file(), "RELEASE_CHECKSUM_MISSING")
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    require(sidecar.read_text(encoding="utf-8-sig").strip() ==
            f"{digest}  {archive.name}", "CHECKSUM_MISMATCH")
    tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], text=True).strip()
    result = verify_archive(archive, sha, tree)
    require(result["status"] == "VERIFIED_RELEASE_ARCHIVE" and
            result["source_sha"] == sha and
            result["sha256"] == digest, "RELEASE_PROVENANCE_INVALID")
    subprocess.run([
        "gh", "release", "create", TAG, str(archive), str(sidecar),
        "--draft", "--target", sha, "--title",
        "BLACK.BOX Universal v0.5.4 — Evidence Graph & Guided Diagnostics",
        "--notes-file", "docs/RELEASE_v0.5.4.md",
    ], check=True, timeout=900)
    published = publish(api, repo, sha, TAG, archive)
    require(published["status"] == "PUBLISHED", "PUBLICATION_NOT_CONFIRMED")
    print(json.dumps({"source": verified, "release": published,
                      "zip_sha256": digest}, indent=2))
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as out:
            out.write("## BLACK.BOX v0.5.4 — verified publication\n\n")
            out.write(f"- Exact main SHA: {sha}\n")
            out.write(f"- Recovery PR: #{verified['recovery_pr']}\n")
            out.write(f"- Upstream green CI: {verified['upstream_ci_run']}\n")
            out.write(f"- ZIP SHA-256: {digest}\n")
            out.write(f"- Release: {published['url']}\n")
            out.write("- GitHub Actions Artifacts: NONE\n")


if __name__ == "__main__":
    main()
