"""Release R10 v0.5.5 from only the owner-approved, fully tested main merge.

Both authorization and publication recheck GitHub source identity, exact QA,
existing v0.5.4 and one immutable new-release draft. No Artifacts or force tags.
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

TAG = "v0.5.5"
REPOSITORY = "jumonja-maker/BlackBox-Rep.-Alva-"
CI_NAME = "BLACK.BOX Universal - independent Windows build and release"
R10_MAIN_SHA = "b0e91ca54ebe4055d9d9df3fe6a193c653d45889"
V055_VERSION_MAIN_SHA = "0bfbb56bcd3a5deaa7d72f1bc995ac890c8a00e9"
APPROVED_RELEASE_BRANCH = "release/r10-v055-20261104"
APPROVED_VERSION_HEAD_SHA = "7eb741a1b05d259ab0998c69e53df5620589e570"
APPROVED_REPAIR_BRANCH = "fix/r10-v055-complete-etw-20261104"
APPROVED_ETW_MAIN_SHA = "d3b63fffa2981fb5f41150e24ee2d16e3c7ff573"
APPROVED_REPAIR_HEAD_SHA = "596498968c771ef8b09c14c89b020fcae210e56a"
APPROVED_RELEASE_QA_PR = 37
APPROVED_RELEASE_QA_BRANCH = "fix/r10-v055-release-qa-20261105"
APPROVED_RELEASE_QA_SCOPE = frozenset({
    ".github/workflows/shell-qa.yml",
    "tools/qa_decoder_apps.py",
    "tools/qa_deep_inspection.py",
    "tools/publish_v055_after_ci.py",
    "tests/test_release_v055_authorization.py",
})
PR_NUMBER = 30
PRIOR_RELEASE_SHA = "74fe0f856776bcee018d79bfeec96f33d2ace0b2"
PRIOR_ZIP_SHA256 = "01390ec18fbac40accc2ae2774c748994a5dcde7d29421dbdcdacb8555c2cdc4"
REQUIRED_JOBS = {
    "Windows source contracts / a-c",
    "Windows source contracts / d-h",
    "Windows source contracts / i-r",
    "Windows source contracts / s-z",
    "Real Windows GUI / process / ETW integration",
    "Linux compatibility check (independent of Windows release)",
    "Windows portable exe",
    "Exact-main complete QA gate (artifactless)",
}


def approved_release_source(client, repo: str, sha: str, run: dict) -> dict:
    require(repo == REPOSITORY, "UNEXPECTED_RELEASE_REPOSITORY")
    require(bool(re.fullmatch(r"[a-f0-9]{40}", sha)), "INVALID_RELEASE_SHA")
    require(isinstance(run, dict) and run.get("conclusion") == "success"
            and run.get("status") == "completed"
            and run.get("event") == "push" and run.get("name") == CI_NAME
            and run.get("head_branch") == "main" and run.get("head_sha") == sha
            and (run.get("head_repository") or {}).get("full_name") == repo,
            "EXACT_MAIN_GREEN_CI_REQUIRED")
    require(type(run.get("id")) is int and run["id"] > 0, "INVALID_UPSTREAM_CI_ID")
    current = client(f"repos/{repo}/git/ref/heads/main")
    require(current.get("object", {}).get("sha") == sha, "MAIN_MOVED")
    r10 = client(f"repos/{repo}/pulls/{PR_NUMBER}")
    require(r10.get("merged") is True
            and r10.get("merge_commit_sha") == R10_MAIN_SHA,
            "APPROVED_R10_MERGE_CHANGED")
    # The v0.5.5 version PR already merged on a fully green main commit.
    # The separate owned ETW fixture repair must follow it directly, never
    # authorize an unrelated push or bypass the previously failed release gate.
    version_pr = client(f"repos/{repo}/pulls/31")
    require(version_pr.get("merged") is True
            and version_pr.get("merge_commit_sha") == V055_VERSION_MAIN_SHA
            and (version_pr.get("head") or {}).get("sha") == APPROVED_VERSION_HEAD_SHA
            and (version_pr.get("head") or {}).get("ref") == APPROVED_RELEASE_BRANCH
            and (version_pr.get("base") or {}).get("ref") == "main",
            "APPROVED_V055_VERSION_MERGE_CHANGED")
    version_commit = client(f"repos/{repo}/git/commits/{V055_VERSION_MAIN_SHA}")
    version_parents = version_commit.get("parents")
    require(isinstance(version_parents, list) and len(version_parents) == 2
            and version_parents[0].get("sha") == R10_MAIN_SHA
            and version_parents[1].get("sha") == APPROVED_VERSION_HEAD_SHA,
            "V055_VERSION_MERGE_ANCESTRY_MISMATCH")
    # Preserve the exact owner-approved ETW repair as a fixed ancestor.
    repair = client(f"repos/{repo}/pulls/32")
    require(repair.get("merged") is True
            and repair.get("merge_commit_sha") == APPROVED_ETW_MAIN_SHA
            and (repair.get("head") or {}).get("sha") == APPROVED_REPAIR_HEAD_SHA
            and (repair.get("head") or {}).get("ref") == APPROVED_REPAIR_BRANCH
            and (repair.get("base") or {}).get("ref") == "main",
            "APPROVED_ETW_REPAIR_MERGE_CHANGED")
    repair_commit = client(f"repos/{repo}/git/commits/{APPROVED_ETW_MAIN_SHA}")
    repair_parents = repair_commit.get("parents")
    require(isinstance(repair_parents, list) and len(repair_parents) == 2
            and repair_parents[0].get("sha") == V055_VERSION_MAIN_SHA
            and repair_parents[1].get("sha") == APPROVED_REPAIR_HEAD_SHA,
            "V055_ETW_REPAIR_ANCESTRY_MISMATCH")

    # The only additional authorized merge may be the owner's bounded
    # release-QA correction; not a feature branch, generic main push or force.
    qa = client(f"repos/{repo}/pulls/{APPROVED_RELEASE_QA_PR}")
    require(qa.get("merged") is True and qa.get("merge_commit_sha") == sha
            and (qa.get("head") or {}).get("ref") == APPROVED_RELEASE_QA_BRANCH
            and (qa.get("base") or {}).get("ref") == "main",
            "APPROVED_V055_RELEASE_QA_MERGE_MISSING")
    changed = client(f"repos/{repo}/pulls/{APPROVED_RELEASE_QA_PR}/files?per_page=100")
    require(isinstance(changed, list) and
            qa.get("changed_files") == len(APPROVED_RELEASE_QA_SCOPE) == len(changed)
            and {item.get("filename") for item in changed} == APPROVED_RELEASE_QA_SCOPE
            and all(item.get("status") == "modified" for item in changed),
            "UNAPPROVED_V055_RELEASE_QA_FILE_SCOPE")
    final_commit = client(f"repos/{repo}/git/commits/{sha}")
    parents = final_commit.get("parents")
    require(isinstance(parents, list) and len(parents) == 2
            and parents[0].get("sha") == APPROVED_ETW_MAIN_SHA
            and parents[1].get("sha") == (qa.get("head") or {}).get("sha"),
            "V055_RELEASE_QA_MERGE_ANCESTRY_MISMATCH")
    response = client(f"repos/{repo}/actions/runs/{run['id']}/jobs?per_page=100")
    jobs = response.get("jobs") if isinstance(response, dict) else None
    require(isinstance(jobs, list), "UPSTREAM_CI_JOBS_UNREADABLE")
    found = {}
    for job in jobs:
        if job.get("name") in REQUIRED_JOBS:
            require(job["name"] not in found, "DUPLICATE_REQUIRED_CI_JOB")
            found[job["name"]] = job
    require(set(found) == REQUIRED_JOBS, "INCOMPLETE_REQUIRED_CI_JOBS")
    require(all(job.get("status") == "completed"
                and job.get("conclusion") == "success" for job in found.values()),
            "NON_GREEN_REQUIRED_CI_JOB")
    old = client(f"repos/{repo}/releases/tags/v0.5.4")
    require(old.get("draft") is False and old.get("prerelease") is False
            and old.get("target_commitish") == PRIOR_RELEASE_SHA,
            "PREVIOUS_PUBLIC_RELEASE_CHANGED")
    assets = old.get("assets", [])
    require(len(assets) == 2 and
            {a.get("name") for a in assets} ==
            {"BLACK.BOX-Universal-Windows.zip", "BLACK.BOX-Universal-Windows.zip.sha256"},
            "PREVIOUS_RELEASE_ASSET_INVENTORY_CHANGED")
    zip_asset = next(a for a in assets if a["name"] == "BLACK.BOX-Universal-Windows.zip")
    require(zip_asset.get("size") == 114144980
            and zip_asset.get("state") == "uploaded"
            and zip_asset.get("digest") == "sha256:" + PRIOR_ZIP_SHA256,
            "PREVIOUS_RELEASE_ZIP_CHANGED")
    return {"main_sha": sha, "r10_pr": PR_NUMBER,
            "version_pr": 31, "version_head": APPROVED_VERSION_HEAD_SHA,
            "etw_repair_pr": 32, "etw_repair_head": APPROVED_REPAIR_HEAD_SHA,
            "release_qa_pr": APPROVED_RELEASE_QA_PR,
            "release_qa_head": (qa.get("head") or {}).get("sha"),
            "upstream_ci_run": run["id"], "required_jobs": len(found)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--authorize-only", action="store_true")
    args = parser.parse_args()
    repo = os.getenv("GITHUB_REPOSITORY", "")
    sha = os.getenv("GITHUB_SHA", "")
    require(os.getenv("GITHUB_ACTIONS") == "true"
            and os.getenv("GITHUB_EVENT_NAME") == "workflow_run"
            and os.getenv("GITHUB_REF") == "refs/heads/main",
            "EXACT_MAIN_WORKFLOW_RUN_REQUIRED")
    require(__version__ == VERSION == "0.5.5", "R10_RELEASE_VERSION_MISMATCH")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    run = event.get("workflow_run", {})
    verified = approved_release_source(api, repo, sha, run)
    checked_out = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    require(checked_out == sha, "CHECKOUT_NOT_VERIFIED_MAIN_SHA")
    preflight(api, repo, sha, TAG)
    if args.authorize_only:
        require(args.archive is None, "UNEXPECTED_ARCHIVE_DURING_AUTHORIZATION")
        output = os.environ.get("GITHUB_OUTPUT")
        require(bool(output), "MISSING_AUTHORIZATION_OUTPUT")
        with open(output, "a", encoding="utf-8") as f:
            f.write("approved=true\n")
        print("OWNER_APPROVED_R10_RELEASE_SOURCE", json.dumps(verified, sort_keys=True))
        return
    archive = args.archive
    require(archive is not None and archive.name == "BLACK.BOX-Universal-Windows.zip"
            and archive.is_file(), "R10_RELEASE_ARCHIVE_MISSING")
    sidecar = Path(str(archive) + ".sha256")
    require(sidecar.is_file(), "R10_RELEASE_CHECKSUM_MISSING")
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    require(sidecar.read_text(encoding="utf-8-sig").strip() ==
            f"{digest}  {archive.name}", "R10_CHECKSUM_MISMATCH")
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"],
                                   text=True).strip()
    checked = verify_archive(archive, sha, tree)
    require(checked["status"] == "VERIFIED_RELEASE_ARCHIVE"
            and checked["version"] == "0.5.5"
            and checked["source_sha"] == sha
            and checked["source_tree_sha"] == tree
            and checked["sha256"] == digest, "R10_ARCHIVE_PROVENANCE_UNVERIFIED")
    subprocess.run([
        "gh", "release", "create", TAG, str(archive), str(sidecar),
        "--draft", "--target", sha, "--title",
        "BLACK.BOX Universal v0.5.5 — One-UAC Administrator Session (R10)",
        "--notes-file", "docs/RELEASE_v0.5.5.md",
    ], check=True, timeout=900)
    published = publish(api, repo, sha, TAG, archive)
    require(published["status"] == "PUBLISHED", "R10_RELEASE_NOT_PUBLIC")
    print(json.dumps({"source": verified, "release": published,
                      "zip_sha256": digest}, sort_keys=True, indent=2))
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write("## BLACK.BOX v0.5.5 — verified R10 release\n")
            f.write(f"- Source SHA: {sha}\n")
            f.write(f"- R10 merge: {R10_MAIN_SHA}\n")
            f.write(f"- Version PR: #{verified['version_pr']}\n")
            f.write(f"- Bounded ETW repair PR: #{verified['etw_repair_pr']}\n")
            f.write(f"- Full main CI: {verified['upstream_ci_run']}\n")
            f.write(f"- Windows ZIP SHA-256: {digest}\n")
            f.write(f"- Official release: {published['url']}\n")
            f.write("- GitHub Actions Artifacts: none\n")


if __name__ == "__main__":
    main()
