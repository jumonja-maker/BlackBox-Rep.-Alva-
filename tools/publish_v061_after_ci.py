"""Fail-closed owner-authorized v0.6.1 release; v0.6.0 remains immutable."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from blackbox_universal import __version__
from tools.release_gate import VERSION, verify_archive
from tools.publish_verified_draft import api, preflight, publish, require
from tools.publish_v060_after_ci import (
    exact_jobs, exact_candidate_run, endurance_proof, MAIN_JOBS,
    UI_JOBS, SHELL_NAME, UI_NAME, R60_JOBS,
)

REPO = "jumonja-maker/BlackBox-Rep.-Alva-"
TAG = "v0.6.1"
BRANCH = "release/v061-expert-integrity-20261114"
PREVIOUS_MAIN_SHA = "d930e774d1b52b3c56ab3164cd940d84acb29808"
EXPERT_PR_SHA = "e338e7eec3c0f7986393d780e60d77329bf287d2"
PREVIOUS_RELEASE_SHA = "b922491ffeb866d24e3948a2f27a88549e5ad9d7"
F3_LONG_SHA = "f3c4078c9e6263497ace9e996748c51fa76bc39f"
OLD_ZIP_SHA = "c0563e3f16274d7785db3dec2a0735abd59674fbcef9db85557c6851cc5ef6b4"
OLD_SIDECAR_SHA = "c0856d49a709ee30b5b615c704564904af04c6f151557f173771d976bdb05ff8"
PR_FILES = {
    ".github/workflows/release-v055.yml": "modified",
    ".github/workflows/release-v060.yml": "modified",
    ".github/workflows/release-v061.yml": "added",
    ".github/workflows/shell-qa.yml": "modified",
    "README.md": "modified",
    "README.ru.md": "modified",
    "docs/EXPERT_TECH_AUDIT_RU.md": "modified",
    "docs/RELEASE_v0.6.0.md": "modified",
    "docs/RELEASE_v0.6.1.md": "added",
    "docs/UPDATES_FEEDBACK_UNINSTALL.md": "modified",
    "pyproject.toml": "modified",
    "src/blackbox_core/__init__.py": "modified",
    "tests/test_expert_packaging.py": "modified",
    "tests/test_review_release_20261028.py": "modified",
    "tests/test_release_v061_authorization.py": "added",
    "tools/publish_v061_after_ci.py": "added",
    "tools/qa_windows_maintenance_e2e.py": "modified",
}
# Exact Git comparison f3 -> PR49 merge was independently verified to contain
# precisely these thirteen paths, none modifying recorder/sampler/helper/engine.
PREVIOUS_NONRECORDER_DELTA = {
    ".github/workflows/bb-expert-qa.yml",
    ".github/workflows/bb-r60-qa.yml",
    ".github/workflows/shell-qa.yml",
    "blackbox_universal/chain_builder.py",
    "blackbox_universal/chain_qa.py",
    "docs/EXPERT_TECH_AUDIT_RU.md",
    "tests/test_chain_workspace_gui.py",
    "tests/test_inv_gui_sections.py",
    "tests/test_qa_failure_truthfulness.py",
    "tests/test_release_v060_authorization.py",
    "tools/publish_v060_after_ci.py",
    "tools/qa_inv_gui.py",
    "tools/qa_linux_unit_gdb.py",
}
QUALIFIED_DELTA_FILES = PREVIOUS_NONRECORDER_DELTA | set(PR_FILES)


def verify_scope(rows, expected=PR_FILES):
    require(isinstance(rows, list) and len(rows) == len(expected),
            "V061_SOURCE_SCOPE_COUNT_MISMATCH")
    actual = {x.get("filename"): x.get("status") for x in rows if isinstance(x, dict)}
    require(len(actual) == len(rows) and actual == expected,
            "V061_UNAPPROVED_RELEASE_SOURCE_FILE")


def verify_qualified_delta(rows):
    require(isinstance(rows, list) and len(rows) == len(QUALIFIED_DELTA_FILES),
            "V061_F3_DELTA_INCOMPLETE")
    actual = {x.get("filename") for x in rows if isinstance(x, dict)}
    require(len(actual) == len(rows) and actual == QUALIFIED_DELTA_FILES,
            "V061_F3_NATIVE_OR_RECORDING_SOURCE_CHANGED")


def verify_old_release(old):
    require(isinstance(old, dict) and old.get("tag_name") == "v0.6.0" and
            old.get("draft") is False and old.get("prerelease") is False and
            old.get("target_commitish") == PREVIOUS_RELEASE_SHA,
            "V061_PREVIOUS_PUBLIC_RELEASE_CHANGED")
    assets = old.get("assets") or []
    require(len(assets) == 2 and {a.get("name") for a in assets} ==
            {"BLACK.BOX-Universal-Windows.zip", "BLACK.BOX-Universal-Windows.zip.sha256"},
            "V061_PREVIOUS_ASSET_SCOPE_CHANGED")
    old_assets = {
        "BLACK.BOX-Universal-Windows.zip": (115958681, OLD_ZIP_SHA),
        "BLACK.BOX-Universal-Windows.zip.sha256": (99, OLD_SIDECAR_SHA),
    }
    for asset in assets:
        size, digest = old_assets[asset["name"]]
        require(asset.get("state") == "uploaded" and asset.get("size") == size and
                asset.get("digest") == "sha256:" + digest,
                "V061_PREVIOUS_ASSET_BYTES_CHANGED")


def require_run(client, repo, run_id, sha, required_jobs):
    data = client(f"repos/{repo}/actions/runs/{run_id}")
    require(data.get("head_sha") == sha and data.get("status") == "completed" and
            data.get("conclusion") == "success", "V061_HISTORICAL_RUN_NOT_GREEN")
    return exact_jobs(client, repo, run_id, required_jobs)


def require_base_recording(repo, job_id, profile, seconds):
    result = subprocess.run(
        ["gh", "run", "view", "--repo", repo, "--job", str(job_id), "--log"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=90, check=True,
    )
    marker = "PROGRAM_ENDURANCE_RECEIPT "
    found = [json.loads(line.split(marker, 1)[1].strip())
             for line in result.stdout.splitlines() if marker in line]
    require(len(found) == 1, "V061_BASE_GUI_RECEIPT_MISSING_OR_DUPLICATE")
    receipt = found[0]
    verdict = receipt.get("verdict") or {}
    cleanup = verdict.get("gui_cleanup") or {}
    require(receipt.get("source_sha") == F3_LONG_SHA and
            receipt.get("status") == "PASS" and receipt.get("profile") == profile and
            receipt.get("requested_seconds") == seconds and
            verdict.get("actual_seconds", 0) >= seconds and
            cleanup.get("status") == "COMPLETED" and
            cleanup.get("helper_alive") is False and
            cleanup.get("running_qthreads") == 0,
            "V061_BASE_GUI_PERSISTED_LIFECYCLE_UNVERIFIED")
    return {"profile": profile, "seconds": verdict["actual_seconds"],
            "actual_source_sha": F3_LONG_SHA}


def authorize(client, repo, sha, upstream):
    require(repo == REPO and bool(re.fullmatch(r"[0-9a-f]{40}", sha or "")),
            "V061_INVALID_REPO_OR_SHA")
    require(isinstance(upstream, dict) and
            upstream.get("name") == SHELL_NAME and
            upstream.get("event") == "push" and
            upstream.get("head_branch") == "main" and
            upstream.get("head_sha") == sha and
            upstream.get("status") == "completed" and
            upstream.get("conclusion") == "success" and
            (upstream.get("head_repository") or {}).get("full_name") == repo,
            "V061_EXACT_MAIN_PUSH_REQUIRED")
    require((client(f"repos/{repo}/git/ref/heads/main").get("object") or {}).get("sha") == sha,
            "V061_MAIN_MOVED")
    main = client(f"repos/{repo}/git/commits/{sha}")
    parents = main.get("parents") or []
    require(len(parents) == 2 and parents[0].get("sha") == PREVIOUS_MAIN_SHA
            and bool(re.fullmatch("[0-9a-f]{40}", parents[1].get("sha") or "")),
            "V061_NORMAL_MERGE_ANCESTRY_CHANGED")

    prs = client(f"repos/{repo}/pulls?state=closed&head=jumonja-maker:{BRANCH}&per_page=100")
    require(isinstance(prs, list) and len(prs) == 1, "V061_RELEASE_PR_NOT_UNIQUE")
    listed = prs[0]
    require(type(listed.get("number")) is int, "V061_RELEASE_PR_NUMBER_INVALID")
    pr = client(f"repos/{repo}/pulls/{listed['number']}")
    require(pr.get("number") == listed["number"], "V061_RELEASE_PR_DETAIL_CHANGED")
    require(type(pr.get("number")) is int and pr.get("merged_at") and
            pr.get("merge_commit_sha") == sha and pr.get("changed_files") == len(PR_FILES) and
            (pr.get("head") or {}).get("sha") == parents[1]["sha"] and
            (pr.get("head") or {}).get("ref") == BRANCH and
            (pr.get("base") or {}).get("ref") == "main",
            "V061_UNAPPROVED_RELEASE_PR")
    verify_scope(client(f"repos/{repo}/pulls/{pr['number']}/files?per_page=100"))

    expert = client(f"repos/{repo}/pulls/49")
    require(expert.get("merged") is True and
            expert.get("merge_commit_sha") == PREVIOUS_MAIN_SHA and
            (expert.get("head") or {}).get("sha") == EXPERT_PR_SHA,
            "V061_PREVIOUS_EXPERT_PR_CHANGED")
    previous_main = client(f"repos/{repo}/git/commits/{PREVIOUS_MAIN_SHA}")
    previous_parents = previous_main.get("parents") or []
    require(len(previous_parents) == 2 and
            previous_parents[0].get("sha") == PREVIOUS_RELEASE_SHA and
            previous_parents[1].get("sha") == EXPERT_PR_SHA,
            "V061_PREVIOUS_MAIN_ANCESTRY_CHANGED")

    verify_old_release(client(f"repos/{repo}/releases/tags/v0.6.0"))
    require((client(f"repos/{repo}/git/ref/tags/v0.6.0").get("object") or {}).get("sha")
            == PREVIOUS_RELEASE_SHA, "V061_PREVIOUS_TAG_MOVED")

    exact_jobs(client, repo, upstream["id"], MAIN_JOBS)
    candidate = parents[1]["sha"]
    source, _ = exact_candidate_run(client, repo, candidate, BRANCH, SHELL_NAME, MAIN_JOBS)
    ui, _ = exact_candidate_run(client, repo, candidate, BRANCH, UI_NAME, UI_JOBS)
    require_run(client, repo, 43543933152, PREVIOUS_MAIN_SHA, MAIN_JOBS)
    require_run(client, repo, 43534452633, EXPERT_PR_SHA, MAIN_JOBS)

    # Reuse the real 5h30 only when an exhaustive exact comparison shows NO
    # changes to source recorder/sampler/native helper/resource ownership.
    diff = client(f"repos/{repo}/compare/{F3_LONG_SHA}...{sha}")
    require(diff.get("status") == "ahead" and diff.get("behind_by") == 0,
            "V061_LONG_WITNESS_NOT_ANCESTOR")
    verify_qualified_delta(diff.get("files"))
    r60_jobs = require_run(client, repo, 42630906763, F3_LONG_SHA, R60_JOBS)
    os.environ["V060_SOURCE_PR_SHA"] = F3_LONG_SHA
    r60 = endurance_proof(
        repo, r60_jobs["R60 actual persisted 5h30 scheduler and owned recording lifecycle"])

    base = client(f"repos/{repo}/actions/runs/42636517392")
    require(base.get("head_sha") == F3_LONG_SHA and
            base.get("status") == "completed" and base.get("conclusion") == "success",
            "V061_BASE_GUI_RUN_NOT_GREEN")
    response = client(f"repos/{repo}/actions/runs/42636517392/jobs?per_page=100")
    jobs = response.get("jobs") if isinstance(response, dict) else None
    require(isinstance(jobs, list), "V061_BASE_GUI_JOBS_UNAVAILABLE")
    names = {
        "STANDARD": "Separate base GUI Standard and Detailed recording acceptance / Real recording / STANDARD / 19800 seconds",
        "DETAILED": "Separate base GUI Standard and Detailed recording acceptance / Real recording / DETAILED / 3600 seconds",
    }
    base_proof = {}
    for profile, name in names.items():
        found = [j for j in jobs if j.get("name") == name]
        require(len(found) == 1 and found[0].get("status") == "completed" and
                found[0].get("conclusion") == "success",
                "V061_BASE_GUI_REQUIRED_JOB_FAILED")
        base_proof[profile] = require_base_recording(
            repo, found[0]["id"], profile, 19800 if profile == "STANDARD" else 3600)

    return {"tag": TAG, "main_sha": sha, "source_sha": candidate,
            "release_pr": pr["number"], "main_ci": upstream["id"],
            "source_ci": source["id"], "ui_ci": ui["id"],
            "historical_r60_sha": F3_LONG_SHA,
            "historical_r60_run": 42630906763,
            "historical_r60_receipt": r60, "historical_base_gui": base_proof,
            "new_r60_5h30_on_v061": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorize-only", action="store_true")
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("GITHUB_SHA", "")
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("GITHUB_EVENT_NAME") == "workflow_run" and
            os.environ.get("GITHUB_REF") == "refs/heads/main",
            "V061_OWNER_APPROVED_MAIN_WORKFLOW_REQUIRED")
    require(__version__ == VERSION == "0.6.1", "V061_VERSION_MISMATCH")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    approved = authorize(api, repo, sha, event.get("workflow_run"))
    require(subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == sha,
            "V061_CHECKOUT_NOT_EXACT_MAIN")
    preflight(api, repo, sha, TAG)

    if args.authorize_only:
        require(args.archive is None, "V061_ARCHIVE_DURING_AUTHORIZATION")
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write("approved=true\n")
        print("V061_OWNER_AUTHORIZED", json.dumps(approved, sort_keys=True))
        return

    path = args.archive
    require(path is not None and path.name == "BLACK.BOX-Universal-Windows.zip"
            and path.is_file() and not path.is_symlink(), "V061_ARCHIVE_MISSING")
    sidecar = Path(str(path) + ".sha256")
    require(sidecar.is_file() and not sidecar.is_symlink(), "V061_SIDECAR_MISSING")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    require(sidecar.read_text(encoding="utf-8-sig").strip() ==
            f"{digest}  {path.name}", "V061_SIDECAR_SHA256_MISMATCH")
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip()
    verified = verify_archive(path, sha, tree)
    require(verified.get("status") == "VERIFIED_RELEASE_ARCHIVE" and
            verified.get("version") == "0.6.1" and
            verified.get("sha256") == digest and
            verified.get("source_sha") == sha and
            verified.get("source_tree_sha") == tree,
            "V061_ARCHIVE_PROVENANCE_INVALID")

    subprocess.run(["gh", "release", "create", TAG, str(path), str(sidecar),
                    "--draft", "--target", sha,
                    "--title", "BLACK.BOX Universal v0.6.1 — Expert Workflow / Evidence Integrity",
                    "--notes-file", "docs/RELEASE_v0.6.1.md"],
                   check=True, timeout=900)
    public = publish(api, repo, sha, TAG, path)
    require(public.get("status") == "PUBLISHED", "V061_RELEASE_PUBLICATION_UNCONFIRMED")
    print("V061_RELEASE_PUBLISHED", json.dumps(
        {"authorization": approved, "release": public, "zip_sha256": digest},
        sort_keys=True))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write(f"## BLACK.BOX Universal {TAG} — verified release\n")
            out.write(f"- Main source: {sha}\n- ZIP sha256: {digest}\n")
            out.write(f"- Previous 5h30 source: {F3_LONG_SHA}\n")
            out.write(f"- Public URL: {public.get('url')}\n")
            out.write("- GitHub Actions Artifacts: none\n")


if __name__ == "__main__":
    main()
