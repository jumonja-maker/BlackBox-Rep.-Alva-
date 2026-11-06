"""Owner-authorized, exact-main, independently tested cumulative v0.6.0 release.

Fail closed on a moved main, unreviewed release PR, missing R60 5h30
evidence, incomplete CI, older-release mutation, or missing artifact digest.
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

REPO = "jumonja-maker/BlackBox-Rep.-Alva-"
TAG = "v0.6.0"
BASE_MAIN_SHA = "57bb147892ef5dd514e179d325dd2a412f943216"
R60_SOURCE_SHA = "de03faa173de234071cd2198750bebfb41839185"
R60_PR = 41
RELEASE_PR = 42
RELEASE_BRANCH = "release/v060-r10-r60-20261106"
PR_FILES = {
    ".github/workflows/bb-r60-qa.yml": "modified",
    ".github/workflows/release-v060.yml": "added",
    "blackbox_universal/__init__.py": "modified",
    "docs/RELEASE_v0.6.0.md": "added",
    "pyproject.toml": "modified",
    "tests/test_release_v060_authorization.py": "added",
    "tests/test_review_release_20261028.py": "modified",
    "tools/publish_v060_after_ci.py": "added",
    "tools/release_gate.py": "modified",
}
SHELL_NAME = "BLACK.BOX Universal - independent Windows build and release"
R60_NAME = "BB-R60 Chain Builder exact-source acceptance"
UI_NAME = "BLACK.BOX UI selection contrast"
MAIN_JOBS = {
    "Windows source contracts / a-c",
    "Windows source contracts / d-h",
    "Windows source contracts / i-r",
    "Windows source contracts / s-z",
    "Real Windows GUI / process / ETW integration",
    "Linux compatibility check (independent of Windows release)",
    "Windows portable exe",
    "BB-WAVE-02 exact-source lifecycle scope",
    "BB-WAVE-02 one-hour Standard and Incident Burst lifecycle",
    "Exact-main complete QA gate (artifactless)",
    "BB-WAVE-02 required containers and lifecycle gate",
}
R60_JOBS = {
    "scope",
    "R60 contracts / windows-latest",
    "R60 contracts / ubuntu-latest",
    "R60 actual Windows source / frozen / RU-EN DPI / native",
    "R60 actual persisted 5h30 scheduler and owned recording lifecycle",
    "R60 complete required candidate gates",
}
UI_JOBS = {"Popup contrast / windows", "Popup contrast / offscreen"}
PRIOR_SHA = "74fe0f856776bcee018d79bfeec96f33d2ace0b2"
PRIOR_ZIP_SHA = "01390ec18fbac40accc2ae2774c748994a5dcde7d29421dbdcdacb8555c2cdc4"


def exact_jobs(client, repo, run_id, required):
    response = client(f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100")
    jobs = response.get("jobs") if isinstance(response, dict) else None
    require(isinstance(jobs, list), "CI_JOB_LIST_UNAVAILABLE")
    found = {}
    for job in jobs:
        name = job.get("name")
        if name in required:
            require(name not in found, "DUPLICATE_REQUIRED_JOB")
            found[name] = job
    require(set(found) == required, "REQUIRED_CI_JOBS_INCOMPLETE")
    require(all(j.get("status") == "completed" and j.get("conclusion") == "success"
                for j in found.values()), "REQUIRED_CI_JOB_NOT_GREEN")
    return found


def exact_candidate_run(client, repo, sha, branch, workflow, jobs):
    response = client(f"repos/{repo}/actions/runs?head_sha={sha}&per_page=100")
    runs = response.get("workflow_runs") if isinstance(response, dict) else None
    require(isinstance(runs, list), "CANDIDATE_RUNS_UNAVAILABLE")
    selected = [r for r in runs if r.get("name") == workflow and
                r.get("head_sha") == sha and r.get("event") == "pull_request" and
                r.get("head_branch") == branch and r.get("status") == "completed" and
                r.get("conclusion") == "success"]
    require(len(selected) >= 1, "EXACT_RELEASE_PR_SOURCE_CI_MISSING")
    selected.sort(key=lambda r: r.get("id", 0), reverse=True)
    run = selected[0]
    require(type(run.get("id")) is int, "CI_RUN_ID_INVALID")
    return run, exact_jobs(client, repo, run["id"], jobs)


def endurance_proof(repo, job):
    """Read the mandatory *actual* 5h30 receipt, not a green workflow label."""
    response = subprocess.run(
        ["gh", "api", f"repos/{repo}/actions/jobs/{job['id']}/logs"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=90, check=True,
    )
    marker = "R60_ENDURANCE_RECEIPT "
    records = []
    for line in response.stdout.splitlines():
        if marker in line:
            records.append(json.loads(line.split(marker, 1)[1].strip()))
    require(len(records) == 1, "R60_ENDURANCE_RECEIPT_MISSING_OR_DUPLICATE")
    proof = records[0]
    engine = proof.get("engine") or {}
    recording = proof.get("recording") or {}
    sampling = recording.get("sampling_coverage") or {}
    final = recording.get("database_finalization") or {}
    observe = proof.get("observe_engine") or {}
    cleanup = observe.get("cleanup") or {}
    engine_cleanup = observe.get("engine_cleanup") or {}
    require(proof.get("status") == "PASS" and proof.get("source_sha") ==
            os.environ["V060_SOURCE_PR_SHA"], "R60_ENDURANCE_SOURCE_OR_STATUS_INVALID")
    require(engine.get("actual_invocations") == 331 and
            engine.get("persisted_invocation_span_seconds", 0) >= 19800 and
            engine.get("all_actual_intervals_at_least_requested") is True and
            engine.get("all_actual_cleanup_acknowledgements") is True,
            "R60_331_ACTUAL_READS_NOT_VERIFIED")
    require(sampling.get("persisted_span_seconds", 0) >= 19800 and
            final.get("integrity_ok_databases") == final.get("database_count") and
            final.get("database_count", 0) >= 2 and
            final.get("nonempty_wal_files") == 0 and
            final.get("recording_resources_closed") is True,
            "R60_PERSISTED_RECORDING_OR_SQLITE_NOT_CLOSED")
    require(cleanup.get("confirmed") is True and
            engine_cleanup.get("confirmed") is True and
            engine_cleanup.get("retained_resource_count") == 0 and
            observe.get("workflow_state") == "CANCELLED" and
            observe.get("expected_cancellation_scenario") is True,
            "R60_STOP_OR_OWNERSHIP_NOT_CONFIRMED")
    return {"calls": 331,
            "engine_span_s": engine["persisted_invocation_span_seconds"],
            "recording_span_s": sampling["persisted_span_seconds"],
            "cleanup": "CONFIRMED"}


def authorize(client, repo, sha, upstream):
    require(repo == REPO and bool(re.fullmatch("[0-9a-f]{40}", sha or "")),
            "INVALID_RELEASE_REPOSITORY_OR_SHA")
    require(isinstance(upstream, dict) and upstream.get("status") == "completed"
            and upstream.get("conclusion") == "success"
            and upstream.get("event") == "push"
            and upstream.get("name") == SHELL_NAME
            and upstream.get("head_branch") == "main"
            and upstream.get("head_sha") == sha
            and (upstream.get("head_repository") or {}).get("full_name") == repo,
            "EXACT_MAIN_PUSH_CI_REQUIRED")
    require((client(f"repos/{repo}/git/ref/heads/main").get("object") or {}).get("sha") == sha,
            "MAIN_MOVED")
    main = client(f"repos/{repo}/git/commits/{sha}")
    parent = main.get("parents") or []
    require(len(parent) == 2 and parent[0].get("sha") == BASE_MAIN_SHA,
            "RELEASE_VERSION_MERGE_ANCESTRY_CHANGED")

    r60 = client(f"repos/{repo}/pulls/{R60_PR}")
    require(r60.get("merged") is True and r60.get("merge_commit_sha") == BASE_MAIN_SHA
            and (r60.get("head") or {}).get("sha") == R60_SOURCE_SHA
            and (r60.get("base") or {}).get("ref") == "main",
            "OWNER_APPROVED_R60_SOURCE_CHANGED")
    previous = client(f"repos/{repo}/git/commits/{BASE_MAIN_SHA}")
    require(len(previous.get("parents") or []) == 2 and
            previous["parents"][1].get("sha") == R60_SOURCE_SHA,
            "R60_MAIN_MERGE_PARENT_CHANGED")

    pr = client(f"repos/{repo}/pulls/{RELEASE_PR}")
    require(pr.get("number") == RELEASE_PR and pr.get("merged") is True and
            pr.get("merge_commit_sha") == sha and
            (pr.get("head") or {}).get("ref") == RELEASE_BRANCH and
            (pr.get("base") or {}).get("ref") == "main" and
            (pr.get("head") or {}).get("sha") == parent[1].get("sha"),
            "UNAPPROVED_RELEASE_VERSION_PR")
    files = client(f"repos/{repo}/pulls/{RELEASE_PR}/files?per_page=100")
    require(isinstance(files, list) and pr.get("changed_files") == len(PR_FILES)
            and len(files) == len(PR_FILES) and
            {x.get("filename"): x.get("status") for x in files} == PR_FILES,
            "UNAPPROVED_RELEASE_FILE_SCOPE")

    exact_jobs(client, repo, upstream["id"], MAIN_JOBS)
    source_sha = parent[1]["sha"]
    shell, _ = exact_candidate_run(client, repo, source_sha, RELEASE_BRANCH,
                                   SHELL_NAME, MAIN_JOBS)
    ui, _ = exact_candidate_run(client, repo, source_sha, RELEASE_BRANCH,
                                UI_NAME, UI_JOBS)
    r60_run, r60_jobs = exact_candidate_run(client, repo, source_sha, RELEASE_BRANCH,
                                            R60_NAME, R60_JOBS)
    os.environ["V060_SOURCE_PR_SHA"] = source_sha
    endurance = endurance_proof(repo, r60_jobs[
        "R60 actual persisted 5h30 scheduler and owned recording lifecycle"])
    old = client(f"repos/{repo}/releases/tags/v0.5.4")
    require(old.get("draft") is False and old.get("prerelease") is False
            and old.get("target_commitish") == PRIOR_SHA, "PUBLIC_V054_CHANGED")
    assets = old.get("assets") or []
    require(len(assets) == 2 and
            {a.get("name") for a in assets} ==
            {"BLACK.BOX-Universal-Windows.zip", "BLACK.BOX-Universal-Windows.zip.sha256"},
            "PUBLIC_V054_ASSETS_CHANGED")
    old_zip = next(a for a in assets if a["name"] == "BLACK.BOX-Universal-Windows.zip")
    require(old_zip.get("state") == "uploaded" and old_zip.get("size") == 114144980
            and old_zip.get("digest") == "sha256:" + PRIOR_ZIP_SHA,
            "PUBLIC_V054_ZIP_CHANGED")
    return {"tag": TAG, "main_sha": sha, "release_pr": RELEASE_PR,
            "candidate_sha": source_sha, "main_ci": upstream["id"],
            "source_ci": shell["id"], "ui_ci": ui["id"],
            "r60_ci": r60_run["id"], "r60_endurance": endurance}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--authorize-only", action="store_true")
    args = parser.parse_args()
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("GITHUB_SHA", "")
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("GITHUB_EVENT_NAME") == "workflow_run" and
            os.environ.get("GITHUB_REF") == "refs/heads/main",
            "OWNER_APPROVED_MAIN_WORKFLOW_REQUIRED")
    require(__version__ == VERSION == "0.6.0", "RELEASE_VERSION_NOT_V060")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    upstream = event.get("workflow_run")
    approved = authorize(api, repo, sha, upstream)
    require(subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
            == sha, "RELEASE_CHECKOUT_NOT_EXACT_MAIN")
    preflight(api, repo, sha, TAG)
    if args.authorize_only:
        require(args.archive is None, "ARCHIVE_DURING_AUTHORIZATION")
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write("approved=true\n")
        print("OWNER_AUTHORIZED_V060_RELEASE", json.dumps(approved, sort_keys=True))
        return

    archive = args.archive
    require(archive is not None and archive.is_file() and
            archive.name == "BLACK.BOX-Universal-Windows.zip",
            "V060_ZIP_MISSING")
    sidecar = Path(str(archive) + ".sha256")
    require(sidecar.is_file(), "V060_SIDECAR_MISSING")
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    require(sidecar.read_text(encoding="utf-8-sig").strip() ==
            f"{digest}  {archive.name}", "V060_SHA256_SIDECAR_MISMATCH")
    tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], text=True).strip()
    verified_zip = verify_archive(archive, sha, tree)
    require(verified_zip.get("status") == "VERIFIED_RELEASE_ARCHIVE" and
            verified_zip.get("version") == "0.6.0" and
            verified_zip.get("sha256") == digest and
            verified_zip.get("source_sha") == sha and
            verified_zip.get("source_tree_sha") == tree,
            "V060_ARCHIVE_PROVENANCE_UNVERIFIED")
    subprocess.run(["gh", "release", "create", TAG, str(archive), str(sidecar),
                    "--draft", "--target", sha, "--title",
                    "BLACK.BOX Universal v0.6.0 — R10–R60 Cumulative / Chain Builder",
                    "--notes-file", "docs/RELEASE_v0.6.0.md"],
                   check=True, timeout=900)
    published = publish(api, repo, sha, TAG, archive)
    require(published.get("status") == "PUBLISHED", "V060_PUBLICATION_UNCONFIRMED")
    print("V060_RELEASE_PUBLISHED", json.dumps(
        {"authorization": approved, "release": published, "zip_sha256": digest},
        sort_keys=True))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write(f"## BLACK.BOX Universal {TAG} — verified release\n")
            out.write(f"- Exact source SHA: {sha}\n- ZIP SHA-256: {digest}\n")
            out.write(f"- R60 5h30 acceptance run: {approved['r60_ci']}\n")
            out.write(f"- Main exact CI: {approved['main_ci']}\n")
            out.write(f"- Public URL: {published.get('url')}\n")
            out.write("- GitHub Actions Artifacts: none\n")


if __name__ == "__main__":
    main()
