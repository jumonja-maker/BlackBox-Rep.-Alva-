"""Fail-closed checks for the owner-authorized cumulative v0.6.0 release."""
from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from tools.publish_v060_after_ci import (
    authorize, endurance_proof, BASE_MAIN_SHA, R60_SOURCE_SHA, REPO,
    RELEASE_PR, RELEASE_BRANCH, PR_FILES, RELEASE_MAIN_SHA, RELEASE_HEAD_SHA,
    PUBLISHER_REPAIR_PR, PUBLISHER_REPAIR_BRANCH, PUBLISHER_REPAIR_FILES,
    SHELL_NAME, MAIN_JOBS,
    R60_NAME, R60_JOBS, UI_NAME, UI_JOBS, PRIOR_SHA, PRIOR_ZIP_SHA,
)

SHA = "f" * 40
HEAD = "d" * 40


def job(name, jid=42):
    return {"name": name, "id": jid, "status": "completed", "conclusion": "success"}


def successful_run(name, run_id, sha, branch, event="pull_request"):
    return {"name": name, "id": run_id, "head_sha": sha, "event": event,
            "head_branch": branch, "status": "completed", "conclusion": "success"}


def actual_endurance_receipt():
    return {
        "status": "PASS", "source_sha": HEAD,
        "engine": {"actual_invocations": 331,
                   "persisted_invocation_span_seconds": 19851.781,
                   "all_actual_intervals_at_least_requested": True,
                   "all_actual_cleanup_acknowledgements": True},
        "recording": {
            "sampling_coverage": {"persisted_span_seconds": 19850.36},
            "database_finalization": {"integrity_ok_databases": 3,
                                      "database_count": 3,
                                      "nonempty_wal_files": 0,
                                      "recording_resources_closed": True}},
        "observe_engine": {"workflow_state": "CANCELLED",
                           "expected_cancellation_scenario": True,
                           "cleanup": {"confirmed": True},
                           "engine_cleanup": {"confirmed": True,
                                              "retained_resource_count": 0}}
    }


class CumulativeV060ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.source_runs = [
            successful_run(SHELL_NAME, 301, HEAD, PUBLISHER_REPAIR_BRANCH),
            successful_run(UI_NAME, 302, HEAD, PUBLISHER_REPAIR_BRANCH),
            successful_run(R60_NAME, 303, HEAD, PUBLISHER_REPAIR_BRANCH)]
        self.main_jobs = [job(n, i + 1) for i, n in enumerate(sorted(MAIN_JOBS))]
        self.ui_jobs = [job(n, i + 31) for i, n in enumerate(sorted(UI_JOBS))]
        self.r60_jobs = [job(n, i + 41) for i, n in enumerate(sorted(R60_JOBS))]
        self.head_parent = HEAD
        self.main_ref = SHA
        self.release_pr_merged = True
        self.changed = [{"filename": p, "status": PR_FILES[p]}
                        for p in sorted(PR_FILES)]
        self.repair_pr_merged = True
        self.repair_changed = [{"filename": p, "status": PUBLISHER_REPAIR_FILES[p]}
                               for p in sorted(PUBLISHER_REPAIR_FILES)]
        self.r60_sha = R60_SOURCE_SHA
        self.upstream = successful_run(SHELL_NAME, 321, SHA, "main", "push")
        self.upstream["head_repository"] = {"full_name": REPO}
        self.receipt = actual_endurance_receipt()

    def client(self, endpoint):
        path = endpoint.removeprefix(f"repos/{REPO}/")
        table = {
            "git/ref/heads/main": {"object": {"sha": self.main_ref}},
            f"git/commits/{SHA}": {"parents": [
                {"sha": RELEASE_MAIN_SHA}, {"sha": self.head_parent}]},
            f"git/commits/{RELEASE_MAIN_SHA}": {"parents": [
                {"sha": BASE_MAIN_SHA}, {"sha": RELEASE_HEAD_SHA}]},
            f"pulls/{RELEASE_PR}": {
                "number": RELEASE_PR, "merged": self.release_pr_merged,
                "merge_commit_sha": RELEASE_MAIN_SHA,
                "head": {"sha": RELEASE_HEAD_SHA, "ref": RELEASE_BRANCH},
                "base": {"ref": "main"}, "changed_files": len(self.changed)},
            f"pulls/{RELEASE_PR}/files?per_page=100": self.changed,
            f"pulls/{PUBLISHER_REPAIR_PR}": {
                "number": PUBLISHER_REPAIR_PR, "merged": self.repair_pr_merged,
                "merge_commit_sha": SHA,
                "head": {"sha": HEAD, "ref": PUBLISHER_REPAIR_BRANCH},
                "base": {"ref": "main"}, "changed_files": len(self.repair_changed)},
            f"pulls/{PUBLISHER_REPAIR_PR}/files?per_page=100": self.repair_changed,
            "pulls/41": {
                "merged": True, "merge_commit_sha": BASE_MAIN_SHA,
                "head": {"sha": self.r60_sha},
                "base": {"ref": "main"}},
            f"git/commits/{BASE_MAIN_SHA}": {"parents": [
                {"sha": "a"*40}, {"sha": R60_SOURCE_SHA}]},
            f"actions/runs/{self.upstream['id']}/jobs?per_page=100":
                {"jobs": self.main_jobs},
            f"actions/runs?head_sha={HEAD}&per_page=100":
                {"workflow_runs": self.source_runs},
            "actions/runs/301/jobs?per_page=100": {"jobs": self.main_jobs},
            "actions/runs/302/jobs?per_page=100": {"jobs": self.ui_jobs},
            "actions/runs/303/jobs?per_page=100": {"jobs": self.r60_jobs},
            "releases/tags/v0.5.4": {
                "draft": False, "prerelease": False,
                "target_commitish": PRIOR_SHA,
                "assets": [
                    {"name": "BLACK.BOX-Universal-Windows.zip",
                     "state": "uploaded", "size": 114144980,
                     "digest": "sha256:" + PRIOR_ZIP_SHA},
                    {"name": "BLACK.BOX-Universal-Windows.zip.sha256",
                     "state": "uploaded", "size": 99,
                     "digest": "sha256:" + "0"*64}]},
        }
        if path not in table:
            raise AssertionError("Unexpected GitHub endpoint: " + path)
        return table[path]

    def verify(self):
        log = ("2026-11-06T16:21:48Z R60_ENDURANCE_RECEIPT " +
               json.dumps(self.receipt, sort_keys=True) + "\n")
        with patch("tools.publish_v060_after_ci.subprocess.run",
                   return_value=SimpleNamespace(stdout=log)) as caller:
            result = authorize(self.client, REPO, SHA, self.upstream)
            lifecycle = next(j for j in self.r60_jobs if j["name"] ==
                             "R60 actual persisted 5h30 scheduler and owned recording lifecycle")
            self.assertEqual(caller.call_args.args[0],
                             ["gh", "run", "view", "--repo", REPO,
                              "--job", str(lifecycle["id"]), "--log"])
            return result

    def test_authorized_merged_source_and_all_green_jobs(self):
        proof = self.verify()
        self.assertEqual(proof["main_sha"], SHA)
        self.assertEqual(proof["release_pr"], RELEASE_PR)
        self.assertEqual(proof["publisher_repair_pr"], PUBLISHER_REPAIR_PR)
        self.assertEqual(proof["r60_endurance"]["calls"], 331)
        self.assertGreater(proof["r60_endurance"]["engine_span_s"], 19800)

    def test_moved_main_blocks_even_when_ci_green(self):
        self.main_ref = "e"*40
        with self.assertRaisesRegex(ValueError, "MAIN_MOVED"):
            self.verify()

    def test_wrong_merge_parent_blocks(self):
        self.head_parent = "e"*40
        with self.assertRaisesRegex(ValueError, "UNAPPROVED_PUBLISHER_REPAIR_PR"):
            self.verify()
        self.head_parent = HEAD
        self.repair_pr_merged = False
        with self.assertRaisesRegex(ValueError, "UNAPPROVED_PUBLISHER_REPAIR_PR"):
            self.verify()

    def test_unmerged_original_release_pr_blocks(self):
        self.release_pr_merged = False
        with self.assertRaisesRegex(ValueError, "UNAPPROVED_RELEASE_VERSION_PR"):
            self.verify()

    def test_changed_publisher_repair_file_scope_blocks(self):
        self.repair_changed[0]["filename"] = "blackbox_universal/maintenance.py"
        with self.assertRaisesRegex(ValueError, "UNAPPROVED_PUBLISHER_REPAIR_FILE_SCOPE"):
            self.verify()
        self.repair_changed[0]["filename"] = sorted(PUBLISHER_REPAIR_FILES)[0]
        self.repair_changed[0]["status"] = "removed"
        with self.assertRaisesRegex(ValueError, "UNAPPROVED_PUBLISHER_REPAIR_FILE_SCOPE"):
            self.verify()

    def test_changed_pr_file_or_added_scope_blocks(self):
        self.changed[0]["filename"] = "blackbox_universal/maintenance.py"
        with self.assertRaisesRegex(ValueError, "UNAPPROVED_RELEASE_FILE_SCOPE"):
            self.verify()
        self.changed[0]["filename"] = sorted(PR_FILES)[0]
        self.changed[0]["status"] = "removed"
        with self.assertRaisesRegex(ValueError, "UNAPPROVED_RELEASE_FILE_SCOPE"):
            self.verify()

    def test_wrong_r60_source_identity_blocks(self):
        self.r60_sha = "e"*40
        with self.assertRaisesRegex(ValueError, "OWNER_APPROVED_R60_SOURCE_CHANGED"):
            self.verify()

    def test_failed_mandatory_shell_job_blocks(self):
        self.main_jobs[0]["conclusion"] = "skipped"
        with self.assertRaisesRegex(ValueError, "REQUIRED_CI_JOB_NOT_GREEN"):
            self.verify()

    def test_r60_long_lifecycle_cannot_be_skipped(self):
        self.r60_jobs[-1]["conclusion"] = "failure"
        with self.assertRaisesRegex(ValueError, "REQUIRED_CI_JOB_NOT_GREEN"):
            self.verify()

    def test_missing_main_ui_or_r60_run_blocks(self):
        self.source_runs = self.source_runs[:1]
        with self.assertRaisesRegex(ValueError, "EXACT_RELEASE_PR_SOURCE_CI_MISSING"):
            self.verify()

    def test_missing_actual_reads_and_duration_blocks(self):
        self.receipt["engine"]["actual_invocations"] = 330
        with self.assertRaisesRegex(ValueError, "R60_331_ACTUAL_READS_NOT_VERIFIED"):
            self.verify()
        self.receipt["engine"]["actual_invocations"] = 331
        self.receipt["recording"]["sampling_coverage"]["persisted_span_seconds"] = 19799
        with self.assertRaisesRegex(ValueError, "R60_PERSISTED_RECORDING_OR_SQLITE_NOT_CLOSED"):
            self.verify()

    def test_unconfirmed_stop_or_wal_blocks(self):
        self.receipt["observe_engine"]["cleanup"]["confirmed"] = False
        with self.assertRaisesRegex(ValueError, "R60_STOP_OR_OWNERSHIP_NOT_CONFIRMED"):
            self.verify()
        self.receipt["observe_engine"]["cleanup"]["confirmed"] = True
        self.receipt["recording"]["database_finalization"]["nonempty_wal_files"] = 1
        with self.assertRaisesRegex(ValueError, "R60_PERSISTED_RECORDING_OR_SQLITE_NOT_CLOSED"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
