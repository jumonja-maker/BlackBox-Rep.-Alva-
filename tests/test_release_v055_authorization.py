"""Owner-authorized v0.5.5 ETW repair release: exact ancestry and QA regression."""
import copy
import unittest

from tools.publish_v055_after_ci import (
    approved_release_source, REPOSITORY, CI_NAME, APPROVED_RELEASE_BRANCH,
    APPROVED_REPAIR_BRANCH, APPROVED_VERSION_HEAD_SHA, V055_VERSION_MAIN_SHA,
    APPROVED_ETW_MAIN_SHA, APPROVED_REPAIR_HEAD_SHA,
    APPROVED_RELEASE_QA_PR, APPROVED_RELEASE_QA_BRANCH, APPROVED_RELEASE_QA_SCOPE,
    R10_MAIN_SHA, PRIOR_RELEASE_SHA, PRIOR_ZIP_SHA256, REQUIRED_JOBS,
)

SHA = "a" * 40
HEAD = "b" * 40
RUN = {
    "id": 123, "status": "completed", "conclusion": "success",
    "event": "push", "name": CI_NAME, "head_branch": "main",
    "head_sha": SHA, "head_repository": {"full_name": REPOSITORY},
}


class R10V055PublicationAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.main = SHA
        self.r10_merged = True
        self.r10_sha = R10_MAIN_SHA
        self.version_merged = True
        self.version_merge = V055_VERSION_MAIN_SHA
        self.version_head = APPROVED_VERSION_HEAD_SHA
        self.version_branch = APPROVED_RELEASE_BRANCH
        self.version_parent = R10_MAIN_SHA
        self.version_other_parent = APPROVED_VERSION_HEAD_SHA
        self.repair_branch = APPROVED_REPAIR_BRANCH
        self.repair_merge = APPROVED_ETW_MAIN_SHA
        self.repair_head = APPROVED_REPAIR_HEAD_SHA
        self.repair_merged = True
        self.repair_parent = V055_VERSION_MAIN_SHA
        self.repair_other_parent = APPROVED_REPAIR_HEAD_SHA
        self.qa_branch = APPROVED_RELEASE_QA_BRANCH
        self.qa_merge = SHA
        self.qa_merged = True
        self.qa_head = HEAD
        self.qa_base = "main"
        self.qa_files = [{"filename": name, "status": "modified"}
                         for name in sorted(APPROVED_RELEASE_QA_SCOPE)]
        self.qa_changed_files = len(self.qa_files)
        self.parent = APPROVED_ETW_MAIN_SHA
        self.other_parent = HEAD
        self.jobs = [{"name": name, "status": "completed", "conclusion": "success"}
                     for name in sorted(REQUIRED_JOBS)]
        self.old_sha = PRIOR_RELEASE_SHA
        self.old_digest = "sha256:" + PRIOR_ZIP_SHA256
        self.visited = []

    def api(self, endpoint):
        self.visited.append(endpoint)
        prefix = "repos/" + REPOSITORY + "/"
        table = {
            prefix + "git/ref/heads/main": {"object": {"sha": self.main}},
            prefix + "pulls/30": {
                "merged": self.r10_merged, "merge_commit_sha": self.r10_sha,
            },
            prefix + "pulls/31": {
                "merged": self.version_merged,
                "merge_commit_sha": self.version_merge,
                "head": {"ref": self.version_branch, "sha": self.version_head},
                "base": {"ref": "main"},
            },
            prefix + "git/commits/" + V055_VERSION_MAIN_SHA: {
                "parents": [{"sha": self.version_parent},
                            {"sha": self.version_other_parent}],
            },
            prefix + "pulls/32": {
                "merged": self.repair_merged, "merge_commit_sha": self.repair_merge,
                "head": {"ref": self.repair_branch, "sha": self.repair_head},
                "base": {"ref": "main"},
            },
            prefix + "git/commits/" + APPROVED_ETW_MAIN_SHA: {
                "parents": [{"sha": self.repair_parent}, {"sha": self.repair_other_parent}],
            },
            prefix + f"pulls/{APPROVED_RELEASE_QA_PR}": {
                "merged": self.qa_merged, "merge_commit_sha": self.qa_merge,
                "head": {"ref": self.qa_branch, "sha": self.qa_head},
                "base": {"ref": self.qa_base},
                "changed_files": self.qa_changed_files,
            },
            prefix + f"pulls/{APPROVED_RELEASE_QA_PR}/files?per_page=100": self.qa_files,
            prefix + "git/commits/" + SHA: {
                "parents": [{"sha": self.parent}, {"sha": self.other_parent}],
            },
            prefix + "actions/runs/123/jobs?per_page=100": {"jobs": self.jobs},
            prefix + "releases/tags/v0.5.4": {
                "draft": False, "prerelease": False,
                "target_commitish": self.old_sha,
                "assets": [
                    {"name": "BLACK.BOX-Universal-Windows.zip",
                     "size": 114144980, "state": "uploaded",
                     "digest": self.old_digest},
                    {"name": "BLACK.BOX-Universal-Windows.zip.sha256",
                     "size": 99, "state": "uploaded", "digest": "sha256:" + "c" * 64},
                ],
            },
        }
        if endpoint not in table:
            raise AssertionError("Unexpected GitHub API endpoint: " + endpoint)
        return copy.deepcopy(table[endpoint])

    def verify(self, run=None):
        return approved_release_source(self.api, REPOSITORY, SHA,
                                       RUN if run is None else run)

    def test_exact_r10_version_repair_chain_and_eight_green_jobs(self):
        receipt = self.verify()
        self.assertEqual(receipt["version_pr"], 31)
        self.assertEqual(receipt["etw_repair_pr"], 32)
        self.assertEqual(receipt["release_qa_pr"], APPROVED_RELEASE_QA_PR)
        self.assertEqual(receipt["r10_pr"], 30)
        self.assertEqual(receipt["required_jobs"], 8)
        self.assertEqual(receipt["main_sha"], SHA)

    def test_cancelled_partial_or_unrelated_ci_cannot_publish(self):
        for change in ({"conclusion": "cancelled"},
                       {"status": "in_progress"}, {"head_sha": HEAD},
                       {"event": "pull_request"}, {"head_branch": "feature"}):
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError, "EXACT_MAIN_GREEN_CI_REQUIRED"):
                    self.verify({**RUN, **change})

    def test_moved_main_or_original_r10_changed_blocks_release(self):
        self.main = HEAD
        with self.assertRaisesRegex(ValueError, "MAIN_MOVED"):
            self.verify()
        self.main = SHA
        self.r10_merged = False
        with self.assertRaisesRegex(ValueError, "APPROVED_R10_MERGE_CHANGED"):
            self.verify()

    def test_version_pr_must_match_original_verified_source(self):
        for attribute, value in (
            ("version_merged", False),
            ("version_merge", HEAD),
            ("version_head", HEAD),
            ("version_branch", "other-version"),
        ):
            with self.subTest(field=attribute):
                before = getattr(self, attribute)
                setattr(self, attribute, value)
                with self.assertRaisesRegex(ValueError, "APPROVED_V055_VERSION_MERGE_CHANGED"):
                    self.verify()
                setattr(self, attribute, before)

    def test_version_ancestry_must_be_exact(self):
        self.version_parent = HEAD
        with self.assertRaisesRegex(ValueError, "V055_VERSION_MERGE_ANCESTRY_MISMATCH"):
            self.verify()
        self.version_parent = R10_MAIN_SHA
        self.version_other_parent = HEAD
        with self.assertRaisesRegex(ValueError, "V055_VERSION_MERGE_ANCESTRY_MISMATCH"):
            self.verify()

    def test_original_etw_repair_and_merge_ancestry_must_be_exact(self):
        self.repair_branch = "unapproved"
        with self.assertRaisesRegex(ValueError, "APPROVED_ETW_REPAIR_MERGE_CHANGED"):
            self.verify()
        self.repair_branch = APPROVED_REPAIR_BRANCH
        self.repair_merge = HEAD
        with self.assertRaisesRegex(ValueError, "APPROVED_ETW_REPAIR_MERGE_CHANGED"):
            self.verify()
        self.repair_merge = APPROVED_ETW_MAIN_SHA
        self.repair_merged = False
        with self.assertRaisesRegex(ValueError, "APPROVED_ETW_REPAIR_MERGE_CHANGED"):
            self.verify()
        self.repair_merged = True
        self.repair_parent = R10_MAIN_SHA
        with self.assertRaisesRegex(ValueError, "V055_ETW_REPAIR_ANCESTRY_MISMATCH"):
            self.verify()
        self.repair_parent = V055_VERSION_MAIN_SHA
        self.repair_other_parent = HEAD
        with self.assertRaisesRegex(ValueError, "V055_ETW_REPAIR_ANCESTRY_MISMATCH"):
            self.verify()

    def test_only_owner_approved_release_qa_merge_can_publish(self):
        self.qa_branch = "unapproved"
        with self.assertRaisesRegex(ValueError, "APPROVED_V055_RELEASE_QA_MERGE_MISSING"):
            self.verify()
        self.qa_branch = APPROVED_RELEASE_QA_BRANCH
        self.qa_merged = False
        with self.assertRaisesRegex(ValueError, "APPROVED_V055_RELEASE_QA_MERGE_MISSING"):
            self.verify()
        self.qa_merged = True
        self.qa_merge = HEAD
        with self.assertRaisesRegex(ValueError, "APPROVED_V055_RELEASE_QA_MERGE_MISSING"):
            self.verify()
        self.qa_merge = SHA
        self.qa_base = "release"
        with self.assertRaisesRegex(ValueError, "APPROVED_V055_RELEASE_QA_MERGE_MISSING"):
            self.verify()
        self.qa_base = "main"
        self.parent = V055_VERSION_MAIN_SHA
        with self.assertRaisesRegex(ValueError, "V055_RELEASE_QA_MERGE_ANCESTRY_MISMATCH"):
            self.verify()
        self.parent = APPROVED_ETW_MAIN_SHA
        self.other_parent = "c" * 40
        with self.assertRaisesRegex(ValueError, "V055_RELEASE_QA_MERGE_ANCESTRY_MISMATCH"):
            self.verify()

    def test_release_qa_file_scope_fails_closed(self):
        self.qa_files[0]["filename"] = "docs/roadmap.md"
        with self.assertRaisesRegex(ValueError, "UNAPPROVED_V055_RELEASE_QA_FILE_SCOPE"):
            self.verify()
        self.qa_files[0]["filename"] = sorted(APPROVED_RELEASE_QA_SCOPE)[0]
        self.qa_files[0]["status"] = "added"
        with self.assertRaisesRegex(ValueError, "UNAPPROVED_V055_RELEASE_QA_FILE_SCOPE"):
            self.verify()
        self.qa_files[0]["status"] = "modified"
        self.qa_changed_files += 1
        with self.assertRaisesRegex(ValueError, "UNAPPROVED_V055_RELEASE_QA_FILE_SCOPE"):
            self.verify()

    def test_any_missing_failed_skipped_or_duplicate_mandatory_job_blocks(self):
        self.jobs.pop()
        with self.assertRaisesRegex(ValueError, "INCOMPLETE_REQUIRED_CI_JOBS"):
            self.verify()
        self.jobs = [{"name": name, "status": "completed", "conclusion": "success"}
                     for name in sorted(REQUIRED_JOBS)]
        for bad in ("skipped", "cancelled", "failure"):
            with self.subTest(bad=bad):
                self.jobs[0]["conclusion"] = bad
                with self.assertRaisesRegex(ValueError, "NON_GREEN_REQUIRED_CI_JOB"):
                    self.verify()
        self.jobs[0]["conclusion"] = "success"
        self.jobs.append(dict(self.jobs[0]))
        with self.assertRaisesRegex(ValueError, "DUPLICATE_REQUIRED_CI_JOB"):
            self.verify()

    def test_changed_prior_public_release_asset_or_source_blocks(self):
        self.old_digest = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "PREVIOUS_RELEASE_ZIP_CHANGED"):
            self.verify()
        self.old_digest = "sha256:" + PRIOR_ZIP_SHA256
        self.old_sha = HEAD
        with self.assertRaisesRegex(ValueError, "PREVIOUS_PUBLIC_RELEASE_CHANGED"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
