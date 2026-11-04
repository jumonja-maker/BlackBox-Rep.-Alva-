"""Fail-closed tests for new owner-approved R10 v0.5.5 publication."""
import copy
import unittest

from tools.publish_v055_after_ci import (
    approved_release_source, REPOSITORY, CI_NAME, APPROVED_RELEASE_BRANCH,
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
        self.version_branch = APPROVED_RELEASE_BRANCH
        self.version_merge = SHA
        self.parent = R10_MAIN_SHA
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
            prefix + "pulls?state=closed&per_page=100": [{
                "merged_at": "2026-11-04T18:00:00Z", "number": 31,
                "merge_commit_sha": self.version_merge,
                "head": {"ref": self.version_branch, "sha": HEAD},
                "base": {"ref": "main"},
            }],
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
        return approved_release_source(
            self.api, REPOSITORY, SHA,
            RUN if run is None else run,
        )

    def test_exact_release_merge_and_eight_green_jobs(self):
        good = self.verify()
        self.assertEqual(good["version_pr"], 31)
        self.assertEqual(good["r10_pr"], 30)
        self.assertEqual(good["required_jobs"], 8)

    def test_cancelled_partial_or_unrelated_ci_never_releases(self):
        for change in (
            {"conclusion": "cancelled"}, {"status": "in_progress"},
            {"head_sha": HEAD}, {"event": "pull_request"},
            {"head_branch": "feature"},
        ):
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError, "EXACT_MAIN_GREEN_CI_REQUIRED"):
                    self.verify({**RUN, **change})

    def test_moved_main_and_unmerged_original_r10_block_release(self):
        self.main = HEAD
        with self.assertRaisesRegex(ValueError, "MAIN_MOVED"):
            self.verify()
        self.main = SHA
        self.r10_merged = False
        with self.assertRaisesRegex(ValueError, "APPROVED_R10_MERGE_CHANGED"):
            self.verify()

    def test_wrong_release_branch_or_ancestry_blocks_publication(self):
        self.version_branch = "unrelated"
        with self.assertRaisesRegex(ValueError, "OWNER_APPROVED_V055_VERSION_MERGE_MISSING"):
            self.verify()
        self.version_branch = APPROVED_RELEASE_BRANCH
        self.parent = HEAD
        with self.assertRaisesRegex(ValueError, "V055_SOURCE_PARENT_MISMATCH"):
            self.verify()

    def test_missing_or_skipped_windows_job_blocks_publication(self):
        self.jobs.pop()
        with self.assertRaisesRegex(ValueError, "INCOMPLETE_REQUIRED_CI_JOBS"):
            self.verify()
        self.jobs = [{"name": name, "status": "completed", "conclusion": "success"}
                     for name in sorted(REQUIRED_JOBS)]
        self.jobs[0]["conclusion"] = "skipped"
        with self.assertRaisesRegex(ValueError, "NON_GREEN_REQUIRED_CI_JOB"):
            self.verify()

    def test_tampered_original_public_release_blocks_publication(self):
        self.old_digest = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "PREVIOUS_RELEASE_ZIP_CHANGED"):
            self.verify()
        self.old_digest = "sha256:" + PRIOR_ZIP_SHA256
        self.old_sha = HEAD
        with self.assertRaisesRegex(ValueError, "PREVIOUS_PUBLIC_RELEASE_CHANGED"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
