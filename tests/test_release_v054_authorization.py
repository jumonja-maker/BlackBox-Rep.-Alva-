"""Fail-closed unit tests for exact owner-approved v0.5.4 repair-merge authority."""
import copy
import unittest
from tools.publish_v054_after_ci import (
    APPROVED_REPAIR_BRANCH, CI_NAME, INVESTIGATION_MERGE_SHA, REPOSITORY,
    approved_release_source,
)

SOURCE = "a" * 40
FIX_HEAD = "b" * 40
RUN = {
    "conclusion": "success",
    "event": "push",
    "name": CI_NAME,
    "head_branch": "main",
    "head_sha": SOURCE,
    "head_repository": {"full_name": REPOSITORY},
    "id": 42,
}


class ReleaseRecoveryAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.main = SOURCE
        self.original_merge = INVESTIGATION_MERGE_SHA
        self.repair_branch = APPROVED_REPAIR_BRANCH
        self.repair_merge = SOURCE
        self.parent = INVESTIGATION_MERGE_SHA
        self.second_parent = FIX_HEAD
        self.merged = True
        self.checked = []

    def api(self, endpoint):
        self.checked.append(endpoint)
        prefix = f"repos/{REPOSITORY}/"
        routes = {
            prefix + "git/ref/heads/main": {"object": {"sha": self.main}},
            prefix + "pulls/27": {
                "merged": self.merged,
                "merge_commit_sha": self.original_merge,
            },
            prefix + "pulls?state=closed&per_page=100": [{
                "number": 29, "merged_at": "2026-10-31T00:00:00Z",
                "merge_commit_sha": self.repair_merge,
                "head": {"ref": self.repair_branch, "sha": FIX_HEAD},
                "base": {"ref": "main"},
            }],
            prefix + f"git/commits/{SOURCE}": {
                "parents": [{"sha": self.parent}, {"sha": self.second_parent}],
            },
        }
        if endpoint not in routes:
            raise AssertionError("Unexpected fake GitHub API call: " + endpoint)
        return copy.deepcopy(routes[endpoint])

    def verify(self, run=None):
        return approved_release_source(self.api, REPOSITORY, SOURCE,
                                       dict(RUN if run is None else run))

    def test_exact_owned_merge_and_green_ci_accept(self):
        receipt = self.verify()
        self.assertEqual(receipt["original_pr"], 27)
        self.assertEqual(receipt["recovery_pr"], 29)
        self.assertEqual(receipt["upstream_ci_run"], 42)

    def test_cancelled_or_other_branch_ci_cannot_publish(self):
        for changed in ({"conclusion": "cancelled"},
                        {"event": "pull_request"},
                        {"head_branch": "somewhere"},
                        {"head_sha": "c" * 40},
                        {"name": "Other Workflow"}):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(ValueError, "GREEN_EXACT_MAIN_QA_REQUIRED"):
                    self.verify({**RUN, **changed})

    def test_any_moved_main_or_unmerged_original_blocks_release(self):
        self.main = "c" * 40
        with self.assertRaisesRegex(ValueError, "MAIN_MOVED"):
            self.verify()
        self.main = SOURCE
        self.merged = False
        with self.assertRaisesRegex(ValueError, "PR27_MERGE_NOT_VERIFIED"):
            self.verify()

    def test_wrong_repair_branch_or_unmerged_head_blocks_release(self):
        self.repair_branch = "unrelated"
        with self.assertRaisesRegex(ValueError, "RECOVERY_MERGE_MISSING"):
            self.verify()
        self.repair_branch = APPROVED_REPAIR_BRANCH
        self.repair_merge = "c" * 40
        with self.assertRaisesRegex(ValueError, "RECOVERY_MERGE_MISSING"):
            self.verify()

    def test_unrelated_parent_or_wrong_patch_head_blocks_release(self):
        self.parent = "d" * 40
        with self.assertRaisesRegex(ValueError, "ANCESTRY_MISMATCH"):
            self.verify()
        self.parent = INVESTIGATION_MERGE_SHA
        self.second_parent = "e" * 40
        with self.assertRaisesRegex(ValueError, "ANCESTRY_MISMATCH"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
