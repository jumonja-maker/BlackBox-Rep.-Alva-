"""Owner-authorized v0.5.5 ETW repair release: exact ancestry and QA regression."""
import copy
import unittest

from tools.publish_v055_after_ci import (
    approved_release_source, REPOSITORY, CI_NAME, APPROVED_RELEASE_BRANCH,
    APPROVED_REPAIR_BRANCH, APPROVED_VERSION_HEAD_SHA, V055_VERSION_MAIN_SHA,
    APPROVED_ETW_MAIN_SHA, APPROVED_REPAIR_HEAD_SHA,
    APPROVED_RELEASE_QA_PR, APPROVED_RELEASE_QA_BRANCH, APPROVED_RELEASE_QA_SCOPE,
    APPROVED_RELEASE_QA_MAIN_SHA, APPROVED_RELEASE_QA_HEAD_SHA,
    APPROVED_DECODER_QA_PR, APPROVED_DECODER_QA_BRANCH, APPROVED_DECODER_QA_FILES,
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
        self.qa_merge = APPROVED_RELEASE_QA_MAIN_SHA
        self.qa_merged = True
        self.qa_head = APPROVED_RELEASE_QA_HEAD_SHA
        self.qa_base = "main"
        self.qa_files = [{"filename": name, "status": "modified"}
                         for name in sorted(APPROVED_RELEASE_QA_SCOPE)]
        self.qa_changed_files = len(self.qa_files)
        self.qa_parents = [APPROVED_ETW_MAIN_SHA, APPROVED_RELEASE_QA_HEAD_SHA]
        self.decoder_number = APPROVED_DECODER_QA_PR
        self.decoder_branch = APPROVED_DECODER_QA_BRANCH
        self.decoder_merge = SHA
        self.decoder_merged = True
        self.decoder_head = HEAD
        self.decoder_base = "main"
        self.decoder_head_repo = REPOSITORY
        self.decoder_base_repo = REPOSITORY
        self.decoder_files = [{"filename": name, "status": status}
                              for name, status in sorted(APPROVED_DECODER_QA_FILES.items())]
        self.decoder_changed_files = len(self.decoder_files)
        self.final_parents = [APPROVED_RELEASE_QA_MAIN_SHA, HEAD]
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
            prefix + "git/commits/" + APPROVED_RELEASE_QA_MAIN_SHA: {
                "parents": [{"sha": parent} for parent in self.qa_parents],
            },
            prefix + f"pulls/{APPROVED_DECODER_QA_PR}": {
                "number": self.decoder_number,
                "merged": self.decoder_merged, "merge_commit_sha": self.decoder_merge,
                "head": {"ref": self.decoder_branch, "sha": self.decoder_head,
                         "repo": {"full_name": self.decoder_head_repo}},
                "base": {"ref": self.decoder_base, "repo": {"full_name": self.decoder_base_repo}},
                "changed_files": self.decoder_changed_files,
            },
            prefix + f"pulls/{APPROVED_DECODER_QA_PR}/files?per_page=100": self.decoder_files,
            prefix + "git/commits/" + SHA: {
                "parents": [{"sha": parent} for parent in self.final_parents],
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
        self.assertEqual(receipt["release_qa_merge_sha"], APPROVED_RELEASE_QA_MAIN_SHA)
        self.assertEqual(receipt["release_qa_head"], APPROVED_RELEASE_QA_HEAD_SHA)
        self.assertEqual(receipt["decoder_qa_repair_pr"], APPROVED_DECODER_QA_PR)
        self.assertEqual(receipt["decoder_qa_repair_head"], HEAD)
        self.assertEqual(receipt["decoder_qa_repair_branch"], APPROVED_DECODER_QA_BRANCH)
        self.assertEqual(receipt["decoder_qa_repair_base_main_sha"], APPROVED_RELEASE_QA_MAIN_SHA)
        self.assertEqual(receipt["decoder_qa_repair_merge_sha"], SHA)
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
        self.qa_merge = APPROVED_RELEASE_QA_MAIN_SHA
        self.qa_base = "release"
        with self.assertRaisesRegex(ValueError, "APPROVED_V055_RELEASE_QA_MERGE_MISSING"):
            self.verify()
        self.qa_base = "main"
        self.qa_parents[0] = V055_VERSION_MAIN_SHA
        with self.assertRaisesRegex(ValueError, "V055_RELEASE_QA_MERGE_ANCESTRY_MISMATCH"):
            self.verify()
        self.qa_parents[0] = APPROVED_ETW_MAIN_SHA
        self.qa_parents[1] = "c" * 40
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

    def test_original_release_qa_head_and_merge_parent_count_are_immutable(self):
        self.qa_head = HEAD
        with self.assertRaisesRegex(ValueError, "APPROVED_V055_RELEASE_QA_MERGE_MISSING"):
            self.verify()
        self.qa_head = APPROVED_RELEASE_QA_HEAD_SHA
        for parents in ([], [APPROVED_ETW_MAIN_SHA],
                        [APPROVED_ETW_MAIN_SHA, APPROVED_RELEASE_QA_HEAD_SHA, HEAD]):
            with self.subTest(parents=parents):
                self.qa_parents = parents
                with self.assertRaisesRegex(ValueError, "V055_RELEASE_QA_MERGE_ANCESTRY_MISMATCH"):
                    self.verify()

    def test_only_exact_same_repository_decoder_repair_pr_can_follow_release_qa(self):
        for attribute, value in (
            ("decoder_number", APPROVED_DECODER_QA_PR + 1),
            ("decoder_number", float(APPROVED_DECODER_QA_PR)),
            ("decoder_branch", "feature/bb-wave-02-r20-evidence-lifecycle"),
            ("decoder_merged", False), ("decoder_merge", HEAD),
            ("decoder_base", "release"),
            ("decoder_head_repo", "fork/BlackBox-Rep.-Alva-"),
            ("decoder_base_repo", "fork/BlackBox-Rep.-Alva-"),
            ("decoder_head", "not-a-source-sha"), ("decoder_head", None),
        ):
            with self.subTest(field=attribute, value=value):
                original = getattr(self, attribute)
                setattr(self, attribute, value)
                with self.assertRaisesRegex(ValueError, "APPROVED_V055_DECODER_QA_MERGE_MISSING"):
                    self.verify()
                setattr(self, attribute, original)

    def test_decoder_repair_is_the_immediate_two_parent_main_merge(self):
        for parents in ([], [APPROVED_RELEASE_QA_MAIN_SHA],
                        [APPROVED_RELEASE_QA_MAIN_SHA, HEAD, "c" * 40],
                        [APPROVED_ETW_MAIN_SHA, HEAD],
                        [APPROVED_RELEASE_QA_MAIN_SHA, "c" * 40],
                        [HEAD, APPROVED_RELEASE_QA_MAIN_SHA]):
            with self.subTest(parents=parents):
                self.final_parents = parents
                with self.assertRaisesRegex(ValueError, "V055_DECODER_QA_MERGE_ANCESTRY_MISMATCH"):
                    self.verify()

    def test_decoder_repair_head_cannot_differ_from_the_reviewed_merge_parent(self):
        self.decoder_head = "c" * 40
        with self.assertRaisesRegex(ValueError, "V055_DECODER_QA_MERGE_ANCESTRY_MISMATCH"):
            self.verify()

    def test_decoder_repair_file_names_and_each_added_modified_status_are_exact(self):
        original = copy.deepcopy(self.decoder_files)
        for index, item in enumerate(original):
            for wrong_status in ({"added", "modified", "removed", "renamed"} - {item["status"]}):
                with self.subTest(path=item["filename"], wrong_status=wrong_status):
                    self.decoder_files = copy.deepcopy(original)
                    self.decoder_files[index]["status"] = wrong_status
                    with self.assertRaisesRegex(ValueError, "UNAPPROVED_V055_DECODER_QA_FILE_SCOPE"):
                        self.verify()
        self.decoder_files = copy.deepcopy(original)
        self.decoder_files[0]["filename"] = "src/blackbox_core/optional_jobs.py"
        with self.assertRaisesRegex(ValueError, "UNAPPROVED_V055_DECODER_QA_FILE_SCOPE"):
            self.verify()
        self.decoder_files = copy.deepcopy(original)
        self.decoder_files[0] = copy.deepcopy(self.decoder_files[1])
        with self.assertRaisesRegex(ValueError, "UNAPPROVED_V055_DECODER_QA_FILE_SCOPE"):
            self.verify()

    def test_decoder_repair_scope_rejects_missing_extra_unreadable_and_bad_counts(self):
        original = copy.deepcopy(self.decoder_files)
        for files in (None, original[:-1],
                      original + [{"filename": "docs/roadmap.md", "status": "added"}],
                      [None, *original[1:]]):
            with self.subTest(files=files):
                self.decoder_files = files
                with self.assertRaisesRegex(ValueError, "UNAPPROVED_V055_DECODER_QA_FILE_SCOPE"):
                    self.verify()
        self.decoder_files = original
        for changed_files in (len(original) - 1, len(original) + 1, float(len(original)), None):
            with self.subTest(changed_files=changed_files):
                self.decoder_changed_files = changed_files
                with self.assertRaisesRegex(ValueError, "UNAPPROVED_V055_DECODER_QA_FILE_SCOPE"):
                    self.verify()

    def test_old_main_success_and_a_later_wave_merge_cannot_authorize_decoder_repair(self):
        with self.assertRaisesRegex(ValueError, "EXACT_MAIN_GREEN_CI_REQUIRED"):
            self.verify({**RUN, "head_sha": APPROVED_RELEASE_QA_MAIN_SHA})
        # Even a green current main must be this repair's exact merge, never
        # a later descendant whose first parent happens to be the repair.
        self.decoder_merge = "c" * 40
        self.final_parents = ["c" * 40, HEAD]
        with self.assertRaisesRegex(ValueError, "APPROVED_V055_DECODER_QA_MERGE_MISSING"):
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
