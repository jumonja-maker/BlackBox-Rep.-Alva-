"""File-backed lineage regressions; fixtures do not claim captured diagnostics."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from blackbox_core.chain_adapters import _links
from blackbox_core.chain_contracts import Artifact, WorkflowError
from blackbox_core.chain_io import make_file_artifact, verify_artifact


class WorkflowLineageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sequence = 0

    def file(self, kind, *, metadata=None):
        self.sequence += 1
        path = self.root / (str(self.sequence) + ".json")
        path.write_text('{"fixture":"lineage consistency only","id":' + str(self.sequence) + "}",
                        encoding="utf-8")
        return make_file_artifact(kind, path, metadata=metadata,
            sources=({"verification": "UNVERIFIED_IMPORT", "source_id": "fixture"},),
            clock_domains=("NOT_ESTABLISHED",), coverage={"evidence_completeness": "UNKNOWN"})

    @staticmethod
    def flat(artifact):
        row = deepcopy(artifact.to_dict())
        row["value"].pop("upstream_artifacts", None)
        return Artifact.from_dict(row)

    def test_flat_report_incident_comparison_locators_use_rehashed_sibling_sources(self):
        for kind in ("REPORT", "INCIDENT", "COMPARISON"):
            with self.subTest(kind=kind):
                if kind == "INCIDENT":
                    folder = self.root / "session"
                    folder.mkdir()
                    # Byte consistency fixture, not a real SQLite recording.
                    (folder / "session-v2.sqlite3").write_bytes(b"saved database fixture")
                    source = make_file_artifact("SESSION", folder)
                    sources, locators = (source,), {"_session_path": source.value["_path"]}
                elif kind == "COMPARISON":
                    before, after = self.file("CASE"), self.file("CASE")
                    sources = (before, after)
                    locators = {"_before_path": before.value["_path"], "_after_path": after.value["_path"]}
                else:
                    source = self.file("CASE")
                    sources, locators = (source,), {"_case_path": source.value["_path"]}
                analysis = self.file(kind, metadata={**locators,
                    "upstream_artifacts": [source.to_dict() for source in sources]})
                exported = self.file("REPORT", metadata={"upstream_artifacts": _links((analysis,))})
                # Exercise the actual adapter representation: the parent has
                # no nested dependencies and its proved sources are siblings.
                parent = next(row for row in exported.value["upstream_artifacts"]
                              if row["artifact_id"] == analysis.artifact_id)
                self.assertNotIn("upstream_artifacts", parent["value"])
                unchanged = deepcopy(exported.to_dict())
                result = verify_artifact(exported)
                self.assertEqual(result["status"], "VERIFIED_BYTE_OR_INSTANCE_CONSISTENCY")
                self.assertEqual(result["producer_authentication"], "NOT_ESTABLISHED")
                self.assertEqual(exported.to_dict(), unchanged)
                self.assertEqual(exported.clock_domains, ("NOT_ESTABLISHED",))
                self.assertEqual(exported.sources[0]["verification"], "UNVERIFIED_IMPORT")

    def test_same_artifact_full_and_flat_views_work_in_either_order(self):
        source = self.file("CASE")
        full = self.file("REPORT", metadata={"_case_path": source.value["_path"],
            "upstream_artifacts": [source.to_dict()]})
        flat = self.flat(full)
        for references in ((flat, full), (full, flat)):
            with self.subTest(flat_first=references[0] is flat):
                root = Artifact("EVIDENCE_SET", {"items": [row.to_dict() for row in references]})
                self.assertEqual(verify_artifact(root)["producer_authentication"], "NOT_ESTABLISHED")

    def test_seen_flat_reference_does_not_hide_changed_dependency_in_later_full_view(self):
        source = self.file("CASE")
        full = self.file("REPORT", metadata={"_case_path": source.value["_path"],
            "upstream_artifacts": [source.to_dict()]})
        root = Artifact("EVIDENCE_SET", {"items": [self.flat(full).to_dict(), full.to_dict()]})
        Path(source.value["_path"]).write_bytes(b"changed bytes after selection")
        with self.assertRaisesRegex(WorkflowError, "WORKFLOW_SOURCE_HASH_CHANGED"):
            verify_artifact(root)

    def test_seen_full_reference_does_not_hide_additional_changed_dependency(self):
        source, additional = self.file("CASE"), self.file("TRACE")
        full = self.file("REPORT", metadata={"_case_path": source.value["_path"],
            "upstream_artifacts": [source.to_dict()]})
        extended = replace(full, value={**full.value,
            "upstream_artifacts": [source.to_dict(), additional.to_dict()]})
        root = Artifact("EVIDENCE_SET", {"items": [full.to_dict(), extended.to_dict()]})
        Path(additional.value["_path"]).write_bytes(b"changed bytes in additional reference")
        with self.assertRaisesRegex(WorkflowError, "WORKFLOW_SOURCE_HASH_CHANGED"):
            verify_artifact(root)

    def test_existing_private_locator_without_fingerprinted_reference_is_rejected(self):
        missing_reference = self.file("CASE")
        other = self.file("CASE")
        parent = self.file("REPORT", metadata={"_case_path": missing_reference.value["_path"]})
        exported = self.file("REPORT", metadata={"upstream_artifacts": [parent.to_dict(), other.to_dict()]})
        self.assertTrue(Path(missing_reference.value["_path"]).is_file())
        with self.assertRaisesRegex(WorkflowError, "WORKFLOW_UNBOUND_PRIVATE_SOURCE_LOCATOR"):
            verify_artifact(exported)

    def test_rehashed_sibling_source_change_still_invalidates_flat_lineage(self):
        source = self.file("CASE")
        parent = self.file("REPORT", metadata={"_case_path": source.value["_path"],
            "upstream_artifacts": [source.to_dict()]})
        exported = self.file("REPORT", metadata={"upstream_artifacts": _links((parent,))})
        Path(source.value["_path"]).write_bytes(b"source changed after export")
        with self.assertRaisesRegex(WorkflowError, "WORKFLOW_SOURCE_HASH_CHANGED"):
            verify_artifact(exported)

    def test_full_flat_normalization_does_not_allow_other_identity_changes(self):
        source = self.file("CASE")
        full = self.file("REPORT", metadata={"_case_path": source.value["_path"],
            "upstream_artifacts": [source.to_dict()]})
        flat = self.flat(full)
        variants = (replace(flat, kind="CASE"),
                    replace(flat, sources=({"verification": "CLAIMED_AUTHENTICATED"},)),
                    replace(flat, clock_domains=("CLAIMED_ALIGNED",)),
                    replace(flat, coverage={"evidence_completeness": "CLAIMED_COMPLETE"}),
                    replace(flat, value={**flat.value, "_case_path": full.value["_path"]}),
                    replace(flat, value={**flat.value, "sha256": "0" * 64}))
        for changed in variants:
            with self.subTest(changed=changed.to_dict()):
                root = Artifact("EVIDENCE_SET", {"items": [full.to_dict(), changed.to_dict()]})
                with self.assertRaisesRegex(WorkflowError, "WORKFLOW_ARTIFACT_ID_CONTRADICTION"):
                    verify_artifact(root)

    def test_cycle_is_rejected_even_when_the_repeated_reference_has_no_dependencies(self):
        base = self.file("REPORT")
        circular = replace(base, value={**base.value, "upstream_artifacts": [base.to_dict()]})
        with self.assertRaisesRegex(WorkflowError, "WORKFLOW_ARTIFACT_LINEAGE_CYCLE"):
            verify_artifact(circular)
