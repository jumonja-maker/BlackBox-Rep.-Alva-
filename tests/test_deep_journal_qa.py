"""Malformed local evidence must fail QA; these format fixtures are not native evidence."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from tools.qa_deep_journal import verify_action_journal


class DeepJournalEvidenceContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = {"pid": 123, "created_100ns": 456, "image_path": "owned-format-fixture.exe"}
        self.action = {"operation_id": "fixture-action", "operation": "memory.write",
                       "status": "COMPLETED", "target": self.target}

    def evidence(self, *, omit_result=False, wrong_target=False, leaked=None, bad_hash=False,
                 export_wrong=False, extra_action=False):
        base = {"source": "BLACKBOX_DIAGNOSTIC_ACTION_ENGINE", "action_id": "fixture-action",
                "target": self.target, "operation": "memory.write"}
        records = [{**base, "operation_id": "fixture-action:requested", "phase": "REQUESTED"}]
        if not omit_result:
            records.append({**base, "operation_id": "fixture-action:result", "phase": "RESULT",
                            "status": "COMPLETED"})
        if wrong_target:
            records[0]["target"] = {**self.target, "created_100ns": 457}
        if leaked:
            records[0]["parameters"] = {"value_hex": leaked}
        if extra_action:
            records.append({**base, "action_id": "unobserved", "operation_id": "unobserved:requested",
                            "phase": "REQUESTED"})
        path, export = self.root / "format-fixture.sqlite3", self.root / "format-fixture.jsonl"
        previous = "0" * 64
        lines = []
        with closing(sqlite3.connect(path)) as db:
            db.execute("CREATE TABLE actions(sequence INTEGER,operation_id TEXT,record_json TEXT,"
                       "previous_sha256 TEXT,record_sha256 TEXT)")
            for sequence, record in enumerate(records, 1):
                raw = json.dumps(record, sort_keys=True, separators=(",", ":"))
                digest = hashlib.sha256(previous.encode("ascii") + raw.encode("utf-8")).hexdigest()
                if bad_hash and sequence == 1:
                    digest = "f" * 64
                db.execute("INSERT INTO actions VALUES(?,?,?,?,?)",
                           (sequence, record["operation_id"], raw, previous, digest))
                lines.append({"record": record, "previous_sha256": previous, "record_sha256": digest})
                previous = digest
            db.commit()
        if export_wrong:
            lines[0]["record"] = {**lines[0]["record"], "target": {**self.target, "pid": 124}}
        export.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
        return path, export

    def test_exact_action_pair_and_export_checked_without_mutating_database(self):
        result = verify_action_journal(*self.evidence(), [self.action])
        self.assertEqual(result["observed_actions"], 1)
        self.assertTrue(result["read_only_source_unchanged"])
        self.assertIn("NOT_AUTHENTICATED", result["scope"])

    def test_missing_result_cannot_pass_even_with_valid_local_chain(self):
        with self.assertRaisesRegex(AssertionError, "INTENT_RESULT_PAIR"):
            verify_action_journal(*self.evidence(omit_result=True), [self.action])

    def test_same_pid_different_creation_time_cannot_pass(self):
        with self.assertRaisesRegex(AssertionError, "ACTION_TARGET_OR_PHASE"):
            verify_action_journal(*self.evidence(wrong_target=True), [self.action])

    def test_corrupt_chain_is_rejected_independently_of_export(self):
        with self.assertRaisesRegex(AssertionError, "HASH_CHAIN"):
            verify_action_journal(*self.evidence(bad_hash=True), [self.action])

    def test_changed_export_is_not_accepted_as_metadata_copy(self):
        with self.assertRaisesRegex(AssertionError, "EXPORT_CONTENT"):
            verify_action_journal(*self.evidence(export_wrong=True), [self.action])

    def test_cancelled_or_other_unobserved_native_action_is_detected(self):
        with self.assertRaisesRegex(AssertionError, "UNEXPECTED_OR_MISSING_ACTION"):
            verify_action_journal(*self.evidence(extra_action=True), [self.action])

    def test_valid_chain_does_not_excuse_known_raw_memory_in_journal(self):
        marker = "00112233445566778899aabbccddeeff"
        with self.assertRaisesRegex(AssertionError, "RAW_MEMORY_LEAK"):
            verify_action_journal(*self.evidence(leaked=marker), [self.action], forbidden_payloads=(marker,))

    def test_saved_success_does_not_override_observed_failure(self):
        with self.assertRaisesRegex(AssertionError, "OBSERVED_STATUS"):
            verify_action_journal(*self.evidence(), [{**self.action, "status": "RECOVERY_UNCONFIRMED"}])


if __name__ == "__main__":
    unittest.main()
