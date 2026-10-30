"""Hosted context hashing/declared-comparison contracts, synthetic records."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackbox_core.investigation_graph_contracts import InvestigationBudget
from blackbox_core.issue_grouping import compare_investigations, group_recurrent_issues
from blackbox_universal.investigation_context import apply_user_context, prepare_user_context


APP = {"application_id": "SYNTHETIC_APPLICATION", "version": "1.0"}
SCENARIO = {"scenario_id": "SYNTHETIC_FILE_IO", "workload_id": "TWO_OPERATIONS", "source_profile": "SDK_FILE_V1",
            "operation_count": 2, "input_bytes": 29, "complete": True}


class DeclaredContextContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.binary = Path(self.temp.name) / "synthetic-selected-file.bin"
        self.binary.write_bytes(b"SYNTHETIC LOCAL FILE HASH CONTRACT ONLY")

    def prepare(self, **changes):
        return prepare_user_context(**{"app_fields": deepcopy(APP), "scenario_fields": deepcopy(SCENARIO),
            "binary_path": str(self.binary), "scope_confirmed": True, **changes})

    def test_selected_file_hash_is_observed_while_application_association_is_user_reported(self):
        result = self.prepare()
        app = result["app_identity"]
        self.assertEqual(app["sha256"], hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertEqual(app["verification_class"], "USER_SELECTED_FILE_SHA256")
        self.assertEqual(app["source_binding"], "USER_REPORTED")
        self.assertEqual(result["source_binding"], "NOT_ESTABLISHED")
        self.assertEqual(result["scenario"]["verification_class"], "USER_REPORTED")
        self.assertNotIn(str(self.binary), json.dumps(result))

    def test_unchecked_whole_case_scope_and_invalid_workload_fields_are_refused(self):
        with self.assertRaisesRegex(ValueError, "ENTIRE_CASE"):
            self.prepare(scope_confirmed=False)
        for key, value in (("operation_count", True), ("operation_count", "-1"), ("input_bytes", "1e9"),
                           ("scenario_id", "path/masquerading/as/id"), ("complete", "true")):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.prepare(scenario_fields={**SCENARIO, key: value})

    def test_metadata_json_cannot_supply_a_fabricated_hash_or_promote_its_authority(self):
        path = Path(self.temp.name) / "declared-context.json"
        path.write_text(json.dumps({"app_identity": {**APP, "verification_class": "OS_OBSERVED", "sha256": "a" * 64},
                                    "scenario": SCENARIO}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "INVALID_DECLARED_CONTEXT_FIELDS"):
            self.prepare(context_path=str(path))
        path.write_text(json.dumps({"app_identity": APP, "scenario": SCENARIO}), encoding="utf-8")
        result = self.prepare(context_path=str(path))
        self.assertEqual(result["app_identity"]["verification_class"], "USER_SELECTED_FILE_SHA256")
        self.assertEqual(result["declaration_file_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_missing_selected_binary_remains_an_unverified_declaration(self):
        result = self.prepare(binary_path=None)
        self.assertNotIn("sha256", result["app_identity"])
        self.assertEqual(result["app_identity"]["verification_class"], "USER_REPORTED")

    def test_file_changes_during_hash_are_refused(self):
        budget = InvestigationBudget()
        native_check, calls = budget.check, []
        def change_during_read():
            native_check()
            calls.append(True)
            if len(calls) == 3:
                with self.binary.open("ab") as stream:
                    stream.write(b"CHANGED")
        with patch.object(budget, "check", side_effect=change_during_read), \
                self.assertRaisesRegex(ValueError, "CONTEXT_FILE_CHANGED_DURING_READ"):
            self.prepare(budget=budget)

    def test_nonregular_context_is_refused_before_opening_any_descriptor(self):
        with patch("blackbox_universal.investigation_context.os.open") as opener, \
                self.assertRaisesRegex(ValueError, "CONTEXT_REGULAR_FILE_BYTE_BUDGET"):
            self.prepare(binary_path=self.temp.name)
        opener.assert_not_called()

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"), "POSIX FIFO contract")
    def test_fifo_context_is_refused_before_opening_any_descriptor(self):
        fifo = Path(self.temp.name) / "never-open-pipe"
        os.mkfifo(fifo)
        with patch("blackbox_universal.investigation_context.os.open") as opener, \
                self.assertRaisesRegex(ValueError, "CONTEXT_REGULAR_FILE_BYTE_BUDGET"):
            self.prepare(binary_path=str(fifo))
        opener.assert_not_called()

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"), "POSIX FIFO race contract")
    def test_regular_file_replaced_by_fifo_is_opened_nonblocking_rejected_and_closed(self):
        native_open, descriptors = os.open, []
        def replace_then_open(path, flags):
            self.assertTrue(flags & os.O_NONBLOCK)
            self.binary.unlink()
            os.mkfifo(self.binary)
            descriptor = native_open(path, flags)
            descriptors.append(descriptor)
            return descriptor
        with patch("blackbox_universal.investigation_context.os.open", side_effect=replace_then_open), \
                self.assertRaisesRegex(ValueError, "CONTEXT_REGULAR_FILE_BYTE_BUDGET"):
            self.prepare()
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])

    def test_worker_prepared_context_enables_only_conditional_comparison_without_mutating_sources(self):
        # Separate typed synthetic captures; this is an API/GUI composition
        # control, not evidence of actual native historical application binding.
        from test_inv_grouping import case
        first, second = case("context-first"), case("context-second")
        original = deepcopy([first, second])
        context = self.prepare()
        left = apply_user_context(first, context)
        right = apply_user_context(second, context)
        comparison = compare_investigations(left, right)
        self.assertEqual(comparison["status"], "COMPARABLE_WITH_DECLARED_CONTEXT")
        self.assertTrue(comparison["conditional"])
        self.assertEqual(comparison["source_binding"], "NOT_ESTABLISHED")
        groups = group_recurrent_issues([left, right])
        self.assertEqual(groups["groups"][0]["status"], "MATCHING_DECLARED_ANCHORS")
        self.assertFalse(groups["groups"][0]["root_cause_established"])
        self.assertEqual(left["context_parent_case_id"], first["case_id"])
        self.assertNotEqual(left["case_id"], first["case_id"])
        self.assertEqual([first, second], original)
