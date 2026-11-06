"""Strict QA policy over injected token facts, not Windows acceptance proof."""
from copy import deepcopy
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from blackbox_core.chain_qa import restricted_medium_permission_proof


def restricted_facts(pid=12345, *, helper=False):
    return {"schema": "blackbox.r60.process-token-facts/1" if helper else "blackbox.r60.current-token-facts/1",
        "status": "OBSERVED", "pid": pid, "process_identity": {"pid": pid, "created_100ns": 123456789},
        "identity_source": "INDEPENDENT_GET_PROCESS_ID_AND_GET_PROCESS_TIMES",
        "query_returned_bytes": {"20": 4, "18": 4, "21": 1},
        "cleanup": {"confirmed": True}, "effective_administrators_member": False,
        "effective_membership_scope": "REQUESTED_PROCESS_PRIMARY_TOKEN_DUPLICATED_FOR_MEMBERSHIP_QUERY" if helper else
            "CURRENT_EFFECTIVE_THREAD_TOKEN_OR_PROCESS_TOKEN",
        "process_token": {"elevation_raw": 1, "elevated": True, "elevation_type": 1,
            "integrity": {"sid": "S-1-16-8192", "rid": 8192, "attributes": 0x60},
            "administrators_group": {"present": True, "attributes": 0x10, "enabled": False, "deny_only": True},
            "has_restrictions_raw": 1, "privileges": [{"name": "SeChangeNotifyPrivilege", "attributes": 3,
                "enabled": True, "enabled_by_default": True, "removed": False}]}}


class RestrictedMediumPolicyTests(unittest.TestCase):
    def test_raw_elevation_is_preserved_while_all_actual_restrictions_are_required(self):
        for helper in (False, True):
            for size in (1, 4):
                with self.subTest(helper=helper, has_restrictions_bytes=size):
                    facts = restricted_facts(helper=helper)
                    facts["query_returned_bytes"]["21"] = size
                    before = deepcopy(facts)
                    proof = restricted_medium_permission_proof(facts, 12345)
                    self.assertTrue(proof["confirmed"])
                    self.assertEqual(proof["raw_token_elevation"], 1)
                    self.assertEqual(proof["raw_elevation_type"], 1)
                    self.assertEqual(facts, before)
                    self.assertIn("NOT_UAC_FILTERED_OR_SEPARATE_STANDARD_ACCOUNT", proof["scope"])

    def test_nonmedium_enabled_or_effective_admin_membership_cannot_pass(self):
        for failure in ("integrity", "group_enabled", "deny_missing", "effective_admin", "group_missing"):
            with self.subTest(failure=failure):
                facts = restricted_facts()
                if failure == "integrity":
                    facts["process_token"]["integrity"] = {"sid": "S-1-16-12288", "rid": 12288}
                elif failure == "group_enabled":
                    facts["process_token"]["administrators_group"].update(attributes=0x14, enabled=True)
                elif failure == "deny_missing":
                    facts["process_token"]["administrators_group"].update(attributes=0, deny_only=False)
                elif failure == "effective_admin":
                    facts["effective_administrators_member"] = True
                else:
                    facts["process_token"]["administrators_group"] = None
                self.assertFalse(restricted_medium_permission_proof(facts, 12345)["confirmed"])

    def test_unexpected_present_privilege_is_refused_even_if_disabled(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                facts = restricted_facts()
                facts["process_token"]["privileges"].append({"name": "SeDebugPrivilege",
                    "attributes": 2 if enabled else 0, "enabled": enabled,
                    "enabled_by_default": False, "removed": False})
                proof = restricted_medium_permission_proof(facts, 12345)
                self.assertFalse(proof["confirmed"])
                self.assertIn("UNEXPECTED_PRESENT_PRIVILEGE_OR_QUERY_UNCERTAINTY", proof["failures"])

    def test_query_identity_cleanup_and_strict_types_cannot_be_replaced_by_unknowns(self):
        for failure in ("cleanup", "wrong_pid", "wrong_identity", "bool_identity", "bad_scalar20",
                        "bad_scalar21", "bool_restrictions", "oversized_attrs", "missing_privileges", "membership_scope"):
            with self.subTest(failure=failure):
                facts = restricted_facts(helper=True)
                expected_pid = 12345
                if failure == "cleanup":
                    facts["cleanup"] = None
                elif failure == "wrong_pid":
                    facts["pid"] = 22
                elif failure == "wrong_identity":
                    facts["process_identity"]["created_100ns"] = 0
                elif failure == "bool_identity":
                    facts = restricted_facts(1, helper=True)
                    facts["process_identity"]["pid"] = True
                    expected_pid = 1
                elif failure == "bad_scalar20":
                    facts["query_returned_bytes"]["20"] = 1
                elif failure == "bad_scalar21":
                    facts["query_returned_bytes"]["21"] = 2
                elif failure == "bool_restrictions":
                    facts["process_token"]["has_restrictions_raw"] = True
                elif failure == "oversized_attrs":
                    facts["process_token"]["administrators_group"]["attributes"] = 0x100000010
                elif failure == "missing_privileges":
                    facts["process_token"]["privileges"] = None
                else:
                    facts["effective_membership_scope"] = "CURRENT_EFFECTIVE_THREAD_TOKEN_OR_PROCESS_TOKEN"
                self.assertFalse(restricted_medium_permission_proof(facts, expected_pid)["confirmed"])
        self.assertFalse(restricted_medium_permission_proof(None, 12345)["confirmed"])

    def test_remote_helper_observations_keep_identity_permissions_and_rejected_cleanup(self):
        from tools.qa_chain_builder import _standard_token_precondition
        own, helper = restricted_facts(), restricted_facts(54321, helper=True)
        observed = _standard_token_precondition({"status": "OBSERVED", "current_token_facts": own,
            "helper_token_observations": [{"pid": 54321, "elevated": False, "token_facts": helper,
                "permission_proof": restricted_medium_permission_proof(helper, 54321)},
                {"pid": 54322, "elevated": False,
                "native_call_diagnostic": {"api": "DuplicateToken", "return_bool": False, "get_last_error": 5},
                "rejected_helper_cleanup": {"confirmed": True}, "query_error_type": "AssertionError"}]}, 12345)
        result = observed["helper_token_observations"][0]
        self.assertEqual(result["token_facts"]["process_identity"], helper["process_identity"])
        self.assertEqual(result["token_facts"]["query_returned_bytes"]["21"], 1)
        self.assertTrue(result["permission_proof"]["confirmed"])
        self.assertEqual(result["permission_proof"]["failures"], [])
        failed = observed["helper_token_observations"][1]
        self.assertEqual(failed["token_facts"]["status"], "NOT_BOUND_OR_NOT_COLLECTED")
        self.assertEqual(failed["native_call_diagnostic"]["get_last_error"], 5)
        self.assertTrue(failed["rejected_helper_cleanup"]["confirmed"])

    def test_helper_query_failure_closes_created_broker_owner_before_reraising_primary(self):
        for close_confirmed in (True, False):
            with self.subTest(close_confirmed=close_confirmed):
                from blackbox_core import chain_qa as native_qa
                facts = restricted_facts(os.getpid())
                owner = Mock()
                owner.pid, owner.process, owner._process_handle = 54321, object(), 987
                owner._close_lock, owner._handle_closed = threading.RLock(), False
                owner.alive.return_value = True
                owner.wait_for_exit.return_value = True
                owner.close_handle.return_value = {"confirmed": close_confirmed}
                service, fixture = Mock(), Mock()
                fixture.process.pid = 60001
                service.broker.launch.return_value = owner
                original_launch = service.broker.launch
                retained = []
                service.close.return_value = {"status": "COMPLETED"}
                fixture.close.return_value = {"status": "COMPLETED"}
                primary = AssertionError("CONTROLLED_HELPER_TOKEN_QUERY_FAILURE")
                primary.native_call_diagnostic = {"api": "DuplicateToken", "return_bool": False, "get_last_error": 5}
                evidence = {}

                def actual_launch_boundary(*_args, **_kwargs):
                    return service.broker.launch(["CONTROLLED_ARGUMENTS_NOT_EXECUTED"])

                with tempfile.TemporaryDirectory() as directory, \
                        patch("blackbox_core.chain_qa_native.actual_token", return_value={"pid": os.getpid(), "elevated": True, "elevation_type": 1}), \
                        patch("blackbox_core.chain_qa_native.actual_current_token_facts", return_value=facts), \
                        patch("blackbox_core.chain_qa_native.actual_process_token_facts", side_effect=primary), \
                        patch("blackbox_core.windows_research.privilege", return_value={"mode": "STANDARD", "windows": True}), \
                        patch("blackbox_core.chain_qa_native.OwnedWaveProbe", return_value=fixture), \
                        patch("blackbox_core.deep_service.InspectorService", return_value=service), \
                        patch.object(native_qa, "run_graph", side_effect=actual_launch_boundary), \
                        patch.object(native_qa, "_RETAINED_REJECTED_QA_HELPERS", retained):
                    with self.assertRaises(AssertionError) as caught:
                        native_qa.standard_live_graph(Path(directory), Path(directory) / "unused.exe", "a" * 40,
                                                      token_evidence=evidence)
                    self.assertIs(caught.exception, primary)
                    if not close_confirmed:
                        self.assertEqual(retained, [owner])
                        self.assertTrue(primary.cleanup_unconfirmed)
                        self.assertTrue(primary.owner_retained)
                        with self.assertRaisesRegex(AssertionError, "R60_STANDARD_QA_HELPER_SCOPE_OR_OWNER_UNCONFIRMED"):
                            service.broker.launch(["CONTROLLED_SECOND_LAUNCH_MUST_BE_REFUSED"])
                        self.assertEqual(original_launch.call_count, 1)
                self.assertIs(caught.exception, primary)
                owner.terminate.assert_called_once()
                owner.wait_for_exit.assert_called_once_with(timeout_ms=5000)
                owner.close_handle.assert_called_once()
                service.close.assert_called_once()
                self.assertIs(evidence["helper_token_observations"][0]["rejected_helper_cleanup"]["confirmed"], close_confirmed)
                self.assertEqual(evidence["helper_token_observations"][0]["native_call_diagnostic"]["get_last_error"], 5)


if __name__ == "__main__":
    unittest.main()
