"""Wire regression for actual P4 API *shape*, with a labelled fake Alva.

These fakes never attest private Alva provenance. A real installed private
Alva at the pinned SHA must be tested separately in an authorized environment.
"""
from __future__ import annotations
import json
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

from blackbox_rep_alva.alva_evidence_pipeline import verified_session_evidence
from blackbox_rep_alva import alva_sidecar_worker as worker
from blackbox_universal.platform_connector import _validate_output, ConnectionError

NAMES = ("blackbox.evidence.samples", "blackbox.evidence.lifecycle",
         "blackbox.evidence.metrics", "blackbox.evidence.errors")
SUMMARY = {
    "sample_count": 5, "peak_rss_bytes": 2048,
    "peak_cpu_percent": 4.0, "observation_error_count": 1,
    "closed": True, "state": "COMPLETED",
}


class FakeAlvaPipeline:
    calls = []

    @classmethod
    def run_checked_pipeline(cls, steps):
        cls.calls.clear()
        accepted = 0
        first = None
        for name, method, checker, data in steps:
            cls.calls.append((name, dict(data)))
            if checker(method(dict(data))) is not True:
                first = name
                break
            accepted += 1
        return {"status": "ok", "result": {
            "observed_pipeline_status": "error" if first else "ok",
            "declared_stages": len(steps),
            "executed_stages": len(cls.calls),
            "accepted_checks": accepted,
            "first_unverified_component": first,
            "verification_coverage": (
                "INCOMPLETE_OR_AMBIGUOUS" if first else "ALL_DECLARED_CHECKS_ACCEPTED"),
            "next_action_code": (
                "REVIEW_DECLARED_CONTRACT" if first else "ALL_DECLARED_CHECKS_ACCEPTED"),
            "evidence_origin": "APP_SUPPLIED_NOT_AUTHENTICATED",
        }}

    @staticmethod
    def review_pipeline_evidence(report):
        return {"status": "ok",
                "code": "STRUCTURALLY_CONSISTENT_UNAUTHENTICATED",
                "root_cause_proven": False, "external_attestation": False}

    @staticmethod
    def build_ai_handoff(report):
        r = report["result"]
        return {"status": "ok", "result": {
            "permission_to_act": False, "root_cause_proven": False,
            "execution_attested": False, "review_required": True,
            "record_status": "STRUCTURALLY_CONSISTENT_UNAUTHENTICATED",
            "declared_stages": r["declared_stages"],
            "executed_stages": r["executed_stages"],
            "accepted_checks": r["accepted_checks"],
            "verification_coverage": r["verification_coverage"],
            "observed_pipeline_status": r["observed_pipeline_status"],
            "first_unverified_component": r["first_unverified_component"],
        }}


class FakeComponent:
    def __init__(self, name, fn):
        self.name, self.fn = name, fn


class FakeHost:
    def __init__(self, components, *, allow_dispatch=False):
        assert allow_dispatch
        self.components = {c.name: c for c in components}
        self.state = "new"

    def __enter__(self):
        self.state = "ready"
        return self

    def __exit__(self, *args):
        self.state = "closed"

    def open_scope(self, *, permitted_operations):
        assert set(permitted_operations) == set(self.components)
        return FakeScope(self)


class FakeScope:
    def __init__(self, host):
        self.host = host

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def invoke_with_diagnostics(self, request):
        name = request["operation"]
        data = self.host.components[name].fn(request["payload"])
        return type("Call", (), {
            "response": {"status": "ok", "result": data},
            "execution_state": "RESPONSE_AVAILABLE",
            "diagnostics": {"result": {
                "contract_verdict": "CHECK_ACCEPTED",
                "visibility": "SCOPE_ONLY",
                "ai_handoff": {"status": "ok"},
            }},
        })()


def fake_checked(method, checker):
    value = method()
    if checker(value) is not True:
        raise ValueError("CHECK_REJECTED")
    return value


class P4EvidenceTests(unittest.TestCase):
    def test_four_real_adapter_stage_uses_are_bounded(self):
        info = verified_session_evidence(FakeAlvaPipeline, SUMMARY, "inspect")
        self.assertEqual([name for name, _ in FakeAlvaPipeline.calls], list(NAMES))
        self.assertEqual(info["accepted_checks"], 4)
        self.assertEqual(info["observed_pipeline_status"], "ok")
        self.assertFalse(info["execution_attested"])
        self.assertFalse(info["root_cause_proven"])
        self.assertFalse(info["permission_to_act"])
        self.assertTrue(info["handoff_review_required"])
        self.assertNotIn("pid", json.dumps(info).casefold())

    def test_bad_observer_evidence_rejected_without_target_blame(self):
        info = verified_session_evidence(FakeAlvaPipeline, {
            **SUMMARY, "sample_count": 0}, "inspect")
        self.assertEqual(info["observed_pipeline_status"], "error")
        self.assertEqual(info["first_unverified_component"], NAMES[0])
        self.assertEqual(info["accepted_checks"], 0)
        self.assertEqual(info["executed_stages"], 1)
        self.assertFalse(info["root_cause_proven"])

    def test_ping_has_no_false_missing_samples_failure(self):
        info = verified_session_evidence(FakeAlvaPipeline, {
            **SUMMARY, "sample_count": 0, "closed": False,
            "state": "UNKNOWN", "peak_cpu_percent": None,
            "peak_rss_bytes": None}, "ping")
        self.assertEqual(info["observed_pipeline_status"], "ok")

    def test_reviewer_and_handoff_rejection_fail_closed(self):
        class Forged(FakeAlvaPipeline):
            @staticmethod
            def review_pipeline_evidence(report):
                return {"status": "ok",
                        "code": "STRUCTURALLY_CONSISTENT_UNAUTHENTICATED",
                        "root_cause_proven": True, "external_attestation": False}
        with self.assertRaisesRegex(ValueError, "PIPELINE_REVIEW_FAILED"):
            verified_session_evidence(Forged, SUMMARY, "inspect")

    def test_actual_worker_v2_handshake_uses_p4_api(self):
        root, host = ModuleType("alva"), ModuleType("alva.host")
        root.Component = FakeComponent
        root.invoke_adapter_checked = fake_checked
        root.run_checked_pipeline = FakeAlvaPipeline.run_checked_pipeline
        root.review_pipeline_evidence = FakeAlvaPipeline.review_pipeline_evidence
        root.build_ai_handoff = FakeAlvaPipeline.build_ai_handoff
        root.__version__ = "test-double-not-private-alva"
        host.ComponentHost = FakeHost
        with patch.dict(sys.modules, {"alva": root, "alva.host": host}):
            result = worker._run({
                "schema_version": 1, "operation": "inspect",
                "summary": dict(SUMMARY),
            })
        self.assertEqual(result["bridge_schema"], 2)
        self.assertEqual(result["component_count"], 3)
        self.assertEqual(result["extended_diagnostics"]["accepted_checks"], 4)
        self.assertEqual(_validate_output(result), result)

    def test_v2_forged_root_cause_proof_is_rejected(self):
        root, host = ModuleType("alva"), ModuleType("alva.host")
        root.Component = FakeComponent
        root.invoke_adapter_checked = fake_checked
        root.run_checked_pipeline = FakeAlvaPipeline.run_checked_pipeline
        root.review_pipeline_evidence = FakeAlvaPipeline.review_pipeline_evidence
        root.build_ai_handoff = FakeAlvaPipeline.build_ai_handoff
        root.__version__ = "test-double"
        host.ComponentHost = FakeHost
        with patch.dict(sys.modules, {"alva": root, "alva.host": host}):
            result = worker._run({
                "schema_version": 1, "operation": "inspect",
                "summary": dict(SUMMARY),
            })
        result["extended_diagnostics"]["root_cause_proven"] = True
        with self.assertRaises(ConnectionError):
            _validate_output(result)

    def test_private_package_not_installed_by_worker(self):
        source = Path(worker.__file__).read_text(encoding="utf-8")
        self.assertNotIn("pip install", source)
        self.assertIn('import alva', source)


if __name__ == "__main__":
    unittest.main()
