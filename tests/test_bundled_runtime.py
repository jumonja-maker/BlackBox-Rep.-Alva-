"""Bundle selection must never rely on a user-installed Python interpreter."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackbox_universal import platform_connector as bridge

VALID_SHA = "a" * 40
MANIFEST = {"schema_version": 1, "runtime": "bundled",
            "alva_commit": VALID_SHA, "blackbox_commit": "b" * 40}


class BundledRuntimeTests(unittest.TestCase):
    def _marker(self, directory: Path, value: object = MANIFEST) -> None:
        (directory / "alva_runtime_manifest.json").write_text(
            json.dumps(value), encoding="utf-8")

    def test_no_marker_no_private_bundle_even_if_frozen(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bridge.sys, "frozen", True, create=True), \
                 patch.object(bridge.sys, "_MEIPASS", tmp, create=True):
                self.assertFalse(bridge.bundled_runtime_available())
                with self.assertRaisesRegex(
                        bridge.ConnectionError, "BUNDLED_RUNTIME_NOT_AVAILABLE"):
                    bridge.inspect_bundled(None)

    def test_manifest_is_exact_versioned_and_pinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with patch.object(bridge.sys, "frozen", True, create=True), \
                 patch.object(bridge.sys, "_MEIPASS", tmp, create=True):
                self._marker(base)
                self.assertTrue(bridge.bundled_runtime_available())
                self._marker(base, {**MANIFEST, "alva_commit": "not-a-git-sha"})
                self.assertFalse(bridge.bundled_runtime_available())
                self._marker(base, {**MANIFEST, "unexpected": "ignored"})
                self.assertFalse(bridge.bundled_runtime_available())

    def test_normal_public_source_never_claims_bundled_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._marker(Path(tmp))
            with patch.object(bridge.sys, "frozen", False, create=True), \
                 patch.object(bridge.sys, "_MEIPASS", tmp, create=True):
                self.assertFalse(bridge.bundled_runtime_available())

    def test_embedded_runtime_passes_only_bounded_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._marker(Path(tmp))
            result = {"status": "ok", "bridge_schema": 2,
                      "extended_diagnostics": {"accepted_checks": 4}}
            with patch.object(bridge.sys, "frozen", True, create=True), \
                 patch.object(bridge.sys, "_MEIPASS", tmp, create=True), \
                 patch("blackbox_universal.platform_connector._summary",
                       return_value={"sample_count": 5, "closed": True}) as summary, \
                 patch("blackbox_rep_alva.alva_sidecar_worker._run",
                       return_value=result) as run, \
                 patch("blackbox_universal.platform_connector._validate_output",
                       side_effect=lambda packet: packet):
                packet = bridge.inspect_bundled(Path(tmp))
            summary.assert_called_once()
            run.assert_called_once()
            self.assertEqual(packet, result)
            sent = run.call_args.args[0]
            self.assertEqual(sent["operation"], "inspect")
            self.assertEqual(set(sent), {"schema_version", "operation", "summary"})
            self.assertNotIn("pid", json.dumps(sent).casefold())
            self.assertNotIn("path", json.dumps(sent).casefold())

    def test_success_diagnostics_are_append_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp)
            packet = {
                "status": "ok", "component_count": 3,
                "extended_diagnostics": {
                    "accepted_checks": 4, "declared_stages": 4,
                    "observed_pipeline_status": "ok",
                    "verification_coverage": "ALL_DECLARED_CHECKS_ACCEPTED"}}
            with patch("blackbox_universal.platform_connector.inspect_bundled",
                       return_value=packet):
                report = bridge.save_bundled_diagnostics(session)
                self.assertEqual(report["reviewed_checks"], 4)
                self.assertEqual(report["file"], "evidence-checks.json")
                self.assertTrue((session / "evidence-checks.json").is_file())
                second = bridge.save_bundled_diagnostics(session)
                self.assertEqual(second["status"], "error")

    def test_real_failure_is_not_misrepresented_as_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("blackbox_universal.platform_connector.inspect_bundled",
                       side_effect=bridge.ConnectionError("BUNDLED_RUNTIME_CHECK_FAILED")):
                report = bridge.save_bundled_diagnostics(Path(tmp))
            self.assertEqual(report["status"], "error")
            self.assertNotIn("reviewed_checks", report)
            self.assertIn("BUNDLED_RUNTIME_CHECK_FAILED",
                          (Path(tmp) / "evidence-checks.json").read_text("utf-8"))


if __name__ == "__main__":
    unittest.main()
