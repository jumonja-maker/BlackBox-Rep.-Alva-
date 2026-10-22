"""Public-user Alva onboarding never invents an actual private-runtime connection."""
from __future__ import annotations
import unittest
from blackbox_universal.access_status import explain_access, unconfigured_access

class AccessStatusTests(unittest.TestCase):
    def test_first_download_has_real_offline_capabilities(self):
        info = unconfigured_access()
        self.assertEqual(info["status"], "unavailable")
        self.assertEqual(info["error_code"], "ALVA_RUNTIME_NOT_CONFIGURED")
        self.assertTrue(info["standalone_ready"])
        self.assertFalse(info["alva_bundled"])
        self.assertFalse(info["permission_to_act"])
        text = explain_access(info)
        self.assertIn("ready", text)
        self.assertIn("without Alva", text)
        self.assertIn("separately authorized", text)

    def test_untrusted_python_without_alva_is_not_auto_installed(self):
        text = explain_access({"status": "unavailable", "error_code": "ALVA_NOT_INSTALLED"})
        self.assertIn("No installation was attempted", text)
        self.assertIn("authorized", text)

    def test_success_never_claims_source_authentication_or_target_causality(self):
        text = explain_access({"status": "ok", "alva_origin_authenticated": False})
        self.assertIn("NOT authenticated", text)
        self.assertIn("does not prove", text)

    def test_bad_or_malformed_response_never_says_connected(self):
        for value in (None, [], "ok", {}, {"status": "error"}, {"status": "unavailable"}):
            with self.subTest(value=value):
                self.assertNotIn("answered the limited", explain_access(value))

    def test_errors_remain_safe_without_internal_diagnostic_details(self):
        text = explain_access({"status": "error", "error_code": "ALVA_UNKNOWN_FAILURE",
                               "internal_path": "C:/Sensitive/data"})
        self.assertNotIn("Sensitive", text)
        self.assertIn("ordinary offline reports", text)

if __name__ == "__main__":
    unittest.main()
