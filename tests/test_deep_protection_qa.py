"""Evidence-policy tests; only hosted native QA can prove a real PPL denial."""
import unittest

from tools.qa_deep_protection import classify_protection_observation


def observed(**changes):
    return {"source": "WIN32_ACCESS_PROBE", "status": "PROTECTED_PROCESS", "winerror": 5,
            "protection_level": 3, "process_access_mask": 0x410, **changes}


class ProtectedProcessEvidenceContracts(unittest.TestCase):
    def test_denial_needs_both_real_protection_metadata_and_access_denied(self):
        self.assertEqual(classify_protection_observation(3, observed()), "PROTECTED_DENIAL_OBSERVED")
        for level, result in ((0xFFFFFFFE, observed()), (3, observed(winerror=87)),
                              (3, observed(protection_level=None)), (3, observed(source="MOCK_LABEL"))):
            with self.subTest(level=level, result=result), self.assertRaises(AssertionError):
                classify_protection_observation(level, result)

    def test_os_granted_rights_do_not_become_invented_denial(self):
        self.assertEqual(classify_protection_observation(3, observed(status="AVAILABLE", winerror=None)),
                         "PROTECTION_PRESENT_REQUESTED_RIGHTS_AVAILABLE")

    def test_generic_access_denied_cannot_misclassify_confirmed_protected_denial(self):
        with self.assertRaisesRegex(AssertionError, "STATUS_NOT_PRESERVED"):
            classify_protection_observation(3, observed(status="ACCESS_DENIED"))

    def test_exited_process_is_inconclusive(self):
        self.assertEqual(classify_protection_observation(3, observed(status="PROCESS_CHANGED", winerror=87)),
                         "PROCESS_CHANGED_DURING_READ_ONLY_PROBE")

    def test_image_identity_query_denial_remains_explicitly_incomplete(self):
        result = {"source": "WIN32_ACCESS_PROBE", "status": "ACCESS_DENIED", "winerror": 5,
                  "reason": "QUERY_PROCESS_IMAGE_FAILED"}
        self.assertEqual(classify_protection_observation(3, result),
                         "PROTECTION_METADATA_SEEN_BUT_PRODUCT_IDENTITY_PROBE_INCOMPLETE")


if __name__ == "__main__":
    unittest.main()
