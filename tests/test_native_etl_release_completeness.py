"""Ensure busy Windows ETW acceptance never disguises a bounded prefix as complete.

Real Windows CPU.Verbose sampling / PDB / symbol integration runs separately
in the existing hosted Windows source and release workflows; these tests
exercise only fail-closed metadata contracts.
"""
import unittest

from tools.qa_decoder_patch import (
    NATIVE_QA_CAPTURE_SECONDS,
    require_complete_native_etl,
)

SOURCE = "a" * 64
FULL = {
    "schema": "blackbox.decoder-index/4",
    "status": "DECODED",
    "import_completeness": "ALL_EMITTED_RECORDS",
    "input_sha256": SOURCE,
    "rows": 50_000,
    "decoder_reported_lost_events": 0,
}


class BoundedRealNativeCapturePolicyTests(unittest.TestCase):
    def test_real_wpr_capture_is_bounded_without_disabling_stacks(self):
        self.assertEqual(NATIVE_QA_CAPTURE_SECONDS, 2)

    def test_lossless_fully_emitted_source_is_accepted(self):
        self.assertIsNone(require_complete_native_etl(dict(FULL), SOURCE))

    def test_truncated_384mib_jsonl_prefix_is_never_full(self):
        altered = dict(FULL, status="TRUNCATED", import_completeness="BOUNDED_PREFIX",
                       rows=124881)
        with self.assertRaisesRegex(AssertionError, "NATIVE_ETL_DECODE_FAILED"):
            require_complete_native_etl(altered, SOURCE)

    def test_metadata_claims_fullness_even_with_prefix_denied(self):
        for meta in (
            {**FULL, "status": "DECODED", "import_completeness": "BOUNDED_PREFIX"},
            {**FULL, "status": "TRUNCATED", "import_completeness": "ALL_EMITTED_RECORDS"},
            {**FULL, "status": "FAILED"},
            None,
        ):
            with self.subTest(meta=meta):
                with self.assertRaisesRegex(
                        AssertionError, "NATIVE_ETL_(DECODE_FAILED|RESULT_MISSING)"):
                    require_complete_native_etl(meta, SOURCE)

    def test_wrong_source_hash_is_denied(self):
        with self.assertRaisesRegex(AssertionError, "NATIVE_ETL_SOURCE_HASH_MISMATCH"):
            require_complete_native_etl({**FULL, "input_sha256": "b" * 64}, SOURCE)

    def test_missing_or_nonzero_source_decoder_loss_is_denied(self):
        for lost in (1, 100, None):
            with self.subTest(lost=lost):
                with self.assertRaisesRegex(
                        AssertionError, "NATIVE_ETL_DECODER_REPORTED_LOST_EVENTS"):
                    require_complete_native_etl({**FULL, "decoder_reported_lost_events": lost},
                                                SOURCE)


if __name__ == "__main__":
    unittest.main()
