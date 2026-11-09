"""Bound ZIP metadata before allocation; malformed manifests stay controlled."""
import hashlib
from io import BytesIO
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from blackbox_core.archive_policy import MAX_CENTRAL_BYTES, _BoundedReads, bounded_zip
from blackbox_core.casebook import verify_package


class ArchivePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "source.zip"

    def package(self, manifest=None, *, zip64=False):
        body = b"TEST_ONLY_PACKAGE_PAYLOAD"
        manifest = manifest if manifest is not None else {
            "kind": "BLACKBOX_RESEARCH_PACKAGE", "files": [{"name": "session.sqlite3",
            "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}]}
        with patch("zipfile.ZIP64_LIMIT", 20 if zip64 else zipfile.ZIP64_LIMIT):
            with zipfile.ZipFile(self.path, "w") as archive:
                archive.writestr("session.sqlite3", body)
                archive.writestr("manifest.json", json.dumps(manifest))
        return body

    def test_actual_standard_and_zip64_packages_remain_readable_and_unchanged(self):
        for zip64 in (False, True):
            with self.subTest(zip64=zip64):
                self.package(zip64=zip64)
                before = self.path.read_bytes()
                result = verify_package(self.path)
                self.assertEqual(result["integrity"], "VERIFIED")
                self.assertEqual(result["authenticity"], "UNVERIFIED")
                self.assertEqual(self.path.read_bytes(), before)

    def test_forged_small_footer_count_cannot_materialize_extra_members(self):
        self.package()
        data = bytearray(self.path.read_bytes())
        footer = data.rfind(b"PK\x05\x06")
        self.assertGreaterEqual(footer, 0)
        struct.pack_into("<HH", data, footer + 8, 1, 1)
        self.path.write_bytes(data)
        with patch("blackbox_core.archive_policy.zipfile.ZipFile") as materialize:
            with self.assertRaisesRegex(ValueError, "ZIP_DIRECTORY_COUNT_MISMATCH"):
                with bounded_zip(self.path, max_total_bytes=1024):
                    self.fail("forged metadata cannot open an archive")
            materialize.assert_not_called()

    def test_directory_size_and_member_policies_fail_before_materialization(self):
        self.package()
        raw = bytearray(self.path.read_bytes())
        footer = raw.rfind(b"PK\x05\x06")
        struct.pack_into("<I", raw, footer + 12, MAX_CENTRAL_BYTES + 1)
        self.path.write_bytes(raw)
        with patch("blackbox_core.archive_policy.zipfile.ZipFile") as materialize:
            with self.assertRaisesRegex(ValueError, "ZIP_DIRECTORY_BUDGET"):
                with bounded_zip(self.path, max_total_bytes=1024):
                    self.fail("oversized directory cannot open an archive")
            materialize.assert_not_called()
        self.package()
        with self.assertRaisesRegex(ValueError, "ZIP_DIRECTORY_BUDGET"):
            with bounded_zip(self.path, max_members=1, max_total_bytes=1024):
                self.fail("member count exceeds explicit policy")

    def test_single_read_cap_survives_replaced_metadata_without_allocating_it(self):
        source = BytesIO(b"unchanged")
        with self.assertRaisesRegex(ValueError, "ZIP_SINGLE_READ_BUDGET"):
            _BoundedReads(source).read(MAX_CENTRAL_BYTES + 1)
        self.assertEqual(source.tell(), 0)

    def test_invalid_manifest_shapes_never_escape_as_attribute_or_type_errors(self):
        invalid = ([], {"kind": "BLACKBOX_RESEARCH_PACKAGE", "files": ["wrong"]},
            {"kind": "BLACKBOX_RESEARCH_PACKAGE", "files": [{"name": [], "size": 1, "sha256": "a"*64}]},
            {"kind": "BLACKBOX_RESEARCH_PACKAGE", "files": [{"name": "session.sqlite3", "size": True, "sha256": "a"*64}]})
        for manifest in invalid:
            with self.subTest(manifest=manifest):
                self.package(manifest)
                before = self.path.read_bytes()
                with self.assertRaises(ValueError):
                    verify_package(self.path)
                self.assertEqual(self.path.read_bytes(), before)

    def test_invalid_zip_and_invalid_budget_are_controlled(self):
        self.path.write_bytes(b"not an archive")
        with self.assertRaises(ValueError):
            verify_package(self.path)
        for policy in (float("nan"), True, 0, None):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                verify_package(self.path, max_total_bytes=policy)
