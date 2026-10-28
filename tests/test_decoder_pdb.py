"""Adversarial synthetic PE CodeView RSDS / MSF 7.0 PDB tests.

Synthetic bytes test the identity *preflight*, never true symbol resolution.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID

from blackbox_core.decoder_pdb import review_local_pe_pdb, MSF7_MAGIC

GOOD_GUID = UUID("12345678-1234-4321-8765-123456789abc")
OTHER_GUID = UUID("12345678-1234-4321-8765-123456789abd")


def fixture_pe(path, *, guid=GOOD_GUID, age=7, portable=False, duplicate=False):
    data = bytearray(2048)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 224, 0)
    opt = 0x80 + 24
    struct.pack_into("<H", data, opt, 0x10B)
    struct.pack_into("<I", data, opt + 60, 512)
    struct.pack_into("<I", data, opt + 92, 16)
    struct.pack_into("<II", data, opt + 96 + 6*8, 0x2000, 56 if duplicate else 28)
    sec = opt + 224
    data[sec:sec+8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, sec + 8, 512, 0x2000, 512, 512)
    record = b"RSDS" + guid.bytes_le + struct.pack("<I", age) + b"C:\\secret\\build\\test.pdb\0"
    debug = 512
    struct.pack_into("<I", data, debug + 12, 2)
    struct.pack_into("<III", data, debug + 16, len(record), 0x2040, 512 + 64)
    if portable:
        struct.pack_into("<H", data, debug + 10, 0x504D)
    data[576:576+len(record)] = record
    if duplicate:
        second = record[:4] + OTHER_GUID.bytes_le + record[20:]
        struct.pack_into("<I", data, debug + 28 + 12, 2)
        struct.pack_into("<III", data, debug + 28 + 16, len(record), 0x2080, 512 + 128)
        data[640:640+len(second)] = second
    path.write_bytes(data)


def fixture_pdb(path, *, guid=GOOD_GUID, age=7, version=20000404):
    block = 512
    data = bytearray(block * 6)
    data[:32] = MSF7_MAGIC
    struct.pack_into("<6I", data, 32, block, 1, 6, 16, 0, 3)
    struct.pack_into("<I", data, block*3, 4)
    struct.pack_into("<4I", data, block*4, 2, 0xffffffff, 28, 5)
    struct.pack_into("<III16s", data, block*5, version, 0, age, guid.bytes_le)
    path.write_bytes(data)


class LocalPdbIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pe = self.root / "test.exe"
        self.pdb = self.root / "test.pdb"
        fixture_pe(self.pe)
        fixture_pdb(self.pdb)

    def test_matching_rsds_and_pdb_info_does_not_claim_resolved_symbols(self):
        before = [hashlib.sha256(p.read_bytes()).hexdigest() for p in (self.pe, self.pdb)]
        result = review_local_pe_pdb(self.pe, self.pdb)
        self.assertEqual(result["status"], "PE_PDB_GUID_AGE_MATCH_UNLINKED_TO_TRACE")
        self.assertEqual(result["binary"]["guid"], str(GOOD_GUID))
        self.assertEqual(result["pdb"]["age"], 7)
        self.assertEqual(result["pdb_name_matching"], "MATCH")
        self.assertEqual(result["trace_module_identity"], "NOT_ESTABLISHED")
        self.assertFalse(result["stack_symbols_resolved"])
        self.assertFalse(result["symbol_server_contacted"])
        self.assertFalse(result["source_execution"])
        self.assertNotIn("secret", str(result))
        self.assertEqual(before, [hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in (self.pe, self.pdb)])

    def test_mismatched_guid_and_age_never_verify(self):
        for kwargs in ({"guid": OTHER_GUID}, {"age": 8}):
            with self.subTest(kwargs=kwargs):
                fixture_pdb(self.pdb, **kwargs)
                result = review_local_pe_pdb(self.pe, self.pdb)
                self.assertEqual(result["status"], "PE_PDB_GUID_AGE_MISMATCH")
                self.assertFalse(result["stack_symbols_resolved"])

    def test_malformed_input_is_explicit_unavailable(self):
        for target, payload in ((self.pe, b"NOT_PE"),
                                (self.pdb, b"NOT_PDB"),
                                (self.pdb, b"BSJB" + b"\x00"*96)):
            with self.subTest(target=target.name, payload=payload[:8]):
                target.write_bytes(payload)
                result = review_local_pe_pdb(self.pe, self.pdb)
                self.assertEqual(result["status"], "LOCAL_IDENTITY_UNAVAILABLE")
                self.assertFalse(result["stack_symbols_resolved"])
                fixture_pe(self.pe)
                fixture_pdb(self.pdb)

    def test_portable_and_ambiguous_codeview_records_are_rejected(self):
        fixture_pe(self.pe, portable=True)
        self.assertEqual(review_local_pe_pdb(self.pe, self.pdb)["reason"],
                         "PORTABLE_PDB_UNSUPPORTED")
        fixture_pe(self.pe, duplicate=True)
        self.assertEqual(review_local_pe_pdb(self.pe, self.pdb)["reason"],
                         "AMBIGUOUS_PE_RSDS_IDENTITY")

    def test_unsupported_pdb_version_is_not_guessed(self):
        fixture_pdb(self.pdb, version=20030901)
        self.assertEqual(review_local_pe_pdb(self.pe, self.pdb)["reason"],
                         "UNSUPPORTED_PDB_INFO_VERSION")

    def test_bad_block_map_fails_closed(self):
        data = bytearray(self.pdb.read_bytes())
        struct.pack_into("<I", data, 512*3, 9999)
        self.pdb.write_bytes(data)
        self.assertEqual(review_local_pe_pdb(self.pe, self.pdb)["status"],
                         "LOCAL_IDENTITY_UNAVAILABLE")

    def test_symlink_and_oversized_file_are_rejected(self):
        link = self.root / "linked.pdb"
        try:
            link.symlink_to(self.pdb)
        except (OSError, NotImplementedError):
            pass
        else:
            self.assertEqual(review_local_pe_pdb(self.pe, link)["reason"],
                             "UNSAFE_LOCAL_PATH")
        with patch("blackbox_core.decoder_pdb.MAX_LOCAL_FILE_BYTES", 2048):
            self.assertEqual(review_local_pe_pdb(self.pe, self.pdb)["reason"],
                             "LOCAL_FILE_SIZE_OR_TYPE_UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
