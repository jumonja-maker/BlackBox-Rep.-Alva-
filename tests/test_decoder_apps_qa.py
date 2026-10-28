"""Portable checks for the real-app QA download boundary, not Windows evidence."""
from contextlib import closing
from pathlib import Path
import json
import sqlite3
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from tools.qa_decoder_apps import (etw_observations, installed, native_pe_identity,
                                   observed_process_image, safe_extract)


class ApplicationImageIdentityTests(unittest.TestCase):
    def test_explicit_application_precedes_path_shim_and_owns_observed_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            native = root / "program-files-7z.exe"
            shim = root / "chocolatey-7z.exe"
            native.write_bytes(b"native-file-identity-fixture")
            shim.write_bytes(b"launcher-file-identity-fixture")
            with patch("tools.qa_decoder_apps.shutil.which", return_value=str(shim)):
                self.assertEqual(installed("7z", [native]), native.resolve())
            with self.assertRaisesRegex(AssertionError, "OWNED_PROCESS_IMAGE_MISMATCH"):
                observed_process_image(shim, native)
            self.assertEqual(observed_process_image(native, native), str(native.resolve()))

    def pe_header_fixture(self, *, magic=0x20B, managed=False, dll=False):
        # Explicit binary-format fixture only; never executed and never
        # presented as acceptance of an actual Windows application.
        directory_at = 112 if magic == 0x20B else 96
        optional_size = directory_at + 16 * 8
        data = bytearray(128 + 24 + optional_size)
        data[:2] = b"MZ"; struct.pack_into("<I", data, 60, 128)
        data[128:132] = b"PE\0\0"
        struct.pack_into("<H", data, 132, 0x8664 if magic == 0x20B else 0x14C)
        struct.pack_into("<HH", data, 148, optional_size, 0x2002 if dll else 0x2)
        struct.pack_into("<H", data, 152, magic)
        struct.pack_into("<I", data, 152 + directory_at - 4, 16)
        if managed:
            struct.pack_into("<II", data, 152 + directory_at + 14 * 8, 0x2000, 72)
        return data

    def test_clr_launcher_cannot_certify_native_application_for_either_pe_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "image.exe"
            for magic in (0x10B, 0x20B):
                with self.subTest(magic=magic):
                    binary.write_bytes(self.pe_header_fixture(magic=magic, managed=True))
                    with self.assertRaisesRegex(AssertionError, "CLR_LAUNCHER_OR_MANAGED_IMAGE_REJECTED"):
                        native_pe_identity(binary)
                    binary.write_bytes(self.pe_header_fixture(magic=magic))
                    proof = native_pe_identity(binary)
                    self.assertEqual(proof["code_kind"], "NATIVE_PE_NO_CLR_COM_DESCRIPTOR")
                    self.assertEqual(proof["clr_com_descriptor_bytes"], 0)

    def test_truncated_header_and_dll_do_not_count_as_native_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "image.exe"
            for data in (b"MZ", self.pe_header_fixture()[:-1], self.pe_header_fixture(dll=True)):
                with self.subTest(length=len(data)):
                    binary.write_bytes(data)
                    with self.assertRaises(AssertionError):
                        native_pe_identity(binary)


class ApplicationLifetimeEvidenceTests(unittest.TestCase):
    def observations(self, rows, pids):
        # Explicit protocol fixture: this exercises acceptance proof handling,
        # not Windows ETW capture or third-party application execution.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "observations.sqlite3"
            with closing(sqlite3.connect(path)) as db:
                db.execute("CREATE TABLE events(data TEXT NOT NULL)")
                db.executemany("INSERT INTO events VALUES (?)",
                               [(json.dumps(row),) for row in rows])
                db.commit()
            return etw_observations(path, pids)

    def test_absent_or_missing_pid_identity_is_not_lifetime_evidence(self):
        for rows in ([], [{"pid": 10}], [{"pid": 10, "process_instance": 1}]):
            with self.subTest(rows=rows):
                observed = self.observations(rows, [10, 20])
                self.assertFalse(observed["pid_reuse_ambiguous"])
                self.assertFalse(observed["pid_lifetimes_confirmed"])
        self.assertFalse(self.observations([], [])["pid_lifetimes_confirmed"])

    def test_each_owned_pid_needs_one_unique_observed_lifetime(self):
        rows = [{"pid": 10, "process_instance": 0},
                {"pid": 20, "process_instance": 1},
                {"pid": 20, "process_instance": 1}]
        self.assertTrue(self.observations(rows, [10, 20])["pid_lifetimes_confirmed"])
        rows.append({"pid": 10, "process_instance": 2})
        observed = self.observations(rows, [10, 20])
        self.assertTrue(observed["pid_reuse_ambiguous"])
        self.assertFalse(observed["pid_lifetimes_confirmed"])


class ApplicationArchiveBoundaryTests(unittest.TestCase):
    def archive(self, root, entries):
        path = root / "app.zip"
        with zipfile.ZipFile(path, "w") as z:
            for name, value in entries:
                z.writestr(name, value)
        return path

    def test_complete_validation_precedes_any_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = self.archive(root, [("notepad++.exe", b"owned-fixture"),
                                          ("../outside", b"not allowed")])
            with self.assertRaisesRegex(AssertionError, "UNSAFE_APP_ARCHIVE"):
                safe_extract(archive, root / "output")
            self.assertFalse((root / "output").exists())
            self.assertFalse((root / "outside").exists())

    def test_windows_case_collision_and_file_directory_conflict_rejected(self):
        for entries in [[("App.exe", b"a"), ("app.exe", b"b")],
                        [("assets", b"a"), ("assets/one", b"b")]]:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with self.assertRaises(AssertionError):
                    safe_extract(self.archive(root, entries), root / "output")
                self.assertFalse((root / "output").exists())

    def test_link_member_rejected_without_writing_earlier_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            symlink = zipfile.ZipInfo("link")
            symlink.create_system = 3
            symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive = self.archive(root, [("notepad++.exe", b"owned-fixture"),
                                          (symlink, "../../escape")])
            with self.assertRaisesRegex(AssertionError, "UNSAFE_APP_ARCHIVE"):
                safe_extract(archive, root / "output")
            self.assertFalse((root / "output").exists())

    def test_fixed_payload_retains_runtime_and_omits_active_updater_plugins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = self.archive(root, [("notepad++.exe", b"owned-fixture"),
                                          ("localization/english.xml", b"text"),
                                          ("updater/gup.exe", b"not executed"),
                                          ("plugins/Plugin.dll", b"not executed")])
            safe_extract(archive, root / "output")
            self.assertEqual((root / "output/notepad++.exe").read_bytes(), b"owned-fixture")
            self.assertEqual((root / "output/localization/english.xml").read_bytes(), b"text")
            self.assertFalse((root / "output/updater").exists())
            self.assertFalse((root / "output/plugins").exists())


if __name__ == "__main__":
    unittest.main()
