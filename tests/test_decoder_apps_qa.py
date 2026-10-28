"""Portable checks for the real-app QA download boundary, not Windows evidence."""
from pathlib import Path
import json
import sqlite3
import stat
import tempfile
import unittest
import zipfile

from tools.qa_decoder_apps import etw_observations, safe_extract


class ApplicationLifetimeEvidenceTests(unittest.TestCase):
    def observations(self, rows, pids):
        # Explicit protocol fixture: this exercises acceptance proof handling,
        # not Windows ETW capture or third-party application execution.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "observations.sqlite3"
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE events(data TEXT NOT NULL)")
                db.executemany("INSERT INTO events VALUES (?)",
                               [(json.dumps(row),) for row in rows])
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
