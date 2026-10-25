"""Offline checks for releases, safe maintenance, and bilingual GUI.

No live network calls or destructive access to a real user's installation.
"""
from __future__ import annotations

from contextlib import contextmanager
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
import zipfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication, QMessageBox

from blackbox_universal.releases import (
    ARCHIVE_NAME, EXECUTABLE_NAME, INSTALL_MARKER, MAINTENANCE_NAME,
    RELEASE_API, RELEASES_API, NoOfficialRelease, Release, check_latest_release,
    stage_release, version_tuple,
    _extract_release,
)
from blackbox_universal.maintenance import (
    MaintenanceError, apply_update, uninstall,
)
from blackbox_universal.theme import set_retro_theme
from blackbox_universal.window import UniversalWindow

MARKER = {"product": "blackbox-universal", "install_type": "portable"}


def fake_install(path: Path, name: str = "old") -> None:
    path.mkdir(parents=True)
    (path / INSTALL_MARKER).write_text(json.dumps(MARKER), encoding="utf-8")
    (path / EXECUTABLE_NAME).write_text(name, encoding="utf-8")
    (path / MAINTENANCE_NAME).write_text(name, encoding="utf-8")


def make_zip(*, bad_path=False) -> bytes:
    storage = BytesIO()
    with zipfile.ZipFile(storage, "w") as z:
        base = "BLACK.BOX-Universal/"
        z.writestr(base + EXECUTABLE_NAME, "new")
        z.writestr(base + MAINTENANCE_NAME, "new")
        z.writestr(base + INSTALL_MARKER, json.dumps(MARKER))
        if bad_path:
            z.writestr(base + "../injected-file", "NO")
    return storage.getvalue()


class ReleasesTests(unittest.TestCase):
    def test_semver_strict(self):
        self.assertEqual(version_tuple("v0.1.2"), (0, 1, 2))
        self.assertEqual(version_tuple("0.4.0"), (0, 4, 0))
        self.assertIsNone(version_tuple("v0.1.2-alpha"))
        self.assertIsNone(version_tuple("latest"))

    def test_only_verified_newer_official_release_turns_update_available(self):
        digest = "a" * 64
        tag = "v0.1.1"
        metadata = {
            "tag_name": tag, "draft": False, "prerelease": False,
            "html_url": "https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/releases/tag/" + tag,
            "assets": [{
                "name": ARCHIVE_NAME, "digest": "sha256:" + digest,
                "size": 1700,
                "browser_download_url":
                    "https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/releases/download/"
                    + tag + "/" + ARCHIVE_NAME,
            }],
        }
        def fake_response(url):
            self.assertEqual(url, RELEASE_API)
            return BytesIO(json.dumps(metadata).encode("utf-8"))
        with patch("blackbox_universal.releases._open", side_effect=fake_response):
            release = check_latest_release("0.1.0")
            self.assertEqual(release.sha256, digest)
            self.assertEqual(release.version, tag)
            self.assertIsNone(check_latest_release("0.1.1"))
            metadata["assets"][0]["digest"] = None
            with self.assertRaisesRegex(ValueError, "RELEASE_DIGEST_MISSING"):
                check_latest_release("0.1.0")
            metadata["assets"][0]["digest"] = "sha256:" + digest
            metadata["assets"][0]["browser_download_url"] = "https://evil.invalid/file.zip"
            with self.assertRaisesRegex(ValueError, "RELEASE_ASSET_URL_UNTRUSTED"):
                check_latest_release("0.1.0")

    def test_no_official_release_has_a_separate_status(self):
        seen = []
        def fake_response(url):
            seen.append(url)
            if url == RELEASE_API:
                raise HTTPError(url, 404, "Not Found", None, None)
            self.assertEqual(url, RELEASES_API)
            return BytesIO(b"[]")
        with patch("blackbox_universal.releases._open", side_effect=fake_response):
            with self.assertRaises(NoOfficialRelease):
                check_latest_release("0.3.0")
        self.assertEqual(seen, [RELEASE_API, RELEASES_API])

    def test_prerelease_only_does_not_claim_official_update(self):
        def fake_response(url):
            if url == RELEASE_API:
                raise HTTPError(url, 404, "Not Found", None, None)
            return BytesIO(json.dumps([{"draft": False, "prerelease": True}]).encode())
        with patch("blackbox_universal.releases._open", side_effect=fake_response):
            with self.assertRaises(NoOfficialRelease):
                check_latest_release("0.3.0")

    def test_404_for_missing_repo_is_still_real_error(self):
        def unavailable(url):
            raise HTTPError(url, 404, "Not Found", None, None)
        with patch("blackbox_universal.releases._open", side_effect=unavailable):
            with self.assertRaises(HTTPError):
                check_latest_release("0.3.0")

    def test_inconsistent_or_corrupt_release_listing_not_accepted(self):
        def check(data):
            def fake_response(url):
                if url == RELEASE_API:
                    raise HTTPError(url, 404, "Not Found", None, None)
                return BytesIO(data)
            with patch("blackbox_universal.releases._open", side_effect=fake_response):
                check_latest_release("0.3.0")
        with self.assertRaisesRegex(ValueError, "RELEASE_LIST_INVALID"):
            check(b'{"message":"Not Found"}')
        with self.assertRaisesRegex(ValueError, "RELEASE_METADATA_INCONSISTENT"):
            check(b'[{"draft":false,"prerelease":false}]')

    def test_clean_verified_staging_then_corrupt_download_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            installation = parent / "BLACK.BOX-Universal"
            fake_install(installation)
            old = (installation / EXECUTABLE_NAME).read_bytes()
            raw = make_zip()
            release = Release(
                "v0.1.1", "https://github.com/fake/test.zip", len(raw),
                hashlib.sha256(raw).hexdigest(), "https://github.com")
            with patch("blackbox_universal.releases._open",
                       return_value=BytesIO(raw)):
                staged = stage_release(release, installation)
            self.assertTrue((staged / EXECUTABLE_NAME).is_file())
            self.assertEqual((installation / EXECUTABLE_NAME).read_bytes(), old)
            with patch("blackbox_universal.releases._open",
                       return_value=BytesIO(raw)):
                bad = Release(release.version, release.asset_url,
                              release.size, "f" * 64, release.notes_url)
                with self.assertRaisesRegex(ValueError, "RELEASE_CHECKSUM_MISMATCH"):
                    stage_release(bad, installation)
            self.assertEqual(len(list(parent.glob(".blackbox-stage-*"))), 1)

    def test_zip_path_traversal_rejected_with_no_file_outside_staging(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            src = root / "bad.zip"
            src.write_bytes(make_zip(bad_path=True))
            with self.assertRaisesRegex(ValueError, "ARCHIVE_PATH_INVALID"):
                _extract_release(src, root / "staging")
            self.assertFalse((root / "injected-file").exists())


class PortableMaintenanceTests(unittest.TestCase):
    def test_update_replaces_old_files_and_preserves_logs_without_backups(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            install = parent / "BLACK.BOX-Universal"
            fake_install(install)
            (install / "obsolete.dll").write_text("OLD")
            logs = install / "logs"
            logs.mkdir()
            (logs / "keep.txt").write_text("IMPORTANT")
            stage = parent / ".blackbox-stage-check"
            fake_install(stage / "BLACK.BOX-Universal", "new")
            with patch("blackbox_universal.maintenance.subprocess.Popen"):
                apply_update(install, stage / "BLACK.BOX-Universal")
            self.assertEqual((install / EXECUTABLE_NAME).read_text(), "new")
            self.assertFalse((install / "obsolete.dll").exists())
            self.assertEqual((install / "logs/keep.txt").read_text(), "IMPORTANT")
            self.assertFalse(list(parent.glob(".blackbox-old-*")))
            self.assertFalse(stage.exists())

    def test_uninstall_keeps_logs_sessions_and_cannot_erase_unmarked_dir(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            install = parent / "BLACK.BOX-Universal"
            fake_install(install)
            for dirname in ("logs", "sessions"):
                folder = install / dirname
                folder.mkdir()
                (folder / "evidence.txt").write_text(dirname)
            data = parent / "user-data"
            with patch("blackbox_universal.maintenance._user_data_root",
                       return_value=data), \
                 patch("blackbox_universal.maintenance.remove_shortcut_if_matches"):
                uninstall(install)
            self.assertFalse(install.exists())
            kept = list(data.glob("Preserved-*/logs/evidence.txt"))
            self.assertEqual(len(kept), 1)
            self.assertEqual(kept[0].read_text(), "logs")
            self.assertEqual(len(list(data.glob("Preserved-*/sessions/evidence.txt"))), 1)
            other = parent / "Other"
            other.mkdir()
            with self.assertRaises(MaintenanceError):
                uninstall(other)


    def test_uninstall_resolves_shortcut_before_deleting_exe(self):
        with tempfile.TemporaryDirectory() as directory:
            install = Path(directory) / "BLACK.BOX-Universal"
            fake_install(install)
            observed = []
            def detach(exe):
                self.assertTrue(exe.is_file(), "must resolve .lnk before EXE removal")
                observed.append("detached")
                return None
            with patch("blackbox_universal.maintenance._detach_matching_desktop_shortcut",
                       side_effect=detach):
                uninstall(install)
            self.assertEqual(observed, ["detached"])
            self.assertFalse(install.exists())

    def test_failed_uninstall_restores_original_shortcut_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            install = base / "BLACK.BOX-Universal"
            fake_install(install)
            shortcut = base / "BLACK.BOX Universal.lnk"
            original = b"original-link-file-bytes"
            shortcut.write_bytes(original)
            def detach(_exe):
                shortcut.unlink()
                return shortcut, original
            with patch("blackbox_universal.maintenance._detach_matching_desktop_shortcut",
                       side_effect=detach), \
                 patch("blackbox_universal.maintenance.shutil.rmtree",
                       side_effect=PermissionError("locked")):
                with self.assertRaises(PermissionError):
                    uninstall(install)
            self.assertEqual(shortcut.read_bytes(), original)
            self.assertTrue(install.exists())

class LanguageAndFeedbackQtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        set_retro_theme(cls.app)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.window = UniversalWindow()
        self.window._timer.stop()

    def tearDown(self):
        self.window._timer.stop()
        self.window.close()
        self.tmp.cleanup()

    def test_ru_eng_without_recreating_widgets_or_losing_pid(self):
        self.window._set_language("RU")
        self.assertEqual(self.window.language, "RU")
        self.assertEqual(self.window._nav_buttons["dashboard"].text(), "   01  ОБЗОР")
        self.assertIn("НАЧАТЬ", self.window.start_btn.text())
        self.assertEqual(self.window.lang_ru.property("active"), True)
        self.window._set_language("EN")
        self.assertEqual(self.window._nav_buttons["dashboard"].text(), "   01  OVERVIEW")
        self.assertEqual(self.window.lang_en.property("active"), True)

    def test_feedback_buttons_open_correct_targets_without_upload(self):
        with patch("blackbox_universal.window.QDesktopServices.openUrl") as open_url:
            self.window.github_button.click()
            self.window.email_button.click()
            self.assertEqual(open_url.call_count, 2)
            self.assertEqual(open_url.call_args_list[0].args[0].toString(),
                             "https://github.com/jumonja-maker/BlackBox-Rep.-Alva-")
            self.assertTrue(open_url.call_args_list[1].args[0].toString().startswith(
                "mailto:jumonjescu@mail.ru"))

    def test_update_button_only_green_for_a_verified_new_release(self):
        self.window._available_release = None
        self.window._refresh_update_button("latest")
        self.assertFalse(self.window.update_button.property("available"))
        self.window._available_release = Release("v0.1.1", "", 2, "a" * 64, "")
        self.window._refresh_update_button()
        self.assertTrue(self.window.update_button.property("available"))
        self.assertIn("UPDATE AVAILABLE", self.window.update_button.text())

    def test_no_official_release_is_not_a_network_failure_or_a_green_update(self):
        self.window._available_release = None
        self.window._set_language("EN")
        self.window._update_checked(None, "NO_OFFICIAL_RELEASE")
        self.assertIn("NO OFFICIAL RELEASE", self.window.update_button.text())
        self.assertFalse(self.window.update_button.property("available"))
        self.assertIn("not automatic updates", self.window.update_button.toolTip())
        self.window._set_language("RU")
        self.window._update_checked(None, "NO_OFFICIAL_RELEASE")
        self.assertIn("РЕЛИЗОВ ПОКА НЕТ", self.window.update_button.text())
        self.window._update_checked(None, "HTTPError")
        self.assertIn("ПРОВЕРКА НЕ УДАЛАСЬ", self.window.update_button.text())

    def test_uninstall_refuses_unmarked_source_tree(self):
        with patch("blackbox_universal.window.runtime_directory", return_value=None), \
             patch.object(QMessageBox, "information", return_value=None):
            self.window._request_uninstall()
            self.window._create_shortcut()


if __name__ == "__main__":
    unittest.main()
