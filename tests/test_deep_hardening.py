"""Deep consumer adversarial QA: reports, installer ZIPs, junctions and graph fidelity.

Deliberately offline; temporary files only; no real app install or downloads.
"""
from __future__ import annotations

from io import BytesIO
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile, ZipInfo

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication

from blackbox_core.contracts import ObserverError
from blackbox_core.report import summarize, write_report
from blackbox_core.storage import SessionStore
from blackbox_universal.releases import (
    _extract_release, EXECUTABLE_NAME, MAINTENANCE_NAME, INSTALL_MARKER)
from blackbox_universal.maintenance import (
    _safe_install, _keep_local_logs, _is_directory_link,
    apply_update, MaintenanceError)
from blackbox_universal.widgets import TrendChart

MARKER = {"product": "blackbox-universal", "install_type": "portable"}


def _release_zip(extra=None) -> bytes:
    out = BytesIO()
    with ZipFile(out, "w") as archive:
        root = "BLACK.BOX-Universal/"
        archive.writestr(root + EXECUTABLE_NAME, b"win")
        archive.writestr(root + MAINTENANCE_NAME, b"maint")
        archive.writestr(root + INSTALL_MARKER, json.dumps(MARKER))
        if extra is not None:
            for path, value in extra:
                if isinstance(path, ZipInfo):
                    archive.writestr(path, value)
                else:
                    archive.writestr(path, value)
    return out.getvalue()


class ReportIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="bb-deep-report-")
        self.addCleanup(self.tmp.cleanup)
        store = SessionStore(Path(self.tmp.name), 92)
        self.folder = store.folder
        self.db = store
        self.addCleanup(store.close)

    def _complete(self):
        self.db.finish("COMPLETED")
        self.db.close()

    def test_user_problem_is_never_counted_as_observer_error(self):
        self.db.write_event({"kind": "user_problem", "source": "USER",
                             "elapsed_ms": 1, "note": "Window not responsive"})
        self.db.write_event({"kind": "observer_lifecycle", "code": "UI_CLOSED"})
        self.db.write_event({"kind": "observer_error", "code": "ACCESS_DENIED"})
        self._complete()
        summary = summarize(self.folder)
        self.assertEqual(summary["observation_errors"], {"ACCESS_DENIED": 1})
        self.assertFalse(summary["execution_attested"])

    def test_report_streams_many_events_without_false_faults(self):
        for i in range(1400):
            self.db.write_event({"kind": "user_problem", "elapsed_ms": i, "note": "slow"})
        self._complete()
        self.assertEqual(summarize(self.folder)["observation_errors"], {})

    def test_invalid_event_shape_fails_with_controlled_observer_error(self):
        self.db.db.execute("INSERT INTO events(data) VALUES (?)", ('["not", "object"]',))
        self.db.db.commit()
        self._complete()
        with self.assertRaisesRegex(ObserverError, "report:INVALID_DATA"):
            summarize(self.folder)

    def test_racing_second_publisher_cannot_overwrite_other_report(self):
        self._complete()
        actual_link = os.link
        conflicting = self.folder / "report.json"

        def intruder(src, dest):
            if Path(dest) == conflicting and not conflicting.exists():
                conflicting.write_bytes(b"OTHER_AUTHOR_DATA")
            return actual_link(src, dest)

        with patch("blackbox_core.report.os.link", side_effect=intruder):
            with self.assertRaisesRegex(ObserverError, "storage:STORAGE_ERROR"):
                write_report(self.folder)
        self.assertEqual(conflicting.read_bytes(), b"OTHER_AUTHOR_DATA")
        self.assertFalse((self.folder / "report.html").exists())
        self.assertFalse(list(self.folder.glob(".blackbox-report-*")))

    def test_positive_report_creates_two_separate_outputs(self):
        self._complete()
        result = write_report(self.folder)
        self.assertEqual(result["report_file"], "report.json")
        self.assertTrue((self.folder / "report.html").is_file())
        self.assertIn("UNKNOWN", (self.folder / "report.json").read_text(encoding="utf-8"))
        self.assertFalse(list(self.folder.glob(".blackbox-report-*")))


class OfflineInstallerAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="bb-deep-zip-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def rejection(self, extra, reason):
        archive = self.root / "candidate.zip"
        archive.write_bytes(_release_zip(extra))
        destination = self.root / "staging"
        destination.mkdir(exist_ok=True)
        with self.assertRaisesRegex(ValueError, reason):
            _extract_release(archive, destination)

    def test_windows_reserved_devices_and_illegal_characters(self):
        for value in ("COM9.tmp", "LPT8.txt", "CON", "NUL.txt", "bad?.dll",
                      "trail. ", "stream:name", "under<test>.dll"):
            with self.subTest(name=value), tempfile.TemporaryDirectory() as folder:
                path = Path(folder)
                archive = path / "in.zip"
                archive.write_bytes(_release_zip([
                    ("BLACK.BOX-Universal/" + value, "EXTERNAL")]))
                with self.assertRaisesRegex(ValueError, "ARCHIVE_PATH_INVALID"):
                    _extract_release(archive, path / "output")

    def test_archive_file_must_not_be_parent_directory(self):
        self.rejection([
            ("BLACK.BOX-Universal/nested", "a"),
            ("BLACK.BOX-Universal/nested/data.dll", "b")],
            "ARCHIVE_FILE_DIRECTORY_COLLISION")

    def test_nonregular_unix_zip_entry_is_rejected_before_writes(self):
        item = ZipInfo("BLACK.BOX-Universal/device")
        item.create_system = 3
        item.external_attr = (stat.S_IFIFO | 0o600) << 16
        self.rejection([(item, b"danger")], "ARCHIVE_SPECIAL_FILE_REFUSED")

    def test_existing_root_link_not_followed(self):
        out = self.root / "outside"
        out.mkdir()
        dest = self.root / "stage"
        dest.mkdir()
        link = dest / "BLACK.BOX-Universal"
        try:
            link.symlink_to(out, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation restricted")
        archive = self.root / "archive.zip"
        archive.write_bytes(_release_zip())
        with self.assertRaisesRegex(ValueError, "STAGING_NOT_EMPTY"):
            _extract_release(archive, dest)
        self.assertEqual(list(out.iterdir()), [])

    def test_windows_reparse_install_is_rejected_before_deletion(self):
        install = self.root / "BlackBox"
        install.mkdir()
        for name in (EXECUTABLE_NAME, MAINTENANCE_NAME, INSTALL_MARKER):
            (install / name).write_text(json.dumps(MARKER) if name == INSTALL_MARKER else "binary")
        with patch("blackbox_universal.maintenance._is_directory_link",
                   side_effect=lambda path: Path(path) == install):
            with self.assertRaisesRegex(MaintenanceError, "INSTALL_FOLDER_INVALID"):
                _safe_install(install)

    def test_lstat_access_error_cannot_be_treated_as_safe(self):
        folder = self.root / "install"
        folder.mkdir()
        with patch.object(Path, "lstat", side_effect=PermissionError("blocked")):
            with self.assertRaisesRegex(MaintenanceError, "PATH_INSPECTION_FAILED"):
                _is_directory_link(folder)

    def test_junction_ancestor_blocks_uninstall_target(self):
        parent = self.root / "junction-parent"
        install = parent / "BLACK.BOX-Universal"
        install.mkdir(parents=True)
        for name in (EXECUTABLE_NAME, MAINTENANCE_NAME, INSTALL_MARKER):
            (install / name).write_text(
                json.dumps(MARKER) if name == INSTALL_MARKER else "binary")
        actual = __import__("blackbox_universal.maintenance", fromlist=[
            "_is_directory_link"])._is_directory_link
        with patch("blackbox_universal.maintenance._is_directory_link",
                   side_effect=lambda path: Path(path) == parent or actual(path)):
            with self.assertRaisesRegex(MaintenanceError, "INSTALL_FOLDER_INVALID"):
                _safe_install(install)
        self.assertTrue((install / EXECUTABLE_NAME).is_file())

    def test_update_rollback_keeps_previous_session_if_new_has_collision(self):
        parent = self.root / "installs"
        install = parent / "BLACK.BOX-Universal"
        stage = parent / ".blackbox-stage-test" / "BLACK.BOX-Universal"
        for folder, build in ((install, "old"), (stage, "new")):
            folder.mkdir(parents=True)
            (folder / INSTALL_MARKER).write_text(json.dumps(MARKER))
            (folder / EXECUTABLE_NAME).write_text(build)
            (folder / MAINTENANCE_NAME).write_text(build)
            (folder / "sessions").mkdir()
        (install / "sessions" / "session.sqlite3").write_bytes(b"REAL_USER_EVIDENCE")
        (stage / "sessions" / "unwanted").write_bytes(b"NEW_INSTALL_COLLISION")
        with self.assertRaisesRegex(MaintenanceError, "UPDATE_DATA_COLLISION"):
            apply_update(install, stage)
        self.assertEqual((install / EXECUTABLE_NAME).read_text(), "old")
        self.assertEqual((install / "sessions" / "session.sqlite3").read_bytes(),
                         b"REAL_USER_EVIDENCE")
        self.assertTrue((stage / EXECUTABLE_NAME).is_file())
        self.assertFalse(list(parent.glob(".blackbox-old-*")))

    def test_staging_junction_ancestor_blocks_update_without_mutating_install(self):
        parent = self.root / "installs"
        install = parent / "BLACK.BOX-Universal"
        stage_parent = parent / ".blackbox-stage-test"
        stage = stage_parent / "BLACK.BOX-Universal"
        for folder, build in ((install, "old"), (stage, "new")):
            folder.mkdir(parents=True)
            (folder / INSTALL_MARKER).write_text(json.dumps(MARKER))
            (folder / EXECUTABLE_NAME).write_text(build)
            (folder / MAINTENANCE_NAME).write_text(build)
        actual = __import__("blackbox_universal.maintenance", fromlist=[
            "_is_directory_link"])._is_directory_link
        with patch("blackbox_universal.maintenance._is_directory_link",
                   side_effect=lambda path: Path(path) == stage_parent or actual(path)):
            with self.assertRaisesRegex(MaintenanceError, "STAGING_ROOT_NOT_SIBLING"):
                apply_update(install, stage)
        self.assertEqual((install / EXECUTABLE_NAME).read_text(), "old")

    def test_saved_user_data_link_blocks_preservation(self):
        folder = self.root / "portable"
        folder.mkdir()
        logs = folder / "logs"
        logs.mkdir()
        preserved = self.root / "keep"
        with patch("blackbox_universal.maintenance._is_directory_link",
                   side_effect=lambda path: Path(path) == logs):
            with self.assertRaisesRegex(MaintenanceError, "DATA_LINK_REFUSED"):
                _keep_local_logs(folder, preserved)
        self.assertTrue(logs.exists())
        self.assertFalse(preserved.exists())


class VisualIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_multicore_cpu_chart_does_not_clip_at_100(self):
        chart = TrendChart()
        chart.resize(450, 250)
        chart.set_samples([
            {"cpu_pct": 50.0, "rss_mb": 90.0},
            {"cpu_pct": 225.0, "rss_mb": 160.0},
            {"cpu_pct": None, "rss_mb": None},
        ])
        self.assertGreaterEqual(chart.cpu_scale, 225)
        self.assertEqual(chart._cpu[-1], None)
        chart.show()
        self.assertFalse(chart.grab().isNull())
        chart.close()

    def test_normal_cpu_chart_remains_100_percent_scale(self):
        chart = TrendChart()
        chart.set_samples([{"cpu_pct": 30.0, "rss_mb": 20.0}])
        self.assertEqual(chart.cpu_scale, 100)
        chart.close()


if __name__ == "__main__":
    unittest.main()
