"""Safe executable selection: offline files are not processes or auto-launched."""
from __future__ import annotations

import os
from pathlib import Path
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication, QMessageBox

from blackbox_universal.file_targets import (
    HASH_LIMIT, find_running_executable, inspect_file,
)
from blackbox_universal.window import UniversalWindow


def fake_pe(path: Path, machine: int = 0x8664) -> Path:
    data = bytearray(256)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 128)
    data[128:132] = b"PE\x00\x00"
    struct.pack_into("<H", data, 132, machine)
    path.write_bytes(data)
    return path


class FileTargetCoreTests(unittest.TestCase):
    def test_pe_exe_is_read_only_and_is_recognized(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = fake_pe(Path(tmp) / "Example.EXE")
            item = inspect_file(path)
            self.assertTrue(item.executable_target)
            self.assertEqual(item.architecture, "x64")
            self.assertEqual(item.size_bytes, 256)
            self.assertEqual(len(item.sha256), 64)
            self.assertEqual(item.path, path.resolve())
            self.assertEqual(path.read_bytes()[:2], b"MZ")

    def test_dll_and_script_are_metadata_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            dll = inspect_file(fake_pe(Path(tmp) / "mylib.dll"))
            cmd = Path(tmp) / "sample.cmd"
            cmd.write_text("echo NO EXECUTION", encoding="utf-8")
            script = inspect_file(cmd)
            self.assertEqual(dll.architecture, "x64")
            self.assertFalse(dll.executable_target)
            self.assertFalse(script.executable_target)
            self.assertIn("script", script.kind.lower())

    def test_disguised_exe_cannot_be_launched(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fake.exe"
            path.write_text("not a Windows binary", encoding="utf-8")
            item = inspect_file(path)
            self.assertFalse(item.executable_target)
            self.assertIsNone(item.architecture)

    def test_oversized_file_skips_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "huge.dll"
            with path.open("wb") as stream:
                stream.truncate(HASH_LIMIT + 1)
            result = inspect_file(path)
            self.assertIsNone(result.sha256)
            self.assertFalse(result.executable_target)

    def test_exact_executable_match_not_similar_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = str(Path(tmp) / "blackbox.exe")
            lookalike = str(Path(tmp) / "other" / "blackbox.exe")
            fake = [
                SimpleNamespace(info={"pid": 84, "name": "blackbox.exe", "exe": lookalike}),
                SimpleNamespace(info={"pid": 12, "name": "blackbox.exe", "exe": target}),
                SimpleNamespace(info={"pid": 5, "name": "blackbox.exe", "exe": None}),
            ]
            with patch("blackbox_universal.file_targets.psutil.process_iter",
                       return_value=fake):
                self.assertEqual(find_running_executable(target), [(12, "blackbox.exe")])


class FileTargetGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sessions = patch("blackbox_universal.monitor._default_sessions_root",
                              return_value=Path(self.tmp.name) / "sessions")
        self.sessions.start()
        self.window = UniversalWindow()
        self.window._timer.stop()

    def tearDown(self):
        self.window.close()
        self.sessions.stop()
        self.tmp.cleanup()

    def _select(self, path: Path):
        with patch("blackbox_universal.window.QFileDialog.getOpenFileName",
                   return_value=(str(path), "")):
            self.window._choose_application_file()

    def test_selecting_exe_does_not_launch_or_attach(self):
        path = fake_pe(Path(self.tmp.name) / "example.exe")
        with patch("blackbox_universal.window.subprocess.Popen") as launched:
            self._select(path)
            launched.assert_not_called()
        self.assertEqual(self.window._selected_file.path, path.resolve())
        self.assertTrue(self.window.find_file_process_button.isEnabled())
        self.assertEqual(self.window.launch_exe_button.isEnabled(), os.name == "nt")
        self.assertIsNone(self.window.probe.pid)
        self.assertIn("x64", self.window.file_description.text())
        self.window._set_language("RU")
        self.assertIn("EXE", self.window.file_description.text())

    def test_dll_inspection_never_allows_process_attach_or_launch(self):
        path = fake_pe(Path(self.tmp.name) / "example.dll")
        self._select(path)
        self.assertFalse(self.window.find_file_process_button.isEnabled())
        self.assertFalse(self.window.launch_exe_button.isEnabled())
        self.assertIsNone(self.window.probe.pid)

    def test_matching_running_executable_attaches_exact_pid(self):
        path = fake_pe(Path(self.tmp.name) / "running.exe")
        self._select(path)
        fake = SimpleNamespace(exe=lambda: str(path))
        with patch("blackbox_universal.window.find_running_executable",
                   return_value=[(101, "running.exe")]), \
             patch("blackbox_universal.window.psutil.Process", return_value=fake), \
             patch.object(self.window, "_attach_pid") as attach:
            self.window._attach_file_target()
            attach.assert_called_once_with(101)

    @unittest.skipUnless(os.name == "nt", "EXE launch is Windows-specific")
    def test_launch_requires_confirmation_and_never_uses_shell(self):
        path = fake_pe(Path(self.tmp.name) / "approved.exe")
        self._select(path)
        with patch.object(QMessageBox, "question",
                          return_value=QMessageBox.StandardButton.No), \
             patch("blackbox_universal.window.subprocess.Popen") as launched:
            self.window._launch_file_target()
            launched.assert_not_called()
        with patch.object(QMessageBox, "question",
                          return_value=QMessageBox.StandardButton.Yes), \
             patch("blackbox_universal.window.subprocess.Popen",
                   return_value=SimpleNamespace(pid=710)) as launched, \
             patch.object(self.window, "_attach_pid") as attached:
            self.window._launch_file_target()
            launched.assert_called_once_with(
                [str(path)], cwd=str(path.parent), close_fds=True)
            attached.assert_called_once_with(710)

    @unittest.skipUnless(os.name == "nt", "EXE launch is Windows-specific")
    def test_changed_file_is_rejected_before_launch(self):
        path = fake_pe(Path(self.tmp.name) / "changed.exe")
        self._select(path)
        with path.open("ab") as f:
            f.write(b"changed since selection")
        with patch.object(QMessageBox, "question",
                          return_value=QMessageBox.StandardButton.Yes), \
             patch.object(QMessageBox, "warning", return_value=None), \
             patch("blackbox_universal.window.subprocess.Popen") as launched:
            self.window._launch_file_target()
            launched.assert_not_called()

    def test_absent_process_does_not_start_selected_exe(self):
        path = fake_pe(Path(self.tmp.name) / "stopped.exe")
        self._select(path)
        with patch("blackbox_universal.window.find_running_executable",
                   return_value=[]), \
             patch("blackbox_universal.window.subprocess.Popen") as launched, \
             patch.object(QMessageBox, "information", return_value=None):
            self.window._attach_file_target()
            launched.assert_not_called()
            self.assertIsNone(self.window.probe.pid)


if __name__ == "__main__":
    unittest.main()
