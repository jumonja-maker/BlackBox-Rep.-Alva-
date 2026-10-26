"""Real Windows portable v0.4.0 -> next build -> uninstall acceptance probe.

Only runs on disposable GitHub-hosted Windows runners. Never operates on the
user's machine or any preexisting installation. Source and old official
release SHA-256 must both be verified before moving a single app file.
No release is published by this probe.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

import psutil
import winreg

from blackbox_universal.maintenance import _safe_install, _user_data_root, prepare_external_helper
from blackbox_universal.releases import (
    EXECUTABLE_NAME, MAINTENANCE_NAME, Release, stage_release,
    check_latest_release, version_tuple,
)
from blackbox_universal.shortcuts import create_shortcut, remove_shortcut_if_matches, _desktop, SHORTCUT_TITLE

# Immutable v0.4.0 official GitHub release. Refuse a changed/republished asset.
OLD_RELEASE = Release(
    "v0.4.0",
    "https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/releases/"
    "download/v0.4.0/BLACK.BOX-Universal-Windows.zip",
    62468600,
    "01d5161abe76b74314cb7709925b36221da4916a16b2e9e3da8a37c28f72c813",
    "https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/releases/tag/v0.4.0",
)


class QaFailure(RuntimeError):
    pass


def require(predicate, reason):
    if not predicate:
        raise QaFailure(reason)


def sha256(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as fd:
        for chunk in iter(lambda: fd.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_exe(command, *, cwd, env, timeout=120):
    child = subprocess.Popen(command, cwd=cwd, env=env,
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    try:
        code = child.wait(timeout=timeout)
        require(code == 0, "EXE_EXIT_NOT_ZERO_" + str(code))
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)


def _maintenance(exe, action, install, env, *, staged=None, wait_pid=0,
                 timeout=150):
    command = [str(exe), action, "--install", str(install),
               "--wait-pid", str(wait_pid)]
    if staged is not None:
        command.extend(["--staged", str(staged)])
    proc = subprocess.Popen(command, cwd=str(exe.parent), env=env,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    return proc


def _matching_live_app(exe_path: Path):
    result = []
    target = os.path.normcase(os.path.abspath(exe_path))
    for item in psutil.process_iter(["pid", "exe"]):
        try:
            if os.path.normcase(os.path.abspath(item.info.get("exe") or "")) == target:
                result.append(item)
        except (OSError, psutil.Error):
            pass
    return result


def _terminate_apps(exe_path: Path):
    for proc in _matching_live_app(exe_path):
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


def acceptance(built_zip: Path, source_sha: str, evidence: Path):
    require(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_TEMP"),
            "DISPOSABLE_GITHUB_WINDOWS_RUNNER_REQUIRED")
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    evidence = evidence.resolve()
    require(not evidence.is_symlink() and not evidence.exists(),
            "EVIDENCE_MUST_NOT_EXIST")
    evidence.mkdir(parents=True)
    built_zip = built_zip.resolve(strict=True)
    require(built_zip.is_file(), "CANDIDATE_ARCHIVE_MISSING")
    require(len(source_sha) == 40 and all(c in "0123456789abcdef" for c in source_sha),
            "QA_SOURCE_SHA_INVALID")
    report = {
        "result": "RUNNING", "source_sha": source_sha,
        "old_version": "v0.4.0", "new_version": "v0.4.1",
        "candidate_sha256": sha256(built_zip),
        "profile": "GITHUB_HOSTED_WINDOWS_ISOLATED_PORTABLE",
        "real_official_old_release_digest_pinned": True,
        "real_new_release_discovery": False,
        "real_physical_windows_installed_acceptance": False,
        "files_and_data_outside_owned_QA_root_deleted": False,
        "steps": [],
    }
    exe_root = None
    desktop_link = None
    new_helper_scratch = None
    try:
        from blackbox_universal import __version__
        require(__version__ == "0.4.1", "CANDIDATE_VERSION_NOT_BUMPED")
        require(version_tuple("v0.4.1") > version_tuple("v0.4.0"),
                "CANDIDATE_NOT_NEWER_THAN_INSTALLED")
        with tempfile.TemporaryDirectory(prefix="bb-native-maint-", dir=str(runner)) as tmp:
            root = Path(tmp)
            install = root / "BLACK.BOX-Universal"
            exe_root = install / EXECUTABLE_NAME
            profile = root / "qa-profile"
            profile.mkdir()
            env = os.environ.copy()
            env["USERPROFILE"] = str(profile)
            env["APPDATA"] = str(profile / "AppData" / "Roaming")
            env["LOCALAPPDATA"] = str(profile / "AppData" / "Local")
            env["QT_QPA_PLATFORM"] = "offscreen"
            env["PYTHONUTF8"] = "1"
            (profile / "AppData" / "Roaming").mkdir(parents=True)
            (profile / "AppData" / "Local").mkdir(parents=True)
            data = profile / "Documents" / "BLACK.BOX Universal"
            data.mkdir(parents=True)
            require(_user_data_root().name == "BLACK.BOX Universal",
                    "INVALID_DATA_DESTINATION_CONVENTION")
            user_sentinel = data / "own-session.txt"
            user_sentinel.write_bytes(b"Important saved user session; do not remove")
            user_digest = sha256(user_sentinel)
            adjacent = root / "DO-NOT-TOUCH-SIBLING.txt"
            adjacent.write_bytes(b"Foreign file owned by QA, never change")
            foreign_digest = sha256(adjacent)

            # Real published archive: official URL, pinned size, SHA-256,
            # full production ZIP extractor; no mock or invented old install.
            old_stage = stage_release(OLD_RELEASE, install)
            require(_safe_install(old_stage) == old_stage,
                    "OLD_STAGED_INSTALL_INVALID")
            old_stage.replace(install)
            old_stage.parent.rmdir()
            old_exe_hash = sha256(exe_root)
            report["old_exe_sha256"] = old_exe_hash
            report["steps"].append("OLD_OFFICIAL_RELEASE_DOWNLOAD_VERIFIED_AND_INSTALLED")
            _run_exe([str(exe_root), "--smoke"], cwd=str(install), env=env)
            report["steps"].append("REAL_OLD_FROZEN_EXE_SMOKE_PASS")

            # Original user evidence lives inside the old portable folder.
            for name in ("logs", "sessions", "reports"):
                d = install / name
                d.mkdir()
                (d / "keep.txt").write_bytes(("retain-"+name).encode())
            (install / "obsolete-application-file.bin").write_bytes(b"old_only")

            # Stage THE SAME candidate ZIP that Windows CI would publish.
            # Offline _open substitution does not imply a published v0.4.1
            # release; the public GitHub metadata/asset does not exist yet.
            new_release = Release("v0.4.1", "qa://verified-candidate",
                                  built_zip.stat().st_size,
                                  report["candidate_sha256"],
                                  "qa://unpublished-candidate")
            with patch("blackbox_universal.releases._open",
                       side_effect=lambda url: built_zip.open("rb")
                       if url == new_release.asset_url else
                       (_ for _ in ()).throw(QaFailure("QA_UNEXPECTED_ASSET_URL"))):
                staged = stage_release(new_release, install)
            require(_safe_install(staged) == staged, "CANDIDATE_STAGE_INVALID")
            new_exe_hash = sha256(staged / EXECUTABLE_NAME)
            require(new_exe_hash != old_exe_hash, "OLD_AND_NEW_BINARY_IDENTICAL")
            build_manifest = staged / "_internal" / "blackbox-build.json"
            require(build_manifest.is_file(), "FROZEN_SOURCE_MANIFEST_MISSING")
            manifest = json.loads(build_manifest.read_text("utf-8"))
            require(manifest.get("source_sha") == source_sha and
                    manifest.get("tracked_worktree_clean") is True,
                    "FROZEN_SOURCE_SHA_MISMATCH")
            report["steps"].append("CANDIDATE_OFFLINE_RELEASE_ZIP_DIGEST_AND_SOURCE_VERIFIED")

            # Real old executable runs during maintenance start; it closes
            # naturally, and the OLD frozen maintenance helper must wait.
            old_process = subprocess.Popen(
                [str(exe_root), "--smoke"], cwd=str(install), env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            old_maintenance = root / "outside-old-maintenance"
            old_maintenance.mkdir()
            shutil.copy2(install / MAINTENANCE_NAME,
                         old_maintenance / MAINTENANCE_NAME)
            maintenance = _maintenance(
                old_maintenance / MAINTENANCE_NAME, "update",
                install, env, staged=staged, wait_pid=old_process.pid)
            try:
                require(old_process.wait(timeout=120) == 0,
                        "OLD_APPLICATION_FAILED_TO_EXIT")
                require(maintenance.wait(timeout=180) == 0,
                        "OLD_MAINTENANCE_UPDATE_FAILED")
            finally:
                for proc in (old_process, maintenance):
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=15)
            require(_safe_install(install) == install,
                    "UPDATED_INSTALL_INVALID")
            require(sha256(exe_root) == new_exe_hash,
                    "CANDIDATE_NOT_INSTALLED")
            require(not (install / "obsolete-application-file.bin").exists(),
                    "OLD_APPLICATION_FILE_RETAINED")
            require(not list(root.glob(".blackbox-old-*")),
                    "OLD_BACKUP_NOT_REMOVED")
            require(not list(root.glob(".blackbox-stage-*")),
                    "STAGING_DIRECTORY_NOT_REMOVED")
            for name in ("logs", "sessions", "reports"):
                require((install / name / "keep.txt").read_bytes()
                        == ("retain-"+name).encode(),
                        "USER_EVIDENCE_LOST_ON_UPDATE")
            require(sha256(user_sentinel) == user_digest and
                    sha256(adjacent) == foreign_digest,
                    "NON_APP_FILES_CHANGED_ON_UPDATE")
            report["steps"].append("REAL_OLD_MAINTENANCE_REPLACED_AND_CLEANED_FILES")
            # apply_update normally relaunches the just-installed GUI.
            deadline = time.monotonic() + 35
            restarted = False
            while time.monotonic() < deadline:
                if _matching_live_app(exe_root):
                    restarted = True
                    break
                time.sleep(.25)
            report["new_gui_restarted_after_update"] = restarted
            require(restarted, "UPDATED_GUI_NOT_RESTARTED")
            _terminate_apps(exe_root)
            _run_exe([str(exe_root), "--smoke"], cwd=str(install), env=env)
            report["steps"].append("REAL_NEW_FROZEN_EXE_RESTART_AND_SMOKE_PASS")

            # Keep Shell's known Desktop folder in the SAME isolated
            # USERPROFILE used by the frozen maintenance child. Previously the
            # QA parent created a real-runner Desktop shortcut, but maintenance
            # ran with a fake profile lacking Desktop and failed SHGetFolderPathW.
            # Never create or remove a shortcut on the real runner's Desktop.
            qa_desktop = profile / "Desktop"
            qa_desktop.mkdir()
            with patch.dict(os.environ, {
                    "USERPROFILE": str(profile),
                    "APPDATA": str(profile / "AppData" / "Roaming"),
                    "LOCALAPPDATA": str(profile / "AppData" / "Local")}):
                actual_desktop = _desktop()
                require(actual_desktop.resolve(strict=True) ==
                        qa_desktop.resolve(strict=True),
                        "QA_DESKTOP_PROFILE_NOT_ISOLATED")
                desktop_link = actual_desktop / SHORTCUT_TITLE
                require(not desktop_link.exists(), "QA_DESKTOP_SHORTCUT_COLLISION")
                create_shortcut(exe_root)
                require(desktop_link.is_file(), "SHORTCUT_CREATION_FAILED")
            report["qa_desktop_profile_isolated"] = True
            # App-scoped QSettings marker: uninstall must remove this registry
            # subtree and must never modify unrelated HKCU keys.
            app_settings_key = r"Software\BlackBox\BLACK.BOX Universal"
            neighbor_key = r"Software\BlackBox\BLACKBOX_QA_FOREIGN_KEEP"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  app_settings_key) as settings:
                winreg.SetValueEx(settings, "bb_native_qa_marker", 0,
                                  winreg.REG_SZ, "must-be-removed")
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  neighbor_key) as neighbor:
                winreg.SetValueEx(neighbor, "bb_native_qa_foreign", 0,
                                  winreg.REG_SZ, "must-stay")

            new_helper = prepare_external_helper(install)
            new_helper_scratch = new_helper.parent
            require(new_helper_scratch.name.startswith("bb-maintenance-"),
                    "TEMP_HELPER_NOT_MARKED")
            before_uninstall = sha256(exe_root)
            require(before_uninstall == new_exe_hash,
                    "NEW_INSTALL_CHANGED_BEFORE_UNINSTALL")
            # Use the actual new frozen GUI as the PID the maintenance EXE
            # waits for; never remove a running application directory.
            running = subprocess.Popen(
                [str(exe_root), "--smoke"], cwd=str(install), env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            remover = _maintenance(
                new_helper, "uninstall", install,
                env, wait_pid=running.pid)
            try:
                require(running.wait(timeout=120) == 0, "NEW_GUI_EXIT_FAILED")
                remover_code = remover.wait(timeout=180)
                report["new_maintenance_exit_code"] = remover_code
                if remover_code != 0:
                    # Capture the real frozen maintenance error *before* the
                    # isolated TemporaryDirectory is destroyed. The log and
                    # every inspected path belong to this disposable QA run.
                    error_log = data / "maintenance-errors.log"
                    try:
                        recent_errors = error_log.read_text(
                            encoding="utf-8", errors="replace")[-4096:]
                    except OSError as error:
                        recent_errors = "UNAVAILABLE: " + type(error).__name__
                    report["uninstall_failure_context"] = {
                        "install_exists": install.exists(),
                        "desktop_shortcut_exists": desktop_link.exists(),
                        "user_data_root_exists": data.exists(),
                        "preserved_folder_count": len(list(data.glob("Preserved-*"))),
                        "maintenance_errors": recent_errors,
                        "helper_files": sorted(
                            p.name for p in new_helper_scratch.iterdir())
                        if new_helper_scratch.is_dir() else [],
                    }
                require(remover_code == 0,
                        "NEW_MAINTENANCE_UNINSTALL_FAILED")
            finally:
                for proc in (running, remover):
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=15)
            require(not install.exists() and not install.is_symlink(),
                    "APP_FOLDER_REMAINED_AFTER_UNINSTALL")
            require(not desktop_link.exists(), "APP_SHORTCUT_REMAINED")
            # Self-deletion is asynchronous: the external script waits for
            # the frozen maintenance EXE to finish and releases its own files.
            deadline = time.monotonic() + 45
            while new_helper_scratch.exists() and time.monotonic() < deadline:
                time.sleep(.25)
            require(not new_helper_scratch.exists(),
                    "TEMP_MAINTENANCE_HELPER_REMAINED")
            report["temporary_maintenance_helper_removed"] = True
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                    app_settings_key):
                    raise QaFailure("OWN_QSETTINGS_REMAINED")
            except FileNotFoundError:
                pass
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                neighbor_key) as foreign_settings:
                value, _ = winreg.QueryValueEx(foreign_settings,
                                               "bb_native_qa_foreign")
                require(value == "must-stay", "FOREIGN_QSETTINGS_CHANGED")
            report["owned_qsettings_removed"] = True
            require(sha256(user_sentinel) == user_digest,
                    "USER_SESSIONS_OUTSIDE_INSTALL_REMOVED")
            require(sha256(adjacent) == foreign_digest,
                    "FOREIGN_SIBLING_REMOVED")
            require(not list(root.glob(".blackbox-old-*")) and
                    not list(root.glob(".blackbox-stage-*")),
                    "RELEASE_STAGING_OR_BACKUP_REMAINED")
            preserved = list(data.glob("Preserved-*"))
            require(len(preserved) == 1 and preserved[0].is_dir(),
                    "PRESERVED_SESSION_FOLDER_MISSING")
            for name in ("logs", "sessions", "reports"):
                require((preserved[0] / name / "keep.txt").read_bytes()
                        == ("retain-"+name).encode(),
                        "ON_UNINSTALL_USER_EVIDENCE_MISSING")
            report["steps"].append("REAL_NEW_UNINSTALL_REMOVED_APP_AND_SHORTCUT")
            report["steps"].append("USER_DATA_AND_FOREIGN_FILES_PRESERVED")
            report["old_vs_new_exe_different"] = True
            report["new_exe_sha256"] = new_exe_hash
            report["uninstall_install_directory_gone"] = True
            report["shortcut_removed"] = True
            report["all_three_evidence_dirs_preserved"] = True
            report["user_document_session_preserved"] = True
            report["result"] = "PASS"
    except BaseException as exc:
        report["result"] = "FAIL"
        report["error"] = type(exc).__name__ + ": " + str(exc)[:400]
        raise
    finally:
        if exe_root is not None and os.name == "nt":
            try:
                _terminate_apps(exe_root)
            except (OSError, psutil.Error):
                pass
        # Only remove a link that points to this precisely QA-owned EXE.
        if desktop_link is not None and desktop_link.is_file() and exe_root:
            try:
                remove_shortcut_if_matches(exe_root)
            except (OSError, subprocess.SubprocessError):
                pass
        # The marker is owned by this disposable QA run, not BLACK.BOX.
        if os.name == "nt":
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\BlackBox\BLACKBOX_QA_FOREIGN_KEEP")
            except FileNotFoundError:
                pass
        if new_helper_scratch is not None and new_helper_scratch.exists():
            # Leave diagnostic evidence but do not leak this QA-owned helper
            # outside the isolated disposable runner's temporary space.
            report["helper_residue"] = sorted(p.name for p in
                                              new_helper_scratch.iterdir())
            shutil.rmtree(new_helper_scratch, ignore_errors=True)
        (evidence / "maintenance-native-result.json").write_text(
            json.dumps(report, ensure_ascii=True, indent=2) + "\n",
            encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--built-zip", type=Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    acceptance(args.built_zip, args.expected_sha, args.evidence)
    print("REAL_WINDOWS_PORTABLE_UPDATE_AND_UNINSTALL " +
          json.dumps({"result": "PASS", "source": args.expected_sha},
                     ensure_ascii=True), flush=True)


if __name__ == "__main__":
    main()
