"""Real medium-token child/grandchild IPC contract on hosted Windows only."""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import traceback
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from blackbox_core.optional_jobs import OwnedProcess
from blackbox_core.deep_ipc import IPCError, token_authority, token_is_elevated
from blackbox_core.windows_research import privilege
from tools.qa_decoder_standard_token import (
    current_medium_startup_diagnostics, restricted_child, restricted_interpreter,
    require_ephemeral_qa_default_dacl, token_default_dacl, token_integrity,
)

MARKER = b"BLACKBOX_MEDIUM_OWNED_PIPE_CONTRACT\n"
HOSTED_WINDOWS = (os.name == "nt" and C.sizeof(C.c_void_p) == 8 and
                  os.environ.get("GITHUB_ACTIONS") == "true" and
                  os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted")


class EffectiveTokenAuthorityContracts(unittest.TestCase):
    """Regression: a restricted administrator's elevation flag is not authority."""

    def observe(self, *, elevated=True, administrator=True, integrity=0x3000, fault=None):
        kernel, adv = Mock(), Mock()
        kernel.GetCurrentProcess.return_value = -1
        def open_token(process, rights, token):
            self.assertEqual((process, rights), (-1, 0xA))  # Query and duplicate, no adjustment.
            token._obj.value = 101
            return True
        adv.OpenProcessToken.side_effect = open_token
        def duplicate(token, level, output):
            self.assertEqual((token.value, level), (101, 1))
            output._obj.value = 202
            return True
        adv.DuplicateToken.side_effect = duplicate
        def membership(token, sid, output):
            self.assertEqual(token.value, 202)  # Explicit process-token duplicate.
            output._obj.value = administrator
            return fault != "membership_failure"
        adv.CheckTokenMembership.side_effect = membership
        def query(token, kind, output, capacity, needed):
            self.assertEqual(token.value, 101)
            if kind == 20:
                output._obj.value = elevated
                needed._obj.value = C.sizeof(W.DWORD)
                return True
            self.assertEqual(kind, 25)
            header = 2 * C.sizeof(C.c_void_p)
            needed._obj.value = 65537 if fault == "oversize_integrity" else header + 12
            if output is None:
                return False
            self.assertEqual(capacity, header + 12)
            start = C.addressof(output)
            C.c_void_p.from_buffer(output).value = start + (capacity if fault == "outside_sid" else header)
            authority = b"\0\0\0\0\0\x05" if fault == "wrong_authority" else b"\0\0\0\0\0\x10"
            raw = struct.pack("<BB6sI", 1, 1, authority, integrity)
            C.memmove(start + header, raw, len(raw))
            return True
        adv.GetTokenInformation.side_effect = query
        try:
            with patch("blackbox_core.deep_ipc.os.name", "nt"), \
                    patch("blackbox_core.deep_ipc._kernel", return_value=kernel), \
                    patch("blackbox_core.deep_ipc.C.WinDLL", return_value=adv, create=True), \
                    patch("blackbox_core.deep_ipc.C.get_last_error", return_value=5, create=True):
                return token_authority()
        finally:
            self.assertEqual([call.args[0].value for call in kernel.CloseHandle.call_args_list], [202, 101])

    def test_elevation_flag_deny_only_admin_and_medium_integrity_never_grant_authority(self):
        restricted = self.observe(elevated=True, administrator=False, integrity=0x2000)
        self.assertTrue(restricted["elevation_flag"])
        self.assertFalse(restricted["enabled_administrators"])
        self.assertEqual(restricted["integrity_sid"], "S-1-16-8192")
        self.assertFalse(restricted["elevated"])
        self.assertFalse(self.observe(administrator=False)["elevated"])
        self.assertFalse(self.observe(integrity=0x2000)["elevated"])
        self.assertFalse(self.observe(elevated=False)["elevated"])
        self.assertTrue(self.observe()["elevated"])

    def test_failed_membership_and_invalid_integrity_evidence_are_errors_not_grants(self):
        for fault in ("membership_failure", "oversize_integrity", "outside_sid", "wrong_authority"):
            with self.subTest(fault=fault), self.assertRaises(IPCError):
                self.observe(fault=fault)


class QaDefaultDaclPolicyContracts(unittest.TestCase):
    """Pure policy checks, separate from the actual Windows token evidence."""
    user = "S-1-5-21-1-2-3-500"

    def observed(self):
        return {"status": "OBSERVED", "null_dacl": False,
                "sddl_dacl": "D:(A;;GA;;;SY)(A;;GA;;;LA)",
                "aces": [{"type": 0, "flags": 0, "mask": 0x10000000, "sid": "S-1-5-18"},
                         {"type": 0, "flags": 0, "mask": 0x10000000, "sid": self.user}]}

    def test_full_sid_and_exact_rights_accept_alias_text_and_equivalent_allow_order(self):
        observed = self.observed()
        require_ephemeral_qa_default_dacl(observed, self.user)
        observed["aces"].reverse()
        observed["sddl_dacl"] = f"D:(A;;GA;;;{self.user})(A;;GA;;;SY)"
        require_ephemeral_qa_default_dacl(observed, self.user)

    def test_extra_denied_inherited_wrong_identity_and_wrong_rights_never_match(self):
        mutations = {
            "null": lambda value: value.update(null_dacl=True),
            "missing": lambda value: value["aces"].pop(),
            "extra": lambda value: value["aces"].append(dict(value["aces"][0])),
            "deny": lambda value: value["aces"][1].update(type=1),
            "inherit_only": lambda value: value["aces"][1].update(flags=8),
            "inherited": lambda value: value["aces"][1].update(flags=16),
            "read_only": lambda value: value["aces"][1].update(mask=0x80000000),
            "extra_rights": lambda value: value["aces"][1].update(mask=0x10000001),
            "everyone": lambda value: value["aces"][1].update(sid="S-1-1-0"),
            "duplicate_system": lambda value: value["aces"][1].update(sid="S-1-5-18"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                observed = self.observed()
                mutate(observed)
                with self.assertRaisesRegex(AssertionError, "QA_TOKEN_DEFAULT_DACL_READBACK_MISMATCH"):
                    require_ephemeral_qa_default_dacl(observed, self.user)


def _grandchild():
    if not HOSTED_WINDOWS:
        return 2
    # pythonw has no Python console streams. Use only the real redirected
    # process HANDLEs supplied by subprocess, exactly as a native helper does.
    kernel = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    kernel.GetStdHandle.argtypes, kernel.GetStdHandle.restype = [W.DWORD], W.HANDLE
    kernel.ReadFile.argtypes = [W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p]
    kernel.ReadFile.restype = W.BOOL
    kernel.WriteFile.argtypes = [W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p]
    kernel.WriteFile.restype = W.BOOL
    buffer, read = C.create_string_buffer(128), W.DWORD()
    if not kernel.ReadFile(kernel.GetStdHandle(0xFFFFFFF6), buffer, len(buffer), C.byref(read), None):
        raise C.WinError(C.get_last_error())
    value = {"pid": os.getpid(), "privilege": privilege(), "integrity": token_integrity(),
             "helper_token_authority": token_authority(), "helper_is_elevated": token_is_elevated(),
             "default_dacl": token_default_dacl(), "received_expected_marker": buffer.raw[:read.value] == MARKER}
    encoded = json.dumps(value, ensure_ascii=True).encode("ascii") + b"\n"
    output, written = C.create_string_buffer(encoded), W.DWORD()
    if (not kernel.WriteFile(kernel.GetStdHandle(0xFFFFFFF5), output, len(encoded), C.byref(written), None)
            or written.value != len(encoded)):
        raise C.WinError(C.get_last_error())
    return 0


def _worker(destination):
    if not HOSTED_WINDOWS:
        return 2
    proof = {"status": "RUNNING", "pid": os.getpid(), "privilege": privilege(),
             "helper_token_authority": token_authority(), "helper_is_elevated": token_is_elevated(),
             "integrity": token_integrity(), "default_dacl": token_default_dacl()}
    owner = None
    try:
        proof["startup"] = current_medium_startup_diagnostics()
        owner = OwnedProcess([sys.executable, str(Path(__file__).resolve()), "--medium-grandchild"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             detach_console=True)
        stdout, stderr = owner.process.communicate(MARKER, timeout=20)
        if owner.process.returncode or len(stdout) > 65536:
            raise AssertionError("MEDIUM_GRANDCHILD_FAILED: " + str(owner.process.returncode) + ": " +
                                 stderr.decode("utf-8", "replace")[:1000])
        proof["grandchild"] = json.loads(stdout)
        proof["owned_process"] = {"pid": owner.process.pid, "exit_code": owner.process.returncode,
                                  "windows_creation_flags": owner.windows_creation_flags,
                                  "redirected_stdin_stdout": True}
        proof["status"] = "COMPLETED"
    except BaseException as error:
        proof.update(status="FAILED", error=type(error).__name__, reason=str(error),
                     traceback=traceback.format_exc()[-12000:])
    finally:
        cleanup_errors = []
        if owner is not None:
            try:
                owner.close(kill=True)
            except Exception as error:
                cleanup_errors.append({"resource": "owned_process", "reason": str(error)[:1000]})
            for stream in (owner.process.stdin, owner.process.stdout, owner.process.stderr):
                if stream is not None and not stream.closed:
                    try:
                        stream.close()
                    except Exception as error:
                        cleanup_errors.append({"resource": "redirected_stream", "reason": str(error)[:1000]})
        proof["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            proof["status"] = "FAILED"
        Path(destination).write_text(json.dumps(proof, indent=2), encoding="utf-8")
    return 0 if proof["status"] == "COMPLETED" else 1


@unittest.skipUnless(HOSTED_WINDOWS, "Actual token/pipe contract requires a GitHub-hosted Windows x64 runner")
class DeepMediumTokenNativeContract(unittest.TestCase):
    def test_default_retains_existing_token_defaults_without_relabeling_old_decoder_qa(self):
        # Existing decoder QA deliberately retains its original IL. This
        # independent child proof uses no PIPE or grandchild, as before.
        parent_before = {"integrity": token_integrity(), "default_dacl": token_default_dacl()}
        with tempfile.TemporaryDirectory(prefix="deep default token ") as temporary:
            destination = Path(temporary) / "worker token.json"
            script = (
                "import json,os,sys; from pathlib import Path; "
                "from tools.qa_decoder_standard_token import token_integrity,token_default_dacl; "
                "from blackbox_core.windows_research import privilege; "
                "from blackbox_core.deep_ipc import token_authority,token_is_elevated; "
                "Path(sys.argv[1]).write_text(json.dumps({'pid':os.getpid(),"
                "'integrity':token_integrity(),'default_dacl':token_default_dacl(),"
                "'helper_token_authority':token_authority(),'helper_is_elevated':token_is_elevated(),"
                "'privilege':privilege()}),encoding='utf-8')"
            )
            child = restricted_child([restricted_interpreter(sys.executable), "-c", script, destination],
                                     cwd=ROOT, timeout_seconds=30)
            self.assertEqual(child["exit_code"], 0, str(child))
            self.assertTrue(destination.is_file(), "Restricted child must write its own token evidence")
            worker = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(worker["pid"], child["pid"])
        self.assertEqual(worker["privilege"], {"mode": "STANDARD", "windows": True})
        self.assertFalse(worker["helper_is_elevated"], str(worker))
        self.assertFalse(worker["helper_token_authority"]["enabled_administrators"], str(worker))
        self.assertEqual(worker["integrity"], parent_before["integrity"])
        self.assertEqual(worker["default_dacl"], parent_before["default_dacl"])
        self.assertTrue(child["job_assigned_before_resume"])
        self.assertNotIn("medium_integrity_requested", child)
        self.assertNotIn("qa_default_dacl_adjustment", child)
        self.assertEqual(parent_before, {"integrity": token_integrity(), "default_dacl": token_default_dacl()})

    def test_medium_token_owns_pipes_and_grandchild_without_changing_parent(self):
        parent_before = {"integrity": token_integrity(), "default_dacl": token_default_dacl()}
        with tempfile.TemporaryDirectory(prefix="blackbox-medium-native-") as temporary:
            destination = Path(temporary) / "worker-proof.json"
            child = restricted_child([restricted_interpreter(sys.executable), str(Path(__file__).resolve()),
                                      "--medium-worker", str(destination)],
                                     cwd=ROOT, timeout_seconds=60, medium_integrity=True)
            self.assertTrue(destination.is_file(), str(child))
            proof = json.loads(destination.read_text(encoding="utf-8"))
        details = json.dumps({"launcher": child, "worker": proof}, ensure_ascii=True)
        self.assertEqual(child["exit_code"], 0, details)
        self.assertEqual(proof["status"], "COMPLETED", details)
        self.assertFalse(proof["cleanup_errors"], details)
        self.assertEqual(proof["pid"], child["pid"])
        for process in (proof, proof["grandchild"]):
            self.assertEqual(process["privilege"], {"mode": "STANDARD", "windows": True}, details)
            self.assertEqual(process["integrity"]["sid"], "S-1-16-8192", details)
            authority = process["helper_token_authority"]
            self.assertEqual(authority["source"], "WINDOWS_PROCESS_TOKEN", details)
            self.assertEqual(authority["integrity_sid"], process["integrity"]["sid"], details)
            self.assertFalse(authority["enabled_administrators"], details)
            self.assertFalse(authority["elevated"], details)
            self.assertFalse(process["helper_is_elevated"], details)
        self.assertEqual(proof["integrity"], child["token_integrity"])
        self.assertEqual(proof["integrity"], child["child_token_integrity"])
        self.assertTrue(child["job_assigned_before_resume"])
        self.assertEqual(child["interactive_uac_secure_desktop"], "NOT_TESTED")
        self.assertNotEqual(proof["grandchild"]["pid"], proof["pid"])
        self.assertEqual(proof["grandchild"]["pid"], proof["owned_process"]["pid"])
        self.assertEqual(proof["owned_process"]["windows_creation_flags"], 0x8)
        self.assertTrue(proof["grandchild"]["received_expected_marker"], details)
        self.assertEqual(proof["startup"]["stages"]["create_pipe_default_security"]["status"], "SUCCEEDED", details)
        self.assertEqual(proof["startup"]["stages"]["duplicate_owned_temporary_file"]["status"], "SUCCEEDED", details)
        self.assertFalse(proof["startup"]["cleanup_errors"], details)
        adjustment = child["qa_default_dacl_adjustment"]
        require_ephemeral_qa_default_dacl(adjustment["after"], adjustment["token_user_sid"])
        require_ephemeral_qa_default_dacl(proof["default_dacl"], adjustment["token_user_sid"])
        require_ephemeral_qa_default_dacl(proof["grandchild"]["default_dacl"], adjustment["token_user_sid"])
        self.assertEqual(adjustment["child_readback"], proof["default_dacl"])
        self.assertEqual(proof["grandchild"]["default_dacl"], proof["default_dacl"])
        self.assertFalse(adjustment["existing_object_or_file_acl_changes"])
        self.assertTrue(child["parent_token_unchanged"])
        self.assertEqual(child["parent_token_before"], child["parent_token_after"])
        self.assertEqual(parent_before, {"integrity": token_integrity(), "default_dacl": token_default_dacl()})


if __name__ == "__main__":
    if sys.argv[1:2] == ["--medium-grandchild"]:
        raise SystemExit(_grandchild())
    if sys.argv[1:2] == ["--medium-worker"] and len(sys.argv) == 3:
        raise SystemExit(_worker(sys.argv[2]))
    unittest.main()
