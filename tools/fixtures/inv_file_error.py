"""Owned Windows file-error workload; raw SDK events are application statements.

The parent may copy this file changing only WORKLOAD_VERSION to produce two
different, hashable controlled application source builds. No version claim is
made about the Python interpreter or an unrelated third-party application.
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import sys
import time

WORKLOAD_VERSION = "A"
QA_TOKEN = "BLACKBOX_INV_QA_PUBLIC_FIXTURE_TOKEN"
PRIVATE_SENTINEL = "BLACKBOX_INV_QA_PRIVATE_SECRET_NEVER_EXPORT"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--error-code", type=int, choices=(2, 5), default=5)
    parser.add_argument("--operations", type=int, default=6)
    args = parser.parse_args()
    if (os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise RuntimeError("GITHUB_HOSTED_WINDOWS_REQUIRED")
    if not 2 <= args.operations <= 32:
        raise ValueError("BOUNDED_FIXTURE_OPERATION_COUNT_REQUIRED")
    from blackbox_core.instrumentation import EventWriter
    from blackbox_core.deep_native import capture_identity

    folder = args.output.resolve()
    folder.mkdir(parents=True, exist_ok=False)
    denied = folder / "controlled-denied.bin"
    permitted = folder / "controlled-permitted.bin"
    missing = folder / "controlled-missing.bin"
    denied.write_bytes(b"BLACKBOX_INV_CONTROLLED_FILE\n")
    permitted.write_bytes(b"BLACKBOX_INV_CONTROLLED_FILE\n")
    writer = EventWriter(folder / "application-events.jsonl", QA_TOKEN)
    kernel = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    adv = C.WinDLL("advapi32", use_last_error=True, winmode=0x800)
    kernel.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p,
                                   W.DWORD, W.DWORD, W.HANDLE]
    kernel.CreateFileW.restype = W.HANDLE
    kernel.CloseHandle.argtypes, kernel.CloseHandle.restype = [W.HANDLE], W.BOOL
    kernel.LocalFree.argtypes, kernel.LocalFree.restype = [C.c_void_p], C.c_void_p
    adv.GetFileSecurityW.argtypes = [W.LPCWSTR, W.DWORD, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)]
    adv.GetFileSecurityW.restype = W.BOOL
    adv.SetFileSecurityW.argtypes = [W.LPCWSTR, W.DWORD, C.c_void_p]
    adv.SetFileSecurityW.restype = W.BOOL
    adv.GetSecurityDescriptorControl.argtypes = [C.c_void_p, C.POINTER(W.WORD), C.POINTER(W.DWORD)]
    adv.GetSecurityDescriptorControl.restype = W.BOOL
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        W.LPCWSTR, W.DWORD, C.POINTER(C.c_void_p), C.c_void_p]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = W.BOOL
    adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        C.c_void_p, W.DWORD, W.DWORD, C.POINTER(C.c_void_p), C.POINTER(W.DWORD)]
    adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = W.BOOL

    def security():
        required = W.DWORD()
        adv.GetFileSecurityW(str(denied), 4, None, 0, C.byref(required))
        if not 20 <= required.value <= 65536:
            raise RuntimeError("OWNED_FILE_DACL_SIZE_INVALID")
        descriptor = C.create_string_buffer(required.value)
        if not adv.GetFileSecurityW(str(denied), 4, descriptor, len(descriptor), C.byref(required)):
            raise C.WinError(C.get_last_error())
        text, length = C.c_void_p(), W.DWORD()
        try:
            if not adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor, 1, 4, C.byref(text), C.byref(length)):
                raise C.WinError(C.get_last_error())
            value = C.wstring_at(text)
            if len(value) > 65536:
                raise RuntimeError("OWNED_FILE_DACL_TEXT_BUDGET")
            return descriptor, value
        finally:
            if text:
                kernel.LocalFree(text)

    original, original_sddl = security()
    original_control, descriptor_revision = W.WORD(), W.DWORD()
    if not adv.GetSecurityDescriptorControl(original, C.byref(original_control), C.byref(descriptor_revision)):
        raise C.WinError(C.get_last_error())
    replacement = C.c_void_p()
    changed = False
    proof = {"status": "RUNNING", "pid": os.getpid(), "target": capture_identity(os.getpid()).to_dict(),
             "application": {"application_id": "BLACKBOX_INV_QA_FILE_TOOL", "version": WORKLOAD_VERSION,
                 "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 "runtime_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
                 "version_scope": "CONTROLLED_APPLICATION_SOURCE_BUILD_NOT_INTERPRETER_VERSION"},
             "source_type": "APPLICATION_EVENT_UNAUTHENTICATED",
             "expected_error_code": args.error_code, "operations": [],
             "input_bytes": len(b"BLACKBOX_INV_CONTROLLED_FILE\n"),
             "file_acl_scope": "ONLY_QA_OWNED_CONTROLLED_FILE", "system_policy_changed": False}
    try:
        if args.error_code == 5:
            if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    "D:P(D;;GW;;;WD)(A;;GA;;;OW)(A;;GA;;;SY)", 1, C.byref(replacement), None):
                raise C.WinError(C.get_last_error())
            if not adv.SetFileSecurityW(str(denied), 4 | 0x80000000, replacement):
                raise C.WinError(C.get_last_error())
            changed = True
        # The parent's owned kernel capture is already recording when this
        # process starts. These are real operations, not fabricated ETW rows.
        for ordinal in range(1, args.operations + 1):
            for role, resource, expected in (("EXPECTED_ERROR", denied if args.error_code == 5 else missing,
                                               args.error_code), ("PERMITTED_CONTROL", permitted, 0)):
                operation_id = f"inv-qa-{os.getpid()}-{ordinal}-{role}"
                common = {"io_kind": "WRITE", "resource": resource.name,
                          "requested_access": 0x40000000, "workload_version": WORKLOAD_VERSION,
                          "process_created_100ns": proof["target"]["created_100ns"]}
                if not writer.emit("io.operation.begin", operation_id=operation_id, **common):
                    raise RuntimeError("ACTUAL_APPLICATION_BEGIN_NOT_WRITTEN")
                begin = time.perf_counter_ns()
                C.set_last_error(0)
                handle = kernel.CreateFileW(str(resource), 0x40000000, 7, None, 3, 0x80, None)
                error = C.get_last_error()
                invalid = handle is None or handle == C.c_void_p(-1).value
                if not invalid:
                    if not kernel.CloseHandle(handle):
                        raise C.WinError(C.get_last_error())
                    error = 0
                duration = time.perf_counter_ns() - begin
                if error != expected or invalid != bool(expected):
                    raise RuntimeError(f"ACTUAL_FILE_RESULT_DIFFERS_FROM_ORACLE_{role}_{error}")
                status = "ERROR" if invalid else "COMPLETED"
                if not writer.emit("io.operation.end", operation_id=operation_id, **common,
                                   status=status, error_code=error, winerror=error,
                                   latency_ns=duration, latency_clock="PYTHON_PERF_COUNTER_NS",
                                   semantics="APP_SUPPLIED_WALL_LATENCY_NOT_DEVICE_SERVICE_TIME",
                                   private_secret=PRIVATE_SENTINEL):
                    raise RuntimeError("ACTUAL_APPLICATION_END_NOT_WRITTEN")
                if invalid and not writer.emit("incident.file_error",
                        operation_id="incident-" + operation_id, parent_id=operation_id,
                        **common, status="ERROR", error_code=error, winerror=error,
                        incident_scope="APPLICATION_REPORTED_ACTUAL_CREATEFILE_FAILURE"):
                    raise RuntimeError("ACTUAL_APPLICATION_INCIDENT_NOT_WRITTEN")
                proof["operations"].append({"operation_id": operation_id, "role": role,
                    "expected_error_code": expected, "actual_winerror": error, "status": status,
                    "resource": resource.name, "latency_ns": duration})
                time.sleep(.025)
        proof["status"] = "PASS"
    except BaseException as error:
        proof.update(status="FAIL", error=type(error).__name__, reason=str(error)[:1200])
    finally:
        try:
            restore_flags = 4 | (0x80000000 if original_control.value & 0x1000 else 0x20000000)
            if changed and not adv.SetFileSecurityW(str(denied), restore_flags, original):
                raise C.WinError(C.get_last_error())
            _, restored = security()
            if restored != original_sddl:
                raise RuntimeError("OWNED_FILE_DACL_RESTORE_NOT_CONFIRMED")
            proof["owned_file_dacl_restored"] = True
        except BaseException as error:
            proof.update(status="FAIL", cleanup_error=type(error).__name__ + ": " + str(error)[:1200])
        if replacement:
            kernel.LocalFree(replacement)
        proof["input_file_bytes_unchanged"] = denied.read_bytes() == permitted.read_bytes() == b"BLACKBOX_INV_CONTROLLED_FILE\n"
        if proof["status"] == "PASS" and proof["input_file_bytes_unchanged"]:
            if not writer.emit("blackbox.completed", status="COMPLETED",
                               expected_operations=len(proof["operations"]),
                               scope="CONTROLLED_QA_APPLICATION_COMPLETED_AFTER_OWNED_ACL_RESTORE"):
                proof.update(status="FAIL", reason="APPLICATION_COMPLETION_EVENT_NOT_WRITTEN")
        proof["client_events_dropped"] = writer.dropped
        (folder / "fixture-result.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")
    print(json.dumps({"status": proof["status"], "pid": os.getpid(), "operations": len(proof["operations"])}), flush=True)
    return 0 if proof["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
