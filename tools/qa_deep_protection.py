"""Read-only hosted Windows protected-process availability evidence.

Only process identity/protection metadata and OpenProcess access checks are
requested. No target memory bytes, dump, debug attach, thread operation, service
change, policy change or protection bypass is performed.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
import time

from tools.qa_deep_inspection import require, require_hosted_windows

LEVELS = {0: "WINTCB_LIGHT", 1: "WINDOWS", 2: "WINDOWS_LIGHT", 3: "ANTIMALWARE_LIGHT",
          4: "LSA_LIGHT", 5: "WINTCB", 6: "CODEGEN_LIGHT", 7: "AUTHENTICODE", 8: "PPL_APP"}


def classify_protection_observation(level, result):
    require(type(level) is int and level in LEVELS, "ACTUAL_OS_PROTECTION_METADATA_REQUIRED")
    require(result.get("source") == "WIN32_ACCESS_PROBE", "REAL_WINDOWS_RIGHTS_PROBE_REQUIRED")
    if result.get("status") == "PROCESS_CHANGED":
        return "PROCESS_CHANGED_DURING_READ_ONLY_PROBE"
    if ("protection_level" not in result and result.get("status") in ("ACCESS_DENIED", "OPERATION_FAILED")
            and type(result.get("winerror")) is int and result["winerror"] > 0 and result.get("reason")):
        return "PROTECTION_METADATA_SEEN_BUT_PRODUCT_IDENTITY_PROBE_INCOMPLETE"
    require(result.get("protection_level") == level and result.get("process_access_mask") == 0x410,
            "PROTECTED_PROCESS_METADATA_OR_ACCESS_MASK_CHANGED")
    if result.get("status") == "PROTECTED_PROCESS":
        require(result.get("winerror") == 5, "PROTECTION_DENIAL_REQUIRES_ACTUAL_ACCESS_DENIED_ERROR")
        return "PROTECTED_DENIAL_OBSERVED"
    require(result.get("status") == "AVAILABLE", "ACTUAL_PROTECTED_ACCESS_STATUS_NOT_PRESERVED")
    return "PROTECTION_PRESENT_REQUESTED_RIGHTS_AVAILABLE"


def probe_protected_processes(*, seconds=5):
    require_hosted_windows()
    import psutil
    from blackbox_core.deep_contracts import ProcessIdentity
    from blackbox_core.deep_native import probe_access

    kernel = C.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    kernel.OpenProcess.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    kernel.CloseHandle.restype = W.BOOL
    kernel.GetProcessInformation.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD]
    kernel.GetProcessInformation.restype = W.BOOL
    kernel.GetProcessTimes.argtypes = [W.HANDLE] + [C.POINTER(W.FILETIME)] * 4
    kernel.GetProcessTimes.restype = W.BOOL
    kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
    kernel.WaitForSingleObject.restype = W.DWORD
    report = {"status": "NOT_AVAILABLE_WITH_OBSERVED_REASONS", "examined_processes": 0,
              "protection_metadata_observed": 0, "observed_reasons": {}, "protected_candidates": [],
              "scope": "READ_ONLY_PROTECTION_METADATA_AND_ACCESS_HANDLE_CHECK_NO_MEMORY_BYTES",
              "protected_denial_exercised": False, "security_policy_changed": False,
              "protective_mechanisms_bypassed": False}

    def reason(name, error=None):
        key = name + ("_WINERROR_" + str(error) if error is not None else "")
        report["observed_reasons"][key] = report["observed_reasons"].get(key, 0) + 1

    deadline = time.monotonic() + min(10, max(1, seconds))
    for pid in sorted(psutil.pids())[:4096]:
        if time.monotonic() >= deadline:
            reason("BOUNDED_ENUMERATION_DEADLINE")
            break
        if pid <= 0:
            continue
        report["examined_processes"] += 1
        handle = kernel.OpenProcess(0x1000 | 0x100000, False, pid)
        if not handle:
            reason("OPEN_QUERY_IDENTITY_DENIED_OR_UNAVAILABLE", C.get_last_error())
            continue
        try:
            level = W.DWORD()
            if not kernel.GetProcessInformation(handle, 7, C.byref(level), C.sizeof(level)):
                reason("PROTECTION_METADATA_UNAVAILABLE", C.get_last_error())
                continue
            report["protection_metadata_observed"] += 1
            if level.value not in LEVELS:
                reason("NO_RECOGNIZED_PROTECTED_LEVEL_" + str(level.value))
                continue
            times = [W.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *(C.byref(value) for value in times)):
                reason("PROTECTED_PROCESS_CREATION_TIME_UNAVAILABLE", C.get_last_error())
                continue
            if kernel.WaitForSingleObject(handle, 0) != 258:
                reason("PROTECTED_PROCESS_EXITED_BEFORE_ACCESS_CHECK")
                continue
            created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            # Retain this handle through the API probe, binding observations to
            # the original process object instead of accepting a recycled PID.
            result = probe_access(ProcessIdentity(pid, created), "memory_read")
            if kernel.WaitForSingleObject(handle, 0) != 258:
                reason("PROTECTED_PROCESS_EXITED_DURING_ACCESS_CHECK")
                continue
            observed = classify_protection_observation(level.value, result)
            candidate = {"pid": pid, "created_100ns": created, "protection_level": level.value,
                         "protection_name": LEVELS[level.value], "observation": observed,
                         "operation": "ACCESS_MASK_CHECK_ONLY_NOT_MEMORY_READ",
                         "status": result.get("status"), "winerror": result.get("winerror"),
                         "reason": result.get("reason"), "process_access_mask": result.get("process_access_mask")}
            report["protected_candidates"].append(candidate)
            if observed == "PROTECTED_DENIAL_OBSERVED":
                report.update(status="PASS", protected_denial_exercised=True)
                break
            reason(observed)
            if len(report["protected_candidates"]) >= 16:
                reason("BOUNDED_PROTECTED_CANDIDATE_LIMIT")
                break
        finally:
            kernel.CloseHandle(handle)
    return report
