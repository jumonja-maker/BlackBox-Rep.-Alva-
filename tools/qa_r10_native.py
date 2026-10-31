"""Real R10 one-run​as, two-target acceptance on GitHub-hosted Windows.

Every successful native claim is checked against the compiled owned process's
separate control pipe.  Error injection changes only owned QA resources.  The
production broker, helper, token verification and native operations are used;
physical Secure Desktop consent is explicitly outside hosted acceptance.
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from tools.qa_deep_inspection import Probe, file_hash, require, require_hosted_windows, save
from blackbox_core.deep_contracts import ActionRequest, MAX_MEMORY_BYTES
from blackbox_core.deep_journal import journal_metadata
from blackbox_core.deep_service import InspectorService

SCOPE = ["capabilities", "modules", "threads", "handles", "memory_read", "memory_map",
         "thread_stacks", "snapshot", "memory.write", "memory.rollback",
         "thread.suspend", "thread.resume", "debug.attach", "debug.detach"]


def actual_token(pid: int) -> dict:
    """Independently query the actual process token held by Windows."""
    kernel = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    advapi = C.WinDLL("advapi32", use_last_error=True, winmode=0x800)
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    kernel.OpenProcess.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    kernel.CloseHandle.restype = W.BOOL
    advapi.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
    advapi.OpenProcessToken.restype = W.BOOL
    advapi.GetTokenInformation.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD,
                                          C.POINTER(W.DWORD)]
    advapi.GetTokenInformation.restype = W.BOOL
    process, token = kernel.OpenProcess(0x1000, False, pid), W.HANDLE()
    require(bool(process), "HELPER_TOKEN_PROCESS_HANDLE_REQUIRED")
    try:
        require(bool(advapi.OpenProcessToken(process, 8, C.byref(token))),
                "HELPER_ACTUAL_TOKEN_QUERY_REQUIRED")
        elevated, elevation_type, needed = W.DWORD(), W.DWORD(), W.DWORD()
        require(bool(advapi.GetTokenInformation(token, 20, C.byref(elevated),
                                               C.sizeof(elevated), C.byref(needed))),
                "HELPER_ACTUAL_TOKEN_ELEVATION_REQUIRED")
        require(bool(advapi.GetTokenInformation(token, 18, C.byref(elevation_type),
                                               C.sizeof(elevation_type), C.byref(needed))),
                "HELPER_ACTUAL_TOKEN_ELEVATION_TYPE_REQUIRED")
        return {"source": "INDEPENDENT_OPEN_PROCESS_TOKEN_GET_TOKEN_INFORMATION",
                "pid": pid, "elevated": elevated.value != 0,
                "elevation_type": elevation_type.value}
    finally:
        if token:
            kernel.CloseHandle(token)
        kernel.CloseHandle(process)


def controlled_external_write(identity, address: int, raw: bytes) -> None:
    """Simulate a concurrent writer to our own fixture, never another process."""
    from blackbox_core.deep_native import verify_identity
    verify_identity(identity)
    kernel = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    kernel.OpenProcess.restype = W.HANDLE
    kernel.WriteProcessMemory.argtypes = [W.HANDLE, C.c_void_p, C.c_void_p,
                                          C.c_size_t, C.POINTER(C.c_size_t)]
    kernel.WriteProcessMemory.restype = W.BOOL
    kernel.CloseHandle.argtypes = [W.HANDLE]
    kernel.CloseHandle.restype = W.BOOL
    process = kernel.OpenProcess(0x8 | 0x10 | 0x20 | 0x1000, False, identity.pid)
    require(bool(process), "CONTROLLED_EXTERNAL_WRITER_HANDLE_REQUIRED")
    try:
        verify_identity(identity)
        buffer, written = C.create_string_buffer(raw), C.c_size_t()
        require(bool(kernel.WriteProcessMemory(process, address, buffer, len(raw), C.byref(written)))
                and written.value == len(raw), "CONTROLLED_EXTERNAL_WRITE_FAILED")
    finally:
        kernel.CloseHandle(process)


class NativeAcceptance:
    def __init__(self, output: Path, probe_path: Path, source_sha: str, helper: Path | None):
        self.output, self.probe_path, self.source_sha, self.helper_path = output, probe_path, source_sha, helper
        self.events: list[dict] = []
        self.services: list[InspectorService] = []
        self.probes: list[Probe] = []
        self.expected_unconfirmed_services: set[int] = set()
        from blackbox_universal.provenance import source_identity
        identity = source_identity(source_sha)
        require(identity.get("source_identity_status") == "VERIFIED_EXPECTED_HEAD",
                "R10_NATIVE_ACTUAL_CHECKOUT_IDENTITY_MISMATCH")
        self.proof = {"schema": "blackbox.r10.native.v1", "status": "RUNNING",
                      "source_sha": source_sha, "probe_sha256": file_hash(probe_path),
                      "source_identity": identity,
                      "physical_interactive_uac": "NOT_TESTED",
                      "uac_coverage": "REAL_PRODUCTION_SHELLEXECUTEEXW_RUNAS_AND_ACTUAL_WINDOWS_TOKEN",
                      "denial_coverage": "CONTRACT_TESTS_SEPARATE_FROM_REAL_TOKEN_NATIVE_EVIDENCE",
                      "scenarios": {}, "events": self.events}

    def record(self, label: str, value: dict) -> dict:
        row = {"label": label, "result": journal_metadata(value)}
        self.events.append(row)
        save(self.output / "r10-native.json", self.proof)
        print("R10_NATIVE_EVENT " + json.dumps({"label": label,
              "operation": value.get("operation"), "status": value.get("status"),
              "error": str(value.get("error") or "")[:500],
              "helper_pid": value.get("helper_pid", value.get("data", {}).get("helper_pid"))},
              sort_keys=True), flush=True)
        return value

    def service(self, name: str) -> tuple[InspectorService, list[dict]]:
        service = InspectorService(self.output / name / "journal", helper_executable=self.helper_path)
        launches: list[dict] = []
        production_launch = service.broker.launch

        def observed_launch(arguments, *, elevated=False):
            # Measurement delegates to the unmodified production runas broker.
            process = production_launch(arguments, elevated=elevated)
            launches.append({"elevated": elevated, "pid": process.pid,
                             "identity": service.identity(process.pid).to_dict(),
                             "broker": "PRODUCTION_ELEVATION_BROKER",
                             "launch_api": "ShellExecuteExW/runas" if elevated else "CreateProcess"})
            return process

        service.broker.launch = observed_launch
        self.services.append(service)
        return service, launches

    def probe(self, label: str) -> Probe:
        probe = Probe(self.probe_path, self.output / ("target-" + label))
        self.probes.append(probe)
        return probe

    def action(self, service, target, name, parameters=None, *, confirmed=False,
               expected=("COMPLETED",), cancel=None, timeout=15):
        value = service.execute(ActionRequest(name, target, parameters or {}, confirmed=confirmed,
                                              timeout_seconds=timeout), cancel_event=cancel)
        self.record(name, value)
        require(value.get("status") in expected,
                "R10_UNEXPECTED_" + name + "_" + str(value.get("status")) + ":" +
                str(value.get("error") or "")[:700])
        require(bool(value.get("operation_id")), "R10_ACTION_OPERATION_ID_REQUIRED")
        receipt = value.get("run_receipt", {})
        require(receipt.get("contract_version") == 1 and receipt.get("status") == value.get("status")
                and receipt.get("operation") == name and receipt.get("run_id") == value.get("operation_id"),
                "R10_V1_RUN_RECEIPT_STATUS_AND_IDENTITY_REQUIRED")
        if value.get("status") in ("COMPLETED", "INCOMPLETE_EVIDENCE"):
            require(receipt.get("execution_started") is True and receipt.get("source", {}).get("verified") is True
                    and receipt.get("source", {}).get("helper_pid") == service.helper_pid
                    and receipt.get("target", {}).get("verified") is True
                    and receipt.get("target", {}).get("identity") == target.to_dict(),
                    "R10_REAL_HELPER_RUN_RECEIPT_EXECUTION_PROOF_REQUIRED")
        return value

    def heartbeat(self, service, identity, deadline, launches):
        status = service.session_status(refresh=True)
        require(status.get("state") == "ACTIVE" and status.get("elevated_verified") is True
                and status.get("admin_active") is True, "R10_HELPER_MUST_BE_VERIFIED_ACTIVE")
        require(status.get("helper_identity") == identity, "R10_HELPER_IDENTITY_CHANGED_WITHIN_LEASE")
        require(abs(status.get("session_deadline_monotonic", 0) - deadline) < .001,
                "R10_HELPER_LEASE_WAS_EXTENDED")
        require(len(launches) == 1 and launches[0]["elevated"] is True,
                "R10_SECOND_HELPER_OR_SECOND_RUNAS_IN_ACTIVE_LEASE")
        return status

    def run_primary(self, a: Probe, b: Probe) -> dict:
        service, launches = self.service("one-lease")
        ia, ib = service.identity(a.process.pid), service.identity(b.process.pid)
        require(ia.created_100ns == a.ready["created_100ns"] and ib.created_100ns == b.ready["created_100ns"]
                and ia.pid != ib.pid, "R10_TWO_EXACT_OWNED_PROCESS_IDENTITIES_REQUIRED")
        denied = self.record("unconfirmed-session", service.start_admin_session(confirmed=False))
        require(denied.get("status") == "CONFIRMATION_REQUIRED" and not launches,
                "R10_UNCONFIRMED_SESSION_LAUNCHED_HELPER")
        opened = self.record("start-before-target", service.start_admin_session(confirmed=True))
        require(opened.get("status") == "COMPLETED", "R10_PRODUCTION_RUNAS_START_FAILED")
        status = service.session_status(refresh=True)
        identity, deadline = status.get("helper_identity"), status.get("session_deadline_monotonic")
        require(isinstance(identity, dict) and identity.get("created_100ns", 0) > 0
                and identity.get("pid") != os.getpid() and status.get("target") is None,
                "R10_VERIFIED_SEPARATE_HELPER_BEFORE_TARGET_REQUIRED")
        token = actual_token(identity["pid"])
        require(token["elevated"] and status.get("helper_token_authority", {}).get("elevated") is True,
                "R10_ACTUAL_HELPER_ADMINISTRATOR_TOKEN_REQUIRED")
        duplicate = self.record("active-session-request-reuses-existing-helper", service.start_admin_session(confirmed=True))
        require(duplicate.get("status") == "COMPLETED" and duplicate.get("uac", {}).get("requested") is False,
                "R10_ACTIVE_SESSION_REQUEST_REQUESTED_SECOND_UAC")
        self.heartbeat(service, identity, deadline, launches)
        self.action(service, ia, "modules", expected=("CONFIRMATION_REQUIRED",))
        unbound = self.record("unconfirmed-target-A", service.bind_target(ia, SCOPE, confirmed=False))
        require(unbound.get("status") == "CONFIRMATION_REQUIRED", "R10_TARGET_CONSENT_REQUIRED")
        require(self.record("bind-A", service.bind_target(ia, SCOPE, confirmed=True)).get("status") == "COMPLETED",
                "R10_TARGET_A_BIND_FAILED")
        self.heartbeat(service, identity, deadline, launches)

        for probe, target, label in ((a, ia, "A"), (b, ib, "B")):
            if label == "B":
                refused = self.record("unconfirmed-target-B", service.bind_target(ib, SCOPE, confirmed=False))
                require(refused.get("status") == "CONFIRMATION_REQUIRED", "R10_B_INHERITED_A_CONSENT")
                require(service.session_status(refresh=True).get("target") == ia.to_dict(),
                        "R10_REFUSED_TARGET_SWITCH_CHANGED_SCOPE")
                self.action(service, ib, "memory_read", {"address": b.ready["buffer_address"], "length": 64},
                            expected=("CONFIRMATION_REQUIRED", "PROCESS_CHANGED"))
                require(self.record("bind-B", service.bind_target(ib, SCOPE, confirmed=True)).get("status") == "COMPLETED",
                        "R10_TARGET_B_BIND_FAILED")
                require(a.state()["buffer_hex"] == a.ready["buffer_hex"],
                        "R10_SWITCH_DID_NOT_RESTORE_A_MEMORY")
                a.progress(a.state())
            self.heartbeat(service, identity, deadline, launches)
            known, address = probe.ready["buffer_hex"], probe.ready["buffer_address"]
            read = self.action(service, target, "memory_read", {"address": address, "length": 64})
            require(read.get("data", {}).get("hex") == known and probe.state()["buffer_hex"] == known,
                    "R10_READ_ONLY_NATIVE_MEMORY_ORACLE_MISMATCH")
            require(read.get("diagnostic_execution", {}).get("source_verified") is True
                    and read.get("diagnostic_execution", {}).get("target_verified") is True,
                    "R10_HELPER_NATIVE_TARGET_EVIDENCE_REQUIRED")
            modules = self.action(service, target, "modules", expected=("COMPLETED", "INCOMPLETE_EVIDENCE"))
            require(bool(modules.get("data", {}).get("rows")), "R10_REAL_MODULES_EMPTY")
            changed = bytes(i ^ (0xA5 if label == "A" else 0x3C) for i in range(64)).hex()
            params = {"address": address, "expected_hex": known, "value_hex": changed}
            self.action(service, target, "memory.write", params, expected=("CONFIRMATION_REQUIRED",))
            require(probe.state()["buffer_hex"] == known, "R10_UNCONFIRMED_WRITE_CHANGED_MEMORY")
            written = self.action(service, target, "memory.write", params, confirmed=True)
            require(written.get("data", {}).get("readback_verified") is True
                    and probe.state()["buffer_hex"] == changed,
                    "R10_HELPER_MEMORY_WRITE_EFFECT_NOT_INDEPENDENTLY_OBSERVED")
            self.action(service, target, "memory.rollback", {"change_id": written["data"]["change_id"]}, confirmed=True)
            require(probe.state()["buffer_hex"] == known, "R10_ROLLBACK_EFFECT_NOT_INDEPENDENTLY_OBSERVED")
            thread = {"tid": probe.ready["heartbeat_tid"],
                      "thread_created_100ns": probe.ready["heartbeat_thread_created_100ns"]}
            suspended = self.action(service, target, "thread.suspend", thread, confirmed=True)
            before = probe.state()
            stop_deadline = time.monotonic() + 3
            while True:
                threading.Event().wait(.1)
                stopped = probe.state()
                require(stopped["heartbeat"] == before["heartbeat"], "R10_SUSPENDED_THREAD_STILL_PROGRESSED")
                if stopped["io_cycles"] > before["io_cycles"]:
                    break
                require(time.monotonic() < stop_deadline, "R10_EXACT_THREAD_SUSPENSION_EFFECT_NOT_OBSERVED")
            self.action(service, target, "thread.resume", {"suspension_id": suspended["data"]["suspension_id"]},
                        confirmed=True)
            probe.progress(stopped)
            self.heartbeat(service, identity, deadline, launches)
            if label == "A":
                # Leave one owned change for the real A -> B cleanup path.
                self.action(service, target, "memory.write", params, confirmed=True)
                require(probe.state()["buffer_hex"] == changed, "R10_PENDING_SWITCH_CHANGE_NOT_OBSERVED")
            self.proof["scenarios"]["target-" + label] = {"status": "PASS", "identity": target.to_dict(),
                "read_only_memory_verified": True, "native_write_rollback_verified": True,
                "exact_thread_suspend_resume_verified": True}

        wrong = replace(ib, created_100ns=ib.created_100ns + 1)
        self.action(service, wrong, "memory_read", {"address": b.ready["buffer_address"], "length": 64},
                    expected=("CONFIRMATION_REQUIRED", "PROCESS_CHANGED"))
        mismatch = self.record("bind-wrong-FILETIME", service.bind_target(wrong, SCOPE, confirmed=True))
        require(mismatch.get("status") in ("PROCESS_CHANGED", "OPERATION_FAILED"),
                "R10_WRONG_CREATION_FILETIME_ACCEPTED")
        scope_refusal = self.action(service, ib, "processes", expected=("CONFIRMATION_REQUIRED", "ACCESS_DENIED"))
        require(scope_refusal.get("run_receipt", {}).get("execution_started") is False
                and service.session_status().get("operations") == sorted(SCOPE),
                "R10_OUTSIDE_SCOPE_ACTION_EXECUTED_OR_CHANGED_AUTHORIZATION")
        self.action(service, ib, "memory_read", {"address": b.ready["buffer_address"], "length": MAX_MEMORY_BYTES + 1},
                    expected=("OPERATION_FAILED", "LIMIT_REACHED"))
        try:
            ActionRequest("not-a-supported-tool", ib)
        except ValueError as error:
            require("OPERATION_NOT_ALLOWED" in str(error), "R10_UNEXPECTED_OPERATION_REFUSAL")
        else:
            raise AssertionError("R10_UNSUPPORTED_OPERATION_ACCEPTED")
        try:
            service.execute(ActionRequest("memory_read", ib, {"command": "not-executed"}))
        except ValueError as error:
            require("UNTRUSTED_NATIVE_HANDLE_OR_COMMAND" in str(error), "R10_UNEXPECTED_PARAMETER_REFUSAL")
        else:
            raise AssertionError("R10_ARBITRARY_COMMAND_PARAMETER_ACCEPTED")
        self.proof["scenarios"]["identity-scope-budget-invalid-input"] = {"status": "PASS"}

        # A real filesystem obstruction prevents a durable intent; no effect is allowed.
        journal_path, backup = service.journal.path, service.journal.path.with_suffix(".qa-held")
        journal_path.rename(backup)
        journal_path.mkdir()
        try:
            self.action(service, ib, "memory.write", {"address": b.ready["buffer_address"],
                "expected_hex": b.ready["buffer_hex"], "value_hex": "CC" * 64}, confirmed=True,
                expected=("OPERATION_FAILED",))
            require(b.state()["buffer_hex"] == b.ready["buffer_hex"], "R10_JOURNAL_FAILURE_ALLOWED_EFFECT")
        finally:
            journal_path.rmdir()
            backup.rename(journal_path)
        self.proof["scenarios"]["real-journal-storage-failure"] = {"status": "PASS", "injection": "OWNED_SQLITE_PATH_IS_DIRECTORY"}
        self.heartbeat(service, identity, deadline, launches)

        # The competing debugger is this QA process's own real Windows debug
        # context.  No second diagnostic helper or runas is launched.
        from blackbox_core.deep_debug import DebugSession
        competing_debugger = DebugSession(ib)
        try:
            attached = competing_debugger.execute("debug.attach", {"_confirmed": True},
                                                   deadline=time.monotonic() + 20)
            require(attached.get("status") == "COMPLETED", "R10_OWNED_COMPETING_DEBUGGER_ATTACH_FAILED")
            self.action(service, ib, "debug.attach", confirmed=True, expected=("ALREADY_DEBUGGED",))
        finally:
            debugger_cleanup = competing_debugger.close()
            require(debugger_cleanup.get("status") == "COMPLETED", "R10_COMPETING_DEBUGGER_CLEANUP_FAILED")
        b.progress(b.state())
        self.proof["scenarios"]["real-debugger-resource-conflict"] = {"status": "PASS",
            "source": "OWNED_NATIVE_DEBUG_SESSION_IN_QA_CONTROLLER", "second_diagnostic_helper": False,
            "cleanup": journal_metadata(debugger_cleanup)}
        self.heartbeat(service, identity, deadline, launches)

        cancelled = threading.Event()
        cancelled.set()
        self.action(service, ib, "modules", cancel=cancelled, expected=("CANCELLED",))
        cancelled.clear()
        channel, timers = service._channel, []
        production_send = channel.send

        def observed_send(message, **kwargs):
            production_send(message, **kwargs)
            if message.get("kind") == "execute" and message.get("request", {}).get("operation") == "handles":
                timer = threading.Timer(.025, cancelled.set)
                timers.append(timer)
                timer.start()

        channel.send = observed_send
        try:
            interrupted = self.action(service, ib, "handles", {"limit": 1024, "name_limit": 64},
                                      cancel=cancelled, expected=("CANCELLED",), timeout=15)
            require(interrupted.get("cancellation_requested") is True,
                    "R10_LIVE_HELPER_CANCEL_ACK_REQUIRED")
        finally:
            channel.send = production_send
            for timer in timers:
                timer.join(timeout=1)
        # Querying each handle name starts a bounded owned query process. Allow
        # enough budget to reach the real helper, then verify native dispatch
        # before accepting the deadline outcome (100ms is a pre-dispatch floor).
        deadline_dispatches = []

        def observed_deadline_send(message, **kwargs):
            production_send(message, **kwargs)
            if message.get("kind") == "execute" and message.get("request", {}).get("operation") == "handles":
                deadline_dispatches.append(message["request_id"])

        channel.send = observed_deadline_send
        try:
            self.action(service, ib, "handles", {"limit": 1024, "name_limit": 64},
                        expected=("TIMED_OUT",), timeout=.5)
        finally:
            channel.send = production_send
        require(len(deadline_dispatches) == 1, "R10_NATIVE_TIMEOUT_WAS_NOT_DISPATCHED")
        subsequent_modules = self.action(service, ib, "modules", expected=("COMPLETED", "INCOMPLETE_EVIDENCE"))
        self.proof["scenarios"]["cancellation-and-following-observation"] = {"status": "PASS",
            "phases": ["BEFORE_NATIVE_DISPATCH", "LIVE_HELPER_REQUEST_SENT_AND_CANCEL_ACK_RECEIVED"],
            "real_native_deadline": "TIMED_OUT", "subsequent_real_modules": subsequent_modules["status"]}
        self.heartbeat(service, identity, deadline, launches)

        # Repeat B -> A -> B within the same lease.  Leave an owned suspension
        # and then an owned write for the actual target-release paths to undo.
        thread_b = {"tid": b.ready["heartbeat_tid"],
                    "thread_created_100ns": b.ready["heartbeat_thread_created_100ns"]}
        self.action(service, ib, "thread.suspend", thread_b, confirmed=True)
        paused_b = b.state()
        threading.Event().wait(.12)
        require(b.state()["heartbeat"] == paused_b["heartbeat"],
                "R10_REPEAT_SWITCH_PENDING_SUSPENSION_NOT_OBSERVED")
        require(self.record("repeat-bind-A", service.bind_target(ia, SCOPE, confirmed=True)).get("status") == "COMPLETED",
                "R10_REPEAT_TARGET_A_BIND_FAILED")
        b.progress(paused_b)
        self.heartbeat(service, identity, deadline, launches)
        repeat_change = bytes([0xA9] * 64).hex()
        self.action(service, ia, "memory.write", {"address": a.ready["buffer_address"],
                    "expected_hex": a.ready["buffer_hex"], "value_hex": repeat_change}, confirmed=True)
        require(a.state()["buffer_hex"] == repeat_change, "R10_REPEAT_SWITCH_PENDING_WRITE_NOT_OBSERVED")
        require(self.record("repeat-bind-B", service.bind_target(ib, SCOPE, confirmed=True)).get("status") == "COMPLETED",
                "R10_REPEAT_TARGET_B_BIND_FAILED")
        require(a.state()["buffer_hex"] == a.ready["buffer_hex"],
                "R10_REPEAT_SWITCH_NATIVE_MEMORY_NOT_RESTORED")
        self.heartbeat(service, identity, deadline, launches)
        self.proof["scenarios"]["repeat-switch-resource-lifecycle"] = {"status": "PASS",
            "order": ["A", "B", "A", "B"], "pending_B_thread_resumed_on_switch": True,
            "pending_A_write_restored_on_switch": True, "same_helper_and_deadline": True,
            "runas_count": len(launches)}

        destination = self.output / "journal-export.jsonl"
        exported = self.record("journal-export", service.export_journal(destination))
        require(exported.get("status") == "COMPLETED", "R10_JOURNAL_EXPORT_FAILED")
        lines = [json.loads(line) for line in destination.read_text(encoding="utf-8").splitlines()]
        require(len(lines) > 10 and all(isinstance(row, dict) for row in lines), "R10_EXPORT_READBACK_EMPTY")
        previous = "0" * 64
        for row in lines:
            raw = json.dumps(row["record"], ensure_ascii=False, allow_nan=False,
                             separators=(",", ":")).encode("utf-8")
            digest = hashlib.sha256(previous.encode("ascii") + raw).hexdigest()
            require(row.get("previous_sha256") == previous and row.get("record_sha256") == digest,
                    "R10_INDEPENDENT_EXPORT_HASH_CHAIN_READBACK_FAILED")
            previous = digest
        require(exported.get("data", {}).get("exported_chain_head_sha256") == previous,
                "R10_EXPORT_CHAIN_HEAD_RECEIPT_DIFFERS_FROM_READBACK")
        self.proof["scenarios"]["independent-jsonl-readback"] = {"status": "PASS", "records": len(lines),
            "sha256": file_hash(destination), "hash_chain_independently_verified": True}
        old_hash = file_hash(destination)
        failed_export = self.record("export-existing-refused", service.export_journal(destination))
        require(failed_export.get("status") == "OPERATION_FAILED" and file_hash(destination) == old_hash,
                "R10_FAILED_EXPORT_OVERWROTE_EXISTING_REPORT")
        self.heartbeat(service, identity, deadline, launches)
        helper_owner = service.helper
        closed = self.record("primary-session-close", service.end_admin_session())
        require(closed.get("status") == "COMPLETED" and not helper_owner.alive()
                and service.session_status().get("state") == "INACTIVE", "R10_PRIMARY_HELPER_CLOSE_NOT_VERIFIED")
        require(a.state()["buffer_hex"] == a.ready["buffer_hex"] and b.state()["buffer_hex"] == b.ready["buffer_hex"],
                "R10_NATIVE_BYTES_NOT_RESTORED_AFTER_CLOSE")
        return {"status": "PASS", "helper_identity": identity, "independent_token": token,
                "broker_launches": launches, "runas_count": len(launches), "fixed_deadline": deadline,
                "switch_A_to_B_cleanup_verified": True, "final_helper_exit_verified": True}

    def run_expiry_and_crash(self, probe: Probe) -> dict:
        expiry, launches = self.service("short-expiry")
        opened = self.record("short-lease-start", expiry.start_admin_session(confirmed=True, session_seconds=2))
        require(opened.get("status") == "COMPLETED", "R10_SHORT_REAL_ADMIN_LEASE_FAILED")
        owner, identity = expiry.helper, expiry.session_status().get("helper_identity")
        threading.Event().wait(2.4)
        status = self.record("expired-heartbeat", expiry.session_status(refresh=True))
        require(status.get("state") == "EXPIRED" and not status.get("admin_active")
                and not status.get("elevated_verified"), "R10_EXPIRED_LEASE_SHOWN_ACTIVE")
        expiry.end_admin_session()
        require(not owner.alive() and len(launches) == 1, "R10_EXPIRED_HELPER_OR_SECOND_RUNAS_REMAINED")
        crashed, crash_launches = self.service("crashed-helper")
        require(self.record("crash-lease-start", crashed.start_admin_session(confirmed=True)).get("status") == "COMPLETED",
                "R10_CRASH_REAL_ADMIN_LEASE_FAILED")
        require(crashed.bind_target(crashed.identity(probe.process.pid), SCOPE, confirmed=True).get("status") == "COMPLETED",
                "R10_CRASH_TARGET_BIND_FAILED")
        crash_owner = crashed.helper
        crash_owner.terminate()
        status_after = self.record("crash-heartbeat", crashed.session_status(refresh=True))
        require(status_after.get("state") == "FAILED" and not status_after.get("admin_active")
                and not status_after.get("elevated_verified") and not crash_owner.alive()
                and len(crash_launches) == 1, "R10_CRASHED_HELPER_SHOWN_ACTIVE_OR_RELAUNCHED")
        crashed.end_admin_session()
        return {"status": "PASS", "expiry_helper_identity": identity,
                "expiry_seconds": 2, "expiry_launches": launches, "crash_launches": crash_launches,
                "independent_fixture_progress_after_crash": probe.progress(probe.state())["heartbeat"]}

    def run_cleanup_failure(self, a: Probe, b: Probe) -> dict:
        service, launches = self.service("real-cleanup-failure")
        ia, ib = service.identity(a.process.pid), service.identity(b.process.pid)
        require(service.start_admin_session(confirmed=True).get("status") == "COMPLETED", "R10_CLEANUP_SESSION_FAILED")
        require(service.bind_target(ia, SCOPE, confirmed=True).get("status") == "COMPLETED", "R10_CLEANUP_BIND_FAILED")
        original = a.ready["buffer_hex"]
        changed, concurrent = bytes([0xD3] * 64).hex(), bytes([0xE7] * 64)
        self.action(service, ia, "memory.write", {"address": a.ready["buffer_address"],
                    "expected_hex": original, "value_hex": changed}, confirmed=True)
        require(a.state()["buffer_hex"] == changed, "R10_CLEANUP_PENDING_NATIVE_CHANGE_MISSING")
        controlled_external_write(ia, a.ready["buffer_address"], concurrent)
        require(a.state()["buffer_hex"] == concurrent.hex(), "R10_CONCURRENT_NATIVE_WRITER_NOT_OBSERVED")
        failed = self.record("real-cleanup-failure-target-switch", service.bind_target(ib, SCOPE, confirmed=True))
        status = self.record("cleanup-required-heartbeat", service.session_status(refresh=True))
        require(failed.get("status") == "RECOVERY_UNCONFIRMED" and status.get("state") == "CLEANUP_REQUIRED"
                and status.get("target") == ia.to_dict() and not status.get("admin_active"),
                "R10_UNCONFIRMED_CLEANUP_DID_NOT_BLOCK_RETARGET_OR_ACTIVE_BADGE")
        require(a.state()["buffer_hex"] == concurrent.hex() and b.state()["buffer_hex"] == b.ready["buffer_hex"],
                "R10_CLEANUP_FAILURE_CORRUPTED_OR_NEW_TARGET_WAS_TOUCHED")
        again = self.record("cleanup-blocks-B-consent", service.bind_target(ib, SCOPE, confirmed=True))
        require(again.get("status") == "RECOVERY_UNCONFIRMED" and len(launches) == 1,
                "R10_CLEANUP_FAILURE_RETRIED_EFFECT_OR_LAUNCHED_SECOND_HELPER")
        # The external QA writer restores its own concurrent bytes explicitly.
        controlled_external_write(ia, a.ready["buffer_address"], bytes.fromhex(original))
        require(a.state()["buffer_hex"] == original, "R10_EXTERNAL_QA_MUTATION_RESTORATION_FAILED")
        close = self.record("unconfirmed-session-close", service.end_admin_session())
        require(close.get("status") == "RECOVERY_UNCONFIRMED", "R10_CLEANUP_FAILURE_WAS_REPORTED_AS_SUCCESS")
        self.expected_unconfirmed_services.add(id(service))
        # Preserve receipt, then stop only this no-debug-attachment helper to avoid
        # leaving elevated QA processes on the disposable runner.  This is not a
        # product success claim: the failed cleanup receipt remains unconfirmed.
        if service.helper is not None:
            service.helper.terminate()
            service._discard_helper(force=True)
        return {"status": "PASS", "actual_operation_status": "RECOVERY_UNCONFIRMED",
                "injection": "INDEPENDENT_WRITER_CHANGED_OWNED_BUFFER_AFTER_HELPER_WRITE",
                "target_B_refused": True, "concurrent_bytes_preserved": True,
                "elevated_helper_stopped_for_disposable_runner_cleanup": service.helper is None,
                "broker_launches": launches}

    def run(self) -> dict:
        a, b = self.probe("A"), self.probe("B")
        # Prove ordinary observation before any elevated session is requested.
        ordinary, launches = self.service("ordinary-observation")
        identity = ordinary.identity(a.process.pid)
        read = self.action(ordinary, identity, "memory_read", {"address": a.ready["buffer_address"], "length": 64})
        require(read.get("data", {}).get("hex") == a.ready["buffer_hex"]
                and launches and all(not row["elevated"] for row in launches),
                "R10_ORDINARY_DIAGNOSTICS_UNEXPECTEDLY_REQUESTED_RUNAS")
        require(ordinary.close().get("status") == "COMPLETED", "R10_ORDINARY_HELPER_CLOSE_FAILED")
        self.proof["scenarios"]["ordinary-without-elevation"] = {"status": "PASS", "launches": launches}
        self.proof["one_helper_two_targets"] = self.run_primary(a, b)
        self.proof["scenarios"]["actual-expiry-and-crash"] = self.run_expiry_and_crash(b)
        self.proof["scenarios"]["actual-cleanup-failure"] = self.run_cleanup_failure(a, b)
        self.proof["status"] = "PASS"
        return self.proof

    def cleanup(self) -> None:
        cleanup = []
        for service in reversed(self.services):
            try:
                response = service.close()
                if service.helper is not None:
                    # A failed acceptance must still stop its disposable helper.
                    service.helper.terminate()
                    service._discard_helper(force=True)
                cleanup.append({"kind": "service",
                    "status": "COMPLETED" if id(service) in self.expected_unconfirmed_services
                              and service.helper is None else response.get("status"),
                    "diagnostic_cleanup_status": response.get("status"),
                    "expected_negative_cleanup_branch": id(service) in self.expected_unconfirmed_services,
                    "runner_owned_helper_stopped": service.helper is None, "helper_pid": service.helper_pid})
            except Exception as error:
                cleanup.append({"kind": "service", "status": "RECOVERY_UNCONFIRMED", "error": str(error)[:500]})
        for probe in reversed(self.probes):
            try:
                cleanup.append({"kind": "owned-probe", **probe.close()})
            except Exception as error:
                cleanup.append({"kind": "owned-probe", "status": "RECOVERY_UNCONFIRMED", "error": str(error)[:500]})
        self.proof["runner_cleanup"] = journal_metadata(cleanup)
        if any(row.get("status") == "RECOVERY_UNCONFIRMED" for row in cleanup):
            self.proof["status"] = "FAIL"


def publish_receipt(path: Path, proof: dict) -> None:
    save(path, proof)
    digest = file_hash(path)
    compact = {"status": proof["status"], "source_sha": proof["source_sha"], "receipt_sha256": digest,
               "receipt_bytes": path.stat().st_size, "scenario_statuses": {
                   key: value.get("status") for key, value in proof.get("scenarios", {}).items()},
               "one_helper_two_targets": proof.get("one_helper_two_targets"),
               "physical_interactive_uac": "NOT_TESTED"}
    require(path.stat().st_size <= 2 * 1024 * 1024, "R10_QA_RECEIPT_BUDGET_EXCEEDED")
    print("R10_NATIVE_RECEIPT " + json.dumps(compact, sort_keys=True), flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as stream:
            stream.write("\n### R10 real Windows helper/native acceptance\n\n")
            stream.write("```json\n" + json.dumps(compact, indent=2, sort_keys=True) + "\n```\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--helper", type=Path)
    args = parser.parse_args()
    require_hosted_windows()
    require(bool(re.fullmatch(r"[0-9a-f]{40}", args.source_sha)), "EXACT_SOURCE_SHA_REQUIRED")
    args.output.mkdir(parents=True, exist_ok=False)
    acceptance = NativeAcceptance(args.output.resolve(), args.probe.resolve(strict=True), args.source_sha, args.helper)
    try:
        acceptance.run()
    except BaseException as error:
        acceptance.proof["status"] = "FAIL"
        acceptance.proof["error"] = {"type": type(error).__name__, "message": str(error)[:2000],
                                      "traceback": traceback.format_exc()[-8000:]}
        raise
    finally:
        acceptance.cleanup()
        publish_receipt(args.output / "r10-native.json", acceptance.proof)
    require(acceptance.proof["status"] == "PASS", "R10_RUNNER_CLEANUP_NOT_VERIFIED")


if __name__ == "__main__":
    main()
