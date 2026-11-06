"""Frozen-safe reader for the existing Wave02 native QA fixture protocol.

The source harness compiles the unchanged fixture on hosted Windows. This module
only owns that supplied executable and independently queries Windows tokens.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import time

from .chain_qa import require, require_hosted_windows, save


# These capabilities belong to this independent QA query, never to the product
# helper. An unsuccessful CloseHandle must not be reported as successful cleanup
# or lose its exact handle when the acceptance harness catches an exception.
_TOKEN_HANDLES_LOCK = threading.RLock()
_PENDING_TOKEN_HANDLES = []


def _close_token_handles(kernel, handles, primary):
    failed = []
    for label, handle in handles:
        if not handle:
            continue
        try:
            if not kernel.CloseHandle(handle):
                failed.append((label, handle, C.get_last_error()))
        except BaseException as error:
            failed.append((label, handle, type(error).__name__))
    if failed:
        with _TOKEN_HANDLES_LOCK:
            _PENDING_TOKEN_HANDLES.append((kernel, failed))
        cleanup = OSError("R60_INDEPENDENT_TOKEN_QUERY_CLOSE_UNCONFIRMED: " +
                          ",".join(label for label, _handle, _error in failed))
        cleanup.cleanup_required = True
        if primary is not None:
            primary.add_note(str(cleanup))
        else:
            raise cleanup


class OwnedWaveProbe:
    """The independent oracle is separate from the product/helper under test."""
    def __init__(self, executable: Path, output: Path):
        require_hosted_windows()
        from blackbox_core.optional_jobs import OwnedProcess
        self.output = output.resolve()
        self.output.mkdir(parents=True, exist_ok=False)
        self.dump = self.output / "private-crash.dmp"
        self.stderr = (self.output / "fixture-stderr.log").open("wb")
        self.records: list[dict] = []
        self.pending: list[dict] = []
        self.lines: queue.Queue = queue.Queue(maxsize=256)
        self.owner = self.reader = None
        self.expected_crash = False
        try:
            self.owner = OwnedProcess([str(executable.resolve(strict=True)),
                str(self.output), str(self.dump)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=self.stderr, detach_console=True)
            self.process = self.owner.process
            self.reader = threading.Thread(target=self._read, name="wave02-oracle", daemon=True)
            self.reader.start()
            self.ready = self.receive("ready", timeout=20)
            require(self.ready["pid"] == self.process.pid and self.ready["created_100ns"] > 0
                    and self.ready["qpc_frequency"] > 0 and self.ready["hwnd"] > 0
                    and self.ready["ui_tid"] != self.ready["control_tid"],
                    "WAVE02_NATIVE_IDENTITY_OR_UI_ORACLE_INVALID")
            save(self.output / "ready.json", self.ready)
        except BaseException:
            self.close(kill=True)
            raise

    def _read(self):
        try:
            while True:
                line = self.process.stdout.readline(16385)
                if not line:
                    self.lines.put_nowait(EOFError("WAVE02_ORACLE_CLOSED"))
                    return
                require(len(line) <= 16384 and line.endswith(b"\n"), "WAVE02_ORACLE_LINE_BUDGET")
                item = json.loads(line)
                require(type(item) is dict and type(item.get("event")) is str,
                        "WAVE02_ORACLE_RECORD_INVALID")
                self.lines.put_nowait(item)
        except BaseException as error:
            try:
                self.lines.put_nowait(error)
            except queue.Full:
                pass

    def send(self, command):
        require(command in {"state", "freeze", "release", "file", "burst", "crash", "stop"},
                "WAVE02_CONTROL_COMMAND_NOT_ALLOWED")
        require(self.owner is not None and self.process.poll() is None,
                "WAVE02_TARGET_EXITED_BEFORE_COMMAND")
        if command == "crash":
            self.expected_crash = True
        self.process.stdin.write((command + "\n").encode("ascii"))
        self.process.stdin.flush()

    def receive(self, event, *, timeout=20):
        for index, record in enumerate(self.pending):
            if record["event"] == event:
                return self.pending.pop(index)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "WAVE02_ORACLE_TIMEOUT_" + event)
            try:
                item = self.lines.get(timeout=remaining)
            except queue.Empty as error:
                raise TimeoutError("WAVE02_ORACLE_TIMEOUT_" + event) from error
            if isinstance(item, BaseException):
                raise item
            self.records.append(item)
            require(len(self.records) <= 4096, "WAVE02_ORACLE_RECORD_BUDGET")
            if item["event"] == event:
                return item
            self.pending.append(item)

    def command(self, command, event=None, *, timeout=20):
        self.send(command)
        return self.receive(event or command, timeout=timeout)

    def close(self, *, kill=False):
        result = {"status": "NOT_STARTED"}
        try:
            if self.owner is not None:
                if self.process.poll() is None and not kill:
                    self.send("stop")
                    stopped = self.receive("normal_exit", timeout=20)
                    self.process.wait(timeout=10)
                    require(stopped.get("cleanup_complete") is True and self.process.returncode == 0,
                            "WAVE02_FIXTURE_NORMAL_CLEANUP_NOT_CONFIRMED")
                    result = {"status": "COMPLETED", "exit_code": 0, "oracle": stopped}
                elif self.expected_crash and not kill:
                    require((self.process.returncode & 0xFFFFFFFF) == 0xC0000005,
                            "WAVE02_EXPECTED_ACCESS_VIOLATION_EXIT_NOT_OBSERVED")
                    result = {"status": "OWNED_CRASH_EXIT_VERIFIED", "exit_code": self.process.returncode}
                else:
                    require(kill, "WAVE02_UNEXPECTED_TARGET_EXIT")
                    result = {"status": "FORCED_QA_CLEANUP", "exit_code": self.process.poll()}
        finally:
            if self.owner is not None:
                self.owner.close(kill=True)
                for stream in (self.process.stdin, self.process.stdout):
                    if stream is not None:
                        stream.close()
                if self.reader is not None:
                    self.reader.join(timeout=2)
                    require(not self.reader.is_alive(), "WAVE02_ORACLE_READER_NOT_CLOSED")
                self.owner = None
            self.stderr.close()
            save(self.output / "oracle-records.json", self.records)
        return result


def actual_token(pid):
    """Separate OpenProcessToken query of the real helper process."""
    require_hosted_windows()
    with _TOKEN_HANDLES_LOCK:
        require(not _PENDING_TOKEN_HANDLES, "R60_PRIOR_INDEPENDENT_TOKEN_QUERY_CLEANUP_UNCONFIRMED")
    kernel = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    advapi = C.WinDLL("advapi32", use_last_error=True, winmode=0x800)
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    kernel.OpenProcess.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    kernel.CloseHandle.restype = W.BOOL
    advapi.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
    advapi.OpenProcessToken.restype = W.BOOL
    advapi.GetTokenInformation.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)]
    advapi.GetTokenInformation.restype = W.BOOL
    process, token = kernel.OpenProcess(0x1000, False, pid), W.HANDLE()
    require(bool(process), "R60_HELPER_PROCESS_QUERY_HANDLE")
    primary = None
    try:
        require(advapi.OpenProcessToken(process, 8, C.byref(token)), "R60_HELPER_TOKEN_QUERY")
        elevated, elevation_type, needed = W.DWORD(), W.DWORD(), W.DWORD()
        require(advapi.GetTokenInformation(token, 20, C.byref(elevated), C.sizeof(elevated), C.byref(needed)),
                "R60_HELPER_TOKEN_ELEVATION_QUERY")
        require(advapi.GetTokenInformation(token, 18, C.byref(elevation_type), C.sizeof(elevation_type), C.byref(needed)),
                "R60_HELPER_TOKEN_TYPE_QUERY")
        return {"pid": pid, "elevated": elevated.value != 0, "elevation_type": elevation_type.value,
                "source": "INDEPENDENT_OPEN_PROCESS_TOKEN_GET_TOKEN_INFORMATION"}
    except BaseException as error:
        primary = error
        raise
    finally:
        _close_token_handles(kernel, (("token", token), ("process", process)), primary)


def actual_current_token_facts():
    """Independent read-only primary/effective token facts, never authority.

    Mandatory integrity, TokenElevation, effective group membership and enabled
    privileges answer different questions. In particular, Medium IL alone does
    not establish that TokenElevation is zero. No account SID, native pointer,
    token contents or existing object's ACL is published or changed here.
    """
    require_hosted_windows()
    require(C.sizeof(C.c_void_p) == 8, "R60_TOKEN_FACTS_X64_REQUIRED")
    with _TOKEN_HANDLES_LOCK:
        require(not _PENDING_TOKEN_HANDLES, "R60_PRIOR_INDEPENDENT_TOKEN_QUERY_CLEANUP_UNCONFIRMED")
    u32, i32, handle = C.c_uint32, C.c_int32, C.c_void_p

    class SidAttributes(C.Structure):
        _fields_ = [("sid", handle), ("attributes", u32)]

    class Groups(C.Structure):
        _fields_ = [("count", u32), ("entries", SidAttributes * 1)]

    class Luid(C.Structure):
        _fields_ = [("low", u32), ("high", i32)]

    class Privilege(C.Structure):
        _fields_ = [("luid", Luid), ("attributes", u32)]

    class Privileges(C.Structure):
        _fields_ = [("count", u32), ("entries", Privilege * 1)]

    kernel = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    adv = C.WinDLL("advapi32", use_last_error=True, winmode=0x800)
    kernel.GetCurrentProcess.argtypes, kernel.GetCurrentProcess.restype = [], handle
    kernel.CloseHandle.argtypes, kernel.CloseHandle.restype = [handle], i32
    adv.OpenProcessToken.argtypes, adv.OpenProcessToken.restype = [handle, u32, C.POINTER(handle)], i32
    adv.GetTokenInformation.argtypes = [handle, C.c_int, handle, u32, C.POINTER(u32)]
    adv.GetTokenInformation.restype = i32
    adv.IsValidSid.argtypes, adv.IsValidSid.restype = [handle], i32
    adv.GetLengthSid.argtypes, adv.GetLengthSid.restype = [handle], u32
    adv.CheckTokenMembership.argtypes, adv.CheckTokenMembership.restype = [handle, handle, C.POINTER(i32)], i32
    adv.LookupPrivilegeNameW.argtypes = [C.c_wchar_p, C.POINTER(Luid), C.c_wchar_p, C.POINTER(u32)]
    adv.LookupPrivilegeNameW.restype = i32
    restricted_api = getattr(adv, "IsTokenRestricted", None)
    if restricted_api is not None:
        restricted_api.argtypes, restricted_api.restype = [handle], i32
    token, primary = handle(), None

    def checked_query(valid, reason, *, kind, stage, returned, error, needed, capacity):
        if not valid:
            failure = AssertionError(reason + ":" + str(kind) + ":stage=" + stage +
                ":return=" + str(int(bool(returned))) + ":error=" + str(error) +
                ":needed=" + str(needed) + ":capacity=" + str(capacity))
            failure.token_query_diagnostic = {"information_class": kind, "stage": stage,
                "return_bool": bool(returned), "get_last_error": error,
                "returned_bytes": needed, "capacity": capacity}
            raise failure

    def information(kind, minimum=4):
        needed = u32()
        C.set_last_error(0)
        first = adv.GetTokenInformation(token, kind, None, 0, C.byref(needed))
        error = C.get_last_error()
        checked_query(not first and error == 122 and minimum <= needed.value <= 65536,
            "R60_TOKEN_FACTS_INFORMATION_SIZE", kind=kind, stage="SIZE", returned=first,
            error=error, needed=needed.value, capacity=0)
        capacity = needed.value
        buffer = C.create_string_buffer(capacity)
        C.set_last_error(0)
        returned = adv.GetTokenInformation(token, kind, buffer, capacity, C.byref(needed))
        error = C.get_last_error()
        checked_query(returned and minimum <= needed.value <= capacity,
            "R60_TOKEN_FACTS_INFORMATION_QUERY", kind=kind, stage="QUERY", returned=returned,
            error=error, needed=needed.value, capacity=capacity)
        return buffer, needed.value

    def scalar(kind):
        # Fixed DWORD classes use the same direct four-byte boundary as the
        # existing independent actual_token query. Variable-size buffer probing
        # is unnecessary here and its result cannot stand in for this read.
        value, needed = u32(), u32()
        C.set_last_error(0)
        returned = adv.GetTokenInformation(token, kind, C.byref(value), C.sizeof(value), C.byref(needed))
        error = C.get_last_error()
        checked_query(returned and needed.value == C.sizeof(value),
            "R60_TOKEN_FACTS_SCALAR_QUERY", kind=kind, stage="SCALAR", returned=returned,
            error=error, needed=needed.value, capacity=C.sizeof(value))
        return value.value

    def sid_bytes(pointer, buffer, used):
        start, end = C.addressof(buffer), C.addressof(buffer) + used
        require(type(pointer) is int and start <= pointer <= end - 8, "R60_TOKEN_FACTS_SID_POINTER_BOUNDS")
        revision = C.c_ubyte.from_address(pointer).value
        count = C.c_ubyte.from_address(pointer + 1).value
        size = 8 + count * 4
        require(revision == 1 and count <= 15 and size <= end - pointer,
                "R60_TOKEN_FACTS_SID_CONTENT_BOUNDS")
        require(adv.IsValidSid(pointer) and adv.GetLengthSid(pointer) == size,
                "R60_TOKEN_FACTS_SID_NATIVE_VALIDATION")
        return C.string_at(pointer, size)

    try:
        require(adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, C.byref(token)),
                "R60_CURRENT_TOKEN_QUERY_OPEN")
        elevation, elevation_type = scalar(20), scalar(18)
        require(elevation in (0, 1) and elevation_type in (1, 2, 3), "R60_TOKEN_FACTS_ELEVATION_VALUE")
        integrity_buffer, integrity_used = information(25, C.sizeof(SidAttributes))
        integrity_label = SidAttributes.from_buffer(integrity_buffer)
        integrity_sid = sid_bytes(integrity_label.sid, integrity_buffer, integrity_used)
        require(integrity_sid[1] == 1 and integrity_sid[2:8] == b"\0\0\0\0\0\x10" and
                integrity_label.attributes & 0x20, "R60_TOKEN_FACTS_INTEGRITY_SID_OR_ATTRIBUTES")
        integrity_rid = int.from_bytes(integrity_sid[8:12], "little")
        # S-1-5-32-544 is a fixed well-known group, never an account SID.
        administrators_sid = b"\x01\x02\0\0\0\0\0\x05" + (32).to_bytes(4, "little") + (544).to_bytes(4, "little")
        groups_buffer, groups_used = information(2)
        group_count = u32.from_buffer(groups_buffer).value
        require(group_count <= 1024 and Groups.entries.offset + group_count * C.sizeof(SidAttributes) <= groups_used,
                "R60_TOKEN_FACTS_GROUP_ARRAY_BOUNDS")
        administrators = []
        for index in range(group_count):
            group = SidAttributes.from_buffer(groups_buffer, Groups.entries.offset + index * C.sizeof(SidAttributes))
            if sid_bytes(group.sid, groups_buffer, groups_used) == administrators_sid:
                administrators.append(group.attributes)
        require(len(administrators) <= 1, "R60_TOKEN_FACTS_AMBIGUOUS_ADMINISTRATORS_GROUP")
        attributes = administrators[0] if administrators else None
        privileges_buffer, privileges_used = information(3)
        privilege_count = u32.from_buffer(privileges_buffer).value
        require(privilege_count <= 256 and Privileges.entries.offset + privilege_count * C.sizeof(Privilege) <= privileges_used,
                "R60_TOKEN_FACTS_PRIVILEGE_ARRAY_BOUNDS")
        privileges = []
        for index in range(privilege_count):
            item = Privilege.from_buffer(privileges_buffer, Privileges.entries.offset + index * C.sizeof(Privilege))
            length = u32()
            C.set_last_error(0)
            first = adv.LookupPrivilegeNameW(None, C.byref(item.luid), None, C.byref(length))
            require(not first and C.get_last_error() == 122 and 0 < length.value <= 256,
                    "R60_TOKEN_FACTS_PRIVILEGE_NAME_SIZE")
            capacity = length.value + 1
            text = C.create_unicode_buffer(capacity)
            length.value = capacity
            require(adv.LookupPrivilegeNameW(None, C.byref(item.luid), text, C.byref(length)) and
                    0 < length.value < capacity, "R60_TOKEN_FACTS_PRIVILEGE_NAME_QUERY")
            name = text.value
            require(len(name) == length.value and all(character.isascii() and
                    (character.isalnum() or character == "_") for character in name),
                    "R60_TOKEN_FACTS_PRIVILEGE_NAME_FORMAT")
            privileges.append({"name": name, "attributes": item.attributes,
                "enabled": bool(item.attributes & 2), "enabled_by_default": bool(item.attributes & 1),
                "removed": bool(item.attributes & 4)})
        require(len({item["name"] for item in privileges}) == len(privileges),
                "R60_TOKEN_FACTS_DUPLICATE_PRIVILEGE")
        restricted = scalar(21)
        require(restricted in (0, 1), "R60_TOKEN_FACTS_RESTRICTIONS_VALUE")
        member = i32()
        fixed_sid = C.create_string_buffer(administrators_sid)
        require(adv.CheckTokenMembership(None, fixed_sid, C.byref(member)) and member.value in (0, 1),
                "R60_TOKEN_FACTS_EFFECTIVE_ADMIN_MEMBERSHIP_QUERY")
        return {"schema": "blackbox.r60.current-token-facts/1", "status": "OBSERVED", "pid": os.getpid(),
            "source": "INDEPENDENT_CURRENT_PROCESS_TOKEN_QUERY_AND_EFFECTIVE_TOKEN_MEMBERSHIP",
            "scope": "READ_ONLY_RAW_TOKEN_FACTS_NOT_AUTHORIZATION_OR_STANDARD_ACCOUNT_PROOF",
            "process_token": {"elevation_raw": elevation, "elevated": elevation != 0, "elevation_type": elevation_type,
                "integrity": {"sid": "S-1-16-" + str(integrity_rid), "rid": integrity_rid,
                              "attributes": integrity_label.attributes},
                "administrators_group": {"present": attributes is not None, "attributes": attributes,
                    "enabled": bool(attributes is not None and attributes & 4),
                    "deny_only": bool(attributes is not None and attributes & 0x10)},
                "privileges": sorted(privileges, key=lambda item: item["name"]),
                "has_restrictions_raw": restricted,
                "has_restrictions_meaning": "TOKEN_HAS_EVER_BEEN_FILTERED_NOT_EFFECTIVE_ADMIN_STATUS",
                "is_token_restricted": {"available": restricted_api is not None,
                    "value": bool(restricted_api(token)) if restricted_api is not None else None,
                    "meaning": "TOKEN_CONTAINS_RESTRICTING_SIDS"}},
            "effective_administrators_member": member.value != 0,
            "effective_membership_scope": "CURRENT_EFFECTIVE_THREAD_TOKEN_OR_PROCESS_TOKEN",
            "cleanup": {"confirmed": True, "scope": "OWNED_QUERY_TOKEN_HANDLE_CLOSED_BEFORE_RETURN"}}
    except BaseException as error:
        primary = error
        raise
    finally:
        # The current-process pseudohandle is borrowed and must never be closed.
        _close_token_handles(kernel, (("current_query_token", token),), primary)


def native_checkpoint_graph(output, executable, source_sha, diagnostic_helper=None):
    """Actual same-helper debug attach/checkpoint/restore/detach acceptance."""
    from copy import deepcopy
    from uuid import uuid4
    from .chain_qa import definition, independent_journal, actual_invocations, link, source_proof
    from .chain_adapters import ChainRuntime, build_catalog
    from .chain_engine import WorkflowEngine
    from .chain_store import WorkflowRunStore
    from .deep_native import capture_identity_checked
    from .deep_service import InspectorService
    require_hosted_windows()
    identity_proof = source_proof(source_sha)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    fixture = service = engine = None
    proof = {"schema": "blackbox.r60.native-checkpoint-qa/1", "status": "FAIL",
             "source_sha": source_sha, "source_identity": identity_proof,
             "physical_windows_10_11": "NOT_TESTED", "physical_secure_desktop": "NOT_TESTED"}
    approvals, launches, close_proofs = [], [], []
    owned_run_id = uuid4().hex
    helper_identity = None
    lease_deadline = None
    scope_confirmation = None
    primary = None
    kernel = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    kernel.GetHandleInformation.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
    kernel.GetHandleInformation.restype = W.BOOL
    def observed_close(label, original, capability):
        flags = W.DWORD()
        require(capability is not None and kernel.GetHandleInformation(capability, C.byref(flags)),
                "R60_CHECKPOINT_OWNED_HANDLE_NOT_OBSERVED_OPEN")
        answer = original()
        C.set_last_error(0)
        closed = not kernel.GetHandleInformation(capability, C.byref(flags)) and C.get_last_error() == 6
        require(closed, "R60_CHECKPOINT_PRODUCT_CLOSE_ACK_NOT_OBSERVED")
        close_proofs.append({"resource": label, "opened_before": True, "invalid_handle_after": True,
                             "post_close_winerror": 6})
        return answer
    try:
        fixture = OwnedWaveProbe(Path(executable), output / "target")
        service = InspectorService(output / "native-journal", helper_executable=diagnostic_helper)
        launch = service.broker.launch
        def counted_launch(arguments, *, elevated=False):
            owner = launch(arguments, elevated=elevated)
            launches.append({"pid": owner.pid, "elevated": elevated})
            close = owner.close_handle
            def checked_close():
                capability = owner.handle if owner.handle is not None else int(owner.process._handle)
                return observed_close("helper_process", close, capability)
            owner.close_handle = checked_close
            return owner
        service.broker.launch = counted_launch
        start = service._start_session
        def checked_start(*args, **kwargs):
            answer = start(*args, **kwargs)
            if answer.get("status") == "COMPLETED":
                channel = service._channel
                close = channel.close
                channel.close = lambda: observed_close("pipe", close, channel.handle)
            return answer
        service._start_session = checked_start
        # Initial session/target authorization is independent of each action's
        # fresh approval. The adapter deliberately never opens UAC or grants an
        # administrative target scope implicitly.
        opened = service.start_admin_session_owned(owner_run_id=owned_run_id, confirmed=True)
        require(opened.get("status") == "COMPLETED" and
                type(opened.get("native_context_ownership")) is dict,
                "R60_CHECKPOINT_EXPLICIT_ADMINISTRATIVE_LEASE_REQUIRED")
        session = service.session_status(refresh=True)
        helper_identity = session["helper_identity"]
        lease_deadline = session["session_deadline_monotonic"]
        token = actual_token(helper_identity["pid"])
        require(token["elevated"] is True and len(launches) == 1 and launches[0]["elevated"] is True,
                "R60_CHECKPOINT_REAL_SCOPED_RUNAS_REQUIRED")
        target_identity = capture_identity_checked(fixture.process.pid, owner_run_id=owned_run_id)
        require(target_identity.created_100ns == fixture.ready["created_100ns"],
                "R60_CHECKPOINT_EXACT_SCOPE_TARGET_REQUIRED")
        bound = service.bind_target_owned(target_identity, ["debug.attach", "debug.detach"],
            owner_run_id=owned_run_id, expected_context=opened["native_context_ownership"], confirmed=True)
        require(bound.get("status") == "COMPLETED" and type(bound.get("native_context_ownership")) is dict,
                "R60_CHECKPOINT_EXPLICIT_TARGET_DEBUG_SCOPE_REQUIRED")
        scope_confirmation = {"target": target_identity.to_dict(), "operations": ["debug.attach", "debug.detach"],
                              "confirmed_monotonic_ns": time.monotonic_ns(), "helper_token": token}
        def approve(operation, parameters, target, ctx):
            require(operation in ("debug.attach", "debug.detach") and
                    target["pid"] == fixture.ready["pid"] and
                    target["created_100ns"] == fixture.ready["created_100ns"],
                    "R60_CHECKPOINT_FRESH_CONSENT_WRONG_SCOPE")
            ctx.check()
            require(capture_identity_checked(target["pid"], owner_run_id=ctx.run_id).to_dict() == target,
                    "R60_CHECKPOINT_TARGET_IDENTITY_CHANGED")
            live = service.session_status()
            require(ctx.run_id == owned_run_id and live["helper_identity"] == helper_identity and len(launches) == 1
                    and abs(live["session_deadline_monotonic"] - lease_deadline) < .001,
                    "R60_CHECKPOINT_HELPER_REPLACED_OR_LEASE_RENEWED_BEFORE_ACTION")
            approvals.append({"operation": operation, "node_run_id": ctx.node_run_id,
                "target": target, "fresh_monotonic_ns": time.monotonic_ns()})
            return True
        runtime = ChainRuntime(inspector=service, authorize=approve, owned_session_run_id=owned_run_id,
                               native_context_ref=bound["native_context_ownership"])
        workflow = definition([
            {"node_id": "target", "tool_id": "process_select", "budget_seconds": 10,
             "parameters": {"pid": fixture.process.pid}},
            {"node_id": "attach", "tool_id": "deep.debug.attach", "budget_seconds": 30},
            {"node_id": "checkpoint", "kind": "CHECKPOINT", "budget_seconds": 1},
            {"node_id": "detach", "tool_id": "deep.debug.detach", "budget_seconds": 30}], [
                link("target", "process", "attach", "process"),
                link("attach", "receipt", "checkpoint", "after"),
                link("target", "process", "detach", "process"),
                link("checkpoint", "continue", "detach", "when")],
            identity="native-checkpoint", seconds=180, allow_effectful=True)
        store = WorkflowRunStore.create(output / "runs", workflow, run_id=owned_run_id)
        engine = WorkflowEngine(workflow, catalog=build_catalog(runtime), store=store, runtime=runtime)
        paused = engine.run()
        require(paused["state"] == "WAITING_FOR_HUMAN" and len(approvals) == len(launches) == 1,
                "R60_CHECKPOINT_REAL_ATTACH_DID_NOT_PAUSE")
        preserved = deepcopy(next(row for row in paused["nodes"] if row["node_id"] == "attach"))
        require(preserved["run_receipt"]["operation"] == "debug.attach" and
                preserved["run_receipt"]["execution_started"] is True and
                preserved["run_receipt"]["cleanup"]["status"] == "RETAINED" and
                preserved["run_receipt"]["cleanup"]["confirmed"] is False,
                "R60_CHECKPOINT_ACTUAL_ATTACHED_OWNER_REQUIRED")
        require(service.session_status()["helper_identity"] == helper_identity and
                service._native_owner_matches(store.run_id, runtime.native_context_ref),
                "R60_CHECKPOINT_ACTUAL_SAME_OWNER_REFERENCE_REQUIRED")
        new_runtime = ChainRuntime(inspector=service, authorize=approve,
            owned_session_run_id=runtime.owned_session_run_id, native_context_ref=deepcopy(runtime.native_context_ref))
        restored = WorkflowEngine.restore(WorkflowRunStore.open(store.folder),
                                         catalog=build_catalog(new_runtime), runtime=new_runtime)
        require(restored is engine and restored.runtime is runtime,
                "R60_CHECKPOINT_DID_NOT_REUSE_ORIGINAL_LIVE_EXECUTOR")
        complete = restored.resume()
        require(complete["state"] == "COMPLETED" and complete["cleanup"]["confirmed"] is True and
                [row["operation"] for row in approvals] == ["debug.attach", "debug.detach"] and len(launches) == 1 and
                next(row for row in complete["nodes"] if row["node_id"] == "attach") == preserved,
                "R60_CHECKPOINT_RESUME_REPLAYED_OR_LOST_ACTUAL_ACTION")
        require(service.helper is None and service._channel is None and runtime.native_context_ref is None and
                {row["resource"] for row in close_proofs} == {"pipe", "helper_process"},
                "R60_CHECKPOINT_ACTUAL_PRODUCT_OWNER_NOT_CLOSED")
        records, journal = independent_journal(store.folder)
        attached, detached = actual_invocations(records, "debug.attach"), actual_invocations(records, "debug.detach")
        require(len(attached) == len(detached) == 1 and detached[0][1]["execution_started"] is True,
                "R60_CHECKPOINT_ACTUAL_ACTION_RECEIPTS_NOT_PRESERVED")
        closes = [row for row in service.journal.timeline() if row.get("source") == "DIAGNOSTIC_SESSION_CLEANUP"]
        require(len(closes) == 1 and closes[0]["status"] == "COMPLETED",
                "R60_CHECKPOINT_NATIVE_OWNER_CLOSE_NOT_ACKNOWLEDGED")
        terminal = closes[0]["data"].get("expiry_cleanup", {})
        require(terminal.get("confirmed") is True and terminal.get("session_nonce_verified") is True and
                terminal.get("helper_identity") == helper_identity,
                "R60_CHECKPOINT_AUTHENTICATED_HELPER_CLOSE_REQUIRED")
        debug_ack = terminal.get("data", {}).get("cleanup", {}).get("data", {}).get(
            "debug_cleanup", {}).get("native_owner_cleanup", {})
        require(debug_ack.get("confirmed") is True and debug_ack.get("worker_exit_confirmed") is True,
                "R60_CHECKPOINT_NATIVE_DEBUG_WORKER_CLOSE_NOT_ACKNOWLEDGED")
        proof.update(status="PASS", graph_state=complete["state"], journal=journal, approvals=approvals,
            launches=launches, same_helper_identity=helper_identity, original_live_executor_reused=True,
            initial_session_scope_confirmation=scope_confirmation, unchanged_lease_deadline=lease_deadline,
            attach_replay_count=0, attach_receipt_unchanged=True, helper_debug_worker_exit_acknowledged=True,
            product_handle_close_observations=close_proofs, cleanup=complete["cleanup"])
    except BaseException as error:
        primary = error
        proof.update(status="FAIL", error=type(error).__name__, reason=str(error)[:1200])
        raise
    finally:
        cleanup_errors = []
        if engine is not None and engine.snapshot()["cleanup"].get("confirmed") is not True:
            try:
                engine.request_cancel()
                engine.resume()
            except BaseException as error:
                cleanup_errors.append("WORKFLOW:" + str(error)[:180])
        if service is not None:
            try:
                answer = service.close()
                require(answer.get("status") == "COMPLETED" and service.helper is None and service._channel is None,
                        "R60_CHECKPOINT_PRODUCT_CLEANUP_UNCONFIRMED")
            except BaseException as error:
                cleanup_errors.append("PRODUCT_OWNER:" + str(error)[:180])
        if fixture is not None:
            try:
                cleanup = fixture.close(kill=proof["status"] != "PASS")
                require(cleanup.get("status") == "COMPLETED", "R60_CHECKPOINT_TARGET_CLEANUP_UNCONFIRMED")
                proof["target_cleanup"] = cleanup
            except BaseException as error:
                cleanup_errors.append("TARGET_OWNER:" + str(error)[:180])
        if cleanup_errors:
            proof.update(status="FAIL", cleanup_errors=cleanup_errors)
        save(output / "result.json", proof)
        print("R60_NATIVE_CHECKPOINT_OUTCOME " + json.dumps(proof, sort_keys=True, ensure_ascii=True), flush=True)
        if cleanup_errors:
            if primary is not None:
                primary.add_note("R60_CHECKPOINT_CLEANUP_UNCONFIRMED: " + ";".join(cleanup_errors))
            else:
                raise AssertionError("R60_CHECKPOINT_CLEANUP_UNCONFIRMED: " + ";".join(cleanup_errors))
    return proof
