"""Real BB-DEEP-001 acceptance on disposable GitHub-hosted Windows runners.

The target is our compiled C program, never an unrelated running application.
No local execution, synthetic Windows success, or interactive UAC claim is made.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import struct
import subprocess
import sys
import threading
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]


def require(value: object, reason: str) -> None:
    if not value:
        raise AssertionError(reason)


def require_hosted_windows() -> None:
    require(os.name == "nt" and struct.calcsize("P") == 8 and
            os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
            "DISPOSABLE_GITHUB_HOSTED_WINDOWS_X64_REQUIRED")


def file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False,
                                    allow_nan=False), encoding="utf-8")
    os.replace(temporary, path)


def compiler_environment(output: Path) -> tuple[str, dict[str, str]]:
    """Use the installed Microsoft x64 build environment; never print its env."""
    compiler = shutil.which("cl.exe")
    if compiler:
        return compiler, dict(os.environ)
    installer = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    require(installer.is_file(), "WINDOWS_NATIVE_COMPILER_INSTALLATION_REQUIRED")
    discovered = subprocess.run([str(installer), "-latest", "-products", "*", "-requires",
                                 "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property",
                                 "installationPath"], capture_output=True,
                                text=True, errors="replace", timeout=20)
    (output / "compiler-discovery.log").write_text(
        discovered.stdout + discovered.stderr, encoding="utf-8")
    require(discovered.returncode == 0, "WINDOWS_NATIVE_COMPILER_DISCOVERY_FAILED")
    location = discovered.stdout.strip()
    require(bool(location) and "\n" not in location and '"' not in location,
            "WINDOWS_NATIVE_COMPILER_LOCATION_INVALID")
    setup = Path(location) / "VC/Auxiliary/Build/vcvars64.bat"
    require(setup.is_file(), "WINDOWS_X64_COMPILER_SETUP_REQUIRED")
    # cmd.exe does not use the CRT argv quoting implemented by list2cmdline:
    # a list containing `call "C:\\Program Files\\..."` inserts literal backslashes
    # before the quotes. Supply its raw command line, with /s's outer quotes.
    # Keep setup output separate: successful stdout contains the environment and
    # MUST NOT be persisted in artifacts, including on setup/compiler failures.
    command_processor = os.environ.get("COMSPEC", "cmd.exe")
    setup_log = output / "compiler-setup.log"
    require(all(not any(character in str(value) for character in ('"', '\r', '\n', '%', '!'))
                for value in (command_processor, setup, setup_log)),
            "WINDOWS_COMPILER_SETUP_PATH_UNSAFE")
    command = (f'"{command_processor}" /d /s /c "call "{setup}" '
               f'>"{setup_log}" 2>&1 && set"')
    result = subprocess.run(command, shell=False, capture_output=True,
                            text=True, errors="replace", timeout=45)
    if result.stderr:
        with setup_log.open("a", encoding="utf-8") as log:
            log.write(result.stderr)
    require(result.returncode == 0, "WINDOWS_X64_COMPILER_SETUP_FAILED_SEE_COMPILER_SETUP_LOG")
    environment = dict(os.environ)
    for line in result.stdout.splitlines():
        name, separator, value = line.partition("=")
        if separator and name and not name.startswith("="):
            environment[name] = value
    compiler = shutil.which("cl.exe", path=environment.get("Path", environment.get("PATH", "")))
    require(compiler, "WINDOWS_X64_COMPILER_NOT_READY")
    return str(compiler), environment


def build_probe(output: Path) -> Path:
    require_hosted_windows()
    output.mkdir(parents=True, exist_ok=False)
    compiler, environment = compiler_environment(output)
    source = ROOT / "tools/fixtures/DeepInspectionProbe/probe.c"
    executable = output / "deep-probe.exe"
    command = [compiler, "/nologo", "/W4", "/Od", "/Zi", "/MT", "/DUNICODE",
               "/D_UNICODE", "/Fe:" + str(executable), "/Fo:" + str(output / "deep-probe.obj"),
               "/Fd:" + str(output / "compiler.pdb"), str(source), "/link", "/DEBUG:FULL",
               "/PDB:" + str(output / "deep-probe.pdb"), "/INCREMENTAL:NO", "ws2_32.lib", "advapi32.lib"]
    compiled = subprocess.run(command, env=environment, capture_output=True,
                              text=True, errors="replace", timeout=90)
    (output / "compiler.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
    require(compiled.returncode == 0 and executable.is_file(),
            "CONTROLLED_NATIVE_PROBE_COMPILATION_FAILED")
    save(output / "build.json", {"source_sha256": file_hash(source),
                                  "executable_sha256": file_hash(executable),
                                  "pdb_sha256": file_hash(output / "deep-probe.pdb"),
                                  "compiler": compiler, "command": command,
                                  "source_sha": os.environ.get("GITHUB_SHA")})
    return executable


class Probe:
    """Owned native process with a bounded JSON line control channel."""

    def __init__(self, executable: Path, output: Path):
        from blackbox_core.optional_jobs import OwnedProcess
        require_hosted_windows()
        output.mkdir(parents=True, exist_ok=False)
        self.output = output
        self.path = output / "controlled-io.bin"
        self.stderr = (output / "probe-stderr.log").open("wb")
        self.owner = None
        self.reader = None
        self.lines: queue.Queue = queue.Queue(maxsize=32)
        try:
            self.owner = OwnedProcess([str(executable.resolve(strict=True)), str(self.path)],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=self.stderr, detach_console=True)
            self.process = self.owner.process
            self.reader = threading.Thread(target=self._reader, name="deep-qa-probe-reader", daemon=True)
            self.reader.start()
            self.ready = self.receive("ready", timeout=15)
            require(self.ready["pid"] == self.process.pid and self.ready["created_100ns"] > 0,
                    "NATIVE_PROBE_PROCESS_IDENTITY_MISMATCH")
            require(self.ready["buffer_hex"] == bytes(i ^ 0x5A for i in range(64)).hex(),
                    "KNOWN_NATIVE_MEMORY_ORACLE_MISMATCH")
            save(output / "oracle.json", self.ready)
        except BaseException:
            self.close(kill=True)
            raise

    def _reader(self) -> None:
        try:
            while True:
                line = self.process.stdout.readline(16 * 1024 + 1)
                if not line:
                    self.lines.put_nowait(EOFError("NATIVE_PROBE_PIPE_CLOSED"))
                    return
                if len(line) > 16 * 1024 or not line.endswith(b"\n"):
                    raise ValueError("NATIVE_PROBE_RESPONSE_LIMIT")
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("NATIVE_PROBE_RESPONSE_TYPE")
                self.lines.put_nowait(value)
        except BaseException as error:
            try:
                self.lines.put_nowait(error)
            except queue.Full:
                pass

    def send(self, command: str) -> None:
        require(command in {"state", "call", "stop", "deny_read", "allow_read"}, "NATIVE_PROBE_COMMAND_NOT_ALLOWED")
        require(self.process.poll() is None, "NATIVE_PROBE_NOT_RUNNING")
        self.process.stdin.write((command + "\n").encode("ascii"))
        self.process.stdin.flush()

    def receive(self, kind: str, *, timeout: float = 10) -> dict:
        try:
            value = self.lines.get(timeout=timeout)
        except queue.Empty as error:
            raise TimeoutError("NATIVE_PROBE_RESPONSE_TIMEOUT_" + kind) from error
        if isinstance(value, BaseException):
            raise value
        require(value.get("kind") == kind, "NATIVE_PROBE_UNEXPECTED_RESPONSE_" + repr(value))
        return value

    def state(self) -> dict:
        self.send("state")
        return self.receive("state")

    def progress(self, before: dict, *, timeout: float = 6) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.state()
            if all(result[key] > before[key] for key in ("heartbeat", "io_cycles", "network_cycles")):
                return result
            threading.Event().wait(.1)
        raise AssertionError("NATIVE_HEARTBEAT_FILE_AND_NETWORK_PROGRESS_NOT_CONFIRMED")

    def close(self, *, kill: bool = False) -> dict:
        result = {"status": "NOT_STARTED"}
        try:
            if self.owner is not None:
                if self.process.poll() is None and not kill:
                    self.send("stop")
                    stopped = self.receive("stopped", timeout=12)
                    self.process.wait(timeout=8)
                    require(self.process.returncode == 0, "NATIVE_PROBE_GRACEFUL_EXIT_FAILED")
                    result = {"status": "COMPLETED", "exit_code": 0, "last_state": stopped}
                else:
                    result = {"status": "KILLED_FOR_QA_CLEANUP" if kill else "EXITED",
                              "exit_code": self.process.poll()}
        finally:
            if self.owner is not None:
                self.owner.close(kill=True)
                for stream in (self.process.stdin, self.process.stdout):
                    if stream:
                        stream.close()
                if self.reader is not None:
                    self.reader.join(timeout=2)
                self.owner = None
            self.stderr.close()
        return result


def minidump_evidence(path: Path, *, full: bool, expected_address: int | None = None,
                      expected_hex: str | None = None) -> dict:
    """Validate real minidump directory bounds and required stream kinds."""
    length = path.stat().st_size
    require(32 <= length <= 512 * 1024 * 1024, "MINIDUMP_SIZE_OUT_OF_BOUNDS")
    with path.open("rb") as stream:
        header = stream.read(32)
        signature, version, count, directory_rva, checksum, timestamp, flags = struct.unpack("<6IQ", header)
        require(signature == 0x504D444D and (version & 0xFFFF) == 0xA793,
                "REAL_WINDOWS_MINIDUMP_HEADER_REQUIRED")
        require(0 < count <= 4096 and 32 <= directory_rva <= length - count * 12,
                "MINIDUMP_DIRECTORY_OUT_OF_BOUNDS")
        stream.seek(directory_rva)
        entries = []
        for _ in range(count):
            kind, size, rva = struct.unpack("<III", stream.read(12))
            require(rva <= length and size <= length - rva, "MINIDUMP_STREAM_OUT_OF_BOUNDS")
            entries.append({"type": kind, "size": size, "rva": rva})
        kinds = {entry["type"] for entry in entries}
        require(3 in kinds and 4 in kinds and 7 in kinds, "MINIDUMP_THREADS_MODULES_SYSTEM_REQUIRED")
        counts = {}
        for kind, item_size, label in ((3, 48, "threads"), (4, 108, "modules")):
            entry = next(item for item in entries if item["type"] == kind)
            require(entry["size"] >= 4, "MINIDUMP_LIST_HEADER_MISSING_" + label)
            stream.seek(entry["rva"])
            item_count = struct.unpack("<I", stream.read(4))[0]
            require(0 < item_count <= (entry["size"] - 4) // item_size,
                    "MINIDUMP_LIST_ITEMS_INVALID_" + label)
            counts[label] = item_count
        system = next(item for item in entries if item["type"] == 7)
        require(system["size"] >= 56, "MINIDUMP_SYSTEM_STREAM_TRUNCATED")
        known_buffer_verified = False
        if full:
            require(9 in kinds and flags & 0x2, "EXTENDED_DUMP_MEMORY64_STREAM_REQUIRED")
            memory = next(item for item in entries if item["type"] == 9)
            require(memory["size"] >= 16, "MINIDUMP_MEMORY64_HEADER_MISSING")
            stream.seek(memory["rva"])
            regions, payload_offset = struct.unpack("<QQ", stream.read(16))
            require(0 < regions <= (memory["size"] - 16) // 16 and payload_offset <= length,
                    "MINIDUMP_MEMORY64_DIRECTORY_INVALID")
            ranges = [struct.unpack("<QQ", stream.read(16)) for _ in range(regions)]
            offset = payload_offset
            expected = bytes.fromhex(expected_hex) if expected_hex is not None else None
            for address, size in ranges:
                require(size <= length - offset, "MINIDUMP_MEMORY64_PAYLOAD_TRUNCATED")
                if expected_address is not None and expected is not None and address <= expected_address and \
                        expected_address + len(expected) <= address + size:
                    stream.seek(offset + expected_address - address)
                    require(stream.read(len(expected)) == expected, "FULL_DUMP_KNOWN_MEMORY_DIFFERS_FROM_LIVE_ORACLE")
                    known_buffer_verified = True
                offset += size
            if expected is not None:
                require(known_buffer_verified, "FULL_DUMP_KNOWN_NATIVE_BUFFER_NOT_PRESENT")
            counts["memory64_regions"] = regions
    return {"status": "PASS", "bytes": length, "sha256": file_hash(path),
            "flags": flags, "streams": entries, "full_requested": full,
            "counts": counts, "known_native_buffer_verified": known_buffer_verified,
            "source": "ACTUAL_MINIDUMPWRITEDUMP_CONTROLLED_NATIVE_TARGET"}


def rows(result: dict) -> list[dict]:
    value = result.get("data", {}).get("rows", [])
    require(isinstance(value, list), "OPERATION_ROWS_NOT_LIST")
    return value


class Acceptance:
    def __init__(self, output: Path, probe: Probe, *, helper: Path | None = None):
        from blackbox_core.deep_service import InspectorService
        self.output, self.probe = output, probe
        self.helper = helper
        self.service = InspectorService(journal_root=output / "journal", helper_executable=helper)
        self.identity = self.service.identity(probe.process.pid)
        require(self.identity.created_100ns == probe.ready["created_100ns"],
                "INSPECTOR_TARGET_CREATION_TIME_DIFFERS_FROM_NATIVE_ORACLE")
        self.operations: list[dict] = []

    def perform(self, operation: str, parameters: dict | None = None, *, confirmed: bool = False,
                statuses: tuple[str, ...] = ("COMPLETED",), timeout: float = 15,
                target: Any = None, cancel_event: threading.Event | None = None) -> dict:
        from blackbox_core.deep_contracts import ActionRequest
        started = time.monotonic()
        response = self.service.execute(ActionRequest(operation=operation,
                                                      target=target or self.identity,
                                                      parameters=parameters or {}, confirmed=confirmed,
                                                      timeout_seconds=timeout),
                                        cancel_event=cancel_event)
        require(isinstance(response, dict), "ACTION_RESULT_NOT_OBJECT")
        from blackbox_core.deep_journal import journal_metadata
        self.operations.append({"requested_operation": operation,
                                "elapsed_seconds": time.monotonic() - started,
                                "result": journal_metadata(response)})
        save(self.output / "operations.json", self.operations)
        require(response.get("status") in statuses,
                "UNEXPECTED_" + operation + "_STATUS_" + str(response.get("status")) +
                ":" + str(response.get("error"))[:700])
        require(response.get("operation_id"), "ACTION_OPERATION_ID_MISSING")
        return response

    def inspect(self) -> dict:
        oracle = self.probe.ready
        result: dict[str, Any] = {}
        processes = self.perform("processes", statuses=("COMPLETED", "INCOMPLETE_EVIDENCE"))
        require(any(row.get("pid") == oracle["pid"] for row in rows(processes)),
                "OWNED_PROCESS_NOT_ENUMERATED")
        modules = self.perform("modules", statuses=("COMPLETED", "INCOMPLETE_EVIDENCE"))
        own_modules = [row for row in rows(modules) if int(row.get("base", 0)) <= oracle["function_address"] <
                       int(row.get("base", 0)) + int(row.get("size", 0))]
        require(own_modules, "BREAKPOINT_ADDRESS_NOT_BOUND_TO_REAL_NATIVE_MODULE")
        result["owned_module"] = own_modules
        threads = self.perform("threads", statuses=("COMPLETED", "INCOMPLETE_EVIDENCE"))
        require(any(row.get("tid") == oracle["wait_tid"] and
                    row.get("created_100ns") == oracle["wait_thread_created_100ns"] for row in rows(threads)),
                "OWNED_WAIT_THREAD_IDENTITY_NOT_ENUMERATED")
        handles = self.perform("handles", statuses=("COMPLETED", "INCOMPLETE_EVIDENCE"), timeout=30)
        require(rows(handles), "REAL_HANDLE_INVENTORY_EMPTY")
        mapping = self.perform("memory_map", statuses=("COMPLETED", "INCOMPLETE_EVIDENCE"))
        address = oracle["buffer_address"]
        require(any(int(row.get("base", row.get("address", 0))) <= address <
                    int(row.get("base", row.get("address", 0))) + int(row.get("size", 0))
                    for row in rows(mapping)), "KNOWN_NATIVE_BUFFER_REGION_NOT_ENUMERATED")
        memory = self.perform("memory_read", {"address": address, "length": 64})
        require(memory["data"].get("hex") == oracle["buffer_hex"] and
                memory["data"].get("bytes_read") == 64, "NATIVE_MEMORY_READ_DIFFERS_FROM_ORACLE")
        stacks = self.perform("thread_stacks", {"tid": oracle["wait_tid"],
                                               "thread_created_100ns": oracle["wait_thread_created_100ns"]},
                              confirmed=True, statuses=("COMPLETED", "INCOMPLETE_EVIDENCE"), timeout=30)
        require(any(row.get("tid") == oracle["wait_tid"] and row.get("frames") for row in rows(stacks)),
                "LIVE_OWNED_THREAD_STACK_NOT_COLLECTED")
        waiting_stack = next(row for row in rows(stacks) if row.get("tid") == oracle["wait_tid"])
        frames = waiting_stack["frames"]
        require(len({frame.get("address") for frame in frames}) >= 2,
                "LIVE_STACK_HAS_ONLY_INITIAL_CONTEXT_NOT_UNWOUND_CALLERS")
        require(any(module["base"] <= frame.get("address", 0) < module["base"] + module["size"]
                    for frame in frames for module in own_modules),
                "LIVE_WAIT_STACK_DID_NOT_REACH_CONTROLLED_NATIVE_CALLER")
        result["wait_stack"] = {"distinct_frame_addresses": len({frame["address"] for frame in frames}),
                                "controlled_native_module_frame_observed": True}
        wait = self.perform("wait_chains", {"tid": oracle["wait_tid"],
                                            "thread_created_100ns": oracle["wait_thread_created_100ns"]},
                            statuses=("COMPLETED", "INCOMPLETE_EVIDENCE"))
        require(any(row.get("tid") == oracle["wait_tid"] for row in rows(wait)),
                "OWNED_THREAD_WAIT_CHAIN_NOT_RETURNED")
        network = self.perform("network", statuses=("COMPLETED", "INCOMPLETE_EVIDENCE"))
        result["network_rows"] = rows(network)
        for key, protocol in (("tcp4_port", "TCP"), ("tcp6_port", "TCP"),
                              ("udp4_port", "UDP"), ("udp6_port", "UDP")):
            matching = [row for row in rows(network) if row.get("protocol") == protocol
                        and row.get("family") == ("IPv6" if "6" in key else "IPv4")
                        and isinstance(row.get("local"), dict)
                        and row["local"].get("port") == oracle[key]]
            require(matching, "REAL_LOOPBACK_ENDPOINT_NOT_OBSERVED_" + key)
        disk = self.perform("disk", statuses=("COMPLETED", "INCOMPLETE_EVIDENCE"))
        require(disk.get("data"), "DISK_OBSERVATION_EMPTY")
        result["workload_after_inspection"] = self.probe.progress(oracle)
        result["operation_names"] = [item["requested_operation"] for item in self.operations]
        return result

    def intervention(self) -> dict:
        oracle = self.probe.ready
        address = oracle["buffer_address"]
        expected = oracle["buffer_hex"]
        changed = bytes((i ^ 0xA5) for i in range(64)).hex()
        rejected = self.perform("memory.write", {"address": address, "expected_hex": "00" * 64,
                                                  "value_hex": changed}, confirmed=True,
                                statuses=("OPERATION_FAILED", "PRECONDITION_FAILED", "INCOMPLETE_EVIDENCE"))
        require(self.probe.state()["buffer_hex"] == expected,
                "FAILED_EXPECTED_BYTE_COMPARISON_CHANGED_NATIVE_MEMORY")
        unconfirmed = self.perform("memory.write", {"address": address, "expected_hex": expected,
                                                     "value_hex": changed},
                                   statuses=("CONFIRMATION_REQUIRED", "OPERATION_FAILED"))
        require(self.probe.state()["buffer_hex"] == expected,
                "UNCONFIRMED_OPERATION_CHANGED_NATIVE_MEMORY")
        write = self.perform("memory.write", {"address": address, "expected_hex": expected,
                                              "value_hex": changed}, confirmed=True)
        require(self.probe.state()["buffer_hex"] == changed, "NATIVE_TARGET_DID_NOT_OBSERVE_CHANGED_BYTES")
        change_id = write["data"]["change_id"]
        restored = self.perform("memory.rollback", {"change_id": change_id}, confirmed=True)
        require(self.probe.state()["buffer_hex"] == expected, "NATIVE_TARGET_DID_NOT_CONFIRM_RESTORED_BYTES")

        thread = {"tid": oracle["heartbeat_tid"],
                  "thread_created_100ns": oracle["heartbeat_thread_created_100ns"]}
        suspended = self.perform("thread.suspend", thread, confirmed=True)
        before = self.probe.state()
        deadline = time.monotonic() + 5
        stopped = before
        while stopped["io_cycles"] == before["io_cycles"] and time.monotonic() < deadline:
            threading.Event().wait(.1)
            stopped = self.probe.state()
        require(stopped["heartbeat"] == before["heartbeat"] and
                stopped["io_cycles"] > before["io_cycles"],
                "ONLY_OWNED_HEARTBEAT_THREAD_SUSPENSION_NOT_CONFIRMED")
        resumed = self.perform("thread.resume", thread, confirmed=True)
        self.probe.progress(stopped)
        preexisting_suspension = self.preserve_external_suspension(thread)

        protection = {"before_attach": self.code_protection()}
        attached = self.perform("debug.attach", confirmed=True, timeout=25)
        from blackbox_core.deep_service import InspectorService
        from blackbox_core.deep_contracts import ActionRequest
        competitor = InspectorService(journal_root=self.output / "second-debugger-journal",
                                      helper_executable=self.helper)
        try:
            second_attach = competitor.execute(ActionRequest("debug.attach", self.identity,
                                                             confirmed=True, timeout_seconds=15))
            require(second_attach.get("status") == "ALREADY_DEBUGGED",
                    "SECOND_REAL_DEBUGGER_NOT_REJECTED_AS_ALREADY_DEBUGGED")
        finally:
            second_cleanup = competitor.close()
        paused = self.perform("debug.pause", confirmed=True)
        context = self.perform("debug.context")
        require(context.get("data"), "PAUSED_THREAD_CONTEXT_EMPTY")
        bp = self.perform("debug.breakpoint.add", {"address": oracle["function_address"]}, confirmed=True)
        protection["after_add"] = self.code_protection(protection["before_attach"])
        breakpoint_id = bp["data"]["breakpoint_id"]
        self.perform("debug.continue", confirmed=True)
        self.probe.send("call")
        deadline = time.monotonic() + 8
        hit = None
        while time.monotonic() < deadline:
            state = self.perform("debug.context", statuses=("COMPLETED", "OPERATION_FAILED", "INCOMPLETE_EVIDENCE"))
            if (state.get("status") == "COMPLETED" and
                    state.get("data", {}).get("tid") == oracle["main_tid"] and
                    state["data"].get("registers", {}).get("rip") == oracle["function_address"]):
                hit = state
                break
            threading.Event().wait(.05)
        require(hit, "CONTROLLED_NATIVE_BREAKPOINT_HIT_NOT_OBSERVED")
        protection["after_hit"] = self.code_protection(protection["before_attach"])
        stepped = self.perform("debug.step", confirmed=True)
        require(stepped.get("data", {}).get("state") == "PAUSED", "NATIVE_SINGLE_STEP_DID_NOT_STOP")
        self.perform("debug.breakpoint.disable", {"breakpoint_id": breakpoint_id}, confirmed=True)
        self.perform("debug.breakpoint.remove", {"breakpoint_id": breakpoint_id}, confirmed=True)
        protection["after_remove"] = self.code_protection(protection["before_attach"])
        self.perform("debug.continue", confirmed=True)
        called = self.probe.receive("called", timeout=10)
        require(called["result"] == 137 and called["calls"] == 1,
                "NATIVE_FUNCTION_SEMANTICS_CHANGED_BY_BREAKPOINT_OR_STEP")
        detach = self.perform("debug.detach", confirmed=True)
        protection["after_detach"] = self.code_protection(protection["before_attach"])
        self.probe.progress(before)
        return {"expected_bytes_rejected": rejected["status"], "unconfirmed_rejected": unconfirmed["status"],
                "memory_change_id": change_id, "rollback": restored,
                "thread_suspend": suspended, "thread_resume": resumed,
                "preexisting_suspension_preserved": preexisting_suspension,
                "attach": attached, "pause": paused, "breakpoint_hit": hit,
                "single_step": stepped, "detach": detach, "target_function": called,
                "code_page_protection": protection,
                "already_debugged": second_attach, "second_debugger_cleanup": second_cleanup}

    def code_protection(self, expected: dict | None = None) -> dict:
        """Independent VirtualQueryEx against Popen's still-owned process handle."""
        import ctypes as C
        from ctypes import wintypes as W

        class MemoryBasicInformation(C.Structure):
            _fields_ = [("base", C.c_void_p), ("allocation_base", C.c_void_p),
                        ("allocation_protect", W.DWORD), ("partition", W.WORD),
                        ("region_size", C.c_size_t), ("state", W.DWORD),
                        ("protect", W.DWORD), ("kind", W.DWORD)]

        query = C.WinDLL("kernel32", use_last_error=True).VirtualQueryEx
        query.argtypes = [W.HANDLE, C.c_void_p, C.POINTER(MemoryBasicInformation), C.c_size_t]
        query.restype = C.c_size_t
        info = MemoryBasicInformation()
        address = self.probe.ready["function_address"]
        require(C.sizeof(info) == 48 and
                query(W.HANDLE(int(self.probe.process._handle)), address, C.byref(info), C.sizeof(info)) == C.sizeof(info),
                "INDEPENDENT_BREAKPOINT_PAGE_PROTECTION_QUERY_FAILED")
        result = {"base": info.base, "allocation_base": info.allocation_base,
                  "region_size": info.region_size, "state": info.state,
                  "protect": info.protect, "kind": info.kind}
        require(info.base <= address < info.base + info.region_size and info.state == 0x1000,
                "BREAKPOINT_PAGE_NOT_COMMITTED")
        if expected is not None:
            require(result == expected, "BREAKPOINT_PAGE_PROTECTION_NOT_RESTORED_TO_BASELINE")
        return result

    def profiling(self, permission: str) -> dict:
        """Capture real fixture activity; lack of privilege is not a trace result."""
        destination = self.output / "profile-controlled.etl"
        parameters = {"destination": str(destination), "duration_seconds": 5,
                      "profile": "GeneralProfile.Light", "systemwide_confirmed": True}
        before = self.probe.state()
        result = self.perform("profile.etw", parameters, confirmed=True, timeout=120,
                              statuses=("COMPLETED",) if permission == "ADMINISTRATOR" else ("ADMIN_REQUIRED",))
        after = self.probe.progress(before)
        if permission != "ADMINISTRATOR":
            require(not destination.exists(), "UNPRIVILEGED_PROFILE_CREATED_OUTPUT_BEFORE_UAC")
            return {"status": "PASS", "capture_status": "ADMIN_REQUIRED", "operation": result,
                    "native_capture_executed": False, "interactive_uac": "NOT_TESTED"}
        require(destination.is_file() and 0 < destination.stat().st_size <= 256 * 1024 * 1024,
                "REAL_ETW_PROFILE_OUTPUT_MISSING_OR_UNBOUNDED")
        require(after["created_100ns"] == before["created_100ns"] == self.identity.created_100ns,
                "PROFILE_FIXTURE_INSTANCE_CHANGED")
        return {"status": "PASS", "capture_status": "COMPLETED", "operation": result,
                "native_capture_executed": True, "requested_duration_seconds": 5,
                "trace": destination.name, "bytes": destination.stat().st_size,
                "sha256": file_hash(destination), "target_instance": self.identity.to_dict(),
                "fixture_oracle": "probe/oracle.json",
                "workload_before": before, "workload_after": after,
                "decoded_io_oracle": "REQUIRES_SEPARATE_DECODER_VALIDATION",
                "scope": "SYSTEMWIDE_ETW_METADATA_WITH_OWNED_FIXTURE_ACTIVITY"}

    def preserve_external_suspension(self, thread: dict) -> dict:
        """An independent native caller owns one increment throughout helper actions."""
        import ctypes as C
        from ctypes import wintypes as W
        kernel = C.WinDLL("kernel32", use_last_error=True)
        kernel.OpenThread.argtypes = [W.DWORD, W.BOOL, W.DWORD]
        kernel.OpenThread.restype = W.HANDLE
        kernel.GetProcessIdOfThread.argtypes = [W.HANDLE]
        kernel.GetProcessIdOfThread.restype = W.DWORD
        kernel.GetThreadTimes.argtypes = [W.HANDLE] + [C.POINTER(W.FILETIME)] * 4
        kernel.GetThreadTimes.restype = W.BOOL
        kernel.CloseHandle.argtypes = [W.HANDLE]
        kernel.CloseHandle.restype = W.BOOL
        for name in ("SuspendThread", "ResumeThread"):
            getattr(kernel, name).argtypes = [W.HANDLE]
            getattr(kernel, name).restype = W.DWORD
        handle = kernel.OpenThread(0x0002 | 0x0800, False, thread["tid"])
        require(handle, "QA_EXTERNAL_SUSPENSION_THREAD_OPEN_FAILED")
        increment_owned = False
        proof = {"source": "INDEPENDENT_QA_WIN32_SUSPEND_RESUME_ON_EXACT_FIXTURE_THREAD"}
        try:
            times = [W.FILETIME() for _ in range(4)]
            require(kernel.GetProcessIdOfThread(handle) == self.probe.ready["pid"] and
                    kernel.GetThreadTimes(handle, *(C.byref(value) for value in times)),
                    "QA_EXTERNAL_SUSPENSION_THREAD_IDENTITY_UNAVAILABLE")
            created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            require(created == thread["thread_created_100ns"],
                    "QA_EXTERNAL_SUSPENSION_THREAD_INSTANCE_CHANGED")
            previous = kernel.SuspendThread(handle)
            require(previous != 0xFFFFFFFF, "QA_EXTERNAL_SUSPENSION_FAILED")
            increment_owned = True
            proof["qa_initial_count"] = previous
            require(previous == 0, "CONTROLLED_FIXTURE_ALREADY_SUSPENDED_EXTERNALLY")
            suspended = self.perform("thread.suspend", thread, confirmed=True)
            require(suspended["data"]["previous_suspend_count"] == 1,
                    "HELPER_DID_NOT_OBSERVE_EXISTING_SUSPENSION")
            resumed = self.perform("thread.resume", thread, confirmed=True)
            require(resumed["data"]["remaining_suspend_count_observed"] == 1,
                    "HELPER_DID_NOT_PRESERVE_EXISTING_SUSPENSION")
            before = self.probe.state()
            deadline = time.monotonic() + 5
            after = before
            while after["io_cycles"] == before["io_cycles"] and time.monotonic() < deadline:
                threading.Event().wait(.1)
                after = self.probe.state()
            require(after["heartbeat"] == before["heartbeat"] and
                    after["io_cycles"] > before["io_cycles"],
                    "PREEXISTING_THREAD_SUSPENSION_NOT_INDEPENDENTLY_CONFIRMED")
            proof.update(helper_increment=suspended, helper_decrement=resumed,
                         heartbeat_remained_stopped=True, other_threads_progressed=True)
        finally:
            try:
                if increment_owned:
                    previous = kernel.ResumeThread(handle)
                    proof["qa_final_previous_count"] = previous
                    require(previous == 1, "QA_OWN_SUSPENSION_CLEANUP_NOT_CONFIRMED")
            finally:
                kernel.CloseHandle(handle)
        self.probe.progress(after)
        proof["status"] = "PASS"
        return proof

    def negatives(self) -> dict:
        changed_identity = replace(self.identity, created_100ns=self.identity.created_100ns + 1)
        mismatch = self.perform("memory_read", {"address": self.probe.ready["buffer_address"], "length": 64},
                                target=changed_identity, statuses=("PROCESS_CHANGED",))
        cancelled = threading.Event()
        cancelled.set()
        cancellation = self.perform("modules", cancel_event=cancelled,
                                    statuses=("CANCELLED", "OPERATION_CANCELLED"))
        return {"mismatched_creation_identity": mismatch,
                "pre_start_cancellation": cancellation,
                "pid_recycling": "IDENTITY_MISMATCH_REJECTION; ACTUAL_OS_PID_RECYCLING_NOT_FORCED",
                "protected_process": "NOT_PROBED_NO_UNRELATED_SYSTEM_TARGETS"}

    def access_denial(self) -> dict:
        self.probe.send("deny_read")
        changed = self.probe.receive("permissions")
        require(changed.get("ok") is True, "CONTROLLED_PROCESS_READ_DENY_DACL_NOT_ESTABLISHED")
        try:
            denied = self.perform("memory_read", {"address": self.probe.ready["buffer_address"], "length": 64},
                                  statuses=("ACCESS_DENIED", "ADMIN_REQUIRED"))
            require(denied.get("status") != "PROTECTED_PROCESS",
                    "ORDINARY_DACL_DENIAL_MISLABELLED_AS_PROTECTED_PROCESS")
        finally:
            self.probe.send("allow_read")
            restored = self.probe.receive("permissions")
            require(restored.get("ok") is True, "CONTROLLED_PROCESS_DACL_RESTORATION_FAILED")
        readback = self.perform("memory_read", {"address": self.probe.ready["buffer_address"], "length": 64})
        require(readback["data"].get("hex") == self.probe.ready["buffer_hex"],
                "READ_NOT_RECOVERED_AFTER_CONTROLLED_PROCESS_DACL_RESTORE")
        return {"status": "PASS", "source": "ACTUAL_WINDOWS_DACL_DENIED_PROCESS_VM_READ_ON_OWNED_FIXTURE",
                "denial": denied, "dacl_restored": True, "read_after_restore": readback["status"],
                "system_policy_or_account_changed": False}

    def dumps(self) -> list[dict]:
        output = []
        private = self.output / "private-controlled-dumps"
        private.mkdir(exist_ok=False)
        for full in (False, True):
            destination = private / ("extended.dmp" if full else "normal.dmp")
            require(not destination.exists(), "CONTROLLED_DUMP_DESTINATION_ALREADY_EXISTS")
            try:
                result = self.perform("dump", {"path": str(destination), "full": full,
                                                "max_bytes": 256 * 1024 * 1024},
                                      confirmed=True, timeout=60)
                evidence = minidump_evidence(destination, full=full,
                                             expected_address=self.probe.ready["buffer_address"] if full else None,
                                             expected_hex=self.probe.ready["buffer_hex"] if full else None)
                output.append({"operation_id": result["operation_id"], **evidence})
            finally:
                # This directory was created exclusively by this QA invocation.
                # Even partial/corrupt dumps can contain inherited environment
                # values. Never preserve them in ordinary uploaded evidence.
                destination.unlink(missing_ok=True)
            output[-1]["raw_dump_retained_in_shared_evidence"] = False
        return output

    def compare_and_journal(self) -> dict:
        before = self.perform("snapshot", statuses=("COMPLETED", "INCOMPLETE_EVIDENCE"))
        self.probe.progress(self.probe.state())
        after = self.perform("snapshot", statuses=("COMPLETED", "INCOMPLETE_EVIDENCE"))
        before_id, after_id = before["data"]["snapshot_id"], after["data"]["snapshot_id"]
        require(before_id != after_id, "BEFORE_AFTER_SNAPSHOT_ID_REUSED")
        comparison = self.perform("compare", {"before_id": before_id, "after_id": after_id})
        require(comparison["data"].get("before_id") == before_id and
                comparison["data"].get("after_id") == after_id,
                "BEFORE_AFTER_COMPARISON_LOST_ORIGINAL_IDENTITIES")
        timeline = self.perform("timeline")
        entries = timeline.get("data", {}).get("entries", [])
        require(len(entries) >= 2, "DIAGNOSTIC_ACTION_JOURNAL_EMPTY")
        # The normal journal must not acquire either the known original buffer
        # or our replacement bytes merely because a memory action was performed.
        serialized = json.dumps(entries, ensure_ascii=False)
        require(self.probe.ready["buffer_hex"] not in serialized and
                bytes(i ^ 0xA5 for i in range(64)).hex() not in serialized,
                "NORMAL_ACTION_JOURNAL_LEAKED_RAW_MEMORY_BYTES")
        return {"before_id": before_id, "after_id": after_id, "comparison": comparison,
                "journal_entry_count": len(entries), "normal_journal_raw_memory_omitted": True}

    def crash_recovery(self) -> dict:
        """Kill only our helper and independently check our controlled target."""
        import psutil
        oracle = self.probe.ready
        expected = oracle["buffer_hex"]
        changed = bytes(i ^ 0xA5 for i in range(64)).hex()
        protection_before = self.code_protection()
        self.perform("debug.attach", confirmed=True, timeout=25)
        self.perform("debug.breakpoint.add", {"address": oracle["function_address"]}, confirmed=True)
        self.perform("memory.write", {"address": oracle["buffer_address"],
                                       "expected_hex": expected, "value_hex": changed}, confirmed=True)
        self.perform("thread.suspend", {"tid": oracle["heartbeat_tid"],
                                         "thread_created_100ns": oracle["heartbeat_thread_created_100ns"]},
                     confirmed=True)
        self.perform("debug.continue", confirmed=True)
        before = self.probe.state()
        require(before["buffer_hex"] == changed, "CRASH_FIXTURE_MUTATION_NOT_ESTABLISHED")
        helper_pid = self.service.helper_pid
        helper = psutil.Process(helper_pid)
        helper_created = helper.create_time()
        require(helper_pid not in (os.getpid(), oracle["pid"]) and
                helper_pid == self.service.helper_pid, "CRASH_QA_HELPER_OWNERSHIP_NOT_CONFIRMED")
        helper.kill()
        helper.wait(timeout=10)
        deadline = time.monotonic() + 20
        recovered = None
        while time.monotonic() < deadline:
            require(self.probe.process.poll() is None, "TARGET_DIED_WHEN_DIAGNOSTIC_HELPER_CRASHED")
            observed = self.probe.state()
            if (observed["buffer_hex"] == expected and observed["heartbeat"] > before["heartbeat"] and
                    observed["io_cycles"] > before["io_cycles"] and
                    observed["network_cycles"] > before["network_cycles"]):
                recovered = observed
                break
            threading.Event().wait(.2)
        require(recovered, "CONTROLLED_TARGET_RECOVERY_AFTER_HELPER_CRASH_NOT_CONFIRMED")
        protection_after = self.code_protection(protection_before)
        # The breakpoint address was not executed during the crash window.
        # Calling it only after guardian restoration proves the selected code
        # byte is usable; it does not generalize to arbitrary crash timing.
        self.probe.send("call")
        called = self.probe.receive("called", timeout=10)
        require(called["result"] == 137 and called["calls"] == before["breakpoint_calls"] + 1,
                "BREAKPOINT_CODE_RECOVERY_AFTER_HELPER_CRASH_NOT_CONFIRMED")
        closed = self.service.close()
        require(closed.get("status") in ("COMPLETED", "RECOVERY_UNCONFIRMED"),
                "CRASHED_HELPER_RECOVERY_STATUS_NOT_EXPLICIT")
        return {"status": "PASS", "killed_owned_helper_pid": helper_pid,
                "killed_owned_helper_created": helper_created,
                "target_instance": self.identity.to_dict(),
                "target_progress_verified": True, "selected_bytes_restored_verified": True,
                "own_thread_resumed_verified": True, "breakpoint_function_after_crash": called,
                "code_page_protection_before": protection_before,
                "code_page_protection_after": protection_after,
                "service_recovery": closed,
                "limitation": "CONTROLLED_CRASH_WHILE_BREAKPOINT_NOT_EXECUTING; ARBITRARY_INSTRUCTION_TIMING_NOT_PROVEN"}


def exited_target_check(output: Path, executable: Path, helper: Path | None) -> dict:
    from blackbox_core.deep_contracts import ActionRequest
    from blackbox_core.deep_service import InspectorService
    probe = Probe(executable, output / "exited-probe")
    service = InspectorService(journal_root=output / "exit-race-journal", helper_executable=helper)
    try:
        identity = service.identity(probe.process.pid)
        address = probe.ready["buffer_address"]
        cleanup = probe.close()
        result = service.execute(ActionRequest("memory_read", identity, {"address": address, "length": 64}))
        require(result.get("status") == "PROCESS_CHANGED", "EXITED_TARGET_WAS_NOT_REJECTED")
        return {"status": "PASS", "target": identity.to_dict(), "target_cleanup": cleanup,
                "operation_result": result}
    finally:
        service.close()
        if probe.owner is not None:
            probe.close(kill=True)


def run_acceptance(output: Path, executable: Path, helper: Path | None) -> dict:
    from blackbox_core.windows_research import privilege
    require_hosted_windows()
    proof: dict[str, Any] = {"status": "RUNNING", "source_sha": os.environ.get("GITHUB_SHA"),
                             "runner_environment": os.environ.get("RUNNER_ENVIRONMENT"),
                             "pid": os.getpid(), "privilege": privilege(),
                             "scope": "REAL_OWNED_WINDOWS_NATIVE_INSPECT_AND_INTERVENE",
                             "interactive_uac_secure_desktop": "NOT_TESTED_GITHUB_HOSTED_RUNNER",
                             "physical_windows_10_11": "NOT_TESTED",
                             "probe_sha256": file_hash(executable)}
    probe = None
    acceptance = None
    try:
        probe = Probe(executable, output / "probe")
        acceptance = Acceptance(output, probe, helper=helper)
        proof["target"] = acceptance.identity.to_dict()
        proof["inspection"] = acceptance.inspect()
        proof["helper_pid"] = acceptance.service.helper_pid
        proof["helper_session"] = acceptance.service.session_status()
        require(proof["helper_pid"] and proof["helper_pid"] != os.getpid() and
                proof["helper_pid"] != probe.process.pid, "OWNED_DIAGNOSTIC_HELPER_REQUIRED")
        require(proof["helper_session"].get("permission_level") == proof["privilege"]["mode"],
                "HELPER_TOKEN_LEVEL_DIFFERS_FROM_ACTUAL_PARENT_TOKEN")
        proof["profiling"] = acceptance.profiling(proof["privilege"]["mode"])
        proof["access_denial"] = (acceptance.access_denial() if proof["privilege"]["mode"] == "STANDARD" else
                                   {"status": "NOT_EXECUTED", "reason": "EXECUTED_BY_RESTRICTED_TOKEN_CHILD"})
        proof["intervention"] = acceptance.intervention()
        proof["negative_controls"] = acceptance.negatives()
        proof["dumps"] = acceptance.dumps()
        proof["before_after_journal"] = acceptance.compare_and_journal()
        proof["helper_crash"] = acceptance.crash_recovery()
        proof["target_exit_race"] = exited_target_check(output, executable, helper)
        proof["operation_count"] = len(acceptance.operations)
        proof["status"] = "PASS"
    except BaseException as error:
        proof.update(status="FAIL", error=type(error).__name__, reason=str(error)[:1500])
    finally:
        if acceptance is not None:
            try:
                proof["helper_cleanup"] = acceptance.service.close()
                if proof["status"] == "PASS":
                    require(proof["helper_cleanup"].get("status") == "COMPLETED",
                            "NORMAL_HELPER_FINAL_CLEANUP_UNCONFIRMED")
            except BaseException as error:
                proof.update(status="FAIL", cleanup_error=type(error).__name__, cleanup_reason=str(error)[:1000])
        if probe is not None:
            try:
                proof["target_cleanup"] = probe.close(kill=proof["status"] != "PASS")
            except BaseException as error:
                proof.update(status="FAIL", target_cleanup_error=type(error).__name__,
                             target_cleanup_reason=str(error)[:1000])
        save(output / "acceptance.json", proof)
    return proof


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--helper", type=Path)
    parser.add_argument("--standard-worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    require_hosted_windows()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    executable = args.probe.resolve(strict=True) if args.probe else build_probe(output / "build")
    helper = args.helper.resolve(strict=True) if args.helper else None
    if args.standard_worker:
        from blackbox_core.windows_research import privilege
        require(privilege() == {"mode": "STANDARD", "windows": True},
                "ACTUAL_STANDARD_TOKEN_REQUIRED")
    report = run_acceptance(output, executable, helper)
    if report["status"] != "PASS":
        print("DEEP_NATIVE_ACCEPTANCE_FAIL", report.get("reason", ""))
        return 1
    if not args.standard_worker:
        from tools.qa_decoder_standard_token import restricted_child, restricted_interpreter
        standard_output = output / "standard-token"
        command = [restricted_interpreter(sys.executable), Path(__file__).resolve(),
                   "--standard-worker", "--output", standard_output, "--probe", executable]
        if helper:
            command.extend(["--helper", helper])
        try:
            child = restricted_child(command, cwd=ROOT, timeout_seconds=420)
            report["standard_child"] = child
            standard_proof = standard_output / "acceptance.json"
            require(standard_proof.is_file(), "STANDARD_WORKER_PROOF_MISSING_0x" + format(child["exit_code"], "08X"))
            standard = json.loads(standard_proof.read_text(encoding="utf-8"))
            require(child["exit_code"] == 0 and standard["status"] == "PASS" and
                    standard["pid"] == child["pid"] and
                    standard["privilege"] == {"mode": "STANDARD", "windows": True},
                    "STANDARD_TOKEN_NATIVE_ACCEPTANCE_NOT_CONFIRMED:" + str(standard.get("reason", "")))
            report["standard_token"] = {"status": "PASS", "pid": child["pid"],
                                         "helper_pid": standard["helper_pid"],
                                         "operation_count": standard["operation_count"],
                                         "proof": "standard-token/acceptance.json"}
        except BaseException as error:
            report.update(status="FAIL", error=type(error).__name__, reason=str(error)[:1500])
            print("DEEP_STANDARD_TOKEN_ACCEPTANCE_FAIL", report["reason"])
            return 1
        finally:
            save(output / "acceptance.json", report)
    print("DEEP_NATIVE_ACCEPTANCE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
