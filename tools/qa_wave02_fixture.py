"""Owned BB-WAVE-02 native fixture, compiled/executed only on hosted Windows."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from tools.qa_deep_inspection import (compiler_environment, file_hash, require,
                                     require_hosted_windows, save)


def build(output: Path, source_sha: str) -> Path:
    require_hosted_windows()
    from blackbox_universal.provenance import source_identity
    identity = source_identity(source_sha)
    require(identity["source_identity_status"] == "VERIFIED_EXPECTED_HEAD",
            "WAVE02_FIXTURE_CHECKOUT_MISMATCH")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    compiler, environment = compiler_environment(output)
    source = ROOT / "tools/fixtures/Wave02Probe/probe.c"
    executable = output / "wave02-probe.exe"
    pdb = output / "wave02-probe.pdb"
    command = [compiler, "/nologo", "/W4", "/Od", "/Zi", "/MT", "/DUNICODE",
        "/D_UNICODE", "/Fe:" + str(executable), "/Fo:" + str(output / "probe.obj"),
        "/Fd:" + str(output / "compiler.pdb"), str(source), "/link", "/DEBUG:FULL",
        "/PDB:" + str(pdb), "/INCREMENTAL:NO", "user32.lib", "advapi32.lib", "dbghelp.lib"]
    completed = subprocess.run(command, env=environment, capture_output=True,
                               text=True, errors="replace", timeout=90)
    (output / "compiler.log").write_text(completed.stdout + completed.stderr, encoding="utf-8")
    require(completed.returncode == 0 and executable.is_file() and pdb.is_file(),
            "WAVE02_NATIVE_FIXTURE_COMPILATION_FAILED")
    receipt = {"status": "PASS", "schema": "blackbox.wave02.fixture/1",
        "source_identity": identity, "source_sha256": file_hash(source),
        "executable_sha256": file_hash(executable), "pdb_sha256": file_hash(pdb),
        "compiler": compiler, "command": command,
        "oracle": "OWNED_NATIVE_STDIN_STDOUT_WIN32_QPC_RESULT",
        "physical_windows_10_11": "NOT_TESTED", "physical_secure_desktop": "NOT_TESTED"}
    save(output / "build.json", receipt)
    print("WAVE02_FIXTURE_RECEIPT " + json.dumps(receipt, sort_keys=True), flush=True)
    return executable


class WaveProbe:
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    build(args.output, args.source_sha)


if __name__ == "__main__":
    main()
