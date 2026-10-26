"""Offline trace decode supervisor; the recorder and its databases are not touched."""
from __future__ import annotations
import os
from pathlib import Path
import sys
import tempfile
import time

from .decoder_index import build_index, file_hash


def helper_path():
    root = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[2]
    return root / "decoder" / ("BLACK.BOX-Decoder.exe" if os.name == "nt" else "BLACK.BOX-Decoder")


def capability():
    tool = helper_path()
    return {"engine": "Microsoft.Diagnostics.Tracing.TraceEvent 4.0.0", "helper_present": tool.is_file(),
            "formats": [".etl", ".nettrace", ".jsonl"], "etl_requires_windows": True,
            "symbol_downloads": False, "capture_started": False}


def _local_file(path):
    from .session_v2 import safe_path
    path = safe_path(path)
    # safe_path checks ancestors/reparse points as well as network paths.
    if not path.is_file() or not 0 < path.stat().st_size <= 256 * 1024**2:
        raise ValueError("DECODER_INPUT_SIZE_OR_TYPE")
    if path.suffix.lower() not in (".etl", ".nettrace", ".jsonl"):
        raise ValueError("UNSUPPORTED_FORMAT")
    return path


def decode_file(path, destination, *, cancel=None, timeout=180):
    if type(timeout) not in (int, float) or not 1 <= timeout <= 600:
        raise ValueError("INVALID_DECODE_TIMEOUT")
    path = _local_file(path)
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("OUTPUT_EXISTS")
    if path.suffix.lower() == ".etl" and os.name != "nt":
        raise OSError("ETL_REQUIRES_WINDOWS")
    before = file_hash(path, cancel)
    with tempfile.TemporaryDirectory(prefix="blackbox-decode-") as temp:
        root = Path(temp)
        snapshot = root / ("input" + path.suffix.lower())
        # Decoder sees a private snapshot, not the mutable original file.
        with path.open("rb") as source, snapshot.open("xb") as target:
            total = 0
            while chunk := source.read(1024 * 1024):
                if cancel is not None and cancel.is_set():
                    raise InterruptedError("DECODER_CANCELLED")
                total += len(chunk)
                if total > 256 * 1024**2:
                    raise ValueError("INPUT_GREW_BEYOND_BUDGET")
                target.write(chunk)
        if file_hash(snapshot, cancel) != before:
            raise ValueError("INPUT_CHANGED_DURING_SNAPSHOT")
        decoded = snapshot
        if path.suffix.lower() != ".jsonl":
            tool = helper_path()
            if not tool.is_file() or tool.is_symlink():
                raise OSError("DECODER_HELPER_MISSING_BUILD_OR_DOWNLOAD_MAIN_ARTIFACT")
            from .optional_jobs import OwnedProcess
            import psutil
            decoded = root / "decoded.jsonl"
            # The managed heap limit is hard; native RSS and disk limits are polled.
            env = {**os.environ, "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_GCHeapHardLimit": "40000000",
                   "_NT_SYMBOL_PATH": "", "_NT_ALT_SYMBOL_PATH": ""}
            owner = None
            with (root / "decoder.log").open("xb") as log:
                try:
                    owner = OwnedProcess([str(tool), str(snapshot), str(decoded)], stdout=log, stderr=log, env=env)
                    process = psutil.Process(owner.process.pid)
                    try: process.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS if os.name == "nt" else 5)
                    except psutil.Error: pass
                    deadline = time.monotonic() + timeout
                    while owner.process.poll() is None:
                        if cancel is not None and cancel.is_set():
                            raise InterruptedError("DECODER_CANCELLED")
                        if time.monotonic() > deadline:
                            raise TimeoutError("DECODER_TIMEOUT")
                        try:
                            if process.memory_info().rss > 1536 * 1024**2:
                                raise MemoryError("DECODER_RSS_BUDGET")
                        except psutil.NoSuchProcess: pass
                        size = 0
                        for item in root.rglob("*"):
                            try:
                                if item.is_file(): size += item.stat().st_size
                            except FileNotFoundError: pass
                        if size > 1024**3:
                            raise ValueError("DECODER_DISK_BUDGET")
                        time.sleep(.1)
                    if owner.process.returncode != 0:
                        raise OSError("DECODER_FAILED_EXIT_" + str(owner.process.returncode))
                finally:
                    if owner is not None:
                        owner.close(kill=True)
        if file_hash(path, cancel) != before:
            raise ValueError("ORIGINAL_INPUT_CHANGED_DURING_DECODE")
        return build_index(decoded, destination, input_sha256=before, format_name=path.suffix.lower(), cancel=cancel)
