"""Offline trace decode supervisor; the recorder and its databases are not touched."""
from __future__ import annotations
from contextlib import contextmanager
import os
from pathlib import Path
import sys
import tempfile
import time

from .decoder_index import (FRAME_MODULE_INLINE, FRAME_MODULE_PER_EVENT,
                            build_index, file_hash)
from .decoder_limits import DecodeBudget, MAX_INPUT_BYTES, MAX_WORK_BYTES, failure_details


def helper_path():
    root = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[2]
    return root / "decoder" / ("BLACK.BOX-Decoder.exe" if os.name == "nt" else "BLACK.BOX-Decoder")


def capability():
    tool = helper_path()
    return {"engine": "Microsoft.Diagnostics.Tracing.TraceEvent 4.0.0", "helper_present": tool.is_file(),
            "formats": [".etl", ".nettrace", ".jsonl"], "etl_requires_windows": True,
            "symbol_downloads": False, "capture_started": False,
            "max_input_bytes": MAX_INPUT_BYTES, "timeout_scope": "ENTIRE_IMPORT",
            "recovery": "RETRY_FROM_ORIGINAL; PARTIAL_INDEXES_ARE_NEVER_REUSED"}


def _local_file(path):
    from .session_v2 import safe_path
    path = safe_path(path)
    # safe_path checks ancestors/reparse points as well as network paths.
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_INPUT_BYTES:
        raise ValueError("DECODER_INPUT_SIZE_OR_TYPE")
    if path.suffix.lower() not in (".etl", ".nettrace", ".jsonl"):
        raise ValueError("UNSUPPORTED_FORMAT")
    return path


def _check_work_bytes(root, budget):
    """Count a changing private workspace, tolerating only vanished children.

    TraceEvent removes its .etlx scratch directory before the helper exits.
    pathlib.rglob can raise while advancing the iterator, outside a per-file
    stat guard. Check each scandir advancement and each entry while preserving
    permission and other I/O failures as import failures.
    """
    root = Path(root)
    budget.check("NATIVE_DECODE")
    pending = [root]
    size = 0
    while pending:
        budget.check("NATIVE_DECODE")
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    budget.check("NATIVE_DECODE")
                    try:
                        # As with rglob, never traverse directory symlinks.
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(Path(entry.path))
                        elif entry.is_file():
                            size += entry.stat().st_size
                    except FileNotFoundError:
                        continue
                    if size > MAX_WORK_BYTES:
                        raise ValueError("DECODER_DISK_BUDGET")
        except FileNotFoundError:
            if directory == root:
                raise  # Loss of our staging root is not ordinary scratch cleanup.
            budget.check("NATIVE_DECODE")
    return size


@contextmanager
def _private_decode_stage():
    stage = tempfile.TemporaryDirectory(prefix="blackbox-decode-")
    released = False
    def release():
        nonlocal released
        if not released:
            stage.cleanup()
            released = True
    try:
        yield stage.name, release
    except BaseException as error:
        owner = getattr(error, "owner", None)
        if owner is not None and getattr(owner, "cleanup_required", False):
            # Keep the actual TemporaryDirectory object alive with its native
            # owner until an explicit verified close can release both.
            owner.retain_cleanup_resource(stage)
            released = True
        raise
    finally:
        release()


def decode_file(path, destination, *, cancel=None, timeout=180, native_module_encoding=None):
    if native_module_encoding not in (None, FRAME_MODULE_INLINE, FRAME_MODULE_PER_EVENT):
        raise ValueError("UNSUPPORTED_FRAME_MODULE_ENCODING")
    from .deep_tool_contracts import begin_evidence_run, record_evidence_failure
    # Preserve the established validation error before constructing metadata.
    DecodeBudget(cancel, timeout)
    context = begin_evidence_run("decoder.decode", timeout_seconds=timeout)
    try:
        return _decode_file(path, destination, cancel=cancel, timeout=timeout, context=context,
                            native_module_encoding=native_module_encoding)
    except Exception as error:
        record_evidence_failure(context, error)
        raise


def _decode_file(path, destination, *, cancel, timeout, context, native_module_encoding=None):
    from .session_v2 import safe_path
    if native_module_encoding not in (None, FRAME_MODULE_INLINE, FRAME_MODULE_PER_EVENT):
        raise ValueError("UNSUPPORTED_FRAME_MODULE_ENCODING")
    budget = DecodeBudget(cancel, timeout)
    budget.check("VALIDATE")
    path = _local_file(path)
    destination = safe_path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("OUTPUT_EXISTS")
    if path.suffix.lower() == ".etl" and os.name != "nt":
        raise OSError("ETL_REQUIRES_WINDOWS")
    before = file_hash(path, cancel, budget=budget, max_bytes=MAX_INPUT_BYTES)
    with _private_decode_stage() as (temp, release_private_stage):
        root = Path(temp)
        snapshot = root / ("input" + path.suffix.lower())
        # Decoder sees a private snapshot, not the mutable original file.
        with path.open("rb") as source, snapshot.open("xb") as target:
            total = 0
            while chunk := source.read(1024 * 1024):
                budget.check("SNAPSHOT")
                total += len(chunk)
                if total > MAX_INPUT_BYTES:
                    raise ValueError("INPUT_GREW_BEYOND_BUDGET")
                target.write(chunk)
        if file_hash(snapshot, cancel, budget=budget, max_bytes=MAX_INPUT_BYTES) != before:
            raise ValueError("INPUT_CHANGED_DURING_SNAPSHOT")
        decoded = snapshot
        if path.suffix.lower() != ".jsonl":
            tool = helper_path()
            if not tool.is_file() or tool.is_symlink():
                raise OSError("DECODER_HELPER_MISSING_REINSTALL_COMPLETE_PORTABLE_PACKAGE")
            from .optional_jobs import OwnedProcess
            import psutil
            decoded = root / "decoded.jsonl"
            # The managed heap limit is hard; native RSS and disk limits are polled.
            env = {**os.environ, "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_GCHeapHardLimit": "40000000",
                   "_NT_SYMBOL_PATH": "", "_NT_ALT_SYMBOL_PATH": ""}
            owner = None
            command = [str(tool), str(snapshot), str(decoded)]
            if native_module_encoding == FRAME_MODULE_INLINE:
                command.append("--inline-modules")
            with (root / "decoder.log").open("xb") as log:
                try:
                    owner = OwnedProcess(command, stdout=log, stderr=log,
                                         env=env, detach_console=True)
                    process = psutil.Process(owner.process.pid)
                    try: process.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS if os.name == "nt" else 5)
                    except psutil.Error: pass
                    while owner.process.poll() is None:
                        budget.check("NATIVE_DECODE")
                        try:
                            if process.memory_info().rss > 1536 * 1024**2:
                                raise MemoryError("DECODER_RSS_BUDGET")
                        except psutil.NoSuchProcess: pass
                        _check_work_bytes(root, budget)
                        time.sleep(.1)
                    if owner.process.returncode != 0:
                        raise OSError("DECODER_FAILED_EXIT_" + str(owner.process.returncode))
                    budget.check("NATIVE_DECODE")
                    # A fast helper can finish between polls. Enforce its
                    # final disk budget as well, before indexing any output.
                    _check_work_bytes(root, budget)
                finally:
                    if owner is not None:
                        owner.close(kill=True)
        def verify_original():
            budget.check("VERIFY_ORIGINAL")
            if _local_file(path) != path or file_hash(
                    path, cancel, budget=budget, max_bytes=MAX_INPUT_BYTES) != before:
                raise ValueError("ORIGINAL_INPUT_CHANGED_DURING_DECODE")

        def complete_metadata(meta):
            from .deep_tool_contracts import attach_evidence_run_receipt
            verify_original()
            # build_index has closed the parser and its private SQLite writer.
            # Native OwnedProcess.close must also have returned successfully.
            release_private_stage()
            source = {"source_id": "trace-input:" + before, "source_type": "TRACE_FILE",
                "source_sha256": before, "source_size_bytes": total,
                "verification_class": "UNVERIFIED_IMPORT",
                "provenance": "EXPLICIT_LOCAL_FILE_SELECTION_NOT_PRODUCER_AUTHENTICATION"}
            partial = (meta["status"] == "TRUNCATED" or meta.get("events_with_errors", 0) > 0 or
                       meta.get("events_without_fields_or_schema", 0) > 0 or meta.get("bounded_events", 0) > 0 or
                       (meta.get("decoder_reported_lost_events") or 0) > 0)
            return attach_evidence_run_receipt(context, meta, sources=(source,),
                source_revalidated=True, execution_started=True,
                coverage={"completeness": "INCOMPLETE_EVIDENCE" if partial else "UNKNOWN_CAPTURE_COMPLETENESS",
                    "rows": meta["rows"], "import_completeness": meta["import_completeness"],
                    "original_capture_complete": None},
                cleanup={"status": "CONFIRMED", "confirmed": True,
                    "scope": "DECODE_HELPER_AND_PRIVATE_INPUT_STAGING",
                    "private_staging_removed": True, "capture_started": False})

        verify_original()
        return build_index(decoded, destination, input_sha256=before, format_name=path.suffix.lower(),
                           cancel=cancel, budget=budget, before_publish=verify_original,
                           metadata_adapter=complete_metadata)
