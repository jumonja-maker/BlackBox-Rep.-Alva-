"""Bounded private copies for navigating an existing untrusted trace index.

The GUI's decoder cache owns the copy; an imported index is never installed
as ``DecoderPanel.index`` and can never be deleted by a later decode.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import math
import os
from pathlib import Path
import re
import sqlite3
import time

from blackbox_core.decoder_index import read_index
from blackbox_core.decoder_limits import MAX_INDEX_BYTES
from blackbox_core.session_v2 import safe_path


def navigation_filters(*, process_instance=None, pid=None, tid=None,
                       start_ms=None, end_ms=None):
    values = {"process_instance": process_instance, "pid": pid, "tid": tid,
              "start_ms": start_ms, "end_ms": end_ms}
    for name in ("process_instance", "pid", "tid"):
        value = values[name]
        maximum = 2147483647 if name == "pid" else 2**63 - 1
        if value is not None and (type(value) is not int or not 0 <= value <= maximum):
            raise ValueError("INVALID_DECODER_NAVIGATION_IDENTITY")
    for name in ("start_ms", "end_ms"):
        value = values[name]
        if value is not None and (type(value) not in (int, float) or
                                  not math.isfinite(value) or abs(value) >= 1e15):
            raise ValueError("INVALID_DECODER_NAVIGATION_TIME")
    if start_ms is not None and end_ms is not None and start_ms >= end_ms:
        raise ValueError("INVALID_DECODER_NAVIGATION_INTERVAL")
    return values


def _identity(stat):
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def _validate_view_summary(summary):
    """Reject malformed display fields before they reach the Qt renderer."""
    def counts(value, keys):
        return isinstance(value, dict) and all(type(value.get(key)) is int and
            0 <= value[key] <= 250000 for key in keys)
    if (not counts(summary, ("rows", "events_with_stacks", "events_with_errors", "bounded_events")) or
            not counts(summary.get("gc"), ("gc_pairs",)) or
            summary.get("format") not in (".etl", ".nettrace", ".jsonl")):
        raise ValueError("DECODER_NAVIGATION_DISPLAY_SUMMARY_INVALID")
    profiles = summary.get("profiles")
    if profiles and not counts(profiles, ("cpu_profiler_samples_recorded", "cpu_stack_groups_indexed",
                                         "cpu_profiler_samples_omitted_from_groups")):
        raise ValueError("DECODER_NAVIGATION_DISPLAY_PROFILES_INVALID")
    clock = summary.get("calendar_clock")
    if clock and (not counts(clock, ("events_with_utc_projection", "relative_vs_utc_offset_disagreements_over_10ms")) or
                  type(clock.get("trace_to_blackbox_session_clock_alignment")) is not str or
                  len(clock["trace_to_blackbox_session_clock_alignment"]) > 128):
        raise ValueError("DECODER_NAVIGATION_DISPLAY_CLOCK_INVALID")


def copy_navigation_index(source, output, *, expected_trace_sha256=None,
                          expected_index_sha256=None, filters=None,
                          cancel_event=None, timeout_seconds=60):
    """Validate a closed index and publish only a complete private cache copy.

    Trace hash is the original capture's hash in the saved summary; index hash
    binds the SQLite file itself. Neither one authenticates imported claims.
    """
    if (type(timeout_seconds) not in (int, float) or
            not math.isfinite(timeout_seconds) or not 1 <= timeout_seconds <= 120):
        raise ValueError("INVALID_DECODER_NAVIGATION_DEADLINE")
    for digest in (expected_trace_sha256, expected_index_sha256):
        if digest is not None and (type(digest) is not str or
                                   re.fullmatch(r"[0-9a-f]{64}", digest) is None):
            raise ValueError("INVALID_DECODER_NAVIGATION_SOURCE_HASH")
    selection = navigation_filters(**(filters or {}))
    deadline = time.monotonic() + timeout_seconds

    def check():
        if cancel_event is not None and cancel_event.is_set():
            raise InterruptedError("DECODER_INDEX_NAVIGATION_CANCELLED")
        if time.monotonic() > deadline:
            raise TimeoutError("DECODER_INDEX_NAVIGATION_TIMEOUT")

    check()
    source, output = safe_path(source), Path(output)
    before = source.stat()
    if not source.is_file() or not 16 <= before.st_size <= MAX_INDEX_BYTES:
        raise ValueError("DECODER_NAVIGATION_INDEX_SIZE_BUDGET")
    if source.resolve() == output.resolve():
        raise ValueError("DECODER_NAVIGATION_REQUIRES_PRIVATE_COPY")

    def require_closed_source():
        for suffix in ("-wal", "-journal"):
            sidecar = Path(str(source) + suffix)
            if sidecar.exists() and sidecar.stat().st_size:
                raise ValueError("DECODER_NAVIGATION_SOURCE_NOT_CLOSED")

    require_closed_source()
    created = False
    try:
        digest, count = hashlib.sha256(), 0
        with source.open("rb") as original, output.open("xb") as target:
            created = True
            if _identity(os.fstat(original.fileno())) != _identity(before):
                raise ValueError("DECODER_NAVIGATION_SOURCE_CHANGED")
            while True:
                check()
                chunk = original.read(1024 * 1024)
                if not chunk:
                    break
                count += len(chunk)
                if count > before.st_size or count > MAX_INDEX_BYTES:
                    raise ValueError("DECODER_NAVIGATION_SOURCE_GREW")
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
            check()
            if (_identity(os.fstat(original.fileno())) != _identity(before) or
                    count != before.st_size):
                raise ValueError("DECODER_NAVIGATION_SOURCE_CHANGED")
        if _identity(source.stat()) != _identity(before):
            raise ValueError("DECODER_NAVIGATION_SOURCE_CHANGED")
        require_closed_source()
        observed_hash = digest.hexdigest()
        if expected_index_sha256 is not None and observed_hash != expected_index_sha256:
            raise ValueError("DECODER_NAVIGATION_INDEX_HASH_MISMATCH")
        check()
        # Validate copied bytes only; no SQLite connection touches the source.
        with closing(sqlite3.connect(output.resolve().as_uri() + "?mode=ro&immutable=1",
                                     uri=True, timeout=1)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA cache_size=-2048")
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2 * 1024 * 1024)
            db.set_progress_handler(lambda: int((cancel_event is not None and cancel_event.is_set()) or
                                               time.monotonic() > deadline), 1000)
            try:
                result = db.execute("PRAGMA quick_check").fetchmany(2)
            except sqlite3.OperationalError:
                check()
                raise
            if result != [("ok",)]:
                raise ValueError("DECODER_NAVIGATION_INDEX_INTEGRITY_FAILED")
        check()
        page = read_index(output, limit=200, pid=selection.get("pid") or 0)
        summary = page["summary"]
        _validate_view_summary(summary)
        if (expected_trace_sha256 is not None and
                summary["input_sha256"] != expected_trace_sha256):
            raise ValueError("DECODER_NAVIGATION_TRACE_HASH_MISMATCH")
        check()
        if _identity(source.stat()) != _identity(before):
            raise ValueError("DECODER_NAVIGATION_SOURCE_CHANGED")
        require_closed_source()
        return {"path": str(output), "summary": summary, "initial_page": page, "navigation": selection,
                "index_sha256": observed_hash, "source_trace_sha256": summary["input_sha256"],
                "source_modified": False, "source_verification": "UNVERIFIED_IMPORT",
                "selection_clock": "TRACE_RELATIVE_MS", "live_identity_binding": "NOT_ESTABLISHED"}
    except BaseException:
        if created:
            for suffix in ("", "-wal", "-shm", "-journal"):
                Path(str(output) + suffix).unlink(missing_ok=True)
        raise
