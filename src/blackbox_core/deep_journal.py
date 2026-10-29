"""Append-only diagnostic metadata, deliberately outside ordinary share ZIPs."""
from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
from uuid import uuid4

from .deep_contracts import bounded_json

_SENSITIVE = {"bytes", "bytes_hex", "hex", "data_hex", "expected_hex", "value_hex", "original_hex",
              "before_hex", "after_hex", "memory", "memory_bytes", "buffer", "content", "contents",
              "replacement_hex", "old_bytes", "new_bytes", "original_bytes", "expected_bytes",
              "password", "token", "nonce", "file_handle", "handle", "payload", "raw"}
_SENSITIVE.update({"command_line", "commandline", "cmdline", "environment", "environ"})


def journal_metadata(value, *, depth=0):
    """Keep useful attribution, replacing sensitive payloads with hashes/lengths."""
    if depth > 12:
        return {"omitted": "DEPTH_BUDGET"}
    if isinstance(value, dict):
        output = {}
        for key, item in list(value.items())[:256]:
            if str(key).lower() in _SENSITIVE or str(key).lower().endswith(("_hex", "_bytes_raw")):
                encoded = json.dumps(item, ensure_ascii=False, default=str).encode("utf-8")
                output[str(key)] = {"redacted": "SENSITIVE_PAYLOAD", "serialized_bytes": len(encoded),
                                    "sha256": hashlib.sha256(encoded).hexdigest()}
            else:
                output[str(key)] = journal_metadata(item, depth=depth + 1)
        if len(value) > 256:
            output["omitted_keys"] = len(value) - 256
        return output
    if isinstance(value, (list, tuple)):
        out = [journal_metadata(v, depth=depth + 1) for v in value[:512]]
        if len(value) > 512:
            out.append({"omitted_rows": len(value) - 512})
        return out
    if isinstance(value, str):
        return value[:8192] + ("…[truncated]" if len(value) > 8192 else "")
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return {"omitted_type": type(value).__name__}


class EvidenceJournal:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "deep-inspection.sqlite3"
        if self.path.is_symlink():
            raise ValueError("JOURNAL_SYMLINK_REFUSED")
        self._lock = threading.RLock()
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS actions (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id TEXT NOT NULL UNIQUE,
                    timestamp_utc TEXT NOT NULL,
                    monotonic_ns INTEGER NOT NULL,
                    record_json TEXT NOT NULL,
                    previous_sha256 TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS snapshots (
                    snapshot_id TEXT PRIMARY KEY, identity_json TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL, data_json TEXT NOT NULL);
            """)

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute("PRAGMA busy_timeout=5000")
            with db:
                yield db
        finally:
            db.close()

    def _storage_budget(self):
        if self.path.stat().st_size > 128 * 1024 * 1024:
            raise ValueError("JOURNAL_STORAGE_BUDGET_EXCEEDED")

    def append(self, record: dict) -> dict:
        clean = journal_metadata(record)
        clean.setdefault("operation_id", uuid4().hex)
        clean.setdefault("timestamp_utc", datetime.now(timezone.utc).isoformat())
        clean.setdefault("monotonic_ns", time.monotonic_ns())
        clean["evidence_scope"] = "LOCAL_DIAGNOSTIC_METADATA_NOT_AUTHENTICATED_PROVENANCE"
        raw = bounded_json(clean)
        if len(raw) > 512 * 1024:
            raise ValueError("JOURNAL_RECORD_BUDGET_EXCEEDED")
        with self._lock:
            self._storage_budget()
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                previous = db.execute("SELECT record_sha256 FROM actions ORDER BY sequence DESC LIMIT 1").fetchone()
                previous_hash = previous[0] if previous else "0" * 64
                digest = hashlib.sha256(previous_hash.encode("ascii") + raw).hexdigest()
                db.execute("INSERT INTO actions(operation_id,timestamp_utc,monotonic_ns,record_json,previous_sha256,record_sha256) VALUES(?,?,?,?,?,?)",
                           (clean["operation_id"], clean["timestamp_utc"], clean["monotonic_ns"],
                            raw.decode("utf-8"), previous_hash, digest))
        return {"operation_id": clean["operation_id"], "record_sha256": digest,
                "payloads": "REDACTED", "chain": "LOCAL_CHANGE_DETECTION_ONLY"}

    def timeline(self, *, limit: int = 200) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("INVALID_TIMELINE_LIMIT")
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT sequence,record_json,record_sha256 FROM actions ORDER BY sequence DESC LIMIT ?", (limit,)).fetchall()
        return [{"sequence": seq, **json.loads(raw), "record_sha256": digest} for seq, raw, digest in rows]

    def snapshot(self, identity: dict, data: dict) -> str:
        identifier = uuid4().hex
        raw = bounded_json(journal_metadata(data)).decode("utf-8")
        with self._lock, self._connect() as db:
            self._storage_budget()
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT count(*) FROM snapshots").fetchone()[0] >= 10000:
                raise ValueError("SNAPSHOT_BUDGET_EXCEEDED")
            db.execute("INSERT INTO snapshots VALUES(?,?,?,?)", (identifier, json.dumps(identity, sort_keys=True),
                       datetime.now(timezone.utc).isoformat(), raw))
        return identifier

    def compare(self, before_id: str, after_id: str) -> dict:
        with self._lock, self._connect() as db:
            before = db.execute("SELECT identity_json,timestamp_utc,data_json FROM snapshots WHERE snapshot_id=?", (before_id,)).fetchone()
            after = db.execute("SELECT identity_json,timestamp_utc,data_json FROM snapshots WHERE snapshot_id=?", (after_id,)).fetchone()
        if before is None or after is None:
            raise ValueError("SNAPSHOT_NOT_FOUND")
        if before[0] != after[0]:
            raise ValueError("SNAPSHOT_PROCESS_IDENTITY_MISMATCH")
        old, new = json.loads(before[2]), json.loads(after[2])

        def section_values(value):
            # Only the native section envelope's collection cost is acquisition
            # metadata. Never recursively discard durations inside measured
            # data, or suppress status/source/limitations/error changes.
            if isinstance(value, dict) and {"status", "source", "data"} <= value.keys():
                return ({key: item for key, item in value.items() if key != "duration_ns"},
                        {"duration_ns": value["duration_ns"]} if "duration_ns" in value else {})
            return value, {}

        changed, acquisition = [], {}
        for key in sorted(set(old) | set(new)):
            old_content, old_acquisition = section_values(old.get(key))
            new_content, new_acquisition = section_values(new.get(key))
            if key not in old or key not in new or old_content != new_content:
                changed.append(key)
            if old_acquisition != new_acquisition:
                acquisition[key] = {"before": old_acquisition, "after": new_acquisition}
        return {"before_id": before_id, "after_id": after_id, "target": json.loads(before[0]),
                "before_timestamp_utc": before[1], "after_timestamp_utc": after[1],
                "before": old, "after": new,
                "changed_sections": changed, "acquisition_metadata_changes": acquisition,
                "comparison_scope": "SECTION_CONTENT_AND_EVIDENCE_EXCLUDING_COLLECTION_DURATION",
                "interpretation": "OBSERVED_DIFFERENCE_NOT_CAUSAL_PROOF"}

    def export(self, destination: str | Path, *, cancel_event=None) -> Path:
        """Publish one immutable journal snapshot; preserve the Path API."""
        return Path(self.export_snapshot(destination, cancel_event=cancel_event)["path"])

    def export_snapshot(self, destination: str | Path, *, cancel_event=None) -> dict:
        """Return the exact verified prefix receipt without appending records.

        The service journals intent before this copy and outcome afterwards.
        An export cannot contain its own acknowledged publication result.
        """
        target = Path(destination)
        descriptor, temporary = tempfile.mkstemp(prefix=".blackbox-deep-export-", suffix=".tmp", dir=target.parent)
        published = False
        records = last_sequence = 0
        previous_expected = "0" * 64
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                with self._lock, self._connect() as db:
                    for sequence, raw, previous, digest in db.execute("SELECT sequence,record_json,previous_sha256,record_sha256 FROM actions ORDER BY sequence"):
                        if cancel_event is not None and cancel_event.is_set():
                            raise InterruptedError("JOURNAL_EXPORT_CANCELLED")
                        actual = hashlib.sha256(previous.encode("ascii") + raw.encode("utf-8")).hexdigest()
                        if previous != previous_expected or actual != digest:
                            raise ValueError("JOURNAL_HASH_CHAIN_MISMATCH")
                        previous_expected = digest
                        records += 1
                        last_sequence = sequence
                        stream.write(json.dumps({"record": json.loads(raw), "previous_sha256": previous,
                                                 "record_sha256": digest}, ensure_ascii=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            # Atomic, create-new publication: an existing destination is never replaced.
            os.link(temporary, target)
            published = True
        finally:
            Path(temporary).unlink(missing_ok=True)
        if not published:
            raise OSError("JOURNAL_EXPORT_NOT_PUBLISHED")
        return {"path": str(target), "exported_records": records,
                "exported_last_sequence": last_sequence,
                "exported_chain_head_sha256": previous_expected}
