"""Bounded workflow history over the existing local EvidenceJournal.

The journal is change detection, not authenticated provenance. Immutable private
result sidecars retain file fingerprints losslessly: EvidenceJournal's ordinary
metadata redactor deliberately replaces payload fields including ``bytes``.
Non-node events that exceed the journal's shallower metadata contract use the
same bounded immutable storage, including the actual nested cleanup evidence.
Opening a run is passive and never creates a database or claims native rights.
"""
from __future__ import annotations

from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
from uuid import uuid4

from .chain_contracts import (RUN_SCHEMA, STATES, WorkflowDefinition, WorkflowError,
                              canonical, identifier, parse_json, require)
from .chain_io import fingerprint_file
from .deep_journal import EvidenceJournal, _SENSITIVE, journal_metadata
from .library_files import atomic_json
from .owned_unlink import file_identity, remove_entry
from .session_v2 import safe_path

RESULT_SCHEMA = "blackbox.workflow-node-result/1"
EVENT_RECORD_SCHEMA = "blackbox.workflow-event/1"
MAX_RESULT_BYTES = 512 * 1024
MAX_JOURNAL_BYTES = 128 * 1024 * 1024
MAX_EVENTS = 100000
MAX_HISTORY_METADATA_BYTES = 64 * 1024 * 1024
_EVENTS = frozenset(("run.created", "node.intent", "node.state", "node.result",
                    "run.checkpoint", "run.state", "run.cleanup"))
_TRANSIENT = frozenset(("expected_context", "native_context_ref", "owner_token",
                        "execution_guard", "native_owner_ref", "native_context_ownership", "consent_token"))
_RESULT_KEYS = ("node_id", "node_run_id", "iteration", "state", "component_status",
                "execution_started", "started_monotonic_ns", "ended_monotonic_ns")
_EVENT_BINDING_KEYS = frozenset(("event_record_schema", "event_record_path", "event_record_sha256",
                               "event_record_size_bytes", "event_record_file_identity", "event_record_sequence"))


def _strict_json(raw, *, limit=MAX_RESULT_BYTES):
    """A deeper lossless record parser; the graph parser has a smaller depth."""
    require(type(raw) is bytes and len(raw) <= limit, "WORKFLOW_RECORD_BYTE_BUDGET")
    def pairs(items):
        output = {}
        for key, value in items:
            require(key not in output, "WORKFLOW_DUPLICATE_JSON_KEY")
            output[key] = value
        return output
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(WorkflowError("WORKFLOW_NONFINITE_NUMBER")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise WorkflowError("WORKFLOW_RECORD_CORRUPT") from error
    require(type(value) is dict, "WORKFLOW_RECORD_OBJECT_REQUIRED")
    _record(value, redact=False)
    return value


def _record(value, *, redact=True, depth=0):
    """Reject excess metadata; never silently truncate authoritative results."""
    require(depth <= 32, "WORKFLOW_RECORD_DEPTH")
    if type(value) is dict:
        require(len(value) <= 512 and all(type(k) is str and len(k) <= 128 for k in value),
                "WORKFLOW_RECORD_KEYS")
        output = {}
        for key, item in value.items():
            lower = key.lower()
            sensitive = (lower in _SENSITIVE and not (lower == "bytes" and type(item) is int and item >= 0)) or \
                lower.endswith(("_hex", "_bytes_raw", "_password", "_secret", "_token"))
            if redact and (lower in _TRANSIENT or sensitive):
                encoded = canonical(_record(item, redact=False, depth=depth + 1)).encode("utf-8")
                output[key] = {"redacted": "SENSITIVE_PAYLOAD", "serialized_bytes": len(encoded),
                               "sha256": hashlib.sha256(encoded).hexdigest()}
            else:
                output[key] = _record(item, redact=redact, depth=depth + 1)
        return output
    if type(value) in (list, tuple):
        require(len(value) <= 10000, "WORKFLOW_RECORD_ROWS")
        return [_record(item, redact=redact, depth=depth + 1) for item in value]
    if type(value) is str:
        require(len(value) <= 32768 and not any(ord(c) < 32 and c not in "\n\r\t" for c in value),
                "WORKFLOW_RECORD_TEXT")
        return value
    if type(value) is float:
        require(math.isfinite(value), "WORKFLOW_NONFINITE_NUMBER")
        return value
    require(value is None or type(value) in (bool, int), "WORKFLOW_NON_JSON_RECORD")
    return value


def _read(path, *, limit=MAX_RESULT_BYTES):
    path = safe_path(Path(path))
    before = fingerprint_file(path, max_bytes=limit)
    raw = path.read_bytes()
    require(len(raw) <= limit and hashlib.sha256(raw).hexdigest() == before["sha256"],
            "WORKFLOW_RECORD_CHANGED_DURING_READ")
    require(fingerprint_file(path, max_bytes=limit) == before, "WORKFLOW_RECORD_INSTANCE_CHANGED")
    return _strict_json(raw, limit=limit), before


def _observed_writer_birth(pid=None):
    import psutil
    value=psutil.Process(pid).create_time() if pid is not None else psutil.Process().create_time()
    try:
        valid=type(value) in (int,float) and value>0 and math.isfinite(value)
    except OverflowError:
        valid=False
    require(valid,"WORKFLOW_WRITER_OWNERSHIP_UNCONFIRMED")
    return value


def load_definition(path):
    path = safe_path(Path(path))
    value, _ = _read(path, limit=1024 * 1024)
    return WorkflowDefinition.from_dict(parse_json(canonical(value)))


def save_definition(definition, path):
    """Create a new versioned definition; never replace another user's file."""
    if not isinstance(definition, WorkflowDefinition):
        definition = WorkflowDefinition.from_dict(definition)
    definition = WorkflowDefinition.from_dict(definition.to_dict())
    path = safe_path(Path(path))
    atomic_json(path, definition.to_dict(), exclusive=True, max_bytes=1024 * 1024)
    require(load_definition(path).fingerprint == definition.fingerprint, "WORKFLOW_DEFINITION_READBACK_FAILED")
    return path


class WorkflowRunStore:
    """A passive facade; every SQLite connection and file handle is scoped."""
    def __init__(self, folder, definition, marker):
        self.folder = safe_path(Path(folder))
        self.definition, self.run_id = definition, marker["run_id"]
        self._marker = marker
        self._lock = threading.RLock()
        self._writer_nonce = None
        self._writer_identity = None
        self._writer_pins = 0
        self._root_identity = file_identity(self.folder)
        self._history_metadata_bytes = 0
        self._event_count = 0

    @classmethod
    def create(cls, root, definition, *, run_id=None):
        if not isinstance(definition, WorkflowDefinition):
            definition = WorkflowDefinition.from_dict(definition)
        definition = WorkflowDefinition.from_dict(definition.to_dict())
        run_id = identifier(run_id or uuid4().hex)
        root = safe_path(Path(root))
        root.mkdir(parents=True, exist_ok=True)
        folder = safe_path(root / run_id)
        folder.mkdir(mode=0o700)
        (folder / ".results").mkdir(mode=0o700)
        (folder / ".events").mkdir(mode=0o700)
        save_definition(definition, folder / "definition.bbchain.json")
        marker = {"schema": RUN_SCHEMA, "run_id": run_id, "workflow_id": definition.workflow_id,
                  "definition_sha256": definition.fingerprint, "definition_file": "definition.bbchain.json",
                  "created_utc": datetime.now(timezone.utc).isoformat(), "mode": "USER_CONTROLLED",
                  "trust": "LOCAL_CHANGE_DETECTION_NOT_AUTHENTICATED"}
        atomic_json(folder / "workflow-run.json", marker, exclusive=True)
        EvidenceJournal(folder / "journal")
        store = cls(folder, definition, marker)
        store.append("run.created", data={"state": "QUEUED", "definition_sha256": definition.fingerprint,
                                         "workflow_id": definition.workflow_id})
        return store

    @classmethod
    def open(cls, folder):
        folder = safe_path(Path(folder))
        require(folder.is_dir(), "WORKFLOW_RUN_FOLDER_MISSING")
        marker, _ = _read(folder / "workflow-run.json", limit=65536)
        require(marker.get("schema") == RUN_SCHEMA and marker.get("mode") == "USER_CONTROLLED" and
                marker.get("definition_file") == "definition.bbchain.json", "WORKFLOW_RUN_MARKER_INVALID")
        identifier(marker.get("run_id"))
        definition = load_definition(folder / "definition.bbchain.json")
        require(marker.get("definition_sha256") == definition.fingerprint and
                marker.get("workflow_id") == definition.workflow_id, "WORKFLOW_RUN_DEFINITION_CHANGED")
        require(safe_path(folder / ".results").is_dir() and
                safe_path(folder / "journal" / "deep-inspection.sqlite3").is_file(),
                "WORKFLOW_RUN_HISTORY_MISSING")
        store = cls(folder, definition, marker)
        # Passive verification is fail-closed and never invokes EvidenceJournal's
        # constructor (which is allowed to initialize tables for new histories).
        store.read_events()
        return store

    def _check_identity(self):
        require(file_identity(self.folder)["identity"] == self._root_identity["identity"],
                "WORKFLOW_RUN_FOLDER_CHANGED")
        marker, _ = _read(self.folder / "workflow-run.json", limit=65536)
        require(marker == self._marker and load_definition(self.folder / "definition.bbchain.json").fingerprint ==
                self.definition.fingerprint, "WORKFLOW_RUN_DEFINITION_CHANGED")

    def acquire_writer(self, *, recover_stale=True):
        """Claim this local history, not a native helper or user consent.

        A stale claim is removed only after its exact process instance is proven
        gone and its filesystem identity still matches the examined lock.
        """
        import psutil
        require(type(recover_stale) is bool, "WORKFLOW_WRITER_RECOVERY_POLICY_INVALID")
        with self._lock:
            self._check_identity()
            if self._writer_nonce is not None:
                self._check_writer()
                return self._writer_nonce
            path = self.folder / ".writer.json"
            for _ in range(3):
                nonce = uuid4().hex
                marker = {"schema": "blackbox.workflow-writer/1", "run_id": self.run_id,
                          "pid": os.getpid(), "process_created": _observed_writer_birth(),
                          "owner_nonce": nonce}
                try:
                    atomic_json(path, marker, exclusive=True, max_bytes=4096)
                except FileExistsError:
                    existing, _ = _read(path, limit=4096)
                    lock_identity = file_identity(path)
                    require(existing.get("schema") == "blackbox.workflow-writer/1" and
                            existing.get("run_id") == self.run_id and type(existing.get("pid")) is int and
                            existing["pid"] > 0 and
                            type(existing.get("process_created")) in (int, float) and
                            math.isfinite(existing["process_created"]) and existing["process_created"] > 0,
                            "WORKFLOW_WRITER_LOCK_INVALID")
                    try:
                        alive = _observed_writer_birth(existing["pid"]) == existing["process_created"]
                    except psutil.NoSuchProcess:
                        alive = False
                    except (psutil.AccessDenied, OSError) as error:
                        raise WorkflowError("WORKFLOW_WRITER_OWNERSHIP_UNCONFIRMED") from error
                    require(recover_stale and not alive, "WORKFLOW_RUN_WRITER_BUSY")
                    require(_read(path, limit=4096)[0] == existing, "WORKFLOW_WRITER_LOCK_CHANGED")
                    remove_entry(self.folder, ".writer.json", lock_identity, self._root_identity)
                    continue
                self._writer_nonce, self._writer_identity = nonce, file_identity(path)
                try:
                    self._check_writer()
                    # A different facade can have appended after this facade's
                    # passive preview. Refresh the bounded budget under the
                    # writer claim before admitting another result.
                    journal = self.folder / "journal" / "deep-inspection.sqlite3"
                    require(safe_path(journal).stat().st_size <= MAX_JOURNAL_BYTES,
                            "WORKFLOW_HISTORY_STORAGE_BUDGET")
                    with closing(sqlite3.connect(journal.as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
                        db.execute("PRAGMA query_only=ON")
                        db.execute("PRAGMA trusted_schema=OFF")
                        deadline = time.monotonic() + 5
                        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                        require(db.execute("SELECT type FROM sqlite_master WHERE name='actions'").fetchone() ==
                                ("table",), "WORKFLOW_HISTORY_SCHEMA_INVALID")
                        count = db.execute("SELECT count(*) FROM actions").fetchone()[0]
                    require(type(count) is int and 0 <= count <= MAX_EVENTS, "WORKFLOW_HISTORY_EVENT_BUDGET")
                    if count != self._event_count:
                        self.read_events()
                    return nonce
                except BaseException:
                    self.release_writer()
                    raise
            raise WorkflowError("WORKFLOW_RUN_WRITER_BUSY")

    def _check_writer(self):
        require(self._writer_nonce is not None, "WORKFLOW_WRITER_NOT_OWNED")
        marker, _ = _read(self.folder / ".writer.json", limit=4096)
        require(marker.get("owner_nonce") == self._writer_nonce and marker.get("run_id") == self.run_id and
                file_identity(self.folder / ".writer.json")["identity"] == self._writer_identity["identity"],
                "WORKFLOW_WRITER_OWNERSHIP_CHANGED")

    def release_writer(self):
        with self._lock:
            require(self._writer_pins == 0, "WORKFLOW_WRITER_RETAINED_BY_LIVE_WORKER")
            if self._writer_nonce is None:
                return
            self._check_writer()
            remove_entry(self.folder, ".writer.json", self._writer_identity, self._root_identity)
            self._writer_nonce = self._writer_identity = None

    def pin_writer(self):
        """Keep the history claim reachable while its worker is still live.

        This is a scoped local lifetime guard, not native ownership or consent.
        Its caller must already own the writer and must retain this facade until
        the actual worker and pool boundaries have acknowledged completion.
        """
        with self._lock:
            self._check_writer()
            self._writer_pins += 1

    def unpin_writer(self):
        with self._lock:
            require(self._writer_pins > 0, "WORKFLOW_WRITER_PIN_NOT_OWNED")
            self._check_writer()
            self._writer_pins -= 1

    def append(self, event, node_id=None, data=None):
        require(type(event) is str and event in _EVENTS and (data is None or type(data) is dict),
                "WORKFLOW_EVENT_INVALID")
        if node_id is not None:
            identifier(node_id)
            require(node_id in {node.node_id for node in self.definition.nodes}, "WORKFLOW_EVENT_UNKNOWN_NODE")
        with self._lock:
            temporary_claim = self._writer_nonce is None
            if temporary_claim:
                self.acquire_writer()
            try:
                self._check_identity()
                self._check_writer()
                value = _record(data or {})
                if node_id is not None:
                    require(value.get("node_id", node_id) == node_id, "WORKFLOW_EVENT_NODE_MISMATCH")
                    value.setdefault("node_id", node_id)
                require(event == "node.result" or not any(key in value for key in _EVENT_BINDING_KEYS),
                        "WORKFLOW_EVENT_RESERVED_STORAGE_FIELDS")
                self._validate_event_data(event, node_id, value)
                metadata_bytes = 0
                require(self._event_count < MAX_EVENTS, "WORKFLOW_HISTORY_EVENT_BUDGET")
                record = {"event": event, "run_id": self.run_id,
                          "definition_sha256": self.definition.fingerprint, "data": value}
                if node_id is not None:
                    record["node_id"] = node_id
                if event == "node.result":
                    require(node_id is not None and value.get("node_id") == node_id, "WORKFLOW_RESULT_NODE_MISMATCH")
                    identifier(value.get("node_run_id"))
                    require(type(value.get("iteration")) is int and value["iteration"] >= 0 and
                            type(value.get("state")) is str and value["state"] in STATES,
                            "WORKFLOW_RESULT_POLICY_INVALID")
                    envelope = {"schema": RESULT_SCHEMA, "run_id": self.run_id,
                                "definition_sha256": self.definition.fingerprint, "node": value}
                    metadata_bytes = len(canonical(envelope).encode("utf-8"))
                    require(self._history_metadata_bytes + metadata_bytes + 4096 <= MAX_HISTORY_METADATA_BYTES,
                            "WORKFLOW_HISTORY_METADATA_BUDGET")
                    path = self.folder / ".results" / (value["node_run_id"] + ".json")
                    atomic_json(path, envelope, exclusive=True, max_bytes=MAX_RESULT_BYTES)
                    verified, stamp = _read(path)
                    require(verified == envelope, "WORKFLOW_RESULT_READBACK_FAILED")
                    value = {key: value[key] for key in _RESULT_KEYS if key in value}
                    value.update(result_path=path.relative_to(self.folder).as_posix(),
                                 result_sha256=stamp["sha256"], result_size_bytes=stamp["bytes"],
                                 result_file_identity=stamp["file_identity"])
                elif journal_metadata(record) != record:
                    # Compare the WHOLE journal record: its wrapper consumes
                    # depth too. Preserve actual nested ACKs, numeric byte
                    # counts and already-redacted fields without asking the
                    # ordinary journal redactor to silently rewrite them.
                    sequence = self._event_count + 1
                    envelope = {"schema": EVENT_RECORD_SCHEMA, "run_id": self.run_id,
                        "definition_sha256": self.definition.fingerprint, "event": event,
                        "node_id": node_id, "sequence": sequence, "data": value}
                    _record(envelope, redact=False)
                    metadata_bytes = len(canonical(envelope).encode("utf-8"))
                    require(metadata_bytes <= MAX_RESULT_BYTES, "WORKFLOW_RECORD_BYTE_BUDGET")
                    require(self._history_metadata_bytes + metadata_bytes + 4096 <= MAX_HISTORY_METADATA_BYTES,
                            "WORKFLOW_HISTORY_METADATA_BUDGET")
                    directory = safe_path(self.folder / ".events")
                    directory.mkdir(mode=0o700, exist_ok=True)
                    # Sequence is checked under the writer claim. A failed
                    # publication leaves an immutable orphan and refuses an
                    # uncertain replay at the same sequence, rather than
                    # generating unlimited differently named retry records.
                    path = directory / (str(sequence) + ".json")
                    atomic_json(path, envelope, exclusive=True, max_bytes=MAX_RESULT_BYTES)
                    verified, stamp = _read(path)
                    require(verified == envelope, "WORKFLOW_EVENT_READBACK_FAILED")
                    value = {"event_record_schema": EVENT_RECORD_SCHEMA,
                        "event_record_path": path.relative_to(self.folder).as_posix(),
                        "event_record_sha256": stamp["sha256"], "event_record_size_bytes": stamp["bytes"],
                        "event_record_file_identity": stamp["file_identity"], "event_record_sequence": sequence}
                record["data"] = value
                require(journal_metadata(record) == record, "WORKFLOW_EVENT_WOULD_LOSE_METADATA")
                # The fixed headroom includes EvidenceJournal's own operation,
                # UTC, monotonic and provenance fields. It is conservative.
                metadata_bytes += len(canonical(record).encode("utf-8")) + 1024
                require(self._history_metadata_bytes + metadata_bytes <= MAX_HISTORY_METADATA_BYTES,
                        "WORKFLOW_HISTORY_METADATA_BUDGET")
                answer = EvidenceJournal(self.folder / "journal").append(record)
                self._event_count += 1
                self._history_metadata_bytes += metadata_bytes
                return {**answer,"sequence":self._event_count}
            finally:
                if temporary_claim:
                    self.release_writer()

    def _hydrate_result(self, data, node_id):
        require(type(data) is dict and data.get("node_id") == node_id, "WORKFLOW_RESULT_NODE_MISMATCH")
        identifier(data.get("node_run_id"))
        expected = ".results/" + data["node_run_id"] + ".json"
        require(data.get("result_path") == expected, "WORKFLOW_RESULT_PATH_INVALID")
        envelope, stamp = _read(self.folder / expected)
        require(stamp["sha256"] == data.get("result_sha256") and stamp["bytes"] == data.get("result_size_bytes") and
                stamp["file_identity"] == data.get("result_file_identity"), "WORKFLOW_RESULT_BINDING_CHANGED")
        require(set(envelope) == {"schema", "run_id", "definition_sha256", "node"} and
                envelope.get("schema") == RESULT_SCHEMA and envelope.get("run_id") == self.run_id and
                envelope.get("definition_sha256") == self.definition.fingerprint and type(envelope.get("node")) is dict,
                "WORKFLOW_RESULT_ENVELOPE_INVALID")
        value = envelope["node"]
        require(all(value.get(key) == data.get(key) for key in _RESULT_KEYS if key in data) and
                value.get("node_id") == node_id, "WORKFLOW_RESULT_METADATA_MISMATCH")
        return value

    def _hydrate_event(self, data, event, node_id, sequence):
        require(set(data) == _EVENT_BINDING_KEYS and data.get("event_record_schema") == EVENT_RECORD_SCHEMA and
                type(data.get("event_record_sequence")) is int and data["event_record_sequence"] == sequence,
                "WORKFLOW_EVENT_BINDING_INVALID")
        expected = ".events/" + str(sequence) + ".json"
        require(data.get("event_record_path") == expected, "WORKFLOW_EVENT_PATH_INVALID")
        envelope, stamp = _read(self.folder / expected)
        require(stamp["sha256"] == data.get("event_record_sha256") and
                stamp["bytes"] == data.get("event_record_size_bytes") and
                stamp["file_identity"] == data.get("event_record_file_identity"),
                "WORKFLOW_EVENT_BINDING_CHANGED")
        require(set(envelope) == {"schema", "run_id", "definition_sha256", "event", "node_id", "sequence", "data"}
                and envelope.get("schema") == EVENT_RECORD_SCHEMA and envelope.get("run_id") == self.run_id
                and envelope.get("definition_sha256") == self.definition.fingerprint and envelope.get("event") == event
                and envelope.get("node_id") == node_id and type(envelope.get("sequence")) is int
                and envelope["sequence"] == sequence and type(envelope.get("data")) is dict,
                "WORKFLOW_EVENT_ENVELOPE_INVALID")
        return envelope["data"]

    def _validate_event_data(self, event, node_id, data):
        indexed = {node.node_id: node for node in self.definition.nodes}
        if event.startswith("node.") or event == "run.checkpoint":
            require(type(node_id) is str and node_id in indexed and data.get("node_id") == node_id,
                    "WORKFLOW_HISTORY_NODE_BINDING_INVALID")
        if event == "node.intent":
            node = indexed[node_id]
            identifier(data.get("node_run_id"))
            require(node.kind in ("TOOL", "REPEAT") and data.get("tool_id") == node.tool_id and
                    type(data.get("read_only")) is bool and data.get("state") == "RUNNING" and
                    type(data.get("iteration")) is int and 0 <= data["iteration"] < node.repeat_count,
                    "WORKFLOW_INTENT_INVALID")
        elif event == "node.result":
            node = indexed[node_id]
            identifier(data.get("node_run_id"))
            require(type(data.get("iteration")) is int and 0 <= data["iteration"] < node.repeat_count and
                    type(data.get("state")) is str and data["state"] in STATES,
                    "WORKFLOW_RESULT_POLICY_INVALID")
        elif event == "run.checkpoint":
            require(indexed[node_id].kind == "CHECKPOINT" and data.get("state") == "WAITING_FOR_HUMAN",
                    "WORKFLOW_CHECKPOINT_INVALID")
        elif event in ("run.state", "node.state"):
            require(type(data.get("state")) is str and data["state"] in STATES, "WORKFLOW_HISTORY_STATE_INVALID")
        elif event == "run.cleanup":
            require(type(data.get("cleanup")) is dict, "WORKFLOW_RUNTIME_CLEANUP_INVALID")

    def _journal_advanced(self, sequence, digest, deadline):
        """Observe a committed append after our prefix, without adopting it."""
        require(time.monotonic() < deadline, "WORKFLOW_HISTORY_READ_DEADLINE")
        path = safe_path(self.folder / "journal" / "deep-inspection.sqlite3")
        require(path.stat().st_size <= MAX_JOURNAL_BYTES, "WORKFLOW_HISTORY_STORAGE_BUDGET")
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=.5)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_RESULT_BYTES + 65536)
            db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            db.execute("BEGIN")
            latest = db.execute("SELECT sequence FROM actions ORDER BY sequence DESC LIMIT 1").fetchone()
            if latest is None:
                return False
            require(type(latest[0]) is int and 1 <= latest[0] <= MAX_EVENTS, "WORKFLOW_HISTORY_EVENT_BUDGET")
            if latest[0] <= sequence:
                return False
            old = db.execute("SELECT record_sha256 FROM actions WHERE sequence=?", (sequence,)).fetchone()
            return (sequence == 0 and old is None) or old == (digest,)

    def _other_history_writer_live(self, deadline):
        """Check only a local history lease; this never grants native rights."""
        import psutil
        require(time.monotonic() < deadline, "WORKFLOW_HISTORY_READ_DEADLINE")
        path = safe_path(self.folder / ".writer.json")
        try:
            owner, stamp = _read(path, limit=4096)
        except FileNotFoundError:
            return False
        require(owner.get("schema") == "blackbox.workflow-writer/1" and owner.get("run_id") == self.run_id
                and type(owner.get("pid")) is int and owner["pid"] > 0
                and type(owner.get("process_created")) in (int, float)
                and math.isfinite(owner["process_created"]) and owner["process_created"] > 0,
                "WORKFLOW_WRITER_LOCK_INVALID")
        identifier(owner.get("owner_nonce"), "WORKFLOW_WRITER_LOCK_INVALID")
        # acquire_writer can verify an older facade after obtaining a NEW claim.
        # That own claim is not evidence that an old orphan is an in-flight write.
        if self._writer_nonce is not None and owner["owner_nonce"] == self._writer_nonce:
            return False
        try:
            live = _observed_writer_birth(owner["pid"]) == owner["process_created"]
        except psutil.NoSuchProcess:
            live = False
        except (psutil.AccessDenied, OSError) as error:
            raise WorkflowError("WORKFLOW_WRITER_OWNERSHIP_UNCONFIRMED") from error
        try:
            after, after_stamp = _read(path, limit=4096)
        except FileNotFoundError:
            return False  # The fresh committed tail is checked again by the caller.
        require(after == owner and after_stamp == stamp, "WORKFLOW_HISTORY_BUSY")
        require(time.monotonic() < deadline, "WORKFLOW_HISTORY_READ_DEADLINE")
        return live

    def _foreign_event_record(self, path, sequence, digest, deadline):
        """Separate a racing publisher from a stable unbound immutable record."""
        if self._journal_advanced(sequence, digest, deadline):
            raise WorkflowError("WORKFLOW_HISTORY_BUSY")
        next_name = str(sequence + 1) + ".json"
        candidate = path.name == next_name or re.fullmatch(re.escape(next_name) + r"\.[0-9a-f]{32}\.tmp", path.name)
        if candidate and self._other_history_writer_live(deadline):
            raise WorkflowError("WORKFLOW_HISTORY_BUSY")
        if self._journal_advanced(sequence, digest, deadline) or not path.exists():
            raise WorkflowError("WORKFLOW_HISTORY_BUSY")
        raise WorkflowError("WORKFLOW_EVENT_ORPHAN_OR_FOREIGN_RECORD")

    def read_events(self):
        # The counters below belong to this facade. A concurrent read must not
        # overwrite a newer append's sequence/budget after its SQL snapshot.
        with self._lock:
            return self._read_events_locked()

    def _read_events_locked(self):
        self._check_identity()
        path = safe_path(self.folder / "journal" / "deep-inspection.sqlite3")
        require(path.is_file() and path.stat().st_size <= MAX_JOURNAL_BYTES, "WORKFLOW_HISTORY_STORAGE_BUDGET")
        records, previous, metadata_bytes, results, event_records = [], "0" * 64, 0, set(), set()
        deadline = time.monotonic() + 30
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA cache_size=-4096")
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_RESULT_BYTES + 65536)
            db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            require(db.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "WORKFLOW_HISTORY_SQL_CORRUPT")
            schema = db.execute("SELECT type,name,tbl_name FROM sqlite_master").fetchall()
            require(all(kind == "table" and name in ("actions", "snapshots", "sqlite_sequence") or
                        kind == "index" and name.startswith("sqlite_autoindex_") and table in ("actions", "snapshots")
                        for kind, name, table in schema), "WORKFLOW_HISTORY_SCHEMA_UNEXPECTED")
            expected = [("sequence", "INTEGER"), ("operation_id", "TEXT"), ("timestamp_utc", "TEXT"),
                        ("monotonic_ns", "INTEGER"), ("record_json", "TEXT"), ("previous_sha256", "TEXT"),
                        ("record_sha256", "TEXT")]
            require([(row[1], row[2]) for row in db.execute("PRAGMA table_info(actions)")] == expected,
                    "WORKFLOW_HISTORY_SCHEMA_INVALID")
            require(db.execute("SELECT count(*) FROM snapshots").fetchone() == (0,), "WORKFLOW_HISTORY_FOREIGN_SNAPSHOTS")
            db.execute("BEGIN")
            rows = db.execute("SELECT sequence,operation_id,timestamp_utc,monotonic_ns,record_json,previous_sha256,record_sha256 FROM actions ORDER BY sequence")
            for count, (sequence, operation_id, timestamp, mono, raw, linked, digest) in enumerate(rows, 1):
                require(count <= MAX_EVENTS and count == sequence and type(raw) is str and linked == previous and
                        type(linked) is str and len(linked) == 64 and
                        hashlib.sha256(linked.encode("ascii") + raw.encode("utf-8")).hexdigest() == digest,
                        "WORKFLOW_HISTORY_HASH_CHAIN_MISMATCH")
                event = _strict_json(raw.encode("utf-8"))
                metadata_bytes += len(raw.encode("utf-8"))
                require(event.get("operation_id") == operation_id and event.get("timestamp_utc") == timestamp and
                        event.get("monotonic_ns") == mono and event.get("run_id") == self.run_id and
                        event.get("definition_sha256") == self.definition.fingerprint and type(event.get("event")) is str and
                        event["event"] in _EVENTS and
                        type(event.get("data")) is dict, "WORKFLOW_HISTORY_RECORD_INVALID")
                if event["event"] == "node.result":
                    event["journal_binding"] = deepcopy(event["data"])
                    event["data"] = self._hydrate_result(event["data"], event.get("node_id"))
                    metadata_bytes += event["journal_binding"]["result_size_bytes"]
                    require(event["data"]["node_run_id"] not in results, "WORKFLOW_HISTORY_DUPLICATE_RESULT")
                    results.add(event["data"]["node_run_id"])
                elif any(key in event["data"] for key in _EVENT_BINDING_KEYS):
                    event["journal_binding"] = deepcopy(event["data"])
                    event["data"] = self._hydrate_event(event["data"], event["event"], event.get("node_id"), sequence)
                    metadata_bytes += event["journal_binding"]["event_record_size_bytes"]
                    event_records.add(str(sequence) + ".json")
                self._validate_event_data(event["event"], event.get("node_id"), event["data"])
                require(event["event"] != "run.created" or count == 1, "WORKFLOW_HISTORY_DUPLICATE_CREATED")
                require(metadata_bytes <= MAX_HISTORY_METADATA_BYTES, "WORKFLOW_HISTORY_METADATA_BUDGET")
                event["sequence"], event["record_sha256"] = sequence, digest
                records.append(event)
                previous = digest
        directory = safe_path(self.folder / ".events")
        if directory.exists():
            require(directory.is_dir(), "WORKFLOW_EVENT_STORAGE_INVALID")
            observed = set()
            with os.scandir(directory) as entries:
                for count, entry in enumerate(entries, 1):
                    require(time.monotonic() < deadline, "WORKFLOW_HISTORY_READ_DEADLINE")
                    require(count <= MAX_EVENTS, "WORKFLOW_HISTORY_EVENT_BUDGET")
                    entry_path = safe_path(Path(entry.path))
                    if entry.name not in event_records:
                        self._foreign_event_record(entry_path, len(records), previous, deadline)
                    require(entry_path.is_file(), "WORKFLOW_EVENT_RECORD_MISSING")
                    observed.add(entry.name)
            require(observed == event_records, "WORKFLOW_EVENT_RECORD_MISSING")
        else:
            require(not event_records, "WORKFLOW_EVENT_RECORD_MISSING")
        require(bool(records) and records[0]["event"] == "run.created", "WORKFLOW_HISTORY_CREATED_MISSING")
        self._event_count, self._history_metadata_bytes = len(records), metadata_bytes
        return records

    def load_state(self):
        return self._state_from_events(self.read_events())

    def _state_from_events(self,events):
        """Hydrate one already verified snapshot; never mix journal prefixes."""
        nodes = {node.node_id: {"node_id": node.node_id, "tool_id": node.tool_id, "kind": node.kind,
                 "state": "QUEUED", "iterations_completed": 0, "total_iterations": node.repeat_count,
                 "outputs": {}, "run_receipt": None, "run_context": None, "tool_descriptor": None,
                 "cleanup": {"status": "NOT_STARTED", "confirmed": False}, "component_status": None,
                 "attempts": []}
                 for node in self.definition.nodes}
        state = {"schema": RUN_SCHEMA, "run_id": self.run_id, "workflow_id": self.definition.workflow_id,
                 "definition_sha256": self.definition.fingerprint, "state": "QUEUED", "coverage": {},
                 "cleanup": {"status": "NOT_COLLECTED", "confirmed": False}, "elapsed_seconds": 0,
                 "output_folder": str(self.folder), "errors": []}
        unfinished = {}
        for event in events:
            data, event_type = event["data"], event["event"]
            node_id = event.get("node_id") or data.get("node_id")
            if event_type == "node.intent":
                require(node_id in nodes and type(data.get("node_run_id")) is str, "WORKFLOW_INTENT_INVALID")
                unfinished[data["node_run_id"]] = data
                nodes[node_id]["state"] = data.get("state", "RUNNING")
            elif event_type == "node.result":
                require(node_id in nodes, "WORKFLOW_HISTORY_UNKNOWN_NODE")
                old = nodes[node_id]
                attempts = old["attempts"] + [{key: data.get(key) for key in
                    ("node_run_id", "iteration", "state", "component_status", "reason_code")}]
                iterations = max(old["iterations_completed"], data.get("iteration", 0) + 1)
                old.update(deepcopy(data))
                old.update(attempts=attempts[-64:], iterations_completed=iterations)
                if old["state"] == "COMPLETED" and iterations < old["total_iterations"]:
                    old["state"] = "QUEUED"
                unfinished.pop(data["node_run_id"], None)
            elif event_type == "node.state":
                require(node_id in nodes and data.get("state") in STATES, "WORKFLOW_NODE_STATE_INVALID")
                # phase is an event annotation; the live engine changes only
                # these state fields, so a reopen preserves its node record.
                nodes[node_id].update({key: deepcopy(value) for key, value in data.items() if key in
                    ("node_id", "node_run_id", "state", "reason_code", "execution_started")})
            elif event_type in ("run.state", "run.checkpoint"):
                state.update({key: deepcopy(value) for key, value in data.items() if key not in
                              ("nodes", "run_id", "workflow_id", "definition_sha256", "schema")})
                if event_type == "run.checkpoint":
                    state["state"] = "WAITING_FOR_HUMAN"
                    if node_id in nodes:
                        nodes[node_id]["state"] = "WAITING_FOR_HUMAN"
            elif event_type == "run.cleanup":
                require(type(data.get("cleanup")) is dict, "WORKFLOW_RUNTIME_CLEANUP_INVALID")
                state["cleanup"] = deepcopy(data["cleanup"])
        for intent in unfinished.values():
            node = nodes[intent["node_id"]]
            node["state"] = "RECOVERY_UNCONFIRMED" if intent.get("read_only") is not True else "QUEUED"
            node["reason_code"] = "UNFINISHED_EFFECT_INTENT" if intent.get("read_only") is not True else "READONLY_REVALIDATION_REQUIRED"
            node["unfinished_intent"] = deepcopy(intent)
            if intent.get("read_only") is not True:
                state["state"] = "RECOVERY_UNCONFIRMED"
        state["nodes"] = list(nodes.values())
        state["unfinished_intents"] = list(unfinished.values())
        return state

    def close(self):
        """Release only this facade's history writer; no native owner is touched."""
        with self._lock:
            if self._writer_pins:
                return False
            self.release_writer()
            return True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
