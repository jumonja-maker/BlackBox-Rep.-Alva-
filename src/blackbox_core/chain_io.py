"""Ordinary-token workflow references; hashing is change detection, not trust."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import time

from .chain_contracts import Artifact, WorkflowError, canonical, require
from .deep_contracts import ProcessIdentity
from .session_v2 import safe_path

MAX_SOURCE_BYTES = 8 * 1024**3
_SESSION_FILES = ("session-v2.sqlite3", "research.sqlite3", "session.sqlite3")


def check_cancel(cancel=None, deadline=None):
    if cancel is not None and (cancel.is_set() if hasattr(cancel, "is_set") else cancel()):
        raise InterruptedError("WORKFLOW_CANCELLED")
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("WORKFLOW_DEADLINE")


def _stamp(value):
    return {"device": value.st_dev, "inode": value.st_ino, "size": value.st_size, "mtime_ns": value.st_mtime_ns}


def fingerprint_file(path, cancel=None, deadline=None, max_bytes=MAX_SOURCE_BYTES):
    path = safe_path(Path(path))
    check_cancel(cancel, deadline)
    initial = path.stat()
    require(stat.S_ISREG(initial.st_mode) and initial.st_size <= max_bytes, "WORKFLOW_SOURCE_FILE_BUDGET_OR_TYPE")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    digest = hashlib.sha256()
    count = 0
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(_stamp(opened) == _stamp(initial) and stat.S_ISREG(opened.st_mode), "WORKFLOW_SOURCE_CHANGED_AT_OPEN")
        while block := stream.read(1024 * 1024):
            check_cancel(cancel, deadline)
            count += len(block)
            require(count <= max_bytes, "WORKFLOW_SOURCE_FILE_BUDGET")
            digest.update(block)
        final = os.fstat(stream.fileno())
    check_cancel(cancel, deadline)
    require(_stamp(opened) == _stamp(final) == _stamp(path.stat()) and count == opened.st_size,
            "WORKFLOW_SOURCE_CHANGED_DURING_READ")
    return {"_path": str(path), "sha256": digest.hexdigest(), "bytes": count, "file_identity": _stamp(final)}


def _verify_file(reference, *, cancel=None, deadline=None):
    require(type(reference) is dict and type(reference.get("_path")) is str and
            type(reference.get("sha256")) is str and len(reference["sha256"]) == 64,
            "WORKFLOW_SOURCE_FINGERPRINT_REQUIRED")
    actual = fingerprint_file(reference["_path"], cancel=cancel, deadline=deadline)
    require(actual["sha256"] == reference["sha256"] and actual["bytes"] == reference.get("bytes"),
            "WORKFLOW_SOURCE_HASH_CHANGED")
    if "file_identity" in reference:
        require(actual["file_identity"] == reference["file_identity"], "WORKFLOW_SOURCE_INSTANCE_CHANGED")
    return actual


def make_file_artifact(kind, path, *, metadata=None, sources=(), coverage=None, clock_domains=()):
    path = safe_path(Path(path))
    value = dict(metadata or {})
    if path.is_dir():
        require(kind == "SESSION", "WORKFLOW_DIRECTORY_ARTIFACT_TYPE")
        files = [fingerprint_file(path / name) for name in _SESSION_FILES if (path / name).is_file()]
        require(bool(files), "WORKFLOW_SESSION_DATABASES_MISSING")
        for name in _SESSION_FILES:
            wal = path / (name + "-wal")
            require(not wal.exists() or wal.stat().st_size == 0, "WORKFLOW_SESSION_STILL_WRITING")
        value.update(_path=str(path), files=files,
                     sha256=hashlib.sha256(canonical(files).encode()).hexdigest(),
                     bytes=sum(row["bytes"] for row in files))
    else:
        value.update(fingerprint_file(path))
    return Artifact(kind, value, sources=tuple(sources), clock_domains=tuple(clock_domains),
                    coverage=coverage or {"evidence_completeness": "UNKNOWN_CAPTURE_COMPLETENESS"})


def make_process_artifact(identity):
    identity = ProcessIdentity.from_dict(identity)
    return Artifact("PROCESS", {"identity": identity.to_dict()},
        sources=({"kind": "LIVE_PROCESS_INSTANCE", "identity": identity.to_dict(),
                  "provenance": "LOCAL_OS_OBSERVATION_NOT_AUTHENTICATED"},),
        clock_domains=("WINDOWS_CREATION_FILETIME",),
        coverage={"evidence_completeness": "IDENTITY_ONLY_NOT_DIAGNOSTIC_COVERAGE"})


def verify_artifact(artifact, *, cancel=None, deadline=None, _seen=None, _depth=0):
    """Revalidate every declared byte source; no origin/authentication promotion."""
    if not isinstance(artifact, Artifact):
        artifact = Artifact.from_dict(artifact)
    require(_depth <= 16, "WORKFLOW_ARTIFACT_LINEAGE_DEPTH")
    seen = {} if _seen is None else _seen
    raw = canonical(artifact.to_dict())
    if artifact.artifact_id in seen:
        require(seen[artifact.artifact_id] == raw, "WORKFLOW_ARTIFACT_ID_CONTRADICTION")
        return {"status": "VERIFIED_REFERENCE_ALREADY_CHECKED", "artifact_id": artifact.artifact_id}
    require(len(seen) < 4096, "WORKFLOW_ARTIFACT_LINEAGE_BUDGET")
    seen[artifact.artifact_id] = raw
    check_cancel(cancel, deadline)
    value = artifact.value
    if artifact.kind == "PROCESS":
        expected = ProcessIdentity.from_dict(value.get("identity"))
        if os.name != "nt":
            raise WorkflowError("WORKFLOW_NATIVE_FILETIME_REQUIRES_WINDOWS")
        from .deep_native import capture_identity
        actual = ProcessIdentity.from_dict(capture_identity(expected.pid))
        require(actual == expected, "WORKFLOW_PROCESS_INSTANCE_CHANGED")
    elif value.get("_path"):
        path = safe_path(Path(value["_path"]))
        if artifact.kind == "SESSION" and "files" in value:
            require(path.is_dir() and type(value["files"]) is list and 0 < len(value["files"]) <= 16,
                    "WORKFLOW_SESSION_SOURCE_REQUIRED")
            for row in value["files"]:
                require(Path(row["_path"]).parent == path, "WORKFLOW_SESSION_SOURCE_PATH_MISMATCH")
                _verify_file(row, cancel=cancel, deadline=deadline)
                wal = Path(row["_path"] + "-wal")
                require(not wal.exists() or wal.stat().st_size == 0, "WORKFLOW_SESSION_STILL_WRITING")
            require(hashlib.sha256(canonical(value["files"]).encode()).hexdigest() == value.get("sha256"),
                    "WORKFLOW_SESSION_FINGERPRINT_CHANGED")
        else:
            _verify_file(value, cancel=cancel, deadline=deadline)
    elif artifact.kind not in ("EVIDENCE_SET", "RECEIPT", "BOOLEAN", "PROCESS_SET"):
        raise WorkflowError("WORKFLOW_ARTIFACT_HAS_NO_VERIFIABLE_SOURCE")
    auxiliary = value.get("auxiliary_files", [])
    require(type(auxiliary) is list and len(auxiliary) <= 64, "WORKFLOW_AUXILIARY_SOURCE_BUDGET")
    for row in auxiliary:
        _verify_file(row, cancel=cancel, deadline=deadline)
    upstream = value.get("upstream_artifacts", [])
    members = value.get("items", []) if artifact.kind == "EVIDENCE_SET" else []
    require(type(upstream) is list and len(upstream) <= 1024 and type(members) is list and len(members) <= 256,
            "WORKFLOW_ARTIFACT_LINEAGE_BUDGET")
    paths = {str(safe_path(Path(row["_path"]))) for row in auxiliary}
    if value.get("_path"):
        paths.add(str(safe_path(Path(value["_path"]))))
    for row in [*upstream, *members]:
        source = Artifact.from_dict(row)
        verify_artifact(source, cancel=cancel, deadline=deadline, _seen=seen, _depth=_depth + 1)
        if source.value.get("_path"):
            paths.add(str(safe_path(Path(source.value["_path"]))))
    for key in ("_before_path", "_after_path", "_case_path", "_session_path"):
        if value.get(key):
            require(str(safe_path(Path(value[key]))) in paths, "WORKFLOW_UNBOUND_PRIVATE_SOURCE_LOCATOR")
    return {"status": "VERIFIED_BYTE_OR_INSTANCE_CONSISTENCY", "artifact_id": artifact.artifact_id,
            "producer_authentication": "NOT_ESTABLISHED"}


def owned_output_bytes(folder, *, maximum, cancel=None, deadline=None):
    """Bound the run's files only; never traverse or remove diagnostic inputs."""
    root = safe_path(Path(folder))
    count = size = 0
    for parent, directories, names in os.walk(root, followlinks=False):
        check_cancel(cancel, deadline)
        for name in [*directories, *names]:
            path = safe_path(Path(parent) / name)
            count += 1
            require(count <= 10000, "WORKFLOW_OWNED_FILE_COUNT_BUDGET")
            try:
                info = path.stat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode):
                size += info.st_size
                require(size <= maximum, "WORKFLOW_OWNED_OUTPUT_BYTE_BUDGET")
    return size
