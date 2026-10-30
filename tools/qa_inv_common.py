"""Small evidence helpers; graph QA is executed only on hosted runners."""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "blackbox.investigation-graph/1"
RELATIONS = {"EXACT_IDENTITY", "DIRECT_REFERENCE", "BOUNDED_TIME_CORRELATION",
             "OBSERVED_DEPENDENCY", "TEMPORAL_COINCIDENCE", "HYPOTHESIS_ONLY",
             "NOT_ESTABLISHED", "CONTRADICTED"}
PRIVATE_SENTINEL = "BLACKBOX_INV_QA_PRIVATE_SECRET_NEVER_EXPORT"
QA_TOKEN = "BLACKBOX_INV_QA_PUBLIC_FIXTURE_TOKEN"


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def require_hosted(*, windows=False):
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
            "ALL_INVESTIGATION_QA_REQUIRES_GITHUB_HOSTED_RUNNER")
    if windows:
        require(os.name == "nt", "ACTUAL_WINDOWS_QA_REQUIRED")


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def exact_source():
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    require(len(sha) == 40 and sha == os.environ.get("GITHUB_SHA"), "EXACT_GITHUB_SHA_REQUIRED")
    dirty = subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=no"],
                                    cwd=ROOT, text=True).strip()
    require(not dirty, "INVESTIGATION_QA_TRACKED_SOURCE_MUST_BE_CLEAN")
    return sha


def readonly(path):
    db = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    db.execute("PRAGMA query_only=ON")
    return db


def trace_instances(index, pid):
    observed = set()
    with closing(readonly(index)) as db:
        for raw, in db.execute("SELECT data FROM events WHERE pid=? ORDER BY id", (pid,)):
            event = json.loads(raw)
            if type(event.get("process_instance")) is int:
                observed.add(event["process_instance"])
    require(len(observed) == 1, "OWNED_TRACE_LIFETIME_MISSING_OR_AMBIGUOUS_" + str(pid))
    return next(iter(observed))


def trace_source(index, pid):
    return {"source_type": "TRACE_INDEX", "path": str(index),
            "selection": {"pid": pid, "process_instance": trace_instances(index, pid)}}


def graph_facts(case):
    require(case.get("schema") == SCHEMA and type(case.get("case_id")) is str,
            "INVESTIGATION_GRAPH_SCHEMA_OR_CASE_ID_INVALID")
    nodes, edges = case.get("nodes"), case.get("edges")
    require(type(nodes) is list and type(edges) is list and type(case.get("coverage")) is dict,
            "INVESTIGATION_GRAPH_FIELDS_MISSING")
    by_id = {node.get("node_id"): node for node in nodes}
    require(len(by_id) == len(nodes) and None not in by_id, "INVESTIGATION_NODE_IDS_INVALID")
    for node in nodes:
        require(node.get("source_identity") and node.get("source_record_id") and
                len(node.get("source_sha256", "")) == 64 and node.get("verification_class"),
                "GRAPH_NODE_SOURCE_PROVENANCE_REQUIRED")
    edge_ids = set()
    for edge in edges:
        require(edge.get("edge_id") not in edge_ids and edge.get("from_node") in by_id and
                edge.get("to_node") in by_id and edge.get("relation_type") in RELATIONS,
                "GRAPH_EDGE_ENDPOINT_OR_CLASS_INVALID")
        edge_ids.add(edge["edge_id"])
        require(type(edge.get("limitations")) is list and type(edge.get("evidence_refs")) is list,
                "GRAPH_EDGE_LIMITATIONS_AND_REFERENCES_REQUIRED")
        if edge["relation_type"] == "DIRECT_REFERENCE":
            require(by_id[edge["from_node"]]["source_identity"] ==
                    by_id[edge["to_node"]]["source_identity"],
                    "UNVERIFIED_CROSS_SOURCE_REFERENCE_PROMOTED_TO_DIRECT")
    return by_id


def metadata(case, observation_type=None):
    return [node.get("metadata", {}) for node in case["nodes"]
            if observation_type is None or node.get("observation_type") == observation_type]


def assert_sources_unchanged(before):
    require(all(digest(Path(path)) == value for path, value in before.items()),
            "INVESTIGATION_READER_MODIFIED_ORIGINAL_SOURCE")


def validate_export(path, *, forbidden=()):
    path = Path(path)
    require(path.is_file() and 0 < path.stat().st_size <= 64 * 1024**2,
            "INVESTIGATION_EXPORT_SIZE_OR_FILE_INVALID")
    text = path.read_text(encoding="utf-8")
    for value in (PRIVATE_SENTINEL, QA_TOKEN, *forbidden):
        require(not value or value not in text, "INVESTIGATION_EXPORT_LEAKED_PRIVATE_PAYLOAD")
    if path.suffix == ".json":
        parsed = json.loads(text)
        require(type(parsed) is dict, "INVESTIGATION_JSON_EXPORT_NOT_OBJECT")
    else:
        require("<html" in text.lower(), "INVESTIGATION_HTML_EXPORT_MISSING")
    return {"file": path.name, "bytes": path.stat().st_size, "sha256": digest(path),
            "private_payload_absent": True}
