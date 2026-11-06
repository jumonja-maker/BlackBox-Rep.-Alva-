"""Artifactless R60 acceptance, exclusively on standard hosted Windows.

Source and frozen entry points call the same engine/adapters over real closed
Wave02 recordings. Contract fault fixtures are reported separately. No ordinary
SQLite recording is relabelled as a decoder trace, and no saved consent is used.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import threading
import time
import traceback


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def require_hosted_windows():
    require(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("RUNNER_OS") == "Windows", "R60_QA_REQUIRES_STANDARD_GITHUB_HOSTED_WINDOWS")


def file_hash(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 4 * 1024**3,
            "R60_QA_FILE_BUDGET")
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            digest.update(block)
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "R60_QA_FILE_CHANGED_WHILE_HASHING")
    return digest.hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False), encoding="ascii")


def read_json(path, *, maximum=32 * 1024**2):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum,
            "R60_QA_JSON_BUDGET")
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "R60_QA_DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def constant(_):
        raise AssertionError("R60_QA_NONFINITE_JSON")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def source_proof(expected):
    require_hosted_windows()
    require(type(expected) is str and re.fullmatch(r"[0-9a-f]{40}", expected), "R60_EXACT_SOURCE_REQUIRED")
    from blackbox_universal.provenance import source_identity
    proof = source_identity(expected)
    require(proof.get("source_identity_status") == "VERIFIED_EXPECTED_HEAD" and
            proof.get("actual_source_sha") == expected, "R60_CHECKOUT_OR_FROZEN_SOURCE_MISMATCH")
    return proof


def walk_metadata(value, *, depth=0):
    require(depth <= 32, "R60_QA_METADATA_DEPTH")
    if type(value) is dict:
        yield value
        for child in value.values():
            yield from walk_metadata(child, depth=depth + 1)
    elif type(value) is list:
        require(len(value) <= 100000, "R60_QA_METADATA_ROWS")
        for child in value:
            yield from walk_metadata(child, depth=depth + 1)


def independent_journal(folder):
    """Check the existing EvidenceJournal with stdlib SQL, without product readers."""
    folder = Path(folder).resolve(strict=True)
    marker = read_json(folder / "workflow-run.json", maximum=65536)
    require(marker.get("schema") == "blackbox.workflow-run/1" and
            type(marker.get("run_id")) is str and
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", marker["run_id"]) and
            type(marker.get("definition_sha256")) is str and
            re.fullmatch(r"[0-9a-f]{64}", marker["definition_sha256"]),
            "R60_RUN_MARKER_SCHEMA_OR_IDENTITY")
    paths = list(folder.rglob("deep-inspection.sqlite3"))
    path = folder / "journal" / "deep-inspection.sqlite3"
    require(len(paths) == 1 and paths[0] == path and not path.is_symlink() and
            path.stat().st_size <= 128 * 1024 * 1024,
            "R60_ONE_EXISTING_EVIDENCE_JOURNAL_REQUIRED")
    run_definition = read_json(folder / "definition.bbchain.json", maximum=1024**2)
    definition_raw = json.dumps(run_definition, sort_keys=True, ensure_ascii=True,
                                allow_nan=False, separators=(",", ":")).encode("ascii")
    require(hashlib.sha256(definition_raw).hexdigest() == marker["definition_sha256"],
            "R60_PERSISTED_DEFINITION_FINGERPRINT_MISMATCH")
    before = file_hash(path)
    records, previous, count, metadata_bytes, event_records = [], "0" * 64, 0, 0, set()
    event_keys = {"event_record_schema", "event_record_path", "event_record_sha256",
                  "event_record_size_bytes", "event_record_file_identity", "event_record_sequence"}
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA cache_size=-4096")
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 512 * 1024 + 65536)
        deadline = time.monotonic() + 30
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        require(db.execute("PRAGMA integrity_check").fetchone() == ("ok",), "R60_JOURNAL_SQL_INTEGRITY")
        objects = db.execute("SELECT type,name FROM sqlite_schema WHERE substr(name,1,7)!='sqlite_'").fetchall()
        require(all(kind in ("table", "index") for kind, _name in objects) and
                {name for kind, name in objects if kind == "table"} == {"actions", "snapshots"},
                "R60_JOURNAL_UNEXPECTED_SQL_OBJECTS")
        rows = db.execute("SELECT sequence,record_json,previous_sha256,record_sha256 FROM actions ORDER BY sequence")
        for count, (sequence, raw, linked, digest) in enumerate(rows, 1):
            require(count <= 100000 and sequence == count and linked == previous and type(raw) is str and
                    len(raw.encode("utf-8")) <= 512 * 1024 and
                    hashlib.sha256(linked.encode("ascii") + raw.encode("utf-8")).hexdigest() == digest,
                    "R60_JOURNAL_HASHCHAIN_OR_SEQUENCE")
            record = json.loads(raw)
            require(type(record) is dict, "R60_JOURNAL_RECORD_SHAPE")
            metadata_bytes += len(raw.encode("utf-8"))
            if record.get("event") == "node.result":
                reference = record.get("data", {})
                node_run_id = reference.get("node_run_id")
                require(type(node_run_id) is str and
                        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", node_run_id) and
                        reference.get("result_path") == ".results/" + node_run_id + ".json",
                        "R60_NODE_RESULT_SIDECAR_PATH")
                sidecar = folder / ".results" / (node_run_id + ".json")
                require(not (folder / ".results").is_symlink() and not sidecar.is_symlink(),
                        "R60_NODE_RESULT_SIDECAR_SYMLINK")
                stat = sidecar.stat()
                identity = {"device": stat.st_dev, "inode": stat.st_ino,
                            "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
                require(0 < stat.st_size <= 512 * 1024 and
                        reference.get("result_size_bytes") == stat.st_size and
                        reference.get("result_file_identity") == identity and
                        reference.get("result_sha256") == file_hash(sidecar),
                        "R60_NODE_RESULT_SIDECAR_IDENTITY_OR_HASH")
                envelope = read_json(sidecar, maximum=512 * 1024)
                require(set(envelope) == {"schema", "run_id", "definition_sha256", "node"} and
                        envelope["schema"] == "blackbox.workflow-node-result/1" and
                        envelope["run_id"] == marker["run_id"] and
                        envelope["definition_sha256"] == marker["definition_sha256"] and
                        type(envelope["node"]) is dict, "R60_NODE_RESULT_SIDECAR_ENVELOPE")
                node = envelope["node"]
                require(node.get("node_run_id") == node_run_id and
                        node.get("node_id") == record.get("node_id") == reference.get("node_id") and
                        node.get("iteration") == reference.get("iteration") and
                        node.get("state") == reference.get("state"),
                        "R60_NODE_RESULT_SIDECAR_EVENT_BINDING")
                record = {**record, "data": node}
                metadata_bytes += stat.st_size
            elif isinstance(record.get("data"), dict) and any(key in record["data"] for key in event_keys):
                reference = record["data"]
                require(set(reference) == event_keys and
                        reference.get("event_record_schema") == "blackbox.workflow-event/1" and
                        type(reference.get("event_record_sequence")) is int and
                        reference["event_record_sequence"] == sequence and
                        reference.get("event_record_path") == ".events/" + str(sequence) + ".json",
                        "R60_EVENT_RECORD_SIDECAR_BINDING")
                directory = folder / ".events"
                sidecar = directory / (str(sequence) + ".json")
                require(not directory.is_symlink() and not sidecar.is_symlink(),
                        "R60_EVENT_RECORD_SIDECAR_SYMLINK")
                stat = sidecar.stat()
                identity = {"device": stat.st_dev, "inode": stat.st_ino,
                            "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
                require(0 < stat.st_size <= 512 * 1024 and
                        reference.get("event_record_size_bytes") == stat.st_size and
                        reference.get("event_record_file_identity") == identity and
                        reference.get("event_record_sha256") == file_hash(sidecar),
                        "R60_EVENT_RECORD_SIDECAR_IDENTITY_OR_HASH")
                envelope = read_json(sidecar, maximum=512 * 1024)
                require(set(envelope) == {"schema", "run_id", "definition_sha256", "event", "node_id", "sequence", "data"}
                        and envelope.get("schema") == "blackbox.workflow-event/1"
                        and envelope.get("run_id") == marker["run_id"]
                        and envelope.get("definition_sha256") == marker["definition_sha256"]
                        and envelope.get("event") == record.get("event")
                        and envelope.get("node_id") == record.get("node_id")
                        and type(envelope.get("sequence")) is int and envelope["sequence"] == sequence
                        and type(envelope.get("data")) is dict,
                        "R60_EVENT_RECORD_SIDECAR_ENVELOPE")
                after = sidecar.stat()
                require(reference["event_record_sha256"] == file_hash(sidecar) and
                        identity == {"device": after.st_dev, "inode": after.st_ino,
                                     "size": after.st_size, "mtime_ns": after.st_mtime_ns},
                        "R60_EVENT_RECORD_SIDECAR_CHANGED_DURING_READBACK")
                record = {**record, "data": envelope["data"]}
                metadata_bytes += stat.st_size
                event_records.add(sidecar.name)
            require(metadata_bytes <= 64 * 1024 * 1024, "R60_JOURNAL_FULL_METADATA_BUDGET")
            records.append(record)
            previous = digest
    directory = folder / ".events"
    if directory.exists():
        require(directory.is_dir() and not directory.is_symlink(), "R60_EVENT_RECORD_DIRECTORY_INVALID")
        observed = set()
        with os.scandir(directory) as entries:
            for number, entry in enumerate(entries, 1):
                require(time.monotonic() < deadline, "R60_JOURNAL_READ_DEADLINE")
                require(number <= 100000 and entry.is_file() and not entry.is_symlink() and entry.name in event_records,
                        "R60_EVENT_RECORD_ORPHAN_OR_FOREIGN")
                observed.add(entry.name)
        require(observed == event_records, "R60_EVENT_RECORD_MISSING")
    else:
        require(not event_records, "R60_EVENT_RECORD_MISSING")
    require(file_hash(path) == before and count > 0, "R60_JOURNAL_CHANGED_DURING_READBACK")
    return records, {"sqlite_integrity": "ok", "hashchain_verified": True, "event_count": count,
                     "sha256": before, "source_unchanged": True,
                     "scope": "LOCAL_CHANGE_DETECTION_NOT_AUTHENTICATED_PROVENANCE"}


def actual_invocations(records, operation):
    """Require one unambiguous persisted context and receipt per actual run ID."""
    contexts, receipts = {}, {}
    for event in records:
        if event.get("event") != "node.result":
            continue
        data = event.get("data", {})
        context, receipt = data.get("run_context"), data.get("run_receipt")
        if type(context) is not dict or context.get("operation") != operation:
            continue
        require(type(receipt) is dict and receipt.get("operation") == operation and
                receipt.get("contract_version") == 1 and receipt.get("run_id") == context.get("run_id") and
                type(context.get("started_monotonic_ns")) is int and
                type(data.get("node_run_id")) is str and type(data.get("iteration")) is int,
                "R60_ACTUAL_RESULT_CONTEXT_RECEIPT_REQUIRED")
        run_id = context["run_id"]
        require(run_id not in contexts, "R60_DUPLICATE_ACTUAL_RESULT")
        contexts[run_id], receipts[run_id] = context, receipt
    require(contexts and set(contexts) == set(receipts), "R60_ACTUAL_CONTEXT_RECEIPT_BINDING_REQUIRED")
    return sorted(((contexts[key], receipts[key]) for key in contexts),
                  key=lambda pair: pair[0]["started_monotonic_ns"])


def definition(nodes, edges, *, identity="native-full", seconds=10800, workers=4, allow_effectful=False):
    from blackbox_core.chain_contracts import WorkflowDefinition
    return WorkflowDefinition.from_dict({"schema": "blackbox.workflow-definition/1",
        "workflow_id": "qa-r60-" + identity, "title": "Explicit hosted R60 " + identity,
        "description": "Actual owned QA evidence; imported clocks and root cause remain explicit.",
        "profile": {"profile_id": "application" if allow_effectful else "case", "overrides": {
            "max_seconds": seconds, "max_workers": workers, "allow_effectful": allow_effectful}},
        "nodes": nodes, "edges": edges, "budget": {"seconds": seconds, "max_workers": workers,
            "max_owned_resources": 16, "max_output_bytes": 512 * 1024**2}})


def link(first, source_port, second, target_port):
    return {"edge_id": first + "." + source_port + "-" + second + "." + target_port,
            "source_node": first, "source_port": source_port,
            "target_node": second, "target_port": target_port}


def run_graph(workflow, output, *, runtime=None, allow_partial=True, run_id=None):
    from blackbox_core.chain_adapters import build_catalog
    from blackbox_core.chain_engine import WorkflowEngine
    from blackbox_core.chain_store import WorkflowRunStore
    from blackbox_core.chain_validation import validate_workflow
    catalog = build_catalog(runtime)
    validation = validate_workflow(workflow, catalog, runtime=runtime)
    require(validation.get("ready") is True, "R60_NATIVE_GRAPH_PREFLIGHT: " +
            json.dumps(validation.get("errors", []), ensure_ascii=True)[:1800])
    store = WorkflowRunStore.create(output, workflow, run_id=run_id)
    engine = WorkflowEngine(workflow, catalog=catalog, store=store, runtime=runtime)
    snapshot = engine.run()
    # Artifactless acceptance must preserve the actual failing boundary before
    # an assertion exits the process and the hosted workspace disappears.
    summary = {key: snapshot.get(key) for key in
        ("run_id", "workflow_id", "definition_sha256", "state", "errors", "cleanup", "elapsed_seconds")}
    summary["nodes"] = [{key: row.get(key) for key in
        ("node_id", "state", "component_status", "execution_started", "reason_code", "cleanup",
         "resource_reservations", "component_failure_details")}
        for row in snapshot["nodes"]]
    for observed, row in zip(summary["nodes"], snapshot["nodes"]):
        receipt = row.get("run_receipt")
        if type(receipt) is dict:
            observed["component_receipt"] = {key: receipt.get(key) for key in
                ("run_id", "operation", "status", "execution_started", "limitations", "cleanup")}
    print("R60_GRAPH_OUTCOME " + json.dumps(summary, sort_keys=True, ensure_ascii=True), flush=True)
    save(Path(store.folder) / "qa-outcome.json", summary)
    allowed = ("COMPLETED", "PARTIAL") if allow_partial else ("COMPLETED",)
    require(snapshot["state"] in allowed, "R60_ACTUAL_GRAPH_DID_NOT_COMPLETE: " + str(snapshot["state"]))
    require(len(snapshot["nodes"]) == len(workflow.nodes), "R60_NATIVE_NODE_COUNT")
    for node in snapshot["nodes"]:
        require(node["state"] in allowed and node.get("outputs"),
                "R60_UNEXECUTED_OR_FAILED_NODE: " + str(node.get("node_id")) + ":" + str(node.get("state")))
    records, journal = independent_journal(store.folder)
    return store, snapshot, records, journal


def _incident_id(folder):
    path = Path(folder) / "session-v2.sqlite3"
    before = file_hash(path)
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        require(db.execute("PRAGMA integrity_check").fetchone() == ("ok",), "R60_INCIDENT_SOURCE_INTEGRITY")
        rows = db.execute("SELECT incident_id FROM incidents ORDER BY incident_id LIMIT 1").fetchall()
    require(len(rows) == 1 and file_hash(path) == before, "R60_REAL_PERSISTED_INCIDENT_REQUIRED")
    return rows[0][0]


def saved_evidence_graph(evidence):
    """Construct an actual multi-domain graph; separate sources keep separate identities."""
    sources = read_json(evidence / "sources.json")
    wave = read_json(evidence / "wave02-native.json")
    require(wave["status"] == "PASS" and set(wave["container_results"]) == {"R20", "R30", "R40", "R50"},
            "R60_ALL_REAL_WAVE02_BRANCHES_REQUIRED")
    crash, research = wave["container_results"]["R40"], wave["container_results"]["R50"]
    nodes, edges, hashes = [], [], {}
    def add(node_id, tool_id, parameters=None, **policy):
        nodes.append({"node_id": node_id, "tool_id": tool_id, "parameters": parameters or {},
                      "budget_seconds": 180, "allow_partial_inputs": True, **policy})
    def source(node_id, kind, path, *, selection=None):
        path = Path(path).resolve(strict=True)
        parameters = {"kind": kind, "path": str(path)}
        if selection is not None:
            parameters["selection"] = dict(selection)
        add(node_id, "load_source", parameters)
        if path.is_file():
            hashes[str(path)] = file_hash(path)
        else:
            for name in ("session.sqlite3", "session-v2.sqlite3", "research.sqlite3"):
                database = path / name
                hashes[str(database)] = file_hash(database)
    def connect(first, port, second, target):
        edges.append(link(first, port, second, target))
    def exports(first, port, prefix):
        for format in ("json", "html"):
            target = prefix + "-" + format
            add(target, "export_report", {"format": format})
            connect(first, port, target, "case")
    source("recorded-trace", "TRACE", sources["trace"], selection={"pid": sources["fixture"]["pid"]})
    add("decoder", "decode_trace")
    connect("recorded-trace", "source", "decoder", "trace")
    previous = "decoder"
    for tool in ("waits", "file_io", "disk_io"):
        add(tool, tool, {"pid": sources["fixture"]["pid"]})
        connect(previous, "index", tool, "index")
        exports(tool, "report", tool + "-export")
        previous = tool
    add("trace-critical-path", "critical_path")
    connect(previous, "index", "trace-critical-path", "case")
    exports("trace-critical-path", "report", "trace-critical-path-export")
    source("saved-graph", "CASE", sources["case_index"])
    add("reopen-graph", "load_graph")
    connect("saved-graph", "source", "reopen-graph", "source")
    add("saved-critical-path", "critical_path")
    connect("reopen-graph", "case", "saved-critical-path", "case")
    exports("saved-critical-path", "report", "saved-critical-path-export")
    source("minidump", "DUMP", crash["private_dump_path"])
    add("crash", "crash", {"image_path": crash["local_image_path"], "pdb_path": crash["local_pdb_path"]})
    connect("minidump", "source", "crash", "dump")
    exports("crash", "case", "crash-export")
    source("session-before", "SESSION", research["before"]["folder"])
    source("session-after", "SESSION", research["after"]["folder"])
    add("incident", "incident", {"incident_id": _incident_id(research["before"]["folder"]),
                                   "pre_seconds": 2, "post_seconds": 1})
    connect("session-before", "source", "incident", "session")
    exports("incident", "case", "incident-export")
    add("comparison", "compare")
    connect("session-before", "source", "comparison", "before")
    connect("session-after", "source", "comparison", "after")
    exports("comparison", "comparison", "comparison-export")
    nodes.append({"node_id": "join", "kind": "JOIN", "parameters": {"mode": "ALLOW_PARTIAL"},
                  "allow_partial_inputs": True, "budget_seconds": 60})
    for first, port in (("decoder", "index"), ("minidump", "source"), ("session-before", "source")):
        connect(first, port, "join", "evidence")
    add("investigation", "investigate")
    connect("join", "evidence", "investigation", "evidence")
    add("critical-path", "critical_path")
    connect("investigation", "case", "critical-path", "case")
    exports("critical-path", "case", "combined-export")
    return definition(nodes, edges), hashes


def _verify_live_case_budget(snapshot, records, *, fixture_pid, maximum):
    """Independently check the actual explicit result limit and saved view.

    The limit measures logical CASE JSON and export bytes. The SQLite index
    also stores navigation rows and has its existing separate physical cap.
    """
    observed = {}
    for operation in ("investigation.create", "investigation.export"):
        calls = actual_invocations(records, operation)
        require(len(calls) == 1 and calls[0][0].get("parameters", {}).get("max_result_bytes") == maximum,
                "R60_LIVE_ACTUAL_COMPONENT_RESULT_LIMIT_NOT_EXPLICIT:" + operation)
        observed[operation] = {"run_id": calls[0][0]["run_id"], "max_result_bytes": maximum}
    rows = {row["node_id"]: row for row in snapshot["nodes"]}
    artifacts = {"trace": rows["capture"]["outputs"]["trace"][0],
                 "index": rows["decoder"]["outputs"]["index"][0],
                 "case": rows["graph"]["outputs"]["case"][0],
                 "export": rows["report"]["outputs"]["report"][0]}
    paths = {name: Path(artifact["value"]["_path"]) for name, artifact in artifacts.items()}
    hashes = {name: file_hash(path) for name, path in paths.items()}
    require(all(hashes[name] == artifact["value"]["sha256"] for name, artifact in artifacts.items()) and
            artifacts["index"]["value"]["trace_sha256"] == hashes["trace"],
            "R60_LIVE_CASE_ORIGINAL_SOURCE_OR_OUTPUT_HASH_MISMATCH")
    with closing(sqlite3.connect(paths["case"].resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, maximum + 65536)
        deadline = time.monotonic() + 30
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        require(db.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "R60_LIVE_CASE_SQL_INTEGRITY")
        contents = db.execute("SELECT case_id,schema,content_json,content_sha256 FROM investigation LIMIT 2").fetchall()
        require(len(contents) == 1, "R60_LIVE_CASE_SINGLE_SAVED_RESULT_REQUIRED")
        case_id, schema, raw, content_sha = contents[0]
        content_bytes = len(raw.encode("ascii"))
        require(content_bytes <= maximum and hashlib.sha256(raw.encode("ascii")).hexdigest() == content_sha,
                "R60_LIVE_CASE_EXPLICIT_LOGICAL_BYTE_BUDGET_OR_HASH")
        case = json.loads(raw)
        require(case.get("schema") == schema == "blackbox.investigation-graph/1" and
                case.get("case_id") == case_id == artifacts["case"]["value"]["case_id"] and
                db.execute("SELECT count(*) FROM nodes").fetchone()[0] == len(case["nodes"]) and
                db.execute("SELECT count(*) FROM edges").fetchone()[0] == len(case["edges"]),
                "R60_LIVE_CASE_SAVED_CONTENT_IDENTITY_OR_NAVIGATION")
    exported = read_json(paths["export"], maximum=maximum)
    selected = {"pid": fixture_pid}
    for name, value in (("saved", case), ("export", exported)):
        sources = value.get("sources", [])
        require(value.get("case_id") == case_id and value.get("schema") == schema and
                len(sources) == 1 and sources[0].get("source_type") == "TRACE_INDEX" and
                sources[0].get("selection") == selected and sources[0].get("index_sha256") == hashes["index"] and
                value.get("root_cause_proven") is False,
                "R60_LIVE_CASE_EXPLICIT_RESULT_LIMIT_CHANGED_PID_OR_SOURCE_SCOPE:" + name)
    require(all(file_hash(path) == hashes[name] for name, path in paths.items()),
            "R60_LIVE_CASE_READBACK_MODIFIED_ORIGINAL_SOURCE_OR_OUTPUT")
    return {"status": "PASS", "scope": "EXPLICIT_PER_NODE_LOGICAL_RESULT_LIMIT_AND_RECORDED_PID_VIEW",
            "max_result_bytes": maximum, "actual_component_contexts": observed,
            "case_content_bytes": content_bytes, "case_content_sha256": content_sha,
            "case_index_file_bytes": paths["case"].stat().st_size,
            "json_export_bytes": paths["export"].stat().st_size,
            "selected_pid": fixture_pid, "source_hashes_unchanged": hashes,
            "root_cause_proven": False}


def native_live_graph(output, executable, source_sha, diagnostic_helper=None):
    """Real current-consent capture -> decoder -> graph, plus owned observation."""
    from blackbox_core.chain_adapters import ChainRuntime
    from blackbox_core.deep_profiling import PROFILE
    from blackbox_core.deep_service import InspectorService
    from blackbox_core.optional_jobs import OwnedProcess
    from .chain_qa_native import actual_token, OwnedWaveProbe
    from uuid import uuid4
    owned_run_id = uuid4().hex
    # Run11's unchanged full workload exceeded the default32MiB result cap
    # (34,024,440 bytes at BUILD_GRAPH). Exercise the public per-node setting
    # with explicit headroom; retain that actual32MiB refusal as negative QA.
    live_result_bytes = 48 * 1024**2
    service = fixture = None
    proof, approvals, launches = {"status": "FAIL"}, [], []
    burst_thread, burst_errors = None, []
    try:
        fixture = OwnedWaveProbe(Path(executable), output / "target")
        service = InspectorService(output / "native-journal", helper_executable=diagnostic_helper)
        original_launch = service.broker.launch
        def launch(arguments, *, elevated=False):
            owner = original_launch(arguments, elevated=elevated)
            launches.append({"pid": owner.pid, "elevated": elevated})
            return owner
        service.broker.launch = launch
        opened = service.start_admin_session_owned(owner_run_id=owned_run_id, confirmed=True)
        require(opened["status"] == "COMPLETED" and
                type(opened.get("native_context_ownership")) is dict, "R60_NATIVE_ADMIN_LEASE")
        native_reference = opened["native_context_ownership"]
        status = service.session_status(refresh=True)
        helper_identity, lease = status["helper_identity"], status["session_deadline_monotonic"]
        token = actual_token(helper_identity["pid"])
        require(token["elevated"] is True and len(launches) == 1 and launches[0]["elevated"],
                "R60_NATIVE_ONE_REAL_SCOPED_RUNAS")
        target = service.identity(fixture.process.pid)
        require(target.created_100ns == fixture.ready["created_100ns"], "R60_NATIVE_EXACT_TARGET_BIRTH")
        bound = service.bind_target_owned(target, ["profile.etw", "snapshot", "dump"],
            owner_run_id=owned_run_id, expected_context=native_reference, confirmed=True)
        require(bound["status"] == "COMPLETED" and type(bound.get("native_context_ownership")) is dict,
                "R60_NATIVE_FRESH_TARGET_SCOPE")
        native_reference = bound["native_context_ownership"]
        def authorize(operation, parameters, identity, ctx):
            nonlocal burst_thread
            require(operation == "profile.etw" and identity["pid"] == target.pid and
                    identity["created_100ns"] == target.created_100ns, "R60_UNEXPECTED_QA_CONSENT_SCOPE")
            live = service.session_status(refresh=True)
            require(ctx.run_id == owned_run_id and live["helper_identity"] == helper_identity and
                    len(launches) == 1 and abs(live["session_deadline_monotonic"] - lease) < .001,
                    "R60_HELPER_LEASE_REPLACED_OR_RENEWED_BEFORE_ACTION")
            approvals.append({"operation": operation, "target": identity, "node_run_id": ctx.node_run_id,
                              "fresh_monotonic_ns": time.monotonic_ns()})
            def burst():
                try:
                    fixture.send("burst")
                    fixture.receive("burst_begin", timeout=10)
                    done = fixture.receive("burst_done", timeout=20)
                    require(done["worker_exit_verified"] and done["worker_threads"] == 4,
                            "R60_LIVE_CAPTURE_NATIVE_WORKLOAD_NOT_CLOSED")
                except BaseException as error:
                    burst_errors.append(error)
            burst_thread = threading.Thread(target=burst, name="r60-live-native-oracle", daemon=True)
            burst_thread.start()
            return {**parameters, "systemwide_confirmed": True}
        runtime = ChainRuntime(inspector=service, authorize=authorize, output_root=output / "recordings",
            owned_session_run_id=owned_run_id, native_context_ref=native_reference)
        nodes = [{"node_id": "target", "tool_id": "process_select", "parameters": {"pid": target.pid}},
            {"node_id": "capture", "tool_id": "deep.profile.etw", "budget_seconds": 120,
             "parameters": {"parameters": {"duration_seconds": 3, "profile": PROFILE}}},
            {"node_id": "decoder", "tool_id": "decode_trace", "budget_seconds": 180,
             "allow_partial_inputs": True},
            {"node_id": "graph", "tool_id": "investigate", "budget_seconds": 120,
             "allow_partial_inputs": True, "parameters": {"selection": {"pid": target.pid},
                "max_result_bytes": live_result_bytes}},
            {"node_id": "observe", "tool_id": "observe", "budget_seconds": 30,
             "parameters": {"duration_seconds": 3}},
            {"node_id": "report", "tool_id": "export_report", "allow_partial_inputs": True,
             "parameters": {"format": "json", "max_result_bytes": live_result_bytes}}]
        edges = [link("target", "process", "capture", "process"),
                 link("capture", "trace", "decoder", "trace"), link("decoder", "index", "graph", "evidence"),
                 link("target", "process", "observe", "process"), link("graph", "case", "report", "case")]
        store, snapshot, records, journal = run_graph(definition(nodes, edges, identity="live", seconds=600,
                                                                 allow_effectful=True),
                                                     output / "runs", runtime=runtime, run_id=owned_run_id)
        require(len(approvals) == 1, "R60_FRESH_CONSENT_NOT_REQUESTED_ONCE")
        captures = actual_invocations(records, "profile.etw")
        require(len(captures) == 1 and captures[0][1]["execution_started"] is True and
                captures[0][1]["cleanup"]["confirmed"] is True, "R60_ACTUAL_CAPTURE_RECEIPT_OR_CLEANUP")
        result_budget_proof = _verify_live_case_budget(snapshot, records, fixture_pid=target.pid,
                                                       maximum=live_result_bytes)
        live = service.session_status(refresh=True)
        require(live["helper_identity"] is None and len(launches) == 1 and
                runtime.owned_session_run_id is None and runtime.native_context_ref is None and
                snapshot.get("cleanup", {}).get("confirmed") is True,
                "R60_CHAIN_DID_NOT_RELEASE_ITS_EXACT_NATIVE_OWNER")
        # The second graph deliberately refuses fresh dump consent. Its ordinary
        # read-only source branch still runs through the actual file adapter.
        refused = []
        def deny(operation, parameters, identity, ctx):
            refused.append({"operation": operation, "node_run_id": ctx.node_run_id})
            return False
        runtime.authorize = deny
        from blackbox_core.chain_adapters import build_catalog
        from blackbox_core.chain_engine import WorkflowEngine
        from blackbox_core.chain_store import WorkflowRunStore
        denied_definition = definition([
            {"node_id": "target", "tool_id": "process_select", "parameters": {"pid": target.pid}},
            {"node_id": "denied", "tool_id": "deep.dump"},
            {"node_id": "ordinary", "tool_id": "load_source", "parameters": {"kind": "TRACE",
             "path": str(next(Path(store.folder).rglob("*.etl")))}}],
            [link("target", "process", "denied", "process")], identity="denied", seconds=240,
            allow_effectful=True)
        denied_store = WorkflowRunStore.create(output / "denied-runs", denied_definition)
        denied = WorkflowEngine(denied_definition, catalog=build_catalog(runtime), store=denied_store,
                                runtime=runtime).run()
        rows = {row["node_id"]: row for row in denied["nodes"]}
        require(denied["state"] != "COMPLETED" and rows["ordinary"]["state"] == "COMPLETED" and
                rows["denied"]["state"] != "COMPLETED" and len(refused) == 1 and
                not list(Path(denied_store.folder).rglob("*.dmp")), "R60_DENIED_CONSENT_DAMAGED_READONLY_BRANCH")
        if burst_thread is not None:
            burst_thread.join(timeout=30)
            require(not burst_thread.is_alive() and not burst_errors, "R60_NATIVE_ORACLE_THREAD_NOT_CLOSED")
        proof = {"status": "PASS", "state": snapshot["state"], "journal": journal,
            "fresh_consent_count": len(approvals), "denied_fresh_consent_count": len(refused),
            "helper_token": token, "runas_count": len(launches), "helper_identity": helper_identity,
            "source_sha": source_sha, "denied_branch_state": rows["denied"]["state"],
            "ordinary_branch_state": rows["ordinary"]["state"], "explicit_result_budget": result_budget_proof}
    finally:
        if burst_thread is not None and burst_thread.is_alive():
            burst_thread.join(timeout=30)
            require(not burst_thread.is_alive(), "R60_FAILURE_NATIVE_ORACLE_THREAD_NOT_CLOSED")
        if service is not None:
            proof["helper_cleanup"] = service.close()
            require(proof["helper_cleanup"].get("status") == "COMPLETED", "R60_LIVE_HELPER_CLEANUP_UNCONFIRMED")
        if fixture is not None:
            proof["target_cleanup"] = fixture.close(kill=proof["status"] != "PASS")
            require(proof["target_cleanup"]["status"] == "COMPLETED" if proof["status"] == "PASS" else True,
                    "R60_LIVE_TARGET_CLEANUP_UNCONFIRMED")
        require(not OwnedProcess.pending_cleanup(), "R60_LIVE_PENDING_OWNED_PROCESS")
    return proof


def standard_live_graph(output, executable, source_sha, diagnostic_helper=None, *, token_evidence=None):
    """Actual chain adapters under the independently restricted medium token."""
    from .chain_adapters import ChainRuntime
    from .chain_qa_native import actual_current_token_facts, actual_token, OwnedWaveProbe
    from .deep_service import InspectorService
    from .optional_jobs import OwnedProcess
    from .windows_research import privilege
    fixture = service = None
    proof, launches = {"status": "FAIL"}, []
    try:
        evidence = token_evidence if token_evidence is not None else {}
        evidence.update(schema="blackbox.r60.standard-token-precondition/1", status="COLLECTING",
                        pid=os.getpid(), source_sha=source_sha)
        own_token = actual_token(os.getpid())
        evidence["own_token"] = own_token
        own_privilege = privilege()
        evidence["privilege"] = own_privilege
        evidence["current_token_facts"] = actual_current_token_facts()
        evidence["status"] = "OBSERVED"
        evidence["gate_conditions"] = {"privilege_standard": own_privilege == {"mode": "STANDARD", "windows": True},
                                       "raw_token_elevation_false": own_token["elevated"] is False}
        require(own_privilege == {"mode": "STANDARD", "windows": True} and own_token["elevated"] is False,
                "R60_CHAIN_ACTUAL_STANDARD_TOKEN_REQUIRED")
        fixture = OwnedWaveProbe(Path(executable), output / "target")
        service = InspectorService(output / "native-journal", helper_executable=diagnostic_helper)
        original_launch = service.broker.launch
        def launch(arguments, *, elevated=False):
            owner = original_launch(arguments, elevated=elevated)
            launches.append({"pid": owner.pid, "elevated": elevated, "token": actual_token(owner.pid)})
            return owner
        service.broker.launch = launch
        runtime = ChainRuntime(inspector=service, output_root=output / "recordings")
        nodes = [{"node_id": "target", "tool_id": "process_select", "budget_seconds": 5,
                  "parameters": {"pid": fixture.process.pid}},
                 {"node_id": "snapshot", "tool_id": "deep.snapshot", "budget_seconds": 20},
                 {"node_id": "observe", "tool_id": "observe", "budget_seconds": 10,
                  "parameters": {"duration_seconds": 3}}]
        edges = [link("target", "process", "snapshot", "process"),
                 link("target", "process", "observe", "process")]
        _store, snapshot, records, journal = run_graph(definition(nodes, edges, identity="standard-token",
                                                                 seconds=60, workers=2), output / "runs", runtime=runtime)
        require(launches and all(row["elevated"] is False for row in launches),
                "R60_STANDARD_CHAIN_UNEXPECTED_RUNAS")
        require(service.helper_pid is None and runtime.owned_session_run_id is None and
                snapshot.get("cleanup", {}).get("confirmed") is True,
                "R60_STANDARD_CHAIN_OWNER_NOT_RELEASED")
        token = launches[0]["token"]
        require(token["elevated"] is False and all(row["token"]["elevated"] is False for row in launches),
                "R60_STANDARD_CHAIN_HELPER_ELEVATED")
        calls = actual_invocations(records, "snapshot")
        require(len(calls) == 1 and calls[0][1]["execution_started"] is True and
                calls[0][1]["cleanup"]["confirmed"] is True, "R60_STANDARD_REAL_NATIVE_RECEIPT_REQUIRED")
        proof = {"status": "PASS", "source_sha": source_sha, "state": snapshot["state"],
                 "own_token": own_token, "helper_token": token, "helper_launches": launches,
                 "journal": journal, "scope": "RESTRICTED_SAME_RUNNER_IDENTITY_STANDARD_MEDIUM_TOKEN"}
    finally:
        if service is not None:
            proof["helper_cleanup"] = service.close()
            require(proof["helper_cleanup"].get("status") == "COMPLETED", "R60_STANDARD_HELPER_CLEANUP_UNCONFIRMED")
        if fixture is not None:
            proof["target_cleanup"] = fixture.close(kill=proof["status"] != "PASS")
            if proof["status"] == "PASS":
                require(proof["target_cleanup"]["status"] == "COMPLETED", "R60_STANDARD_TARGET_CLEANUP_UNCONFIRMED")
        require(not OwnedProcess.pending_cleanup(), "R60_STANDARD_PENDING_PROCESS_OWNER")
    return proof


def run_embedded(output, evidence_root, source_sha, diagnostic_helper=None, *, standard_token=False):
    """Same actual engine/adapters in app.py, including inside the frozen EXE."""
    identity = source_proof(source_sha)
    output, evidence = Path(output).resolve(), Path(evidence_root).resolve(strict=True)
    output.mkdir(parents=True, exist_ok=False)
    proof = {"schema": "blackbox.r60.chain-native-qa/1", "status": "FAIL", "source_identity": identity,
        "pid": os.getpid(), "started_monotonic_ns": time.monotonic_ns(),
        "source_sha": source_sha, "frozen": bool(getattr(sys, "frozen", False)),
        "standard_token": standard_token,
        "physical_windows_10_11": "NOT_TESTED", "physical_secure_desktop": "NOT_TESTED",
        "claims": "ACTUAL_HOSTED_ENGINE_ADAPTER_AND_NATIVE_OPERATIONS_ONLY"}
    try:
        workflow, sources = saved_evidence_graph(evidence)
        store, snapshot, records, journal = run_graph(workflow, output / "runs")
        from .chain_qa_faults import run_actual_faults, verify_io_critical_path
        source_manifest = read_json(evidence / "sources.json")
        proof["io_critical_path"] = verify_io_critical_path(workflow, records,
                                                           fixture_pid=source_manifest["fixture"]["pid"])
        require(all(file_hash(Path(path)) == digest for path, digest in sources.items()),
                "R60_ORIGINAL_SOURCES_CHANGED")
        executed = {}
        for operation in ("workflow.load_source", "decoder.decode", "investigation.create",
                          "workflow.load_graph", "workflow.critical_path", "workflow.waits",
                          "workflow.file_io", "workflow.disk_io"):
            executed[operation] = len(actual_invocations(records, operation))
        incident_results = [event["data"] for event in records if event.get("event") == "node.result" and
                            event.get("node_id") == "incident"]
        require(len(incident_results) == 1 and incident_results[0]["execution_started"] is True and
                incident_results[0]["run_receipt"]["operation"] == "investigation.create",
                "R60_ACTUAL_INCIDENT_COMPONENT_RECEIPT_REQUIRED")
        proof.update(state=snapshot["state"], node_count=len(snapshot["nodes"]), journal=journal,
                     actual_invocation_counts=executed, source_hashes=list(sources.values()),
                     source_hash_count=len(sources), source_hashes_unchanged=True)
        executable = Path(source_manifest["fixture_executable"])
        require(file_hash(executable) == source_manifest["fixture_executable_sha256"],
                "R60_NATIVE_FIXTURE_BINARY_CHANGED")
        live_check = standard_live_graph if standard_token else native_live_graph
        if standard_token:
            # Keep the actual precondition facts reachable if its strict gate
            # raises before standard_live_graph returns its successful proof.
            proof["standard_token_precondition"] = {}
            proof["live"] = live_check(output / "live", executable, source_sha, diagnostic_helper,
                                      token_evidence=proof["standard_token_precondition"])
        else:
            proof["live"] = live_check(output / "live", executable, source_sha, diagnostic_helper)
        if not standard_token:
            from .chain_qa_native import native_checkpoint_graph
            proof["native_checkpoint"] = native_checkpoint_graph(output / "native-checkpoint", executable,
                                                                  source_sha, diagnostic_helper)
        proof["actual_negative_chains"] = run_actual_faults(output / "actual-negative-chains", executable,
            source_sha, trace_path=Path(source_manifest["trace"]), diagnostic_helper=diagnostic_helper)
        proof["final_source_identity"] = source_proof(source_sha)
        proof["status"] = "PASS"
    except BaseException as error:
        proof.update(status="FAIL", error=type(error).__name__, reason=str(error)[:2000])
        traceback.print_exc(limit=12)
    finally:
        save(output / "result.json", proof)
        print("R60_CHAIN_NATIVE_RECEIPT " + json.dumps({**proof, "result_sha256": file_hash(output / "result.json")},
                                                      sort_keys=True), flush=True)
    return 0 if proof["status"] == "PASS" else 1
