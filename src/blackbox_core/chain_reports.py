"""Bounded, passive R60 run reports using the existing export transaction.

A workflow report describes actual persisted operations and their evidence
links. A completed orchestration does not authenticate imported observations or
establish an application's root cause. No tool is dispatched by this module.
"""
from __future__ import annotations

import hashlib
from html import escape
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import time

from .chain_contracts import canonical, require
from .chain_io import fingerprint_file
from .export_recovery import export_stage
from .investigation_graph_store import public_metadata
from .session_v2 import safe_path

SCHEMA = "blackbox.workflow-report/1"
MAX_REPORT_BYTES = 64 * 1024**2
MAX_EVENTS = 100000


def _check(cancel, deadline):
    if cancel is not None and (cancel.is_set() if hasattr(cancel, "is_set") else cancel()):
        raise InterruptedError("WORKFLOW_REPORT_CANCELLED")
    if time.monotonic() >= deadline:
        raise TimeoutError("WORKFLOW_REPORT_DEADLINE")


def _json(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "WORKFLOW_REPORT_DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def constant(_value):
        raise ValueError("WORKFLOW_REPORT_NONFINITE_JSON")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


class _ReportHTML(HTMLParser):
    def __init__(self, script_id="blackbox-workflow-data"):
        super().__init__(convert_charrefs=False)
        self.script_id = script_id
        self.active, self.parts, self.documents = False, [], []

    def handle_starttag(self, tag, attributes):
        values = dict(attributes)
        if tag == "script" and values.get("id") == self.script_id:
            require(not self.active and not self.documents and values.get("type") == "application/json",
                    "WORKFLOW_REPORT_HTML_METADATA_INVALID")
            self.active = True

    def handle_data(self, text):
        if self.active:
            self.parts.append(text)

    def handle_endtag(self, tag):
        if tag == "script" and self.active:
            self.documents.append(_json("".join(self.parts)))
            self.active = False


def _readback(path, format, *, script_id="blackbox-workflow-data"):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_REPORT_BYTES,
            "WORKFLOW_REPORT_READBACK_BUDGET")
    with path.open("rb") as stream:
        raw = stream.read(MAX_REPORT_BYTES + 1)
    require(len(raw) <= MAX_REPORT_BYTES, "WORKFLOW_REPORT_READBACK_BUDGET")
    text = raw.decode("utf-8")
    if format == "json":
        return _json(text)
    reader = _ReportHTML(script_id)
    reader.feed(text)
    reader.close()
    require(not reader.active and len(reader.documents) == 1, "WORKFLOW_REPORT_HTML_METADATA_MISSING")
    return reader.documents[0]


def export_analysis_report(source, destination, *, format="json", cancel=None, deadline=None, owner_run_id=None):
    """Export an actual saved waits/FileIO/DiskIO report, without inventing a case.

    The source report and its exact decoder index remain hash-bound dependencies.
    Export completion describes publication; it never upgrades analysis coverage.
    """
    from .chain_contracts import Artifact
    from .chain_io import verify_artifact
    require(format in ("json", "html"), "WORKFLOW_REPORT_FORMAT_UNSUPPORTED")
    deadline = min(deadline, time.monotonic() + 120) if deadline is not None else time.monotonic() + 120
    _check(cancel, deadline)
    require(isinstance(source, Artifact) and source.kind == "REPORT" and
            source.value.get("report_type") in ("WAITS", "FILE_IO", "DISK_IO"),
            "WORKFLOW_SAVED_ANALYSIS_REPORT_REQUIRED")
    destination = safe_path(Path(destination))
    require(destination.parent.is_dir() and len(destination.name) <= 256, "WORKFLOW_REPORT_DIRECTORY_REQUIRED")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("WORKFLOW_REPORT_DESTINATION_EXISTS")
    verify_artifact(source, cancel=cancel, deadline=deadline, owner_run_id=owner_run_id)
    path = safe_path(Path(source.value["_path"]))
    require(path.stat().st_size <= 32 * 1024**2, "WORKFLOW_ANALYSIS_REPORT_SOURCE_BUDGET")
    indices = [Artifact.from_dict(row) for row in source.value.get("upstream_artifacts", [])
               if row.get("kind") == "TRACE_INDEX" and row.get("value", {}).get("_path") == source.value.get("_index_path")]
    require(len(indices) == 1, "WORKFLOW_ANALYSIS_REPORT_BOUND_INDEX_REQUIRED")
    index = indices[0]
    with path.open("rb") as stream:
        saved_analysis = stream.read(32 * 1024**2 + 1)
    require(len(saved_analysis) <= 32 * 1024**2, "WORKFLOW_ANALYSIS_REPORT_SOURCE_BUDGET")
    require(hashlib.sha256(saved_analysis).hexdigest() == source.value["sha256"],
            "WORKFLOW_ANALYSIS_REPORT_SOURCE_CHANGED_DURING_READ")
    analysis = _json(saved_analysis.decode("utf-8"))
    require(type(analysis) is dict and type(analysis.get("status")) is str,
            "WORKFLOW_ANALYSIS_REPORT_DOCUMENT_REQUIRED")
    verify_artifact(source, cancel=cancel, deadline=deadline, owner_run_id=owner_run_id)
    document = public_metadata({"schema": "blackbox.analysis-report/1",
        "report_type": source.value["report_type"], "analysis_status": analysis["status"], "analysis": analysis,
        "sources": list(source.sources), "clock_domains": list(source.clock_domains), "coverage": source.coverage,
        "source_trust": "UNVERIFIED_IMPORT", "root_cause": "UNKNOWN",
        "verification": {"source_report_artifact_id": source.artifact_id,
            "source_report_sha256": source.value["sha256"], "source_report_bytes": source.value["bytes"],
            "source_index_artifact_id": index.artifact_id, "source_index_sha256": index.value["sha256"],
            "source_index_bytes": index.value["bytes"],
            "scope": "SAVED_REPORT_AND_INDEX_BYTE_CONSISTENCY_NOT_PRODUCER_AUTHENTICATION"},
        "privacy": {"raw_memory_or_dump_bytes_included": False, "private_navigation_included": False}})
    if format == "json":
        text = canonical(document) + "\n"
    else:
        embedded = canonical(document).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
        text = ("<!doctype html><html lang='ru'><meta charset='utf-8'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            "<title>BLACK.BOX — " + escape(document["report_type"]) + "</title>"
            "<style>body{font:15px sans-serif;max-width:1100px;margin:2em auto;padding:1em}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>BLACK.BOX — " +
            escape(document["report_type"]) + "</h1><p>Analysis status: " + escape(document["analysis_status"]) +
            ". Root cause: UNKNOWN. Imported observations: UNVERIFIED_IMPORT.</p>"
            "<p>Export completion confirms publication only; missing evidence and clock alignment remain explicit.</p><pre>" +
            escape(json.dumps(document["analysis"], ensure_ascii=False, sort_keys=True, indent=2)) +
            "</pre><script type=\"application/json\" id=\"blackbox-analysis-data\">" + embedded + "</script></html>")
    raw = text.encode("utf-8")
    require(len(raw) <= MAX_REPORT_BYTES, "WORKFLOW_REPORT_BYTE_BUDGET")
    expected_sha256 = hashlib.sha256(raw).hexdigest()
    with export_stage(destination.parent, kind="WORKFLOW_SAVED_ANALYSIS_REPORT") as transaction:
        staged = transaction.reserve(destination.name)
        with staged.open("r+b") as stream:
            for offset in range(0, len(raw), 65536):
                _check(cancel, deadline)
                stream.write(raw[offset:offset + 65536])
            stream.flush()
            os.fsync(stream.fileno())
        require(_readback(staged, format, script_id="blackbox-analysis-data") == document,
                "WORKFLOW_REPORT_STAGE_SEMANTIC_READBACK")
        transaction.prepare({destination.name: staged})
        _check(cancel, deadline)
        verify_artifact(source, cancel=cancel, deadline=deadline, owner_run_id=owner_run_id)
        transaction.publish()
    try:
        actual = fingerprint_file(destination, deadline=deadline, max_bytes=MAX_REPORT_BYTES)
        require(actual["sha256"] == expected_sha256 and
                _readback(destination, format, script_id="blackbox-analysis-data") == document,
                "WORKFLOW_REPORT_PUBLICATION_READBACK_UNCONFIRMED")
        verify_artifact(source, deadline=deadline, owner_run_id=owner_run_id)
    except Exception as error:
        error.publication_unconfirmed = True
        raise
    return {"status": "COMPLETED", "path": str(destination), "format": format,
        "sha256": expected_sha256, "size_bytes": len(raw), "readback_verified": True,
        "source_modified": False, "analysis_status": document["analysis_status"],
        "source_trust": "UNVERIFIED_IMPORT", "root_cause": "UNKNOWN",
        "cleanup": {"confirmed": True, "status": "CONFIRMED", "scope": "ANALYSIS_EXPORT_HANDLES_AND_STAGING"}}


def _links(definition, records):
    latest = {}
    for event in records:
        if event.get("event") == "node.result":
            data = event.get("data", {})
            latest[data.get("node_id")] = data
    rows = []
    for edge in definition.edges:
        upstream = latest.get(edge.source_node, {})
        output = upstream.get("outputs", {}).get(edge.source_port, [])
        receipt = upstream.get("run_receipt") or {}
        rows.append({"edge_id": edge.edge_id, "upstream_node_id": edge.source_node,
            "upstream_port": edge.source_port, "downstream_node_id": edge.target_node,
            "downstream_port": edge.target_port,
            "source_artifact_ids": [item["artifact_id"] for item in output if type(item) is dict and
                                    type(item.get("artifact_id")) is str],
            "receipt_refs": [receipt["run_id"]] if type(receipt.get("run_id")) is str else [],
            "upstream_state": upstream.get("state", "NOT_EXECUTED"),
            "link_scope": "DECLARED_WORKFLOW_DEPENDENCY_NOT_CAUSAL_PROOF"})
    return rows


def _document(store, cancel, deadline):
    _check(cancel, deadline)
    journal = Path(store.folder) / "journal" / "deep-inspection.sqlite3"
    before = fingerprint_file(journal, cancel=cancel, deadline=deadline, max_bytes=128 * 1024**2)
    records = store.read_events()
    require(type(records) is list and len(records) <= MAX_EVENTS, "WORKFLOW_REPORT_EVENT_BUDGET")
    snapshot = store.load_state()
    _check(cancel, deadline)
    after = fingerprint_file(journal, cancel=cancel, deadline=deadline, max_bytes=128 * 1024**2)
    require(before == after, "WORKFLOW_REPORT_RUN_CHANGED_DURING_READ")
    # The public projection is deliberately reused, including its recognizable
    # path/URL policy. It cannot detect arbitrary secrets in free-text titles.
    document = public_metadata({"schema": SCHEMA, "run": snapshot, "events": records,
        "links": _links(store.definition, records), "source_trust": "UNVERIFIED_IMPORT",
        "root_cause": "UNKNOWN", "privacy": {
            "raw_memory_or_dump_bytes_included": False, "runtime_authority_included": False,
            "private_navigation_included": False, "known_paths_and_urls": "REDACTED",
            "arbitrary_free_text_secret_detection": False},
        "verification": {"journal_sha256": before["sha256"],
            "scope": "LOCAL_HASHCHAIN_AND_SIDECAR_INTEGRITY_NOT_AUTHENTICATED_PROVENANCE"}})
    require(document["run"].get("run_id") == store.run_id and
            document["run"].get("definition_sha256") == store.definition.fingerprint,
            "WORKFLOW_REPORT_SOURCE_IDENTITY_MISMATCH")
    return document, before


def _html(document):
    run = document["run"]
    rows = []
    for node in run.get("nodes", []):
        rows.append("<tr>" + "".join("<td>" + escape(str(node.get(key, "UNKNOWN"))) + "</td>"
                    for key in ("node_id", "tool_id", "state", "component_status")) + "</tr>")
    # Escaping '<' keeps a node title containing '</script>' inside JSON text.
    embedded = canonical(document).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return ("<!doctype html><html lang='ru'><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<title>BLACK.BOX — Workflow run</title><style>body{font:15px sans-serif;max-width:1100px;"
        "margin:2em auto;padding:1em}table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbb;"
        "padding:.4em}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>"
        "<h1>Цепочка диагностики / Diagnostic workflow</h1><p>Run: " + escape(str(run["run_id"])) +
        "; status: " + escape(str(run.get("state", "UNKNOWN"))) + ".</p>"
        "<p>Root cause: UNKNOWN. Imported observations: UNVERIFIED_IMPORT. "
        "A workflow edge records a dependency, not a causal conclusion. "
        "Missing sources, clock alignment and cleanup remain explicit.</p>"
        "<table><tr><th>Node</th><th>Tool</th><th>Workflow state</th><th>Component status</th></tr>" +
        "".join(rows) + "</table><h2>Coverage / Полнота</h2><pre>" +
        escape(json.dumps(run.get("coverage", {}), ensure_ascii=False, sort_keys=True, indent=2)) +
        "</pre><h2>Cleanup / Освобождение ресурсов</h2><pre>" +
        escape(json.dumps(run.get("cleanup", {}), ensure_ascii=False, sort_keys=True, indent=2)) +
        "</pre><script type=\"application/json\" id=\"blackbox-workflow-data\">" + embedded +
        "</script></html>")


def export_workflow_run(store, destination, *, format="json", cancel=None):
    """Publish one create-new report and independently parse its committed form.

    Cancellation before publication aborts only owned staged files. Once the
    transaction publishes, readback is completed without a late cancellation;
    an unverifiable committed file is retained and explicitly reported.
    """
    require(format in ("json", "html"), "WORKFLOW_REPORT_FORMAT_UNSUPPORTED")
    deadline = time.monotonic() + 120
    _check(cancel, deadline)
    destination = safe_path(Path(destination))
    require(destination.parent.is_dir() and len(destination.name) <= 256, "WORKFLOW_REPORT_DIRECTORY_REQUIRED")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("WORKFLOW_REPORT_DESTINATION_EXISTS")
    document, original_journal = _document(store, cancel, deadline)
    raw = (canonical(document) + "\n" if format == "json" else _html(document)).encode("utf-8")
    require(len(raw) <= MAX_REPORT_BYTES, "WORKFLOW_REPORT_BYTE_BUDGET")
    expected_sha256 = hashlib.sha256(raw).hexdigest()
    with export_stage(destination.parent, kind="WORKFLOW_RUN_REPORT") as transaction:
        staged = transaction.reserve(destination.name)
        with staged.open("r+b") as stream:
            for offset in range(0, len(raw), 65536):
                _check(cancel, deadline)
                stream.write(raw[offset:offset + 65536])
            stream.flush()
            os.fsync(stream.fileno())
        require(_readback(staged, format) == document, "WORKFLOW_REPORT_STAGE_SEMANTIC_READBACK")
        transaction.prepare({destination.name: staged})
        _check(cancel, deadline)
        # An active writer must not produce a report combining different
        # generations of the same run, even when individual records are valid.
        require(fingerprint_file(Path(store.folder) / "journal" / "deep-inspection.sqlite3",
                    cancel=cancel, deadline=deadline, max_bytes=128 * 1024**2) == original_journal,
                "WORKFLOW_REPORT_RUN_CHANGED_BEFORE_PUBLICATION")
        transaction.publish()
    try:
        actual = fingerprint_file(destination, deadline=deadline, max_bytes=MAX_REPORT_BYTES)
        require(actual["sha256"] == expected_sha256 and _readback(destination, format) == document,
                "WORKFLOW_REPORT_PUBLICATION_READBACK_UNCONFIRMED")
    except Exception as error:
        error.publication_unconfirmed = True
        raise
    return {"status": "COMPLETED", "path": str(destination), "format": format,
        "sha256": expected_sha256, "size_bytes": len(raw), "run_id": store.run_id,
        "definition_sha256": store.definition.fingerprint, "readback_verified": True,
        "source_modified": False, "source_trust": "UNVERIFIED_IMPORT", "root_cause": "UNKNOWN"}
