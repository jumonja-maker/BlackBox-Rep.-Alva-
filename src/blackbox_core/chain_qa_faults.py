"""Actual owned Windows failures through the production R60 engine/adapters.

This module is an explicit hosted QA entry point, including inside the frozen
EXE. Faults affect only owned fixture processes/recorders/helper. No fabricated
native result, mocked process identity or historical baseline is accepted.
"""
from __future__ import annotations

from contextlib import closing
from copy import deepcopy
from html.parser import HTMLParser
import json
from pathlib import Path
import sqlite3
import threading
import time

from .chain_qa import (definition, file_hash, independent_journal, link, require,
                       read_json, require_hosted_windows, save, source_proof)


def _wait(predicate, reason, *, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        threading.Event().wait(.02)
    raise AssertionError(reason)


def _rows(snapshot):
    return {node["node_id"]: node for node in snapshot["nodes"]}


def _source_node(trace_path):
    return {"node_id": "preserved-source", "tool_id": "load_source", "budget_seconds": 10,
            "parameters": {"kind": "TRACE", "path": str(Path(trace_path).resolve(strict=True))}}


def _result_stamps(store):
    return {path.name: file_hash(path) for path in (Path(store.folder) / ".results").glob("*.json")}


def _sql_integrity(path):
    before = file_hash(path)
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA cache_size=-4096")
        deadline = time.monotonic() + 15
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        require(db.execute("PRAGMA integrity_check").fetchall() == [("ok",)],
                "R60_NEGATIVE_RECORDING_SQL_INTEGRITY")
    require(file_hash(path) == before, "R60_NEGATIVE_READBACK_MODIFIED_RECORDING")
    return {"sha256": before, "integrity": "ok", "unchanged_during_readback": True}


def checkpoint_target_exit(output, executable, source_sha, *, trace_path, diagnostic_helper=None):
    """A persisted actual FILETIME target dies before explicit reopened resume."""
    from .chain_adapters import ChainRuntime, build_catalog
    from .chain_engine import WorkflowEngine
    from .chain_store import WorkflowRunStore
    from .chain_qa_native import OwnedWaveProbe
    from .deep_service import InspectorService
    from .optional_jobs import OwnedProcess
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    before_hash = file_hash(trace_path)
    fixture = service = None
    proof, launches, approvals = {"status": "FAIL"}, [], []
    try:
        fixture = OwnedWaveProbe(Path(executable), output / "target")
        target = {key: fixture.ready[key] for key in ("pid", "created_100ns")}
        service = InspectorService(output / "native-journal", helper_executable=diagnostic_helper)
        original_launch = service.broker.launch
        def launch(arguments, *, elevated=False):
            owner = original_launch(arguments, elevated=elevated)
            launches.append({"pid": owner.pid, "elevated": elevated})
            return owner
        service.broker.launch = launch
        def forbidden_consent(operation, parameters, identity, ctx):
            approvals.append({"operation": operation, "node_run_id": ctx.node_run_id})
            raise AssertionError("R60_DEAD_CHECKPOINT_TARGET_REACHED_EFFECTFUL_CONSENT")
        runtime = ChainRuntime(inspector=service, authorize=forbidden_consent)
        workflow = definition([_source_node(trace_path),
            {"node_id": "actual-target", "tool_id": "process_select", "budget_seconds": 10,
             "parameters": {"pid": target["pid"]}},
            {"node_id": "manual-review", "kind": "CHECKPOINT", "budget_seconds": 1},
            {"node_id": "never-replayed-effect", "tool_id": "deep.dump", "budget_seconds": 30}], [
                link("preserved-source", "receipt", "manual-review", "after"),
                link("actual-target", "receipt", "manual-review", "after"),
                link("manual-review", "continue", "never-replayed-effect", "when"),
                link("actual-target", "process", "never-replayed-effect", "process")],
            identity="checkpoint-actual-target-exit", seconds=120, allow_effectful=True)
        store = WorkflowRunStore.create(output / "runs", workflow)
        catalog = build_catalog(runtime)
        engine = WorkflowEngine(workflow, catalog=catalog, store=store, runtime=runtime)
        paused = engine.run()
        require(paused["state"] == "WAITING_FOR_HUMAN", "R60_ACTUAL_IDENTITY_CHECKPOINT_NOT_REACHED")
        saved = store.load_state()
        rows = _rows(saved)
        identity = rows["actual-target"]["outputs"]["process"][0]["value"]["identity"]
        require(all(identity[key] == target[key] for key in target) and
                rows["preserved-source"]["state"] == rows["actual-target"]["state"] == "COMPLETED",
                "R60_CHECKPOINT_ACTUAL_NATIVE_IDENTITY_NOT_PERSISTED")
        stamps = _result_stamps(store)
        receipts = {name: deepcopy(rows[name]["run_receipt"]) for name in ("preserved-source", "actual-target")}
        process = fixture.process
        normal_exit = fixture.close()
        fixture = None
        require(normal_exit["status"] == "COMPLETED" and process.poll() == 0,
                "R60_CHECKPOINT_OWNED_TARGET_EXIT_NOT_CONFIRMED")
        reopened = WorkflowRunStore.open(store.folder)
        restored = WorkflowEngine.restore(reopened, catalog=catalog, runtime=runtime)
        # Opening/restore itself remains passive, even after a live source died.
        require(not approvals and not launches, "R60_CHECKPOINT_OPEN_DISPATCHED_NATIVE_ACTION")
        resumed = restored.resume()
        rows = _rows(resumed)
        require(resumed["state"] == "RECOVERY_UNCONFIRMED" and
                rows["never-replayed-effect"]["state"] != "COMPLETED" and not approvals and not launches,
                "R60_ACTUAL_DEAD_TARGET_RESUME_WAS_NOT_REFUSED")
        require(_result_stamps(store) == stamps and all(rows[name]["run_receipt"] == receipts[name]
                for name in receipts), "R60_CHECKPOINT_OLD_RESULT_OR_RECEIPT_WAS_REWRITTEN")
        records, journal = independent_journal(store.folder)
        require(not any(event["event"] == "node.intent" and event.get("node_id") == "never-replayed-effect"
                        for event in records) and file_hash(trace_path) == before_hash,
                "R60_CHECKPOINT_EFFECT_REPLAY_OR_SOURCE_MODIFICATION")
        proof = {"status": "PASS", "source_sha": source_sha, "target": target,
            "normal_target_exit": normal_exit, "resume_state": resumed["state"],
            "errors": resumed.get("errors", []), "fresh_consent_requests": 0, "helper_launches": 0,
            "completed_results_immutable": True, "original_trace_sha256": before_hash,
            "journal": journal, "scope": "ACTUAL_OS_PROCESS_EXIT_BEFORE_EXPLICIT_REOPENED_RESUME"}
    finally:
        if service is not None:
            cleanup = service.close()
            require(cleanup.get("status") == "COMPLETED", "R60_CHECKPOINT_SERVICE_CLEANUP_UNCONFIRMED")
            proof["service_cleanup"] = cleanup
        if fixture is not None:
            cleanup = fixture.close(kill=True)
            proof["failure_target_cleanup"] = cleanup
        require(not OwnedProcess.pending_cleanup(), "R60_CHECKPOINT_PENDING_OWNED_PROCESS")
    return proof


def observe_mid_cancel(output, executable, source_sha, *, trace_path):
    """Cancel an actual active ResearchSession node after another result is durable."""
    from .casebook import context
    from .chain_adapters import ChainRuntime, build_catalog
    from .chain_engine import WorkflowEngine
    from .chain_store import WorkflowRunStore
    from .chain_qa_native import OwnedWaveProbe
    from .optional_jobs import OwnedProcess
    from .research_worker import ResearchSession
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    before_hash = file_hash(trace_path)
    fixture = session = engine = worker = writer = journal_owner = None
    results, errors = [], []
    proof = {"status": "FAIL"}
    try:
        fixture = OwnedWaveProbe(Path(executable), output / "target")
        target = {key: fixture.ready[key] for key in ("pid", "created_100ns")}
        session = ResearchSession(output / "recordings")
        runtime = ChainRuntime(research=session, output_root=output / "recordings")
        workflow = definition([_source_node(trace_path),
            {"node_id": "actual-target", "tool_id": "process_select", "budget_seconds": 10,
             "parameters": {"pid": target["pid"]}},
            {"node_id": "actual-observe", "tool_id": "observe", "budget_seconds": 45,
             "parameters": {"duration_seconds": 30}}], [
                link("actual-target", "process", "actual-observe", "process")],
            identity="actual-observe-mid-cancel", seconds=120, workers=2)
        store = WorkflowRunStore.create(output / "runs", workflow)
        engine = WorkflowEngine(workflow, catalog=build_catalog(runtime), store=store, runtime=runtime)
        def execute():
            try:
                results.append(engine.run())
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=execute, name="r60-actual-observe-cancel-qa", daemon=True)
        worker.start()
        _wait(lambda: bool(session.probe.active and session.probe._store is not None and
              session.probe.total_samples >= 2 and
              _rows(engine.snapshot())["preserved-source"]["state"] == "COMPLETED"),
              "R60_CANCEL_ACTUAL_RECORDER_AND_PERSISTED_BRANCH_NOT_READY", seconds=20)
        active_at_cancel = session.probe.active
        require(worker.is_alive() and _rows(engine.snapshot())["actual-observe"]["state"] == "RUNNING",
                "R60_CANCEL_WAS_NOT_IN_FLIGHT")
        saved_source = deepcopy(_rows(engine.snapshot())["preserved-source"])
        durable_before = independent_journal(store.folder)[0]
        require(any(event["event"] == "node.result" and event.get("node_id") == "preserved-source"
                    for event in durable_before), "R60_CANCEL_OTHER_BRANCH_WAS_NOT_DURABLY_PUBLISHED")
        folder = Path(session.probe.session_folder).resolve(strict=True)
        writer = session.probe._store.v2
        journal_owner = session.probe._store._journal
        require(writer.thread.is_alive(), "R60_CANCEL_SCHEMA2_WRITER_WAS_NOT_ACTUALLY_RUNNING")
        cancel_at = time.monotonic_ns()
        engine.request_cancel()
        worker.join(timeout=30)
        require(not worker.is_alive() and not errors and len(results) == 1,
                "R60_CANCEL_ACTUAL_ENGINE_DID_NOT_ACKNOWLEDGE_STOP")
        snapshot = results[0]
        rows = _rows(snapshot)
        observed = rows["actual-observe"]
        require(snapshot["state"] == "CANCELLED" and observed["state"] == "CANCELLED" and
                observed["execution_started"] is True and observed["cleanup"].get("confirmed") is True and
                observed["cleanup"]["stop_result"].get("cleanup_required") is False and
                not observed["cleanup"]["stop_result"].get("errors"),
                "R60_CANCEL_NATIVE_RECORDER_STOP_ACK_MISSING")
        require(rows["preserved-source"] == saved_source and not session.probe.active and
                session.book is None and session._recording_resources_closed() and not writer.thread.is_alive() and
                (journal_owner is None or not journal_owner._worker.is_alive()) and
                snapshot["cleanup"].get("confirmed") is True,
                "R60_CANCEL_PUBLISHED_RESULT_CHANGED_OR_ACTUAL_RESOURCE_RETAINED")
        persisted = context(folder)
        require(persisted.get("capture_health", {}).get("recording_resources_closed") is True,
                "R60_CANCEL_PERSISTED_RECORDING_CLEANUP_NOT_CONFIRMED")
        sql = {name: _sql_integrity(folder / name) for name in
               ("session.sqlite3", "session-v2.sqlite3", "research.sqlite3") if (folder / name).is_file()}
        require(set(sql) == {"session.sqlite3", "session-v2.sqlite3", "research.sqlite3"},
                "R60_CANCEL_ALL_REAL_RECORDING_DATABASES_REQUIRED")
        records, journal = independent_journal(store.folder)
        completed_sources = [event for event in records if event["event"] == "node.result" and
                             event.get("node_id") == "preserved-source"]
        require(len(completed_sources) == 1 and file_hash(trace_path) == before_hash,
                "R60_CANCEL_OLD_BRANCH_REPLAYED_OR_ORIGINAL_TRACE_CHANGED")
        proof = {"status": "PASS", "source_sha": source_sha, "target": target,
            "state": snapshot["state"], "observe_state": observed["state"],
            "actual_recorder_active_at_cancel": active_at_cancel, "sample_count": session.probe.total_samples,
            "cancel_requested_monotonic_ns": cancel_at, "cleanup": observed["cleanup"],
            "engine_cleanup": snapshot["cleanup"], "writer_thread_closed": not writer.thread.is_alive(),
            "journal_thread_closed": journal_owner is None or not journal_owner._worker.is_alive(),
            "recording_sql": sql, "original_trace_sha256": before_hash, "journal": journal,
            "scope": "ACTUAL_RESEARCHSESSION_CANCEL_DURING_PRODUCTION_CHAIN_NODE"}
    finally:
        if engine is not None and worker is not None and worker.is_alive():
            engine.request_cancel()
            worker.join(timeout=30)
            require(not worker.is_alive(), "R60_CANCEL_FAILURE_WORKER_OWNER_RETAINED")
        if session is not None and not session._recording_resources_closed():
            stopped = session.stop("USER_STOPPED")
            require(stopped.get("cleanup_required") is False and session._recording_resources_closed(),
                    "R60_CANCEL_FAILURE_RECORDER_CLEANUP_UNCONFIRMED")
        if fixture is not None:
            cleanup = fixture.close(kill=proof["status"] != "PASS")
            proof["target_cleanup"] = cleanup
            if proof["status"] == "PASS":
                require(cleanup["status"] == "COMPLETED", "R60_CANCEL_TARGET_EXIT_UNCONFIRMED")
        require(not OwnedProcess.pending_cleanup(), "R60_CANCEL_PENDING_OWNED_PROCESS")
    return proof


def _persisted_case_scope(artifact):
    """Read the committed case independently of the production case reader."""
    import hashlib
    path = Path(artifact["value"]["_path"])
    before = file_hash(path)
    require(before == artifact["value"]["sha256"], "R60_SELECTED_CASE_ARTIFACT_HASH_MISMATCH")
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 34 * 1024**2)
        deadline = time.monotonic() + 30
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        require(db.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "R60_SELECTED_CASE_SQL_INTEGRITY")
        rows = db.execute("SELECT case_id,schema,content_json,content_sha256 FROM investigation LIMIT 2").fetchall()
        require(len(rows) == 1 and len(rows[0][2].encode("utf-8")) <= 32 * 1024**2,
                "R60_SELECTED_CASE_DEFAULT_RECORD_BUDGET")
        case_id, schema, raw, recorded = rows[0]
        require(hashlib.sha256(raw.encode("ascii")).hexdigest() == recorded,
                "R60_SELECTED_CASE_CONTENT_HASH_MISMATCH")
        value = json.loads(raw)
        require(value.get("schema") == schema == "blackbox.investigation-graph/1" and
                value.get("case_id") == case_id == artifact["value"]["case_id"] and
                db.execute("SELECT count(*) FROM nodes").fetchone()[0] == len(value["nodes"]),
                "R60_SELECTED_CASE_SOURCE_IDENTITY_MISMATCH")
    require(file_hash(path) == before, "R60_SELECTED_CASE_READBACK_CHANGED_SOURCE")
    return value, {"case_id": case_id, "case_sha256": before, "content_sha256": recorded,
                   "content_bytes": len(raw.encode("ascii")), "source_unchanged": True}


def _verify_selected_source_views(workflow, rows, index, fixture_pid):
    require(type(fixture_pid) is int and fixture_pid > 0, "R60_SELECTED_TRACE_FIXTURE_PID_REQUIRED")
    declared = {node.node_id: node for node in workflow.nodes}
    selected = {"pid": fixture_pid}
    require(declared["recorded-trace"].parameters.get("selection") == selected and
            index["value"].get("selection") == selected,
            "R60_SELECTED_TRACE_SCOPE_NOT_PRESERVED_THROUGH_DECODE")
    for node in workflow.nodes:
        if node.tool_id == "load_source" and node.node_id != "recorded-trace":
            require(node.parameters.get("selection", {}) == {}, "R60_TRACE_PID_LEAKED_INTO_OTHER_SOURCE_SCOPE")
    trace = rows["recorded-trace"]["outputs"]["source"][0]
    require(file_hash(trace["value"]["_path"]) == trace["value"]["sha256"],
            "R60_SELECTED_VIEW_CHANGED_ORIGINAL_TRACE")
    with closing(sqlite3.connect(Path(index["value"]["_path"]).resolve().as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        summary = json.loads(db.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
        total, target_rows = db.execute("SELECT count(*),sum(CASE WHEN pid=? THEN 1 ELSE 0 END) FROM events",
                                       (fixture_pid,)).fetchone()
        require(total == summary["rows"] and target_rows > 0, "R60_SELECTED_VIEW_RAW_INDEX_OR_TARGET_ROWS_CHANGED")
    case_proofs, combined = {}, None
    for node_id in ("trace-critical-path", "investigation"):
        case, proof = _persisted_case_scope(rows[node_id]["outputs"]["case"][0])
        traces = [source for source in case["sources"] if source["source_type"] == "TRACE_INDEX"]
        require(len(traces) == 1 and traces[0]["selection"] == selected and
                traces[0]["index_sha256"] == index["value"]["sha256"],
                "R60_PERSISTED_CASE_LOST_SELECTED_TRACE_SCOPE")
        require(not any(edge.get("relation_type") == "BOUNDED_TIME_CORRELATION" for edge in case["edges"]) and
                case["critical_path"]["end_to_end_established"] is False and
                case["root_cause_proven"] is False, "R60_SELECTED_VIEW_PROMOTED_CROSS_SOURCE_CLOCK_OR_CAUSE")
        proof.update(trace_selection=selected, cross_source_clock_alignment="NOT_ESTABLISHED",
                     end_to_end_established=False, root_cause_proven=False)
        case_proofs[node_id] = proof
        if node_id == "investigation":
            combined = case
    sessions = []
    for node_id in ("session-before", "session-after"):
        artifact = rows[node_id]["outputs"]["source"][0]
        require(artifact["value"].get("selection", {}) == {}, "R60_SESSION_SELECTION_OVERWRITTEN_BY_TRACE_PID")
        saved = [entry for entry in artifact["value"]["files"] if Path(entry["_path"]).name == "session-v2.sqlite3"]
        require(len(saved) == 1, "R60_SELECTED_VIEW_ACTUAL_SESSION_V2_SOURCE_REQUIRED")
        database = saved[0]
        require(file_hash(database["_path"]) == database["sha256"], "R60_SELECTED_VIEW_SESSION_HASH_CHANGED")
        with closing(sqlite3.connect(Path(database["_path"]).resolve().as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            target = db.execute("SELECT session_uuid,root_pid,root_creation_time FROM targets WHERE target_id=1").fetchone()
            instance = db.execute("SELECT pid,creation_time FROM process_instances WHERE instance_id=1").fetchone()
        require(target is not None and instance == target[1:] and file_hash(database["_path"]) == database["sha256"],
                "R60_SELECTED_VIEW_SESSION_ROOT_IDENTITY_CHANGED")
        if node_id == "session-before":
            candidates = [source for source in combined["sources"] if source["source_type"] == "SESSION" and
                          source.get("session_uuid") == target[0]]
            require(len(candidates) == 1 and candidates[0]["selection"] == {},
                    "R60_COMBINED_CASE_FILTERED_ITS_INDEPENDENT_SESSION")
            source_id = candidates[0]["source_id"]
            identities = [node.get("process_identity") for node in combined["nodes"]
                          if node["source_identity"] == source_id and node["observation_type"] == "PROCESS"]
            require(any(identity and identity.get("pid") == target[1] and identity.get("creation_time") == target[2]
                        and identity.get("instance_id") == 1 and identity.get("exact") is False for identity in identities),
                    "R60_COMBINED_CASE_REBOUND_SESSION_TO_TRACE_PROCESS")
        sessions.append({"node_id": node_id, "session_uuid": target[0], "root_pid": target[1],
            "root_creation_time": target[2], "identity_quality": "RECORDED_FLOAT_NOT_EXACT_FILETIME",
            "selection": {}, "source_sha256": database["sha256"], "source_unchanged": True})
    require(file_hash(index["value"]["_path"]) == index["value"]["sha256"],
            "R60_SELECTED_VIEW_RAW_INDEX_MODIFIED")
    return {"status": "PASS", "scope": "PER_SOURCE_RECORDED_VIEW_SELECTION_NOT_GLOBAL_PROCESS_REBINDING",
        "trace_fixture_pid": fixture_pid, "original_trace_sha256": trace["value"]["sha256"],
        "raw_index_sha256": index["value"]["sha256"], "raw_index_rows": total,
        "target_header_rows": target_rows, "other_header_rows": total - target_rows,
        "raw_index_rewritten_or_filtered": False, "case_readback": case_proofs, "session_roots": sessions,
        "cross_source_clock_alignment": "NOT_ESTABLISHED", "root_cause": "UNKNOWN"}


def verify_io_critical_path(workflow, records, *, fixture_pid=None):
    """Prove real receipts and passthrough dependencies, not sibling execution."""
    rows = {event["node_id"]: event["data"] for event in records
            if event["event"] == "node.result"}
    sequence = (("decoder", "index", "waits", "index"),
                ("waits", "index", "file_io", "index"),
                ("file_io", "index", "disk_io", "index"),
                ("disk_io", "index", "trace-critical-path", "case"),
                ("trace-critical-path", "report", "trace-critical-path-export-json", "case"),
                ("trace-critical-path", "report", "trace-critical-path-export-html", "case"))
    declared = {(edge.source_node, edge.source_port, edge.target_node, edge.target_port)
                for edge in workflow.edges}
    index = rows["decoder"]["outputs"]["index"][0]
    require(index["kind"] == "TRACE_INDEX" and index["clock_domains"] and index["value"].get("sha256"),
            "R60_Q15_ACTUAL_DECODER_INDEX_OR_CLOCK_DOMAIN_MISSING")
    links = []
    for source, port, target, input_port in sequence:
        require((source, port, target, input_port) in declared, "R60_Q15_GRAPH_DOES_NOT_DECLARE_ACTUAL_PATH")
        upstream, downstream = rows[source], rows[target]
        require(upstream["execution_started"] is True and downstream["execution_started"] is True and
                upstream["state"] in ("COMPLETED", "PARTIAL") and downstream["state"] in ("COMPLETED", "PARTIAL") and
                downstream["started_monotonic_ns"] >= upstream["ended_monotonic_ns"] and
                type(upstream.get("run_receipt")) is dict and type(downstream.get("run_receipt")) is dict and
                upstream["cleanup"].get("confirmed") is True and downstream["cleanup"].get("confirmed") is True,
                "R60_Q15_ACTUAL_ORDER_RECEIPT_OR_CLEANUP_UNCONFIRMED")
        artifact = upstream["outputs"][port][0]
        if port == "index":
            require(artifact == index, "R60_Q15_INDEX_PASSTHROUGH_IDENTITY_OR_CLOCK_CHANGED")
        links.append({"upstream": source, "downstream": target, "artifact_id": artifact["artifact_id"],
                      "sha256": artifact["value"]["sha256"], "clock_domains": artifact["clock_domains"],
                      "upstream_receipt": upstream["run_receipt"]["run_id"],
                      "downstream_receipt": downstream["run_receipt"]["run_id"],
                      "upstream_component_status": upstream["component_status"],
                      "downstream_component_status": downstream["component_status"]})
    require(file_hash(index["value"]["_path"]) == index["value"]["sha256"],
            "R60_Q15_ORIGINAL_INDEX_CHANGED")
    critical = rows["trace-critical-path"]["outputs"]["report"][0]
    actual_path = read_json(critical["value"]["_path"])
    require(actual_path.get("schema") == "blackbox.critical-path/1" and
            actual_path.get("end_to_end_established") is False and
            actual_path.get("status") == rows["trace-critical-path"]["component_status"],
            "R60_Q15_CRITICAL_PATH_STATUS_OR_SCOPE_WAS_PROMOTED")
    class HTMLCases(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.active, self.parts, self.documents = False, [], []
        def handle_starttag(self, tag, attrs):
            if tag == "pre":
                require(not self.active, "R60_Q15_NESTED_HTML_SOURCE")
                self.active, self.parts = True, []
        def handle_data(self, text):
            if self.active:
                self.parts.append(text)
        def handle_endtag(self, tag):
            if tag == "pre" and self.active:
                self.active = False
                try:
                    value = json.loads("".join(self.parts))
                except ValueError:
                    return
                if type(value) is dict and "case_id" in value and "critical_path" in value:
                    self.documents.append(value)
    documents, exported_hashes = [], {}
    for format in ("json", "html"):
        output = rows["trace-critical-path-export-" + format]["outputs"]["report"][0]
        require(output["value"].get("readback_verified") is True and
                file_hash(output["value"]["_path"]) == output["value"]["sha256"],
                "R60_Q15_COMMITTED_EXPORT_HASH_OR_READBACK_FLAG")
        if format == "json":
            document = read_json(output["value"]["_path"])
        else:
            reader = HTMLCases()
            reader.feed(Path(output["value"]["_path"]).read_text(encoding="utf-8"))
            reader.close()
            require(not reader.active and len(reader.documents) == 1, "R60_Q15_HTML_SOURCE_METADATA_MISSING")
            document = reader.documents[0]
        require(document.get("critical_path") == actual_path and document.get("root_cause_proven") is False,
                "R60_Q15_EXPORT_DID_NOT_PRESERVE_ACTUAL_CRITICAL_PATH_SEMANTICS")
        documents.append(document)
        exported_hashes[format] = output["value"]["sha256"]
    require(documents[0] == documents[1], "R60_Q15_JSON_HTML_SEMANTIC_MISMATCH")
    view_scope = _verify_selected_source_views(workflow, rows, index, fixture_pid) if fixture_pid is not None else None
    return {"status": "PASS", "source_index_sha256": index["value"]["sha256"], "links": links,
            "json_html_semantic_readback": True, "export_sha256": exported_hashes,
            "selected_source_views": view_scope,
            "scope": "ACTUAL_DECLARED_AND_EXECUTED_INDEX_PASSTHROUGH_CHAIN_NOT_CAUSAL_PROOF",
            "clock_alignment": "NOT_PROMOTED_BY_WORKFLOW"}


def run_actual_faults(output, executable, source_sha, *, trace_path, diagnostic_helper=None):
    require_hosted_windows()
    identity = source_proof(source_sha)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    from .chain_qa_faults_helper import helper_crash_graph
    proof = {"schema": "blackbox.r60.actual-negative-chains/1", "status": "FAIL",
             "source_identity": identity, "source_sha": source_sha, "physical_secure_desktop": "NOT_TESTED"}
    try:
        proof["checkpoint_target_exit"] = checkpoint_target_exit(output / "checkpoint", executable, source_sha,
            trace_path=trace_path, diagnostic_helper=diagnostic_helper)
        save(output / "result.json", proof)
        print("R60_ACTUAL_CHECKPOINT_EXIT_RECEIPT " + json.dumps(proof["checkpoint_target_exit"], sort_keys=True), flush=True)
        proof["observe_mid_cancel"] = observe_mid_cancel(output / "cancel", executable, source_sha,
                                                        trace_path=trace_path)
        save(output / "result.json", proof)
        print("R60_ACTUAL_OBSERVE_CANCEL_RECEIPT " + json.dumps(proof["observe_mid_cancel"], sort_keys=True), flush=True)
        proof["helper_crash_in_flight"] = helper_crash_graph(output / "helper-crash", executable, source_sha,
            trace_path=trace_path, diagnostic_helper=diagnostic_helper)
        proof["status"] = "PASS"
    except BaseException as error:
        proof.update(error=type(error).__name__, reason=str(error)[:1600])
        raise
    finally:
        save(output / "result.json", proof)
        print("R60_ACTUAL_NEGATIVE_CHAINS_RECEIPT " + json.dumps(proof, sort_keys=True), flush=True)
    return proof
