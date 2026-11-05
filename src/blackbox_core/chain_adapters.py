"""R60 adapters call existing BLACK.BOX components; definitions grant no rights.

All imports of collectors and Qt-facing owners are deferred until an explicit
execution. Artifacts carry bounded references, never memory or dump contents.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Callable
from uuid import uuid4

from .chain_contracts import Artifact, NodeOutcome, PortSpec, ToolAdapter, WorkflowError, canonical, require
from .deep_contracts import ActionRequest, DEEP_ACTIONS, ProcessIdentity
from .deep_tool_contracts import RunContext, RunReceipt, ToolDescriptor, describe_tool


@dataclass
class ChainRuntime:
    """One runtime owner, injected by the GUI or explicitly by headless callers.

    native_call(operation, parameters, target, ctx) uses the existing GUI Deep
    confirmation path. Headless native execution requires an explicit inspector
    and fresh authorize(operation, parameters, target, ctx); a returned dict is
    fresh private action parameters, not saved authority. process_select(pid,
    ctx) returns a freshly verified ProcessIdentity. observe_call(process,
    policy, duration, ctx) returns actual start/stop ACKs and final snapshot.
    """
    inspector: object = None
    native_call: Callable | None = None
    authorize: Callable | None = None
    output_root: object = None
    process_select: Callable | None = None
    observe_call: Callable | None = None
    research: object = None
    research_factory: Callable | None = None
    session_finalize: Callable | None = None
    owned_session_run_id: str | None = None
    native_context_ref: dict | None = None
    finish_run: Callable | None = None


_SOURCE_KINDS = ("TRACE", "TRACE_INDEX", "SESSION", "CASE", "DUMP", "DEEP_RESULT")
_SOURCE_TYPES = {"TRACE_INDEX": "TRACE_INDEX", "SESSION": "SESSION", "DUMP": "DUMP_METADATA",
                 "DEEP_RESULT": "DEEP_JOURNAL"}
_CLEAN_FILES = {"status": "CONFIRMED", "confirmed": True,
                "scope": "OPERATION_FILE_HANDLES_CLOSED_AND_RESULT_READ_BACK"}


def _descriptor(name, inputs, outputs, *, resources=(), effects="READ_ONLY_SOURCE; CREATE_NEW_RESULT_ONLY",
                required_rights="READ_ONLY_LOCAL_EVIDENCE"):
    return ToolDescriptor("blackbox.workflow." + name, 1, tuple(inputs), tuple(outputs),
        ("workflow." + name,), required_rights, effects,
        {"max_result_metadata_bytes": 256 * 1024, "deadline": "CALLER_MONOTONIC_DEADLINE"},
        tuple(resources), {"supported": True, "method": "CANCEL_EVENT_AND_EXISTING_COMPONENT_DEADLINE",
                           "cleanup": "ACTUAL_COMPONENT_ACK_REQUIRED", "completion_is_not_rollback": True})


def _flat(value):
    if isinstance(value, Artifact):
        if value.kind == "EVIDENCE_SET":
            for item in value.value.get("items", []):
                yield from _flat(Artifact.from_dict(item))
        else:
            yield value
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from _flat(item)


def _all(inputs):
    return tuple(artifact for value in inputs.values() for artifact in _flat(value))


def _sources(artifacts):
    rows = {}
    for artifact in artifacts:
        for source in artifact.sources:
            rows[canonical(source)] = source
    require(len(rows) <= 64, "WORKFLOW_SOURCE_REFERENCE_BUDGET")
    return tuple(rows[key] for key in sorted(rows))


def _clocks(artifacts):
    return tuple(sorted({clock for artifact in artifacts for clock in artifact.clock_domains}))


def _links(artifacts):
    """Flat immutable file dependencies; historical evidence is not a live PID."""
    result = {}
    for artifact in artifacts:
        if artifact.kind in ("PROCESS", "RECEIPT"):
            continue
        row = artifact.to_dict()
        value = dict(row["value"])
        upstream = value.pop("upstream_artifacts", [])
        row["value"] = value
        result[artifact.artifact_id] = row
        for reference in upstream:
            result[reference["artifact_id"]] = reference
    require(len(result) <= 64, "WORKFLOW_UPSTREAM_REFERENCE_BUDGET")
    return [result[key] for key in sorted(result)]


def _path(artifact):
    require(isinstance(artifact, Artifact) and type(artifact.value.get("_path")) is str,
            "WORKFLOW_FILE_REFERENCE_REQUIRED")
    return Path(artifact.value["_path"])


def _verify(artifact, ctx):
    from .chain_io import verify_artifact
    return verify_artifact(artifact, cancel=ctx.cancel, deadline=ctx.deadline, owner_run_id=ctx.run_id)


def _file(kind, path, *, metadata=None, sources=(), coverage=None, clocks=()):
    from .chain_io import make_file_artifact
    return make_file_artifact(kind, path, metadata=metadata, sources=sources,
                              coverage=coverage or {"evidence_completeness": "UNKNOWN"},
                              clock_domains=clocks)


def _output(ctx, name):
    from .session_v2 import safe_path
    ctx.check()
    root = safe_path(Path(ctx.output_dir))
    root.mkdir(parents=True, exist_ok=True)
    return root / (name + "-" + uuid4().hex)


def _budget(ctx):
    from .investigation_graph_contracts import InvestigationBudget
    return InvestigationBudget(timeout_seconds=min(300, max(.001, ctx.remaining_seconds())),
                               cancel_event=ctx.cancel, deadline=ctx.deadline)


def _save_metadata(ctx, value, name):
    """Publish metadata through the existing no-clobber export transaction."""
    from .export_recovery import export_stage
    from .investigation_graph_store import public_metadata
    value = public_metadata(value)
    raw = canonical(value).encode("ascii")
    require(len(raw) <= 32 * 1024**2, "WORKFLOW_RESULT_METADATA_BUDGET")
    destination = _output(ctx, name).with_suffix(".json")
    with export_stage(destination.parent, kind="WORKFLOW_METADATA") as transaction:
        staged = transaction.reserve(destination.name)
        with staged.open("r+b") as stream:
            for start in range(0, len(raw), 65536):
                ctx.check()
                stream.write(raw[start:start + 65536])
            stream.flush()
            os.fsync(stream.fileno())
        require(json.loads(staged.read_text(encoding="ascii")) == value,
                "WORKFLOW_RESULT_SEMANTIC_READBACK")
        transaction.prepare({destination.name: staged})
        ctx.check()
        transaction.publish()
    # A committed result is retained if public read-back cannot verify it.
    try:
        require(json.loads(destination.read_text(encoding="ascii")) == value,
                "WORKFLOW_RESULT_PUBLICATION_UNCONFIRMED")
    except Exception as error:
        error.publication_unconfirmed = True
        raise
    return destination


def _receipt_outcome(answer, outputs, *, status=None, cleanup=None, reason=None):
    receipt = answer.get("run_receipt")
    return NodeOutcome(status or (receipt or {}).get("status") or answer.get("status", "UNKNOWN"), outputs,
        receipt=receipt, descriptor=answer.get("tool_descriptor"), context=answer.get("run_context"),
        cleanup=dict(cleanup if cleanup is not None else (receipt or {}).get("cleanup", {})),
        execution_started=(receipt or {}).get("execution_started"), reason_code=reason)


def _materialize_result(answer, build_outputs):
    """A reference/publication failure cannot erase an already returned action."""
    try:
        return _receipt_outcome(answer, build_outputs())
    except Exception as error:
        uncertain = any(getattr(error, key, False) for key in
                        ("cleanup_required", "cleanup_unconfirmed", "publication_unconfirmed", "offline_owner_retained"))
        status = ("RECOVERY_UNCONFIRMED" if uncertain else "CANCELLED" if isinstance(error, InterruptedError)
                  else "TIMED_OUT" if isinstance(error, TimeoutError) else "OPERATION_FAILED")
        return _receipt_outcome(answer, {}, status=status,
            reason="WORKFLOW_RESULT_REFERENCE_FAILED:" + (getattr(error, "code", str(error)[:200]) or type(error).__name__))


def _wrap(name, descriptor, call):
    """Add existing run records only when the component has none of its own."""
    def execute(ctx, inputs, parameters):
        artifacts = _all(inputs)
        now, begun = datetime.now(timezone.utc), time.monotonic_ns()
        run = RunContext(ctx.node_run_id, "workflow." + name, None, _sources(artifacts), parameters,
            now.isoformat(), begun,
            (now + timedelta(seconds=max(0, ctx.remaining_seconds()))).isoformat(),
            int(ctx.deadline * 1_000_000_000),
            {"level_at_request": "READ_ONLY_LOCAL_EVIDENCE", "authorization": "DESCRIPTIVE_ONLY"},
            {"timeout_seconds": max(0, ctx.remaining_seconds())})
        started, outcome = False, None
        try:
            ctx.check()
            for artifact in artifacts:
                _verify(artifact, ctx)
            # A returned component outcome supplies its actual execution flag.
            # A validation/dispatch exception alone cannot prove collection ran.
            started = None
            outcome = call(ctx, inputs, parameters)
            # Revalidate consumed originals after analysis, not after native
            # intervention (which legitimately changes the live process).
            for artifact in artifacts:
                if artifact.kind != "PROCESS":
                    _verify(artifact, ctx)
        except Exception as error:
            if getattr(error, "run_receipt", None):
                raise
            uncertain = any(getattr(error, key, False) for key in
                            ("cleanup_required", "cleanup_unconfirmed", "publication_unconfirmed", "offline_owner_retained"))
            status = ("RECOVERY_UNCONFIRMED" if uncertain else "CANCELLED" if isinstance(error, InterruptedError)
                      else "TIMED_OUT" if isinstance(error, TimeoutError) else getattr(error, "status", "OPERATION_FAILED"))
            if outcome is not None:
                # Published component evidence survives a later cancellation or
                # failed source revalidation. Its original receipt is immutable.
                outcome.status = status
                outcome.reason_code = getattr(error, "code", str(error)[:256] or type(error).__name__)
            else:
                outcome = NodeOutcome(status, cleanup={"status": "RECOVERY_UNCONFIRMED" if uncertain else "NOT_COLLECTED",
                    "confirmed": False, "owner_retained": uncertain}, execution_started=started,
                    reason_code=getattr(error, "code", str(error)[:256] or type(error).__name__))
        if outcome.receipt is None:
            references = tuple({"kind": artifact.kind, "artifact_id": artifact.artifact_id,
                "sha256": artifact.value.get("sha256"), "bytes": artifact.value.get("bytes")}
                for value in outcome.outputs.values() for artifact in _flat(value))
            receipt = RunReceipt(run.run_id, run.operation, descriptor.tool_id, run.started_at_utc,
                datetime.now(timezone.utc).isoformat(), max(0, time.monotonic_ns() - begun), outcome.status,
                outcome.execution_started if outcome.execution_started is not None else started,
                {"name": "EXISTING_BLACKBOX_COMPONENT", "verified": outcome.execution_started is True,
                 "verification_scope": "ACTUAL_CALL_PATH_NOT_PRODUCER_AUTHENTICATION", "sources": list(run.sources)},
                {"identity": None, "verified": False, "scope": "NO_LIVE_TARGET_AUTHORITY"}, references,
                {"completeness": "UNKNOWN", "scope": "ACTUAL_COMPONENT_INVOCATION_ONLY"},
                ((outcome.reason_code,) if outcome.reason_code else ()), run.limits, outcome.cleanup,
                descriptor.effects).to_dict()
            outcome.receipt, outcome.context, outcome.descriptor = receipt, run.to_dict(), descriptor.to_dict()
            outcome.execution_started = receipt["execution_started"]
        return outcome
    return execute


def _runtime(ctx, fallback):
    return getattr(ctx, "runtime", None) or fallback or ChainRuntime()


def _case_artifact(ctx, case, path, *, upstream=()):
    domains = tuple(sorted({str(row["time_domain"]) for row in case.get("nodes", []) if row.get("time_domain")}))
    return _file("CASE", path, metadata={"case_id": case["case_id"], "schema": case["schema"],
                 "upstream_artifacts": _links(upstream)},
                 sources=tuple(case.get("sources", [])), coverage=case.get("coverage", {}), clocks=domains)


def _source_specs(artifacts):
    specs = []
    for artifact in artifacts:
        if artifact.kind == "INCIDENT":
            require(type(artifact.value.get("_session_path")) is str, "WORKFLOW_INCIDENT_SESSION_REFERENCE_REQUIRED")
            specs.append({"source_type": "SESSION", "path": artifact.value["_session_path"],
                          "selection": artifact.value.get("selection", {})})
            continue
        require(artifact.kind in _SOURCE_TYPES, "WORKFLOW_UNSUPPORTED_INVESTIGATION_SOURCE_" + artifact.kind)
        spec = {"source_type": _SOURCE_TYPES[artifact.kind], "path": str(_path(artifact))}
        if artifact.value.get("selection"):
            spec["selection"] = artifact.value["selection"]
        for key in ("image_path", "pdb_path", "session_path", "clock_journal"):
            if artifact.value.get("_" + key):
                spec[key] = artifact.value["_" + key]
        specs.append(spec)
    require(1 <= len(specs) <= 16, "WORKFLOW_INVESTIGATION_SOURCE_BUDGET")
    return specs


def _make_case(ctx, artifacts, parameters=None):
    from .investigation_v3 import create_investigation
    path = _output(ctx, "investigation").with_suffix(".sqlite3")
    case = create_investigation(_source_specs(artifacts), selection=(parameters or {}).get("selection"),
        scenario=(parameters or {}).get("scenario"), budget=_budget(ctx), index_path=path)
    try:
        return case, _case_artifact(ctx, case, path, upstream=artifacts)
    except Exception as error:
        error.run_receipt = case.get("run_receipt")
        error.run_context = case.get("run_context")
        error.tool_descriptor = case.get("tool_descriptor")
        raise


def _load_case(ctx, artifact):
    from .investigation_v3 import load_investigation
    return load_investigation(_path(artifact), budget=_budget(ctx))


def _load_source(ctx, inputs, parameters):
    kind = parameters["kind"]
    require(kind in _SOURCE_KINDS, "WORKFLOW_UNSUPPORTED_SOURCE_KIND")
    artifact = _file(kind, parameters["path"], metadata={"selection": parameters.get("selection", {})})
    from dataclasses import replace
    artifact = replace(artifact, sources=({"source_id": artifact.value["sha256"], "kind": kind,
        "verification": "UNVERIFIED_IMPORT", "identity_scope": "REFERENCED_BYTE_FINGERPRINT_NOT_PRODUCER_AUTHENTICATION"},))
    _verify(artifact, ctx)
    # Loading a saved reference never turns it into a live target or decoder run.
    return NodeOutcome("COMPLETED", {"source": artifact}, cleanup=dict(_CLEAN_FILES), execution_started=True)


def _select_process(runtime):
    def execute(ctx, inputs, parameters):
        from .chain_io import make_process_artifact
        owner = _runtime(ctx, runtime)
        pid = parameters.get("pid")
        if owner.process_select is not None:
            identity = owner.process_select(pid, ctx)
        else:
            require(type(pid) is int and pid > 0, "WORKFLOW_PROCESS_SELECTION_REQUIRED")
            from .deep_native import capture_identity_checked
            identity = capture_identity_checked(pid, owner_run_id=ctx.run_id)
        identity = ProcessIdentity.from_dict(identity)
        artifact = make_process_artifact(identity)
        _verify(artifact, ctx)
        return NodeOutcome("COMPLETED", {"process": artifact}, cleanup={"status": "CONFIRMED", "confirmed": True,
            "scope": "NATIVE_IDENTITY_QUERY_HANDLES_CLOSED"}, execution_started=True)
    return execute


def _direct_observe(owner, identity, policy, duration, ctx):
    from .research_worker import ResearchSession
    from .deep_native import capture_identity_checked
    require(capture_identity_checked(identity.pid, owner_run_id=ctx.run_id) == identity,
            "WORKFLOW_PROCESS_INSTANCE_CHANGED")
    session = owner.research
    if session is None:
        session = (owner.research_factory or ResearchSession)(output_root=owner.output_root or ctx.output_dir)
    require(not session.probe.active and session.book is None, "WORKFLOW_RECORDING_OWNER_BUSY")
    owner.research = session
    started, failure = None, None
    try:
        session.command({"op": "attach", "args": {"pid": identity.pid}})
        if policy:
            session.command({"op": "capture_policy", "args": {"policy": policy}})
        require(capture_identity_checked(identity.pid, owner_run_id=ctx.run_id) == identity,
                "WORKFLOW_PROCESS_INSTANCE_CHANGED")
        started = session.command({"op": "start", "args": {}})
        end = min(ctx.deadline, time.monotonic() + duration)
        while time.monotonic() < end and session.probe.active:
            ctx.check()
            session.tick()
            ctx.cancel.wait(min(session.interval_ms / 1000, max(0, end - time.monotonic())))
    except Exception as error:
        failure = error
    finally:
        # Use the existing explicit-stop reason. The workflow receipt separately
        # preserves cancellation, timeout, early target exit and actual errors.
        stopped = session.stop("USER_STOPPED")
        snapshot = session.snapshot()
        if stopped.get("cleanup_required"):
            # Preserve the owner, not only its path, for explicit cleanup retry.
            owner.research = session
    if started is None and failure is not None:
        raise failure
    return {"folder": (started or {}).get("folder") or str(session.probe.session_folder),
            "start_result": started, "stop_result": stopped, "snapshot": snapshot,
            "execution_status": ("CANCELLED" if ctx.cancel.is_set() or isinstance(failure, InterruptedError) else
                "TIMED_OUT" if isinstance(failure, TimeoutError) else "OPERATION_FAILED" if failure else None),
            "reason_code": (getattr(failure, "code", type(failure).__name__) if failure else None)}


def _observe(runtime):
    def execute(ctx, inputs, parameters):
        from .casebook import context
        owner = _runtime(ctx, runtime)
        identity = ProcessIdentity.from_dict(inputs["process"].value.get("identity", inputs["process"].value))
        duration = parameters.get("duration_seconds", 3.0)
        policy = parameters.get("policy", {})
        packet = (owner.observe_call(identity.to_dict(), policy, duration, ctx) if owner.observe_call else
                  _direct_observe(owner, identity, policy, duration, ctx))
        require(type(packet) is dict and type(packet.get("folder")) is str,
                "WORKFLOW_RECORDING_RESULT_REFERENCE_REQUIRED")
        folder = Path(packet["folder"])
        stopped, snapshot = packet.get("stop_result", {}), packet.get("snapshot", {})
        persisted = context(folder)
        confirmed = (stopped.get("cleanup_required") is False and not stopped.get("errors") and
            snapshot.get("active") is False and
            persisted.get("capture_health", {}).get("recording_resources_closed") is True)
        status = packet.get("execution_status") or stopped.get("state", "FINALIZATION_UNCONFIRMED")
        if not confirmed:
            status = "RECOVERY_UNCONFIRMED"
        artifact = _file("SESSION", folder, metadata={"recording_state": status,
            "recorded_target": identity.to_dict()}, coverage={"evidence_completeness": "UNKNOWN_CAPTURE_COMPLETENESS",
                "recording_state": status})
        return NodeOutcome(status, {"session": artifact}, cleanup={"status": "CONFIRMED" if confirmed else
            "RECOVERY_UNCONFIRMED", "confirmed": confirmed, "owner_retained": not confirmed,
            "scope": "EXISTING_RESEARCH_RECORDING_OWNER_FINALIZATION", "stop_result": stopped},
            execution_started=packet.get("start_result") is not None, reason_code=packet.get("reason_code"))
    return execute


def _decode(ctx, inputs, parameters):
    from .decoder_service import decode_file
    require(inputs["trace"].kind == "TRACE", "WORKFLOW_DECODER_REQUIRES_SUPPORTED_TRACE_SOURCE")
    path = _output(ctx, "trace-index").with_suffix(".sqlite3")
    answer = decode_file(_path(inputs["trace"]), path, cancel=_budget(ctx),
                         timeout=min(600, max(1, ctx.remaining_seconds())))
    def outputs():
        artifact = _file("TRACE_INDEX", path, metadata={"trace_sha256": answer.get("input_sha256"),
            "upstream_artifacts": _links((inputs["trace"],))},
            sources=tuple(answer.get("run_receipt", {}).get("source", {}).get("sources", ())),
            coverage=answer.get("run_receipt", {}).get("coverage", {}),
            clocks=("TRACE_RECORDED:" + str(answer.get("input_sha256")),))
        return {"index": artifact}
    return _materialize_result(answer, outputs)


def _load_graph(ctx, inputs, parameters):
    from .investigation_v3 import load_investigation
    source = inputs["source"]
    case = load_investigation(_path(source), budget=_budget(ctx))
    return NodeOutcome("COMPLETED", {"case": _case_artifact(ctx, case, _path(source), upstream=(source,))},
                       cleanup=dict(_CLEAN_FILES), execution_started=True)


def _investigate(ctx, inputs, parameters):
    case, artifact = _make_case(ctx, tuple(_flat(inputs["evidence"])), parameters)
    return _receipt_outcome(case, {"case": artifact})


def _critical_path(ctx, inputs, parameters):
    from .investigation_v3 import analyze_critical_path
    source = inputs["case"]
    if source.kind == "CASE":
        case, artifact = _load_case(ctx, source), source
    else:
        case, artifact = _make_case(ctx, (source,))
    report = analyze_critical_path(case, budget=_budget(ctx))
    path = _save_metadata(ctx, report, "critical-path")
    output = _file("REPORT", path, metadata={"report_type": "CRITICAL_PATH", "_case_path": str(_path(artifact)),
                   "upstream_artifacts": _links((artifact,))},
                   sources=artifact.sources, coverage=artifact.coverage, clocks=artifact.clock_domains)
    return NodeOutcome(report.get("status", "COMPLETED"), {"report": output, "case": artifact},
                       cleanup=dict(_CLEAN_FILES), execution_started=True)


def _trace_analysis(kind):
    def execute(ctx, inputs, parameters):
        if kind == "waits":
            from .decoder_waits import build_wait_report as analyze
        elif kind == "file_io":
            from .decoder_io import build_file_io_report as analyze
        else:
            from .decoder_io import build_disk_io_report as analyze
        index = inputs["index"]
        report = analyze(_path(index), cancel=_budget(ctx), **parameters)
        path = _save_metadata(ctx, report, kind)
        output = _file("REPORT", path, metadata={"report_type": kind.upper(), "_index_path": str(_path(index)),
                       "upstream_artifacts": _links((index,))},
                       sources=index.sources, coverage={**index.coverage, "analysis_status": report.get("status")},
                       clocks=index.clock_domains)
        return NodeOutcome(report.get("status", "COMPLETED"), {"report": output, "index": index},
                           cleanup=dict(_CLEAN_FILES), execution_started=True)
    return execute


def _crash(ctx, inputs, parameters):
    source = inputs["dump"]
    if parameters.get("image_path") or parameters.get("pdb_path"):
        from .chain_io import fingerprint_file
        auxiliary = [fingerprint_file(value, cancel=ctx.cancel, deadline=ctx.deadline)
                     for value in parameters.values() if value]
        source = Artifact(source.kind, {**source.value, **{"_" + key: value for key, value in parameters.items() if value},
                          "auxiliary_files": auxiliary},
                          sources=source.sources, clock_domains=source.clock_domains, coverage=source.coverage)
    case, artifact = _make_case(ctx, (source,))
    return _receipt_outcome(case, {"case": artifact})


def _incident(ctx, inputs, parameters):
    from .investigation_v2 import incident_card
    session = inputs["session"]
    report = incident_card(_path(session), parameters["incident_id"],
        pre_seconds=parameters.get("pre_seconds", 60), post_seconds=parameters.get("post_seconds", 20))
    require(type(report.get("range_ns")) is list and len(report["range_ns"]) == 2,
            "WORKFLOW_INCIDENT_HAS_NO_RECORDED_SAMPLE_RANGE")
    path = _save_metadata(ctx, report, "incident")
    selected = {"start_ns": report["range_ns"][0], "end_ns": report["range_ns"][1]}
    artifact = _file("INCIDENT", path, metadata={"incident_id": parameters["incident_id"],
        "_session_path": str(_path(session)), "selection": selected,
        "upstream_artifacts": _links((session,))}, sources=session.sources,
        coverage={**session.coverage, "post_context_complete": report.get("post_context_complete")},
        clocks=session.clock_domains)
    case, graph = _make_case(ctx, (artifact,))
    return _receipt_outcome(case, {"incident": artifact, "case": graph})


def _compare(ctx, inputs, parameters):
    first, second = inputs["before"], inputs["after"]
    require(first.kind == second.kind, "WORKFLOW_COMPARISON_REQUIRES_MATCHING_SOURCE_KINDS")
    if first.kind == "SESSION":
        from .casebook import compare_cases
        answer = compare_cases(_path(first), _path(second))
        mode = "RESEARCH_SESSION"
    else:
        from .investigation_v3 import compare_investigations
        answer = compare_investigations(_load_case(ctx, first), _load_case(ctx, second), budget=_budget(ctx))
        mode = "INVESTIGATION_GRAPH"
    path = _save_metadata(ctx, answer, "comparison")
    artifact = _file("COMPARISON", path, metadata={"mode": mode,
        "_before_path": str(_path(first)), "_after_path": str(_path(second)),
        "comparison_status": answer.get("comparison_status", answer.get("status", "UNKNOWN")),
        "upstream_artifacts": _links((first, second))},
        sources=_sources((first, second)), coverage={"completeness": "UNKNOWN", "causal_link_proven": False},
        clocks=_clocks((first, second)))
    if "run_receipt" in answer:
        return _receipt_outcome(answer, {"comparison": artifact})
    return NodeOutcome("COMPLETED", {"comparison": artifact}, cleanup=dict(_CLEAN_FILES), execution_started=True)


def _export_report(ctx, inputs, parameters):
    from .investigation_v3 import export_investigation, load_investigation
    source = inputs["case"]
    format_name = parameters.get("format", "json")
    path = _output(ctx, "report").with_suffix("." + format_name)
    if source.kind == "COMPARISON" and source.value.get("mode") == "RESEARCH_SESSION":
        from .casebook import export_comparison
        answer = export_comparison(source.value["_before_path"], source.value["_after_path"], path,
                                   format=format_name, cancel=ctx.cancel.is_set)
    else:
        if source.kind == "COMPARISON":
            case = load_investigation(source.value["_before_path"], budget=_budget(ctx))
            case["workflow_comparison"] = json.loads(_path(source).read_text(encoding="ascii"))
        elif source.kind == "REPORT":
            require(type(source.value.get("_case_path")) is str, "WORKFLOW_EXISTING_CASE_REPORT_REQUIRED")
            case = load_investigation(source.value["_case_path"], budget=_budget(ctx))
        else:
            case = _load_case(ctx, source)
        answer = export_investigation(case, path, format=format_name, budget=_budget(ctx))
    def outputs():
        artifact = _file("REPORT", path, metadata={"format": format_name,
            "readback_verified": answer.get("readback_verified"), "upstream_artifacts": _links((source,))},
            sources=source.sources, coverage=source.coverage, clocks=source.clock_domains)
        return {"report": artifact}
    return _materialize_result(answer, outputs)


def _snapshot_journal(ctx, owner, answer):
    source = answer.get("_journal_path") or getattr(getattr(owner.inspector, "journal", None), "path", None)
    if source is None:
        return None
    from .session_v2 import safe_path
    source = safe_path(Path(source))
    destination = _output(ctx, "deep-evidence").with_suffix(".sqlite3")
    require(source.is_file(), "WORKFLOW_DEEP_JOURNAL_MISSING")
    # Snapshot the existing journal schema, never invent a decoder/application
    # event from a native response. Later native calls cannot mutate this input.
    original = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=1)
    copy = None
    try:
        with destination.open("xb"):
            pass
        copy = sqlite3.connect(destination)
        original.backup(copy, pages=128, sleep=.01, progress=lambda *_: ctx.check())
        require(copy.execute("PRAGMA integrity_check").fetchone() == ("ok",), "WORKFLOW_DEEP_SNAPSHOT_INTEGRITY")
    finally:
        if copy is not None:
            copy.close()
        original.close()
    return destination


def _deep(operation, runtime):
    def execute(ctx, inputs, parameters):
        owner = _runtime(ctx, runtime)
        process = inputs["process"]
        identity = ProcessIdentity.from_dict(process.value.get("identity", process.value))
        actual = dict(parameters)
        if operation in ("dump", "profile.etw"):
            actual["destination"] = str(_output(ctx, "capture").with_suffix(".dmp" if operation == "dump" else ".etl"))
        spec = DEEP_ACTIONS[operation]
        if owner.native_call is not None:
            answer = owner.native_call(operation, actual, identity.to_dict(), ctx)
        else:
            require(owner.inspector is not None, "WORKFLOW_EXISTING_INSPECTOR_REQUIRED")
            confirmed = False
            if spec.confirmation_required:
                require(owner.authorize is not None, "WORKFLOW_FRESH_ACTION_CONFIRMATION_REQUIRED")
                ctx.waiting_for_human({"operation": operation, "target": identity.to_dict()})
                approval = owner.authorize(operation, dict(actual), identity.to_dict(), ctx)
                ctx.running()
                if type(approval) is dict:
                    actual = approval
                    confirmed = True
                else:
                    confirmed = approval is True
                if not confirmed:
                    return NodeOutcome("CONFIRMATION_REQUIRED", cleanup={"status": "CONFIRMED", "confirmed": True,
                        "scope": "NOT_DISPATCHED_NO_OPERATION_RESOURCES"}, execution_started=False,
                        reason_code="WORKFLOW_FRESH_ACTION_CONFIRMATION_REQUIRED")
            # Service rechecks exact instance, helper scope, rights and durable
            # intent. This adapter never starts UAC or authorizes a target.
            ctx.check()  # Fresh consent can outlive cancellation or its deadline.
            answer = owner.inspector.execute_owned(ActionRequest(operation, identity, actual, confirmed=confirmed,
                timeout_seconds=min(120, max(.1, ctx.remaining_seconds()))), owner_run_id=ctx.run_id,
                expected_context=owner.native_context_ref, cancel_event=ctx.cancel)
        require(type(answer) is dict, "WORKFLOW_NATIVE_RESULT_REQUIRED")
        reference = answer.get("native_context_ownership")
        if type(reference) is dict and reference.get("owner_run_id") == ctx.run_id:
            # Service-issued ownership is private runtime state, never evidence
            # or confirmation authority. Only its exact owner may later release.
            owner.native_context_ref = dict(reference)
            owner.owned_session_run_id = ctx.run_id
        receipt = answer.get("run_receipt")
        require(type(receipt) is dict, "WORKFLOW_NATIVE_RECEIPT_REQUIRED")
        def outputs():
            references = {}
            snapshot = _snapshot_journal(ctx, owner, answer)
            if snapshot is not None:
                selection = {"pid": identity.pid}
                started_ns = (answer.get("run_context") or {}).get("started_monotonic_ns")
                if type(started_ns) is int:
                    selection.update(start_ns=started_ns, end_ns=time.monotonic_ns())
                references["result"] = _file("DEEP_RESULT", snapshot, metadata={"operation": operation,
                    "operation_id": answer.get("operation_id"), "status": answer.get("status"),
                    "selection": selection,
                    "journal_scope": "ACTION_PID_AND_RECORDED_TIME_FILTER; SNAPSHOTS_KEEP_RECORDED_IDENTITIES"},
                    sources=process.sources, coverage=receipt.get("coverage", {}),
                    clocks=("NATIVE_CAPTURE:" + str(receipt.get("run_id")),))
            else:
                # No sensitive result body crosses the workflow boundary. A
                # receipt without its journal is usable for control only.
                references["result"] = Artifact("DEEP_RESULT", {"operation": operation,
                    "operation_id": answer.get("operation_id"), "status": answer.get("status"),
                    "source_unavailable_reason": "EXISTING_NATIVE_JOURNAL_REFERENCE_NOT_PROVIDED"},
                    sources=process.sources, coverage=receipt.get("coverage", {}))
            destination = (answer.get("data") or {}).get("destination")
            if destination and (answer.get("data") or {}).get("saved_verified") is True:
                kind, port = ("DUMP", "dump") if operation == "dump" else ("TRACE", "trace")
                references[port] = _file(kind, destination, metadata={"native_operation": operation},
                    sources=process.sources, coverage=receipt.get("coverage", {}), clocks=process.clock_domains)
            return references
        return _materialize_result(answer, outputs)
    return execute


def _finalize_session(runtime):
    def execute(ctx, inputs, parameters):
        owner = _runtime(ctx, runtime)
        require(owner.owned_session_run_id == ctx.run_id, "WORKFLOW_SESSION_NOT_OWNED_BY_THIS_RUN")
        if owner.session_finalize is not None:
            answer = owner.session_finalize(ctx)
        else:
            require(owner.inspector is not None, "WORKFLOW_EXISTING_INSPECTOR_REQUIRED")
            require(type(owner.native_context_ref) is dict, "WORKFLOW_NATIVE_CONTEXT_REFERENCE_REQUIRED")
            answer = owner.inspector.release_native_context(ctx.run_id, expected_context=owner.native_context_ref)
        require(type(answer) is dict, "WORKFLOW_SESSION_CLEANUP_RESULT_REQUIRED")
        data = answer.get("data") or {}
        cleanup = answer.get("cleanup") or data.get("expiry_cleanup") or data.get("cleanup") or {}
        confirmed = cleanup.get("confirmed") is True and answer.get("status") == "COMPLETED"
        if confirmed:
            owner.owned_session_run_id = None
            owner.native_context_ref = None
        elif type(answer.get("native_context_ownership")) is dict:
            owner.native_context_ref = dict(answer["native_context_ownership"])
        status = answer.get("status", "UNKNOWN") if confirmed else "RECOVERY_UNCONFIRMED"
        result = Artifact("DEEP_RESULT", {"operation": "session.close", "status": answer.get("status"),
            "cleanup_scope": cleanup.get("scope", "EXISTING_ADMINISTRATIVE_SESSION"),
            "source_unavailable_reason": "CONTROL_ONLY_NOT_DIAGNOSTIC_EVIDENCE"})
        return NodeOutcome(status, {"result": result}, cleanup={**cleanup, "confirmed": confirmed,
            "status": "CONFIRMED" if confirmed else "RECOVERY_UNCONFIRMED", "owner_retained": not confirmed},
            execution_started=True, reason_code=None if confirmed else "WORKFLOW_SESSION_CLEANUP_ACK_UNCONFIRMED")
    return execute


def _param(type_name, *, required=False, default=None, **options):
    value = {"type": type_name, "required": required, **options}
    if default is not None:
        value["default"] = default
    return value


def build_catalog(runtime=None):
    """Discover actual existing tools; construction performs no native action."""
    runtime = runtime or ChainRuntime()
    catalog = {}
    def add(name, inputs, outputs, parameters, call, *, resources=(), read_only=True, confirmation=False,
            required_rights="READ_ONLY_LOCAL_EVIDENCE"):
        descriptor = _descriptor(name, inputs, outputs, resources=resources, required_rights=required_rights,
            effects="READ_ONLY_SOURCE; CREATE_NEW_RESULT_ONLY" if read_only else "EXPLICIT_OWNED_SESSION_FINALIZATION")
        catalog[name] = ToolAdapter(name, descriptor, inputs, outputs, parameters,
            _wrap(name, descriptor, call), read_only=read_only,
            confirmation_required=confirmation, resources=resources)

    one = lambda *types, **flags: PortSpec(tuple(types), **flags)
    add("load_source", {}, {"source": one(*_SOURCE_KINDS)}, {
        "kind": _param("string", required=True, choices=list(_SOURCE_KINDS)),
        "path": _param("string", required=True), "selection": _param("object", default={})}, _load_source)
    add("process_select", {}, {"process": one("PROCESS")}, {"pid": _param("integer", min=1, max=0xFFFFFFFF)},
        _select_process(runtime), required_rights="WINDOWS_PROCESS_QUERY_LIMITED_INFORMATION; NO_ELEVATION")
    add("observe", {"process": one("PROCESS")}, {"session": one("SESSION")}, {
        "duration_seconds": _param("number", default=3, min=.1, max=21600),
        "policy": _param("object", default={})}, _observe(runtime), resources=("RESEARCH_RECORDING_OWNER",),
        required_rights="ORDINARY_PROCESS_QUERY_AND_COUNTER_READ; NO_ELEVATION")
    add("decode_trace", {"trace": one("TRACE")}, {"index": one("TRACE_INDEX")}, {}, _decode,
        resources=("DECODER_OWNED_STAGING",))
    add("load_graph", {"source": one("CASE")}, {"case": one("CASE")}, {}, _load_graph)
    add("investigate", {"evidence": one("SESSION", "TRACE_INDEX", "DUMP", "DEEP_RESULT", "INCIDENT", "EVIDENCE_SET", many=True)},
        {"case": one("CASE")}, {"selection": _param("object", default={}), "scenario": _param("object", default={})},
        _investigate, resources=("OFFLINE_DBGHELP_OWNER",))
    add("critical_path", {"case": one("CASE", "TRACE_INDEX")}, {"report": one("REPORT"), "case": one("CASE")},
        {}, _critical_path)
    filters = {"pid": _param("integer", default=0, min=0, max=0xFFFFFFFF),
        "process_instance": _param("integer", min=0), "tid": _param("integer", min=0),
        "start_ms": _param("number", min=0), "end_ms": _param("number", min=0)}
    for name in ("waits", "file_io", "disk_io"):
        add(name, {"index": one("TRACE_INDEX")}, {"report": one("REPORT"), "index": one("TRACE_INDEX")},
            dict(filters), _trace_analysis(name))
    add("crash", {"dump": one("DUMP")}, {"case": one("CASE")}, {
        "image_path": _param("string"), "pdb_path": _param("string")}, _crash,
        resources=("OFFLINE_DBGHELP_OWNER",))
    add("incident", {"session": one("SESSION")}, {"incident": one("INCIDENT"), "case": one("CASE")}, {
        "incident_id": _param("integer", required=True, min=1),
        "pre_seconds": _param("integer", default=60, min=0, max=300),
        "post_seconds": _param("integer", default=20, min=0, max=60)}, _incident)
    add("compare", {"before": one("CASE", "SESSION"), "after": one("CASE", "SESSION")},
        {"comparison": one("COMPARISON")}, {}, _compare)
    add("export_report", {"case": one("CASE", "COMPARISON", "REPORT")}, {"report": one("REPORT")}, {
        "format": _param("string", default="json", choices=["json", "html"])}, _export_report)
    add("session_finalize", {"after": one("RECEIPT", required=False, many=True)}, {"result": one("DEEP_RESULT")},
        {}, _finalize_session(runtime), resources=("EXISTING_DEEP_INSPECTOR_OWNER",), read_only=False)
    for operation, spec in DEEP_ACTIONS.items():
        descriptor = describe_tool(operation)
        outputs = {"result": one("DEEP_RESULT")}
        if operation == "dump":
            outputs["dump"] = one("DUMP", required=False)
        elif operation == "profile.etw":
            outputs["trace"] = one("TRACE", required=False)
        # Action parameter validation stays in the existing service/helper.
        # No memory bytes or stored confirmation may enter a definition.
        parameters = {"parameters": _param("object", default={})}
        def call(ctx, inputs, params, operation=operation):
            return _deep(operation, runtime)(ctx, inputs, params.get("parameters", {}))
        read_only = spec.mode != "INTERVENE" and operation not in ("thread_stacks", "dump")
        catalog["deep." + operation] = ToolAdapter("deep." + operation, descriptor,
            {"process": one("PROCESS")}, outputs, parameters, _wrap("deep." + operation, descriptor, call),
            read_only=read_only, confirmation_required=spec.confirmation_required,
            resources=("EXISTING_DEEP_INSPECTOR_OWNER",))
    # Discovery reports actual platform/runtime boundaries without constructing
    # an InspectorService, starting a collector, or trying a permission probe.
    from dataclasses import replace
    if os.name != "nt":
        if not (runtime and runtime.process_select):
            catalog["process_select"] = replace(catalog["process_select"], available=False,
                unavailable_reason="WINDOWS_NATIVE_CREATION_FILETIME_UNAVAILABLE_ON_THIS_PLATFORM")
        if not (runtime and runtime.observe_call):
            catalog["observe"] = replace(catalog["observe"], available=False,
                unavailable_reason="WORKFLOW_OBSERVE_REQUIRES_EXACT_WINDOWS_PROCESS_IDENTITY")
        if not (runtime and runtime.native_call):
            for key in tuple(catalog):
                if key.startswith("deep."):
                    catalog[key] = replace(catalog[key], available=False,
                        unavailable_reason="EXACT_WINDOWS_NATIVE_PROCESS_RUNTIME_REQUIRED")
    return catalog
