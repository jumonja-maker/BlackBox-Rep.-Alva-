"""Additive v1 run contracts for the existing, allowlisted Deep operations.

These records describe an actual InspectorService invocation. They neither grant
rights nor replace ActionRequest, the helper checks, or the legacy result schema.
Only metadata and result references cross this boundary; returned memory and
imported payloads stay in their existing explicitly requested result channels.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import time
from typing import Any
from uuid import uuid4

from .deep_contracts import (ActionRequest, DEEP_ACTIONS, MAX_MEMORY_BYTES,
                             MAX_MESSAGE_BYTES, MAX_OPERATION_SECONDS,
                             MAX_SESSION_SECONDS, ProcessIdentity,
                             canonical_operation)
from .deep_journal import journal_metadata

CONTRACT_VERSION = 1
_LOCAL = frozenset({"timeline", "compare", "trace_evidence", "dump_inspect",
                    "dump_read_memory", "symbols_verify"})
_EVIDENCE_OPERATIONS = frozenset({"decoder.decode", "investigation.create", "investigation.export",
                                "research.compare", "research.export_comparison"})
# Descriptive receipt labels only. This list adds no ActionRequest operation,
# Helper command, permission or authority to repeat a saved workflow action.
_WORKFLOW_OPERATIONS = frozenset("workflow." + name for name in (
    "load_source", "process_select", "observe", "decode_trace", "load_graph", "investigate",
    "critical_path", "waits", "file_io", "disk_io", "crash", "incident", "compare", "export_report",
    "session_finalize")) | frozenset("workflow.deep." + name for name in DEEP_ACTIONS)


@dataclass(frozen=True)
class ToolDescriptor:
    tool_id: str
    version: int
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    operations: tuple[str, ...]
    required_rights: str
    effects: str
    budgets: dict[str, Any]
    resources: tuple[str, ...]
    cancellation: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return journal_metadata(dict(self.__dict__, inputs=list(self.inputs),
                                     outputs=list(self.outputs), operations=list(self.operations),
                                     resources=list(self.resources),
                                     authority="DESCRIPTIVE_ONLY_EXISTING_HELPER_RECHECKS_AUTHORIZATION"))


def describe_tool(operation: str) -> ToolDescriptor:
    """Derive discovery from ActionSpec; never add a second executable catalog."""
    operation = canonical_operation(operation)
    spec = DEEP_ACTIONS[operation]
    resources = (("read-only local evidence inputs",) if operation in _LOCAL else
                 ("exact process instance handles", "target-bound diagnostic context"))
    if spec.mode == "INTERVENE" or operation in ("thread_stacks", "dump"):
        resources += ("operation-owned resources requiring acknowledged cleanup",)
    budgets = {"default_timeout_seconds": spec.timeout_seconds,
               "max_operation_seconds": MAX_OPERATION_SECONDS,
               "max_admin_session_seconds": MAX_SESSION_SECONDS,
               "max_message_bytes": MAX_MESSAGE_BYTES}
    if operation == "memory_read":
        budgets["max_memory_read_bytes"] = MAX_MEMORY_BYTES
    elif operation == "dump_read_memory":
        budgets["max_memory_read_bytes"] = 4096
    elif operation == "memory.write":
        budgets.update(max_write_bytes=4096, max_private_recovery_bytes=65536)
    elif operation == "dump":
        budgets["max_dump_bytes"] = 512 * 1024 * 1024
    elif operation == "profile.etw":
        budgets["max_capture_seconds"] = 30
    return ToolDescriptor(
        tool_id="blackbox.deep." + operation, version=CONTRACT_VERSION,
        inputs=("ActionRequest/v1", "ProcessIdentity/PID+creation_FILETIME", "bounded operation parameters"),
        outputs=("legacy Deep result", "RunReceipt/v1", spec.output), operations=(operation,),
        required_rights=spec.required_rights, effects=spec.impact,
        budgets=budgets,
        resources=resources,
        cancellation={"supported": True, "method": spec.stop_method,
                      "cleanup": spec.cleanup,
                      "completion_is_not_rollback": True})


@dataclass(frozen=True)
class RunContext:
    run_id: str
    operation: str
    target: ProcessIdentity | None
    sources: tuple[dict[str, Any], ...]
    parameters: dict[str, Any]
    started_at_utc: str
    started_monotonic_ns: int
    deadline_utc: str
    deadline_monotonic_ns: int
    permissions: dict[str, Any]
    limits: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return journal_metadata(dict(self.__dict__, contract_version=CONTRACT_VERSION,
                                     target=self.target.to_dict() if self.target is not None else None,
                                     sources=list(self.sources),
                                     clock_scope="CALLING_PROCESS_MONOTONIC_NS"))


def begin_run(request: ActionRequest, *, run_id: str,
              permission_level: str = "STANDARD") -> RunContext:
    if not isinstance(request, ActionRequest):
        raise ValueError("TYPED_ACTION_REQUEST_REQUIRED")
    if (not isinstance(run_id, str) or not run_id or len(run_id) > 128
            or any(ord(character) < 32 for character in run_id)):
        raise ValueError("INVALID_DIAGNOSTIC_RUN_ID")
    # Keep the allowlist check here as well as in ActionRequest. Descriptor
    # discovery and receipts can never introduce arbitrary helper commands.
    operation = canonical_operation(request.operation)
    spec = DEEP_ACTIONS[operation]
    now = datetime.now(timezone.utc)
    monotonic = time.monotonic_ns()
    sources = []
    for key in ("path", "pe_path", "pdb_path", "index_path", "before_id", "after_id",
                "source_sha256", "process_instance"):
        if key in request.parameters:
            sources.append({"kind": key, "reference": journal_metadata(request.parameters[key]),
                            "verification": "RECHECK_BY_EXISTING_OPERATION"})
    if not sources:
        sources.append({"kind": "LOCAL_JOURNAL" if operation in _LOCAL else "LIVE_PROCESS",
                        "verification": "RECHECK_BY_EXISTING_OPERATION"})
    return RunContext(
        run_id=run_id, operation=operation, target=request.target, sources=tuple(sources),
        parameters=journal_metadata(request.parameters), started_at_utc=now.isoformat(),
        started_monotonic_ns=monotonic,
        deadline_utc=(now + timedelta(seconds=request.timeout_seconds)).isoformat(),
        deadline_monotonic_ns=monotonic + int(request.timeout_seconds * 1_000_000_000),
        permissions={"level_at_request": permission_level,
                     "confirmation_required": spec.confirmation_required,
                     "confirmation_provided": request.confirmed,
                     "scope": "THIS_EXACT_TARGET_OPERATION_AND_PARAMETERS",
                     "authorization": "SERVICE_AND_HELPER_RECHECK_REQUIRED"},
        limits={"timeout_seconds": request.timeout_seconds,
                "max_message_bytes": MAX_MESSAGE_BYTES})


@dataclass(frozen=True)
class RunReceipt:
    run_id: str
    operation: str
    tool_id: str
    started_at_utc: str
    ended_at_utc: str
    duration_ns: int
    status: str
    execution_started: bool | None
    source: dict[str, Any]
    target: dict[str, Any]
    result_references: tuple[dict[str, Any], ...]
    coverage: dict[str, Any]
    limitations: tuple[Any, ...]
    limits: dict[str, Any]
    cleanup: dict[str, Any]
    effects: str

    def to_dict(self) -> dict[str, Any]:
        return journal_metadata(dict(self.__dict__, contract_version=CONTRACT_VERSION,
                                     status_adapter=("WORKFLOW_LEGACY_STATUS_IDENTITY_V1" if
                                         self.operation in _WORKFLOW_OPERATIONS else
                                         "EVIDENCE_LEGACY_STATUS_IDENTITY_V1" if
                                         self.operation in _EVIDENCE_OPERATIONS else "DEEP_LEGACY_STATUS_IDENTITY_V1"),
                                     result_references=list(self.result_references),
                                     limitations=list(self.limitations),
                                     evidence_scope="LOCAL_DIAGNOSTIC_METADATA_NOT_AUTHENTICATED_PROVENANCE"))


def _cleanup_receipt(context: RunContext, answer: dict, cleanup: dict | None) -> dict:
    data = answer.get("data") if isinstance(answer.get("data"), dict) else {}
    if answer.get("status") == "RECOVERY_UNCONFIRMED" or data.get("owner_retained"):
        return {"status": "RECOVERY_UNCONFIRMED", "confirmed": False,
                "evidence": journal_metadata(cleanup) if cleanup else None,
                "scope": "OPERATION_AND_RETAINED_SESSION_RESOURCES"}
    if cleanup is not None:
        # An explicit ACK must say what was checked. COMPLETED alone is only
        # the operation status and is never manufactured into cleanup proof.
        confirmed = cleanup.get("confirmed") is True
        return {"status": "CONFIRMED" if confirmed else cleanup.get("status", "NOT_COLLECTED"),
                "confirmed": confirmed, "evidence": journal_metadata(cleanup),
                "scope": cleanup.get("scope", "OPERATION_OWNED_RESOURCES")}
    if data.get("cleanup") == "CONFIRMED":
        return {"status": "CONFIRMED", "confirmed": True,
                "scope": "OPERATION_OWNED_CAPTURE_AND_STAGING", "evidence": "HELPER_EXPLICIT_CLEANUP_ACK"}
    if (context.operation == "debug.detach" and answer.get("status") == "COMPLETED"
            and data.get("state") == "DETACHED" and data.get("owned_resources_remaining") == 0):
        return {"status": "CONFIRMED", "confirmed": True,
                "scope": "TARGET_BOUND_DEBUG_CONTEXT", "evidence": "HELPER_DETACHED_ZERO_OWNED_RESOURCES_ACK"}
    return {"status": "NOT_COLLECTED", "confirmed": False,
            "scope": "OPERATION_OWNED_RESOURCES", "reason": "NO_EXPLICIT_CLEANUP_ACKNOWLEDGEMENT"}


def attach_run_receipt(context: RunContext, answer: dict, *,
                       execution_started: bool | None = None,
                       source: str | None = None, source_verified: bool = False,
                       target_verified: bool = False, helper_pid: int | None = None,
                       cleanup: dict | None = None) -> dict:
    """Return the legacy result plus a bounded, redacted factual receipt.

    Call again after a journal failure: the new receipt must describe the final
    returned status, including the possibility of an already committed effect.
    Verification flags come from the actual service/helper execution path, never
    from a successful status, mock availability, or the selected GUI target.
    """
    if not isinstance(answer, dict):
        raise ValueError("INVALID_DIAGNOSTIC_RESULT")
    status = answer.get("status", "OPERATION_FAILED")
    data = answer.get("data") if isinstance(answer.get("data"), dict) else {}
    limitations = answer.get("limitations", [])
    if not isinstance(limitations, (list, tuple)):
        limitations = ["INVALID_LEGACY_LIMITATIONS"]
    references = [{"kind": "operation", "operation_id": answer.get("operation_id", context.run_id)}]
    journal = answer.get("journal")
    if isinstance(journal, dict) and journal.get("operation_id"):
        references.append({"kind": "journal", "operation_id": journal["operation_id"],
                           "record_sha256": journal.get("record_sha256"),
                           "verification": "LOCAL_CHANGE_DETECTION_ONLY"})
    for key in ("snapshot_id", "before_id", "after_id", "change_id", "breakpoint_id", "suspension_id"):
        if isinstance(data.get(key), str):
            references.append({"kind": key, "reference": data[key]})
    if context.operation in ("dump", "profile.etw") and data.get("destination"):
        references.append({"kind": "sensitive_artifact", "reference": "EXPLICIT_LOCAL_RESULT_DESTINATION",
                           "sha256": data.get("sha256"), "saved_verified": data.get("saved_verified") is True,
                           "automatic_share_export": False})
    if status in ("COMPLETED", "AVAILABLE"):
        completeness = "REPORTED_COMPLETE_FOR_REQUEST"
    elif status in ("INCOMPLETE_EVIDENCE", "LIMIT_REACHED"):
        completeness = "PARTIAL"
    elif execution_started is False or status in ("NOT_COLLECTED", "ADMIN_REQUIRED", "CONFIRMATION_REQUIRED"):
        completeness = "NOT_COLLECTED"
    else:
        completeness = "UNKNOWN"
    effectful = DEEP_ACTIONS[context.operation].mode == "INTERVENE" or context.operation in ("dump", "thread_stacks")
    effects = "READ_ONLY" if not effectful else (
        "NOT_STARTED" if execution_started is False else
        "REPORTED_COMPLETED" if status == "COMPLETED" else "MAY_HAVE_COMMITTED")
    receipt = RunReceipt(
        run_id=context.run_id, operation=context.operation,
        tool_id="blackbox.deep." + context.operation,
        started_at_utc=context.started_at_utc, ended_at_utc=datetime.now(timezone.utc).isoformat(),
        duration_ns=max(0, time.monotonic_ns() - context.started_monotonic_ns),
        status=status, execution_started=execution_started,
        source={"name": source or answer.get("source") or "NOT_COLLECTED",
                "verified": source_verified is True, "helper_pid": helper_pid,
                "verification_scope": "EXECUTION_PATH_ATTRIBUTION_NOT_AUTHENTICATED_PROVENANCE"},
        target={"identity": context.target.to_dict(), "verified": target_verified is True,
                "scope": "EXACT_PID_AND_CREATION_FILETIME" if target_verified else "REQUESTED_IDENTITY_ONLY"},
        result_references=tuple(references),
        coverage={"completeness": completeness, "scope": "REQUESTED_OPERATION_ONLY",
                  "reported_operation_status": data.get("reported_operation_status", status)},
        limitations=tuple(journal_metadata(list(limitations))), limits=context.limits,
        cleanup=_cleanup_receipt(context, answer, cleanup), effects=effects)
    return {**answer, "tool_descriptor": describe_tool(context.operation).to_dict(),
            "run_context": context.to_dict(), "run_receipt": receipt.to_dict()}


def begin_evidence_run(operation, *, run_id=None, sources=(), timeout_seconds=30,
                       target=None, parameters=None):
    """Use the existing contracts for three actual, read-only evidence paths.

    This descriptive list is not a Helper execution catalog. Deep ActionRequest
    still requires its exact live ProcessIdentity and unchanged authorization.
    No target is invented for an offline source that cannot establish one.
    """
    if type(operation) is not str or operation not in _EVIDENCE_OPERATIONS:
        raise ValueError("UNSUPPORTED_EVIDENCE_OPERATION")
    if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 600:
        raise ValueError("INVALID_EVIDENCE_OPERATION_TIMEOUT")
    run_id = uuid4().hex if run_id is None else run_id
    if (type(run_id) is not str or not 1 <= len(run_id) <= 128 or
            any(ord(c) < 32 for c in run_id)):
        raise ValueError("INVALID_DIAGNOSTIC_RUN_ID")
    if target is not None and not isinstance(target, ProcessIdentity):
        target = ProcessIdentity.from_dict(target)
    if (not isinstance(sources, (list, tuple)) or len(sources) > 64 or
            any(type(source) is not dict for source in sources) or
            parameters is not None and type(parameters) is not dict):
        raise ValueError("INVALID_EVIDENCE_RUN_METADATA")
    now, monotonic = datetime.now(timezone.utc), time.monotonic_ns()
    return RunContext(run_id, operation, target,
        tuple(journal_metadata(source) for source in sources),
        journal_metadata(parameters or {}), now.isoformat(), monotonic,
        (now + timedelta(seconds=timeout_seconds)).isoformat(),
        monotonic + int(timeout_seconds * 1_000_000_000),
        {"level_at_request": "READ_ONLY_LOCAL_EVIDENCE", "confirmation_required": False,
         "authorization": "NO_HELPER_OR_NATIVE_INTERVENTION_AUTHORITY"},
        {"timeout_seconds": timeout_seconds, "scope": "EXISTING_COMPONENT_BUDGET"})


def attach_evidence_run_receipt(context, answer, *, sources=(), coverage=None,
                                cleanup=None, source_revalidated=False, execution_started=None):
    """Attach factual R10 records without replacing a component's legacy status.

    COMPLETE describes neither original capture coverage nor producer identity.
    Only an explicitly supplied resource/readback acknowledgement confirms
    cleanup. Source revalidation means byte consistency, never authentication.
    """
    if (not isinstance(context, RunContext) or type(context.operation) is not str or
            context.operation not in _EVIDENCE_OPERATIONS or
            type(answer) is not dict or not isinstance(sources, (list, tuple)) or
            len(sources) > 64 or any(type(source) is not dict for source in sources) or
            coverage is not None and type(coverage) is not dict or
            cleanup is not None and type(cleanup) is not dict or
            execution_started is not None and type(execution_started) is not bool):
        raise ValueError("INVALID_EVIDENCE_RUN_RESULT")
    status = answer.get("status", "UNKNOWN")
    descriptor = ToolDescriptor("blackbox." + context.operation, CONTRACT_VERSION,
        ("existing local evidence inputs",), ("legacy result", "RunReceipt/v1"),
        (context.operation,), "READ_ONLY_LOCAL_FILES", "NO_NATIVE_INTERVENTION",
        context.limits, ("operation-owned file handles and private staging",),
        {"supported": True, "method": "EXISTING_COMPONENT_CANCEL_AND_DEADLINE",
         "cleanup": "ACKNOWLEDGED_BY_COMPONENT", "completion_is_not_rollback": True})
    sources = tuple(journal_metadata(source) for source in (sources or context.sources))
    coverage = journal_metadata(coverage or {"completeness": "UNKNOWN", "scope": "AVAILABLE_SOURCE_RECORDS"})
    cleanup = journal_metadata(cleanup or {"status": "NOT_COLLECTED", "confirmed": False})
    if cleanup.get("confirmed") is not True:
        cleanup["confirmed"] = False
    references = []
    for key in ("case_id", "input_sha256", "sha256"):
        if isinstance(answer.get(key), str):
            references.append({"kind": key, "reference": answer[key]})
    limitations = answer.get("limitations", [])
    if not isinstance(limitations, (list, tuple)):
        limitations = ["INVALID_LEGACY_LIMITATIONS"]
    receipt = RunReceipt(context.run_id, context.operation, descriptor.tool_id,
        context.started_at_utc, datetime.now(timezone.utc).isoformat(),
        max(0, time.monotonic_ns() - context.started_monotonic_ns), status, execution_started,
        {"name": "LOCAL_EVIDENCE_COMPONENT", "verified": source_revalidated is True,
         "verification_scope": "BYTE_CONSISTENCY_ONLY_NOT_PRODUCER_AUTHENTICATION",
         "sources": list(sources), "producer_authentication": "NOT_ESTABLISHED"},
        {"identity": context.target.to_dict() if context.target is not None else None,
         "verified": False, "scope": "RECORDED_IDENTITY_NOT_LIVE_BINDING"},
        tuple(references), coverage, tuple(journal_metadata(list(limitations))),
        context.limits, cleanup, "READ_ONLY_SOURCE; CREATE_NEW_RESULT_ONLY")
    return {**answer, "tool_descriptor": descriptor.to_dict(),
            "run_context": context.to_dict(), "run_receipt": receipt.to_dict()}


def record_evidence_failure(context, error, *, sources=()):
    """Add metadata to the original exception; preserve its type and traceback."""
    uncertain = (getattr(error, "cleanup_unconfirmed", False) or
                 getattr(error, "cleanup_required", False) or getattr(error, "publication_unconfirmed", False) or
                 getattr(getattr(error, "owner", None), "cleanup_required", False))
    legacy = getattr(error, "status", None)
    status = ("RECOVERY_UNCONFIRMED" if uncertain else
              legacy if type(legacy) is str and legacy in {"CANCELLED", "TIMED_OUT", "RECOVERY_UNCONFIRMED", "PROCESS_CHANGED",
                  "ACCESS_DENIED", "NOT_COLLECTED", "INCOMPLETE_EVIDENCE", "OPERATION_FAILED"} else
              "CANCELLED" if isinstance(error, InterruptedError) else
              "TIMED_OUT" if isinstance(error, TimeoutError) else "OPERATION_FAILED")
    result = attach_evidence_run_receipt(context, {"status": status,
        "limitations": ["FAILED_READ_ONLY_EVIDENCE_RUN", "CLEANUP_NOT_INFERRED_FROM_EXCEPTION"]},
        sources=sources, coverage={"completeness": "UNKNOWN", "scope": "FAILED_OPERATION"})
    error.run_receipt = result["run_receipt"]
    error.run_context = result["run_context"]
