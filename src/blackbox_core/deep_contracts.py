"""Typed, bounded BB-DEEP-001 commands shared by GUI and diagnostic helper.

This module is platform independent. It describes permissions; it never grants
them. The helper repeats validation before invoking a Windows operation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
from typing import Any

MAX_MESSAGE_BYTES = 2 * 1024 * 1024
MAX_MEMORY_BYTES = 64 * 1024
MAX_SESSION_SECONDS = 900
MAX_OPERATION_SECONDS = 120

STATUSES = frozenset({
    "AVAILABLE", "ADMIN_REQUIRED", "UAC_CANCELLED", "ACCESS_DENIED",
    "PROTECTED_PROCESS", "PROCESS_CHANGED", "ALREADY_DEBUGGED",
    "OPERATION_FAILED", "INCOMPLETE_EVIDENCE", "COMPLETED",
    "RECOVERY_UNCONFIRMED", "CANCELLED", "TIMED_OUT", "UNSUPPORTED_PLATFORM",
    "CONFIRMATION_REQUIRED", "SESSION_EXPIRED", "NOT_COLLECTED",
    "LIMIT_REACHED",
})


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    created_100ns: int
    image_path: str = ""

    def __post_init__(self) -> None:
        if type(self.pid) is not int or not 0 < self.pid <= 0xFFFFFFFF:
            raise ValueError("INVALID_PROCESS_PID")
        if type(self.created_100ns) is not int or not 0 < self.created_100ns < 2**64:
            raise ValueError("INVALID_PROCESS_CREATION_TIME")
        if not isinstance(self.image_path, str) or len(self.image_path) > 32768 or "\0" in self.image_path:
            raise ValueError("INVALID_PROCESS_IMAGE")

    def to_dict(self) -> dict[str, Any]:
        return {"pid": self.pid, "created_100ns": self.created_100ns,
                "image_path": self.image_path}

    @classmethod
    def from_dict(cls, value: dict[str, Any] | ProcessIdentity) -> ProcessIdentity:
        if isinstance(value, cls):
            return value
        if not isinstance(value, dict) or set(value) - {"pid", "created_100ns", "image_path"}:
            raise ValueError("INVALID_PROCESS_IDENTITY")
        return cls(value["pid"], value["created_100ns"], value.get("image_path", ""))


@dataclass(frozen=True)
class ActionSpec:
    operation: str
    mode: str
    confirmation_required: bool
    impact: str
    required_rights: str
    timeout_seconds: float = 15.0
    cleanup: str = "Close owned process handles; preserve collected evidence."
    preconditions: tuple[str, ...] = ()
    stop_method: str = "Set the request cancellation event; wait for its bounded cleanup result."
    failure_action: str = "Report the actual status and preserve ordinary observation."
    output: str = "Typed result and diagnostic journal operation_id."

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__, preconditions=list(self.preconditions),
                    authority="DESCRIPTIVE_ONLY_SERVICE_AND_HELPER_RECHECK_AUTHORIZATION")


_LIVE_PRECONDITIONS = (
    "Valid bounded request; exact target PID, process creation FILETIME and selected image identity are rechecked.",
    "Operation is within the live helper session scope and its actual Windows access rights.",
)
_DEBUG_CLEANUP = (
    "Request debug.detach or InspectorService.end_admin_session(): verify owned breakpoint bytes and RIP/TF restoration, "
    "restore recorded memory where comparison permits, decrement only owned suspensions, continue held events and detach. "
    "Preserve RECOVERY_UNCONFIRMED whenever restoration or detachment is not verified."
)
_DEBUG_STOP = (
    "Set cancel_event for the active request; to end retained debug state, explicitly request debug.detach or "
    "InspectorService.end_admin_session(). Review cleanup and guardian evidence before another intervention."
)


def _scenario_contract(name: str, mode: str) -> dict[str, Any]:
    """Discovery metadata for future scenario editors, never executable policy."""
    contract = dict(preconditions=_LIVE_PRECONDITIONS,
                    stop_method="Set cancel_event; the request deadline bounds collection and helper cancellation grace.",
                    cleanup="Close owned query handles and temporary resources; preserve collected evidence.",
                    output="Typed observation data, source, limitations and diagnostic journal operation_id.",
                    failure_action="Report the actual status; preserve ordinary observation and any RECOVERY_UNCONFIRMED result.")
    if mode == "INTERVENE":
        contract["preconditions"] += ("Explicit confirmation of this target, action parameters and impact; durable journal intent before effects.",)
        contract["failure_action"] += " Never automatically retry memory writes, breakpoints or other effects after an uncertain result."
    extra = ()
    if name.startswith("debug."):
        contract.update(stop_method=_DEBUG_STOP, cleanup=_DEBUG_CLEANUP)
        if name == "debug.attach":
            extra = ("New attachment requires no competing debugger; an already-owned attachment is idempotent.",
                     "Guardian accepts recovery intent before DebugActiveProcess; KillOnExit=False must be established after attachment.")
            contract["output"] = "Debug lifecycle state, attachment/paused-event state, before/after observations and operation_id."
        elif name == "debug.pause":
            extra = ("ATTACHED session; an already-held PAUSED event needs no second debug break.",)
            contract["output"] = "PAUSED debug-event state, event thread identity and operation_id."
        elif name in ("debug.continue", "debug.step"):
            extra = ("ATTACHED session with a held PAUSED or PAUSED_EXCEPTION debug event.",
                     "An owned breakpoint's instruction-pointer rewind must be verified before continuation.")
            contract["output"] = ("RUNNING state after continuation, or the next held stop after step; before/after state and operation_id. "
                                  "Executed application instructions are not reversible.")
        elif name == "debug.context":
            extra = ("Held PAUSED debug event; requested TID must be that event's thread, with creation FILETIME checked when supplied.",)
            contract["output"] = "Saved live-event registers, stopped_tid, thread_created_100ns, lifecycle state and operation_id."
        elif name == "debug.breakpoints":
            extra = ("Read only this session's breakpoint ledger; the list does not establish attachment or a current stop.",)
            contract["output"] = "Owned breakpoint_id, address, enabled and installed fields for subsequent explicit operations."
        elif name == "debug.breakpoint.add":
            extra = ("ATTACHED session with a held PAUSED debug event; bounded executable address not already owned or an existing foreign INT3.",
                     "Original byte/protection are readable and recovery intent is acknowledged before patching.")
            contract["output"] = "breakpoint_id, address, enabled flag, before/after code hashes and operation_id."
        elif name in ("debug.breakpoint.disable", "debug.breakpoint.remove"):
            extra = ("ATTACHED session with a held PAUSED debug event and an existing owned breakpoint_id.",
                     "Any recorded hit context and original code byte/protection must be restorable and verifiable.")
            contract["output"] = "breakpoint_id, enabled=False, removed flag and original_byte_verified; an unresolved restore stays explicit."
        elif name == "debug.detach":
            extra = ("Operate only on this session's attachment, pending events and recovery ledger; detachment is also the cleanup entry point.",)
            contract["output"] = "DETACHED or RECOVERY_UNCONFIRMED state, remaining owned resources, cleanup errors and operation_id."
    elif name in ("thread.suspend", "thread.resume"):
        contract.update(stop_method=_DEBUG_STOP, cleanup=_DEBUG_CLEANUP)
        if name == "thread.suspend":
            extra = ("Exact TID and thread_created_100ns belong to the selected process instance; no duplicate owned suspension.",
                     "Guardian acknowledges the pending increment before SuspendThread.")
            contract["output"] = "suspension_id, exact thread identity, previous_suspend_count and owned_increment=1."
        else:
            extra = ("Active owned suspension_id, or exact TID plus thread_created_100ns matching that session's suspension ledger.",)
            contract["output"] = "suspension_id, owned_decrement=1 and remaining observed count; unrelated suspend counts are preserved."
    elif name in ("memory.write", "memory.rollback"):
        contract.update(stop_method=_DEBUG_STOP, cleanup=_DEBUG_CLEANUP)
        if name == "memory.write":
            extra = ("Bounded address with equal-length expected_hex/value_hex; original read must equal expected_hex.",
                     "No overlap with an unrestored owned change or breakpoint; private recovery budget and guardian acknowledgement are available.")
            contract["output"] = "change_id, address, size, before/after hashes and readback_verified; original bytes stay private."
        else:
            extra = ("Existing owned change_id; current bytes must match the recorded replacement before restoring original bytes.",)
            contract["output"] = "change_id and original_bytes_verified after readback; restoring bytes does not reverse application side effects."
    elif name == "thread_stacks":
        extra = ("Explicit snapshot-impact confirmation; selected thread creation FILETIME is checked when filtering by TID.",)
        contract["cleanup"] = "Release PSS clone/snapshot and DbgHelp resources; report RECOVERY_UNCONFIRMED if PssFreeSnapshot fails."
        contract["output"] = "Current snapshot thread frames, addresses and verified local symbol/module evidence, distinct from historical ETW stacks."
    elif name == "dump":
        extra = ("Explicit sensitive-dump confirmation, supported completeness/size limits and an empty ordinary-GUI-created file HANDLE.",)
        contract["stop_method"] = "Set cancel_event; MiniDumpWriteDump callbacks check cancellation/deadline and write budget."
        contract["cleanup"] = "Close the borrowed output duplicate and process handles; retain any partial file with its incomplete status, excluded from automatic sharing."
        contract["output"] = "Explicit destination, verified minidump signature/size/completeness flags and operation_id; no automatic share inclusion."
    elif name == "profile.etw":
        extra = ("Verified administrator helper token; fixed GeneralProfile.Light+FileIO.Light policy, duration_seconds 1–30 and explicit systemwide_confirmed consent.",
                 "Empty ordinary-GUI-created output HANDLE and protected administrator-owned staging directory.")
        contract["stop_method"] = "Set cancel_event or close the owner lease; the finite guardian stops only its named WPR session, never global capture."
        contract["cleanup"] = "Wait for named capture stop and protected staging removal; retain RECOVERY_UNCONFIRMED for unresolved owner or staging cleanup."
        contract["output"] = "Named capture instance, destination, trace_bytes, SHA-256 and saved_verified after copy/readback, plus explicit cleanup status."
    elif name in ("timeline", "compare", "trace_evidence", "dump_inspect", "dump_read_memory", "symbols_verify"):
        contract["preconditions"] = ("Valid bounded local request; no helper elevation and no live-process access implied.",)
        contract["stop_method"] = "Set cancel_event; local readers stop at cancellation/deadline checkpoints, while bounded journal queries complete within storage timeouts."
        contract["cleanup"] = "Close local read-only inputs and preserve source files unchanged."
        if name == "timeline":
            extra = ("Readable local evidence journal and bounded entry limit.",)
            contract["output"] = "Ordered diagnostic journal entries and operation_id; imported payloads and memory remain excluded."
        elif name == "compare":
            extra = ("Existing before_id and after_id snapshots with identical exact process identity matching the selected target.",)
            contract["output"] = "before_id, after_id, immutable before/after data and changed_sections; observed differences are not causal proof."
        elif name == "trace_evidence":
            extra = ("Readable trace index; explicit recorded process_instance for history selection and matching source hash when supplied.",)
            contract["output"] = "Recorded instance candidates or filtered historical events/stacks/waits/I/O; live-target relation remains separately qualified."
        elif name in ("dump_inspect", "dump_read_memory"):
            extra = ("Readable bounded minidump with stable source identity; saved memory reads additionally require a captured address range and bounded size.",)
            contract["output"] = "Saved dump metadata or explicitly selected captured bytes; neither claims current process state or complete heap analysis."
        else:
            extra = ("Explicit local PE/PDB files; bounded parsing and actual debug identity agreement are required before symbol claims.",)
            contract["output"] = "PE/PDB identity match status and available local symbol/RVA details, with unsupported cases explicit."
    elif name == "snapshot":
        contract["output"] = "snapshot_id and retained sequential section observations for compare; not an atomic process snapshot."
    elif name == "memory_read":
        extra = ("Readable bounded address range and size; unavailable bytes remain incomplete evidence.",)
        contract["output"] = "Explicitly requested memory bytes and read status; payload is omitted from the ordinary journal/share export."
    elif name == "wait_chains":
        extra = ("Selected TID creation FILETIME is checked when supplied; WCT availability and completeness remain explicit.",)
        contract["output"] = "Observed WCT nodes, cycle indication and limitations; no causal diagnosis from missing chains."
    elif name == "capabilities":
        contract["output"] = "Per-operation actual access status and descriptive ActionSpec; availability does not authorize a later action."
    contract["preconditions"] += extra
    return contract


def _spec(name: str, mode: str = "INSPECT", confirmation: bool = False,
          impact: str = "Read-only observation; source may change during collection.",
          rights: str = "Operation-specific process query/read rights.",
          timeout: float = 15.0) -> ActionSpec:
    return ActionSpec(name, mode, confirmation, impact, rights, timeout, **_scenario_contract(name, mode))


DEEP_ACTIONS = {s.operation: s for s in (
    *(_spec(n) for n in ("processes", "modules", "threads", "handles", "memory_map",
                         "memory_read", "wait_chains", "network", "disk", "snapshot")),
    _spec("thread_stacks", confirmation=True,
          impact="Windows process snapshot may briefly pause the target while capturing; no persistent owned thread suspension.",
          rights="Process snapshot clone, duplicate-handle, query and memory-read rights."),
    _spec("dump", confirmation=True, timeout=120,
          impact="Creates a sensitive diagnostic dump in the explicitly selected file; may briefly stop the target.",
          rights="Process query/read/duplicate-handle rights; explicit ordinary-user file handle."),
    _spec("profile.etw", mode="INTERVENE", confirmation=True, timeout=120,
          impact="Records system-wide ETW metadata for 1–30 seconds, including other processes; adds tracing overhead.",
          rights="Administrator helper token; a scoped owned WPR session and ordinary-user output file handle."),
    _spec("timeline", "OBSERVE"), _spec("compare", "OBSERVE"),
    _spec("capabilities", "OBSERVE"),
    _spec("trace_evidence", "OBSERVE"), _spec("dump_inspect", "OBSERVE"),
    _spec("dump_read_memory", "INSPECT"), _spec("symbols_verify", "OBSERVE"),
    *(_spec(n, "INTERVENE", True, "Changes target execution state; cleanup may remain unconfirmed.",
            "Windows Debug API or exact-thread context/suspend rights.", 30)
      for n in ("debug.attach", "debug.pause", "debug.continue", "debug.step", "debug.detach",
                "debug.breakpoint.add", "debug.breakpoint.disable", "debug.breakpoint.remove",
                "thread.suspend", "thread.resume")),
    _spec("debug.context", "INSPECT"), _spec("debug.breakpoints", "INSPECT"),
    _spec("memory.write", "INTERVENE", True,
          "Writes explicitly selected bytes after comparing the expected original bytes. Full rollback is not guaranteed.",
          "PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ."),
    _spec("memory.rollback", "INTERVENE", True,
          "Attempts to restore only the recorded bytes after checking current state; result must be read back.",
          "PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ."),
)}

ALIASES = {
    "debug_attach": "debug.attach", "debug_pause": "debug.pause",
    "debug_continue": "debug.continue", "debug_step": "debug.step",
    "debug_context": "debug.context", "debug_detach": "debug.detach",
    "breakpoint_add": "debug.breakpoint.add", "breakpoint_disable": "debug.breakpoint.disable",
    "breakpoint_remove": "debug.breakpoint.remove", "thread_suspend": "thread.suspend",
    "thread_resume": "thread.resume", "memory_write": "memory.write",
    "memory_restore": "memory.rollback", "stacks": "thread_stacks", "waits": "wait_chains",
}


def canonical_operation(operation: str) -> str:
    if not isinstance(operation, str):
        raise ValueError("INVALID_OPERATION")
    if operation.startswith("inspect."):
        operation = operation[8:]
    operation = ALIASES.get(operation, operation)
    if operation not in DEEP_ACTIONS:
        raise ValueError("OPERATION_NOT_ALLOWED")
    return operation


def bounded_json(value: Any) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError("DIAGNOSTIC_MESSAGE_BUDGET_EXCEEDED")
    return raw


def validate_profile_parameters(parameters: dict[str, Any], *, allow_destination: bool = False) -> None:
    """One fixed WPR policy, never a command line or provider expression."""
    permitted = {"duration_seconds", "profile", "systemwide_confirmed"}
    if allow_destination:
        permitted.update({"destination", "output_path", "path"})
    if set(parameters) - permitted:
        raise ValueError("UNSUPPORTED_PROFILE_PARAMETER")
    duration = parameters.get("duration_seconds")
    if type(duration) is not int or not 1 <= duration <= 30:
        raise ValueError("INVALID_PROFILE_DURATION")
    if parameters.get("profile") != "GeneralProfile.Light+FileIO.Light":
        raise ValueError("PROFILE_NOT_ALLOWED")
    if parameters.get("systemwide_confirmed") is not True:
        raise ValueError("EXPLICIT_SYSTEMWIDE_PROFILE_CONSENT_REQUIRED")
    if allow_destination:
        destinations = [key for key in ("destination", "output_path", "path") if key in parameters]
        if len(destinations) > 1:
            raise ValueError("AMBIGUOUS_PROFILE_DESTINATION")
        if destinations:
            value = parameters[destinations[0]]
            if not isinstance(value, str) or not value or "\0" in value or len(value) > 32768:
                raise ValueError("INVALID_PROFILE_DESTINATION")


@dataclass(frozen=True)
class ActionRequest:
    operation: str
    target: ProcessIdentity
    parameters: dict[str, Any] = field(default_factory=dict)
    confirmed: bool = False
    timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation", canonical_operation(self.operation))
        object.__setattr__(self, "target", ProcessIdentity.from_dict(self.target))
        if not isinstance(self.parameters, dict) or any(not isinstance(k, str) or k.startswith("_") for k in self.parameters):
            raise ValueError("INVALID_ACTION_PARAMETERS")
        if type(self.confirmed) is not bool:
            raise ValueError("INVALID_CONFIRMATION")
        if (type(self.timeout_seconds) not in (int, float) or not math.isfinite(self.timeout_seconds)
                or not 0.1 <= self.timeout_seconds <= MAX_OPERATION_SECONDS):
            raise ValueError("INVALID_ACTION_DEADLINE")
        if self.operation == "profile.etw":
            validate_profile_parameters(self.parameters, allow_destination=True)
        bounded_json(self.parameters)

    def to_dict(self) -> dict[str, Any]:
        return {"operation": self.operation, "target": self.target.to_dict(),
                "parameters": self.parameters, "confirmed": self.confirmed,
                "timeout_seconds": self.timeout_seconds}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ActionRequest:
        if not isinstance(value, dict) or set(value) - {"operation", "target", "parameters", "confirmed", "timeout_seconds"}:
            raise ValueError("INVALID_ACTION_REQUEST")
        return cls(value["operation"], ProcessIdentity.from_dict(value["target"]),
                   value.get("parameters", {}), value.get("confirmed", False),
                   value.get("timeout_seconds", 15.0))


def describe_actions() -> list[dict[str, Any]]:
    return [s.to_dict() for s in DEEP_ACTIONS.values()]


def result(operation: str, status: str, *, data: Any = None, error: str | None = None,
           limitations: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    if status not in STATUSES:
        status = "OPERATION_FAILED"
    return {"operation": operation, "status": status, "data": {} if data is None else data,
            "error": error, "limitations": limitations or [], **extra}
