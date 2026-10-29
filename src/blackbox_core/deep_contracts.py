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

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__, failure_action="Report the actual Windows status; preserve ordinary observation.",
                    output="Typed result and append-only diagnostic journal entry.")


def _spec(name: str, mode: str = "INSPECT", confirmation: bool = False,
          impact: str = "Read-only observation; source may change during collection.",
          rights: str = "Operation-specific process query/read rights.",
          timeout: float = 15.0) -> ActionSpec:
    return ActionSpec(name, mode, confirmation, impact, rights, timeout)


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
    if parameters.get("profile") != "GeneralProfile.Light":
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
