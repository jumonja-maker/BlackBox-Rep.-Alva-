"""Bounded, deterministic contracts for the read-only Investigation Engine 3."""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import math
import time

SCHEMA = "blackbox.investigation-graph/1"
ALGORITHM_VERSION = "3.0.0"
RELATION_TYPES = frozenset({"EXACT_IDENTITY", "DIRECT_REFERENCE", "BOUNDED_TIME_CORRELATION",
    "OBSERVED_DEPENDENCY", "TEMPORAL_COINCIDENCE", "HYPOTHESIS_ONLY", "NOT_ESTABLISHED", "CONTRADICTED"})
OBSERVATION_TYPES = frozenset({"PROCESS", "THREAD", "MODULE", "FUNCTION", "STACK", "CPU_SAMPLE",
    "WAIT_INTERVAL", "SCHEDULER_EVENT", "FILE_OPERATION", "NETWORK_OPERATION", "DISK_COMPLETION",
    "INCIDENT", "ERROR", "USER_ACTION", "DIAGNOSTIC_ACTION", "MEASUREMENT", "ARTIFACT", "COVERAGE", "ANNOTATION"})
HYPOTHESIS_STATUSES = frozenset({"CANDIDATE", "SUPPORTED_BY_OBSERVATION",
    "SUPPORTED_BY_CONTROLLED_EXPERIMENT", "CONTRADICTED", "INCONCLUSIVE", "USER_CONFIRMED"})
SOURCE_TYPES = frozenset({"SESSION", "TRACE_INDEX", "DEEP_JOURNAL", "INVESTIGATION_V2", "EVENTS_JSONL", "DUMP_METADATA"})


class InvestigationError(ValueError):
    pass


def canonical_json(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))


def stable_id(kind, *parts):
    return hashlib.sha256(canonical_json([ALGORITHM_VERSION, kind, *parts]).encode("ascii")).hexdigest()


def finite_number(value):
    return type(value) in (int, float) and abs(value) < 2**63 and math.isfinite(value)


@dataclass
class InvestigationBudget:
    max_events: int = 250_000
    max_nodes: int = 10_000
    max_edges: int = 20_000
    max_result_bytes: int = 32 * 1024**2
    max_source_bytes: int = 4 * 1024**3
    timeout_seconds: float = 30
    cancel_event: object = None
    deadline: float | None = None

    def __post_init__(self):
        for key, low, high in (("max_events", 1, 250_000), ("max_nodes", 1, 10_000),
                ("max_edges", 1, 20_000), ("max_result_bytes", 1024, 64 * 1024**2),
                ("max_source_bytes", 1024, 16 * 1024**3)):
            if type(getattr(self, key)) is not int or not low <= getattr(self, key) <= high:
                raise InvestigationError("INVALID_INVESTIGATION_BUDGET_" + key.upper())
        if not finite_number(self.timeout_seconds) or not 0 < self.timeout_seconds <= 300:
            raise InvestigationError("INVALID_INVESTIGATION_TIMEOUT")
        now = time.monotonic()
        if self.deadline is not None and (not finite_number(self.deadline) or self.deadline <= 0):
            raise InvestigationError("INVALID_INVESTIGATION_DEADLINE")
        self.deadline = min(self.deadline, now + self.timeout_seconds) if self.deadline is not None else now + self.timeout_seconds

    def check(self):
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise InterruptedError("INVESTIGATION_CANCELLED")
        if time.monotonic() >= self.deadline:
            raise TimeoutError("INVESTIGATION_DEADLINE")

    def is_set(self):
        """Cancellation adapter for existing readers, retaining the outer deadline."""
        self.check()
        return False

    def result(self, value):
        self.check()
        if len(canonical_json(value).encode("ascii")) > self.max_result_bytes:
            raise InvestigationError("INVESTIGATION_RESULT_BYTE_BUDGET")
        return value


def use_budget(budget=None, *, cancel_event=None):
    if budget is None:
        return InvestigationBudget(cancel_event=cancel_event)
    if isinstance(budget, dict):
        return InvestigationBudget(**{**budget, **({"cancel_event": cancel_event} if cancel_event is not None else {})})
    if not isinstance(budget, InvestigationBudget):
        raise InvestigationError("INVALID_INVESTIGATION_BUDGET")
    budget.check()
    if cancel_event is not None and cancel_event is not budget.cancel_event:
        original = budget.cancel_event
        class CombinedCancellation:
            def is_set(self):
                return bool((original is not None and original.is_set()) or cancel_event.is_set())
        budget = replace(budget, cancel_event=CombinedCancellation())
        budget.check()
    return budget


def evidence_node(source, record_id, observation_type, *, metadata=None, process_identity=None,
                  thread_identity=None, time_domain="UNKNOWN", time_bounds=None,
                  verification_class="UNVERIFIED_IMPORT", completeness_status="INCOMPLETE_EVIDENCE", subtype=""):
    if observation_type not in OBSERVATION_TYPES:
        raise InvestigationError("INVALID_EVIDENCE_OBSERVATION_TYPE")
    identifier = source["source_id"]
    return {"node_id": stable_id("node", identifier, str(record_id), observation_type, subtype),
        "source_type": source["source_type"], "source_identity": identifier,
        "source_record_id": str(record_id), "source_sha256": source["source_sha256"],
        "process_identity": process_identity, "thread_identity": thread_identity,
        "time_domain": time_domain, "time_bounds": time_bounds,
        "observation_type": observation_type, "verification_class": verification_class,
        "completeness_status": completeness_status, "metadata": metadata or {}}


def evidence_edge(first, second, relation_type, *, relation="RELATED", evidence_refs=None,
                  verification_class="DERIVED", time_uncertainty=None, limitations=None):
    if relation_type not in RELATION_TYPES:
        raise InvestigationError("INVALID_EVIDENCE_RELATION")
    refs = sorted(set(evidence_refs or [first, second]))
    return {"edge_id": stable_id("edge", first, second, relation_type, relation, refs),
        "from_node": first, "to_node": second, "relation_type": relation_type, "relation": relation,
        "evidence_refs": refs, "verification_class": verification_class,
        "time_uncertainty": time_uncertainty, "limitations": list(limitations or [])}
