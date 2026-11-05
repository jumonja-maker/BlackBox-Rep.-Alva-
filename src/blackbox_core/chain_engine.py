"""Finite, evidence preserving workflow scheduler, independent of Qt.

Only an explicit run/resume dispatches tools. A receipt describes an invocation;
neither a saved receipt nor a completed graph establishes a diagnosis or consent.
"""
from __future__ import annotations

from collections import deque
from concurrent.futures import Future
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
import queue
import threading
import time
from uuid import uuid4

from .chain_contracts import (Artifact, NodeOutcome, RUN_SCHEMA, TERMINAL,
    WorkflowDefinition, WorkflowError, canonical, require)
from .chain_io import verify_artifact, owned_output_bytes
from .chain_validation import evaluate_condition, get_ports, validate_parameters, validate_workflow


class _Cancellation:
    """Cooperative cancellation also wakes deadline-aware component waits."""
    def __init__(self, parent, deadline):
        self.parent, self.deadline = parent, deadline
        self.local = threading.Event()

    def is_set(self):
        return self.local.is_set() or self.parent.is_set() or time.monotonic() >= self.deadline

    def wait(self, timeout=None):
        end = self.deadline if timeout is None else min(self.deadline, time.monotonic() + max(0, timeout))
        while not self.is_set():
            remaining = end - time.monotonic()
            if remaining <= 0:
                return self.is_set()
            self.parent.wait(min(.05, remaining))
        return True

    def set(self):
        self.local.set()


class _Workers:
    """Bounded daemon workers; an unresponsive owner is retained, never killed."""
    def __init__(self, count):
        self.tasks = queue.Queue(maxsize=count)
        self.threads = []
        for ordinal in range(count):
            thread = threading.Thread(target=self._work, name="blackbox-chain-" + str(ordinal), daemon=True)
            thread.start()
            self.threads.append(thread)

    def _work(self):
        while True:
            item = self.tasks.get()
            if item is None:
                return
            future, call = item
            if future.set_running_or_notify_cancel():
                try:
                    future.set_result(call())
                except BaseException as error:
                    future.set_exception(error)

    def submit(self, call):
        future = Future()
        self.tasks.put_nowait((future, call))
        return future

    def close(self):
        for _ in self.threads:
            self.tasks.put(None)
        for thread in self.threads:
            thread.join(timeout=.2)
        return not any(thread.is_alive() for thread in self.threads)


_LEASE_LOCK = threading.RLock()
_LEASES = {}  # exact run owner, active invocation, retained state; never persisted authority
_RETAINED_WORKERS = {}


@dataclass
class ExecutionContext:
    run_id: str
    node_id: str
    node_run_id: str
    iteration: int
    output_dir: Path
    deadline: float
    cancel: _Cancellation
    runtime: object
    _engine: object
    component_dispatch_started: bool = False

    def remaining_seconds(self):
        return max(0, self.deadline - time.monotonic())

    def check(self):
        if self.cancel.parent.is_set() or self.cancel.local.is_set():
            raise InterruptedError("WORKFLOW_CANCELLED")
        if time.monotonic() >= self.deadline:
            raise TimeoutError("WORKFLOW_NODE_DEADLINE")

    def emit(self, phase, details=None):
        self._engine._context_event(self, phase, details)

    def waiting_for_human(self, details=None):
        self.emit("WAITING_FOR_HUMAN", details)

    def running(self):
        self.check()
        self.emit("RUNNING")


def _state(status):
    if status in ("RECOVERY_UNCONFIRMED", "FINALIZATION_UNCONFIRMED", "CLEANUP_UNCONFIRMED"):
        return "RECOVERY_UNCONFIRMED"
    if status in ("CANCELLED", "TIMED_OUT", "TIMEOUT"):
        return "CANCELLED" if status == "CANCELLED" else "FAILED"
    if status in ("PARTIAL", "PARTIAL_EVIDENCE", "INCOMPLETE_EVIDENCE", "NOT_ESTABLISHED", "CONTRADICTED",
                  "NO_COMPLETE_INTERVALS", "NO_SCHEDULER_EVENTS", "REDECODE_REQUIRED"):
        return "PARTIAL"
    if status in ("COMPLETED", "STOPPED", "CLOSED", "READY", "OBSERVED_INTERVALS", "OBSERVED_OPERATIONS",
                  "OBSERVED_REQUESTS", "NO_FILE_IO_EVENTS", "NO_DISK_REQUEST_EVENTS"):
        return "COMPLETED"
    return "FAILED"


def _known_owner(cleanup):
    evidence = cleanup.get("evidence")
    return cleanup.get("ownership_known") is True or (type(evidence) is dict and evidence.get("ownership_known") is True)


class WorkflowEngine:
    def __init__(self, definition, *, catalog, store, runtime=None):
        self.definition = WorkflowDefinition.from_dict(definition.to_dict())
        require(store.definition.fingerprint == self.definition.fingerprint, "WORKFLOW_STORE_DEFINITION_MISMATCH")
        self.catalog, self.store, self.runtime = dict(catalog), store, runtime
        self._cancel, self._pause = threading.Event(), threading.Event()
        self._lock = threading.RLock()
        self._driving = False
        self._callback = None
        self._last_emit = 0
        self._errors = []
        self._state = "QUEUED"
        self._elapsed = 0.0
        self._started = None
        self._cleanup = {"status": "NOT_STARTED", "confirmed": False, "scope": "WORKFLOW_OWNED_RESOURCES"}
        self._records = {node.node_id: self._empty(node) for node in self.definition.nodes}
        self._incoming = {node.node_id: [] for node in self.definition.nodes}
        for edge in self.definition.edges:
            self._incoming[edge.target_node].append(edge)
        self._not_before = {}
        self._checkpoint = None
        self._cancel_at = None

    @staticmethod
    def _empty(node):
        return {"node_id": node.node_id, "tool_id": node.tool_id, "kind": node.kind,
            "state": "QUEUED", "iterations_completed": 0, "total_iterations": node.repeat_count,
            "outputs": {}, "run_receipt": None, "run_context": None, "tool_descriptor": None,
            "cleanup": {"status": "NOT_STARTED", "confirmed": False}, "component_status": None,
            "attempts": []}

    @classmethod
    def restore(cls, store, *, catalog, runtime=None):
        engine = cls(store.definition, catalog=catalog, store=store, runtime=runtime)
        saved = store.load_state()
        engine._state = saved.get("state", "QUEUED")
        engine._elapsed = saved.get("elapsed_seconds", 0) or 0
        engine._cleanup = saved.get("cleanup", engine._cleanup)
        engine._errors = saved.get("errors", [])
        for row in saved.get("nodes", []):
            if row.get("node_id") in engine._records:
                engine._records[row["node_id"]].update(deepcopy(row))
        intents, results = {}, set()
        for event in store.read_events():
            data = event.get("data", {})
            if event.get("event") == "node.intent":
                intents[data["node_run_id"]] = data
            elif event.get("event") == "node.result":
                results.add(data["node_run_id"])
            elif event.get("event") == "run.checkpoint":
                engine._checkpoint = data.get("node_id")
        for invocation, intent in intents.items():
            if invocation not in results:
                key = intent["node_id"]
                engine._records[key].update(state="RECOVERY_UNCONFIRMED",
                    reason_code="UNFINISHED_DURABLE_INTENT_REQUIRES_INDEPENDENT_RECOVERY",
                    execution_started=None, node_run_id=invocation)
                engine._state = "RECOVERY_UNCONFIRMED"
        # Lost ephemeral native ownership is never recreated from saved data.
        for row in engine._records.values():
            cleanup = row.get("cleanup", {})
            if cleanup.get("status") == "RETAINED" and cleanup.get("confirmed") is not True and \
                    saved.get("cleanup", {}).get("confirmed") is not True:
                row["state"] = "RECOVERY_UNCONFIRMED"
                row["reason_code"] = "RUNTIME_NATIVE_OWNERSHIP_NOT_RESTORED_FROM_DISK"
                engine._state = "RECOVERY_UNCONFIRMED"
        # Reserve completed invocations' full declared costs after restart.
        # This deliberately overestimates consumption rather than resetting a
        # lost monotonic budget or trusting a wall-clock/reboot correlation.
        reserved = 0
        for node in engine.definition.nodes:
            done = engine._records[node.node_id].get("iterations_completed", 0)
            reserved += done * node.budget_seconds + max(0, done - 1) * node.repeat_interval_seconds
            if done and done < node.repeat_count:
                engine._not_before[node.node_id] = time.monotonic() + node.repeat_interval_seconds
        engine._elapsed = max(engine._elapsed, reserved)
        if engine._state == "RUNNING":
            engine._state = "WAITING_FOR_HUMAN"
        return engine

    def request_cancel(self):
        if self._cancel_at is None:
            self._cancel_at = time.monotonic()
        self._cancel.set()

    def request_pause(self):
        self._pause.set()

    def snapshot(self):
        with self._lock:
            elapsed = self._elapsed + (max(0, time.monotonic() - self._started) if self._started else 0)
            rows = [deepcopy(self._records[node.node_id]) for node in self.definition.nodes]
            incomplete = [row["node_id"] for row in rows if row["state"] != "COMPLETED"]
            return {"schema": RUN_SCHEMA, "run_id": self.store.run_id,
                "workflow_id": self.definition.workflow_id, "definition_sha256": self.definition.fingerprint,
                "state": self._state, "nodes": rows, "errors": deepcopy(self._errors),
                "coverage": {"execution_scope": "DECLARED_FINITE_GRAPH_ONLY", "incomplete_nodes": incomplete,
                    "evidence_completeness": "UNKNOWN", "source_trust": "UNVERIFIED_IMPORT",
                    "root_cause": "UNKNOWN", "sufficiency_scope": "REQUESTED_OPERATION_NOT_CAUSAL_PROOF"},
                "cleanup": deepcopy(self._cleanup), "elapsed_seconds": elapsed,
                "output_folder": str(self.store.folder), "folder": str(self.store.folder)}

    def _notify(self, *, force=False):
        callback = self._callback
        if callback is not None and (force or time.monotonic() - self._last_emit >= .1):
            self._last_emit = time.monotonic()
            try:
                callback(self.snapshot())
            except Exception:
                # A disconnected UI consumer must not erase component evidence.
                pass

    def _context_event(self, ctx, phase, details):
        with self._lock:
            row = self._records.get(ctx.node_id)
            if row is None or row.get("node_run_id") != ctx.node_run_id:
                return
            state = "WAITING_FOR_HUMAN" if phase == "WAITING_FOR_HUMAN" else "RUNNING"
            row["state"] = state
            self.store.append("node.state", node_id=ctx.node_id,
                data={"node_id": ctx.node_id, "node_run_id": ctx.node_run_id, "state": state,
                      "phase": str(phase)[:128]})
            self._notify(force=True)

    def _run_state(self, state):
        with self._lock:
            self._state = state
            snapshot = self.snapshot()
            self.store.append("run.state", data={key: snapshot[key] for key in
                ("state", "coverage", "cleanup", "elapsed_seconds", "errors")})
            self._notify(force=True)

    def _skip(self, node, reason, *, state="SKIPPED"):
        row = self._records[node.node_id]
        row.update(state=state, reason_code=reason, execution_started=False)
        self.store.append("node.state", node_id=node.node_id,
            data={"node_id": node.node_id, "state": state, "reason_code": reason, "execution_started": False})

    def _inputs(self, node):
        """Return readiness, actual typed values, and explicit partial lineage."""
        edges = self._incoming[node.node_id]
        if any(self._records[e.source_node]["state"] not in TERMINAL for e in edges):
            return "WAIT", {}, False
        inputs, partial, missing = {}, False, []
        allow_partial = node.allow_partial_inputs or (node.kind == "JOIN" and
            (node.parameters.get("mode") == "ALLOW_PARTIAL" or node.parameters.get("allow_partial") is True))
        specs = get_ports(node, self.catalog)[0]
        for edge in edges:
            source = self._records[edge.source_node]
            values = source.get("outputs", {}).get(edge.source_port, [])
            if edge.target_port == "when":
                if not values or any(Artifact.from_dict(v).value.get("value") is not True for v in values):
                    return "INACTIVE", {}, False
                continue
            if source["state"] != "COMPLETED":
                if not allow_partial or source["state"] not in ("PARTIAL", "SKIPPED", "FAILED", "CANCELLED"):
                    return "BLOCKED", {}, True
                partial = True
            if not values:
                missing.append(edge.target_port)
                partial = True
                continue
            artifacts = [Artifact.from_dict(value) for value in values]
            require(all(artifact.kind in specs[edge.target_port].types for artifact in artifacts),
                    "WORKFLOW_RUNTIME_PORT_TYPE_MISMATCH", node_id=node.node_id)
            inputs.setdefault(edge.target_port, []).extend(artifacts)
        if missing and not (allow_partial and node.kind == "JOIN"):
            return "BLOCKED", {}, True
        for name, spec in specs.items():
            if name == "when":
                continue
            if spec.required and not inputs.get(name):
                return "BLOCKED", {}, True
            if name in inputs:
                require(spec.many or len(inputs[name]) == 1, "WORKFLOW_RUNTIME_INPUT_CARDINALITY")
                inputs[name] = tuple(inputs[name]) if spec.many else inputs[name][0]
        return "READY", inputs, partial

    def _resource_keys(self, node):
        if node.kind not in ("TOOL", "REPEAT"):
            return ()
        adapter = self.catalog[node.tool_id]
        return tuple(sorted(set(adapter.resources + (() if adapter.read_only else ("R60_EFFECTFUL_EXECUTION",)))))

    def _lease(self, node, invocation):
        keys = self._resource_keys(node)
        with _LEASE_LOCK:
            for key in keys:
                owner = _LEASES.get(key)
                if owner and (owner["run_id"] != self.store.run_id or owner["active"] or
                              owner["status"] != "RETAINED"):
                    return False
            owned = {key for key, owner in _LEASES.items() if owner["run_id"] == self.store.run_id}
            if len(owned | set(keys)) > self.definition.budget.get("max_owned_resources", 8):
                return False
            for key in keys:
                _LEASES[key] = {"run_id": self.store.run_id, "invocation": invocation,
                               "active": True, "status": "RUNNING"}
        return True

    def _finish_lease(self, node, invocation, cleanup):
        with _LEASE_LOCK:
            for key in self._resource_keys(node):
                owner = _LEASES.get(key)
                if not owner or owner["run_id"] != self.store.run_id or owner["invocation"] != invocation:
                    continue
                if cleanup.get("confirmed") is True:
                    del _LEASES[key]
                else:
                    known = _known_owner(cleanup)
                    owner.update(active=False, status="RETAINED" if cleanup.get("status") == "RETAINED" and
                                 known else "RECOVERY_UNCONFIRMED")

    def _context(self, node, iteration, deadline):
        invocation = uuid4().hex
        folder = Path(self.store.folder) / "outputs" / node.node_id / invocation
        folder.mkdir(parents=True, exist_ok=False)
        return ExecutionContext(self.store.run_id, node.node_id, invocation, iteration, folder,
            min(deadline, time.monotonic() + node.budget_seconds),
            _Cancellation(self._cancel, min(deadline, time.monotonic() + node.budget_seconds)), self.runtime, self)

    def _dispatch(self, node, ctx, inputs):
        ctx.check()
        for value in inputs.values():
            for artifact in value if isinstance(value, tuple) else (value,):
                verify_artifact(artifact, cancel=ctx.cancel, deadline=ctx.deadline)
        profile = self._preview["effective_profile"]
        expected = profile.get("target")
        allowed_sources = set(profile.get("source_ids", []))
        for value in inputs.values():
            for artifact in value if isinstance(value, tuple) else (value,):
                if artifact.kind == "PROCESS" and expected is not None:
                    require(artifact.value.get("identity") == expected, "WORKFLOW_PROFILE_TARGET_MISMATCH")
                if allowed_sources and artifact.kind not in ("RECEIPT", "BOOLEAN", "PROCESS"):
                    require(bool(artifact.sources) and all(source.get("source_id") in allowed_sources for source in artifact.sources),
                            "WORKFLOW_PROFILE_SOURCE_NOT_ALLOWED")
        parameters = validate_parameters(self.catalog[node.tool_id], node.parameters)
        ctx.check()
        ctx.component_dispatch_started = True
        return self.catalog[node.tool_id].execute(ctx, inputs, parameters)

    def _result(self, node, ctx, result, partial=False):
        require(isinstance(result, NodeOutcome), "WORKFLOW_COMPONENT_OUTCOME_REQUIRED")
        status = _state(result.status)
        cleanup = dict(result.cleanup or {"confirmed": False, "status": "NOT_COLLECTED"})
        outputs = {}
        errors = []
        specs = get_ports(node, self.catalog)[1]
        for port, value in result.outputs.items():
            try:
                require(port in specs, "WORKFLOW_UNDECLARED_RESULT_PORT")
                values = value if isinstance(value, (tuple, list)) else (value,)
                require(len(values) <= 64, "WORKFLOW_RESULT_PORT_BUDGET")
                for artifact in values:
                    require(isinstance(artifact, Artifact) and artifact.kind in specs[port].types,
                            "WORKFLOW_RESULT_TYPE_MISMATCH")
                    # Published references survive even a subsequent validation failure.
                    outputs.setdefault(port, []).append(artifact.to_dict())
                    profile = self._preview["effective_profile"]
                    if artifact.kind == "PROCESS" and profile.get("target") is not None:
                        require(artifact.value.get("identity") == profile["target"], "WORKFLOW_PROFILE_TARGET_MISMATCH")
                    allowed = profile.get("source_ids", [])
                    if allowed and artifact.kind not in ("RECEIPT", "BOOLEAN", "PROCESS"):
                        require(bool(artifact.sources) and all(s.get("source_id") in allowed for s in artifact.sources),
                                "WORKFLOW_PROFILE_SOURCE_NOT_ALLOWED")
                    if not (artifact.kind == "DEEP_RESULT" and not artifact.value.get("_path")):
                        verify_artifact(artifact, deadline=time.monotonic() + min(30, max(.1, ctx.remaining_seconds())))
            except Exception as error:
                errors.append(getattr(error, "code", "WORKFLOW_RESULT_REFERENCE_UNCONFIRMED"))
        receipt = result.receipt
        if node.kind in ("TOOL", "REPEAT"):
            if type(receipt) is not dict or receipt.get("contract_version") != 1:
                errors.append("WORKFLOW_ACTUAL_RUN_RECEIPT_MISSING")
            else:
                outputs["receipt"] = [Artifact("RECEIPT", {"receipt": receipt},
                    coverage={"scope": "ACTUAL_COMPONENT_INVOCATION_NOT_CAUSAL_PROOF"}).to_dict()]
            if status == "COMPLETED":
                if result.execution_started is not True or (receipt or {}).get("execution_started") is not True:
                    errors.append("WORKFLOW_COMPONENT_EXECUTION_NOT_ESTABLISHED")
                if any(spec.required and not outputs.get(port) for port, spec in
                       self.catalog[node.tool_id].outputs.items()):
                    errors.append("WORKFLOW_REQUIRED_RESULT_NOT_PUBLISHED")
        if errors:
            status = "RECOVERY_UNCONFIRMED" if cleanup.get("owner_retained") else "FAILED"
        if partial and status == "COMPLETED":
            status = "PARTIAL"
        known = _known_owner(cleanup)
        unknown_cleanup = (cleanup.get("confirmed") is not True and not
            (cleanup.get("status") == "RETAINED" and known))
        if unknown_cleanup and self._resource_keys(node):
            status = "RECOVERY_UNCONFIRMED"
        record = {"node_id": node.node_id, "node_run_id": ctx.node_run_id, "iteration": ctx.iteration,
            "state": status, "component_status": result.status, "execution_started": result.execution_started,
            "run_receipt": receipt, "run_context": result.context,
            "tool_descriptor": result.descriptor or (self.catalog[node.tool_id].descriptor.to_dict()
                if node.kind in ("TOOL", "REPEAT") else None),
            "outputs": outputs, "cleanup": cleanup,
            "reason_code": ";".join(errors) if errors else result.reason_code,
            "started_monotonic_ns": self._records[node.node_id].get("started_monotonic_ns", time.monotonic_ns()),
            "ended_monotonic_ns": time.monotonic_ns(), "partial_inputs": partial}
        with self._lock:
            row = self._records[node.node_id]
            attempts = row["attempts"] + [{"node_run_id": ctx.node_run_id, "iteration": ctx.iteration,
                "state": status, "component_status": result.status, "reason_code": record["reason_code"]}]
            row.update(record)
            row["attempts"] = attempts[-64:]
            row["iterations_completed"] = ctx.iteration + 1
            # Keep the actual returned receipt/reference reachable even when a
            # disk failure prevents its durable publication. This is explicitly
            # unconfirmed persistence, never a replacement synthetic receipt.
            try:
                self.store.append("node.result", node_id=node.node_id, data=record)
            except Exception:
                row.update(state="RECOVERY_UNCONFIRMED", persistence="PUBLICATION_UNCONFIRMED")
                raise
            if status == "COMPLETED" and ctx.iteration + 1 < node.repeat_count:
                row["state"] = "QUEUED"
                self._not_before[node.node_id] = time.monotonic() + node.repeat_interval_seconds
            self._finish_lease(node, ctx.node_run_id, cleanup)
            self._notify(force=True)

    def _exception(self, node, ctx, error):
        receipt = getattr(error, "run_receipt", None)
        cleanup = (receipt or {}).get("cleanup") or {"confirmed": False, "status": "NOT_COLLECTED"}
        uncertain = any(getattr(error, flag, False) for flag in
            ("cleanup_required", "cleanup_unconfirmed", "owner_retained", "offline_owner_retained"))
        if uncertain:
            cleanup = {**cleanup, "confirmed": False, "status": "RECOVERY_UNCONFIRMED", "owner_retained": True}
        elif not ctx.component_dispatch_started:
            cleanup = {"confirmed": True, "status": "CONFIRMED",
                       "scope": "SCHEDULER_RESERVATION_ONLY_COMPONENT_NOT_DISPATCHED"}
        return NodeOutcome("RECOVERY_UNCONFIRMED" if uncertain else "CANCELLED" if isinstance(error, InterruptedError)
            else "TIMED_OUT" if isinstance(error, TimeoutError) else "OPERATION_FAILED",
            receipt=receipt, context=getattr(error, "run_context", None),
            descriptor=getattr(error, "tool_descriptor", None), cleanup=cleanup,
            execution_started=(receipt or {}).get("execution_started") if ctx.component_dispatch_started else False,
            reason_code=getattr(error, "code", type(error).__name__))

    def _control(self, node, inputs, partial, deadline):
        if node.kind == "CHECKPOINT":
            self._checkpoint = node.node_id
            self._records[node.node_id]["state"] = "WAITING_FOR_HUMAN"
            self.store.append("run.checkpoint", node_id=node.node_id,
                              data={"node_id": node.node_id, "state": "WAITING_FOR_HUMAN"})
            self._pause.set()
            return
        ctx = self._context(node, 0, deadline)
        row = self._records[node.node_id]
        row.update(node_run_id=ctx.node_run_id, started_monotonic_ns=time.monotonic_ns())
        if node.kind == "CONDITION":
            artifact = inputs["input"]
            actual = artifact.value.get("receipt", {}) if artifact.kind == "RECEIPT" else {
                "value": artifact.value, "coverage": artifact.coverage}
            condition = node.parameters.get("condition", node.parameters or {"status": "COMPLETED"})
            decision = evaluate_condition(condition, actual)
            outputs = {} if decision is None else {"true" if decision else "false": Artifact("BOOLEAN",
                {"value": True, "predicate_result": decision, "basis_artifact_id": artifact.artifact_id,
                 "scope": "REQUESTED_PREDICATE_NOT_ROOT_CAUSE"})}
            result = NodeOutcome("PARTIAL" if decision is None else "COMPLETED", outputs,
                cleanup={"confirmed": True, "status": "CONFIRMED", "scope": "NO_NATIVE_CONTROL_RESOURCES"},
                execution_started=True, reason_code="CONDITION_EVIDENCE_UNKNOWN" if decision is None else None)
        else:
            artifacts = inputs.get("evidence", ())
            missing = [{"upstream_node_id": edge.source_node, "source_port": edge.source_port,
                "state": self._records[edge.source_node]["state"],
                "reason_code": self._records[edge.source_node].get("reason_code")}
                for edge in self._incoming[node.node_id] if edge.target_port != "when" and
                (self._records[edge.source_node]["state"] != "COMPLETED" or not
                 self._records[edge.source_node].get("outputs", {}).get(edge.source_port))]
            sources = {canonical(s): s for artifact in artifacts for s in artifact.sources}
            clocks = tuple(sorted({clock for artifact in artifacts for clock in artifact.clock_domains}))
            for artifact in artifacts:
                verify_artifact(artifact, cancel=ctx.cancel, deadline=ctx.deadline)
            artifact = Artifact("EVIDENCE_SET", {"items": [a.to_dict() for a in artifacts],
                "join_policy": node.parameters.get("mode", "ALL_REQUIRED"), "partial_branches": partial,
                "missing_or_partial_branches": missing},
                sources=tuple(sources.values()), clock_domains=clocks,
                coverage={"completeness": "PARTIAL" if partial else "UNKNOWN", "clock_alignment": "NOT_ESTABLISHED"})
            result = NodeOutcome("PARTIAL" if partial else "COMPLETED", {"evidence": artifact},
                cleanup={"confirmed": True, "status": "CONFIRMED", "scope": "VALIDATED_REFERENCE_HANDLES_CLOSED"},
                execution_started=True)
        self._result(node, ctx, result, partial)

    def _revalidate(self, deadline):
        for row in self._records.values():
            if row["state"] in ("COMPLETED", "PARTIAL"):
                for port in row.get("outputs", {}).values():
                    for value in port:
                        artifact = Artifact.from_dict(value)
                        if artifact.kind == "DEEP_RESULT" and not artifact.value.get("_path"):
                            continue
                        verify_artifact(artifact, cancel=self._cancel, deadline=deadline)

    def _finalize(self):
        callback = getattr(self.runtime, "finish_run", None)
        adapter = None
        if callback is None and getattr(self.runtime, "owned_session_run_id", None) == self.store.run_id:
            callback = getattr(self.runtime, "session_finalize", None)
            if callback is None:
                adapter = self.catalog.get("session_finalize")
        if callback is None and adapter is None:
            return
        from .chain_contracts import NodeDefinition
        node = NodeDefinition("runtime-cleanup", budget_seconds=100)
        parent = threading.Event()  # cancellation must not skip actual cleanup
        deadline = time.monotonic() + 100
        ctx = ExecutionContext(self.store.run_id, node.node_id, uuid4().hex, 0,
            Path(self.store.folder), deadline, _Cancellation(parent, deadline), self.runtime, self)
        try:
            actual_cleanup_call = None
            if adapter is not None:
                outcome = adapter.execute(ctx, {}, {})
                require(isinstance(outcome, NodeOutcome), "WORKFLOW_RUNTIME_CLEANUP_OUTCOME_REQUIRED")
                answer = {"status": outcome.status, "cleanup": outcome.cleanup}
                actual_cleanup_call = {"run_receipt": outcome.receipt, "run_context": outcome.context,
                                       "tool_descriptor": outcome.descriptor}
            else:
                answer = callback(ctx)
            require(type(answer) is dict, "WORKFLOW_RUNTIME_CLEANUP_ACK_REQUIRED")
            cleanup = answer.get("cleanup") or (answer.get("data") or {}).get("expiry_cleanup") or answer
            require(type(cleanup) is dict and type(cleanup.get("confirmed")) is bool,
                    "WORKFLOW_RUNTIME_CLEANUP_ACK_REQUIRED")
            if answer.get("status") not in (None, "COMPLETED", "CONFIRMED", "CLOSED"):
                self._errors.append({"code": "WORKFLOW_RUNTIME_FINALIZATION_FAILED",
                                     "component_status": str(answer["status"])[:128]})
        except Exception as error:
            cleanup = {"confirmed": False, "status": "RECOVERY_UNCONFIRMED", "owner_retained": True,
                       "reason_code": getattr(error, "code", type(error).__name__)}
        self.store.append("run.cleanup", data={"cleanup": cleanup, "scope": "ACTUAL_RUNTIME_OWNER_BOUNDARY",
                                               "actual_cleanup_call": actual_cleanup_call})
        if cleanup.get("confirmed") is True:
            with _LEASE_LOCK:
                for key in list(_LEASES):
                    owner = _LEASES[key]
                    if key in ("EXISTING_DEEP_INSPECTOR_OWNER", "R60_EFFECTFUL_EXECUTION") and \
                            owner["run_id"] == self.store.run_id and not owner["active"] and owner["status"] == "RETAINED":
                        del _LEASES[key]
        else:
            self._errors.append({"code": "WORKFLOW_RUNTIME_CLEANUP_UNCONFIRMED"})
        self._runtime_cleanup = cleanup

    def _drain_retained(self, pool, pending):
        """Preserve a late real outcome and eventually release the same owners.

        This observer cannot interrupt a non-cooperative component. Until its
        actual return, the writer, worker and resource capabilities stay held.
        """
        def drain():
            try:
                for future, (node, ctx, partial) in list(pending.items()):
                    try:
                        outcome = future.result()
                    except BaseException as error:
                        outcome = self._exception(node, ctx, error)
                    self._result(node, ctx, outcome, partial)
                self._finalize()
                exited = pool.close()
                with _LEASE_LOCK:
                    leases = [o for o in _LEASES.values() if o["run_id"] == self.store.run_id]
                self._cleanup = {"confirmed": exited and not leases and
                    getattr(self, "_runtime_cleanup", {}).get("confirmed", True) is True,
                    "status": "LATE_OWNER_BOUNDARY_OBSERVED", "worker_exit_confirmed": exited,
                    "scope": "LATE_ACTUAL_COMPLETION_NOT_RETROACTIVE_SUCCESS"}
                self._run_state("RECOVERY_UNCONFIRMED")
            except BaseException:
                # Failed durable readback/cleanup leaves this exact owner pinned.
                return
            try:
                self.store.unpin_writer()
                self.store.release_writer()
            except Exception:
                return
            _RETAINED_WORKERS.pop(self.store.run_id, None)
        thread = threading.Thread(target=drain, name="blackbox-chain-retained-drain", daemon=True)
        thread.start()

    def resume(self, on_event=None):
        return self._drive(resuming=True, on_event=on_event)

    def run(self, on_event=None):
        return self._drive(resuming=False, on_event=on_event)

    def _return_snapshot(self):
        self._returned_snapshot = self.snapshot()
        return self._returned_snapshot

    def _drive(self, *, resuming, on_event):
        with self._lock:
            require(not self._driving, "WORKFLOW_ALREADY_RUNNING")
            if self._state in ("COMPLETED", "CANCELLED", "FAILED", "RECOVERY_UNCONFIRMED", "PARTIAL") and not self._cancel.is_set():
                return self._return_snapshot()
            require(resuming or self._state == "QUEUED", "WORKFLOW_EXPLICIT_RESUME_REQUIRED")
            self._driving, self._callback = True, on_event
        pool, pending = None, {}
        acquired = False
        retained = False
        try:
            self.store.acquire_writer()
            acquired = True
            if self._cancel.is_set():
                # Cancellation of a paused/reopened run never dispatches a
                # diagnostic node, validates consent, or completes a checkpoint.
                for node in self.definition.nodes:
                    if self._records[node.node_id]["state"] in ("QUEUED", "WAITING_FOR_HUMAN"):
                        self._skip(node, "WORKFLOW_CANCELLED_BEFORE_DISPATCH", state="CANCELLED")
                self._finalize()
                with _LEASE_LOCK:
                    live = [owner for owner in _LEASES.values() if owner["run_id"] == self.store.run_id]
                clean = not live and getattr(self, "_runtime_cleanup", {}).get("confirmed", True) is True
                self._cleanup = {"confirmed": clean, "status": "CONFIRMED" if clean else "RECOVERY_UNCONFIRMED",
                    "scope": "CANCELLED_PAUSED_RUN_ACTUAL_OWNERS_ONLY", "worker_exit_confirmed": True}
                uncertain = any(row["state"] == "RECOVERY_UNCONFIRMED" for row in self._records.values())
                self._run_state("RECOVERY_UNCONFIRMED" if not clean or uncertain else "CANCELLED")
                return self._return_snapshot()
            self._preview = validate_workflow(self.definition, self.catalog, runtime=self.runtime)
            if not self._preview["ready"]:
                self._errors.extend(self._preview["errors"])
                self._run_state("FAILED")
                return self._return_snapshot()
            profile = self._preview["effective_profile"]
            remaining = profile["max_seconds"] - self._elapsed
            require(remaining > 0, "WORKFLOW_GLOBAL_BUDGET_EXHAUSTED")
            self._started = time.monotonic()
            deadline = self._started + remaining
            if resuming:
                try:
                    self._revalidate(deadline)
                except Exception as error:
                    self._errors.append({"code": getattr(error, "code", "WORKFLOW_RESUME_SOURCE_NOT_VERIFIED")})
                    self._run_state("RECOVERY_UNCONFIRMED")
                    return self._return_snapshot()
                self._pause.clear()
                if self._checkpoint:
                    key = self._checkpoint
                    node = next(n for n in self.definition.nodes if n.node_id == key)
                    if self._records[key]["state"] == "WAITING_FOR_HUMAN":
                        ctx = self._context(node, 0, deadline)
                        self._records[key].update(node_run_id=ctx.node_run_id, started_monotonic_ns=time.monotonic_ns())
                        self._result(node, ctx, NodeOutcome("COMPLETED", {"continue": Artifact("BOOLEAN", {"value": True,
                            "scope": "EXPLICIT_RESUME_AFTER_SOURCE_REVALIDATION"})},
                            cleanup={"confirmed": True, "status": "CONFIRMED", "scope": "NO_NATIVE_CONTROL_RESOURCES"},
                            execution_started=True))
                    self._checkpoint = None
            pool = _Workers(profile["max_workers"])
            self._run_state("RUNNING")
            ready = deque(self._preview["order"])
            indexed = {n.node_id: n for n in self.definition.nodes}
            next_size_check = 0
            while True:
                changed = False
                for future in list(pending):
                    node, ctx, partial = pending[future]
                    if future.done():
                        del pending[future]
                        try:
                            result = future.result()
                        except BaseException as error:
                            result = self._exception(node, ctx, error)
                        self._result(node, ctx, result, partial)
                        changed = True
                    elif time.monotonic() > min(ctx.deadline + 120,
                            (self._cancel_at + 120) if self._cancel_at is not None else float("inf")):
                        ctx.cancel.set()
                        self._skip(node, "COMPONENT_OWNER_DID_NOT_ACKNOWLEDGE_STOP", state="RECOVERY_UNCONFIRMED")
                        self.request_cancel()
                        retained = True
                if retained:
                    break
                if time.monotonic() >= deadline:
                    self.request_cancel()
                    if not any(e.get("code") == "WORKFLOW_GLOBAL_DEADLINE" for e in self._errors):
                        self._errors.append({"code": "WORKFLOW_GLOBAL_DEADLINE"})
                if time.monotonic() >= next_size_check:
                    next_size_check = time.monotonic() + 1
                    try:
                        owned_output_bytes(self.store.folder, maximum=profile["max_output_bytes"])
                    except (WorkflowError, OSError) as error:
                        self.request_cancel()
                        if not any(e.get("code") == "WORKFLOW_OUTPUT_BYTE_BUDGET" for e in self._errors):
                            self._errors.append({"code": "WORKFLOW_OUTPUT_BYTE_BUDGET",
                                                 "reason_code": getattr(error, "code", type(error).__name__)})
                if not self._cancel.is_set() and not self._pause.is_set():
                    for _ in range(len(ready)):
                        key = ready.popleft()
                        node, row = indexed[key], self._records[key]
                        if row["state"] != "QUEUED":
                            continue
                        readiness, inputs, partial = self._inputs(node)
                        if readiness in ("INACTIVE", "BLOCKED"):
                            self._skip(node, "CONDITION_BRANCH_NOT_SELECTED" if readiness == "INACTIVE" else
                                       "UPSTREAM_EVIDENCE_NOT_AVAILABLE_FOR_DECLARED_POLICY")
                            changed = True
                            continue
                        if readiness == "WAIT" or time.monotonic() < self._not_before.get(key, 0):
                            ready.append(key)
                            continue
                        if node.kind == "CHECKPOINT" and pending:
                            ready.append(key)
                            continue
                        if node.kind not in ("TOOL", "REPEAT"):
                            self._control(node, inputs, partial, deadline)
                            changed = True
                            if self._pause.is_set():
                                break
                            continue
                        if len(pending) >= profile["max_workers"]:
                            ready.append(key)
                            continue
                        effect_active = any(not self.catalog[active_node.tool_id].read_only
                                            for active_node, _ctx, _partial in pending.values())
                        if effect_active or (not self.catalog[node.tool_id].read_only and pending):
                            ready.append(key)
                            continue
                        if profile.get("allowed_node_ids") and key not in profile["allowed_node_ids"]:
                            self._skip(node, "WORKFLOW_PROFILE_NODE_NOT_ALLOWED", state="FAILED")
                            changed = True
                            continue
                        invocation = uuid4().hex
                        if not self._lease(node, invocation):
                            ready.append(key)
                            continue
                        try:
                            ctx = self._context(node, row["iterations_completed"], deadline)
                            # lease identity must match the actual persisted invocation
                            with _LEASE_LOCK:
                                for resource in self._resource_keys(node):
                                    _LEASES[resource]["invocation"] = ctx.node_run_id
                            row.update(state="RUNNING", node_run_id=ctx.node_run_id,
                                       started_monotonic_ns=time.monotonic_ns())
                            self.store.append("node.intent", node_id=key, data={"node_id": key,
                                "node_run_id": ctx.node_run_id, "iteration": ctx.iteration, "state": "RUNNING",
                                "tool_id": node.tool_id, "read_only": self.catalog[node.tool_id].read_only,
                                "execution_started": None, "started_monotonic_ns": row["started_monotonic_ns"]})
                            pending[pool.submit(lambda n=node, c=ctx, i=inputs: self._dispatch(n, c, i))] = (node, ctx, partial)
                            changed = True
                        except BaseException:
                            self._finish_lease(node, row.get("node_run_id", invocation),
                                {"confirmed": True, "scope": "SCHEDULER_RESERVATION_COMPONENT_NOT_SUBMITTED"})
                            raise
                # A repeat becomes ready only after its preceding result is durable.
                for key, row in self._records.items():
                    if row["state"] == "QUEUED" and key not in ready:
                        ready.append(key)
                if not pending:
                    if self._cancel.is_set() or self._pause.is_set():
                        break
                    queued = [indexed[key] for key in ready if self._records[key]["state"] == "QUEUED"]
                    if not queued:
                        break
                    if not changed and not any(time.monotonic() < self._not_before.get(n.node_id, 0) for n in queued):
                        for node in queued:
                            self._skip(node, "RESOURCE_LEASE_OR_UPSTREAM_RECOVERY_UNCONFIRMED", state="RECOVERY_UNCONFIRMED")
                        break
                if not changed:
                    time.sleep(.02)
            if self._pause.is_set() and not self._cancel.is_set():
                self._cleanup = {"confirmed": False, "status": "RETAINED_AT_CHECKPOINT",
                    "scope": "PAUSED_RUN_REQUIRES_EXPLICIT_RESUME_OR_CANCEL"}
                self._run_state("WAITING_FOR_HUMAN")
                return self._return_snapshot()
            for node in self.definition.nodes:
                if self._records[node.node_id]["state"] == "QUEUED":
                    self._skip(node, "WORKFLOW_CANCELLED_BEFORE_DISPATCH", state="CANCELLED")
            if not retained:
                self._finalize()
                worker_exit = pool.close()
                if worker_exit:
                    pool = None
                else:
                    retained = True
            with _LEASE_LOCK:
                leases = [dict(value) for value in _LEASES.values() if value["run_id"] == self.store.run_id]
            clean = not leases and not retained and getattr(self, "_runtime_cleanup", {}).get("confirmed", True) is True
            self._cleanup = {"confirmed": clean, "status": "CONFIRMED" if clean else "RECOVERY_UNCONFIRMED",
                "scope": "ACTUAL_WORKFLOW_WORKERS_AND_DECLARED_RESOURCE_LEASES_ONLY",
                "retained_resource_count": len(leases), "worker_exit_confirmed": not retained,
                "runtime": getattr(self, "_runtime_cleanup", None)}
            states = {row["state"] for row in self._records.values()}
            state = ("RECOVERY_UNCONFIRMED" if not clean or "RECOVERY_UNCONFIRMED" in states else
                     "CANCELLED" if self._cancel.is_set() else
                     "COMPLETED" if not self._errors and all(self._records[n.node_id]["state"] == "COMPLETED" or
                         (not n.required and self._records[n.node_id]["state"] == "SKIPPED") for n in self.definition.nodes)
                     else "PARTIAL" if states & {"COMPLETED", "PARTIAL"} else "FAILED")
            self._run_state(state)
            return self._return_snapshot()
        except BaseException as error:
            self.request_cancel()
            # Persisting history itself can fail. Preserve live owners and the
            # primary failure in memory; never release a writer/lease while an
            # invocation may still be executing or silently reopen that intent.
            retained = bool(pending)
            for _future, (node, ctx, _partial) in pending.items():
                ctx.cancel.set()
                self._records[node.node_id].update(state="RECOVERY_UNCONFIRMED",
                    reason_code="SCHEDULER_FAILED_WITH_LIVE_COMPONENT_OWNER")
            self._errors.append({"code": getattr(error, "code", type(error).__name__),
                                 "scope": "WORKFLOW_SCHEDULER_PRIMARY_FAILURE"})
            self._state = "RECOVERY_UNCONFIRMED"
            self._cleanup = {"confirmed": False, "status": "RECOVERY_UNCONFIRMED",
                             "owner_retained": retained, "scope": "SCHEDULER_FAILURE"}
            if not retained:
                try:
                    self._finalize()
                except Exception:
                    pass
            self._notify(force=True)
            return self._return_snapshot()
        finally:
            if self._started:
                self._elapsed += max(0, time.monotonic() - self._started)
                self._started = None
            if pool is not None:
                if retained:
                    # The live owner and writer lock remain reachable. Reopening a
                    # folder cannot turn this unacknowledged call into permission.
                    self.store.pin_writer()
                    _RETAINED_WORKERS[self.store.run_id] = (self, pool, pending)
                    self._drain_retained(pool, pending)
                else:
                    pool.close()
            if acquired and not retained:
                try:
                    self.store.release_writer()
                except Exception as error:
                    self._state = "RECOVERY_UNCONFIRMED"
                    self._errors.append({"code": getattr(error, "code", "WORKFLOW_WRITER_RELEASE_UNCONFIRMED")})
                    self._notify(force=True)
                    returned = getattr(self, "_returned_snapshot", None)
                    if returned is not None:
                        returned.clear()
                        returned.update(self.snapshot())
            with self._lock:
                self._driving = False
