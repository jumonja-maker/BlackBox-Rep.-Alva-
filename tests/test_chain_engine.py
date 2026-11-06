"""Deterministic scheduler fault fixtures, separate from real Windows QA.

Adapters here are explicit in-process boundary fixtures. They cannot establish
Windows token, helper, native capture, or physical-machine acceptance.
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace

from blackbox_core.chain_contracts import Artifact, NodeOutcome, PortSpec, ToolAdapter, WorkflowDefinition
from blackbox_core.chain_engine import WorkflowEngine
from blackbox_core.chain_store import WorkflowRunStore
from blackbox_core.deep_tool_contracts import RunReceipt, ToolDescriptor


def adapter(tool_id, call, *, inputs=None, resources=(), read_only=True, available=True):
    descriptor = ToolDescriptor("qa.workflow." + tool_id, 1, tuple((inputs or {}).keys()),
        ("report", "RunReceipt/v1"), ("qa.fixture." + tool_id,), "IN_PROCESS_TEST_FIXTURE",
        "NO_NATIVE_EFFECTS", {"fixture": True}, resources,
        {"supported": True, "cleanup": "EXPLICIT_FIXTURE_ACK"})
    return ToolAdapter(tool_id, descriptor, inputs or {}, {"report": PortSpec(("REPORT",))}, {}, call,
                       read_only=read_only, resources=resources, available=available,
                       unavailable_reason=None if available else "EXPLICIT_UNAVAILABLE_FIXTURE")


def outcome(ctx, *, status="COMPLETED", cleanup=True, value=None, execution_started=True):
    from blackbox_core.chain_io import make_file_artifact
    now = datetime.now(timezone.utc).isoformat()
    ack = {"confirmed": cleanup, "status": "CONFIRMED" if cleanup else "RECOVERY_UNCONFIRMED",
           "scope": "IN_PROCESS_TEST_FIXTURE_ONLY"}
    receipt = RunReceipt(ctx.node_run_id, "qa.fixture.call", "qa.workflow.fixture", now, now, 0,
        status, execution_started, {"verified": True, "scope": "EXPLICIT_TEST_FIXTURE"},
        {"identity": None, "verified": False}, (), {"completeness": "UNKNOWN"},
        ("IN_PROCESS_FIXTURE_NOT_NATIVE_ACCEPTANCE",), {}, ack, "NO_NATIVE_EFFECTS").to_dict()
    path = Path(ctx.output_dir) / ("fixture-" + str(ctx.iteration) + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"fixture_value": value or ctx.node_id}), encoding="utf-8")
    artifact = make_file_artifact("REPORT", path)
    return NodeOutcome(status, {"report": artifact},
                       receipt=receipt, cleanup=ack, execution_started=execution_started)


def workflow(nodes, edges=(), *, workers=2, seconds=30):
    return WorkflowDefinition.from_dict({"schema": "blackbox.workflow-definition/1",
        "workflow_id": "qa-engine", "title": "Explicit scheduler fixture",
        "nodes": [{"budget_seconds": 3, **node} for node in nodes],
        "edges": list(edges), "budget": {"seconds": seconds, "max_workers": workers,
            "max_owned_resources": 8, "max_output_bytes": 1024**2}})


def edge(first, second, *, port="report", target="input"):
    return {"edge_id": first + "-" + second, "source_node": first, "source_port": port,
            "target_node": second, "target_port": target}


def node_records(snapshot):
    return {record["node_id"]: record for record in snapshot["nodes"]}


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def engine(self, definition, catalog, *, runtime=None):
        store = WorkflowRunStore.create(self.root / "runs", definition)
        return WorkflowEngine(definition, catalog=catalog, store=store, runtime=runtime), store

    def run_thread(self, engine):
        result, errors = [], []
        def work():
            try:
                result.append(engine.run())
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=work, daemon=True)
        thread.start()
        def cleanup():
            engine.request_cancel()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive(), "fixture engine worker was not drained")
        self.addCleanup(cleanup)
        return thread, result, errors

    def test_parallel_ready_nodes_fill_bounded_workers_and_keep_each_result(self):
        lock, release = threading.Lock(), threading.Event()
        two_running = threading.Event()
        active = peak = calls = 0
        def execute(ctx, inputs, parameters):
            nonlocal active, peak, calls
            with lock:
                active += 1
                calls += 1
                peak = max(peak, active)
                if active == 2:
                    two_running.set()
            self.assertTrue(release.wait(3), "scheduler did not fill the ready worker pair")
            try:
                return outcome(ctx)
            finally:
                with lock:
                    active -= 1
        definition = workflow([{"node_id": "n" + str(n), "tool_id": "read"} for n in range(6)])
        engine, _store = self.engine(definition, {"read": adapter("read", execute)})
        thread, result, errors = self.run_thread(engine)
        try:
            self.assertTrue(two_running.wait(3), "two independent branches never ran together")
        finally:
            release.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(calls, 6)
        self.assertEqual(peak, 2)
        self.assertEqual(result[0]["state"], "COMPLETED")
        self.assertTrue(all(row["state"] == "COMPLETED" for row in result[0]["nodes"]))

    def test_exclusive_resource_serializes_actual_fixture_dispatch(self):
        lock = threading.Lock()
        first_running, release = threading.Event(), threading.Event()
        active = peak = calls = 0
        def execute(ctx, inputs, parameters):
            nonlocal active, peak, calls
            with lock:
                active += 1
                calls += 1
                ordinal = calls
                peak = max(peak, active)
            try:
                if ordinal == 1:
                    first_running.set()
                    self.assertTrue(release.wait(3))
                return outcome(ctx)
            finally:
                with lock:
                    active -= 1
        definition = workflow([{"node_id": key, "tool_id": "exclusive"} for key in ("a", "b")])
        engine, _store = self.engine(definition, {"exclusive": adapter("exclusive", execute,
                                                                     resources=("OWNED_FIXTURE",))})
        thread, result, errors = self.run_thread(engine)
        try:
            self.assertTrue(first_running.wait(3))
            with lock:
                self.assertEqual(calls, 1)
        finally:
            release.set()
        thread.join(timeout=5)
        self.assertEqual(errors, [])
        self.assertEqual(peak, 1)
        self.assertEqual(calls, 2)
        self.assertEqual(result[0]["state"], "COMPLETED")

    def test_effectful_invocation_never_overlaps_readonly_in_either_ready_order(self):
        # Both queue orders matter: effects must wait for running reads, and
        # newly ready reads must wait for a running effect. No native effects
        # are performed by these explicit boundary fixtures.
        for first, second in (("effect", "read"), ("read", "effect")):
            with self.subTest(first=first):
                lock = threading.Lock()
                entered, release, second_entered = (threading.Event() for _ in range(3))
                active, overlaps, calls = set(), [], []
                def execute(ctx, inputs, parameters):
                    with lock:
                        if active:
                            overlaps.append((tuple(sorted(active)), ctx.node_id))
                        active.add(ctx.node_id)
                        calls.append(ctx.node_id)
                    try:
                        if ctx.node_id == first:
                            entered.set()
                            self.assertTrue(release.wait(3), "fixture release was not signalled")
                        else:
                            second_entered.set()
                        return outcome(ctx)
                    finally:
                        with lock:
                            active.remove(ctx.node_id)
                document = workflow([{"node_id": name, "tool_id": name} for name in (first, second)]).to_dict()
                document["profile"] = {"profile_id": "application", "overrides": {"allow_effectful": True}}
                definition = WorkflowDefinition.from_dict(document)
                engine, _store = self.engine(definition, {
                    "read": adapter("read", execute),
                    "effect": adapter("effect", execute, read_only=False)})
                thread, results, errors = self.run_thread(engine)
                try:
                    self.assertTrue(entered.wait(3), "first declared invocation did not start")
                    self.assertFalse(second_entered.wait(.15), "effect overlapped the read-only branch")
                finally:
                    release.set()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(overlaps, [])
                self.assertEqual(calls, [first, second])
                self.assertEqual(results[0]["state"], "COMPLETED")

    def test_cancel_reopened_checkpoint_runs_cleanup_without_forward_dispatch(self):
        calls, finalized = [], []
        def execute(ctx, inputs, parameters):
            calls.append(ctx.node_id)
            return outcome(ctx)
        def finish(ctx):
            # Cleanup has its own live budget; cancelling diagnostics must not
            # cancel the actual release boundary before it can be observed.
            self.assertFalse(ctx.cancel.is_set())
            finalized.append(ctx.run_id)
            return {"status": "COMPLETED", "cleanup": {"confirmed": True, "status": "CONFIRMED",
                "scope": "EXPLICIT_UNIT_CLEANUP_BOUNDARY_NOT_NATIVE_ACCEPTANCE"}}
        definition = workflow([{"node_id": "saved", "tool_id": "read"},
            {"node_id": "checkpoint", "kind": "CHECKPOINT", "budget_seconds": 1},
            {"node_id": "after", "tool_id": "consume"}], [
                edge("saved", "checkpoint", port="receipt", target="after"),
                edge("saved", "after"), edge("checkpoint", "after", port="continue", target="when")])
        catalog = {"read": adapter("read", execute),
            "consume": adapter("consume", execute, inputs={"input": PortSpec(("REPORT",))})}
        runtime = SimpleNamespace(finish_run=finish)
        engine, store = self.engine(definition, catalog, runtime=runtime)
        paused = engine.run()
        self.assertEqual(paused["state"], "WAITING_FOR_HUMAN")
        preserved = deepcopy(node_records(paused)["saved"])
        self.assertEqual(finalized, [], "a checkpoint must retain its owner until explicit resume/cancel")
        reopened = WorkflowEngine.restore(WorkflowRunStore.open(store.folder), catalog=catalog, runtime=runtime)
        reopened.request_cancel()
        cancelled = reopened.resume()
        self.assertEqual(cancelled["state"], "CANCELLED")
        self.assertEqual(calls, ["saved"])
        self.assertEqual(finalized, [store.run_id])
        self.assertTrue(cancelled["cleanup"]["confirmed"])
        records = node_records(cancelled)
        self.assertEqual(records["saved"], preserved)
        self.assertEqual(records["checkpoint"]["state"], "CANCELLED")
        self.assertEqual(records["checkpoint"]["outputs"], {})
        self.assertEqual(records["after"]["state"], "CANCELLED")
        self.assertIsNone(records["after"]["run_receipt"])
        self.assertEqual(len([event for event in store.read_events() if event["event"] == "run.cleanup"]), 1)

    def test_nested_known_retained_receipt_reenters_same_owner_then_actual_finalizer_releases(self):
        calls, finalized, original_receipts = [], [], []
        retained = {"confirmed": False, "status": "RETAINED", "scope": "TARGET_BOUND_DEBUG_CONTEXT",
            "evidence": {"ownership_known": True, "scope": "EXPLICIT_UNIT_OWNER_NOT_NATIVE_ACCEPTANCE"}}
        def execute(ctx, inputs, parameters):
            calls.append(ctx.node_id)
            result = outcome(ctx)
            result.cleanup = deepcopy(retained)
            result.receipt["cleanup"] = deepcopy(retained)
            original_receipts.append(deepcopy(result.receipt))
            return result
        def finish(ctx):
            finalized.append(ctx.run_id)
            return {"status": "COMPLETED", "cleanup": {"confirmed": True, "status": "CONFIRMED",
                "scope": "CHAIN_OWNED_NATIVE_CONTEXT", "evidence": {"fixture": True}}}
        definition = workflow([{"node_id": "first", "tool_id": "owned"},
            {"node_id": "next", "tool_id": "consume"}], [edge("first", "next")])
        resource = ("EXISTING_DEEP_INSPECTOR_OWNER",)
        catalog = {"owned": adapter("owned", execute, resources=resource),
            "consume": adapter("consume", execute, inputs={"input": PortSpec(("REPORT",))}, resources=resource)}
        engine, store = self.engine(definition, catalog, runtime=SimpleNamespace(finish_run=finish))
        snapshot = engine.run()
        self.assertEqual(calls, ["first", "next"], "known retained ownership must permit its same-run successor")
        self.assertEqual(finalized, [store.run_id])
        self.assertEqual(snapshot["state"], "COMPLETED")
        self.assertTrue(snapshot["cleanup"]["confirmed"])
        records = node_records(snapshot)
        for position, name in enumerate(("first", "next")):
            self.assertEqual(records[name]["run_receipt"], original_receipts[position])
            self.assertEqual(records[name]["cleanup"], retained)
            self.assertFalse(records[name]["run_receipt"]["cleanup"]["confirmed"],
                "later finalization must not rewrite the earlier retained-resource receipt")

    def test_failed_branch_does_not_erase_independent_completed_evidence(self):
        called = []
        def execute(ctx, inputs, parameters):
            called.append(ctx.node_id)
            return outcome(ctx, status="OPERATION_FAILED" if ctx.node_id == "fail" else "COMPLETED")
        catalog = {"read": adapter("read", execute),
                   "consume": adapter("consume", execute, inputs={"input": PortSpec(("REPORT",))})}
        definition = workflow([{"node_id": "fail", "tool_id": "read"},
            {"node_id": "kept", "tool_id": "read"}, {"node_id": "blocked", "tool_id": "consume"}],
            [edge("fail", "blocked")])
        engine, _store = self.engine(definition, catalog)
        result = engine.run()
        records = node_records(result)
        self.assertEqual(records["kept"]["state"], "COMPLETED")
        self.assertNotIn("blocked", called)
        self.assertNotEqual(result["state"], "COMPLETED")
        self.assertTrue(records["kept"]["outputs"])

    def test_unknown_cleanup_retains_exclusive_lease_and_never_dispatches_competitor(self):
        calls = []
        def execute(ctx, inputs, parameters):
            calls.append(ctx.node_id)
            return outcome(ctx, cleanup=False)
        definition = workflow([{"node_id": key, "tool_id": "uncertain"} for key in ("a", "b")])
        engine, _store = self.engine(definition, {"uncertain": adapter("uncertain", execute,
                                                                     resources=("RETAINED_OWNER",))})
        result = engine.run()
        self.assertEqual(len(calls), 1)
        self.assertNotEqual(result["state"], "COMPLETED")
        self.assertIn("RECOVERY_UNCONFIRMED", {row["state"] for row in result["nodes"]})

    def test_pause_drains_current_call_and_explicit_resume_preserves_completed_node(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def execute(ctx, inputs, parameters):
            calls.append(ctx.node_id)
            if ctx.node_id == "first":
                entered.set()
                self.assertTrue(release.wait(3))
            return outcome(ctx)
        catalog = {"read": adapter("read", execute),
                   "consume": adapter("consume", execute, inputs={"input": PortSpec(("REPORT",))})}
        engine, _store = self.engine(workflow([{"node_id": "first", "tool_id": "read"},
            {"node_id": "next", "tool_id": "consume"}], [edge("first", "next")]), catalog)
        thread, result, errors = self.run_thread(engine)
        try:
            self.assertTrue(entered.wait(3))
            engine.request_pause()
        finally:
            release.set()
        thread.join(timeout=5)
        self.assertEqual(errors, [])
        self.assertEqual(result[0]["state"], "WAITING_FOR_HUMAN")
        self.assertEqual(calls, ["first"])
        preserved = deepcopy(node_records(result[0])["first"])
        resumed = engine.resume()
        self.assertEqual(resumed["state"], "COMPLETED")
        self.assertEqual(calls, ["first", "next"])
        self.assertEqual(node_records(resumed)["first"], preserved)

    def test_cancel_keeps_published_result_and_drains_running_context(self):
        entered = threading.Event()
        def execute(ctx, inputs, parameters):
            if ctx.node_id == "waiting":
                entered.set()
                self.assertTrue(ctx.cancel.wait(3))
                ctx.check()
            return outcome(ctx)
        catalog = {"read": adapter("read", execute),
                   "consume": adapter("consume", execute, inputs={"input": PortSpec(("REPORT",))})}
        engine, _store = self.engine(workflow([{"node_id": "published", "tool_id": "read"},
            {"node_id": "waiting", "tool_id": "consume"}], [edge("published", "waiting")]), catalog)
        thread, result, errors = self.run_thread(engine)
        self.assertTrue(entered.wait(3))
        preserved = deepcopy(node_records(engine.snapshot())["published"])
        engine.request_cancel()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(node_records(result[0])["published"], preserved)
        self.assertNotEqual(result[0]["state"], "COMPLETED")

    def test_repeat_has_distinct_actual_contexts_and_receipts(self):
        contexts = []
        def execute(ctx, inputs, parameters):
            contexts.append((ctx.iteration, ctx.node_run_id))
            return outcome(ctx)
        engine, store = self.engine(workflow([{"node_id": "repeat", "tool_id": "read", "kind": "REPEAT",
            "repeat_count": 3}]), {"read": adapter("read", execute)})
        result = engine.run()
        self.assertEqual(result["state"], "COMPLETED")
        self.assertEqual(len(contexts), 3)
        self.assertEqual(len({value[1] for value in contexts}), 3)
        self.assertEqual(len({value[0] for value in contexts}), 3)
        self.assertGreaterEqual(len(store.read_events()), 6)

    def test_real_receipt_condition_dispatches_only_selected_optional_branch(self):
        calls = []
        def execute(ctx, inputs, params):
            calls.append(ctx.node_id)
            return outcome(ctx)
        definition = workflow([{"node_id": "source", "tool_id": "read"},
            {"node_id": "decision", "kind": "CONDITION", "budget_seconds": 1,
             "parameters": {"condition": {"all": [{"status": "COMPLETED"},
                {"field": "cleanup.confirmed", "value": True}]}}},
            {"node_id": "selected", "tool_id": "consume"},
            {"node_id": "inactive", "tool_id": "consume", "required": False}], [
                edge("source", "decision", port="receipt"), edge("source", "selected"),
                edge("source", "inactive"), edge("decision", "selected", port="true", target="when"),
                edge("decision", "inactive", port="false", target="when")])
        engine, _store = self.engine(definition, {"read": adapter("read", execute),
            "consume": adapter("consume", execute, inputs={"input": PortSpec(("REPORT",))})})
        snapshot = engine.run()
        records = node_records(snapshot)
        self.assertEqual(calls, ["source", "selected"])
        self.assertEqual(snapshot["state"], "COMPLETED")
        self.assertEqual(records["inactive"]["state"], "SKIPPED")
        self.assertFalse(records["inactive"]["execution_started"])
        self.assertIsNone(records["inactive"]["run_receipt"])
        self.assertIsNone(records["decision"]["run_receipt"])
        self.assertEqual(records["decision"]["outputs"]["true"][0]["value"]["basis_artifact_id"],
                         records["source"]["outputs"]["receipt"][0]["artifact_id"])
        self.assertEqual(snapshot["coverage"]["root_cause"], "UNKNOWN")

    def test_unknown_sufficiency_never_selects_a_required_diagnostic_branch(self):
        calls = []
        def execute(ctx, inputs, params):
            calls.append(ctx.node_id)
            return outcome(ctx)
        definition = workflow([{"node_id": "source", "tool_id": "read"},
            {"node_id": "decision", "kind": "CONDITION", "budget_seconds": 1,
             "parameters": {"condition": {"sufficient": True}}},
            {"node_id": "unproved", "tool_id": "consume"}], [
                edge("source", "decision", port="receipt"), edge("source", "unproved"),
                edge("decision", "unproved", port="true", target="when")])
        engine, _store = self.engine(definition, {"read": adapter("read", execute),
            "consume": adapter("consume", execute, inputs={"input": PortSpec(("REPORT",))})})
        snapshot = engine.run()
        records = node_records(snapshot)
        self.assertEqual(calls, ["source"])
        self.assertNotEqual(snapshot["state"], "COMPLETED")
        self.assertEqual(records["decision"]["state"], "PARTIAL")
        self.assertEqual(records["decision"]["outputs"], {})
        self.assertEqual(records["decision"]["reason_code"], "CONDITION_EVIDENCE_UNKNOWN")
        self.assertEqual(records["unproved"]["state"], "SKIPPED")
        self.assertIsNone(records["unproved"]["run_receipt"])

    def test_join_preserves_two_independently_validated_source_references(self):
        definition = workflow([{"node_id": "left", "tool_id": "read"},
            {"node_id": "right", "tool_id": "read"},
            {"node_id": "joined", "kind": "JOIN", "budget_seconds": 1}], [
                edge("left", "joined", target="evidence"), edge("right", "joined", target="evidence")])
        engine, _store = self.engine(definition, {"read": adapter("read", lambda ctx, inputs, params: outcome(ctx))})
        snapshot = engine.run()
        self.assertEqual(snapshot["state"], "COMPLETED")
        records = node_records(snapshot)
        joined = records["joined"]["outputs"]["evidence"][0]
        expected = {records[name]["outputs"]["report"][0]["artifact_id"] for name in ("left", "right")}
        self.assertEqual({item["artifact_id"] for item in joined["value"]["items"]}, expected)
        self.assertEqual(joined["coverage"]["clock_alignment"], "NOT_ESTABLISHED")
        self.assertIsNone(records["joined"]["run_receipt"])

    def test_join_refuses_changed_source_without_erasing_original_completed_metadata(self):
        saved = []
        def execute(ctx, inputs, params):
            result = outcome(ctx)
            if ctx.node_id == "left":
                saved.append(result.outputs["report"])
            else:
                Path(saved[0].value["_path"]).write_text("changed by explicit negative fixture")
            return result
        definition = workflow([{"node_id": "left", "tool_id": "read"},
            {"node_id": "right", "tool_id": "consume"},
            {"node_id": "joined", "kind": "JOIN", "budget_seconds": 1}], [
                edge("left", "right"), edge("left", "joined", target="evidence"),
                edge("right", "joined", target="evidence")])
        engine, _store = self.engine(definition, {"read": adapter("read", execute),
            "consume": adapter("consume", execute, inputs={"input": PortSpec(("REPORT",))})})
        snapshot = engine.run()
        self.assertNotEqual(snapshot["state"], "COMPLETED")
        records = node_records(snapshot)
        self.assertNotEqual(records["joined"]["state"], "COMPLETED")
        self.assertEqual(records["left"]["state"], "COMPLETED")
        self.assertEqual(records["left"]["outputs"]["report"][0], saved[0].to_dict())

    def test_partial_join_requires_explicit_policy_and_keeps_missing_branch_visible(self):
        for allow in (False, True):
            with self.subTest(allow=allow):
                def execute(ctx, inputs, params):
                    result = outcome(ctx, status="OPERATION_FAILED" if ctx.node_id == "failed" else "COMPLETED")
                    if ctx.node_id == "failed":
                        result.outputs = {}
                    return result
                definition = workflow([{"node_id": "kept", "tool_id": "read"},
                    {"node_id": "failed", "tool_id": "read"},
                    {"node_id": "joined", "kind": "JOIN", "budget_seconds": 1,
                     "parameters": {"mode": "ALLOW_PARTIAL" if allow else "ALL_REQUIRED"}}], [
                        edge("kept", "joined", target="evidence"), edge("failed", "joined", target="evidence")])
                engine, _store = self.engine(definition, {"read": adapter("read", execute)})
                snapshot = engine.run()
                records = node_records(snapshot)
                self.assertNotEqual(snapshot["state"], "COMPLETED")
                if allow:
                    self.assertEqual(records["joined"]["state"], "PARTIAL")
                    value = records["joined"]["outputs"]["evidence"][0]
                    self.assertTrue(value["value"]["partial_branches"])
                    self.assertEqual(value["coverage"]["completeness"], "PARTIAL")
                    self.assertEqual(len(value["value"]["items"]), 1)
                else:
                    self.assertEqual(records["joined"]["state"], "SKIPPED")
                    self.assertEqual(records["joined"]["outputs"], {})
                self.assertEqual(records["kept"]["state"], "COMPLETED")

    def test_runtime_finalizer_requires_actual_ack_and_preserves_its_reported_failure(self):
        for confirmed, status in ((True, "COMPLETED"), (False, "COMPLETED"), (True, "OPERATION_FAILED")):
            with self.subTest(confirmed=confirmed, status=status):
                calls = []
                ack = {"confirmed": confirmed, "status": "CONFIRMED" if confirmed else "RECOVERY_UNCONFIRMED",
                       "scope": "EXPLICIT_UNIT_BOUNDARY_NOT_NATIVE_ACCEPTANCE"}
                def finish(ctx):
                    calls.append(ctx.run_id)
                    return {"status": status, "cleanup": ack}
                engine, store = self.engine(workflow([{"node_id": "read", "tool_id": "read"}]),
                    {"read": adapter("read", lambda ctx, inputs, params: outcome(ctx))},
                    runtime=SimpleNamespace(finish_run=finish))
                snapshot = engine.run()
                self.assertEqual(calls, [store.run_id])
                if confirmed and status == "COMPLETED":
                    self.assertEqual(snapshot["state"], "COMPLETED")
                    self.assertTrue(snapshot["cleanup"]["confirmed"])
                else:
                    self.assertNotEqual(snapshot["state"], "COMPLETED")
                cleanup_events = [event for event in store.read_events() if event.get("event") == "run.cleanup"]
                self.assertEqual(len(cleanup_events), 1)
                self.assertNotIn("run_receipt", cleanup_events[0]["data"])

    def test_complete_component_with_missing_or_wrong_output_cannot_be_success(self):
        for mode in ("missing", "wrong-type", "not-executed"):
            with self.subTest(mode=mode):
                def execute(ctx, inputs, params):
                    result = outcome(ctx, execution_started=mode != "not-executed")
                    if mode == "missing":
                        result.outputs = {}
                    elif mode == "wrong-type":
                        result.outputs = {"report": Artifact("BOOLEAN", {"value": True})}
                    return result
                engine, _store = self.engine(workflow([{"node_id": "read", "tool_id": "read"}]),
                    {"read": adapter("read", execute)})
                snapshot = engine.run()
                self.assertNotEqual(snapshot["state"], "COMPLETED")
                self.assertEqual(node_records(snapshot)["read"]["component_status"], "COMPLETED")

    def test_repeat_pause_and_resume_never_replays_the_completed_invocation(self):
        invocations = []
        def execute(ctx, inputs, params):
            invocations.append((ctx.iteration, ctx.node_run_id))
            return outcome(ctx)
        engine, store = self.engine(workflow([{"node_id": "repeat", "tool_id": "read", "kind": "REPEAT",
            "repeat_count": 3, "repeat_interval_seconds": .05}]), {"read": adapter("read", execute)})
        def progress(snapshot):
            if len(invocations) == 1 and node_records(snapshot)["repeat"]["iterations_completed"] == 1:
                engine.request_pause()
        first = engine.run(on_event=progress)
        self.assertEqual(first["state"], "WAITING_FOR_HUMAN")
        self.assertEqual(len(invocations), 1)
        completed = invocations[0]
        resumed = engine.resume()
        self.assertEqual(resumed["state"], "COMPLETED")
        self.assertEqual([iteration for iteration, _run_id in invocations], [0, 1, 2])
        self.assertEqual(invocations[0], completed)
        results = [event["data"] for event in store.read_events() if event.get("event") == "node.result"]
        self.assertEqual(len(results), 3)
        self.assertEqual(len({row["node_run_id"] for row in results}), 3)
        self.assertEqual({row["iteration"] for row in results}, {0, 1, 2})

    def test_unavailable_tool_cannot_become_success_without_execution(self):
        calls = []
        tool = adapter("unavailable", lambda ctx, inputs, params: calls.append(ctx.node_id), available=False)
        engine, _store = self.engine(workflow([{"node_id": "absent", "tool_id": "unavailable"}]),
                                     {"unavailable": tool})
        result = engine.run()
        self.assertEqual(calls, [])
        self.assertNotEqual(result["state"], "COMPLETED")

    def test_component_exception_keeps_primary_reason_and_original_receipt(self):
        original = []
        def execute(ctx, inputs, params):
            receipt = outcome(ctx, status="OPERATION_FAILED").receipt
            original.append(deepcopy(receipt))
            error = ValueError("EXPLICIT_FIXTURE_SOURCE_LIMIT")
            error.run_receipt = receipt
            error.actual_result_bytes = 2048
            error.result_byte_limit = 1024
            error.reserved_result_bytes = "untrusted string is not a measured counter"
            raise error
        engine, store = self.engine(workflow([{"node_id": "read", "tool_id": "read"}]),
            {"read": adapter("read", execute)})
        snapshot = engine.run()
        row = node_records(snapshot)["read"]
        self.assertEqual(row["state"], "FAILED")
        self.assertEqual(row["reason_code"], "EXPLICIT_FIXTURE_SOURCE_LIMIT")
        self.assertEqual(row["run_receipt"], original[0])
        self.assertEqual(row["component_status"], "OPERATION_FAILED")
        self.assertEqual(row["component_failure_details"], {"actual_result_bytes": 2048, "result_byte_limit": 1024})
        persisted = [event["data"] for event in store.read_events() if event.get("event") == "node.result"]
        self.assertEqual(persisted[0]["reason_code"], row["reason_code"])
        self.assertEqual(persisted[0]["run_receipt"], original[0])
        self.assertEqual(persisted[0]["component_failure_details"], row["component_failure_details"])


if __name__ == "__main__":
    unittest.main()
