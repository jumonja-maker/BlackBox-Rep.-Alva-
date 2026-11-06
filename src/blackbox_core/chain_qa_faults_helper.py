"""Real hosted helper-crash oracle for R60; no fabricated product answers.

Only the broker-returned helper is paused and terminated. Its actual request is
written while every observed helper thread holds one QA-owned suspension, so no
reply can race ahead of the crash. This proves loss of the reply for a dispatched
request; it does not claim that the requested native query executed.
"""
from __future__ import annotations

from copy import deepcopy
import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
import time

from .chain_qa import (definition, file_hash, independent_journal, link, require,
                       require_hosted_windows, save, source_proof)


_RETAINED_THREAD_OWNERS = []


def _kernel():
    kernel = C.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    for name, arguments, result in (
        ("OpenThread", [W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
        ("GetProcessIdOfThread", [W.HANDLE], W.DWORD),
        ("GetThreadTimes", [W.HANDLE] + [C.POINTER(W.FILETIME)] * 4, W.BOOL),
        ("SuspendThread", [W.HANDLE], W.DWORD),
        ("ResumeThread", [W.HANDLE], W.DWORD),
        ("WaitForSingleObject", [W.HANDLE, W.DWORD], W.DWORD),
        ("CloseHandle", [W.HANDLE], W.BOOL),
        ("GetHandleInformation", [W.HANDLE, C.POINTER(W.DWORD)], W.BOOL),
    ):
        method = getattr(kernel, name)
        method.argtypes, method.restype = arguments, result
    return kernel


def _thread_birth(kernel, handle):
    created, exited, system, user = (W.FILETIME() for _ in range(4))
    require(kernel.GetThreadTimes(handle, C.byref(created), C.byref(exited),
                                  C.byref(system), C.byref(user)),
            "R60_CRASH_QA_THREAD_BIRTH_QUERY_FAILED")
    return (created.dwHighDateTime << 32) | created.dwLowDateTime


def _handle_open(kernel, handle):
    flags = W.DWORD()
    C.set_last_error(0)
    ok = bool(kernel.GetHandleInformation(handle, C.byref(flags)))
    return ok, 0 if ok else C.get_last_error()


class _OwnedHelperHold:
    """Suspend exactly one increment per held thread capability of our helper."""

    def __init__(self, kernel, service, owner, identity):
        self.kernel, self.service = kernel, service
        self.owner, self.identity = owner, identity
        self.rows = []
        self.proof = {"scope": "EXACT_BROKER_OWNED_HELPER_THREADS_ONLY", "thread_count": 0,
                      "own_suspensions_restored_or_threads_exited": False,
                      "thread_handles_closed": False}

    def pause(self):
        import psutil
        require(self.service.helper is self.owner and self.owner.alive() and
                self.service.identity(self.owner.pid) == self.identity,
                "R60_CRASH_QA_FOREIGN_HELPER_REFUSED")
        threads = psutil.Process(self.owner.pid).threads()
        require(0 < len(threads) <= 32, "R60_CRASH_QA_HELPER_THREAD_BUDGET")
        for thread in threads:
            handle = self.kernel.OpenThread(0x2 | 0x800 | 0x100000, False, thread.id)
            require(bool(handle), "R60_CRASH_QA_THREAD_CAPABILITY_UNAVAILABLE")
            row = {"handle": handle, "tid": thread.id, "suspended": False}
            self.rows.append(row)
            require(self.kernel.GetProcessIdOfThread(handle) == self.owner.pid,
                    "R60_CRASH_QA_THREAD_OWNER_CHANGED")
            row["created_100ns"] = _thread_birth(self.kernel, handle)
            previous = self.kernel.SuspendThread(handle)
            require(previous != 0xFFFFFFFF, "R60_CRASH_QA_SUSPEND_FAILED")
            row["suspended"] = True
            require(previous == 0 and _thread_birth(self.kernel, handle) == row["created_100ns"],
                    "R60_CRASH_QA_FOREIGN_SUSPENSION_OR_CHANGED_THREAD")
        observed = {thread.id for thread in psutil.Process(self.owner.pid).threads()}
        require(observed == {row["tid"] for row in self.rows} and self.owner.alive() and
                self.service.identity(self.owner.pid) == self.identity,
                "R60_CRASH_QA_HELPER_THREADS_CHANGED_DURING_PAUSE")
        self.proof.update(thread_count=len(self.rows), prior_suspend_counts_all_zero=True,
                          thread_set_stable=True, exact_helper_identity_verified=True)

    def close(self):
        errors = []
        for row in list(self.rows):
            try:
                exited = self.kernel.WaitForSingleObject(row["handle"], 0)
                require(exited in (0, 258), "R60_CRASH_QA_THREAD_EXIT_QUERY_FAILED")
                if row["suspended"] and exited == 258:
                    previous = self.kernel.ResumeThread(row["handle"])
                    require(previous != 0xFFFFFFFF and previous > 0,
                            "R60_CRASH_QA_OWN_SUSPENSION_RELEASE_UNCONFIRMED")
                row["suspended"] = False
                require(self.kernel.CloseHandle(row["handle"]),
                        "R60_CRASH_QA_THREAD_HANDLE_CLOSE_UNCONFIRMED")
                self.rows.remove(row)
            except BaseException as error:
                errors.append(type(error).__name__ + ":" + str(error)[:160])
        if errors:
            if self not in _RETAINED_THREAD_OWNERS:
                _RETAINED_THREAD_OWNERS.append(self)
            raise OSError("R60_CRASH_QA_THREAD_OWNER_RETAINED: " + ";".join(errors))
        if self in _RETAINED_THREAD_OWNERS:
            _RETAINED_THREAD_OWNERS.remove(self)
        self.proof.update(own_suspensions_restored_or_threads_exited=True, thread_handles_closed=True)


def helper_crash_graph(output, executable, source_sha, diagnostic_helper=None, *, trace_path):
    """Run the real graph, crash its own helper, and inspect persisted recovery."""
    require_hosted_windows()
    require(not _RETAINED_THREAD_OWNERS, "R60_CRASH_QA_PREVIOUS_THREAD_OWNER_RETAINED")
    identity_proof = source_proof(source_sha)
    from .chain_adapters import ChainRuntime, build_catalog
    from .chain_engine import WorkflowEngine
    from .chain_store import WorkflowRunStore
    from .chain_validation import validate_workflow
    from .chain_qa_native import OwnedWaveProbe
    from .deep_service import InspectorService
    from .optional_jobs import OwnedProcess

    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    trace = Path(trace_path).resolve(strict=True)
    trace_sha = file_hash(trace)
    kernel = _kernel()
    fixture = service = hold = None
    helper_owner = channel = recovery_stream = None
    launches, close_proofs, sends = [], [], []
    injected, receive_attempts = False, 0
    primary = None
    proof = {"schema": "blackbox.r60.helper-crash-qa/1", "status": "FAIL",
             "source_sha": source_sha, "source_identity": identity_proof,
             "fault_scope": "REAL_REQUEST_SENT_WHILE_OWNED_HELPER_THREADS_SUSPENDED_THEN_HELPER_TERMINATED",
             "native_query_execution": "NOT_ESTABLISHED", "root_cause": "UNKNOWN",
             "physical_secure_desktop": "NOT_TESTED"}

    def checked_close(label, original, capability):
        require(capability is not None and _handle_open(kernel, capability)[0],
                "R60_CRASH_QA_PRODUCT_HANDLE_NOT_OBSERVED_OPEN")
        result = original()
        opened, error = _handle_open(kernel, capability)
        require(opened is False and error == 6,
                "R60_CRASH_QA_PRODUCT_" + label.upper() + "_HANDLE_CLOSE_NOT_OBSERVED")
        close_proofs.append({"resource": label, "opened_before": True, "invalid_handle_after": True,
                             "post_close_winerror": error})
        return result

    try:
        fixture = OwnedWaveProbe(Path(executable), output / "target")
        service = InspectorService(output / "native-journal", helper_executable=diagnostic_helper)
        production_launch = service.broker.launch

        def launch(arguments, *, elevated=False):
            nonlocal helper_owner
            require(not launches, "R60_CRASH_QA_UNEXPECTED_HELPER_RELAUNCH")
            owner = production_launch(arguments, elevated=elevated)
            helper_owner = owner
            launches.append({"pid": owner.pid, "elevated": elevated})
            close = owner.close_handle
            def close_handle():
                capability = (owner.handle if owner.handle is not None else
                              int(owner.process._handle) if owner.process is not None else None)
                return checked_close("helper_process", close, capability)
            owner.close_handle = close_handle
            return owner
        service.broker.launch = launch
        production_start = service._start_session

        def start_session(*args, **kwargs):
            nonlocal channel, recovery_stream
            answer = production_start(*args, **kwargs)
            if answer.get("status") != "COMPLETED":
                return answer
            channel, recovery_stream = service._channel, service._recovery_stream
            production_send, production_receive, production_close = channel.send, channel.receive, channel.close

            def send(message, **options):
                nonlocal injected, hold
                if message.get("kind") == "execute":
                    require(not injected and message.get("request", {}).get("operation") == "modules" and
                            service.helper is helper_owner, "R60_CRASH_QA_UNEXPECTED_NATIVE_DISPATCH")
                    observed = service.identity(helper_owner.pid)
                    hold = _OwnedHelperHold(kernel, service, helper_owner, observed)
                    hold.pause()
                    production_send(message, **options)
                    sends.append({"request_id": message["request_id"], "operation": "modules",
                                  "helper_identity": observed.to_dict(), "sent_monotonic_ns": time.monotonic_ns()})
                    injected = True
                    helper_owner.terminate()
                    require(helper_owner.wait_for_exit(timeout_ms=5000) is True and not helper_owner.alive(),
                            "R60_CRASH_QA_EXACT_HELPER_EXIT_UNCONFIRMED")
                    hold.close()
                    return
                return production_send(message, **options)

            def receive(**options):
                nonlocal receive_attempts
                if injected:
                    receive_attempts += 1
                return production_receive(**options)

            def close_channel():
                return checked_close("pipe", production_close, channel.handle)

            channel.send, channel.receive, channel.close = send, receive, close_channel
            return answer
        service._start_session = start_session
        workflow = definition([
            {"node_id": "ordinary", "tool_id": "load_source", "budget_seconds": 10,
             "parameters": {"kind": "TRACE", "path": str(trace)}},
            {"node_id": "ordinary-complete", "kind": "CONDITION", "budget_seconds": 1,
             "parameters": {"condition": {"status": "COMPLETED"}}},
            {"node_id": "target", "tool_id": "process_select", "budget_seconds": 5,
             "parameters": {"pid": fixture.process.pid}},
            {"node_id": "helper-query", "tool_id": "deep.modules", "budget_seconds": 20}], [
                link("ordinary", "receipt", "ordinary-complete", "input"),
                link("ordinary-complete", "true", "target", "when"),
                link("target", "process", "helper-query", "process")],
            identity="helper-crash", seconds=90, workers=2)
        runtime = ChainRuntime(inspector=service)
        catalog = build_catalog(runtime)
        require(validate_workflow(workflow, catalog, runtime=runtime).get("ready") is True,
                "R60_CRASH_QA_GRAPH_PREFLIGHT_FAILED")
        store = WorkflowRunStore.create(output / "runs", workflow)
        snapshot = WorkflowEngine(workflow, catalog=catalog, store=store, runtime=runtime).run()
        rows = {row["node_id"]: row for row in snapshot["nodes"]}
        require(injected and len(launches) == len(sends) == 1 and receive_attempts >= 1,
                "R60_CRASH_QA_REAL_SEND_CRASH_AND_RECEIVE_NOT_OBSERVED")
        require(snapshot["state"] != "COMPLETED" and rows["ordinary"]["state"] == "COMPLETED" and
                rows["helper-query"]["state"] in ("FAILED", "RECOVERY_UNCONFIRMED") and
                rows["helper-query"]["run_receipt"]["execution_started"] is None and
                rows["helper-query"]["run_receipt"]["cleanup"]["confirmed"] is not True,
                "R60_CRASH_QA_LOST_REPLY_WAS_FALSELY_CONFIRMED")
        previous = deepcopy({row["node_id"]: row for row in store.load_state()["nodes"]}["ordinary"])
        records, journal = independent_journal(store.folder)
        native_results = [event["data"] for event in records if event.get("event") == "node.result" and
                          event.get("node_id") == "helper-query"]
        require(len(native_results) == 1 and native_results[0]["run_receipt"]["operation"] == "modules" and
                native_results[0]["run_receipt"]["run_id"] == sends[0]["request_id"],
                "R60_CRASH_QA_DURABLE_REAL_REQUEST_BINDING_FAILED")
        restored = WorkflowEngine.restore(WorkflowRunStore.open(store.folder), catalog=catalog, runtime=runtime)
        resumed = restored.resume()
        require(resumed["state"] != "COMPLETED" and len(launches) == len(sends) == 1 and
                {row["node_id"]: row for row in resumed["nodes"]}["ordinary"] == previous and
                independent_journal(store.folder)[1]["sha256"] == journal["sha256"] and
                file_hash(trace) == trace_sha, "R60_CRASH_QA_RECOVERY_RETRIED_OR_CHANGED_COMPLETED_SOURCE")
        proof.update(status="PASS", graph_state=snapshot["state"], recovery_state=resumed["state"],
            actual_request=sends[0], launches=launches, real_receive_attempts=receive_attempts,
            source_sha256=trace_sha, source_unchanged=True, completed_branch_unchanged=True,
            automatic_retry_count=0, journal=journal, helper_exit_observed=True,
            query_receipt_status=native_results[0]["run_receipt"]["status"],
            query_execution_started=native_results[0]["run_receipt"]["execution_started"],
            query_cleanup_confirmed=native_results[0]["run_receipt"]["cleanup"]["confirmed"])
    except BaseException as error:
        primary = error
        proof.update(status="FAIL", error=type(error).__name__, reason=str(error)[:1200])
        raise
    finally:
        cleanup_errors = []
        if hold is not None and hold.rows:
            try:
                hold.close()
            except BaseException as error:
                cleanup_errors.append("QA_THREAD_OWNER:" + str(error)[:180])
        if service is not None:
            try:
                proof["service_close"] = service.close()
                require(service.helper is None and service._channel is None and
                        recovery_stream is not None and recovery_stream.closed and
                        {row["resource"] for row in close_proofs} == {"helper_process", "pipe"},
                        "R60_CRASH_QA_PRODUCT_OWNED_RESOURCES_NOT_RELEASED")
            except BaseException as error:
                cleanup_errors.append("PRODUCT_OWNER:" + str(error)[:180])
        if fixture is not None:
            try:
                proof["target_cleanup"] = fixture.close(kill=proof["status"] != "PASS")
                require(proof["status"] != "PASS" or proof["target_cleanup"]["status"] == "COMPLETED",
                        "R60_CRASH_QA_TARGET_CLEANUP_UNCONFIRMED")
            except BaseException as error:
                cleanup_errors.append("TARGET_OWNER:" + str(error)[:180])
        proof.update(product_handle_close_observations=close_proofs,
                     qa_thread_cleanup=hold.proof if hold is not None else None)
        if OwnedProcess.pending_cleanup() or _RETAINED_THREAD_OWNERS:
            cleanup_errors.append("RETAINED_OWNED_RESOURCES")
        if cleanup_errors:
            proof.update(status="FAIL", cleanup_errors=cleanup_errors)
        save(output / "result.json", proof)
        if cleanup_errors:
            if primary is not None:
                primary.add_note("R60_CRASH_QA_CLEANUP_NOT_CONFIRMED: " + ";".join(cleanup_errors))
            else:
                raise AssertionError("R60_CRASH_QA_CLEANUP_NOT_CONFIRMED: " + ";".join(cleanup_errors))
    require(proof["status"] == "PASS", "R60_CRASH_QA_NOT_ESTABLISHED")
    return proof
