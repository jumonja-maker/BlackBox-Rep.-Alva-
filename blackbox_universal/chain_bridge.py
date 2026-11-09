"""Qt boundary for the R60 engine, existing recorder and single R10 owner.

Only this QObject touches widgets. Files, validation, identity reads and engine
execution stay in workers. Runtime consent packets are never persisted.
"""
from __future__ import annotations

from copy import deepcopy
from itertools import islice
import os
from pathlib import Path
import queue
import threading
import time
from uuid import uuid4

from PySide6.QtCore import QObject, QThread, QTimer, Signal, Qt
from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QFormLayout, QLineEdit,
                              QMessageBox, QVBoxLayout)


class _RuntimeUnconfirmed(RuntimeError):
    status = "RECOVERY_UNCONFIRMED"
    cleanup_required = True


class _ChainTask(QThread):
    result_ready = Signal(str, object, str)
    progress_available = Signal()

    def __init__(self, bridge, operation, arguments):
        super().__init__(bridge)
        self.bridge, self.operation, self.arguments = bridge, operation, arguments
        self.engine = None
        self.cancel_event = threading.Event()
        self._progress_lock = threading.Lock()
        self._latest_progress = None
        self._progress_wake_pending = False
        self._progress_closed = False

    def publish_snapshot(self, snapshot):
        """Retain one latest immutable snapshot and at most one tiny Qt wake.

        The engine passes an independent snapshot; individual receipts remain
        durable in its journal. A stalled GUI must not accumulate full copies
        of every intermediate progress state in the Qt event queue.
        """
        with self._progress_lock:
            if self._progress_closed:
                return
            self._latest_progress = snapshot
            if self._progress_wake_pending:
                return
            self._progress_wake_pending = True
        self.progress_available.emit()

    def take_snapshot(self):
        with self._progress_lock:
            latest = self._latest_progress
            self._latest_progress = None
            self._progress_wake_pending = False
            return latest

    def close_progress(self):
        """The full terminal result supersedes any pending progress wake."""
        with self._progress_lock:
            self._progress_closed = True
            self._latest_progress = None
            self._progress_wake_pending = False

    def run(self):
        store = None
        try:
            from blackbox_core.chain_adapters import build_catalog
            from blackbox_core.chain_contracts import WorkflowDefinition, NodeDefinition, control_ports
            from blackbox_core.chain_validation import validate_workflow, get_ports
            runtime = self.bridge.runtime()
            catalog = build_catalog(runtime)
            args, operation = self.arguments, self.operation
            if operation == "catalog":
                controls = {}
                for kind in ("CONDITION", "JOIN", "CHECKPOINT"):
                    inputs, outputs = control_ports(kind)
                    controls[kind] = {"inputs": {k: v.to_dict() for k, v in inputs.items()},
                                      "outputs": {k: v.to_dict() for k, v in outputs.items()}}
                answer = {"tools": {k: v.to_dict() for k, v in catalog.items()}, "controls": controls}
            elif operation == "history":
                from blackbox_core.chain_store import WorkflowRunStore
                answer = []
                root = Path(args["root"])
                if root.is_dir():
                    # Bounded scan; a malformed folder never hides good runs.
                    for folder in sorted(islice(root.iterdir(), 500), key=lambda p: p.name, reverse=True):
                        if not folder.is_dir() or folder.is_symlink():
                            continue
                        try:
                            with WorkflowRunStore.open(folder) as past:
                                state = past.load_state()
                                answer.append({"folder": str(folder), "run_id": past.run_id,
                                    "title": past.definition.title, "state": state.get("state", "UNKNOWN")})
                        except (OSError, ValueError, KeyError):
                            continue
                        if len(answer) >= 100:
                            break
            elif operation in ("open", "open_run"):
                from blackbox_core.chain_store import WorkflowRunStore, load_definition
                if operation == "open_run":
                    store = WorkflowRunStore.open(args["path"])
                    answer = {"definition": store.definition.to_dict(), "snapshot": store.load_state(),
                              "folder": str(store.folder)}
                else:
                    definition = load_definition(args["path"])
                    answer = {"definition": definition.to_dict()}
            elif operation == "export":
                from blackbox_core.chain_store import WorkflowRunStore
                from blackbox_core.chain_reports import export_workflow_run
                store = WorkflowRunStore.open(args["folder"])
                answer = export_workflow_run(store,
                    args["path"], format=args["format"], cancel=self.cancel_event)
            else:
                document = deepcopy(args["definition"])
                if operation == "connect":
                    edge = args["edge"]
                    nodes = {n["node_id"]: n for n in document["nodes"]}
                    source, target = nodes[edge["source_node"]], nodes[edge["target_node"]]
                    def ports(node, side):
                        return get_ports(NodeDefinition.from_dict(node), catalog)[0 if side == "inputs" else 1]
                    output = ports(source, "outputs")[edge["source_port"]]
                    incoming = ports(target, "inputs")[edge["target_port"]]
                    if not set(output.types) <= set(incoming.types):
                        raise ValueError("INCOMPATIBLE_PORT_TYPES: " + ",".join(output.types) + " → " + ",".join(incoming.types))
                    if source["node_id"] == target["node_id"]:
                        raise ValueError("WORKFLOW_CYCLE")
                    if any(e["target_node"] == edge["target_node"] and e["target_port"] == edge["target_port"]
                           for e in document["edges"]) and not incoming.many:
                        raise ValueError("INPUT_ALREADY_CONNECTED")
                    downstream = {}
                    for existing in document["edges"]:
                        downstream.setdefault(existing["source_node"], []).append(existing["target_node"])
                    pending, visited = [target["node_id"]], set()
                    while pending:
                        current = pending.pop()
                        if current == source["node_id"]:
                            raise ValueError("WORKFLOW_CYCLE")
                        if current not in visited:
                            visited.add(current)
                            pending.extend(downstream.get(current, ()))
                    document["edges"].append(edge)
                definition = WorkflowDefinition.from_dict(document)
                if operation in ("validate", "connect"):
                    answer = {"definition": definition.to_dict(),
                              "validation": validate_workflow(definition, catalog, runtime=runtime)}
                elif operation == "save":
                    from blackbox_core.chain_store import save_definition
                    save_definition(definition, args["path"])
                    answer = {"path": args["path"], "definition": definition.to_dict()}
                elif operation in ("save_profile", "open_profile"):
                    from blackbox_core.chain_profiles import save_profile, load_profile
                    if operation == "open_profile":
                        profile = load_profile(args["path"])
                        document["profile"] = {key: value for key, value in profile.items() if key != "schema"}
                        if document["profile"].get("inherits") is None:
                            document["profile"].pop("inherits", None)
                        definition = WorkflowDefinition.from_dict(document)
                    validation = validate_workflow(definition, catalog, runtime=runtime)
                    if operation == "save_profile":
                        save_profile(definition.profile, args["path"])
                    answer = {"definition": definition.to_dict(), "validation": validation, "path": args["path"]}
                elif operation in ("start", "resume", "cancel_saved_run"):
                    from blackbox_core.chain_store import WorkflowRunStore
                    from blackbox_core.chain_engine import WorkflowEngine
                    if operation == "start":
                        validation = validate_workflow(definition, catalog, runtime=runtime)
                        if not validation.get("ready"):
                            self.result_ready.emit("validate", {"definition": definition.to_dict(), "validation": validation}, "")
                            raise ValueError("WORKFLOW_NOT_READY")
                        store = WorkflowRunStore.create(args["root"], definition)
                        self.engine = WorkflowEngine(definition, catalog=catalog, store=store, runtime=runtime)
                    else:
                        store = WorkflowRunStore.open(args["folder"])
                        if operation == "resume" and definition.fingerprint != store.definition.fingerprint:
                            raise ValueError("WORKFLOW_DEFINITION_CHANGED_REOPEN_SAVED_RUN")
                        self.engine = WorkflowEngine.restore(store, catalog=catalog, runtime=runtime)
                    if self.cancel_event.is_set() or operation == "cancel_saved_run":
                        self.engine.request_cancel()
                    self.publish_snapshot({"run_id": store.run_id, "folder": str(store.folder), "state": "QUEUED", "nodes": []})
                    if operation in ("resume", "cancel_saved_run"):
                        answer = self.engine.resume(on_event=self.publish_snapshot)
                    else:
                        answer = self.engine.run(on_event=self.publish_snapshot)
                    answer = dict(answer, folder=str(store.folder))
                else:
                    raise ValueError("UNKNOWN_CHAIN_GUI_OPERATION")
            self.close_progress()
            self.result_ready.emit(operation, answer, "")
        except Exception as error:
            self.close_progress()
            self.result_ready.emit(self.operation, None, str(getattr(error, "code", error))[:1500])
        finally:
            if store is not None:
                store.close()


class ChainBuilderBridge(QObject):
    result_ready = Signal(str, object, str)
    snapshot_changed = Signal(object)
    busy_changed = Signal(bool)
    human_required = Signal(object)
    closed = Signal()
    _human_request = Signal(object)
    _native_request = Signal(object)
    _research_request = Signal(object)
    _native_cancel = Signal(str)
    _finalize_request = Signal(object)

    def __init__(self, window, root):
        super().__init__(window)
        self.window, self.root = window, Path(root)
        self.worker = None
        self._closing = False
        self._requests = {}
        self._native = None
        self._research = {}
        self._observe_owner = None
        self._observe_cleanup_unknown = False
        self._confirmed = {}
        self._selection = None
        self._owned_session_run_id = None
        self._native_contexts = {}
        self._finalizing = None
        self._seed = {}
        self._paused_run = None
        self._paused_runs = {}
        self._close_cleanup_attempted = set()
        self._human_request.connect(self._ask_identity)
        self._native_request.connect(self._dispatch_native)
        self._research_request.connect(self._dispatch_research)
        self._native_cancel.connect(self._cancel_own_native)
        self._finalize_request.connect(self._dispatch_finalize)
        deep = window.deep_inspector_panel.bridge
        deep.owned_result_ready.connect(self._native_result)
        deep.busy_changed.connect(self._native_idle)
        deep.idle.connect(self._native_idle)
        deep.recovery_required.connect(self._native_idle)
        deep.target_changed.connect(self._target_changed)
        probe = window.probe
        if hasattr(probe, "command_result"):
            probe.command_result.connect(self._research_result)
            probe.updated.connect(self._research_updated)
        self._poll = QTimer(self)
        self._poll.setInterval(100)
        self._poll.timeout.connect(self._expire_requests)
        self._poll.start()

    @property
    def busy(self):
        return self.worker is not None

    def submit(self, operation, **arguments):
        if self.busy or self._closing and operation != "cancel_saved_run":
            return False
        self._seed = {"pid": self.window.probe.pid}
        worker = _ChainTask(self, operation, deepcopy(arguments))
        if operation == "start":
            self._paused_run = None
        self.worker = worker
        worker.result_ready.connect(self._receive)
        worker.progress_available.connect(self._progress_ready, Qt.ConnectionType.QueuedConnection)
        worker.finished.connect(self._finished)
        self.busy_changed.emit(True)
        worker.start()
        return True

    def _progress_ready(self):
        worker = self.sender()
        if not isinstance(worker, _ChainTask):
            return
        latest = worker.take_snapshot()
        if worker is self.worker and latest is not None:
            self.snapshot_changed.emit(latest)

    def runtime(self):
        """Called by the worker, never reads Qt objects or live widget state."""
        from blackbox_core.chain_adapters import ChainRuntime
        native = os.name == "nt"
        return ChainRuntime(native_call=self.native_call if native else None,
                            process_select=self.process_select if native else None,
                            observe_call=self.observe_call if native else None,
                            session_finalize=self.session_finalize if native else None,
                            finish_run=self.finish_run if native else None,
                            owned_session_run_id=self._owned_session_run_id, output_root=self.root)

    def _exchange(self, signal, packet, *, context=None, cleanup=False):
        packet = dict(packet, request_id=uuid4().hex, event=threading.Event(), response=None,
                      phases=queue.SimpleQueue(),
                      expires=time.monotonic() + (100 if cleanup else max(1, context.remaining_seconds()) if context else 30))
        signal.emit(packet)
        cancelled = False
        while not packet["event"].wait(.05):
            while not packet["phases"].empty():
                phase = packet["phases"].get()
                if context is not None:
                    if phase == "RUNNING":
                        context.running()
                    else:
                        context.waiting_for_human({"operation": packet.get("operation", "diagnostic"), "reason": phase})
            if context is not None and context.cancel.is_set() and not cleanup and not cancelled:
                cancelled = True
                self._native_cancel.emit(packet["request_id"])
            if time.monotonic() > packet["expires"] + 3:
                raise _RuntimeUnconfirmed("WORKFLOW_RUNTIME_RESPONSE_UNCONFIRMED")
        response = packet["response"]
        if isinstance(response, Exception):
            raise response
        return response

    def session_finalize(self, ctx):
        return self._exchange(self._finalize_request, {"operation": "session_finalize", "context": ctx,
            "tag": "chain:" + ctx.run_id + ":finalize:" + uuid4().hex},
                              context=ctx, cleanup=True)

    def finish_run(self, ctx):
        """Drain our actual native request before checking its cleanup boundary.

        Ownership may become known only in a late native result after a node
        timeout. The GUI retains that request until its worker has drained.
        This callback never adopts or closes another diagnostic owner's scope.
        """
        return self._exchange(self._finalize_request, {"operation": "finish_run", "context": ctx,
            "tag": "chain:" + ctx.run_id + ":finish:" + uuid4().hex}, context=ctx, cleanup=True)

    def process_select(self, pid, ctx):
        from blackbox_core.deep_native import capture_identity_checked
        pid = pid or self._seed.get("pid")
        if not pid:
            raise ValueError("CHOOSE_PROCESS_IN_OVERVIEW_FIRST")
        identity = capture_identity_checked(int(pid), owner_run_id=ctx.run_id).to_dict()
        ctx.waiting_for_human({"operation": "process_select", "target": identity})
        approved = self._exchange(self._human_request, {"operation": "process_select", "target": identity,
            "context": ctx}, context=ctx)
        if approved is not True:
            raise InterruptedError("PROCESS_SELECTION_DECLINED")
        # Revalidate the native instance after the modal choice.
        if capture_identity_checked(int(pid), owner_run_id=ctx.run_id).to_dict() != identity:
            raise ValueError("PROCESS_IDENTITY_CHANGED")
        ctx.running()
        return identity

    def native_call(self, operation, parameters, target, ctx):
        if hasattr(target, "to_dict"):
            target = target.to_dict()
        ctx.waiting_for_human({"operation": operation, "target": target, "parameters": {
            k: v for k, v in parameters.items() if "hex" not in k}})
        return self._exchange(self._native_request, {"operation": operation, "parameters": dict(parameters),
            "target": target, "context": ctx, "tag": "chain:" + ctx.run_id + ":" + ctx.node_id + ":" + uuid4().hex}, context=ctx)

    def observe_call(self, process, policy, duration, ctx):
        if hasattr(process, "to_dict"):
            process = process.to_dict()
        target = process.get("value", process) if isinstance(process, dict) else process
        if isinstance(target, dict) and "identity" in target:
            target = target["identity"]
        def command(operation, *, cleanup=False, **arguments):
            return self._exchange(self._research_request, {"operation": operation, "arguments": arguments,
                "target": target, "owner": ctx.node_run_id, "context": ctx}, context=ctx, cleanup=cleanup)
        started, attempted_start, execution_status, reason = None, False, None, None
        command("claim")
        try:
            command("attach", pid=target["pid"])
            command("capture_policy", policy=policy)
            attempted_start = True
            started = command("start")
            end = time.monotonic() + duration
            while time.monotonic() < end:
                ctx.check()
                ctx.cancel.wait(min(.1, max(0, end - time.monotonic())))
        except Exception as error:
            if not attempted_start:
                raise
            execution_status = "CANCELLED" if ctx.cancel.is_set() else "TIMED_OUT"
            reason = str(getattr(error, "code", error))[:500]
        finally:
            # Stop belongs to this callback even after node cancellation/deadline.
            if attempted_start:
                stopped = command("stop", cleanup=True, reason="USER_STOPPED")
                if stopped["result"].get("cleanup_required") is False:
                    command("release", cleanup=True)
            else:
                command("release", cleanup=True)
        return {"folder": stopped["snapshot"].get("session_folder"),
                "start_result": (started or {}).get("result"), "stop_result": stopped["result"],
                "snapshot": stopped["snapshot"], "execution_status": execution_status, "reason_code": reason}

    def _is_target(self, identity):
        bridge = self.window.deep_inspector_panel.bridge
        target = bridge.target
        created = (identity.get("created_100ns", 0) - 116444736000000000) / 10000000
        return bool(target and target[0] == identity.get("pid") and target[1] is not None
                    and abs(target[1] - created) <= .000002)

    def _reply(self, packet, value):
        if packet["event"].is_set():
            return
        packet["response"] = value
        packet["event"].set()
        self._requests.pop(packet["request_id"], None)
        if packet.get("tag"):
            self.window.deep_inspector_panel.release_investigation_guard(packet["tag"])
        if packet.get("operation") in ("process_select", "session_finalize", "finish_run") or packet.get("tag"):
            self.human_required.emit({"state": "RUNNING", "operation": packet.get("operation", "process_select")})

    def _remember(self, packet):
        self._requests[packet["request_id"]] = packet
        if self._closing or packet["context"].cancel.is_set():
            self._reply(packet, InterruptedError("WORKFLOW_CANCELLED"))
            return False
        return True

    def _ask_identity(self, packet):
        if not self._remember(packet):
            return
        identity = packet["target"]
        if not self._is_target(identity):
            self._selection = packet
            self.human_required.emit({"state": "WAITING_FOR_HUMAN", "reason": "CHOOSE_PROCESS_THEN_CONTINUE",
                                      "target": identity})
            self.window._navigate("processes")
            return
        self._selection = None
        bridge = self.window.deep_inspector_panel.bridge
        generation = bridge.generation
        ru = self.window.language == "RU"
        text = ("Использовать этот экземпляр для новых измерений цепочки?" if ru else
                "Use this exact process instance for new workflow measurements?")
        text += f"\nPID: {identity['pid']}\nCreation FILETIME: {identity['created_100ns']}\n{identity.get('image_path', '')}"
        text += "\n" + ("Это не подтверждение будущих вмешательств." if ru else "Future interventions require separate confirmation.")
        dialog = QMessageBox(QMessageBox.Icon.Question, "BLACK.BOX", text,
                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, self.window)
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        accepted = dialog.exec() == QMessageBox.StandardButton.Yes
        accepted = accepted and generation == bridge.generation and self._is_target(identity) and not packet["context"].cancel.is_set()
        if accepted:
            self._confirmed[(identity["pid"], identity["created_100ns"])] = generation
        self._reply(packet, accepted)

    def continue_human(self):
        if self._selection is None:
            if self._native is not None and self._native.get("awaiting_owner"):
                packet, self._native = self._native, None
                self.window.deep_inspector_panel.release_investigation_guard(packet["tag"])
                packet["tag"] = "chain:" + packet["context"].run_id + ":" + packet["context"].node_id + ":" + uuid4().hex
                packet["parameters"] = dict(packet["base_parameters"])
                packet.pop("awaiting_owner", None)
                self._dispatch_native(packet)
                return True
            return False
        packet = self._selection
        if packet["event"].is_set():
            self._selection = None
            return False
        self._ask_identity(packet)
        return True

    def _dispatch_native(self, packet):
        if not self._remember(packet):
            return
        panel = self.window.deep_inspector_panel
        identity, bridge = packet["target"], panel.bridge
        key = (identity.get("pid"), identity.get("created_100ns"))
        if (not self._is_target(identity) or self._confirmed.get(key) != bridge.generation):
            self._reply(packet, ValueError("FRESH_PROCESS_CONFIRMATION_REQUIRED"))
            return
        if bridge.busy or self._native is not None:
            self._reply(packet, RuntimeError("DIAGNOSTIC_OWNER_BUSY"))
            return
        packet["generation"] = bridge.generation
        packet.setdefault("base_parameters", {key: value for key, value in packet["parameters"].items()
                                               if "hex" not in key and key != "systemwide_confirmed"})
        if packet["operation"] == "profile.etw":
            # Ephemeral only. The original R10 system-wide ETW dialog below
            # obtains the actual consent before this packet can be submitted.
            packet["parameters"]["systemwide_confirmed"] = True
            packet["parameters"].setdefault("profile", "BLACKBOX.Deep.Light")
            packet["parameters"].setdefault("duration_seconds", 5)
        if packet["operation"] == "memory.write":
            dialog = QDialog(self.window)
            dialog.setWindowTitle("BLACK.BOX · " + ("Новые значения памяти" if self.window.language == "RU" else "Fresh memory values"))
            layout, form = QVBoxLayout(dialog), QFormLayout()
            fields = {}
            for name, label in (("address", "Address / Адрес"), ("expected_hex", "Expected bytes (hex) / Исходные байты"),
                                ("value_hex", "New bytes (hex) / Новые байты")):
                field = QLineEdit(dialog)
                field.setMaxLength(8192 if name != "address" else 22)
                field.setObjectName("chainRuntime_" + name)
                form.addRow(label, field)
                fields[name] = field
            layout.addLayout(form)
            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            layout.addWidget(buttons)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                self._reply(packet, InterruptedError("FRESH_MEMORY_INPUT_DECLINED"))
                return
            try:
                packet["parameters"].update(address=int(fields["address"].text(), 0),
                    expected_hex=bytes.fromhex(fields["expected_hex"].text()).hex(),
                    value_hex=bytes.fromhex(fields["value_hex"].text()).hex())
            except ValueError:
                self._reply(packet, ValueError("INVALID_FRESH_MEMORY_INPUT"))
                return
            finally:
                for field in fields.values():
                    field.clear()
                dialog.deleteLater()
        if bridge.generation != packet["generation"] or not self._is_target(identity):
            self._reply(packet, ValueError("PROCESS_IDENTITY_CHANGED"))
            return
        self._native = packet
        def execution_guard():
            return (self._native is packet and self._requests.get(packet["request_id"]) is packet
                    and not packet["event"].is_set() and not packet["context"].cancel.is_set()
                    and bridge.generation == packet["generation"] and self._is_target(identity))
        accepted = panel.request_investigation_action(packet["operation"], packet["parameters"],
            tag=packet["tag"], execution_guard=execution_guard, native_owner_run_id=packet["context"].run_id,
            expected_context=self._native_contexts.get(packet["context"].run_id), expected_target=identity)
        # Parameters remain only in the original runtime action owner, not metadata.
        packet["parameters"] = {}
        if not accepted:
            self._native = None
            self._reply(packet, InterruptedError("DIAGNOSTIC_ACTION_NOT_ACCEPTED"))
        else:
            packet["phases"].put("RUNNING")
            self.human_required.emit({"state": "RUNNING", "operation": packet["operation"]})

    def _native_result(self, result):
        packet = self._native
        if (self._finalizing is not None and result.get("request_kind") == "owned_release"
                and result.get("request_tag") == self._finalizing["tag"]):
            self._finalizing["actual_result"] = deepcopy(result)
            self._native_idle()
            return
        if packet is None:
            return
        reference = result.get("native_context_ownership")
        if isinstance(reference, dict) and reference.get("owner_run_id") == packet["context"].run_id:
            self._native_contexts[packet["context"].run_id] = deepcopy(reference)
            self._owned_session_run_id = packet["context"].run_id
            packet["context"].runtime.owned_session_run_id = self._owned_session_run_id
        if result.get("request_kind") in ("elevate", "authorize_target"):
            if result.get("request_tag") != packet["tag"]:
                return
            if packet["context"].cancel.is_set():
                packet["actual_result"] = _RuntimeUnconfirmed("WORKFLOW_UAC_CANCELLED_AFTER_NATIVE_OWNER_DRAIN")
                self._native_idle()
                return
            if packet.get("awaiting_uac") and result.get("status") != "COMPLETED":
                packet["actual_result"] = deepcopy(result)
                self._native_idle()
            elif result.get("status") == "COMPLETED":
                packet.pop("awaiting_uac", None)
                packet["phases"].put("RUNNING")
                self.human_required.emit({"state": "RUNNING", "operation": packet["operation"]})
            return
        if result.get("request_tag") != packet["tag"]:
            return
        bridge = self.window.deep_inspector_panel.bridge
        if bridge.generation != packet["generation"] or not self._is_target(packet["target"]):
            self._native = None
            self._reply(packet, _RuntimeUnconfirmed("PROCESS_IDENTITY_CHANGED_DURING_ACTION"))
            return
        if result.get("next_action") == "REVIEW_EXISTING_DIAGNOSTIC_OWNER_BEFORE_CHAIN_ACTION":
            packet["awaiting_owner"] = True
            packet["phases"].put("NATIVE_CONTEXT_OWNERSHIP_CONFLICT")
            self.human_required.emit({"state": "WAITING_FOR_HUMAN", "operation": packet["operation"],
                "reason": "REVIEW_EXISTING_DIAGNOSTIC_OWNER_BEFORE_CHAIN_ACTION"})
            return
        if result.get("status") == "ADMIN_REQUIRED" or (result.get("status") == "CONFIRMATION_REQUIRED"
                and result.get("next_action") == "AUTHORIZE_TARGET_AND_OPERATION_SCOPE"):
            packet["awaiting_uac"] = True
            packet["phases"].put("ADMIN_REQUIRED")
            self.human_required.emit({"state": "WAITING_FOR_HUMAN", "operation": packet["operation"],
                                     "reason": result.get("status"), "grant_permission": True})
            return
        answer = deepcopy(result)
        service = getattr(self.window.deep_inspector_panel.bridge, "_service", None)
        journal = getattr(service, "journal", None)
        if getattr(journal, "path", None) is not None:
            answer["_journal_path"] = str(journal.path)
        packet["actual_result"] = answer
        self._native_idle()

    def _native_idle(self, *_):
        if self.window.deep_inspector_panel.bridge.worker is not None:
            return
        if self._finalizing is not None and "actual_result" in self._finalizing:
            packet, self._finalizing = self._finalizing, None
            answer = packet["actual_result"]
            if answer.get("cleanup", {}).get("confirmed") is True:
                self._owned_session_run_id = None
                self._native_contexts.pop(packet["context"].run_id, None)
                packet["context"].runtime.owned_session_run_id = None
            self._reply(packet, answer)
        if self._native is not None and "actual_result" in self._native:
            packet, self._native = self._native, None
            self._reply(packet, packet["actual_result"])
        if self._finalizing is not None and self._finalizing.get("waiting_for_native_drain"):
            packet, self._finalizing = self._finalizing, None
            if not packet["event"].is_set():
                packet.pop("waiting_for_native_drain", None)
                self._dispatch_finalize(packet)

    def grant_permission(self):
        if self._native and self._native.get("awaiting_uac"):
            self._native["started_inactive_admin"] = not self.window.deep_inspector_panel.bridge.admin_active
            self.window.deep_inspector_panel.request_investigation_elevation()

    def _dispatch_finalize(self, packet):
        self._requests[packet["request_id"]] = packet
        bridge = self.window.deep_inspector_panel.bridge
        run_id = packet["context"].run_id
        pending = self._native
        worker = bridge.worker
        passive_status = (worker is not None and worker.command.get("kind") == "session_status")
        if self._finalizing is not None:
            self._reply(packet, RuntimeError("DIAGNOSTIC_OWNER_BUSY"))
        elif pending is not None and pending["context"].run_id == run_id:
            self._finalizing = packet
            packet["waiting_for_native_drain"] = True
        elif passive_status:
            self._finalizing = packet
            packet["waiting_for_native_drain"] = True
        elif (worker is not None or pending is not None or getattr(bridge, "_queued_command", None) is not None
              or getattr(bridge, "_reset_pending", False)):
            self._reply(packet, RuntimeError("DIAGNOSTIC_OWNER_BUSY"))
        elif self._owned_session_run_id != run_id and packet["operation"] == "finish_run":
            self._reply(packet, {"status": "COMPLETED", "cleanup": {
                "status": "CONFIRMED", "confirmed": True,
                "scope": "R60_NATIVE_CONTEXT_ONLY",
                "evidence": "NO_NATIVE_CONTEXT_OWNED_BY_THIS_RUN_AFTER_REQUEST_DRAIN"}})
        elif self._owned_session_run_id != run_id:
            self._reply(packet, RuntimeError("WORKFLOW_SESSION_NOT_OWNED_BY_THIS_RUN"))
        else:
            self._finalizing = packet
            if not bridge.release_native_context(packet["context"].run_id,
                    self._native_contexts.get(packet["context"].run_id), tag=packet["tag"]):
                self._finalizing = None
                self._reply(packet, RuntimeError("SESSION_FINALIZATION_NOT_ACCEPTED"))

    def _cancel_own_native(self, request_id):
        packet = self._requests.get(request_id)
        if packet is None:
            return
        if self._native is packet:
            worker = self.window.deep_inspector_panel.bridge.worker
            if worker is not None and worker.command.get("tag") == packet["tag"]:
                self.window.deep_inspector_panel.bridge.cancel()
            elif packet.get("awaiting_uac") or packet.get("awaiting_owner"):
                self._native = None
                self._reply(packet, InterruptedError("WORKFLOW_HUMAN_STEP_CANCELLED"))

    def _target_changed(self):
        self._confirmed.clear()
        packet = self._native
        if packet is not None:
            self._cancel_own_native(packet["request_id"])
            if self._native is not None and self.window.deep_inspector_panel.bridge.worker is None:
                self._native = None
                self._reply(packet, ValueError("PROCESS_IDENTITY_CHANGED"))

    def _dispatch_research(self, packet):
        # Cleanup is allowed after cancellation and close; it is never a replay.
        self._requests[packet["request_id"]] = packet
        probe, operation = self.window.probe, packet["operation"]
        if not hasattr(probe, "command_result"):
            self._reply(packet, RuntimeError("CHAIN_OBSERVE_REQUIRES_ISOLATED_RECORDING_OWNER"))
            return
        if operation == "claim":
            if self._observe_owner is not None or probe.active or probe.pending or not self._is_target(packet["target"]):
                self._reply(packet, RuntimeError("RECORDING_OWNER_BUSY_OR_TARGET_CHANGED"))
            else:
                self._observe_owner = packet["owner"]
                self._observe_cleanup_unknown = False
                self._reply(packet, True)
            return
        if self._observe_owner != packet["owner"]:
            self._reply(packet, RuntimeError("WORKFLOW_DOES_NOT_OWN_RECORDING"))
            return
        if operation == "release":
            if probe.active or self._observe_cleanup_unknown:
                self._reply(packet, RuntimeError("RECORDING_CLEANUP_UNCONFIRMED"))
            else:
                self._observe_owner = None
                self._reply(packet, True)
            return
        if operation != "stop" and (self._closing or packet["context"].cancel.is_set() or not self._is_target(packet["target"])):
            self._reply(packet, InterruptedError("WORKFLOW_CANCELLED_OR_TARGET_CHANGED"))
            return
        try:
            ident = probe.send(operation, **packet["arguments"])
            self._research[ident] = packet
        except (RuntimeError, ValueError) as error:
            self._reply(packet, error)

    def _research_result(self, ident, operation, result, error):
        packet = self._research.get(ident)
        if packet is None:
            return
        if error:
            self._research.pop(ident, None)
            self._reply(packet, _RuntimeUnconfirmed(error) if operation == "stop" else RuntimeError(error))
        else:
            packet["ack"] = result
            self._research_updated()

    def _research_updated(self):
        probe = self.window.probe
        for ident, packet in list(self._research.items()):
            if "ack" not in packet:
                continue
            operation = packet["operation"]
            if operation == "start" and not probe.active:
                continue
            if operation == "stop" and probe.active:
                continue
            if operation == "attach" and probe.pid != packet["target"]["pid"]:
                continue
            self._research.pop(ident, None)
            if operation == "stop":
                self._observe_cleanup_unknown = packet["ack"].get("cleanup_required") is not False
            snapshot = deepcopy(probe.snapshot())
            snapshot["active"] = probe.active
            self._reply(packet, {"result": packet["ack"], "snapshot": snapshot})

    def _expire_requests(self):
        now = time.monotonic()
        if (self._finalizing is not None and self._finalizing.get("waiting_for_native_drain")
                and self.window.deep_inspector_panel.bridge.worker is None):
            self._native_idle()
        for packet in list(self._requests.values()):
            if now <= packet["expires"]:
                continue
            if self._native is packet:
                self._cancel_own_native(packet["request_id"])
                # A timed-out callback is not proof that the native owner has
                # exited. Keep its exact packet for late receipt/ownership ACK.
                packet["deadline_expired"] = True
            self._reply(packet, _RuntimeUnconfirmed("WORKFLOW_RUNTIME_RESPONSE_TIMEOUT"))

    def pause(self):
        if self.worker is not None and self.worker.engine is not None:
            self.worker.engine.request_pause()

    def cancel(self):
        if self.worker is not None:
            self.worker.cancel_event.set()
            if self.worker.engine is not None:
                self.worker.engine.request_cancel()
        elif self._paused_run is not None:
            if self._closing:
                self._close_cleanup_attempted.add(self._paused_run["run_id"])
            self.submit("cancel_saved_run", folder=self._paused_run["folder"],
                        definition=self._paused_run["definition"])
        if self._native is not None:
            self._cancel_own_native(self._native["request_id"])
        if self._selection is not None:
            self._reply(self._selection, InterruptedError("PROCESS_SELECTION_CANCELLED"))
            self._selection = None

    def shutdown(self):
        self._closing = True
        if self.worker is None:
            self._select_close_cleanup()
        self.cancel()
        if not self.busy:
            self._poll.stop()
            self.closed.emit()

    def _select_close_cleanup(self):
        self._paused_run = next((row for key, row in self._paused_runs.items()
                                 if key not in self._close_cleanup_attempted), None)

    def _receive(self, operation, result, error):
        if operation in ("start", "resume", "cancel_saved_run", "open_run") and isinstance(result, dict):
            state = result.get("snapshot", result)
            run_id = state.get("run_id")
            if state.get("state") in ("WAITING_FOR_HUMAN", "RECOVERY_UNCONFIRMED"):
                definition = (result["definition"] if operation == "open_run" else
                              self.worker.engine.definition.to_dict())
                self._paused_run = {"folder": result["folder"], "run_id": run_id, "definition": definition}
                self._paused_runs[run_id] = self._paused_run
            elif state.get("state") in ("COMPLETED", "PARTIAL", "CANCELLED", "FAILED"):
                self._paused_runs.pop(run_id, None)
                self._paused_run = None
            if operation != "open_run":
                self.snapshot_changed.emit(result)
        self.result_ready.emit(operation, result, error)

    def _finished(self):
        old, self.worker = self.worker, None
        if old is not None:
            old.deleteLater()
        self.busy_changed.emit(False)
        if self._closing:
            self._select_close_cleanup()
            if self._paused_run is not None:
                self.cancel()
            else:
                self._poll.stop()
                self.closed.emit()
