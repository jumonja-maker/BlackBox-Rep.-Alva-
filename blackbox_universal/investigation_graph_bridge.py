"""Cancellable read-only investigation work outside the Qt event loop.

This owner never starts a diagnostic helper. Native actions stay on the existing
DeepInspectorBridge, with its original confirmation and cleanup lifecycle.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import threading

from PySide6.QtCore import QObject, QThread, Signal


def _group_paths(paths):
    from blackbox_core.investigation_graph_contracts import InvestigationError
    if (type(paths) is not list or len(paths) > 32 or
            any(type(path) is not str or not 1 <= len(path) <= 32768 or "\0" in path for path in paths)):
        raise InvestigationError("INVESTIGATION_GROUP_PATH_BUDGET")
    return paths


def _bounded_group_cases(api, first, paths, budget):
    """Bound retained input collectively, before keeping each additional case."""
    from blackbox_core.investigation_graph_contracts import InvestigationError, canonical_json
    paths = _group_paths(paths)
    cases, total_bytes, total_nodes = [], 2, 0
    def retain(case):
        nonlocal total_bytes, total_nodes
        budget.check()
        if type(case) is not dict or type(case.get("nodes")) is not list:
            raise InvestigationError("INVALID_INVESTIGATION_GROUP_CASE")
        count = len(case["nodes"])
        if count > budget.max_events - total_nodes:
            raise InvestigationError("INVESTIGATION_GROUP_INPUT_NODE_BUDGET")
        size = len(canonical_json(case).encode("ascii")) + bool(cases)
        budget.check()
        if size > budget.max_result_bytes - total_bytes:
            raise InvestigationError("INVESTIGATION_GROUP_INPUT_BYTE_BUDGET")
        total_bytes += size
        total_nodes += count
        cases.append(case)
    retain(first)
    for path in paths:
        budget.check()
        retain(api.load_investigation(path, budget=budget))
    return cases


class InvestigationGraphWorker(QThread):
    result_ready = Signal(str, object, str, int)

    def __init__(self, operation, arguments, generation, parent=None, *, api=None):
        super().__init__(parent)
        self.operation, self.arguments, self.generation = operation, arguments, generation
        self.cancel_event = threading.Event()
        self.api = api

    def cancel(self):
        self.cancel_event.set()

    def run(self):
        try:
            if self.api is None:
                from blackbox_core import investigation_v3 as api
            else:
                api = self.api
            from blackbox_core.investigation_graph_contracts import InvestigationBudget
            budget = InvestigationBudget(timeout_seconds=120, cancel_event=self.cancel_event)
            if self.operation == "group":
                _group_paths(self.arguments.get("other_paths"))
                # Validate the known bounded starting case before its worker copy.
                _bounded_group_cases(api, self.arguments.get("case"), [], budget)
            args = deepcopy(self.arguments)  # Potentially large cases are copied here, not on Qt.
            case = args.pop("case", None)
            if self.operation == "context":
                from .investigation_context import apply_user_context, prepare_user_context
                destination = args.pop("index_path", None)
                context = prepare_user_context(budget=budget, **args)
                packet = {"context": context}
                if case is not None:
                    from blackbox_core.investigation_graph_store import save_investigation
                    updated = apply_user_context(case, context, budget=budget)
                    destination = Path(destination)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    save_investigation(updated, destination, budget=budget)
                    packet.update(case=updated, index_path=str(destination))
            elif self.operation == "build":
                index_path = Path(args.pop("index_path"))
                index_path.parent.mkdir(parents=True, exist_ok=True)
                answer = api.create_investigation(index_path=index_path, budget=budget, **args)
                packet = {"case": answer, "index_path": str(index_path)}
            elif self.operation == "open":
                answer = api.load_investigation(args["path"], budget=budget)
                packet = {"case": answer, "index_path": str(args["path"])}
            elif self.operation == "export":
                answer = api.export_investigation(case, args["destination"], format=args["format"], budget=budget)
                packet = {"export": str(answer) if isinstance(answer, Path) else answer}
            elif self.operation == "actions":
                recommended = api.suggest_diagnostic_actions(case, budget=budget, **args)
                from blackbox_core.investigation_planner import describe_diagnostic_actions
                manual = describe_diagnostic_actions(case, capabilities=args.get("capabilities"),
                    target_identity=args.get("target_identity"), budget=budget)
                selected = {row["operation"] for row in recommended}
                packet = {"actions": recommended + [row for row in manual if row["operation"] not in selected]}
            elif self.operation == "related":
                packet = {"related": api.get_related_evidence(case, budget=budget, **args)}
            elif self.operation == "compare_cases":
                other = api.load_investigation(args["other_path"], budget=budget)
                packet = {"comparison": api.compare_investigations(case, other, budget=budget)}
            elif self.operation == "group":
                cases = _bounded_group_cases(api, case, args["other_paths"], budget)
                packet = {"grouping": api.group_recurrent_issues(cases, budget=budget)}
            elif self.operation == "group_change":
                from blackbox_core.issue_grouping import manual_group_change
                grouping = args.pop("groups")
                packet = {"grouping": manual_group_change(grouping, budget=budget, **args)}
            elif self.operation == "fork":
                packet = {"experiment_case": api.fork_for_experiment(case, args["target_identity"],
                                                                      confirmed=True, budget=budget)}
            elif self.operation in ("record_experiment", "save_case"):
                from blackbox_core.investigation_graph_store import save_investigation
                if self.operation == "record_experiment":
                    from blackbox_core.investigation_planner import record_experiment_result
                    case = record_experiment_result(case, args["record"], budget=budget)
                destination = Path(args["index_path"])
                destination.parent.mkdir(parents=True, exist_ok=True)
                save_investigation(case, destination, budget=budget)
                packet = {"experiment_case" if self.operation == "record_experiment" or args.get("experiment") else "case": case,
                          "index_path": str(destination)}
            else:
                raise ValueError("UNKNOWN_INVESTIGATION_GUI_OPERATION")
            if self.operation != "export":
                budget.check()
            self.result_ready.emit(self.operation, packet, "", self.generation)
        except Exception as error:
            # Reader/native errors remain plain text, never HTML or executable input.
            self.result_ready.emit(self.operation, None,
                str(getattr(error, "code", str(error)))[:1500] or type(error).__name__, self.generation)


class InvestigationGraphBridge(QObject):
    result_ready = Signal(str, object, str, int)
    busy_changed = Signal(bool)
    closed = Signal()

    def __init__(self, parent=None, *, api=None):
        super().__init__(parent)
        self.api, self.worker, self.generation = api, None, 0
        self._closing = False

    @property
    def busy(self):
        return self.worker is not None

    def submit(self, operation, **arguments):
        if self.worker is not None or self._closing:
            return False
        task = InvestigationGraphWorker(operation, arguments, self.generation, self, api=self.api)
        self.worker = task
        task.result_ready.connect(self._receive)
        task.finished.connect(self._finished)
        self.busy_changed.emit(True)
        task.start()
        return True

    def invalidate(self):
        self.generation += 1
        self.cancel()

    def cancel(self):
        if self.worker is not None:
            self.worker.cancel()

    def shutdown(self):
        if self._closing:
            return
        self._closing = True
        self.invalidate()
        if self.worker is None:
            self.closed.emit()

    def _receive(self, operation, packet, error, generation):
        if generation == self.generation and not self._closing:
            self.result_ready.emit(operation, packet, error, generation)

    def _finished(self):
        old, self.worker = self.worker, None
        if old is not None:
            old.deleteLater()
        self.busy_changed.emit(False)
        if self._closing:
            self.closed.emit()
