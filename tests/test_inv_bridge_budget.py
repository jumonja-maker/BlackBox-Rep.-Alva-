"""Aggregate GUI input contracts; no Qt application or native helper is started."""
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from blackbox_core.investigation_graph_contracts import InvestigationBudget, InvestigationError
from blackbox_universal.investigation_graph_bridge import _bounded_group_cases


def case(identifier="one", payload="", nodes=0):
    return {"case_id": identifier, "nodes": [{} for _ in range(nodes)], "payload": payload}


class InvestigationBridgeBudgetContracts(unittest.TestCase):
    def test_cumulative_case_bytes_stop_loading_before_remaining_paths(self):
        loaded = case("second", "b" * 600)
        api = SimpleNamespace(load_investigation=Mock(return_value=loaded))
        with self.assertRaisesRegex(InvestigationError, "GROUP_INPUT_BYTE_BUDGET"):
            _bounded_group_cases(api, case(payload="a" * 600), ["second", "third"],
                                 InvestigationBudget(max_result_bytes=1024))
        api.load_investigation.assert_called_once()

    def test_path_count_and_shape_are_checked_before_any_load(self):
        api = SimpleNamespace(load_investigation=Mock())
        for paths in (["case"] * 33, "case", ["bad\0path"]):
            with self.subTest(paths=type(paths).__name__), self.assertRaisesRegex(InvestigationError, "GROUP_PATH_BUDGET"):
                _bounded_group_cases(api, case(), paths, InvestigationBudget())
        api.load_investigation.assert_not_called()

    def test_cumulative_nodes_respect_operation_scan_budget(self):
        api = SimpleNamespace(load_investigation=Mock(return_value=case("second", nodes=2)))
        with self.assertRaisesRegex(InvestigationError, "GROUP_INPUT_NODE_BUDGET"):
            _bounded_group_cases(api, case(nodes=2), ["second", "third"], InvestigationBudget(max_events=3))
        api.load_investigation.assert_called_once()

    def test_bounded_cases_are_retained_in_order_without_copies(self):
        first, second = case(), case("second")
        api = SimpleNamespace(load_investigation=Mock(return_value=second))
        output = _bounded_group_cases(api, first, ["second"], InvestigationBudget())
        self.assertIs(output[0], first)
        self.assertIs(output[1], second)

    def test_cancellation_prevents_loading_additional_inputs(self):
        stop = threading.Event()
        stop.set()
        api = SimpleNamespace(load_investigation=Mock())
        with self.assertRaises(InterruptedError):
            _bounded_group_cases(api, case(), ["second"], InvestigationBudget(cancel_event=stop))
        api.load_investigation.assert_not_called()
