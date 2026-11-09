"""Finite graph/profile/port validation. Preview never invokes an adapter."""
from __future__ import annotations

from collections import deque
from pathlib import Path
import math
import re

from .chain_contracts import (MAX_DEPTH, MAX_INVOCATIONS, MAX_NODE_PARAMETERS_BYTES, Artifact, NodeDefinition, PortSpec,
    WorkflowDefinition, WorkflowError, canonical, control_ports, json_data, number, require)
from .chain_profiles import effective_profile


def get_ports(node, catalog):
    if node.kind not in ("TOOL", "REPEAT"):
        inputs, outputs = control_ports(node.kind)
    else:
        require(node.tool_id in catalog, "WORKFLOW_UNKNOWN_TOOL", node_id=node.node_id)
        adapter = catalog[node.tool_id]
        inputs = dict(adapter.inputs)
        outputs = {**adapter.outputs, "receipt": PortSpec(("RECEIPT",))}
        if node.tool_id == "load_source" and node.parameters.get("kind"):
            selected = node.parameters["kind"]
            require(type(selected) is str and selected in outputs["source"].types, "WORKFLOW_SOURCE_KIND_UNSUPPORTED")
            outputs["source"] = PortSpec((selected,))
    return {**inputs, "when": PortSpec(("BOOLEAN",), required=False)}, outputs


def validate_parameters(adapter, parameters):
    require(type(parameters) is dict and set(parameters) <= set(adapter.parameters), "WORKFLOW_UNKNOWN_PARAMETER")
    parameters = json_data(parameters, configuration=True)
    result = {}
    for name, spec in adapter.parameters.items():
        if name not in parameters:
            require(not spec.get("required", False) or "default" in spec, "WORKFLOW_REQUIRED_PARAMETER_MISSING")
            if "default" not in spec:
                continue
        value = json_data(parameters.get(name, spec.get("default")), configuration=True)
        kind = spec.get("type", "string")
        if kind in ("string", "path", "choice"):
            require(type(value) is str and len(value) <= spec.get("max_length", 8192), "WORKFLOW_INVALID_TEXT_PARAMETER")
        elif kind == "integer":
            require(type(value) is int, "WORKFLOW_INVALID_INTEGER_PARAMETER")
        elif kind == "number":
            number(value, spec.get("min", -1e18), spec.get("max", 1e18), "WORKFLOW_INVALID_NUMBER_PARAMETER")
        elif kind == "boolean":
            require(type(value) is bool, "WORKFLOW_INVALID_BOOLEAN_PARAMETER")
        elif kind == "object":
            require(type(value) is dict, "WORKFLOW_INVALID_OBJECT_PARAMETER")
        else:
            raise WorkflowError("WORKFLOW_UNKNOWN_PARAMETER_TYPE")
        if kind == "integer":
            require(spec.get("min", -(2**63)) <= value <= spec.get("max", 2**63 - 1), "WORKFLOW_PARAMETER_RANGE")
        if "choices" in spec:
            require(value in spec["choices"], "WORKFLOW_PARAMETER_CHOICE")
        result[name] = value
    if adapter.validate_parameters is not None:
        adapter.validate_parameters(result)
    result = json_data(result, configuration=True)
    require(len(canonical(result).encode()) <= MAX_NODE_PARAMETERS_BYTES, "WORKFLOW_PARAMETER_BUDGET")
    return result


_FIELD_ROOTS = frozenset(("status", "execution_started", "source", "cleanup", "coverage", "effects", "value"))


def validate_condition(condition, *, depth=0):
    require(type(condition) is dict and depth <= 8, "WORKFLOW_CONDITION_DEPTH_OR_TYPE")
    if "all" in condition or "any" in condition:
        key = "all" if "all" in condition else "any"
        require(set(condition) == {key} and type(condition[key]) is list and 0 < len(condition[key]) <= 32,
                "INVALID_WORKFLOW_BOOLEAN_CONDITION")
        for item in condition[key]:
            validate_condition(item, depth=depth + 1)
        return
    require(set(condition) <= {"field", "op", "value", "status", "has_evidence", "sufficient"},
            "INVALID_WORKFLOW_CONDITION_FIELDS")
    if "status" in condition:
        require(set(condition) == {"status"} and type(condition["status"]) is str and
                0 < len(condition["status"]) <= 128, "INVALID_WORKFLOW_STATUS_CONDITION")
        return
    if "has_evidence" in condition or "sufficient" in condition:
        key = "has_evidence" if "has_evidence" in condition else "sufficient"
        require(set(condition) == {key} and type(condition[key]) is bool, "INVALID_WORKFLOW_SUFFICIENCY_CONDITION")
        return
    path = condition.get("field")
    require(type(path) is str and len(path) <= 256 and path.split(".")[0] in _FIELD_ROOTS and
            len(path.split(".")) <= 8 and all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", p) for p in path.split(".")) and
            condition.get("op", "EQ") in ("EQ", "NE", "EXISTS", "GT", "GE", "LT", "LE"),
            "WORKFLOW_CONDITION_FIELD_OR_OPERATOR")
    if condition.get("op", "EQ") != "EXISTS":
        require("value" in condition, "WORKFLOW_CONDITION_VALUE_REQUIRED")
        value = condition.get("value")
        require(value is None or type(value) in (str, bool, int, float), "WORKFLOW_CONDITION_SCALAR_REQUIRED")
        if type(value) is float:
            require(math.isfinite(value), "WORKFLOW_NONFINITE_NUMBER")
        if condition.get("op") in ("GT", "GE", "LT", "LE"):
            number(value, -1e18, 1e18, "WORKFLOW_NUMERIC_CONDITION_REQUIRED")


def evaluate_condition(condition, receipt):
    """Three-valued conditions: absent evidence never becomes truthy success."""
    validate_condition(condition)
    if type(receipt) is not dict:
        return None
    if "all" in condition or "any" in condition:
        key = "all" if "all" in condition else "any"
        values = [evaluate_condition(item, receipt) for item in condition[key]]
        if key == "all":
            return False if False in values else None if None in values else True
        return True if True in values else None if None in values else False
    if "status" in condition:
        return None if type(receipt.get("status")) is not str else receipt["status"] == condition["status"]
    if "has_evidence" in condition:
        references = receipt.get("result_references")
        source = receipt.get("source")
        if type(references) is not list or any(type(row) is not dict or
                type(row.get("kind")) is not str or not row["kind"] for row in references):
            return None
        verified = type(source) is dict and source.get("verified") is True
        useful = any(row["kind"] != "operation" for row in references)
        observed = useful if verified and receipt.get("execution_started") is True else None
        return None if observed is None else observed is condition["has_evidence"]
    if "sufficient" in condition:
        coverage = receipt.get("coverage", {})
        if type(coverage) is not dict:
            return None
        completeness = coverage.get("completeness", coverage.get("evidence_completeness"))
        if completeness not in ("REPORTED_COMPLETE_FOR_REQUEST", "COMPLETE", "PARTIAL", "INCOMPLETE_EVIDENCE"):
            return None
        observed = completeness in ("REPORTED_COMPLETE_FOR_REQUEST", "COMPLETE")
        return observed is condition["sufficient"]
    value = receipt
    for part in condition["field"].split("."):
        if type(value) is not dict or part not in value:
            return None if condition.get("op") != "EXISTS" else False
        value = value[part]
    if condition.get("op") == "EXISTS":
        return value is not None
    if value is None:
        return None
    if type(value) not in (str, bool, int, float) or type(value) is float and not math.isfinite(value):
        return None
    expected = condition.get("value")
    if condition.get("op") in ("GT", "GE", "LT", "LE"):
        if type(value) not in (int, float) or type(expected) not in (int, float):
            return None
        return {"GT": value > expected, "GE": value >= expected,
                "LT": value < expected, "LE": value <= expected}[condition["op"]]
    equal = type(value) is type(expected) and value == expected
    return not equal if condition.get("op") == "NE" else equal


def validate_workflow(definition, catalog, *, runtime=None):
    result = {"ready": False, "errors": [], "warnings": [], "required_rights": [], "resources": [],
        "declared_budgets": {}, "effective_profile": None,
        "preview_scope": "STRUCTURE_PARAMETERS_AND_DECLARED_CAPABILITIES; NO_TOOL_EXECUTION_OR_SUCCESS_RECEIPTS"}
    try:
        if isinstance(definition, dict):
            definition = WorkflowDefinition.from_dict(definition)
        else:
            definition = WorkflowDefinition.from_dict(definition.to_dict())
        profile = effective_profile(definition, catalog, profiles=getattr(runtime, "profiles", None))
        result["effective_profile"] = profile
        indexed = {node.node_id: node for node in definition.nodes}
        require(len(indexed) == len(definition.nodes), "WORKFLOW_DUPLICATE_NODE_ID")
        require(all(key in indexed for key in profile["allowed_node_ids"]), "WORKFLOW_PROFILE_NODE_MISSING")
        require(len({edge.edge_id for edge in definition.edges}) == len(definition.edges), "WORKFLOW_DUPLICATE_EDGE_ID")
        degrees = {key: 0 for key in indexed}
        children, incoming, unique = {key: [] for key in indexed}, {}, set()
        for edge in definition.edges:
            require(edge.source_node in indexed and edge.target_node in indexed, "WORKFLOW_EDGE_NODE_MISSING")
            require(edge.source_node != edge.target_node, "WORKFLOW_CYCLE")
            source = get_ports(indexed[edge.source_node], catalog)[1]
            target = get_ports(indexed[edge.target_node], catalog)[0]
            require(edge.source_port in source and edge.target_port in target, "WORKFLOW_PORT_MISSING")
            require(set(source[edge.source_port].types) <= set(target[edge.target_port].types), "WORKFLOW_PORT_TYPE_MISMATCH")
            require(not source[edge.source_port].many or target[edge.target_port].many,
                    "WORKFLOW_PORT_CARDINALITY_MISMATCH")
            endpoint = (edge.source_node, edge.source_port, edge.target_node, edge.target_port)
            require(endpoint not in unique, "WORKFLOW_DUPLICATE_CONNECTION")
            unique.add(endpoint)
            key = (edge.target_node, edge.target_port)
            require(target[edge.target_port].many or key not in incoming, "WORKFLOW_INPUT_ALREADY_CONNECTED")
            incoming.setdefault(key, []).append(edge)
            children[edge.source_node].append(edge.target_node)
            degrees[edge.target_node] += 1
        declared = 0.0
        invocations = 0
        rights, resources = set(), set()
        for node in definition.nodes:
            for name, port in get_ports(node, catalog)[0].items():
                require(not port.required or (node.node_id, name) in incoming, "WORKFLOW_REQUIRED_INPUT_MISSING", node_id=node.node_id)
            if node.kind in ("TOOL", "REPEAT"):
                require(node.tool_id in profile["allowed_tools"], "WORKFLOW_PROFILE_TOOL_NOT_ALLOWED", node_id=node.node_id)
                adapter = catalog[node.tool_id]
                require(adapter.available, adapter.unavailable_reason or "WORKFLOW_TOOL_UNAVAILABLE", node_id=node.node_id)
                require(adapter.read_only or profile["allow_effectful"] or node.tool_id == "session_finalize",
                        "WORKFLOW_EFFECTFUL_PLANNING_OPT_IN_REQUIRED", node_id=node.node_id)
                require(node.kind != "REPEAT" or adapter.read_only, "WORKFLOW_EFFECTFUL_REPEAT_REFUSED", node_id=node.node_id)
                parameters = validate_parameters(adapter, node.parameters)
                cap = adapter.descriptor.budgets.get("max_operation_seconds", adapter.descriptor.budgets.get("max_timeout_seconds"))
                if type(cap) in (int, float):
                    require(node.budget_seconds <= cap, "WORKFLOW_EXISTING_TOOL_BUDGET_EXCEEDED", node_id=node.node_id)
                if node.tool_id == "load_source" and parameters.get("path"):
                    from .session_v2 import safe_path
                    path = safe_path(Path(parameters["path"]))
                    require(path.exists(), "WORKFLOW_SOURCE_MISSING", node_id=node.node_id)
                    require(path.is_file() or parameters.get("kind")=="SESSION" and path.is_dir(),
                            "WORKFLOW_SOURCE_TYPE_MISMATCH", node_id=node.node_id)
                rights.add(adapter.descriptor.required_rights)
                resources.update(adapter.resources)
                if adapter.confirmation_required:
                    result["warnings"].append({"node_id": node.node_id, "code": "FRESH_RUNTIME_CONFIRMATION_REQUIRED"})
            elif node.kind == "CONDITION":
                require("condition" not in node.parameters or set(node.parameters)=={"condition"},
                        "INVALID_WORKFLOW_CONDITION_FIELDS", node_id=node.node_id)
                validate_condition(node.parameters.get("condition", node.parameters or {"status": "COMPLETED"}))
            elif node.kind == "JOIN":
                require(set(node.parameters) <= {"mode", "allow_partial"} and
                        node.parameters.get("mode", "ALL_REQUIRED") in ("ALL_REQUIRED", "ALLOW_PARTIAL"), "INVALID_WORKFLOW_JOIN_POLICY")
                require(type(node.parameters.get("allow_partial", False)) is bool, "INVALID_WORKFLOW_JOIN_POLICY")
            else:
                require(set(node.parameters) <= {"message"} and type(node.parameters.get("message", "")) is str,
                        "INVALID_WORKFLOW_CHECKPOINT")
                result["warnings"].append({"node_id": node.node_id, "code": "MANUAL_CHECKPOINT"})
            declared += node.repeat_count * node.budget_seconds + (node.repeat_count - 1) * node.repeat_interval_seconds
            invocations += node.repeat_count
        require(invocations <= MAX_INVOCATIONS, "WORKFLOW_INVOCATION_BUDGET")
        require(declared <= profile["max_seconds"], "WORKFLOW_DECLARED_TIME_BUDGET_EXCEEDED")
        queue = deque(key for key, count in degrees.items() if count == 0)
        depth, order = {key: 1 for key in queue}, []
        while queue:
            key = queue.popleft()
            order.append(key)
            require(depth[key] <= MAX_DEPTH, "WORKFLOW_GRAPH_DEPTH_BUDGET")
            for child in children[key]:
                degrees[child] -= 1
                depth[child] = max(depth.get(child, 1), depth[key] + 1)
                if degrees[child] == 0:
                    queue.append(child)
        require(len(order) == len(indexed), "WORKFLOW_CYCLE")
        result.update(ready=True, order=order, required_rights=sorted(rights), resources=sorted(resources),
            declared_budgets={"maximum_declared_sequential_seconds": declared,
                "measured_duration": None, "global_seconds": profile["max_seconds"],
                "max_workers": profile["max_workers"], "max_invocations": invocations,
                "note": "DECLARATIONS_NOT_OBSERVED_EXECUTION_TIME_OR_HARD_OS_COMPLETION_GUARANTEE"})
    except (WorkflowError, ValueError, TypeError, KeyError, AttributeError, OSError, OverflowError, RecursionError) as error:
        result["errors"].append({"node_id": getattr(error, "node_id", None),
            "code": getattr(error, "code", "WORKFLOW_INVALID_DEFINITION_OR_SOURCE")})
    return result


node_ports = get_ports
