"""R60 bounded workflow data. Definitions describe calls; they never grant rights.

No collector runs during import, deserialization, or preview. Persisted receipts
are local observations, not authenticated authority to repeat an intervention.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
import re
from typing import Any, Callable
from uuid import uuid4

from .deep_tool_contracts import ToolDescriptor

SCHEMA = "blackbox.workflow-definition/1"
RUN_SCHEMA = "blackbox.workflow-run/1"
PROFILE_SCHEMA = "blackbox.workflow-profile/1"
MAX_NODES = 256
MAX_EDGES = 1024
MAX_DEPTH = 64
MAX_DEFINITION_BYTES = 1024 * 1024
MAX_NODE_PARAMETERS_BYTES = 16384
MAX_RUN_SECONDS = 21600
MAX_WORKERS = 4
MAX_ITERATIONS = 4096
MAX_INVOCATIONS = 10000
KINDS = frozenset(("TOOL", "CONDITION", "JOIN", "CHECKPOINT", "REPEAT"))
STATES = frozenset(("QUEUED", "RUNNING", "COMPLETED", "PARTIAL", "FAILED", "CANCELLED",
                    "WAITING_FOR_HUMAN", "SKIPPED", "RECOVERY_UNCONFIRMED"))
TERMINAL = frozenset(("COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "SKIPPED", "RECOVERY_UNCONFIRMED"))
PORT_TYPES = frozenset(("PROCESS", "PROCESS_SET", "TRACE", "TRACE_INDEX", "SESSION", "CASE",
    "DEEP_RESULT", "DUMP", "INCIDENT", "COMPARISON", "REPORT", "EVIDENCE_SET", "RECEIPT", "BOOLEAN"))
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_AUTHORITY = frozenset(("confirmed", "confirmation", "approved", "authorization", "uac_consent",
    "password", "passwd", "token", "access_token", "refresh_token", "secret", "credentials",
    "private_key", "environment", "environ", "command", "command_line", "script", "plugin",
    "expected_hex", "value_hex", "original_hex", "replacement_hex", "memory_bytes", "payload"))


class WorkflowError(ValueError):
    def __init__(self, code: str, *, node_id: str | None = None):
        self.code, self.node_id = code, node_id
        super().__init__(code)


def require(value: Any, code: str, *, node_id: str | None = None) -> None:
    if not value:
        raise WorkflowError(code, node_id=node_id)


def identifier(value: Any, code: str = "INVALID_WORKFLOW_IDENTIFIER") -> str:
    require(type(value) is str and _ID.fullmatch(value) is not None, code)
    return value


def number(value: Any, low: float, high: float, code: str) -> float:
    require(type(value) in (int, float) and math.isfinite(value) and low <= value <= high, code)
    return float(value)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def json_data(value: Any, *, depth: int = 0, configuration: bool = False) -> Any:
    require(depth <= 16, "WORKFLOW_DATA_DEPTH")
    if type(value) is dict:
        require(len(value) <= 256 and all(type(k) is str and len(k) <= 128 for k in value), "WORKFLOW_DATA_KEYS")
        if configuration:
            require(not any(k.lower() in _AUTHORITY or k.lower().endswith(("_password", "_token", "_secret"))
                            for k in value), "WORKFLOW_SAVED_AUTHORITY_OR_PAYLOAD_REFUSED")
        return {k: json_data(v, depth=depth + 1, configuration=configuration) for k, v in value.items()}
    if type(value) in (list, tuple):
        require(len(value) <= MAX_EDGES, "WORKFLOW_DATA_ROWS")
        return [json_data(v, depth=depth + 1, configuration=configuration) for v in value]
    if type(value) is str:
        require(len(value) <= 8192 and not any(ord(c) < 32 and c not in "\n\t\r" for c in value), "WORKFLOW_DATA_TEXT")
        return value
    if type(value) is float:
        require(math.isfinite(value), "WORKFLOW_NONFINITE_NUMBER")
        return value
    require(value is None or type(value) in (int, bool), "WORKFLOW_NON_JSON_DATA")
    return value


def parse_json(raw: bytes | str) -> dict:
    if isinstance(raw, bytes):
        require(len(raw) <= MAX_DEFINITION_BYTES, "WORKFLOW_JSON_BYTE_BUDGET")
        raw = raw.decode("utf-8")
    require(type(raw) is str and len(raw.encode("utf-8")) <= MAX_DEFINITION_BYTES, "WORKFLOW_JSON_BYTE_BUDGET")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "WORKFLOW_DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def constant(_):
        raise WorkflowError("WORKFLOW_NONFINITE_NUMBER")
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as error:
        raise WorkflowError("WORKFLOW_JSON_CORRUPT") from error
    require(type(value) is dict, "WORKFLOW_JSON_OBJECT_REQUIRED")
    return json_data(value)


@dataclass(frozen=True)
class PortSpec:
    types: tuple[str, ...]
    required: bool = True
    many: bool = False

    def __post_init__(self):
        require(bool(self.types) and len(set(self.types)) == len(self.types) and
                all(t in PORT_TYPES for t in self.types), "INVALID_WORKFLOW_PORT_TYPES")
        require(type(self.required) is bool and type(self.many) is bool, "INVALID_WORKFLOW_PORT_FLAGS")

    def to_dict(self):
        return {"types": list(self.types), "required": self.required, "many": self.many}


@dataclass(frozen=True)
class Artifact:
    kind: str
    value: dict
    artifact_id: str = field(default_factory=lambda: uuid4().hex)
    sources: tuple[dict, ...] = ()
    clock_domains: tuple[str, ...] = ()
    coverage: dict = field(default_factory=lambda: {"evidence_completeness": "UNKNOWN"})

    def __post_init__(self):
        require(self.kind in PORT_TYPES, "INVALID_WORKFLOW_ARTIFACT_TYPE")
        identifier(self.artifact_id)
        require(type(self.value) is dict and type(self.coverage) is dict and len(self.sources) <= 64 and
                len(self.clock_domains) <= 64, "INVALID_WORKFLOW_ARTIFACT")
        value = self.to_dict()
        json_data(value)
        require(len(canonical(value).encode()) <= 256 * 1024, "WORKFLOW_ARTIFACT_METADATA_BUDGET")

    @classmethod
    def from_dict(cls, value):
        require(type(value) is dict and set(value) <= {"kind", "value", "artifact_id", "sources", "clock_domains", "coverage"},
                "INVALID_WORKFLOW_ARTIFACT")
        return cls(value["kind"], json_data(value["value"]), identifier(value["artifact_id"]),
                   tuple(json_data(value.get("sources", []))), tuple(value.get("clock_domains", [])),
                   json_data(value.get("coverage", {"evidence_completeness": "UNKNOWN"})))

    def to_dict(self, *, public=False):
        value = {"artifact_id": self.artifact_id, "kind": self.kind, "value": self.value,
                 "sources": list(self.sources), "clock_domains": list(self.clock_domains), "coverage": self.coverage}
        if public:
            from .investigation_graph_store import public_metadata
            return public_metadata(value)
        return value


@dataclass(frozen=True)
class NodeDefinition:
    node_id: str
    tool_id: str = ""
    kind: str = "TOOL"
    title: str = ""
    parameters: dict = field(default_factory=dict)
    budget_seconds: float = 60
    required: bool = True
    repeat_count: int = 1
    position: tuple[float, float] = (0, 0)
    repeat_interval_seconds: float = 0
    allow_partial_inputs: bool = False

    @classmethod
    def from_dict(cls, value):
        require(type(value) is dict and set(value) <= {"node_id", "tool_id", "kind", "title", "parameters",
            "budget_seconds", "required", "repeat_count", "position", "repeat_interval_seconds", "allow_partial_inputs"}, "INVALID_WORKFLOW_NODE_FIELDS")
        node_id = identifier(value.get("node_id"))
        kind = value.get("kind", "TOOL")
        require(type(kind) is str and kind in KINDS, "INVALID_WORKFLOW_NODE_KIND", node_id=node_id)
        tool = value.get("tool_id", "")
        require(type(tool) is str and (not tool or _ID.fullmatch(tool)), "INVALID_WORKFLOW_TOOL_ID")
        require(kind not in ("TOOL", "REPEAT") or bool(tool), "WORKFLOW_TOOL_REQUIRED", node_id=node_id)
        title = value.get("title", "")
        require(type(title) is str and len(title) <= 256, "INVALID_WORKFLOW_NODE_TITLE")
        parameters = json_data(value.get("parameters", {}), configuration=True)
        require(type(parameters) is dict and len(canonical(parameters).encode()) <= MAX_NODE_PARAMETERS_BYTES,
                "WORKFLOW_PARAMETER_BUDGET")
        seconds = number(value.get("budget_seconds", 60), .01, MAX_RUN_SECONDS, "INVALID_WORKFLOW_NODE_BUDGET")
        required, repeat = value.get("required", True), value.get("repeat_count", 1)
        require(type(required) is bool and type(repeat) is int and 1 <= repeat <= MAX_ITERATIONS, "INVALID_WORKFLOW_NODE_POLICY")
        require(kind == "REPEAT" or repeat == 1, "WORKFLOW_REPEAT_NODE_REQUIRED")
        position = value.get("position", [0, 0])
        require(type(position) in (list, tuple) and len(position) == 2, "INVALID_WORKFLOW_NODE_POSITION")
        position = tuple(number(v, -1000000, 1000000, "INVALID_WORKFLOW_NODE_POSITION") for v in position)
        interval = number(value.get("repeat_interval_seconds", 0), 0, 3600, "INVALID_WORKFLOW_REPEAT_INTERVAL")
        require(kind == "REPEAT" or interval == 0, "WORKFLOW_REPEAT_NODE_REQUIRED")
        partial = value.get("allow_partial_inputs", False)
        require(type(partial) is bool, "INVALID_WORKFLOW_PARTIAL_INPUT_POLICY")
        return cls(node_id, tool, kind, title, parameters, seconds, required, repeat, position, interval, partial)

    def to_dict(self):
        return {"node_id": self.node_id, "tool_id": self.tool_id, "kind": self.kind, "title": self.title,
            "parameters": self.parameters, "budget_seconds": self.budget_seconds, "required": self.required,
            "repeat_count": self.repeat_count, "position": list(self.position),
            "repeat_interval_seconds": self.repeat_interval_seconds, "allow_partial_inputs": self.allow_partial_inputs}


@dataclass(frozen=True)
class EdgeDefinition:
    edge_id: str
    source_node: str
    source_port: str
    target_node: str
    target_port: str

    @classmethod
    def from_dict(cls, value):
        keys = ("edge_id", "source_node", "source_port", "target_node", "target_port")
        require(type(value) is dict and set(value) == set(keys), "INVALID_WORKFLOW_EDGE_FIELDS")
        return cls(*(identifier(value.get(key), "INVALID_WORKFLOW_EDGE") for key in keys))

    def to_dict(self):
        return dict(self.__dict__)


@dataclass(frozen=True)
class WorkflowDefinition:
    workflow_id: str
    title: str
    nodes: tuple[NodeDefinition, ...]
    edges: tuple[EdgeDefinition, ...] = ()
    description: str = ""
    revision: int = 1
    profile: dict = field(default_factory=lambda: {"profile_id": "application", "overrides": {}})
    budget: dict = field(default_factory=lambda: {"seconds": 1800, "max_workers": 2,
        "max_owned_resources": 8, "max_output_bytes": 1024**3})

    @classmethod
    def from_dict(cls, value):
        require(type(value) is dict and set(value) <= {"schema", "schema_version", "workflow_id", "title",
            "description", "revision", "mode", "nodes", "edges", "profile", "budget"}, "INVALID_WORKFLOW_FIELDS")
        require(value.get("schema") == SCHEMA and value.get("schema_version", 1) == 1 and
                type(value.get("schema_version", 1)) is int, "UNSUPPORTED_WORKFLOW_SCHEMA")
        require(value.get("mode", "USER_CONTROLLED") == "USER_CONTROLLED", "WORKFLOW_AUTOMATIC_EXECUTION_REFUSED")
        identifier(value.get("workflow_id"))
        title, description, revision = value.get("title"), value.get("description", ""), value.get("revision", 1)
        require(type(title) is str and 1 <= len(title) <= 256 and type(description) is str and len(description) <= 8192,
                "INVALID_WORKFLOW_DESCRIPTION")
        require(type(revision) is int and 1 <= revision <= 2**31 - 1, "INVALID_WORKFLOW_REVISION")
        nodes, edges = value.get("nodes"), value.get("edges", [])
        require(type(nodes) is list and 0 < len(nodes) <= MAX_NODES and type(edges) is list and len(edges) <= MAX_EDGES,
                "WORKFLOW_GRAPH_SIZE_BUDGET")
        profile = json_data(value.get("profile", {"profile_id": "application", "overrides": {}}), configuration=True)
        budget = json_data(value.get("budget", {"seconds": 1800, "max_workers": 2,
            "max_owned_resources": 8, "max_output_bytes": 1024**3}), configuration=True)
        require(type(profile) is dict and type(budget) is dict and set(budget) <= {
            "seconds", "max_workers", "max_owned_resources", "max_output_bytes"}, "INVALID_WORKFLOW_BUDGET_FIELDS")
        number(budget.get("seconds", 1800), .01, MAX_RUN_SECONDS, "INVALID_WORKFLOW_BUDGET")
        require(type(budget.get("max_workers", 2)) is int and 1 <= budget.get("max_workers", 2) <= MAX_WORKERS,
                "INVALID_WORKFLOW_PARALLELISM")
        require(type(budget.get("max_owned_resources", 8)) is int and 1 <= budget.get("max_owned_resources", 8) <= 64 and
            type(budget.get("max_output_bytes", 1024**3)) is int and 1024 <= budget.get("max_output_bytes", 1024**3) <= 4 * 1024**3,
            "INVALID_WORKFLOW_RESOURCE_BUDGET")
        result = cls(value["workflow_id"], title, tuple(NodeDefinition.from_dict(n) for n in nodes),
                     tuple(EdgeDefinition.from_dict(e) for e in edges), description, revision, profile, budget)
        require(len(canonical(result.to_dict()).encode()) <= MAX_DEFINITION_BYTES, "WORKFLOW_JSON_BYTE_BUDGET")
        return result

    def to_dict(self):
        return {"schema": SCHEMA, "schema_version": 1, "workflow_id": self.workflow_id, "title": self.title,
            "description": self.description, "revision": self.revision, "mode": "USER_CONTROLLED",
            "profile": self.profile, "budget": self.budget,
            "nodes": [n.to_dict() for n in self.nodes], "edges": [e.to_dict() for e in self.edges]}

    @property
    def fingerprint(self):
        return hashlib.sha256(canonical(self.to_dict()).encode()).hexdigest()


@dataclass
class NodeOutcome:
    """One actual component outcome, preserving its legacy status and receipt."""
    status: str
    outputs: dict[str, Artifact | tuple[Artifact, ...]] = field(default_factory=dict)
    receipt: dict | None = None
    descriptor: dict | None = None
    context: dict | None = None
    cleanup: dict = field(default_factory=lambda: {"confirmed": False, "status": "NOT_COLLECTED"})
    execution_started: bool | None = None
    reason_code: str | None = None


@dataclass(frozen=True)
class ToolAdapter:
    tool_id: str
    descriptor: ToolDescriptor
    inputs: dict[str, PortSpec]
    outputs: dict[str, PortSpec]
    parameters: dict
    execute: Callable[..., NodeOutcome]
    read_only: bool = True
    confirmation_required: bool = False
    resources: tuple[str, ...] = ()
    available: bool = True
    unavailable_reason: str | None = None
    validate_parameters: Callable[[dict], Any] | None = None

    def to_dict(self):
        return {"tool_id": self.tool_id, "descriptor": self.descriptor.to_dict(),
            "inputs": {k: v.to_dict() for k, v in self.inputs.items()},
            "outputs": {k: v.to_dict() for k, v in {**self.outputs, "receipt": PortSpec(("RECEIPT",))}.items()},
            "parameters": self.parameters, "read_only": self.read_only,
            "confirmation_required": self.confirmation_required, "resources": list(self.resources),
            "available": self.available, "unavailable_reason": self.unavailable_reason}


def control_ports(kind):
    if kind == "CONDITION":
        types = tuple(sorted(PORT_TYPES - {"BOOLEAN", "PROCESS_SET"}))
        return {"input": PortSpec(types)}, {"true": PortSpec(("BOOLEAN",)), "false": PortSpec(("BOOLEAN",))}
    if kind == "JOIN":
        types = tuple(sorted(PORT_TYPES - {"BOOLEAN", "RECEIPT"}))
        return {"evidence": PortSpec(types, many=True)}, {"evidence": PortSpec(("EVIDENCE_SET",))}
    if kind == "CHECKPOINT":
        return {"after": PortSpec(("RECEIPT",), required=False, many=True)}, {"continue": PortSpec(("BOOLEAN",))}
    raise WorkflowError("INVALID_WORKFLOW_CONTROL_KIND")
