"""Passive diagnostic profiles. Planning scope never grants native consent."""
from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from .chain_contracts import (MAX_RUN_SECONDS, MAX_WORKERS, PROFILE_SCHEMA, WorkflowError,
    identifier, json_data, number, parse_json, require)
from .library_files import atomic_json
from .session_v2 import safe_path

_OVERRIDES = frozenset(("allowed_tools", "max_seconds", "max_workers", "max_output_bytes",
                       "allow_effectful", "source_ids", "allowed_node_ids", "target"))


def builtin_profiles():
    return {key: {"schema": PROFILE_SCHEMA, "profile_id": key, "title": title, "scope": scope,
        "inherits": None, "overrides": {"max_seconds": 1800, "max_workers": 2,
            "max_output_bytes": 1024**3, "allow_effectful": False}}
        for key, title, scope in (("windows", "Вся Windows / Windows", "EXPLICIT_SELECTED_OS_SOURCES"),
            ("application", "Выбранное приложение / Selected application", "EXACT_SELECTED_PROCESS"),
            ("case", "Конкретное расследование / Saved investigation", "EXPLICIT_SAVED_EVIDENCE"))}


def _overrides(value):
    value = json_data(value, configuration=True)
    require(type(value) is dict and set(value) <= _OVERRIDES, "INVALID_WORKFLOW_PROFILE_OVERRIDES")
    if "max_seconds" in value:
        number(value["max_seconds"], .01, MAX_RUN_SECONDS, "INVALID_PROFILE_TIME_BUDGET")
    if "max_workers" in value:
        require(type(value["max_workers"]) is int and 1 <= value["max_workers"] <= MAX_WORKERS,
                "INVALID_PROFILE_PARALLELISM")
    if "max_output_bytes" in value:
        require(type(value["max_output_bytes"]) is int and 1024 <= value["max_output_bytes"] <= 4 * 1024**3,
                "INVALID_PROFILE_BYTE_BUDGET")
    if "allow_effectful" in value:
        require(type(value["allow_effectful"]) is bool, "INVALID_PROFILE_EFFECT_POLICY")
    for key in ("allowed_tools", "source_ids", "allowed_node_ids"):
        if key in value:
            require(type(value[key]) is list and len(value[key]) <= 256,
                    "INVALID_PROFILE_SELECTION")
            for item in value[key]:
                identifier(item, "INVALID_PROFILE_SELECTION")
            require(len(set(value[key])) == len(value[key]), "INVALID_PROFILE_SELECTION")
    if value.get("target") is not None:
        from .deep_contracts import ProcessIdentity
        value["target"] = ProcessIdentity.from_dict(value["target"]).to_dict()
    return value


def validate_profile(profile):
    require(type(profile) is dict and set(profile) <= {"schema", "profile_id", "title", "inherits", "overrides"},
            "INVALID_WORKFLOW_PROFILE")
    require(profile.get("schema", PROFILE_SCHEMA) == PROFILE_SCHEMA, "UNSUPPORTED_WORKFLOW_PROFILE_SCHEMA")
    identifier(profile.get("profile_id"))
    require(type(profile.get("title", "")) is str and len(profile.get("title", "")) <= 256,
            "INVALID_WORKFLOW_PROFILE_TITLE")
    if profile.get("inherits") is not None:
        identifier(profile["inherits"])
    return {"schema": PROFILE_SCHEMA, "profile_id": profile["profile_id"], "title": profile.get("title", ""),
            "inherits": profile.get("inherits"), "overrides": _overrides(profile.get("overrides", {}))}


def effective_profile(definition, catalog, *, target=None, profiles=None):
    requested = definition.profile
    require(type(requested) is dict and set(requested) <= {"profile_id", "title", "inherits", "overrides"},
            "INVALID_WORKFLOW_PROFILE_REFERENCE")
    stock = builtin_profiles()
    require(profiles is None or type(profiles) is dict, "INVALID_WORKFLOW_PROFILE_CATALOG")
    custom = profiles or {}
    require(not (set(custom) & set(stock)), "WORKFLOW_BUILTIN_PROFILE_REPLACEMENT_REFUSED")
    for key in custom:
        identifier(key, "INVALID_WORKFLOW_PROFILE_CATALOG")
    known = {**stock, **custom}
    requested_id = identifier(requested.get("profile_id", "application"))
    if requested.get("inherits") is not None:
        identifier(requested["inherits"], "INVALID_WORKFLOW_PROFILE_PARENT")
    require(type(requested.get("title", "")) is str and len(requested.get("title", "")) <= 256,
            "INVALID_WORKFLOW_PROFILE_TITLE")
    current = requested.get("inherits") or requested_id
    chain, layers, visited = [], [], set()
    while current is not None:
        require(current not in visited and len(visited) < 8, "WORKFLOW_PROFILE_INHERITANCE_CYCLE_OR_DEPTH")
        visited.add(current)
        require(current in known, "WORKFLOW_PROFILE_PARENT_MISSING")
        record = known[current]
        if current not in stock:
            record = validate_profile(record)
            require(record["profile_id"] == current, "WORKFLOW_PROFILE_IDENTITY_MISMATCH")
        chain.append(current)
        layers.append(record.get("overrides", {}))
        current = record.get("inherits")
    merged = {}
    for layer in reversed(layers):
        merged.update(_overrides(layer))
    overrides = _overrides(requested.get("overrides", {}))
    merged.update(overrides)
    permitted = merged.get("allowed_tools", list(catalog))
    require(all(tool in catalog for tool in permitted), "WORKFLOW_PROFILE_TOOL_UNAVAILABLE")
    seconds = min(definition.budget.get("seconds", 1800), merged.get("max_seconds", 1800))
    workers = min(definition.budget.get("max_workers", 2), merged.get("max_workers", 2))
    output = min(definition.budget.get("max_output_bytes", 1024**3), merged.get("max_output_bytes", 1024**3))
    effective_target = merged.get("target", target)
    if effective_target is not None:
        from .deep_contracts import ProcessIdentity
        effective_target = ProcessIdentity.from_dict(effective_target).to_dict()
    base = next((item for item in reversed(chain) if item in stock), "case")
    return {"schema": PROFILE_SCHEMA, "profile_id": requested_id, "inherits_chain": chain,
        "scope": stock[base]["scope"], "allowed_tools": list(permitted),
        "max_seconds": seconds, "max_workers": workers, "max_output_bytes": output,
        "allow_effectful": merged.get("allow_effectful", False), "source_ids": merged.get("source_ids", []),
        "allowed_node_ids": merged.get("allowed_node_ids", []), "target": effective_target,
        "overrides": overrides, "authority": "NO_RUNTIME_AUTHORIZATION_OR_SAVED_CONSENT"}


def save_profile(profile, path):
    value = validate_profile(profile)
    path = safe_path(Path(path))
    require(path.name.endswith(".bbprofile.json"), "WORKFLOW_PROFILE_SUFFIX_REQUIRED")
    atomic_json(path, value, exclusive=True)
    require(load_profile(path) == value, "WORKFLOW_PROFILE_READBACK_MISMATCH")
    return value


def load_profile(path):
    return validate_profile(parse_json(safe_path(Path(path)).read_bytes()))
