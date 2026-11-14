"""Passive diagnostic profiles. Planning scope never grants native consent."""
from __future__ import annotations

from pathlib import Path
import hashlib
from uuid import uuid4

from .chain_contracts import (MAX_DEPTH, MAX_DEFINITION_BYTES, MAX_RUN_SECONDS, MAX_WORKERS, PROFILE_SCHEMA, WorkflowError,
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
    from .chain_io import fingerprint_file
    path = safe_path(Path(path))
    before = fingerprint_file(path, max_bytes=MAX_DEFINITION_BYTES)
    with path.open("rb") as stream:
        raw = stream.read(MAX_DEFINITION_BYTES + 1)
    require(len(raw) <= MAX_DEFINITION_BYTES and hashlib.sha256(raw).hexdigest()==before["sha256"],
            "WORKFLOW_PROFILE_CHANGED_DURING_READ")
    require(fingerprint_file(path, max_bytes=MAX_DEFINITION_BYTES)==before, "WORKFLOW_PROFILE_CHANGED_DURING_READ")
    return validate_profile(parse_json(raw))


def verify_source_scope(artifact, source_ids, *, known_artifacts=(), inputs=None,
                        output_dir=None, cancel=None, deadline=None, owner_run_id=None):
    """Check selected byte roots without rewriting component source identities.

    A derived source ID may differ from a selected file's SHA. Its dependency
    references must match actual published workflow artifacts and resolve to
    selected, rehashed roots. New derived files must belong to this invocation;
    a source label or a copied ``upstream_artifacts`` list alone grants nothing.
    This is a descriptive workflow boundary, not OS authority or causal proof.
    """
    from .chain_contracts import Artifact, canonical
    from .chain_io import verify_artifact
    require(type(source_ids) in (list, tuple) and len(source_ids) <= 256 and
            all(type(value) is str for value in source_ids), "INVALID_PROFILE_SELECTION")
    if not isinstance(artifact, Artifact):
        artifact = Artifact.from_dict(artifact)
    verify_artifact(artifact, cancel=cancel, deadline=deadline, owner_run_id=owner_run_id)
    if not source_ids or artifact.kind in ("RECEIPT", "BOOLEAN", "PROCESS"):
        return {"scope": "WORKFLOW_PLAN_ONLY_NOT_AUTHORIZATION", "byte_roots": []}
    allowed = {value.lower() if len(value)==64 and all(character in "0123456789abcdefABCDEF" for character in value)
               else value for value in source_ids}
    # A selected SHA cannot be reinterpreted as an arbitrary metadata alias
    # attached to different bytes by an imported source declaration.
    aliases = {value for value in allowed if not (len(value) == 64 and
               all(character in "0123456789abcdefABCDEF" for character in value))}
    registry, roots, visiting, verified = {}, {}, set(), {canonical(artifact.to_dict())}

    def normalized(value):
        row = value.to_dict()
        row["value"] = {key: item for key, item in row["value"].items() if key != "upstream_artifacts"}
        return canonical(row)

    for value in known_artifacts:
        value = value if isinstance(value, Artifact) else Artifact.from_dict(value)
        require(len(registry) < 4096 or value.artifact_id in registry, "WORKFLOW_PROFILE_LINEAGE_BUDGET")
        previous = registry.get(value.artifact_id)
        require(previous is None or normalized(previous) == normalized(value),
                "WORKFLOW_ARTIFACT_ID_CONTRADICTION")
        registry[value.artifact_id] = value

    def dependencies(value):
        members = value.value.get("items", []) if value.kind == "EVIDENCE_SET" else []
        upstream = value.value.get("upstream_artifacts", [])
        require(type(members) is list and type(upstream) is list and len(members) + len(upstream) <= 1024,
                "WORKFLOW_PROFILE_LINEAGE_BUDGET")
        return [Artifact.from_dict(row) for row in [*upstream, *members]]

    def published(reference):
        existing = registry.get(reference.artifact_id)
        require(existing is not None and normalized(existing) == normalized(reference),
                "WORKFLOW_PROFILE_UNPUBLISHED_SOURCE_LINEAGE")
        return existing

    def selected(value):
        digest = value.value.get("sha256")
        if type(digest) is not str or not value.value.get("_path"):
            return False
        if digest in allowed:
            return True
        # An arbitrary source ID is usable only when it explicitly names these
        # same revalidated bytes, not a child source embedded in a case file.
        return any(type(source) is dict and source.get("source_id") in aliases and
                   source.get("source_sha256", source.get("sha256")) == digest
                   for source in value.sources)

    def resolve(value, *, fresh=False, depth=0):
        require(depth <= MAX_DEPTH, "WORKFLOW_PROFILE_LINEAGE_BUDGET")
        key = value.artifact_id
        if key in roots:
            return roots[key]
        require(key not in visiting, "WORKFLOW_PROFILE_SOURCE_LINEAGE_CYCLE")
        visiting.add(key)
        try:
            raw = canonical(value.to_dict())
            if raw not in verified:
                verify_artifact(value, cancel=cancel, deadline=deadline, owner_run_id=owner_run_id)
                verified.add(raw)
            require(value.kind not in ("RECEIPT", "BOOLEAN", "PROCESS", "PROCESS_SET"),
                    "WORKFLOW_PROFILE_SOURCE_NOT_ALLOWED")
            own_selected = selected(value)
            refs = dependencies(value)
            gathered = set()
            for reference in refs:
                gathered.update(resolve(published(reference), depth=depth + 1))
            for auxiliary in value.value.get("auxiliary_files", []):
                require(auxiliary.get("sha256") in allowed, "WORKFLOW_PROFILE_AUXILIARY_SOURCE_NOT_ALLOWED")
                gathered.add(auxiliary["sha256"])
            if own_selected:
                gathered.add(value.value["sha256"])
            else:
                require(bool(refs) and bool(gathered), "WORKFLOW_PROFILE_SOURCE_NOT_ALLOWED")
                if fresh and value.kind != "EVIDENCE_SET":
                    path = safe_path(Path(value.value["_path"])) if value.value.get("_path") else None
                    owned = path is not None and output_dir is not None and path.is_relative_to(safe_path(Path(output_dir)))
                    # Actual unchanged passthrough files can retain their source
                    # path; a newly created unrelated external file cannot.
                    same_file = any(all(value.value.get(field) == source.value.get(field) for field in
                        ("_path", "sha256", "bytes", "file_identity", "files")) and path is not None
                        for source in (inputs or ()))
                    require(owned or same_file, "WORKFLOW_PROFILE_UNOWNED_DERIVED_SOURCE")
            roots[key] = gathered
            return gathered
        finally:
            visiting.remove(key)

    if inputs is None:
        # A dispatch input is either a selected file or an actual previously
        # published result. Revalidate full stored lineage, including references
        # omitted by the adapters' intentionally flat dependency representation.
        existing = registry.get(artifact.artifact_id)
        if existing is not None:
            require(normalized(existing) == normalized(artifact), "WORKFLOW_PROFILE_UNPUBLISHED_SOURCE_LINEAGE")
            artifact = existing
        else:
            require(selected(artifact), "WORKFLOW_PROFILE_SOURCE_NOT_ALLOWED")
        accepted = resolve(artifact)
    else:
        existing = registry.get(artifact.artifact_id)
        require(existing is None or normalized(existing) == normalized(artifact),
                "WORKFLOW_ARTIFACT_ID_CONTRADICTION")
        permitted, pending = set(), list(inputs)
        while pending:
            value = pending.pop()
            # Adapters intentionally flatten dependency references. Expand only
            # an exact matching published artifact, never every known artifact
            # or an arbitrary caller-provided source label.
            existing = registry.get(value.artifact_id)
            if existing is not None:
                require(normalized(existing) == normalized(value),
                        "WORKFLOW_PROFILE_UNPUBLISHED_SOURCE_LINEAGE")
                value = existing
            if value.artifact_id in permitted:
                continue
            require(len(permitted) < 4096, "WORKFLOW_PROFILE_LINEAGE_BUDGET")
            permitted.add(value.artifact_id)
            pending.extend(dependencies(value))
        refs = dependencies(artifact)
        require(all(reference.artifact_id in permitted for reference in refs),
                "WORKFLOW_PROFILE_SOURCE_OUTSIDE_CALL_INPUTS")
        accepted = resolve(artifact, fresh=True)
    return {"scope": "VERIFIED_SELECTED_BYTE_ROOTS_NOT_PRODUCER_AUTHENTICATION", "byte_roots": sorted(accepted)}
