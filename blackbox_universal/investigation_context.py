"""Bounded user-declared context, prepared only in the read worker.

A selected binary's hash proves its bytes. It does not authenticate a source,
prove which historical process used it, or verify the declared workload.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from blackbox_core.investigation_graph_contracts import InvestigationError, stable_id, use_budget

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")


def _stamp(value):
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _read_stable(path, budget, *, collect=False):
    selected = Path(path)
    if selected.is_symlink():
        raise InvestigationError("CONTEXT_FILE_SYMLINK_NOT_ALLOWED")
    selected = selected.resolve(strict=True)
    limit = 16384 if collect else budget.max_source_bytes
    digest, chunks, total = hashlib.sha256(), [], 0
    with selected.open("rb") as stream:
        initial = os.fstat(stream.fileno())
        if not stat.S_ISREG(initial.st_mode) or initial.st_size > limit:
            raise InvestigationError("CONTEXT_REGULAR_FILE_BYTE_BUDGET")
        while True:
            budget.check()
            data = stream.read(min(1024 * 1024, limit - total + 1))
            if not data:
                break
            total += len(data)
            if total > limit:
                raise InvestigationError("CONTEXT_FILE_BYTE_BUDGET")
            digest.update(data)
            if collect:
                chunks.append(data)
        if _stamp(initial) != _stamp(os.fstat(stream.fileno())) or _stamp(initial) != _stamp(selected.stat()):
            raise InvestigationError("CONTEXT_FILE_CHANGED_DURING_READ")
    budget.check()
    return {"sha256": digest.hexdigest(), "size_bytes": total}, b"".join(chunks)


def _integer(value, key, *, minimum=0):
    if type(value) is str and value.isascii() and value.isdecimal() and len(value) <= 19:
        value = int(value)
    if type(value) is not int or not minimum <= value <= 2**63 - 1:
        raise InvestigationError("INVALID_DECLARED_CONTEXT_" + key.upper())
    return value


def prepare_user_context(*, app_fields, scenario_fields, binary_path=None,
                         context_path=None, scope_confirmed=False, budget=None):
    budget = use_budget(budget)
    if scope_confirmed is not True:
        raise InvestigationError("EXPLICIT_ENTIRE_CASE_CONTEXT_DECLARATION_REQUIRED")
    context_file = None
    if context_path:
        context_file, raw = _read_stable(context_path, budget, collect=True)
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise InvestigationError("DUPLICATE_DECLARED_CONTEXT_FIELD")
                result[key] = value
            return result
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique)
        if type(value) is not dict or set(value) - {"app_identity", "scenario"}:
            raise InvestigationError("INVALID_DECLARED_CONTEXT_FILE")
        app_fields, scenario_fields = value.get("app_identity", {}), value.get("scenario", {})
    if (type(app_fields) is not dict or set(app_fields) - {"application_id", "version"} or
            type(scenario_fields) is not dict or set(scenario_fields) - {
                "scenario_id", "workload_id", "source_profile", "operation_count", "input_bytes", "complete"}):
        raise InvestigationError("INVALID_DECLARED_CONTEXT_FIELDS")
    app, scenario = dict(app_fields), dict(scenario_fields)
    family, version = app.get("application_id"), app.get("version")
    if (type(family) is not str or _NAME.fullmatch(family) is None or type(version) is not str or
            not 1 <= len(version) <= 128 or any(ord(c) < 32 or c in "\\/" for c in version)):
        raise InvestigationError("INVALID_DECLARED_APPLICATION_ID_OR_VERSION")
    for key in ("scenario_id", "workload_id", "source_profile"):
        if type(scenario.get(key)) is not str or _NAME.fullmatch(scenario[key]) is None:
            raise InvestigationError("INVALID_DECLARED_CONTEXT_" + key.upper())
    scenario["operation_count"] = _integer(scenario.get("operation_count"), "operation_count", minimum=1)
    scenario["input_bytes"] = _integer(scenario.get("input_bytes"), "input_bytes")
    if type(scenario.get("complete")) is not bool:
        raise InvestigationError("DECLARED_WORKLOAD_COMPLETENESS_REQUIRED")
    app.update(verification_class="USER_REPORTED", source_binding="USER_REPORTED",
               identity_origin="USER_REPORTED", context_scope="ENTIRE_CASE")
    if binary_path:
        observed, _ = _read_stable(binary_path, budget)
        app.update(sha256=observed["sha256"], binary_size_bytes=observed["size_bytes"],
                   verification_class="USER_SELECTED_FILE_SHA256", file_hash_status="STABLE_FILE_OBSERVED")
    scenario.update(verification_class="USER_REPORTED", context_scope="ENTIRE_CASE")
    result = {"app_identity": app, "scenario": scenario,
              "source_binding": "NOT_ESTABLISHED", "context_provenance": "USER_REPORTED"}
    if context_file is not None:
        result["declaration_file_sha256"] = context_file["sha256"]
    return budget.result(result)


def apply_user_context(case, context, *, budget=None):
    """Create another immutable investigation; keep the original untouched."""
    from blackbox_core.evidence_graph import validate_case
    from blackbox_core.issue_grouping import group_recurrent_issues
    budget = use_budget(budget)
    validate_case(case, budget=budget)
    value = deepcopy(case)
    value.update(case_id=stable_id("declared-context-case", case["case_id"], context),
                 context_parent_case_id=case["case_id"], app_identity=context["app_identity"],
                 scenario=context["scenario"], context_provenance="USER_REPORTED",
                 declared_context_source_binding="NOT_ESTABLISHED")
    value["context_declaration"] = {"scope": "ENTIRE_CASE", "actor": "USER",
        "verification_class": "USER_REPORTED", "source_binding": "NOT_ESTABLISHED",
        "source_ids": [source["source_id"] for source in value["sources"]],
        "selected_file_sha256": context["app_identity"].get("sha256")}
    if context.get("declaration_file_sha256"):
        value["context_declaration"]["declaration_file_sha256"] = context["declaration_file_sha256"]
    value.pop("issue_grouping", None)
    value.pop("version_comparison", None)
    value.pop("_index_receipt", None)
    value["limitations"] = list(dict.fromkeys([*value.get("limitations", []),
        "APPLICATION_BINARY_ASSOCIATION_AND_WORKLOAD_CONTEXT_ARE_USER_DECLARED",
        "SELECTED_FILE_HASH_DOES_NOT_ESTABLISH_HISTORICAL_PROCESS_BINDING"]))
    grouping = group_recurrent_issues([value], budget=budget)
    value["issues"] = grouping["groups"] + grouping["candidates"]
    value["coverage"] = {**value.get("coverage", {}), "issue_groups": len(grouping["groups"]),
                         "candidate_issues": len(grouping["candidates"])}
    validate_case(value, budget=budget)
    return budget.result(value)
