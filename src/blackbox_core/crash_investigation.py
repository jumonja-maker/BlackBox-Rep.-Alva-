"""A bounded crash view of existing Investigation 3 evidence, not a new engine.

This projection never opens a process, collects WER, requests UAC or reads dump
memory. It keeps source references and reports recorded facts without inferring
an internal root cause from an exception or temporal coincidence.
"""
from __future__ import annotations

import re
from .investigation_graph_contracts import use_budget


def _integer(value, maximum=2**64 - 1):
    return value if type(value) is int and 0 <= value <= maximum else None


def _text(value, limit=160):
    return value[:limit] if isinstance(value, str) else None


def _name(value):
    value = _text(value, 1024)
    return value.replace("\\", "/").rsplit("/", 1)[-1][:160] if value else None


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _rows(value):
    return value if isinstance(value, list) else []


def _digest(value):
    return value if isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) else None


def _version(value):
    return value if isinstance(value, str) and len(value) <= 64 and re.fullmatch(
        r"[0-9]{1,10}(?:\.[0-9]{1,10}){1,3}", value) else None


def validate_crash_report(report, *, nodes=None, budget=None):
    """Validate a bounded saved view without granting its claims authority."""
    from .investigation_graph_contracts import InvestigationError
    budget = use_budget(budget)

    def require(condition, reason):
        if not condition:
            raise InvestigationError(reason)

    require(type(report) is dict and report.get("schema") == "blackbox.crash-investigation/1",
            "INVALID_CRASH_REPORT_SCHEMA")
    require(report.get("root_cause") == "UNKNOWN" and
            report.get("status") in ("NOT_COLLECTED", "INCOMPLETE_EVIDENCE"),
            "CRASH_REPORT_CANNOT_PROVE_ROOT_CAUSE")
    require(set(report) == {"schema", "status", "root_cause", "summary", "events", "dumps", "modules",
                           "threads", "frames", "coverage", "privacy", "limitations"},
            "INVALID_CRASH_REPORT_FIELDS")
    require(report.get("privacy") == {"memory_contents_included": False, "dump_bytes_included": False,
                                     "source_paths": "BASENAME_ONLY"} and
            report["privacy"]["memory_contents_included"] is False and
            report["privacy"]["dump_bytes_included"] is False, "CRASH_REPORT_PRIVATE_PAYLOAD")
    indexed = None
    identifiers = None
    if nodes is not None:
        if isinstance(nodes, dict):
            indexed = nodes
        elif isinstance(nodes, list):
            indexed = {n["node_id"]: n for n in nodes}
        elif isinstance(nodes, (set, frozenset)):
            identifiers = nodes
        else:
            raise InvestigationError("INVALID_CRASH_REPORT_NODE_INDEX")
    refs = {"node_id", "source_id", "source_record_id", "source_sha256", "verification_class", "process_instance_binding"}
    fields = {
        "events": {"provider", "event_id", "record_id", "event_utc_ns", "event_time_domain", "observer_receipt_is_event_time",
                   "recorded_event_sha256", "target_pid", "logger_pid", "recorded_creation_100ns", "recorded_process_binding",
                   "wer_event_name", "report_id", "exception_code", "application_name", "application_version", "module_name",
                   "module_version", "classification"},
        "dumps": {"file", "size_bytes", "sha256", "architecture", "recorded_pid", "recorded_creation_unix_seconds",
                  "exception_stream_recorded", "exception_tid", "exception_code", "exception_address", "exception_node_id",
                  "live_process_binding", "module_count", "thread_count", "memory_range_count", "modules_omitted",
                  "threads_omitted", "memory_ranges_omitted"},
        "modules": {"name", "base_address", "image_size", "image_timestamp", "recorded_pdb_guid", "recorded_pdb_age", "module_binding"},
        "threads": {"tid", "recorded_creation_100ns", "context_status", "context_source", "frame_count", "unwind_status", "unwind_completeness"},
        "frames": {"tid", "ordinal", "address", "module", "rva", "origin", "recorded_symbol", "recorded_symbol_status",
                   "recorded_source_file", "recorded_source_line", "recorded_source_status", "symbol_binding"}}
    names = {"file", "name", "module", "recorded_source_file", "application_name", "module_name"}
    for kind, maximum in (("events", 200), ("dumps", 16), ("modules", 200), ("threads", 200), ("frames", 2000)):
        rows = report.get(kind)
        require(type(rows) is list and len(rows) <= maximum, "CRASH_REPORT_ROW_BUDGET")
        for row in rows:
            budget.check()
            require(type(row) is dict and set(row) == refs | fields[kind], "INVALID_CRASH_REPORT_ROW")
            require(all(value is None or type(value) in (str, int, bool) for value in row.values()),
                    "CRASH_REPORT_PRIVATE_OR_STRUCTURED_PAYLOAD")
            require(all(type(value) is not str or len(value) <= 512 for value in row.values()),
                    "CRASH_REPORT_TEXT_BUDGET")
            require(all(type(value) is not int or 0 <= value < 2**64 for value in row.values()),
                    "INVALID_CRASH_REPORT_NUMBER")
            require(type(row.get("source_record_id")) is str and len(row["source_record_id"]) <= 256 and
                    type(row.get("verification_class")) is str and len(row["verification_class"]) <= 128,
                    "INVALID_CRASH_REPORT_SOURCE_FIELDS")
            require(_digest(row.get("node_id")) and _digest(row.get("source_id")) and _digest(row.get("source_sha256")),
                    "INVALID_CRASH_REPORT_REFERENCE")
            require(row.get("process_instance_binding") == "NOT_ESTABLISHED_FROM_IMPORTED_SOURCE",
                    "CRASH_REPORT_CANNOT_PROMOTE_IMPORT_IDENTITY")
            for key in names & set(row):
                value = row[key]
                require(value is None or isinstance(value, str) and "/" not in value and "\\" not in value,
                        "CRASH_REPORT_FULL_PATH_FORBIDDEN")
            if indexed is not None:
                node = indexed.get(row["node_id"])
                require(isinstance(node, dict) and row["source_id"] == node.get("source_identity") and
                        row["source_record_id"] == node.get("source_record_id") and
                        row["source_sha256"] == node.get("source_sha256") and
                        row["verification_class"] == node.get("verification_class"), "DANGLING_CRASH_REPORT_SOURCE")
            elif identifiers is not None:
                require(row["node_id"] in identifiers, "DANGLING_CRASH_REPORT_SOURCE")
            if kind == "dumps":
                require(row["live_process_binding"] == "NOT_ESTABLISHED", "CRASH_REPORT_LIVE_DUMP_BINDING_FORBIDDEN")
                require(type(row["exception_stream_recorded"]) is bool, "INVALID_CRASH_EXCEPTION_FLAG")
                if row["exception_node_id"] is not None:
                    require(indexed is None or row["exception_node_id"] in indexed, "DANGLING_CRASH_EXCEPTION")
                    require(identifiers is None or row["exception_node_id"] in identifiers, "DANGLING_CRASH_EXCEPTION")
            if kind == "events":
                require(row["classification"] in ("UNATTRIBUTED_WER_REPORT_CANDIDATE_NOT_TARGET_CRASH_PROOF",
                         "RECORDED_FAILURE_EVENT_NOT_INTERNAL_ROOT_CAUSE"), "INVALID_CRASH_EVENT_CLASSIFICATION")
                require(row["event_id"] in {"Application Error": {1000}, "Windows Error Reporting": {1001},
                        ".NET Runtime": {1026}}.get(row["provider"], set()), "INVALID_CRASH_EVENT_PROVIDER")
                require(row["observer_receipt_is_event_time"] is False and
                        row["event_time_domain"] == "EVENTLOG_UTC:" + row["source_id"], "CRASH_REPORT_CLOCK_DOMAIN_MISMATCH")
                require(all(row[key] is None or _version(row[key]) == row[key]
                            for key in ("application_version", "module_version")), "INVALID_CRASH_RECORDED_VERSION")
                if row["classification"] == "UNATTRIBUTED_WER_REPORT_CANDIDATE_NOT_TARGET_CRASH_PROOF":
                    require(row["target_pid"] is None and row["recorded_creation_100ns"] is None and
                            row["recorded_process_binding"] == "NOT_ESTABLISHED_IMAGE_AND_TIME_CANDIDATE_ONLY",
                            "WER_CANDIDATE_CANNOT_CLAIM_PROCESS_IDENTITY")
    require(isinstance(report.get("limitations"), list) and len(report["limitations"]) <= 32 and
            all(type(v) is str and len(v) <= 256 for v in report["limitations"]), "CRASH_REPORT_LIMITATION_BUDGET")
    expected_summary = {"failure_events": len(report["events"]), "saved_dumps": len(report["dumps"]),
        "recorded_exceptions": sum(d["exception_stream_recorded"] for d in report["dumps"]),
        "modules": len(report["modules"]), "threads": len(report["threads"]), "frames": len(report["frames"]),
        "unwound_callers": sum(f["origin"] == "DBGHELP_UNWOUND_CALLER" for f in report["frames"]),
        "unattributed_wer_candidates": sum(e["classification"] == "UNATTRIBUTED_WER_REPORT_CANDIDATE_NOT_TARGET_CRASH_PROOF"
                                         for e in report["events"])}
    require(report.get("summary") == expected_summary and
            all(type(v) is int for v in report["summary"].values()), "INVALID_CRASH_REPORT_SUMMARY")
    require(isinstance(report.get("coverage"), dict) and set(report["coverage"]) ==
            {"invalid_records", "omitted_records", "source_completeness"} and
            report["coverage"].get("source_completeness") == "NOT_PROVEN" and
            all(type(report["coverage"].get(key)) is int and 0 <= report["coverage"][key] < 2**63
                for key in ("invalid_records", "omitted_records")),
            "CRASH_REPORT_CANNOT_PROMOTE_COMPLETENESS")
    budget.result(report)
    return report


def project_crash_evidence(case, *, budget=None, cancel_event=None):
    """Project selected graph evidence without authenticating imported labels."""
    from .evidence_graph import validate_case
    budget = use_budget(budget, cancel_event=cancel_event)
    validate_case(case, budget=budget)
    nodes = case["nodes"]
    by_record = {(n["source_identity"], n["source_record_id"]): n for n in nodes}
    events, dumps, modules, threads, frames = [], [], [], [], []
    invalid = omitted = 0

    def reference(node, record=None):
        bound = by_record.get((node["source_identity"], record), node)
        return {"node_id": bound["node_id"], "source_id": bound["source_identity"],
                "source_record_id": bound["source_record_id"], "source_sha256": bound["source_sha256"],
                "verification_class": bound["verification_class"],
                "process_instance_binding": "NOT_ESTABLISHED_FROM_IMPORTED_SOURCE"}

    def add_event(node, event, candidate=False):
        nonlocal omitted, invalid
        if len(events) >= 200:
            omitted += 1
            return
        event = _mapping(event)
        if not event or event.get("provider") not in ("Application Error", "Windows Error Reporting", ".NET Runtime"):
            invalid += 1
            return
        application = _mapping(event.get("application"))
        module = _mapping(event.get("faulting_module"))
        events.append({**reference(node), "provider": event["provider"],
            "event_id": _integer(event.get("event_id"), 65535),
            "record_id": _text(event.get("record_id"), 32),
            "event_utc_ns": _integer(event.get("event_utc_ns")),
            "event_time_domain": "EVENTLOG_UTC:" + node["source_identity"],
            "observer_receipt_is_event_time": False,
            "recorded_event_sha256": _digest(event.get("source_sha256")),
            "target_pid": None if candidate else _integer(event.get("target_pid"), 0xFFFFFFFF),
            "logger_pid": _integer(event.get("logger_pid"), 0xFFFFFFFF),
            "recorded_creation_100ns": None if candidate else _integer(event.get("recorded_creation_100ns")),
            "recorded_process_binding": "NOT_ESTABLISHED_IMAGE_AND_TIME_CANDIDATE_ONLY"
            if candidate else _text(event.get("process_instance_binding")),
            "wer_event_name": _text(event.get("wer_event_name"), 32),
            "report_id": _text(event.get("report_id"), 38),
            "exception_code": _integer(event.get("exception_code"), 0xFFFFFFFF),
            "application_name": _name(application.get("name")),
            "application_version": _version(application.get("version")),
            "module_name": _name(module.get("name")), "module_version": _version(module.get("version")),
            "classification": "UNATTRIBUTED_WER_REPORT_CANDIDATE_NOT_TARGET_CRASH_PROOF"
            if candidate else "RECORDED_FAILURE_EVENT_NOT_INTERNAL_ROOT_CAUSE"})

    for node in nodes:
        budget.check()
        metadata = _mapping(node.get("metadata"))
        if metadata.get("kind") in ("WINDOWS_CRASH_EVENT", "WINDOWS_WER_CANDIDATE"):
            add_event(node, metadata.get("event"), metadata.get("kind") == "WINDOWS_WER_CANDIDATE")
        if metadata.get("event_kind") == "crash.system_events":
            fields = _mapping(metadata.get("fields"))
            for event in _rows(fields.get("events"))[:200]:
                budget.check()
                add_event(node, event)
            for event in _rows(fields.get("wer_candidates"))[:20]:
                budget.check()
                add_event(node, event, True)
        if metadata.get("kind") != "SAVED_MINIDUMP":
            continue
        if len(dumps) >= 16:
            omitted += 1
            continue
        report = _mapping(metadata.get("report"))
        data = _mapping(report.get("data"))
        if not data:
            invalid += 1
            continue
        exception = _mapping(data.get("exception"))
        coverage = _mapping(data.get("coverage"))
        dumps.append({**reference(node), "file": _name(data.get("file")),
            "size_bytes": _integer(data.get("size_bytes")), "sha256": _digest(data.get("sha256")),
            "architecture": _text(data.get("architecture")), "recorded_pid": _integer(data.get("recorded_pid"), 0xFFFFFFFF),
            "recorded_creation_unix_seconds": _integer(data.get("recorded_creation_unix_seconds")),
            "exception_stream_recorded": bool(exception),
            "exception_tid": _integer(exception.get("tid"), 0xFFFFFFFF),
            "exception_code": _integer(exception.get("code"), 0xFFFFFFFF),
            "exception_address": _integer(exception.get("address")),
            "exception_node_id": reference(node, "minidump:exception")["node_id"] if exception else None,
            "live_process_binding": "NOT_ESTABLISHED",
            "module_count": _integer(coverage.get("module_count")),
            "thread_count": _integer(coverage.get("thread_count")),
            "memory_range_count": _integer(coverage.get("memory_range_count")),
            "modules_omitted": _integer(coverage.get("modules_omitted")),
            "threads_omitted": _integer(coverage.get("threads_omitted")),
            "memory_ranges_omitted": _integer(coverage.get("memory_ranges_omitted"))})
        module_rows = _rows(data.get("modules"))
        omitted += max(0, len(module_rows) - 200)
        for index, value in enumerate(module_rows[:200]):
            budget.check()
            if len(modules) >= 200:
                omitted += min(len(module_rows), 200) - index
                break
            value = _mapping(value)
            pdb = _mapping(value.get("pdb_identity"))
            modules.append({**reference(node, "minidump:module:" + str(index)),
                "name": _name(value.get("name")), "base_address": _integer(value.get("base_address")),
                "image_size": _integer(value.get("image_size"), 0xFFFFFFFF),
                "image_timestamp": _integer(value.get("image_timestamp"), 0xFFFFFFFF),
                "recorded_pdb_guid": _text(pdb.get("guid"), 36),
                "recorded_pdb_age": _integer(pdb.get("age"), 0xFFFFFFFF),
                "module_binding": "RECORDED_DUMP_MODULE_NOT_LIVE_LOAD_PROOF"})
        unwound = _mapping(data.get("stack_unwind"))
        unwind_rows = unwound.get("threads", [])
        unwind_rows = unwind_rows if isinstance(unwind_rows, list) else []
        by_tid = {r.get("tid"): r for r in unwind_rows if isinstance(r, dict)}
        thread_rows = _rows(data.get("threads"))
        omitted += max(0, len(thread_rows) - 200)
        for thread_index, value in enumerate(thread_rows[:200]):
            budget.check()
            if len(threads) >= 200:
                omitted += min(len(thread_rows), 200) - thread_index
                break
            value = _mapping(value)
            tid = _integer(value.get("tid"), 0xFFFFFFFF)
            context = _mapping(value.get("context"))
            unwind = _mapping(by_tid.get(tid))
            stack_node = by_record.get((node["source_identity"], "minidump:stack:" + str(tid)), {})
            stack_metadata = _mapping(stack_node.get("metadata"))
            rows = stack_metadata.get("frames", unwind.get("frames", value.get("frames", [])))
            rows = rows if isinstance(rows, list) else []
            omitted += max(0, len(rows) - 128)
            threads.append({**reference(node, "minidump:thread:" + str(tid)), "tid": tid,
                "recorded_creation_100ns": _integer(value.get("recorded_creation_100ns")),
                "context_status": _text(stack_metadata.get("context_status")) or _text(context.get("status")),
                "context_source": _text(stack_metadata.get("context_source")) or _text(value.get("context_source")),
                "frame_count": len(rows),
                "unwind_status": _text(stack_metadata.get("unwind_status")) or _text(unwind.get("status")) or "ONLY_CAPTURED_CONTEXT_PC",
                "unwind_completeness": "NOT_PROVEN"})
            for ordinal, frame in enumerate(rows[:128]):
                budget.check()
                if len(frames) >= 2000:
                    omitted += min(len(rows), 128) - ordinal
                    break
                frame = _mapping(frame)
                symbol = _mapping(frame.get("symbol"))
                location = _mapping(symbol.get("source_location"))
                saved_module = _mapping(frame.get("module"))
                frames.append({**reference(node, "minidump:stack:" + str(tid)),
                    "tid": tid, "ordinal": ordinal,
                    "address": _integer(frame.get("address", frame.get("instruction_pointer"))),
                    "module": _name(frame.get("module")) if isinstance(frame.get("module"), str) else _name(saved_module.get("name")),
                    "rva": _integer(frame.get("rva", saved_module.get("rva"))),
                    "origin": _text(frame.get("origin", frame.get("method"))),
                    "recorded_symbol": _text(symbol.get("name"), 512),
                    "recorded_symbol_status": _text(symbol.get("status")),
                    "recorded_source_file": _name(location.get("file")),
                    "recorded_source_line": _integer(location.get("line"), 2**31 - 1),
                    "recorded_source_status": _text(symbol.get("source_status")),
                    "symbol_binding": _text(frame.get("symbol_binding"))})
    result = {"schema": "blackbox.crash-investigation/1",
        "status": "INCOMPLETE_EVIDENCE" if events or dumps else "NOT_COLLECTED",
        "root_cause": "UNKNOWN", "events": events, "dumps": dumps, "modules": modules,
        "threads": threads, "frames": frames,
        "summary": {"failure_events": len(events), "saved_dumps": len(dumps),
            "recorded_exceptions": sum(d["exception_stream_recorded"] for d in dumps),
            "modules": len(modules), "threads": len(threads), "frames": len(frames),
            "unwound_callers": sum(f["origin"] == "DBGHELP_UNWOUND_CALLER" for f in frames),
            "unattributed_wer_candidates": sum(e["classification"] == "UNATTRIBUTED_WER_REPORT_CANDIDATE_NOT_TARGET_CRASH_PROOF" for e in events)},
        "coverage": {"invalid_records": invalid, "omitted_records": omitted, "source_completeness": "NOT_PROVEN"},
        "privacy": {"memory_contents_included": False, "dump_bytes_included": False,
                    "source_paths": "BASENAME_ONLY"},
        "limitations": ["PROCESS_EXIT_ALONE_IS_NOT_A_CRASH", "NO_DATA_IS_NOT_PROOF_OF_NO_CRASH",
            "IMPORTED_DUMP_PID_AND_SECOND_RESOLUTION_BIRTH_DO_NOT_ATTEST_LIVE_FILETIME",
            "RECORDED_EXCEPTION_OR_MODULE_DOES_NOT_PROVE_INTERNAL_ROOT_CAUSE",
            "PDB_LINE_METADATA_DOES_NOT_READ_OR_AUTHENTICATE_SOURCE_CODE",
            "MANAGED_HEAP_AND_UNIVERSAL_WINDBG_ANALYSIS_NOT_PERFORMED"]}
    return validate_crash_report(result, nodes=nodes, budget=budget)
