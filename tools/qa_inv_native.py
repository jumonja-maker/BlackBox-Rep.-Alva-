"""Actual BB-INV-003 Windows sources and correlation oracles (hosted only).

Real ETW, WCT/PSS and helper operations remain separate from explicit negative
format fixtures. Source identities and missing joins are checked, not guessed.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from tools.qa_inv_common import (assert_sources_unchanged, digest, exact_source, graph_facts,
    metadata, readonly, require, require_hosted, save, trace_source, validate_export)


def inspect_case(case):
    graph_facts(case)
    for hypothesis in case["hypotheses"]:
        require(hypothesis.get("root_cause_proven") is False and
                type(hypothesis.get("alternatives")) is list and
                type(hypothesis.get("missing_data")) is list and
                hypothesis.get("supporting_nodes"),
                "HYPOTHESIS_CAUSE_OR_UNCERTAINTY_CONTRACT_LOST")
        require(hypothesis.get("status") != "USER_CONFIRMED", "ENGINE_INVENTED_USER_CONFIRMATION")
    return {"case_id": case["case_id"], "nodes": len(case["nodes"]), "edges": len(case["edges"]),
            "coverage": case["coverage"], "hypothesis_categories": sorted({
                hypothesis["category"] for hypothesis in case["hypotheses"]}),
            "critical_path_status": case["critical_path"]["status"]}


def assert_sdk_file_case(case, oracle):
    nodes = [node for node in case["nodes"] if node["observation_type"] in ("FILE_OPERATION", "ERROR")]
    actual = {row["operation_id"]: row for row in oracle["operations"]}
    ended = {node["metadata"].get("operation_id"): node for node in nodes
             if node["metadata"].get("status") in ("ERROR", "COMPLETED")}
    require(set(actual) <= set(ended), "ACTUAL_SDK_FILE_RESULTS_NOT_REPRESENTED")
    for identifier, observed in actual.items():
        node = ended[identifier]
        require(node["metadata"].get("error_code") == observed["actual_winerror"] and
                node["metadata"].get("status") == observed["status"],
                "APPLICATION_RESULT_CHANGED_DURING_NORMALIZATION")
        require(node["source_type"] == "EVENTS_JSONL" and
                node["verification_class"] not in ("OS_OBSERVED", "EXACT_IDENTITY"),
                "APPLICATION_STATEMENT_PROMOTED_TO_OS_AUTHORITY")
    errors = [node for node in nodes if node["metadata"].get("status") == "ERROR"]
    require(errors and any(h["category"] == "FILE_OPERATION_ERROR" and
                          set(h["supporting_nodes"]) & {node["node_id"] for node in errors}
                          for h in case["hypotheses"]),
            "ACTUAL_FILE_ERROR_HYPOTHESIS_WITH_SOURCE_FACTS_REQUIRED")
    require(any(edge["relation_type"] == "DIRECT_REFERENCE" for edge in case["edges"]),
            "SDK_BEGIN_END_REFERENCE_NOT_REPRESENTED")


def medium_worker(output, source_path, helper=None):
    from blackbox_core.deep_contracts import ActionRequest
    from blackbox_core.deep_ipc import token_authority
    from blackbox_core.deep_service import InspectorService
    from blackbox_core.investigation_v3 import create_investigation
    from blackbox_core.windows_research import privilege
    from tools.qa_deep_inspection import Probe

    output.mkdir(parents=True, exist_ok=False)
    proof = {"status": "FAIL", "scope": "ACTUAL_MEDIUM_GRAPH_READ_AND_SCOPED_ACTION_REFUSAL",
             "secure_desktop": "NOT_TESTED", "privilege": privilege(), "authority": token_authority()}
    service = probe = None
    try:
        require(proof["privilege"]["mode"] == "STANDARD" and
                proof["authority"]["integrity_sid"] == "S-1-16-8192" and
                proof["authority"]["elevated"] is False, "ACTUAL_MEDIUM_TOKEN_REQUIRED")
        case = create_investigation([{"source_type": "EVENTS_JSONL", "path": str(source_path)}],
                                   budget={"timeout_seconds": 120}, index_path=output / "case.sqlite3")
        proof["offline_graph"] = inspect_case(case)
        executable = Path(os.environ["BB_INV_QA_PROBE_EXE"])
        probe = Probe(executable, output / "probe")
        service = InspectorService(journal_root=output / "journal", helper_executable=helper)
        target = service.identity(probe.process.pid)
        destination = output / "must-not-exist.etl"
        result = service.execute(ActionRequest("profile.etw", target,
            {"destination": str(destination), "duration_seconds": 1,
             "profile": "BLACKBOX.Deep.Light", "systemwide_confirmed": True}, True, 30))
        require(result["status"] == "ADMIN_REQUIRED" and not destination.exists(),
                "STANDARD_PROFILE_DID_NOT_REFUSE_BEFORE_OUTPUT_OR_CAPTURE")
        proof.update(status="PASS", native_refusal={"status": result["status"],
            "operation_id": result["operation_id"], "output_created": False,
            "interactive_uac": "NOT_TESTED"})
    except BaseException as error:
        proof.update(status="FAIL", error=type(error).__name__, reason=str(error)[:1500],
                     traceback=traceback.format_exc(limit=8))
    finally:
        if service is not None:
            try:
                proof["helper_cleanup"] = service.close()
            except BaseException as error:
                proof["helper_cleanup"] = {"status": "FAILED", "reason": str(error)[:1000]}
            if proof["helper_cleanup"].get("status") != "COMPLETED":
                proof["status"] = "FAIL"
        if probe is not None:
            try:
                proof["target_cleanup"] = probe.close(kill=proof["status"] != "PASS")
            except BaseException as error:
                proof.update(status="FAIL", target_cleanup={"status": "FAILED", "reason": str(error)[:1000]})
        save(output / "medium-result.json", proof)
    return 0 if proof["status"] == "PASS" else 1


def run(args):
    require_hosted(windows=True)
    from blackbox_core.deep_contracts import ActionRequest
    from blackbox_core.deep_service import InspectorService
    from blackbox_core.decoder_service import decode_file
    from blackbox_core.investigation_v3 import (create_investigation, compare_investigations,
        export_investigation, group_recurrent_issues)
    from blackbox_core.optional_jobs import OwnedProcess
    from tools.qa_decoder_patch import build_pair
    from tools.qa_deep_inspection import Probe, build_probe
    from tools.qa_schedule_capture import OwnedScheduleCapture
    from unittest.mock import patch

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    proof = {"status": "RUNNING", "source_sha": exact_source(),
             "scope": "ACTUAL_WINDOWS_ETW_WCT_PSS_APPLICATION_FILE_ERROR_AND_DIAGNOSTIC_HELPER",
             "secure_desktop": "NOT_TESTED", "physical_windows_10_11": "NOT_TESTED",
             "cases": {}, "operations": []}
    probe = service = capture = cpu = None
    children, streams, before_hashes = [], [], {}
    successful = False

    def phase(name):
        proof["phase"] = name
        save(output / "native-investigation-qa.json", proof)
        print("INV_NATIVE_PHASE " + name, flush=True)

    try:
        phase("COMPILE_AND_START_OWNED_NATIVE_FIXTURES")
        executable = build_probe(output / "build")
        probe = Probe(executable, output / "probe")
        oracle = probe.ready
        service = InspectorService(journal_root=output / "journal",
                                   helper_executable=args.diagnostic_helper.resolve(strict=True)
                                   if args.diagnostic_helper else None)
        target = service.identity(probe.process.pid)
        require(target.created_100ns == oracle["created_100ns"], "NATIVE_EXACT_TARGET_IDENTITY_REQUIRED")
        cpu_folder = output / "cpu-build"
        cpu_folder.mkdir()
        cpu_exe, cpu_pdb = build_pair(cpu_folder, busy=True)
        capture_folder = output / "capture"
        capture_folder.mkdir()
        capture = OwnedScheduleCapture(capture_folder)
        proof["capture_start"] = capture.start()
        cpu = OwnedProcess([str(cpu_exe)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cpu_pid = cpu.process.pid

        def launch(label, command):
            log = (output / (label + ".log")).open("wb")
            streams.append(log)
            owner = OwnedProcess(command, stdout=log, stderr=subprocess.STDOUT, detach_console=True)
            children.append((label, owner))
            return owner

        wait_oracle_path = output / "wait-fixture.json"
        wait = launch("wait-fixture", [sys.executable, str(ROOT / "tools/fixtures/ThreadWaitProbe/probe.py"),
                                        str(wait_oracle_path)])
        file_source = (ROOT / "tools/fixtures/inv_file_error.py").read_text()
        variants = {}
        file_runs = []
        for version in ("A", "B"):
            path = output / ("file-application-" + version + ".py")
            path.write_text(file_source.replace('WORKLOAD_VERSION = "A"', 'WORKLOAD_VERSION = "' + version + '"'))
            variants[version] = path
        for label, version, error in (("same-1", "A", 5), ("same-2", "A", 5),
                                       ("same-3", "A", 5), ("different-error", "A", 2),
                                       ("version-B", "B", 5)):
            folder = output / label
            owner = launch(label, [sys.executable, str(variants[version]), "--output", str(folder),
                                   "--error-code", str(error), "--operations", "6"])
            file_runs.append((label, version, error, folder, owner))

        def action(operation, parameters=None, *, confirmed=False, statuses=("COMPLETED", "INCOMPLETE_EVIDENCE")):
            result = service.execute(ActionRequest(operation, target, parameters or {}, confirmed, 30))
            require(result["status"] in statuses, "ACTUAL_DIAGNOSTIC_ACTION_FAILED_" + operation + ":" + str(result.get("error")))
            proof["operations"].append({"operation": operation, "operation_id": result["operation_id"],
                                        "status": result["status"]})
            return result

        phase("ACTUAL_WCT_PSS_AND_BEFORE_AFTER_INTERVENTION")
        thread = {"tid": oracle["wait_tid"], "thread_created_100ns": oracle["wait_thread_created_100ns"]}
        wait_chain = action("wait_chains", thread)
        stacks = action("thread_stacks", thread, confirmed=True)
        require(any(row.get("frames") for row in stacks["data"]["rows"]), "ACTUAL_PSS_STACK_REQUIRED")
        before = action("snapshot")
        changed = bytes(index ^ 0xA5 for index in range(64)).hex()
        write = action("memory.write", {"address": oracle["buffer_address"],
            "expected_hex": oracle["buffer_hex"], "value_hex": changed}, confirmed=True)
        require(probe.state()["buffer_hex"] == changed, "ACTUAL_TARGET_DID_NOT_CONFIRM_WRITTEN_STATE")
        after = action("snapshot")
        compared = action("compare", {"before_id": before["data"]["snapshot_id"],
                                       "after_id": after["data"]["snapshot_id"]})
        require(compared["data"]["interpretation"] == "OBSERVED_DIFFERENCE_NOT_CAUSAL_PROOF",
                "BEFORE_AFTER_DIFFERENCE_PROMOTED_TO_CAUSAL_PROOF")
        action("memory.rollback", {"change_id": write["data"]["change_id"]}, confirmed=True)
        require(probe.state()["buffer_hex"] == oracle["buffer_hex"], "OWNED_BYTES_ROLLBACK_NOT_CONFIRMED")
        proof["live_experiment"] = {"target": target.to_dict(), "before_id": before["data"]["snapshot_id"],
            "after_id": after["data"]["snapshot_id"], "independent_write_and_restore_verified": True,
            "wct_status": wait_chain["status"], "pss_status": stacks["status"], "root_cause_proven": False}
        for label, child in children:
            child.process.wait(timeout=30)
            require(child.process.returncode == 0, "ACTUAL_OWNED_FIXTURE_FAILED_" + label)
        require(cpu.process.poll() is None, "ACTUAL_NATIVE_CPU_WORKLOAD_EXITED_EARLY")
        proof["capture_result"] = capture.stop()
        trace = capture_folder / proof["capture_result"]["path"]
        cpu.close(kill=True)
        cpu = None
        proof["helper_cleanup"] = service.close()
        service = None
        require(proof["helper_cleanup"]["status"] == "COMPLETED", "NATIVE_HELPER_CLEANUP_UNCONFIRMED")
        index = output / "trace.sqlite3"
        with patch("blackbox_core.decoder_service.helper_path", return_value=args.decoder.resolve(strict=True)):
            decoded = decode_file(trace, index, timeout=180)
        require(decoded["status"] == "DECODED", "ACTUAL_INV_ETL_DECODE_FAILED")
        proof["trace"] = {"file": str(trace), "sha256": digest(trace), "bytes": trace.stat().st_size,
                          "index": str(index), "rows": decoded["rows"],
                          "reported_lost_events": decoded.get("decoder_reported_lost_events")}
        before_hashes[str(index)] = digest(index)
        before_hashes[str(trace)] = digest(trace)
        journal = output / "journal/deep-inspection.sqlite3"
        before_hashes[str(journal)] = digest(journal)
        budget = {"timeout_seconds": 300, "max_events": 250000, "max_nodes": 10000, "max_edges": 20000}

        phase("BUILD_REAL_WAIT_CPU_AND_JOURNAL_GRAPHS")
        waiting = json.loads(wait_oracle_path.read_text())
        case_a = create_investigation([trace_source(index, wait.process.pid)], budget=budget,
                                     index_path=output / "case-waits.sqlite3")
        proof["cases"]["A_wait"] = inspect_case(case_a)
        path = case_a["critical_path"]
        require(any(segment["state"] == "BLOCKED" and segment["duration_ms"] > 10
                    for segment in path["segments"]), "REAL_WAIT_NOT_IN_CRITICAL_PATH")
        require(path["end_to_end_established"] is False, "PARTIAL_WAIT_PATH_CLAIMED_FULL_CAUSAL_PATH")
        matched_waits = {}
        with closing(readonly(index)) as db:
            for wait_phase in waiting["observations"]:
                matches = []
                for segment in path["segments"]:
                    identity = segment.get("thread_identity") or {}
                    if (identity.get("tid") != wait_phase["tid"] or segment.get("state") != "BLOCKED" or
                            not segment.get("duration_ms") or segment["duration_ms"] <= 10):
                        continue
                    refs = segment.get("source_event_ids", [])
                    if len(refs) < 2 or any(type(value) is not int for value in refs):
                        continue
                    first = db.execute("SELECT data FROM events WHERE id=?", (refs[0],)).fetchone()
                    last = db.execute("SELECT data FROM events WHERE id=?", (refs[-1],)).fetchone()
                    if first is None or last is None:
                        continue
                    begin, end = json.loads(first[0]), json.loads(last[0])
                    if (wait_phase["begin_qpc"] <= int(begin["source_ticks"]) <= int(end["source_ticks"])
                            <= wait_phase["end_qpc"]):
                        matches.append(segment["segment_id"])
                require(matches, "REAL_GRAPH_WAIT_NOT_WITHIN_ACTUAL_QPC_ORACLE_" + wait_phase["role"])
                matched_waits[wait_phase["role"]] = matches
        proof["graph_wait_oracle_matches"] = matched_waits
        proof["actual_wait_oracle"] = waiting
        case_c = create_investigation([trace_source(index, cpu_pid)], budget=budget,
                                     index_path=output / "case-cpu.sqlite3")
        proof["cases"]["C_cpu"] = inspect_case(case_c)
        require(case_a["case_id"] != case_c["case_id"],
                "DISTINCT_SELECTED_PROCESS_INVESTIGATIONS_HAVE_COLLIDING_CASE_IDENTITY")
        require(any(node["observation_type"] == "CPU_SAMPLE" for node in case_c["nodes"]),
                "REAL_NATIVE_CPU_SAMPLE_NOT_IN_GRAPH")
        require(any(node["observation_type"] == "STACK" for node in case_c["nodes"]),
                "REAL_NATIVE_CPU_STACK_NOT_IN_GRAPH")
        require(any(h["category"] == "HIGH_CPU" for h in case_c["hypotheses"]),
                "REAL_CPU_GRAPH_WITHOUT_CPU_HYPOTHESIS")
        from blackbox_core.decoder_calltree import build_calltree, export_analysis
        tree = build_calltree(index, source="etw", pid=cpu_pid,
            binary_path=cpu_exe, pdb_path=cpu_pdb)
        counts = tree["coverage"]
        require(counts["samples_selected"] > 0 and
                counts["samples_represented"] + counts["samples_omitted_node_budget"] == counts["samples_selected"] and
                sum(node["self_samples"] for node in tree["nodes"]) == counts["samples_represented"],
                "ACTUAL_NATIVE_CPU_SAMPLE_COUNTS_NOT_CONSERVED")
        require(tree["symbolization"]["frame_occurrences_resolved"] > 0 and
                any((node.get("derived_symbol") or {}).get("symbol", {}).get("name") in
                    {"blackbox_leaf", "blackbox_parent", "entry"} for node in tree["nodes"]),
                "ACTUAL_NATIVE_CPU_STACK_NOT_RESOLVED_WITH_ITS_REAL_LOCAL_PDB")
        export_analysis(tree, output / "actual-native-cpu-calltree.json")
        export_analysis(tree, output / "actual-native-cpu-flame.html", html=True)
        proof["cpu_oracle"] = {"pid": cpu_pid, "source_build_sha256": digest(cpu_exe),
            "local_pdb_sha256": digest(cpu_pdb), "count_coverage": counts,
            "symbolization": tree["symbolization"], "sample_counts_are_cpu_percentage": False}
        e_sources = [{"source_type": "DEEP_JOURNAL", "path": str(journal)},
                     trace_source(index, target.pid)]
        case_e = create_investigation(e_sources, target_identity=target.to_dict(), budget=budget,
                                     index_path=output / "case-experiment.sqlite3")
        proof["cases"]["E_experiment"] = inspect_case(case_e)
        require(any(node["observation_type"] == "DIAGNOSTIC_ACTION" for node in case_e["nodes"]),
                "ACTUAL_HELPER_ACTIONS_NOT_IN_GRAPH")
        save(output / "gui-sources.json", {"sources": e_sources, "historical_case": case_e,
            "source_target": target.to_dict(), "new_live_binding_requires_explicit_consent": True})

        phase("ACTUAL_FILE_ERROR_GROUPING_AND_VERSION_COMPARISON")
        grouped_cases, cases_by_label = [], {}
        for label, version, expected_error, folder, child in file_runs:
            result = json.loads((folder / "fixture-result.json").read_text())
            require(result["status"] == "PASS" and result["owned_file_dacl_restored"] is True and
                    result["client_events_dropped"] == 0 and result["input_file_bytes_unchanged"] is True,
                    "ACTUAL_FILE_ERROR_FIXTURE_OR_CLEANUP_NOT_CONFIRMED")
            source = folder / "application-events.jsonl"
            before_hashes[str(source)] = digest(source)
            app = {"application_id": result["application"]["application_id"], "version": version,
                   "sha256": result["application"]["source_sha256"],
                   "host_image_sha256": result["application"]["runtime_sha256"],
                   "verification_class": "QA_VERIFIED_SOURCE_BUILD"}
            require(app["sha256"] == digest(variants[version]), "ACTUAL_APP_SOURCE_BUILD_HASH_MISMATCH")
            scenario = {"scenario_id": "INV_FILE_OPEN_WRITE", "workload_id": "SIX_DENIED_PLUS_SIX_PERMITTED",
                        "operation_count": 12, "input_bytes": result["input_bytes"], "source_profile": "SDK_FILE_OPEN_V1",
                        "complete": True}
            case = create_investigation([{"source_type": "EVENTS_JSONL", "path": str(source)}],
                scenario=scenario, app_identity=app, budget=budget, index_path=folder / "case.sqlite3")
            inspect_case(case)
            assert_sdk_file_case(case, result)
            cases_by_label[label] = case
            grouped_cases.append(case)
            proof["cases"][label] = {**inspect_case(case), "expected_error": expected_error,
                                      "app_build_sha256": app["sha256"], "application_version": version}
            combined = create_investigation([{"source_type": "EVENTS_JSONL", "path": str(source)},
                                              trace_source(index, child.process.pid)], budget=budget)
            graph_facts(combined)
            combined_nodes = {node["node_id"]: node for node in combined["nodes"]}
            require(not any(combined_nodes[edge["from_node"]]["source_identity"] !=
                            combined_nodes[edge["to_node"]]["source_identity"] and
                            edge["relation_type"] in ("EXACT_IDENTITY", "DIRECT_REFERENCE",
                                "BOUNDED_TIME_CORRELATION", "OBSERVED_DEPENDENCY")
                            for edge in combined["edges"]),
                    "UNALIGNED_SDK_TRACE_PAIR_ACQUIRED_UNPROVEN_IDENTITY_CLOCK_OR_DEPENDENCY")
            sdk_ids = {row["operation_id"] for row in result["operations"]}
            require(not any(node["source_type"] == "TRACE_INDEX" and
                            node["metadata"].get("operation_id") in sdk_ids for node in combined["nodes"]),
                    "SDK_OPERATION_RESULT_SILENTLY_TRANSFERRED_TO_KERNEL_EVENT")
            etw_files = [node for node in combined["nodes"] if node["source_type"] == "TRACE_INDEX" and
                         node["observation_type"] == "FILE_OPERATION"]
            require(etw_files, "ACTUAL_FILE_APPLICATION_HAS_NO_RECORDED_KERNEL_FILE_OPERATIONS_" + label)
            proof["cases"][label]["kernel_file_observations"] = len(etw_files)
            proof["cases"][label]["kernel_file_error_join"] = "NOT_ESTABLISHED_NO_SHARED_OPERATION_ID"
        proof["grouping"] = group_recurrent_issues(grouped_cases)
        same_ids = {cases_by_label[label]["case_id"] for label in ("same-1", "same-2", "same-3")}
        wrong_id = cases_by_label["different-error"]["case_id"]
        matching_groups = [group for group in proof["grouping"]["groups"]
            if same_ids <= set(group.get("case_ids", [])) and
               group.get("anchors", {}).get("failure", {}).get("error_code") == 5]
        require(matching_groups and all(wrong_id not in group["case_ids"] for group in matching_groups),
                "ACTUAL_REPEATED_FILE_ERRORS_NOT_GROUPED_OR_DISTINCT_ERROR_FALSELY_MERGED")
        require(all(group.get("root_cause_established") is False for group in proof["grouping"]["groups"]),
                "GROUP_MATCH_PROMOTED_TO_COMMON_ROOT_CAUSE")
        from blackbox_core.issue_grouping import manual_group_change
        grouping_before = json.dumps(proof["grouping"], sort_keys=True)
        split = manual_group_change(proof["grouping"], action="SPLIT",
            group_ids=[matching_groups[0]["group_id"]], case_ids=[cases_by_label["same-1"]["case_id"]],
            reason="QA: preserve an explicit user partition without changing recorded observations")
        require(json.dumps(proof["grouping"], sort_keys=True) == grouping_before and
                split.get("manual_history", [])[-1]["action"] == "SPLIT" and
                split["manual_history"][-1]["source_events_modified"] is False,
                "MANUAL_GROUP_CHANGE_MUTATED_ORIGINAL_OR_LOST_REASON")
        proof["manual_grouping"] = {"action": "SPLIT", "source_events_unchanged": True,
                                     "history_recorded": True}
        proof["version_comparison"] = compare_investigations(cases_by_label["same-1"], cases_by_label["version-B"])
        require(proof["version_comparison"].get("status") == "COMPARABLE", "ACTUAL_CONTROLLED_SOURCE_BUILDS_NOT_COMPARABLE")
        incompatible = json.loads(json.dumps(cases_by_label["version-B"]))
        incompatible["scenario"]["workload_id"] = "DIFFERENT_WORKLOAD"
        require(compare_investigations(cases_by_label["same-1"], incompatible).get("status") == "NOT_COMPARABLE",
                "DIFFERENT_WORKLOAD_FALSELY_COMPARABLE")
        incomplete = json.loads(json.dumps(cases_by_label["version-B"]))
        incomplete["coverage"]["events_omitted"] = 1
        incomplete["coverage"]["has_more"] = True
        require(compare_investigations(cases_by_label["same-1"], incomplete).get("status") == "NOT_COMPARABLE",
                "EXPLICIT_PARTIAL_COVERAGE_FALSELY_COMPARABLE")
        proof["comparison_negative_controls"] = {
            "different_workload": "NOT_COMPARABLE", "partial_coverage": "NOT_COMPARABLE",
            "fixture_class": "EXPLICIT_NEGATIVE_METADATA_MUTATION_NOT_CAPTURED_OBSERVATION"}
        # The actual APP incident has no established identity/clock link to
        # the separate native stack capture. GUI acceptance must show that
        # gap while exercising the independently captured thread/stack path.
        gui_sources = [{"source_type": "EVENTS_JSONL",
            "path": str(file_runs[0][3] / "application-events.jsonl")}, *e_sources]
        preflight_started, preflight_cpu = time.monotonic(), time.thread_time()
        gui_preflight = create_investigation(gui_sources, budget={**budget, "timeout_seconds": 120},
            index_path=output / "case-gui-preflight.sqlite3")
        proof["cases"]["H_composed_source_preflight"] = inspect_case(gui_preflight)
        proof["cases"]["H_composed_source_preflight"].update(
            wall_seconds=time.monotonic() - preflight_started,
            thread_cpu_seconds=time.thread_time() - preflight_cpu, timeout_seconds=120)
        save(output / "gui-sources.json", {
            "sources": gui_sources,
            "historical_case": case_e, "source_target": target.to_dict(),
            "new_live_binding_requires_explicit_consent": True,
            "app_incident_to_native_thread_and_stack": "NOT_ESTABLISHED"})

        phase("EXPLICIT_NEGATIVE_SOURCE_FORMAT_CONTROLS")
        negative = output / "negative-controls"
        negative.mkdir()
        original_lines = (file_runs[0][3] / "application-events.jsonl").read_text().splitlines()
        parsed_rows = [json.loads(line) for line in original_lines]
        require(parsed_rows[-1]["kind"] == "blackbox.completed", "SDK_COMPLETION_MARKER_MISSING")
        negative_results = {"fixture_class": "EXPLICIT_MUTATIONS_OF_QA_SOURCE_NOT_NEW_OS_OBSERVATIONS"}
        for label in ("missing-completion", "reported-event-loss"):
            rows = json.loads(json.dumps(parsed_rows))
            if label == "missing-completion":
                rows.pop()
            else:
                rows[-1]["client_dropped"] = 1
            path = negative / (label + ".jsonl")
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            before_hashes[str(path)] = digest(path)
            reference = cases_by_label["same-1"]
            uncertain = create_investigation([{"source_type": "EVENTS_JSONL", "path": str(path)}],
                scenario=reference["scenario"], app_identity=reference["app_identity"], budget=budget)
            inspect_case(uncertain)
            require(all(source.get("application_events_complete") is False for source in uncertain["sources"]),
                    "INCOMPLETE_OR_LOSSY_APPLICATION_SOURCE_WAS_DECLARED_COMPLETE")
            comparison = compare_investigations(reference, uncertain)
            require(comparison["status"] == "NOT_COMPARABLE", "LOSS_OR_MISSING_COMPLETION_FALSELY_COMPARABLE")
            negative_results[label] = {"status": "EXPECTED_UNCERTAINTY", "comparison": "NOT_COMPARABLE",
                "source_sha256": digest(path), "source_complete": False}
        broken = negative / "partial-tail.jsonl"
        broken.write_text("\n".join(original_lines[:-1]) + '\n{"partial":', encoding="utf-8")
        before_hashes[str(broken)] = digest(broken)
        from blackbox_core.investigation_graph_contracts import InvestigationError
        try:
            create_investigation([{"source_type": "EVENTS_JSONL", "path": str(broken)}], budget=budget,
                                 index_path=negative / "must-not-publish.sqlite3")
        except InvestigationError as error:
            require(not (negative / "must-not-publish.sqlite3").exists() and
                    not list(negative.glob(".blackbox-investigation-*")),
                    "CORRUPT_SOURCE_PUBLISHED_PARTIAL_INDEX")
            negative_results["partial-tail"] = {"status": "EXPECTED_REJECTION", "reason": str(error)}
        else:
            raise AssertionError("CORRUPT_APPLICATION_SOURCE_WAS_ACCEPTED")
        proof["F_negative_controls"] = negative_results

        phase("EXPORT_AND_REAL_MEDIUM_TOKEN")
        json_export, html_export = output / "investigation.json", output / "investigation.html"
        export_investigation(case_e, json_export)
        export_investigation(case_e, html_export, format="html")
        proof["exports"] = [validate_export(path, forbidden=(oracle["buffer_hex"], changed))
                            for path in (json_export, html_export)]
        private_case = cases_by_label["same-1"]
        private_export = output / "file-investigation.json"
        export_investigation(private_case, private_export)
        proof["exports"].append(validate_export(private_export))
        from tools.qa_decoder_standard_token import restricted_child, restricted_interpreter
        os.environ["BB_INV_QA_PROBE_EXE"] = str(executable)
        command = [restricted_interpreter(sys.executable), str(Path(__file__).resolve()),
                   "--medium-worker", "--output", str(output / "medium"),
                   "--source", str(file_runs[0][3] / "application-events.jsonl")]
        if args.diagnostic_helper:
            command += ["--diagnostic-helper", str(args.diagnostic_helper.resolve())]
        launched = restricted_child(command, cwd=ROOT, timeout_seconds=180, medium_integrity=True)
        medium = json.loads((output / "medium/medium-result.json").read_text())
        require(launched["exit_code"] == 0 and medium["status"] == "PASS", "REAL_MEDIUM_INVESTIGATION_QA_FAILED")
        proof["G_permissions"] = medium
        assert_sources_unchanged(before_hashes)
        proof["source_hashes"] = before_hashes
        proof["source_integrity_preserved"] = True
        successful = True
    except BaseException as error:
        proof.update(error=type(error).__name__, reason=str(error)[:1800],
                     traceback=traceback.format_exc(limit=12))
    finally:
        if capture is not None and capture.active:
            try:
                capture.cancel()
            except BaseException as error:
                successful = False
                proof["capture_cleanup_error"] = str(error)[:1000]
        for label, owner in children:
            try:
                owner.close(kill=owner.process.poll() is None)
            except BaseException as error:
                successful = False
                proof.setdefault("owned_cleanup_errors", []).append(label + ":" + str(error)[:800])
        if cpu is not None:
            try:
                cpu.close(kill=True)
            except BaseException as error:
                successful = False
                proof.setdefault("owned_cleanup_errors", []).append("cpu:" + str(error)[:800])
        if service is not None:
            try:
                proof["helper_cleanup"] = service.close()
                successful = successful and proof["helper_cleanup"].get("status") == "COMPLETED"
            except BaseException as error:
                successful = False
                proof["helper_cleanup"] = {"status": "FAILED", "reason": str(error)[:1000]}
        if probe is not None:
            try:
                proof["target_cleanup"] = probe.close(kill=not successful)
                successful = successful and proof["target_cleanup"].get("status") == "COMPLETED"
            except BaseException as error:
                successful = False
                proof["target_cleanup"] = {"status": "FAILED", "reason": str(error)[:1000]}
        for stream in streams:
            stream.close()
        proof["status"] = "PASS" if successful else "FAIL"
        save(output / "native-investigation-qa.json", proof)
    print("INV_NATIVE_QA_" + proof["status"], flush=True)
    return 0 if successful else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--decoder", type=Path)
    parser.add_argument("--diagnostic-helper", type=Path)
    parser.add_argument("--medium-worker", action="store_true")
    parser.add_argument("--source", type=Path)
    args = parser.parse_args()
    require_hosted(windows=True)
    if args.medium_worker:
        return medium_worker(args.output.resolve(), args.source.resolve(strict=True),
                             args.diagnostic_helper.resolve(strict=True) if args.diagnostic_helper else None)
    require(args.decoder is not None, "ACTUAL_DECODER_HELPER_REQUIRED")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
