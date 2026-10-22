"""Public, standalone Alva-side worker executed in an authorized Python env.

The user selects the external interpreter. Python -I starts this script in
isolated mode, and that interpreter imports its OWN installed Alva package.
No private Alva source or wheel is bundled with BLACK.BOX Universal.

Uses only process summary metadata, not document contents, paths, PIDs,
process names, raw event payloads or credentials. This is diagnostics about
BLACK.BOX observer evidence, not a native-app root cause finder.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
import importlib.util

MAX_INPUT = 8192
OPERATIONS = ("blackbox.observer.samples", "blackbox.observer.lifecycle",
              "blackbox.observer.errors")


def _json_pairs(rows):
    output = {}
    for key, value in rows:
        if key in output:
            raise ValueError("DUPLICATE_JSON_KEY")
        output[key] = value
    return output


def _consume_payload():
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError("ALVA_INPUT_TOO_LARGE")
    obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_pairs,
                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if type(obj) is not dict or obj.keys() != {
        "schema_version", "operation", "summary"} or obj["schema_version"] != 1:
        raise ValueError("ALVA_BAD_REQUEST")
    if obj["operation"] not in ("ping", "inspect"):
        raise ValueError("ALVA_BAD_OPERATION")
    summary = obj["summary"]
    if type(summary) is not dict or summary.keys() != {
        "sample_count", "peak_rss_bytes", "peak_cpu_percent",
        "observation_error_count", "closed", "state"}:
        raise ValueError("ALVA_BAD_SUMMARY")
    for name in ("sample_count", "observation_error_count"):
        value = summary[name]
        if type(value) is not int or not 0 <= value <= 10**9:
            raise ValueError("ALVA_BAD_COUNTER")
    for name in ("peak_rss_bytes", "peak_cpu_percent"):
        value = summary[name]
        if value is not None and (type(value) not in (int, float)
                                  or not 0 <= value <= 10**15):
            raise ValueError("ALVA_BAD_METRIC")
    if type(summary["closed"]) is not bool or summary["state"] not in (
            "COMPLETED", "INTERRUPTED", "PROCESS_EXITED",
            "ACCESS_DENIED", "PID_REUSED", "SAMPLE_UNAVAILABLE",
            "STORAGE_ERROR", "UNKNOWN"):
        raise ValueError("ALVA_BAD_STATE")
    return obj



def _public_evidence_pipeline():
    """Load only the adjacent public BLACK.BOX helper in isolated Python.

    The frozen EXE must package this public helper beside the worker; it is
    not a private platform import and never uses PYTHONPATH or the target app.
    """
    path = Path(__file__).resolve().with_name("alva_evidence_pipeline.py")
    if not path.is_file() or path.is_symlink():
        raise ValueError("PUBLIC_EVIDENCE_PIPELINE_MISSING")
    spec = importlib.util.spec_from_file_location("_blackbox_evidence_pipeline", path)
    if spec is None or spec.loader is None:
        raise ValueError("PUBLIC_EVIDENCE_PIPELINE_INVALID")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(packet):
    import alva
    from alva import Component, invoke_adapter_checked
    from alva.host import ComponentHost

    sample = packet["summary"]
    observations = {
        OPERATIONS[0]: {
            "samples_present": sample["sample_count"] > 0,
            "memory_observed": sample["peak_rss_bytes"] is not None,
            "cpu_observed": sample["peak_cpu_percent"] is not None},
        OPERATIONS[1]: {
            "finished": sample["closed"],
            "end_state": sample["state"]},
        OPERATIONS[2]: {
            "observer_errors_present": sample["observation_error_count"] > 0,
            "observer_error_count": sample["observation_error_count"]},
    }

    calls = {}
    def handler(operation):
        def run(payload):
            if type(payload) is not dict or payload:
                raise ValueError("ALVA_OPERATION_PAYLOAD_REJECTED")
            def action():
                calls[operation] = calls.get(operation, 0) + 1
                return observations[operation]
            expected = set(observations[operation])
            return {"evidence": invoke_adapter_checked(
                action,
                lambda value: (type(value) is dict and
                               value.keys() == expected and
                               all(type(v) in (bool, int, str)
                                   for v in value.values())))}
        return run

    components = tuple(Component(name, handler(name)) for name in OPERATIONS)
    outcomes = []
    observed_traces = []
    with ComponentHost(components, allow_dispatch=True) as host:
        with host.open_scope(permitted_operations=OPERATIONS) as scope:
            for operation in OPERATIONS:
                call = scope.invoke_with_diagnostics({
                    "schema_version": 1, "operation": operation, "payload": {}})
                response, diagnostics = call.response, call.diagnostics
                evidence = diagnostics.get("result") if type(diagnostics) is dict else None
                result = response.get("result") if type(response) is dict else None
                if not (call.execution_state == "RESPONSE_AVAILABLE"
                        and calls.get(operation) == 1 and
                        type(response) is dict and response.get("status") == "ok"
                        and type(result) is dict
                        and result.get("evidence") == observations[operation]
                        and type(evidence) is dict
                        and evidence.get("contract_verdict") == "CHECK_ACCEPTED"
                        and evidence.get("visibility") == "SCOPE_ONLY"):
                    raise ValueError("ALVA_SCOPED_CONTRACT_FAILED")
                observed_traces.append((operation, evidence))
                outcomes.append({
                    "component": operation,
                    "execution_state": call.execution_state,
                    "contract_verdict": "CHECK_ACCEPTED",
                    "visibility": evidence["visibility"],
                    "observation": result["evidence"],
                })
    if host.state != "closed":
        raise ValueError("ALVA_HOST_NOT_CLOSED")
    # The pinned Alva PREVIEW provides checked pipeline and evidence reviewer.
    # No AI handoff is requested or exported by BLACK.BOX.
    features = ("run_checked_pipeline", "review_pipeline_evidence")
    advanced = all(callable(getattr(alva, key, None)) for key in features)
    if advanced:
        helpers = _public_evidence_pipeline()
        extended = helpers.verified_session_evidence(alva, sample, packet["operation"])
        trace_apis = ("classify_failure", "build_report")
        extended["host_trace_checks"] = (
            helpers.verified_host_traces(alva, observed_traces)
            if all(callable(getattr(alva, key, None)) for key in trace_apis)
            else [])
    else:
        extended = None
    result = {
        "status": "ok",
        "bridge_schema": 2 if advanced else 1,
        "mode": "EXTERNAL_ALVA_SCOPED_INSPECTION",
        "alva_version": str(getattr(alva, "__version__", "unknown"))[:50],
        "alva_origin_authenticated": False,
        "target_root_cause_proven": False,
        "permission_to_act": False,
        "evidence_origin": "APP_SUPPLIED_NOT_AUTHENTICATED",
        "operations": outcomes,
        "component_count": len(outcomes),
    }
    if advanced:
        result["extended_diagnostics"] = extended
    return result


def main():
    try:
        packet = _consume_payload()
        result = _run(packet)
    except ImportError:
        result = {"status": "unavailable", "error_code": "ALVA_NOT_INSTALLED"}
    except (ValueError, TypeError, AttributeError, RuntimeError):
        result = {"status": "error", "error_code": "ALVA_CONTRACT_OR_RUNTIME_FAILURE"}
    except Exception:
        result = {"status": "error", "error_code": "ALVA_UNKNOWN_FAILURE"}
    # Output is a strict single JSON line, bounded, no file paths or exception
    # texts. Parent validates it independently before persistence.
    sys.stdout.write(json.dumps(result, ensure_ascii=True,
                                separators=(",", ":"), allow_nan=False) + "\n")
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    sys.exit(main())
