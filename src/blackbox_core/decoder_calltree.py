"""Bounded, source-separated CPU occurrence trees; no duration or CPU% claims.

Typed native ETW SampledProfile and legacy .NET SampleProfiler are separate
choices. DPC/ISR, unknown native attribution and absent typed classifications
remain explicit. Optional local symbols are derived, never rewritten frames.
"""
from __future__ import annotations
from contextlib import closing
import hashlib
from html import escape
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import time

from .decoder_index import APP_ID, validate_event
from .decoder_modules import validate_module_frame, integer, number
from .decoder_cpu import CPU_SOURCES, classify_cpu_sample
from .decoder_native_symbols import load_native_symbols, resolve_bound_frame
from .session_v2 import safe_path

MAX_TREE_NODES = 20000
MAX_TREE_EVENTS = 250000


def parse_calltree_filters(*, source="dotnet", pid=0, instance_text="",
                           tid_text="", start_text="", end_text=""):
    """Validate UI text before starting a worker; blank is not numeric zero."""
    def optional_id(text):
        if type(text) is not str or len(text) > 32:
            raise ValueError("INVALID_CALLTREE_ID_FILTER")
        text = text.strip()
        if not text:
            return None
        if not re.fullmatch(r"[0-9]{1,19}", text) or int(text) > 2**63-1:
            raise ValueError("INVALID_CALLTREE_ID_FILTER")
        return int(text)

    def optional_time(text):
        if type(text) is not str or len(text) > 40:
            raise ValueError("INVALID_CALLTREE_TIME_FILTER")
        text = text.strip()
        if not text:
            return None
        try:
            value = float(text)
        except ValueError:
            raise ValueError("INVALID_CALLTREE_TIME_FILTER") from None
        if not number(value):
            raise ValueError("INVALID_CALLTREE_TIME_FILTER")
        return value

    arguments = {"source": source, "pid": pid,
                 "process_instance": optional_id(instance_text),
                 "tid": optional_id(tid_text),
                 "start_ms": optional_time(start_text), "end_ms": optional_time(end_text)}
    _validate_filters(**arguments, max_nodes=10000)
    return arguments


def _validate_filters(*, source, pid, process_instance, tid, start_ms, end_ms, max_nodes):
    if (type(source) is not str or source not in CPU_SOURCES or not integer(pid) or
            (process_instance is not None and not integer(process_instance)) or
            (tid is not None and not integer(tid)) or
            type(max_nodes) is not int or not 4 <= max_nodes <= MAX_TREE_NODES or
            (start_ms is not None and not number(start_ms)) or
            (end_ms is not None and not number(end_ms)) or
            (start_ms is not None and end_ms is not None and end_ms <= start_ms)):
        raise ValueError("INVALID_CALLTREE_FILTER")


def build_calltree(index_path, *, source="dotnet", pid=0, process_instance=None,
                   tid=None, start_ms=None, end_ms=None, max_nodes=10000,
                   binary_path=None, pdb_path=None, cancel=None):
    _validate_filters(source=source, pid=pid, process_instance=process_instance, tid=tid,
                      start_ms=start_ms, end_ms=end_ms, max_nodes=max_nodes)
    if (binary_path is None) != (pdb_path is None):
        raise ValueError("CALLTREE_SYMBOL_PAIR_REQUIRED")
    path = safe_path(index_path)
    if not path.is_file():
        raise ValueError("INVALID_INDEX_FILE")
    deadline = time.monotonic()+30

    def check():
        if cancel is not None and cancel.is_set():
            raise InterruptedError("CALLTREE_CANCELLED")
        if time.monotonic() > deadline:
            raise TimeoutError("CALLTREE_DEADLINE")

    def node(identifier, parent, label, frame=None, symbol=None):
        return {"id": identifier, "parent_id": parent, "label": label,
                "inclusive_samples": 0, "self_samples": 0, "frame": frame,
                "derived_symbol": symbol}

    check()
    # Parse one user-selected local pair once. Binding is still checked for
    # every frame; a local file name never establishes membership in a trace.
    symbols = (load_native_symbols(binary_path, pdb_path, cancel=cancel)
               if binary_path is not None else None)
    check()
    provider, event_name = CPU_SOURCES[source]
    nodes = [node(0, None, "Recorded CPU samples / "+source+" (not CPU time)")]
    edges = {}; selected = missing = clipped = omitted = represented = unknown = 0
    scanned = in_scope = nonprocess = attribution_unknown = unclassified = 0
    symbol_frames = symbol_resolved = 0; symbol_reasons = {}; symbol_cache = {}
    try:
        with closing(sqlite3.connect(path.resolve().as_uri()+"?mode=ro", uri=True, timeout=1)) as db:
            db.execute("PRAGMA query_only=ON"); db.execute("PRAGMA trusted_schema=OFF")
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2*1024**2)
            db.set_progress_handler(lambda: int(time.monotonic() > deadline or
                                                (cancel is not None and cancel.is_set())), 1000)
            if (db.execute("PRAGMA application_id").fetchone()[0] != APP_ID or
                    db.execute("PRAGMA user_version").fetchone()[0] not in (1, 2, 3, 4)):
                raise ValueError("INVALID_INDEX_SCHEMA")
            db.execute("BEGIN")
            summary = json.loads(db.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
            sql = "SELECT id,pid,time_ms,data FROM events WHERE provider=? AND name=?"
            values = [provider, event_name]
            if pid:
                sql += " AND pid=?"; values.append(pid)
            if start_ms is not None:
                sql += " AND time_ms>=?"; values.append(start_ms)
            if end_ms is not None:
                sql += " AND time_ms<?"; values.append(end_ms)
            for event_id, stored_pid, stored_ms, raw in db.execute(sql+" ORDER BY id", values):
                check(); scanned += 1
                if scanned > MAX_TREE_EVENTS:
                    raise ValueError("CALLTREE_EVENT_BUDGET")
                row = json.loads(raw)
                validate_event(row, event_id)
                if (row["pid"] != stored_pid or row["time_ms"] != stored_ms or
                        row["provider"] != provider or row["name"] != event_name):
                    raise ValueError("INDEX_EVENT_METADATA_MISMATCH")
                instance = row["process_instance"]
                if ((process_instance is not None and instance != process_instance) or
                        (tid is not None and row["tid"] != tid)):
                    continue
                in_scope += 1
                classification = classify_cpu_sample(row, source)
                if classification == "DPC_ISR_SAMPLE":
                    nonprocess += 1; continue
                if classification == "ATTRIBUTION_UNKNOWN":
                    attribution_unknown += 1; continue
                if classification == "TYPED_CLASSIFICATION_MISSING":
                    unclassified += 1; continue
                if classification != "PROCESS_SAMPLE":
                    raise ValueError("INDEX_CPU_SOURCE_MISMATCH")
                selected += 1
                nodes[0]["inclusive_samples"] += 1
                if instance is None:
                    unknown += 1
                scope = (stored_pid, instance if instance is not None else -event_id)
                labels = [("process:"+repr(scope), f"PID {stored_pid} / instance {instance if instance is not None else 'unknown event '+str(event_id)}", None, None)]
                frames = row["frames"]
                if not frames:
                    missing += 1
                    labels.append(("missing", "[stack not recorded]", None, None))
                else:
                    if row.get("stack_status") == "TRUNCATED_128_FRAMES":
                        clipped += 1
                        labels.append(("truncated", "[callers omitted: truncated stack]", None, None))
                    for frame in reversed(frames):
                        check(); validate_module_frame(row, frame)
                        canonical = json.dumps(frame, sort_keys=True, ensure_ascii=True,
                                               separators=(",", ":"), allow_nan=False)
                        key = hashlib.sha256(canonical.encode("ascii")).hexdigest()
                        label = frame["name"] or "[unresolved "+frame["address"]+"]"
                        derived = None
                        if symbols is not None:
                            symbol_frames += 1
                            # Module/time/address validity was checked above for every
                            # occurrence, including cache hits in a new event.
                            derived = symbol_cache.get(key)
                            if derived is None:
                                derived = resolve_bound_frame(row, frame, symbols)
                                if len(symbol_cache) < 8192:
                                    symbol_cache[key] = derived
                            symbol_reasons[derived["symbol"]["status"]] = symbol_reasons.get(derived["symbol"]["status"], 0)+1
                            if derived["symbol"]["name"] is not None:
                                symbol_resolved += 1
                                label = derived["symbol"]["name"]
                                displacement = derived["symbol"].get("displacement", 0)
                                if displacement:
                                    label += f"+0x{displacement:x}"
                        labels.append((key, label, frame, derived))
                # Reserve a whole path: omissions cannot manufacture function self weight.
                parent = 0; first_new = len(labels); path_ids = []
                for at, (key, _, _, _) in enumerate(labels):
                    found = edges.get((parent, key))
                    if found is None:
                        first_new = at; break
                    path_ids.append(found); parent = found
                if len(nodes)+(len(labels)-first_new) > max_nodes:
                    omitted += 1; continue
                for key, label, frame, derived in labels[first_new:]:
                    identifier = len(nodes); nodes.append(node(identifier, parent, label, frame, derived))
                    edges[(parent, key)] = identifier; parent = identifier; path_ids.append(identifier)
                for identifier in path_ids:
                    nodes[identifier]["inclusive_samples"] += 1
                nodes[path_ids[-1]]["self_samples"] += 1
                represented += 1
            check()
    except sqlite3.OperationalError:
        # SQLite progress callbacks interrupt before Python sees another row.
        # Preserve a truthful cancellation/deadline reason instead of leaking
        # a generic database error for a user-requested stop.
        check()
        raise
    status = ("REDECODE_REQUIRED_FOR_ETW" if unclassified and not selected else
              "PARTIAL_CLASSIFICATION" if unclassified else
              "RECORDED_SAMPLES" if selected else "NO_ATTRIBUTABLE_SAMPLES")
    return {"schema": "blackbox.cpu-calltree/1", "nodes": nodes, "status": status,
            "source_trace_sha256": summary.get("input_sha256"),
            "filters": {"cpu_source": source, "pid": pid, "process_instance": process_instance,
                        "tid": tid, "start_ms_inclusive": start_ms, "end_ms_exclusive": end_ms},
            "coverage": {"candidates_in_scope": in_scope, "samples_selected": selected,
                         "samples_represented": represented, "samples_omitted_node_budget": omitted,
                         "samples_without_stack": missing, "samples_with_truncated_stack": clipped,
                         "samples_without_process_identity": unknown,
                         "samples_excluded_dpc_isr": nonprocess,
                         "samples_excluded_attribution_unknown": attribution_unknown,
                         "samples_missing_typed_classification": unclassified},
            "symbolization": ({"status": "LOCAL_PAIR_REVIEWED", "local_files": symbols.summary(),
                               "frame_occurrences_reviewed": symbol_frames,
                               "frame_occurrences_resolved": symbol_resolved,
                               "frame_occurrences_unresolved": symbol_frames-symbol_resolved,
                               "reasons": symbol_reasons,
                               "count_scope": "SELECTED_SAMPLES_BEFORE_NODE_BUDGET",
                               "raw_frames_preserved": True} if symbols else {"status": "NOT_REQUESTED"}),
            "provider": provider, "event": event_name,
            "measurement": "RECORDED_SAMPLE_OCCURRENCES_NOT_CPU_TIME_OR_CPU_PERCENT",
            "sample_weight_policy": "ONE_EVENT_OCCURRENCE_NOT_PAYLOAD_COUNT",
            "capture_complete": None, "trace_to_session_alignment": "NOT_ESTABLISHED",
            "root_cause": "UNKNOWN", "verification_class": "UNVERIFIED_IMPORT", "max_nodes": max_nodes}


def calltree_html(report):
    """Script-free, offline SVG flame view. All imported names are escaped."""
    nodes = report["nodes"]; coverage = report["coverage"]
    children = {}; depths = {0: 0}; positions = {0: 0.0}
    for n in nodes[1:]:
        parent = n["parent_id"]
        if type(parent) is not int or not 0 <= parent < n["id"]:
            raise ValueError("INVALID_CALLTREE_HIERARCHY")
        depths[n["id"]] = depths[parent]+1
        children.setdefault(parent, []).append(n)
    represented = coverage["samples_represented"]
    width = 1400; unit = width/max(1, represented); parts = []
    for parent in nodes:
        x = positions[parent["id"]]
        for n in children.get(parent["id"], []):
            positions[n["id"]] = x; x += n["inclusive_samples"]*unit
    height = (max(depths.values())+1)*26+12
    for n in nodes[1:]:
        x, y, w = positions[n["id"]], depths[n["id"]]*26, n["inclusive_samples"]*unit
        label = escape(n["label"], quote=True)
        parts.append(f'<g><title>{label} | inclusive samples: {n["inclusive_samples"]}; self: {n["self_samples"]}</title>'
                     f'<rect x="{x:.3f}" y="{y}" width="{max(0,w-1):.3f}" height="24" rx="2"/>'
                     f'<text x="{x+3:.3f}" y="{y+16}">{escape(n["label"][:max(0, int(w//7)-1)])}</text></g>')
    return ('<!doctype html><html><head><meta charset="utf-8">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
            '<title>BLACK.BOX recorded CPU samples</title><style>'
            'body{font:15px sans-serif;margin:24px}svg{max-width:100%;height:auto}rect{fill:#d8c8a0;stroke:#555}'
            'text{font:11px monospace;pointer-events:none}p{max-width:80em}</style></head><body>'
            '<h1>Recorded CPU sample call tree</h1>'
            '<p>Width = recorded sample count, NOT CPU%, duration or a time axis. '
            'Imported data is unverified; capture completeness is unknown. No causal conclusion.</p>'
            '<pre>'+escape(json.dumps({"status": report.get("status"),
                "filters": report.get("filters"), "coverage": coverage,
                "symbolization": report.get("symbolization"),
                "source_trace_sha256": report.get("source_trace_sha256")}, indent=2))+'</pre>'
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" role="img" '
            'aria-label="Call tree of recorded samples">'+''.join(parts)+'</svg></body></html>')


def export_analysis(report, destination, *, html=False):
    """Exclusive, atomic creation. Never overwrite source/index/other evidence."""
    path = safe_path(destination)
    if path.exists() or path.is_symlink():
        raise ValueError("OUTPUT_EXISTS")
    content = calltree_html(report) if html else json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2)
    data = content.encode("utf-8")
    if len(data) > 64*1024**2:
        raise ValueError("ANALYSIS_EXPORT_BUDGET")
    fd, name = tempfile.mkstemp(prefix=".bb-analysis-", dir=path.parent)
    part = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.link(part, path)
    finally:
        part.unlink(missing_ok=True)
