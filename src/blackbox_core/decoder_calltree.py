"""Bounded CPU sample call tree from original events, never CPU time/percent.

Uses only the explicitly recognized .NET SampleProfiler Thread/Sample source.
GC/event-associated stacks are excluded. A flame chart is an aggregation,
not a timeline. Missing samples and truncated stacks remain visible.
"""
from __future__ import annotations
from contextlib import closing
import hashlib
from html import escape
import json
import math
import os
from pathlib import Path
import sqlite3
import tempfile
import time

from .decoder_index import APP_ID, validate_event
from .decoder_modules import validate_module_frame, integer, number
from .decoder_profiles import SAMPLE_PROVIDER, SAMPLE_EVENT
from .session_v2 import safe_path

MAX_TREE_NODES = 20000
MAX_TREE_EVENTS = 250000


def build_calltree(index_path, *, pid=0, process_instance=None, start_ms=None,
                   end_ms=None, max_nodes=10000, cancel=None):
    if (not integer(pid) or (process_instance is not None and not integer(process_instance)) or
            type(max_nodes) is not int or not 4 <= max_nodes <= MAX_TREE_NODES or
            (start_ms is not None and not number(start_ms)) or
            (end_ms is not None and not number(end_ms)) or
            (start_ms is not None and end_ms is not None and end_ms <= start_ms)):
        raise ValueError("INVALID_CALLTREE_FILTER")
    path = safe_path(index_path)
    if not path.is_file():
        raise ValueError("INVALID_INDEX_FILE")
    deadline = time.monotonic()+30

    def check():
        if cancel is not None and cancel.is_set():
            raise InterruptedError("CALLTREE_CANCELLED")
        if time.monotonic() > deadline:
            raise TimeoutError("CALLTREE_DEADLINE")

    def node(identifier, parent, label, frame=None):
        return {"id": identifier, "parent_id": parent, "label": label,
                "inclusive_samples": 0, "self_samples": 0, "frame": frame}

    check()
    nodes = [node(0, None, "Recorded CPU samples (not CPU time)")]
    edges = {}; selected = missing = clipped = omitted = represented = unknown = 0
    with closing(sqlite3.connect(path.resolve().as_uri()+"?mode=ro", uri=True, timeout=1)) as db:
        db.execute("PRAGMA query_only=ON"); db.execute("PRAGMA trusted_schema=OFF")
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2*1024**2)
        db.set_progress_handler(lambda: int(time.monotonic() > deadline or
                                            (cancel is not None and cancel.is_set())), 1000)
        if (db.execute("PRAGMA application_id").fetchone()[0] != APP_ID or
                db.execute("PRAGMA user_version").fetchone()[0] not in (1, 2, 3, 4)):
            raise ValueError("INVALID_INDEX_SCHEMA")
        # One read snapshot: source totals and selected rows must not mix transactions.
        db.execute("BEGIN")
        summary = json.loads(db.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()[0])
        sql = "SELECT id,pid,time_ms,data FROM events WHERE provider=? AND name=?"
        values = [SAMPLE_PROVIDER, SAMPLE_EVENT]
        if pid:
            sql += " AND pid=?"; values.append(pid)
        if start_ms is not None:
            sql += " AND time_ms>=?"; values.append(start_ms)
        if end_ms is not None:
            sql += " AND time_ms<?"; values.append(end_ms)
        for event_id, stored_pid, stored_ms, raw in db.execute(sql+" ORDER BY id", values):
            check()
            row = json.loads(raw)
            validate_event(row, event_id)
            if (row["pid"] != stored_pid or row["time_ms"] != stored_ms or
                    row["provider"] != SAMPLE_PROVIDER or row["name"] != SAMPLE_EVENT):
                raise ValueError("INDEX_EVENT_METADATA_MISMATCH")
            instance = row["process_instance"]
            if process_instance is not None and instance != process_instance:
                continue
            selected += 1
            if selected > MAX_TREE_EVENTS:
                raise ValueError("CALLTREE_EVENT_BUDGET")
            nodes[0]["inclusive_samples"] += 1
            if instance is None:
                unknown += 1
            scope = (stored_pid, instance if instance is not None else -event_id)
            labels = [("process:"+repr(scope), f"PID {stored_pid} / instance {instance if instance is not None else 'unknown event '+str(event_id)}", None)]
            frames = row["frames"]
            if not frames:
                missing += 1
                labels.append(("missing", "[stack not recorded]", None))
            else:
                if row.get("stack_status") == "TRUNCATED_128_FRAMES":
                    clipped += 1
                    labels.append(("truncated", "[callers omitted: truncated stack]", None))
                for frame in reversed(frames):
                    validate_module_frame(row, frame)
                    # Keep addresses and module lifetimes in identity even with identical names.
                    canonical = json.dumps(frame, sort_keys=True, ensure_ascii=True,
                                           separators=(",", ":"), allow_nan=False)
                    key = hashlib.sha256(canonical.encode("ascii")).hexdigest()
                    label = frame["name"] or "[unresolved "+frame["address"]+"]"
                    labels.append((key, label, frame))
            # Reserve the entire path before counting this sample. Never silently
            # lose descendants or turn a budget omission into function self-time.
            parent = 0; first_new = len(labels); path_ids = []
            for at, (key, _, _) in enumerate(labels):
                found = edges.get((parent, key))
                if found is None:
                    first_new = at; break
                path_ids.append(found); parent = found
            if len(nodes)+(len(labels)-first_new) > max_nodes:
                omitted += 1; continue
            for key, label, frame in labels[first_new:]:
                identifier = len(nodes); nodes.append(node(identifier, parent, label, frame))
                edges[(parent, key)] = identifier; parent = identifier; path_ids.append(identifier)
            for identifier in path_ids:
                nodes[identifier]["inclusive_samples"] += 1
            nodes[path_ids[-1]]["self_samples"] += 1
            represented += 1
        check()
    return {"schema": "blackbox.cpu-calltree/1", "nodes": nodes,
            "source_trace_sha256": summary.get("input_sha256"),
            "filters": {"pid": pid, "process_instance": process_instance,
                        "start_ms_inclusive": start_ms, "end_ms_exclusive": end_ms},
            "coverage": {"samples_selected": selected, "samples_represented": represented,
                         "samples_omitted_node_budget": omitted, "samples_without_stack": missing,
                         "samples_with_truncated_stack": clipped, "samples_without_process_identity": unknown},
            "provider": SAMPLE_PROVIDER, "event": SAMPLE_EVENT,
            "measurement": "RECORDED_SAMPLE_OCCURRENCES_NOT_CPU_TIME_OR_CPU_PERCENT",
            "capture_complete": None, "trace_to_session_alignment": "NOT_ESTABLISHED",
            "root_cause": "UNKNOWN", "verification_class": "UNVERIFIED_IMPORT",
            "max_nodes": max_nodes}


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
            '<pre>'+escape(json.dumps(coverage, indent=2))+'</pre>'
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
