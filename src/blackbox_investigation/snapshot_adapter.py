"""Exact adapter for ReadOnlyProbe.snapshot() from BLACK.BOX v0.3.4."""
from __future__ import annotations

import math
from .engine import analyze
from .model import InvestigationError, Policy, validate_policy


def analyze_snapshot(snapshot: dict, *, policy: Policy | None = None,
                     user_markers: list[dict] | None = None) -> dict:
    policy = validate_policy(policy)
    if (type(snapshot) is not dict or snapshot.get("schema_version") != 1 or
            snapshot.get("product") != "BLACK.BOX Universal" or
            type(snapshot.get("recent_samples")) is not list):
        raise InvestigationError("UNSUPPORTED_BLACKBOX_SNAPSHOT")
    if len(snapshot["recent_samples"]) > policy.max_samples:
        raise InvestigationError("SAMPLE_LIMIT")
    ident = snapshot.get("observed_process")
    if type(ident) is not dict or type(ident.get("pid")) is not int or ident["pid"] <= 0:
        raise InvestigationError("INVALID_SESSION_IDENTITY")
    rows = []
    for sample in snapshot["recent_samples"]:
        if type(sample) is not dict:
            raise InvestigationError("INVALID_SAMPLE")
        seconds = sample.get("seconds")
        rss_mb = sample.get("rss_mb")
        if (type(seconds) not in (int, float) or not math.isfinite(seconds) or
                seconds < 0 or seconds > 30 * 24 * 3600):
            raise InvestigationError("INVALID_ELAPSED_MS")
        if (rss_mb is not None and
                (type(rss_mb) not in (int, float) or not math.isfinite(rss_mb) or
                 rss_mb < 0 or rss_mb > (2**63 - 1) / 1048576)):
            raise InvestigationError("INVALID_RSS_BYTES")
        count = sample.get("process_count")
        if count is not None and (type(count) is not int or count < 1):
            raise InvestigationError("INVALID_CHILDREN_COUNT")
        rows.append({"elapsed_ms": round(seconds * 1000), "cpu_percent": sample.get("cpu_pct"),
                     "rss_bytes": round(rss_mb * 1048576) if rss_mb is not None else None,
                     "num_threads": sample.get("thread_count"), "read_bytes": sample.get("read_bytes"),
                     "write_bytes": sample.get("write_bytes"),
                     "children_count": count - 1 if count is not None else None})
    report = analyze(rows, markers=user_markers, policy=policy,
                     identity={"pid": ident["pid"], "creation_time": None})
    report["provenance"].update(sample_source="BLACKBOX_QT_SNAPSHOT_V1",
                                pid_creation_verified=False, snapshot_origin="APP_SUPPLIED_NOT_AUTHENTICATED")
    return report
