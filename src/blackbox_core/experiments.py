"""Bounded statistics for explicitly user-timed application action experiments.

This is command-to-command duration, not target-internal function runtime.
No statistical significance or causal speedup can be inferred from these values.
"""
from __future__ import annotations

import math
from statistics import median

_LIMIT = 20
_MAX_GROUPS = 16
_MAX_NS = 30 * 24 * 3600 * 1_000_000_000


def _p95(values: list[float]) -> float:
    ordered = sorted(values)
    index = (len(ordered) - 1) * 0.95
    lo = int(index)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (index - lo)


def _valid_id(value: object) -> bool:
    return (type(value) is str and len(value) == 32 and
            all(ch in "0123456789abcdef" for ch in value))


class ExperimentAccumulator:
    """Stream completed action rows without retaining arbitrary event text."""

    def __init__(self):
        self._groups: dict[str, dict] = {}
        self.invalid = 0
        self.groups_omitted = 0

    def observe(self, event: object) -> None:
        if type(event) is not dict or event.get("kind") != "action_marker":
            return
        if event.get("event") != "ACTION_COMPLETED":
            return
        eid, aid = event.get("experiment_id"), event.get("action_id")
        duration = event.get("duration_ns")
        if not (_valid_id(eid) and _valid_id(aid) and
                type(duration) is int and 0 <= duration <= _MAX_NS):
            self.invalid += 1
            return
        group = self._groups.get(eid)
        if group is None:
            if len(self._groups) >= _MAX_GROUPS:
                self.groups_omitted += 1
                return
            group = {"experiment_id": eid, "durations_ns": [],
                     "seen_actions": set(), "duplicates": 0, "omitted": 0}
            self._groups[eid] = group
        if aid in group["seen_actions"]:
            group["duplicates"] += 1
            return
        # Limit memory, but preserve a correct 'partial coverage' warning.
        if len(group["seen_actions"]) >= _LIMIT:
            group["omitted"] += 1
            return
        group["seen_actions"].add(aid)
        group["durations_ns"].append(duration)

    def result(self) -> dict:
        groups = []
        for group in self._groups.values():
            values = [v / 1_000_000 for v in group["durations_ns"]]
            middle = median(values)
            mad = median([abs(x - middle) for x in values])
            groups.append({
                "experiment_id": group["experiment_id"],
                "repeats": len(values),
                "duration_ms": {
                    "minimum": round(min(values), 3),
                    "median": round(middle, 3),
                    "p95": round(_p95(values), 3),
                    "maximum": round(max(values), 3),
                    "mad": round(mad, 3),
                },
                "actions_omitted": group["omitted"],
                "duplicate_markers_ignored": group["duplicates"],
                "warnings": (["INSUFFICIENT_REPEATS"] if len(values) < 2 else []) +
                            (["PARTIAL_COVERAGE"] if group["omitted"] else []),
                "source": "USER_COMMAND_UNVERIFIED",
                "runtime_semantics": "TIME_BETWEEN_USER_COMMANDS_NOT_INTERNAL_FUNCTION",
            })
        return {"experiments": groups, "groups_omitted": self.groups_omitted,
                "invalid_completed_markers": self.invalid,
                "root_cause_proven": False}


def compare_experiments(first: dict, second: dict, *,
                        same_workload: bool = False) -> dict:
    """Conservative comparison; caller must explicitly affirm same workload."""
    for candidate in (first, second):
        if (type(candidate) is not dict or
                type(candidate.get("repeats")) is not int or
                not 1 <= candidate["repeats"] <= _LIMIT or
                type(candidate.get("duration_ms")) is not dict):
            raise ValueError("INVALID_EXPERIMENT")
        metrics = candidate["duration_ms"]
        for key in ("median", "p95", "minimum", "maximum"):
            number = metrics.get(key)
            if type(number) not in (int, float) or not math.isfinite(number) or number < 0:
                raise ValueError("INVALID_EXPERIMENT")
    base = first["duration_ms"]["median"]
    new = second["duration_ms"]["median"]
    warnings = []
    if first["repeats"] < 5 or second["repeats"] < 5:
        warnings.append("INSUFFICIENT_REPEATS")
    if not same_workload:
        warnings.append("INCOMPARABLE_CONFIG_NOT_VERIFIED")
    if first.get("actions_omitted") or second.get("actions_omitted"):
        warnings.append("PARTIAL_COVERAGE")
    return {
        "before_median_ms": base, "after_median_ms": new,
        "delta_median_ms": round(new-base, 3),
        "relative_change_percent": round(100*(new-base)/base, 3) if base else None,
        "warnings": warnings,
        "speedup_proven": False,
        "causal_link_proven": False,
        "semantics": "USER_COMMAND_DURATION_COMPARISON",
    }
