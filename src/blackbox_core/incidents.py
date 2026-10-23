"""Bounded opt-in CPU/gap incident capture from actual process measurements.

The session SQLite already owns complete samples. Incident events contain
references to real sample seq ranges; no imputation, OS hang claims or dumps.
"""
from __future__ import annotations
from collections import deque


class IncidentCapture:
    def __init__(self, *, threshold=85.0, min_duration_ms=3000,
                 gap_ms=5500, pre_ms=60000, post_ms=20000,
                 cooldown_ms=30000, max_incidents=20):
        if (type(threshold) not in (float, int) or not 0 < threshold <= 6400 or
                any(type(x) is not int or x < 0 for x in (
                    min_duration_ms, gap_ms, pre_ms, post_ms, cooldown_ms)) or
                type(max_incidents) is not int or not 1 <= max_incidents <= 100):
            raise ValueError("INVALID_INCIDENT_POLICY")
        self.threshold = float(threshold)
        self.min_duration_ms = min_duration_ms
        self.gap_ms = gap_ms
        self.pre_ms = pre_ms
        self.post_ms = post_ms
        self.cooldown_ms = cooldown_ms
        self.max_incidents = max_incidents
        self._history = deque(maxlen=512)
        self._last_time = None
        self._cpu_since = None
        self._active = None
        self._next_allowed_ms = 0
        self.incidents = 0
        self.buffer_evictions = 0

    def observe(self, *, elapsed_ms: int, sample_seq: int,
                cpu_percent: float | None) -> list[dict]:
        if (type(elapsed_ms) is not int or elapsed_ms < 0 or
                type(sample_seq) is not int or sample_seq <= 0 or
                (cpu_percent is not None and
                 (type(cpu_percent) not in (int, float) or
                  not 0 <= cpu_percent <= 6400)) or
                (self._last_time is not None and elapsed_ms < self._last_time)):
            raise ValueError("INVALID_INCIDENT_SAMPLE")
        old_time = self._last_time
        discontinuous = old_time is not None and elapsed_ms-old_time > self.gap_ms
        self._last_time = elapsed_ms
        while self._history and elapsed_ms-self._history[0]["elapsed_ms"] > self.pre_ms:
            self._history.popleft()
        if len(self._history) >= self._history.maxlen:
            self.buffer_evictions += 1
        self._history.append({"sample_seq": sample_seq, "elapsed_ms": elapsed_ms,
                              "cpu_percent": cpu_percent})
        events = []
        if discontinuous:
            self._cpu_since = None
            events.append({
                "kind": "sampling_gap", "code": "SAMPLING_GAP_OBSERVED",
                "start_ms": old_time, "end_ms": elapsed_ms,
                "gap_ms": elapsed_ms-old_time,
                "source": "BLACKBOX_LOCAL_MONOTONIC_SAMPLING",
                "interpretation": "OBSERVED_GAP_NOT_TARGET_HANG",
            })
        if cpu_percent is not None and cpu_percent >= self.threshold:
            if self._cpu_since is None:
                self._cpu_since = elapsed_ms
        else:
            self._cpu_since = None
        if self._active is None and self.incidents < self.max_incidents and (
                self._cpu_since is not None and
                elapsed_ms-self._cpu_since >= self.min_duration_ms and
                elapsed_ms >= self._next_allowed_ms):
            first = self._history[0] if self._history else None
            self._active = {
                "start_ms": elapsed_ms,
                "trigger_code": "CPU_SUSTAINED",
                "pre_first_seq": first["sample_seq"] if first else sample_seq,
                "trigger_seq": sample_seq,
                "pre_observed_count": len(self._history),
                "buffer_evictions_before": self.buffer_evictions,
            }
            events.append({
                "kind": "incident_boundary", "code": "AUTO_INCIDENT_STARTED",
                "source": "BLACKBOX_OBSERVED_PROCESS_CPU",
                "trigger_code": "CPU_SUSTAINED",
                "threshold_percent_one_cpu": self.threshold,
                "elapsed_ms": elapsed_ms, "sample_seq": sample_seq,
                "pre_first_seq": self._active["pre_first_seq"],
                "pre_observed_count": len(self._history),
                "proven_root_cause": False,
            })
        if self._active is not None and (
                elapsed_ms-self._active["start_ms"] >= self.post_ms):
            events.append(self._complete(sample_seq, elapsed_ms, status="CAPTURED"))
        return events

    def _complete(self, seq: int, time: int, *, status: str) -> dict:
        current = self._active
        self._active = None
        self.incidents += 1
        self._next_allowed_ms = time + self.cooldown_ms
        return {
            "kind": "incident_boundary", "code": "AUTO_INCIDENT_COMPLETED",
            "trigger_code": current["trigger_code"],
            "start_ms": current["start_ms"], "end_ms": time,
            "first_sample_seq": current["pre_first_seq"],
            "trigger_sample_seq": current["trigger_seq"], "last_sample_seq": seq,
            "pre_observed_count": current["pre_observed_count"],
            "buffer_evictions_before": current["buffer_evictions_before"],
            "status": status, "source": "BLACKBOX_EXTERNAL_COUNTERS",
            "proven_root_cause": False,
        }

    def stop(self, *, elapsed_ms: int, sample_seq: int) -> list[dict]:
        if self._active is None:
            return []
        return [self._complete(sample_seq, elapsed_ms, status="INCOMPLETE_RECORDING_STOPPED")]
