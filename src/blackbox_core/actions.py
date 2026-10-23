"""Command-timestamped, durable user-action measurement state machine.

User interactions are not OS-attested events; sample timestamps must never be
substituted for the time a command was received by the application.
"""
from __future__ import annotations

import time
from uuid import uuid4


class ActionError(ValueError):
    pass


class ActionCycle:
    STATES = ("IDLE", "ARMED", "BASELINE", "RUNNING", "COOL_DOWN", "COMPLETED", "ABORTED")

    def __init__(self, *, clock=None, baseline_ms=5000, cool_down_ms=1000):
        if type(baseline_ms) is not int or not 0 <= baseline_ms <= 60000:
            raise ActionError("INVALID_BASELINE")
        if type(cool_down_ms) is not int or not 0 <= cool_down_ms <= 60000:
            raise ActionError("INVALID_COOL_DOWN")
        self.clock = clock if clock is not None else time.monotonic_ns
        self.baseline_ms = baseline_ms
        self.cool_down_ms = cool_down_ms
        self.state = "IDLE"
        self.action_id = None
        self.experiment_id = uuid4().hex  # Stable across repeats in one recording.
        self.prepared_ns = None
        self.started_ns = None
        self.ended_ns = None
        self.last_timestamp_ns = None
        self.completed = []
        self.completed_total = 0

    def _now(self):
        now = self.clock()
        if type(now) is not int or now < 0 or (self.last_timestamp_ns is not None and now < self.last_timestamp_ns):
            raise ActionError("INVALID_MONOTONIC_CLOCK")
        return now

    def _emit(self, event, new_state, now, persist, **details):
        record = {"kind": "action_marker", "source": "USER_COMMAND_UNVERIFIED",
                  "timestamp_precision": "COMMAND_MONOTONIC_NS",
                  "action_id": self.action_id, "experiment_id": self.experiment_id,
                  "event": event,
                  "timestamp_monotonic_ns": now, "state": new_state, **details}
        # The SQLite transaction commits before in-memory state advances.
        persist(record)
        self.state = new_state
        self.last_timestamp_ns = now
        return record

    def prepare(self, persist):
        if self.state not in ("IDLE", "COMPLETED", "ABORTED"):
            raise ActionError("ACTION_ALREADY_ACTIVE")
        now = self._now()
        previous_id = self.action_id
        self.action_id = uuid4().hex
        try:
            record = self._emit("ACTION_PREPARED", "ARMED", now, persist,
                                baseline_ms=self.baseline_ms)
        except BaseException:
            self.action_id = previous_id
            raise
        self.prepared_ns, self.started_ns, self.ended_ns = now, None, None
        return record

    def advance(self, persist):
        now = self._now()
        if self.state == "ARMED":
            return self._emit("BASELINE_STARTED", "BASELINE", now, persist)
        if self.state == "COOL_DOWN" and now - self.ended_ns >= self.cool_down_ms * 1000000:
            record = self._emit("ACTION_COMPLETED", "COMPLETED", now, persist,
                                duration_ns=self.ended_ns - self.started_ns)
            self.completed.append({"action_id": self.action_id, "experiment_id": self.experiment_id,
                                   "start_ns": self.started_ns,
                                   "end_ns": self.ended_ns,
                                   "duration_ns": self.ended_ns - self.started_ns})
            self.completed_total += 1
            # Durable SQLite retains every run; GUI keeps only a recent tail.
            if len(self.completed) > 256:
                del self.completed[0]
            return record
        return None

    def ready_to_start(self):
        return (self.state in ("ARMED", "BASELINE") and self.prepared_ns is not None and
                self._now() - self.prepared_ns >= self.baseline_ms * 1000000)

    def begin(self, persist):
        if self.state not in ("ARMED", "BASELINE"):
            raise ActionError("ACTION_NOT_PREPARED")
        now = self._now()
        if now - self.prepared_ns < self.baseline_ms * 1000000:
            raise ActionError("BASELINE_NOT_READY")
        record = self._emit("ACTION_STARTED", "RUNNING", now, persist,
                            baseline_elapsed_ns=now - self.prepared_ns)
        self.started_ns = now
        return record

    def finish(self, persist):
        if self.state != "RUNNING":
            raise ActionError("ACTION_NOT_RUNNING")
        now = self._now()
        record = self._emit("ACTION_ENDED", "COOL_DOWN", now, persist,
                            duration_ns=now - self.started_ns)
        self.ended_ns = now
        return record

    def abort(self, persist, reason="RECORDING_STOPPED"):
        if self.state not in ("ARMED", "BASELINE", "RUNNING", "COOL_DOWN"):
            return None
        if reason not in ("RECORDING_STOPPED", "PROCESS_UNAVAILABLE", "RECORDING_RESTARTED"):
            raise ActionError("INVALID_ABORT_REASON")
        return self._emit("ACTION_ABORTED", "ABORTED", self._now(), persist, reason=reason)
