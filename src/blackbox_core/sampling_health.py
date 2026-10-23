"""Bounded evidence of Qt timer callbacks skipped while base sampler is busy.

This only counts *delivered* timer callbacks rejected because a previous
sample worker was in flight. Qt can coalesce timer callbacks when the event
loop is blocked: those invisible deadlines CANNOT be counted by this class.
Likewise this is not an OS-observed sample gap, lost TID evidence or hang.
"""
from __future__ import annotations

MAX_BUSY_CALLBACKS = 1_000_000


class BusyTickTracker:
    def __init__(self) -> None:
        self._count = 0
        self._first_ns: int | None = None
        self._last_ns: int | None = None
        self._interval_ms: int | None = None
        self._clock_ok = True
        self._truncated = False

    def skipped(self, timestamp_ns: int, interval_ms: int) -> None:
        """Record one rejected callback; never pretend it was an OS sample."""
        if (type(timestamp_ns) is not int or timestamp_ns < 0 or
                type(interval_ms) is not int or not 1 <= interval_ms <= 60000):
            raise ValueError("INVALID_BUSY_TICK_CLOCK")
        if self._count == 0:
            self._first_ns = timestamp_ns
            self._interval_ms = interval_ms
        else:
            if timestamp_ns < self._last_ns:
                self._clock_ok = False
            if interval_ms != self._interval_ms:
                self._interval_ms = None  # interval changed during episode
        self._last_ns = timestamp_ns
        if self._count < MAX_BUSY_CALLBACKS:
            self._count += 1
        else:
            self._truncated = True

    def drain(self) -> dict | None:
        """Return a small immutable-value summary and start a fresh episode."""
        if not self._count:
            return None
        result = {
            "kind": "sampling_gap",
            "code": "BASE_TIMER_CALLBACK_SKIPPED_BUSY",
            "source": "QT_TIMER_SCHEDULER",
            "verification_class": "OBSERVED_GUI_CALLBACK_ONLY",
            "root_cause_proven": False,
            "missed_callback_count": self._count,
            "first_skipped_monotonic_ns": self._first_ns,
            "last_skipped_monotonic_ns": self._last_ns,
            "scheduled_interval_ms": self._interval_ms,
            "clock_quality": ("MONOTONIC" if self._clock_ok else
                              "CALLBACK_CLOCK_REVERSAL"),
            "count_truncated": self._truncated,
            "limitations": "QT_COALESCED_CALLBACKS_NOT_COUNTED",
        }
        self.__init__()
        return result


class MonotonicSampleCadence:
    """Derive spacing between real accepted samples from the same probe clock.

    The elapsed_ms values originate from PsutilProbe.start's monotonic clock
    and retain millisecond resolution. Spacing is factual; an implied number
    of missing scheduled OS samples is NEVER inferred.
    """

    def __init__(self) -> None:
        self.previous_elapsed_ms: int | None = None
        self.previous_interval_ms: int | None = None
        self.comparable_pairs = 0
        self.interval_changes = 0
        self.extended_pairs = 0
        self.max_observed_spacing_ms: int | None = None

    @staticmethod
    def _validate(elapsed_ms: int, interval_ms: int) -> None:
        if (type(elapsed_ms) is not int or elapsed_ms < 0 or
                type(interval_ms) is not int or not 1 <= interval_ms <= 60000):
            raise ValueError("INVALID_SAMPLE_CADENCE")

    def preview(self, elapsed_ms: int, interval_ms: int) -> dict | None:
        """Preview a gap event WITHOUT altering state before durable persistence."""
        self._validate(elapsed_ms, interval_ms)
        old = self.previous_elapsed_ms
        if old is None:
            return None
        if elapsed_ms < old:
            raise ValueError("SAMPLE_CLOCK_REVERSED")
        if self.previous_interval_ms != interval_ms:
            return None  # cannot compare across a user interval change
        delta = elapsed_ms - old
        threshold = max(2 * interval_ms, interval_ms + 500)
        if delta <= threshold:
            return None
        return {
            "kind": "sampling_gap",
            "code": "EXTENDED_MONOTONIC_SAMPLE_SPACING",
            "source": "BLACKBOX_MONOTONIC_SAMPLE_CLOCK",
            "verification_class": "DERIVED_ADJACENT_OS_COUNTER_SNAPSHOTS",
            "root_cause_proven": False,
            "previous_elapsed_ms": old,
            "current_elapsed_ms": elapsed_ms,
            "observed_spacing_ms": delta,
            "configured_interval_ms": interval_ms,
            "threshold_ms": threshold,
            "missing_sample_count": None,
            "limitations": "UNKNOWN_SCHEDULING_CAUSE_NO_OS_GAP_ATTESTATION",
        }

    def commit(self, elapsed_ms: int, interval_ms: int, *,
               was_extended: bool) -> None:
        """Advance only after caller has accepted the persisted sample."""
        self._validate(elapsed_ms, interval_ms)
        old = self.previous_elapsed_ms
        if old is not None:
            if elapsed_ms < old:
                raise ValueError("SAMPLE_CLOCK_REVERSED")
            if self.previous_interval_ms != interval_ms:
                self.interval_changes += 1
            else:
                spacing = elapsed_ms - old
                self.comparable_pairs += 1
                if (self.max_observed_spacing_ms is None or
                        spacing > self.max_observed_spacing_ms):
                    self.max_observed_spacing_ms = spacing
                if was_extended:
                    self.extended_pairs += 1
        self.previous_elapsed_ms = elapsed_ms
        self.previous_interval_ms = interval_ms


class BaseWorkerTiming:
    """Bounded summaries of worker-owned monotonic instrumentation."""

    def __init__(self) -> None:
        self.completed_workers = 0
        self.max_sensor_ms = 0
        self.max_sqlite_ms = 0
        self.max_signal_delivery_ms = 0

    def observe(self, *, started_ns: int, sensor_done_ns: int,
                write_done_ns: int, received_ns: int) -> None:
        values = (started_ns, sensor_done_ns, write_done_ns, received_ns)
        if (any(type(x) is not int or x < 0 for x in values) or
                list(values) != sorted(values)):
            raise ValueError("INVALID_WORKER_TIMING")
        # Integer flooring is part of the stated resolution. It cannot
        # substitute for an OS deadline or an instrumented process trace.
        self.completed_workers += 1
        self.max_sensor_ms = max(
            self.max_sensor_ms, (sensor_done_ns - started_ns) // 1_000_000)
        self.max_sqlite_ms = max(
            self.max_sqlite_ms, (write_done_ns - sensor_done_ns) // 1_000_000)
        self.max_signal_delivery_ms = max(
            self.max_signal_delivery_ms, (received_ns - write_done_ns) // 1_000_000)

    def event(self, cadence: MonotonicSampleCadence) -> dict | None:
        if self.completed_workers <= 0:
            return None
        return {
            "kind": "worker_health",
            "code": "BASE_SAMPLE_WORKER_TIMING_SUMMARY",
            "source": "PYTHON_MONOTONIC_BRACKETS",
            "verification_class": "INTERNAL_WORKER_TIMING_DERIVED",
            "root_cause_proven": False,
            "completed_workers": self.completed_workers,
            "max_sensor_ms": self.max_sensor_ms,
            "max_sqlite_ms": self.max_sqlite_ms,
            "max_signal_delivery_ms": self.max_signal_delivery_ms,
            "comparable_sample_pairs": cadence.comparable_pairs,
            "extended_sample_pairs": cadence.extended_pairs,
            "interval_changes": cadence.interval_changes,
            "max_observed_spacing_ms": cadence.max_observed_spacing_ms,
            "limitations": "SUMMARY_ON_ORDERLY_STOP_ONLY_NO_OS_DEADLINE",
        }
