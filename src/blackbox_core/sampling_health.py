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
