"""One-shot Qt worker for base read-only process sampling and SQLite writes.

No Python psutil sampling or schema-1 sample INSERT runs in the GUI event loop.
Only one worker is active per UI session; no unbounded queue is permitted.
User command/event writes retain their existing independently committed
SessionStore connection on the GUI thread.
"""
from __future__ import annotations

from pathlib import Path
import time

from PySide6.QtCore import QThread, Signal
from blackbox_core.contracts import ObserverError
from blackbox_core.probe import PsutilProbe
from blackbox_core.storage import write_sample_from_worker


class BaseSampleWorker(QThread):
    result_ready = Signal(object, str)

    def __init__(self, core: PsutilProbe, folder: Path, parent=None,
                 *, requested_interval_ms: int = 1000):
        super().__init__(parent)
        if (type(requested_interval_ms) is not int or
                not 1 <= requested_interval_ms <= 60000):
            raise ValueError("INVALID_REQUESTED_INTERVAL")
        self.core = core
        self.folder = Path(folder)
        self.requested_interval_ms = requested_interval_ms

    def run(self) -> None:
        try:
            started_ns = time.monotonic_ns()
            sample = self.core.sample()
            sensor_done_ns = time.monotonic_ns()
            seq = write_sample_from_worker(self.folder, sample)
            write_done_ns = time.monotonic_ns()
            self.result_ready.emit({
                "sample": sample, "seq": seq,
                "folder": str(self.folder),
                "requested_interval_ms": self.requested_interval_ms,
                "worker_timing": {
                    "started_ns": started_ns,
                    "sensor_done_ns": sensor_done_ns,
                    "write_done_ns": write_done_ns,
                },
            }, "")
        except ObserverError as exc:
            self.result_ready.emit(None, exc.code)
        except Exception:
            # Unexpected psutil/SQLite failures cannot be reclassified as
            # successful collection. Never leak full OS paths or exceptions.
            self.result_ready.emit(None, "SAMPLE_UNAVAILABLE")
