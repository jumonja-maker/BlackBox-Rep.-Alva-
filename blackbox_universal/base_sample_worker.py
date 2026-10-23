"""One-shot Qt worker for base read-only process sampling and SQLite writes.

No Python psutil sampling or schema-1 sample INSERT runs in the GUI event loop.
Only one worker is active per UI session; no unbounded queue is permitted.
User command/event writes retain their existing independently committed
SessionStore connection on the GUI thread.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal
from blackbox_core.contracts import ObserverError
from blackbox_core.probe import PsutilProbe
from blackbox_core.storage import write_sample_from_worker


class BaseSampleWorker(QThread):
    result_ready = Signal(object, str)

    def __init__(self, core: PsutilProbe, folder: Path, parent=None):
        super().__init__(parent)
        self.core = core
        self.folder = Path(folder)

    def run(self) -> None:
        try:
            sample = self.core.sample()
            seq = write_sample_from_worker(self.folder, sample)
            self.result_ready.emit({"sample": sample, "seq": seq,
                                    "folder": str(self.folder)}, "")
        except ObserverError as exc:
            self.result_ready.emit(None, exc.code)
        except Exception:
            # Unexpected psutil/SQLite failures cannot be reclassified as
            # successful collection. Never leak full OS paths or exceptions.
            self.result_ready.emit(None, "SAMPLE_UNAVAILABLE")
