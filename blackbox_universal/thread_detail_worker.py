"""Qt worker for read-only, bounded per-TID CPU analysis.

The SQLite reader never executes on the GUI main thread.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal

from blackbox_core.detail_analysis import analyze_detail_threads


class ThreadDetailWorker(QThread):
    result_ready = Signal(object, str)

    def __init__(self, folder: Path, parent=None):
        super().__init__(parent)
        self.folder = Path(folder)

    def run(self) -> None:
        try:
            result = analyze_detail_threads(self.folder)
            self.result_ready.emit({
                "folder": str(self.folder), "analysis": result,
            }, "")
        except (OSError, ValueError, TypeError):
            self.result_ready.emit(None, "DETAIL_READ_UNAVAILABLE")
