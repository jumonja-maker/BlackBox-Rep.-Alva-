"""Owner-managed offline report generation outside the Qt GUI event loop.

This QThread never receives a live SQLite SessionStore or mutates the
ReadOnlyProbe. It opens the completed schema1 session read-only through
write_report, and returns an immutable payload via queued Qt signals.
"""
from __future__ import annotations

from pathlib import Path
from PySide6.QtCore import QThread, Signal

from blackbox_core.report import write_report


class ReportWorker(QThread):
    result_ready = Signal(object, str)

    def __init__(self, session_folder: Path, parent=None):
        super().__init__(parent)
        self.session_folder = Path(session_folder)

    def run(self) -> None:
        try:
            report = write_report(self.session_folder)
            self.result_ready.emit(report, "")
        except Exception:
            # Never expose disk paths or arbitrary OS exceptions in the UI.
            # A report failure is not evidence of target-process failure.
            self.result_ready.emit(None, "REPORT_UNAVAILABLE")
