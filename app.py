"""Run BLACK.BOX Universal. --smoke performs a short offscreen startup check."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from blackbox_universal.monitor import ReadOnlyProbe
from blackbox_universal.theme import set_retro_theme
from blackbox_universal.window import UniversalWindow


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BLACK.BOX Universal retro desktop")
    parser.add_argument("--smoke", action="store_true",
                        help="Run Qt offscreen and exit automatically (QA only)")
    parser.add_argument("--require-bundled-alva", action="store_true",
                        help="QA only: fail if genuine packaged Alva checks cannot execute")
    options = parser.parse_args(argv)
    if options.require_bundled_alva and not options.smoke:
        parser.error("--require-bundled-alva also requires --smoke")
    if options.smoke:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("BLACK.BOX Universal")
    app.setOrganizationName("BlackBox")
    set_retro_theme(app)
    window = UniversalWindow()
    window.show()
    if options.smoke:
        # Exercise the ACTUAL Python/frozen binary, not only a Qt import.
        # Entirely temporary, offline and independent of private Alva.
        expected = ("dashboard", "processes", "events", "reports", "settings")
        if tuple(key for key, _ in window.PAGES) != expected:
            raise RuntimeError("SMOKE_GUI_PAGES_INCORRECT")
        if window.stack.count() != 5 or hasattr(window, "alva_check"):
            raise RuntimeError("SMOKE_PLATFORM_PAGE_PRESENT")
        with tempfile.TemporaryDirectory(prefix="bb-human-smoke-") as temp:
            probe = ReadOnlyProbe(output_root=Path(temp))
            probe.attach(os.getpid())
            probe.start()
            if probe.tick() is None:
                raise RuntimeError("SMOKE_PROCESS_SAMPLE_MISSING")
            probe.stop()
            folder = probe.session_folder
            if folder is None or probe.last_error:
                raise RuntimeError("SMOKE_SESSION_FAILED")
            for filename in ("session.sqlite3", "report.json", "report.html"):
                if not (folder / filename).is_file():
                    raise RuntimeError("SMOKE_HUMAN_REPORT_MISSING")
            if (folder / "ai-handoff.json").exists():
                raise RuntimeError("SMOKE_AI_HANDOFF_FORBIDDEN")
            html = (folder / "report.html").read_text(encoding="utf-8")
            if "Application root cause not determined" not in html:
                raise RuntimeError("SMOKE_REPORT_NOT_HUMAN_READABLE")
            if options.require_bundled_alva:
                # Private-release CI *must* execute genuine Alva inside the
                # ACTUAL PyInstaller binary before any public distribution.
                from blackbox_universal.platform_connector import (
                    bundled_runtime_available, save_bundled_diagnostics)
                if not bundled_runtime_available():
                    raise RuntimeError("SMOKE_REAL_ALVA_NOT_BUNDLED")
                evidence = save_bundled_diagnostics(folder)
                if (evidence.get("status") != "ok" or
                        evidence.get("declared_checks") != 4 or
                        evidence.get("reviewed_checks") != 4 or
                        not (folder / "evidence-checks.json").is_file()):
                    raise RuntimeError("SMOKE_REAL_ALVA_NOT_EXECUTED")
        QTimer.singleShot(280, app.quit)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
