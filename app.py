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
    parser.add_argument("--deep-smoke",action="store_true",help="Run real Qt action/thread/incident/export QA")
    parser.add_argument("--qa-output",type=Path,help="Explicit QA artifact directory")
    parser.add_argument("--qa-fixture",choices=("cpu","ui","waitchain"),help=argparse.SUPPRESS)
    parser.add_argument("--qa-commit-sha",default="UNKNOWN",help=argparse.SUPPRESS)
    options = parser.parse_args(argv)
    if options.qa_fixture:
        if options.qa_output is None:
            parser.error("--qa-fixture requires --qa-output")
        from blackbox_universal.qa_fixtures import run_fixture
        return run_fixture(options.qa_fixture,options.qa_output)
    if options.smoke or options.deep_smoke:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("BLACK.BOX Universal")
    app.setOrganizationName("BlackBox")
    set_retro_theme(app)
    window = UniversalWindow()
    window.show()
    if options.deep_smoke:
        if options.qa_output is None:
            parser.error("--deep-smoke requires --qa-output")
        from blackbox_universal.deep_smoke import DeepSmoke
        controller=DeepSmoke(app,window,options.qa_output,options.qa_commit_sha)
        controller.start()
        return app.exec()
    if options.smoke:
        # Exercise the ACTUAL Python/frozen binary, not only a Qt import.
        # Entirely temporary and offline.
        expected = ("dashboard", "processes", "events", "reports", "settings")
        if tuple(key for key, _ in window.PAGES) != expected:
            raise RuntimeError("SMOKE_GUI_PAGES_INCORRECT")
        if window.stack.count() != 5:
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
            # Exercise the actual bundled Investigation Engine + Qt worker.
            # A green desktop startup alone cannot prove the module is packed.
            from blackbox_universal.investigation_worker import InvestigationWorker
            probe_markers = []
            smoke_worker = InvestigationWorker(folder, "EN")
            smoke_worker.result_ready.connect(
                lambda packet, error: probe_markers.append((packet, error)))
            smoke_worker.run()
            if len(probe_markers) != 1 or probe_markers[0][1]:
                raise RuntimeError("SMOKE_INVESTIGATION_WORKER_FAILED")
            packet = probe_markers[0][0]
            if not isinstance(packet, dict) or packet.get("result", {}).get("schema_version") != 2:
                raise RuntimeError("SMOKE_INVESTIGATION_SCHEMA_FAILED")
            if not Path(packet["json"]).is_file() or not Path(packet["html"]).is_file():
                raise RuntimeError("SMOKE_INVESTIGATION_REPORT_MISSING")
            if "Root cause: UNKNOWN" not in Path(packet["html"]).read_text(encoding="utf-8"):
                raise RuntimeError("SMOKE_INVESTIGATION_CLAIM_UNSAFE")
            html = (folder / "report.html").read_text(encoding="utf-8")
            if "Application root cause not determined" not in html:
                raise RuntimeError("SMOKE_REPORT_NOT_HUMAN_READABLE")
        QTimer.singleShot(280, app.quit)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
