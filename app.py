"""Run BLACK.BOX Universal. --smoke performs a short offscreen startup check."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile


def _qa_checkpoint(stage: str) -> None:
    if "--smoke" in sys.argv:
        Path("blackbox-smoke-progress.json").write_text(
            __import__("json").dumps({"stage": stage, "pid": os.getpid()}), encoding="utf-8")

if __name__=='__main__' and '--qa-workload' in sys.argv:
    from blackbox_core.qa_workloads import main as workload_main
    raise SystemExit(workload_main(sys.argv[sys.argv.index('--qa-workload')+1:]))

if __name__=='__main__' and '--qa-production' in sys.argv:
    from blackbox_universal.production_qa import main as production_main
    raise SystemExit(production_main(sys.argv[sys.argv.index('--qa-production')+1:]))

if __name__ == "__main__" and "--trace-owner" in sys.argv:
    from blackbox_core.trace_owner import run as trace_main
    raise SystemExit(trace_main(sys.argv[sys.argv.index("--trace-owner")+1]))

if __name__=='__main__' and '--runtime-owner' in sys.argv:
    from blackbox_core.runtime_trace import run as runtime_main
    raise SystemExit(runtime_main(sys.argv[sys.argv.index('--runtime-owner')+1]))

# Optional diagnostics use a disposable child of the same frozen executable.
if __name__ == "__main__" and "--research-operation" in sys.argv:
    from blackbox_core.operation_worker import main as operation_main
    operation_index = sys.argv.index("--research-operation")
    raise SystemExit(operation_main(*sys.argv[operation_index+1:]))

# Dispatch before importing Qt. The same packaged EXE owns the session child.
if __name__ == "__main__" and "--research-worker" in sys.argv:
    worker_parser = argparse.ArgumentParser()
    worker_parser.add_argument("--research-worker", action="store_true")
    worker_parser.add_argument("--research-root")
    worker_options = worker_parser.parse_args()
    from blackbox_core.research_worker import main as research_main
    raise SystemExit(research_main(worker_options.research_root))

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from blackbox_universal.monitor import ReadOnlyProbe
from blackbox_universal.theme import set_retro_theme, font_coverage
from blackbox_universal.window import UniversalWindow


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BLACK.BOX Universal retro desktop")
    parser.add_argument("--smoke", action="store_true",
                        help="Run Qt offscreen and exit automatically (QA only)")
    parser.add_argument("--attach-pid", type=int, help="Select an existing process; recording remains explicit")
    parser.add_argument("--research-e2e", type=Path, help="Run isolated end-to-end research QA into an explicit directory")
    parser.add_argument("--deep-smoke",action="store_true",help="Run real Qt action/thread/incident/export QA")
    parser.add_argument("--qa-output",type=Path,help="Explicit QA artifact directory")
    parser.add_argument("--qa-fixture",choices=("cpu","ui","waitchain"),help=argparse.SUPPRESS)
    parser.add_argument("--qa-commit-sha",default="UNKNOWN",help=argparse.SUPPRESS)
    options = parser.parse_args(argv)
    if options.deep_smoke and options.qa_output is None:
        parser.error("--deep-smoke requires --qa-output")
    if options.qa_fixture:
        if options.qa_output is None:
            parser.error("--qa-fixture requires --qa-output")
        from blackbox_universal.qa_fixtures import run_fixture
        return run_fixture(options.qa_fixture,options.qa_output)
    if options.smoke or options.deep_smoke:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        _qa_checkpoint("QT_START")
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("BLACK.BOX Universal")
    app.setOrganizationName("BlackBox")
    set_retro_theme(app)
    window = UniversalWindow(isolated=True,
        output_root=(options.research_e2e or options.qa_output) / "sessions" if (options.research_e2e or options.deep_smoke) else None,
        allow_update_check=not (options.smoke or options.research_e2e or options.deep_smoke))
    # Native Windows starts maximized, while retaining the normal window frame,
    # minimize/restore and user resizing (not exclusive fullscreen mode).
    window.showMaximized()
    if options.deep_smoke:
        if options.qa_output is None:
            parser.error("--deep-smoke requires --qa-output")
        from blackbox_universal.deep_smoke import DeepSmoke
        controller=DeepSmoke(app,window,options.qa_output,options.qa_commit_sha)
        controller.start()
        return app.exec()
    if options.smoke:
        if not font_coverage(app)["ok"]:
            raise RuntimeError("SMOKE_RU_EN_FONT_GLYPHS_MISSING")
        _qa_checkpoint("WINDOW_SHOWN")
    if options.attach_pid:
        QTimer.singleShot(0, lambda: window._attach_pid(options.attach_pid))
    if options.research_e2e:
        from blackbox_universal.research_e2e import run_e2e
        run_e2e(app, window, options.research_e2e)
    if options.smoke:
        # Exercise the ACTUAL Python/frozen binary, not only a Qt import.
        # Entirely temporary and offline.
        expected = ("dashboard", "processes", "events", "reports", "settings")
        if tuple(key for key, _ in window.PAGES) != expected:
            raise RuntimeError("SMOKE_GUI_PAGES_INCORRECT")
        if window.stack.count() != 5:
            raise RuntimeError("SMOKE_PLATFORM_PAGE_PRESENT")
        with tempfile.TemporaryDirectory(prefix="bb-human-smoke-") as temp:
            from blackbox_universal.qa_fixtures import observer_identity
            probe = ReadOnlyProbe(output_root=Path(temp))
            probe.attach(observer_identity()[0])
            probe.start()
            _qa_checkpoint("PROBE_STARTED")
            if probe.tick() is None:
                raise RuntimeError("SMOKE_PROCESS_SAMPLE_MISSING")
            probe.stop()
            _qa_checkpoint("PROBE_STOPPED")
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
            _qa_checkpoint("INVESTIGATION_RETURNED")
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
        QTimer.singleShot(280, window.close)
        _qa_checkpoint("EVENT_LOOP_CLOSE_SCHEDULED")
    result = app.exec()
    if options.smoke:
        _qa_checkpoint("EXIT_" + str(result))
    return result


if __name__ == "__main__":
    if "--smoke" in sys.argv or "--research-e2e" in sys.argv or "--deep-smoke" in sys.argv:
        # A windowed PyInstaller failure otherwise opens a blocking error
        # dialog on the headless runner. QA must retain the real traceback and
        # return failure, never certify a hanging binary as a successful build.
        import traceback
        def qa_error(kind, value, tb):
            Path("blackbox-qa-error.txt").write_text(
                "".join(traceback.format_exception(kind, value, tb)), encoding="utf-8")
            app = QApplication.instance()
            if app is not None:
                app.exit(1)
        sys.excepthook = qa_error
        try:
            raise SystemExit(main())
        except Exception:
            qa_error(*sys.exc_info())
            raise SystemExit(1)
    raise SystemExit(main())
