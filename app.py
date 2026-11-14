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

if __name__ == '__main__' and '--qa-sdk-prepare' in sys.argv:
    from tools.qa_sdk_clients import prepare_main
    try:
        raise SystemExit(prepare_main(sys.argv[1:]))
    except Exception:
        import traceback
        Path('blackbox-sdk-qa-error.txt').write_text(traceback.format_exc(), encoding='utf-8')
        raise SystemExit(1)

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

_CHAIN_QA_GUARD = None
if __name__ == "__main__" and "--chain-e2e" in sys.argv:
    from blackbox_core.chain_qa_guard import ChainQaFailureGuard
    _CHAIN_QA_GUARD = ChainQaFailureGuard()
    _CHAIN_QA_GUARD.install()

try:
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication

    from blackbox_universal.monitor import ReadOnlyProbe
    from blackbox_universal.theme import set_retro_theme, font_coverage
    from blackbox_universal.decoder_window import DecoderWindow as UniversalWindow
except Exception:
    if _CHAIN_QA_GUARD is None:
        raise
    _CHAIN_QA_GUARD.record(*sys.exc_info())
    raise SystemExit(1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BLACK.BOX Universal retro desktop")
    parser.add_argument("--smoke", action="store_true",
                        help="Run Qt offscreen and exit automatically (QA only)")
    parser.add_argument("--attach-pid", type=int, help="Select an existing process; recording remains explicit")
    parser.add_argument("--research-e2e", type=Path, help="Run isolated end-to-end research QA into an explicit directory")
    parser.add_argument("--deep-smoke",action="store_true",help="Run real Qt action/thread/incident/export QA")
    parser.add_argument("--r10-e2e", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--r10-probe", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--expert-e2e", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--wave02-e2e", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--chain-e2e", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--chain-evidence", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--chain-gui-only", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--chain-standard-token", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--wave02-evidence", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--wave02-container", choices=("r20", "r30", "r40", "full"), help=argparse.SUPPRESS)
    parser.add_argument("--qa-output",type=Path,help="Explicit QA artifact directory")
    parser.add_argument("--qa-fixture",choices=("cpu","ui","waitchain"),help=argparse.SUPPRESS)
    parser.add_argument("--qa-commit-sha",default="UNKNOWN",help=argparse.SUPPRESS)
    options = parser.parse_args(argv)
    if options.chain_e2e and options.chain_evidence is None:
        parser.error("--chain-e2e requires --chain-evidence")
    if options.chain_gui_only and not options.chain_e2e:
        parser.error("--chain-gui-only requires --chain-e2e")
    if options.chain_e2e and not options.chain_gui_only:
        from blackbox_core.chain_qa import run_embedded
        code = run_embedded(options.chain_e2e, options.chain_evidence, options.qa_commit_sha,
                            standard_token=options.chain_standard_token)
        if code:
            return code
    elif options.chain_e2e:
        from blackbox_core.chain_qa import save, source_proof
        options.chain_e2e.mkdir(parents=True, exist_ok=False)
        save(options.chain_e2e / "result.json", {"status": "PASS", "scope": "GUI_ONLY",
            "source_sha": options.qa_commit_sha, "source_identity": source_proof(options.qa_commit_sha),
            "frozen": bool(getattr(sys, "frozen", False))})
    if options.deep_smoke and options.qa_output is None:
        parser.error("--deep-smoke requires --qa-output")
    if options.qa_fixture:
        if options.qa_output is None:
            parser.error("--qa-fixture requires --qa-output")
        from blackbox_universal.qa_fixtures import run_fixture
        return run_fixture(options.qa_fixture,options.qa_output)
    if options.r10_e2e and options.r10_probe is None:
        parser.error("--r10-e2e requires --r10-probe")
    if options.wave02_e2e and (options.wave02_evidence is None or options.wave02_container is None):
        parser.error("--wave02-e2e requires --wave02-evidence and --wave02-container")
    if options.smoke or options.deep_smoke or options.r10_e2e or options.wave02_e2e or options.chain_e2e or options.expert_e2e:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        _qa_checkpoint("QT_START")
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("BLACK.BOX Universal")
    app.setOrganizationName("BlackBox")
    set_retro_theme(app)
    window = UniversalWindow(isolated=True,
        output_root=(options.research_e2e or options.r10_e2e or options.wave02_e2e or options.chain_e2e or options.expert_e2e or options.qa_output) / "sessions" if (options.research_e2e or options.deep_smoke or options.r10_e2e or options.wave02_e2e or options.chain_e2e or options.expert_e2e) else None,
        allow_update_check=not (options.smoke or options.research_e2e or options.deep_smoke or options.r10_e2e or options.wave02_e2e or options.chain_e2e or options.expert_e2e))
    # Native Windows starts maximized, while retaining the normal window frame,
    # minimize/restore and user resizing (not exclusive fullscreen mode).
    window.showMaximized()
    if options.expert_e2e:
        from tools.qa_expert_workflow import run_gui
        return run_gui(app, window, options.expert_e2e, options.qa_commit_sha)
    if options.chain_e2e:
        from blackbox_universal.chain_qa import run_chain_gui
        try:
            proof = run_chain_gui(app, window, options.chain_e2e / "gui", options.chain_evidence,
                                  options.qa_commit_sha, failure_guard=_CHAIN_QA_GUARD)
        finally:
            window.close()
            app.processEvents()
        # A Qt callback can fail during the last close, after the harness has
        # returned. Evaluate acceptance only after that real event boundary.
        if _CHAIN_QA_GUARD is not None:
            _CHAIN_QA_GUARD.apply(proof)
            if _CHAIN_QA_GUARD.failed:
                from blackbox_core.chain_qa import save
                save(options.chain_e2e / "gui" / "result.json", proof)
        return 0 if proof.get("status") == "PASS" else 1
    if options.wave02_e2e:
        from blackbox_universal.wave02_qa import run_wave02_e2e
        return run_wave02_e2e(app, window, options.wave02_e2e, options.wave02_evidence,
                            options.wave02_container, options.qa_commit_sha)
    if options.r10_e2e:
        from blackbox_universal.r10_qa import run_r10_e2e
        return run_r10_e2e(app, window, options.r10_e2e, options.r10_probe, options.qa_commit_sha)
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
        expected = ("dashboard", "processes", "events", "reports", "settings", "decoder")
        if tuple(key for key, _ in window.PAGES) != expected:
            raise RuntimeError("SMOKE_GUI_PAGES_INCORRECT")
        if window.stack.count() != 6:
            raise RuntimeError("SMOKE_GUI_PAGE_COUNT_INCORRECT")
        window._navigate("decoder")
        if not hasattr(window, "decoder_panel"):
            raise RuntimeError("SMOKE_DECODER_PAGE_MISSING")
        if not hasattr(window, "deep_inspector_panel"):
            raise RuntimeError("SMOKE_DEEP_INSPECTION_PANEL_MISSING")
        if getattr(sys, "frozen", False):
            import json
            import subprocess
            from blackbox_core.decoder_service import helper_path
            check = subprocess.run([str(helper_path()), "--version"], capture_output=True,
                text=True, timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if check.returncode or json.loads(check.stdout).get("protocol") != "blackbox.trace-event/1":
                raise RuntimeError("SMOKE_PACKAGED_DECODER_FAILED")
            diagnostic = Path(sys.executable).parent / "diagnostic" / "BLACK.BOX-Diagnostic.exe"
            if not diagnostic.is_file():
                raise RuntimeError("SMOKE_DIAGNOSTIC_HELPER_MISSING")
        window._navigate("dashboard")
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
    if _CHAIN_QA_GUARD is not None:
        try:
            code = main()
        except Exception:
            _CHAIN_QA_GUARD.record(*sys.exc_info())
            code = 1
        raise SystemExit(_CHAIN_QA_GUARD.exit_code(code))
    if any(flag in sys.argv for flag in ("--smoke", "--research-e2e", "--deep-smoke", "--r10-e2e", "--expert-e2e")):
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
