"""Run BLACK.BOX Universal. --smoke performs a short offscreen startup check."""
from __future__ import annotations

import argparse
import json
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
                from blackbox_rep_alva import alva_sidecar_worker
                from blackbox_universal.platform_connector import (
                    _validate_output, bundled_runtime_available,
                    save_bundled_diagnostics)
                if not bundled_runtime_available():
                    raise RuntimeError("SMOKE_REAL_ALVA_NOT_BUNDLED")
                evidence = save_bundled_diagnostics(folder)
                evidence_path = folder / "evidence-checks.json"
                if (evidence.get("status") != "ok" or
                        evidence.get("declared_checks") != 4 or
                        evidence.get("reviewed_checks") != 4 or
                        not evidence_path.is_file()):
                    raise RuntimeError("SMOKE_REAL_ALVA_NOT_EXECUTED")
                # A successful counter alone is insufficient: the frozen
                # executable must contain the actual 3 scoped operations,
                # 3 trace receipts, and P4 review result.
                saved = _validate_output(json.loads(
                    evidence_path.read_text(encoding="utf-8")))
                extended = saved.get("extended_diagnostics")
                if (saved.get("bridge_schema") != 2 or
                        saved.get("component_count") != 3 or
                        type(extended) is not dict or
                        extended.get("declared_stages") != 4 or
                        extended.get("executed_stages") != 4 or
                        extended.get("accepted_checks") != 4 or
                        extended.get("observed_pipeline_status") != "ok" or
                        len(extended.get("host_trace_checks", ())) != 3):
                    raise RuntimeError("SMOKE_REAL_ALVA_INCOMPLETE")
                # These negative scenarios must also execute in the *frozen*
                # app against the packaged real runtime, not a fake module.
                baseline = {
                    "sample_count": 5, "peak_rss_bytes": 2048,
                    "peak_cpu_percent": 12.0,
                    "observation_error_count": 0,
                    "closed": True, "state": "COMPLETED"}
                rejected = (
                    ({"sample_count": 0, "peak_rss_bytes": None,
                      "peak_cpu_percent": None},
                     "blackbox.evidence.samples", 1, 0),
                    ({"closed": False, "state": "INTERRUPTED"},
                     "blackbox.evidence.lifecycle", 2, 1),
                    ({"peak_rss_bytes": None, "peak_cpu_percent": None},
                     "blackbox.evidence.metrics", 3, 2),
                )
                for changes, first, executed, accepted in rejected:
                    summary = {**baseline, **changes}
                    result = _validate_output(alva_sidecar_worker._run({
                        "schema_version": 1,
                        "operation": "inspect",
                        "summary": summary}))
                    stage = result.get("extended_diagnostics")
                    if (result.get("bridge_schema") != 2 or
                            type(stage) is not dict or
                            stage.get("observed_pipeline_status") != "error" or
                            stage.get("first_unverified_component") != first or
                            stage.get("executed_stages") != executed or
                            stage.get("accepted_checks") != accepted or
                            len(stage.get("host_trace_checks", ())) != 3):
                        raise RuntimeError("SMOKE_REAL_ALVA_NEGATIVE_NOT_REJECTED")
        QTimer.singleShot(280, app.quit)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
