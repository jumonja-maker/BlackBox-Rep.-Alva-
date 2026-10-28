"""GitHub-hosted offscreen Overview layout QA, not physical Windows UAC QA.

Run once per QT_SCALE_FACTOR. Synthetic table values are visibly labelled and
never invoke the diagnostic backend or substitute for native acceptance.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PySide6.QtCore import QPoint
from PySide6.QtWidgets import QApplication, QPushButton

from blackbox_universal.decoder_window import DecoderWindow
from blackbox_universal.theme import set_retro_theme


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication([])
    set_retro_theme(app)
    window = DecoderWindow(allow_update_check=False)
    window._timer.stop()
    window.show()
    app.processEvents()
    panel = window.deep_inspector_panel
    scale = os.environ.get("QT_SCALE_FACTOR", "1")
    evidence = {"status": "RUNNING", "source": "SYNTHETIC_UI_LAYOUT_ONLY", "scale": scale,
                "secure_desktop": "NOT_TESTED", "native_actions": "NOT_EXECUTED", "views": []}
    try:
        if window.stack.count() != 6 or len(window.PAGES) != 6:
            raise AssertionError("EXISTING_SIX_PRIMARY_PAGES_CHANGED")
        if not panel.isHidden() or panel.bridge.has_session:
            raise AssertionError("DEEP_INSPECTION_NOT_LAZY_AND_COLLAPSED")
        for language in ("RU", "EN"):
            window._set_language(language)
            window._navigate("dashboard")
            window.deep_inspector_toggle.setChecked(True)
            for width, height in ((1330, 850), (1020, 690)):
                window.resize(width, height)
                app.processEvents()
                for section in range(panel.section.count()):
                    panel.section.setCurrentIndex(section)
                    key = panel.section.currentData()
                    panel._request_section = key
                    panel._receive({"operation": "layout_fixture", "status": "INCOMPLETE_EVIDENCE",
                                    "data": {"rows": [{"source": "SYNTHETIC_UI_LAYOUT_ONLY", "pid": 123,
                                                       "note": "Макет интерфейса / UI layout fixture"}]},
                                    "limitations": ["SYNTHETIC_UI_LAYOUT_ONLY — NO NATIVE RESULT"]})
                    app.processEvents()
                    visible = [button for button in panel.findChildren(QPushButton)
                               if button.isVisibleTo(panel)]
                    checks = []
                    for button in visible:
                        start = button.mapTo(panel, QPoint(0, 0))
                        if start.x() < -1 or start.x() + button.width() > panel.width() + 1:
                            raise AssertionError("DEEP_ACTION_OUTSIDE_PANEL: " + button.objectName())
                        if button.width() < button.minimumSizeHint().width():
                            raise AssertionError("DEEP_ACTION_TEXT_CLIPPED: " + button.objectName())
                        checks.append({"control": button.objectName(), "text": button.text(),
                                       "width": button.width(), "minimum_hint": button.minimumSizeHint().width()})
                    image = panel.grab()
                    filename = f"deep-{scale}-{language}-{width}-{key}.png"
                    if image.isNull() or not image.save(str(options.output / filename), "PNG"):
                        raise AssertionError("DEEP_SCREENSHOT_FAILED")
                    evidence["views"].append({"language": language, "window_width": width,
                                              "section": key, "screenshot": filename,
                                              "visible_controls": checks})
                    if panel.bridge.has_session:
                        raise AssertionError("LAYOUT_STARTED_DIAGNOSTIC_HELPER")
        evidence["status"] = "PASS"
        evidence["new_sections"] = panel.section.count()
        evidence["primary_pages"] = window.stack.count()
        print(f"Deep Overview layout PASS: scale={scale}, {len(evidence['views'])} views; native operations not executed")
        return 0
    except Exception as exc:
        evidence["status"] = "FAIL"
        evidence["error"] = str(exc)
        raise
    finally:
        (options.output / f"deep-overview-{scale}.json").write_text(
            json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
        window.close()
        app.processEvents()


if __name__ == "__main__":
    raise SystemExit(main())
