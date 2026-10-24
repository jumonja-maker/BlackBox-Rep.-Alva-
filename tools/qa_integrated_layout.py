"""Expanded PR17+18 controls at minimum app width; no diagnostic commands.

Checks ordinary Qt geometry and records empty-interface screenshots. This
is offscreen QA, not evidence of real-display accessibility or native capture.
"""
from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import QPoint, QRect
from PySide6.QtWidgets import QScrollArea


def _settle(app):
    # Geometry delivery only. Do not call sample/Start or process external IO.
    for _ in range(3):
        app.processEvents()


def _save(window, output, name):
    image = window.grab()
    if image.isNull() or not image.save(str(output / name), "PNG"):
        raise RuntimeError("INTEGRATED_LAYOUT_SCREENSHOT_FAILED")


def capture_integrated_layout(window, app, output: Path, scale: str) -> None:
    """Preserve all controls, scroll to them and check horizontal reachability."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    original = {
        "research": list(window.research_panel.buttons),
        "markers": [button for _, button in window.marker_panel.buttons],
    }
    if len(original["research"]) != 17 or len(original["markers"]) != 4:
        raise RuntimeError("INTEGRATED_ACTION_INVENTORY_CHANGED")
    result = {"status": "RUNNING", "scale": scale,
              "scope": "EMPTY_OFFSCREEN_EXPANDED_ACTION_GEOMETRY",
              "five_pages": window.stack.count() == 5,
              "requested_window_size": [1020, 690], "cases": []}
    failures = []
    window.resize(1020, 690)
    window.research_toggle.setChecked(True)
    try:
        for language in ("EN", "RU"):
            window._set_language(language)
            window._navigate("reports")
            _settle(app)
            scroll = window.stack.currentWidget()
            if not isinstance(scroll, QScrollArea):
                raise RuntimeError("INTEGRATED_REPORT_SCROLL_MISSING")
            for name, panel in (("research", window.research_panel),
                                ("markers", window.marker_panel)):
                buttons = (list(panel.buttons) if name == "research" else
                           [button for _, button in panel.buttons])
                if buttons != original[name]:
                    raise RuntimeError("INTEGRATED_ACTION_WIDGET_REPLACED")
                case = {"language": language, "panel": name,
                        "actual_window_size": [window.width(), window.height()],
                        "panel_size": [panel.width(), panel.height()],
                        "viewport_size": [scroll.viewport().width(),
                                          scroll.viewport().height()],
                        "buttons": [], "overlaps": []}
                result["cases"].append(case)
                for index, button in enumerate(buttons):
                    rect = button.geometry()
                    point = button.mapTo(scroll.viewport(), QPoint(0, 0))
                    fits = (point.x() >= 0 and
                            point.x() + button.width() <= scroll.viewport().width())
                    row = {"index": index, "text": button.text(),
                           "geometry": [rect.x(), rect.y(), rect.width(), rect.height()],
                           "contained": panel.rect().contains(rect),
                           "hidden": button.isHidden(), "fits_viewport_width": fits,
                           "label_fits": button.width() >= button.sizeHint().width()}
                    case["buttons"].append(row)
                    if not row["contained"] or row["hidden"] or not fits or not row["label_fits"]:
                        failures.append([language, name, index, "CLIPPED_OR_HIDDEN"])
                    for other_index in range(index + 1, len(buttons)):
                        if rect.intersects(buttons[other_index].geometry()):
                            case["overlaps"].append([index, other_index])
                            failures.append([language, name, index, "OVERLAP"])
                # Screenshots are genuine full-window grabs after scrolling,
                # rather than manual geometry assignments used by unit tests.
                for index in sorted({0, len(buttons) - 1}):
                    button = buttons[index]
                    scroll.ensureWidgetVisible(button, 12, 24)
                    _settle(app)
                    location = button.mapTo(scroll.viewport(), QPoint(0, 0))
                    visible_rect = QRect(location, button.size())
                    if not scroll.viewport().rect().contains(visible_rect):
                        failures.append([language, name, index, "UNREACHABLE_AFTER_SCROLL"])
                    _save(window, output,
                          f"expanded-{scale}-{language}-{name}-{index}.png")
        if not result["five_pages"]:
            failures.append(["PAGES", window.stack.count()])
        result["failures"] = failures
        result["status"] = "PASS" if not failures else "FAIL"
    finally:
        (output / f"expanded-layout-{scale}.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    if failures:
        raise RuntimeError("INTEGRATED_LAYOUT_CHECK_FAILED: " + json.dumps(failures))
