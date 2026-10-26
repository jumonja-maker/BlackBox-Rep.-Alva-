"""Automated *offscreen* DPI screenshots, not a physical-Windows acceptance test.

Usage: python tools/qa_dpi_offscreen.py <directory>
Set QT_QPA_PLATFORM=offscreen and QT_SCALE_FACTOR before starting Python.
Only synthetic empty-interface data is captured. No user process metadata.
"""
from __future__ import annotations
import os
import json
from pathlib import Path
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PySide6.QtCore import QPoint
from PySide6.QtWidgets import QApplication, QWidget
from blackbox_universal.decoder_window import DecoderWindow as UniversalWindow
from blackbox_universal.theme import set_retro_theme, font_coverage


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("Specify screenshot output directory")
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication([])
    set_retro_theme(app)
    fonts = font_coverage(app)
    (output / "font-coverage.json").write_text(json.dumps(fonts, ensure_ascii=False, indent=2), encoding="utf-8")
    if not fonts["ok"]:
        raise RuntimeError("DPI_RU_EN_FONT_GLYPHS_MISSING: " + json.dumps(fonts, ensure_ascii=False))
    window = UniversalWindow(allow_update_check=False)
    window._timer.stop()
    window.resize(1330, 850)
    window.show()
    app.processEvents()
    try:
        if window.stack.count() != 6 or len(window.PAGES) != 6:
            raise RuntimeError("DPI_SIX_PAGES_REQUIRED")
        scale = os.environ.get("QT_SCALE_FACTOR", "1")
        header_evidence = []
        for lang in ("EN", "RU"):
            window._set_language(lang)
            app.processEvents()
            body = window.findChild(QWidget, "shellBody")
            workspace_y = body.mapTo(window.centralWidget(), QPoint(0, 0)).y()
            header_evidence.append({"language": lang, "workspace_top_y": workspace_y,
                                    "window_size": [window.width(), window.height()]})
            if workspace_y > 145:
                raise RuntimeError(f"DPI_TOP_CHROME_NOT_COMPACT:{scale}:{lang}:{workspace_y}")
            for page, _ in window.PAGES:
                (output/"progress.json").write_text(json.dumps({"scale":scale,"language":lang,"page":page}),encoding="utf-8")
                window._navigate(page)
                app.processEvents()
                shot = window.grab()
                if shot.isNull() or shot.width() < 500 or shot.height() < 300:
                    raise RuntimeError("DPI_GRAB_FAILED")
                path = output / f"dpi-{scale}-{lang}-{page}.png"
                if not shot.save(str(path), "PNG"):
                    raise RuntimeError("DPI_SCREENSHOT_WRITE_FAILED")
        (output / f"top-chrome-{scale}.json").write_text(
            json.dumps(header_evidence, ensure_ascii=False, indent=2), encoding="utf-8")
        from tools.qa_integrated_layout import capture_integrated_layout
        capture_integrated_layout(window, app, output, scale)
        print(f"DPI offscreen capture PASS: scale={scale}, 12 page and 8 expanded snapshots")
        return 0
    finally:
        window.close()


if __name__ == "__main__":
    raise SystemExit(main())
