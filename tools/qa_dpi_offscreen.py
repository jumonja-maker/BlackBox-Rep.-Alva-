"""Automated *offscreen* DPI screenshots, not a physical-Windows acceptance test.

Usage: python tools/qa_dpi_offscreen.py <directory>
Set QT_QPA_PLATFORM=offscreen and QT_SCALE_FACTOR before starting Python.
Only synthetic empty-interface data is captured. No user process metadata.
"""
from __future__ import annotations
import os
from pathlib import Path
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PySide6.QtWidgets import QApplication
from blackbox_universal.window import UniversalWindow
from blackbox_universal.theme import set_retro_theme


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("Specify screenshot output directory")
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication([])
    set_retro_theme(app)
    window = UniversalWindow()
    window._timer.stop()
    window.resize(1330, 850)
    window.show()
    app.processEvents()
    try:
        if window.stack.count() != 5 or len(window.PAGES) != 5:
            raise RuntimeError("DPI_FIVE_PAGES_REQUIRED")
        scale = os.environ.get("QT_SCALE_FACTOR", "1")
        for lang in ("EN", "RU"):
            window._set_language(lang)
            for page, _ in window.PAGES:
                window._navigate(page)
                app.processEvents()
                shot = window.grab()
                if shot.isNull() or shot.width() < 500 or shot.height() < 300:
                    raise RuntimeError("DPI_GRAB_FAILED")
                path = output / f"dpi-{scale}-{lang}-{page}.png"
                if not shot.save(str(path), "PNG"):
                    raise RuntimeError("DPI_SCREENSHOT_WRITE_FAILED")
        print(f"DPI offscreen capture PASS: scale={scale}, 10 snapshots")
        return 0
    finally:
        window.close()


if __name__ == "__main__":
    raise SystemExit(main())
