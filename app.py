"""Run BLACK.BOX Universal. --smoke performs a short offscreen startup check."""
from __future__ import annotations

import argparse
import os
import sys

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from blackbox_universal.theme import set_retro_theme
from blackbox_universal.window import UniversalWindow


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BLACK.BOX Universal retro desktop")
    parser.add_argument("--smoke", action="store_true",
                        help="Run Qt offscreen and exit automatically (QA only)")
    options = parser.parse_args(argv)
    if options.smoke:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("BLACK.BOX Universal")
    app.setOrganizationName("BlackBox")
    set_retro_theme(app)
    window = UniversalWindow()
    window.show()
    if options.smoke:
        QTimer.singleShot(280, app.quit)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
