"""Original BLACK.BOX Universal visual system.

Inspired by early Windows desktop ergonomics and warm 1990s pixel art.
No third-party screenshots, icon packs, fonts or proprietary artwork bundled.
"""
from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtGui import QColor, QFont, QFontInfo, QFontDatabase, QPalette, QRawFont, QTextLayout
from PySide6.QtWidgets import QApplication, QProxyStyle, QStyle

COLORS = {
    "teal": "#078b84",
    "deep_teal": "#056c6d",
    "navy": "#302c43",
    "coral": "#ec725d",
    "peach": "#ffb475",
    "cream": "#fff7e4",
    "paper": "#f7e3c9",
    "beige": "#ddd0b5",
    "gray": "#c8c6bf",
    "lilac": "#cbb3d1",
    "muted": "#77718a",
    "white": "#ffffff",
    "mint": "#83d5b3",
    "alert": "#b84e50",
    "selection": "#ffddaa",
}

STYLE = """
QMainWindow, QWidget#desktop {
    background: #078b84;
    color: #302c43;
    font-family: "Segoe UI", "Tahoma", sans-serif;
}
QWidget { font-size: 12px; }
QFrame#shell {
    background: #fff7e4;
    border: 2px solid #302c43;
}
QFrame#topChrome {
    background: #ec725d;
    border: 0;
    border-bottom: 2px solid #302c43;
}
QFrame#sideNav {
    background: #ddd0b5;
    border: 0;
    border-right: 2px solid #302c43;
}
QFrame#toolbar {
    background: #f7e3c9;
    border: 0;
    border-bottom: 1px solid #a99c9b;
}
QFrame#card, QFrame#paperCard {
    background: #fffaf0;
    border: 2px solid #302c43;
}
QFrame#metricCard {
    background: #fff7e4;
    border: 2px solid #302c43;
}
QFrame#inset {
    background: #f3e8d6;
    border: 2px solid #8e8290;
}
QFrame#notice {
    background: #ffebc0;
    border: 1px solid #b69a71;
}
QLabel#chromeTitle { color: #fffaf0; font-size: 14px; font-weight: 900; letter-spacing: 1px; }
QLabel#eyebrow { color: #796c88; font-size: 10px; font-weight: 800; letter-spacing: 2px; }
QLabel#hero { color: #302c43; font-size: 27px; font-weight: 900; }
QLabel#h2 { color: #302c43; font-size: 16px; font-weight: 900; }
QLabel#caption { color: #77718a; font-size: 11px; }
QLabel#cardTitle { color: #70677f; font-size: 11px; font-weight: 800; }
QLabel#metricValue { color: #302c43; font-size: 25px; font-weight: 900; }
QLabel#logo { color: #fff7e4; font-size: 17px; font-weight: 900; letter-spacing: 1px; }
QLabel#signal { color: #046e64; font-weight: 800; }
QPushButton {
    min-height: 29px;
    padding: 4px 12px;
    background: #ddd0b5;
    color: #302c43;
    border-top: 2px solid #fffdf0;
    border-left: 2px solid #fffdf0;
    border-right: 2px solid #62576b;
    border-bottom: 2px solid #62576b;
    font-size: 12px;
    font-weight: 800;
}
QPushButton:hover { background: #ffe4bf; }
QPushButton:pressed {
    background: #c4b5aa;
    border-top: 2px solid #62576b;
    border-left: 2px solid #62576b;
    border-right: 2px solid #fffdf0;
    border-bottom: 2px solid #fffdf0;
}
QPushButton:disabled { color: #96929d; background: #ded8ce; }
QPushButton#primary {
    background: #ec725d;
    color: #281f39;
}
QPushButton#primary:hover { background: #ff9476; }
QPushButton#accent { background: #83d5b3; }
QPushButton#primary:disabled, QPushButton#accent:disabled {
    color: #62576b;
    background: #ded8ce;
}
QPushButton#nav {
    min-height: 42px;
    padding: 6px 12px;
    text-align: left;
    background: transparent;
    border: 0;
    font-family: "Consolas", monospace;
    font-size: 11px;
}
QPushButton#nav:hover { background: #f6e9d5; }
QPushButton#nav[active="true"] {
    background: #fff7e4;
    border-left: 5px solid #ec725d;
}
QPushButton#smallLink {
    padding: 2px 5px;
    min-height: 20px;
    max-height: 24px;
    font-size: 10px;
    font-weight: 900;
    font-family: "Consolas", monospace;
    color: #302c43;
    background: #f7e3c9;
    border-top: 2px solid #fffaf0;
    border-left: 2px solid #fffaf0;
    border-bottom: 2px solid #796c88;
    border-right: 2px solid #796c88;
}
QPushButton#smallLink:hover { background: #ffcb9a; }
QPushButton#smallLink[active="true"] {
    background: #83d5b3;
    border-bottom: 3px solid #056c6d;
}
QPushButton#update {
    min-height: 23px;
    padding: 2px 10px;
    font-family: "Consolas", monospace;
    font-weight: 900;
    font-size: 11px;
    background: #e8d6bc;
    color: #302c43;
}
QPushButton#update[available="true"] {
    background: #83d5b3;
    color: #123e36;
    border-top: 2px solid #dcfbe9;
    border-left: 2px solid #dcfbe9;
    border-right: 2px solid #056c6d;
    border-bottom: 2px solid #056c6d;
}
QPushButton#update[available="true"]:hover { background: #a6f0c6; }
QPushButton#toolbarMenu {
    min-height: 23px;
    padding: 2px 10px;
    font-size: 11px;
}
QPushButton#windowControl {
    min-width: 24px;
    max-width: 24px;
    min-height: 22px;
    max-height: 22px;
    padding: 0;
    background: #f7e3c9;
    font-size: 12px;
}
QComboBox {
    min-height: 29px;
    padding: 4px 8px;
    background: #fffaf0;
    color: #302c43;
    border: 2px solid #8a7f90;
}
QComboBox:hover, QComboBox:focus { border-color: #056c6d; }
QComboBox:disabled { background: #ded8ce; color: #62576b; }
QComboBox QAbstractItemView {
    background: #fffaf0;
    color: #302c43;
    border: 2px solid #796e87;
    selection-background-color: #ffddaa;
    selection-color: #302c43;
}
QComboBox QAbstractItemView::item {
    min-height: 24px;
    padding: 4px 8px;
}
QComboBox QAbstractItemView::item:selected,
QComboBox QAbstractItemView::item:hover {
    background: #ffddaa;
    color: #302c43;
}
QMenu {
    background: #fffaf0;
    color: #302c43;
    border: 1px solid #796e87;
}
QMenu::item:selected { background: #ffddaa; color: #302c43; }
QMenu::item:disabled { color: #77718a; }
QLineEdit {
    min-height: 29px;
    background: #fffdf4;
    padding: 4px 8px;
    border-top: 2px solid #776d82;
    border-left: 2px solid #776d82;
    border-right: 2px solid #fffaf0;
    border-bottom: 2px solid #fffaf0;
    color: #302c43;
    selection-background-color: #078b84;
    selection-color: #ffffff;
}
QTableWidget, QTreeWidget {
    background: #fffaf0;
    color: #302c43;
    gridline-color: #e2cdbf;
    border: 2px solid #796e87;
    selection-background-color: #ffddaa;
    selection-color: #302c43;
    alternate-background-color: #faf0df;
}
QHeaderView::section {
    background: #d7c5ca;
    color: #302c43;
    border: 1px solid #8a7f90;
    padding: 7px;
    font-family: "Consolas", monospace;
    font-weight: 800;
}
QTableCornerButton::section { background: #d7c5ca; }
QScrollBar:vertical { width: 12px; background: #f6e7d5; }
QScrollBar::handle:vertical { background: #aa98ad; min-height: 24px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QTextEdit, QPlainTextEdit {
    background: #fffaf0;
    color: #302c43;
    border: 2px solid #8a7f90;
    padding: 8px;
    font-family: "Consolas", monospace;
    font-size: 11px;
}
QSplitter::handle { background: #ddd0b5; }
QToolTip {
    background: #fff7e4;
    color: #302c43;
    border: 1px solid #302c43;
}
"""


def _load_windows_offscreen_fonts(app: QApplication) -> None:
    """Qt's basic offscreen font database does not enumerate Windows fonts.

    Register only installed OS fonts in this process, with no download, font
    bundling or system installation. Native Windows uses its normal database.
    """
    if os.name != "nt" or app.platformName() != "offscreen":
        return
    if app.property("blackbox_offscreen_fonts_loaded"):
        return
    folder = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Fonts"
    for name in ("segoeui.ttf", "segoeuib.ttf", "consola.ttf", "consolab.ttf", "seguisym.ttf"):
        path = folder / name
        if path.is_file():
            QFontDatabase.addApplicationFont(str(path))
    app.setProperty("blackbox_offscreen_fonts_loaded", True)


def font_coverage(app: QApplication) -> dict:
    """QA evidence from the actual resolved font, not screenshot dimensions."""
    cyrillic = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
    alphabet = "BLACK.BOX 0123456789 " + cyrillic + cyrillic.lower()
    rows = []
    for family in ("Segoe UI", "Consolas"):
        for weight in (QFont.Weight.Normal, QFont.Weight.Bold):
            font = QFont(family, 10)
            font.setWeight(weight)
            raw = QRawFont.fromFont(font)
            # Use the Unicode-codepoint overload. PySide's narrow-char overload
            # rejects Cyrillic even when the font has its real glyphs.
            missing = sorted({c for c in alphabet if not raw.supportsCharacter(ord(c))}) if raw.isValid() else sorted(set(alphabet))
            rows.append({"requested_family": family, "weight": int(weight),
                         "resolved_family": QFontInfo(font).family(),
                         "valid": raw.isValid(), "missing_characters": missing})
    # Check shaped fallback glyphs too: the alphabet alone cannot detect
    # missing icons. These are the actual chrome symbols used by the shell.
    symbols="▾●"  # all other chrome icons are original vectors, not glyphs
    symbol_rows=[]
    for symbol in symbols:
        layout=QTextLayout(symbol,app.font());layout.beginLayout()
        line=layout.createLine();line.setLineWidth(100);layout.endLayout()
        runs=layout.glyphRuns()
        valid=bool(runs) and all(run.rawFont().isValid() and all(run.glyphIndexes()) for run in runs)
        symbol_rows.append({"text":symbol,"valid":valid,"families":[run.rawFont().familyName() for run in runs]})
    alphabet_ok=all(r["valid"] and not r["missing_characters"] for r in rows)
    symbols_ok=all(r["valid"] for r in symbol_rows)
    return {"platform": app.platformName(), "ok":alphabet_ok and (symbols_ok or os.name!="nt"),
            "alphabet_ok":alphabet_ok,"symbols_ok":symbols_ok,"fonts":rows,"symbols":symbol_rows}


class RetroStyle(QProxyStyle):
    """Use list rendering instead of menu rendering for styled combo popups."""
    def styleHint(self, hint, option=None, widget=None, returnData=None):
        if hint == QStyle.StyleHint.SH_ComboBox_Popup:
            return 0
        if hint == QStyle.StyleHint.SH_ComboBox_ListMouseTracking:
            return 1
        return super().styleHint(hint, option, widget, returnData)


def set_retro_theme(app: QApplication) -> None:
    _load_windows_offscreen_fonts(app)
    app.setStyle(RetroStyle("Fusion"))
    app.setFont(QFont("Segoe UI", 10))
    palette = app.palette()
    palette.setColor(QPalette.ColorRole.Window, QColor(COLORS["cream"]))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(COLORS["navy"]))
    palette.setColor(QPalette.ColorRole.Base, QColor(COLORS["white"]))
    palette.setColor(QPalette.ColorRole.Text, QColor(COLORS["navy"]))
    palette.setColor(QPalette.ColorRole.Button, QColor(COLORS["beige"]))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(COLORS["navy"]))
    # Set both roles for every group. A popup can use the inactive group;
    # inherited system HighlightedText must not become white on cream.
    palette.setColor(QPalette.ColorRole.Highlight, QColor(COLORS["selection"]))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(COLORS["navy"]))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(COLORS["muted"]))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(COLORS["muted"]))
    app.setPalette(palette)
    app.setStyleSheet(STYLE)
