"""Reusable original pixel-inspired widgets for the universal shell."""
from __future__ import annotations

from PySide6.QtCore import QPointF, Qt, QRectF
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from .theme import COLORS


class DesktopMark(QWidget):
    """Small vector monitor glyph: no copied 1990s icons or external assets."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(46, 44)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        painter.setPen(QPen(QColor(COLORS["navy"]), 2))
        painter.setBrush(QColor(COLORS["cream"]))
        painter.drawRect(5, 5, 34, 27)
        painter.setBrush(QColor(COLORS["deep_teal"]))
        painter.drawRect(9, 9, 26, 19)
        painter.setPen(QPen(QColor(COLORS["mint"]), 2))
        painter.drawLine(13, 23, 20, 15)
        painter.drawLine(20, 15, 25, 20)
        painter.setPen(QPen(QColor(COLORS["navy"]), 3))
        painter.drawLine(20, 33, 20, 38)
        painter.drawLine(11, 39, 30, 39)
        painter.end()


class SparkleBorder(QWidget):
    """Subtle bitmap-like wallpaper accents, kept outside interaction zones."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(15)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        pen = QPen(QColor(COLORS["peach"]), 2)
        painter.setPen(pen)
        w = max(10, self.width())
        for ratio, y in ((.08, 6), (.28, 10), (.54, 5), (.77, 9), (.94, 4)):
            x = int(w * ratio)
            painter.drawLine(x - 4, y, x + 4, y)
            painter.drawLine(x, y - 4, x, y + 4)
        painter.end()


class MetricCard(QFrame):
    def __init__(self, label: str, value: str, foot: str, stripe: str, parent=None):
        super().__init__(parent)
        self.setObjectName("metricCard")
        self.setMinimumHeight(112)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 10, 14, 10)
        outer.setSpacing(6)
        self.hdr = QLabel(label.upper())
        self.hdr.setObjectName("cardTitle")
        outer.addWidget(self.hdr)
        self.value = QLabel(value)
        self.value.setObjectName("metricValue")
        outer.addWidget(self.value)
        line = QFrame()
        line.setFixedHeight(4)
        line.setStyleSheet(f"background: {stripe}; border: 0;")
        outer.addWidget(line)
        self.foot = QLabel(foot)
        self.foot.setObjectName("caption")
        outer.addWidget(self.foot)

    def set_readout(self, value: str, detail: str | None = None) -> None:
        self.value.setText(value)
        if detail is not None:
            self.foot.setText(detail)


class WindowPanel(QFrame):
    """Beveled retro subwindow with a title stripe and content region."""

    def __init__(self, heading: str, tag: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        title_row = QFrame()
        title_row.setStyleSheet(
            f"background: {COLORS['lilac']}; "
            f"border: 0; border-bottom: 2px solid {COLORS['navy']};")
        title = QHBoxLayout(title_row)
        title.setContentsMargins(10, 6, 10, 6)
        name = QLabel(heading.upper())
        name.setStyleSheet("font: 800 11px 'Consolas'; color: #302c43;")
        title.addWidget(name)
        title.addStretch()
        if tag:
            label = QLabel(tag)
            label.setStyleSheet("font: 800 10px 'Consolas'; color: #6c586d;")
            title.addWidget(label)
            self.tag_label = label
        root.addWidget(title_row)
        self.body = QWidget()
        self.body.setStyleSheet("background: #fffaf0;")
        self.content = QVBoxLayout(self.body)
        self.content.setContentsMargins(15, 15, 15, 15)
        self.content.setSpacing(11)
        root.addWidget(self.body, 1)


class TrendChart(QWidget):
    """Accessible vector chart rendered from actual sampled values, not art."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._cpu: list[float] = []
        self._ram: list[float] = []
        self.language = "EN"
        self.setMinimumHeight(205)
        self.setAccessibleName("CPU and memory trend graph")

    def set_language(self, language: str) -> None:
        self.language = language
        self.update()

    def set_samples(self, samples: list[dict]) -> None:
        window = samples[-100:]
        self._cpu = [float(x.get("cpu_pct", 0)) for x in window]
        self._ram = [float(x.get("rss_mb", 0)) for x in window]
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        plot = QRectF(46, 17, max(10, self.width() - 64),
                      max(10, self.height() - 53))
        painter.fillRect(self.rect(), QColor("#fffaf0"))
        grid_pen = QPen(QColor("#e7d4cf"), 1)
        painter.setPen(grid_pen)
        for i in range(5):
            y = plot.top() + plot.height() * i / 4
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
        painter.setPen(QColor("#887b89"))
        font = QFont("Consolas", 9)
        painter.setFont(font)
        for i in range(5):
            pct = int(100 - 25 * i)
            painter.drawText(QRectF(0, plot.top() + plot.height() * i / 4 - 7,
                                    40, 15),
                             Qt.AlignmentFlag.AlignRight, f"{pct}%")
        if not self._cpu:
            painter.setPen(QColor("#867c92"))
            painter.drawText(plot, Qt.AlignmentFlag.AlignCenter,
                             ("ОЖИДАНИЕ ИЗМЕРЕНИЙ" if self.language == "RU"
                              else "AWAITING LIVE SAMPLES"))
            painter.end()
            return

        def draw_series(values: list[float], color: str, max_value: float):
            if len(values) == 1:
                painter.setBrush(QColor(color))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawEllipse(QPointF(plot.left(), plot.bottom() -
                                      plot.height() * min(values[0] / max_value, 1)),
                                    4, 4)
                return
            path = QPainterPath()
            for idx, value in enumerate(values):
                x = plot.left() + plot.width() * idx / (len(values) - 1)
                y = plot.bottom() - plot.height() * min(max(value / max_value, 0), 1)
                if idx == 0:
                    path.moveTo(x, y)
                else:
                    path.lineTo(x, y)
            painter.setPen(QPen(QColor(color), 2.8))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(path)

        # RAM is a relative trend, so CPU% and RAM colors remain distinct.
        draw_series(self._cpu, COLORS["coral"], 100)
        peak_ram = max(max(self._ram, default=1), 1.0)
        draw_series(self._ram, COLORS["teal"], peak_ram * 1.08)
        painter.setFont(QFont("Consolas", 9))
        painter.setPen(QColor(COLORS["coral"]))
        painter.drawText(47, self.height() - 9, "━━ CPU (%)")
        painter.setPen(QColor(COLORS["teal"]))
        painter.drawText(151, self.height() - 9,
                         (f"━━ ОЗУ (пик {peak_ram:.0f} МБ)" if self.language == "RU"
                          else f"━━ RAM (relative; peak {peak_ram:.0f} MB)"))
        painter.end()
