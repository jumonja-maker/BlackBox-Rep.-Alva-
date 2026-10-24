"""Small original vector chrome icons; no OS symbol font is required."""
from __future__ import annotations
from PySide6.QtCore import Qt,QPointF,QSize,QRect
from PySide6.QtGui import QIcon,QIconEngine,QPainter,QPen,QColor,QPolygonF,QPixmap
from PySide6.QtWidgets import QPushButton

SYMBOLS=frozenset('↻⌂✉▦▣▶■⚑◈≍◫□×')

class ChromeIcon(QIconEngine):
    def __init__(self,symbol):super().__init__();self.symbol=symbol
    def clone(self):return ChromeIcon(self.symbol)
    def actualSize(self,size,mode,state):return size
    def pixmap(self,size,mode,state):
        result=QPixmap(size);result.fill(Qt.GlobalColor.transparent)
        painter=QPainter(result)
        self.paint(painter,QRect(0,0,size.width(),size.height()),mode,state)
        painter.end();return result
    def paint(self,painter,rect,mode,state):
        painter.save();painter.translate(rect.x(),rect.y());painter.scale(rect.width()/16,rect.height()/16)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        color=QColor('#96929d' if mode==QIcon.Mode.Disabled else '#302c43')
        painter.setPen(QPen(color,1.5));painter.setBrush(Qt.BrushStyle.NoBrush)
        s=self.symbol
        if s=='▶':
            painter.setBrush(color);painter.drawPolygon(QPolygonF([QPointF(4,2),QPointF(13,8),QPointF(4,14)]))
        elif s=='■':painter.fillRect(3,3,10,10,color)
        elif s=='↻':
            painter.drawArc(2,2,12,12,40*16,290*16)
            painter.drawLine(13,1,13,6);painter.drawLine(9,5,13,6)
        elif s=='⚑':
            painter.drawLine(3,1,3,15);painter.drawRect(3,2,10,6)
        elif s=='⌂':
            painter.drawPolyline(QPolygonF([QPointF(1,8),QPointF(8,2),QPointF(15,8)]));painter.drawRect(4,8,8,6)
        elif s=='✉':
            painter.drawRect(1,3,14,10);painter.drawLine(1,3,8,9);painter.drawLine(8,9,15,3)
        elif s=='◈':
            painter.drawPolygon(QPolygonF([QPointF(8,1),QPointF(15,8),QPointF(8,15),QPointF(1,8)]));painter.drawEllipse(6,6,4,4)
        elif s=='≍':
            painter.drawLine(1,5,15,5);painter.drawLine(1,11,15,11);painter.drawLine(12,2,15,5);painter.drawLine(1,11,4,14)
        elif s=='×':painter.drawLine(3,3,13,13);painter.drawLine(3,13,13,3)
        else:
            painter.drawRect(2,2,12,12)
            if s=='▣':painter.drawRect(5,5,6,6)
            elif s=='◫':painter.drawLine(8,2,8,14)
            elif s=='▦':painter.drawLine(2,8,14,8);painter.drawLine(8,2,8,14)
        painter.restore()

def icon(symbol):return QIcon(ChromeIcon(symbol))

class ChromeButton(QPushButton):
    def __init__(self,text='',parent=None):
        super().__init__(parent);self.setProperty('bb_english',text);self.setText(text)
        self.setIconSize(QSize(14,14))
    def setText(self,text):
        if self.menu() is not None:
            # QMenu already supplies its native indicator. Retain bb_english
            # as the original translation key, not a second visible arrow.
            text=str(text).rstrip().removesuffix('▾').rstrip()
        stripped=str(text).lstrip()
        if stripped and stripped[0] in SYMBOLS:
            self.setIcon(icon(stripped[0]));text=stripped[1:].lstrip()
        else:self.setIcon(QIcon())
        super().setText(text)
    def setMenu(self,menu):
        super().setMenu(menu)
        if menu is not None:
            # Do not re-run icon extraction on already displayed text: Start
            # and other icon-bearing menus must retain their original icon.
            super().setText(self.text().rstrip().removesuffix('▾').rstrip())
        self.updateGeometry()
    def sizeHint(self):
        size=super().sizeHint()
        if self.menu() is not None:
            # Reserve CSS padding/borders plus a separate native arrow area.
            # A non-shrinkable menu hint avoids clipped leading RU glyphs.
            label_width=self.fontMetrics().horizontalAdvance(self.text())
            icon_width=0 if self.icon().isNull() else self.iconSize().width()+6
            size.setWidth(max(size.width()+20,label_width+icon_width+60))
        return size
    def minimumSizeHint(self):
        return self.sizeHint() if self.menu() is not None else super().minimumSizeHint()
