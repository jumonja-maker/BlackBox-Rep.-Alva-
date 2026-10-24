"""Width-aware action layout: keep every control, signal and keyboard target.

Unlike a fixed column grid, narrow RU/EN panels trade height for width. The
parent page remains scrollable. No command is invoked while arranging widgets.
"""
from __future__ import annotations

from PySide6.QtCore import QRect, QSize, Qt
from PySide6.QtWidgets import QLayout, QWidgetItem


class ActionGrid(QLayout):
    def __init__(self, parent=None, *, max_columns: int = 2, spacing: int = 6):
        super().__init__(parent)
        if type(max_columns) is not int or not 1 <= max_columns <= 4:
            raise ValueError("INVALID_ACTION_COLUMNS")
        self._items = []
        self.max_columns = max_columns
        self.setContentsMargins(0, 0, 0, 0)
        self.setSpacing(spacing)

    def addItem(self, item):
        self._items.append(item)
        self.invalidate()

    def addWidget(self, widget):
        self.addChildWidget(widget)
        self.addItem(QWidgetItem(widget))

    def count(self):
        return len(self._items)

    def itemAt(self, index):
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index):
        if not 0 <= index < len(self._items):
            return None
        item = self._items.pop(index)
        self.invalidate()
        return item

    def expandingDirections(self):
        return Qt.Orientation.Horizontal

    def hasHeightForWidth(self):
        return True

    def _visible_items(self):
        return [item for item in self._items if not item.isEmpty()]

    @staticmethod
    def _hint(item):
        return item.sizeHint().expandedTo(item.minimumSize())

    def _columns(self, width, items):
        if not items:
            return 1
        widest = max(self._hint(item).width() for item in items)
        space = max(0, self.spacing())
        return max(1, min(self.max_columns, len(items),
                          (max(0, width) + space) // max(1, widest + space)))

    def heightForWidth(self, width):
        return self._arrange(QRect(0, 0, width, 0), apply=False)

    def minimumSize(self):
        size = QSize(0, 0)
        for item in self._visible_items():
            size = size.expandedTo(self._hint(item))
        left, top, right, bottom = self.getContentsMargins()
        return size + QSize(left + right, top + bottom)

    def sizeHint(self):
        items = self._visible_items()
        if not items:
            return self.minimumSize()
        left, top, right, bottom = self.getContentsMargins()
        columns = min(self.max_columns, len(items))
        width = (max(self._hint(item).width() for item in items) * columns
                 + max(0, self.spacing()) * (columns - 1) + left + right)
        return QSize(width, self.heightForWidth(width))

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self._arrange(rect, apply=True)

    def _arrange(self, rect, *, apply):
        left, top, right, bottom = self.getContentsMargins()
        items = self._visible_items()
        available = max(0, rect.width() - left - right)
        columns = self._columns(available, items)
        space = max(0, self.spacing())
        usable = max(0, available - space * (columns - 1))
        cell, remainder = divmod(usable, columns)
        y = rect.y() + top
        for row_start in range(0, len(items), columns):
            row = items[row_start:row_start + columns]
            height = max(self._hint(item).height() for item in row)
            x = rect.x() + left
            for column, item in enumerate(row):
                width = cell + (1 if column < remainder else 0)
                if apply:
                    item.setGeometry(QRect(x, y, width, height))
                x += width + space
            y += height + space
        return y - rect.y() + bottom - (space if items else 0)
