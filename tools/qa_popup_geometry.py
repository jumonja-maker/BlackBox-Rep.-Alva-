"""Pure geometry for genuine pointer input in popup QA (logical Qt pixels).

A scaled hosted desktop may expose only part of a wide popup. Never move the
OS cursor to a row's off-screen centre, and never fabricate a hover event to
hide that failure. Choose a reachable interior point or fail explicitly.
"""
from __future__ import annotations

from collections.abc import Iterable

Rect = tuple[int, int, int, int]


def visible_row_point(row: Rect, screens: Iterable[Rect], *, margin: int = 3) -> tuple[int, int]:
    """Return a point within the row AND one real available screen rectangle.

    Rectangles are (x, y, width, height), in device-independent coordinates.
    Do not use the bounding union of monitors: it can include desktop gaps.
    No DPI multiplication is appropriate for these Qt geometry values.
    """
    if isinstance(margin, bool) or not isinstance(margin, int) or margin < 1:
        raise ValueError('POPUP_INVALID_POINTER_MARGIN')
    x, y, width, height = row
    if width <= 2 * margin or height <= 2 * margin:
        raise AssertionError('POPUP_ROW_TOO_SMALL_FOR_POINTER')
    areas = []
    for sx, sy, sw, sh in screens:
        left, top = max(x, sx) + margin, max(y, sy) + margin
        right, bottom = min(x + width, sx + sw) - margin, min(y + height, sy + sh) - margin
        if left < right and top < bottom:
            areas.append((left, top, right, bottom))
    if not areas:
        raise AssertionError('POPUP_ROW_OUTSIDE_AVAILABLE_SCREENS')
    left, top, right, bottom = max(areas, key=lambda a: (a[2] - a[0]) * (a[3] - a[1]))
    # An interior point in the visible part, rather than the full row's centre.
    return (left + right - 1) // 2, (top + bottom - 1) // 2
