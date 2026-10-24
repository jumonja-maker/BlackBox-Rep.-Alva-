"""Bounded recorded process hierarchy. No sensor or filesystem work on Qt."""
from __future__ import annotations

import math

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTreeWidget, QTreeWidgetItem


HEADERS = {
    "EN": ("PROCESS / PID", "BIRTH (UTC epoch s)", "PEAK CPU % / 1 CPU",
           "CPU seconds", "RSS peak MiB", "PRIVATE peak MiB", "USS peak MiB",
           "HANDLES peak", "AGE estimate s", "OBSERVED span s", "OBSERVATION"),
    "RU": ("ПРОЦЕСС / PID", "СОЗДАН (UTC epoch с)", "ПИК CPU % / 1 CPU",
           "CPU секунды", "ПИК RSS МиБ", "ПИК PRIVATE МиБ", "ПИК USS МиБ",
           "ПИК ДЕСКРИПТОРОВ", "ВОЗРАСТ оценка с", "НАБЛЮДАЛСЯ с", "НАБЛЮДЕНИЕ"),
}


def _number(value, *, scale=1, precision=3):
    if type(value) not in (int, float) or not math.isfinite(value):
        return "—"
    return f"{value / scale:.{precision}f}"


class RecordedProcessTree(QTreeWidget):
    """At most one resource page plus 256 context ancestors in memory.

    PPID plus overlapping lifetime is only a candidate relationship. An
    imported file does not attest lineage; ambiguous/cyclic links are never
    forced into a hierarchy. Context nodes are labelled and have no invented
    resource values. Selecting any node emits only the normal Qt signal.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("recordedProcessTree")
        self.language = "EN"
        self._page = None
        self._items = {}
        self.setColumnCount(len(HEADERS["EN"]))
        self.setHeaderLabels(HEADERS["EN"])
        self.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.header().setStretchLastSection(False)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setUniformRowHeights(True)
        self.setAlternatingRowColors(True)
        self.setMinimumHeight(190)
        self.setAccessibleName("Recorded process tree")

    def selected_instance(self):
        item = self.currentItem()
        return item.data(0, Qt.ItemDataRole.UserRole) if item else None

    def item_for_instance(self, identity):
        return self._items.get(identity)

    def set_language(self, language):
        self.language = "RU" if language == "RU" else "EN"
        self.setHeaderLabels(HEADERS[self.language])
        self.setAccessibleName("Дерево записанных процессов" if self.language == "RU"
                               else "Recorded process tree")
        if self._page is not None:
            self.apply_page(self._page, selected_instance=self.selected_instance())

    def apply_page(self, page, *, selected_instance=None):
        self._page = page
        # These bounds are also enforced by the worker's SQLite page API.
        rows = list(page.get("rows", ()))[:256]
        context = list(page.get("ancestors", ()))[:256]
        records = {r["instance_id"]: r for r in context}
        records.update((r["instance_id"], r) for r in rows)
        previous = self.blockSignals(True)
        try:
            self.clear()
            self._items = {}
            ru = self.language == "RU"
            for identity, row in records.items():
                r = row.get("resources", {})
                context_only = bool(row.get("context_only"))
                name = str(row.get("executable_name") or "?")[:512]
                process = f"{name} · PID {row['pid']}"
                if context_only:
                    process += " · контекст" if ru else " · context"
                absent = row.get("absence_observed_ns")
                span = row["last_observed_ns"] - row["first_observed_ns"]
                observation = ("Отсутствие замечено" if ru else "Absence observed") if absent is not None else (
                    "Последнее наблюдение" if ru else "Last observed")
                if identity == page.get("root_instance_id"):
                    observation = ("Корень · " if ru else "Root · ") + observation
                values = (process, _number(row["creation_time"], precision=6),
                          _number(r.get("cpu_peak_percent_one_cpu")),
                          _number(r.get("cpu_seconds")),
                          *(_number(r.get(k), scale=1048576) for k in (
                              "rss_peak_bytes", "private_peak_bytes", "uss_peak_bytes")),
                          _number(r.get("handles_peak"), precision=0),
                          _number(row.get("age_at_last_observation_s")),
                          _number(span, scale=1e9) if span >= 0 else "—", observation)
                item = QTreeWidgetItem(values)
                item.setData(0, Qt.ItemDataRole.UserRole, identity)
                raw = (f"instance_id={identity}; PID={row['pid']}; birth={row['creation_time']}\n"
                       f"first_ns={row['first_observed_ns']}; last_ns={row['last_observed_ns']}; "
                       f"absence_observed_ns={absent}\n"
                       f"{row.get('parent_link_quality', 'PARENT_NOT_OBSERVED')}\n"
                       "UNVERIFIED_IMPORT · " + (
                           "Связь PPID предполагаемая; отсутствие не является точным временем выхода."
                           if ru else "PPID link is a candidate; absence is not an exact exit time."))
                if context_only:
                    raw += "\n" + ("Контекст предка; ресурсные значения не загружены на этой странице."
                                    if ru else "Ancestor context; resources not loaded in this page.")
                for column, value in enumerate(values):
                    item.setToolTip(column, str(value) + "\n" + raw)
                    if 0 < column < 10:
                        item.setTextAlignment(column, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                item.setToolTip(8, raw + "\n" + row.get("age_quality", "NOT_OBSERVED"))
                self._items[identity] = item
            for identity, row in records.items():
                parent = row.get("parent_instance_candidate")
                # Imported malformed cycles must not make Qt recurse forever.
                seen = {identity}
                cursor = parent
                cycle = False
                while cursor in records:
                    if cursor in seen:
                        cycle = True
                        break
                    seen.add(cursor)
                    cursor = records[cursor].get("parent_instance_candidate")
                item = self._items[identity]
                if parent in self._items and not cycle:
                    self._items[parent].addChild(item)
                else:
                    self.addTopLevelItem(item)
                    if cycle:
                        item.setToolTip(0, item.toolTip(0) + "\nINVALID_CYCLIC_PARENT_CANDIDATE")
            # Finite page, keyboard expansion stays available for deeper nodes.
            self.expandToDepth(1)
            if selected_instance in self._items:
                self.setCurrentItem(self._items[selected_instance])
        finally:
            self.blockSignals(previous)
