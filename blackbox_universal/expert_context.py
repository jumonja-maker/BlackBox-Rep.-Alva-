"""Pure, bounded presentation of the selected recorded ANALYSIS source.

The interval packet is the only evidence source. A path is displayed and
compared as supplied; this formatter does not inspect or authenticate it.
"""
from __future__ import annotations

import math
from pathlib import Path


_LABELS = {
    "source": ("Analysis source (recorded session)", "Источник анализа (сохранённая сессия)"),
    "none": ("none selected", "не выбран"),
    "read": ("Read", "Чтение"),
    "no_source": ("no source", "источник не выбран"),
    "loading": ("loading", "загрузка"),
    "failed": ("unavailable", "недоступно"),
    "waiting": ("awaiting selected source / instance", "ожидание выбранного источника / экземпляра"),
    "ready": ("ready", "готово"),
    "unknown": ("unknown", "неизвестно"),
    "root_pid": ("Root PID", "PID корневого процесса"),
    "created": ("Root creation (Unix s)", "Создание корневого процесса (Unix, с)"),
    "instance": ("Selected recorded instance", "Выбранный сохранённый экземпляр"),
    "range": ("Selected range", "Выбранный интервал"),
    "origin": ("recorded monotonic origin", "сохранённое начало монотонных часов"),
    "raw": ("raw ns", "исходные нс"),
    "seconds": ("s", "с"),
    "ns": ("ns", "нс"),
    "relative": ("relative to", "относительно"),
    "order": ("invalid bound order", "неверный порядок границ"),
}


def _integer(value, *, minimum=0):
    return type(value) is int and minimum <= value < 2**63


def _number_text(value, unknown):
    # bool is not a recorded PID, timestamp, status or clock measurement.
    if type(value) is int or type(value) is float and math.isfinite(value):
        return str(value)
    return unknown


def _recorded_text(value, unknown):
    if type(value) is str and value:
        return value if len(value)<=512 else value[:512]+"… [recorded text truncated]"
    return _number_text(value, unknown)


def _seconds(nanoseconds):
    """Keep integer-nanosecond precision without float rounding or overflow."""
    whole, fraction = divmod(abs(nanoseconds), 1_000_000_000)
    suffix = f".{fraction:09d}".rstrip("0") if fraction else ""
    return ("-" if nanoseconds < 0 else "") + str(whole) + suffix


def _range_text(interval, metadata, label):
    bounds = interval.get("selected_interval_ns")
    lo, hi = bounds if isinstance(bounds, (tuple, list)) and len(bounds) == 2 else (None, None)
    origin = metadata.get("monotonic_origin_ns")
    known_lo, known_hi, known_origin = (_integer(value) for value in (lo, hi, origin))
    unknown = label("unknown")
    if known_lo and known_hi and lo <= hi and known_origin:
        return (f"{label('range')}: {_seconds(lo-origin)}–{_seconds(hi-origin)} "
                f"{label('seconds')} {label('relative')} {label('origin')} {origin} {label('ns')}")
    start = str(lo) if known_lo else unknown
    end = str(hi) if known_hi else unknown
    base = str(origin) if known_origin else unknown
    text = (f"{label('range')} ({label('raw')}): {start}–{end} · "
            f"{label('origin')} ({label('ns')}): {base}")
    if known_lo and known_hi and lo > hi:
        text += f" · {label('order')}"
    return text


def format_analysis_context(folder: Path | None, packet, *, loading=False, failed=False,
                            language="EN", instance_id=1) -> str:
    """Format only a matching, ready recorded interval; never use live identity.

    ``folder`` is the selected analysis source, not a fallback from ``packet``.
    Loading/failure and stale source or instance packets suppress all recorded
    values. Missing packet instance IDs use the explicitly selected instance;
    present IDs must match it. Unknown numeric data is never converted to zero.
    The caller should display this string as plain text and use the full selected
    source path as its copyable tooltip.
    """
    index = 1 if str(language).upper() == "RU" else 0

    def label(key):
        return _LABELS[key][index]

    unknown = label("unknown")
    selected = str(folder) if folder is not None else label("none")
    source_line = f"{label('source')}: {selected}"
    selected_instance = str(instance_id) if _integer(instance_id, minimum=1) else unknown
    instance_text = f"{label('instance')}: {selected_instance}"

    if folder is None:
        return source_line + f"\n{label('read')}: {label('no_source')}"

    interval = packet.get("interval") if isinstance(packet, dict) else None
    matching = (_integer(instance_id, minimum=1) and isinstance(packet, dict) and packet.get("folder") == selected
                and isinstance(interval, dict))
    if matching:
        for key, allowed in (("schema_version", (2,)), ("source_schema_version", (1, 2))):
            if key in interval and (type(interval[key]) is not int or interval[key] not in allowed):
                matching = False
        if interval.get("source_schema_version") == 1 and instance_id != 1:
            matching = False
    if matching and "instance_id" in interval:
        recorded_instance = interval["instance_id"]
        matching = (type(recorded_instance) is type(instance_id)
                    and recorded_instance == instance_id)
    state = ("failed" if failed else "loading" if loading else
             "ready" if matching else "waiting")
    read_line = f"{label('read')}: {label(state)}"
    if state != "ready":
        return source_line + f"\n{read_line} · {instance_text}"

    metadata = interval.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    pid = metadata.get("pid")
    root_pid = str(pid) if _integer(pid, minimum=1) else unknown
    created = _number_text(metadata.get("creation_time"), unknown)
    identity_line = (f"{read_line} · {label('root_pid')}: {root_pid} · "
                     f"{label('created')}: {created} · {instance_text}")
    provenance_line = " · ".join(
        f"{key}: {_recorded_text(metadata.get(key), unknown)}"
        for key in ("file_trust", "clock_quality", "recorded_status"))
    return "\n".join((source_line, identity_line, _range_text(interval, metadata, label),
                      provenance_line))
