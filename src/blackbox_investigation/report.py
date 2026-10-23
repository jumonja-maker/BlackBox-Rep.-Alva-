"""Standalone, safe, static bilingual evidence view. No JS, links or remote assets."""
from __future__ import annotations

from html import escape
import json
from .model import InvestigationError

_LABELS = {
    "SUSTAINED_HIGH_CPU": ("Высокая загрузка CPU", "Sustained high CPU"),
    "MEMORY_GROWTH_CANDIDATE": ("Рост памяти — требуется проверка", "Memory growth — investigate"),
    "HIGH_IO_RATE": ("Высокая скорость I/O", "High I/O throughput"),
    "HOT_THREAD_OBSERVED": ("Активный поток", "High-CPU thread"),
    "OBSERVATION_GAP": ("Пробел в измерениях", "Observation gap"),
    "COUNTER_RESET": ("Сброс счётчика", "Counter reset"),
    "PROCESS_EXIT_RECORDED": ("Завершение записано в сеансе (не подтверждено ОС)",
                              "Exit recorded in session (not OS-attested)"),
}


_LIMIT_RU = {
    "Nothing is observed inside the gap.": "Внутри промежутка измерения отсутствуют.",
    "Process or counter reset; negative I/O speed is invalid.": "Счётчик сброшен: отрицательная скорость I/O недопустима.",
    "High process CPU does not identify the executing function.": "Высокая нагрузка CPU не устанавливает выполняемую функцию.",
    "Memory growth is not proof of a leak; repeat equivalent operations and inspect allocations.":
        "Рост памяти не доказывает утечку; повторите одинаковые действия и исследуйте выделения.",
    "Byte throughput does not reveal operation latency, path or responsible code.":
        "Скорость I/O не раскрывает задержку операции, путь или участок кода.",
    "Without independently obtained stacks no function, wait state or root cause is known.":
        "Без независимо полученных стеков неизвестны функции, ожидания и причина.",
    "Local session metadata records an exit; it does not prove why or independently attest OS events.":
        "Метаданные локального сеанса фиксируют завершение, но не его причину и не независимое подтверждение ОС.",
}
_WARN_RU = {"NO_OBSERVATIONS": "Нет измерений", "FINDING_LIMIT_REACHED": "Достигнут лимит результатов",
            "PARTIAL_SESSION_INTERVAL": "Анализ частичного интервала: часть измерений не обработана"}


def to_html(report: dict, *, lang: str = "RU") -> str:
    if (lang not in ("RU", "EN") or type(report) is not dict or
            report.get("type") != "BLACKBOX_INVESTIGATION" or
            report.get("schema_version") != 2 or type(report.get("findings")) is not list):
        raise InvestigationError("INVALID_REPORT")
    pick = 0 if lang == "RU" else 1
    esc = lambda x: escape(str(x), quote=True)
    title = "Расследование BLACK.BOX" if lang == "RU" else "BLACK.BOX Investigation"
    warning = ("Это наблюдения и гипотезы, а не доказательство причины ошибки." if lang == "RU" else
               "These are observations and hypotheses, not proof of root cause.")
    items = []
    for item in report.get("findings", [])[:200]:
        if type(item) is not dict or type(item.get("code")) is not str:
            raise InvestigationError("INVALID_REPORT")
        caption = _LABELS.get(item.get("code"), ("Наблюдение", "Observation"))[pick]
        try:
            facts = esc(json.dumps(item.get("facts", []), ensure_ascii=False, allow_nan=False))
        except (TypeError, ValueError):
            raise InvestigationError("INVALID_REPORT") from None
        limitation = item.get("limitation", "")
        if type(limitation) is not str:
            raise InvestigationError("INVALID_REPORT")
        if lang == "RU":
            limitation = _LIMIT_RU.get(limitation, "Ограничение: объяснение не переведено (код сохранён)")
        items.append(f"<li><strong>{esc(caption)}</strong> · {esc(item.get('start_ms'))}–{esc(item.get('end_ms'))} ms"
                     f"<p>{facts}</p><small>{esc(limitation)}</small></li>")
    warnings = report.get("warnings", [])
    if type(warnings) is not list or any(type(w) is not str for w in warnings):
        raise InvestigationError("INVALID_REPORT")
    warning_text = ", ".join(_WARN_RU.get(w, w) if lang == "RU" else w for w in warnings)
    coverage = report.get("coverage")
    coverage_text = ""
    if coverage is not None:
        if type(coverage) is not dict or type(coverage.get("omitted_samples")) is not int:
            raise InvestigationError("INVALID_REPORT")
        coverage_text = ("<p>" + ("Пропущено измерений: " if lang == "RU" else "Omitted samples: ") +
                         esc(coverage["omitted_samples"]) + "</p>")
    footer = ("Причина: НЕ УСТАНОВЛЕНА" if lang == "RU" else "Root cause: UNKNOWN")
    return ("<!doctype html><html lang='" + ("ru" if lang == "RU" else "en") +
            "'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>" + esc(title) + "</title><style>body{font:15px system-ui;max-width:950px;margin:36px auto;"
            "padding:0 24px;background:#f8f4ea;color:#24353b}h1{color:#086e6c}"
            "li{background:white;padding:14px;margin:10px 0;border-left:4px solid #087e78;overflow-wrap:anywhere}"
            "small{color:#52585d}code{overflow-wrap:anywhere}</style></head><body><h1>" + esc(title) +
            "</h1><p>" + esc(warning) + "</p><p>Evidence SHA-256: <code>" +
            esc(report.get("evidence_sha256")) + "</code></p>" + coverage_text +
            "<p>" + esc(warning_text) + "</p><ol>" + "".join(items) + "</ol>" +
            "<footer>BLACK.BOX Investigation · " + esc(footer) + "</footer></body></html>")
