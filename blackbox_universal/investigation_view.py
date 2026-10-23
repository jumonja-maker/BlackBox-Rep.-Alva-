"""Human-facing presentation of Investigation Engine schema 2 evidence.

Never translate a measured value or promote an inference into a proven cause.
This file is independent of Qt to keep evidence rendering testable.
"""
from __future__ import annotations
import json

_TITLES = {
    "SUSTAINED_HIGH_CPU": ("Длительная нагрузка CPU", "Sustained high CPU"),
    "MEMORY_GROWTH_CANDIDATE": ("Подозрительный рост памяти", "Memory growth candidate"),
    "HIGH_IO_RATE": ("Высокая скорость I/O", "High I/O throughput"),
    "HOT_THREAD_OBSERVED": ("Активный поток", "High-CPU thread"),
    "OBSERVATION_GAP": ("Пропуск измерений", "Sampling gap"),
    "COUNTER_RESET": ("Сброс счётчика", "Counter reset"),
    "PROCESS_EXIT_RECORDED": ("Записано завершение процесса", "Process exit recorded"),
}
_LIMITS_RU = {
    "Nothing is observed inside the gap.": "Внутри интервала нет измерений.",
    "Process or counter reset; negative I/O speed is invalid.":
        "Счётчик сброшен; отрицательная скорость I/O недопустима.",
    "High process CPU does not identify the executing function.":
        "Высокий CPU не показывает выполняющуюся функцию.",
    "Memory growth is not proof of a leak; repeat equivalent operations and inspect allocations.":
        "Рост памяти не доказывает утечку. Повторите одинаковые действия и исследуйте выделения.",
    "Byte throughput does not reveal operation latency, path or responsible code.":
        "Скорость I/O не сообщает задержку, путь файла или исполняемый код.",
    "Without independently obtained stacks no function, wait state or root cause is known.":
        "Без стеков невозможно достоверно определить функцию, ожидание и причину.",
    "Local session metadata records an exit; it does not prove why or independently attest OS events.":
        "В сеансе записано завершение, но не установлена его причина.",
}
_METRICS = {
    "cpu_percent": ("CPU", "CPU"),
    "rss_bytes": ("RSS", "RSS"),
    "private_bytes": ("Private Bytes", "Private Bytes"),
    "uss_bytes": ("USS", "USS"),
    "read_bps": ("Чтение/с", "Read/s"),
    "write_bps": ("Запись/с", "Write/s"),
    "gap_ms": ("Пропуск, мс", "Gap, ms"),
    "thread_cpu_percent_one_core": ("CPU потока", "Thread CPU"),
}
_WARN_RU = {
    "PARTIAL_SESSION_INTERVAL": "Проанализирована лишь часть сеанса",
    "NO_OBSERVATIONS": "Измерения отсутствуют",
    "FINDING_LIMIT_REACHED": "Часть находок не показана из-за ограничения",
}

def title(code: str, language: str) -> str:
    return _TITLES.get(code, (code, code))[0 if language == "RU" else 1]

def interval_text(item: dict) -> str:
    lo, hi = item.get("start_ms"), item.get("end_ms")
    if type(lo) is not int or type(hi) is not int:
        return "—"
    if lo == hi:
        return f"{lo / 1000:.2f} s"
    return f"{lo / 1000:.2f}–{hi / 1000:.2f} s"

def fact_text(item: dict, language: str, *, limit: int = 12) -> str:
    facts = item.get("facts", [])
    if not isinstance(facts, list):
        return "—"
    pieces = []
    for fact in facts[:limit]:
        if not isinstance(fact, dict):
            continue
        metric = fact.get("metric", "value")
        key = _METRICS.get(metric, (str(metric), str(metric)))[0 if language == "RU" else 1]
        value = fact.get("value", fact.get("growth_bytes", fact.get("bytes_per_second", fact.get("threshold"))))
        if value is None:
            value = {k: v for k, v in fact.items() if k != "metric"}
        pieces.append(f"{key}: {str(value)[:120]}")
    return " · ".join(pieces) if pieces else "—"

def finding_details(item: dict, language: str) -> str:
    code = str(item.get("code", "UNKNOWN"))
    assessment = item.get("interpretation", "OBSERVATION_ONLY")
    candidate = assessment == "CANDIDATE_NOT_CAUSAL_PROOF"
    intro = ("Предположение — не доказанная причина" if language == "RU" else
             "Candidate — not a proven root cause") if candidate else (
             "Наблюдение из сохранённых измерений" if language == "RU" else
             "Observation from saved measurements")
    limit = str(item.get("limitation", ""))
    if language == "RU":
        limit = _LIMITS_RU.get(limit, limit)
    return (f"{title(code, language)} · {interval_text(item)}\n"
            f"{intro}\n"
            f"{fact_text(item, language)}\n"
            + ("Ограничение: " if language == "RU" else "Limitation: ") + limit)

def summary_text(report: dict | None, language: str) -> str:
    if not report:
        return ("Проведите анализ завершённого сеанса, чтобы увидеть находки." if language == "RU"
                else "Investigate a completed session to see findings.")
    findings = report.get("findings", [])
    coverage = report.get("coverage", {})
    count = len(findings) if isinstance(findings, list) else 0
    total = coverage.get("total_samples", 0) if isinstance(coverage, dict) else 0
    selected = coverage.get("selected_samples", 0) if isinstance(coverage, dict) else 0
    incomplete = isinstance(coverage, dict) and not coverage.get("full_session_covered", True)
    if language == "RU":
        result = f"Находок: {count} · Измерений: {selected}/{total} · Причина не установлена"
        if incomplete:
            result += " · Внимание: частичный интервал"
    else:
        result = f"Findings: {count} · Samples: {selected}/{total} · Root cause unknown"
        if incomplete:
            result += " · Partial interval only"
    return result
