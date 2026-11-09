"""RU/EN presentation of recorded evidence, without changing its meaning.

The raw packet remains the authority. Unknown codes, fields, times and identities
are kept verbatim; a friendly label must never supply missing evidence.
"""
from __future__ import annotations

import json
import math
from io import StringIO

from .investigation_view import title as legacy_title


_LABELS = {
    "ALL": ("All", "Все"),
    "INFO": ("Information", "Информация"),
    "WARNING": ("Warning", "Предупреждение"),
    "ERROR": ("Error", "Ошибка"),
    "USER": ("User", "Пользователь"),
    "WIN32": ("Windows / Win32", "Windows / Win32"),
    "WCT": ("Wait Chain Traversal (WCT)", "Цепочки ожидания (WCT)"),
    "ETW": ("Windows trace (ETW)", "Трасса Windows (ETW)"),
    "EVENTPIPE": (".NET trace (EventPipe)", "Трасса .NET (EventPipe)"),
    "APP": ("Application events", "События приложения"),
    "OBSERVER": ("Observer", "Наблюдатель"),
    "OBSERVED": ("Recorded observation", "Сохранённое наблюдение"),
    "DERIVED": ("Derived from recorded data", "Вычислено по сохранённым данным"),
    "USER_REPORTED": ("User statement", "Сообщение пользователя"),
    "UNAVAILABLE": ("Measurement unavailable", "Измерение недоступно"),
    "UNVERIFIED_IMPORT": ("Source authenticity unverified", "Подлинность источника не проверена"),
    "UNKNOWN": ("Unknown", "Не установлено"),
    "CANDIDATE": ("Candidate for investigation", "Вариант для проверки"),
    "NEXT_MEASUREMENT": ("Next measurement", "Следующее измерение"),
    "OBSERVATION_ONLY": ("Observations only", "Только наблюдения"),
    "NOT_OBSERVED": ("Not observed", "Не наблюдалось"),
    "LEGACY_LIMITED_DATA": ("Limited legacy data", "Ограниченные данные старого формата"),
    "NO_RESOURCE_SAMPLES": ("No resource samples", "Нет измерений ресурсов"),
    "SAMPLED_GAP": ("Sampling gap at boundary", "Разрыв измерений у границы"),
    "OBSERVED_NEAR_BOUNDARY_NOT_INTERPOLATED": (
        "Observed near boundary; no interpolation", "Измерено вблизи границы, без интерполяции"),
    "CAPTURED": ("Context captured", "Контекст сохранён"),
    "INCOMPLETE_RECORDING_STOPPED": ("Incomplete: recording stopped", "Неполно: запись остановлена"),
    "INCOMPLETE_PROCESS_EXITED": ("Incomplete: process exited", "Неполно: процесс завершился"),
    "NO_POST_TARGET_EXITED": ("No post-context: process exited", "Нет контекста после: процесс завершился"),
    "SENSOR_TIMEOUT": ("Sensor timeout", "Тайм-аут датчика"),
    "COUNTERS_DO_NOT_ESTABLISH_ROOT_CAUSE": (
        "Resource counters do not establish the internal root cause.",
        "Счётчики ресурсов не устанавливают внутреннюю причину."),
    "SOURCE_FILE_NOT_AUTHENTICATED": (
        "The source file is not authenticated.", "Подлинность файла источника не удостоверена."),
    "BETWEEN_SAMPLE_ACTIVITY_UNKNOWN": (
        "Activity between samples is unknown.", "Активность между измерениями неизвестна."),
    "TID_REUSE_CANNOT_BE_EXCLUDED": (
        "Thread ID reuse cannot be excluded.", "Повторное использование TID нельзя исключить."),
    "PRE_POST_MAY_BE_PARTIAL": (
        "Pre/post context may be incomplete.", "Контекст до и после может быть неполным."),
    "TEMPORAL_COINCIDENCE_NOT_CAUSATION": (
        "Temporal coincidence does not establish causation.", "Совпадение по времени не устанавливает причинность."),
    "NO_BOUNDARY_EXTRAPOLATION": (
        "Values are not extrapolated to interval boundaries.", "Значения не экстраполируются к границам интервала."),
    "EXPECTED_WORKLOAD": ("Expected workload", "Ожидаемая работа"),
    "EXPECTED_WORK": ("Expected work", "Ожидаемая работа"),
    "BACKGROUND_WORK": ("Background work", "Фоновая работа"),
    "OBSERVER_EFFECT": ("Observer overhead", "Влияние наблюдателя"),
    "RETAINED_CACHE": ("Retained cache", "Сохранённый кеш"),
    "DELAYED_GC": ("Delayed garbage collection", "Отложенная сборка мусора"),
    "DIFFERENT_WORKLOAD": ("Different workload", "Другая нагрузка"),
    "LONG_UI_HANDLER": ("Long-running UI handler", "Длительный обработчик интерфейса"),
    "LOCK_OR_EXTERNAL_WAIT": ("Lock or external wait", "Блокировка или внешнее ожидание"),
    "SCHEDULING_DELAY": ("Scheduling delay", "Задержка планирования"),
    "EXPECTED_TRANSFER": ("Expected data transfer", "Ожидаемая передача данных"),
    "BUFFERING": ("Buffering", "Буферизация"),
    "OTHER_PROCESS_WORK": ("Work in another process", "Работа другого процесса"),
    "SOURCE_FAILURE_OR_COLLECTION_LIMIT": ("Source failure or collection limit", "Сбой источника или предел сбора"),
    "UNOBSERVED_ACTIVITY_BETWEEN_SAMPLES": ("Unobserved activity between samples", "Ненаблюдавшаяся активность между измерениями"),
    "INSPECT_COINCIDENT_WORK_AND_SOURCE_COVERAGE": (
        "Inspect coincident work and source coverage", "Проверить совпавшую работу и полноту источников"),
    "INSPECT_COINCIDENT_WORK_OR_WAITS": (
        "Inspect coincident work or waits", "Проверить совпавшую работу или ожидания"),
    "INSTRUMENT_VOLUNTARY_ACTION_STAGES": (
        "Add application events for action stages", "Добавить события приложения для этапов действия"),
    "INSPECT_AVAILABLE_WCT": (
        "Inspect available WCT evidence", "Посмотреть доступные данные WCT"),
    "REPEAT_EQUIVALENT_WORKLOAD": (
        "Repeat an equivalent workload for comparison", "Повторить эквивалентную нагрузку для сравнения"),
    "ADD_VOLUNTARY_STAGE_EVENTS": (
        "Add voluntary application stage events", "Добавить добровольные события этапов из приложения"),
    "GROWTH_OBSERVED_NOT_A_PROVEN_LEAK": (
        "Observed growth; a leak is not proven", "Наблюдался рост; утечка не доказана"),
    "THROUGHPUT_NOT_IO_LATENCY": (
        "Byte throughput; operation latency is not measured", "Скорость передачи байтов; задержка операций не измерена"),
    "OBSERVED_GAP_NOT_TARGET_HANG": (
        "Sampling gap; target hang is not established", "Разрыв измерений; зависание цели не установлено"),
}

_TITLES = {
    "CPU_SUSTAINED": ("Sustained CPU threshold", "Длительное превышение порога CPU"),
    "RSS_GROWTH": ("RSS growth threshold", "Порог роста RSS"),
    "PRIVATE_GROWTH": ("Private Bytes growth threshold", "Порог роста Private Bytes"),
    "HANDLE_GROWTH": ("Handle count growth threshold", "Порог роста числа дескрипторов"),
    "IO_BURST": ("I/O throughput threshold", "Порог скорости I/O"),
    "SAMPLING_GAP": ("Sampling gap", "Разрыв измерений"),
    "MANUAL_PROBLEM": ("User-marked problem", "Проблема, отмеченная пользователем"),
    "APP_CRASH_MARKER": ("Application-reported crash marker", "Сообщение приложения о сбое"),
    "CRASH_OBSERVED": ("Application crash observed by Windows", "Сбой приложения, зафиксированный Windows"),
    "PROCESS_EXIT_OBSERVED": ("Process exit observed", "Наблюдалось завершение процесса"),
    "UI_TIMEOUT": ("Window response probe timeout", "Тайм-аут проверки отклика окна"),
    "UI_UNRESPONSIVE_OBSERVED": ("Window did not respond to probe", "Окно не ответило на проверку"),
    "AUTO_INCIDENT_STARTED": ("Incident context started", "Начат контекст инцидента"),
    "AUTO_INCIDENT_COMPLETED": ("Incident context completed", "Завершён контекст инцидента"),
    "SAMPLING_GAP_OBSERVED": ("Sampling gap observed", "Наблюдался разрыв измерений"),
    "SENSOR_UNAVAILABLE": ("Sensor measurement unavailable", "Измерение датчика недоступно"),
    "ACTION_RESOURCE_COINCIDENCE": ("Resources during a user action", "Ресурсы во время действия пользователя"),
    "user_problem": ("User-reported problem", "Сообщение пользователя о проблеме"),
    "application.source_failed": ("Application event source failed", "Сбой источника событий приложения"),
    "observer.operation_failed": ("Observer operation failed", "Сбой операции наблюдателя"),
    "USER_STATEMENT": ("User statement", "Сообщение пользователя"),
    "SOURCE_STATUS": ("Source status", "Состояние источника"),
    "RECORDED_INCIDENT": ("Recorded incident", "Сохранённый инцидент"),
    "RESOURCES_INSIDE_USER_ACTION_INTERVAL": ("Resources inside the declared action interval", "Ресурсы внутри заявленного интервала действия"),
}

_FIELDS = {
    "metric": ("Metric", "Метрика"), "value": ("Value", "Значение"),
    "code": ("Code", "Код"), "status": ("Status", "Состояние"),
    "class": ("Class", "Класс"), "recommendation_type": ("Recommendation type", "Тип рекомендации"),
    "interpretation": ("Interpretation", "Трактовка"),
    "cpu_percent": ("CPU (% of one logical CPU)", "CPU (% одного логического CPU)"),
    "cpu_interval_percent": ("Interval CPU (% of one logical CPU)", "CPU за интервал (% одного логического CPU)"),
    "observed_percent": ("Observed CPU (% of one CPU)", "Измеренный CPU (% одного CPU)"),
    "threshold_percent_one_cpu": ("CPU threshold (% of one CPU)", "Порог CPU (% одного CPU)"),
    "rss_bytes": ("Resident memory (RSS)", "Резидентная память (RSS)"),
    "private_bytes": ("Private Bytes", "Private Bytes"),
    "uss_bytes": ("Unique memory (USS)", "Уникальная память (USS)"),
    "read_bytes": ("Read counter", "Счётчик чтения"),
    "write_bytes": ("Write counter", "Счётчик записи"),
    "observed_bytes_s": ("Observed I/O throughput", "Измеренная скорость I/O"),
    "threshold_bytes_s": ("I/O throughput threshold", "Порог скорости I/O"),
    "handle_count": ("Handles", "Дескрипторы"), "thread_count": ("Threads", "Потоки"),
    "cpu_user_s": ("Cumulative CPU user time (s)", "Накопленное время CPU в режиме пользователя (с)"),
    "cpu_system_s": ("Cumulative CPU system time (s)", "Накопленное время CPU в режиме ядра (с)"),
    "delta": ("Change", "Изменение"), "threshold": ("Threshold", "Порог"),
    "gap_ms": ("Sampling gap (ms)", "Разрыв измерений (мс)"),
    "observed_window_ms": ("Observed window (ms)", "Окно наблюдений (мс)"),
    "start_ms": ("Start (ms)", "Начало (мс)"), "end_ms": ("End (ms)", "Конец (мс)"),
    "start_ns": ("Start timestamp (ns)", "Метка начала (нс)"),
    "end_ns": ("End timestamp (ns)", "Метка конца (нс)"),
    "observed_ns": ("Observed timestamp (ns)", "Метка измерения (нс)"),
    "nearest_observed_ns": ("Nearest observed timestamp (ns)", "Ближайшая метка измерения (нс)"),
    "offset_ns": ("Offset from boundary (ns)", "Смещение от границы (нс)"),
    "values": ("Recorded values", "Сохранённые значения"),
    "first_seq": ("First sample sequence", "Порядковый номер первого измерения"),
    "primary_event_id": ("Primary event ID", "ID основного события"),
    "instance_id": ("Process instance ID", "ID экземпляра процесса"),
    "incident_id": ("Incident ID", "ID инцидента"),
    "evidence_ref": ("Evidence reference", "Ссылка на свидетельство"),
    "source": ("Source", "Источник"), "verification_class": ("Verification class", "Класс проверки"),
    "min": ("Minimum", "Минимум"), "max": ("Maximum", "Максимум"),
    "mean": ("Mean", "Среднее"), "count": ("Count", "Количество"),
    "selected_samples": ("Selected samples", "Измерения в интервале"),
    "total_samples": ("Total samples", "Всего измерений"),
    "spacing_gap_pairs": ("Sampling gap pairs", "Пары с разрывом измерений"),
    "exact_missed_samples": ("Exact missed sample count", "Точное число пропущенных измерений"),
}


def tr(language: str, en: str, ru: str) -> str:
    return ru if language == "RU" else en


def label(code, language: str, *, with_code: bool = False) -> str:
    code = _literal(code)
    pair = _LABELS.get(code) or _TITLES.get(code)
    text = tr(language, *pair) if pair else code
    return f"{text} [{code}]" if with_code and text != code else text


def title(code, language: str) -> str:
    code = _literal(code)
    if code in _TITLES:
        return label(code, language)
    for prefix in ("INCIDENT_", "DERIVED_"):
        if code.startswith(prefix) and code[len(prefix):] in _TITLES:
            text = label(code[len(prefix):], language)
            return tr(language, "Recorded incident: ", "Сохранённый инцидент: ") + text if prefix == "INCIDENT_" else text
    return legacy_title(code, language)


def raw_json(row: dict) -> str:
    """Keep complete JSON without quadratic indentation of deep imports.

    Ordinary records remain indented. Large or deeply nested records use an
    iterative compact encoder: no fields are discarded and recursion depth
    does not depend on an imported document's shape.
    """
    pending = [(row, 0)]
    nodes = 0
    characters = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > 4096 or depth > 24 or characters > 131072:
            return _compact_json(row)
        if isinstance(value, dict):
            if len(value) > 4096:
                return _compact_json(row)
            if any(not isinstance(key, str) for key in value):
                raise TypeError("Evidence JSON object keys must be strings")
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            if len(value) > 4096:
                return _compact_json(row)
            pending.extend((item, depth + 1) for item in value)
        elif isinstance(value, str):
            characters += len(value)
        elif value is not None and type(value) not in (bool, int, float):
            raise TypeError("Unsupported evidence JSON value")
    return _unicode_text(json.dumps(row, ensure_ascii=False, indent=2, allow_nan=False))


def _compact_json(value) -> str:
    output = StringIO()
    pending = [("value", value)]
    active = set()
    while pending:
        frame = pending.pop()
        if frame[0] in ("object", "array"):
            kind, iterator, first, identity = frame
            try:
                item = next(iterator)
            except StopIteration:
                output.write("}" if kind == "object" else "]")
                active.remove(identity)
                continue
            if not first:
                output.write(",")
            pending.append((kind, iterator, False, identity))
            if kind == "object":
                key, item = item
                if not isinstance(key, str):
                    raise TypeError("Evidence JSON object keys must be strings")
                output.write(json.dumps(key, ensure_ascii=False))
                output.write(":")
            pending.append(("value", item))
        else:
            item = frame[1]
            if isinstance(item, (dict, list)):
                identity = id(item)
                if identity in active:
                    raise ValueError("Circular evidence object")
                active.add(identity)
                output.write("{" if isinstance(item, dict) else "[")
                iterator = iter(item.items()) if isinstance(item, dict) else iter(item)
                pending.append(("object" if isinstance(item, dict) else "array", iterator, True, identity))
            else:
                if item is not None and type(item) not in (bool, int, float, str):
                    raise TypeError("Unsupported evidence JSON value")
                output.write(json.dumps(item, ensure_ascii=False, allow_nan=False))
    return _unicode_text(output.getvalue())


def _unicode_text(text: str) -> str:
    """Escape lone imported surrogates without altering JSON string meaning."""
    return text.encode("utf-8", errors="backslashreplace").decode("utf-8")


def _literal(value, *, limit=4096) -> str:
    if isinstance(value, (dict, list)):
        return "[recorded structure; see Raw JSON]"
    text = _unicode_text(str(value))
    return text if len(text) <= limit else text[:limit] + "… [see complete Raw JSON]"


def _scalar(value, language: str) -> str:
    if value is None:
        return tr(language, "Not recorded / unknown (null)", "Не записано / неизвестно (null)")
    if type(value) is bool:
        return tr(language, "Yes (true)", "Да (true)") if value else tr(language, "No (false)", "Нет (false)")
    if type(value) is float and not math.isfinite(value):
        return tr(language, "Invalid non-finite value: ", "Недопустимое неконечное значение: ") + str(value)
    return _literal(value)


def _number(value) -> bool:
    return type(value) is int or type(value) is float and math.isfinite(value)


def scaled_text(value, divisor: int, *, places: int = 2) -> str:
    """Format integer measurements without converting huge imports to float."""
    if type(value) is int:
        scale = 10 ** places
        rounded = (abs(value) * scale + divisor // 2) // divisor
        whole, fraction = divmod(rounded, scale)
        return ("-" if value < 0 else "") + f"{whole}.{fraction:0{places}d}"
    if type(value) is float and math.isfinite(value):
        return f"{value / divisor:.{places}f}"
    return _literal(value)


def valid_timestamp(value) -> bool:
    return type(value) is int and 0 <= value < 2**63


def seconds_text(nanoseconds: int) -> str:
    return scaled_text(nanoseconds, 1_000_000_000, places=3)


def _value(value, key: str, metric: str, language: str) -> str:
    if not _number(value):
        return _scalar(value, language)
    unit_key = metric if key in ("delta", "threshold", "value", "min", "max", "mean") else key
    if unit_key in ("rss_bytes", "private_bytes", "uss_bytes", "read_bytes", "write_bytes", "growth_bytes"):
        return f"{scaled_text(value, 1048576)} MiB ({value} " + tr(language, "bytes)", "байт)")
    if unit_key in ("observed_bytes_s", "threshold_bytes_s", "read_bps", "write_bps"):
        return f"{scaled_text(value, 1048576)} MiB/s ({value} " + tr(language, "bytes/s)", "байт/с)")
    return str(value)


def fact_lines(value, language: str, *, indent: int = 0, metric: str = "", _budget=None) -> list[str]:
    """Bound the default view; complete unknown additions remain in Raw JSON."""
    if _budget is None:
        _budget = [1024]
    pad = "  " * indent
    if _budget[0] <= 0 or indent >= 24:
        return [pad + tr(language, "More recorded data in complete Raw JSON", "Остальные сохранённые данные — в полном JSON")]
    _budget[0] -= 1
    if isinstance(value, dict):
        metric = value.get("metric", metric)
        metric = metric if isinstance(metric, str) else ""
        lines = []
        for key, item in value.items():
            if _budget[0] <= 0:
                lines.append(pad + tr(language, "More recorded fields in complete Raw JSON", "Остальные поля — в полном JSON"))
                break
            _budget[0] -= 1
            name = tr(language, *_FIELDS[key]) if key in _FIELDS else _literal(key)
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}{name}:")
                lines.extend(fact_lines(item, language, indent=indent + 1,
                                        metric=key if key in _FIELDS and key.endswith("_bytes") else "", _budget=_budget))
            else:
                shown = label(item, language, with_code=True) if key in ("code", "status", "interpretation", "verification_class", "class", "recommendation_type") and item is not None else _value(item, key, metric, language)
                if key == "metric" and isinstance(item, str) and item in _FIELDS:
                    shown = f"{tr(language, *_FIELDS[item])} [{item}]"
                lines.append(f"{pad}{name}: {shown}")
        return lines or [pad + tr(language, "Empty object", "Пустой объект")]
    if isinstance(value, list):
        if not value:
            return [pad + tr(language, "None recorded", "Не записано")]
        lines = []
        for number, item in enumerate(value, 1):
            if _budget[0] <= 0:
                lines.append(pad + tr(language, "More recorded rows in complete Raw JSON", "Остальные строки — в полном JSON"))
                break
            _budget[0] -= 1
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}{number}.")
                lines.extend(fact_lines(item, language, indent=indent + 1, metric=metric, _budget=_budget))
            else:
                lines.append(f"{pad}• {_scalar(item, language)}")
        return lines
    return [pad + _scalar(value, language)]


def time_text(row: dict, origin, language: str, *, events: bool = False) -> str:
    start = row.get("time_ns" if events else "start_ns")
    end = start if events else row.get("end_ns")
    if not valid_timestamp(start):
        return tr(language, "Time not recorded", "Время не записано") if start is None else tr(language, "Invalid recorded timestamp: ", "Недопустимая метка времени: ") + _scalar(start, language)
    if not events and end is not None and (not valid_timestamp(end) or end < start):
        return tr(language, "Invalid recorded interval: ", "Недопустимый сохранённый интервал: ") + _scalar(start, language) + "–" + _scalar(end, language) + " ns"
    exact = f"{start}" if end == start or end is None else f"{start}–{end}"
    if not valid_timestamp(origin):
        result = exact + tr(language, " ns; recording origin unknown", " нс; начало отсчёта записи неизвестно")
        if not events and end is None:
            result += tr(language, "; end not recorded", "; конец не записан")
        return result
    result = seconds_text(start - origin)
    if type(end) is int and end != start:
        result += "–" + seconds_text(end - origin)
    result += tr(language, " s from recording origin", " с от начала отсчёта записи")
    if not events and end is None:
        result += tr(language, "; end not recorded", "; конец не записан")
    return result + f" ({exact} ns)"


def _section(lines: list[str], language: str, en: str, ru: str, value) -> None:
    lines.extend(("", _literal(tr(language, en, ru))))
    lines.extend(fact_lines(value, language))


def _codes(lines: list[str], language: str, en: str, ru: str, values) -> None:
    lines.extend(("", tr(language, en, ru)))
    if isinstance(values, list):
        lines.extend("• " + label(value, language, with_code=True) for value in values[:1024])
        if len(values) > 1024:
            lines.append(tr(language, "Additional codes in complete Raw JSON", "Остальные коды — в полном JSON"))
        if not values:
            lines.append(tr(language, "None recorded", "Не записано"))
    else:
        lines.extend(fact_lines(values, language))


def detail_text(row: dict, language: str, *, origin=None, events: bool = False, card: bool = False) -> str:
    if card:
        return _bounded_detail(incident_text(row, language), language)
    code = row.get("code", "UNKNOWN")
    lines = [title(code, language), tr(language, "Code: ", "Код: ") + _literal(code),
             time_text(row, origin, language, events=events),
             tr(language, "Severity: ", "Уровень: ") + label(row.get("severity", "UNKNOWN"), language, with_code=True)]
    if events:
        lines.extend((tr(language, "Source group: ", "Группа источника: ") + label(row.get("source", "UNKNOWN"), language, with_code=True),
                      tr(language, "Measurement status: ", "Состояние измерения: ") + label(row.get("status", "UNKNOWN"), language, with_code=True),
                      tr(language, "Source trust: ", "Доверие к источнику: ") + label(row.get("verification_class", "UNKNOWN"), language, with_code=True)))
        _section(lines, language, "Recorded event fields", "Сохранённые поля события", row.get("detail"))
        consumed = {"code", "time_ns", "severity", "source", "status", "verification_class", "detail"}
    else:
        lines.extend((tr(language, "Evidence class: ", "Класс свидетельства: ") + label(row.get("confidence_class", "UNKNOWN"), language, with_code=True),
                      tr(language, "Source trust: ", "Доверие к источнику: ") + label(row.get("source_trust", "UNKNOWN"), language, with_code=True),
                      tr(language, "Root cause: ", "Причина: ") + label(row.get("root_cause", "UNKNOWN"), language, with_code=True)))
        _section(lines, language, "Recorded facts", "Сохранённые факты", row.get("facts"))
        _codes(lines, language, "Alternative explanations to check", "Альтернативы для проверки", row.get("alternative_explanations"))
        _codes(lines, language, "Evidence limitations", "Ограничения свидетельств", row.get("limitations"))
        _section(lines, language, "Suggested next measurements / candidates", "Предлагаемые измерения / варианты проверки", row.get("hypotheses"))
        _section(lines, language, "Source references", "Ссылки на источники", row.get("sources"))
        _section(lines, language, "Coverage", "Полнота наблюдений", row.get("coverage"))
        consumed = {"code", "start_ns", "end_ns", "severity", "confidence_class", "source_trust", "root_cause", "facts", "alternative_explanations", "limitations", "hypotheses", "sources", "coverage"}
    extra = {key: value for key, value in row.items() if key not in consumed}
    if extra:
        _section(lines, language, "References and additional recorded fields", "Ссылки и дополнительные сохранённые поля", extra)
    return _bounded_detail("\n".join(lines), language)


def _bounded_detail(text: str, language: str) -> str:
    text = _unicode_text(text)
    if len(text) <= 65536:
        return text
    return text[:65536] + "\n" + tr(language, "Display limit reached. Complete record remains in Raw JSON.",
                                    "Достигнут предел показа. Полная запись сохранена в JSON.")


def incident_text(row: dict, language: str) -> str:
    lines = [tr(language, "Incident observations", "Наблюдения инцидента"),
             tr(language, "Status: ", "Состояние: ") + label(row.get("status", "UNKNOWN"), language, with_code=True),
             tr(language, "Root cause: ", "Причина: ") + label(row.get("root_cause", "UNKNOWN"), language, with_code=True),
             tr(language, "Source trust: ", "Доверие к источнику: ") + label(row.get("source_trust", "UNKNOWN"), language, with_code=True)]
    _section(lines, language, "Recorded incident", "Сохранённый инцидент", row.get("incident"))
    snapshots = row.get("snapshots")
    if snapshots is not None and not isinstance(snapshots, dict):
        _section(lines, language, "Recorded snapshots (unrecognized structure)", "Сохранённые измерения (неизвестная структура)", snapshots)
    for name, snapshot in (snapshots.items() if isinstance(snapshots, dict) else ()):
        title_pair = {"before": ("Snapshot near start", "Измерение вблизи начала"),
                      "at_end": ("Snapshot near end", "Измерение вблизи конца"),
                      "post": ("Snapshot in post-context", "Измерение в контексте после")}.get(name, (name, name))
        _section(lines, language, *title_pair, snapshot)
    lines.extend(("", tr(language, "Post-context complete: ", "Контекст после полный: ") + _scalar(row.get("post_context_complete"), language)))
    _codes(lines, language, "Next measurements", "Следующие измерения", row.get("next_actions"))
    _codes(lines, language, "Evidence limitations", "Ограничения свидетельств", row.get("limitations"))
    # These packets may contain hundreds of sample buckets. Their presence is
    # summarized here; the complete original structures remain in raw mode.
    for name in ("resources", "threads", "process_tree", "events", "native_windows", "wct", "trace_evidence", "runtime_evidence"):
        packet = row.get(name)
        if not isinstance(packet, dict):
            continue
        names = {"resources": ("Resource intervals", "Интервалы ресурсов"),
                 "threads": ("Threads", "Потоки"), "process_tree": ("Process tree", "Дерево процессов"),
                 "events": ("Events", "События"), "native_windows": ("Windows events", "События окон"),
                 "wct": ("Wait chain evidence (WCT)", "Свидетельства цепочек ожидания (WCT)"),
                 "trace_evidence": ("ETW evidence", "Свидетельства ETW"),
                 "runtime_evidence": ("EventPipe evidence", "Свидетельства EventPipe")}
        summary = {key: packet[key] for key in ("status", "total_matching", "has_more", "coverage", "limitations", "source_trust") if key in packet}
        if name == "resources":
            summary = {phase: {key: report[key] for key in ("status", "coverage", "metrics") if key in report}
                       for phase, report in packet.items() if isinstance(report, dict)}
        _section(lines, language, *names[name], summary or tr(language, "Recorded packet; complete data in Raw JSON", "Пакет сохранён; полные данные в JSON"))
    known = {"status", "root_cause", "source_trust", "incident", "snapshots", "post_context_complete", "next_actions", "limitations", "resources", "threads", "process_tree", "events", "native_windows", "wct", "trace_evidence", "runtime_evidence"}
    extra = {key: value for key, value in row.items() if key not in known}
    if extra:
        _section(lines, language, "Additional recorded fields", "Дополнительные сохранённые поля", extra)
    lines.extend(("", tr(language, "Raw JSON contains the complete incident packet, including all resource and event rows.",
                                  "JSON содержит полный пакет инцидента, включая все строки ресурсов и событий.")))
    return "\n".join(lines)
