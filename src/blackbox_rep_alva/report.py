"""Offline reports: summaries do not contain command lines, secrets, file paths."""
from __future__ import annotations
from html import escape
import hashlib
from contextlib import closing
import json
from pathlib import Path
import sqlite3
from .contracts import ObserverError, bounded
from .storage import _open_ro


def summarize(folder: Path) -> dict:
    try:
        with closing(_open_ro(Path(folder))) as db:
            row = db.execute("SELECT * FROM metadata LIMIT 1").fetchone()
            if row is None or row["schema_version"] != 1:
                raise ObserverError("UNSUPPORTED_SCHEMA", "report")
            agg = db.execute("""SELECT count(*) AS samples, MAX(rss_bytes) AS peak_rss_bytes,
                       MAX(cpu_percent) AS peak_cpu_percent, MAX(children_count) AS max_children,
                       MAX(elapsed_ms) AS elapsed_ms FROM samples""").fetchone()
            events = db.execute("SELECT data FROM events ORDER BY seq").fetchall()
            counts = {}
            for entry in events:
                record = json.loads(entry["data"])
                kind = record.get("code", "UNKNOWN")
                counts[kind] = counts.get(kind, 0) + 1
            result = {
                "schema_version": 1,
                "report_type": "BLACKBOX_PROCESS_OBSERVATION",
                "session_id": row["session_id"], "pid": row["pid"],
                "state": "closed" if row["ended_utc"] else "interrupted_or_live",
                "exit_code": row["exit_code"] or "UNKNOWN",
                "started_utc": row["started_utc"], "ended_utc": row["ended_utc"],
                "samples": agg["samples"],
                "peak_rss_bytes": agg["peak_rss_bytes"],
                "peak_cpu_percent": agg["peak_cpu_percent"],
                "max_children": agg["max_children"], "elapsed_ms": agg["elapsed_ms"],
                "observation_errors": counts,
                "root_cause": "UNKNOWN", "root_cause_confidence": "UNKNOWN",
                "execution_attested": False,
                "limitations": ["external_sampling_only", "no_proof_of_memory_leak",
                                "not_an_application_internal_trace"],
            }
            bounded(result, max_bytes=65536)
            return result
    except (sqlite3.Error, ValueError, KeyError, TypeError, json.JSONDecodeError):
        raise ObserverError("INVALID_DATA", "report") from None


def _human_html(report: dict) -> str:
    """Portable, static, bilingual human report. No JS, CDN or private runtime.

    User-supplied IDs/error codes are escaped; every outcome is an observation,
    never a claim about the target application's internal root cause.
    """
    def safe(value: object) -> str:
        return escape(str(value if value is not None else "not available / нет данных"),
                      quote=True)

    def metric(label: str, value: object, unit: str = "") -> str:
        suffix = (" " + unit) if value is not None and unit else ""
        rendered = safe(value) + suffix
        return ('<div class="metric"><span class="key">' + label +
                '</span><strong>' + rendered + '</strong></div>')

    state = report["exit_code"]
    status_descriptions = {
        "COMPLETED": "Session stopped normally / Наблюдение остановлено",
        "INTERRUPTED": "Session interrupted / Сеанс прерван",
        "PROCESS_EXITED": "Observed process exited / Процесс завершился",
        "PID_REUSED": "PID changed identity / PID использован повторно",
        "ACCESS_DENIED": "OS access denied / Доступ запрещён",
        "SAMPLE_UNAVAILABLE": "Sample unavailable / Измерение недоступно",
        "STORAGE_ERROR": "Storage error / Ошибка сохранения",
        "UNKNOWN": "Unknown status / Статус неизвестен",
    }
    errors = report.get("observation_errors", {})
    errors_html = "".join(
        "<tr><td>" + safe(code) + "</td><td>" + safe(count) + "</td></tr>"
        for code, count in sorted(errors.items())
    ) or "<tr><td colspan='2'>None recorded / Нет зарегистрированных</td></tr>"
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>BlackBox Process Observation</title>"
        "<style>"
        "body{font:15px system-ui,Segoe UI,Tahoma,sans-serif;max-width:960px;"
        "margin:28px auto;padding:0 18px;color:#302c43;background:#fff7e4}"
        "h1{border-bottom:5px solid #087f7b;padding-bottom:12px}"
        "h2{margin-top:26px;font-size:18px}"
        ".summary{background:#d8f3e8;border:2px solid #056c6d;padding:15px}"
        ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(185px,1fr));gap:10px}"
        ".metric{background:#fff;border:2px solid #a69caa;padding:12px}"
        ".key{display:block;color:#605e6b;font-size:12px;margin-bottom:7px}"
        "strong{font-size:18px}table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #bcb6c4;text-align:left;padding:9px}"
        "th{background:#ead5c6}.warning{border-left:5px solid #ec725d;"
        "background:#fff0e5;padding:12px}"
        "</style></head><body>"
        "<h1>BlackBox Process Observation</h1>"
        "<p>Локальный отчёт о наблюдении / Local observation report</p>"
        "<div class='summary'><strong>" + safe(state) + "</strong><p>" +
        status_descriptions.get(state, "Unrecognized observer state / Неизвестное состояние") +
        "</p></div>"
        "<h2>Измерения / Measurements</h2><div class='grid'>" +
        metric("Измерений / Samples", report["samples"]) +
        metric("CPU (макс.) / Peak CPU", report["peak_cpu_percent"], "%") +
        metric("RAM RSS (макс.) / Peak RSS", report["peak_rss_bytes"], "bytes") +
        metric("Дочерние процессы / Max children", report["max_children"]) +
        metric("Длительность / Elapsed", report["elapsed_ms"], "ms") +
        "</div><h2>Сеанс / Session</h2><div class='grid'>" +
        metric("Начало UTC / Started", report["started_utc"]) +
        metric("Конец UTC / Ended", report["ended_utc"]) +
        metric("Идентификатор / Session ID", report["session_id"]) +
        "</div>"
        "<h2>Ошибки наблюдателя / Observer events</h2>"
        "<table><thead><tr><th>Код / Code</th><th>Количество / Count</th>"
        "</tr></thead><tbody>" + errors_html + "</tbody></table>"
        "<h2>Ограничения / Limitations</h2>"
        "<p class='warning'><strong>Причина ошибки приложения не установлена / "
        "Application root cause not determined.</strong><br>"
        "CPU, RAM and I/O are external system measurements, not proof "
        "of a memory leak, deadlock or internal application defect. "
        "Высокая нагрузка не доказывает сбой, утечку памяти или зависание.</p>"
        "<p>Работает автономно; внешние ресурсы, AI и закрытая платформа "
        "не требуются / Offline: no external resources required.</p>"
        "</body></html>"
    )


def write_report(folder: Path) -> dict:
    folder = Path(folder)
    report = summarize(folder)
    # New report artifacts are session-local only; no arbitrary destination paths.
    if folder.is_symlink():
        raise ObserverError("STORAGE_ERROR", "storage")
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    path = folder / "report.json"
    if path.exists() or path.is_symlink():
        raise ObserverError("STORAGE_ERROR", "storage")
    try:
        with path.open("xb") as out:
            out.write(payload)
        html = _human_html(report)
        with (folder / "report.html").open("x", encoding="utf-8") as output:
            output.write(html)
    except OSError:
        raise ObserverError("STORAGE_ERROR", "storage") from None
    return {"report_sha256": hashlib.sha256(payload).hexdigest(),
            "report_file": "report.json", "sample_count": report["samples"],
            "session_id": report["session_id"]}


def compare(before: Path, after: Path) -> dict:
    a, b = summarize(before), summarize(after)
    values = {}
    for key in ("samples", "peak_rss_bytes", "peak_cpu_percent", "max_children", "elapsed_ms"):
        av, bv = a[key], b[key]
        values[key] = {"before": av, "after": bv, "delta": bv-av if av is not None and bv is not None else None}
    return {"schema_version": 1, "comparison": "OBSERVATION_ONLY",
            "before": a["session_id"], "after": b["session_id"],
            "metrics": values, "regression_proven": False,
            "reason": "sampling data alone does not establish regression or root cause"}
