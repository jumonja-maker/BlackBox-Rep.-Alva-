"""Offline reports: summaries do not contain command lines, secrets, file paths."""
from __future__ import annotations
from html import escape
import hashlib
from contextlib import closing
import json
import os
import tempfile
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
            # Stream the SQLite cursor: long recordings must not materialize
            # every event as a Python list. User problem markers are not faults.
            counts = {}
            actions, completed_total, malformed_actions = [], 0, 0
            for entry in db.execute("SELECT data FROM events ORDER BY seq"):
                record = json.loads(entry["data"])
                if type(record) is not dict:
                    raise ObserverError("INVALID_DATA", "report")
                if record.get("kind") == "action_marker" and record.get("event") == "ACTION_COMPLETED":
                    # These are recorded USER commands, not independently attested OS events.
                    value = record.get("duration_ns")
                    action_id = record.get("action_id")
                    if (type(value) is int and 0 <= value <= 30 * 86400 * 1_000_000_000 and
                            type(action_id) is str and len(action_id) == 32 and
                            all(c in "0123456789abcdef" for c in action_id)):
                        completed_total += 1
                        if len(actions) < 50:
                            actions.append({"action_id": action_id,
                                            "duration_ms": round(value / 1_000_000, 3),
                                            "source": "RECORDED_USER_COMMAND_NOT_ATTESTED"})
                    else:
                        malformed_actions += 1
                if record.get("kind") in ("observer_warning", "observer_error"):
                    code = record.get("code", "UNKNOWN")
                    if type(code) is not str or len(code) > 64:
                        raise ObserverError("INVALID_DATA", "report")
                    counts[code] = counts.get(code, 0) + 1
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
                "completed_actions_total": completed_total,
                "completed_actions": actions,
                "completed_actions_omitted": max(0, completed_total - len(actions)),
                "invalid_action_markers": malformed_actions,
                "action_evidence": "RECORDED_USER_COMMAND_NOT_ATTESTED",
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
    actions = report.get("completed_actions", [])
    actions_html = "".join(
        "<tr><td>" + safe(item["action_id"][:12]) + "</td><td>" +
        safe(item["duration_ms"]) + "</td></tr>" for item in actions
    ) or "<tr><td colspan='2'>No completed action / Нет завершённых действий</td></tr>"
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
        "<h2>Замеры действий / Action intervals</h2>"
        "<p>Recorded user commands, not OS-attested function timings / "
        "Команды пользователя, не подтверждённое профилирование функции.</p>"
        "<p>Total / Всего: " + safe(report.get("completed_actions_total", 0)) +
        "; omitted from preview / скрыто: " + safe(report.get("completed_actions_omitted", 0)) + "</p>"
        "<table><thead><tr><th>Action ID</th><th>Duration / Длительность (ms)</th>"
        "</tr></thead><tbody>" + actions_html + "</tbody></table>"
        "<h2>Ошибки наблюдателя / Observer events</h2>"
        "<table><thead><tr><th>Код / Code</th><th>Количество / Count</th>"
        "</tr></thead><tbody>" + errors_html + "</tbody></table>"
        "<h2>Ограничения / Limitations</h2>"
        "<p class='warning'><strong>Причина ошибки приложения не установлена / "
        "Application root cause not determined.</strong><br>"
        "CPU, RAM and I/O are external system measurements, not proof "
        "of a memory leak, deadlock or internal application defect. "
        "Высокая нагрузка не доказывает сбой, утечку памяти или зависание.</p>"
        "<p>Работает автономно; дополнительные сервисы не требуются / "
        "Offline: no external resources required.</p>"
        "</body></html>"
    )


def write_report(folder: Path) -> dict:
    folder = Path(folder)
    report = summarize(folder)
    # New report artifacts are session-local only; no arbitrary destination paths.
    if folder.is_symlink():
        raise ObserverError("STORAGE_ERROR", "storage")
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    json_path = folder / "report.json"
    html_path = folder / "report.html"
    if any(p.exists() or p.is_symlink() for p in (json_path, html_path)):
        raise ObserverError("STORAGE_ERROR", "storage")
    staged = []
    published = []
    try:
        for content, encoding in ((payload, None),
                                  (_human_html(report).encode("utf-8"), "utf-8")):
            fd, tmp_name = tempfile.mkstemp(prefix=".blackbox-report-",
                                             suffix=".tmp", dir=folder)
            tmp = Path(tmp_name)
            staged.append(tmp)
            with os.fdopen(fd, "wb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
        # No TOCTOU overwrite: hard-link exclusive publishing refuses an
        # existing destination even if another process created it after preflight.
        # Staging files are on the same volume. JSON remains the last marker.
        for source, target in ((staged[1], html_path), (staged[0], json_path)):
            os.link(source, target)
            published.append(target)
    except OSError:
        for target in reversed(published):
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass  # Preserve the first failure; warn caller of incomplete publish.
        raise ObserverError("STORAGE_ERROR", "storage") from None
    finally:
        for tmp in staged:
            tmp.unlink(missing_ok=True)
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
