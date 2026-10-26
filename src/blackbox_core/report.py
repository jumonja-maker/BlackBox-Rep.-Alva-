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
from .experiments import ExperimentAccumulator
from .detailed_capture import summarize_detail
from .detail_analysis import analyze_detail_threads
from .storage import _open_ro


def summarize(folder: Path) -> dict:
    try:
        with closing(_open_ro(Path(folder))) as db:
            row = db.execute("SELECT * FROM metadata LIMIT 1").fetchone()
            if row is None or row["schema_version"] != 1:
                raise ObserverError("UNSUPPORTED_SCHEMA", "report")
            # SQLite schema1 is not STRICT: an imported file may carry
            # "bogus" TEXT in INTEGER/REAL counter columns. MAX() can then
            # select text as a fake peak instead of rejecting it. Validate
            # all selected aggregates in the SAME full-table scan.
            integer_fields=("rss_bytes","num_threads","read_bytes","write_bytes","children_count")
            invalid=["typeof(elapsed_ms)!='integer' OR elapsed_ms<0"]
            invalid.extend(f"({name} IS NOT NULL AND (typeof({name})!='integer' OR {name}<0))"
                           for name in integer_fields)
            invalid.append("(cpu_percent IS NOT NULL AND ("
                           "typeof(cpu_percent) NOT IN ('integer','real') OR "
                           "cpu_percent<0 OR cpu_percent>1e308))")
            sql=("SELECT count(*) AS samples, MAX(rss_bytes) AS peak_rss_bytes, "
                 "MAX(cpu_percent) AS peak_cpu_percent, MAX(children_count) AS max_children, "
                 "MAX(elapsed_ms) AS elapsed_ms, "
                 "coalesce(sum(CASE WHEN " + " OR ".join(invalid) +
                 " THEN 1 ELSE 0 END),0) AS invalid_counter_rows FROM samples")
            agg=db.execute(sql).fetchone()
            if agg["invalid_counter_rows"]:
                raise ObserverError("INVALID_DATA","report")
            # Stream the SQLite cursor: long recordings must not materialize
            # every event as a Python list. User problem markers are not faults.
            counts = {}
            actions, completed_total, malformed_actions = [], 0, 0
            experiments = ExperimentAccumulator()
            incident_count, incident_preview, sampling_gaps = 0, [], 0
            busy_ticks, busy_episodes, bad_busy_events = 0, 0, 0
            truncated_busy_episodes = 0
            extended_sample_spacing, largest_spacing, invalid_spacing = 0, None, 0
            worker_health, invalid_worker_health = None, 0
            for entry in db.execute("SELECT data FROM events ORDER BY seq"):
                record = json.loads(entry["data"])
                if type(record) is not dict:
                    raise ObserverError("INVALID_DATA", "report")
                experiments.observe(record)
                if record.get("kind") == "sampling_gap" and record.get("code") == "SAMPLING_GAP_OBSERVED":
                    sampling_gaps += 1
                if (record.get("kind") == "sampling_gap" and
                        record.get("code") == "BASE_TIMER_CALLBACK_SKIPPED_BUSY"):
                    missed = record.get("missed_callback_count")
                    if (type(missed) is int and 1 <= missed <= 1_000_000 and
                            record.get("source") == "QT_TIMER_SCHEDULER" and
                            record.get("verification_class") == "OBSERVED_GUI_CALLBACK_ONLY"):
                        busy_ticks += missed
                        busy_episodes += 1
                        if record.get("count_truncated") is True:
                            truncated_busy_episodes += 1
                    else:
                        bad_busy_events += 1
                if (record.get("kind") == "sampling_gap" and
                        record.get("code") == "EXTENDED_MONOTONIC_SAMPLE_SPACING"):
                    previous = record.get("previous_elapsed_ms")
                    current = record.get("current_elapsed_ms")
                    spacing = record.get("observed_spacing_ms")
                    configured = record.get("configured_interval_ms")
                    threshold = record.get("threshold_ms")
                    if (all(type(x) is int for x in (
                            previous, current, spacing, configured, threshold)) and
                            previous >= 0 and current > previous and
                            spacing == current - previous and 1 <= configured <= 60000 and
                            threshold == max(2 * configured, configured + 500) and
                            spacing > threshold and
                            record.get("source") == "BLACKBOX_MONOTONIC_SAMPLE_CLOCK" and
                            record.get("verification_class") ==
                            "DERIVED_ADJACENT_OS_COUNTER_SNAPSHOTS" and
                            record.get("missing_sample_count") is None):
                        extended_sample_spacing += 1
                        largest_spacing = max(largest_spacing or 0, spacing)
                    else:
                        invalid_spacing += 1
                if (record.get("kind") == "worker_health" and
                        record.get("code") == "BASE_SAMPLE_WORKER_TIMING_SUMMARY"):
                    numeric = ("completed_workers", "max_sensor_ms", "max_sqlite_ms",
                               "max_signal_delivery_ms", "comparable_sample_pairs",
                               "extended_sample_pairs", "interval_changes")
                    numbers = [record.get(key) for key in numeric]
                    if (worker_health is None and
                            all(type(value) is int and 0 <= value <= 1_000_000_000
                                for value in numbers) and numbers[0] > 0 and
                            numbers[5] <= numbers[4] and
                            (record.get("max_observed_spacing_ms") is None or
                             (type(record.get("max_observed_spacing_ms")) is int and
                              0 <= record["max_observed_spacing_ms"] <= 86400000)) and
                            record.get("source") == "PYTHON_MONOTONIC_BRACKETS" and
                            record.get("verification_class") ==
                            "INTERNAL_WORKER_TIMING_DERIVED"):
                        worker_health = {key: record[key] for key in numeric}
                        worker_health["max_observed_spacing_ms"] = (
                            record.get("max_observed_spacing_ms"))
                        worker_health["source"] = "UNVERIFIED_SAVED_WORKER_TIMING"
                    else:
                        invalid_worker_health += 1
                if (record.get("kind") == "incident_boundary" and
                        record.get("code") == "AUTO_INCIDENT_COMPLETED"):
                    # Imported event strings cannot attest OS responsiveness.
                    incident_count += 1
                    if len(incident_preview) < 20:
                        incident_preview.append({
                            "trigger_code": "CPU_SUSTAINED",
                            "first_sample_seq": record.get("first_sample_seq"),
                            "last_sample_seq": record.get("last_sample_seq"),
                            "status": record.get("status"),
                            "verification_class": "UNVERIFIED_SESSION_RECORD",
                        })
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
                "experiment_summary": experiments.result(),
                "detailed_capture": summarize_detail(folder),
                "thread_cpu_analysis": (analyze_detail_threads(folder)
                                        if (Path(folder) / "detail-v2.sqlite3").is_file()
                                        else None),
                "automatic_incident_count": incident_count,
                "automatic_incident_preview": incident_preview,
                "automatic_incidents_omitted": max(0, incident_count-len(incident_preview)),
                "sampling_gap_count": sampling_gaps,
                "extended_monotonic_spacing_count": extended_sample_spacing,
                "max_extended_monotonic_spacing_ms": largest_spacing,
                "invalid_monotonic_spacing_events": invalid_spacing,
                "monotonic_spacing_provenance": "DERIVED_SAVED_SNAPSHOT_SPACING",
                "worker_health_summary": worker_health,
                "invalid_worker_health_events": invalid_worker_health,
                "observed_busy_timer_callbacks": busy_ticks,
                "observed_busy_timer_episodes": busy_episodes,
                "invalid_busy_timer_events": bad_busy_events,
                "truncated_busy_timer_episodes": truncated_busy_episodes,
                "busy_timer_coverage": "OBSERVED_QT_CALLBACK_ONLY",
                "busy_timer_limitations": "QT_COALESCED_CALLBACKS_NOT_COUNTED",
                "automatic_event_provenance": "UNVERIFIED_STORED_EXTERNAL_COUNTERS",
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
    deep = report.get("detailed_capture")
    provenance = deep.get("provenance") if isinstance(deep, dict) else None
    provenance_html = ""
    if isinstance(provenance, dict):
        clock = provenance.get("clock_mapping")
        latest = provenance.get("latest_quality")
        mapping = (" / " + safe(clock.get("utc_anchor_iso")) +
                   " · ±" + safe(clock.get("uncertainty_ns_at_anchor")) +
                   " ns (anchor only; system UTC clock may adjust)"
                   if isinstance(clock, dict) else
                   " / No UTC mapping in this legacy detailed sidecar")
        statuses = (
            " · ".join(safe(k.removesuffix("_status")) + ": " + safe(v)
                       for k, v in sorted(latest.get("measurement_status", {}).items()))
            if isinstance(latest, dict) else
            "No per-field measurement status in this detailed sidecar")
        provenance_html = (
            "<h3>Timestamp and measurement quality / Время и качество</h3>"
            "<p>Contract: " + safe(provenance.get("contract_status")) +
            " · quality coverage: " + safe(provenance.get("quality_coverage")) +
            mapping + "</p><p>Latest measurement: " + statuses + "</p>"
            "<p>Stored file claims are not independently attested on import: " +
            safe(provenance.get("file_trust")) + ".</p>"
            "<p>PSUTIL external counters; OS-observed metrics do not prove "
            "Windows hang, deadlock or application-internal cause.</p>")
    detail_html = (
        "<p>Detailed mode not enabled / Углублённый режим не включён.</p>"
        if not isinstance(deep, dict) else
        "<p>Independent v2 sidecar, read-only external counters. "
        "No stacks, no wait chains, no OS-authenticated root cause.</p>"
        "<div class='grid'>" +
        metric("Detailed samples / Отсчётов", deep.get("samples")) +
        metric("Thread records / Потоки", deep.get("thread_records")) +
        metric("Child records / Потомки", deep.get("child_records")) +
        metric("Peak Private Bytes", deep.get("peak_private_bytes"), "bytes") +
        metric("Peak handles / Дескрипторы", deep.get("peak_handles")) +
        metric("Sensor errors / Ошибки датчика", deep.get("sensor_errors")) +
        "</div><p>Status: " + safe(deep.get("status")) + "</p>" +
        provenance_html
    )
    thread_cpu = report.get("thread_cpu_analysis")
    thread_rows = ""
    if isinstance(thread_cpu, dict):
        thread_rows = "".join(
            "<tr><td>" + safe(item.get("tid")) + "</td><td>" +
            safe(item.get("segment_start_seq")) + "</td><td>" +
            safe(item.get("cpu_percent")) + "</td><td>" +
            safe(item.get("peak_cpu_percent")) + "</td><td>" +
            safe(item.get("observed_pairs")) + "</td></tr>"
            for item in thread_cpu.get("top_threads", [])[:16]
            if isinstance(item, dict)
        )
    thread_html = (
        "<p>No detailed thread CPU data recorded / Нет замеров CPU потоков.</p>"
        if not isinstance(thread_cpu, dict) else
        "<p>Derived single-core-equivalent CPU% from adjacent TID snapshots; "
        "TID reuse between samples cannot be ruled out. "
        "No proof of hangs, deadlocks or root cause. / "
        "CPU% вычислен из соседних замеров TID; повторное использование TID "
        "не исключено.</p>"
        "<p>Status: " + safe(thread_cpu.get("status")) +
        " · Source: " + safe(thread_cpu.get("source_kind")) +
        " · Verification: " + safe(thread_cpu.get("verification_class")) +
        " · Warnings: " + safe(", ".join(thread_cpu.get("warnings", []))) + "</p>"
        "<table><thead><tr><th>TID</th><th>Segment first seq</th>"
        "<th>Mean CPU%</th><th>Peak CPU%</th><th>Valid pairs</th>"
        "</tr></thead><tbody>" +
        (thread_rows or "<tr><td colspan='5'>No comparable intervals</td></tr>") +
        "</tbody></table>"
    )
    incidents = report.get("automatic_incident_preview", [])
    incidents_html = "".join(
        "<tr><td>" + safe(e.get("trigger_code")) + "</td><td>" +
        safe(e.get("first_sample_seq")) + "</td><td>" +
        safe(e.get("last_sample_seq")) + "</td><td>" +
        safe(e.get("status")) + "</td></tr>" for e in incidents
    ) or "<tr><td colspan='4'>No incidents / Нет инцидентов</td></tr>"
    errors_html = "".join(
        "<tr><td>" + safe(code) + "</td><td>" + safe(count) + "</td></tr>"
        for code, count in sorted(errors.items())
    ) or "<tr><td colspan='2'>None recorded / Нет зарегистрированных</td></tr>"
    actions = report.get("completed_actions", [])
    experiment_groups = report.get("experiment_summary", {}).get("experiments", [])
    experiment_html = "".join(
        "<tr><td>" + safe(e["experiment_id"][:12]) + "</td><td>" +
        safe(e["repeats"]) + "</td><td>" +
        safe(e["duration_ms"]["median"]) + "</td><td>" +
        safe(e["duration_ms"]["p95"]) + "</td><td>" +
        safe(e["duration_ms"]["mad"]) + "</td><td>" +
        safe(", ".join(e["warnings"]) or "—") + "</td></tr>"
        for e in experiment_groups
    ) or "<tr><td colspan='6'>No experiment / Нет повторов</td></tr>"
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
        metric("Занятый сборщик / Busy timer callbacks",
               report.get("observed_busy_timer_callbacks")) +
        metric("Удлинённые интервалы / Extended sample pairs",
               report.get("extended_monotonic_spacing_count")) +
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
        "<h2>Эксперименты / Repeat experiments</h2>"
        "<p>Only completed USER-command intervals. MAD is median absolute "
        "deviation. Differences do not prove speedup or causal improvement.</p>"
        "<table><thead><tr><th>Experiment</th><th>Repeats</th>"
        "<th>Median ms</th><th>p95 ms</th><th>MAD ms</th>"
        "<th>Coverage / Warnings</th></tr></thead><tbody>" +
        experiment_html + "</tbody></table>"
        "<h2>Углублённые данные / Detailed process capture (opt-in)</h2>" +
        detail_html +
        "<h2>Потоки / Per-thread CPU (derived)</h2>" + thread_html +
        "<h2>Фактические интервалы / Actual snapshot spacing</h2>"
        "<p>Extended adjacent monotonic sample intervals: " +
        safe(report.get("extended_monotonic_spacing_count")) +
        " · maximum extended spacing (ms): " +
        safe(report.get("max_extended_monotonic_spacing_ms")) +
        " · invalid imported spacing events: " +
        safe(report.get("invalid_monotonic_spacing_events")) +
        ". Consecutive OS-counter snapshots are separated in actual "
        "monotonic time; the number of missing scheduled samples, Windows "
        "hang status and delay cause are UNKNOWN. Interval-change pairs "
        "are not classified. / Известна только реальная пауза между "
        "снимками счётчиков, количество несделанных замеров неизвестно.</p>"
        "<h2>Здоровье фонового сборщика / Base worker timing</h2>"
        "<p>Worker timing: " + safe(report.get("worker_health_summary")) +
        " · invalid summaries: " +
        safe(report.get("invalid_worker_health_events")) +
        ". Python monotonic brackets for sensor, SQLite and signal "
        "delivery, not Windows deadline proof. Stored claims not attested.</p>"
        "<h2>Пропущенные такты GUI / Skipped timer callbacks</h2>"
        "<p>Count: " + safe(report.get("observed_busy_timer_callbacks")) +
        " · episodes: " + safe(report.get("observed_busy_timer_episodes")) +
        " · invalid events: " + safe(report.get("invalid_busy_timer_events")) +
        " · truncated episodes: " + safe(report.get("truncated_busy_timer_episodes")) +
        ". Only delivered Qt timer callbacks rejected by a busy sample worker "
        "are counted. Coalesced callbacks and actual OS sample gaps are NOT "
        "measured by this counter. / Учтены только доставленные вызовы таймера "
        "при занятом сборщике. Пропущенные Qt вызовы и реальные пропуски "
        "измерений ОС неизвестны.</p>"
        "<h2>Автоинциденты / Automatic incidents (opt-in)</h2>"
        "<p>Stored external-counter observations only. CPU threshold and "
        "sampling gaps are not evidence of a Windows hang or internal defect."
        " / Только внешние счётчики, причина не доказана.</p>"
        "<p>Captured / Захвачено: " + safe(report.get("automatic_incident_count", 0)) +
        "; hidden / скрыто: " + safe(report.get("automatic_incidents_omitted", 0)) +
        "; gaps / пропуски: " + safe(report.get("sampling_gap_count", 0)) + "</p>"
        "<table><thead><tr><th>Trigger</th><th>First seq</th>"
        "<th>Last seq</th><th>Status</th></tr></thead><tbody>" +
        incidents_html + "</tbody></table>"
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
