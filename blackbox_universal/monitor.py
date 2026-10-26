"""Qt facade over the independent BLACK.BOX process-observation core.

No process injection, modification or external runtime is required.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any

from blackbox_core.actions import ActionCycle, ActionError
from blackbox_core.incidents import IncidentCapture
from blackbox_core.detailed_capture import DetailedCapture, DetailSensorError
from blackbox_core.contracts import ObserverError, event
from blackbox_core.probe import PsutilProbe, list_processes
from blackbox_core.report import write_report
from blackbox_core.storage import SessionStore
from blackbox_core.sampling_health import MonotonicSampleCadence, BaseWorkerTiming
from blackbox_core.windows_observer import WindowCapture


def utc_stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def available_processes(limit: int = 500) -> list[dict]:
    """Enumerate all discovered names/PIDs; sample RSS for a bounded subset.

    Limiting the returned list to 500 alphabetic names made every later
    process unselectable, even with an exact PID query. Never silently drop
    discovered targets; limit the expensive RSS/status inspection instead.
    """
    # Legacy callers pass limit=10000. It is a *requested* inspection
    # budget, never permission to perform 10,000 costly psutil probes.
    # Preserve the old public API while capping actual RAM/status lookups;
    # process names and PIDs remain searchable beyond the inspection budget.
    if type(limit) is not int or not 1 <= limit <= 10000:
        raise ValueError("INVALID_PROCESS_DETAIL_LIMIT")
    inspection_budget = min(limit, 500)
    try:
        import psutil
    except ImportError:
        return []
    rows: list[dict] = []
    discovered = sorted(list_processes(), key=lambda row: (row["name"].casefold(), row["pid"]))
    for index, item in enumerate(discovered):
        if index < inspection_budget:
            try:
                proc = psutil.Process(item["pid"])
                memory = proc.memory_info()
                status = proc.status()
                rss = round(memory.rss / 1048576, 1)
            except (psutil.Error, OSError):
                rss, status = None, "unknown"
        else:
            # Unknown is NOT 0 MiB. Exact-PID/name search can still attach
            # these processes, even though we did not fetch their RSS.
            rss, status = None, "not sampled"
        rows.append({
            "pid": item["pid"], "name": item["name"],
            "rss_mb": rss, "status": str(status)[:32],
        })
    return rows


def _default_sessions_root() -> Path:
    return Path.home() / "Documents" / "BLACK.BOX Universal" / "sessions"


class ReadOnlyProbe:
    """A durable recording per explicit Start; all GUI views are read-only."""

    def __init__(self, output_root: Path | None = None, *,
                 background_events: bool = False) -> None:
        if type(background_events) is not bool:
            raise ValueError("INVALID_EVENT_WRITER_POLICY")
        self.background_events = background_events
        self.output_root = Path(output_root) if output_root else _default_sessions_root()
        self.pid: int | None = None
        self.name = ""
        self.active = False
        self.started_at: str | None = None
        self._core: PsutilProbe | None = None
        self._store: SessionStore | None = None
        self.session_folder: Path | None = None
        self.session_state = "NO_SESSION"
        self.report_result: dict | None = None
        self.last_error: str | None = None
        self.history: deque[dict] = deque(maxlen=3600)
        self.total_samples = 0
        self.busy_timer_callbacks = 0
        self.busy_timer_episodes = 0
        self._sample_cadence = MonotonicSampleCadence()
        self._worker_timing = BaseWorkerTiming()
        self.last_elapsed_ms: int | None = None
        self.events: deque[dict] = deque(maxlen=300)
        self.actions = ActionCycle()
        self.incident_capture: IncidentCapture | None = None
        self.detail_policy={};self._stopped_detail=None
        self.incident_events=deque(maxlen=32)
        self.detailed_capture: DetailedCapture | None = None
        # Retain ownership of a worker whose blocking OS call outlived stop().
        self._pending_detailed: DetailedCapture | None = None
        self._pending_v2 = None
        self.window_capture = None
        self._pending_windows = None
        self._recording_origin_ns: int | None = None

    def _reap_detailed(self) -> None:
        """Never rebind a session while its previous sensor still owns SQLite."""
        if self._pending_windows is not None:
            if not self._pending_windows.stop(timeout=0):
                raise RuntimeError("WINDOW_SENSOR_STOP_PENDING")
            self._pending_windows=None
        if self._pending_v2 is not None:
            if self._pending_v2.thread.is_alive():
                raise RuntimeError("SCHEMA2_WRITER_STOP_PENDING")
            self._pending_v2 = None
        pending = self._pending_detailed
        if pending is not None:
            if not pending.stop(timeout=0):
                raise RuntimeError("DETAILED_CAPTURE_STOP_PENDING")
            self._pending_detailed = None

    def _event(self, code: str, detail: str = "") -> None:
        entry = {"timestamp_utc": utc_stamp(), "code": code,
                 "detail": detail[:120]}
        self.events.append(entry)
        if self._store is not None:
            try:
                self._store.write_lifecycle_event({"kind": "observer_lifecycle",
                                         "code": code,
                                         "timestamp_utc": entry["timestamp_utc"],
                                         "detail": entry["detail"]})
            except ObserverError:
                self.last_error = "STORAGE_ERROR"
                self.events.append({"timestamp_utc": utc_stamp(),
                                    "code": "STORAGE_ERROR",
                                    "detail": "Event persistence unavailable"})

    def _optional_sensor_error(self, sensor_id: str, code: str) -> None:
        if self._store is not None and self._store.v2 is not None:
            try:
                self._store.v2.submit("error",{"time_ns":time.monotonic_ns(),
                                              "sensor_id":sensor_id,"code":code})
            except ObserverError:
                # A failed optional sink must not prevent primary shutdown.
                self.last_error="STORAGE_ERROR"

    def attach(self, pid: int) -> None:
        if self.active:
            raise RuntimeError("Stop observation before switching targets.")
        self._reap_detailed()
        core = PsutilProbe(pid)
        self._core = core
        self.pid = pid
        try:
            self.name = core.process.name()[:96]
        except Exception:
            self.name = "Unknown"
        self.started_at = None
        self.session_folder = None
        self.session_state = "NO_SESSION"
        self.report_result = None
        self.last_error = None
        self.history.clear()
        self.total_samples = 0
        self.busy_timer_callbacks = 0
        self.busy_timer_episodes = 0
        self._sample_cadence = MonotonicSampleCadence()
        self._worker_timing = BaseWorkerTiming()
        self.last_elapsed_ms = None
        self.events.clear()
        self.actions = ActionCycle()
        self.incident_capture = None
        self.detailed_capture = None
        self.window_capture = None
        self._recording_origin_ns = None
        self._event("PROCESS_SELECTED", f"{self.name} · PID {pid}")

    def start(self) -> None:
        self._reap_detailed()
        if self.pid is None:
            raise RuntimeError("Choose an accessible process first.")
        if self.active:
            return
        # Fail closed if the selected PID was recycled after Attach.
        core = PsutilProbe(self.pid)
        if self._core is not None and abs(core.created - self._core.created) > 0.000001:
            raise ObserverError("PID_REUSED", "attach")
        root = self.output_root
        if root.is_symlink():
            raise RuntimeError("Session root must not be a symlink.")
        root.mkdir(parents=True, exist_ok=True)
        if not root.is_dir() or root.is_symlink():
            raise RuntimeError("Session root is unavailable.")
        store = SessionStore(root, self.pid)
        try:
            store.enable_v2(pid=self.pid, created=core.created,
                            name=self.name if self.name!="Unknown" else None,
                            origin_ns=core.origin_ns)
        except Exception:
            store.close()
            raise
        if self.background_events:
            try:
                store.enable_background_events()
            except (ObserverError, OSError, RuntimeError):
                store.close()
                raise
        self._core = core
        self._store = store
        self.session_folder = store.folder
        self.session_state = "RECORDING"
        self.report_result = None
        self.last_error = None
        self.history.clear()
        self.total_samples = 0
        self.busy_timer_callbacks = 0
        self.busy_timer_episodes = 0
        self._sample_cadence = MonotonicSampleCadence()
        self._worker_timing = BaseWorkerTiming()
        self.last_elapsed_ms = None
        self.events.clear()
        self.actions = ActionCycle()
        self.incident_capture = None
        self.detailed_capture = None
        self.window_capture = None
        # PsutilProbe computes each elapsed_ms from its own monotonic origin.
        self._recording_origin_ns = core.origin_ns
        self._stopped_detail=None;self.incident_events.clear()
        self.active = True
        self.started_at = utc_stamp()
        self._event("OBSERVATION_STARTED")

    def stop(self, reason: str = "USER_STOPPED", *,
             defer_report: bool = False) -> None:
        if not self.active or self._store is None:
            return
        status = {
            "USER_STOPPED": "COMPLETED", "UI_CLOSED": "INTERRUPTED",
            "PROCESS_EXITED": "PROCESS_EXITED", "PID_REUSED": "PID_REUSED",
            "ACCESS_DENIED": "ACCESS_DENIED", "SAMPLE_UNAVAILABLE": "SAMPLE_UNAVAILABLE",
            "STORAGE_ERROR": "STORAGE_ERROR",
            "TIME_LIMIT_REACHED":"TIME_LIMIT_REACHED", "STORAGE_LIMIT_REACHED":"STORAGE_LIMIT_REACHED",
        }.get(reason, "INTERRUPTED")
        # Separate sidecar worker is owned by this recording and stopped first.
        if self.window_capture is not None:
            self.set_window_capture(False)
        if self.detailed_capture is not None:
            capture = self.detailed_capture
            if not capture.stop(timeout=0.5):
                self._pending_detailed = capture
                self.last_error = "DETAILED_CAPTURE_STOP_PENDING"
                self._optional_sensor_error("PSUTIL_DETAILED","DETAILED_CAPTURE_STOP_PENDING")
                capture.session_writer = None
            self.detailed_capture = None
        # Close a partially captured CPU episode as incomplete, not successful.
        if self.incident_capture is not None:
            capture = self.incident_capture
            boundaries = (capture.process_exited(elapsed_ms=max(0,(time.monotonic_ns()-self._recording_origin_ns)//1_000_000),
                sample_seq=self.total_samples or 1) if reason=="PROCESS_EXITED" else [])
            boundaries += capture.stop(elapsed_ms=self.last_elapsed_ms or 0, sample_seq=self.total_samples or 1)
            for finding in boundaries:
                try:
                    self._store.write_event(finding)
                except ObserverError:
                    self.last_error = "STORAGE_ERROR"
        # Preserve an explicit incomplete interval, not a fictional complete action.
        try:
            self.actions.abort(self._persist_action,
                               "PROCESS_UNAVAILABLE" if reason in ("PROCESS_EXITED", "PID_REUSED") else "RECORDING_STOPPED")
        except (ObserverError, ActionError):
            self.last_error = "STORAGE_ERROR"
        # Save bounded worker health before marking this recording ended.
        # An unavailable health write must not become a fictional COMPLETED.
        worker_summary = self._worker_timing.event(self._sample_cadence)
        if worker_summary is not None:
            try:
                self._store.write_event(worker_summary)
            except ObserverError:
                self.last_error = "STORAGE_ERROR"
                status = "STORAGE_ERROR"
        self.active = False
        store = self._store
        self.session_state = status
        self._event(reason)
        # Incidents, aborted actions and the final lifecycle event are
        # durability obligations. A successful base write cannot conceal
        # a failed required event write.
        if self.last_error in ("STORAGE_ERROR", "INCIDENT_STORAGE_ERROR"):
            status = "STORAGE_ERROR"
            self.session_state = status
        self._store = None
        try:
            store.finish(status)
        except ObserverError as exc:
            self.last_error = exc.code
            self.session_state = "STORAGE_ERROR"
            self._event("STORAGE_ERROR", exc.code)
        finally:
            try:
                store.close()
            except ObserverError:
                self.last_error = "STORAGE_ERROR"
            if store.v2 is not None and store.v2.thread.is_alive():
                self._pending_v2 = store.v2
        if not defer_report:
            self.generate_report()

    def generate_report(self) -> None:
        """Compatibility sync report path for CLI. Qt uses ReportWorker."""
        if self.session_folder is None:
            return
        try:
            report = write_report(self.session_folder)
            self.complete_report(report, "")
        except (ObserverError, OSError, ValueError, TypeError):
            self.complete_report(None, "REPORT_UNAVAILABLE")

    def complete_report(self, report: dict | None, error: str) -> None:
        """Accept an already finished report on the GUI-owning thread only."""
        if self.active or self._store is not None:
            raise RuntimeError("REPORT_NOT_READY")
        if error or type(report) is not dict:
            self.report_result = None
            self.last_error = "REPORT_UNAVAILABLE"
            self._event("REPORT_UNAVAILABLE", "SQLite data retained")
        else:
            self.report_result = report
            self._event("EVIDENCE_SAVED", "SQLite, HTML, JSON")

    def _accept_persisted_sample(self, sample, seq: int) -> dict:
        """Apply an already committed sample on the owner (Qt) thread only.

        Action/incident events still use the GUI-owned SessionStore. Worker
        threads never touch mutable ReadOnlyProbe, ActionCycle or Qt state.
        """
        if not self.active or self._store is None:
            raise ObserverError("INVALID_DATA", "storage")
        if type(seq) is not int or seq != self.total_samples + 1:
            raise ObserverError("INVALID_DATA", "storage")
        self._store.seq = seq
        try:
            if self.incident_capture is not None:
                try:
                    detail = self.detailed_capture.latest_metrics if self.detailed_capture else None
                    if detail and time.monotonic_ns()-detail["time_ns"] > max(5, self.detailed_capture.interval_s*3)*1e9:
                        detail = None
                    boundaries = self.incident_capture.observe(
                        elapsed_ms=sample.elapsed_ms, sample_seq=self.total_samples + 1,
                        cpu_percent=sample.cpu_percent, rss_bytes=sample.rss_bytes,
                        private_bytes=detail.get("private_bytes") if detail else None,
                        handle_count=detail.get("handle_count") if detail else None,
                        read_bytes=sample.read_bytes, write_bytes=sample.write_bytes,
                        detail_ref=detail.get("correlation_key") if detail else None)
                    for boundary in boundaries:
                        try:
                            self._store.write_event(boundary)
                            self.incident_events.append(boundary)
                            self.events.append({
                                "timestamp_utc": utc_stamp(),
                                "code": boundary["code"],
                                "detail": "Automatic external-counter observation; no proven cause"})
                        except ObserverError:
                            # A noncritical sensor failure cannot abort base samples.
                            self.last_error = "INCIDENT_STORAGE_ERROR"
                except ValueError:
                    self.last_error = "INCIDENT_SENSOR_UNAVAILABLE"
            self.actions.advance(self._persist_action)
            record = {
                "at": utc_stamp(),
                "seconds": round(sample.elapsed_ms / 1000, 2),
                "cpu_pct": (round(float(sample.cpu_percent), 1)
                            if sample.cpu_percent is not None else None),
                "rss_mb": (round(sample.rss_bytes / 1048576, 1)
                           if sample.rss_bytes is not None else None),
                "process_count": (1 + int(sample.children_count)
                                  if sample.children_count is not None else None),
                "thread_count": (int(sample.num_threads)
                                  if sample.num_threads is not None else None),
                "read_bytes": sample.read_bytes,
                "write_bytes": sample.write_bytes,
            }
            self.history.append(record)
            self.total_samples += 1
            self.last_elapsed_ms = sample.elapsed_ms
            return record
        except ObserverError:
            raise

    def accept_background_sample(
            self, sample, seq: int, *,
            requested_interval_ms: int | None = None,
            worker_timing: dict | None = None,
            received_ns: int | None = None) -> dict:
        """Apply real worker result and independently classify monotonic gaps.

        Commit a detected gap before updating the accepted-sample baseline.
        A failed gap event leaves the recording in storage-error state; it
        never fabricates an OS-missed-sample count.
        """
        if (not self.active or self._store is None or
                type(seq) is not int or seq != self.total_samples + 1):
            raise ObserverError("INVALID_DATA", "storage")
        gap = None
        if requested_interval_ms is not None:
            try:
                gap = self._sample_cadence.preview(
                    sample.elapsed_ms, requested_interval_ms)
            except (ValueError, AttributeError):
                raise ObserverError("INVALID_DATA", "sample") from None
            if gap is not None:
                if self._store is None:
                    raise ObserverError("STORAGE_ERROR", "storage")
                self._store.write_event(gap)
        if worker_timing is not None:
            if type(worker_timing) is not dict or type(received_ns) is not int:
                raise ObserverError("INVALID_DATA", "sample")
            # Validate timing BEFORE acceptance to avoid displaying a sample
            # whose metadata is invalid. Validation does not mutate timing.
            values = tuple(worker_timing.get(k) for k in (
                "started_ns", "sensor_done_ns", "write_done_ns"))
            if (any(type(v) is not int or v < 0 for v in values) or
                    values[0] > values[1] or values[1] > values[2] or
                    values[2] > received_ns):
                raise ObserverError("INVALID_DATA", "sample")
        result = self._accept_persisted_sample(sample, seq)
        if requested_interval_ms is not None:
            self._sample_cadence.commit(
                sample.elapsed_ms, requested_interval_ms,
                was_extended=gap is not None)
            if gap is not None:
                self.events.append({
                    "timestamp_utc": utc_stamp(),
                    "code": "EXTENDED_MONOTONIC_SAMPLE_SPACING",
                    "detail": str(gap["observed_spacing_ms"]) +
                              " ms between sampled OS-counter snapshots; cause UNKNOWN"})
        if worker_timing is not None:
            self._worker_timing.observe(
                started_ns=worker_timing["started_ns"],
                sensor_done_ns=worker_timing["sensor_done_ns"],
                write_done_ns=worker_timing["write_done_ns"],
                received_ns=received_ns)
        return result

    def record_busy_timer_gap(self, observation: dict) -> None:
        """Persist only observed GUI-busy timer callbacks, never OS outages.

        This is a synchronous durability acknowledgement on the Qt owner
        thread; if it fails the caller MUST stop with a storage failure.
        """
        if not self.active or self._store is None:
            raise ObserverError("STORAGE_ERROR", "storage")
        if (type(observation) is not dict or
                observation.get("code") != "BASE_TIMER_CALLBACK_SKIPPED_BUSY" or
                type(observation.get("missed_callback_count")) is not int or
                observation["missed_callback_count"] <= 0):
            raise ObserverError("INVALID_DATA", "storage")
        self._store.write_event(observation)
        self.busy_timer_callbacks += observation["missed_callback_count"]
        self.busy_timer_episodes += 1
        self.events.append({"timestamp_utc": utc_stamp(),
                            "code": "BASE_TIMER_CALLBACK_SKIPPED_BUSY",
                            "detail": (str(observation["missed_callback_count"]) +
                                       " observed busy callbacks; NOT OS missed samples")})

    def record_background_failure(self, code: str) -> None:
        """Persist a failed async sample with the original observer semantics."""
        if not self.active or self._store is None:
            return
        if code not in ("PROCESS_EXITED", "PID_REUSED", "ACCESS_DENIED",
                        "SAMPLE_UNAVAILABLE", "STORAGE_ERROR"):
            code = "SAMPLE_UNAVAILABLE"
        self.last_error = code
        stage = "storage" if code == "STORAGE_ERROR" else "sample"
        try:
            self._store.write_event(event(
                "observer_error", code, stage, self.last_elapsed_ms or 0))
        except ObserverError:
            self.last_error = "STORAGE_ERROR"

    def tick(self, *, requested_interval_ms: int = 1000, track_cadence: bool = False) -> dict | None:
        """Legacy synchronous path for CLI/explicit callers, not Qt timer."""
        if not self.active or self._core is None or self._store is None:
            return None
        try:
            sample = self._core.sample()
            self._store.write_sample(sample)
            if self._store.v2 is not None and self._core.last_observation is not None:
                self._store.v2.submit("base", {
                    **self._core.last_observation,
                    "correlation_key": f"schema1:{self._store.seq}",
                    "requested_interval_ns": requested_interval_ms*1_000_000})
            if track_cadence:
                return self.accept_background_sample(sample,self._store.seq,
                    requested_interval_ms=requested_interval_ms)
            return self._accept_persisted_sample(sample, self._store.seq)
        except ObserverError as exc:
            self.last_error = exc.code
            try:
                self._store.write_event(event("observer_error", exc.code, exc.stage, 0))
            except ObserverError:
                pass
            self.stop(exc.code)
            return None

    def _persist_action(self, record: dict) -> None:
        if not self.active or self._store is None or self._recording_origin_ns is None:
            raise ActionError("RECORDING_NOT_ACTIVE")
        data = dict(record)
        # Actual command time, not the timestamp of the last process sample.
        data["session_elapsed_ms"] = max(
            0, (data["timestamp_monotonic_ns"] - self._recording_origin_ns) // 1_000_000)
        data["previous_sample_seq"] = self.total_samples or None
        data["pid"] = self.pid
        data["pid_creation_time"] = self._core.created if self._core else None
        self._store.write_event(data)
        self.events.append({"timestamp_utc": utc_stamp(), "code": data["event"],
                            "detail": f'{data["session_elapsed_ms"]} ms · action {data["action_id"][:8]}'})

    def set_detailed_capture(self, enabled: bool) -> None:
        """Explicit opt-in; detailed probes never run on the Qt event loop."""
        if type(enabled) is not bool or not self.active or self._store is None:
            raise RuntimeError("DETAILED_CAPTURE_REQUIRES_RECORDING")
        if enabled:
            self._reap_detailed()
            if self.detailed_capture is None:
                if self._core is None or self._recording_origin_ns is None:
                    raise RuntimeError("DETAILED_TARGET_MISSING")
                capture = DetailedCapture(
                    self._store.folder, self.pid, self._core.created,
                    self._recording_origin_ns, **self.detail_policy,
                    **({"resume_from":self._stopped_detail} if self._stopped_detail else {}))
                capture.session_writer = self._store.v2
                capture.start()
                self.detailed_capture = capture
                self._event("DETAILED_CAPTURE_ENABLED",
                            "Opt-in v2 sidecar; psutil process/threads/children")
        elif self.detailed_capture is not None:
            capture = self.detailed_capture
            self._stopped_detail=capture
            stopped = capture.stop(timeout=0.5)
            if not stopped:
                self._pending_detailed = capture
                self.last_error = "DETAILED_CAPTURE_STOP_PENDING"
                self._optional_sensor_error("PSUTIL_DETAILED","DETAILED_CAPTURE_STOP_PENDING")
                capture.session_writer = None
            self._event("DETAILED_CAPTURE_DISABLED",
                        "Stopped" if stopped else "Stop pending")
            self.detailed_capture = None

    def set_window_capture(self, enabled: bool) -> None:
        if type(enabled) is not bool or not self.active or self._store is None:
            raise RuntimeError("WINDOW_CAPTURE_REQUIRES_RECORDING")
        if enabled:
            self._reap_detailed()
            if self.window_capture is None:
                cap=WindowCapture(self.pid,self._core.created,self._store.v2)
                cap.start()
                self.window_capture=cap
        elif self.window_capture is not None:
            cap=self.window_capture
            if not cap.stop(timeout=.05):
                self._pending_windows=cap
                self._optional_sensor_error("WIN32_WCT","WINDOW_SENSOR_STOP_PENDING")
                cap.writer=None
            self.window_capture=None

    def set_incident_capture(self, enabled: bool, *, policy: dict | None = None) -> None:
        """Explicit, local-only opt in; never enables system tracing or dumps."""
        if type(enabled) is not bool or not self.active or self._store is None:
            raise RuntimeError("INCIDENT_CAPTURE_REQUIRES_RECORDING")
        if enabled:
            if self.incident_capture is None:
                self.incident_capture = IncidentCapture(**(policy or {}))
                self._event("INCIDENT_CAPTURE_ENABLED", "CPU + sampling gap only")
        elif self.incident_capture is not None:
            for boundary in self.incident_capture.stop(
                    elapsed_ms=self.last_elapsed_ms or 0,
                    sample_seq=self.total_samples or 1):
                self._store.write_event(boundary)
            self.incident_capture = None
            self._event("INCIDENT_CAPTURE_DISABLED")

    def prepare_action(self, *, baseline_ms: int | None = None) -> dict:
        if not self.active or self._core is None:
            raise ActionError("RECORDING_NOT_ACTIVE")
        if baseline_ms is not None:
            if self.actions.state not in ("IDLE", "COMPLETED", "ABORTED"):
                raise ActionError("ACTION_ALREADY_ACTIVE")
            # Keep existing experiment identity and previous repeat timings.
            # Replacing the ActionCycle here silently erased past repeats.
            if type(baseline_ms) is not int or not 0 <= baseline_ms <= 60000:
                raise ActionError("INVALID_BASELINE")
            self.actions.baseline_ms = baseline_ms
        # Refuse PID reuse before recording the beginning of a user action.
        if abs(self._core.process.create_time() - self._core.created) > 0.000001:
            raise ObserverError("PID_REUSED", "sample")
        return self.actions.prepare(self._persist_action)

    def begin_action(self) -> dict:
        if not self.active:
            raise ActionError("RECORDING_NOT_ACTIVE")
        return self.actions.begin(self._persist_action)

    def finish_action(self) -> dict:
        if not self.active:
            raise ActionError("RECORDING_NOT_ACTIVE")
        return self.actions.finish(self._persist_action)

    def mark_problem(self, note: str = "", *, issued_ns: int | None = None) -> int:
        """Record actual command time; preserve provenance as USER_REPORTED.

        The previous sample ordinal is metadata, never substituted for the
        command's real monotonic timestamp. No Windows-hang attestation.
        """
        if (not self.active or self._store is None or
                self.last_elapsed_ms is None or self.pid is None or
                self._recording_origin_ns is None):
            raise RuntimeError("Record at least one sample before marking a problem.")
        if type(note) is not str:
            raise ValueError("INVALID_MARKER_NOTE")
        clipped = note.strip()[:128]
        received_ns = time.monotonic_ns()
        command_ns = received_ns if issued_ns is None else issued_ns
        if (type(command_ns) is not int or command_ns < self._recording_origin_ns or command_ns>received_ns):
            raise ValueError("INVALID_COMMAND_CLOCK")
        elapsed_ms = (command_ns - self._recording_origin_ns) // 1_000_000
        self._store.write_event({
            "kind": "user_problem", "source": "USER",
            "elapsed_ms": elapsed_ms, "note": clipped,
            "timestamp_utc": utc_stamp(),
            "timestamp_monotonic_ns": command_ns,
            "observer_received_monotonic_ns": received_ns,
            "command_clock_origin": "GUI_ISSUED" if issued_ns is not None else "LOCAL_OWNER_RECEIVED",
            "timestamp_precision": "COMMAND_MONOTONIC_NS",
            "previous_sample_elapsed_ms": self.last_elapsed_ms,
            "previous_sample_seq": self.total_samples,
            "nearest_sample_id": None,
        })
        self.events.append({"timestamp_utc": utc_stamp(), "code": "USER_PROBLEM",
                            "detail": f"{elapsed_ms} ms · {clipped}"[:120]})
        return elapsed_ms

    @property
    def last(self) -> dict:
        return self.history[-1] if self.history else {
            "seconds": 0.0, "cpu_pct": 0.0, "rss_mb": 0.0,
            "process_count": 0, "thread_count": 0,
        }

    def snapshot(self) -> dict:
        return {
            "schema_version": 1, "product": "BLACK.BOX Universal",
            "source": "local_read_only_psutil",
            "evidence_origin": "APP_SUPPLIED_NOT_AUTHENTICATED",
            "root_cause_proven": False,
            "observed_process": {"name": self.name, "pid": self.pid},
            "started_at_utc": self.started_at, "exported_at_utc": utc_stamp(),
            "observation_active_at_export": self.active,
            "session_state": self.session_state,
            "session_folder": str(self.session_folder) if self.session_folder else None,
            "sample_count": self.total_samples, "recent_samples": list(self.history),
            "observed_busy_timer_callbacks": self.busy_timer_callbacks,
            "observed_busy_timer_episodes": self.busy_timer_episodes,
            "busy_timer_limitations": "QT_COALESCED_CALLBACKS_NOT_COUNTED",
            "extended_monotonic_spacing_pairs": self._sample_cadence.extended_pairs,
            "comparable_monotonic_spacing_pairs": self._sample_cadence.comparable_pairs,
            "monotonic_spacing_interval_changes": self._sample_cadence.interval_changes,
            "max_observed_monotonic_spacing_ms": self._sample_cadence.max_observed_spacing_ms,
            "completed_base_workers": self._worker_timing.completed_workers,
            "max_base_worker_sensor_ms": self._worker_timing.max_sensor_ms,
            "max_base_worker_sqlite_ms": self._worker_timing.max_sqlite_ms,
            "max_base_worker_signal_delivery_ms": self._worker_timing.max_signal_delivery_ms,
            "action_state": self.actions.state,
            "completed_actions": self.actions.completed[-20:],
            "completed_actions_total": self.actions.completed_total,
            "recent_events": list(self.events),
            "report_generated": self.report_result is not None,
            "limitations": [
                "Only process/system sampling, not internal app tracing.",
                "Memory growth alone does not prove a memory leak.",
                "The recorded evidence is app-supplied and unauthenticated.",
                "Process names/PIDs are private; inspect before sharing.",
            ],
        }


def save_snapshot(path: Path, data: dict) -> None:
    """Explicit user-selected JSON snapshot with atomic publication."""
    destination = Path(path)
    stage: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=destination.parent,
                prefix=".blackbox-", suffix=".tmp", delete=False) as out:
            stage = Path(out.name)
            json.dump(data, out, ensure_ascii=False, indent=2, allow_nan=False)
            out.write("\n")
        os.replace(stage, destination)
    finally:
        if stage is not None:
            stage.unlink(missing_ok=True)
