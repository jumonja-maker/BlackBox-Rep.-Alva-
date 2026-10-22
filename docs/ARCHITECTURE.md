# BlackBox Rep. Alva — architecture v0.1 (standalone consumer)

## Four independent layers

1. **Process adapter** — `probe.PsutilProbe`, explicit PID+creation-time identity, read-only sampling of a user-selected accessible local process. Supports any process psutil can inspect; **not** automatic access to app internals. Future adapters can supply Windows event telemetry, performance counters, or opt-in application JSONL through separately documented permissions.
2. **Evidence recorder** — `recorder.record` and `storage.SessionStore`. Only the chosen session output root is writable. Each new session uses its own UUID folder, SQLite WAL and `synchronous=FULL`. Sampling and commit happen in one synchronous loop, bounded duration/interval. No network or AI. The observer is not a Windows service.
3. **Report and handoff** — `report.summarize/write_report/compare`, `handoff.build_handoff`. Read database with `mode=ro`. Report says `UNKNOWN` for external causes, `execution_attested=false`. Handoff is data, not instructions to change code. Report export does not overwrite a previous report; generation should eventually be atomic and multi-process safe before stable release.
4. **Platform adapter (optional)** — `alva_bridge.inspect_platform` binds a minimal app-owned report summary to the genuine pre-release Alva `Component`, `ComponentHost` and scoped `invoke_with_diagnostics` API. It never vendors, imports by default, or publishes Alva. All diagnostics are metadata about the **local component call**, not proof of underlying observed application's correctness.

```text
Any Windows process (no Alva requirement)
    | [psutil read-only sampling; explicit user PID]
    v
ProcessProbe -> SessionStore (SQLite) -> report/handoff (JSON+HTML)
                                              |
                                     optional Alva consumer adapter
                                              |
                                  trusted in-process ComponentHost
```

## Lifecycle and failure behavior

- Fail attach before opening a session if target not accessible. A process exit, PID reuse or permission denial during an active session ends the observation with an explicit code.
- Unexpected `KeyboardInterrupt` may leave committed samples and a closed/partial state; hard crash leaves metadata `ended_utc=NULL` and report `interrupted_or_live`.
- `SAMPLE_UNAVAILABLE` is an observation failure. No service restart or process kill is attempted.
- Runtime creation, storage, report, and AI Handoff are separate. All application-specific adapters must label evidence origin and uncertainty.
- No processor user interface is implied; a GUI shell can call the same program services later, without being required for headless operation.

## Why not embed Alva or A.I.O?

The program observes applications **whether or not they use Alva**. The Alva repository stays private and independent, and BLACK.BOX has no business-logic ownership within it. This repository holds ONLY original application code and a thin bridge calling Alva's published Python API, pinned to a known Git commit. The original BLACK.BOX v0.4 is a private source of product lessons, **not** a codebase copied into this public repository.
