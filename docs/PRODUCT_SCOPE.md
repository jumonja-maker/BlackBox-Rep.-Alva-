# Universal BlackBox product contract

## Goal

An independent, installable, offline-first program to collect *technical evidence* about **any user-selected program that the operating system allows it to observe**. The observed application is not required to be written in Python, use Alva, expose network APIs, or ship a diagnostic SDK. The current first adapter is read-only process sampling via psutil, not universal deep introspection.

## User journeys

- **Start**: choose a local PID with permission and a session output directory; no auto-attachment or hidden process interception.
- **Observe**: bounded, local session; periodic CPU, RSS, threads, I/O and child-process observations; clear permission-denied, PID-reused and process-exited states.
- **Review**: offline SQLite, JSON/HTML report, before/after observation deltas. No inferred application root cause from raw metrics.
- **Hand off**: redacted evidence capsule with `permission_to_act=false` for another developer or an explicitly user-chosen AI tool; product works without AI.
- **Extend**: add explicit optional adapters for Windows-native event sources, log file ingest, permissioned app telemetry. Capability, schema, privacy and tests per adapter.
- **Alva**: opt-in, separately installed, pinned version for structured component diagnostics. Never prerequisite for observing other applications.

## Compatibility levels

| Scenario | State |
|---|---|
| Standalone Python CLI, offline reporting | implemented; limited local checks |
| User-selected accessible process with psutil | implemented; local Linux smoke performed |
| GUI and portable Windows EXE | NOT IMPLEMENTED |
| Actual Windows real-program compatibility | NOT RUN |
| App's internal errors/tasks without explicit telemetry | NOT AVAILABLE by passive sampling |
| Any language, **external** metrics | possible within psutil/OS permissions; not universally validated |
| AI cloud analysis or automatic self-repair | out of scope |
| Commercial or public repackaging of private Alva | BLOCKED pending rights/license |

## Non-goals

Unapproved installation of services, drivers or hook DLLs; debugging/injection; sending signals; silent event recording; copying confidential user files; pretending every anomaly has known causality; cloud upload or automatic LLM decisions; editing observed application; replacing LibreOffice with Alva Document Engine.
