# ADR-01 — capture owners and clocks (current implementation)

This PR retains the public synchronous CLI/ReadOnlyProbe API. Qt periodic base
sampling uses one BaseSampleWorker at a time and an independent schema1 sample
connection. A separate bounded event journal owns schema1 event INSERTs. The
new SessionV2Writer owns the normalized live sidecar. DetailedCapture and
WindowCapture are independent low-frequency workers; neither accesses Qt.

Immutable serialized bounded messages cross into the v2 owner. Sample/quality/
thread/child batches commit atomically within that sidecar. There is no atomic
transaction spanning schema1 and v2: if v2 fails, schema1 remains useful and
the recording ends STORAGE_ERROR. Counts/quality must describe this partial
state, never silently promote it to complete data. The v2 queue has 64 slots;
overflow is fail-closed and discarded command counts are explicit.

Monotonic nanoseconds are the duration/correlation clock. Producer capture
brackets and a paired monotonic/UTC anchor preserve timing uncertainty. UTC
after the anchor remains an estimate susceptible to wall-clock adjustments.
GUI receipt time never replaces sample capture time. User-command timestamps
remain unverified declarations of button handling, not application execution.

Read-only interval queries and export run on cancellable QThreads. SQLite
progress callbacks enforce query deadlines; first/min/max/last points bound
the UI DTO size. Historical process/event lists are cursor paged. No per-TID
thread or unbounded Python dictionary of historic TID identities is created.

**Known ownership limits:** start/attach, schema1 lifecycle finish/journal
barriers, durable command acknowledgement and the old DetailedCapture stop can
still block Qt. Python cannot cancel a stalled OS/filesystem syscall. WCT has
native async cancellation, but its final callback cleanup has no unconditional
hard-latency promise. Pending workers remain referenced; rebind is rejected.
These are still release blockers, not fully solved M-027/M-065/M-066/M-069.

See ADR-02 for the normalized sidecar/readers and ADR-04 for the Win32 ABI,
rights and cleanup behavior. No ETW/SDK/cloud dependency is introduced.
