# ADR-06: optional sources, clocks and fixed capabilities

Status: implemented paths, acceptance pending exact-head native/frozen run.

Python voluntary events use PYTHON_PERF_COUNTER_NS plus reported resolution. This avoids coarse Python 3.11 Windows monotonic duration quantization. Observer and application clocks remain distinct. New stage/IO durations measure application wall time inside the wrapper, excluding the begin-event write. Instrumentation overhead and supplied application statements remain explicit; they are not independently attested disk service time.

EventLog uses local read-only EvtQuery/EvtNext/EvtRender with finite batches/deadline and closes every native handle. The native query lives in the existing disposable operation process. Only known provider/event IDs and named payload target PIDs in the UTC window can match. System/Execution PID identifies the logger. UTC rendering is parsed to datetime microseconds; it is not silently mapped onto the monotonic axis. Absence, access denial, truncated results and unmatched PID do not prove absence of crash. No message strings, file paths, HKLM WER settings or automatic dumps.

ETL import explicitly invokes installed Windows System32 tracerpt, records its hash and the input hash and keeps decoded scope limited to event headers. The tool gets no symbol server, PDB/image lookup, remote session or shell arguments. Root cause, internal stacks, GC payload meanings and lost-event counts cannot be derived from a nonempty ETL/header list. Emitter PID is not universal causal attribution. Plain XML entities/DOCTYPE, unsafe paths and oversized output are refused. The optional result's full bounded row set is stored as a separate artifact; primary evidence uses an explicit bounded preview, avoiding overflow and synchronous 500 individual commits.

Native ETW positive test is independent from XML contract tests: its random, own provider writes EventWrite records into its own named session, with cleanup in finally. Manifestless payloads intentionally remain outside the fixture contract. Unit XML examples are synthetic, not native capture proof.

Fixed inventory and Sensor health are separate: cheap capability discovery never starts capture. Existing worker health adapters do not start additional psutil scans. Health-read heartbeat is not proof of native provider delivery. network/GPU/frames reserve future IDs with no system-wide fallback and no fabricated values.

Sources:

- https://docs.python.org/3/library/time.html#time.perf_counter_ns
- https://learn.microsoft.com/en-us/windows/win32/wes/querying-for-events
- https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtnext
- https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtrender
- https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-systempropertiestype-complextype
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tracerpt
- https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
- https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
- https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventwrite

Not established: complete GC/EventPipe decoder, real crash-positive Windows event attribution, physical Win10/11, AV, real 8h/1h and full original BB-DI-001 acceptance. Local-tool SHA records provenance, not independently trusted publisher authentication or a universal compatible pinned tool version.
