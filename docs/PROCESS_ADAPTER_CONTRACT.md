# Universal observation adapter contract (planned extension)

The existing `PsutilProbe` is an implemented, local, read-only Python interface:

- Attach once to positive PID. Capture process creation time as a reuse guard.
- Each `.sample()` returns a frozen `Sample` object with elapsed monotonic milliseconds, RSS bytes, optional CPU percentage, optional thread count, optional read/write bytes, optional child process count.
- Optional values are `None` when unavailable, not synthetic zero.
- Attach/observation failures map to a fixed `ObserverError(code, stage)`; raw system exceptions are not copied into diagnostic artifacts.
- Do not call terminate/kill/suspend, change permissions, attach a debugger, load DLLs, patch a process, inspect arbitrary target memory, copy user files or spawn child processes.

## Independent future adapters

1. **Windows performance counters / ETW:** separate opt-in collector requiring environment-specific validation and explicit privacy/security review; not claimed as implemented.
2. **Application log adapter:** user explicitly selects one log file, with bounded tails, limited formats, secret redaction and no automatic filename traversal; not implemented.
3. **Application telemetry:** optional producer handshake, producer ID, sequence tracking, bounded messages, explicit schema, unknown source provenance; not implemented.
4. **A.I.O compatibility:** existing private BLACK.BOX prototype is an external heritage project only. No implicit A.I.O dependency in the new universal product.

Every new adapter must have a positive observable scenario, a negative permission-denied or partial-stream scenario, privacy impact note, no-modification assertion, bounded recording and offline replay. Unsupported events must be omitted or declared unsupported instead of being constructed from inference.
