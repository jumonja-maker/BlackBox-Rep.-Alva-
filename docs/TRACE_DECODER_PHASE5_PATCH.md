# Decoder Phase 5 patch: modules, local functions and CPU sample trees

> Integration note (2026-10-28): included in the owner-authorized v0.5.0
> candidate. Historical patch-test results below do not certify the release;
> the exact candidate must pass the full release workflow.

**Development branch only:** `patch/trace-decoder-phase5`. No main merge,
version bump, PR or release is implied. Main stays at the accepted Phase 5A.
The original first-line author messages and feedback email are unchanged.

See [packet 2](TRACE_DECODER_PHASE5_PACKET2.md) for the native ETW tree,
GUI filters and optional per-frame PDB tree overlay. Its acceptance is separate.

## Three workstreams

### 1. Trace-scoped native module observations

The TraceEvent host records a frame's module only for a unique native image
load observation covering both the code address and that event time in the
same process instance. It checks conflicting TraceEvent code/module mappings.
Managed, JIT and ReadyToRun code are not interpreted as native PE RVAs. Reused
PIDs, overlapping load intervals, missing records and exhausted budgets do
not receive a guessed module. Full build-machine paths are not exported.

The `blackbox.trace-module/1` metadata includes process instance, module-file
index, image base/size/timestamp, load interval, optional PDB GUID/Age and a
basename. Python checks the complete numeric contract and address/RVA parity.
New `decoder-index/4` databases add a paged module catalog. v1-v3 indexes remain
readable in their old modes; module review requires re-decoding the source.
Even a consistent mapping remains **UNVERIFIED_IMPORT**, not OS attestation.

### 2. Local native PDB procedure ranges

An explicit user action on a selected recorded event chooses one PE and one
Windows PDB. A cancellable worker snapshots the files into private temporary
storage, hashes the copies and verifies source metadata before/after copying.
It parses Windows MSF7, PDB Info, DBI, section headers and CodeView module
procedure symbols. It neither executes the image nor initializes DbgHelp or
contacts a symbol server. Paths recorded inside the PDB are never followed.

The supported records are `S_LPROC32`, `S_GPROC32` and their `_ID` variants.
Procedure **recorded lengths**, not nearest-name heuristics, define ranges.
A function-flagged `S_PUB32` is usable only at its exact entry RVA; addresses
between public entries are not inferred. Overlapping/aliased ranges remain
ambiguous. PDB Info/DBI age, PE CodeView GUID/Age, machine and section headers
must agree. Each trace frame must independently agree on GUID/Age, image size,
timestamp, process and load window. Missing evidence stays unresolved.

The resulting report preserves raw names/addresses and adds derived symbol
names separately. It records the trace hash when supplied and the PE/PDB
SHA-256 hashes. It never rewrites the source trace, recording or decoder index.
Source-line/inline resolution, portable PDB, OMAP and unsupported containers
are outside this patch and fail closed. Optimized multi-range procedures and
all compiler variants are **not** claimed to be fully supported.

### 3. Recorded CPU sample call tree and offline flame view

Only `Microsoft-DotNETCore-SampleProfiler / Thread/Sample` contributes to this
initial tree. **Native ETW CPU-event classification is not included yet.**
GC allocation stacks and arbitrary event-associated stacks do not become CPU
samples. The backend accepts PID, process instance and half-open time filters;
the current GUI uses the selected PID across the trace. Callers-to-leaf
aggregation preserves process instance and full frame/address/module identity.
Unknown instances are separated per event instead of merging reused PIDs.

Inclusive and self values are sample **counts**, not duration or CPU percent.
Missing stacks, truncated caller chains and node-budget omissions are counted
explicitly. The GUI presents a separate tree; derived JSON and script-free,
escaped HTML/SVG flame views are exclusive-created, never overwritten.
The flame view is not a timeline and cannot identify the cause of a hang.

## Resource and lifecycle boundaries

- Module catalog: up to 16,384 identities; host process/load budgets are 4,096
  and 8,192 respectively. Excess information cannot silently certify a mapping.
- Local file limit: 512 MiB per file; symbol stream reads: 64 MiB total;
  CodeView records: 500,000; procedures/publics: 100,000 each.
- Symbol and tree analysis have cooperative cancellation and 30-second checks.
  This is **not** a hard guarantee against stalled filesystem I/O.
- Tree input: at most 250,000 samples; default 10,000 nodes, hard maximum 20,000.
  A whole sample path is omitted atomically when node capacity is insufficient.
- One GUI worker at a time; closing requests cancellation and drains the worker.
  Replacing the source clears derived reports and closes the previous tree.
- Export is capped at 64 MiB and published with create-new semantics.
- No automatic capture, symbol download, telemetry upload or user app execution.

## Validation and acceptance status

Implemented tests cover malformed bindings, reused process instances, RVA
arithmetic, unsupported old-index modes, immutable sources, actual Clang/lld
PE/PDB procedure records checked against a linker map, mismatch refusal,
unknown padding, alias ambiguity, cancellation, source accounting, safe HTML,
RU/EN GUI worker lifecycle and stale-result clearing.

`tools/qa_decoder_patch.py` distinguishes real PE/PDB with **synthetic trace
metadata** from a **real native Windows process + WPR + decoder + PDB** run.
The latter explicitly requests the allowlisted `CPU.Verbose` WPR profile
for its five-second owned fixture. Default production capture stays
`GeneralProfile.Light`. The first end-to-end attempt recorded zero stacks
with the light profile and therefore correctly failed acceptance. Profile
selection is journaled, arbitrary/custom WPR profiles are refused, and the
same named-session guardian owns TTL and cleanup.

This end-to-end test is mandatory in the branch's Windows job: unavailable capture or
missing named fixture frames fails that acceptance gate, not a false success.
Windows compilation and end-to-end results must be read from the exact branch
CI run. Local Linux parser tests alone do not certify Windows/TraceEvent or UI.
No complete feature acceptance or merge authorization is implied by this file.

## Primary format/API references

- Microsoft PerfView TraceEvent `TraceLog.cs`: TraceProcess.LoadedModules,
  TraceLoadedModule load intervals, TraceModuleFile and TraceCodeAddress.
  https://github.com/microsoft/perfview/blob/main/src/TraceEvent/TraceLog.cs
- LLVM MSF and PDB DBI/module symbol stream specifications:
  https://llvm.org/docs/PDB/MsfFile.html
  https://llvm.org/docs/PDB/DbiStream.html
  https://llvm.org/docs/PDB/ModiStream.html
  https://llvm.org/docs/CodeViewSymbols.html

The helper remains pinned to TraceEvent 4.0.0. These references guide parsing;
tests against the pinned build are necessary to validate its actual behavior.

- Microsoft WPR profiles and verbose stack capture:
  https://devblogs.microsoft.com/performance-diagnostics/wpr-start-and-stop-commands/
