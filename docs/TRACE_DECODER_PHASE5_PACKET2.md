# Decoder Phase 5 — packet 2: native CPU, scoped trees, local symbol overlays

> Integration note (2026-10-28): included in the owner-authorized v0.5.0
> candidate. Historical patch-test results below do not certify the release;
> the exact candidate must pass the full release workflow.

Development patch based on `963f27b1976770ba38608950ca4168eca2607a9f`.
Target branch: `patch/trace-decoder-phase5`. No main merge, tag or release.
This packet is not accepted until its exact source passes Windows/Qt and the
extended real-capture test. Previous branch CI success is not this packet's QA.

## 1. Native ETW CPU occurrence tree

The C# TraceEvent host recognizes `SampledProfileTraceData` with Windows Kernel
provider GUID `9e814aad-3204-11d2-9a82-006008a86939`, classic event ID 65535 and
opcode 46. It exports the additive `blackbox.cpu-sample/1` contract containing
the instruction pointer, processor and DPC/ISR flags. Python validates the
contract, primitive types and matching generic payload fields before publishing
an index. A corrupt contract aborts the entire index, not a partially valid one.

The tree's source selector offers `.NET SampleProfiler` or native ETW. No mixed
source mode is offered; sampling rates and CPU-percent denominators are unknown.
One event is one occurrence; the payload `Count` is not used as a multiplier.
PMC, StackWalk, GC and arbitrary name lookalikes do not enter the native tree.
DPC/ISR work is excluded from the process tree and counted explicitly. Missing
flags or missing process/thread attribution are excluded as unknown, not zero.

Older indexes remain readable. Native events without the typed contract are
reported as `TYPED_CLASSIFICATION_MISSING`, with `REDECODE_REQUIRED_FOR_ETW`
when none can be selected. The program does not silently manufacture a typed
claim from an old provider string. Original traces/indexes are not upgraded
or rewritten in place. Import evidence remains unauthenticated.

## 2. Scoped GUI and reproducible export

CPU trees accept a source, the existing PID field, an optional process-instance
index, an optional TID and trace-relative milliseconds in `[start, end)`.
Blank fields mean no filter; process-instance zero is a valid explicit value.
NaN/infinity, oversized numbers, Unicode-lookalike identifiers and reversed or
empty ranges are refused before a worker starts. Filters apply to CPU analysis,
not to the event table's provider text search. TID is not claimed as a thread
lifetime identity: combine it with process instance and time to narrow reuse.

The report and script-free HTML export include the applied filter snapshot,
source trace SHA-256, exclusions, missing stacks and node-budget omissions.
Changing a CPU filter invalidates the previous tree and its export. Controls
are frozen during analysis. Reopening a trace clears instance/time fields and
derived results. RU/EN changes preserve the selected values. Analysis controls
use two rows rather than forcing long buttons into the minimum-width window.

## 3. One explicit local PE/PDB pair for the tree

`TREE + LOCAL PDB` requires two explicit file choices. One cancellable analysis
snapshots and hashes the pair once, checks GUID/Age, machine and section layout,
and tests each recorded native frame against its imported module/load window.
Only matching recorded procedure ranges or exact eligible public entries
produce names. A wrong local pair fails. Frames from other modules or with
missing/mismatched identities remain unresolved, with reason counts.

The original frame (including its old name and address) is retained in `frame`;
the separate `derived_symbol` records the binding and PDB result. No return
address adjustment, nearest-function guessing, automatic symbol discovery,
network lookup, source-code execution or input rewrite is added. Tree identity
continues to include raw address/module/load evidence, even when names match.
All inclusive/self values remain sample counts and are conserved. Symbol
occurrence coverage is explicitly measured before node-budget omissions.

GUI tooltips HTML-escape imported text. Reports remain derived from unverified
trace/local files, not authentication, CPU%, full capture or causal proof.

## Validation

- Core unit tests cover native classification, DPC/ISR exclusion, legacy indexes,
  forged fields, source separation, time/TID/instance filtering, cancellation,
  real Clang/lld procedure records, mismatched modules and byte preservation.
- New Qt tests cover source/filter snapshots, stale export clearing, invalid
  filters, explicit file-pair selection, language switching and cancellation.
- `tools/qa_decoder_patch.py` now requires a real native WPR capture decoded by
  the new helper, a nonempty typed native CPU tree, conserved counts, named
  fixture functions, a nonempty instance/TID/time-filtered tree, and unchanged
  source/index hashes. Unavailability is a failed acceptance gate, not a skip.
- Local Python compilation is not a C# build or a GUI test. Those require the
  isolated branch workflow and are not asserted by this document.

Resource limits remain: 250,000 matching event candidates, 20,000 tree nodes
maximum (10,000 default), 8,192 cached per-frame symbol results, fixed PDB read
budgets and cooperative 30-second analysis checks. Filesystem stalls are not
hard-preempted. Portable PDB, OMAP, inline/source lines, off-CPU analysis and
sampling-duration normalization remain unsupported.

## Primary references

- [Microsoft SampledProfile contract](https://learn.microsoft.com/en-us/windows/win32/etw/sampledprofile)
- [Microsoft TraceEvent kernel parser: typed sample, opcode 46, DPC/ISR](https://github.com/microsoft/perfview/blob/main/src/TraceEvent/Parsers/KernelTraceEventParser.cs)
- [TraceEvent programmers guide](https://github.com/microsoft/perfview/blob/main/documentation/TraceEvent/TraceEventProgrammersGuide.md)

The referenced parser behavior was reviewed during development. Compilation
and capture acceptance must still use this project's pinned TraceEvent 4.0.0.
