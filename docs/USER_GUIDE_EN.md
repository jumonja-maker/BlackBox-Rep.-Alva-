# BLACK.BOX investigation guide

Standard user mode observes accessible process counters. Administrator mode may enable additional sources; it does not make every process fully observable. No DLL injection or target-memory modification. External counters alone do not prove an internal root cause.

## Record and measure

Choose and confirm a running PID on Processes. Selection does not start recording. Check target identity and the capture profile on Overview, then Start. PID plus creation time identifies the instance; browsing a saved descendant does not rebind the live root.

Standard captures base counters. Detailed adds bounded thread/child/memory queries. Incident Burst adds temporary detail after enabled triggers. Profiles never automatically start ETW or a dump. Limits and omitted counts are explicit.

Settings contains intervals, trigger policies, soft storage/time budgets and optional adaptive sampling. Sustained sampled observer usage can reduce frequency to five seconds and records a configuration change. The option can be disabled before recording. Self usage is not an OFF/ON effect measurement; use the separate benchmark for that comparison.

Prepare action → Begin action → perform work in the target → End action. Repeats belong to an experiment; unfinished actions become ABORTED. These are USER boundaries, not internal function timing. Problem/stage/comment markers keep issued and receipt time and remain USER statements.

## Investigate

Reports starts with observations, supporting measurements and limits. Whole-range findings have paging/sorting and offline CPU/UI/Memory/IO/Coverage filters. Incident cards show actual pre/inside/post snapshots, resources, TID/tree/native evidence, gaps and next measurements. Partial post-context is visible; raw technical JSON is optional.

The common timeline supports range selection, zoom/pan, A/B and event tracks. Gaps are not interpolated as zero. Events has source/severity/instance/time/literal-text filters and range navigation. Reopened files retain UNVERIFIED_IMPORT trust.

Comparison covers action duration, CPU, memory/USS/private, handles, IO bytes/ops, gaps/errors and available native timeouts. It shows counts, variability and incompatible conditions. Missing is not zero. Coincidence or a median delta is not proof of causation, a leak or a statistically established speedup.

## Optional instrumentation and native sources

Prepare my application generates local Python/.NET/C++/Node examples and a channel configuration. Add the client to your own source, rebuild/restart and wait for a real control event. Without voluntary instrumentation only external evidence is available. See SDK_GUIDE.md.

Windows/WCT snapshots, WPR ETW, EventPipe and minidumps are separate explicit operations. WPR has Stop, TTL, a named ownership journal and sensitive ETL export. EventPipe uses installed dotnet-trace only, with no automatic download. It requires a compatible .NET diagnostic port; unsupported/runtime/tool/access states are distinct. Opaque nettrace is not decoded GC proof.

Minidumps require separate consent and can contain secrets or briefly pause a target. Imported native symbols must match the executable. System failure events reads bounded local Application records and matches named payload PID fields; logger Execution PID is not the crashed target. Missing records do not mean no crash. Offline ETL decoding is limited to supported event headers and does not infer stacks, GC payloads or device latency.

## Library, export and recovery

The library is index-based. Search does not walk recording folders; older-folder discovery is explicit. Open/compare/export/local comment and reversible Trash are available. Comments stay in the local index and are omitted from share export.

Default exports create redacted copies, preserving original recordings. Raw trace/dump inclusion is a separate option; review sensitive contents before sharing. No background upload. Checksums prove integrity, not author authenticity. JSON/CSV/HTML/explicit ZIP preserve available observations and limitations.

Trash does not free space. Permanent deletion requires separate review/confirmation for owned finalized recordings; changed, live or external data are protected. Export recovery in Settings explicitly inspects a selected output directory. Prepared output may be completed; partial staging requires confirmed discard. Unknown files are retained. Trace-journal recovery never stops a foreign session or the target process.

## Acceptance limits

PR #17 remains Draft / NOT ACCEPTED. Short automatic tests are not real 8h Standard/1h Detailed, physical Win10/11, accessibility or installed upgrade/uninstall acceptance. See BB_DI_001_IMPLEMENTATION_STATUS.md and BB_DI_001_PRODUCTION_QA_RU.md for the unchanged 128 requirements and reproducible harness commands.
