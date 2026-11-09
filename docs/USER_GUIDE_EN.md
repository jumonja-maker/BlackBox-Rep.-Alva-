# BLACK.BOX expert workflow

This guide describes the v0.6.0 source/development workflow. The latest published package verified for this patch is v0.5.4; R10–R60 and the expert workflow patch are not evidence of a published v0.6.0 update. Check the [official Release](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/releases/latest) for the downloadable package and [README](../README.md) for the unsigned-executable notice.

BLACK.BOX records accessible process measurements and keeps evidence locally. OBSERVE is read-only counter collection. Explicit INSPECT/INTERVENE operations are separate: they can capture sensitive memory, pause/debug a target or modify selected bytes after operation-specific confirmation and applicable access checks. Enabling an administrator session does not authorize all operations. Additional access does not make every process observable.

## Choose the question and output

| Question | Minimum useful capture | Output to inspect |
| --- | --- | --- |
| What changed during a slow action? | One selected process, a known workload, an interval or user action boundaries | Counters and events for that interval, gaps, coverage and action duration |
| Is memory consistently higher across runs? | Repeated comparable workloads and capture conditions | Recorded RSS/available memory measures and variability; growth alone does not establish a leak |
| Where was a thread waiting? | Supported saved scheduler/WCT/trace evidence, collected explicitly | Available wait/ready intervals and original references; missing data and ownership remain explicit |
| Did a change improve the workload? | Before/after recordings with compatible workload, target and profile | Comparison, repeat counts, variability and compatibility status |
| What can a saved trace or dump establish? | An existing source and matching local symbols where needed | Supported decoded events/stacks, clock and identity evidence, coverage and source references |

External counters and time coincidence do not prove an internal root cause. Use an observed interval to decide which additional source is needed; collect that source explicitly.

## Select → record → stop → review

### 1. Bind a live target

On **Processes**, filter by name or PID, select the intended running process and attach. Check the executable and PID/creation-time identity in **Overview**. PID alone can be reused. Selecting a table row is distinct from confirming a live target.

For an application file, use **Select Application File**. EXE matching uses the full executable path. **Find Running EXE** selects an existing instance; **Launch Selected EXE** starts it only after a separate confirmation. Metadata/file selection does not record or execute the file. Non-EXE files remain metadata inputs.

Browsing a recorded descendant changes the history being inspected, not the live recording root. Historical trace instance IDs are not substitutes for a current creation time. Stop the current recording before changing the live target.

### 2. Check capture conditions and start

Select the capture profile in Overview or Settings and check the interval before **Start Observing**:

| Profile | Scope |
| --- | --- |
| **Standard** | Base accessible process counters |
| **Detailed** | Additional bounded thread, child-process and memory queries |
| **Incident Burst** | Temporary additional detail after enabled triggers |

Profiles do not automatically start ETW, EventPipe or a dump. Large thread/child sets have explicit limits and omitted counts. Some protected or inaccessible measurements remain unknown. RSS refers to the selected process, not the sum of a whole process tree. CPU is percent of one CPU and can exceed 100%.

Settings holds intervals, trigger policies, storage/time budgets and optional adaptive sampling. Sustained sampled observer usage can reduce collection frequency to five seconds; the change is recorded. Disable the option before recording if the experiment requires a fixed policy. Sampled self usage is not an OFF/ON observer-overhead measurement.

After Start, verify the recording state and increasing sample count. An attached target alone does not mean recording has started.

### 3. Reproduce and annotate

Perform the workload in the target application. Use **Mark Problem** to retain an important moment and note. A problem mark, stage or comment is a USER statement, not an OS-attested crash/hang. Issued and receipt times have distinct meanings.

For repeated action measurements: **Prepare action → Begin action → perform work in the target → End action**. Repeats belong to an experiment; unfinished actions become `ABORTED` at Stop. These boundaries measure the user's commands, not an internal application function. Record version/workload conditions when comparing runs.

Voluntary application instrumentation can provide internal stages. **Prepare my application** generates local Python/.NET/C++/Node examples and channel configuration. Add them to your own source, rebuild/restart and wait for a real control event. An APP statement uses its own clock; SDK `io_operation` wall latency is not physical disk service time. [SDK guide](SDK_GUIDE.md).

### 4. Stop and check persistence

Use **Stop Observing**. Check completion and the session-folder path before treating the recording as saved. Recording, indexing, report generation and share export are separate results. If one fails, retain the shown status/path and retry the failed operation where offered; do not assume an absent HTML report means no SQLite evidence survived.

Default session files are under `%USERPROFILE%\Documents\BLACK.BOX Universal\sessions\<session-folder>`: `session.sqlite3`, `report.json` and `report.html`. Extra captures/analysis have separate files. A stopped recording and a completed report are distinct states; unknown cleanup is not successful completion.

### 5. Review a specific saved context

After Stop/finalization, use **RESULT** in Overview or **Ctrl+Shift+R** to open the most recent live recording as read-only saved evidence in Reports. The tooltip/accessibility name is **Open recording result**. This is an explicit action; stopping does not switch pages automatically. **Open Saved Session** chooses another recording without changing the live PID.

The compact Reports context shows the actual loaded folder and selected range. Its section controls are **Timeline**, **Findings**, **Library**, **Actions / SDK** and **Snapshot / compare**; they navigate within Reports. **Copy analysis context** copies context to the local clipboard without exporting or uploading it. The folder/context can be sensitive; review before sharing.

Before interpreting a finding, check:

- The saved session/source path and process instance.
- The selected interval and any coverage, truncation or trust warning.
- Whether you are viewing raw observations, a derived finding, a user mark or an imported source.

Use the common timeline to select a range, zoom/pan and compare A/B positions. Gaps are not interpolated as zero. Event tracks use the selected range; selecting an event opens its original details. **Reset Range / Root** returns to the recording's full root context. Opening a saved context does not attach its old PID as a live target.

**Event Log** filters source, severity, instance, time and literal text. Recorded process history on **Processes** uses candidate PPID/lifetime links. Ambiguous parents remain unlinked; ancestors outside the current page are labelled context and have no invented resource values. Observed span is not lifetime, absence is not an exact exit time, and missing descendant TIDs are not replaced with the root's threads.

## Keyboard and evidence detail

**Ctrl+1…6** navigates Overview, Processes, Event Log, Reports, Settings and Trace Decoder in that order. Decoder navigation applies when that page is present; the legacy five-page embedding keeps its existing page contract. **Ctrl+L** opens Processes and focuses the process search. **Ctrl+Shift+R** opens the latest stopped recording when finalization is complete. These shortcuts navigate; they do not start a recording or diagnostic action.

Findings present a readable RU/EN summary and the measured facts/limits needed to assess it. Full technical evidence remains available through the technical view. A translated label or readable value does not change the source identity, trust, status or measurement meaning.

## Choose the analysis that matches the source

| Analysis | Entry and output | Boundary |
| --- | --- | --- |
| **Recorded interval** | Reports: timeline, events, process/thread history, selected-interval export | Reads captured measurements; it cannot reconstruct an uncaptured source |
| **Session investigation** | Reports: **Investigate Session**, **Investigate Saved** or **Investigate Interval**; separate findings and JSON/HTML | Detects suspicious recorded intervals, not a proven cause. An offered latest-4096-sample analysis is explicitly partial |
| **Investigation Engine 3** | Overview → Deep Inspection → **Investigate Problem**; source list, graph, partial critical path, hypotheses, verification and recurrences | Correlates supported saved evidence. `TEMPORAL_COINCIDENCE` is not `DIRECT_REFERENCE`; `BLOCKED` does not establish a lock owner |
| **Trace Decoder** | Sixth primary page: import ETL/EventPipe/BLACK.BOX JSONL, then filter process instance/thread/time | Offline decoding is distinct from capture. Sample counts are not CPU%; GC elapsed is not a stop-the-world pause |
| **Deep Inspection** | Expand inside Overview; select the relevant panel and explicit operation | Live identity, operation-specific access, consent and actual result/cleanup apply |
| **Chain Builder** | Source R60 workspace inside Overview and saved run history in Reports | Optional expert composition of existing tools; opening/previewing is passive. Source types, limits, confirmations and recovery remain those of the tools |

For Investigation Engine 3, add previously recorded sources and **Build evidence graph**. Raw ETL/EventPipe first needs Trace Decoder's index. Examine sources, missing identities, clocks and coverage before hypotheses. Manual BEFORE/ACTION/AFTER verification requires a freshly checked live target and individual action confirmation. Inputs are not overwritten. [Detailed guide](BB_INV_003_EN.md).

Trace Decoder does not download symbols or record automatically. Local PE/PDB must match the recorded module. Imported sources remain `UNVERIFIED_IMPORT`; checksums are integrity evidence, not authentication. Trace/session alignment needs usable clock evidence for the actual sources; unknown loss or clocks remain unknown. [Decoder boundaries](TRACE_DECODER_COMPLETION_PATCH.md).

## Compare and export deliberately

Keep the application/workload, process identity, profile, interval and relevant environment conditions comparable. Review action duration, CPU, available RSS/USS/private measures, handles, I/O bytes/operations, gaps/errors and available native timeouts. Comparison preserves counts, variability and incompatible conditions; source R50 can report `COMPARABLE`, `NOT_COMPARABLE` or `INCONCLUSIVE`. Missing is not zero. A median delta alone does not prove causation, a leak or a statistically established speedup.

The local library uses an index; search does not walk recording folders. Discovery of older folders is explicit. Open/compare/export and local comments are available; comments stay in the index, do not alter the recording and are omitted from share export.

In **Snapshot / compare**, **Live snapshot** and **Last comparison** select separate labelled previews. The live snapshot/live JSON use the current observation source; **Latest recording HTML** uses the latest live recording folder. Opening a different saved session for analysis does not change these sources. A comparison names its own two folders and does not overwrite the saved-analysis context or live target.

Use the export that matches the intended artifact: live observation JSON, selected saved interval, session/share copy, separate investigation JSON/HTML, decoder output, or diagnostic/chain history. These represent different scopes. Verify source identity, range and coverage in the result. Export does not upload anything.

Default share export creates redacted copies and preserves originals. Raw traces/dumps require separate inclusion. Memory, ETL and free-text notes may contain secrets; known-field redaction cannot guarantee their removal. Review before sharing. Checksums prove byte identity, not trusted origin.

## Additional native sources and consent

Windows/WCT snapshots, WPR ETW, EventPipe and minidumps are separate operations. A capture profile does not enable them. WPR has explicit Stop, TTL and a named ownership journal; ETL may include other processes. EventPipe capture uses an installed `dotnet-trace`, without automatic download, and requires a compatible .NET diagnostic port. This is separate from the bundled offline decoder. Unsupported tool/runtime/access states remain distinct; opaque `.nettrace` is not decoded GC proof.

A minidump requires separate consent and may contain secrets or briefly pause a target. Saved-dump analysis is bounded by architecture, available records and validated symbols; complete managed-heap analysis or arbitrary full unwinding is not promised. System failure events read bounded local Application records and use named payload PID fields; logger Execution PID is not the crashed target. Missing records do not establish that no crash occurred.

The source R10 **Enable administrator rights** control creates a verified, time-bounded helper session. Multiple permitted process instances can use its active lease, but each intervention retains fresh operation/target consent. The main GUI remains unelevated. Historical consent, a chain profile or opening a saved result cannot authorize a later action. If execution/cleanup is unconfirmed, preserve that status and inspect the journal rather than assuming success or repeating an intervention automatically. [R10](R10_RU.md) · [Deep Inspection](BB_DEEP_001.md) · [Chain Builder](R60_CHAIN_BUILDER_RU.md).

## Recovery and acceptance boundaries

Trash is reversible and does not free space. Permanent deletion requires separate review/confirmation for owned finalized recordings; live, external or changed data are protected. For an interrupted export, explicitly select the output directory in Settings and inspect its journal. Prepared output may be completed; partial staging needs confirmed discard. Unknown files are retained. Trace-journal recovery never stops a foreign session or the target process.

If a diagnostic run was interrupted, opening history is passive. Any continuation rechecks sources and applicable live identity; old consent is not restored from disk. An unconfirmed action or native cleanup remains unconfirmed.

Current acceptance depends on exact-commit CI evidence and the corresponding patch report. The [128-requirement checklist](BB_DI_001_IMPLEMENTATION_STATUS.md) and [production QA instructions](BB_DI_001_PRODUCTION_QA_RU.md) document earlier milestones; the old PR #17 draft status is not the current release/patch status. Short hosted checks do not substitute for real 8h Standard/1h Detailed acceptance, physical Windows 10/11, interactive Secure Desktop, assistive technology or installed upgrade/uninstall acceptance. A green source workflow is not a published Release.
