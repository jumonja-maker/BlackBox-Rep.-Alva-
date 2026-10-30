# BB-INV-003 — investigating linked observations

User and technical guide for the separate patch based on v0.5.3 (`dafa9cdb4b0f4766fc8cd2d5fd0d43579459e485`). [Русский](BB_INV_003_RU.md) · [Original specification](specifications/BB-INV-003.md).

## 1. Purpose and scope

Investigation Engine 3 connects recorded BLACK.BOX, Trace Decoder and Deep Inspection evidence, produces testable hypotheses and helps the user collect additional measurements manually. It reuses existing decoders, wait analysis, clock validation, `InspectorService`, action contracts and journals. It creates no separate collector or second Diagnostic Helper.

This is a source patch, not publication approval. Implemented code does not mean native acceptance is complete. The engine does not automatically prove internal root cause, invent confidence percentages or treat a successful intervention as proof of cause.

## 2. Opening and reading an investigation

Open **Overview → Deep Inspection → INVESTIGATE PROBLEM**, or enter from a saved incident. Add recorded sources and select **Build evidence graph**. Opening the workspace does not start recording, debugging or UAC. The six main application pages remain; the workspace has seven internal sections:

| Section | What to inspect |
| --- | --- |
| Problem overview | Sources, case identity, coverage and limitations. |
| Related observations | Paged observations and the original references behind a claim. |
| Evidence graph | The labelled class of each relation, node details and related objects. |
| Critical path | Known thread intervals and explicitly unknown portions. |
| Hypotheses | Supporting and contradicting evidence, alternatives, missing data and next checks. |
| Verification | An explicitly selected live target, available tools and separate BEFORE/action/AFTER/compare steps. |
| Recurrences | Issue fingerprints, observation history and run comparability. |

Select a row to inspect its details. Thread, stack, module and Trace Decoder interval navigation require recorded references. An unsupported reference is not replaced with a similar name or PID. A moved investigation index may lack the private local path to its original source: add that source and rebuild. The index does not contain the private navigation path map.

## 3. Sources, identity and clocks

Inputs include BLACK.BOX session folders, Trace Decoder SQLite indexes, Deep Inspection journals, Investigation Engine 2 JSON, recorded application JSONL events and saved minidump metadata. Import ETL/EventPipe through the existing Trace Decoder first; the investigation reads its index. The existing dump inspector extracts metadata from a saved minidump without copying memory contents into the graph.

Sources are read without migrations or overwrites. Readers check schemas, sizes, hashes, file stability and acceptable SQLite structure. Active WAL, corruption or a changing source prevents publication of a successful new index. A bounded or unfinished scan may produce a partial graph with explicit coverage.

Every import remains `UNVERIFIED_IMPORT`. A matching SHA-256 identifies content; it does not authenticate its author or origin. Observation IDs depend on source content and record identity rather than the current filename.

A live process uses exact PID and Windows creation FILETIME; a thread also needs supported thread identity. TraceEvent `ProcessIndex`/`ThreadIndex` identify objects within a particular trace. PID/TID alone, an image name, approximate UTC or seconds-based creation time cannot join a historical object to a live process.

Each source retains its original clock domain. Cross-domain relations use only admissible existing `decoder_alignment.py` checks and uncertainty bounds. Without evidence, the relation remains `NOT_ESTABLISHED`; different Windows boots or process lifetimes are not merged. `EXACT_IDENTITY` describes agreement of recorded identities, not authenticity of an imported source.

## 4. Interpreting results

Relations distinguish `EXACT_IDENTITY`, `DIRECT_REFERENCE`, `BOUNDED_TIME_CORRELATION`, `OBSERVED_DEPENDENCY`, `TEMPORAL_COINCIDENCE`, `HYPOTHESIS_ONLY`, `NOT_ESTABLISHED` and `CONTRADICTED`. Temporal coincidence does not establish dependency. A file error code belongs to the source that recorded the outcome; it is not copied into a nearby ETW event without a supported reference. Network metadata, process I/O counters and physical DiskIO completions retain separate meanings.

Critical paths are always partial. `RUNNING` needs actual dispatch/switch-out pairs from an admissible complete scheduler source. `BLOCKED`/`READY` reuse `decoder_waits.py` intervals. CPU samples are not converted to running duration and gaps are not interpolated. Loss, ordering problems or incompatible overlaps produce `UNKNOWN`/`INCOMPLETE` and disputed durations are withheld. WCT is a chain observed at a particular instant; ReadyThread does not identify a lock owner. The sum of known states is not the application's complete operation duration.

Hypotheses cover CPU, execution delay, waits, memory growth, file errors, networking, process exit, UI responsiveness and failed diagnostic actions. `CANDIDATE` is a proposal; `SUPPORTED_BY_OBSERVATION` has specific observational support; `INCONCLUSIVE` lacks sufficient validation; `CONTRADICTED` has contrary evidence. User conclusions are recorded separately as `USER_REPORTED`/`USER_CONFIRMED`. The schema reserves `SUPPORTED_BY_CONTROLLED_EXPERIMENT`, but the engine never assigns it automatically: repeated matched workloads and negative controls are not implemented here.

## 5. Manually verifying a hypothesis

1. Select a hypothesis and inspect its evidence and gaps. A separate catalog of manual Deep tools is also available; choosing a tool does not make it a hypothesis recommendation.
2. In **Verification**, select the current process for **NEW measurements** and confirm. This creates a separate case branch while retaining original observations and clocks. The new target's relation to historical evidence stays `NOT_ESTABLISHED`.
3. Select **Capture BEFORE** and wait for its result and recorded snapshot ID.
4. Choose an action and enter explicit JSON parameters. Inspect its rights, impact, timeout, preconditions, cancellation and cleanup contract. Memory addresses, TIDs and output destinations are not guessed.
5. Select **Confirm chosen action**. Execution uses the existing Deep path and rechecks the current target. `ADMIN_REQUIRED` uses the normal Windows UAC route for a scoped helper; the GUI remains unelevated. Denial leaves the saved investigation usable.
6. Separately select **Capture AFTER**, then **Compare BEFORE / AFTER**. Comparisons reference the exact snapshot IDs. Changed measurements remain observations; without additional controls the causal verdict stays `INCONCLUSIVE`.

Every step is explicit. Changing target invalidates previous consent. A failed step stops that experiment; a retry needs a new BEFORE and run ID. `RECOVERY_UNCONFIRMED` or failed evidence persistence must never trigger automatic intervention retries: inspect the outcome and use existing Deep Inspection cleanup first. Cancelling saved-data analysis and cancelling a chosen native diagnostic step use separate controls.

## 6. Storage, limits and recurrences

The schema is `blackbox.investigation-graph/1`, algorithm version `3.0.0`. The owned SQLite index is published atomically as a new file; inputs and unrelated existing files are never overwritten. Opening validates index integrity and reference structure, but the result remains an imported derivation rather than authenticated evidence. Rebuild from current sources to revalidate source-supported links.

Default limits are 250,000 events per pass, 10,000 nodes, 20,000 edges and 32 MiB of structured results. These are processing budgets, not a guarantee of total RAM usage. The graph draws at most 80 nodes and 160 edges; tables use bounded pages. Coverage, omissions and cursors expose scan limits. Source cursor/interval continuation is available through the API; GUI page controls browse observations already built rather than automatically consuming the whole trace. Analysis runs outside the Qt event loop with cancellation and timeouts.

**Export investigation** saves JSON or standalone HTML with provenance, limitations and manual conclusions. Choose a new filename. Ordinary exports exclude memory contents, dumps, environment variables, recognised secret fields and private navigation paths. Review user-entered free text before sharing. Export does not upload data to a cloud service.

Recurrences use recorded stable application, error, operation and supported module/stack anchors. A PID, ASLR address or error message alone is insufficient. **Merge/split groups** requires a reason, retains `USER_REPORTED` history and leaves source events intact. Frequency describes observations per recorded case; independent clocks do not establish a global first occurrence.

Run comparison requires verifiable `app_identity` (`application_id`, `version`, `sha256`), `scenario` (`scenario_id`, `workload_id`, `operation_count`, `input_bytes`, `source_profile`), independent captures and sufficient comparable coverage. Supply these through the API or an existing saved case; missing context is not inferred. Insufficient conditions return `NOT_COMPARABLE`. An absent error means only “not observed in this comparable run”, not proof of a fix.

The `blackbox_core.investigation_v3` facade exposes case creation/loading, related evidence, critical paths, hypotheses, action catalogs, manual scenario preparation, comparisons, grouping and export. `InvestigationBudget` and `cancel_event` bound operations; use source `selection` and cursors for large traces.

## 7. Validation and remaining boundaries

Automated acceptance runs exclusively on GitHub-hosted runners. [BB-INV-003 QA](../.github/workflows/bb-inv-qa.yml) covers Windows/Linux contracts, controlled real Windows workloads, RU/EN/DPI GUI checks and stress; [general QA](../.github/workflows/shell-qa.yml) covers the rest of the product and portable packaging. At guide preparation, final gates are still pending. Final results must identify completed runs and the patch's exact SHA; the existence of test files does not mean PASS. No application tests were run locally.

Windows CI does not replace physical Windows 10/11 user acceptance or arbitrary third-party application testing. Full registry capture, managed heap analysis, universal dump root-cause analysis, every JIT/PDB/WOW64/ARM64 variant, cloud synchronization and a graphical automation builder are outside this patch. Release publication requires separate approval.
