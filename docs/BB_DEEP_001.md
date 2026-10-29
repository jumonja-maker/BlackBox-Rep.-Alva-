# BB-DEEP-001: Deep Inspection patch

This is the separate `patch/bb-deep-001` development patch, based on the v0.5.2 source. It is not an official Release or an automatic update. The [original owner specification](specifications/BB-DEEP-001.md) is retained separately; [Russian instructions](BB_DEEP_001_RU.md) describe the same scope.

## Entry point and modes

Select a running process on Processes, then expand **Deep Inspection** in Overview. CPU/RSS graphs, recording, previous research controls and the six main pages remain available. The new sections are internal panels, not a seventh page. Opening a panel does not attach a debugger, capture memory or request UAC.

| Mode | What it means |
| --- | --- |
| OBSERVE | Existing sampling and recorded evidence. No change to target execution. |
| INSPECT | Explicit process/module/thread/handle/memory queries, live stacks, WCT, connection metadata and diagnostic snapshots. Some operations briefly suspend threads or capture sensitive data. |
| INTERVENE | Explicit debugger, breakpoints, execution control, owned thread suspension and compare-before-write memory changes. Confirmation is specific to the selected target and action. |

The target is an exact process instance: PID plus the creation FILETIME returned by Windows, with executable identity where available. TID alone never identifies a persistent thread. A changed or exited target is not replaced silently with the newest process that has the same PID.

## Ordinary permissions and UAC

Choose an operation first. BLACK.BOX checks the rights needed for that operation and keeps ordinary observation available. If access can be requested, the UI explains the target, operation and possible effect before invoking **Windows' own UAC prompt** for the dedicated Diagnostic Helper. The main GUI remains `asInvoker`; BLACK.BOX never collects an administrator password.

The elevated session is scoped to a target and an allowlist of operations, has a finite lifetime and can be closed from Overview. `ADMIN: ACTIVE` describes that helper session, not unlimited permissions for every application feature. A rejected UAC request leaves ordinary mode usable. Windows can still refuse access after elevation; protected-process and debugger conflicts must retain their observed status.

The local named pipe uses a restricted DACL, rejects remote clients and checks peer process identity as well as a single-use handshake. Commands are typed diagnostic operations, not shell strings. Output dumps use an ordinary-user-created exclusive file handle rather than allowing a privileged helper to open an arbitrary destination path.

## Inspecting a target

| Panel | Evidence and actions | Boundary |
| --- | --- | --- |
| Processes | Process identity, creation time, owner, image and process relations | Access failures and vanished processes remain visible. |
| Modules | Loaded images, base/size/layout and local PE/PDB review | Matching names are not identity; local GUID/age consistency is not a live module load proof. |
| Threads | Thread identities, current contexts/stacks, WCT and owned suspend/resume | A live snapshot and a historical ETW stack are different observations. |
| Handles | Target handle inventory and available object metadata | Type/name lookup is bounded and may remain incomplete. |
| Memory | Virtual regions, explicit bounded read, normal/extended dump and saved dump inspection | Memory/dumps can contain private data and are excluded from ordinary sharing. |
| Network | Observed TCP/UDP endpoints and related recorded kernel events | Metadata is not packet content; absent transfer counters remain absent. |
| Disk | Process I/O counters, available files and recorded kernel event metadata | Process counters are not physical device activity. |
| Debug | Attach, pause, context, single step, continue, breakpoints and detach | These change execution and may alter timing or application behavior. |
| Timeline | Operation journal, snapshots and comparison | Before evidence is retained; later state does not overwrite it. |

Current stacks use Windows PSS snapshot contexts and a copy-on-write VA clone; Windows may briefly pause the target during capture. Deep Inspection does not increment target suspend counts for this stack reader. Explicit thread-control actions are separate: BLACK.BOX records its own suspension actions and attempts to release exactly those actions, without clearing another tool's suspend count. A failed or unverifiable recovery is `RECOVERY_UNCONFIRMED`, not successful cleanup.

## Memory and debugger actions

For a memory write, specify the address, expected original bytes and replacement bytes, review the exact target and confirm. The engine verifies original bytes, performs the requested write and reads the result back. A later rollback attempt checks the current state before restoring the original bytes. A successful byte readback does not reverse effects the application may already have caused while different bytes were present.

Debug attachment uses Windows Debug API and records the lifecycle separately from the sampler. After attach, the helper requests `DebugSetProcessKillOnExit(False)`. This does not remove the risk of a helper crash before that setting succeeds. Breakpoints and owned suspensions need explicit cleanup; an interrupted cleanup is reported as unconfirmed. Do not infer successful restoration merely because the helper process exited.

Debug contexts and software breakpoints currently require native AMD64. WOW64 and ARM64 targets are explicitly refused by the context architecture check. Before inserting a breakpoint, the separate guardian acknowledges both the original byte and page protection. Normal and emergency cleanup verify restoration of both; a competing protection change leaves recovery unconfirmed. Byte/protection restoration alone cannot prove that an interrupted instruction or the application's side effects were recovered.

**ETW profiling:** Timeline can request a fixed `GeneralProfile.Light` capture for 1–30 seconds, with explicit confirmation that the recording is system-wide and may contain other processes. Only the scoped diagnostic helper is elevated. WPR writes to an administrator-owned protected staging directory, supervised by a separate named-session owner. The helper copies the finished ETL into the GUI's already-open destination HANDLE and verifies its hash by readback. This is a bounded memory-mode recording with a post-flush size check, not a hard disk quota. Cleanup that cannot be confirmed remains `RECOVERY_UNCONFIRMED`; recordings are not automatically added to share exports.

The operation journal separates requested action, observed state, performed changes, returned result and recovery status. `COMPLETED` means the operation's own verification finished; it does not establish an internal application root cause or complete reversibility.

## Historical traces, local symbols and dumps

**Trace evidence:** choose a decoded SQLite index, then explicitly select its process instance. TraceEvent's `ProcessIndex` is a trace-local identifier; it is not a live Windows creation FILETIME. Matching PID, image name or approximate wall time does not establish a join. The historical panel preserves `live_target_relation: NOT_ESTABLISHED`, original source hash, trace instance, thread/time filters and capture-loss uncertainty. No selection returns candidate instances without attributing rows to the live process.

Historical stack frames retain original addresses/names and load-window module metadata. The existing scheduler analysis supplies bounded off-CPU/ready intervals with its original loss/order restrictions. The new typed I/O projection recognizes classic-kernel disk read/write completions and supported TCP/UDP send/receive events. It keeps per-event byte counts and endpoints; a disk completion's reported QPC duration is checked against the persisted source frequency and TraceEvent's elapsed milliseconds. Its derived start is labelled as a completion-reported interval, not a separately observed start boundary or proof of device busy time. Other generic fields retain unknown units instead of becoming a guessed latency. Network events do not establish transfer totals or send/receive latency, and no packet bodies are invented. Older indexes remain readable but need re-decoding for typed I/O evidence.

**Symbols:** choose local PE and PDB files. BLACK.BOX checks their recorded GUID/age using the existing decoder readers. Optional RVA lookup uses native function ranges, available C13 lines, inline sites and OMAP support. This does not itself bind those local files to a live loaded image. No symbol-server lookup or source-file execution occurs.

**Minidump view:** open a saved dump in Deep Inspection or use **Open Dump** directly in Trace Decoder, including after the original process has exited. This is a separate bounded local reader, not a claim that the TraceEvent engine parses minidumps. It reads the stream directory, saved modules/RSDS identities, saved thread contexts, captured memory ranges and available process metadata. A supported AMD64 control context exposes the saved instruction pointer and its matching saved module/RVA. Full dump stack unwinding, managed heap analysis and arbitrary JIT mapping are outside this reader. Creation time in a dump's standard miscellaneous stream is only second-resolution and cannot prove an exact live FILETIME identity.

Dump metadata inspection does not return memory bytes. An explicit saved-memory read is limited to 4096 bytes and rejects absent, overlapping or cross-range descriptors. The default dump size limit is 2 GiB; metadata reads are limited to 8 MiB, lists to 65,536 entries and display lists to 200 rows. Large/unsupported/damaged structures fail with an explicit reason; partial bytes are not silently interpreted as valid structures.

After opening a dump in Trace Decoder, enter a saved address and length in **READ SAVED DUMP MEMORY**. This works without a live process or trace index. Private bytes appear in a separate view and never enter **SAVE DUMP METADATA**. File replacement, cancellation or changing the selection invalidates pending reads. File identity checks detect changes during review; they are not authenticated provenance.

## Status and recovery

`AVAILABLE`, `ADMIN_REQUIRED`, `UAC_CANCELLED`, `ACCESS_DENIED`, `PROTECTED_PROCESS`, `PROCESS_CHANGED`, `ALREADY_DEBUGGED`, `OPERATION_FAILED`, `INCOMPLETE_EVIDENCE` and `COMPLETED` retain different meanings. Cancellation/deadline/session expiration and `RECOVERY_UNCONFIRMED` are explicit additional states. Show the underlying Windows error where it is available; access denial alone does not prove PPL protection.

Closing the deep panel's active session or exiting the application requests owned cleanup. Emergency recovery is best effort and must report which state was actually verified. Memory writes and application side effects are not automatically reversible. Snapshot comparisons show observed differences, not an assertion that an intervention caused every difference.

If instruction-pointer, trap-flag or breakpoint restoration cannot be verified while a debug event is held, cleanup retains the owner instead of knowingly continuing that event. The GUI stays open with **RECOVERY_UNCONFIRMED** and **Retry diagnostic cleanup**. This does not extend the original 15-minute helper lease; expiry or forced process termination is a last-resort boundary that may resume an unverified execution context. A lost operation acknowledgement remains unconfirmed even if later cleanup succeeds. Confirmation is bound to the selected process instance and is discarded if selection changes while a dialog is open.

## Automation and acceptance

All automated tests for this patch run **exclusively on GitHub-hosted runners** through [bb-deep-qa.yml](../.github/workflows/bb-deep-qa.yml). The patch workflow runs Linux/Windows contracts, native controlled Windows acceptance, the existing application regressions and actual portable-EXE checks. It does not publish a Release.

The optional endurance job requests 19,800 seconds (5 hours 30 minutes) of continuous controlled work, within the hosted job's six-hour limit, reserving time for stop, integrity analysis and artifact upload. A shorter or interrupted run must report actual elapsed time and incomplete acceptance. It is never described as an eight-hour continuous recording. Dispatch `run_endurance=true`, or use the documented `[deep-endurance]` commit marker when the final source is ready.

Synthetic format/policy tests prove parser and state-machine behavior only. Real Windows fixtures must separately prove native operations, standard-token behavior, elevated helper checks, cancellation, controlled I/O and target survival/recovery. Hosted API/UAC mocks do **not** establish interactive UAC Secure Desktop behavior. Physical Windows 10/11, real UAC approval/cancellation and display/hardware acceptance remain separately identified.

No CI pass, final acceptance or root cause is asserted merely by the presence of this guide. The final technical report must name the exact source commit, workflow run, actual outcomes, skipped/manual items and unresolved limitations.
