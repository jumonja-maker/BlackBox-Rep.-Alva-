# Independent read-only review: decoder, guardian, optional process ownership

Reviewed current changes to decoder_profiles.py, trace_owner.py and optional_jobs.py plus their call sites/tests. No product edits in this review.

## Findings

- Decoder CPU-profile search now queries decoded JSON frame name/address values. Literal SQL LIKE escaping is preserved. JSON field names cannot create matches. Existing index v2/v3/v4 reading remains without migration. JSON1 was already used by profile construction. reader resource bounds remain: SQLite length limit and 1.5-second progress deadline in read_index. No blocker found.
- TraceSupervisor checks child exit before reading the final journal, refuses foreign-instance/non-dictionary/broken journals, and reports CLEANUP_REQUIRED after exit with RECORDING/STARTING/STOPPING/RESERVED. COMPLETED additionally requires zero exit status. It never claims native cleanup from the mere exit. poll emits one terminal observation; stop returns the cached observation after poll already consumed it. Owned journal bytes remain untouched for explicit recovery. FAILED/CLEANUP_REQUIRED remain failed/unconfirmed even at exit 0. Native target processes are not killed here. No blocker found in the new control flow.
- A missing journal while the guardian is still alive remains an explicit JOURNAL_UNAVAILABLE; this previous behavior is not converted to false terminal success.
- OptionalJobs startup now retains and cleans an owner when ready-marker writing fails, preserving the original error plus cleanup notes. Windows Job Object cleanup is not replaced by POSIX signaling. No blocker found.

## Residual numeric-PGID limitation (not a reproduced exploit)

On POSIX the new close always signals the fresh session/group even after the immediate parent exits, fixing BB-10. The normal OptionalJobs.poll path closes immediately after observed process exit. However, the ownership token remains a numeric PGID: if an owner is held long after Popen.poll reaped the leader, every member has exited, and that numeric process-group ID is later reused, a delayed close could signal the new group. This theoretical race already exists in the old explicit kill=True path and is extended to the corrected normal close. It was not dynamically reproduced, is not a Windows Job Object finding, and does not justify claiming arbitrary PID-reuse-proof POSIX tree ownership. Completely pinning the leader/group would need a separately designed lifecycle change; an obvious reused-live-PID guard could narrow but not eliminate the race. Root was informed before publication.

No new confirmed blocker requires edits from this reviewer. This is a static cross-platform review; exact-source remote Windows/Linux acceptance remains the integration gate.
