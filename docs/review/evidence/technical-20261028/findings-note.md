# BB-05 / BB-06 and related export correctness

Base: 765156068a2d2f0171be4d048e74c7676feba143. No commits, no publication performed by this worker.

## Reproduced defects / fixes

- **BB-05:** UI streamed persisted, counter, research and action findings; export omitted the fourth stream. A shared `finding_streams` generator now supplies both. No whole-history list introduced; SQL sorting and bounded UI pagination preserved. A 65-action fixture crosses the first UI page and exports the exact same IDs in JSON/CSV/HTML. Explicit clipped interval produces the same clipped action finding ID and retains `partial_action_interval`.
- **BB-06:** the first redact pass erased note/comment before consent was evaluated. Finding export now calls the shared redactor once with a consent flag scoped to `USER_REPORTED` findings, followed by identifier/field projection. Central redaction still removes arbitrary `attributes`, recognized paths/URLs and other sensitive fields. Non-user evidence notes remain omitted even when user notes are allowed. Default false remains private.
- **Adjacent confirmed omission:** legacy `user_problem` research rows with source USER or BLACKBOX_LEGACY were not selected at all. The query now narrowly includes this known producer kind; new USER_MARKER rows retain their original path. This adds a user statement, never an OS/root-cause attestation.
- **Adjacent confirmed series mismatch:** `export_interval(series='STANDARD')` reported 8 standard samples, but the findings silently auto-selected 2 detailed samples. Explicit series now propagates to the finding writer.
- **Adjacent confirmed tail omission:** default interactive analysis extends through the research tail, while default export ended at the last resource sample. User comments made after that sample disappeared from export. Default end now matches investigation; an explicitly selected end remains unchanged.
- **Adjacent confirmed privacy gap:** scalar event_type/correlation_key in interval `.events.jsonl` could retain known paths although JSON detail was omitted. Each final exported event now uses the central path/URL redactor. Source evidence remains read-only.
- Findings reuse `csv_safety.csv_safe`, created/owned by the privacy agent; its old import path remains compatible through re-export.

## Tests

`test_audit_findings_20261028.py`: **10 new PASS**. On a separate exact-baseline git-archive snapshot: **7 FAIL / 3 positive PASS**; see findings-red-all.log. Initial unmocked six-test run also reproduced five data defects and one positive control (findings-red.log).

The 10 new tests plus existing `test_investigation_v2`: **17 PASS, 0 SKIP**, findings-green.log. Existing controls include 513 incident IDs, 10,003 event paging, immutable source hashes, no false root cause, action coincidence and explicit gaps. New controls include no-clobber repeat export, cancellation that preserves an unrelated file, all-format default notes omission, opted-in marker/legacy notes, and exclusion of arbitrary app attributes.

## Test boundary and runtime limitation

New fixtures use real synthetic SQLite files, the production parser/analysis/export/transaction/publication code, and independently reread output documents and SHA-256 source bytes. They do not attach to a real process. Only `psutil.Process().create_time()` for the export transaction owner metadata is explicitly mocked: this environment's `/proc` mount can disagree with Python PID namespace (NoSuchProcess for current PID). This avoids mistaking that host limitation for an export-data defect; it is not proof of OS owner-liveness/recovery correctness. The default production owner implementation is untouched. Windows and full integration tests remain the root agent's responsibility.

Static pyflakes on owned files reports no undefined names; two unused interval_report imports already existed in the base (os/tempfile) and were not cosmetically altered. HTML finding IDs are generated SHA-256 hex digests in all streams, so the raw article-id interpolation has no discovered imported-attribute injection path.

## Compatibility / remaining scope

No storage schema, release version, public UI page or source evidence is rewritten. Export consent does not cover arbitrary secrets hidden in free text; recognizing every secret is not claimed. Derived-trigger budget and SQL deadline behavior stay explicit. This patch does not add a complete forensic reconstruction or infer a root cause from counter coincidence.
