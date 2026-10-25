# BB-DI-001 — controlled endurance retry, 25 October 2026

## Preserved failures, not retroactive PASS

Original long run 40174622393 on 48b99ec587789ae4d08bc3a4a2004822483708e9 failed after both requested durations. The existing fix in f55025c14a28448348b2d4314c5e9389aa1925eb replaces an unconditional SQLite progress-handler cancellation with a five-second monotonic deadline. Original artifacts and failed outcomes are retained; they are not rewritten as successful runs.

Full CI 40194071431 on f55025c1 passed Linux and failed Windows at tests/test_real_scale_workloads.py while opening the disposable CPU fixture's state.json (PermissionError). The trace identifies the failing read but not the identity of the handle briefly denying access. It is not evidence that CPU measurements or the SQLite correction are wrong.

## Bounded QA protocol correction

- A QA-only wait_fixture_ack helper retries native Windows error codes 5/32/33 or Windows CRT errno-only EACCES without a native error code, within the original five-second ACK deadline. CPython FileIO uses _wopen and reports errno for this path: a sharing denial can appear as PermissionError [Errno 13] without winerror. That fallback is never enabled on POSIX or for unrelated native codes.
- The exact command ID is required and the original fixture error field is returned unchanged. No chmod, ACL changes, elevation, synthetic ACK, lowered CPU expectation or skipped functional test.
- Missing files, malformed JSON and unrelated errors propagate. Permanent denial and stale ACKs expire as failures. The command writer reuses the existing atomic_json owned-file primitive.
- Ten tests cover recovery, permanent denial, Windows CRT errno-only behavior, mismatched ACK, malformed/missing data, retained command errors, bounds, and an actual Windows exclusive CreateFile handle released by a fixture thread. The last test is explicitly Windows-only.
- Three additional real-SQLite tests cover 9906 and 100001 rows, cancellation after the real time limit, and a wrong source mapping hidden within an otherwise matching large count. Large synthetic rows are query tests, never elapsed endurance evidence.
- The first retry candidate 7dffc2a26c0902c686d69d65e1b9ec1f2936b89f handled native errors only. Review caught the missing CRT errno fallback before long runs; this follow-up preserves that history and uses a new exact-source candidate. Do not treat a superseded run as evidence for the new one.

## Retry gate and evidence

The same explicit commit subject starts the existing one-time endurance workflow. New preflight first waits for the existing shell-qa.yml workflow to complete SUCCESS on exactly the same head SHA (Windows/Linux and real packaged-EXE checks). It uses actions:read only; it cannot rerun, cancel or modify the other workflow. Failure/cancellation or no success within 28 minutes blocks the long jobs. After that, both existing 90-second real GUI preflights must succeed.

Only then STANDARD 19800 real seconds and DETAILED 3600 real seconds start on separate hosted Windows runners. The existing strict final SQLite parity, CLOSED/COMPLETED, source identity, interval query/export and original-hash checks are unchanged. No run or job from the older SHA is reused as evidence for this candidate. The hourly chat monitor should track the new run ID, not the failed original.

The 5h30 Standard run is an explicitly requested GitHub-limited trial, not the original 8h Standard M-064 acceptance. Hosted Windows offscreen is not physical Win10/11 QA. Full final outcomes remain pending until the new jobs and qa-verdict artifacts complete. Main and releases stay untouched; PR #17 remains Draft.
