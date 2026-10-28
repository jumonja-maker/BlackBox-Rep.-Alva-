# Decoder / guardian — technical patch 2026-10-28

Base: `765156068a2d2f0171be4d048e74c7676feba143`.

## BB-08: real frame values, not JSON serialization

Confirmed old `frames_json LIKE` cannot find Cyrillic source names stored with `ensure_ascii=True`, but does match JSON keys `name`, `address` and escape syntax. New query searches `json_each` frame objects and only decoded `$.name` / `$.address`, with the existing literal `%`, `_`, backslash escaping. The saved schema is unchanged; no index rewrite or migration. Existing read_index has a 1.5 s SQLite progress deadline, a 2 MiB SQLite string budget, page size <=200 and a search length <=120. The native profile builder remains bounded at 8192 distinct groups; no full Python result-list scan or new library added. Case behavior remains the prior SQLite LIKE contract (ASCII case-insensitive; not full Unicode casefold).

Regression controls: actual native decoder index fixture with Cyrillic stack; false field-name / serialization matches absent; literal wildcard/backslash; stable filtered keyset pagination/PID; old v2 profile layout is read without migration; byte-for-byte source SQLite unchanged. Existing suite covers v1 re-decode requirement and profile-group cap.

## Additional confirmed defect: guardian exit can report stale RECORDING

Old poll returned last journal state after process exit, including RESERVED/STARTING/RECORDING/STOPPING, and stop after a previously consumed poll discarded complete terminal details and again returned stale raw state. A corrupt JSON root `[]` caused AttributeError; a foreign-instance journal could be reported as this owned capture.

New terminal observation returns CLEANUP_REQUIRED for a guardian that exited without a final journal or when journal identity/shape is unavailable, or when COMPLETED conflicts with nonzero process exit. Last journal state and exit code remain explicit; `lost_events=None`. The journal is not rewritten: no global WPR stop/cancel is introduced and only explicit named-instance recovery can confirm cleanup. The observation is cached so subsequent stop preserves exactly the result already delivered by poll. Exit is observed before reading the journal to avoid a final-write/exit race. Remaining child stdin pipe is closed after observed process exit.

Tests use genuine owned Python child exits and forced terminate, plus a controlled final-write/poll interleaving. They do **not** claim an actual WPR session was captured, killed or recovered. Birth-time collection is an unrelated constructor dependency mocked only in these journal-contract fixtures; child PIDs and exit codes remain real. Windows native WPR-negative acceptance must be reported separately if executed.

## Validation and host limits

- Initial negative run of 8 new test methods: 16 failing subcases, 1 error; one positive literal-pagination control passed. `decoder-red.log`.
- Final dedicated audit module: **10 tests PASS**, no skip (`decoder-audit-green.log`).
- Decoder/index/cpu/calltree/modules/PDB plus new audit tests: **61 tests executed successfully**; native symbol and symbol-tree classes not run because local Clang/lld-link are absent (2 class-level skip records). `decoder-green.log`. Do not present this as native-symbol acceptance.
- The old real guardian Linux test is locally blocked by host PID/proc inconsistency: `os.getpid()` differs from `/proc/self/stat`; psutil can resolve an unrelated process or raise NoSuchProcess. Root independently confirmed unshare/mount-proc unavailable. Product was not modified to accommodate that host defect. Full Windows/normal-Linux CI must run the existing real guardian test.

Reviewed adjacent decoder/index/cpu/calltree/module/PDB/native-symbol contracts and their tests. No additional confirmed defect was found within this review. Imported trace counts remain event occurrences, not CPU percentage; GC elapsed is not an application pause; native local symbol identities remain unauthenticated. No ETW loss/clock/root-cause certainty was added.

Files: src/blackbox_core/decoder_profiles.py, src/blackbox_core/trace_owner.py, tests/test_audit_decoder_20261028.py. No commit/push performed by this agent.
