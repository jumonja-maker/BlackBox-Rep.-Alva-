# BLACK.BOX Universal — manual Windows release acceptance

**Status: NOT RUN.** This is a proposed hands-on protocol, not a claim of acceptance. Prepared 2026-10-22 for cumulative [Draft PR #12](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/pull/12) at exact source SHA `4b1dd4c3be1b2654e03e56b60272840a717b81b1`.

## Test candidate and rules

- Download **BLACK.BOX-Universal-Windows** from [successful Actions run #39838913391](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions/runs/39838913391) (artifact ID `12452241891`, expiration 2026-11-05), not the obsolete PR #7 build or a historical Release. The Actions artifact is **not** an official Release.
- On an ordinary **Windows x64 PC or clean VM**, use a standard, non-admin user account, no installed Python and no private Alva. Extract **the complete** `BLACK.BOX-Universal` directory from the archive; do not move the EXE away from its `_internal` directory.
- Before taking screenshots, redact user names, process lists, documents and personal paths. Never upload private Alva source/wheel, credentials, full process dumps or sensitive logs to public PR comments. Record OS build, DPI scaling, AV status, ZIP origin and optionally local ZIP SHA-256; **a ZIP hash recorded by the tester is not a claim of GitHub code signing**.
- For ordinary tests no terminal, Python, admin rights or AI account should be needed. All planned tests below begin **NOT RUN**. Use `PASS` only when personally observed; `LIMITED` for incomplete coverage, `FAIL` with reproduction details, `BLOCKED` for missing external prerequisites.

## Human GUI acceptance — run with the actual mouse and desktop

| ID | Action | Expected result |
| --- | --- | --- |
| W01 | Disconnect from internet; double-click `BLACK.BOX-Universal.exe` inside extracted folder | Native window opens without Python, PowerShell, login, account, admin elevation or cloud service. An optional update-check failure does not block use |
| W02 | Inspect navigation and open each page | Exactly Overview, Processes, Event Log, Reports, Settings; no Alva Lab, setup Python, AI Handoff or separate deep-diagnostics page |
| W03 | Toggle RU → ENG → RU, close and reopen | Labels change and preference persists; no stale Alva/AI consumer actions |
| W04 | Open Processes, refresh and search for a safe user-owned process such as Notepad; select/Attach | Process can be selected without starting observation. Normal insufficient access gets a clear error, not a privilege bypass |
| W05 | Open Overview; Start, use the selected process, observe for at least 30 seconds, Stop | CPU/RSS/live graph and sample count correspond to available OS data; normal Stop finishes without freezing |
| W06 | Open newly saved session in Documents | `session.sqlite3`, `report.json`, `report.html` exist and `ai-handoff.json` was NOT generated. Existing old sessions must remain untouched |
| W07 | Open `report.html` in a browser with network disconnected | Readable standalone RU+EN report, timestamps, metric units, error codes, and explicit statement that target application's root cause is not proven. No remote scripts or CDN needed |
| W08 | Repeat a second 30-second observation; use Reports to compare two sessions | Comparison opens and shows honest before/after differences; does not assert an application regression or code-level cause |
| W09 | Use Reports' explicitly requested JSON export | File is written where selected; no automatic sharing or upload |
| W10 | Exit target process during a session; exercise an inaccessible process and PID reuse where safely reproducible | Errors `PROCESS_EXITED`, `ACCESS_DENIED`, `PID_REUSED` or other accurate observer statuses, without crashing or falsely claiming a completed healthy session |
| W11 | Change interval to 1 / 2 / 5 seconds, then test display scaling at 100%, 150%, 200% | Settings work, controls remain usable and text is readable without clipping at the tested resolutions |
| W12 | Create desktop shortcut in Settings, close app and start through shortcut | Target points to the real portable EXE; check icon and localization. Generic icon is a cosmetic finding unless shortcut cannot launch |
| W13 | Leave application running for an extended session (suggested at least 30 min and 1,000+ samples in a separate stress run) | No unbounded UI growth or loss of persisted samples; handle storage access failures and abrupt termination without overwriting older sessions |
| W14 | Test Documents redirected to OneDrive and a read-only/low-space location in a controlled test profile | No silent data loss; protected folders produce explicit storage errors, and already finalized reports survive |
| W15 | Check Windows Defender/reputation and ordinary antivirus/file-lock behavior | Record real warnings and file locks; do not claim unsigned EXE has good reputation merely because CI passed |

Avoid testing arbitrary system/security processes by elevating privileges. Do not intentionally cause loss of genuine user data.

## Maintenance acceptance — MUST use disposable folders and backups

| ID | Action | Expected result |
| --- | --- | --- |
| M01 | With test sessions/logs copied into portable folder, click uninstall but **cancel** confirmation | No deletion, shortcut changes or data relocation |
| M02 | Confirm uninstall of disposable portable copy | App closes, helper removes **only** that marked portable folder, moves internal `logs/`, `sessions/`, `reports/` to Documents preservation path, and retains sessions already in Documents |
| M03 | Try controls on unmarked source folder or a different folder under a test profile | No deletion of unmarked folders; no broad cleanup |
| M04 | Check maintenance log and desktop shortcut after uninstall | Any failure is recorded outside deleted folder; only shortcut targeting this app is removed |
| M05 | Once an official newer GitHub Release with verified SHA-256 is available, check Updates from a safely installed previous version | Button turns green only for a newer valid Release; consent required; checksum and archive path validation; old runtime replaced without accumulating old releases |
| M06 | On a disposable test copy simulate file locks/interrupted maintenance in a controlled manner | Rollback or clear failure without deleting unrelated files; preserves user data and avoids broken partial update |

**M05/M06 are BLOCKED until a safe, actually publishable Release/update test setup exists.** An Actions PR artifact cannot serve as official update metadata and must not be treated as one. Never create a public stable Release merely to satisfy a smoke test.

## Private Alva integration — separate authorized gate

Only on a maintainer-controlled, already-authorized host with independently established legal access: preserve the private Alva source SHA and wheel SHA-256 in a **private** test record; invoke `tools/verify_authorized_alva.py` with that approved Python interpreter; capture positive (3 host traces / 4 P4) and negative empty-sample outcomes, plus preservation of standard human reports if the optional worker fails. An `-I` Python flag is not a sandbox or package provenance attestation. Mark **BLOCKED** without such an environment. No private package, API dump or wheel belongs in the public CI or PR.

## Evidence form — fill in only after real execution

| Field | Observed value |
| --- | --- |
| Executor / date / Windows edition, build, architecture | NOT RUN |
| Hardware/VM, standard user, display resolution/DPI | NOT RUN |
| Downloaded run, source SHA, artifact name and local ZIP SHA-256 | NOT RUN |
| Python absent? Network disconnected? Antivirus product/status? | NOT RUN |
| W01–W15: individual PASS/LIMITED/FAIL/BLOCKED + evidence | NOT RUN |
| M01–M06: individual PASS/LIMITED/FAIL/BLOCKED + evidence | NOT RUN |
| Genuine Alva separate check (if legally available) | BLOCKED |
| Issues/bugs with reproducible steps and redacted screenshots | None recorded |
| Reviewer / owner acceptance decision and date | NOT APPROVED |

Any fix to executable code creates a **new source SHA**, invalidates this exact-head certificate for the changed build and requires rerunning the appropriate CI plus affected manual checks. Owner/reviewer approval is required before lifting Draft/release gates.
