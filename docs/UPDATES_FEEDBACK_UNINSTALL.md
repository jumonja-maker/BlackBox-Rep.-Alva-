# Updates and portable maintenance

**Current source/development candidate: v0.6.1. Latest published official release: v0.6.0 (2026-11-09).** The [official GitHub Release](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/releases/latest) determines downloadable updates. A source version, a development branch or green CI does not publish a new release.

The built-in updater checks the official latest GitHub Release for a strictly newer semantic version and the named portable ZIP asset with SHA-256 digest and expected byte size. User confirmation is required to download and install. Downloading and verifying staging data does not replace the running installation. The Maintenance EXE waits for the running application to exit before proceeding. A development build reporting no newer verified official version does not establish that its own version has been published.

## Filesystem guardrails

- A valid marked installation folder is required for update or removal. System roots and protected installation paths are refused.
- Windows junction/reparse points in the installation folder or its parent chain are refused; uninspectable paths fail closed.
- Staging is required to be a specific sibling folder with no junction/reparse ancestry.
- ZIP extraction refuses traversal, Windows reserved names, trailing aliases, special nodes, file/directory collisions, duplicate aliases and preexisting staging roots. Unverified or malformed archives cannot start an install.
- Local `logs`, `sessions`, `reports` inside the portable directory are moved to the new version during replacement, or into a separately named directory under Documents on uninstall. Normal user sessions stored directly in Documents are not part of the portable app removal.
- A data-directory collision aborts replacement and attempts to restore the old executable and preserved user files, subject to filesystem availability. A locked or partly deleted backup may require manual recovery; universal rollback is not guaranteed. Preservation uses filesystem renames and can refuse a move across volumes before removal starts.
- A verified, matching Windows desktop shortcut is removed **before** deleting the program EXE. On a failed removal, original shortcut bytes can be restored without overwriting a replacement/foreign shortcut. Unrelated links are never removed.
- Uninstall removes only the application's exact `HKCU\Software\BlackBox\BLACK.BOX Universal` QSettings subtree; neighboring registry entries are not deleted. Saved diagnostic evidence in Documents remains untouched.
- The GUI creates a marker-scoped helper in a new `bb-maintenance-*` temp folder. The frozen helper invokes a bounded, independent Windows Script Host cleanup after it exits. Cleanup is limited to the helper EXE, its fixed marker/script, and the empty owned temp directory; foreign files are not force-deleted. Windows Script Host, filesystem permissions or antivirus locks can prevent completion.
- No cleanup is performed on arbitrary, unmarked paths. Maintenance errors are recorded separately in the user's `BLACK.BOX Universal\maintenance-errors.log` when the location is writable.

## Verification scope

The current `.github/workflows/shell-qa.yml` configures Windows/Linux integration tests, rollback/hardening tests, frozen EXE smoke and native portable update/uninstall QA from the immutable published **v0.6.0** baseline. The native harness is `tools/qa_windows_maintenance_e2e.py --baseline-release v0.6.0`; it checks the pinned old release, the exact new candidate, restart, preserved evidence, shortcut/settings removal and helper cleanup on disposable GitHub-hosted Windows.

These are configured checks, not a claim that the final candidate has passed. They must complete on the exact final candidate before the corresponding behavior is called CI-verified. A locally supplied v0.6.1 candidate in this harness does not establish a public v0.6.1 Release. Use the patch's actual run links, source SHA and results for current acceptance.

Earlier versions of this document described the v0.4.0 development milestone and an old-v0.3.6-to-v0.4.0 scenario. That is historical scope, not evidence for the current v0.6.1 candidate or the current v0.6.0 baseline gate.

A live in-use update, OneDrive redirection, antivirus locks, physical 100–200% DPI, and screen reader acceptance remain separate manual checks and are not guaranteed by hosted CI. Executables remain unsigned. Required access to the portable parent, temporary directory and user-data folder is still subject to Windows policy.

Feedback opens the repository or the user's mail client on explicit user action. The recipient is **[DonJeoJesky@outlook.com](mailto:DonJeoJesky@outlook.com)**. No session data is automatically uploaded; review excerpts before sending and remove sensitive information.
