# Updates and portable maintenance (0.4.0 development candidate)

The built-in updater checks the official latest GitHub Release for a strictly newer semantic version and the named portable ZIP asset with SHA-256 digest and expected byte size. User confirmation is required to download and install. Downloading and verifying staging data does not replace the running installation. The Maintenance EXE waits for the running application to exit before proceeding.

### Filesystem guardrails

- A valid marked installation folder is required for update or removal. System roots and protected installation paths are refused.
- Windows junction/reparse points in the installation folder or its parent chain are refused; uninspectable paths fail closed.
- Staging is required to be a specific sibling folder with no junction/reparse ancestry.
- ZIP extraction refuses traversal, Windows reserved names, trailing aliases, special nodes, file/directory collisions, duplicate aliases and preexisting staging roots. Unverified or malformed archives cannot start an install.
- Local `logs`, `sessions`, `reports` inside the portable directory are moved to the new version during replacement, or into a separately named directory under Documents on uninstall. Normal user sessions stored directly in Documents are not part of the portable app removal.
- A data-directory collision aborts the replacement and restores the old executable and preserved user files, subject to filesystem availability. A locked or partly deleted backup may require manual recovery; do not advertise universal rollback.
- A verified, matching Windows desktop shortcut is removed **before** deleting the program EXE. If removal fails, the original shortcut bytes are restored without overwriting a replacement/foreign shortcut. Unrelated links are never removed.
- Uninstall removes only the application's exact `HKCU\\Software\\BlackBox\\BLACK.BOX Universal` QSettings subtree; neighboring registry entries are not deleted. Saved diagnostic evidence in Documents remains untouched.
- The GUI creates a marker-scoped helper in a new `bb-maintenance-*` temp folder. The frozen helper invokes a bounded, independent Windows Script Host cleanup after it exits. Cleanup is limited to the helper EXE, its fixed marker/script, and the empty owned temp directory; foreign files are not force-deleted.
- No cleanup is performed on arbitrary, unmarked paths.

Windows/Linux integration tests, simulated Windows rollback tests, frozen EXE smoke and native old-v0.3.6-to-v0.4.0 update/uninstall acceptance on disposable GitHub-hosted Windows are automated. The native test must pass on the exact candidate HEAD before these paths can be called CI-verified. A live in-use update, OneDrive redirection, antivirus locks, physical 100–200% DPI, and screen reader acceptance **remain manual and are not guaranteed by CI**.

Feedback opens the repository or email client on explicit user action. No session data is automatically uploaded.
