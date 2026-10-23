# Updates and portable maintenance (v0.3.6)

The built-in updater checks the official latest GitHub Release for a strictly newer semantic version and the named portable ZIP asset with SHA-256 digest and expected byte size. User confirmation is required to download and install. Downloading and verifying staging data does not replace the running installation. The Maintenance EXE waits for the running application to exit before proceeding.

### Filesystem guardrails

- A valid marked installation folder is required for update or removal. System roots and protected installation paths are refused.
- Windows junction/reparse points in the installation folder or its parent chain are refused; uninspectable paths fail closed.
- Staging is required to be a specific sibling folder with no junction/reparse ancestry.
- ZIP extraction refuses traversal, Windows reserved names, trailing aliases, special nodes, file/directory collisions, duplicate aliases and preexisting staging roots. Unverified or malformed archives cannot start an install.
- Local `logs`, `sessions`, `reports` inside the portable directory are moved to the new version during replacement, or into a separately named directory under Documents on uninstall. Normal user sessions stored directly in Documents are not part of the portable app removal.
- A data-directory collision aborts the replacement and restores the old executable and preserved user files, subject to filesystem availability. A locked or partly deleted backup may require manual recovery; do not advertise universal rollback.
- No cleanup is performed on arbitrary, unmarked paths.

Windows/Linux integration tests, simulated Windows rollback tests and frozen EXE smoke are automated. A live in-use update, OneDrive redirection, antivirus locks, physical 100–200% DPI, and screen reader acceptance **remain manual and are not guaranteed by CI**.

Feedback opens the repository or email client on explicit user action. No session data is automatically uploaded.
