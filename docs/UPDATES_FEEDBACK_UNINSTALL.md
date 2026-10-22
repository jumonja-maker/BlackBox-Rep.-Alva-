# Updates and portable maintenance

The built-in updater reads `/releases/latest` for the repository, verifies a strictly newer `vMAJOR.MINOR.PATCH` tag and a `BLACK.BOX-Universal-Windows.zip` asset with its SHA-256 digest. It downloads into staging and asks before installing. The separate Maintenance EXE waits until the main app closes, performs safe replacement and preserves user session data in Documents. Protected paths, symlink escapes, malformed ZIP members and oversized archives are rejected.

The next release after v0.3.1 is v0.3.2. A new main commit **does not** become an update until an official Release with a higher version exists. Desktop shortcuts are optional. Uninstallation removes only an appropriately marked portable installation; existing session evidence remains outside the installed folder.

Feedback links lead to the repository or email client and are user initiated. Network access is otherwise limited to update checks; no session data is automatically uploaded.
