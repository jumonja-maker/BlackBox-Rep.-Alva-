# Release acceptance checklist

- [ ] Exact HEAD Windows and Linux tests PASS, with the run URL and SHA.
- [ ] Windows packaged EXE smoke PASS; no retired worker or platform components bundled.
- [ ] Both EXEs use the correct branded icon; essential libraries and readable notices included.
- [ ] Official GitHub Release ZIP matches the built artifact and has a SHA-256 digest.
- [ ] Test old portable version → Check Updates → verified ZIP download → maintenance replacement → reopen new version.
- [ ] Repeat for failed download, malicious ZIP, locked files, unexpected exit, rollback and preserved sessions.
- [ ] Manual clean user Windows run, access denied, process exit, native DPI, antivirus and privacy reviewed.
- [ ] Binary dependency licenses, Qt notices and code signing/reputation addressed.

A green automation run proves only the checks it actually executed. Do not call unperformed manual checks PASS.
