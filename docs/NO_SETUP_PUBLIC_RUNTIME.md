# Download-and-use access plan while Alva stays private

**Decision (2026-10-22):** `jumonja-maker/Alva` remains **private** and PREVIEW. Its code, wheel, source tree and binaries **MUST NOT** be uploaded to this public repo, CI artifacts, PyInstaller distribution, GitHub Releases or an unauthenticated web endpoint. The current repo has **no public GitHub Releases**; a Draft PR or short-lived Actions artifact is not a published release.

## One download: actual user experience

1. When a reviewed Windows portable build is legitimately released, download the complete ZIP from this public repo's official Releases page.
2. Extract the complete folder and double-click `BLACK.BOX-Universal.exe`. **No Python, Alva installation, GitHub credentials, AI subscription or internet is required for ordinary monitoring.**
3. In **Processes**, select a process → Attach → Start Observing → Stop Observing.
4. Find SQLite, JSON/HTML and offline `ai-handoff.json` in the documented session folder. The untrusted handoff contains structured observations, not verified root cause, and does not contact an AI service.
5. **Alva Lab** explains that the standalone observer is already ready. An unconfigured frozen EXE returns explicit `ALVA_RUNTIME_NOT_CONFIGURED` without spawning an unknown Python executable or trying hidden installation. Ordinary monitoring continues without Alva.

## Authorized advanced connection (developer/limited-access users only)

A user who **already has permission** to install the private Alva package can choose **CONNECT EXTERNAL ALVA**, select a *trusted* Python interpreter in their Alva environment, and run a limited local check. This is **not a general-public installation path**.

- The Python executable must come from a trusted source. Selecting it runs code under the user's own account; `-I` does not sandbox malicious Python or authenticate source provenance.
- Only a bounded summary of the observer's session is passed to the sidecar. The code must never silently copy logs, documents, file paths, PID or process names to it.
- The real Alva sidecar executes 3 scoped component calls about observer data. A passing response does **not** prove a defect in an arbitrary external process, nor verify the installed Alva package originated from the exact pinned Git commit.
- No Python/Alva installer, credential prompt, private package download, network listener or server is started by this feature.
- Disconnection removes the saved interpreter preference, never deletes an existing authorized Python installation.

## What would make complete Alva truly one-click for *everyone*?

There is no technical shortcut satisfying all four requirements simultaneously: **no runtime redistribution**, **no accessible remote service**, **no pre-existing user installation**, and **full genuine Alva runtime for every new user**. The owner would need to approve one of these *future* options:

A. **Explicit distribution rights and a separately licensed, vetted Alva runtime package** fetched or bundled with the user's consent. Repository source may remain private but Python binaries and bytecode are inspectable; do not promise secrecy. Verify pinned digest/signature and license/security audit, package and public Windows CI before enabling; offline use after installation can remain possible.

B. **Separately hosted access-controlled service** supporting allowed Alva operations, with privacy, operational cost, authentication, network dependency and an explicit architecture change. This conflicts with the current offline/no-server product promise and requires a separate owner decision.

Until then, **standalone BLACK.BOX must remain useful and first-class**. Do not rename its native reporting `Alva diagnostics` or present a synthetic shim as the actual Alva runtime.

## Minimum release acceptance

- Windows user without Python and without Alva: fresh portable EXE launches; sample real process; save SQLite/JSON/HTML/handoff; no false Alva check; no remote request necessary.
- Windows user with authorized Alva: select trusted interpreter; observe explicit limited PASS and provenance warning; disconnect; restart; no persisted connection.
- Negative scenarios: nonexistent interpreter, interpreter without Alva, unsupported API, timeout/crash, malicious or oversized result, malformed session, lack of filesystem permission. No target-process mutation or upload.
- Validate the *exact new commit SHA* in Windows 3.11 build and GUI smoke, offline isolation and dependency license notices before publishing a first real Release.
- Verify GitHub Actions permissions/cost policy with the owner; this change does **not** create/alter workflows.
- Review license compatibility for the **public** PySide6/PyInstaller/psutil build; do not infer public redistribution rights for private Alva.

**QA status of this UX change:** code review + focused Linux unit tests only (record exact results in PR). Frozen Windows EXE / end-user acceptance and real authorized Alva runtime invocation: **NOT RUN**.
