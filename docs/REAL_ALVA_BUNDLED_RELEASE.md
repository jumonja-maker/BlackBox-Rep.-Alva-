# Official BLACK.BOX with Alva inside — private-source binary release

**Owner goal:** ordinary Windows users download the official
`BLACK.BOX-Universal-Windows.zip`, extract the *whole* folder and launch
`BLACK.BOX-Universal.exe`. They receive genuine Alva-backed diagnostics in
BLACK.BOX's native five-screen UI after pressing Stop. No Alva tab, no Python
selection, no user access to the private GitHub and no external service.

## Actual implementation

- `blackbox_universal.platform_connector.bundled_runtime_available()`
  selects the owner-built runtime only in a **frozen executable** carrying a
  tightly structured manifest with pinned public and private SHA-1 commits.
  The manifest is a selection marker, **not** a signature.
- If packaged, `_finalize_alva_if_configured()` automatically invokes the
  internal checked Alva worker on the GUI's existing background QThread.
  Its summary is bounded; a real `alva.ComponentHost`, 3 scoped
  operations, 4-stage `run_checked_pipeline`, review and limited trace
  classification/reporting are invoked directly **inside the shipped app**.
  No external `python.exe`, download, account or environment picker.
- Results are appended to the local session's `evidence-checks.json`,
  reflected as an accepted-check count in normal **Reports**. If the
  Alva check fails, it reports a failure, **never a fake successful Alva
  execution**, and the observer's SQLite/JSON/HTML remain intact.
- A legacy previously-authorized external Python fallback remains
  *maintainer-only* and invisible to end-users for development builds.
- The private Alva's `src/alva/*` files and wheel are **not** put in this
  public GitHub repository or its normal CI; only a PyInstaller package
  built from the private project can actually distribute runtime code.
- Public CI creates only a clearly named **standalone QA, not release**
  artifact; its tag-triggered release upload is disabled in this proposal.

## Build/provenance and first real downloadable release

A separate **private Alva** PR implements a gated, manually dispatched
Windows build on existing approved self-hosted `ALVA-NIKITA`. It pins
and checks the exact public BLACK.BOX SHA (explicit allowlist in the private
repo), installs private Alva in a temporary isolated venv, runs original
Windows app tests and **real** Alva API acceptance, bundles
`--collect-submodules alva` into PyInstaller, and runs the **actual frozen
EXE** with `--smoke --require-bundled-alva`.

Only after real-P4 frozen smoke passes, separate binary runtime license
terms are approved and a scoped publish token is installed by the owner,
the private workflow can upload the bundled ZIP to the **public
BLACK.BOX Releases**. A private repository alone does not grant
redistribution rights, and bytecode in an EXE is reversible. Public source
remains MIT; runtime binary requires distinct owner-approved terms and
third-party notices. Never advertise code privacy for distributed bytecode.

## Progress and gates

- [x] Source path for automatic internal Alva execution after Stop
- [x] No Alva tab, no Python setup, no AI Handoff for end-users
- [x] Bundled-runtime manifest validation and local-only evidence checks
- [x] Explicit source/frozen smoke requiring **real** Alva stages
- [x] Private self-hosted binary build workflow prepared with fail-closed
      owner approval, approved commit pin and separate release token
- [x] Public non-Alva workflow clearly marked **QA only**
- [ ] Entire current public branch SHA runs green on Windows and Ubuntu
- [ ] Owner approves final separate Alva binary redistribution license
      and required dependency notices
- [ ] Owner adds approved exact public SHA to private repo allowlist
- [ ] Owner configures limited `BLACKBOX_RELEASE_TOKEN` in private GitHub
- [ ] Private CI executes actual Alva tests and frozen Windows full-bundle
      smoke (not just test doubles)
- [ ] Real Windows download/use/updates/permissions testing, binary notices
      and final public Release

**THIS IS AN IMPLEMENTED RELEASE PATH, NOT A PUBLISHED PRODUCT YET.**
As long as the license/commit allowlist has not been approved, no public
Alva-bundled binary exists. That is a deliberate release-security gate, not
a dependency on the user's Python or a new online service.

ALVA remains experimental: checks apply to BLACK.BOX's own observer
evidence; this does not prove internal root causes inside arbitrary EXEs.
