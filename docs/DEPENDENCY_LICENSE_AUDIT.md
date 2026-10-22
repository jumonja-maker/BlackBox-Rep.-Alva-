# BLACK.BOX Universal — binary dependency licensing audit

**Status: OPEN / NOT RUN.** This is an inventory and acceptance procedure, **not** a completed legal review or permission grant. It applies to the final Windows portable package of [Draft PR #12](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/pull/12). No one should publish a stable executable based solely on this checklist.

## Scope and reproducibility

The current Windows build installs `requirements.txt` (PySide6 `>=6.8,<6.12`, psutil `>=6,<8`), `pyinstaller>=6,<7`, `Pillow>=10,<13`, plus `pip install -e .`. These are **version ranges**, not an immutable, audited bill of materials. Transitive packages, Qt libraries, compilation toolchain files and Python runtime can enter the frozen ZIP.

Before release, on the **same** Windows runner/environment and inputs that produce the final approved ZIP:

1. Capture a version-pinned `pip freeze`, Python/runtime information and wheel filenames/digests in a build record; identify actual PySide6, PySide6-Essentials, PySide6-Addons, shiboken6, psutil, Pillow, PyInstaller, pyinstaller-hooks-contrib, altgraph and any other resolved transitive package or non-Python DLL actually bundled.
2. Enumerate all binary and data files in `dist/BLACK.BOX-Universal`, identify vendor, version and embedded licenses/notices. The ZIP's own top-level MIT `LICENSE` is **not automatically sufficient** for Qt, PySide6 or other components.
3. Obtain each exact dependency version's authoritative license text and required notice obligations. Document the chosen LGPL/commercial compliance path for PySide6/Qt, including applicable runtime libraries, users' relinking/replacement rights where required, corresponding-source/access notices and other applicable obligations; obtain competent legal review when necessary.
4. Validate psutil, Pillow, PyInstaller, compiled hooks/wheels, Python itself, libraries included by PyInstaller, icons/assets and every redistributed third-party component. Preserve required attribution and license texts in the *actual distributed archive* and manually open the extracted notice files.
5. Confirm the application does not ship private Alva source/wheel, former private BLACK.BOX A.I.O files, private fonts, unauthorized artwork or private test fixtures. Source-level references to a private Alva API are **not** a grant to redistribute its implementation.
6. Record the final artifact's SHA-256 and exact Git commit/release tag. Do not represent unsigned software or unverified wheel provenance as authenticated. Decide code signing and test SmartScreen/AV separately.
7. Check privacy: offline observation, no collection of document contents or credentials by default, opt-out for automatic GitHub metadata checks, no silent process modification or report upload. Audit the contents of `report.json`, `report.html`, SQLite and optional internal evidence for exposed user paths/PIDs before sharing examples.

## Compliance evidence ledger (all currently open)

| Component / question | Evidence required | Status |
| --- | --- | --- |
| PySide6 / shiboken6 / Qt binary components | Exact version, licensing path and all required notices/relinking requirements | NOT RUN |
| psutil | Exact wheel/version and reproduced license notices | NOT RUN |
| Pillow | Exact wheel/version and notices | NOT RUN |
| PyInstaller, hooks, bootloader, altgraph | Exact versions, binary inclusion, applicable licenses | NOT RUN |
| Python runtime and bundled non-Python DLLs | Files, vendors, versions, runtime licenses | NOT RUN |
| Third-party fonts, artwork, bundled assets | Provenance and redistribution permission, or confirmation of none | NOT RUN |
| Private Alva / old A.I.O | Verify **absent** from distributed binaries, wheel list and package contents | NOT RUN |
| Privacy and reporting disclosures | Real offline/opt-out test plus report-sharing review | NOT RUN |
| Notices inside final Windows ZIP | Physical verification of included mandatory license files | NOT RUN |
| Reviewer/owner/legal sign-off | Named decision for exact final build hash | BLOCKED |

## Current distinction

The workflow currently copies the public project's `LICENSE`, READMEs and `docs/LICENSING.md` to the portable ZIP. This is a **packaging step, not an audit of third-party notices**. Real closed Alva compatibility must be separately tested in an approved private environment; it is not a dependency of ordinary offline sampling and is not in the public binary.

Document evidence and approval before considering an official tagged release. See [release gates](RELEASE_GATES.md) and [manual Windows acceptance](WINDOWS_RELEASE_ACCEPTANCE.md).
