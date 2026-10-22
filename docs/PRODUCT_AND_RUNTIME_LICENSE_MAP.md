# Licenses in an official BLACK.BOX Universal download (proposed)
**Public information, not a redistribution grant for private Alva.**
This file accompanies the bundled-runtime implementation proposal in Draft
PR #14. It does not modify BLACK.BOX's current MIT source license.

## Source and executable are not the same thing

The **original BLACK.BOX source code** from this public repository is
licensed under its existing `LICENSE` (MIT). Any party can exercise its
existing MIT rights in that public-source code, including building a
standalone BLACK.BOX application **without** the private Alva module.

The complete **official Windows binary** may additionally contain:
- **Alva Runtime:** separately licensed *proprietary embedded runtime*.
  The owner proposes end-user permission to use Alva as built into an
  authorized first-party application, including offline personal and
  commercial end-use, without a separate license key. The user does **not**
  automatically receive the Alva source or a developer SDK license.
  Actual runtime terms and redistribution rights remain **NOT APPROVED**.
- **Qt for Python / Qt:** applicable open-source LGPL/GPL obligations
  (or separately purchased commercial rights). A separate Alva license
  does **not** cancel Qt license/source/relink requirements.
- **psutil:** BSD-3-Clause copyright/license requirements.
- **Other packaged libraries:** their own legally applicable notices,
  licenses and potential source/relink requirements.

PyInstaller permits packaging commercial applications via its license
exception, subject to the licenses of bundled dependencies.

## For ordinary users

The proposed official, owner-built Windows ZIP would launch without
installing Python, downloading private Alva or signing in. The built-in
diagnostic processor can run automatically after a session; the user sees
the normal BLACK.BOX Reports screen, not an Alva Lab. Users can continue
using BLACK.BOX's standalone process observer if the optional diagnostic
engine has a problem. No AI Handoff or external cloud service is required.

GitHub being PRIVATE does not make bytecode inside a distributed EXE
uninspectable. Proprietary terms must respect legal rights and open-source
library licenses, including LGPL library-replacement rights and
non-waivable interoperability exceptions in relevant jurisdictions.

## Do not confuse the two build channels

- **Public GitHub Actions artifact**: standalone BLACK.BOX QA without
  private Alva; not the official full-Alva binary.
- **Future official Releases ZIP**: will be published only after the owner
  approves final embedded-runtime license, release package dependency
  notices, build infrastructure, private real-Alva acceptance, final
  Windows executable smoke and its exact SHA/digest/signing metadata.

**Current release state:** NO OFFICIAL FULL-ALVA ZIP YET.
The private Alva universal distribution standard is itself still a
proposal; see the private draft PR for review by an authorized maintainer.
A public distribution must bundle the FINAL license text separately; this
public source document is only the product license map.
