# Open-source distribution and private dependencies

The **newly written BlackBox Rep. Alva application code** in this repository is proposed under the MIT License (see root LICENSE); it does not contain files from private `jumonja-maker/Alva` or private `jumonja-maker/BLACK.BOX`.

**Alva is NOT relicensed by this project.** At the inspected private Alva HEAD, the tree contains no top-level LICENSE. Access to a private Git repository is not proof of redistribution rights. Do not mirror, vendor, bundle, embed or publish its source code, wheel, frozen Python package or original docs in this public project without an explicit grant and a separately reviewed legal license. If no redistribution rights are established, distribute only this standalone application, with the Alva bridge non-operational until privately installed in an authorized environment.

The current Windows portable PyInstaller build **does bundle** public third-party components including `psutil`, PySide6/Qt, Pillow and PyInstaller/Python runtime files. These have independent licenses and distribution obligations. Copying the public MIT `LICENSE` into the ZIP does **not** complete third-party notice and Qt LGPL compliance review. The exact resolved wheel versions and shipped binaries have **NOT** yet been inventoried or legally approved for a stable public release. See [binary license audit checklist](DEPENDENCY_LICENSE_AUDIT.md). Do not copy the former private BLACK.BOX application's source or design assets unless their licenses and origins are cleared.

This is a technical licensing boundary, not a legal opinion. The owner should explicitly decide whether Alva itself will eventually be published under a compatible license and how platform binaries may be distributed.
