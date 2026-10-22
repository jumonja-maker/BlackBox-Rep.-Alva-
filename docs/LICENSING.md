# Open-source distribution and private dependencies

The **newly written BlackBox Rep. Alva application code** in this repository is proposed under the MIT License (see root LICENSE); it does not contain files from private `jumonja-maker/Alva` or private `jumonja-maker/BLACK.BOX`.

**Alva is NOT relicensed by this project.** At the inspected private Alva HEAD, the tree contains no top-level LICENSE. Access to a private Git repository is not proof of redistribution rights. Do not mirror, vendor, bundle, embed or publish its source code, wheel, frozen Python package or original docs in this public project without an explicit grant and a separately reviewed legal license. If no redistribution rights are established, distribute only this standalone application, with the Alva bridge non-operational until privately installed in an authorized environment.

`psutil` is an optional separately installed third-party dependency with its own license. PySide6 / PyInstaller (if later used for GUI packaging) also have distinct licensing obligations; evaluate dependencies and frozen distribution before public binaries. Do not copy the former private BLACK.BOX application's source or design assets unless their licenses and origins are cleared.

This is a technical licensing boundary, not a legal opinion. The owner should explicitly decide whether Alva itself will eventually be published under a compatible license and how platform binaries may be distributed.
