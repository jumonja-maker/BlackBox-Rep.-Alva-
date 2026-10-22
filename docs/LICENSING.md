# Software distribution and dependency audit

BLACK.BOX's original application source is under the root MIT LICENSE. A portable Windows EXE also contains third-party dependencies such as Python, PySide6/Qt, psutil and PyInstaller's bootloader, which retain their own licenses. Include the exact-build notices, comply with Qt's applicable LGPL/commercial requirements and review the dependency bill of materials for each release.

The public GitHub Actions artifact and Release contain the independent application's modules only. The Windows EXEs are currently unsigned; SmartScreen and antivirus reputation require separate user testing. This document is not a substitute for a legal or binary bill-of-materials audit.
