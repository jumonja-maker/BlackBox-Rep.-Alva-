"""Inspect actual packaged PE manifests, embedded modules and source identities.

The build stays asInvoker: only an explicit ElevationBroker operation uses
ShellExecuteExW's runas verb. This gate inspects binaries, not spec-file text.
Run exclusively on a GitHub-hosted runner for BB-DEEP-001 acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def execution_level(path):
    import pefile

    levels = []
    with pefile.PE(str(path), fast_load=False) as pe:
        if pe.FILE_HEADER.Machine != 0x8664:
            raise ValueError("DIAGNOSTIC_PACKAGE_REQUIRES_X64")
        for entry in getattr(pe, "DIRECTORY_ENTRY_RESOURCE", ()).entries:
            if entry.id != 24:
                continue
            for identity in entry.directory.entries:
                for language in identity.directory.entries:
                    record = language.data.struct
                    if record.Size > 1024 * 1024:
                        raise ValueError("OVERSIZED_PE_MANIFEST")
                    document = ET.fromstring(pe.get_data(
                        record.OffsetToData, record.Size).rstrip(b"\x00"))
                    for element in document.iter():
                        if element.tag.rsplit("}", 1)[-1] == "requestedExecutionLevel":
                            levels.append(dict(element.attrib))
    if not levels or any(row.get("level") != "asInvoker" or
                         row.get("uiAccess", "false").lower() != "false"
                         for row in levels):
        raise ValueError("PACKAGE_MUST_NOT_ELEVATE_IMPLICITLY")
    return levels


def verify(root):
    from PyInstaller.archive.readers import CArchiveReader

    root = Path(root)
    gui = root / "BLACK.BOX-Universal.exe"
    helper = root / "diagnostic" / "BLACK.BOX-Diagnostic.exe"
    if not gui.is_file() or not helper.is_file():
        raise FileNotFoundError("GUI_AND_DIAGNOSTIC_HELPER_REQUIRED")
    archive = CArchiveReader(str(helper))
    embedded = archive.open_embedded_archive("PYZ.pyz")
    required = ("deep_contracts", "deep_helper", "deep_ipc", "deep_native",
                "deep_debug", "deep_debug_guardian")
    missing = [name for name in required
               if "blackbox_core." + name not in embedded.toc]
    if missing:
        raise ValueError("DIAGNOSTIC_MODULES_MISSING: " + ", ".join(missing))
    gui_source = json.loads((root / "_internal" / "blackbox-build.json").read_text())
    helper_source = json.loads((helper.parent / "_internal" / "blackbox-build.json").read_text())
    if (helper_source != gui_source or not gui_source.get("tracked_worktree_clean")
            or len(gui_source.get("source_sha", "")) != 40):
        raise ValueError("DIAGNOSTIC_GUI_SOURCE_IDENTITY_MISMATCH")
    result = {
        "status": "PASS",
        "source": gui_source,
        "gui_execution_level": execution_level(gui),
        "helper_execution_level": execution_level(helper),
        "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        "required_embedded_modules": list(required),
        "secure_desktop_acceptance": "NOT_TESTED_BY_BINARY_INSPECTION",
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = verify(args.payload)
    encoded = json.dumps(result, indent=2) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
