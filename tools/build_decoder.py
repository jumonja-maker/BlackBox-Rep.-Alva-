"""Build the self-contained offline helper; no release/tag operations."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def run(args):
    subprocess.run(args, cwd=ROOT, check=True, timeout=600)


def build(rid):
    if rid not in ("win-x64", "linux-x64"):
        raise ValueError("SUPPORTED_RID_REQUIRED")
    project = ROOT / "tools/decoder-host/BlackBox.Decoder.csproj"
    output = ROOT / "decoder"
    if output.exists():
        raise FileExistsError("DECODER_OUTPUT_MUST_BE_NEW")
    run(["dotnet", "publish", str(project), "-c", "Release", "-r", rid, "--self-contained", "true",
         "-p:PublishSingleFile=false", "-p:PublishTrimmed=false", "-o", str(output)])
    exe = output / ("BLACK.BOX-Decoder.exe" if rid.startswith("win") else "BLACK.BOX-Decoder")
    version = subprocess.check_output([str(exe), "--version"], text=True, timeout=20)
    metadata = json.loads(version)
    if metadata["protocol"] != "blackbox.trace-event/1":
        raise ValueError("WRONG_DECODER_PROTOCOL")
    notices = output / "notices"
    notices.mkdir()
    shutil.copy2(ROOT / "docs/TRACE_DECODER_PHASE1.md", output / "DECODER-README.md")
    shutil.copy2(ROOT / "LICENSE", notices / "BLACKBOX-LICENSE")
    shutil.copy2(ROOT / "docs/vendor/TraceEvent-LICENSE.txt", notices / "TraceEvent-LICENSE.txt")
    assets = json.loads((project.parent / "obj/project.assets.json").read_text(encoding="utf-8"))
    package_roots = [Path(folder) for folder in assets["packageFolders"]]
    packages = []
    for identity, library in assets["libraries"].items():
        if library.get("type") != "package":
            continue
        relative = Path(library["path"])
        root = next((base / relative for base in package_roots if (base / relative).is_dir()), None)
        if root is None:
            raise FileNotFoundError("PACKAGE_METADATA_MISSING:" + identity)
        dest = notices / identity.replace("/", "-")
        dest.mkdir()
        declarations = []
        for nuspec in root.glob("*.nuspec"):
            shutil.copy2(nuspec, dest / nuspec.name)
            doc = ET.parse(nuspec)
            for node in doc.iter():
                if node.tag.split("}")[-1] == "license":
                    declarations.append({"type": node.get("type"), "value": node.text})
                    if node.get("type") == "file" and node.text:
                        license_file = (root / node.text).resolve()
                        if not license_file.is_relative_to(root.resolve()) or not license_file.is_file():
                            raise ValueError("INVALID_PACKAGE_LICENSE_FILE")
                        shutil.copy2(license_file, dest / license_file.name)
        for candidate in root.iterdir():
            if candidate.is_file() and any(x in candidate.name.lower() for x in ("license", "notice")):
                shutil.copy2(candidate, dest / candidate.name)
        packages.append({"package": identity, "sha512": library.get("sha512"), "licenses": declarations})
    runtime = json.loads((output / "BLACK.BOX-Decoder.runtimeconfig.json").read_text(encoding="utf-8"))
    runtime_notices = []
    for framework in runtime["runtimeOptions"].get("includedFrameworks", []):
        package = framework["name"].lower() + ".runtime." + rid
        roots = [base / package / framework["version"] for base in package_roots]
        found = 0
        for pack in roots:
            if not pack.is_dir():
                continue
            dest = notices / (package + "-" + framework["version"])
            dest.mkdir(exist_ok=True)
            for item in pack.iterdir():
                if item.is_file() and any(term in item.name.lower() for term in ("license", "notice")):
                    shutil.copy2(item, dest / item.name)
                    found += 1
        if not found:
            raise FileNotFoundError("RUNTIME_REDISTRIBUTION_NOTICES_MISSING:" + package)
        runtime_notices.append({"package": package, "version": framework["version"], "files": found})
    manifest = {"decoder": metadata, "runtime_notices": runtime_notices, "rid": rid, "self_contained": True,
                "traceevent_package": "4.0.0", "packages": packages,
                "files": {str(p.relative_to(output)).replace(os.sep, "/"): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in output.rglob("*") if p.is_file()}}
    (output / "decoder-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("SELF_CONTAINED_DECODER_BUILD_PASS", metadata)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rid", required=True)
    build(parser.parse_args().rid)
