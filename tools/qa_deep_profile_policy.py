"""Hosted Windows preflight for the actual immutable diagnostic WPRP.

WPR reads only the protected copy. Artifacts retain that exact definition and
the installed tool's schema verdict; this does not substitute for ETL capture.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("GITHUB_HOSTED_WINDOWS_REQUIRED")
    from blackbox_core.deep_ipc import token_is_elevated
    from blackbox_core import deep_profiling as P
    if not token_is_elevated():
        raise SystemExit("ELEVATED_HOSTED_TOKEN_REQUIRED")
    args.output.mkdir(parents=True, exist_ok=False)
    report = {"status": "FAIL", "source_sha": os.environ.get("GITHUB_SHA"),
              "profile": P.PROFILE, "capture_evidence": "SEPARATE_REAL_ETL_ACCEPTANCE_REQUIRED"}
    stage = P.ProtectedStaging()
    try:
        capture = P._capture_factory(stage.path, profile=P.PROFILE)
        actual = P._read_profile(stage.path / P.PROFILE_FILENAME)
        if actual != P.PROFILE_XML:
            raise AssertionError("PROTECTED_PROFILE_NOT_EXACT_EMBEDDED_POLICY")
        root = ET.fromstring(actual)
        keywords = {item.attrib["Value"] for item in root.findall("./Profiles/SystemProvider/Keywords/Keyword")}
        required = {"ProcessThread", "Loader", "CSwitch", "ReadyThread", "SampledProfile",
                    "FileIO", "FileIOInit", "DiskIO", "DiskIOInit"}
        custom = root.findall("./Profiles/SystemProvider/Keywords/CustomKeyword")
        if not required <= keywords or len(custom) != 1 or int(custom[0].attrib["Value"], 16) != 0x10000:
            raise AssertionError("FIXED_KERNEL_FILE_DISK_NETWORK_POLICY_MISSING")
        collector = root.find("./Profiles/SystemCollector")
        if (collector.find("BufferSize").attrib["Value"] != "1024" or
                collector.find("Buffers").attrib["Value"] != "64"):
            raise AssertionError("FIXED_64_MIB_COLLECTOR_POLICY_REQUIRED")
        (args.output / P.PROFILE_FILENAME).write_bytes(actual)
        with (args.output / "profile-details.txt").open("wb") as log:
            completed = subprocess.run([capture.tool, "-profiledetails", capture.profiles[0]],
                                       stdout=log, stderr=subprocess.STDOUT, timeout=30, check=False)
        if completed.returncode != 0:
            raise AssertionError("INSTALLED_WPR_REJECTED_IMMUTABLE_POLICY_" + str(completed.returncode))
        report.update(status="PASS", profile_sha256=hashlib.sha256(actual).hexdigest(),
                      profile_bytes=len(actual), collector_buffer_bytes=64 * 1024**2,
                      kernel_network_keyword="0x00010000", installed_wpr_profiledetails_exit=0,
                      keywords=sorted(keywords))
    finally:
        failures = stage.cleanup()
        report["cleanup"] = "CONFIRMED" if not failures else failures
        if failures:
            report["status"] = "FAIL"
        (args.output / "policy.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        if failures:
            raise AssertionError("PROTECTED_PROFILE_PREFLIGHT_CLEANUP_UNCONFIRMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
