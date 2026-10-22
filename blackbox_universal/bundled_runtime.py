"""Optional bundled Alva worker for owner-authorized offline Windows distributions.

PUBLIC CODE ONLY. This module cannot download/install the private runtime.
Normal public CI produces no bundled Alva worker and BLACK.BOX stays useful.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from .platform_connector import (
    MAX_REQUEST, MAX_RESPONSE, ConnectionError, _summary, _validate_output,
)

WORKER_NAME = "BLACK.BOX-Alva-Diagnostics.exe"
MANIFEST_NAME = "alva-runtime-manifest.json"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_SHA40 = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)


def bundled_runtime_path() -> Path | None:
    """Find only a worker bundled *beside the frozen BLACK.BOX executable*.

    This digest is a consistency check, NOT cryptographic source
    authentication: an attacker with app-folder write access may replace the
    worker AND manifest. Production redistribution requires an independently
    reviewed signing/trust policy and an explicit Alva license decision.
    """
    if not getattr(sys, "frozen", False):
        return None
    root = Path(sys.executable).parent
    worker = root / WORKER_NAME
    manifest = root / MANIFEST_NAME
    if not worker.exists() and not manifest.exists():
        return None
    if (not root.is_dir() or root.is_symlink() or
            not worker.is_file() or worker.is_symlink() or
            not manifest.is_file() or manifest.is_symlink()):
        raise ConnectionError("BUNDLED_RUNTIME_INCOMPLETE")
    try:
        if manifest.stat().st_size > 2048:
            raise ConnectionError("BUNDLED_MANIFEST_INVALID")
        record = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        raise ConnectionError("BUNDLED_MANIFEST_INVALID") from None
    if (type(record) is not dict or record.keys() != {
            "schema_version", "worker", "sha256", "alva_source_sha"} or
            type(record["schema_version"]) is not int or
            record["schema_version"] != 1 or
            record["worker"] != WORKER_NAME or
            type(record["sha256"]) is not str or not _SHA256.fullmatch(record["sha256"]) or
            type(record["alva_source_sha"]) is not str or
            not _SHA40.fullmatch(record["alva_source_sha"])):
        raise ConnectionError("BUNDLED_MANIFEST_INVALID")
    digest = hashlib.sha256()
    try:
        with worker.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise ConnectionError("BUNDLED_RUNTIME_UNREADABLE") from None
    if digest.hexdigest() != record["sha256"]:
        raise ConnectionError("BUNDLED_RUNTIME_DIGEST_MISMATCH")
    return worker


def inspect_bundled(session: Path) -> dict:
    """Run the pinned, separate local executable once on bounded metadata."""
    worker = bundled_runtime_path()
    if worker is None:
        return {"status": "unavailable", "error_code": "ALVA_RUNTIME_NOT_BUNDLED",
                "permission_to_act": False}
    packet = {"schema_version": 1, "operation": "inspect",
              "summary": _summary(Path(session))}
    encoded = json.dumps(packet, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_REQUEST:
        raise ConnectionError("ALVA_REQUEST_TOO_LARGE")
    env = os.environ.copy()
    for var in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT"):
        env.pop(var, None)
    # Distinct PyInstaller child should not reuse the parent EXE bootloader state.
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    try:
        completed = subprocess.run(
            [str(worker)], input=encoded, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, cwd=str(worker.parent), env=env,
            timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        raise ConnectionError("BUNDLED_RUNTIME_EXECUTION_FAILED") from None
    if len(completed.stdout) > MAX_RESPONSE:
        raise ConnectionError("BUNDLED_RUNTIME_RESPONSE_TOO_LARGE")
    try:
        decoded = json.loads(completed.stdout.decode("utf-8", "strict"))
    except (ValueError, UnicodeError):
        raise ConnectionError("BUNDLED_RUNTIME_RESPONSE_INVALID") from None
    result = _validate_output(decoded)
    if (completed.returncode not in (0, 2) or
            (completed.returncode == 0) != (result["status"] == "ok")):
        raise ConnectionError("BUNDLED_RUNTIME_EXIT_CONFLICT")
    return result
