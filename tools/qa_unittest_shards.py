"""Exhaustive, mutually exclusive partitions of the original Windows unittest suite.

Each real test is executed exactly once across all GitHub-hosted Windows shards.
A hung test fails explicitly on the same runner without silently skipping it.
"""
from __future__ import annotations

import argparse
from fnmatch import fnmatchcase
from pathlib import Path
import subprocess
import sys

SHARD_PATTERNS = {
    "a-c": "test_[a-c]*.py",
    "d-h": "test_[d-h]*.py",
    "i-r": "test_[i-r]*.py",
    "s-z": "test_[s-z]*.py",
}
UNIT_SHARD_TIMEOUT_SECONDS = 3600


def assigned_sources(tests_root: Path) -> dict[str, list[str]]:
    filenames = sorted(p.name for p in tests_root.glob("test_*.py") if p.is_file())
    if len(filenames) < 100:
        raise ValueError("MISSING_WINDOWS_TEST_SOURCES")
    mapping = {name: [] for name in SHARD_PATTERNS}
    for filename in filenames:
        matched = [name for name, pattern in SHARD_PATTERNS.items()
                   if fnmatchcase(filename, pattern)]
        if len(matched) != 1:
            raise ValueError("SHARD_OWNERSHIP_INVALID:" + filename)
        mapping[matched[0]].append(filename)
    if any(not names for names in mapping.values()):
        raise ValueError("EMPTY_WINDOWS_TEST_SHARD")
    return mapping


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", choices=SHARD_PATTERNS, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1] / "tests"
    mapping = assigned_sources(root)
    print("EXHAUSTIVE_WINDOWS_TEST_PARTITION",
          {name: len(sources) for name, sources in mapping.items()},
          "total", sum(map(len, mapping.values())), flush=True)
    selected = mapping[args.shard]
    print("RUNNING_REAL_TEST_FILES", args.shard, selected, flush=True)
    command = [sys.executable, "-m", "unittest", "discover", "-s", "tests",
               "-p", SHARD_PATTERNS[args.shard], "-v"]
    subprocess.run(command, check=True, timeout=UNIT_SHARD_TIMEOUT_SECONDS)


if __name__ == "__main__":
    main()
