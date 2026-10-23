"""Explicit user-triggered offline CLI; transactional best-effort multi-file export."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from . import InvestigationError, analyze_session, to_html


def _targets(args):
    result = {}
    paths = (("json", args.json_output), ("html", args.html_output))
    for kind, name in paths:
        if name is not None:
            path = Path(name).absolute()
            if path.is_symlink() or path.exists() or not path.parent.is_dir():
                raise InvestigationError("OUTPUT_EXISTS_OR_DIRECTORY_UNAVAILABLE")
            result[kind] = path
    if len(result) == 2 and (os.path.normcase(str(result["json"].resolve(strict=False))) ==
                             os.path.normcase(str(result["html"].resolve(strict=False)))):
        raise InvestigationError("OUTPUT_PATH_COLLISION")
    return result


def _commit_export(targets: dict, contents: dict) -> None:
    """Stage same-filesystem files, exclusive-create finals; rollback owned finals on failure.

    OS crashes or power failures between separate file publishes cannot be atomic.
    Existing destinations are never intentionally replaced, even under races.
    """
    staged, created = {}, []
    try:
        for kind, target in targets.items():
            with tempfile.NamedTemporaryFile("wb", dir=target.parent, prefix=".investigation-",
                                             suffix=".pending", delete=False) as stream:
                staged[kind] = Path(stream.name)
                stream.write(contents[kind])
                stream.flush()
                os.fsync(stream.fileno())
        for kind, target in targets.items():
            # Atomic no-overwrite publication on filesystems supporting hardlinks.
            # If hardlinks are forbidden, do not downgrade to a partial direct copy.
            os.link(staged[kind], target)
            created.append(target)
    except BaseException:
        for target in reversed(created):
            target.unlink(missing_ok=True)
        raise
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Read-only BLACK.BOX session investigation")
    parser.add_argument("session", help="Existing BLACK.BOX session directory; read-only")
    parser.add_argument("--json", dest="json_output", help="Explicit new JSON output filename")
    parser.add_argument("--html", dest="html_output", help="Explicit new HTML output filename")
    parser.add_argument("--lang", choices=("RU", "EN"), default="RU")
    parser.add_argument("--from-ms", dest="start_ms", type=int, help="Explicit start elapsed ms for long sessions")
    parser.add_argument("--to-ms", dest="end_ms", type=int, help="Explicit end elapsed ms for long sessions")
    args = parser.parse_args(argv)
    try:
        targets = _targets(args)
        report = analyze_session(args.session, interval_start_ms=args.start_ms,
                                 interval_end_ms=args.end_ms)
        content = {}
        if "json" in targets:
            content["json"] = (json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
        if "html" in targets:
            content["html"] = to_html(report, lang=args.lang).encode("utf-8")
        _commit_export(targets, content)
        print(json.dumps({"status": "PASS", "evidence_sha256": report["evidence_sha256"],
                          "findings": len(report["findings"]), "written_json": bool(args.json_output),
                          "written_html": bool(args.html_output), "full_session_covered":
                          report["coverage"]["full_session_covered"]}, ensure_ascii=False))
        return 0
    except (InvestigationError, OSError) as exc:
        print(json.dumps({"status": "BLOCKED", "code": exc.code if isinstance(exc, InvestigationError)
                          else "FILESYSTEM_ERROR"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
