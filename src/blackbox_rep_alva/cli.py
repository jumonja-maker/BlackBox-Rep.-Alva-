"""Offline command line. No network, no subprocess, no target modification."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from .contracts import ObserverError
from .probe import list_processes
from .recorder import record
from .report import summarize, write_report, compare
from .handoff import build_handoff


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="blackbox-rep")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="List accessible processes (psutil optional dependency)")
    r = sub.add_parser("record", help="Read-only process sampling")
    r.add_argument("--pid", type=int, required=True)
    r.add_argument("--output", type=Path, required=True, help="Existing, non-symlink output root")
    r.add_argument("--duration", type=float, default=3.0)
    r.add_argument("--interval", type=float, default=0.5)
    for name in ("summary", "export", "handoff"):
        parser = sub.add_parser(name)
        parser.add_argument("session", type=Path)
    cmp = sub.add_parser("compare")
    cmp.add_argument("before", type=Path)
    cmp.add_argument("after", type=Path)
    args = p.parse_args(argv)
    try:
        if args.command == "list":
            result = {"processes": list_processes()}
        elif args.command == "record":
            result = record(args.pid, args.output, duration=args.duration, interval=args.interval)
        elif args.command == "summary":
            result = summarize(args.session)
        elif args.command == "export":
            result = write_report(args.session)
        elif args.command == "handoff":
            result = build_handoff(args.session)
        elif args.command == "compare":
            result = compare(args.before, args.after)
        else:
            raise AssertionError("parser accepted unknown command")
    except ObserverError as exc:
        print(json.dumps({"status": "error", "code": exc.code, "stage": exc.stage}))
        return 2
    except (OSError, ValueError):
        print(json.dumps({"status": "error", "code": "INVALID_DATA", "stage": "cli"}))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0
