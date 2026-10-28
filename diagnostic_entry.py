"""Dedicated asInvoker diagnostic helper; elevation is explicit via runas."""
from __future__ import annotations

from pathlib import Path
import sys

if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))


def main():
    arguments = sys.argv[1:]
    if arguments and arguments[0] in ("--debug-guardian", "--deep-debug-guardian"):
        from blackbox_core.deep_debug_guardian import main as guardian_main
        return guardian_main()
    if arguments and arguments[0] == "--deep-handle-query":
        from blackbox_core.deep_native_handles import main as handles_main
        return handles_main(arguments[1:])
    from blackbox_core.deep_helper import main as helper_main
    return helper_main(arguments)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # A windowed helper must never display a blocking bootloader traceback
        # dialog. The owning GUI reports the failed authenticated startup.
        raise SystemExit(2)
