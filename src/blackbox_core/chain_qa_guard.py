"""Stdlib-only failure latch for the explicit R60 QA application process.

This module neither imports Qt nor changes the ordinary application hook.
Unhandled callback errors cannot be cleared by later successful UI assertions.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
import time


class ChainQaFailureGuard:
    def __init__(self, log_path="blackbox-chain-qa-error.json"):
        self.log_path = Path(log_path)
        self.failed = False
        self.count = 0
        self.first = None
        self.pid = os.getpid()
        self.source_sha = None
        if "--qa-commit-sha" in sys.argv:
            index = sys.argv.index("--qa-commit-sha") + 1
            if index < len(sys.argv) and re.fullmatch(r"[0-9a-f]{40}", sys.argv[index]):
                self.source_sha = sys.argv[index]
        self.first_recorded_monotonic_ns = None

    def install(self):
        previous = sys.excepthook
        sys.excepthook = self.record
        return previous

    def record(self, kind, _value, tb):
        # Logging and Qt shutdown are best effort. Neither may erase the
        # primary fact, even if the filesystem or QApplication is unavailable.
        self.failed = True
        self.count = min(self.count + 1, 1_000_000)
        if self.first is None:
            self.first_recorded_monotonic_ns = time.monotonic_ns()
            frames = []
            while tb is not None and len(frames) < 12:
                code = tb.tb_frame.f_code
                frames.append({"file": Path(code.co_filename).name[:128],
                    "function": code.co_name[:96], "line": tb.tb_lineno})
                tb = tb.tb_next
            self.first = {"error_type": getattr(kind, "__name__", "Exception")[:64], "frames": frames}
        try:
            self.log_path.write_text(json.dumps(self.metadata(), ensure_ascii=True, sort_keys=True),
                                     encoding="ascii")
        except Exception:
            pass
        try:
            module = sys.modules.get("PySide6.QtWidgets")
            application = getattr(module, "QApplication", None)
            app = application.instance() if application is not None else None
            if app is not None:
                app.exit(1)
        except Exception:
            pass

    def metadata(self):
        return {"scope": "CHAIN_QA_PYTHON_FAILURE_METADATA_ONLY", "count": self.count,
                "pid": self.pid, "source_sha": self.source_sha,
                "first_recorded_monotonic_ns": self.first_recorded_monotonic_ns,
                "first": self.first}

    def apply(self, proof):
        if self.failed:
            proof["status"] = "FAIL"
            proof.setdefault("error", "CHAIN_QA_UNHANDLED_PYTHON_EXCEPTION")
            proof.setdefault("reason", "CHAIN_QA_UNHANDLED_PYTHON_EXCEPTION")
            proof["unhandled_python_failure"] = self.metadata()
        return proof

    def exit_code(self, code):
        # Preserve an actual nonzero result, including a specific failure code.
        return code if code else int(self.failed)
