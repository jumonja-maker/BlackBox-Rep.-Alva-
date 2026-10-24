"""QA source identity; the GitHub event SHA is not the checkout SHA."""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SHA=re.compile(r"^[0-9a-f]{40}$")


def source_identity(expected=None):
    result={"requested_head_sha":expected or "UNKNOWN",
            "workflow_event_sha":os.environ.get("GITHUB_SHA","UNKNOWN"),
            "actual_source_sha":None,"source_tree_sha":None,"tracked_worktree_clean":None}
    if getattr(sys,"frozen",False):
        path=Path(sys._MEIPASS)/"blackbox-build.json"
        if path.is_file() and path.stat().st_size<=4096:
            data=json.loads(path.read_text(encoding="utf-8"))
            if data.get("schema_version")==1 and SHA.fullmatch(data.get("source_sha","")):
                result.update(actual_source_sha=data["source_sha"],source_tree_sha=data.get("source_tree_sha"),
                    tracked_worktree_clean=data.get("tracked_worktree_clean"),identity_source="FROZEN_BUILD_MANIFEST")
    else:
        root=Path(__file__).resolve().parents[1]
        try:
            args={"cwd":root,"capture_output":True,"text":True,"timeout":3,
                  "creationflags":getattr(subprocess,"CREATE_NO_WINDOW",0)}
            head=subprocess.run(["git","rev-parse","HEAD"],**args)
            tree=subprocess.run(["git","rev-parse","HEAD^{tree}"],**args)
            clean=subprocess.run(["git","diff","--quiet","HEAD","--"],**args)
            if head.returncode==0 and SHA.fullmatch(head.stdout.strip()):
                result.update(actual_source_sha=head.stdout.strip(),source_tree_sha=tree.stdout.strip(),
                    tracked_worktree_clean=clean.returncode==0,identity_source="ACTUAL_GIT_CHECKOUT")
        except (OSError,subprocess.TimeoutExpired):pass
    required=bool(expected and SHA.fullmatch(expected))
    result["source_identity_status"]=("VERIFIED_EXPECTED_HEAD" if required and
        result["actual_source_sha"]==expected and result["tracked_worktree_clean"] is True else
        "MISMATCH_OR_DIRTY" if required else "LOCAL_QA_NOT_PINNED")
    return result
