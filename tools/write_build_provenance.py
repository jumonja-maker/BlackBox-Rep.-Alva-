"""Generate the frozen QA identity from the checkout, never an event merge ref."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from blackbox_universal.provenance import source_identity
from blackbox_universal import __version__


if __name__=="__main__":
    data=source_identity(sys.argv[1])
    if data["source_identity_status"]!="VERIFIED_EXPECTED_HEAD":raise RuntimeError("BUILD_CHECKOUT_NOT_VERIFIED")
    path=Path(".qa-build/blackbox-build.json");path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps({"schema_version":1,"source_sha":data["actual_source_sha"],
        "source_tree_sha":data["source_tree_sha"],"tracked_worktree_clean":True,"version":__version__}),encoding="utf-8")
    print("Build source:",data["actual_source_sha"],"tree:",data["source_tree_sha"])
