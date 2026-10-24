"""Build gate: PyInstaller can exit zero despite missing hidden imports."""
from pathlib import Path
import sys
from PyInstaller.archive.readers import CArchiveReader


def verify(path):
    path=Path(path)
    executable=CArchiveReader(str(path))
    archive=executable.open_embedded_archive("PYZ.pyz")
    required=("blackbox_core.observer_budget","blackbox_core.capability_catalog","blackbox_core.crash_events","blackbox_core.trace_decode",
        "blackbox_core.qa_workloads","blackbox_universal.production_qa",
        "blackbox_core.metric_help","blackbox_core.instrumentation_analysis","blackbox_core.runtime_trace",
        "blackbox_core.trace_recovery","blackbox_universal.measurement_help",
        "blackbox_core.owned_unlink","blackbox_core.retention_delete","blackbox_core.export_recovery","blackbox_core.findings_export",
        "blackbox_core.process_tree","blackbox_core.storage_budget","blackbox_universal.recovery_panel",
        "blackbox_core.investigation_v2","blackbox_core.event_stream","blackbox_universal.evidence_panels",
        "blackbox_core.capture_policy","blackbox_core.user_markers","blackbox_universal.capture_settings","blackbox_universal.marker_panel",
        "blackbox_core.research_worker","blackbox_core.operation_worker",
        "blackbox_core.optional_jobs","blackbox_core.trace_owner","blackbox_core.sensors","blackbox_core.casebook",
        "blackbox_core.experiment_metrics","blackbox_core.package_privacy","blackbox_universal.experiment_view",
        "blackbox_core.library_catalog","blackbox_core.library_files","blackbox_universal.library_panel",
        "blackbox_core.instrumentation","blackbox_core.session_v2",
        "blackbox_core.session_view","blackbox_core.windows_research",
        "blackbox_investigation.engine","blackbox_investigation.sqlite_adapter",
        "blackbox_universal.research_bridge","blackbox_universal.preparation_dialog")
    missing=[name for name in required if name not in archive.toc]
    if missing:raise RuntimeError("FROZEN_MODULES_MISSING: "+", ".join(missing))
    source=path.parent/"_internal"/"blackbox_core"/"instrumentation.py"
    if not source.is_file():raise RuntimeError("FROZEN_CLIENT_SOURCE_MISSING")
    print("PASS: real embedded research modules and standalone event client")


if __name__=="__main__":verify(sys.argv[1])
