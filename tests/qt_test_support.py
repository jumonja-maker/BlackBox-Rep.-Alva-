"""Wait for real asynchronous window shutdown before deleting test evidence."""
import time


def close_and_drain(window,app,timeout=10):
    window.close()
    deadline=time.monotonic()+timeout
    names=("_base_sample_worker","_report_worker","_interval_worker","_interval_export_worker",
           "_investigation_worker","_thread_detail_worker")
    while time.monotonic()<deadline:
        app.processEvents()
        if not window.probe.active and all(getattr(window,n,None) is None for n in names):
            window.close()
            app.processEvents()
            return
        time.sleep(.005)
    raise AssertionError("WINDOW_WORKERS_NOT_CLOSED_BEFORE_FIXTURE_CLEANUP")
