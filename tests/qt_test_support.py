"""Drain actual owners, then destroy only the closed fixture's Qt object tree."""
import time


def dispose_closed_fixture(widget, app):
    """Deliver this fixture's DeferredDelete without flushing unrelated owners.

    processEvents alone does not guarantee DeferredDelete when tests do not run
    QApplication.exec. QWidget.close also hides a window without deleting it.
    Refuse a visible widget, a retained bridge, or a running Qt worker instead
    of forcing destruction to make a test finish.
    """
    from PySide6.QtCore import QCoreApplication, QEvent, QThread
    from PySide6.QtWidgets import QWidget
    from shiboken6 import isValid
    if not isValid(widget):
        return
    if ((isinstance(widget, QWidget) and widget.isVisible()) or
            bool(getattr(widget, "busy", False)) or bool(getattr(widget, "has_session", False)) or
            bool(getattr(widget, "cleanup_required", False)) or
            isinstance(widget, QThread) and (widget.isRunning() or not widget.wait(0)) or
            any(worker.isRunning() or not worker.wait(0) for worker in widget.findChildren(QThread))):
        raise AssertionError("FIXTURE_QT_OWNER_NOT_CLOSED_BEFORE_DELETE")
    widget.deleteLater()
    QCoreApplication.sendPostedEvents(widget, QEvent.Type.DeferredDelete)
    if isValid(widget):
        raise AssertionError("FIXTURE_QT_DEFERRED_DELETE_NOT_DELIVERED")
    app.processEvents()


def _pending_window_owners(window):
    from PySide6.QtCore import QThread
    probe = window.probe
    owners = (getattr(probe, name, None) for name in ("_pending_windows", "_pending_detailed", "_pending_v2"))
    native_pending = any(getattr(owner, "thread", None) is not None and owner.thread.is_alive() for owner in owners)
    chain = getattr(getattr(window, "chain_builder_panel", None), "bridge", None)
    chain_pending = bool(chain is not None and (chain.busy or
        any(getattr(chain, name, None) is not None for name in
            ("_native", "_finalizing", "_owned_session_run_id", "_observe_owner", "_selection")) or
        any(getattr(chain, name, None) for name in
            ("_requests", "_native_contexts", "_research", "_observe_cleanup_unknown"))))
    deep = getattr(getattr(window, "deep_inspector_panel", None), "bridge", None)
    graph = getattr(getattr(window, "investigation_graph_panel", None), "bridge", None)
    decoder = getattr(window, "decoder_panel", None)
    names = ("_base_sample_worker", "_report_worker", "_interval_worker", "_interval_export_worker",
             "_investigation_worker", "_thread_detail_worker", "_update_worker")
    return (probe.active or native_pending or bool(getattr(probe, "alive", False)) or chain_pending or
        bool(deep is not None and (deep.has_session or deep.cleanup_required)) or
        bool(graph is not None and graph.busy) or
        bool(decoder is not None and getattr(decoder, "worker", None) is not None) or
        any(worker.isRunning() or not worker.wait(0) for worker in window.findChildren(QThread)) or
        any(getattr(window, name, None) is not None for name in names))


def close_and_drain(window,app,timeout=10):
    window.close()
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        app.processEvents()
        if not _pending_window_owners(window):
            accepted = window.close()
            app.processEvents()
            if accepted and not window.isVisible() and not _pending_window_owners(window):
                dispose_closed_fixture(window, app)
                return
        time.sleep(.005)
    raise AssertionError("WINDOW_WORKERS_NOT_CLOSED_BEFORE_FIXTURE_CLEANUP")
