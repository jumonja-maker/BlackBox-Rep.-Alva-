"""Owned cancellable reader; long interval SELECT/aggregation stays off Qt."""
from pathlib import Path
from PySide6.QtCore import QThread, Signal
from blackbox_core.session_view import SessionView


class SessionIntervalWorker(QThread):
    result_ready = Signal(object,str)

    def __init__(self,folder: Path,parent=None,*,interval=None,instance_id=1,series=None,
                 event_cursor=(0,0),process_after=0):
        super().__init__(parent)
        self.folder=Path(folder)
        self.interval=interval
        self.instance_id=instance_id
        self.series=series
        self.event_cursor=event_cursor
        self.process_after=process_after

    def run(self):
        try:
            with SessionView.open(self.folder,cancel=self.isInterruptionRequested) as view:
                series=self.series or ("DETAILED" if view.is_v2 and
                    view.bounds("DETAILED",self.instance_id)[2] else
                    "STANDARD" if self.instance_id==1 else "CHILD")
                start,end=self.interval or (None,None)
                if self.interval is None:
                    from blackbox_core.investigation_v2 import research_tail
                    tail=research_tail(self.folder)
                    if tail is not None:end=max(view._range(None,None,series,self.instance_id)[1],tail)
                report=view.interval(start,end,series=series,instance_id=self.instance_id)
                from blackbox_core.event_stream import event_tracks
                report['timeline']['events']=event_tracks(view,*report['selected_interval_ns'],folder=self.folder)
                threads=view.thread_summary(start,end,instance_id=self.instance_id)
                from blackbox_core.process_tree import resource_tree_page,tree_totals
                processes=resource_tree_page(view,*report['selected_interval_ns'],after=self.process_after)
                report['process_tree_totals']=tree_totals(view,*report['selected_interval_ns'])
                lo,hi=report["selected_interval_ns"]
                events=view.event_page(lo,hi,after=self.event_cursor)
                self.result_ready.emit({"folder":str(self.folder),"interval":report,
                    "threads":threads,"processes":processes,"events":events},"")
        except Exception:
            self.result_ready.emit(None,"CANCELLED" if self.isInterruptionRequested()
                                   else "SESSION_INTERVAL_UNAVAILABLE")


class SessionExportWorker(QThread):
    result_ready=Signal(object,str)

    def __init__(self,folder,output,parent=None,**options):
        super().__init__(parent)
        self.folder,self.output=Path(folder),Path(output)
        self.options=options

    def run(self):
        try:
            from blackbox_core.interval_report import export_interval
            result=export_interval(self.folder,self.output,cancel=self.isInterruptionRequested,
                                   **self.options)
            self.result_ready.emit(result,"")
        except Exception:
            self.result_ready.emit(None,"EXPORT_CANCELLED_OR_UNAVAILABLE")
