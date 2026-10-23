"""Peak-preserving synchronized historical tracks with bounded point DTOs."""
from __future__ import annotations
from bisect import bisect_left
from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QWidget, QToolTip


class SessionTimeline(QWidget):
    range_requested=Signal(object,object)
    TRACKS=("cpu_interval_percent","rss_bytes","private_bytes","uss_bytes",
            "handle_count","read_bps","write_bps","thread_count","children_total")
    COLORS=("#bb5666","#31847f","#8b5b9f","#596aa4","#947343","#a6522f","#795d49","#5c6b55","#684b85")

    def __init__(self,parent=None):
        super().__init__(parent)
        self.payload=None
        self.visible_tracks=set(self.TRACKS[:3])
        self.selection=None
        self._drag=None
        self.setMinimumHeight(280)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setMouseTracking(True)
        self.setAccessibleName("Session timeline / Шкала сеанса")
        self.setAccessibleDescription("Wheel or +/- zoom. Arrows pan. Drag selects A/B. Home resets. "
                                      "Колесо или +/- масштаб, стрелки прокрутка, выделение мышью A/B.")

    def set_interval(self,payload):
        self.payload=payload
        self.selection=None
        self.update()

    def set_track(self,key,enabled):
        if enabled:
            self.visible_tracks.add(key)
        else:
            self.visible_tracks.discard(key)
        self.update()

    def _plot(self):
        return QRectF(150,12,max(1,self.width()-170),max(1,self.height()-45))

    def _stamp(self,x):
        lo,hi=self.payload["selected_interval_ns"]
        f=max(0,min(1,(x-self._plot().left())/self._plot().width()))
        return lo+int((hi-lo)*f)

    def _request(self,lo,hi):
        if hi>lo>=0:
            self.range_requested.emit(int(lo),int(hi))

    def wheelEvent(self,event):
        if not self.payload:
            return
        lo,hi=self.payload["selected_interval_ns"]
        anchor=self._stamp(event.position().x())
        factor=.5 if event.angleDelta().y()>0 else 2
        self._request(max(0,anchor-int((anchor-lo)*factor)),anchor+max(1,int((hi-anchor)*factor)))
        event.accept()

    def mousePressEvent(self,event):
        if self.payload:
            self.setFocus()
            self._drag=(event.button(),event.position().x(),self._stamp(event.position().x()))

    def mouseMoveEvent(self,event):
        if not self.payload:
            return
        stamp=self._stamp(event.position().x())
        if self._drag:
            self.selection=sorted((self._drag[2],stamp))
            self.update()
            return
        labels=[]
        for key in self.TRACKS:
            if key not in self.visible_tracks:
                continue
            points=self.payload["timeline"]["tracks"].get(key,[])
            i=bisect_left([p["time_ns"] for p in points],stamp)
            if points:
                p=points[min(i,len(points)-1)]
                labels.append(f"{key}: {p['value']:.4g} {self.payload['metrics'][key]['unit']} "
                              f"@ {(p['time_ns']-self.payload['metadata']['monotonic_origin_ns'])/1e9:.6f}s")
        if labels:
            QToolTip.showText(event.globalPosition().toPoint(),"\n".join(labels)+
                             "\nFIRST/MIN/MAX/LAST; gaps are not zero",self)

    def mouseReleaseEvent(self,event):
        if not self._drag or not self.payload:
            return
        button,x,stamp=self._drag
        self._drag=None
        now=self._stamp(event.position().x())
        lo,hi=self.payload["selected_interval_ns"]
        if abs(event.position().x()-x)<5:
            return
        if button==Qt.MouseButton.LeftButton:
            self._request(*sorted((stamp,now)))
        else:
            shift=stamp-now
            self._request(max(0,lo+shift),max(1,hi+shift))

    def keyPressEvent(self,event):
        if not self.payload:
            return
        lo,hi=self.payload["selected_interval_ns"]
        span=max(1,hi-lo)
        if event.key() in (Qt.Key.Key_Plus,Qt.Key.Key_Equal):
            self._request(lo+span//4,hi-span//4)
        elif event.key()==Qt.Key.Key_Minus:
            self._request(max(0,lo-span//2),hi+span//2)
        elif event.key() in (Qt.Key.Key_Left,Qt.Key.Key_Right):
            shift=span//4*(1 if event.key()==Qt.Key.Key_Right else -1)
            self._request(max(0,lo+shift),max(1,hi+shift))
        elif event.key()==Qt.Key.Key_Home:
            self.range_requested.emit(None,None)
        else:
            super().keyPressEvent(event)

    def paintEvent(self,event):
        painter=QPainter(self)
        painter.fillRect(self.rect(),QColor("#fffaf0"))
        painter.setPen(QColor("#584c63"))
        if not self.payload:
            painter.drawText(self.rect(),Qt.AlignmentFlag.AlignCenter,"No interval / Нет интервала")
            return
        plot=self._plot()
        keys=[k for k in self.TRACKS if k in self.visible_tracks]
        lo,hi=self.payload["selected_interval_ns"]
        height=plot.height()/max(1,len(keys))
        for n,key in enumerate(keys):
            y=plot.top()+height*n
            points=self.payload["timeline"]["tracks"].get(key,[])
            maximum=max((p["value"] for p in points),default=1) or 1
            if key=="cpu_interval_percent":
                maximum=max(100,maximum)
            painter.setPen(QColor("#e2d6d3"))
            painter.drawLine(QPointF(plot.left(),y+height-4),QPointF(plot.right(),y+height-4))
            painter.setPen(QColor("#584c63"))
            unit=self.payload["metrics"][key]["unit"]
            painter.drawText(QRectF(3,y,144,height),Qt.AlignmentFlag.AlignVCenter,
                key.replace("_interval_percent"," %")+f"\n{maximum:.3g} {unit}" if points else
                key+"\nUNAVAILABLE")
            path=QPainterPath()
            previous_segment=None
            for point in points:
                x=plot.left()+plot.width()*(point["time_ns"]-lo)/max(1,hi-lo)
                yy=y+height-8-(height-15)*point["value"]/maximum
                if point["segment"]!=previous_segment:
                    path.moveTo(x,yy)
                else:
                    path.lineTo(x,yy)
                previous_segment=point["segment"]
            painter.setPen(QPen(QColor(self.COLORS[self.TRACKS.index(key)]),2))
            painter.drawPath(path)
        origin=self.payload["metadata"]["monotonic_origin_ns"]
        painter.setPen(QColor("#584c63"))
        painter.drawText(150,self.height()-10,f"A {(lo-origin)/1e9:.6f}s  —  B {(hi-origin)/1e9:.6f}s")
        if self.selection:
            for stamp in self.selection:
                x=plot.left()+plot.width()*(stamp-lo)/max(1,hi-lo)
                painter.setPen(QPen(QColor("#5e517c"),1,Qt.PenStyle.DashLine))
                painter.drawLine(QPointF(x,plot.top()),QPointF(x,plot.bottom()))
