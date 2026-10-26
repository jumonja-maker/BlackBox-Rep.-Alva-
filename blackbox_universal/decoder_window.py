"""Production six-page shell; preserves the five-page embedder API unchanged."""
from PySide6.QtCore import QTimer
from .window import UniversalWindow
from .decoder_panel import DecoderPanel


class DecoderWindow(UniversalWindow):
    PAGES = UniversalWindow.PAGES + (("decoder", "06  TRACE DECODER"),)

    def _build(self):
        super()._build()
        self._decoder_close_pending = False
        self.decoder_panel = DecoderPanel(self)
        # The base shell's navigation intentionally resets each page's scroll bar.
        # Wrap the sixth page exactly like the original five, rather than
        # leaving a bare QWidget that crashes when navigation opens it.
        self._page_ids["decoder"] = self.stack.addWidget(self._as_scroll(self.decoder_panel))
        self.decoder_panel.idle.connect(self._decoder_idle)

    def _set_language(self, language):
        super()._set_language(language)
        if hasattr(self, "decoder_panel"):
            self.decoder_panel.retranslate()
            button = self._nav_buttons["decoder"]
            button.setText("   06  ДЕКОДЕР ТРАСС" if self.language == "RU" else "   06  TRACE DECODER")
            button.setToolTip("ETL / EventPipe / JSONL")

    def _decoder_idle(self):
        if self._decoder_close_pending:
            self._decoder_close_pending = False
            QTimer.singleShot(0, self.close)

    def closeEvent(self, event):
        if self.decoder_panel.worker is not None:
            self._decoder_close_pending = True
            self.decoder_panel.cancel()
            event.ignore()
            return
        super().closeEvent(event)
        if event.isAccepted():
            self.decoder_panel.cache.cleanup()
