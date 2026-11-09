"""Qt receives safe text while derived diagnostic JSON keeps exact strings."""
from copy import deepcopy
import json
import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM","offscreen")
from PySide6.QtWidgets import QApplication, QPlainTextEdit, QTableWidget

from blackbox_universal.decoder_analysis import CallTreeDialog, DiagnosticReportDialog
from qt_test_support import dispose_closed_fixture


class DecoderPresentationAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app=QApplication.instance() or QApplication([])

    def test_calltree_escaped_surrogate_label_keeps_original_frame_and_identity(self):
        report={"status":"TEST_ONLY","filters":{"source":"dotnet"},"coverage":{},"nodes":[
            {"id":"node-1","parent_id":None,"label":"raw\ud800<frame>",
             "inclusive_samples":1,"self_samples":1,"frame":{"name":"raw\ud800<frame>"}}]}
        before=deepcopy(report)
        for language in ("RU","EN"):
            dialog=CallTreeDialog(report,language)
            self.assertEqual(dialog.tree.topLevelItem(0).text(0),r"raw\ud800<frame>")
            self.assertIn(r"\ud800",dialog.tree.topLevelItem(0).toolTip(0))
            self.assertEqual(report,before)
            dialog.close()
            dispose_closed_fixture(dialog,self.app)

    def test_wait_table_handles_surrogate_reason_and_complete_json_still_round_trips(self):
        report={"schema":"blackbox.thread-waits/1","status":"TEST_ONLY", "intervals":[
            {"pid":1,"tid":2,"start_ms":0,"end_ms":1,"off_cpu_ms":1,"ready_delay_ms":None,
             "wait_reason":"raw\ud800<reason>","quality":"TEST_ONLY","explanation":"unverified\ud800"}]}
        before=deepcopy(report)
        for language in ("RU","EN"):
            dialog=DiagnosticReportDialog(report,language)
            table=dialog.findChild(QTableWidget)
            self.assertEqual(table.item(0,6).text(),r"raw\ud800<reason>")
            self.assertEqual(json.loads(dialog.findChild(QPlainTextEdit).toPlainText()),before)
            self.assertEqual(report,before)
            dialog.close()
            dispose_closed_fixture(dialog,self.app)


if __name__=="__main__":
    unittest.main()
