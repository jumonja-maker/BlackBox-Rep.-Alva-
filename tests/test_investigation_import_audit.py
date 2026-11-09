"""Finding/card import bounds preserve counts, cursors and source bytes."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from blackbox_core.investigation_v2 import _persisted_findings, _research_findings, incident_card, investigate
from blackbox_core.session_v2 import FILENAME, SessionV2Writer
from blackbox_core.session_view import SessionReadError, SessionView
from test_investigation_v2 import ORIGIN, observation


class InvestigationImportAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name)
        writer=SessionV2Writer(self.folder,pid=123,created=1.,name="TEST_ONLY",origin_ns=ORIGIN)
        for index in range(1,9):
            writer.submit("detail",observation(index))
        writer.finish("COMPLETED")
        self.path=self.folder/FILENAME

    def incident(self,context="{}"):
        with closing(sqlite3.connect(self.path)) as db:
            identity=db.execute("INSERT INTO incidents(trigger_code,start_ns,end_ns,status,primary_event_id,context_json) "
                "VALUES('UI_TIMEOUT',?,?,'TEST_ONLY',1,?)",(ORIGIN+2*10**9,ORIGIN+3*10**9,context)).lastrowid
            db.commit()
        return identity

    def test_forged_incident_scalar_is_refused_before_paging_and_card_arithmetic(self):
        identity=self.incident()
        for field,value in (("trigger_code","x"*500000),("status","x"*500000),
                            ("trigger_code","UI_TIMEOUT\x00hidden"),("status","OK\x00hidden"),
                            ("root_cause","x"*500000),("start_ns","wrong clock"),
                            ("end_ns",1),("primary_event_id",-1)):
            with self.subTest(field=field):
                with closing(sqlite3.connect(self.path)) as db:
                    original=db.execute("SELECT "+field+" FROM incidents WHERE incident_id=?",(identity,)).fetchone()[0]
                    db.execute("UPDATE incidents SET "+field+"=? WHERE incident_id=?",(value,identity))
                    db.commit()
                before=self.path.read_bytes()
                with SessionView.open(self.folder) as view:
                    with self.assertRaisesRegex(SessionReadError,"IMPORTED_FINDING"):
                        list(_persisted_findings(view,0,1,{}))
                with self.assertRaisesRegex(SessionReadError,"IMPORTED_FINDING"):
                    incident_card(self.folder,identity)
                self.assertEqual(self.path.read_bytes(),before)
                with closing(sqlite3.connect(self.path)) as db:
                    db.execute("UPDATE incidents SET "+field+"=? WHERE incident_id=?",(original,identity))
                    db.commit()

    def test_oversized_sensor_identity_is_refused_without_retaining_the_scalar(self):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("INSERT INTO sensor_errors(monotonic_ns,sensor_id,code) VALUES(?,?,?)",
                       (ORIGIN+10**9,"x"*500000,"TEST_ONLY"))
            db.commit()
        before=self.path.read_bytes()
        with self.assertRaisesRegex(SessionReadError,"IMPORTED_FINDING"):
            investigate(self.folder)
        self.assertEqual(self.path.read_bytes(),before)

    def test_research_source_and_clock_validation_precede_interval_or_kind_exclusion(self):
        path=self.folder/"research.sqlite3"
        with closing(sqlite3.connect(path)) as db:
            db.execute("CREATE TABLE evidence(id INTEGER PRIMARY KEY,monotonic_ns,kind,source,data)")
            db.execute("INSERT INTO evidence VALUES(1,?,?,?,?)",(ORIGIN,"unknown","x"*500000,"{}"))
            db.commit()
        before=path.read_bytes()
        with self.assertRaisesRegex(SessionReadError,"IMPORTED_FINDING"):
            list(_research_findings(self.folder,0,1,{}))
        self.assertEqual(path.read_bytes(),before)

    def test_invalid_and_oversized_incident_context_are_explicit_in_findings_and_cards(self):
        for text,status in ((json.dumps({"text":"я"*9000},ensure_ascii=False),"IMPORTED_EVENT_SIZE_LIMIT"),
                            ('{"x":1e999}',"INVALID_IMPORTED_EVENT")):
            with self.subTest(status=status):
                identity=self.incident(text)
                before=self.path.read_bytes()
                with SessionView.open(self.folder) as view:
                    rows=list(_persisted_findings(view,ORIGIN,ORIGIN+9*10**9,{}))
                row=next(item for item in rows if item["detail"]["incident_id"]==identity)
                self.assertEqual(row["detail"]["context"]["status"],status)
                card=incident_card(self.folder,identity,pre_seconds=0,post_seconds=0)
                self.assertEqual(card["incident"]["context"]["status"],status)
                self.assertEqual(self.path.read_bytes(),before)

    def test_byte_limited_finding_pages_keep_exact_inventory_for_each_sort(self):
        for index in range(9):
            self.incident(json.dumps({"ordinal":index,"text":"я"*300}))
        before=self.path.read_bytes()
        for order in ("TIME_ASC","TIME_DESC","SEVERITY"):
            cursor=None;seen=[];limited=False
            with self.subTest(order=order),patch("blackbox_core.investigation_v2.MAX_EVENT_PAGE_BYTES",6000):
                while True:
                    page=investigate(self.folder,after=cursor,sort_order=order,limit=100,question="UI")
                    self.assertEqual(page["findings_total"],9)
                    self.assertLessEqual(page["serialized_findings_bytes"],6000)
                    self.assertTrue(page["findings"])
                    seen.extend(item["finding_id"] for item in page["findings"])
                    limited |= page["page_limit_reason"]=="SERIALIZED_PAGE_BYTE_LIMIT"
                    if not page["has_more"]:
                        break
                    self.assertNotEqual(page["next_cursor"],cursor)
                    cursor=page["next_cursor"]
                self.assertTrue(limited)
                self.assertEqual(len(seen),9)
                self.assertEqual(len(set(seen)),9)
        self.assertEqual(self.path.read_bytes(),before)


if __name__=="__main__":
    unittest.main()
