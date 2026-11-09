"""Read-only imported event bounds and complete keyset paging regressions."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from blackbox_core.event_stream import _union, event_page, event_tracks
from blackbox_core.session_v2 import FILENAME, SessionV2Writer
from blackbox_core.session_view import SessionReadError, SessionView


class EventStreamAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        writer = SessionV2Writer(self.folder, pid=123, created=1., name="TEST_ONLY", origin_ns=10**9)
        writer.finish("COMPLETED")
        self.path = self.folder / FILENAME

    def insert(self, detail="{}", **fields):
        row = {"recorded_ns": 2*10**9, "observed_ns": 2*10**9, "instance_id": 1,
               "event_type": "TEST_ONLY", "source_kind": "WIN32", "verification_class": "TEST_ONLY",
               "timestamp_precision": "TEST_ONLY", "correlation_key": "TEST_ONLY",
               "measurement_status": "OK", "detail_json": detail}
        row.update(fields)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("INSERT INTO events("+",".join(row)+") VALUES("+",".join("?" for _ in row)+")", tuple(row.values()))
            db.commit()

    def test_oversized_scalar_projection_is_bounded_and_never_becomes_a_truncated_match(self):
        for field in ("event_type", "source_kind", "measurement_status"):
            with self.subTest(field=field):
                with closing(sqlite3.connect(self.path)) as db:
                    db.execute("DELETE FROM events")
                    db.commit()
                self.insert(**{field: "x"*500000})
                before = self.path.read_bytes()
                with SessionView.open(self.folder) as view:
                    sql = _union(view, self.folder)
                    row = view.db.execute("SELECT code,status,source FROM ("+sql+")").fetchone()
                    self.assertTrue(all(len(value)<=513 for value in row))
                for filters in ({}, {"search":"absent"}, {"severity":"ERROR"}):
                    with self.assertRaisesRegex(SessionReadError, "IMPORTED_EVENT_SCALAR"):
                        event_page(self.folder, **filters)
                with SessionView.open(self.folder) as view:
                    with self.assertRaisesRegex(SessionReadError, "IMPORTED_EVENT_SCALAR"):
                        event_tracks(view, 0, 3*10**9, folder=self.folder)
                self.assertEqual(self.path.read_bytes(), before)

    def test_malformed_clock_instance_and_nontext_code_fail_before_filter_counting(self):
        for fields in ({"observed_ns":"wrong clock"}, {"observed_ns":1.5},
                       {"instance_id":-1}, {"instance_id":"unknown"},
                       {"event_type":"CODE\x00hidden"},{"source_kind":"WIN32\x00hidden"},
                       {"measurement_status":"OK\x00hidden"},
                       {"event_type":sqlite3.Binary(b"not text")}):
            with self.subTest(fields=fields):
                with closing(sqlite3.connect(self.path)) as db:
                    db.execute("DELETE FROM events")
                    db.commit()
                self.insert(**fields)
                before = self.path.read_bytes()
                with self.assertRaisesRegex(SessionReadError, "IMPORTED_EVENT_SCALAR"):
                    event_page(self.folder, start_ns=0, end_ns=1, instance_id=99)
                self.assertEqual(self.path.read_bytes(), before)

    def test_byte_limited_pages_reach_every_same_timestamp_event_and_keep_exact_count(self):
        for index in range(9):
            self.insert(json.dumps({"ordinal":index,"text":"я"*300}))
        before = self.path.read_bytes()
        seen=[];cursor=None;limited=False
        with patch("blackbox_core.event_stream.MAX_EVENT_PAGE_BYTES", 5000):
            while True:
                page=event_page(self.folder, after=cursor, limit=200)
                self.assertEqual(page["total_matching"], 9)
                self.assertLessEqual(page["serialized_rows_bytes"], 5000)
                self.assertTrue(page["rows"])
                seen.extend(row["id"] for row in page["rows"])
                limited |= page["page_limit_reason"]=="SERIALIZED_PAGE_BYTE_LIMIT"
                if not page["has_more"]:
                    break
                cursor=page["next_cursor"]
                self.assertEqual(cursor, [page["rows"][-1][key] for key in ("time_ns","rank","id")])
        self.assertTrue(limited)
        self.assertEqual(len(seen),9)
        self.assertEqual(len(set(seen)),9)
        self.assertEqual(seen,sorted(seen))
        self.assertEqual(self.path.read_bytes(),before)

    def test_invalid_detail_is_explicit_and_zero_false_null_remain_distinct(self):
        details=['{"zero":0,"false":false,"none":null}', '{"x":NaN}', '{"x":1e999}',
                 '{"x":1,"x":2}', '['*40+'0'+']'*40]
        for detail in details:
            self.insert(detail)
        before=self.path.read_bytes()
        page=event_page(self.folder)
        self.assertEqual(page["total_matching"],5)
        self.assertEqual(page["rows"][0]["detail"],{"zero":0,"false":False,"none":None})
        self.assertTrue(all(row["detail"]["status"]=="INVALID_IMPORTED_EVENT" for row in page["rows"][1:]))
        self.assertEqual(self.path.read_bytes(),before)

    def test_utf8_detail_budget_counts_bytes_and_search_does_not_claim_a_false_negative(self):
        detail=json.dumps({"text":"я"*9000},ensure_ascii=False)
        self.assertLess(len(detail),16384)
        self.insert(detail)
        before=self.path.read_bytes()
        row=event_page(self.folder)["rows"][0]
        self.assertEqual(row["detail"]["status"],"IMPORTED_EVENT_SIZE_LIMIT")
        self.assertEqual(row["detail"]["recorded_size_bytes"],len(detail.encode("utf-8")))
        with self.assertRaisesRegex(SessionReadError,"DETAIL_SEARCH_UNSUPPORTED"):
            event_page(self.folder,search="absent")
        self.assertEqual(self.path.read_bytes(),before)

    def test_session_page_rejects_bad_cursor_and_imported_scalars_without_source_changes(self):
        before=self.path.read_bytes()
        with SessionView.open(self.folder) as view:
            for cursor in (None,1,"00",{},[0],[False,0],[0,-1],[0,2**63]):
                with self.subTest(cursor=cursor),self.assertRaisesRegex(SessionReadError,"INVALID_PAGE"):
                    view.event_page(after=cursor)
            for filters in ({"start_ns":False},{"end_ns":2**63},{"start_ns":2,"end_ns":1}):
                with self.subTest(filters=filters),self.assertRaisesRegex(SessionReadError,"INVALID_PAGE"):
                    view.event_page(**filters)
        self.assertEqual(self.path.read_bytes(),before)
        cases=[{field:"x"*500000} for field in ("event_type","source_kind","verification_class",
               "timestamp_precision","correlation_key","measurement_status")]
        cases.extend(({"observed_ns":1.5},{"recorded_ns":"wrong clock"},{"instance_id":-1},
                      {"event_type":sqlite3.Binary(b"not text")},
                      {"event_type":"CODE\x00hidden"},{"source_kind":"WIN32\x00hidden"},
                      {"verification_class":"OS_OBSERVED\x00hidden"},
                      {"timestamp_precision":"TEST_ONLY\x00hidden"},
                      {"correlation_key":"TEST_ONLY\x00hidden"},
                      {"measurement_status":"OK\x00hidden"}))
        for fields in cases:
            with self.subTest(field=next(iter(fields))):
                with closing(sqlite3.connect(self.path)) as db:
                    db.execute("DELETE FROM events")
                    db.commit()
                self.insert(**fields)
                before=self.path.read_bytes()
                with SessionView.open(self.folder) as view:
                    with self.assertRaisesRegex(SessionReadError,"IMPORTED_EVENT_SCALAR"):
                        view.event_page(0,1)
                self.assertEqual(self.path.read_bytes(),before)

    def test_session_byte_limited_pages_preserve_every_same_clock_event_and_recorded_trust(self):
        for index in range(9):
            self.insert(json.dumps({"ordinal":index,"text":"я"*300}))
        before=self.path.read_bytes()
        seen=[];cursor=(0,0);limited=False
        with patch("blackbox_core.event_stream.MAX_EVENT_PAGE_BYTES",5000),SessionView.open(self.folder) as view:
            while True:
                page=view.event_page(after=cursor,limit=200)
                self.assertTrue(page["rows"])
                self.assertLessEqual(page["serialized_rows_bytes"],5000)
                for row in page["rows"]:
                    self.assertEqual(row["recorded_verification_class"],"TEST_ONLY")
                    self.assertEqual(row["verification_class"],"UNVERIFIED_IMPORT")
                    self.assertEqual(row["detail_read_status"],"RECORDED_JSON")
                    seen.append(row["event_id"])
                limited |= page["page_limit_reason"]=="SERIALIZED_PAGE_BYTE_LIMIT"
                if not page["has_more"]:
                    break
                self.assertNotEqual(cursor,page["next_cursor"])
                cursor=page["next_cursor"]
                self.assertEqual(cursor,[page["rows"][-1][key] for key in ("event_time_ns","event_id")])
        self.assertTrue(limited)
        self.assertEqual(len(seen),9)
        self.assertEqual(len(set(seen)),9)
        self.assertEqual(seen,sorted(seen))
        self.assertEqual(self.path.read_bytes(),before)

    def test_session_detail_read_status_does_not_interpret_a_recorded_status_field_as_an_error(self):
        values=[None,False,0,[0,False,None],{"status":"INVALID_IMPORTED_EVENT","reason":"recorded text"}]
        for value in values:
            self.insert(json.dumps(value))
        for text in ('{"x":1e999}','{"x":1,"x":2}','['*40+'0'+']'*40):
            self.insert(text)
        self.insert(sqlite3.Binary(b"{}"))
        before=self.path.read_bytes()
        with SessionView.open(self.folder) as view:
            page=view.event_page()
        for row,value in zip(page["rows"],values):
            self.assertEqual(type(row["detail"]),type(value))
            self.assertEqual(row["detail"],value)
            self.assertEqual(row["detail_read_status"],"RECORDED_JSON")
            self.assertNotIn("detail_read_error",row)
        for row in page["rows"][len(values):]:
            self.assertIsNone(row["detail"])
            self.assertEqual(row["detail_read_status"],"INVALID_OR_UNSUPPORTED_IMPORTED_JSON")
            self.assertEqual(row["detail_read_error"],"INVALID_IMPORTED_EVENT")
        self.assertEqual(self.path.read_bytes(),before)

    def test_session_detail_byte_limit_preserves_the_existing_oversize_refusal(self):
        detail=json.dumps({"text":"я"*9000},ensure_ascii=False)
        self.assertLess(len(detail),16384)
        self.insert(detail)
        before=self.path.read_bytes()
        with SessionView.open(self.folder) as view:
            with self.assertRaisesRegex(SessionReadError,"IMPORTED_EVENT_SIZE_LIMIT"):
                view.event_page()
        self.assertEqual(self.path.read_bytes(),before)


if __name__=="__main__":
    unittest.main()
