from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from blackbox_investigation import (InvestigationError, Policy, analyze, analyze_session,
                                     analyze_snapshot, compare_reports, load_session, to_html)
from blackbox_investigation.model import normalize_samples


def sample(ms, cpu=5, rss=100, read=0, write=0, threads=None, private=None):
    return {"elapsed_ms": ms, "cpu_percent": cpu, "rss_bytes": rss,
            "read_bytes": read, "write_bytes": write, "children_count": 0,
            "num_threads": 1, "private_bytes": private, "threads": threads}


def fixture_session(folder: Path, state="COMPLETED") -> Path:
    folder.mkdir(exist_ok=True)
    db = sqlite3.connect(folder / "session.sqlite3")
    db.executescript('''
      CREATE TABLE metadata(schema_version INTEGER NOT NULL, session_id TEXT NOT NULL,
        pid INTEGER NOT NULL, started_utc TEXT NOT NULL, ended_utc TEXT,
        exit_code TEXT, probe TEXT NOT NULL);
      CREATE TABLE samples(seq INTEGER PRIMARY KEY,elapsed_ms INTEGER NOT NULL,
        rss_bytes INTEGER,cpu_percent REAL,num_threads INTEGER,read_bytes INTEGER,
        write_bytes INTEGER,children_count INTEGER);
      CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,data TEXT NOT NULL);
    ''')
    db.execute("INSERT INTO metadata VALUES (1,'session-safe',424,'2026-10-23T01:00:00Z',?,?,'psutil-read-only')",
               ('2026-10-23T01:01:00Z', state))
    db.executemany("INSERT INTO samples VALUES (?,?,?,?,?,?,?,?)", [
        (1,0,100,1.0,2,0,0,0), (2,1000,130,2.0,3,100,200,0),
        (3,2000,250,90.0,3,400,500,1), (4,4000,300,99.0,4,900,1000,2)])
    db.commit(); db.close()
    return folder


class InvestigationEngine(unittest.TestCase):
    def test_empty_observations_are_unknown_not_successful_diagnosis(self):
        result = analyze([])
        self.assertIn("NO_OBSERVATIONS", result["warnings"])
        self.assertEqual(result["claims"]["internal_root_cause"], "UNKNOWN")
        self.assertEqual(result["summary"]["cpu_percent"]["count"], 0)

    def test_preserve_null_values_without_inventing_rates(self):
        result = analyze([sample(0, None, None, None, None), sample(1000, None, None, None, None)])
        self.assertIsNone(result["timeline"][1]["read_bps"])
        self.assertIsNone(result["summary"]["rss_bytes"]["mean"])
        self.assertEqual(result["findings"], [])

    def test_explicit_cpu_episode_has_duration_and_noncausal_interpretation(self):
        a = analyze([sample(0,90),sample(1000,95),sample(3000,99),sample(4000,1)])
        high = [x for x in a["findings"] if x["code"] == "SUSTAINED_HIGH_CPU"]
        self.assertEqual(len(high), 1)
        self.assertEqual((high[0]["start_ms"], high[0]["end_ms"]), (0,3000))
        self.assertEqual(high[0]["interpretation"], "CANDIDATE_NOT_CAUSAL_PROOF")
        self.assertEqual(a["claims"]["source_stack"], "NOT_OBSERVED")

    def test_one_cpu_peak_does_not_create_sustained_episode(self):
        result = analyze([sample(0,1),sample(1000,100),sample(2000,1)])
        self.assertFalse(any(x["code"] == "SUSTAINED_HIGH_CPU" for x in result["findings"]))

    def test_gap_does_not_fabricate_cpu_duration_or_io_rates(self):
        result = analyze([sample(0,100,read=0),sample(20000,100,read=1000000)])
        self.assertTrue(any(x["code"] == "OBSERVATION_GAP" for x in result["findings"]))
        self.assertFalse(any(x["code"] == "SUSTAINED_HIGH_CPU" for x in result["findings"]))
        self.assertIsNone(result["timeline"][1]["read_bps"])

    def test_counter_reset_never_becomes_negative_throughput(self):
        r = analyze([sample(0,read=999),sample(1000,read=20)])
        self.assertIsNone(r["timeline"][1]["read_bps"])
        self.assertIn("COUNTER_RESET", [x["code"] for x in r["findings"]])

    def test_io_rate_is_derived_from_elapsed_intervals(self):
        p=Policy(io_rate_alert_bps=100)
        r=analyze([sample(0,read=0,write=0),sample(2000,read=400,write=100)],policy=p)
        self.assertEqual(r["timeline"][1]["read_bps"],200.0)
        self.assertEqual(r["timeline"][1]["write_bps"],50.0)
        self.assertEqual(len([f for f in r["findings"] if f["code"]=="HIGH_IO_RATE"]),1)

    def test_memory_growth_candidate_is_not_leak_proof(self):
        r=analyze([sample(0,rss=10),sample(1000,rss=90),sample(2000,rss=160)],
                  policy=Policy(rss_growth_alert_bytes=50))
        self.assertIn("MEMORY_GROWTH_CANDIDATE",[f["code"] for f in r["findings"]])
        self.assertEqual(r["claims"]["memory_leak"],"NOT_PROVEN")

    def test_memory_decrease_is_not_growth(self):
        r=analyze([sample(0,rss=160),sample(1000,rss=90),sample(2000,rss=10)],
                  policy=Policy(rss_growth_alert_bytes=50))
        self.assertNotIn("MEMORY_GROWTH_CANDIDATE",[f["code"] for f in r["findings"]])

    def test_private_bytes_remain_distinct_from_rss(self):
        r=analyze([sample(0,rss=100,private=10), sample(1000,rss=100,private=20),
                   sample(2000,rss=100,private=99)],policy=Policy(rss_growth_alert_bytes=20))
        growth=[f for f in r["findings"] if f["code"]=="MEMORY_GROWTH_CANDIDATE"]
        self.assertEqual(len(growth),1)
        self.assertEqual(growth[0]["facts"][0]["metric"],"private_bytes")

    def test_persistent_thread_cpu_is_measured_without_fake_symbol(self):
        r=analyze([sample(0,threads=[{"tid":123,"cpu_seconds":1.0}]),
                   sample(1000,threads=[{"tid":123,"cpu_seconds":1.8}])])
        self.assertAlmostEqual(r["timeline"][1]["threads"][0]["cpu_percent_one_core"],80)
        self.assertIn("HOT_THREAD_OBSERVED",[f["code"] for f in r["findings"]])
        self.assertEqual(r["claims"]["source_stack"],"NOT_OBSERVED")

    def test_tid_disappearance_does_not_infer_cpu(self):
        r=analyze([sample(0,threads=[{"tid":123,"cpu_seconds":2.0}]),
                   sample(1000,threads=[{"tid":345,"cpu_seconds":2.0}])])
        self.assertEqual(r["timeline"][1]["threads"],[])

    def test_thread_cpu_reset_is_not_negative(self):
        r=analyze([sample(0,threads=[{"tid":123,"cpu_seconds":10.0}]),
                   sample(1000,threads=[{"tid":123,"cpu_seconds":1.0}])])
        self.assertEqual(r["timeline"][1]["threads"],[])

    def test_manual_problem_marker_carries_bounded_context(self):
        r=analyze([sample(0),sample(1000),sample(2000),sample(3000)],
                  markers=[{"elapsed_ms":2000,"kind":"user_problem","note":"GUI slow"}],
                  policy=Policy(context_before_ms=1000,context_after_ms=1000))
        self.assertEqual(r["captures"][0]["sample_count"],3)
        self.assertEqual(r["markers"][0]["source"],"USER")

    def test_hang_marker_requires_external_os_evidence(self):
        with self.assertRaises(InvestigationError) as err:
            analyze([sample(0)],markers=[{"elapsed_ms":0,"kind":"observed_window_unresponsive"}])
        self.assertEqual(err.exception.code,"UNATTESTED_SYSTEM_EVENT")

    def test_hang_marker_with_source_is_not_deadlock_proof(self):
        with self.assertRaises(InvestigationError) as error:
            analyze([sample(0)], markers=[{"elapsed_ms": 0,
                  "kind": "observed_window_unresponsive", "source": "EXTERNAL_OS_OBSERVATION"}])
        self.assertEqual(error.exception.code, "UNATTESTED_SYSTEM_EVENT")

    def test_exit_marker_requires_lifecycle_provenance(self):
        with self.assertRaises(InvestigationError):
            analyze([sample(0)],markers=[{"elapsed_ms":0,"kind":"observed_process_exit","source":"USER"}])

    def test_out_of_range_marker_refused(self):
        with self.assertRaises(InvestigationError):
            analyze([sample(0),sample(1000)],markers=[{"elapsed_ms":2000,"kind":"user_problem"}])

    def test_duplicate_timestamp_refused(self):
        with self.assertRaises(InvestigationError):
            analyze([sample(1000),sample(1000)])

    def test_nan_infinite_bool_negative_are_refused(self):
        for value in (float("nan"),float("inf"),True,-5):
            with self.subTest(value=value),self.assertRaises(InvestigationError):
                analyze([sample(0,cpu=value)])

    def test_too_many_samples_refused_without_silent_truncation(self):
        with self.assertRaises(InvestigationError):
            analyze([sample(i) for i in range(5)],policy=Policy(max_samples=4))

    def test_canonical_exact_digest_reproducible(self):
        a=analyze([sample(0),sample(1000)])
        b=analyze([sample(0),sample(1000)])
        self.assertEqual(a["input_sha256"],b["input_sha256"])
        self.assertEqual(a["evidence_sha256"],b["evidence_sha256"])
        c=analyze([sample(0),sample(1000,rss=999)])
        self.assertNotEqual(a["evidence_sha256"],c["evidence_sha256"])

    def test_percentile_median_and_pair_comparison_not_proof(self):
        a=analyze([sample(0,cpu=1),sample(1000,cpu=3)])
        b=analyze([sample(0,cpu=3),sample(1000,cpu=5)])
        self.assertEqual(a["summary"]["cpu_percent"]["median"],2)
        cmp=compare_reports(a,b)
        self.assertEqual(cmp["metrics"]["cpu_percent"]["delta"],2)
        self.assertFalse(cmp["performance_regression_proven"])

    def test_input_identity_drops_private_string_keys(self):
        r=analyze([sample(0)],identity={"pid":100,"creation_time":None,
                                           "command":"password=secret", "path":"/private"})
        self.assertNotIn("password",json.dumps(r))
        self.assertEqual(r["identity"],{"pid":100,"creation_time":None})

    def test_bad_policy_rejected(self):
        for config in ({"max_samples":0},{"cpu_alert_percent":float("nan")},
                       {"max_threads_per_sample":99999},{"cpu_min_duration_ms":3600001}):
            with self.subTest(config=config),self.assertRaises(InvestigationError):
                Policy(**config)

    def test_thread_duplicate_refused(self):
        with self.assertRaises(InvestigationError):
            analyze([sample(0,threads=[{"tid":42,"cpu_seconds":1},{"tid":42,"cpu_seconds":2}])])

    def test_html_escapes_notes_and_has_no_script(self):
        r=analyze([sample(0)],markers=[{"elapsed_ms":0,"kind":"user_problem","note":"<svg onload=alert(1)>"}])
        html=to_html(r)
        self.assertNotIn("<svg",html)
        self.assertNotIn("<script",html)
        self.assertIn("Причина: НЕ УСТАНОВЛЕНА",html)
        self.assertIn("Расследование",html)
        self.assertIn("Investigation",to_html(r,lang="EN"))

    def test_unrelated_report_refused(self):
        with self.assertRaises(InvestigationError):
            compare_reports({}, {})


class ExistingBlackBoxAdapters(unittest.TestCase):
    def test_exact_schema_one_read_only_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=fixture_session(Path(tmp)/"session")
            before=(folder/"session.sqlite3").read_bytes()
            data=load_session(folder)
            self.assertEqual(data["pid"],424)
            self.assertEqual(len(data["samples"]),4)
            report=analyze_session(folder)
            self.assertEqual(report["provenance"]["sample_source"],"BLACKBOX_SQLITE_V1_READ_ONLY")
            self.assertFalse(report["provenance"]["pid_creation_verified"])
            self.assertEqual((folder/"session.sqlite3").read_bytes(),before)
            self.assertEqual(set(p.name for p in folder.iterdir()),{"session.sqlite3"})

    def test_real_exit_from_storage_not_mislabeled_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=fixture_session(Path(tmp)/"session","PROCESS_EXITED")
            report=analyze_session(folder)
            self.assertIn("PROCESS_EXIT_RECORDED",[f["code"] for f in report["findings"]])
            self.assertEqual(report["provenance"]["lifecycle_proof"], "RECORDED_NOT_ATTESTED")
            self.assertEqual(report["claims"]["internal_root_cause"],"UNKNOWN")

    def test_legacy_unsupported_schema_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)/"session";folder.mkdir()
            db=sqlite3.connect(folder/"session.sqlite3")
            db.execute("CREATE TABLE samples(a INTEGER)");db.commit();db.close()
            with self.assertRaises(InvestigationError):load_session(folder)

    def test_missing_session_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(InvestigationError):load_session(tmp)

    def test_session_limits_applied_before_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=fixture_session(Path(tmp)/"session")
            with self.assertRaises(InvestigationError):load_session(folder,policy=Policy(max_samples=2))

    def test_qt_snapshot_034_mapping_without_qt_import(self):
        snap={"schema_version":1,"product":"BLACK.BOX Universal", "observed_process":{"pid":999},
              "recent_samples":[{"seconds":0,"cpu_pct":12.0,"rss_mb":10,"process_count":1,
                                  "thread_count":5,"read_bytes":0,"write_bytes":0},
                                {"seconds":1,"cpu_pct":14.0,"rss_mb":11,"process_count":2,
                                 "thread_count":6,"read_bytes":300,"write_bytes":0}]}
        r=analyze_snapshot(snap)
        self.assertEqual(r["timeline"][0]["rss_bytes"],10*1048576)
        self.assertEqual(r["timeline"][1]["read_bps"],300)
        self.assertEqual(r["timeline"][1]["children_count"],1)

    def test_wrong_snapshot_rejected(self):
        with self.assertRaises(InvestigationError):
            analyze_snapshot({"schema_version":1,"product":"Fake","recent_samples":[]})

    def test_html_does_not_require_network_or_gui(self):
        result=analyze([sample(0)])
        rendered=to_html(result)
        self.assertNotIn("http://",rendered)
        self.assertNotIn("https://",rendered)
        self.assertNotIn("<script",rendered)

    def test_source_repo_files_untouched_by_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=fixture_session(Path(tmp)/"session")
            before=sorted(str(p.relative_to(folder)) for p in folder.rglob("*"))
            analyze_session(folder)
            after=sorted(str(p.relative_to(folder)) for p in folder.rglob("*"))
            self.assertEqual(before,after)


if __name__ == "__main__":
    unittest.main()
