"""Saved-evidence fixtures reject false endurance PASS; run by Actions only."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from tools.qa_deep_endurance import ObserverProgressWatchdog, verify_samples
from tools.qa_github_endurance import _evidence, verify_sampling_coverage


class DeepEnduranceCoverageContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def deep_database(self, elapsed):
        path = self.root / "format-fixture-only.sqlite3"
        with closing(sqlite3.connect(path)) as db:
            db.execute("CREATE TABLE samples(seq INTEGER,elapsed REAL,heartbeat INTEGER,io_cycles INTEGER,"
                       "network_cycles INTEGER,qa_rss INTEGER,target_rss INTEGER,helper_pid INTEGER,helper_rss INTEGER)")
            db.executemany("INSERT INTO samples VALUES(?,?,?,?,?,?,?,?,?)",
                           [(i + 1, stamp, i + 1, i + 1, i + 1, 10, 20, 90, 30)
                            for i, stamp in enumerate(elapsed)])
            db.commit()
        return path

    def test_two_observations_five_and_half_hours_apart_do_not_prove_continuity(self):
        with self.assertRaisesRegex(RuntimeError, "PERSISTED_SAMPLE_GAP"):
            verify_samples(self.deep_database([0, 19800]), 19800)

    def test_many_coarse_observations_still_require_minimum_sample_density(self):
        with self.assertRaisesRegex(RuntimeError, "COVERAGE_TOO_LOW"):
            verify_samples(self.deep_database(range(0, 601, 30)), 600)

    def test_monotonic_span_cannot_hide_time_reversal_between_samples(self):
        with self.assertRaisesRegex(RuntimeError, "PERSISTED_SAMPLE_GAP"):
            verify_samples(self.deep_database([0, 5, 4, 10, 15, 20, 25, 30]), 30)

    def test_regular_saved_samples_pass_with_reported_actual_coverage(self):
        result = verify_samples(self.deep_database(range(0, 91, 5)), 90)
        self.assertEqual(result["sampling_coverage"]["max_sample_gap_seconds"], 5)
        self.assertEqual(result["sampling_coverage"]["persisted_samples"], 19)
        self.assertEqual(result["sampling_coverage"]["boundary_tolerance_seconds"], 0)

    def observer_fixture(self, times_ns):
        session = self.root / "run/sessions/owned-format-fixture"
        session.mkdir(parents=True)
        result = {"state": "COMPLETED", "source": {"actual_source_sha": "a" * 40,
                  "source_identity_status": "VERIFIED_EXPECTED_HEAD"}, "phases": [{"phase": "STANDARD",
                  "actual_seconds": 19800, "recording_state": "COMPLETED", "session": str(session),
                  "recorded_samples": len(times_ns)}], "cleanup": {"status": "COMPLETED", "helper_alive": False,
                  "window_visible": False, "running_qthreads": 0}}
        (self.root / "run/result.json").write_text(json.dumps(result), encoding="utf-8")
        with closing(sqlite3.connect(session / "session.sqlite3")) as db:
            db.executescript("CREATE TABLE metadata(schema_version INTEGER,pid INTEGER,exit_code TEXT);"
                             "INSERT INTO metadata VALUES(1,123,'COMPLETED');CREATE TABLE samples(seq INTEGER);")
            db.executemany("INSERT INTO samples VALUES(?)", [(i + 1,) for i in range(len(times_ns))])
            db.commit()
        with closing(sqlite3.connect(session / "session-v2.sqlite3")) as db:
            db.executescript("CREATE TABLE sessions(status TEXT,exit_code TEXT,writer_dropped_commands INTEGER);"
                "INSERT INTO sessions VALUES('CLOSED','COMPLETED',0);"
                "CREATE TABLE targets(root_pid INTEGER);INSERT INTO targets VALUES(123);"
                "CREATE TABLE sensor_errors(sensor_id TEXT);"
                "CREATE TABLE samples(series_seq INTEGER,instance_id INTEGER,correlation_key TEXT,"
                "series TEXT,monotonic_ns INTEGER);")
            db.executemany("INSERT INTO samples VALUES(?,1,?,'STANDARD',?)",
                           [(i + 1, "schema1:" + str(i + 1), stamp) for i, stamp in enumerate(times_ns)])
            db.commit()
        with closing(sqlite3.connect(session / "research.sqlite3")) as db:
            db.execute("CREATE TABLE context(key TEXT,data TEXT)")
            db.execute("INSERT INTO context VALUES('state',?)", (json.dumps("COMPLETED"),))
            db.execute("INSERT INTO context VALUES('capture_health',?)", (json.dumps(
                {'recording_resources_closed': True, 'finalization_errors': []}),))
            db.commit()
        return session

    def detailed_fixture(self, detail_times):
        session = self.observer_fixture([i * 1_000_000_000 for i in range(91)])
        result_path = self.root / 'run/result.json'
        result = json.loads(result_path.read_text(encoding='utf-8'))
        result['phases'][0]['phase'] = 'DETAILED'
        result_path.write_text(json.dumps(result), encoding='utf-8')
        with closing(sqlite3.connect(session / 'session-v2.sqlite3')) as db:
            db.executemany("INSERT INTO samples VALUES(?,1,?,'DETAILED',?)",
                           [(i+1, 'detail:'+str(i+1), stamp) for i, stamp in enumerate(detail_times)])
            db.commit()

    def test_detailed_label_with_only_base_rows_cannot_certify_detailed_endurance(self):
        self.detailed_fixture([])
        with self.assertRaisesRegex(RuntimeError, 'QA_DETAILED_PERSISTED_SPAN_TOO_SHORT'):
            _evidence(self.root, 'DETAILED', 90, 'a'*40)

    def test_completed_rows_cannot_hide_unconfirmed_gui_owner_or_callback_failure(self):
        self.observer_fixture([i * 1_000_000_000 for i in range(91)])
        result_path = self.root / 'run/result.json'
        original = json.loads(result_path.read_text(encoding='utf-8'))
        for key, value, reason in (('cleanup', {'status': 'RECOVERY_UNCONFIRMED', 'helper_alive': True},
                                    'QA_GUI_OWNER_CLEANUP_NOT_CONFIRMED'),
                                   ('unhandled_python_failure', {'count': 1}, 'QA_UNHANDLED_CALLBACK_RECORDED')):
            result_path.write_text(json.dumps({**original, key: value}), encoding='utf-8')
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, reason):
                _evidence(self.root, 'STANDARD', 90, 'a'*40)

    def test_detailed_endpoints_do_not_hide_a_persisted_sampling_hole(self):
        self.detailed_fixture([0, 90_000_000_000])
        with self.assertRaisesRegex(RuntimeError, 'QA_DETAILED_PERSISTED_SAMPLE_GAP'):
            _evidence(self.root, 'DETAILED', 90, 'a'*40)

    def test_completed_states_cannot_hide_unconfirmed_recording_resource_finalization(self):
        session = self.observer_fixture([i * 1_000_000_000 for i in range(91)])
        for health in (None, {}, {'recording_resources_closed': False, 'finalization_errors': []},
                       {'recording_resources_closed': 1, 'finalization_errors': []},
                       {'recording_resources_closed': True, 'finalization_errors': ['WPR_STOP_UNCONFIRMED']}):
            with closing(sqlite3.connect(session / 'research.sqlite3')) as db:
                db.execute("UPDATE context SET data=? WHERE key='capture_health'", (json.dumps(health),))
                db.commit()
            with self.subTest(health=health), self.assertRaisesRegex(RuntimeError, 'QA_RECORDING_RESOURCE_FINALIZATION_NOT_CONFIRMED'):
                _evidence(self.root, 'STANDARD', 90, 'a'*40)

    def test_nonfinite_wall_clock_duration_cannot_certify_recording(self):
        self.observer_fixture([i * 1_000_000_000 for i in range(91)])
        path = self.root / 'run/result.json'
        result = json.loads(path.read_text(encoding='utf-8'))
        for duration in (float('nan'), float('inf')):
            result['phases'][0]['actual_seconds'] = duration
            path.write_text(json.dumps(result), encoding='utf-8')
            with self.subTest(duration=duration), self.assertRaisesRegex(RuntimeError, 'QA_FULL_REQUESTED_DURATION_NOT_MET'):
                _evidence(self.root, 'STANDARD', 90, 'a'*40)

    def test_detailed_span_and_allowed_gaps_still_require_sample_density(self):
        self.detailed_fixture([0, 30_000_000_000, 60_000_000_000, 90_000_000_000])
        with self.assertRaisesRegex(RuntimeError, 'QA_DETAILED_PERSISTED_SAMPLE_COVERAGE_TOO_LOW'):
            _evidence(self.root, 'DETAILED', 90, 'a'*40)

    def test_completed_long_wall_clock_cannot_certify_short_saved_recording(self):
        self.observer_fixture([i * 2_000_000_000 for i in range(5)])
        with self.assertRaisesRegex(RuntimeError, "PERSISTED_SPAN_TOO_SHORT"):
            _evidence(self.root, "STANDARD", 19800, "a" * 40)

    def test_complete_v1_v2_parity_does_not_hide_a_multi_hour_sampling_hole(self):
        self.observer_fixture([0, 9900_000_000_000, 19800_000_000_000])
        with self.assertRaisesRegex(RuntimeError, "PERSISTED_SAMPLE_GAP"):
            _evidence(self.root, "STANDARD", 19800, "a" * 40)

    def test_observer_tolerance_is_explicit_and_allows_supported_adaptive_five_seconds(self):
        result = verify_sampling_coverage(count=3959, span_seconds=19790, max_gap_seconds=5,
            nonpositive_gaps=0, requested_seconds=19800, boundary_tolerance_seconds=10,
            maximum_gap_seconds=30, minimum_count_interval_seconds=10, label="QA_OBSERVER")
        self.assertEqual(result["boundary_tolerance_seconds"], 10)
        self.assertEqual(result["minimum_required_samples"], 1980)

    def test_rewritten_heartbeat_without_new_recorded_samples_times_out(self):
        path = self.root / "progress.json"
        watch = ObserverProgressWatchdog(0)
        path.write_text(json.dumps({"recorded_samples": 1, "actual_phase_seconds": 1}))
        watch.check(path, now=1)
        path.write_text(json.dumps({"recorded_samples": 1, "actual_phase_seconds": 182}))
        with self.assertRaisesRegex(AssertionError, "SAMPLES_NOT_PROGRESSING"):
            watch.check(path, now=182)

    def test_missing_or_zero_sample_progress_does_not_extend_startup_forever(self):
        path = self.root / "progress.json"
        watch = ObserverProgressWatchdog(0)
        watch.check(path, now=100)
        path.write_text(json.dumps({"recorded_samples": 0}))
        with self.assertRaisesRegex(AssertionError, "SAMPLES_NOT_PROGRESSING"):
            watch.check(path, now=181)

    def test_real_sample_progress_extends_watchdog_but_count_regression_fails(self):
        path = self.root / "progress.json"
        watch = ObserverProgressWatchdog(0)
        path.write_text(json.dumps({"recorded_samples": 1}))
        watch.check(path, now=179)
        path.write_text(json.dumps({"recorded_samples": 2}))
        watch.check(path, now=358)
        path.write_text(json.dumps({"recorded_samples": 1}))
        with self.assertRaisesRegex(AssertionError, "COUNT_REGRESSED"):
            watch.check(path, now=359)


if __name__ == "__main__":
    unittest.main()
