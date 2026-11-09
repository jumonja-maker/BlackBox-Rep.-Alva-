"""Saved metadata cannot admit long work after missing or mismatched full CI."""
from copy import deepcopy
import unittest

from tools.qa_program_endurance import REQUIRED_SHORT_JOBS, validate_upstream, validate_verdict

SHA = 'a' * 40
REPOSITORY = 'owner/source-fixture'


def upstream():
    run = {'id': 123, 'run_attempt': 1, 'head_sha': SHA, 'status': 'completed', 'conclusion': 'success',
           'path': '.github/workflows/shell-qa.yml',
           'name': 'BLACK.BOX Universal - independent Windows build and release',
           'head_repository': {'full_name': REPOSITORY}}
    jobs = [{'id': index+1, 'run_id': 123, 'head_sha': SHA, 'name': name,
             'status': 'completed', 'conclusion': 'success'}
            for index, name in enumerate(sorted(REQUIRED_SHORT_JOBS))]
    return run, jobs


def verdict(profile='STANDARD', requested=19800):
    coverage = {'requested_seconds': requested, 'persisted_span_seconds': requested,
                'persisted_samples': requested // 2 + 1, 'max_sample_gap_seconds': 2,
                'nonincreasing_timestamps': 0}
    return {'result': 'PASS', 'profile': profile, 'requested_seconds': requested, 'actual_seconds': requested,
            'source': {'actual_source_sha': SHA, 'source_identity_status': 'VERIFIED_EXPECTED_HEAD'},
            'primary_exit_code': 'COMPLETED', 'research_state': 'COMPLETED', 'normalized_status': 'CLOSED',
            'schema2_writer_errors': 0, 'invalid_source_links': 0, 'persisted_recording_coverage': coverage,
            'gui_cleanup': {'status': 'COMPLETED', 'helper_alive': False, 'window_visible': False, 'running_qthreads': 0},
            'recording_capture_health': {'recording_resources_closed': True, 'finalization_errors': []},
            'detailed_recording_coverage': dict(coverage) if profile == 'DETAILED' else None,
            'source_hashes_sha256': {name: 'b' * 64 for name in
                                    ('session.sqlite3', 'session-v2.sqlite3', 'research.sqlite3')}}


class ProgramEnduranceAdmissionTests(unittest.TestCase):
    def test_every_actual_short_gate_on_the_exact_source_is_required(self):
        run, jobs = upstream()
        proof = validate_upstream(run, jobs, expected_sha=SHA, run_id=123, repository=REPOSITORY)
        self.assertEqual(set(proof['successful_jobs']), REQUIRED_SHORT_JOBS)
        self.assertFalse(proof['published_release'])
        for missing in REQUIRED_SHORT_JOBS:
            with self.subTest(missing=missing), self.assertRaises(AssertionError):
                validate_upstream(run, [job for job in jobs if job['name'] != missing],
                                  expected_sha=SHA, run_id=123, repository=REPOSITORY)

    def test_cancelled_skipped_foreign_and_wrong_source_are_not_admitted(self):
        original, jobs = upstream()
        for key, value in (('head_sha', 'c'*40), ('status', 'in_progress'),
                           ('conclusion', 'cancelled'), ('path', '.github/workflows/other.yml'),
                           ('head_repository', {'full_name': 'foreign/repository'})):
            run = {**original, key: value}
            with self.subTest(key=key), self.assertRaises(AssertionError):
                validate_upstream(run, jobs, expected_sha=SHA, run_id=123, repository=REPOSITORY)
        for conclusion in ('skipped', 'cancelled', 'failure'):
            changed = deepcopy(jobs); changed[0]['conclusion'] = conclusion
            with self.subTest(conclusion=conclusion), self.assertRaises(AssertionError):
                validate_upstream(original, changed, expected_sha=SHA, run_id=123, repository=REPOSITORY)

    def test_duplicate_job_name_cannot_hide_another_required_run(self):
        run, jobs = upstream()
        with self.assertRaisesRegex(AssertionError, 'DUPLICATE_SHORT_JOB'):
            validate_upstream(run, jobs + [jobs[0]], expected_sha=SHA, run_id=123, repository=REPOSITORY)


class ProgramEnduranceVerdictTests(unittest.TestCase):
    def test_fixed_full_profiles_and_explicit_short_preflights_are_distinct(self):
        for profile, seconds in (('STANDARD', 19800), ('DETAILED', 3600), ('STANDARD', 90), ('DETAILED', 90)):
            with self.subTest(profile=profile, seconds=seconds):
                value = verdict(profile, seconds)
                self.assertIs(validate_verdict(value, expected_sha=SHA, profile=profile, requested=seconds), value)

    def test_short_base_only_or_nonfinite_evidence_cannot_certify_detailed_hour(self):
        original = verdict('DETAILED', 3600)
        for key, value in (('actual_seconds', 90), ('actual_seconds', float('inf')),
                           ('detailed_recording_coverage', None), ('research_state', 'INCOMPLETE'),
                           ('recording_capture_health', {}),
                           ('recording_capture_health', {'recording_resources_closed': False, 'finalization_errors': []}),
                           ('gui_cleanup', {'status': 'RECOVERY_UNCONFIRMED', 'helper_alive': True})):
            changed = {**original, key: value}
            with self.subTest(key=key), self.assertRaises(AssertionError):
                validate_verdict(changed, expected_sha=SHA, profile='DETAILED', requested=3600)
        for key, value in (('persisted_samples', 2), ('persisted_span_seconds', 90),
                           ('persisted_span_seconds', float('inf')), ('max_sample_gap_seconds', 90)):
            changed = deepcopy(original); changed['detailed_recording_coverage'][key] = value
            with self.subTest(coverage=key), self.assertRaises(AssertionError):
                validate_verdict(changed, expected_sha=SHA, profile='DETAILED', requested=3600)


if __name__ == '__main__':
    unittest.main()
