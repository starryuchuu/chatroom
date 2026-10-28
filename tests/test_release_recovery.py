"""Recovery can reuse only the exact fully tested tag and complete build set."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from recover_release import REQUIRED_JOBS, validate_evidence


class RecoveryEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.commit = 'a' * 40
        self.run = {'head_sha': self.commit, 'head_branch': 'v2.0.2',
                    'path': '.github/workflows/release.yml', 'event': 'push',
                    'status': 'completed', 'conclusion': 'failure'}
        self.jobs = [{'name': name, 'status': 'completed', 'conclusion': 'success'}
                     for name in sorted(REQUIRED_JOBS)]
        self.jobs.append({'name': 'publish', 'status': 'completed', 'conclusion': 'failure'})

    def test_completed_tag_with_all_tests_and_builds_can_retry_publication(self):
        validate_evidence(self.run, self.jobs, 'v2.0.2', self.commit)

    def test_wrong_commit_tag_workflow_event_or_unfinished_run_is_rejected(self):
        for key, value in [('head_sha', 'b' * 40), ('head_branch', 'v2.0.1'),
                           ('path', '.github/workflows/ci.yml'), ('event', 'pull_request'),
                           ('status', 'in_progress'), ('conclusion', 'success')]:
            run = dict(self.run, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_evidence(run, self.jobs, 'v2.0.2', self.commit)

    def test_missing_duplicate_failed_and_skipped_verification_is_rejected(self):
        cases = [self.jobs[:-2] + self.jobs[-1:], self.jobs + self.jobs[:1]]
        for conclusion in ('failure', 'skipped', 'cancelled'):
            jobs = deepcopy(self.jobs)
            jobs[0]['conclusion'] = conclusion
            cases.append(jobs)
        for jobs in cases:
            with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                validate_evidence(self.run, jobs, 'v2.0.2', self.commit)


if __name__ == '__main__':
    unittest.main()
