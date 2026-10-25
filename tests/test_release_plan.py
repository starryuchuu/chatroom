"""Only a version push or explicit dispatch on master can publish artifacts."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


spec = importlib.util.spec_from_file_location('release_plan', Path(__file__).resolve().parents[1] / 'scripts/release_plan.py')
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


class ReleasePlanTests(unittest.TestCase):
    def test_version_changes_publish_only_on_master_push(self):
        for event in ('push', 'pull_request', 'workflow_dispatch'):
            for ref in ('refs/heads/master', 'refs/heads/test', 'refs/pull/10/merge'):
                with self.subTest(event=event, ref=ref):
                    self.assertEqual(plan.should_publish(event, ref, ['VERSION']),
                                     event == 'push' and ref == 'refs/heads/master')

    def test_regular_changes_do_not_publish_and_dispatch_is_explicit(self):
        self.assertFalse(plan.should_publish('push', 'refs/heads/master', ['server.py']))
        self.assertFalse(plan.should_publish('workflow_dispatch', 'refs/heads/master', []))
        self.assertTrue(plan.should_publish('workflow_dispatch', 'refs/heads/master', [], True))
        self.assertFalse(plan.should_publish('pull_request', 'refs/heads/master', ['VERSION'], True))
        self.assertFalse(plan.should_publish('workflow_dispatch', 'refs/heads/test', [], True))


class ReleasePlanCLITests(unittest.TestCase):
    """Exercise actual version files, Git history and Actions output files."""
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_AUTHOR_NAME='starryuchuu', GIT_COMMITTER_NAME='starryuchuu',
                        GIT_AUTHOR_EMAIL='115001462+starryuchuu@users.noreply.github.com',
                        GIT_COMMITTER_EMAIL='115001462+starryuchuu@users.noreply.github.com')
        self.git('init', '--quiet')
        self.write_versions('v1.0.0')
        self.before = self.commit()
        self.output = self.root / 'actions-output'

    def git(self, *args):
        result = subprocess.run(['git', '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=' + os.devnull,
                                 *args], cwd=self.root, env=self.env, capture_output=True,
                                text=True, timeout=10, check=True)
        return result.stdout.strip()

    def write_versions(self, version, go_version=None):
        (self.root / 'go-server').mkdir(exist_ok=True)
        (self.root / 'VERSION').write_text(version + '\n', encoding='utf-8')
        (self.root / 'go-server/VERSION').write_text((go_version or version) + '\n', encoding='utf-8')

    def commit(self):
        self.git('add', 'VERSION', 'go-server/VERSION')
        if (self.root / 'notes.txt').exists():
            self.git('add', 'notes.txt')
        self.git('commit', '--quiet', '-m', 'Synthetic release plan fixture')
        return self.git('rev-parse', 'HEAD')

    def run_plan(self, *, event='push', ref='refs/heads/master', before=None, publish=False):
        self.output.unlink(missing_ok=True)
        env = dict(self.env, EVENT_NAME=event, GIT_REF=ref,
                   BEFORE_SHA=self.before if before is None else before,
                   PUBLISH_REQUESTED=str(publish).lower(), GITHUB_OUTPUT=str(self.output))
        return subprocess.run([sys.executable, str(Path(plan.__file__).resolve())],
                              cwd=self.root, env=env, capture_output=True, text=True, timeout=10)

    def assert_plan(self, result, expected):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text(), 'release=' + str(expected).lower() + '\n')

    def test_real_version_commit_publishes_but_ordinary_commit_does_not(self):
        (self.root / 'notes.txt').write_text('Synthetic documentation update')
        self.commit()
        self.assert_plan(self.run_plan(), False)
        self.write_versions('v1.0.1')
        self.commit()
        self.assert_plan(self.run_plan(), True)

    def test_first_push_with_zero_before_sha_is_supported(self):
        self.assert_plan(self.run_plan(before='0' * 40), True)
        self.assert_plan(self.run_plan(before='0' * 40, ref='refs/heads/test'), False)

    def test_pr_cannot_publish_or_query_a_before_ref_even_when_requested(self):
        self.assert_plan(self.run_plan(event='pull_request', before='missing-ref', publish=True), False)

    def test_manual_dispatch_needs_master_and_explicit_publication(self):
        self.assert_plan(self.run_plan(event='workflow_dispatch'), False)
        self.assert_plan(self.run_plan(event='workflow_dispatch', publish=True), True)
        self.assert_plan(self.run_plan(event='workflow_dispatch', ref='refs/heads/test', publish=True), False)

    def test_mismatched_versions_fail_before_creating_actions_output(self):
        self.write_versions('v1.0.1', 'v1.0.0')
        result = self.run_plan(event='workflow_dispatch', publish=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())

    def test_invalid_versions_fail_closed(self):
        for version in ('1.0.0', 'v1.0.0-extra', 'v1.0.0\ninvalid', 'v１.０.０', 'v١.٠.٠'):
            with self.subTest(version=version):
                self.write_versions(version)
                self.assertNotEqual(self.run_plan().returncode, 0)
                self.assertFalse(self.output.exists())

    def test_unavailable_push_base_fails_before_creating_actions_output(self):
        result = self.run_plan(before='missing-ref')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())
