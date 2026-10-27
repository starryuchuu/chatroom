"""Tag validation, version synchronization, atomic publication and CI selection."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import ci_plan
import release as release_command
import release_assets
import release_plan
import versioning

PUBLIC_NAME = 'starryuchuu'
PUBLIC_EMAIL = '115001462+starryuchuu@users.noreply.github.com'


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'repo'
        self.root.mkdir()
        self.remote = Path(self.temp.name) / 'origin.git'
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_AUTHOR_NAME=PUBLIC_NAME, GIT_COMMITTER_NAME=PUBLIC_NAME,
                        GIT_AUTHOR_EMAIL=PUBLIC_EMAIL, GIT_COMMITTER_EMAIL=PUBLIC_EMAIL)
        for variable in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE'):
            self.env.pop(variable, None)
        self.git('init', '-q', '-b', 'master')
        self.git('config', 'user.name', PUBLIC_NAME)
        self.git('config', 'user.email', PUBLIC_EMAIL)
        self.write_versions('v1.0.0')
        (self.root / 'scripts').mkdir()
        for name in ('release.py', 'versioning.py', 'check_release_privacy.py', 'release_privacy_assets.py'):
            shutil.copyfile(SCRIPTS / name, self.root / 'scripts' / name)
        (self.root / 'chatroom_client').mkdir()
        (self.root / 'chatroom_client/OPAQUE_THIRD_PARTY_LICENSES.txt').write_text('Synthetic license notice')
        self.first = self.commit()
        subprocess.run(['git', 'init', '-q', '--bare', str(self.remote)], check=True, env=self.env)
        self.git('remote', 'add', 'origin', str(self.remote))
        self.git('push', '-q', '-u', 'origin', 'master')

    def git(self, *args, check=True):
        result = subprocess.run(['git', '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false', *args],
                                cwd=self.root, env=self.env, capture_output=True, text=True, timeout=20)
        if check and result.returncode:
            self.fail('Fixture git command failed: ' + args[0])
        return result

    def write_versions(self, version):
        (self.root / 'go-server').mkdir(exist_ok=True)
        (self.root / 'desktop').mkdir(exist_ok=True)
        (self.root / 'VERSION').write_text(version + '\n')
        (self.root / 'go-server/VERSION').write_text(version + '\n')
        package = {'name': 'synthetic-chatroom', 'version': version[1:]}
        (self.root / 'desktop/package.json').write_text(json.dumps(package))
        (self.root / 'desktop/package-lock.json').write_text(json.dumps({
            'name': package['name'], 'version': version[1:], 'packages': {'': package}}))

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-q', '-m', 'Synthetic fixture')
        return self.git('rev-parse', 'HEAD').stdout.strip()

    def tag(self, version='v1.0.0', ref='HEAD'):
        self.git('tag', '-a', version, ref, '-m', 'Synthetic tag')

    def helper(self, version='1.1.0', *extra):
        return subprocess.run([sys.executable, str(self.root / 'scripts/release.py'), version, *extra],
                              cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30)

    def plan(self, event='push', ref='refs/tags/v1.0.0', dispatch=''):
        return release_plan.validate(self.root, event, ref, dispatch)


class TagPlanTests(RepositoryTests):
    def test_tag_and_manual_retry_resolve_exact_same_commit(self):
        self.tag()
        self.assertEqual(self.plan(), ('v1.0.0', self.first))
        self.assertEqual(self.plan('workflow_dispatch', 'refs/heads/master', 'v1.0.0'), ('v1.0.0', self.first))

    def test_branch_push_and_pull_request_never_publish(self):
        for event, ref in (('push', 'refs/heads/master'), ('pull_request', 'refs/pull/1/merge')):
            with self.subTest(event=event), self.assertRaises(ValueError):
                self.plan(event, ref)

    def test_invalid_tags_and_all_version_copy_mismatches_fail(self):
        self.tag()
        for tag in ('1.0.0', 'v01.0.0', 'v1.0.0-extra', 'v１.０.０'):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                self.plan('push', 'refs/tags/' + tag)
        for name in versioning.VERSION_FILES:
            path = self.root / name
            original = path.read_bytes()
            if name.endswith('.json'):
                value = json.loads(original)
                value['version'] = '0.9.0'
                path.write_text(json.dumps(value))
            else:
                path.write_text('v0.9.0\n')
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.plan()
            path.write_bytes(original)
        path = self.root / 'desktop/package-lock.json'
        value = json.loads(path.read_text())
        value['packages']['']['version'] = '0.9.0'
        path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            self.plan()

    def test_checked_out_head_must_match_tag_even_when_both_on_master(self):
        self.tag()
        (self.root / 'notes.md').write_text('Later commit')
        self.commit()
        with self.assertRaisesRegex(ValueError, 'checkout'):
            self.plan()

    def test_tag_off_master_and_missing_tag_cannot_publish(self):
        self.git('checkout', '-q', '-b', 'feature')
        (self.root / 'notes.md').write_text('Unmerged work')
        self.commit()
        self.tag()
        with self.assertRaises(subprocess.CalledProcessError):
            self.plan()
        self.write_versions('v1.0.1')
        with self.assertRaises(subprocess.CalledProcessError):
            self.plan('workflow_dispatch', '', 'v1.0.1')

    def test_retry_old_version_does_not_replace_newer_latest_release(self):
        self.tag()
        self.write_versions('v1.1.0')
        self.commit()
        self.git('push', '-q', 'origin', 'master')
        self.git('checkout', '-q', 'v1.0.0')
        with self.assertRaisesRegex(ValueError, 'no longer'):
            self.plan('workflow_dispatch', '', 'v1.0.0')

    def test_cli_exports_validated_tag_and_commit(self):
        self.tag()
        output = self.root / 'actions-output'
        result = subprocess.run([sys.executable, str(SCRIPTS / 'release_plan.py')], cwd=self.root,
            env=dict(self.env, GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REF='refs/heads/master',
                     DISPATCH_TAG='v1.0.0', GITHUB_OUTPUT=str(output)), capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(), 'tag=v1.0.0\ncommit=' + self.first + '\n')


class ReleaseCommandTests(RepositoryTests):
    def test_dry_run_makes_no_files_commits_tags_or_remote_calls(self):
        before = {name: (self.root / name).read_bytes() for name in versioning.VERSION_FILES}
        result = self.helper('1.1.0', '--dry-run')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git('status', '--porcelain').stdout, '')
        self.assertEqual(self.git('rev-parse', 'HEAD').stdout.strip(), self.first)
        self.assertEqual(self.git('tag').stdout, '')
        self.assertEqual(before, {name: (self.root / name).read_bytes() for name in versioning.VERSION_FILES})
        self.git('remote', 'set-url', 'origin', 'unavailable-synthetic-remote')
        self.assertEqual(self.helper('1.1.0', '--dry-run').returncode, 0)

    def test_release_synchronizes_every_copy_and_pushes_branch_and_tag(self):
        result = self.helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(versioning.read_version(self.root), 'v1.1.0')
        self.assertEqual(self.git('status', '--porcelain').stdout, '')
        head = self.git('rev-parse', 'HEAD').stdout.strip()
        self.assertNotEqual(head, self.first)
        for ref in ('refs/heads/master', 'refs/tags/v1.1.0^{}'):
            remote = subprocess.check_output(['git', '--git-dir=' + str(self.remote), 'rev-parse', ref], env=self.env, text=True).strip()
            self.assertEqual(remote, head)
        self.assertEqual(self.git('log', '-1', '--format=%an <%ae>').stdout.strip(), PUBLIC_NAME + ' <' + PUBLIC_EMAIL + '>')

    def test_dirty_wrong_branch_repeated_and_older_versions_fail_before_changes(self):
        self.assertNotEqual(self.helper('1.0.0').returncode, 0)
        self.assertNotEqual(self.helper('0.9.0').returncode, 0)
        (self.root / 'uncommitted.md').write_text('Keep this work')
        self.assertNotEqual(self.helper().returncode, 0)
        self.assertEqual(versioning.read_version(self.root), 'v1.0.0')
        (self.root / 'uncommitted.md').unlink()
        self.git('checkout', '-q', '-b', 'feature')
        self.assertNotEqual(self.helper().returncode, 0)
        self.assertEqual(self.git('rev-parse', 'HEAD').stdout.strip(), self.first)

    def test_existing_remote_tag_fails_without_changing_versions(self):
        self.tag('v1.1.0')
        self.git('push', '-q', 'origin', 'v1.1.0')
        self.git('tag', '-d', 'v1.1.0')
        result = self.helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(versioning.read_version(self.root), 'v1.0.0')

    def test_atomic_tag_rejection_does_not_partially_push_master(self):
        if os.name == 'nt':
            self.skipTest('POSIX receive-hook fixture')
        hook = self.remote / 'hooks/update'
        hook.write_text('#!/bin/sh\ncase "$1" in refs/tags/*) exit 1;; esac\nexit 0\n')
        hook.chmod(0o755)
        result = self.helper()
        self.assertNotEqual(result.returncode, 0)
        remote_head = subprocess.check_output(['git', '--git-dir=' + str(self.remote), 'rev-parse', 'master'], env=self.env, text=True).strip()
        self.assertEqual(remote_head, self.first)
        self.assertEqual(versioning.read_version(self.root), 'v1.1.0', 'Prepared local release must remain reviewable')

    def test_diverged_master_fails_before_preparing_version_files(self):
        self.git('update-ref', 'refs/remotes/origin/master', self.first)
        self.git('checkout', '-q', '--orphan', 'diverged')
        self.git('commit', '-q', '-m', 'Diverged tree')
        self.git('branch', '-M', 'master')
        result = self.helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(versioning.read_version(self.root), 'v1.0.0')


class AssetTests(RepositoryTests):
    def make_assets(self):
        assets = Path(self.temp.name) / 'assets'
        assets.mkdir()
        for name in release_assets.BINARIES:
            (assets / name).write_bytes(('Synthetic ' + name).encode())
        return assets

    def test_single_source_archive_and_every_file_has_valid_checksum(self):
        assets = self.make_assets()
        self.assertEqual(release_assets.prepare(self.root, assets), 'v1.0.0')
        source = assets / 'chatroom-v1.0.0-source.zip'
        with zipfile.ZipFile(source) as archive:
            self.assertIn('chatroom-v1.0.0/VERSION', archive.namelist())
            self.assertIn('chatroom-v1.0.0/desktop/package.json', archive.namelist())
        for line in (assets / 'SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(digest, hashlib.sha256((assets / name).read_bytes()).hexdigest())
        self.assertEqual(len(list(assets.glob('*source.zip'))), 1)
        self.assertFalse(list(assets.glob('*client.zip')))

    def test_missing_or_unexpected_attachment_blocks_release(self):
        assets = self.make_assets()
        missing = assets / release_assets.BINARIES[0]
        missing.unlink()
        with self.assertRaisesRegex(ValueError, 'Missing'):
            release_assets.prepare(self.root, assets)
        missing.write_text('Synthetic')
        (assets / 'unexpected.txt').write_text('Unexpected')
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            release_assets.prepare(self.root, assets)

    def test_real_upload_directory_layout_is_flattened_without_changing_binaries(self):
        assets = self.make_assets()
        original = {path.name: path.read_bytes() for path in assets.iterdir()}
        desktop = assets / 'desktop' / 'release'
        desktop.mkdir(parents=True)
        servers = assets / 'dist'
        servers.mkdir()
        for name in release_assets.BINARIES[:4]:
            (assets / name).replace((desktop if name.endswith('.zip') else servers) / name)
        self.assertEqual(release_assets.prepare(self.root, assets), 'v1.0.0')
        self.assertTrue(all(path.is_file() for path in assets.iterdir()))
        for name, content in original.items():
            self.assertEqual((assets / name).read_bytes(), content)
        self.assertEqual(len(list(assets.iterdir())), len(release_assets.BINARIES) + 3)

    def test_duplicate_and_unknown_nested_files_fail_before_moving_anything(self):
        assets = self.make_assets()
        nested = assets / 'desktop' / 'release'
        nested.mkdir(parents=True)
        name = release_assets.BINARIES[0]
        shutil.copyfile(assets / name, nested / name)
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            release_assets.prepare(self.root, assets)
        self.assertTrue((assets / name).exists())
        self.assertTrue((nested / name).exists())
        (assets / name).unlink()
        (nested / 'unexpected.txt').write_text('Synthetic')
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            release_assets.prepare(self.root, assets)
        self.assertFalse((assets / name).exists())
        self.assertTrue((nested / name).exists())


class DailyPlanTests(RepositoryTests):
    def test_components_are_selected_conservatively(self):
        cases = [
            (['README.md', 'docs/images/demo.png'], set()),
            (['desktop/src/styles.css'], {'desktop'}),
            (['server.py'], {'python'}),
            (['chatroom_client/rpc.py'], {'python', 'desktop'}),
            (['go-server/internal/server/server.go'], {'python', 'go'}),
            (['opaque-core/src/lib.rs'], set(ci_plan.COMPONENTS)),
            (['.github/workflows/ci.yml'], set(ci_plan.COMPONENTS)),
            (['unknown.data'], set(ci_plan.COMPONENTS)),
        ]
        for paths, expected in cases:
            with self.subTest(paths=paths):
                result = ci_plan.affected(paths)
                self.assertEqual({name for name, enabled in result.items() if enabled}, expected)

    def test_real_push_diff_and_missing_base_fall_back_to_full_checks(self):
        path = self.root / 'desktop/src'
        path.mkdir()
        (path / 'style.css').write_text('body {}')
        head = self.commit()
        with patch('ci_plan.git', side_effect=lambda *args: self.git(*args).stdout):
            self.assertEqual(ci_plan.changed_paths('push', {'before': self.first, 'after': head}), ['desktop/src/style.css'])
            self.assertEqual(ci_plan.changed_paths('push', {'before': head, 'after': head}), [])
        self.assertIsNone(ci_plan.changed_paths('push', {'before': '0' * 40, 'after': head}))
        with patch('ci_plan.git', side_effect=subprocess.CalledProcessError(1, 'git')):
            self.assertIsNone(ci_plan.changed_paths('push', {'before': 'missing', 'after': head}))

    def test_duplicate_push_only_skips_when_an_active_target_pr_has_the_same_sha(self):
        with patch.dict(os.environ, {'GH_TOKEN': 'synthetic-test-value'}):
            response = subprocess.CompletedProcess([], 0, json.dumps([{'headRefOid': 'abc', 'baseRefName': 'master'}]), '')
            with patch('ci_plan.subprocess.run', return_value=response):
                self.assertTrue(ci_plan.covered_by_pr('push', 'feature', 'abc'))
                self.assertFalse(ci_plan.covered_by_pr('push', 'feature', 'different'))
                self.assertFalse(ci_plan.covered_by_pr('pull_request', 'feature', 'abc'))
            with patch('ci_plan.subprocess.run', side_effect=OSError('API unavailable')):
                self.assertFalse(ci_plan.covered_by_pr('push', 'feature', 'abc'))

    def test_pr_diff_uses_merge_base_and_excludes_unrelated_base_branch_work(self):
        self.git('checkout', '-q', '-b', 'feature')
        (self.root / 'desktop/style.css').write_text('body {}')
        head = self.commit()
        self.git('checkout', '-q', 'master')
        (self.root / 'server.py').write_text('# unrelated base change')
        base = self.commit()
        payload = {'pull_request': {'base': {'sha': base}, 'head': {'sha': head}}}
        with patch('ci_plan.git', side_effect=lambda *args: self.git(*args).stdout):
            self.assertEqual(ci_plan.changed_paths('pull_request', payload), ['desktop/style.css'])

    def test_daily_cli_exports_only_desktop_for_css_changes(self):
        (self.root / 'desktop/style.css').write_text('body {}')
        head = self.commit()
        event = Path(self.temp.name) / 'event.json'
        event.write_text(json.dumps({'before': self.first, 'after': head}))
        output = Path(self.temp.name) / 'actions-output'
        result = subprocess.run([sys.executable, str(SCRIPTS / 'ci_plan.py')], cwd=self.root,
            env=dict(self.env, GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/feature', GITHUB_REF_NAME='feature',
                     GITHUB_SHA=head, GITHUB_EVENT_PATH=str(event), GITHUB_OUTPUT=str(output), GH_TOKEN=''),
            capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(), 'python=false\ngo=false\ndesktop=true\nopaque=false\n')

    def test_only_exact_tagged_master_push_delegates_to_release_workflow(self):
        self.tag()
        with patch('ci_plan.git', side_effect=lambda *args: self.git(*args).stdout):
            self.assertTrue(ci_plan.tagged_release_push('push', 'refs/heads/master', 'v1.0.0'))
            self.assertFalse(ci_plan.tagged_release_push('pull_request', 'refs/pull/1/merge', 'v1.0.0'))
            (self.root / 'notes.md').write_text('Ordinary change after tag')
            self.commit()
            self.assertFalse(ci_plan.tagged_release_push('push', 'refs/heads/master', 'v1.0.0'))
