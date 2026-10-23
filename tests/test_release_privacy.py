"""Release privacy checks run only against temporary, synthetic repositories."""
import base64
from io import BytesIO
import json
import marshal
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib


SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
PUBLIC_NAME = 'starryuchuu'
PUBLIC_EMAIL = '115001462+starryuchuu@users.noreply.github.com'


def fake_private_key():
    # Construct recognizable synthetic material at runtime so this test source
    # cannot itself be mistaken for a checked-in key by the release gate.
    heading = '-----BEGIN ' + 'PRIVATE KEY-----'
    ending = '-----END ' + 'PRIVATE KEY-----'
    body = base64.b64encode(b'synthetic-key-material-' * 4).decode('ascii')
    return (heading + '\n' + body + '\n' + ending + '\n').encode('ascii')


def zipped(files, *, compression=zipfile.ZIP_DEFLATED):
    output = BytesIO()
    with zipfile.ZipFile(output, 'w', compression=compression) as archive:
        for filename, content in files.items():
            archive.writestr(filename, content)
    return output.getvalue()


def png(*metadata):
    def chunk(kind, content):
        return (struct.pack('!I', len(content)) + kind + content
                + struct.pack('!I', zlib.crc32(kind + content)))

    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('!2I5B', 1, 1, 8, 2, 0, 0, 0))
            + b''.join(chunk(kind, content) for kind, content in metadata)
            + chunk(b'IDAT', zlib.compress(b'\0\0\0\0'))
            + chunk(b'IEND', b''))


def pyz(contents):
    body = bytearray()
    toc = []
    for name, code in contents.items():
        packed = zlib.compress(marshal.dumps(code))
        toc.append((name, (0, 12 + len(body), len(packed))))
        body.extend(packed)
    return b'PYZ\0' + b'\0' * 4 + struct.pack('!I', 12 + len(body)) + body + marshal.dumps(toc)


def frozen(contents, prefix=b'\x7fELF' + b'\0' * 60):
    body, toc = bytearray(), bytearray()
    for name, (kind, content) in contents.items():
        packed = zlib.compress(content)
        encoded = name.encode('utf-8') + b'\0'
        size = ((18 + len(encoded) + 15) // 16) * 16
        toc.extend(struct.pack('!IIIIBc', size, len(body), len(packed), len(content), 1, kind))
        toc.extend(encoded.ljust(size - 18, b'\0'))
        body.extend(packed)
    cookie = struct.pack('!8sIIII64s', b'MEI\014\013\012\013\016',
                         len(body) + len(toc) + 88, len(body), len(toc), 311,
                         b'python-test-library')
    return prefix + body + toc + cookie


class ReleasePrivacyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / 'repository'
        self.root.mkdir()
        self.env = dict(os.environ)
        for variable in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE',
                         'PRIVACY_FORBIDDEN_VALUES_JSON'):
            self.env.pop(variable, None)
        self.env.update(
            GIT_AUTHOR_NAME=PUBLIC_NAME, GIT_AUTHOR_EMAIL=PUBLIC_EMAIL,
            GIT_COMMITTER_NAME=PUBLIC_NAME, GIT_COMMITTER_EMAIL=PUBLIC_EMAIL,
            GIT_CONFIG_NOSYSTEM='1',
        )
        # Isolate global configuration without reading or changing the user's
        # configuration. Every test identity is explicitly set above.
        self.env['GIT_CONFIG_GLOBAL'] = str(Path(self.directory.name) / 'absent-gitconfig')
        self.git('init', '-b', 'master')
        (self.root / 'scripts').mkdir()
        for name in ('check_release_privacy.py', 'release_privacy_assets.py'):
            shutil.copyfile(SCRIPTS / name, self.root / 'scripts' / name)
        (self.root / 'README.md').write_text('Synthetic release fixture.\n')
        self.commit('Initial synthetic release')

    def git(self, *args, env=None):
        return subprocess.check_output(
            ['git', '-c', 'commit.gpgSign=false', *args],
            cwd=self.root, env=self.env if env is None else env,
            stderr=subprocess.DEVNULL, text=True,
        ).strip()

    def commit(self, message, *, private_author=False, private_committer=False):
        env = dict(self.env)
        if private_author:
            env.update(GIT_AUTHOR_NAME='synthetic-ancestor',
                       GIT_AUTHOR_EMAIL='synthetic@example.invalid')
        if private_committer:
            env.update(GIT_COMMITTER_NAME='synthetic-committer',
                       GIT_COMMITTER_EMAIL='synthetic-committer@example.invalid')
        self.git('add', '.')
        self.git('commit', '--allow-empty', '-m', message, env=env)
        return self.git('rev-parse', 'HEAD')

    def run_gate(self, *args, env=None, root=None):
        root = self.root if root is None else root
        return subprocess.run(
            [sys.executable, str(root / 'scripts' / 'check_release_privacy.py'), *args],
            cwd=root, env=self.env if env is None else env,
            capture_output=True, text=True, timeout=30,
        )

    def assert_passes(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_rejected(self, result, *sensitive_values):
        self.assertNotEqual(result.returncode, 0, 'Privacy gate accepted unsafe fixture')
        output = result.stdout + result.stderr
        self.assertNotIn('Traceback', output)
        for value in sensitive_values:
            self.assertNotIn(value, output)

    def asset(self, name, data):
        path = self.root / 'artifacts' / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(data)
        return str(path)

    def test_clean_repository_passes(self):
        self.assert_passes(self.run_gate())

    def test_unapproved_ancestor_fails_even_with_approved_head(self):
        self.git('tag', 'v1.0.0')
        self.commit('Synthetic historical change', private_author=True)
        self.commit('Approved release head')
        self.assert_rejected(self.run_gate(), 'synthetic-ancestor',
                             'synthetic@example.invalid')

    def test_unapproved_committer_is_rejected(self):
        self.commit('Synthetic historical change', private_committer=True)
        self.commit('Approved release head')
        self.assert_rejected(self.run_gate(), 'synthetic-committer',
                             'synthetic-committer@example.invalid')

    def test_current_release_tag_uses_previous_tag_as_boundary(self):
        self.git('tag', 'v1.0.0')
        self.commit('Synthetic historical change', private_author=True)
        self.commit('Approved release head')
        self.git('tag', 'v1.1.0')
        self.assert_rejected(self.run_gate(), 'synthetic-ancestor',
                             'synthetic@example.invalid')

    def test_explicit_base_overrides_default_release_boundary(self):
        baseline = self.git('rev-parse', 'HEAD')
        self.commit('Synthetic historical change', private_author=True)
        self.commit('Approved prior release')
        self.git('tag', 'v1.0.0')
        self.commit('Approved release head')
        self.assert_passes(self.run_gate())
        self.assert_rejected(self.run_gate('--base', baseline),
                             'synthetic-ancestor', 'synthetic@example.invalid')

    def test_approved_annotated_and_nested_tags_pass(self):
        self.git('tag', 'v1.0.0')
        self.commit('Approved release head')
        self.git('tag', '-a', 'v1.1.0-inner', '-m', 'Public release notes')
        self.git('tag', '-a', 'v1.1.0', 'v1.1.0-inner', '-m', 'Public nested release tag')
        self.assert_passes(self.run_gate('--require-alias-head'))

    def test_annotated_tag_metadata_and_nested_taggers_are_checked(self):
        self.git('tag', 'v1.0.0')
        self.commit('Approved release head')
        private_env = dict(self.env, GIT_COMMITTER_NAME='synthetic-tagger',
                           GIT_COMMITTER_EMAIL='synthetic-tagger@example.invalid')
        self.git('tag', '-a', 'inner-tag', '-m', 'Synthetic release note', env=private_env)
        self.git('tag', '-a', 'outer-tag', 'inner-tag', '-m', 'Public release note')
        self.assert_rejected(self.run_gate('--require-alias-head'),
                             'synthetic-tagger', 'synthetic-tagger@example.invalid')
        self.git('tag', '-d', 'inner-tag', 'outer-tag')
        secret = 'synthetic-private-tag-message'
        self.git('tag', '-a', 'message-tag', '-m', 'Release note: ' + secret)
        env = dict(self.env, PRIVACY_FORBIDDEN_VALUES_JSON=json.dumps([secret]))
        self.assert_rejected(self.run_gate('--require-alias-head', env=env), secret)

    def test_annotated_tags_on_ancestor_commits_are_checked(self):
        self.git('tag', 'v1.0.0')
        self.commit('Approved intermediate commit')
        private_env = dict(self.env, GIT_COMMITTER_NAME='synthetic-tagger',
                           GIT_COMMITTER_EMAIL='synthetic-tagger@example.invalid')
        self.git('tag', '-a', 'intermediate-tag', '-m', 'Synthetic release note', env=private_env)
        self.commit('Approved release head')
        self.assert_rejected(self.run_gate('--base', 'v1.0.0'),
                             'synthetic-tagger', 'synthetic-tagger@example.invalid')

    def test_shallow_repository_fails_closed(self):
        self.commit('Approved release head')
        clone = Path(self.directory.name) / 'shallow'
        subprocess.run(['git', 'clone', '--depth=1', self.root.as_uri(), str(clone)],
                       env=self.env, capture_output=True, check=True)
        self.assert_rejected(self.run_gate(root=clone))

    def test_exact_forbidden_value_is_not_disclosed(self):
        forbidden = 'synthetic-private-value-for-gate-test'
        (self.root / 'notes.txt').write_text('Fixture contains: ' + forbidden)
        self.commit('Synthetic content')
        env = dict(self.env, PRIVACY_FORBIDDEN_VALUES_JSON=json.dumps([forbidden]))
        self.assert_rejected(self.run_gate(env=env), forbidden)

    def test_private_key_and_github_token_are_detected(self):
        token = 'gh' + 'p_' + 'A' * 36
        for name, content in (('key.txt', fake_private_key()),
                              ('token.txt', token.encode('ascii'))):
            with self.subTest(kind=name):
                asset = self.asset(name, content)
                self.assert_rejected(self.run_gate('--assets', asset),
                                     content.decode('ascii').strip())

    def test_png_text_and_exif_metadata_are_rejected(self):
        for kind, content in ((b'tEXt', b'Comment\0synthetic-private-description'),
                              (b'eXIf', b'II*\0\x08\0\0\0\0\0\0\0\0\0'),
                              (b'iCCP', b'profile\0\0' + zlib.compress(b'synthetic-private-description'))):
            with self.subTest(chunk=kind):
                asset = self.asset('metadata.png', png((kind, content)))
                self.assert_rejected(self.run_gate('--assets', asset),
                                     'synthetic-private-description')

    def test_clean_png_and_zip_assets_pass(self):
        clean_png = self.asset('clean.png', png())
        clean_zip = self.asset('clean.zip', zipped({'README.txt': b'Synthetic clean release.'}))
        self.assert_passes(self.run_gate('--assets', clean_png, '--assets', clean_zip))

    def test_nested_zip_cannot_hide_private_key(self):
        inner = zipped({'configuration.txt': fake_private_key()})
        asset = self.asset('outer.zip', zipped({'package/inner.zip': inner}))
        self.assert_rejected(self.run_gate('--assets', asset))

    def test_high_compression_and_excessive_nesting_fail_closed(self):
        bomb = self.asset('compressed.zip', zipped({'data.txt': b'A' * (8 * 1024 * 1024)}))
        self.assert_rejected(self.run_gate('--assets', bomb))
        nested = b'Synthetic clean content.'
        for index in range(16):
            nested = zipped({f'level-{index}.zip': nested})
        deep = self.asset('deep.zip', nested)
        self.assert_rejected(self.run_gate('--assets', deep))

    def test_removed_secret_is_still_detected_in_release_history(self):
        self.git('tag', 'v1.0.0')
        path = self.root / 'temporary.txt'
        path.write_bytes(fake_private_key())
        self.commit('Synthetic historical content')
        path.unlink()
        self.commit('Removed synthetic content')
        self.assert_rejected(self.run_gate())

    def test_messages_are_checked_without_echoing_contents(self):
        secret = 'synthetic-private-message-value'
        self.commit('Synthetic message: ' + secret)
        env = dict(self.env, PRIVACY_FORBIDDEN_VALUES_JSON=json.dumps([secret]))
        self.assert_rejected(self.run_gate(env=env), secret)

    def test_public_automation_is_allowed_but_release_head_can_be_strict(self):
        identities = [
            ('dependabot[bot]', '49699333+dependabot[bot]@users.noreply.github.com'),
            ('github-actions[bot]', '41898282+github-actions[bot]@users.noreply.github.com'),
            ('GitHub', 'noreply@github.com'),
        ]
        for name, email in identities:
            with self.subTest(public_automation=name):
                env = dict(self.env, GIT_AUTHOR_NAME=name, GIT_AUTHOR_EMAIL=email,
                           GIT_COMMITTER_NAME=name, GIT_COMMITTER_EMAIL=email)
                self.git('commit', '--allow-empty', '-m', 'Synthetic automated update', env=env)
                self.assert_passes(self.run_gate())
                self.assert_rejected(self.run_gate('--require-alias-head'))
        self.commit('Approved release head')
        self.assert_passes(self.run_gate('--require-alias-head'))

    def test_empty_optional_secret_and_public_email_examples_are_allowed(self):
        (self.root / 'LICENSE.txt').write_text('Public upstream author: public-author@example.org\n')
        (self.root / 'examples.txt').write_text('Synthetic test mailbox: synthetic@example.invalid\n')
        self.commit('Public attribution and examples')
        for value in ('', '  ', '[]'):
            self.assert_passes(self.run_gate(env=dict(self.env, PRIVACY_FORBIDDEN_VALUES_JSON=value)))
        self.assert_rejected(self.run_gate(env=dict(self.env, PRIVACY_FORBIDDEN_VALUES_JSON='not-json')))

    def test_runtime_files_personal_paths_and_base_equal_to_head_are_rejected(self):
        self.assert_rejected(self.run_gate('--base', 'HEAD'))
        for name, content in (
                ('private_key.pem', b'synthetic runtime file'),
                ('path.txt', ('/home/' + 'synthetic-private-person/project').encode()),
                ('windows.txt', ('C:' + '\\Users\\' + 'synthetic-private-person\\project').encode())):
            with self.subTest(kind=name):
                asset = self.asset(name, content)
                self.assert_rejected(self.run_gate('--assets', asset), 'synthetic-private-person')

    def test_pyz_code_is_scanned_without_execution(self):
        marker = self.root / 'must-not-run.txt'
        source = 'secret = ' + repr(fake_private_key()) + '\nopen(' + repr(str(marker)) + ', "w").write("executed")'
        archive = pyz({'synthetic_module': compile(source, 'synthetic-module.py', 'exec')})
        asset = self.asset('modules.pyz', archive)
        self.assert_rejected(self.run_gate('--assets', asset))
        self.assertFalse(marker.exists())

    def test_pyz_in_elf_pe_and_macho_containers_is_scanned(self):
        payload = pyz({'synthetic_module': compile('secret = ' + repr(fake_private_key()),
                                                  'synthetic-module.py', 'exec')})
        for name, prefix in (('program-linux', b'\x7fELF' + b'\0' * 60),
                             ('program.exe', b'MZ' + b'\0' * 62),
                             ('program-macos', b'\xcf\xfa\xed\xfe' + b'\0' * 60)):
            with self.subTest(container=name):
                asset = self.asset(name, frozen({'PYZ.pyz': (b'z', payload)}, prefix))
                self.assert_rejected(self.run_gate('--assets', asset))

    def test_clean_pyz_and_frozen_artifacts_pass(self):
        payload = pyz({'asyncio.log': compile('value = "synthetic clean content"',
                                             'synthetic-module.py', 'exec')})
        plain = self.asset('clean.pyz', payload)
        executable = self.asset('clean-frozen', frozen({'PYZ.pyz': (b'z', payload)}))
        self.assert_passes(self.run_gate('--assets', plain, '--assets', executable))

    def test_windows_public_runner_path_is_narrowly_allowed(self):
        public = ('C:' + '\\Users\\' + 'runneradmin\\build\\module.py').encode()
        self.assert_passes(self.run_gate('--assets', self.asset('public-path.txt', public)))
        for path in (('/home/' + 'runneradmin/build/module.py').encode(),
                     ('C:' + '\\Users\\' + 'synthetic private person\\build\\module.py').encode(),
                     ('/home/' + 'synthetic private person/build/module.py').encode()):
            self.assert_rejected(self.run_gate('--assets', self.asset('private-path.txt', path)),
                                 'synthetic private person')
        secret = 'synthetic-forbidden-file-component'
        env = dict(self.env, PRIVACY_FORBIDDEN_VALUES_JSON=json.dumps([secret]))
        asset = self.asset('public-path.txt', public + secret.encode())
        self.assert_rejected(self.run_gate('--assets', asset, env=env), secret)

    def test_outer_zip_cannot_be_bypassed_by_an_inner_frozen_cookie(self):
        executable = frozen({'readme.txt': (b'x', b'Synthetic clean file')})
        archive = zipped({'program': executable, 'other.txt': fake_private_key()},
                         compression=zipfile.ZIP_STORED)
        self.assert_rejected(self.run_gate('--assets', self.asset('outer.zip', archive)))

    def test_malformed_archives_and_pyz_tables_fail_closed(self):
        invalid_toc = b'PYZ\0' + b'\0' * 4 + struct.pack('!I', 12) + b'c'
        for name, data in (('broken.zip', b'PK\x03\x04invalid'),
                           ('broken.pyz', invalid_toc),
                           ('broken-frozen', b'MZ' + b'MEI\014\013\012\013\016')):
            with self.subTest(kind=name):
                self.assert_rejected(self.run_gate('--assets', self.asset(name, data)))


if __name__ == '__main__':
    unittest.main()
