"""Check release history, tracked contents and optional attachments for privacy.

Exact private values may be provided through PRIVACY_FORBIDDEN_VALUES_JSON.
Findings never print their original values. Archive parsing never runs code.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

from release_privacy_assets import ArchiveScanner, PrivacyError, ScanPolicy


PUBLIC_IDENTITY = ('starryuchuu', '115001462+starryuchuu@users.noreply.github.com')
AUTOMATION_IDENTITIES = frozenset({
    ('dependabot[bot]', '49699333+dependabot[bot]@users.noreply.github.com'),
    ('github-actions[bot]', '41898282+github-actions[bot]@users.noreply.github.com'),
    ('GitHub', 'noreply@github.com'),
})
MAX_COMMITS = 10000
MAX_TAGS = 10000
MAX_TAG_DEPTH = 8
MAX_GIT_OUTPUT = 64 * 1024 * 1024


def _git(root, *arguments, allow_failure=False):
    result = subprocess.run(['git', *arguments], cwd=root, capture_output=True)
    if len(result.stdout) > MAX_GIT_OUTPUT:
        raise PrivacyError('repository-limit')
    if result.returncode and not allow_failure:
        raise PrivacyError('repository-unavailable')
    return result.stdout if not result.returncode else None


def _commit(root, revision):
    value = _git(root, 'rev-parse', '--verify', '--end-of-options', revision + '^{commit}')
    value = value.strip().decode('ascii')
    if not re.fullmatch(r'[a-f0-9]{40}|[a-f0-9]{64}', value):
        raise PrivacyError('repository-unavailable')
    return value


def _boundary(root, head, base):
    if base is not None:
        resolved = _commit(root, base)
        if resolved == head or _git(root, 'merge-base', '--is-ancestor', resolved, head,
                                    allow_failure=True) is None:
            raise PrivacyError('invalid-release-base')
        return resolved
    # A tag pointing at HEAD describes this release, not its baseline.
    search = head
    if _git(root, 'tag', '--points-at', head).strip():
        parent = _git(root, 'rev-parse', '--verify', head + '^', allow_failure=True)
        if parent is None:
            return None
        search = parent.strip().decode('ascii')
    tag = _git(root, 'describe', '--tags', '--abbrev=0', search, allow_failure=True)
    return _commit(root, tag.strip().decode('utf-8')) if tag else None


def _identity(header, field):
    lines = [line[len(field) + 1:] for line in header.splitlines()
             if line.startswith(field + b' ')]
    if len(lines) != 1:
        raise PrivacyError('commit-identity')
    match = re.fullmatch(rb'([^<>\r\n]+) <([^<>\s]+)> -?\d+ [+-]\d{4}', lines[0])
    if match is None:
        raise PrivacyError('commit-identity')
    try:
        return match[1].decode('utf-8'), match[2].decode('ascii')
    except UnicodeError:
        raise PrivacyError('commit-identity') from None


def _check_commit(root, sha, policy, *, require_alias=False):
    raw = _git(root, 'cat-file', 'commit', sha)
    header, separator, message = raw.partition(b'\n\n')
    if not separator:
        raise PrivacyError('commit-format')
    allowed = {PUBLIC_IDENTITY} if require_alias else {PUBLIC_IDENTITY, *AUTOMATION_IDENTITIES}
    if any(_identity(header, field) not in allowed for field in (b'author', b'committer')):
        raise PrivacyError('commit-identity')
    policy.content(raw)


def _check_release_tags(root, commits, policy):
    """Check annotated tag chains whose final commits belong to this release."""
    references = _git(root, 'for-each-ref', '--format=%(objectname)%00%(refname)',
                      'refs/tags').splitlines()
    if len(references) > MAX_TAGS:
        raise PrivacyError('release-tag-limit')
    allowed = {PUBLIC_IDENTITY, *AUTOMATION_IDENTITIES}
    inspected = set()
    for reference in references:
        sha, separator, name = reference.partition(b'\0')
        if not separator:
            raise PrivacyError('release-tag-format')
        chain, visited = [], set()
        for _ in range(MAX_TAG_DEPTH + 1):
            if sha in visited or not re.fullmatch(rb'[a-f0-9]{40}|[a-f0-9]{64}', sha):
                raise PrivacyError('release-tag-format')
            visited.add(sha)
            kind = _git(root, 'cat-file', '-t', sha.decode('ascii')).strip()
            if kind != b'tag':
                break
            if len(chain) == MAX_TAG_DEPTH:
                raise PrivacyError('release-tag-limit')
            raw = _git(root, 'cat-file', 'tag', sha.decode('ascii'))
            header, separator, _message = raw.partition(b'\n\n')
            targets = [line[7:] for line in header.splitlines() if line.startswith(b'object ')]
            if not separator or len(targets) != 1:
                raise PrivacyError('release-tag-format')
            chain.append((sha, header, raw))
            sha = targets[0]
        if kind != b'commit' or sha.decode('ascii') not in commits:
            continue
        policy.content(name)
        for tag_sha, header, raw in chain:
            if tag_sha in inspected:
                continue
            if _identity(header, b'tagger') not in allowed:
                raise PrivacyError('release-tag-identity')
            policy.content(raw)
            inspected.add(tag_sha)


def _tree(root, sha):
    for row in _git(root, 'ls-tree', '-r', '-z', '--full-tree', sha).split(b'\0'):
        if not row:
            continue
        info, separator, name = row.partition(b'\t')
        parts = info.split()
        if not separator or len(parts) != 3:
            raise PrivacyError('repository-format')
        yield parts[1], parts[2].decode('ascii'), os.fsdecode(name)


def scan_repository(root, base=None, assets=None, *, require_alias_head=False):
    root = Path(root).resolve()
    if _git(root, 'rev-parse', '--is-shallow-repository').strip() != b'false':
        raise PrivacyError('shallow-history')
    policy = ScanPolicy.from_environment()
    head = _commit(root, 'HEAD')
    boundary = _boundary(root, head, base)
    revision = boundary + '..' + head if boundary else head
    commits = _git(root, 'rev-list', '--reverse', '--topo-order', revision).decode('ascii').splitlines()
    if not commits or len(commits) > MAX_COMMITS:
        raise PrivacyError('release-range-limit')
    _check_release_tags(root, set(commits), policy)
    seen = set()
    for sha in commits:
        _check_commit(root, sha, policy, require_alias=require_alias_head and sha == head)
        # Full trees also catch secrets introduced and removed before HEAD.
        for kind, blob, name in _tree(root, sha):
            policy.filename(name)
            if kind != b'blob':
                raise PrivacyError('unsupported-tracked-entry')
            if blob in seen:
                continue
            if int(_git(root, 'cat-file', '-s', blob).strip()) > policy.max_file_bytes:
                raise PrivacyError('source-size-limit')
            policy.source(_git(root, 'cat-file', 'blob', blob), name)
            seen.add(blob)
    # Include tracked edits during local preflight; release CI has a clean tree.
    for raw_name in _git(root, 'ls-files', '-z').split(b'\0'):
        if not raw_name:
            continue
        name = os.fsdecode(raw_name)
        policy.filename(name)
        path = root / name
        if path.is_symlink():
            target = os.readlink(path)
            if Path(target).is_absolute() or not path.resolve().is_relative_to(root):
                raise PrivacyError('external-tracked-link')
            policy.content(os.fsencode(target))
            continue
        if not path.is_file() or path.stat().st_size > policy.max_file_bytes:
            raise PrivacyError('source-unavailable')
        policy.source(path.read_bytes(), name)
    return {'commits': len(commits), 'source_blobs': len(seen),
            **ArchiveScanner(policy).scan_paths(assets or [])}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', help='Exclusive ancestor commit/tag for the release range')
    parser.add_argument('--assets', action='append', type=Path, default=[],
                        help='Attachment or directory to inspect recursively; repeatable')
    parser.add_argument('--require-alias-head', action='store_true',
                        help='Require the human release HEAD to use the approved public alias')
    args = parser.parse_args(argv)
    try:
        report = scan_repository(Path(__file__).resolve().parents[1], args.base, args.assets,
                                 require_alias_head=args.require_alias_head)
    except PrivacyError as error:
        print('Release privacy check failed [' + error.category + '].', file=sys.stderr)
        return 1
    except Exception:
        print('Release privacy check failed [inspection-unavailable].', file=sys.stderr)
        return 1
    print('Release privacy checks passed: ' + str(report['commits'])
          + ' commits; ' + str(report['asset_files']) + ' asset files.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
