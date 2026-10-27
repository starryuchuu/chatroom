"""Synchronize versions, commit, tag and atomically push a release from master.

Run with --dry-run to inspect without writing files or contacting the remote.
The worktree must be clean. No current work is staged on the user's behalf.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys

# Planning must not create untracked bytecode in an otherwise clean checkout.
if __name__ == '__main__':
    sys.dont_write_bytecode = True

from check_release_privacy import PUBLIC_IDENTITY
from versioning import VERSION_FILES, parse_version, read_version, version_contents


class ReleaseError(Exception):
    pass


def git(root, *args, check=True):
    env = dict(os.environ, GIT_AUTHOR_NAME=PUBLIC_IDENTITY[0], GIT_COMMITTER_NAME=PUBLIC_IDENTITY[0],
               GIT_AUTHOR_EMAIL=PUBLIC_IDENTITY[1], GIT_COMMITTER_EMAIL=PUBLIC_IDENTITY[1])
    result = subprocess.run(['git', *args], cwd=root, env=env, capture_output=True, text=True,
                            timeout=60)
    if check and result.returncode:
        raise ReleaseError('Git operation failed: ' + args[0] + '. Local work is preserved for review.')
    return result


def require_clean(root):
    if git(root, 'status', '--porcelain').stdout.strip():
        raise ReleaseError('Commit or stash current changes before releasing.')


def release(root, requested, *, dry_run=False):
    root = Path(root).resolve()
    if Path(git(root, 'rev-parse', '--show-toplevel').stdout.strip()).resolve() != root:
        raise ReleaseError('Run this command from the repository root.')
    if git(root, 'branch', '--show-current').stdout.strip() != 'master':
        raise ReleaseError('Releases must be made from master.')
    require_clean(root)
    version = requested if requested.startswith('v') else 'v' + requested
    if parse_version(version) <= parse_version(read_version(root)):
        raise ReleaseError('Release version must be newer than the current version.')
    if git(root, 'show-ref', '--verify', '--quiet', 'refs/tags/' + version, check=False).returncode == 0:
        raise ReleaseError('Release tag already exists. Retry its GitHub Actions workflow instead.')
    contents = version_contents(root, version)
    if dry_run:
        print('Would synchronize: ' + ', '.join(VERSION_FILES))
        print('Would create release commit and annotated tag ' + version + ', then atomically push master and tag.')
        return version
    git(root, 'fetch', 'origin', 'refs/heads/master:refs/remotes/origin/master', '--tags')
    if git(root, 'show-ref', '--verify', '--quiet', 'refs/tags/' + version, check=False).returncode == 0:
        raise ReleaseError('Release tag already exists on origin.')
    if git(root, 'merge-base', '--is-ancestor', 'refs/remotes/origin/master', 'HEAD', check=False).returncode:
        raise ReleaseError('Update master from origin and resolve any divergence before releasing.')
    require_clean(root)
    for name, value in contents.items():
        (root / name).write_bytes(value)
    git(root, 'add', '--', *VERSION_FILES)
    git(root, 'commit', '-m', 'Release ' + version)
    git(root, 'tag', '-a', version, '-m', version)
    # This gate also inspects the just-created commit and tag using the public
    # release alias. A failure leaves the concrete local result for inspection.
    subprocess.run([sys.executable, str(root / 'scripts/check_release_privacy.py'), '--require-alias-head'],
                   cwd=root, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), check=True)
    git(root, 'push', '--atomic', 'origin', 'master:refs/heads/master', 'refs/tags/' + version)
    print('Pushed ' + version + '. GitHub Actions will validate, build and publish it.')
    return version


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version', help='New version, for example 1.6.0 or v1.6.0')
    parser.add_argument('--dry-run', action='store_true', help='Plan locally without changes or network access')
    args = parser.parse_args()
    try:
        release(Path.cwd(), args.version, dry_run=args.dry_run)
    except (ReleaseError, ValueError, OSError, subprocess.SubprocessError) as error:
        if isinstance(error, subprocess.SubprocessError):
            print('Release stopped by a failed command; inspect local state before retrying.', file=sys.stderr)
        else:
            print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
