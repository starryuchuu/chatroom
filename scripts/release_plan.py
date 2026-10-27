"""Validate an explicit release tag, its versions, and master ancestry."""
import os
from pathlib import Path
import subprocess

from versioning import parse_version, read_version


def validate(root, event, ref, dispatch_tag=''):
    if event == 'push' and ref.startswith('refs/tags/'):
        tag = ref[len('refs/tags/'):]
    elif event == 'workflow_dispatch':
        tag = dispatch_tag
    else:
        raise ValueError('Only a version tag push or explicit tag retry can publish')
    parse_version(tag)
    if read_version(root) != tag:
        raise ValueError('Release tag does not match every version copy')

    def git(*args):
        return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.DEVNULL).decode('ascii').strip()

    commit = git('rev-parse', '--verify', '--end-of-options', 'refs/tags/' + tag + '^{commit}')
    if git('rev-parse', 'HEAD') != commit:
        raise ValueError('Release checkout must be the tagged commit')
    subprocess.run(['git', 'merge-base', '--is-ancestor', commit, 'refs/remotes/origin/master'],
                   cwd=root, check=True, capture_output=True)
    if git('show', 'refs/remotes/origin/master:VERSION') != tag:
        raise ValueError('This version is no longer the release version on master')
    return tag, commit


def main():
    tag, commit = validate(Path.cwd(), os.environ['GITHUB_EVENT_NAME'], os.environ.get('GITHUB_REF', ''),
                           os.environ.get('DISPATCH_TAG', ''))
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        output.write('tag=' + tag + '\ncommit=' + commit + '\n')
    print('Validated release ' + tag)


if __name__ == '__main__':
    main()
