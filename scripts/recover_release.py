"""Reuse only a completed tagged run whose sole failure was publication."""
import json
import os
from pathlib import Path
import re
import subprocess

from versioning import parse_version, read_version


REQUIRED_JOBS = frozenset({
    'validate', 'tests / regression (ubuntu-latest)', 'tests / regression (windows-latest)',
    'build / build-python (ubuntu-latest, linux)',
    'build / build-python (windows-latest, windows, .exe)',
    'build / build-go (windows, amd64, .exe)', 'build / build-go (windows, arm64, .exe)',
    'build / build-go (linux, amd64)', 'build / build-go (linux, arm64)',
    'build / build-go (darwin, amd64)', 'build / build-go (darwin, arm64)',
})


def validate_evidence(run, jobs, tag, commit):
    parse_version(tag)
    if (run.get('head_sha') != commit or run.get('head_branch') != tag
            or run.get('path') != '.github/workflows/release.yml' or run.get('event') != 'push'
            or run.get('status') != 'completed' or run.get('conclusion') != 'failure'):
        raise ValueError('Recovery requires the exact completed tagged release run')
    names = [job.get('name') for job in jobs]
    if len(set(names)) != len(names) or set(names) != REQUIRED_JOBS | {'publish'}:
        raise ValueError('Recovery requires complete, unambiguous verification jobs')
    for job in jobs:
        expected = 'failure' if job['name'] == 'publish' else 'success'
        if job.get('status') != 'completed' or job.get('conclusion') != expected:
            raise ValueError('Every test and build must pass before publication recovery')


def main():
    if os.environ['GITHUB_EVENT_NAME'] == 'push':
        match = re.fullmatch(r'release/recover-(v[0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)', os.environ['GITHUB_REF_NAME'])
        if match is None:
            raise ValueError('Use release/recover-vX.Y.Z-RUN_ID')
        tag, run_id = match.groups()
    else:
        tag, run_id = os.environ['RECOVERY_TAG'], os.environ['RECOVERY_RUN_ID']
    parse_version(tag)
    if not re.fullmatch(r'[1-9][0-9]*', run_id):
        raise ValueError('Invalid workflow run ID')
    if read_version(Path.cwd()) != tag:
        raise ValueError('Only the current release version may be recovered')
    commit = subprocess.check_output(['git', 'rev-parse', '--verify', '--end-of-options',
                                     'refs/tags/' + tag + '^{commit}'], text=True).strip()
    subprocess.run(['git', 'merge-base', '--is-ancestor', commit, 'origin/master'], check=True)
    repo = os.environ['GITHUB_REPOSITORY']
    def api(endpoint):
        return json.loads(subprocess.check_output(['gh', 'api', 'repos/' + repo + endpoint], text=True))
    run = api('/actions/runs/' + run_id)
    response = api('/actions/runs/' + run_id + '/jobs?per_page=100')
    jobs = response['jobs']
    if response['total_count'] != len(jobs):
        raise ValueError('Incomplete job evidence')
    validate_evidence(run, jobs, tag, commit)
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        output.write('tag=' + tag + '\ncommit=' + commit + '\nrun_id=' + run_id + '\n')
    print('Verified all tests and builds for ' + tag + ' at ' + commit)


if __name__ == '__main__':
    main()
