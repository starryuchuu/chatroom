"""Decide publication in the same run that tests and builds a commit."""
import os
from pathlib import Path
import re
import subprocess


VERSION_FILES = frozenset({'VERSION', 'go-server/VERSION'})


def should_publish(event, ref, changed, requested=False):
    if ref != 'refs/heads/master':
        return False
    return ((event == 'push' and bool(VERSION_FILES.intersection(changed)))
            or (event == 'workflow_dispatch' and requested))


def main():
    version = Path('VERSION').read_text().strip()
    if (not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', version)
            or Path('go-server/VERSION').read_text().strip() != version):
        raise SystemExit('Version files must contain the same vX.Y.Z value')
    event, before = os.environ['EVENT_NAME'], os.environ.get('BEFORE_SHA', '')
    changed = []
    if event == 'push' and before:
        if set(before) == {'0'}:
            changed = list(VERSION_FILES)
        else:
            changed = subprocess.check_output(
                ['git', 'diff', '--name-only', before, 'HEAD', '--', *sorted(VERSION_FILES)],
                text=True).splitlines()
    publish = should_publish(event, os.environ['GIT_REF'], changed,
                             os.environ.get('PUBLISH_REQUESTED') == 'true')
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        output.write('release=' + str(publish).lower() + '\n')
    print('Release publication: ' + str(publish).lower())


if __name__ == '__main__':
    main()
