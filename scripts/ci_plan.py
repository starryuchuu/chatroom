"""Conservative path-based daily checks; packaging belongs to release.yml."""
import json
import os
from pathlib import Path
import subprocess

from versioning import read_version


COMPONENTS = ('python', 'go', 'desktop', 'opaque')


def affected(paths):
    checks = dict.fromkeys(COMPONENTS, False)
    for path in paths:
        if path.startswith('docs/') or path.lower().endswith('.md') or path in ('LICENSE', '.gitignore'):
            continue
        if (path.startswith('opaque-core/') or path.endswith('opaque_core.wasm')):
            return dict.fromkeys(COMPONENTS, True)
        if path.startswith('desktop/'):
            checks['desktop'] = True
        elif path.startswith('go-server/'):
            checks.update(go=True, python=True)
        elif path.startswith('chatroom_client/') or path in ('core_client.py', 'client.py', 'opaque_runtime.py'):
            checks.update(python=True, desktop=True)
        elif path.startswith('.github/') or path.startswith('scripts/') or path == 'VERSION':
            return dict.fromkeys(COMPONENTS, True)
        elif path.startswith('requirements') and path.endswith('.txt'):
            checks.update(python=True, desktop=True)
        elif path.endswith('.py'):
            checks['python'] = True
        else:
            # Unknown file types must not silently bypass compatibility checks.
            return dict.fromkeys(COMPONENTS, True)
    return checks


def git(*args):
    return subprocess.check_output(['git', *args], stderr=subprocess.DEVNULL).decode('utf-8')


def changed_paths(event, payload):
    if event == 'pull_request':
        base, head = payload['pull_request']['base']['sha'], payload['pull_request']['head']['sha']
    elif event == 'push':
        base, head = payload.get('before', ''), payload.get('after', '')
    else:
        return None
    if not base or not head or set(base) == {'0'}:
        return None
    try:
        base = git('rev-parse', '--verify', '--end-of-options', base + '^{commit}').strip()
        head = git('rev-parse', '--verify', '--end-of-options', head + '^{commit}').strip()
        if event == 'pull_request':
            base = git('merge-base', base, head).strip()
        return [path for path in git('diff', '--name-only', '-z', base, head, '--').split('\0') if path]
    except subprocess.CalledProcessError:
        return None


def covered_by_pr(event, branch, commit):
    if event != 'push' or not os.environ.get('GH_TOKEN'):
        return False
    try:
        result = subprocess.run(['gh', 'pr', 'list', '--state', 'open', '--head', branch,
                                 '--json', 'headRefOid,baseRefName'], capture_output=True, text=True,
                                timeout=30, check=True)
        return any(item['headRefOid'] == commit and item['baseRefName'] in ('main', 'master', 'test')
                   for item in json.loads(result.stdout))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # An API problem runs more checks, never fewer.
        return False


def tagged_release_push(event, ref, version):
    if event != 'push' or ref != 'refs/heads/master':
        return False
    try:
        return git('rev-parse', '--verify', '--end-of-options', 'refs/tags/' + version + '^{commit}').strip() == git('rev-parse', 'HEAD').strip()
    except subprocess.CalledProcessError:
        return False


def main():
    version = read_version(Path.cwd())
    event = os.environ['GITHUB_EVENT_NAME']
    payload = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
    paths = changed_paths(event, payload)
    checks = dict.fromkeys(COMPONENTS, True) if paths is None else affected(paths)
    if tagged_release_push(event, os.environ.get('GITHUB_REF', ''), version):
        checks = dict.fromkeys(COMPONENTS, False)
        print('The release workflow validates this tagged master commit.')
    elif covered_by_pr(event, os.environ.get('GITHUB_REF_NAME', ''), os.environ.get('GITHUB_SHA', '')):
        checks = dict.fromkeys(COMPONENTS, False)
        print('This push is covered by its open pull request.')
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        for key, enabled in checks.items():
            output.write(key + '=' + str(enabled).lower() + '\n')
    print('Daily checks: ' + ', '.join(key for key, enabled in checks.items() if enabled))


if __name__ == '__main__':
    main()
