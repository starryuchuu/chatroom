"""Reject accidental personal commit identities and runtime files in a release."""
from pathlib import Path
import subprocess


def main():
    root = Path(__file__).resolve().parents[1]
    identity = subprocess.check_output(
        ['git', 'show', '-s', '--format=%an%n%ae%n%cn%n%ce', 'HEAD'], cwd=root,
        text=True).splitlines()
    expected = ['starryuchuu', '115001462+starryuchuu@users.noreply.github.com'] * 2
    if identity != expected:
        raise SystemExit('Release identity is not the approved public alias and privacy email')
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
    forbidden = {'chat.db', 'private_key.pem', 'public_key.pem', '.gitconfig', 'client.json'}
    for filename in tracked:
        path = Path(filename)
        if path.name in forbidden or path.name.endswith(('.db.key', '.log')):
            raise SystemExit('A runtime or personal file is tracked; release stopped')
    print('Release identity and tracked-file privacy checks passed.')


if __name__ == '__main__':
    main()
