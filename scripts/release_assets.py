"""Prepare a compact, complete release attachment set and SHA256SUMS."""
import hashlib
from pathlib import Path
import shutil
import subprocess

from versioning import read_version


BINARIES = (
    'chatroom-desktop-windows-x64.zip', 'chatroom-desktop-linux-x64.zip',
    'server-windows.exe', 'server-linux',
    'go-server-windows-amd64.exe', 'go-server-windows-arm64.exe',
    'go-server-linux-amd64', 'go-server-linux-arm64',
    'go-server-darwin-amd64', 'go-server-darwin-arm64',
)


def prepare(root, assets):
    root, assets = Path(root), Path(assets)
    version = read_version(root)
    for name in BINARIES:
        path = assets / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            raise ValueError('Missing release artifact: ' + name)
    source = 'chatroom-' + version + '-source.zip'
    license_name = 'OPAQUE_THIRD_PARTY_LICENSES.txt'
    allowed = {*BINARIES, source, license_name, 'SHA256SUMS'}
    if any(item.name not in allowed or item.is_symlink() for item in assets.iterdir()):
        raise ValueError('Unexpected release attachment')
    subprocess.run(['git', 'archive', '--format=zip', '--prefix=chatroom-' + version + '/',
                    '--output=' + str((assets / source).resolve()), 'HEAD'], cwd=root, check=True)
    shutil.copyfile(root / 'chatroom_client' / license_name, assets / license_name)
    lines = []
    for name in sorted(allowed - {'SHA256SUMS'}):
        digest = hashlib.sha256()
        with (assets / name).open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        lines.append(digest.hexdigest() + '  ' + name + '\n')
    (assets / 'SHA256SUMS').write_text(''.join(lines), encoding='ascii')
    return version


if __name__ == '__main__':
    print('Prepared release assets for ' + prepare(Path.cwd(), Path('release-assets')))
