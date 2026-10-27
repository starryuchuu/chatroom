"""One version source, synchronized copies for Go, Electron and npm's lock."""
import json
from pathlib import Path
import re


VERSION_PATTERN = r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
VERSION_FILES = ('VERSION', 'go-server/VERSION', 'desktop/package.json', 'desktop/package-lock.json')


def parse_version(value):
    if not isinstance(value, str) or re.fullmatch(VERSION_PATTERN, value) is None:
        raise ValueError('Version must have the form vX.Y.Z without leading zeroes')
    return tuple(int(part) for part in value[1:].split('.'))


def read_version(root):
    root = Path(root)
    version = (root / 'VERSION').read_text(encoding='utf-8').strip()
    parse_version(version)
    package = json.loads((root / 'desktop/package.json').read_text(encoding='utf-8'))
    lock = json.loads((root / 'desktop/package-lock.json').read_text(encoding='utf-8'))
    if ((root / 'go-server/VERSION').read_text(encoding='utf-8').strip() != version
            or package.get('version') != version[1:] or lock.get('version') != version[1:]
            or lock.get('packages', {}).get('', {}).get('version') != version[1:]):
        raise ValueError('Version copies disagree; use python scripts/release.py <version>')
    return version


def version_contents(root, version):
    """Prepare every new byte before changing any file."""
    root = Path(root)
    parse_version(version)
    result = {'VERSION': (version + '\n').encode(), 'go-server/VERSION': (version + '\n').encode()}
    for name in ('desktop/package.json', 'desktop/package-lock.json'):
        value = json.loads((root / name).read_text(encoding='utf-8'))
        value['version'] = version[1:]
        if name.endswith('package-lock.json'):
            value['packages']['']['version'] = version[1:]
        result[name] = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    return result
