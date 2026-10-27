"""Extract one version's reviewed release notes without older release sections."""
import argparse
from pathlib import Path
import re

from versioning import parse_version


def extract(text, version):
    parse_version(version)
    sections = list(re.finditer(r'^# (v[0-9]+\.[0-9]+\.[0-9]+) — (.+)$', text, re.MULTILINE))
    matches = [index for index, match in enumerate(sections) if match[1] == version]
    if len(matches) != 1:
        raise ValueError('Release notes must contain exactly one section for ' + version)
    index = matches[0]
    start = sections[index].start()
    end = sections[index + 1].start() if index + 1 < len(sections) else len(text)
    notes = text[start:end].strip()
    if not notes.partition('\n')[2].strip():
        raise ValueError('Release notes must contain a description')
    return notes + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    notes = extract(Path('RELEASE_NOTES.md').read_text(encoding='utf-8'), args.version)
    args.output.write_text(notes, encoding='utf-8')


if __name__ == '__main__':
    main()
