"""Release publishing must select only the requested reviewed description."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from release_notes import extract


class ReleaseNotesTests(unittest.TestCase):
    def test_exact_version_and_nested_headings_preserved(self):
        text = ('# v2.0.0 — 客户端重构\n\n## 升级\n\nNew desktop.\n\n'
                '# v1.5.0 — Previous release\n\nOld desktop.\n')
        self.assertEqual(extract(text, 'v2.0.0'),
                         '# v2.0.0 — 客户端重构\n\n## 升级\n\nNew desktop.\n')
        self.assertEqual(extract(text, 'v1.5.0'),
                         '# v1.5.0 — Previous release\n\nOld desktop.\n')

    def test_missing_duplicate_empty_and_invalid_versions_rejected(self):
        for text, version in (('# v2.0.0 — UI\nBody\n', 'v2.0.1'),
                              ('# v2.0.0 — UI\nBody\n# v2.0.0 — Again\nBody\n', 'v2.0.0'),
                              ('# v2.0.0 — UI\n\n', 'v2.0.0'),
                              ('# v2.0.0 — UI\nBody\n', 'v02.0.0')):
            with self.subTest(text=text, version=version), self.assertRaises(ValueError):
                extract(text, version)


if __name__ == '__main__':
    unittest.main()
