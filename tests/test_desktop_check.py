"""The same DPI and clipboard checks run in native and frozen desktop clients."""
import sys
import unittest
from unittest.mock import patch
import weakref
from chatroom_client import desktop_check
from chatroom_client.desktop_check import check_desktop_ui


class DesktopCheckTests(unittest.TestCase):
    def test_ui_probe_releases_interpreters_before_returning_to_other_threads(self):
        roots = []
        create = desktop_check.tk.Tk

        def tracked_root():
            root = create()
            roots.append(weakref.ref(root))
            return root

        with patch.object(desktop_check.tk, 'Tk', side_effect=tracked_root):
            check_desktop_ui(scales=(1,))
        self.assertTrue(roots)
        self.assertTrue(all(reference() is None for reference in roots))

    def test_small_window_dpi_matrix_preserves_controls_and_unicode_input(self):
        report = check_desktop_ui()
        self.assertEqual(len(report['cases']), 10)
        self.assertEqual({case['scale'] for case in report['cases']}, {1, 1.25, 1.5, 1.75, 2})
        self.assertEqual({case['theme'] for case in report['cases']}, {'light', 'dark'})
        self.assertTrue(all(case['chat_height'] >= 80 for case in report['cases']))
        if sys.platform == 'win32':
            self.assertTrue(report['cjk_font_verified'])
            self.assertIn('native', report['input_check'])
