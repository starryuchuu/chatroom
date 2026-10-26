"""The same DPI and clipboard checks run in native and frozen desktop clients."""
import sys
import unittest
from chatroom_client.desktop_check import check_desktop_ui


class DesktopCheckTests(unittest.TestCase):
    def test_small_window_dpi_matrix_preserves_controls_and_unicode_input(self):
        report = check_desktop_ui()
        self.assertEqual(len(report['cases']), 10)
        self.assertEqual({case['scale'] for case in report['cases']}, {1, 1.25, 1.5, 1.75, 2})
        self.assertEqual({case['theme'] for case in report['cases']}, {'light', 'dark'})
        self.assertTrue(all(case['chat_height'] >= 80 for case in report['cases']))
        if sys.platform == 'win32':
            self.assertTrue(report['cjk_font_verified'])
            self.assertIn('native', report['input_check'])
