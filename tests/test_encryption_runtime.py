"""The packaged encryption probe stays headless and reports failures by exit."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import client


class EncryptionRuntimeTests(unittest.TestCase):
    def test_cli_exercises_crypto_without_display_or_user_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            configuration = Path(directory) / 'unused-configuration'
            result = subprocess.run(
                [sys.executable, str(Path(client.__file__).resolve()), '--check-encryption-runtime'],
                env=dict(os.environ, DISPLAY='', CHATROOM_CONFIG_DIR=str(configuration)),
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('PASS encryption runtime:', result.stdout)
            self.assertFalse(configuration.exists(), 'headless check touched user preferences')

    def test_windowed_failure_returns_nonzero_without_streams_or_tk(self):
        with (patch('chatroom_client.runtime_check.check_encryption_runtime', side_effect=ImportError('missing provider')),
                patch.object(client.sys, 'stdout', None), patch.object(client.sys, 'stderr', None),
                patch.object(client.tk, 'Tk', side_effect=AssertionError('Tk must not be created'))):
            self.assertEqual(client.main(['--check-encryption-runtime']), 1)

    def test_normal_gui_entry_point_keeps_its_existing_startup(self):
        with patch.object(client.tk, 'Tk') as make_root, patch.object(client, 'ChatClient') as application:
            self.assertIsNone(client.main([]))
            application.assert_called_once_with(make_root.return_value)
            make_root.return_value.mainloop.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
