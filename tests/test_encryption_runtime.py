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

    def test_normal_entry_launches_electron_with_the_current_python(self):
        with (patch('shutil.which', return_value='npm'), patch('pathlib.Path.is_dir', return_value=True),
              patch('subprocess.call', return_value=0) as launch,
              patch.object(client.tk, 'Tk', side_effect=AssertionError('desktop must not create Tk'))):
            self.assertEqual(client.main([]), 0)
            self.assertEqual(launch.call_args.args[0], ['npm', 'start'])
            self.assertEqual(launch.call_args.kwargs['env']['CHATROOM_PYTHON'], sys.executable)


if __name__ == '__main__':
    unittest.main()
