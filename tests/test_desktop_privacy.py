"""Only immutable, verified upstream runtime bytes may contain public build paths."""
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import release_privacy_assets as privacy


class UpstreamRuntimeTests(unittest.TestCase):
    def test_hash_exception_cannot_hide_appended_bytes_or_explicit_private_values(self):
        upstream = b'public runtime ' + b'/home/' + b'upstream-build-account/source'
        digest = hashlib.sha256(upstream).hexdigest()
        with patch.object(privacy, 'UPSTREAM_RUNTIME_SHA256', frozenset({digest})):
            privacy.ScanPolicy().content(upstream)
            with self.assertRaises(privacy.PrivacyError) as caught:
                privacy.ScanPolicy().content(upstream + b'changed')
            self.assertEqual(caught.exception.category, 'personal-path')
            with self.assertRaises(privacy.PrivacyError) as caught:
                privacy.ScanPolicy(['public runtime']).content(upstream)
            self.assertEqual(caught.exception.category, 'private-value')
