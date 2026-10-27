"""Only immutable, verified upstream runtime bytes may contain public build paths."""
import hashlib
from pathlib import Path
import sys
import struct
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

    def synthetic_pe(self):
        section = b'public build data ' + b'/Users/' + b'upstream-build-account/source\0'
        header = bytearray(512)
        header[:2] = b'MZ'
        struct.pack_into('<I', header, 60, 128)
        header[128:132] = b'PE\0\0'
        struct.pack_into('<H', header, 134, 1)
        header[152:160] = b'.rdata\0\0'
        struct.pack_into('<II', header, 168, len(section), len(header))
        return bytes(header) + section, (b'.rdata', hashlib.sha256(section).hexdigest())

    def test_verified_pe_section_cannot_exempt_other_sections_overlays_or_forbidden_values(self):
        runtime, digest = self.synthetic_pe()
        other = bytearray(runtime)
        struct.pack_into('<H', other, 134, 2)
        other[192:200] = b'.data\0\0\0'
        private_path = b'/Users/' + b'another-account/private'
        struct.pack_into('<II', other, 208, len(private_path), len(other))
        other.extend(private_path)
        with patch.object(privacy, 'UPSTREAM_PE_SECTIONS_SHA256', frozenset({digest})):
            privacy.ScanPolicy().content(runtime)
            for changed in (runtime + private_path,
                            runtime.replace(b'public build data', b'changed build data'), bytes(other)):
                with self.subTest(changed=changed), self.assertRaises(privacy.PrivacyError) as caught:
                    privacy.ScanPolicy().content(changed)
                self.assertEqual(caught.exception.category, 'personal-path')
            with self.assertRaises(privacy.PrivacyError) as caught:
                privacy.ScanPolicy(['public build data']).content(runtime)
            self.assertEqual(caught.exception.category, 'private-value')

    def test_invalid_pe_section_bounds_do_not_exempt_paths(self):
        runtime, digest = self.synthetic_pe()
        for offset, value in ((60, len(runtime)), (168, len(runtime)), (172, 0)):
            changed = bytearray(runtime)
            struct.pack_into('<I', changed, offset, value)
            with patch.object(privacy, 'UPSTREAM_PE_SECTIONS_SHA256', frozenset({digest})):
                with self.subTest(offset=offset), self.assertRaises(privacy.PrivacyError):
                    privacy.ScanPolicy().content(bytes(changed))
