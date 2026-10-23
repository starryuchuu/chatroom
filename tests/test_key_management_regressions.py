"""Bind explicit identity verification and protect the active vault during export."""
from copy import deepcopy
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from chatroom_client.e2ee_crypto import Identity, bundle_fingerprint
from chatroom_client.encryption import EncryptionController
from chatroom_client.key_vault import KeyVault, PeerKeyChanged, VaultError


ENDPOINT = ('demo.invalid', 12345)
SERVER_ID = 'a' * 64
EXPORT_SECRET = b'e' * 64
OFFLINE_PASSWORD = 'synthetic-offline-backup-password'


class KeyManagementRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / 'current-vault.json'
        self.vault = KeyVault(self.path, ENDPOINT, 'demo_alice')
        self.vault.unlock_opaque(EXPORT_SECRET, SERVER_ID, create=True)
        self.addCleanup(self.vault.lock)
        self.identity = self.vault.identity
        self.bob, self.carol = Identity.generate(), Identity.generate()
        self.vault.pin_peer('demo_bob', self.bob.public_bundle())
        self.vault.pin_peer('demo_carol', self.carol.public_bundle(), verified=True)
        self.roster = {'demo_alice': self.identity.public_bundle(),
                       'demo_bob': self.bob.public_bundle(),
                       'demo_carol': self.carol.public_bundle()}
        self.vault.approve_roster('demo_group', self.roster)
        self.vault.observe_envelope(self.bob.fingerprint, 'b' * 32, 7, envelope_digest='c' * 64)
        application = SimpleNamespace(
            state=SimpleNamespace(username='demo_alice'),
            view=SimpleNamespace(refresh_controls=lambda: None))
        self.controller = EncryptionController(application)
        self.controller.vault = self.vault

    def reopen(self):
        other = KeyVault(self.path, ENDPOINT, 'demo_alice')
        other.unlock_opaque(EXPORT_SECRET, SERVER_ID)
        self.addCleanup(other.lock)
        return other

    def assert_preserved_trust(self, vault):
        self.assertEqual(vault.identity.fingerprint, self.identity.fingerprint)
        self.assertTrue(vault.is_verified('demo_carol'))
        self.assertEqual(vault.approved_roster('demo_group'),
                         {name: bundle_fingerprint(bundle) for name, bundle in self.roster.items()})
        self.assertEqual(vault.known_envelope(self.bob.fingerprint, 'b' * 32), 7)

    def test_verified_state_binds_the_confirmed_fingerprint(self):
        self.controller.verify_peer('demo_bob', self.bob.fingerprint)
        self.assertTrue(self.vault.is_verified('demo_bob'))
        self.assert_preserved_trust(self.vault)
        self.assertTrue(self.reopen().is_verified('demo_bob'))

    def test_verification_rejects_a_pin_changed_after_the_user_saw_it(self):
        confirmed = self.controller.peers()[0]['fingerprint']
        replacement = Identity.generate()
        second = self.reopen()
        second.pin_peer('demo_bob', replacement.public_bundle(), replace=True)
        current_bytes = self.path.read_bytes()
        with self.assertRaises(PeerKeyChanged):
            self.controller.verify_peer('demo_bob', confirmed)
        self.assertEqual(self.path.read_bytes(), current_bytes)
        self.assertEqual(self.vault.peer('demo_bob'), replacement.public_bundle())
        self.assertFalse(self.vault.is_verified('demo_bob'))
        self.assert_preserved_trust(self.vault)

    def test_verification_compares_the_pin_in_the_locked_mutation(self):
        second = self.reopen()
        replacement = Identity.generate()
        mutate = self.vault._mutate

        def replace_before_mutation(operation):
            second.pin_peer('demo_bob', replacement.public_bundle(), replace=True)
            return mutate(operation)

        with patch.object(self.vault, '_mutate', side_effect=replace_before_mutation):
            with self.assertRaises(PeerKeyChanged):
                self.controller.verify_peer('demo_bob', self.bob.fingerprint)
        self.assertEqual(self.vault.peer('demo_bob'), replacement.public_bundle())
        self.assertFalse(self.vault.is_verified('demo_bob'))

    def test_legacy_name_only_verification_fails_closed(self):
        original = self.path.read_bytes()
        with self.assertRaises(VaultError):
            self.controller.verify_peer('demo_bob')
        for fingerprint in (None, True, '', 'not-a-fingerprint'):
            with self.subTest(fingerprint=fingerprint), self.assertRaises(VaultError):
                self.vault.verify_peer('demo_bob', fingerprint)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertFalse(self.vault.is_verified('demo_bob'))

    def test_application_wrapper_forwards_the_confirmed_fingerprint(self):
        from chatroom_client.app import ChatApplication

        application = SimpleNamespace(encryption=self.controller)
        with self.assertRaises(VaultError):
            ChatApplication.verify_encryption_peer(application, 'demo_bob')
        ChatApplication.verify_encryption_peer(application, 'demo_bob', self.bob.fingerprint)
        self.assertTrue(self.vault.is_verified('demo_bob'))

    def assert_export_rejected(self, destination):
        original = self.path.read_bytes()
        original_state = deepcopy(self.vault._data)
        original_alias = destination.read_bytes()
        with self.assertRaisesRegex(VaultError, '不能覆盖'):
            self.vault.export_to(destination, OFFLINE_PASSWORD)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(destination.read_bytes(), original_alias)
        self.assertEqual(self.vault._data, original_state)
        self.assertEqual(json.loads(self.path.read_bytes())['v'], 2)
        self.assertTrue(self.vault.single_password)
        self.assertFalse(self.vault.is_verified('demo_bob'))
        self.assert_preserved_trust(self.vault)

    def test_export_rejects_its_own_path_and_normalized_alias(self):
        self.assert_export_rejected(self.path)
        nested = self.directory / 'nested'
        nested.mkdir()
        self.assert_export_rejected(nested / '..' / self.path.name)
        if self.path.drive.lower() == Path.cwd().drive.lower():
            relative = Path(os.path.relpath(self.path, Path.cwd()))
            self.assert_export_rejected(relative)

    def test_export_rejects_a_file_symlink_to_its_vault(self):
        alias = self.directory / 'file-link.json'
        try:
            alias.symlink_to(self.path)
        except (OSError, NotImplementedError):
            self.skipTest('file symlinks are unavailable')
        self.assert_export_rejected(alias)
        self.assertTrue(alias.is_symlink())

    def test_export_rejects_a_directory_symlink_to_its_vault(self):
        alias = self.directory / 'directory-link'
        try:
            alias.symlink_to(self.directory, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('directory symlinks are unavailable')
        self.assert_export_rejected(alias / self.path.name)
        self.assertTrue(alias.is_symlink())

    def test_export_rejects_a_hardlink_to_its_vault(self):
        alias = self.directory / 'hard-link.json'
        try:
            os.link(self.path, alias)
        except (OSError, NotImplementedError):
            self.skipTest('hardlinks are unavailable')
        self.assert_export_rejected(alias)
        self.assertTrue(alias.samefile(self.path))

    def test_export_path_validation_errors_do_not_expose_paths_or_change_the_vault(self):
        original = self.path.read_bytes()
        destination = self.directory / 'offline-backup.json'
        with patch.object(Path, 'resolve', side_effect=PermissionError('synthetic-private-path')):
            with self.assertRaises(VaultError) as raised:
                self.vault.export_to(destination, OFFLINE_PASSWORD)
        self.assertNotIn('synthetic-private-path', str(raised.exception))
        self.assertEqual(self.path.read_bytes(), original)
        self.assertFalse(destination.exists())
        self.assert_preserved_trust(self.vault)

    def test_export_rechecks_an_alias_created_during_offline_key_derivation(self):
        from chatroom_client.key_vault import hash_secret_raw

        alias = self.directory / 'late-link.json'
        try:
            os.link(self.path, alias)
        except (OSError, NotImplementedError):
            self.skipTest('hardlinks are unavailable')
        alias.unlink()
        original = self.path.read_bytes()

        def derive(*args, **kwargs):
            os.link(self.path, alias)
            return hash_secret_raw(*args, **kwargs)

        with patch('chatroom_client.key_vault.hash_secret_raw', side_effect=derive):
            with self.assertRaisesRegex(VaultError, '不能覆盖'):
                self.vault.export_to(alias, OFFLINE_PASSWORD)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertTrue(alias.samefile(self.path))
        self.assert_preserved_trust(self.vault)

    def test_normal_offline_export_and_restore_preserve_the_full_vault(self):
        destination = self.directory / 'offline-backup.json'
        self.controller.verify_peer('demo_bob', self.bob.fingerprint)
        original = self.path.read_bytes()
        self.assertEqual(self.vault.export_to(destination, OFFLINE_PASSWORD), destination)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(json.loads(destination.read_bytes())['v'], 1)
        restored = KeyVault(None, ENDPOINT, 'demo_alice')
        self.addCleanup(restored.lock)
        restored.import_from(destination, OFFLINE_PASSWORD)
        self.assertTrue(restored.is_verified('demo_bob'))
        self.assert_preserved_trust(restored)
        self.assert_preserved_trust(self.vault)

    def test_memory_vault_can_export_an_offline_backup(self):
        vault = KeyVault(None, ENDPOINT, 'demo_alice')
        vault.unlock_opaque(EXPORT_SECRET, SERVER_ID, create=True)
        self.addCleanup(vault.lock)
        destination = self.directory / 'memory-backup.json'
        vault.export_to(destination, OFFLINE_PASSWORD)
        restored = KeyVault(None, ENDPOINT, 'demo_alice')
        self.addCleanup(restored.lock)
        restored.import_from(destination, OFFLINE_PASSWORD)
        self.assertEqual(restored.identity.fingerprint, vault.identity.fingerprint)

    def test_legacy_vault_also_rejects_export_over_itself(self):
        path = self.directory / 'legacy-vault.json'
        vault = KeyVault(path, ENDPOINT, 'demo_alice')
        vault.unlock(OFFLINE_PASSWORD, create=True)
        self.addCleanup(vault.lock)
        original = path.read_bytes()
        with self.assertRaisesRegex(VaultError, '不能覆盖'):
            vault.export_to(path)
        self.assertEqual(path.read_bytes(), original)
        restored = KeyVault(None, ENDPOINT, 'demo_alice')
        self.addCleanup(restored.lock)
        self.assertEqual(vault.identity.fingerprint,
                         restored.import_from(path, OFFLINE_PASSWORD).fingerprint)


if __name__ == '__main__':
    unittest.main()
