"""Password authentication preserves identities and local trust across upgrades."""
import base64
from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from chatroom_client.connection import ClientSettings, ConnectionManager
from chatroom_client.e2ee_crypto import Identity
from chatroom_client.encryption import _VaultPreparation
from chatroom_client.key_vault import KeyVault, VaultError


SERVER_ID = 'a' * 64
EXPORT = base64.b64encode(b'e' * 64).decode()
NEXT_EXPORT = base64.b64encode(b'n' * 64).decode()
ENDPOINT = ('server.test', 12345)
PASSWORD = 'synthetic-unified-password'
OLD_LOCAL = 'synthetic-old-local-secret'


class SinglePasswordVaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'vault.json'
        self.vault = KeyVault(self.path, ENDPOINT, 'alice')
        self.vault.unlock_opaque(EXPORT, SERVER_ID, create=True)
        self.addCleanup(self.vault.lock)
        self.identity = self.vault.identity
        self.bob = Identity.generate()
        self.vault.pin_peer('bob', self.bob.public_bundle(), verified=True)
        self.vault.approve_roster('group', {'alice': self.identity.public_bundle(), 'bob': self.bob.public_bundle()})
        self.vault.observe_envelope(self.bob.fingerprint, 'b' * 32, 7, envelope_digest='c' * 64)

    def assert_trust(self, vault):
        self.assertEqual(vault.identity.fingerprint, self.identity.fingerprint)
        self.assertTrue(vault.is_verified('bob'))
        self.assertIsNotNone(vault.approved_roster('group'))
        self.assertEqual(vault.known_envelope(self.bob.fingerprint, 'b' * 32), 7)

    def test_local_state_and_cloud_backup_are_encrypted_and_separate(self):
        document = json.loads(self.path.read_bytes())
        backup = self.vault.opaque_backup(EXPORT, SERVER_ID)
        self.assertEqual(document['v'], 2)
        self.assertEqual(set(backup), {'v', 'kind', 'server_id', 'username', 'salt', 'nonce', 'data'})
        encoded = json.dumps(backup)
        for private in self.identity.export_private().values():
            if not isinstance(private, str):
                continue
            self.assertNotIn(private, encoded)
            self.assertNotIn(private.encode(), self.path.read_bytes())
        other = KeyVault(None, ('another-device.test', 4444), 'alice')
        other.unlock_opaque(EXPORT, SERVER_ID, backup=backup, remote_identity=self.identity.public_bundle())
        self.addCleanup(other.lock)
        self.assertEqual(other.identity.fingerprint, self.identity.fingerprint)
        self.assertEqual(other.peer_records, [])
        self.assertIsNone(other.approved_roster('group'))

    def test_remote_password_change_recovers_identity_and_preserves_local_trust(self):
        backup = self.vault.opaque_backup(NEXT_EXPORT, SERVER_ID)
        self.vault.lock()
        reopened = KeyVault(self.path, ENDPOINT, 'alice')
        reopened.unlock_opaque(NEXT_EXPORT, SERVER_ID, backup=backup,
                               remote_identity=self.identity.public_bundle())
        self.addCleanup(reopened.lock)
        self.assert_trust(reopened)
        reopened.lock()
        with self.assertRaises(VaultError):
            KeyVault(self.path, ENDPOINT, 'alice').unlock_opaque(EXPORT, SERVER_ID)
        reopened.unlock_opaque(NEXT_EXPORT, SERVER_ID)
        self.assert_trust(reopened)

    def test_wrong_backup_or_damaged_local_trust_never_replaces_file(self):
        stranger = KeyVault(None, ENDPOINT, 'alice')
        stranger.unlock_opaque(NEXT_EXPORT, SERVER_ID, create=True)
        self.addCleanup(stranger.lock)
        wrong = stranger.opaque_backup(NEXT_EXPORT, SERVER_ID)
        original = self.path.read_bytes()
        self.vault.lock()
        with self.assertRaises(VaultError):
            KeyVault(self.path, ENDPOINT, 'alice').unlock_opaque(NEXT_EXPORT, SERVER_ID, backup=wrong)
        self.assertEqual(self.path.read_bytes(), original)
        document = json.loads(original)
        body = bytearray(base64.b64decode(document['data']))
        body[0] ^= 1
        document['data'] = base64.b64encode(body).decode()
        self.path.write_text(json.dumps(document))
        damaged = self.path.read_bytes()
        with self.assertRaises(VaultError):
            KeyVault(self.path, ENDPOINT, 'alice').unlock_opaque(EXPORT, SERVER_ID)
        self.assertEqual(self.path.read_bytes(), damaged)

    def test_local_password_rewrap_preserves_trust_and_offline_backup_is_password_based(self):
        self.vault.rewrap_opaque(NEXT_EXPORT, SERVER_ID)
        self.assert_trust(self.vault)
        backup = Path(self.temp.name) / 'offline.json'
        self.vault.export_to(backup, PASSWORD)
        self.assertEqual(json.loads(backup.read_bytes())['v'], 1)
        imported = KeyVault(None, ENDPOINT, 'alice')
        imported.import_from(backup, PASSWORD)
        self.addCleanup(imported.lock)
        self.assert_trust(imported)
        imported.unlock_opaque(NEXT_EXPORT, SERVER_ID, remote_identity=self.identity.public_bundle())
        self.assert_trust(imported)
        with self.assertRaises(VaultError):
            self.vault.export_to(Path(self.temp.name) / 'ambiguous.json')

    def test_backup_is_bound_to_account_and_server(self):
        backup = self.vault.opaque_backup(EXPORT, SERVER_ID)
        for username, server_id in [('bob', SERVER_ID), ('alice', 'd' * 64)]:
            with self.subTest(username=username, server_id=server_id), self.assertRaises(VaultError):
                KeyVault(None, ENDPOINT, username).unlock_opaque(EXPORT, server_id, backup=backup)

    def test_legacy_migration_is_staged_until_server_commit(self):
        oldpath = Path(self.temp.name) / 'legacy.json'
        old = KeyVault(oldpath, ENDPOINT, 'alice')
        old.unlock(OLD_LOCAL, create=True)
        old.pin_peer('bob', self.bob.public_bundle(), verified=True)
        identity = old.identity
        old.lock()
        original = oldpath.read_bytes()
        preparation = _VaultPreparation(oldpath, ENDPOINT, 'alice', OLD_LOCAL)
        staged = preparation(identity.public_bundle(), export_key=EXPORT, server_id=SERVER_ID,
                             registration=True)
        self.addCleanup(staged.lock)
        self.assertEqual(oldpath.read_bytes(), original)
        self.assertEqual(staged.identity.fingerprint, identity.fingerprint)
        self.assertTrue(staged.is_verified('bob'))
        preparation.commit()
        self.assertEqual(json.loads(oldpath.read_bytes())['v'], 2)
        reopened = KeyVault(oldpath, ENDPOINT, 'alice')
        reopened.unlock_opaque(EXPORT, SERVER_ID)
        self.addCleanup(reopened.lock)
        self.assertTrue(reopened.is_verified('bob'))
        self.assertEqual(reopened.identity.fingerprint, identity.fingerprint)

    def test_aborted_migration_can_unlock_old_file_after_remote_commit(self):
        oldpath = Path(self.temp.name) / 'legacy.json'
        old = KeyVault(oldpath, ENDPOINT, 'alice')
        old.unlock(OLD_LOCAL, create=True)
        old.pin_peer('bob', self.bob.public_bundle(), verified=True)
        identity = old.identity
        old.lock()
        original = oldpath.read_bytes()
        preparation = _VaultPreparation(oldpath, ENDPOINT, 'alice', OLD_LOCAL)
        staged = preparation(identity.public_bundle(), export_key=EXPORT, server_id=SERVER_ID,
                             registration=True)
        # The server accepted this encrypted identity, but its final response was lost.
        backup = staged.opaque_backup(EXPORT, SERVER_ID)
        preparation.abort()
        self.assertFalse(staged.unlocked)
        self.assertIsNone(staged._secret)
        self.assertIsNone(preparation.passphrase)
        self.assertEqual(oldpath.read_bytes(), original)
        ordinary = _VaultPreparation(oldpath, ENDPOINT, 'alice', None)
        with self.assertRaisesRegex(VaultError, '解锁旧密钥'):
            ordinary(identity.public_bundle(), export_key=EXPORT, server_id=SERVER_ID, backup=backup)
        recovered = _VaultPreparation(oldpath, ENDPOINT, 'alice', OLD_LOCAL)
        candidate = recovered(identity.public_bundle(), export_key=EXPORT, server_id=SERVER_ID, backup=backup)
        self.addCleanup(candidate.lock)
        self.assertEqual(candidate.identity.fingerprint, identity.fingerprint)
        self.assertTrue(candidate.is_verified('bob'))
        self.assertEqual(json.loads(oldpath.read_bytes())['v'], 2)

    def test_aborting_old_worker_does_not_lock_new_worker_or_source(self):
        before_prepare = _VaultPreparation(self.path, ENDPOINT, 'alice', None, self.vault)
        before_prepare.abort()
        self.assertTrue(self.vault.unlocked)
        backup = self.vault.opaque_backup(EXPORT, SERVER_ID)
        first = _VaultPreparation(self.path, ENDPOINT, 'alice', None, self.vault)
        second = _VaultPreparation(self.path, ENDPOINT, 'alice', None, self.vault)
        candidate1 = first(self.identity.public_bundle(), export_key=EXPORT, server_id=SERVER_ID, backup=backup)
        candidate2 = second(self.identity.public_bundle(), export_key=EXPORT, server_id=SERVER_ID, backup=backup)
        self.addCleanup(candidate2.lock)
        first.abort()
        self.assertFalse(candidate1.unlocked)
        self.assertTrue(candidate2.unlocked)
        self.assertTrue(self.vault.unlocked)
        self.assert_trust(candidate2)

    def test_wrong_legacy_secret_never_changes_original(self):
        oldpath = Path(self.temp.name) / 'legacy.json'
        old = KeyVault(oldpath, ENDPOINT, 'alice')
        identity = old.unlock(OLD_LOCAL, create=True)
        old.lock()
        original = oldpath.read_bytes()
        preparation = _VaultPreparation(oldpath, ENDPOINT, 'alice', 'synthetic-wrong-old-secret')
        with self.assertRaises(VaultError):
            preparation(identity.public_bundle(), export_key=EXPORT, server_id=SERVER_ID, registration=True)
        self.assertEqual(oldpath.read_bytes(), original)


class SinglePasswordFailClosedTests(unittest.TestCase):
    def test_modern_client_never_sends_password_to_legacy_server(self):
        connection = ConnectionManager(ClientSettings())
        self.addCleanup(connection.close)
        sock = Mock()
        preparation = SimpleNamespace(single_password=True)
        with (patch('chatroom_client.connection.socket.socket', return_value=sock),
              patch('chatroom_client.connection.protocol.recv_msg', return_value={
                  'type': 'public_key', 'capabilities': ['e2ee_v1']}),
              patch('chatroom_client.connection.protocol.check_server_public_key', return_value=(Mock(), None)),
              patch('chatroom_client.connection.protocol.send_msg') as send,
              patch.object(connection, 'start_worker', side_effect=lambda target, *args: target(*args))):
            connection.authenticate('alice', PASSWORD, prepare=preparation)
        result = connection.events.get_nowait()
        connection.accept_auth(result)
        self.assertIsNotNone(result.error)
        self.assertFalse(connection.running)
        self.assertFalse(send.called)
        self.assertNotIn(PASSWORD, repr(result))


if __name__ == '__main__':
    unittest.main()
