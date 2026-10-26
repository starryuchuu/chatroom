"""An idempotent retry must retain its ciphertext without bypassing trust."""
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

import test_regressions as regression
from chatroom_client.e2ee_crypto import Identity, encrypt_message
from chatroom_client.encryption import EncryptionController
from chatroom_client.key_vault import KeyVault
from chatroom_client.models import ChatKey


class EncryptedSendRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.app = regression.headless_client(self)
        self.app.state.username = 'alice'
        self.app.state.current_chat = ChatKey('private', 'bob')
        self.app.connection.endpoint = ('synthetic-server', 12345)
        self.app.connection.session_key = b's' * 16
        self.app.connection.capabilities = ('message_receipts',)
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.vault = KeyVault(Path(self.temp.name) / 'vault.json', self.app.connection.endpoint, 'alice')
        self.vault.unlock('Synthetic local passphrase', create=True)
        self.bob = Identity.generate()
        self.bundles = {'alice': self.vault.identity.public_bundle(), 'bob': self.bob.public_bundle()}
        self.vault.pin_peers(self.bundles)
        self.app.encryption = EncryptionController(self.app)
        self.app.encryption.vault = self.vault
        self.app.encryption.ready = True
        self.addCleanup(self.vault.lock)

    def pending_retry(self, *, group=False):
        key = self.app.state.current_chat
        if group:
            key = self.app.state.current_chat = ChatKey('group', 'g')
            self.app.state.groups['g'] = {'members': list(self.bundles)}
            self.vault.approve_roster('g', self.bundles)
        envelope = encrypt_message(self.vault.identity, 'alice', key.kind, key.target,
                                   'Synthetic secret', self.bundles)
        self.app.send_chat_payload({'type': key.kind + '_chat', 'request_id': 'original-request',
                                   'gid' if group else 'to': key.target, 'e2ee': envelope}, 'Synthetic secret')
        record = self.app.sends.records[0]
        self.app.sends.expire(self.app.connection.sock, record.request_id)
        self.app.sends.handle({'type': 'message_status_result', 'request_id': record.query,
                              'idempotency_key': record.payload['idempotency_key'],
                              'chat_type': key.kind, 'target': key.target,
                              'success': True, 'status': 'not_found'})
        self.assertEqual(record.status, 'retry')
        self.app.connection.send.reset_mock()
        return record

    def other_vault(self):
        other = KeyVault(self.vault.path, self.app.connection.endpoint, 'alice')
        other.unlock('Synthetic local passphrase')
        self.addCleanup(other.lock)
        return other

    def assert_blocked(self, record):
        original = deepcopy(record.payload)
        self.app.sends.recover(record)
        self.app.connection.send.assert_not_called()
        self.assertEqual(record.payload, original)
        self.assertEqual(record.status, 'retry')
        self.assertFalse(self.app.state.pending_messages)

    def test_retry_blocks_unready_encryption_and_locked_vault(self):
        record = self.pending_retry()
        self.app.encryption.ready = False
        self.assert_blocked(record)
        self.app.encryption.ready = True
        self.vault.lock()
        self.assert_blocked(record)

    def test_retry_blocks_contact_key_replaced_by_another_instance(self):
        record = self.pending_retry()
        self.other_vault().pin_peer('bob', Identity.generate().public_bundle(), replace=True)
        self.assert_blocked(record)

    def test_retry_blocks_group_approval_changed_by_another_instance(self):
        record = self.pending_retry(group=True)
        self.other_vault().approve_roster('g', {'alice': self.bundles['alice']})
        self.assert_blocked(record)

    def test_retry_rechecks_trust_at_enqueue_and_keeps_original_envelope(self):
        record = self.pending_retry()
        original = deepcopy(record.payload)
        with patch.object(self.vault, 'send_guard', wraps=self.vault.send_guard) as guard:
            self.app.sends.recover(record)
            guard.assert_called_once()
        sent = self.app.connection.send.call_args.args[0]
        self.assertEqual(sent['e2ee'], original['e2ee'])
        self.assertEqual(sent['idempotency_key'], original['idempotency_key'])
        self.assertNotEqual(sent['request_id'], original['request_id'])
        self.assertEqual(record.status, 'sending')

    def test_retry_rejects_revocation_between_snapshot_and_guard(self):
        record = self.pending_retry()
        other = self.other_vault()
        guard = self.vault.send_guard

        def revoke_then_guard(*args, **kwargs):
            other.pin_peer('bob', Identity.generate().public_bundle(), replace=True)
            return guard(*args, **kwargs)

        with patch.object(self.vault, 'send_guard', side_effect=revoke_then_guard):
            self.assert_blocked(record)

    def test_group_retry_requires_exact_unchanged_approval(self):
        record = self.pending_retry(group=True)
        envelope = deepcopy(record.payload['e2ee'])
        self.app.sends.recover(record)
        self.assertEqual(record.status, 'sending')
        self.assertEqual(self.app.connection.send.call_args.args[0]['e2ee'], envelope)

    def test_failed_enqueue_preserves_retry_state_and_original_payload(self):
        record = self.pending_retry()
        original = deepcopy(record.payload)
        self.app.connection.send.side_effect = ConnectionError('Synthetic queue failure')
        self.app.sends.recover(record)
        self.assertEqual(record.payload, original)
        self.assertEqual(record.status, 'retry')
        self.assertFalse(self.app.state.pending_messages)

    def test_encrypted_client_rejects_retry_without_an_envelope(self):
        record = self.pending_retry()
        record.payload.pop('e2ee')
        record.payload['content'] = 'Synthetic legacy content'
        self.assert_blocked(record)
