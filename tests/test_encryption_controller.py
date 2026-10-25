"""Fail-closed client trust, recipient approval, and asynchronous send contracts."""
from copy import deepcopy
from pathlib import Path
import queue
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from chatroom_client.app import ChatApplication
from chatroom_client.connection import AuthResult, ServerEvent
from chatroom_client.e2ee_crypto import Identity, decrypt_message, encrypt_message
from chatroom_client.encryption import EncryptionController
from chatroom_client.events import ServerEvents
from chatroom_client.key_vault import KeyVault, vault_path
from chatroom_client.models import ChatKey, ClientState
from chatroom_client.preferences import PreferencesStore
from chatroom_client.protocol import encrypt_message as encrypt_legacy


PASSPHRASE = 'a separate local encryption secret'


class FakeView:
    def __init__(self):
        self.text = 'private plaintext which must remain on the client'
        self.passphrase = PASSPHRASE
        self.notifications = []
        self.scheduled = []
        self.confirmations = []
        self.confirm = True
        self.on_confirm = None
        self.username_entry = SimpleNamespace(get=lambda: 'alice')

    def input_text(self):
        return self.text

    def encryption_passphrase(self):
        return self.passphrase

    def notify(self, title, text):
        self.notifications.append((title, text))

    def schedule(self, delay, callback):
        self.scheduled.append((delay, callback))

    def refresh_controls(self):
        pass

    def refresh_encryption(self):
        pass

    def read_port(self):
        return 12345

    def confirm_encryption_roster(self, gid, identities, previous):
        self.confirmations.append((gid, deepcopy(identities), deepcopy(previous)))
        if self.on_confirm is not None:
            self.on_confirm()
        return self.confirm


class EncryptionControllerTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = ('127.0.0.1', 12345)
        self.view = FakeView()
        self.state = ClientState(username='alice')
        self.state.current_chat = ChatKey('private', 'bob')
        self.sent, self.lookups = [], []
        self.app = SimpleNamespace(
            view=self.view, state=self.state, preferences=PreferencesStore(persistent=False),
            connection=SimpleNamespace(sock=object(), running=True, auth_busy=False,
                                       session_key=b's' * 16,
                                       is_login_password=lambda candidate: candidate == 'account-password',
                                       settings=SimpleNamespace(host=self.endpoint[0], port=self.endpoint[1])),
            sync=SimpleNamespace(active=False), reconnecting=False, closing=False,
            queue_send=lambda data: self.lookups.append(deepcopy(data)),
        )

        def send(data, text):
            self.sent.append((deepcopy(data), text))
            self.state.pending_messages[data['request_id']] = text

        self.app.send_chat_payload = send
        self.controller = EncryptionController(self.app)
        self.app.encryption = self.controller
        self.vault = KeyVault(None, self.endpoint, 'alice')
        self.vault.unlock(PASSPHRASE, create=True)
        self.addCleanup(self.vault.lock)
        self.controller.vault = self.vault
        self.controller.ready = True
        self.bob, self.carol = Identity.generate(), Identity.generate()

    def directory_reply(self, *, bundles=None, **changes):
        request = self.lookups[-1]
        bundles = bundles or {'alice': self.vault.identity.public_bundle(), 'bob': self.bob.public_bundle()}
        reply = {'type': 'e2ee_keys', 'request_id': request['request_id'], 'success': True,
                 'kind': request['kind'], 'target': request['target'],
                 'members': sorted(bundles), 'identities': bundles, 'missing': []}
        reply.update(changes)
        return reply

    def private_message(self, *, identity=None, message_id=1, envelope_id=None, text='a secret from bob'):
        identity = identity or self.bob
        envelope = encrypt_message(identity, 'bob', 'private', 'alice', text,
                                   {'alice': self.vault.identity.public_bundle(), 'bob': identity.public_bundle()},
                                   message_id=envelope_id)
        return {'type': 'private_chat', 'from': 'bob', 'to': 'alice', 'e2ee': envelope,
                'message_id': message_id, 'history': False}

    def group_message(self, *, message_id=1, envelope_id=None, members=None, text='a group secret'):
        members = members or {'alice': self.vault.identity.public_bundle(), 'bob': self.bob.public_bundle()}
        envelope = encrypt_message(self.bob, 'bob', 'group', 'g1', text, members, message_id=envelope_id)
        return {'type': 'group_chat', 'from': 'bob', 'gid': 'g1', 'e2ee': envelope,
                'message_id': message_id, 'history': False}

    def test_directory_response_encrypts_once_and_never_contains_plaintext(self):
        self.controller.send_message(self.view.text, self.state.current_chat)
        reply = self.directory_reply()
        self.controller.handle(reply)
        self.controller.handle(reply)
        self.assertEqual(len(self.sent), 1)
        data, plaintext = self.sent[0]
        self.assertNotIn('content', data)
        self.assertNotIn(plaintext, str(data))
        self.assertEqual(decrypt_message(self.bob, 'bob', data['e2ee'],
                                        expected_sender='alice', expected_kind='private',
                                        expected_target='bob',
                                        pinned_sender_bundle=self.vault.identity.public_bundle()), plaintext)
        self.assertFalse(self.controller.sending)

    def test_changed_draft_selection_and_socket_never_send_delayed_lookup(self):
        original_key, original_sock, original_text = self.state.current_chat, self.app.connection.sock, self.view.text
        for changed in ('draft', 'selection', 'socket'):
            with self.subTest(changed=changed):
                self.state.current_chat, self.app.connection.sock, self.view.text = original_key, original_sock, original_text
                self.controller.send_message(original_text, original_key)
                reply = self.directory_reply()
                if changed == 'draft':
                    self.view.text += ' edited'
                elif changed == 'selection':
                    self.state.current_chat = ChatKey('private', 'carol')
                else:
                    self.app.connection.sock = object()
                self.controller.handle(reply)
                self.assertFalse(self.sent)
                if changed == 'socket':
                    self.controller.pause()
                    self.controller.ready = True

    def test_missing_and_changed_recipient_keys_fail_without_encrypting(self):
        self.controller.send_message(self.view.text, self.state.current_chat)
        self.controller.handle(self.directory_reply(missing=['bob']))
        self.assertFalse(self.sent)
        self.vault.pin_peer('bob', self.bob.public_bundle(), verified=True)
        changed = Identity.generate().public_bundle()
        self.controller.send_message(self.view.text, self.state.current_chat)
        self.controller.handle(self.directory_reply(bundles={'alice': self.vault.identity.public_bundle(), 'bob': changed}))
        self.assertFalse(self.sent)
        self.assertEqual(self.controller.peer_change('bob'), changed)
        self.assertEqual(self.vault.peer('bob'), self.bob.public_bundle())

    def test_lookup_timeout_keeps_draft_and_publication_is_correlated(self):
        self.controller.send_message(self.view.text, self.state.current_chat)
        self.view.scheduled[-1][1]()
        self.assertFalse(self.controller.sending)
        self.assertFalse(self.sent)
        result = AuthResult(1, 'alice', False, self.endpoint, self.app.connection.sock,
                            b's' * 16, None, False, ('e2ee_v1',), self.vault)
        self.controller.establish(result)
        request_id = self.lookups[-1]['request_id']
        self.controller.handle({'type': 'e2ee_identity_result', 'request_id': 'stale',
                                'success': True, 'identity': self.vault.identity.public_bundle()})
        self.assertFalse(self.controller.ready)
        self.controller.handle({'type': 'e2ee_identity_result', 'request_id': request_id,
                                'success': True, 'identity': self.vault.identity.public_bundle()})
        self.assertTrue(self.controller.ready)

    def test_group_review_approves_recipient_set_without_sending_a_message(self):
        key = self.state.current_chat = ChatKey('group', 'g1')
        self.state.groups['g1'] = {'members': ['alice', 'bob']}
        self.assertTrue(self.controller.review_group(key))
        self.controller.handle(self.directory_reply())
        self.assertEqual(len(self.view.confirmations), 1)
        self.assertTrue(self.vault.is_roster_approved('g1', {'alice': self.vault.identity.public_bundle(),
                                                          'bob': self.bob.public_bundle()}))
        self.assertFalse(self.sent)
        self.assertFalse(self.state.pending_messages)

    def test_group_decline_and_context_change_do_not_send(self):
        key = self.state.current_chat = ChatKey('group', 'g1')
        self.state.groups['g1'] = {'members': ['alice', 'bob']}
        self.view.confirm = False
        self.controller.send_message(self.view.text, key)
        self.controller.handle(self.directory_reply())
        self.assertFalse(self.sent)
        self.assertIsNone(self.vault.approved_roster('g1'))
        self.view.confirm = True
        self.view.on_confirm = lambda: setattr(self.view, 'text', 'changed during confirmation')
        self.controller.send_message(self.view.text, key)
        self.controller.handle(self.directory_reply())
        self.assertFalse(self.sent)
        self.assertIsNone(self.vault.approved_roster('g1'))

    def test_group_rejoin_invalidates_a_pending_recipient_lookup(self):
        key = self.state.current_chat = ChatKey('group', 'g1')
        self.state.groups['g1'] = {'members': ['alice', 'bob']}
        self.controller.send_message(self.view.text, key)
        reply = self.directory_reply()
        self.state.remove_group('g1')
        self.state.groups['g1'] = {'members': ['alice', 'bob']}
        self.state.current_chat = key
        self.controller.handle(reply)
        self.assertFalse(self.sent)
        self.assertFalse(self.view.confirmations)
        self.assertIsNone(self.vault.approved_roster('g1'))
        self.assertIsNone(self.vault.peer('bob'))
        self.assertFalse(self.controller.sending)

    def test_group_rejoin_during_outgoing_confirmation_cannot_send_or_approve(self):
        key = self.state.current_chat = ChatKey('group', 'g1')
        self.state.groups['g1'] = {'members': ['alice', 'bob']}

        def rejoin():
            self.state.remove_group('g1')
            self.state.groups['g1'] = {'members': ['alice', 'bob']}
            self.state.current_chat = key

        self.view.on_confirm = rejoin
        self.controller.send_message(self.view.text, key)
        self.controller.handle(self.directory_reply())
        self.assertEqual(len(self.view.confirmations), 1)
        self.assertFalse(self.sent)
        self.assertIsNone(self.vault.approved_roster('g1'))
        self.assertIsNone(self.vault.peer('bob'))
        self.assertFalse(self.controller.sending)

    def test_private_decryption_pins_only_a_verified_envelope(self):
        wire = self.private_message()
        corrupted = deepcopy(wire)
        corrupted['e2ee']['body'] = corrupted['e2ee']['body'][:-4] + 'AAAA'
        self.assertEqual(self.controller.decode_message(corrupted)[1], 'failed')
        self.assertIsNone(self.vault.peer('bob'))
        self.assertEqual(self.controller.decode_message(wire), ('a secret from bob', 'e2ee'))
        self.assertEqual(self.vault.peer('bob'), self.bob.public_bundle())
        rebound = deepcopy(wire)
        rebound['from'] = 'mallory'
        self.assertEqual(self.controller.decode_message(rebound)[1], 'failed')

    def message_events(self):
        self.state.friends = ['bob']
        for name in ('append_message', 'render_conversation', 'remove_conversation',
                     'clear_selection', 'refresh_groups'):
            setattr(self.view, name, Mock())
        self.app.activity = Mock()
        self.app.request_group_info = Mock()
        return ServerEvents(self.app)

    def test_verified_retry_replaces_failed_message_without_duplicate_row_or_activity(self):
        events = self.message_events()
        wire = self.private_message()
        corrupted = deepcopy(wire)
        corrupted['e2ee']['body'] = corrupted['e2ee']['body'][:-4] + 'AAAA'
        events.chat_message(corrupted)
        conversation = self.state.conversation(self.state.current_chat)
        self.assertEqual(conversation.messages[0].encryption, 'failed')

        retry = dict(wire, history=True)
        events.chat_message(retry)
        self.assertEqual(len(conversation.messages), 1)
        self.assertEqual(conversation.messages[0].content, 'a secret from bob')
        self.assertEqual(conversation.messages[0].encryption, 'e2ee')
        self.view.append_message.assert_called_once()
        self.view.render_conversation.assert_called_once_with(self.state.current_chat)
        self.app.activity.receive.assert_called_once()
        self.app.activity.refresh.assert_called_once()

        # Neither another history copy nor a later invalid frame may overwrite
        # the verified message or introduce another notification / display row.
        events.chat_message(retry)
        events.chat_message(corrupted)
        self.assertEqual(conversation.messages[0].encryption, 'e2ee')
        self.view.append_message.assert_called_once()
        self.view.render_conversation.assert_called_once()
        self.app.activity.receive.assert_called_once()

    def test_changed_peer_message_recovers_after_explicit_key_acceptance(self):
        events = self.message_events()
        self.vault.pin_peer('bob', self.bob.public_bundle())
        wire = self.private_message(identity=self.carol)
        events.chat_message(wire)
        conversation = self.state.conversation(self.state.current_chat)
        self.assertEqual(conversation.messages[0].encryption, 'failed')
        self.controller.accept_peer('bob', self.carol.public_bundle())
        events.chat_message(dict(wire, history=True))
        self.assertEqual(len(conversation.messages), 1)
        self.assertEqual(conversation.messages[0].content, 'a secret from bob')
        self.assertEqual(conversation.messages[0].encryption, 'e2ee')

    def test_group_removal_during_roster_dialog_does_not_restore_conversation_or_trust(self):
        events = self.message_events()
        key = self.state.current_chat = ChatKey('group', 'g1')
        self.state.groups['g1'] = {'members': ['alice', 'bob']}
        self.state.conversation(key)
        # Tk's modal dialog runs a nested event loop: a removal notification
        # can be handled before the original message handler resumes.
        self.view.on_confirm = lambda: events.remove_group('g1')
        events.chat_message(self.group_message())
        self.assertNotIn(key, self.state.conversations)
        self.assertNotIn('g1', self.state.groups)
        self.assertIsNone(self.vault.approved_roster('g1'))
        self.assertIsNone(self.vault.peer('bob'))
        self.app.activity.receive.assert_not_called()
        self.app.request_group_info.assert_not_called()

    def test_rejoin_during_roster_dialog_cannot_accept_old_membership_confirmation(self):
        events = self.message_events()
        key = self.state.current_chat = ChatKey('group', 'g1')
        self.state.groups['g1'] = {'members': ['alice', 'bob']}

        def rejoin():
            events.remove_group('g1')
            self.state.groups['g1'] = {'members': ['alice', 'bob']}

        self.view.on_confirm = rejoin
        events.chat_message(self.group_message())
        self.assertIn('g1', self.state.groups)
        self.assertNotIn(key, self.state.conversations)
        self.assertIsNone(self.vault.approved_roster('g1'))
        self.assertIsNone(self.vault.peer('bob'))
        self.app.activity.receive.assert_not_called()

    def test_account_switch_during_roster_dialog_does_not_repopulate_reset_session(self):
        events = self.message_events()
        self.state.groups['g1'] = {'members': ['alice', 'bob']}
        self.view.on_confirm = lambda: self.state.reset_session('carol')
        events.chat_message(self.group_message())
        self.assertEqual(self.state.username, 'carol')
        self.assertFalse(self.state.conversations)
        self.assertIsNone(self.vault.approved_roster('g1'))
        self.assertIsNone(self.vault.peer('bob'))
        self.app.request_group_info.assert_not_called()

    def test_canceled_old_roster_dialog_does_not_block_rejoined_group(self):
        events = self.message_events()
        key = ChatKey('group', 'g1')
        self.state.groups['g1'] = {'members': ['alice', 'bob']}

        def rejoin():
            events.remove_group('g1')
            self.state.groups['g1'] = {'members': ['alice', 'bob']}

        self.view.confirm = False
        self.view.on_confirm = rejoin
        events.chat_message(self.group_message())
        self.assertNotIn(key, self.state.conversations)
        self.view.on_confirm = None
        self.view.confirm = True
        events.chat_message(self.group_message(message_id=2))
        self.assertEqual(self.state.conversation(key).messages[0].encryption, 'e2ee')
        self.assertEqual(len(self.view.confirmations), 2)

    def test_replacement_socket_during_roster_dialog_cannot_deliver_old_message(self):
        events = self.message_events()
        self.state.groups['g1'] = {'members': ['alice', 'bob']}
        self.view.on_confirm = lambda: setattr(self.app.connection, 'sock', object())
        events.chat_message(self.group_message())
        self.assertFalse(self.state.conversations)
        self.assertIsNone(self.vault.approved_roster('g1'))
        self.app.activity.receive.assert_not_called()

    def test_signed_envelope_replay_under_new_server_id_is_suppressed(self):
        wire = self.private_message()
        self.assertEqual(self.controller.decode_message(wire)[1], 'e2ee')
        wire['message_id'] += 1
        self.assertIsNone(self.controller.decode_message(wire))

    def test_legacy_content_is_visible_only_as_explicit_historical_legacy(self):
        wire = {'type': 'private_chat', 'from': 'bob', 'to': 'alice', 'history': False,
                'content': encrypt_legacy('legacy plaintext', self.app.connection.session_key)}
        self.assertEqual(self.controller.decode_message(wire)[1], 'failed')
        wire['history'] = True
        self.assertEqual(self.controller.decode_message(wire), ('legacy plaintext', 'legacy'))
        wire.pop('history')
        self.state.history_syncing = True
        self.assertEqual(self.controller.decode_message(wire)[1], 'legacy')
        wire['history'] = False
        self.assertEqual(self.controller.decode_message(wire)[1], 'failed')

    def test_group_first_receive_requires_approval_before_displaying_plaintext(self):
        self.state.groups['g1'] = {'members': ['alice', 'bob']}
        result = self.controller.decode_message(self.group_message())
        self.assertEqual(result, ('a group secret', 'e2ee'))
        self.assertEqual(len(self.view.confirmations), 1)
        self.assertEqual(self.controller.decode_message(self.group_message(message_id=2))[1], 'e2ee')
        self.assertEqual(len(self.view.confirmations), 1)

    def test_group_denial_is_cached_per_group_not_per_attacker_roster(self):
        self.state.groups['g1'] = {'members': ['alice', 'bob']}
        self.view.confirm = False
        first = self.controller.decode_message(self.group_message())
        added = {'alice': self.vault.identity.public_bundle(), 'bob': self.bob.public_bundle(),
                 'carol': self.carol.public_bundle()}
        second = self.controller.decode_message(self.group_message(message_id=2, members=added))
        self.assertEqual((first[1], second[1]), ('failed', 'failed'))
        self.assertNotIn('a group secret', first[0] + second[0])
        self.assertEqual(len(self.view.confirmations), 1)
        self.assertIsNone(self.vault.peer('bob'))
        self.assertEqual(self.controller.decode_message(self.group_message(message_id=3))[1], 'failed')
        self.assertEqual(len(self.view.confirmations), 1)

    def test_unknown_group_never_opens_a_confirmation_dialog(self):
        result = self.controller.decode_message(self.group_message())
        self.assertEqual(result[1], 'failed')
        self.assertFalse(self.view.confirmations)
        self.assertIsNone(self.vault.peer('bob'))

    def test_group_context_change_during_approval_does_not_decrypt_or_pin(self):
        self.state.groups['g1'] = {'members': ['alice', 'bob']}
        self.view.on_confirm = lambda: setattr(self.app.connection, 'sock', object())
        result = self.controller.decode_message(self.group_message())
        self.assertEqual(result[1], 'failed')
        self.assertIsNone(self.vault.peer('bob'))
        self.assertIsNone(self.vault.approved_roster('g1'))

    def test_archived_group_roster_only_accepts_identical_previously_seen_messages(self):
        abc = {'alice': self.vault.identity.public_bundle(), 'bob': self.bob.public_bundle(),
               'carol': self.carol.public_bundle()}
        ac = {'alice': self.vault.identity.public_bundle(), 'carol': self.carol.public_bundle()}
        self.state.groups['g1'] = {'members': list(abc)}
        self.vault.approve_roster('g1', abc)
        old = self.group_message(members=abc)
        self.assertEqual(self.controller.decode_message(old)[1], 'e2ee')
        self.vault.approve_roster('g1', ac)
        self.assertEqual(self.controller.decode_message(old)[1], 'e2ee')
        forged = self.group_message(message_id=2, members=abc)
        self.assertEqual(self.controller.decode_message(forged)[1], 'failed')
        rewritten = self.group_message(members=abc, envelope_id=old['e2ee']['id'], text='forged replacement')
        self.assertEqual(self.controller.decode_message(rewritten)[1], 'failed')
        self.assertFalse(self.view.confirmations, 'an archived roster was silently proposed for reactivation')

    def test_retired_peer_key_needs_the_original_envelope_digest(self):
        old = self.private_message()
        self.assertEqual(self.controller.decode_message(old)[1], 'e2ee')
        new_bob = Identity.generate()
        self.vault.pin_peer('bob', new_bob.public_bundle(), replace=True, verified=True)
        self.assertEqual(self.controller.decode_message(old)[1], 'e2ee')
        unseen = self.private_message(message_id=2)
        self.assertEqual(self.controller.decode_message(unseen)[1], 'failed')
        rewritten = self.private_message(envelope_id=old['e2ee']['id'], text='forged replacement')
        result = self.controller.decode_message(rewritten)
        self.assertEqual(result[1], 'failed')
        self.assertNotIn('forged replacement', result[0])

    def test_stale_vault_and_revocation_during_decrypt_cannot_release_plaintext(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'vault.json'
            first = KeyVault(path, self.endpoint, 'alice')
            first.unlock(PASSPHRASE, create=True)
            self.addCleanup(first.lock)
            self.controller.vault = self.vault = first
            first.pin_peer('bob', self.bob.public_bundle(), verified=True)
            second = KeyVault(path, self.endpoint, 'alice')
            second.unlock(PASSPHRASE)
            self.addCleanup(second.lock)
            new_bob = Identity.generate()
            wire = self.private_message()

            def revoke_after_decrypt(*args, **kwargs):
                plaintext = decrypt_message(*args, **kwargs)
                second.pin_peer('bob', new_bob.public_bundle(), replace=True, verified=True)
                return plaintext

            with patch('chatroom_client.encryption.decrypt_message', side_effect=revoke_after_decrypt):
                result = self.controller.decode_message(wire)
            self.assertEqual(result[1], 'failed')
            self.assertNotIn('a secret from bob', result[0])
            # A previously opened second snapshot must also reject a new UUID
            # from the replaced key, even before its next ordinary metadata save.
            result = self.controller.decode_message(self.private_message(message_id=2))
            self.assertEqual(result[1], 'failed')

    def test_stale_outgoing_roster_cannot_release_a_removed_members_wrapped_key(self):
        with TemporaryDirectory() as directory:
            first = KeyVault(Path(directory) / 'vault.json', self.endpoint, 'alice')
            first.unlock(PASSPHRASE, create=True)
            self.addCleanup(first.lock)
            self.controller.vault = self.vault = first
            abc = {'alice': first.identity.public_bundle(), 'bob': self.bob.public_bundle(),
                   'carol': self.carol.public_bundle()}
            first.approve_roster('g1', abc)
            old_snapshot = first.approved_roster('g1')
            second = KeyVault(first.path, self.endpoint, 'alice')
            second.unlock(PASSPHRASE)
            self.addCleanup(second.lock)
            ac = {'alice': first.identity.public_bundle(), 'carol': self.carol.public_bundle()}
            second.approve_roster('g1', ac)
            self.state.current_chat = ChatKey('group', 'g1')
            self.state.groups['g1'] = {'members': list(abc)}
            self.controller.send_message(self.view.text, self.state.current_chat)
            with patch.object(first, 'approved_roster', return_value=old_snapshot):
                self.controller.handle(self.directory_reply(bundles=abc))
            self.assertFalse(self.sent)
            self.assertFalse(self.view.confirmations)
            self.assertTrue(second.is_roster_approved('g1', ac))

    def test_outgoing_confirmation_cannot_overwrite_a_concurrent_membership_change(self):
        with TemporaryDirectory() as directory:
            first = KeyVault(Path(directory) / 'vault.json', self.endpoint, 'alice')
            first.unlock(PASSPHRASE, create=True)
            self.addCleanup(first.lock)
            self.controller.vault = self.vault = first
            ab = {'alice': first.identity.public_bundle(), 'bob': self.bob.public_bundle()}
            abc = dict(ab, carol=self.carol.public_bundle())
            ac = {'alice': first.identity.public_bundle(), 'carol': self.carol.public_bundle()}
            first.approve_roster('g1', ab)
            second = KeyVault(first.path, self.endpoint, 'alice')
            second.unlock(PASSPHRASE)
            self.addCleanup(second.lock)
            self.state.current_chat = ChatKey('group', 'g1')
            self.state.groups['g1'] = {'members': list(abc)}
            self.view.on_confirm = lambda: second.approve_roster('g1', ac)
            self.controller.send_message(self.view.text, self.state.current_chat)
            self.controller.handle(self.directory_reply(bundles=abc))
            self.assertEqual(len(self.view.confirmations), 1)
            self.assertFalse(self.sent)
            self.assertEqual(first.approved_roster('g1'), second.approved_roster('g1'))

    def test_incoming_confirmation_cannot_overwrite_a_concurrent_membership_change(self):
        with TemporaryDirectory() as directory:
            first = KeyVault(Path(directory) / 'vault.json', self.endpoint, 'alice')
            first.unlock(PASSPHRASE, create=True)
            self.addCleanup(first.lock)
            self.controller.vault = self.vault = first
            ab = {'alice': first.identity.public_bundle(), 'bob': self.bob.public_bundle()}
            abc = dict(ab, carol=self.carol.public_bundle())
            ac = {'alice': first.identity.public_bundle(), 'carol': self.carol.public_bundle()}
            first.approve_roster('g1', ab)
            second = KeyVault(first.path, self.endpoint, 'alice')
            second.unlock(PASSPHRASE)
            self.addCleanup(second.lock)
            self.state.groups['g1'] = {'members': list(abc)}
            self.view.on_confirm = lambda: second.approve_roster('g1', ac)
            result = self.controller.decode_message(self.group_message(members=abc))
            self.assertEqual(result[1], 'failed')
            self.assertNotIn('a group secret', result[0])
            self.assertEqual(first.approved_roster('g1'), second.approved_roster('g1'))

    def test_auth_preparation_preserves_identity_after_passphrase_change(self):
        preparation = self.controller.prepare_login('alice', 'account-password', self.endpoint)
        self.assertNotIn(PASSPHRASE, repr(preparation))
        vault = preparation(self.vault.identity.public_bundle())
        ChatApplication.change_encryption_passphrase(self.app, 'a new independent local vault password')
        self.assertIs(preparation(vault.identity.public_bundle()), vault)
        self.assertIsNone(preparation.passphrase)
        self.view.passphrase = 'account-password'
        with self.assertRaises(ValueError):
            self.controller.prepare_login('alice', 'account-password', self.endpoint)

    def test_changing_local_passphrase_to_account_password_preserves_existing_vault(self):
        fingerprint = self.vault.identity.fingerprint
        with self.assertRaisesRegex(ValueError, '必须与账号密码不同'):
            ChatApplication.change_encryption_passphrase(self.app, 'account-password')
        self.vault.lock()
        self.assertEqual(self.vault.unlock(PASSPHRASE).fingerprint, fingerprint)

    def test_missing_local_vault_does_not_generate_over_an_existing_remote_identity(self):
        with TemporaryDirectory() as directory:
            self.app.preferences.path = Path(directory) / 'client.json'
            self.controller.vault = None
            preparation = self.controller.prepare_login('alice', 'account-password', self.endpoint)
            with self.assertRaisesRegex(ValueError, '导入'):
                preparation(self.bob.public_bundle())
            self.assertFalse(vault_path(self.app.preferences.path, self.endpoint, 'alice').exists())

    def test_import_wrapper_forwards_explicit_rebind_and_replacement_flags(self):
        with patch.object(self.controller, 'import_keys', return_value='fingerprint') as operation:
            result = ChatApplication.import_encryption_keys(self.app, 'backup.json', PASSPHRASE,
                                                            allow_rebind=True, replace=True)
        self.assertEqual(result, 'fingerprint')
        operation.assert_called_once_with('backup.json', PASSPHRASE, 'alice', self.endpoint,
                                          replace=True, allow_rebind=True)

    def test_slow_encrypted_events_yield_to_tk_without_losing_queued_messages(self):
        events = self.app.connection.events = queue.Queue()
        for number in range(10):
            events.put(ServerEvent(self.app.connection.sock, {'number': number}))
        received, clock = [], [0.0]

        def handle(message):
            received.append(message['number'])
            clock[0] += .025

        self.app.handle_server_message = handle
        self.app.notifier = SimpleNamespace(poll=lambda: 0)
        self.app.drain_incoming = lambda: None
        with patch('chatroom_client.app.time.monotonic', side_effect=lambda: clock[0]):
            ChatApplication.drain_incoming(self.app)
        self.assertEqual(received, [0])
        self.assertEqual(events.qsize(), 9)
        self.assertEqual(self.view.scheduled[-1][0], 50)


if __name__ == '__main__':
    unittest.main()
