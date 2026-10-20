"""Opaque storage, immutable identities and fail-closed Python routing."""
import base64
from contextlib import closing
from copy import deepcopy
import json
import os
import threading
import unittest
from unittest.mock import Mock, patch

from chatroom_client.e2ee_crypto import Identity, encrypt_message, decrypt_message, publish_proof
import e2ee_server
import test_regressions as regression


class PythonE2EETests(unittest.TestCase):
    setUpClass = classmethod(regression.ServerTests.setUpClass.__func__)
    tearDownClass = classmethod(regression.ServerTests.tearDownClass.__func__)
    tearDown = regression.ServerTests.tearDown
    connect = regression.ServerTests.connect
    read_type = regression.ServerTests.read_type

    def setUp(self):
        regression.ServerTests.setUp(self)
        self.identities = {name: Identity.generate() for name in ('alice', 'bob', 'carol')}
        self.server.save_friend_relationship('alice', 'bob')
        self.server.user_friends.update(alice={'bob'}, bob={'alice'}, carol=set())

    def publish(self, *names):
        for name in names:
            identity = self.identities[name]
            e2ee_server.publish_identity(name, identity.public_bundle(), publish_proof(identity, name))

    def envelope(self, kind='private', target='bob', members=('alice', 'bob'), sender='alice'):
        return encrypt_message(self.identities[sender], sender, kind, target, '只允许收件人读取 secret-e2ee-body',
                               {name: self.identities[name].public_bundle() for name in members})

    def key_request(self, username, kind, target):
        events = []
        with patch.object(self.server, 'send_msg', side_effect=lambda peer, message: events.append(message)):
            self.server.handle_e2ee_keys(Mock(), username,
                {'request_id': 'keys', 'kind': kind, 'target': target})
        return events[-1]

    def test_identity_binding_is_immutable_and_proof_is_account_bound(self):
        alice = self.identities['alice']
        with self.assertRaises(e2ee_server.E2EEError):
            e2ee_server.publish_identity('bob', alice.public_bundle(), publish_proof(alice, 'alice'))
        self.assertIsNone(e2ee_server.get_identity('bob'))
        self.publish('alice')
        self.publish('alice')
        replacement = Identity.generate()
        with self.assertRaisesRegex(e2ee_server.E2EEError, '原密钥'):
            e2ee_server.publish_identity('alice', replacement.public_bundle(), publish_proof(replacement, 'alice'))
        self.assertEqual(e2ee_server.get_identity('alice'), alice.public_bundle())
        with closing(self.server.storage.connect()) as db:
            token, sealed = db.execute('SELECT username,identity FROM e2ee_identities').fetchone()
            self.assertEqual(token, self.server.storage.token('alice'))
            self.assertNotIn(alice.public_bundle()['sign'], sealed)
            value = self.server.storage.open_field(sealed, 'e2ee_identities', 'identity', token)
            self.assertEqual(json.loads(value), alice.public_bundle())

    def test_low_order_identity_is_rejected_before_immutable_enrollment(self):
        invalid = self.identities['alice'].public_bundle()
        invalid['exchange'] = base64.b64encode(bytes(32)).decode('ascii')
        with self.assertRaises(e2ee_server.E2EEError):
            e2ee_server.publish_identity('alice', invalid, 'bad proof')
        self.assertIsNone(e2ee_server.get_identity('alice'))

    def test_two_concurrent_first_publications_never_replace_each_other(self):
        choices = [Identity.generate(), Identity.generate()]
        start = threading.Barrier(2)
        accepted, rejected = [], []

        def publish(choice):
            start.wait(5)
            try:
                accepted.append(e2ee_server.publish_identity('alice', choice.public_bundle(),
                                                            publish_proof(choice, 'alice')))
            except e2ee_server.E2EEError as error:
                rejected.append(error)

        workers = [threading.Thread(target=publish, args=(choice,)) for choice in choices]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(10)
            self.assertFalse(worker.is_alive())
        self.assertEqual((len(accepted), len(rejected)), (1, 1))
        self.assertEqual(e2ee_server.get_identity('alice'), accepted[0])

    def test_directory_requires_current_conversation_authorization_and_reports_missing(self):
        self.publish('alice')
        private = self.key_request('alice', 'private', 'bob')
        self.assertTrue(private['success'])
        self.assertEqual(private['members'], ['alice', 'bob'])
        self.assertEqual(private['missing'], ['bob'])
        self.assertEqual(set(private['identities']), {'alice'})
        for username, target in (('alice', 'carol'), ('alice', 'alice'), ('carol', 'bob')):
            self.assertFalse(self.key_request(username, 'private', target)['success'])
        gid = self.server.create_group_db('alice', 'Team', ['alice', 'bob'])
        self.assertFalse(self.key_request('carol', 'group', gid)['success'])
        self.assertTrue(self.key_request('alice', 'group', gid)['success'])
        self.server.update_group_members_db(gid, ['bob'])
        self.assertFalse(self.key_request('alice', 'group', gid)['success'])

    def test_envelope_rejects_tamper_routing_and_stale_recipient_keys(self):
        self.publish('alice', 'bob', 'carol')
        envelope = self.envelope()
        self.assertEqual(e2ee_server.validate_envelope(envelope, 'alice', 'private', 'bob',
                                                     ['alice', 'bob']), envelope)
        changes = [('body', 'AA=='), ('signature', 'AA=='), ('target', 'carol'),
                   ('sender', 'carol'), ('v', True), ('unexpected', 'extra')]
        for field, value in changes:
            with self.subTest(field=field):
                changed = deepcopy(envelope)
                changed[field] = value
                with self.assertRaises(e2ee_server.E2EEError):
                    e2ee_server.validate_envelope(changed, 'alice', 'private', 'bob', ['alice', 'bob'])
        changed = deepcopy(envelope)
        changed['recipients']['bob'] = self.identities['carol'].fingerprint
        with self.assertRaises(e2ee_server.E2EEError):
            e2ee_server.validate_envelope(changed, 'alice', 'private', 'bob', ['alice', 'bob'])

    def test_group_envelope_must_match_current_exact_membership(self):
        self.publish('alice', 'bob', 'carol')
        envelope = self.envelope('group', 'group-id')
        self.assertEqual(e2ee_server.validate_envelope(envelope, 'alice', 'group', 'group-id',
                                                     ['bob', 'alice']), envelope)
        for members in (['alice'], ['alice', 'bob', 'carol']):
            with self.assertRaises(e2ee_server.E2EEError):
                e2ee_server.validate_envelope(envelope, 'alice', 'group', 'group-id', members)

    def test_legacy_sends_are_rejected_when_any_participant_enrolled(self):
        key = os.urandom(16)
        request = {'content': self.server.encrypt_message('legacy text', key)}
        result, encrypted = self.server.prepare_chat_content(request, 'alice', 'private', 'bob',
                                                             ['alice', 'bob'], key, 'now')
        self.assertEqual((result, encrypted), ('legacy text', False))
        self.publish('bob')
        with self.assertRaisesRegex(e2ee_server.E2EEError, '拒绝发送'):
            self.server.prepare_chat_content(request, 'alice', 'private', 'bob',
                                             ['alice', 'bob'], key, 'now')
        with self.assertRaises(e2ee_server.E2EEError):
            self.server.prepare_chat_content(request, 'alice', 'group', 'g',
                                             ['alice', 'bob', 'carol'], key, 'now')

    def test_opaque_storage_history_and_sync_never_decrypt_or_reencrypt_bodies(self):
        self.publish('alice', 'bob')
        envelope = self.envelope()
        key, sock, events = os.urandom(16), Mock(), []
        with patch.object(self.server, 'decrypt_message', side_effect=AssertionError('server must not decrypt')):
            content, encrypted = self.server.prepare_chat_content({'e2ee': envelope}, 'alice', 'private',
                                                                 'bob', ['alice', 'bob'], key, 'now')
        message_id = self.server.save_message('private', 'alice', 'bob', None, content, 'now', e2ee=encrypted)
        with closing(self.server.storage.connect()) as db:
            row = db.execute('SELECT id,chat_type,from_user,to_user,gid,message,timestamp,e2ee FROM messages').fetchone()
            decoded = self.server.storage.decode_message(db, row)
            self.assertEqual(decoded[-1], 1)
            self.assertEqual(json.loads(decoded[5]), envelope)
            self.assertNotIn('secret-e2ee-body', decoded[5])
        self.server.session_keys[sock] = key
        try:
            with patch.object(self.server, 'encrypt_message', side_effect=AssertionError('server must not reencrypt')), \
                    patch.object(self.server, 'send_msg', side_effect=lambda peer, event: events.append(event)):
                self.server.send_history(sock, 'alice')
                self.server.send_sync(sock, 'alice', {'request_id': 'recover', 'after_id': 0})
        finally:
            self.server.session_keys.pop(sock)
        frames = [event for event in events if event['type'] == 'private_chat']
        self.assertEqual(len(frames), 2)
        for frame in frames:
            self.assertEqual(frame['message_id'], message_id)
            self.assertEqual(frame['e2ee'], envelope)
            self.assertNotIn('content', frame)
            self.assertEqual(frame['encryption'], 'e2ee_v1')
            self.assertEqual(decrypt_message(self.identities['bob'], 'bob', frame['e2ee'],
                             expected_sender='alice', expected_kind='private', expected_target='bob',
                             pinned_sender_bundle=self.identities['alice'].public_bundle()),
                             '只允许收件人读取 secret-e2ee-body')

    def test_live_private_delivery_never_calls_server_body_crypto(self):
        self.publish('alice', 'bob')
        alice, _, result = self.connect('alice')
        self.assertTrue(result['success'])
        bob, _, result = self.connect('bob')
        self.assertTrue(result['success'])
        self.read_type(bob, 'online_users')
        envelope = self.envelope()
        with patch.object(self.server, 'decrypt_message', side_effect=AssertionError('body decrypt forbidden')), \
                patch.object(self.server, 'encrypt_message', side_effect=AssertionError('body encrypt forbidden')):
            regression.client.send_msg(alice, {'type': 'private_chat', 'to': 'bob',
                                               'request_id': 'live', 'e2ee': envelope})
            receipt = self.read_type(alice, 'private_chat_result')
            self.assertTrue(receipt['success'], receipt)
            delivered = self.read_type(bob, 'private_chat')
            echo = self.read_type(alice, 'private_chat')
        for frame in (delivered, echo):
            self.assertEqual(frame['e2ee'], envelope)
            self.assertEqual(frame['message_id'], receipt['message_id'])
            self.assertIs(frame['history'], False)
            self.assertNotIn('content', frame)

    def test_legacy_text_that_looks_like_an_envelope_remains_legacy(self):
        text = json.dumps(self.envelope())
        self.server.save_message('private', 'alice', 'bob', None, text, 'now')
        sock, events, key = Mock(), [], os.urandom(16)
        self.server.session_keys[sock] = key
        try:
            with patch.object(self.server, 'send_msg', side_effect=lambda peer, event: events.append(event)):
                self.server.send_history(sock, 'bob')
        finally:
            self.server.session_keys.pop(sock)
        frame = events[1]
        self.assertEqual(frame['encryption'], 'legacy')
        self.assertNotIn('e2ee', frame)
        self.assertEqual(self.server.decrypt_message(frame['content'], key), text)

    def test_authenticated_login_exposes_own_existing_public_identity_only(self):
        self.publish('alice')
        _, _, result = self.connect('alice')
        self.assertTrue(result['success'])
        self.assertEqual(result['e2ee_identity'], self.identities['alice'].public_bundle())
        _, _, result = self.connect('bob')
        self.assertTrue(result['success'])
        self.assertIsNone(result['e2ee_identity'])


if __name__ == '__main__':
    unittest.main()
