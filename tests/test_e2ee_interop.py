"""Client-only plaintext across both real servers, history, groups and Tk."""
from copy import deepcopy
import gc
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

import client
from chatroom_client.e2ee_crypto import (
    E2EEError, Identity, decrypt_message, encrypt_message, publish_proof,
)
from chatroom_client.models import ChatKey
from chatroom_client.preferences import PreferencesStore, ServerProfile
from test_system_reliability import PASSWORD, Service


class EncryptedScenarios:
    def setUp(self):
        self.service = Service(self.backend)
        self.addCleanup(self.service.close)
        self.service.start()
        self.counter = 0
        self.identities = {name: Identity.generate() for name in ('alice', 'bob', 'carol')}
        for name in self.identities:
            self.service.connect(name, register=True)
        self.peers = {name: self.service.connect(name) for name in self.identities}
        self.friend('alice', 'bob')
        self.friend('alice', 'carol')

    def friend(self, first, second):
        a, b = self.peers[first], self.peers[second]
        self.assertTrue(a.request({'type': 'friend_request', 'to': second}, 'friend_request_result')['success'])
        b.wait(lambda event: event.get('type') == 'friend_request' and event.get('from') == first)
        b.send({'type': 'friend_response', 'to': first, 'accepted': True})
        a.wait(lambda event: event.get('type') == 'friend_update' and event.get('friend') == second)
        b.wait(lambda event: event.get('type') == 'friend_update' and event.get('friend') == first)

    def request(self, peer, value, response):
        self.counter += 1
        if value.get('type') in ('e2ee_identity_publish', 'e2ee_keys_request', 'private_chat', 'group_chat', 'sync_request'):
            value = dict(value, request_id=f'e2ee-{self.counter}')
        return peer.request(value, response)

    def publish(self, name):
        identity = self.identities[name]
        result = self.request(self.peers[name], {'type': 'e2ee_identity_publish',
                              'identity': identity.public_bundle(), 'proof': publish_proof(identity, name)},
                              'e2ee_identity_result')
        self.assertTrue(result['success'], result)
        self.assertEqual(result['identity'], identity.public_bundle())

    def directory(self, name, kind, target):
        result = self.request(self.peers[name], {'type': 'e2ee_keys_request', 'kind': kind, 'target': target}, 'e2ee_keys')
        self.assertTrue(result['success'], result)
        self.assertEqual(result['missing'], [])
        return result['identities']

    def send(self, name, kind, target, plaintext, *, recipients=None):
        recipients = recipients or self.directory(name, kind, target)
        envelope = encrypt_message(self.identities[name], name, kind, target, plaintext, recipients)
        result = self.request(self.peers[name], {'type': kind + '_chat',
                              'gid' if kind == 'group' else 'to': target, 'e2ee': envelope}, kind + '_chat_result')
        return result, envelope

    def decrypt(self, name, event):
        self.assertNotIn('content', event, 'server mixed transport plaintext into an encrypted frame')
        envelope = event['e2ee']
        return decrypt_message(self.identities[name], name, envelope, expected_sender=event['from'],
                               expected_kind='group' if event['type'] == 'group_chat' else 'private',
                               expected_target=event.get('gid', event.get('to')),
                               pinned_sender_bundle=self.identities[event['from']].public_bundle())

    def test_private_offline_pages_restart_and_server_key_cannot_read(self):
        for name in self.identities:
            self.publish(name)
        recipients = self.directory('alice', 'private', 'bob')
        self.peers['bob'].close()
        self.peers['alice'].wait(lambda event: event.get('type') == 'online_users' and 'bob' not in event.get('users', []))
        expected = {}
        for number in range(205):
            plaintext = f'only clients may read this private secret {number} 中文🙂'
            result, envelope = self.send('alice', 'private', 'bob', plaintext, recipients=recipients)
            self.assertTrue(result['success'], result)
            expected[result['message_id']] = plaintext
            with self.assertRaises((ValueError, KeyError, TypeError)):
                client.decrypt_message(envelope['body'], self.peers['alice'].key)
        # Opening the storage encryption layer gives the operator only the
        # client envelope, never the plaintext or per-message content key.
        rows = self.service.database()
        self.assertEqual(set(rows), set(expected))
        for message_id, row in rows.items():
            self.assertNotIn(expected[message_id], row[5])
            self.assertEqual(json.loads(row[5])['sender'], 'alice')
        self.service.stop(kill=True)
        self.service.start()
        bob = self.service.connect('bob')
        self.peers['bob'] = bob
        after_id, boundary, received, sizes = 0, None, {}, []
        while True:
            after = len(bob.events)
            query = {'type': 'sync_request', 'after_id': after_id}
            if boundary is not None:
                query['boundary'] = boundary
            result = self.request(bob, query, 'sync_end')
            boundary = result['boundary']
            events = [event for event in bob.events[after:] if event.get('type') == 'private_chat']
            sizes.append(len(events))
            for event in events:
                self.assertTrue(event['history'])
                self.assertTrue(event['sync'])
                received[event['message_id']] = self.decrypt('bob', event)
            after_id = result['next_after_id']
            if not result['has_more']:
                break
        self.assertEqual(sizes, [100, 100, 5])
        self.assertEqual(received, expected)
        history = self.service.history(bob, 'private', 'alice')
        self.assertEqual({event['message_id']: self.decrypt('bob', event) for event in history}, expected)
        identity = self.request(bob, {'type': 'e2ee_identity_publish',
                                'identity': self.identities['bob'].public_bundle(),
                                'proof': publish_proof(self.identities['bob'], 'bob')}, 'e2ee_identity_result')
        self.assertTrue(identity['success'], 'identity did not survive process restart')
        for path in self.service.path.glob('*.log'):
            self.assertNotIn('only clients may read this private secret', path.read_text(encoding='utf-8'))

    def test_identity_substitution_tampering_and_plaintext_downgrade_fail(self):
        for name in self.identities:
            self.publish(name)
        impostor = Identity.generate()
        result = self.request(self.peers['alice'], {'type': 'e2ee_identity_publish',
                              'identity': impostor.public_bundle(), 'proof': publish_proof(impostor, 'alice')},
                              'e2ee_identity_result')
        self.assertFalse(result['success'], 'server replaced a published identity')
        unauthorized = self.request(self.peers['bob'], {'type': 'e2ee_keys_request', 'kind': 'private', 'target': 'carol'}, 'e2ee_keys')
        self.assertFalse(unauthorized['success'])
        recipients = self.directory('alice', 'private', 'bob')
        recipients['bob'] = impostor.public_bundle()
        result, _ = self.send('alice', 'private', 'bob', 'wrong directory key', recipients=recipients)
        self.assertFalse(result['success'])
        recipients = self.directory('alice', 'private', 'bob')
        envelope = encrypt_message(self.identities['alice'], 'alice', 'private', 'bob', 'tamper target', recipients)
        damaged = deepcopy(envelope)
        damaged['body'] = ('A' if damaged['body'][0] != 'A' else 'B') + damaged['body'][1:]
        result = self.request(self.peers['alice'], {'type': 'private_chat', 'to': 'bob', 'e2ee': damaged}, 'private_chat_result')
        self.assertFalse(result['success'])
        result = self.request(self.peers['alice'], {'type': 'private_chat', 'to': 'bob',
                              'content': client.encrypt_message('never downgrade', self.peers['alice'].key)}, 'private_chat_result')
        self.assertFalse(result['success'])
        self.assertEqual(self.service.database(), {}, 'invalid/downgraded messages reached storage')

    def test_group_add_remove_uses_exact_current_recipients(self):
        for name in self.identities:
            self.publish(name)
        alice, bob, carol = (self.peers[name] for name in ('alice', 'bob', 'carol'))
        created = self.request(alice, {'type': 'group_create', 'group_name': '加密群', 'members': ['bob']}, 'group_create_result')
        self.assertTrue(created['success'], created)
        gid = created['gid']
        original = self.directory('alice', 'group', gid)
        result, old_envelope = self.send('alice', 'group', gid, 'before carol joined', recipients=original)
        self.assertTrue(result['success'], result)
        self.assertTrue(self.request(alice, {'type': 'group_invite', 'gid': gid, 'to': 'carol'}, 'group_invite_result')['success'])
        self.assertTrue(self.request(carol, {'type': 'group_join', 'gid': gid}, 'group_join_result')['success'])
        result, _ = self.send('alice', 'group', gid, 'stale group roster', recipients=original)
        self.assertFalse(result['success'])
        result, envelope = self.send('alice', 'group', gid, 'all three current members')
        self.assertTrue(result['success'], result)
        delivered = carol.wait(lambda event: event.get('message_id') == result['message_id'] and event.get('type') == 'group_chat')
        self.assertEqual(self.decrypt('carol', delivered), 'all three current members')
        with self.assertRaises(E2EEError):
            decrypt_message(self.identities['carol'], 'carol', old_envelope,
                            pinned_sender_bundle=self.identities['alice'].public_bundle())
        before_kick = self.directory('alice', 'group', gid)
        self.assertTrue(self.request(alice, {'type': 'group_kick', 'gid': gid, 'kick': 'bob'}, 'group_kick_result')['success'])
        result, _ = self.send('alice', 'group', gid, 'removed bob must not receive', recipients=before_kick)
        self.assertFalse(result['success'])
        result, envelope = self.send('alice', 'group', gid, 'alice and carol only')
        self.assertTrue(result['success'], result)
        self.assertNotIn('bob', envelope['recipients'])
        with self.assertRaises(E2EEError):
            decrypt_message(self.identities['bob'], 'bob', envelope,
                            pinned_sender_bundle=self.identities['alice'].public_bundle())

    @unittest.skipUnless(os.environ.get('CHATROOM_GO_SERVER_EXE'), 'Go binary not selected')
    def test_database_and_public_identities_move_between_python_and_go(self):
        self.publish('alice')
        self.publish('bob')
        result, original = self.send('alice', 'private', 'bob', 'ciphertext before backend migration 中文🙂')
        self.assertTrue(result['success'], result)
        message_id = result['message_id']
        self.service.stop(kill=True)
        self.service.backend = 'go' if self.backend == 'python' else 'python'
        if self.service.backend == 'go':
            self.service.port = 12346
        self.service.start()
        self.peers['bob'] = self.service.connect('bob')
        self.peers['alice'] = self.service.connect('alice')
        history = self.service.history(self.peers['bob'], 'private', 'alice')
        event = next(item for item in history if item.get('message_id') == message_id)
        self.assertEqual(event['e2ee'], original)
        self.assertEqual(self.decrypt('bob', event), 'ciphertext before backend migration 中文🙂')
        self.assertEqual(self.directory('alice', 'private', 'bob'),
                         {name: self.identities[name].public_bundle() for name in ('alice', 'bob')})
        result, _ = self.send('bob', 'private', 'alice', 'new ciphertext after migration')
        self.assertTrue(result['success'], result)
        reply = self.peers['alice'].wait(lambda item: item.get('type') == 'private_chat' and
                                        item.get('message_id') == result['message_id'])
        self.assertEqual(self.decrypt('alice', reply), 'new ciphertext after migration')

    def test_real_tk_client_encrypts_verifies_and_reconnects_with_same_keys(self):
        self.publish('bob')
        self.publish('carol')
        alice, bob = self.peers['alice'], self.peers['bob']
        alice.close()
        bob.wait(lambda event: event.get('type') == 'online_users' and 'alice' not in event.get('users', []))
        with tempfile.TemporaryDirectory(prefix='chatroom-e2ee-gui-') as directory:
            profile = ServerProfile('Encrypted test', '127.0.0.1', self.service.port, self.service.fingerprint)
            preferences = PreferencesStore(Path(directory) / 'client.json', default_profile=profile)
            root = client.tk.Tk()
            root.withdraw()
            app = client.ChatClient(root, preferences=preferences)

            def pump(predicate, timeout=20):
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    root.update()
                    if predicate():
                        return
                    time.sleep(.005)
                self.fail('encrypted Tk client did not reach expected state: ' + self.service.log_path.read_text(encoding='utf-8')[-3000:])

            try:
                app.view.username_entry.insert(0, 'alice')
                app.view.password_entry.insert(0, PASSWORD)
                app.view.encryption_entry.insert(0, 'separate local vault passphrase')
                app.login()
                pump(lambda: app.connection.running and app.encryption.ready and 'bob' in app.state.friends)
                fingerprint = app.encryption.fingerprint
                self.identities['alice'] = app.encryption.vault.identity
                key = ChatKey('private', 'bob')
                app.select_chat(key)
                app.view.msg_entry.insert('1.0', 'encrypted GUI secret 中文🙂')
                app.send_message()
                # The GUI event pump drives async key lookup and encryption.
                pump(lambda: bool(app.state.conversation(key).messages) and not app.state.pending_messages)
                event = bob.wait(lambda event: event.get('type') == 'private_chat')
                self.assertEqual(self.decrypt('bob', event), 'encrypted GUI secret 中文🙂')
                self.assertEqual(app.state.conversation(key).messages[-1].encryption, 'e2ee')
                self.assertEqual(app.view.input_text(), '')
                self.assertEqual(app.encryption.peers()[0]['username'], 'bob')
                result, _ = self.send('bob', 'private', 'alice', 'verified reply from bob')
                self.assertTrue(result['success'], result)
                pump(lambda: any(item.content == 'verified reply from bob' for item in app.state.conversation(key).messages))
                self.service.stop(kill=True)
                pump(lambda: app.reconnecting)
                app.view.msg_entry.insert('1.0', 'draft stays private')
                self.service.start()
                pump(lambda: app.connection.running and not app.reconnecting and app.encryption.ready and not app.sync.active and not app.sync.awaiting_initial)
                self.assertEqual(app.encryption.fingerprint, fingerprint)
                self.assertEqual(app.view.input_text(), 'draft stays private')
            finally:
                app.close()
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        if not root.winfo_exists():
                            break
                        root.update()
                    except client.tk.TclError:
                        break
                    time.sleep(.005)
                gc.collect()


class PythonEncryptedTests(EncryptedScenarios, unittest.TestCase):
    backend = 'python'


@unittest.skipUnless(os.environ.get('CHATROOM_GO_SERVER_EXE'), 'Go binary not selected')
class GoEncryptedTests(EncryptedScenarios, unittest.TestCase):
    backend = 'go'


if __name__ == '__main__':
    unittest.main(verbosity=2)
