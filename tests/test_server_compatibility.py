"""Legacy text and imported RSA identities survive Python/Go backend changes."""
import base64
import os
import stat
import unittest

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

import client
from test_system_reliability import Service


class CompatibilityScenarios:
    def setUp(self):
        self.service = Service(self.backend)
        self.addCleanup(self.service.close)

    def switch_backend(self):
        self.service.stop()
        self.service.backend = 'go' if self.service.backend == 'python' else 'python'
        if self.service.backend == 'go':
            self.service.port = 12346
        self.service.start()

    @unittest.skipUnless(os.environ.get('CHATROOM_GO_SERVER_EXE'), 'Go binary not selected')
    def test_invalid_utf8_cannot_poison_cross_backend_history(self):
        self.service.start()
        for name in ('alice', 'bob'):
            self.service.connect(name, register=True)
        alice, bob = (self.service.connect(name) for name in ('alice', 'bob'))
        result = alice.request({'type': 'friend_request', 'to': 'bob'}, 'friend_request_result')
        self.assertTrue(result['success'], result)
        bob.send({'type': 'friend_response', 'to': 'alice', 'accepted': True})
        alice.wait(lambda event: event.get('type') == 'friend_update')
        bob.wait(lambda event: event.get('type') == 'friend_update')
        group = alice.request({'type': 'group_create', 'group_name': 'UTF-8 回归',
                               'members': ['bob']}, 'group_create_result')
        self.assertTrue(group['success'], group)

        # The ciphertext authenticates successfully; only the decoded text is invalid.
        for number, raw in enumerate((b'\xff\xfe\x80', b'\xc0\xaf', b'\xed\xa0\x80',
                                      b'\xf4\x90\x80\x80', b'truncated \xe4\xbd')):
            cipher = AES.new(alice.key, AES.MODE_GCM, nonce=os.urandom(16))
            encrypted, tag = cipher.encrypt_and_digest(raw)
            content = base64.b64encode(cipher.nonce + encrypted + tag).decode('ascii')
            for kind, field, target in (('private', 'to', 'bob'), ('group', 'gid', group['gid'])):
                with self.subTest(kind=kind, raw=raw):
                    result = alice.request({'type': kind + '_chat', field: target,
                                            'request_id': f'invalid-{kind}-{number}',
                                            'content': content}, kind + '_chat_result')
                    self.assertFalse(result['success'], result)
                    self.assertNotIn('message_id', result)
        self.assertEqual(self.service.database(), {})

        expected = {}
        for kind, field, target in (('private', 'to', 'bob'), ('group', 'gid', group['gid'])):
            text = f'{kind}: 合法文本🙂 replacement \ufffd null\x00byte'
            result = alice.request({'type': kind + '_chat', field: target,
                                    'request_id': 'valid-' + kind,
                                    'content': client.encrypt_message(text, alice.key)}, kind + '_chat_result')
            self.assertTrue(result['success'], result)
            expected[result['message_id']] = text
        bob.wait_messages(set(expected))
        deliveries = [event for event in bob.events if event.get('type') in ('private_chat', 'group_chat')]
        self.assertEqual(len(deliveries), len(expected), 'invalid plaintext was forwarded')
        self.assertEqual({event['message_id']: client.decrypt_message(event['content'], bob.key)
                          for event in deliveries}, expected)
        self.assertEqual({mid: row[5] for mid, row in self.service.database().items()}, expected)

        self.switch_backend()
        bob = self.service.connect('bob')  # Includes successful initial history loading.
        history = self.service.history(bob, 'private', 'alice')
        history += self.service.history(bob, 'group', group['gid'])
        self.assertEqual({event['message_id']: client.decrypt_message(event['content'], bob.key)
                          for event in history}, expected)
        self.assertEqual({mid: row[5] for mid, row in self.service.database().items()}, expected)

    @unittest.skipUnless(os.environ.get('CHATROOM_GO_SERVER_EXE'), 'Go binary not selected')
    def test_pkcs8_identity_is_preserved_across_backends(self):
        key = RSA.generate(2048)
        private = key.export_key(pkcs=8)
        public = key.publickey().export_key()
        private_path = self.service.path / 'private_key.pem'
        public_path = self.service.path / 'public_key.pem'
        private_path.write_bytes(private)
        public_path.write_bytes(public)
        private_path.chmod(0o644)
        self.service.start()
        self.service.connect('alice', register=True)
        self.service.connect('alice')
        self.assertEqual(private_path.read_bytes(), private)
        self.assertEqual(public_path.read_bytes(), public)
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(private_path.stat().st_mode), 0o600)

        self.service.stop()
        private_path.chmod(0o644)
        self.switch_backend()
        self.service.connect('alice')  # The fixture checks the original public fingerprint.
        self.assertEqual(private_path.read_bytes(), private)
        self.assertEqual(public_path.read_bytes(), public)
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(private_path.stat().st_mode), 0o600)


class PythonCompatibilityTests(CompatibilityScenarios, unittest.TestCase):
    backend = 'python'


@unittest.skipUnless(os.environ.get('CHATROOM_GO_SERVER_EXE'), 'Go binary not selected')
class GoCompatibilityTests(CompatibilityScenarios, unittest.TestCase):
    backend = 'go'


if __name__ == '__main__':
    unittest.main()
