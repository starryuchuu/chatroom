"""Real TCP OPAQUE lifecycle against the Python and optional Go servers."""
import base64
import hashlib
import json
import os
import socket
import unittest

import client
from chatroom_client.e2ee_crypto import Identity, publish_proof
import opaque_runtime
from test_opaque_server import backup
from test_system_reliability import PASSWORD as LEGACY_PASSWORD, Service


PASSWORD = 'wire synthetic unified password'
CHANGED_PASSWORD = 'changed wire synthetic password'


class WireScenarios:
    def setUp(self):
        self.service = Service(self.backend)
        self.addCleanup(self.service.close)
        self.service.start()
        self.sockets = []
        self.addCleanup(self.close_sockets)

    def close_sockets(self):
        for sock in self.sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
            client.transport.forget(sock)

    def connection(self):
        sock = socket.create_connection(('127.0.0.1', self.service.port), timeout=10)
        self.sockets.append(sock)
        public = client.recv_msg(sock)
        self.assertIn('opaque_v1', public['capabilities'])
        rsa = client.RSA.import_key(public['key'])
        fingerprint = hashlib.sha256(rsa.export_key(format='DER')).hexdigest()
        key = os.urandom(16)
        encrypted = client.PKCS1_OAEP.new(rsa).encrypt(key)
        client.send_msg(sock, {'type': 'session_key', 'protocol': client.transport.VERSION,
                               'key': base64.b64encode(encrypted).decode()})
        client.transport.configure(sock, key)
        return sock, key, fingerprint

    def register(self, username='alice', *, migrate=False):
        sock, key, server_id = self.connection()
        start = opaque_runtime.call({'op': 'registration_start', 'password': PASSWORD})
        packet = {'type': 'opaque_migrate_start' if migrate else 'opaque_register_start',
                  'from': username, 'request': start['request']}
        if migrate:
            packet['legacy_data'] = client.encrypt_message(json.dumps({'password': LEGACY_PASSWORD}), key)
        client.send_msg(sock, packet)
        challenge = client.recv_msg(sock)
        self.assertEqual(challenge['type'], 'opaque_migrate_challenge' if migrate else 'opaque_register_challenge')
        finish = opaque_runtime.call({'op': 'registration_finish', 'password': PASSWORD,
                                      'state': start['state'], 'response': challenge['response'],
                                      'username': username, 'server_id': server_id})
        encrypted_backup = backup(username, server_id)
        client.send_msg(sock, {'type': 'opaque_migrate_finish' if migrate else 'opaque_register_finish',
                               'record': finish['record'], 'backup': encrypted_backup})
        result = client.recv_msg(sock)
        self.assertTrue(result['success'], result)
        if not migrate:
            sock.close()
            client.transport.forget(sock)
        return sock, result, encrypted_backup

    def login(self, password=PASSWORD):
        sock, _, server_id = self.connection()
        start = opaque_runtime.call({'op': 'login_start', 'password': password})
        client.send_msg(sock, {'type': 'opaque_login_start', 'from': 'alice', 'request': start['request']})
        challenge = client.recv_msg(sock)
        if challenge['type'] != 'opaque_login_challenge':
            return sock, challenge
        try:
            finished = opaque_runtime.call({'op': 'login_finish', 'password': password,
                                           'state': start['state'], 'response': challenge['response'],
                                           'username': 'alice', 'server_id': server_id})
        except ValueError:
            sock.close()
            client.transport.forget(sock)
            return sock, {'success': False}
        client.send_msg(sock, {'type': 'opaque_login_finish', 'finalization': finished['finalization']})
        return sock, client.recv_msg(sock)

    def read_type(self, sock, kind):
        for _ in range(100):
            packet = client.recv_msg(sock)
            self.assertIsNotNone(packet)
            if packet['type'] == kind:
                return packet
        self.fail('Expected server event missing')

    def test_register_login_short_change_restart_and_legacy_rejection(self):
        _, _, original = self.register()
        online, result = self.login()
        self.assertTrue(result['success'])
        self.assertEqual(result['opaque_backup'], original)
        self.assertEqual(result['opaque_generation'], 1)
        self.assertIn('alice', self.read_type(online, 'online_users')['users'])

        # Password changes deliberately authenticate on a separate connection
        # without reserving a second online session for the same account.
        sock, _, server_id = self.connection()
        start = opaque_runtime.call({'op': 'login_start', 'password': PASSWORD})
        client.send_msg(sock, {'type': 'opaque_change_start', 'from': 'alice', 'request': start['request']})
        challenge = client.recv_msg(sock)
        self.assertEqual(challenge['type'], 'opaque_change_challenge')
        finish = opaque_runtime.call({'op': 'login_finish', 'password': PASSWORD,
                                     'state': start['state'], 'response': challenge['response'],
                                     'username': 'alice', 'server_id': server_id})
        client.send_msg(sock, {'type': 'opaque_change_finish', 'finalization': finish['finalization']})
        verified = client.recv_msg(sock)
        self.assertEqual(verified['type'], 'opaque_change_verified')
        self.assertEqual(verified['backup'], original)
        start = opaque_runtime.call({'op': 'registration_start', 'password': CHANGED_PASSWORD})
        client.send_msg(sock, {'type': 'opaque_change_register_start', 'request': start['request']})
        challenge = client.recv_msg(sock)
        finish = opaque_runtime.call({'op': 'registration_finish', 'password': CHANGED_PASSWORD,
                                     'state': start['state'], 'response': challenge['response'],
                                     'username': 'alice', 'server_id': server_id})
        replacement = backup(server_id=server_id)
        client.send_msg(sock, {'type': 'opaque_change_register_finish', 'record': finish['record'],
                               'backup': replacement, 'generation': verified['generation']})
        self.assertEqual(client.recv_msg(sock), {'type': 'opaque_change_result', 'success': True})
        client.send_msg(online, {'type': 'history_request', 'chat_type': 'private',
                                 'target': 'nobody', 'before_id': 1})
        self.assertTrue(self.read_type(online, 'history_error')['error'])
        self.close_sockets()
        self.sockets = []
        self.service.stop(kill=True)
        self.service.start()
        self.assertFalse(self.login(PASSWORD)[1]['success'])
        _, result = self.login(CHANGED_PASSWORD)
        self.assertTrue(result['success'])
        self.assertEqual(result['opaque_generation'], 2)
        self.assertEqual(result['opaque_backup'], replacement)

        legacy, key, _ = self.connection()
        client.send_msg(legacy, {'type': 'encrypted_login', 'data': client.encrypt_message(
            json.dumps({'from': 'alice', 'password': CHANGED_PASSWORD}), key)})
        self.assertFalse(client.recv_msg(legacy)['success'])
        log = self.service.log_path.read_text(encoding='utf-8')
        self.assertNotIn(PASSWORD, log)
        self.assertNotIn(CHANGED_PASSWORD, log)

    def test_explicit_legacy_migration_preserves_public_identity(self):
        self.service.connect('alice', register=True)
        legacy = self.service.connect('alice')
        identity = Identity.generate()
        result = legacy.request({'type': 'e2ee_identity_publish', 'request_id': 'original',
                                 'identity': identity.public_bundle(),
                                 'proof': publish_proof(identity, 'alice')}, 'e2ee_identity_result')
        self.assertTrue(result['success'])
        legacy.close()
        # Probe the explicit migration-required response without disclosing any
        # new password to the legacy authentication path.
        _, probe = self.login()
        self.assertTrue(probe['migration_required'])
        sock, migrated, original = self.register(migrate=True)
        self.assertEqual(migrated['e2ee_identity'], identity.public_bundle())
        self.assertEqual(migrated['opaque_backup'], original)
        self.assertEqual(migrated['opaque_generation'], 1)
        self.read_type(sock, 'online_users')
        self.assertNotIn(PASSWORD, self.service.log_path.read_text(encoding='utf-8'))


class PythonOpaqueWireTests(WireScenarios, unittest.TestCase):
    backend = 'python'


@unittest.skipUnless(os.environ.get('CHATROOM_GO_SERVER_EXE'), 'Go binary not selected')
class GoOpaqueWireTests(WireScenarios, unittest.TestCase):
    backend = 'go'
