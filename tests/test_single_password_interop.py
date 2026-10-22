"""Single-password registration, migration and recovery against both real servers."""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import time
import unittest

import client
from chatroom_client.connection import ClientSettings, ConnectionManager, PasswordChangeResult
from chatroom_client.e2ee_crypto import Identity, publish_proof
from chatroom_client.encryption import _VaultPreparation
from chatroom_client.key_vault import KeyVault
from opaque_runtime import call
from test_system_reliability import PASSWORD, Service


FIRST = 'synthetic-unified-password-one'
SECOND = 'synthetic-unified-password-two'


def encoded(size):
    return base64.b64encode(os.urandom(size)).decode('ascii')


class Wire:
    def __init__(self, service):
        self.sock = socket.create_connection(('127.0.0.1', service.port), timeout=30)
        public = client.recv_msg(self.sock)
        if 'opaque_v1' not in public.get('capabilities', []):
            self.close()
            raise AssertionError('server did not advertise single-password authentication')
        rsa = client.RSA.import_key(public['key'])
        self.server_id = hashlib.sha256(rsa.export_key(format='DER')).hexdigest()
        self.key = os.urandom(16)
        client.send_msg(self.sock, {'type': 'session_key', 'protocol': client.transport.VERSION,
            'key': base64.b64encode(client.PKCS1_OAEP.new(rsa).encrypt(self.key)).decode('ascii')})
        client.transport.configure(self.sock, self.key)

    def send(self, packet):
        client.send_msg(self.sock, packet)

    def receive(self, expected):
        response = client.recv_msg(self.sock)
        if not isinstance(response, dict) or response.get('type') != expected:
            raise AssertionError('Unexpected authentication response type')
        return response

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        client.transport.forget(self.sock)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def backup(self, username):
        # This wire-level test treats the client ciphertext as opaque. Actual
        # identity encryption and restore are covered by the vault tests.
        return {'v': 1, 'kind': 'opaque-identity', 'server_id': self.server_id,
                'username': username, 'salt': encoded(16), 'nonce': encoded(12),
                'data': encoded(48)}


class Scenarios:
    def setUp(self):
        self.service = Service(self.backend)
        self.addCleanup(self.service.close)
        self.service.start()

    def register(self, username, password=FIRST, *, migration=False, invalid=False):
        with Wire(self.service) as wire:
            start = call({'op': 'registration_start', 'password': password})
            mode = 'migrate' if migration else 'register'
            packet = {'type': 'opaque_' + mode + '_start', 'from': username,
                      'request': start['request']}
            if migration:
                packet['legacy_data'] = client.encrypt_message(json.dumps({'password': PASSWORD}), wire.key)
            wire.send(packet)
            challenge = wire.receive('opaque_' + mode + '_challenge')
            finish = call({'op': 'registration_finish', 'password': password,
                'state': start['state'], 'response': challenge['response'],
                'username': username, 'server_id': wire.server_id})
            backup = wire.backup(username)
            wire.send({'type': 'opaque_' + mode + '_finish',
                       'record': 'invalid-record' if invalid else finish['record'],
                       'backup': backup})
            result = wire.receive('login_result' if migration else 'register_result')
            return finish, backup, result, challenge

    def login(self, username, password=FIRST):
        wire = Wire(self.service)
        try:
            start = call({'op': 'login_start', 'password': password})
            wire.send({'type': 'opaque_login_start', 'from': username, 'request': start['request']})
            challenge = wire.receive('opaque_login_challenge')
            finish = call({'op': 'login_finish', 'password': password, 'state': start['state'],
                'response': challenge['response'], 'username': username, 'server_id': wire.server_id})
            wire.send({'type': 'opaque_login_finish', 'finalization': finish['finalization']})
            result = wire.receive('login_result')
            self.assertTrue(result['success'])
            return finish, result
        finally:
            wire.close()

    def change(self, username, old_password, new_password):
        with Wire(self.service) as wire:
            start = call({'op': 'login_start', 'password': old_password})
            wire.send({'type': 'opaque_change_start', 'from': username, 'request': start['request']})
            challenge = wire.receive('opaque_change_challenge')
            proof = call({'op': 'login_finish', 'password': old_password,
                'state': start['state'], 'response': challenge['response'],
                'username': username, 'server_id': wire.server_id})
            wire.send({'type': 'opaque_change_finish', 'finalization': proof['finalization']})
            verified = wire.receive('opaque_change_verified')
            start = call({'op': 'registration_start', 'password': new_password})
            wire.send({'type': 'opaque_change_register_start', 'request': start['request']})
            challenge = wire.receive('opaque_change_register_challenge')
            finish = call({'op': 'registration_finish', 'password': new_password,
                'state': start['state'], 'response': challenge['response'],
                'username': username, 'server_id': wire.server_id})
            backup = wire.backup(username)
            wire.send({'type': 'opaque_change_register_finish', 'record': finish['record'],
                       'backup': backup, 'generation': verified['generation']})
            result = wire.receive('opaque_change_result')
            self.assertTrue(result['success'])
            return finish, backup

    def test_register_restart_change_password_and_no_secret_logs(self):
        registered, backup, result, _ = self.register('single')
        self.assertTrue(result['success'])
        logged_in, result = self.login('single')
        self.assertEqual(logged_in['export_key'], registered['export_key'])
        self.assertEqual(result['opaque_backup'], backup)
        self.assertEqual(result['opaque_generation'], 1)
        self.service.stop(kill=True)
        self.service.start()
        logged_in, result = self.login('single')
        self.assertEqual(logged_in['export_key'], registered['export_key'])
        changed, new_backup = self.change('single', FIRST, SECOND)
        logged_in, result = self.login('single', SECOND)
        self.assertEqual(logged_in['export_key'], changed['export_key'])
        self.assertNotEqual(changed['export_key'], registered['export_key'])
        self.assertEqual(result['opaque_backup'], new_backup)
        self.assertEqual(result['opaque_generation'], 2)
        with self.assertRaises(ValueError):
            self.login('single', FIRST)
        for secret in (FIRST, SECOND):
            self.assertNotIn(secret, self.service.log_path.read_text(encoding='utf-8'))
            self.assertNotIn(secret.encode(), (self.service.path / 'chat.db').read_bytes())

    def test_migration_preserves_registered_identity_and_disables_legacy(self):
        self.service.connect('existing', register=True)
        old_peer = self.service.connect('existing')
        identity = Identity.generate()
        published = old_peer.request({'type': 'e2ee_identity_publish', 'request_id': 'migration-test',
            'identity': identity.public_bundle(), 'proof': publish_proof(identity, 'existing')},
            'e2ee_identity_result')
        self.assertTrue(published['success'])
        old_peer.close()
        registration, backup, result, challenge = self.register('existing', migration=True)
        self.assertTrue(result['success'])
        self.assertEqual(challenge['e2ee_identity'], identity.public_bundle())
        self.assertEqual(result['e2ee_identity'], identity.public_bundle())
        self.assertEqual(result['opaque_backup'], backup)
        logged_in, result = self.login('existing')
        self.assertEqual(logged_in['export_key'], registration['export_key'])
        self.assertEqual(result['e2ee_identity'], identity.public_bundle())
        with self.assertRaises(AssertionError):
            self.service.connect('existing')

    def test_bad_record_does_not_create_account(self):
        _, _, result, _ = self.register('invalid', invalid=True)
        self.assertFalse(result['success'])
        _, _, result, _ = self.register('invalid')
        self.assertTrue(result['success'])

    def test_normal_client_register_login_change_and_new_device_restore(self):
        endpoint = ('127.0.0.1', self.service.port)
        manager = ConnectionManager(ClientSettings(*endpoint))
        self.addCleanup(manager.close)
        path = self.service.path / 'client-keys.json'
        prepare = _VaultPreparation(path, endpoint, 'desktop', None)
        self.assertTrue(manager.authenticate('desktop', FIRST, register=True, prepare=prepare))
        registered = manager.events.get(timeout=30)
        self.assertTrue(manager.accept_auth(registered))
        self.assertIsNone(registered.error)
        prepare = _VaultPreparation(path, endpoint, 'desktop', None)
        self.assertTrue(manager.authenticate('desktop', FIRST, prepare=prepare))
        logged_in = manager.events.get(timeout=30)
        self.assertTrue(manager.accept_auth(logged_in))
        self.assertIsNone(logged_in.error)
        vault = logged_in.encryption
        self.addCleanup(vault.lock)
        fingerprint = vault.identity.fingerprint
        other = Identity.generate()
        vault.pin_peer('contact', other.public_bundle(), verified=True)
        client.send_msg(manager.sock, {'type': 'e2ee_identity_publish', 'request_id': 'desktop-test',
            'identity': vault.identity.public_bundle(), 'proof': publish_proof(vault.identity, 'desktop')})
        for _ in range(20):
            reply = client.recv_msg(manager.sock)
            if reply.get('type') == 'e2ee_identity_result':
                self.assertTrue(reply['success'])
                break
        else:
            self.fail('Desktop identity publication was not acknowledged')
        self.assertTrue(manager.change_password(FIRST, SECOND, vault))
        changed = manager.events.get(timeout=30)
        self.assertIsInstance(changed, PasswordChangeResult)
        self.assertIsNone(changed.error)
        self.assertIsNone(changed.warning)
        self.assertTrue(vault.is_verified('contact'))
        manager.disconnect()
        logged_in, result = self.login('desktop', SECOND)
        restored = KeyVault(None, ('another-device.test', 9999), 'desktop')
        self.addCleanup(restored.lock)
        restored.unlock_opaque(logged_in['export_key'], result['opaque_backup']['server_id'],
            backup=result['opaque_backup'], remote_identity=result['e2ee_identity'])
        self.assertEqual(restored.identity.fingerprint, fingerprint)
        self.assertEqual(restored.peer_records, [])

    @unittest.skipUnless(os.environ.get('CHATROOM_GO_SERVER_EXE'), 'Go binary not selected')
    def test_encrypted_database_and_setup_work_on_other_backend(self):
        registration, backup, result, _ = self.register('portable')
        self.assertTrue(result['success'])
        self.service.stop(kill=True)
        self.service.backend = 'go' if self.backend == 'python' else 'python'
        if self.service.backend == 'go':
            self.service.port = 12346
        self.service.start()
        logged_in, result = self.login('portable')
        self.assertEqual(logged_in['export_key'], registration['export_key'])
        self.assertEqual(result['opaque_backup'], backup)


class PythonSinglePasswordTests(Scenarios, unittest.TestCase):
    backend = 'python'


@unittest.skipUnless(os.environ.get('CHATROOM_GO_SERVER_EXE'), 'Go binary not selected')
class GoSinglePasswordTests(Scenarios, unittest.TestCase):
    backend = 'go'


class SharedCoreTests(unittest.TestCase):
    def test_both_runtimes_embed_identical_core(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual((root / 'chatroom_client/opaque_core.wasm').read_bytes(),
                         (root / 'go-server/internal/opaqueauth/opaque_core.wasm').read_bytes())
