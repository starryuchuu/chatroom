"""Real OPAQUE exchanges, atomic credential storage and fail-closed migration."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import opaque_runtime
import opaque_server
import storage


SERVER_ID = 'ab' * 32
PASSWORD = 'synthetic unified password'


def encoded(size):
    return base64.b64encode(os.urandom(size)).decode('ascii')


def backup(username='alice', server_id=SERVER_ID):
    # The server deliberately cannot inspect the encrypted identity payload.
    return {'v': 1, 'kind': 'opaque-identity', 'server_id': server_id,
            'username': username, 'salt': encoded(16), 'nonce': encoded(12),
            'data': encoded(80)}


class OpaqueServerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='chatroom-opaque-server-')
        self.cwd = Path.cwd()
        self.store = storage._store
        os.chdir(self.directory.name)
        storage._store = storage.Storage(os.urandom(32))
        with closing(storage.connect()) as db:
            db.executescript('CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password TEXT NOT NULL);'
                             'CREATE TABLE storage_names(token TEXT PRIMARY KEY,value TEXT NOT NULL);'
                             'CREATE TABLE e2ee_identities(username TEXT PRIMARY KEY,identity TEXT NOT NULL);')
            db.commit()
        opaque_server.initialize()
        self.sent = []
        self.legacy_checks = []

    def tearDown(self):
        os.chdir(self.cwd)
        storage._store = self.store
        self.directory.cleanup()

    def run_exchange(self, first, receive, *, deadline=None, admit=None):
        self.sent = []

        def verify(username, password):
            self.legacy_checks.append((username, password))
            return password == 'old synthetic password' and not opaque_server.has_account(username)

        return opaque_server.authenticate(
            first, receive=lambda: receive(self.sent[-1]), send=self.sent.append,
            server_id=SERVER_ID, decrypt_legacy=lambda value: value,
            verify_legacy=verify, get_identity=lambda username: {'preserved': username},
            deadline=deadline if deadline is not None else time.monotonic() + 30, admit=admit)

    def registration(self, *, username='alice', password=PASSWORD, migration=False, on_finish=None,
                     admit=None):
        start = opaque_runtime.call({'op': 'registration_start', 'password': password})
        self.export_key = None
        value = backup(username)

        def receive(challenge):
            self.assertEqual(challenge['type'], 'opaque_migrate_challenge' if migration else 'opaque_register_challenge')
            if migration:
                self.assertEqual(challenge['e2ee_identity'], {'preserved': username})
            finished = opaque_runtime.call({'op': 'registration_finish', 'password': password,
                                           'state': start['state'], 'response': challenge['response'],
                                           'username': username, 'server_id': SERVER_ID})
            self.export_key = finished['export_key']
            if on_finish:
                on_finish()
            return {'type': 'opaque_migrate_finish' if migration else 'opaque_register_finish',
                    'record': finished['record'], 'backup': value}

        first = {'type': 'opaque_migrate_start' if migration else 'opaque_register_start',
                 'from': username, 'request': start['request']}
        if migration:
            first['legacy_data'] = json.dumps({'password': 'old synthetic password'})
        result = self.run_exchange(first, receive, admit=admit)
        return result, value, self.export_key

    def login(self, *, username='alice', password=PASSWORD, finalization=None, admit=None):
        start = opaque_runtime.call({'op': 'login_start', 'password': password})
        self.login_export = None
        self.finalization = None

        def receive(challenge):
            self.assertEqual(challenge['type'], 'opaque_login_challenge')
            finish = opaque_runtime.call({'op': 'login_finish', 'password': password,
                                         'state': start['state'], 'response': challenge['response'],
                                         'username': username, 'server_id': SERVER_ID})
            self.login_export = finish['export_key']
            self.finalization = finish['finalization']
            return {'type': 'opaque_login_finish',
                    'finalization': finalization if finalization is not None else finish['finalization']}

        return self.run_exchange({'type': 'opaque_login_start', 'from': username,
                                  'request': start['request']}, receive, admit=admit)

    def test_login_admission_requires_proof_and_rechecks_generation(self):
        self.registration()
        admissions = []

        def admit(username):
            admissions.append(username)
            account = opaque_server.get_account(username)
            opaque_server.store_account(username, account['record'], account['backup'], SERVER_ID,
                                        generation=account['generation'])
            return True

        self.assertTrue(self.login(password='wrong synthetic credential', admit=admit).failed)
        self.assertTrue(self.login(username='unknown', admit=admit).failed)
        self.assertEqual(admissions, [])
        self.assertTrue(self.login(admit=admit).failed)
        self.assertEqual(admissions, ['alice'])
        self.assertEqual(opaque_server.get_account('alice')['generation'], 2)

    def test_migration_rechecks_credential_after_admission(self):
        self.add_legacy()
        legacy = opaque_server.legacy_snapshot('alice')
        start = opaque_runtime.call({'op': 'registration_start', 'password': PASSWORD})
        response = opaque_runtime.call({'op': 'registration_respond', 'setup': opaque_server.get_setup(),
                                        'username': 'alice', 'server_id': SERVER_ID,
                                        'request': start['request']})
        finished = opaque_runtime.call({'op': 'registration_finish', 'password': PASSWORD,
                                        'state': start['state'], 'response': response['response'],
                                        'username': 'alice', 'server_id': SERVER_ID})

        def admit(username):
            # Another migration completed and closed before this admission.
            self.assertEqual(len(self.legacy_checks), 1)
            opaque_server.store_account(username, finished['record'], backup(), SERVER_ID,
                                        legacy=legacy)
            return True

        result, _, _ = self.registration(migration=True, admit=admit)
        self.assertTrue(result.failed)
        self.assertEqual(len(self.sent), 1)
        self.assertFalse(self.sent[0]['success'])
        self.assertIsNone(self.export_key, 'stale migration must not receive a challenge')

    def add_legacy(self, username='alice'):
        with closing(storage.connect()) as db:
            token = storage.put_name(db, username)
            db.execute('INSERT INTO users(username,password) VALUES(?,?)',
                       (token, storage.seal('synthetic old hash', 'users', 'password', token)))
            db.execute('INSERT INTO e2ee_identities(username,identity) VALUES(?,?)',
                       (token, 'unchanged public identity'))
            db.commit()

    def test_real_registration_login_export_and_replay_rejection(self):
        registered, original_backup, export_key = self.registration()
        self.assertFalse(registered.failed)
        self.assertIsNone(registered.username)
        self.assertEqual(self.sent[-1], {'type': 'register_result', 'success': True})
        result = self.login()
        self.assertEqual(result.username, 'alice')
        self.assertEqual(self.login_export, export_key)
        self.assertEqual(result.fields, {'opaque_backup': original_backup, 'opaque_generation': 1})
        old_finalization = self.finalization
        self.assertTrue(self.login(finalization=old_finalization).failed)
        self.assertFalse(self.sent[-1]['success'])
        with closing(storage.connect()) as db:
            token = storage.token('alice')
            row = db.execute('SELECT password FROM users WHERE username=?', (token,)).fetchone()
            self.assertEqual(storage.open_field(row[0], 'users', 'password', token), '!opaque-v1!')
            sealed = db.execute('SELECT record,backup FROM opaque_accounts WHERE username=?', (token,)).fetchone()
            self.assertTrue(all(value.startswith('enc1:') for value in sealed))

    def test_wrong_password_and_unknown_account_have_fixed_failure(self):
        self.registration()
        self.assertTrue(self.login(password='different synthetic password').failed)
        first_error = deepcopy(self.sent[-1])
        self.assertTrue(self.login(username='unknown').failed)
        self.assertEqual(self.sent[-1], first_error)
        self.assertEqual(first_error['error'], opaque_server.AUTH_ERROR)
        self.assertNotIn(PASSWORD, json.dumps(self.sent))

    def test_explicit_legacy_migration_preserves_identity_and_disables_legacy(self):
        self.add_legacy()
        self.assertTrue(self.login().failed)
        self.assertTrue(self.sent[-1]['migration_required'])
        result, value, _ = self.registration(migration=True)
        self.assertEqual(result.username, 'alice')
        self.assertEqual(result.fields['opaque_backup'], value)
        self.assertEqual(self.legacy_checks, [('alice', 'old synthetic password')])
        self.assertIsNone(opaque_server.legacy_snapshot('alice'))
        with closing(storage.connect()) as db:
            self.assertEqual(db.execute('SELECT identity FROM e2ee_identities').fetchone()[0],
                             'unchanged public identity')
        self.assertEqual(self.login().username, 'alice')

    def test_migration_cas_does_not_overwrite_concurrent_change(self):
        self.add_legacy()

        def changed():
            with closing(storage.connect()) as db:
                token = storage.token('alice')
                db.execute('UPDATE users SET password=? WHERE username=?',
                           (storage.seal('changed old hash', 'users', 'password', token), token))
                db.commit()

        result, _, _ = self.registration(migration=True, on_finish=changed)
        self.assertTrue(result.failed)
        self.assertIsNone(opaque_server.get_account('alice'))
        with closing(storage.connect()) as db:
            token = storage.token('alice')
            value = db.execute('SELECT password FROM users WHERE username=?', (token,)).fetchone()[0]
            self.assertEqual(storage.open_field(value, 'users', 'password', token), 'changed old hash')

    def test_real_password_change_is_atomic_and_invalidates_old_password(self):
        self.registration()
        start = opaque_runtime.call({'op': 'login_start', 'password': PASSWORD})
        next_password = 'new synthetic unified password'
        registration = None
        new_backup = backup()

        def receive(message):
            nonlocal registration
            if message['type'] == 'opaque_change_challenge':
                finished = opaque_runtime.call({'op': 'login_finish', 'password': PASSWORD,
                                               'state': start['state'], 'response': message['response'],
                                               'username': 'alice', 'server_id': SERVER_ID})
                return {'type': 'opaque_change_finish', 'finalization': finished['finalization']}
            if message['type'] == 'opaque_change_verified':
                self.assertEqual(message['generation'], 1)
                registration = opaque_runtime.call({'op': 'registration_start', 'password': next_password})
                return {'type': 'opaque_change_register_start', 'request': registration['request']}
            finished = opaque_runtime.call({'op': 'registration_finish', 'password': next_password,
                                           'state': registration['state'], 'response': message['response'],
                                           'username': 'alice', 'server_id': SERVER_ID})
            return {'type': 'opaque_change_register_finish', 'record': finished['record'],
                    'backup': new_backup, 'generation': 1}

        result = self.run_exchange({'type': 'opaque_change_start', 'from': 'alice',
                                   'request': start['request']}, receive)
        self.assertFalse(result.failed)
        self.assertIsNone(result.username)
        self.assertEqual(self.sent[-1], {'type': 'opaque_change_result', 'success': True})
        self.assertTrue(self.login().failed)
        changed = self.login(password=next_password)
        self.assertEqual(changed.username, 'alice')
        self.assertEqual(changed.fields['opaque_generation'], 2)
        self.assertEqual(changed.fields['opaque_backup'], new_backup)

    def test_setup_is_stable_and_missing_setup_with_accounts_fails_closed(self):
        original = opaque_server.get_setup()
        opaque_server.initialize()
        self.assertEqual(opaque_server.get_setup(), original)
        self.registration()
        with closing(storage.connect()) as db:
            db.execute("DELETE FROM opaque_meta WHERE key='setup_v1'")
            db.commit()
        with patch.object(opaque_server, '_call') as runtime:
            with self.assertRaisesRegex(ValueError, 'setup is missing'):
                opaque_server.initialize()
            runtime.assert_not_called()

    def test_backup_binding_bounds_and_plaintext_private_fields_rejected(self):
        for field, value in (('username', 'other'), ('server_id', 'cd' * 32),
                             ('v', True), ('kind', 'plaintext'), ('nonce', encoded(11)),
                             ('salt', 'not-base64'), ('data', encoded(15))):
            with self.subTest(field=field):
                invalid = backup()
                invalid[field] = value
                with self.assertRaises((ValueError, TypeError)):
                    opaque_server.validate_backup(invalid, 'alice', SERVER_ID)
        invalid = backup()
        invalid['private'] = 'never accept plaintext private material'
        with self.assertRaises(ValueError):
            opaque_server.validate_backup(invalid, 'alice', SERVER_ID)
        invalid = backup()
        invalid['data'] = encoded(opaque_server.MAX_FIELD)
        with self.assertRaises(ValueError):
            opaque_server.validate_backup(invalid, 'alice', SERVER_ID)

    def test_invalid_record_and_stale_generation_leave_account_pair_unchanged(self):
        self.registration()
        before = opaque_server.get_account('alice')
        with self.assertRaises(ValueError):
            opaque_server.store_account('alice', encoded(32), backup(), SERVER_ID, generation=1)
        with self.assertRaises(ValueError):
            opaque_server.store_account('alice', before['record'], backup(), SERVER_ID, generation=2)
        self.assertEqual(opaque_server.get_account('alice'), before)

    def test_deadline_and_unexpected_step_do_not_create_account(self):
        start = opaque_runtime.call({'op': 'registration_start', 'password': PASSWORD})
        first = {'type': 'opaque_register_start', 'from': 'alice', 'request': start['request']}
        with patch.object(opaque_server, '_call') as runtime:
            result = self.run_exchange(first, lambda message: {}, deadline=time.monotonic() - 1)
            self.assertTrue(result.failed)
            runtime.assert_not_called()
        self.assertTrue(self.run_exchange(first, lambda message: {'type': 'opaque_login_finish'}).failed)
        self.assertIsNone(opaque_server.get_account('alice'))

    def test_concurrent_generation_cas_has_one_winner(self):
        self.registration()
        before = opaque_server.get_account('alice')

        def change(number):
            try:
                opaque_server.store_account('alice', before['record'], backup(), SERVER_ID, generation=1)
                return True
            except ValueError:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(change, (1, 2)))
        self.assertEqual(sorted(outcomes), [False, True])
        self.assertEqual(opaque_server.get_account('alice')['generation'], 2)
