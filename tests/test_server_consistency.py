"""Deterministic login/friend ordering and server identity recovery regressions."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import test_regressions as regressions


class ServerConsistencyTests(unittest.TestCase):
    # Reuse the fixture without inheriting and rerunning all ServerTests.
    setUpClass = classmethod(regressions.ServerTests.setUpClass.__func__)
    tearDownClass = classmethod(regressions.ServerTests.tearDownClass.__func__)
    setUp = regressions.ServerTests.setUp
    tearDown = regressions.ServerTests.tearDown
    connect = regressions.ServerTests.connect
    read_type = regressions.ServerTests.read_type

    def connect_async(self, username):
        results, errors = [], []

        def connect():
            try:
                results.append(self.connect(username))
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=connect, daemon=True)
        thread.start()
        return thread, results, errors

    def assert_group_info_precedes_mutation(self, action, saver, notification):
        s, wire = self.server, regressions.client
        gid = s.create_group_db('alice', 'Team', ['alice', 'bob'])
        alice, _, _ = self.connect('alice')
        self.read_type(alice, 'online_users')
        alice_thread = self.threads[-1]
        bob, _, _ = self.connect('bob')
        self.read_type(bob, 'online_users')
        self.read_type(alice, 'online_users')
        bob_thread = self.threads[-1]
        queried, release_query = threading.Event(), threading.Event()
        requested, mutated = threading.Event(), threading.Event()
        original_query, original_acquire = s.get_group_db, s.group_ops_lock.acquire
        original_save = getattr(s, saver)

        def query(group_id):
            group = original_query(group_id)
            if threading.current_thread() is bob_thread and not queried.is_set():
                queried.set()
                if not release_query.wait(5):
                    raise TimeoutError('test did not release the group snapshot')
            return group

        def acquire():
            if threading.current_thread() is alice_thread:
                requested.set()
            return original_acquire()

        def save(*args, **kwargs):
            mutated.set()
            return original_save(*args, **kwargs)

        with patch.object(s, 'get_group_db', side_effect=query), \
                patch.object(s.group_ops_lock, 'acquire', side_effect=acquire), \
                patch.object(s, saver, side_effect=save):
            try:
                wire.send_msg(bob, {'type': 'group_info', 'gid': gid})
                self.assertTrue(queried.wait(3))
                wire.send_msg(alice, dict(action, gid=gid))
                self.assertTrue(requested.wait(3))
                self.assertFalse(mutated.wait(0.1), 'group mutation bypassed the info snapshot')
            finally:
                release_query.set()
            result = self.read_type(alice, action['type'] + '_result')
            self.assertTrue(result['success'])
            snapshot = wire.recv_msg(bob)
            changed = wire.recv_msg(bob)
            self.assertEqual(snapshot['type'], 'group_info')
            self.assertEqual(snapshot['members'], ['alice', 'bob'])
            self.assertEqual(changed['type'], notification)

        app = regressions.headless_client(self)
        app.state.username = 'bob'
        app.state.groups = {gid: snapshot}
        app.view.notify = app.view.refresh_groups = Mock()
        app.handle_server_message(snapshot)
        app.handle_server_message(changed)
        group = original_query(gid)
        if group is None or 'bob' not in group['members']:
            self.assertNotIn(gid, app.state.groups)
        else:
            self.assertEqual(app.state.groups[gid]['owner'], group['owner'])
            self.assertEqual(app.state.groups[gid]['group_name'], group['group_name'])

        # A subsequent request observes the committed state and also proves
        # that the info handler released its lock after sending the snapshot.
        wire.send_msg(bob, {'type': 'group_info', 'gid': gid})
        latest = self.read_type(bob, 'group_info')
        if group is None or 'bob' not in group['members']:
            self.assertIn('error', latest)
        else:
            self.assertEqual(latest['owner'], group['owner'])
            self.assertEqual(latest['group_name'], group['group_name'])

    def test_group_info_precedes_concurrent_kick(self):
        self.assert_group_info_precedes_mutation(
            {'type': 'group_kick', 'kick': 'bob'}, 'update_group_members_db', 'group_kick_notification')

    def test_group_info_precedes_concurrent_disband(self):
        self.assert_group_info_precedes_mutation(
            {'type': 'group_disband'}, 'delete_group_db', 'group_disband_notification')

    def test_group_info_precedes_concurrent_rename(self):
        self.assert_group_info_precedes_mutation(
            {'type': 'group_rename', 'new_name': 'Updated'}, 'update_group_name_db', 'group_rename_notification')

    def test_group_info_precedes_concurrent_transfer(self):
        self.assert_group_info_precedes_mutation(
            {'type': 'group_transfer', 'new_owner': 'bob'}, 'transfer_group_ownership_db', 'group_transfer_notification')

    def test_group_info_error_paths_release_operation_lock(self):
        s, wire = self.server, regressions.client
        gid = s.create_group_db('alice', 'Team', ['alice'])
        alice, _, _ = self.connect('alice')
        self.read_type(alice, 'online_users')
        bob, _, _ = self.connect('bob')
        self.read_type(bob, 'online_users')
        self.read_type(alice, 'online_users')
        for denied_gid in (gid, 'missing', []):
            with self.subTest(gid=denied_gid):
                wire.send_msg(bob, {'type': 'group_info', 'gid': denied_gid})
                self.assertIn('error', self.read_type(bob, 'group_info'))
                wire.send_msg(alice, {'type': 'group_rename', 'gid': gid, 'new_name': 'Updated'})
                self.assertTrue(self.read_type(alice, 'group_rename_result')['success'])

    def test_failed_group_lookup_closes_database_connection(self):
        s = self.server
        connection = s.storage.connect('chat.db')
        try:
            with patch.object(s.storage, 'connect', return_value=connection):
                with self.assertRaises(s.sqlite3.ProgrammingError):
                    s.get_group_db([])
            with self.assertRaisesRegex(s.sqlite3.ProgrammingError, 'closed'):
                connection.execute('SELECT 1')
        finally:
            connection.close()

    def test_login_snapshot_precedes_concurrent_friend_update(self):
        s = self.server
        bob, _, _ = self.connect('bob')
        self.read_type(bob, 'online_users')
        s.pending_friend_requests[('alice', 'bob')] = time.time()
        snapshot_entered, finish_snapshot = threading.Event(), threading.Event()
        response_read, save_entered, login_sent = (threading.Event() for _ in range(3))
        original_send, original_info = s.send_msg, s.logging.info
        original_save, original_packet = s.save_friend_relationship, s.transport.send_packet

        def send(sock, msg, **kwargs):
            if msg.get('type') == 'friends_list':
                snapshot_entered.set()
                if not finish_snapshot.wait(5):
                    raise TimeoutError('test did not release the friend snapshot')
            return original_send(sock, msg, **kwargs)

        def log_info(message, *args, **kwargs):
            if message.startswith("Processing friend response from 'bob'"):
                response_read.set()
            return original_info(message, *args, **kwargs)

        def save(*args):
            save_entered.set()
            return original_save(*args)

        def send_packet(sock, packet):
            if json.loads(packet[4:]).get('type') == 'login_result':
                login_sent.set()
            return original_packet(sock, packet)

        with patch.object(s, 'send_msg', side_effect=send), \
                patch.object(s.logging, 'info', side_effect=log_info), \
                patch.object(s, 'save_friend_relationship', side_effect=save), \
                patch.object(s.transport, 'send_packet', side_effect=send_packet):
            connector, results, errors = self.connect_async('alice')
            try:
                self.assertTrue(snapshot_entered.wait(5))
                regressions.client.send_msg(bob, {'type': 'friend_response', 'to': 'alice', 'accepted': True})
                self.assertTrue(response_read.wait(3))
                self.assertFalse(save_entered.wait(.1), 'acceptance bypassed snapshot ordering')
                self.assertFalse(login_sent.is_set(), 'network send ran before the snapshot locks were released')
            finally:
                finish_snapshot.set()
                connector.join(5)
            self.assertFalse(connector.is_alive())
            self.assertEqual(errors, [])
            alice, _, result = results[0]
            self.assertTrue(result['success'])  # The first authenticated frame stays login_result.
            friends, received = set(), []
            for _ in range(20):
                msg = regressions.client.recv_msg(alice)
                received.append(msg['type'])
                if msg['type'] == 'friends_list':
                    friends = set(msg['friends'])
                elif msg['type'] == 'friend_update':
                    friends.add(msg['friend'])
                    break
            else:
                self.fail('missing concurrent friend update')
            self.assertLess(received.index('friends_list'), received.index('friend_update'))
            self.assertEqual(friends, {'bob'})
            self.assertEqual(s.user_friends['alice'], {'bob'})
            self.assertEqual(s.load_friends('alice'), {'bob'})

    def test_login_after_friend_commit_loads_committed_relationship(self):
        s = self.server
        bob, _, _ = self.connect('bob')
        self.read_type(bob, 'online_users')
        s.pending_friend_requests[('alice', 'bob')] = time.time()
        committed, finish_commit = threading.Event(), threading.Event()
        validated, loaded = threading.Event(), threading.Event()
        original_save, original_validate, original_load = s.save_friend_relationship, s.validate_user, s.load_friends

        def save(*args):
            original_save(*args)
            committed.set()
            if not finish_commit.wait(5):
                raise TimeoutError('test did not release the committed friendship')

        def validate(username, password):
            result = original_validate(username, password)
            if username == 'alice':
                validated.set()
            return result

        def load(username):
            if username == 'alice':
                loaded.set()
            return original_load(username)

        with patch.object(s, 'save_friend_relationship', side_effect=save), \
                patch.object(s, 'validate_user', side_effect=validate), \
                patch.object(s, 'load_friends', side_effect=load):
            regressions.client.send_msg(bob, {'type': 'friend_response', 'to': 'alice', 'accepted': True})
            self.assertTrue(committed.wait(3))
            connector, results, errors = self.connect_async('alice')
            try:
                self.assertTrue(validated.wait(3))
                self.assertFalse(loaded.wait(.1), 'login did not serialize with friendship commit')
            finally:
                finish_commit.set()
                connector.join(5)
            self.assertFalse(connector.is_alive())
            self.assertEqual(errors, [])
            alice, _, result = results[0]
            self.assertTrue(result['success'])
            self.assertEqual(set(self.read_type(alice, 'friends_list')['friends']), {'bob'})
            self.read_type(bob, 'friend_update')
            self.assertEqual(s.user_friends['alice'], {'bob'})
            self.assertEqual(s.load_friends('alice'), {'bob'})

    @contextmanager
    def key_directory(self):
        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                yield
            finally:
                os.chdir(old_cwd)

    def test_public_key_recovery_preserves_private_identity(self):
        s = self.server
        original_private = s.private_key.export_key()
        mismatched_public = s.RSA.generate(1024).publickey().export_key()
        for public in (None, b'broken public key', mismatched_public, original_private):
            with self.subTest(public=public is not None), self.key_directory():
                Path('private_key.pem').write_bytes(original_private)
                if public is not None:
                    Path('public_key.pem').write_bytes(public)
                with patch.object(s.RSA, 'generate', side_effect=AssertionError('identity was regenerated')):
                    private, public_pem = s.ensure_rsa_keys()
                self.assertEqual(Path('private_key.pem').read_bytes(), original_private)
                self.assertEqual(private.n, s.private_key.n)
                restored = s.RSA.import_key(public_pem)
                self.assertFalse(restored.has_private())
                self.assertEqual((restored.n, restored.e), (private.n, private.e))
                self.assertEqual(Path('public_key.pem').read_bytes(), public_pem)

    def test_invalid_private_key_fails_without_overwriting_files(self):
        s = self.server
        for invalid_private in (b'broken private key', s.private_key.publickey().export_key()):
            for with_public in (False, True):
                with self.subTest(with_public=with_public), self.key_directory():
                    Path('private_key.pem').write_bytes(invalid_private)
                    if with_public:
                        Path('public_key.pem').write_bytes(b'preserve this public file')
                    with patch.object(s.RSA, 'generate', side_effect=AssertionError('identity was regenerated')):
                        with self.assertRaisesRegex(RuntimeError, '无法加载RSA私钥'):
                            s.ensure_rsa_keys()
                    self.assertEqual(Path('private_key.pem').read_bytes(), invalid_private)
                    if with_public:
                        self.assertEqual(Path('public_key.pem').read_bytes(), b'preserve this public file')
                    else:
                        self.assertFalse(Path('public_key.pem').exists())

    def test_missing_private_key_with_existing_public_key_fails(self):
        s = self.server
        with self.key_directory():
            public = s.private_key.publickey().export_key()
            Path('public_key.pem').write_bytes(public)
            with patch.object(s.RSA, 'generate', side_effect=AssertionError('identity was regenerated')):
                with self.assertRaisesRegex(RuntimeError, '私钥文件丢失'):
                    s.ensure_rsa_keys()
            self.assertFalse(Path('private_key.pem').exists())
            self.assertEqual(Path('public_key.pem').read_bytes(), public)

    def test_valid_key_pair_is_not_rewritten(self):
        s = self.server
        with self.key_directory():
            private = s.private_key.export_key()
            public = s.private_key.publickey().export_key()
            Path('private_key.pem').write_bytes(private)
            Path('public_key.pem').write_bytes(public)
            with patch.object(s.RSA, 'generate', side_effect=AssertionError('identity was regenerated')):
                loaded, advertised = s.ensure_rsa_keys()
            self.assertEqual(loaded.n, s.private_key.n)
            self.assertEqual(advertised, public)
            self.assertEqual(Path('private_key.pem').read_bytes(), private)
            self.assertEqual(Path('public_key.pem').read_bytes(), public)

    def test_first_start_creates_matching_key_pair_with_private_permissions(self):
        s = self.server
        with self.key_directory(), patch.object(s, 'RSA_KEY_SIZE', 1024):
            private, public_pem = s.ensure_rsa_keys()
            self.assertTrue(private.has_private())
            self.assertEqual(s.RSA.import_key(public_pem).n, private.n)
            self.assertEqual(Path('private_key.pem').read_bytes(), private.export_key())
            if os.name != 'nt':  # Windows does not expose POSIX owner/group mode bits.
                self.assertEqual(stat.S_IMODE(Path('private_key.pem').stat().st_mode), 0o600)


if __name__ == '__main__':
    unittest.main()
