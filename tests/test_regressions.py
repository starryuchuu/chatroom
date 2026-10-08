"""Regression tests using real RSA/AES/Argon2 and isolated SQLite state."""
import base64
import importlib.util
import io
import os
from pathlib import Path
import queue
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

client = load('chat_client', ROOT / 'client.py')

class ClientTests(unittest.TestCase):
    def app(self):
        app = client.ChatClient.__new__(client.ChatClient)
        app.master = Mock()
        app.sock = Mock()
        app.running = True
        app.incoming = queue.Queue()
        return app

    def test_old_connection_events_do_not_disconnect_new_login(self):
        app = self.app()
        app.handle_server_message = Mock()
        app.disconnect = Mock()
        app.incoming.put((object(), None))
        app.incoming.put((object(), {'type': 'friends_list', 'friends': ['old']}))
        app.incoming.put((app.sock, {'type': 'friends_list', 'friends': ['new']}))
        app.drain_incoming()
        app.disconnect.assert_not_called()
        app.handle_server_message.assert_called_once_with({'type': 'friends_list', 'friends': ['new']})

    def test_receiver_does_not_call_tk_or_mutate_state(self):
        app = self.app()
        sock = app.sock
        app.handle_server_message = Mock()
        with patch.object(client, 'recv_msg', side_effect=[{'type': 'online_users'}, None]):
            worker = threading.Thread(target=app.receive_msg, args=(sock,))
            worker.start(); worker.join(2)
        self.assertFalse(worker.is_alive())
        app.master.assert_not_called()
        self.assertEqual(app.master.mock_calls, [])
        app.handle_server_message.assert_not_called()
        self.assertEqual(app.incoming.get_nowait(), (sock, {'type': 'online_users'}))
        self.assertEqual(app.incoming.get_nowait(), (sock, None))

    def test_disconnect_shutdown_and_clear_session_history(self):
        app = self.app()
        sock = app.sock
        app.session_key = b'secret'
        app.username = 'alice'
        app.group_messages_old = ['old account history']
        app.build_login = Mock()
        app.disconnect()
        sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        sock.close.assert_called_once()
        self.assertIsNone(app.session_key)
        self.assertIsNone(app.username)
        self.assertFalse(hasattr(app, 'group_messages_old'))

    def test_friend_success_waits_for_server_ack(self):
        app = self.app()
        app.friend_request_result = None
        with patch.object(client.messagebox, 'showinfo') as info:
            app.handle_server_message({'type': 'friend_request_result', 'success': True, 'message': 'stored'})
        info.assert_called_once_with('好友申请', 'stored')

    def test_unrelated_group_removal_keeps_current_chat(self):
        for kind in ('group_kick_notification', 'group_disband_notification'):
            app = self.app()
            app.groups = {'old': {'group_name': 'Old'}}
            app.current_group = 'other'
            app.refresh_group_listbox = Mock()
            app.clear_chat_selection = Mock()
            with patch.object(client.messagebox, 'showinfo'):
                app.handle_server_message({'type': kind, 'gid': 'old', 'group_name': 'Old'})
            self.assertNotIn('old', app.groups)
            app.clear_chat_selection.assert_not_called()

    def test_bad_message_does_not_prevent_next_event(self):
        app = self.app()
        app.update_online_users = Mock()
        app.incoming.put((app.sock, {'type': 'user_groups_list', 'groups': None}))
        app.incoming.put((app.sock, {'type': 'online_users', 'users': ['alice']}))
        app.drain_incoming()
        app.update_online_users.assert_called_once_with(['alice'])

    def test_clear_selection_preserves_cached_chat_frames(self):
        app = self.app()
        app.current_friend = None
        app.current_group = 'removed'
        removed_frame, other_frame = Mock(), Mock()
        app.chat_frames = {'removed': removed_frame, 'other': other_frame}
        app.current_chat_frame = removed_frame
        app.chat_container = Mock()
        app.chat_container.winfo_children.return_value = [removed_frame, other_frame]
        app.clear_chat_selection()
        removed_frame.pack_forget.assert_called_once()
        removed_frame.destroy.assert_not_called()
        other_frame.destroy.assert_not_called()
        self.assertIsNone(app.current_chat_frame)
        self.assertIsNone(app.current_group)
        self.assertIsNone(app.current_friend)

class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_cwd = os.getcwd()
        cls.tmp = tempfile.TemporaryDirectory()
        os.chdir(cls.tmp.name)
        cls.server = load('chat_server', ROOT / 'server.py')

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.old_cwd)
        cls.tmp.cleanup()

    def setUp(self):
        self.peers = []
        self.threads = []
        s = self.server
        s.clients.clear()
        for mapping in (s.usernames, s.session_keys, s.session_timestamps, s.user_friends,
                        s.rate_limit_tracker, s.pending_friend_requests, s.group_pending_joins,
                        s.groups_data, s.send_locks):
            mapping.clear()
        Path('chat.db').unlink(missing_ok=True)
        s.init_db()
        for user in ('alice', 'bob', 'carol'):
            self.assertTrue(s.register_user(user, ' password ')[0])

    def tearDown(self):
        for peer, key in self.peers:
            try: peer.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            peer.close()
        for thread in self.threads:
            thread.join(3)
            self.assertFalse(thread.is_alive(), 'server handler did not terminate')

    def connect(self, user, password=' password ', register=False):
        peer, remote = socket.socketpair()
        peer.settimeout(3)
        thread = threading.Thread(target=self.server.handle_client, args=(remote, ('127.0.0.1', 1)), daemon=True)
        thread.start()
        self.threads.append(thread)
        public = client.recv_msg(peer)
        key = os.urandom(16)
        rsa = client.RSA.import_key(public['key'])
        encrypted = client.PKCS1_OAEP.new(rsa).encrypt(key)
        client.send_msg(peer, {'type': 'session_key', 'key': base64.b64encode(encrypted).decode()})
        import json
        client.send_msg(peer, {'type': 'encrypted_register' if register else 'encrypted_login',
                               'data': client.encrypt_message(json.dumps({'from': user, 'password': password}), key)})
        result = client.recv_msg(peer)
        self.peers.append((peer, key))
        return peer, key, result

    def read_type(self, peer, kind):
        for _ in range(50):
            msg = client.recv_msg(peer)
            self.assertIsNotNone(msg)
            if msg['type'] == kind: return msg
        self.fail('missing message: ' + kind)

    def test_rate_limit_cleanup_uses_scalar_timestamps(self):
        s = self.server
        for i in range(1001): s.rate_limit_tracker[str(i)] = [time.time() - 120]
        s.rate_limit_tracker['active'] = [time.time()] * s.RATE_LIMIT_MAX_ATTEMPTS
        self.assertTrue(s.is_rate_limited('active'))
        self.assertEqual(set(s.rate_limit_tracker), {'active'})

    def test_key_generation_with_ascii_console(self):
        previous_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as key_dir:
            try:
                os.chdir(key_dir)
                with io.TextIOWrapper(io.BytesIO(), encoding='ascii') as console:
                    with patch('sys.stdout', console):
                        private_key, public_pem = self.server.ensure_rsa_keys()
                self.assertTrue(private_key.has_private())
                self.assertEqual(client.RSA.import_key(public_pem).n, private_key.n)
            finally:
                os.chdir(previous_cwd)

    def test_rate_limited_connections_do_not_leak_send_locks(self):
        s = self.server
        s.rate_limit_tracker['127.0.0.1'] = [time.time()] * s.RATE_LIMIT_MAX_ATTEMPTS
        peer, remote = socket.socketpair()
        try:
            s.handle_client(remote, ('127.0.0.1', 1))
            self.assertEqual(client.recv_msg(peer)['type'], 'error')
            self.assertNotIn(remote, s.send_locks)
        finally:
            peer.close()

    def test_rate_limited_connections_are_removed_from_clients(self):
        s = self.server
        s.rate_limit_tracker['127.0.0.1'] = [time.time()] * s.RATE_LIMIT_MAX_ATTEMPTS
        peer, remote = socket.socketpair()
        s.clients.append(remote)  # main() tracks accepted sockets before dispatch.
        try:
            s.handle_client(remote, ('127.0.0.1', 1))
            self.assertEqual(client.recv_msg(peer)['type'], 'error')
            self.assertNotIn(remote, s.clients)
            self.assertNotIn(remote, s.send_locks)
        finally:
            peer.close()

    def test_accept_offline_friend_does_not_leak_cache(self):
        s = self.server
        bob, _, _ = self.connect('bob')
        self.read_type(bob, 'online_users')
        s.pending_friend_requests[('alice', 'bob')] = time.time()
        client.send_msg(bob, {'type': 'friend_response', 'to': 'alice', 'accepted': True})
        self.read_type(bob, 'friend_update')
        self.assertNotIn('alice', s.user_friends)
        self.assertIn('bob', s.load_friends('alice'))

    def test_encrypted_registration_login_and_wrong_password(self):
        _, _, result = self.connect('dave', register=True)
        self.assertTrue(result['success'])
        _, _, result = self.connect('dave')
        self.assertTrue(result['success'])
        _, _, result = self.connect('bob', password='wrongpass')
        self.assertFalse(result['success'])

    def test_duplicate_login_and_first_response_order(self):
        results = []
        barrier = threading.Barrier(3)
        def attempt():
            barrier.wait()
            results.append(self.connect('alice')[2])
        threads = [threading.Thread(target=attempt) for _ in range(2)]
        for thread in threads: thread.start()
        barrier.wait()
        for thread in threads: thread.join(5)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(msg['type'] == 'login_result' for msg in results))
        self.assertEqual(sorted(msg['success'] for msg in results), [False, True])

    def test_friend_private_group_lifecycle_and_history(self):
        alice, ak, _ = self.connect('alice')
        bob, bk, _ = self.connect('bob')
        self.read_type(alice, 'online_users'); self.read_type(bob, 'online_users')
        client.send_msg(alice, {'type': 'friend_request', 'to': 'bob'})
        self.assertTrue(self.read_type(alice, 'friend_request_result')['success'])
        self.read_type(bob, 'friend_request')
        client.send_msg(bob, {'type': 'friend_response', 'to': 'alice', 'accepted': True})
        self.read_type(alice, 'friend_update'); self.read_type(bob, 'friend_update')
        client.send_msg(alice, {'type': 'private_chat', 'to': 'bob', 'content': client.encrypt_message('你好 Bob', ak)})
        self.assertEqual(client.decrypt_message(self.read_type(bob, 'private_chat')['content'], bk), '你好 Bob')
        self.assertEqual(client.decrypt_message(self.read_type(alice, 'private_chat')['content'], ak), '你好 Bob')
        client.send_msg(alice, {'type': 'group_create', 'group_name': 'Team', 'members': ['bob']})
        group = self.read_type(alice, 'group_create_result')
        gid = group['gid']
        self.read_type(bob, 'group_create_result')
        client.send_msg(bob, {'type': 'group_chat', 'gid': gid, 'content': client.encrypt_message('群消息', bk)})
        self.assertEqual(client.decrypt_message(self.read_type(alice, 'group_chat')['content'], ak), '群消息')
        self.read_type(bob, 'group_chat')
        # Relogin must replay persisted private and group messages with a fresh key.
        bob.shutdown(socket.SHUT_RDWR); bob.close()
        deadline = time.monotonic() + 3
        while self.server.get_sock_by_username('bob') and time.monotonic() < deadline:
            time.sleep(.01)
        bob, bk, result = self.connect('bob')
        self.assertTrue(result['success'])
        self.assertEqual(client.decrypt_message(self.read_type(bob, 'group_chat')['content'], bk), '群消息')
        self.assertEqual(client.decrypt_message(self.read_type(bob, 'private_chat')['content'], bk), '你好 Bob')
        client.send_msg(alice, {'type': 'group_rename', 'gid': gid, 'new_name': 'Renamed'})
        self.assertTrue(self.read_type(alice, 'group_rename_result')['success'])
        client.send_msg(alice, {'type': 'group_transfer', 'gid': gid, 'new_owner': 'bob'})
        self.assertTrue(self.read_type(alice, 'group_transfer_result')['success'])
        client.send_msg(alice, {'type': 'group_leave', 'gid': gid})
        self.assertTrue(self.read_type(alice, 'group_leave_result')['success'])
        client.send_msg(bob, {'type': 'group_disband', 'gid': gid})
        self.assertTrue(self.read_type(bob, 'group_disband_result')['success'])
        self.assertIsNone(self.server.get_group_db(gid))

    def test_transfer_cannot_race_new_owner_leave(self):
        s = self.server
        s.save_friend_relationship('alice', 'bob')
        gid = s.create_group_db('alice', 'Team', ['alice', 'bob'])
        alice, _, _ = self.connect('alice')
        bob, _, _ = self.connect('bob')
        self.read_type(alice, 'online_users'); self.read_type(bob, 'online_users')
        entered, finish = threading.Event(), threading.Event()
        original = s.transfer_group_ownership_db
        def paused_transfer(gid, owner):
            entered.set()
            self.assertTrue(finish.wait(3))
            return original(gid, owner)
        with patch.object(s, 'transfer_group_ownership_db', side_effect=paused_transfer):
            client.send_msg(alice, {'type': 'group_transfer', 'gid': gid, 'new_owner': 'bob'})
            self.assertTrue(entered.wait(3))
            client.send_msg(bob, {'type': 'group_leave', 'gid': gid})
            try:
                bob.settimeout(.15)
                with self.assertRaises(socket.timeout): client.recv_msg(bob)
            finally:
                bob.settimeout(3)
                finish.set()
            self.assertTrue(self.read_type(alice, 'group_transfer_result')['success'])
            self.assertFalse(self.read_type(bob, 'group_leave_result')['success'])
        group = s.get_group_db(gid)
        self.assertEqual(group['owner'], 'bob')
        self.assertIn('bob', group['members'])

if __name__ == '__main__':
    unittest.main()
