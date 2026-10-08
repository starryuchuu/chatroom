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
        app.ui_tasks = queue.Queue()
        app.pending_messages = {}
        app.seen_message_ids = set()
        app.message_order = {}
        app.group_windows = {}
        app.group_info_requests = set()
        app.request_windows = {}
        app.history_syncing = False
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
        with patch.object(app, 'notify') as info:
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

    def test_history_live_overlap_is_deduplicated_and_sorted(self):
        app = self.app()
        app.username = 'alice'
        app.session_key = os.urandom(16)
        app.friends = ['bob']
        app.private_chats = {}
        app.current_friend = 'bob'
        app.current_group = None
        app.switch_chat_frame = Mock()
        app.display_message_with_time = Mock()
        app.handle_server_message({'type': 'history_begin'})
        for message_id in (8, 3, 8, 5):
            app.handle_server_message({'type': 'private_chat', 'from': 'bob', 'to': 'alice',
                                       'message_id': message_id,
                                       'content': client.encrypt_message(str(message_id), app.session_key)})
        self.assertEqual([row[0][0] for row in app.private_chats['bob']], ['bob: 3', 'bob: 5', 'bob: 8'])
        app.display_message_with_time.assert_not_called()
        app.handle_server_message({'type': 'history_end'})
        app.switch_chat_frame.assert_called_once_with('bob')

    def test_serialized_size_check_never_writes_oversize(self):
        sock = Mock()
        with self.assertRaises(ValueError):
            client.send_msg(sock, {'content': '中' * client.MAX_RECV_MSG_LEN})
        sock.sendall.assert_not_called()

    def test_idle_receive_timeout_preserves_partial_packet(self):
        sock = Mock()
        client.authenticated_sockets.add(sock)
        try:
            sock.recv.side_effect = [b'ab', socket.timeout(), b'cd']
            self.assertEqual(client.recvall(sock, 4), b'abcd')
        finally:
            client.authenticated_sockets.discard(sock)

    def test_ack_preserves_edited_input_and_failure_supports_retry(self):
        app = self.app()
        app.pending_messages = {'request': 'original'}
        app.msg_entry = Mock()
        app.msg_entry.get.return_value = 'edited'
        app.notify = Mock()
        app.update_chat_target = Mock()
        app.finish_pending({'request_id': 'request', 'success': True})
        app.msg_entry.delete.assert_not_called()
        self.assertEqual(app.pending_messages, {})
        app.pending_messages = {'retry': 'edited'}
        app.finish_pending({'request_id': 'retry', 'success': False, 'error': 'database locked'})
        self.assertEqual(app.pending_messages, {})
        app.msg_entry.delete.assert_not_called()

    def test_rejected_invite_sends_response(self):
        app = self.app()
        app.queue_send = Mock()
        app.ask_request = Mock(side_effect=lambda key, title, text, callback: callback(False))
        app.handle_group_invite('bob', 'gid')
        app.queue_send.assert_called_once_with({'type': 'group_invite_response', 'gid': 'gid', 'accepted': False})

class TkClientTests(unittest.TestCase):
    """Exercise real Tk widgets without showing windows or contacting a server."""
    def setUp(self):
        self.root = client.tk.Tk()
        self.root.withdraw()
        self.app = client.ChatClient(self.root)

    def tearDown(self):
        if self.app.auth_busy:
            self.app.cancel_auth()
        if self.app.running:
            self.app.disconnect()
        self.app.close()

    def chat(self):
        self.app.running = True
        self.app.username = 'alice'
        self.app.sock = Mock()
        self.app.session_key = os.urandom(16)
        self.app.build_chat()
        self.app.queue_send = Mock()
        self.app.groups = {'g': {'group_name': 'Before', 'owner': 'alice', 'members': ['alice', 'bob']}}
        self.app.current_group = 'g'
        self.app.refresh_group_listbox()
        self.app.switch_chat_frame('g')

    def test_selection_title_send_state_and_live_group_window(self):
        self.chat()
        app = self.app
        app.show_group_info_after_update('g')
        window = app.group_windows['g']
        def texts(widget):
            result = []
            for child in widget.winfo_children():
                if isinstance(child, (client.tk.Label, client.tk.Button)):
                    result.append(child.cget('text'))
                if isinstance(child, client.tk.Listbox):
                    result.extend(child.get(0, client.tk.END))
                result.extend(texts(child))
            return result
        self.assertIn('踢出成员', texts(window))
        app.handle_server_message({'type': 'group_update', 'gid': 'g', 'group_name': 'After',
                                   'owner': 'bob', 'members': ['alice', 'bob', 'carol']})
        self.assertIs(app.group_windows['g'], window)
        self.assertIn('carol', texts(window))
        self.assertIn('群主: bob', texts(window))
        self.assertNotIn('踢出成员', texts(window))
        self.assertEqual(app.group_listbox.curselection(), (0,))
        self.assertIn('After', app.chat_title.cget('text'))
        app.handle_server_message({'type': 'group_kick_notification', 'gid': 'g', 'group_name': 'After'})
        self.assertFalse(window.winfo_exists())
        self.assertIsNone(app.current_group)
        self.assertEqual(app.send_button.cget('state'), 'disabled')

    def test_input_remains_until_ack_and_oversize_stays_editable(self):
        self.chat()
        app = self.app
        app.msg_entry.insert('1.0', 'hello')
        app.send_msg()
        app.send_msg()
        app.queue_send.assert_called_once()
        self.assertEqual(app.msg_entry.get('1.0', 'end-1c'), 'hello')
        request_id = next(iter(app.pending_messages))
        app.handle_server_message({'type': 'group_chat_result', 'success': True, 'request_id': request_id})
        self.assertEqual(app.msg_entry.get('1.0', 'end-1c'), '')
        app.queue_send = client.ChatClient.queue_send.__get__(app)
        text = '中' * (client.MAX_RECV_MSG_LEN // 2)
        app.msg_entry.insert('1.0', text)
        app.send_msg()
        self.assertEqual(app.msg_entry.get('1.0', 'end-1c'), text)
        self.assertEqual(app.pending_messages, {})
        self.assertIn('1 MiB', app.status_label.cget('text'))

    def test_requests_do_not_pause_event_queue_and_wheel_is_local(self):
        self.chat()
        app = self.app
        app.incoming.put((app.sock, {'type': 'group_invite', 'from': 'bob', 'gid': 'other'}))
        app.incoming.put((app.sock, {'type': 'online_users', 'users': ['carol']}))
        app.drain_incoming()
        self.assertEqual(app.online_listbox.get(0, client.tk.END), ('carol',))
        self.assertIsNone(self.root.grab_current())
        self.assertTrue(app.request_windows[('group', 'other')].winfo_exists())
        self.assertFalse(self.root.bind_all('<MouseWheel>'))
        app.msg_entry.insert('1.0', 'draft')
        app.disconnect()
        self.assertEqual(app.saved_draft, ('alice', 'draft'))
        self.assertFalse(self.root.bind_all('<MouseWheel>'))

    def test_login_runs_off_thread_and_can_be_cancelled(self):
        app = self.app
        entered, release = threading.Event(), threading.Event()
        sock = Mock()
        def slow_connect(address):
            entered.set()
            release.wait(2)
            raise OSError('cancelled')
        sock.connect.side_effect = slow_connect
        with patch.object(client.socket, 'socket', return_value=sock):
            started = time.monotonic()
            app.connect_server('alice', 'password')
            self.assertLess(time.monotonic() - started, .5)
            self.assertTrue(entered.wait(1))
            self.assertEqual(app.login_button.cget('state'), 'disabled')
            app.cancel_auth()
            self.assertEqual(app.login_button.cget('state'), 'normal')
            sock.shutdown.assert_called_once()
            release.set()

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

    def test_database_failure_retains_friend_request_and_cache(self):
        s = self.server
        bob, _, _ = self.connect('bob')
        self.read_type(bob, 'online_users')
        s.pending_friend_requests[('alice', 'bob')] = time.time()
        with patch.object(s, 'save_friend_relationship', side_effect=s.sqlite3.OperationalError('disk full')):
            client.send_msg(bob, {'type': 'friend_response', 'to': 'alice', 'accepted': True})
            result = self.read_type(bob, 'friend_response_result')
            self.assertFalse(result['success'])
        self.assertIn(('alice', 'bob'), s.pending_friend_requests)
        self.assertNotIn('alice', s.user_friends['bob'])
        self.assertEqual(s.load_friends('bob'), set())
        client.send_msg(bob, {'type': 'friend_response', 'to': 'alice', 'accepted': True})
        self.read_type(bob, 'friend_update')
        self.assertNotIn(('alice', 'bob'), s.pending_friend_requests)
        self.assertEqual(s.load_friends('bob'), {'alice'})

    def test_database_failure_does_not_forward_chat(self):
        s = self.server
        s.save_friend_relationship('alice', 'bob')
        gid = s.create_group_db('alice', 'Team', ['alice', 'bob'])
        alice, key, _ = self.connect('alice')
        bob, _, _ = self.connect('bob')
        self.read_type(alice, 'online_users')
        self.read_type(bob, 'online_users')
        # Drain alice's broadcast caused by bob's login.
        self.read_type(alice, 'online_users')
        with patch.object(s, 'save_message', side_effect=s.sqlite3.OperationalError('database locked')):
            for kind in ('private_chat', 'group_chat'):
                data = {'type': kind, 'request_id': kind, 'content': client.encrypt_message('must not forward', key)}
                data['to' if kind == 'private_chat' else 'gid'] = 'bob' if kind == 'private_chat' else gid
                client.send_msg(alice, data)
                result = self.read_type(alice, kind + '_result')
                self.assertFalse(result['success'])
                self.assertEqual(result['request_id'], kind)
        bob.settimeout(.15)
        with self.assertRaises(socket.timeout):
            client.recv_msg(bob)
        conn = s.sqlite3.connect('chat.db')
        try:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM messages').fetchone()[0], 0)
        finally:
            conn.close()

    def test_savers_rollback_and_raise_on_commit_failure(self):
        s = self.server
        for save, args in ((s.save_friend_relationship, ('alice', 'bob')),
                           (s.save_message, ('private', 'alice', 'bob', None, 'text', 'now'))):
            connection = Mock()
            connection.commit.side_effect = s.sqlite3.OperationalError('disk full')
            with patch.object(s.sqlite3, 'connect', return_value=connection):
                with self.assertRaises(s.sqlite3.OperationalError):
                    save(*args)
            connection.rollback.assert_called_once()
            connection.close.assert_called_once()

    def test_declined_and_expired_group_invites_are_not_replayed(self):
        s = self.server
        gid = s.create_group_db('alice', 'Team', ['alice'])
        s.group_pending_joins[gid] = {'bob': ('alice', time.time())}
        bob, _, _ = self.connect('bob')
        self.read_type(bob, 'group_invite')
        self.read_type(bob, 'online_users')
        client.send_msg(bob, {'type': 'group_invite_response', 'gid': gid, 'accepted': False})
        self.assertTrue(self.read_type(bob, 'group_invite_response_result')['success'])
        self.assertNotIn('bob', s.group_pending_joins[gid])
        s.group_pending_joins[gid]['bob'] = ('alice', time.time() - s.PENDING_REQUEST_TIMEOUT_SECONDS - 1)
        client.send_msg(bob, {'type': 'group_join', 'gid': gid})
        self.assertFalse(self.read_type(bob, 'group_join_result')['success'])
        self.assertNotIn('bob', s.get_group_db(gid)['members'])
        self.assertNotIn('bob', s.group_pending_joins[gid])

    def test_group_batch_snapshot_order_and_network_outside_lock(self):
        s = self.server
        sock = Mock()
        packets = []
        def sent(packet):
            self.assertTrue(s.group_ops_lock.lock.acquire(blocking=False))
            s.group_ops_lock.lock.release()
            packets.append(packet)
        sock.sendall.side_effect = sent
        s.group_ops_lock.acquire()
        data = {'type': 'group_update', 'members': ['alice']}
        s.send_msg(sock, data)
        data['members'].append('bob')
        s.send_msg(sock, data)
        sock.sendall.assert_not_called()
        s.group_ops_lock.release()
        deadline = time.monotonic() + 2
        while len(packets) < 2 and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertEqual(len(packets), 2)
        import json
        self.assertEqual(json.loads(packets[0][4:])['members'], ['alice'])
        self.assertEqual(json.loads(packets[1][4:])['members'], ['alice', 'bob'])
        s.remove_send_lock(sock)

    def test_slow_member_does_not_block_other_group_operations(self):
        s = self.server
        slow_gid = s.create_group_db('alice', 'Slow', ['alice', 'bob'])
        fast_gid = s.create_group_db('carol', 'Fast', ['carol'])
        alice, _, _ = self.connect('alice')
        bob, _, _ = self.connect('bob')
        carol, _, _ = self.connect('carol')
        self.read_type(carol, 'online_users')
        remote = s.get_sock_by_username('bob')
        remote.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
        bob.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        # Raw transport stress: exceed OS buffering while this peer stops reading.
        packet = b'x' * (1024 * 1024)
        for _ in range(128):
            s.enqueue_packet(remote, packet)
        time.sleep(.2)
        self.assertGreater(s.send_queues[remote].qsize(), 0, 'test must fill OS buffering')
        client.send_msg(alice, {'type': 'group_rename', 'gid': slow_gid, 'new_name': 'Slow member'})
        self.assertTrue(self.read_type(alice, 'group_rename_result')['success'])
        started = time.monotonic()
        client.send_msg(carol, {'type': 'group_rename', 'gid': fast_gid, 'new_name': 'Still responsive'})
        self.assertTrue(self.read_type(carol, 'group_rename_result')['success'])
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(remote.gettimeout(), s.SEND_TIMEOUT_SECONDS)

    def test_send_timeout_shuts_connection_and_cleans_writer(self):
        s = self.server
        sock = Mock()
        sock.sendall.side_effect = socket.timeout('client stopped reading')
        outbox = queue.Queue()
        outbox.put((b'packet', None))
        s.send_queues[sock] = outbox
        s.send_worker(sock, outbox)
        sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        self.assertNotIn(sock, s.send_queues)
        self.assertNotIn(sock, s.send_locks)

    def test_history_uses_one_id_boundary_across_group_and_private_queries(self):
        s = self.server
        gid = s.create_group_db('alice', 'Team', ['alice', 'bob'])
        s.save_friend_relationship('alice', 'bob')
        first = s.save_message('group', 'bob', None, gid, 'group before', 'now')
        second = s.save_message('private', 'bob', 'alice', None, 'private before', 'now')
        sock = Mock()
        s.session_keys[sock] = os.urandom(16)
        s.user_friends['alice'] = {'bob'}
        events = []
        def send(sock, payload):
            events.append(payload)
            if payload['type'] == 'group_chat':
                s.save_message('private', 'bob', 'alice', None, 'after boundary', 'now')
        with patch.object(s, 'send_msg', side_effect=send):
            s.send_history(sock, 'alice')
        self.assertEqual([event['message_id'] for event in events if 'message_id' in event], [first, second])
        self.assertEqual(events[-1], {'type': 'history_end', 'boundary': second})

    def test_management_result_has_old_name_and_no_duplicate_notification(self):
        s = self.server
        gid = s.create_group_db('alice', 'Before', ['alice', 'bob'])
        alice, _, _ = self.connect('alice')
        self.read_type(alice, 'online_users')
        client.send_msg(alice, {'type': 'group_rename', 'gid': gid, 'new_name': 'After'})
        result = client.recv_msg(alice)
        self.assertEqual(result['type'], 'group_rename_result')
        self.assertEqual((result['old_name'], result['new_name']), ('Before', 'After'))
        client.send_msg(alice, {'type': 'group_transfer', 'gid': gid, 'new_owner': 'bob'})
        self.assertEqual(client.recv_msg(alice)['type'], 'group_transfer_result')

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
