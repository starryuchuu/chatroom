"""Python wire-protocol interoperability against an isolated Go server binary."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('go_interop_client', ROOT / 'client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


@unittest.skipUnless(os.environ.get('CHATROOM_GO_SERVER_EXE'), 'Go binary not selected')
class GoInteropTests(unittest.TestCase):
    def setUp(self):
        probe = socket.socket()
        # Linux retains recently closed TCP endpoints in TIME_WAIT. The Go
        # listener permits address reuse; the preflight probe must do so too.
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(('127.0.0.1', 12346))
        finally:
            probe.close()
        self.tmp = tempfile.TemporaryDirectory()
        self.log = open(Path(self.tmp.name) / 'server.log', 'w', encoding='utf-8')
        self.peers = []
        self.process = subprocess.Popen(
            [str(Path(os.environ['CHATROOM_GO_SERVER_EXE']).resolve())],
            cwd=self.tmp.name, stdout=self.log, stderr=self.log,
        )
        self.addCleanup(self.cleanup_server)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.fail('Go server exited during startup')
            try:
                with socket.create_connection(('127.0.0.1', 12346), timeout=.2):
                    return
            except OSError:
                time.sleep(.05)
        self.fail('Go server startup timed out')

    def cleanup_server(self):
        for peer in self.peers:
            peer.close()
        self.process.terminate()
        self.process.wait(timeout=10)
        self.log.close()
        self.tmp.cleanup()

    def connect(self, username, password=' password ', register=False):
        peer = socket.create_connection(('127.0.0.1', 12346), timeout=5)
        self.peers.append(peer)
        public = client.recv_msg(peer)
        self.assertEqual(public['type'], 'public_key')
        rsa = client.RSA.import_key(public['key'])
        key = os.urandom(16)
        encrypted = client.PKCS1_OAEP.new(rsa).encrypt(key)
        client.send_msg(peer, {'type': 'session_key', 'key': base64.b64encode(encrypted).decode()})
        data = client.encrypt_message(json.dumps({'from': username, 'password': password}), key)
        client.send_msg(peer, {'type': 'encrypted_register' if register else 'encrypted_login', 'data': data})
        result = client.recv_msg(peer)
        self.assertEqual(result['type'], 'register_result' if register else 'login_result')
        return peer, key, result

    def read_type(self, peer, kind):
        for _ in range(100):
            msg = client.recv_msg(peer)
            self.assertIsNotNone(msg)
            if msg['type'] == kind:
                return msg
        self.fail('missing message: ' + kind)

    def test_registration_offline_requests_chat_and_group_lifecycle(self):
        for name in ('alice', 'bob', 'carol'):
            _, _, result = self.connect(name, register=True)
            self.assertTrue(result['success'])
        _, _, bad = self.connect('bob', password='wrongpass')
        self.assertFalse(bad['success'])
        alice, ak, result = self.connect('alice')
        self.assertTrue(result['success'])
        self.read_type(alice, 'online_users')
        _, _, duplicate = self.connect('alice')
        self.assertFalse(duplicate['success'])
        # Offline request must be acknowledged, replayed after login and accepted.
        client.send_msg(alice, {'type': 'friend_request', 'to': 'bob'})
        self.assertTrue(self.read_type(alice, 'friend_request_result')['success'])
        bob, bk, result = self.connect('bob')
        self.assertTrue(result['success'])
        self.assertEqual(self.read_type(bob, 'friend_request')['from'], 'alice')
        client.send_msg(bob, {'type': 'friend_response', 'to': 'alice', 'accepted': True})
        self.read_type(alice, 'friend_update')
        self.read_type(bob, 'friend_update')
        client.send_msg(alice, {'type': 'private_chat', 'to': 'bob', 'content': client.encrypt_message('你好 Bob', ak)})
        self.assertEqual(client.decrypt_message(self.read_type(bob, 'private_chat')['content'], bk), '你好 Bob')
        self.read_type(alice, 'private_chat')
        client.send_msg(alice, {'type': 'group_create', 'group_name': 'Unauthorized', 'members': ['carol']})
        self.assertFalse(self.read_type(alice, 'group_create_result')['success'])
        client.send_msg(alice, {'type': 'group_create', 'group_name': 'Team', 'members': ['bob', 'bob']})
        group = self.read_type(alice, 'group_create_result')
        self.assertTrue(group['success'])
        self.assertEqual(len(group['members']), 2)
        gid = group['gid']
        self.read_type(bob, 'group_create_result')
        client.send_msg(bob, {'type': 'group_chat', 'gid': gid, 'content': client.encrypt_message('群消息', bk)})
        self.assertEqual(client.decrypt_message(self.read_type(alice, 'group_chat')['content'], ak), '群消息')
        self.read_type(bob, 'group_chat')
        client.send_msg(alice, {'type': 'group_rename', 'gid': gid, 'new_name': 'Renamed'})
        self.assertTrue(self.read_type(alice, 'group_rename_result')['success'])
        client.send_msg(alice, {'type': 'group_transfer', 'gid': gid, 'new_owner': 'bob'})
        self.assertTrue(self.read_type(alice, 'group_transfer_result')['success'])
        client.send_msg(alice, {'type': 'group_leave', 'gid': gid})
        self.assertTrue(self.read_type(alice, 'group_leave_result')['success'])
        client.send_msg(bob, {'type': 'group_disband', 'gid': gid})
        self.assertTrue(self.read_type(bob, 'group_disband_result')['success'])

    def test_unicode_registration_and_expired_write_deadline(self):
        username = '中文用户名测试一二三四'
        password = '中文密码六个'
        _, _, result = self.connect(username, password, register=True)
        self.assertTrue(result['success'])
        peer, _, result = self.connect(username, password)
        self.assertTrue(result['success'])
        self.read_type(peer, 'online_users')
        # The original server's write deadline expired 30s after accepting TCP.
        time.sleep(31)
        client.send_msg(peer, {'type': 'group_create', 'group_name': 'Still alive', 'members': []})
        self.assertTrue(self.read_type(peer, 'group_create_result')['success'])

    def test_v107_receipts_history_boundary_and_correlated_errors(self):
        for name in ('alice', 'bob'):
            self.assertTrue(self.connect(name, register=True)[2]['success'])
        alice, ak, _ = self.connect('alice')
        bob, bk, _ = self.connect('bob')
        client.send_msg(alice, {'type': 'friend_request', 'to': 'bob'})
        self.read_type(bob, 'friend_request')
        client.send_msg(bob, {'type': 'friend_response', 'to': 'alice', 'accepted': True})
        self.read_type(alice, 'friend_update')
        self.read_type(bob, 'friend_update')
        client.send_msg(alice, {'type': 'private_chat', 'to': 'bob', 'request_id': 'private-1',
                                'content': client.encrypt_message('private receipt', ak)})
        private_ack = self.read_type(alice, 'private_chat_result')
        self.assertTrue(private_ack['success'])
        self.assertEqual(private_ack['request_id'], 'private-1')
        private_msg = self.read_type(bob, 'private_chat')
        self.assertEqual(private_msg['message_id'], private_ack['message_id'])
        self.assertEqual(self.read_type(alice, 'private_chat')['message_id'], private_ack['message_id'])
        client.send_msg(alice, {'type': 'group_create', 'group_name': 'Before', 'members': ['bob']})
        gid = self.read_type(alice, 'group_create_result')['gid']
        self.read_type(bob, 'group_create_result')
        client.send_msg(bob, {'type': 'group_chat', 'gid': gid, 'request_id': 'group-1',
                             'content': client.encrypt_message('group receipt', bk)})
        group_ack = self.read_type(bob, 'group_chat_result')
        self.assertTrue(group_ack['success'])
        self.assertEqual(group_ack['request_id'], 'group-1')
        self.assertEqual(self.read_type(alice, 'group_chat')['message_id'], group_ack['message_id'])
        self.assertEqual(self.read_type(bob, 'group_chat')['message_id'], group_ack['message_id'])
        bob.shutdown(socket.SHUT_RDWR)
        bob.close()
        for _ in range(10):
            if 'bob' not in self.read_type(alice, 'online_users')['users']:
                break
        else:
            self.fail('bob stayed online after disconnect')
        bob, bk, result = self.connect('bob')
        self.assertTrue(result['success'])
        replay = []
        began = False
        for _ in range(100):
            msg = client.recv_msg(bob)
            if msg['type'] == 'history_begin':
                began = True
            elif msg['type'] in ('private_chat', 'group_chat'):
                self.assertTrue(began)
                replay.append(msg)
            elif msg['type'] == 'history_end':
                boundary = msg['boundary']
                break
        else:
            self.fail('history_end missing')
        self.assertEqual([msg['message_id'] for msg in replay], [private_ack['message_id'], group_ack['message_id']])
        self.assertGreaterEqual(boundary, group_ack['message_id'])
        self.assertEqual([client.decrypt_message(msg['content'], bk) for msg in replay], ['private receipt', 'group receipt'])
        client.send_msg(bob, {'type': 'group_chat', 'gid': 'missing', 'request_id': 'denied', 'content': client.encrypt_message('bad target', bk)})
        denied = self.read_type(bob, 'group_chat_result')
        self.assertFalse(denied['success'])
        self.assertEqual(denied['request_id'], 'denied')
        client.send_msg(alice, {'type': 'group_rename', 'gid': gid, 'new_name': 'After'})
        # The actor gets the result directly, without a duplicate notification.
        for _ in range(20):
            msg = client.recv_msg(alice)
            self.assertNotEqual(msg['type'], 'group_rename_notification')
            if msg['type'] == 'group_rename_result':
                self.assertEqual((msg['old_name'], msg['new_name']), ('Before', 'After'))
                break
        else:
            self.fail('rename result missing')

    def test_v107_invite_decline_is_consumed_and_reinvite_can_be_accepted(self):
        for name in ('alice', 'bob'):
            self.assertTrue(self.connect(name, register=True)[2]['success'])
        alice, _, _ = self.connect('alice')
        bob, _, _ = self.connect('bob')
        client.send_msg(alice, {'type': 'friend_request', 'to': 'bob'})
        self.read_type(bob, 'friend_request')
        client.send_msg(bob, {'type': 'friend_response', 'to': 'alice', 'accepted': True})
        self.read_type(alice, 'friend_update')
        self.read_type(bob, 'friend_update')
        client.send_msg(alice, {'type': 'group_create', 'group_name': 'Invite', 'members': []})
        gid = self.read_type(alice, 'group_create_result')['gid']
        client.send_msg(alice, {'type': 'group_invite', 'gid': gid, 'to': 'bob'})
        self.read_type(bob, 'group_invite')
        client.send_msg(bob, {'type': 'group_invite_response', 'gid': gid, 'accepted': False})
        self.assertTrue(self.read_type(bob, 'group_invite_response_result')['success'])
        client.send_msg(bob, {'type': 'group_join', 'gid': gid})
        self.assertFalse(self.read_type(bob, 'group_join_result')['success'])
        client.send_msg(alice, {'type': 'group_invite', 'gid': gid, 'to': 'bob'})
        self.read_type(bob, 'group_invite')
        client.send_msg(bob, {'type': 'group_join', 'gid': gid})
        self.assertTrue(self.read_type(bob, 'group_join_result')['success'])

    def test_real_v107_tk_client_clears_input_only_after_go_receipt(self):
        for name in ('alice', 'bob'):
            self.assertTrue(self.connect(name, register=True)[2]['success'])
        bob, bk, _ = self.connect('bob')
        root = client.tk.Tk()
        root.withdraw()
        app = client.ChatClient(root)
        try:
            app.username_entry.insert(0, 'alice')
            app.password_entry.insert(0, ' password ')
            app.port_entry.delete(0, client.tk.END)
            app.port_entry.insert(0, '12346')
            app.login()
            def wait_ui(condition):
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    root.update()
                    if condition():
                        return
                    time.sleep(.01)
                self.fail('Tk client did not receive expected Go event')
            wait_ui(lambda: app.running)
            app.handle_friend_request = lambda name: app.queue_send({'type': 'friend_response', 'to': name, 'accepted': True})
            client.send_msg(bob, {'type': 'friend_request', 'to': 'alice'})
            wait_ui(lambda: 'bob' in app.friends)
            app.friends_listbox.selection_set(0)
            app.select_friend(None)
            app.msg_entry.insert('1.0', 'Tk to Go')
            app.send_msg()
            self.assertEqual(app.msg_entry.get('1.0', 'end-1c'), 'Tk to Go')
            self.assertEqual(len(app.pending_messages), 1)
            wait_ui(lambda: not app.pending_messages and len(app.private_chats.get('bob', [])) == 1)
            self.assertEqual(app.msg_entry.get('1.0', 'end-1c'), '')
            forwarded = self.read_type(bob, 'private_chat')
            self.assertEqual(client.decrypt_message(forwarded['content'], bk), 'Tk to Go')
            self.assertIn(forwarded['message_id'], app.seen_message_ids)
            self.assertIn('服务器已保存', app.status_label.cget('text'))
        finally:
            app.close()


if __name__ == '__main__':
    unittest.main()
