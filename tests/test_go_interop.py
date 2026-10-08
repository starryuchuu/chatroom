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


if __name__ == '__main__':
    unittest.main()
