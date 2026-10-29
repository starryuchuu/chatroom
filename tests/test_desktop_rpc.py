"""Desktop boundary regressions: headless imports, scopes, trust and real E2EE."""
import io
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock

from chatroom_client.models import ChatKey, Message
from chatroom_client.preferences import PreferencesStore
from chatroom_client.rpc import CoreRuntime, PROTOCOL_VERSION
from test_system_reliability import Service


ROOT = Path(__file__).resolve().parents[1]
PASSWORD = 'desktop-unified-test-password'


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.runtime = CoreRuntime(preferences=PreferencesStore(persistent=False), encryption=False, output=self.output)
        self.addCleanup(self.runtime.app.close)
        self.view, self.app = self.runtime.view, self.runtime.app

    def invoke(self, method, **params):
        return self.runtime.invoke(method, {'session': self.view.session, **params})

    def test_protocol_version_and_passwords_never_in_state(self):
        with self.assertRaisesRegex(ValueError, '版本'):
            self.invoke('initialize', protocolVersion=1)
        with self.assertRaisesRegex(ValueError, '版本'):
            self.invoke('initialize', protocolVersion=999)
        initial = self.invoke('initialize', protocolVersion=PROTOCOL_VERSION)
        self.assertEqual(initial['implementation'], 'python')
        self.view.password = 'do-not-serialize-this-password'
        self.assertNotIn(self.view.password, json.dumps(self.view.snapshot()))

    def test_stale_session_and_chat_cannot_send_or_replace_draft(self):
        self.app.state.username = 'alice'
        self.app.state.friends = ['bob', 'carol']
        self.invoke('conversation.select', key={'kind': 'private', 'target': 'bob'}, draft='')
        self.invoke('draft.set', key={'kind': 'private', 'target': 'bob'}, text='Bob draft')
        self.invoke('conversation.select', key={'kind': 'private', 'target': 'carol'}, draft='Bob latest edit')
        self.assertEqual(self.app.state.drafts[self.app.draft_key(ChatKey('private', 'bob'))], 'Bob latest edit')
        with self.assertRaisesRegex(ValueError, '会话'):
            self.invoke('draft.set', key={'kind': 'private', 'target': 'bob'}, text='wrong chat')
        self.assertEqual(self.view.input_text(), '')
        old = self.view.session
        self.view.build_login()
        with self.assertRaisesRegex(ValueError, '会话'):
            self.runtime.invoke('friend.add', {'session': old, 'username': 'other'})

    def test_confirmation_cannot_survive_disconnect(self):
        self.app.state.username = 'alice'
        old_session = self.view.session
        self.runtime.incoming.put({'jsonrpc': '2.0', 'id': 1, 'method': 'session.disconnect', 'params': {'session': old_session}})
        self.assertFalse(self.runtime.confirm('Trust', 'Check this identity'))
        self.assertNotEqual(old_session, self.view.session)
        self.assertIsNone(self.runtime.prompt)

    def test_prompt_blocks_other_mutations_but_allows_explicit_reply(self):
        original_emit = self.runtime.emit
        def emit(method, params):
            original_emit(method, params)
            if method == 'prompt':
                self.runtime.incoming.put({'jsonrpc': '2.0', 'id': 1, 'method': 'profile.select',
                    'params': {'session': self.view.session, 'name': 'Go 本机'}})
                self.runtime.incoming.put({'jsonrpc': '2.0', 'id': 2, 'method': 'prompt.reply',
                    'params': {'session': self.view.session, 'id': params['id'], 'accepted': True}})
        self.runtime.emit = emit
        self.assertTrue(self.runtime.confirm('Trust', 'Verify'))
        self.assertEqual(self.app.connection.settings.port, 12345)
        packets = [json.loads(line) for line in self.output.getvalue().splitlines()]
        self.assertTrue(any(item.get('id') == 1 and 'error' in item for item in packets))

    def test_large_message_ids_are_strings_and_failed_messages_stay_failed(self):
        key = ChatKey('private', 'bob')
        self.app.state.current_chat = key
        self.app.state.conversation(key).add(Message('bob', '[验证失败]', message_id=2 ** 62, encryption='failed'))
        message = self.view.snapshot()['messages'][0]
        self.assertEqual(message['id'], str(2 ** 62))
        self.assertEqual(message['protection'], 'failed')

    def test_request_cannot_be_answered_on_replacement_socket(self):
        callback = Mock()
        self.view.ask_request(('friend', 'bob'), 'Friend', 'Request', callback)
        token = next(iter(self.view.requests))
        self.app.connection.sock = Mock()
        self.app.connection.running = True
        with self.assertRaisesRegex(ValueError, '连接'):
            self.invoke('request.reply', id=token, accepted=True)
        callback.assert_not_called()


class CorePeer:
    def __init__(self, directory):
        self.process = subprocess.Popen([sys.executable, '-u', str(ROOT / 'core_client.py')], cwd=ROOT,
            env=dict(os.environ, CHATROOM_CONFIG_DIR=str(directory)), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', bufsize=1)
        self.events = []
        self.condition = threading.Condition()
        self.counter = 0
        self.state = None
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()
        self.request('initialize', {'protocolVersion': PROTOCOL_VERSION}, scoped=False)
        self.wait(lambda: self.state is not None)

    def read(self):
        for line in self.process.stdout:
            packet = json.loads(line)
            with self.condition:
                self.events.append(packet)
                if packet.get('method') == 'state.changed':
                    self.state = packet['params']
                self.condition.notify_all()

    def wait(self, predicate, timeout=30):
        deadline = time.monotonic() + timeout
        with self.condition:
            while not predicate():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError('Desktop core did not reach expected state: ' + str(self.state and {
                        field: self.state[field] for field in ('page', 'authStatus', 'status')}))
                self.condition.wait(min(remaining, .1))

    def request(self, method, params=None, *, scoped=True):
        self.counter += 1
        identifier = self.counter
        data = dict(params or {})
        if scoped and self.state:
            data['session'] = self.state['session']
        with self.condition:
            self.process.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': identifier, 'method': method, 'params': data}) + '\n')
            self.process.stdin.flush()
        self.wait(lambda: any(packet.get('id') == identifier for packet in self.events))
        packet = next(packet for packet in self.events if packet.get('id') == identifier)
        if 'error' in packet:
            raise AssertionError(packet['error']['message'])
        return packet.get('result')

    def wait_state(self, predicate):
        self.wait(lambda: self.state is not None and predicate(self.state))

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.reader.join(3)
        self.process.stdout.close()
        self.process.stderr.close()


class HeadlessTests(unittest.TestCase):
    def test_entry_point_does_not_import_tk_and_stdout_is_only_rpc(self):
        command = ('import sys; import core_client; from chatroom_client.rpc import CoreRuntime; '
                   'assert not any(name.startswith("tkinter") for name in sys.modules); core_client.main()')
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, '-c', command], cwd=ROOT,
                env=dict(os.environ, CHATROOM_CONFIG_DIR=directory, PYTHONIOENCODING='cp1252'), input='not-json\n' + json.dumps({
                    'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': PROTOCOL_VERSION}}) + '\n',
                text=True, encoding='utf-8', capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(ord(character) > 127 for character in result.stdout))
        packets = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertTrue(any(item.get('id') == 1 and 'result' in item for item in packets))
        self.assertTrue(any(item.get('error', {}).get('code') == -32600 for item in packets))


class WireScenarios:
    def test_two_headless_clients_encrypt_messages_and_recover_history(self):
        service = Service(self.backend)
        self.addCleanup(service.close)
        service.start()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        peers = []
        for username in ('alice', 'bob'):
            peer = CorePeer(Path(temporary.name) / username)
            self.addCleanup(peer.close)
            peers.append(peer)
            peer.request('profile.save', {'name': 'Test', 'host': '127.0.0.1', 'port': service.port, 'fingerprint': None})
            peer.request('auth.login', {'username': username, 'password': PASSWORD, 'register': True})
            peer.wait(lambda: any(item.get('method') == 'auth.registered' for item in peer.events))
            peer.wait_state(lambda state: not state['busy'])
            peer.request('auth.login', {'username': username, 'password': PASSWORD})
            peer.wait_state(lambda state: state['page'] == 'chat' and state['encryption']['ready'] and not state['syncing'])
        alice, bob = peers
        alice.request('friend.add', {'username': 'bob'})
        bob.wait_state(lambda state: bool(state['requests']))
        bob.request('request.reply', {'id': bob.state['requests'][0]['id'], 'accepted': True})
        for peer, username in ((alice, 'bob'), (bob, 'alice')):
            peer.wait_state(lambda state: any(item['key']['target'] == username for item in state['conversations']))
            peer.request('conversation.select', {'key': {'kind': 'private', 'target': username}, 'draft': ''})
            peer.wait_state(lambda state: state['currentChat'] == {'kind': 'private', 'target': username})
        plaintext = 'Electron 核心真实加密消息🙂'
        alice.request('message.send', {'key': alice.state['currentChat'], 'text': plaintext})
        for peer in peers:
            peer.wait_state(lambda state: any(item['content'] == plaintext and item['protection'] == 'e2ee' for item in state['messages']))
            peer.wait_state(lambda state: not state['pending'])
        # Existing server storage exposes only an E2EE envelope, not plaintext.
        self.assertNotIn(plaintext, json.dumps(service.database(), ensure_ascii=False))
        self.assertNotIn(plaintext, service.log_path.read_text(encoding='utf-8'))
        alice.request('group.create', {'name': '真实群聊', 'members': ['bob']})
        alice.wait_state(lambda state: bool(state['groups']))
        gid = next(iter(alice.state['groups']))
        for peer in peers:
            peer.wait_state(lambda state: gid in state['groups'])
            peer.request('conversation.select', {'key': {'kind': 'group', 'target': gid}, 'draft': ''})
            peer.wait_state(lambda state: state['currentChat'] == {'kind': 'group', 'target': gid})
        before = {peer: len(peer.events) for peer in peers}
        group_text = '群成员经过显式确认的加密消息🙂'
        alice.request('message.send', {'key': {'kind': 'group', 'target': gid}, 'text': group_text})
        for peer in peers:
            peer.wait(lambda: any(item.get('method') == 'prompt' for item in peer.events[before[peer]:]))
            prompt = next(item['params'] for item in peer.events[before[peer]:] if item.get('method') == 'prompt')
            self.assertEqual({item['username'] for item in prompt['recipients']}, {'alice', 'bob'})
            peer.request('prompt.reply', {'id': prompt['id'], 'accepted': True})
        for peer, username in ((alice, 'bob'), (bob, 'alice')):
            peer.wait_state(lambda state: any(item['content'] == group_text and item['protection'] == 'e2ee' for item in state['messages']))
            peer.request('conversation.select', {'key': {'kind': 'private', 'target': username}, 'draft': ''})
            peer.wait_state(lambda state: state['currentChat'] == {'kind': 'private', 'target': username})
        alice.request('draft.set', {'key': alice.state['currentChat'], 'text': '保留的草稿'})
        old_session = alice.state['session']
        alice.request('session.disconnect')
        alice.wait_state(lambda state: state['page'] == 'login' and state['session'] != old_session)
        alice.request('auth.login', {'username': 'alice', 'password': PASSWORD})
        alice.wait_state(lambda state: state['page'] == 'chat' and not state['syncing'] and state['encryption']['ready'])
        alice.request('conversation.select', {'key': {'kind': 'private', 'target': 'bob'}, 'draft': ''})
        alice.wait_state(lambda state: any(item['content'] == plaintext and item['protection'] == 'e2ee' for item in state['messages']))
        self.assertTrue(any(item.get('method') == 'draft.changed' and item['params']['text'] == '保留的草稿' for item in alice.events))
        for path in Path(temporary.name).rglob('client.json'):
            self.assertNotIn(plaintext, path.read_text())
            self.assertNotIn(PASSWORD, path.read_text())


class PythonWireTests(WireScenarios, unittest.TestCase):
    backend = 'python'


@unittest.skipUnless(os.environ.get('CHATROOM_GO_SERVER_EXE'), 'Go interoperability binary not configured')
class GoWireTests(WireScenarios, unittest.TestCase):
    backend = 'go'
