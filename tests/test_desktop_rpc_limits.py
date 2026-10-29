"""The desktop line budget applies to serialized bytes, including JSON escapes."""
import base64
import io
import json
import os
import unittest
from unittest.mock import Mock, patch

from chatroom_client.e2ee_crypto import Identity, MAX_PLAINTEXT_BYTES, encrypt_message
from chatroom_client.key_vault import KeyVault
from chatroom_client.models import ChatKey
from chatroom_client.preferences import PreferencesStore
from chatroom_client.rpc import CoreRuntime, MAX_LINE_BYTES, PROTOCOL_VERSION


def unpack(lines):
    packets, parts = [], []
    for line in lines:
        packet = json.loads(line)
        if packet.get('method') != 'transport.chunk':
            if parts:
                raise AssertionError('interrupted transfer')
            packets.append(packet)
            continue
        chunk = packet['params']
        if chunk['index'] != len(parts):
            raise AssertionError('out-of-order transfer')
        parts.append(base64.b64decode(chunk['data'], validate=True))
        if len(parts) == chunk['total']:
            raw = b''.join(parts)
            if len(raw) != chunk['bytes']:
                raise AssertionError('wrong transfer size')
            packets.append(json.loads(raw))
            parts.clear()
    if parts:
        raise AssertionError('incomplete transfer')
    return packets


class DesktopRPCLimitTests(unittest.TestCase):
    def runtime(self, *, encryption=False):
        runtime = CoreRuntime(preferences=PreferencesStore(persistent=False),
                              encryption=encryption, output=io.StringIO())
        self.addCleanup(runtime.app.close)
        runtime.output.seek(0)
        runtime.output.truncate()
        return runtime

    def test_verified_large_control_character_history_preserves_every_message(self):
        runtime = self.runtime(encryption=True)
        app = runtime.app
        app.connection.running = True
        app.connection.sock = Mock()
        app.connection.endpoint = ('127.0.0.1', 12345)
        app.connection.session_key = os.urandom(16)
        app.state.username, app.state.friends = 'alice', ['bob']
        key = app.state.current_chat = ChatKey('private', 'bob')
        runtime.view.page = 'chat'
        app.activity.notify_message = Mock()
        vault = KeyVault(None, app.connection.endpoint, 'alice')
        vault.unlock_opaque(b'e' * 64, 'a' * 64, create=True)
        app.encryption.vault, app.encryption.ready = vault, True
        bob = Identity.generate()
        vault.pin_peer('bob', bob.public_bundle())
        recipients = {'alice': vault.identity.public_bundle(), 'bob': bob.public_bundle()}
        text = '\x00' * MAX_PLAINTEXT_BYTES
        for number in range(1, 23):
            envelope = encrypt_message(bob, 'bob', 'private', 'alice', text, recipients,
                                       message_id=f'{number:032x}')
            message = {'type': 'private_chat', 'from': 'bob', 'to': 'alice', 'e2ee': envelope,
                       'message_id': number, 'timestamp': '2026-10-29T16:00:00Z', 'history': False}
            self.assertLess(len(json.dumps(message).encode('utf-8')), 1024 * 1024 - 40)
            app.events.chat_message(message)
        conversation = app.state.conversation(key)
        self.assertEqual(conversation.message_ids, list(range(1, 23)))
        self.assertLess(conversation.cached_bytes, conversation.MAX_BYTES)
        self.assertTrue(all(item.encryption == 'e2ee' for item in conversation.messages))
        snapshot = runtime.view.snapshot()
        self.assertGreater(len(json.dumps(snapshot, ensure_ascii=False).encode('utf-8')), MAX_LINE_BYTES)
        runtime.output = io.StringIO()
        runtime.dirty = True
        runtime.dispatch({'jsonrpc': '2.0', 'id': 7, 'method': 'initialize',
                          'params': {'protocolVersion': PROTOCOL_VERSION}})
        lines = runtime.output.getvalue().splitlines()
        self.assertTrue(all(len(line.encode('utf-8')) <= MAX_LINE_BYTES for line in lines))
        packets = unpack(lines)
        result = next(packet['result'] for packet in packets if packet.get('id') == 7)
        changed = next(packet['params'] for packet in packets if packet.get('method') == 'state.changed')
        for state in (result['state'], changed):
            self.assertEqual([item['id'] for item in state['messages']], [str(n) for n in range(1, 23)])
            self.assertTrue(all(item['content'] == text and item['protection'] == 'e2ee'
                                for item in state['messages']))
        self.assertEqual(conversation.before_id, 1)

    def test_multibyte_text_and_pending_copies_round_trip_across_byte_boundaries(self):
        runtime = self.runtime()
        packet = {'jsonrpc': '2.0', 'method': 'state.changed', 'params': {
            'messages': [{'content': '🙂界\x01' * 1000}],
            'outgoing': [{'content': '\x00' * 1000}], 'pending': [{'text': '\x00' * 1000}]}}
        with patch('chatroom_client.rpc.MAX_LINE_BYTES', 4096), patch('chatroom_client.rpc.CHUNK_BYTES', 257):
            runtime.write(packet)
        lines = runtime.output.getvalue().splitlines()
        self.assertGreater(len(lines), 1)
        self.assertTrue(all(len(line.encode('utf-8')) <= 4096 for line in lines))
        self.assertEqual(unpack(lines), [packet])

    def test_logical_packet_overflow_is_recoverable_and_preserves_request_id(self):
        runtime = self.runtime()
        with patch('chatroom_client.rpc.MAX_PACKET_BYTES', 4096):
            runtime.write({'jsonrpc': '2.0', 'id': 19, 'result': '\x00' * 1000})
            runtime.emit('state.changed', {'messages': ['\x00' * 1000]})
        runtime.write({'jsonrpc': '2.0', 'id': 20, 'result': True})
        packets = unpack(runtime.output.getvalue().splitlines())
        self.assertEqual(packets[0]['id'], 19)
        self.assertEqual(packets[0]['error']['code'], -32000)
        self.assertEqual(packets[1]['method'], 'notice')
        self.assertEqual(packets[2], {'jsonrpc': '2.0', 'id': 20, 'result': True})
        self.assertFalse(runtime.stopped)


if __name__ == '__main__':
    unittest.main()
