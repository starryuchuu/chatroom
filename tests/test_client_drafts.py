"""Draft restoration across accounts and server endpoints, using real Tk widgets."""
import gc
import unittest
from unittest.mock import Mock, patch

import client


class ClientDraftTests(unittest.TestCase):
    def setUp(self):
        self.root = client.tk.Tk()
        self.root.withdraw()
        self.app = client.ChatClient(self.root)
        self.app.queue_send = Mock()

    def tearDown(self):
        self.app.close()
        self.app = self.root = None
        gc.collect()

    def login_as(self, username, *, host='127.0.0.1', port=12345):
        app = self.app
        app.server_port = port
        app.connection_endpoint = (host, port)
        app.username = username
        app.session_key = b'0123456789abcdef'
        app.sock = Mock()
        app.running = True
        app.build_chat()

    def draft(self):
        return self.app.msg_entry.get('1.0', 'end-1c')

    def test_empty_draft_from_another_account_preserves_original(self):
        self.login_as('alice')
        self.app.msg_entry.insert('1.0', 'Alice unsent message')
        self.app.disconnect()

        self.login_as('bob')
        self.assertEqual(self.draft(), '')
        self.app.disconnect()

        self.login_as('alice')
        self.assertEqual(self.draft(), 'Alice unsent message')
        self.assertEqual(self.app.pending_messages, {})
        self.app.queue_send.assert_not_called()

    def test_same_account_keeps_distinct_drafts_on_different_ports(self):
        self.login_as('alice', port=12345)
        self.app.msg_entry.insert('1.0', 'Python server draft')
        self.app.disconnect()

        self.login_as('alice', port=12346)
        self.assertEqual(self.draft(), '')
        self.app.msg_entry.insert('1.0', 'Go server draft')
        self.app.disconnect()

        self.login_as('alice', port=12345)
        self.assertEqual(self.draft(), 'Python server draft')
        self.app.disconnect()
        self.login_as('alice', port=12346)
        self.assertEqual(self.draft(), 'Go server draft')
        self.app.queue_send.assert_not_called()

    def test_same_account_and_port_keeps_server_addresses_separate(self):
        self.login_as('alice', host='server-a.example')
        self.app.msg_entry.insert('1.0', 'Server A draft')
        self.app.disconnect()

        self.login_as('alice', host='server-b.example')
        self.assertEqual(self.draft(), '')
        self.app.disconnect()

        self.login_as('alice', host='server-a.example')
        self.assertEqual(self.draft(), 'Server A draft')
        self.app.queue_send.assert_not_called()

    def test_disconnect_uses_connected_endpoint_after_configuration_changes(self):
        self.login_as('alice', host='server-a.example', port=12345)
        self.app.msg_entry.insert('1.0', 'Connected server draft')
        self.app.server_port = 12346
        with patch.object(client, 'SERVER_HOST', 'server-b.example'):
            self.app.disconnect()

        self.login_as('alice', host='server-a.example', port=12345)
        self.assertEqual(self.draft(), 'Connected server draft')
        self.app.queue_send.assert_not_called()


if __name__ == '__main__':
    unittest.main()
