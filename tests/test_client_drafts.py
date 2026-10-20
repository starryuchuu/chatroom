"""Draft restoration across accounts and server endpoints, using real Tk widgets."""
import gc
import unittest
from unittest.mock import Mock, patch

import client
from chatroom_client.preferences import PreferencesStore


class ClientDraftTests(unittest.TestCase):
    def setUp(self):
        self.root = client.tk.Tk()
        self.root.withdraw()
        self.app = client.ChatClient(self.root, preferences=PreferencesStore(persistent=False), encryption=False)
        self.app.connection.send = Mock()

    def tearDown(self):
        self.app.close()
        self.app = self.root = None
        gc.collect()

    def login_as(self, username, *, host='127.0.0.1', port=12345):
        app = self.app
        app.connection.settings.port = port
        app.connection.endpoint = (host, port)
        app.connection.settings.host = host
        app.state.username = username
        app.connection.session_key = b'0123456789abcdef'
        app.connection.sock = Mock()
        app.connection.running = True
        app.view.build_chat()

    def draft(self):
        return self.app.view.msg_entry.get('1.0', 'end-1c')

    def test_empty_draft_from_another_account_preserves_original(self):
        self.login_as('alice')
        self.app.view.msg_entry.insert('1.0', 'Alice unsent message')
        self.app.disconnect()

        self.login_as('bob')
        self.assertEqual(self.draft(), '')
        self.app.disconnect()

        self.login_as('alice')
        self.assertEqual(self.draft(), 'Alice unsent message')
        self.assertEqual(self.app.state.pending_messages, {})
        self.app.connection.send.assert_not_called()

    def test_same_account_keeps_distinct_drafts_on_different_ports(self):
        self.login_as('alice', port=12345)
        self.app.view.msg_entry.insert('1.0', 'Python server draft')
        self.app.disconnect()

        self.login_as('alice', port=12346)
        self.assertEqual(self.draft(), '')
        self.app.view.msg_entry.insert('1.0', 'Go server draft')
        self.app.disconnect()

        self.login_as('alice', port=12345)
        self.assertEqual(self.draft(), 'Python server draft')
        self.app.disconnect()
        self.login_as('alice', port=12346)
        self.assertEqual(self.draft(), 'Go server draft')
        self.app.connection.send.assert_not_called()

    def test_same_account_and_port_keeps_server_addresses_separate(self):
        self.login_as('alice', host='server-a.example')
        self.app.view.msg_entry.insert('1.0', 'Server A draft')
        self.app.disconnect()

        self.login_as('alice', host='server-b.example')
        self.assertEqual(self.draft(), '')
        self.app.disconnect()

        self.login_as('alice', host='server-a.example')
        self.assertEqual(self.draft(), 'Server A draft')
        self.app.connection.send.assert_not_called()

    def test_disconnect_uses_connected_endpoint_after_configuration_changes(self):
        self.login_as('alice', host='server-a.example', port=12345)
        self.app.view.msg_entry.insert('1.0', 'Connected server draft')
        self.app.connection.settings.port = 12346
        self.app.connection.settings.host = 'server-b.example'
        self.app.disconnect()

        self.login_as('alice', host='server-a.example', port=12345)
        self.assertEqual(self.draft(), 'Connected server draft')
        self.app.connection.send.assert_not_called()


if __name__ == '__main__':
    unittest.main()
