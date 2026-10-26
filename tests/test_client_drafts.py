"""Draft restoration across accounts and server endpoints, using real Tk widgets."""
import gc
import unittest
from unittest.mock import Mock, patch

import client
from chatroom_client.models import ChatKey
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

    def test_private_group_and_unselected_drafts_are_independent(self):
        self.login_as('alice')
        a, b = ChatKey('private', 'same'), ChatKey('group', 'same')
        self.app.state.groups['same'] = {'group_name': 'Synthetic group'}
        self.app.view.replace_input('Unselected draft')
        self.app.select_chat(a)
        self.assertEqual(self.draft(), '')
        self.app.view.replace_input('Private draft')
        self.app.select_chat(b)
        self.assertEqual(self.draft(), '')
        self.app.view.replace_input('Group draft')
        self.app.select_chat(a)
        self.assertEqual(self.draft(), 'Private draft')
        self.app.clear_chat_selection()
        self.assertEqual(self.draft(), 'Unselected draft')
        self.app.select_chat(b)
        self.assertEqual(self.draft(), 'Group draft')

    def test_same_selection_keeps_input_and_switching_clears_undo_history(self):
        self.login_as('alice')
        a, b = ChatKey('private', 'a'), ChatKey('private', 'b')
        self.app.select_chat(a)
        self.app.view.msg_entry.insert('1.0', 'Synthetic A secret')
        self.app.select_chat(a)
        self.assertEqual(self.draft(), 'Synthetic A secret')
        self.app.select_chat(b)
        with self.assertRaises(client.tk.TclError):
            self.app.view.msg_entry.edit_undo()
        self.assertEqual(self.draft(), '')
        self.app.select_chat(a)
        self.assertEqual(self.draft(), 'Synthetic A secret')

    def test_ack_in_another_chat_clears_only_original_unchanged_draft(self):
        self.login_as('alice')
        a, b = ChatKey('private', 'a'), ChatKey('private', 'b')
        self.app.select_chat(a)
        self.app.view.replace_input('Synthetic sent input')
        self.app.send_message()
        record = self.app.sends.records[0]
        self.app.select_chat(b)
        self.app.view.replace_input('Synthetic B draft')
        self.app.handle_server_message({'type': 'private_chat_result', 'request_id': record.request_id, 'success': True})
        self.assertEqual(self.draft(), 'Synthetic B draft')
        self.app.select_chat(a)
        self.assertEqual(self.draft(), '')

    def test_late_ack_preserves_edited_draft_while_another_chat_is_active(self):
        self.login_as('alice')
        a, b = ChatKey('private', 'a'), ChatKey('private', 'b')
        self.app.select_chat(a)
        self.app.view.replace_input('Synthetic original')
        self.app.send_message()
        record = self.app.sends.records[0]
        self.app.view.replace_input('Synthetic edited')
        self.app.select_chat(b)
        self.app.handle_server_message({'type': 'private_chat_result', 'request_id': record.request_id, 'success': True})
        self.app.select_chat(a)
        self.assertEqual(self.draft(), 'Synthetic edited')

    def test_conversation_drafts_survive_login_but_do_not_cross_accounts(self):
        self.login_as('alice')
        a = ChatKey('private', 'a')
        self.app.select_chat(a)
        self.app.view.replace_input('Synthetic Alice conversation draft')
        self.app.disconnect()
        self.login_as('bob')
        self.app.select_chat(a)
        self.assertEqual(self.draft(), '')
        self.app.disconnect()
        self.login_as('alice')
        self.assertEqual(self.draft(), '')
        self.app.select_chat(a)
        self.assertEqual(self.draft(), 'Synthetic Alice conversation draft')

    def test_removed_group_draft_is_not_restored_after_rejoin(self):
        self.login_as('alice')
        key = ChatKey('group', 'g')
        self.app.state.groups['g'] = {'group_name': 'Synthetic group'}
        self.app.select_chat(key)
        self.app.view.replace_input('Synthetic obsolete group draft')
        self.app.select_chat(ChatKey('private', 'peer'))
        self.app.events.remove_group('g')
        self.app.state.groups['g'] = {'group_name': 'Synthetic rejoined group'}
        self.app.select_chat(key)
        self.assertEqual(self.draft(), '')
        self.app.view.replace_input('Synthetic selected group draft')
        self.app.events.remove_group('g')
        self.assertEqual(self.draft(), '')


if __name__ == '__main__':
    unittest.main()
