"""Desktop interactions introduced by the simplified client layout."""
import gc
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import client
from chatroom_client.models import ChatKey, Message
from chatroom_client.preferences import PreferencesStore


class ClientLayoutTests(unittest.TestCase):
    def setUp(self):
        self.root = client.tk.Tk()
        self.root.withdraw()
        self.app = client.ChatClient(self.root, preferences=PreferencesStore(persistent=False), encryption=False)
        self.app.connection.running = True
        self.app.connection.sock = Mock()
        self.app.state.username = 'alice'
        self.app.view.build_chat()

    def tearDown(self):
        self.app.close()
        self.app = self.root = None
        gc.collect()

    def test_online_panel_toggle_preserves_the_latest_snapshot_and_draft(self):
        view = self.app.view
        view.msg_entry.insert('1.0', 'unsent draft')
        view.update_online_users(['alice', 'bob'])
        self.assertFalse(view.online_visible)
        view.toggle_online()
        self.assertEqual(view.online_panel.winfo_manager(), 'grid')
        view.toggle_online()
        view.update_online_users(['alice', 'carol'])
        view.toggle_online()
        self.assertEqual(view.online_listbox.get(0, client.tk.END), ('alice', 'carol'))
        self.assertEqual(view.input_text(), 'unsent draft')

    def test_shift_and_ctrl_enter_insert_newlines_without_sending(self):
        view = self.app.view
        self.app.send_message = Mock()
        for modifier in (0x1, 0x4, 0x5):
            view.msg_entry.delete('1.0', client.tk.END)
            view.msg_entry.insert('1.0', 'draft')
            view.on_message_entry_key(SimpleNamespace(state=modifier))
            self.assertEqual(view.input_text(), 'draft\n')
        self.app.send_message.assert_not_called()
        self.assertEqual(view.on_message_entry_key(SimpleNamespace(state=0)), 'break')
        self.app.send_message.assert_called_once()

    def test_primary_send_button_restores_contrast_after_state_changes(self):
        view = self.app.view
        self.assertEqual(view.send_button.cget('state'), 'disabled')
        self.assertEqual(view.send_button.cget('bg'), view.colors['selected'])
        key = ChatKey('private', 'bob')
        self.app.state.current_chat = key
        self.app.state.conversation(key).add(Message('bob', 'hello', encryption='legacy'))
        view.render_conversation(key)
        self.assertEqual(view.send_button.cget('state'), 'normal')
        self.assertEqual(view.send_button.cget('bg'), view.colors['accent'])
        self.app.state.pending_messages['pending'] = 'hello back'
        view.refresh_controls()
        self.assertEqual(view.send_button.cget('state'), 'disabled')
        self.assertEqual(view.send_button.cget('bg'), view.colors['selected'])


if __name__ == '__main__':
    unittest.main()
