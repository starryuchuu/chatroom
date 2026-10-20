"""Client failures discovered during the release audit."""
import gc
import time
import unittest
from unittest.mock import Mock, patch

import client
from chatroom_client.connection import AuthResult, ClientSettings, ConnectionManager
from chatroom_client.preferences import PreferencesStore


class AuthenticationFailureTests(unittest.TestCase):
    def test_socket_creation_failure_finishes_authentication_and_allows_retry(self):
        connection = ConnectionManager(ClientSettings())
        self.addCleanup(connection.close)
        connection.generation = 1
        connection.auth_busy = True
        with patch('chatroom_client.connection.socket.socket', side_effect=OSError('socket limit reached')):
            connection._authenticate(1, ('127.0.0.1', 12345), 'alice', 'password', False)
        result = connection.events.get_nowait()
        self.assertIsInstance(result, AuthResult)
        self.assertEqual(result.error, 'socket limit reached')
        self.assertIsNone(result.sock)
        self.assertTrue(connection.accept_auth(result))
        self.assertFalse(connection.auth_busy)
        self.assertFalse(connection.running)
        with patch.object(connection, 'start_worker') as start:
            self.assertTrue(connection.authenticate('alice', 'password'))
        start.assert_called_once()


class ClientWindowReviewTests(unittest.TestCase):
    def setUp(self):
        self.root = client.tk.Tk()
        self.root.withdraw()
        self.app = client.ChatClient(self.root, preferences=PreferencesStore(persistent=False), encryption=False)
        self.app.connection.running = True
        self.app.connection.sock = Mock()
        self.app.connection.session_key = b'0123456789abcdef'
        self.app.state.username = 'alice'
        self.app.view.build_chat()
        self.app.connection.send = Mock()

    def tearDown(self):
        self.app.close()
        self.app = self.root = None
        gc.collect()

    def test_group_creation_uses_members_displayed_in_its_window(self):
        self.app.state.friends = ['bob', 'carol']
        self.app.view.groups_ui.create()
        window = next(child for child in self.root.winfo_children()
                      if isinstance(child, client.tk.Toplevel))
        children = window.winfo_children()
        name_entry = next(child for child in children if isinstance(child, client.tk.Entry))
        members = next(child for child in children if isinstance(child, client.tk.Listbox))
        create_button = next(child for child in children if isinstance(child, client.tk.Button))
        name_entry.insert(0, 'Team')
        members.selection_set(0)
        # A fresh server snapshot can arrive while this nonmodal window is open.
        self.app.handle_server_message({'type': 'friends_list', 'friends': ['carol', 'bob']})
        create_button.invoke()
        self.app.connection.send.assert_called_once_with({
            'type': 'group_create', 'from': 'alice', 'group_name': 'Team', 'members': ['bob'],
        })

    def test_closing_cancels_owned_reconnect_and_sync_timers(self):
        callback = Mock()
        self.app.view.schedule(20000, callback)
        pending = set(self.app.view._scheduled)
        self.assertTrue(pending)
        self.app.close()
        deadline = time.monotonic() + 3
        while not self.app.view._destroyed and time.monotonic() < deadline:
            self.root.update()
            time.sleep(.005)
        self.assertTrue(self.app.view._destroyed)
        remaining = set(self.root.tk.call('after', 'info'))
        self.assertFalse(pending & remaining)
        self.assertFalse(self.app.view._scheduled)
        callback.assert_not_called()


if __name__ == '__main__':
    unittest.main()
