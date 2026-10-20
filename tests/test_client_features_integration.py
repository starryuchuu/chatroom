"""Desktop settings, unread activity and reconnect against real server processes."""
import gc
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import patch

import client
from chatroom_client.models import ChatKey
from chatroom_client.preferences import PreferencesStore, ServerProfile
from test_system_reliability import PASSWORD, Service


class DesktopFeatureScenarios:
    """Run the same user-visible recovery contract against both implementations."""

    def setUp(self):
        self.service = Service(self.backend)
        self.addCleanup(self.service.close)
        self.service.start()
        self.config_dir = tempfile.TemporaryDirectory(prefix='chatroom-desktop-prefs-')
        self.addCleanup(self.config_dir.cleanup)
        self.config_path = Path(self.config_dir.name) / 'client.json'
        self.root = self.app = None
        self.counter = 0

    def make_friends(self):
        for name in ('alice', 'bob', 'carol'):
            self.service.connect(name, register=True)
        alice = self.service.connect('alice')
        bob = self.service.connect('bob')
        carol = self.service.connect('carol')
        for peer in (bob, carol):
            result = alice.request({'type': 'friend_request', 'to': peer.username}, 'friend_request_result')
            self.assertTrue(result['success'], result)
            peer.wait(lambda event: event.get('type') == 'friend_request')
            peer.send({'type': 'friend_response', 'to': 'alice', 'accepted': True})
            peer.wait(lambda event: event.get('type') == 'friend_update')
            alice.wait(lambda event: event.get('type') == 'friend_update' and
                       event.get('friend') == peer.username)
        after = len(bob.events)
        alice.close()
        bob.wait(lambda event: event.get('type') == 'online_users' and
                 'alice' not in event.get('users', []), after=after)
        return bob, carol

    def send_private(self, peer, content):
        self.counter += 1
        result = peer.request({
            'type': 'private_chat', 'to': 'alice', 'request_id': f'desktop-{self.counter}',
            'content': client.encrypt_message(content, peer.key),
        }, 'private_chat_result')
        self.assertTrue(result['success'], result)
        return result['message_id']

    def open_client(self):
        profile = ServerProfile('Integration server', '127.0.0.1', self.service.port,
                                self.service.fingerprint)
        preferences = PreferencesStore(self.config_path, default_profile=profile)
        preferences.save_profile(profile, replace_name=profile.name)
        self.root = client.tk.Tk()
        self.root.withdraw()
        self.addCleanup(self.close_client)
        self.app = client.ChatClient(self.root, preferences=preferences, encryption=False)
        self.assertEqual(self.app.connection.settings.host, profile.host)
        self.assertEqual(self.app.connection.settings.port, profile.port)
        self.assertEqual(self.app.connection.settings.expected_fingerprint, profile.fingerprint)
        self.alerts = []
        self.app.activity.notify = lambda title, text: self.alerts.append((title, text))
        # Keeping the window hidden models an inactive desktop window on either
        # platform, without depending on which CI process owns keyboard focus.
        self.app.activity.is_visible = lambda key: False
        self.app.view.username_entry.insert(0, 'alice')
        self.app.view.password_entry.insert(0, PASSWORD)
        self.app.login()
        self.wait_ui(lambda: self.app.connection.running and
                     {'bob', 'carol'} <= set(self.app.state.friends))
        return self.app

    def wait_ui(self, predicate, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.root.update()
            if predicate():
                return
            time.sleep(.005)
        self.fail('Desktop did not reach the expected state; server log:\n' +
                  self.service.log_path.read_text(encoding='utf-8')[-5000:])

    def pump_for(self, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.root.update()
            time.sleep(.005)

    def close_client(self):
        if self.app is None:
            if self.root is not None:
                self.root.destroy()
                self.root = None
            return
        self.app.close()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                if not self.root.winfo_exists():
                    break
                self.root.update()
            except client.tk.TclError:
                break
            time.sleep(.005)
        self.app = self.root = None
        # Tk objects must be collected on the GUI thread before a later socket
        # worker can happen to trigger cyclic garbage collection.
        gc.collect()

    def test_saved_profile_unread_and_multi_page_automatic_reconnect(self):
        bob, carol = self.make_friends()
        seed_id = self.send_private(bob, 'old baseline message')
        app = self.open_client()
        endpoint = ('127.0.0.1', self.service.port)
        key = ChatKey('private', 'bob')
        selected = ChatKey('private', 'carol')
        self.wait_ui(lambda: app.preferences.account(endpoint, 'alice').get('sync_cursor', -1) >= seed_id)
        self.assertEqual(app.state.conversation(key).unread_count, 0)
        self.assertEqual(self.alerts, [], 'the initial history page triggered a desktop alert')
        app.select_chat(selected)

        app.preferences.set_notifications(do_not_disturb=True)
        quiet_id = self.send_private(bob, 'quiet live message')
        sent_echo = bob.wait(lambda event: event.get('type') == 'private_chat' and
                             event.get('message_id') == quiet_id)
        self.assertIs(sent_echo.get('history'), False)
        self.wait_ui(lambda: quiet_id in app.state.conversation(key).message_ids)
        self.assertEqual(app.state.conversation(key).unread_count, 1)
        self.assertEqual(self.alerts, [])
        app.preferences.set_notifications(do_not_disturb=False)
        live_id = self.send_private(bob, 'ordinary live message')
        self.wait_ui(lambda: live_id in app.state.conversation(key).message_ids)
        self.assertEqual(app.state.conversation(key).unread_count, 2)
        self.assertEqual(len(self.alerts), 1)

        # A real, confirmed outgoing message never counts as unread.
        app.view.msg_entry.insert('1.0', 'confirmed outgoing message')
        app.send_message()
        self.wait_ui(lambda: not app.state.pending_messages and
                     len(app.state.conversation(selected).messages) == 1)
        self.assertEqual(app.state.conversation(selected).unread_count, 0)

        # An enqueued send whose result is unknown must retain the input and
        # must not be submitted again after reconnecting with a new socket.
        uncertain = 'unconfirmed private draft'
        app.view.msg_entry.insert('1.0', uncertain)
        accepted_for_send = []
        with patch.object(app.connection, 'send', side_effect=accepted_for_send.append):
            app.send_message()
        self.assertEqual(len(accepted_for_send), 1)
        self.assertEqual(len(app.state.pending_messages), 1)

        after = len(bob.events)
        app.connection.sock.shutdown(socket.SHUT_RDWR)
        bob.wait(lambda event: event.get('type') == 'online_users' and
                 'alice' not in event.get('users', []), after=after)
        # The GUI event pump has not run since the disconnect. More than two
        # pages therefore accumulate before its first automatic retry can run.
        offline_ids = [self.send_private(bob, f'offline message {index:03}') for index in range(205)]
        last_id = offline_ids[-1]
        self.wait_ui(lambda: app.connection.running and not app.reconnecting and
                     last_id in app.state.conversation(key).message_ids and
                     app.preferences.account(endpoint, 'alice').get('sync_cursor', -1) >= last_id,
                     timeout=25)
        conversation = app.state.conversation(key)
        self.assertEqual(conversation.message_ids, [seed_id, quiet_id, live_id, *offline_ids])
        self.assertEqual(conversation.unread_count, 207)
        self.assertEqual(conversation.preview, 'offline message 204')
        self.assertEqual(len(self.alerts), 1, 'history catchup produced a desktop alert storm')
        self.assertEqual(app.state.current_chat, selected)
        self.assertEqual(len(app.view.friends_listbox.curselection()), 1)
        app.view.select_friend(None)
        self.assertEqual(app.state.current_chat, selected, 'badges changed the selected friend identity')
        self.assertEqual(app.view.input_text(), uncertain)

        app.handle_server_message({
            'type': 'private_chat', 'from': 'bob', 'to': 'alice', 'message_id': last_id,
            'content': client.encrypt_message('duplicate must not replace original', app.connection.session_key),
        })
        self.assertEqual(conversation.unread_count, 207)
        self.assertEqual(conversation.preview, 'offline message 204')
        self.assertEqual(len(self.alerts), 1)
        rows = self.service.database()
        self.assertEqual(sum(record[2] == 'alice' for record in rows.values()), 1,
                         'the uncertain draft was automatically resent')

        self.root.deiconify()
        self.root.focus_force()
        self.root.update()
        app.activity.is_visible = lambda candidate: candidate == app.state.current_chat
        app.select_chat(key)
        app.activity.focus_changed()
        self.assertEqual(conversation.unread_count, 0)
        app.activity.flush()
        restored = PreferencesStore(self.config_path)
        self.assertEqual(restored.selected_profile.name, 'Integration server')
        self.assertEqual(restored.selected_profile.port, self.service.port)
        encoded = self.config_path.read_text(encoding='utf-8')
        for secret in (PASSWORD, uncertain, 'confirmed outgoing message', 'offline message 204'):
            self.assertNotIn(secret, encoded)

    def test_manual_disconnect_cancels_scheduled_reconnect_and_forgets_credentials(self):
        bob, _ = self.make_friends()
        app = self.open_client()
        self.wait_ui(lambda: app.connection.can_reconnect)
        after = len(bob.events)
        app.connection.sock.shutdown(socket.SHUT_RDWR)
        bob.wait(lambda event: event.get('type') == 'online_users' and
                 'alice' not in event.get('users', []), after=after)
        self.wait_ui(lambda: app.reconnecting)
        with patch.object(app.connection, 'authenticate_saved', wraps=app.connection.authenticate_saved) as retry:
            app.disconnect()
            self.assertFalse(app.reconnecting)
            self.assertFalse(app.connection.can_reconnect)
            self.assertIsNone(app.state.username)
            self.pump_for(1.3)
            retry.assert_not_called()
        self.assertFalse(app.connection.running)


class PythonDesktopFeatureTests(DesktopFeatureScenarios, unittest.TestCase):
    backend = 'python'


@unittest.skipUnless(os.environ.get('CHATROOM_GO_SERVER_EXE'), 'Go binary not selected')
class GoDesktopFeatureTests(DesktopFeatureScenarios, unittest.TestCase):
    backend = 'go'


if __name__ == '__main__':
    unittest.main()
