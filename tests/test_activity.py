"""Account-scoped unread state, replay handling, and notification privacy."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from chatroom_client.activity import ActivityController
from chatroom_client.events import ServerEvents
from chatroom_client.models import ChatKey, ClientState, Message
from chatroom_client.preferences import PreferencesStore
from chatroom_client.protocol import encrypt_message


class ActivityTests(unittest.TestCase):
    def setUp(self):
        self.preferences = PreferencesStore(persistent=False)
        self.state = ClientState(username='alice')
        self.notices = []
        self.visible = False
        self.key = ChatKey('private', 'bob')
        self.activity = self.make_activity(self.state)
        self.activity.activate(('server.example', 12345), 'alice')

    def make_activity(self, state):
        return ActivityController(
            state, self.preferences, notify=lambda *notice: self.notices.append(notice),
            is_visible=lambda key: self.visible and state.current_chat == key)

    def receive(self, message_id, *, key=None, historical=False, catchup=False,
                is_self=False, content='a private message'):
        key = key or self.key
        item = Message('alice' if is_self else 'bob', content,
                       message_id=message_id, is_self=is_self)
        if self.state.conversation(key).add(item) is not None:
            self.activity.receive(key, item, historical=historical, catchup=catchup)

    def test_first_login_snapshot_establishes_read_baseline_without_alerts(self):
        self.receive(10, historical=True)
        self.receive(11, historical=True)
        conversation = self.state.conversation(self.key)
        self.assertEqual(conversation.unread_count, 0)
        self.assertEqual(conversation.read_id, 11)
        self.assertEqual(self.notices, [])
        self.activity.history_complete()
        self.receive(12)
        self.assertEqual(conversation.unread_count, 1)

    def test_new_live_message_is_unread_once_and_notification_has_no_body(self):
        self.activity.history_complete()
        self.receive(12)
        self.receive(12)
        self.assertEqual(self.state.total_unread, 1)
        self.assertEqual(len(self.notices), 1)
        self.assertNotIn('a private message', json.dumps(self.notices))
        self.assertEqual(self.state.conversation(self.key).preview, 'a private message')

    def test_selected_background_chat_waits_for_focus_before_marking_read(self):
        self.state.current_chat = self.key
        self.receive(1)
        self.assertEqual(self.state.total_unread, 1)
        self.visible = True
        self.activity.focus_changed()
        self.assertEqual(self.state.total_unread, 0)
        self.receive(2)
        self.assertEqual(self.state.total_unread, 0)
        self.assertEqual(len(self.notices), 1)

    def test_self_messages_and_old_pages_never_inflate_unread(self):
        self.receive(10, historical=True)
        self.activity.history_complete()
        self.receive(11, is_self=True)
        self.receive(7, historical=True)
        self.assertEqual(self.state.total_unread, 0)
        self.assertEqual(self.notices, [])

    def test_catchup_counts_offline_messages_without_notification_storm(self):
        self.receive(10, historical=True)
        self.activity.history_complete()
        for mid in range(11, 216):
            self.receive(mid, historical=True, catchup=True)
        self.assertEqual(self.state.total_unread, 205)
        self.assertEqual(self.notices, [])
        for mid in range(11, 216):
            self.receive(mid, historical=True, catchup=True)
        self.assertEqual(self.state.total_unread, 205)

    def test_unread_and_read_markers_survive_reopening_without_plaintext(self):
        self.receive(10, historical=True)
        self.activity.history_complete()
        self.receive(11)
        self.activity.flush()
        stored = self.preferences.account(('server.example', 12345), 'alice')
        self.assertNotIn('a private message', json.dumps(stored))
        self.assertEqual(stored['activity']['conversations'][0]['unread_ids'], [11])
        self.state = ClientState(username='alice')
        self.activity = self.make_activity(self.state)
        self.activity.activate(('server.example', 12345), 'alice')
        self.assertEqual(self.state.total_unread, 1)
        self.receive(11, historical=True)
        self.assertEqual(self.state.total_unread, 1)
        self.receive(12, historical=True)
        self.assertEqual(self.state.total_unread, 2)
        self.activity.mark_read(self.key)
        self.assertEqual(self.state.total_unread, 0)
        self.assertEqual(self.state.conversation(self.key).read_id, 12)

    def test_accounts_and_endpoints_keep_independent_unread_state(self):
        self.receive(10)
        self.activity.reset()
        for endpoint, username in [(('other.example', 12345), 'alice'),
                                   (('server.example', 12346), 'alice'),
                                   (('server.example', 12345), 'carol')]:
            state = ClientState(username=username)
            activity = self.make_activity(state)
            activity.activate(endpoint, username)
            self.assertEqual(state.total_unread, 0)
        state = ClientState(username='alice')
        activity = self.make_activity(state)
        activity.activate(('server.example', 12345), 'alice')
        self.assertEqual(state.total_unread, 1)

    def test_private_and_group_with_same_name_are_distinct(self):
        self.receive(1)
        self.receive(2, key=ChatKey('group', 'bob'))
        self.assertEqual(self.state.total_unread, 2)
        self.activity.mark_read(self.key)
        self.assertEqual(self.state.total_unread, 1)

    def test_do_not_disturb_and_notifications_off_keep_unread_badges(self):
        self.preferences.set_notifications(do_not_disturb=True)
        self.receive(1)
        self.preferences.set_notifications(do_not_disturb=False, enabled=False)
        self.receive(2)
        self.assertEqual(self.state.total_unread, 2)
        self.assertEqual(self.notices, [])

    def test_persistence_debounces_and_preserves_reconnect_cursor(self):
        callbacks = []
        self.activity.schedule = lambda milliseconds, callback: callbacks.append(callback)
        self.receive(1)
        self.receive(2)
        self.assertEqual(len(callbacks), 1)
        self.preferences.update_account(('server.example', 12345), 'alice', {'sync_cursor': 99})
        callbacks.pop()()
        account = self.preferences.account(('server.example', 12345), 'alice')
        self.assertEqual(account['sync_cursor'], 99)
        self.assertEqual(account['activity']['conversations'][0]['unread_ids'], [1, 2])

    def test_removed_offline_group_does_not_restore_phantom_badge(self):
        self.receive(1, key=ChatKey('group', 'gone'))
        self.activity.reconcile_groups({'current'})
        self.assertEqual(self.state.total_unread, 0)
        self.assertEqual(self.preferences.account(('server.example', 12345), 'alice')
                         ['activity']['conversations'], [])

    def test_failed_metadata_write_leaves_session_usable_and_retries(self):
        error_notice = Mock()
        self.activity.on_error = error_notice
        original_update = self.preferences.update_account
        self.preferences.update_account = Mock(side_effect=OSError('disk full'))
        self.receive(1)
        self.receive(2)
        self.assertEqual(self.state.total_unread, 2)
        error_notice.assert_called_once()
        self.preferences.update_account = original_update
        self.activity.flush()
        self.assertEqual(self.preferences.account(('server.example', 12345), 'alice')
                         ['activity']['conversations'][0]['unread_ids'], [1, 2])

    def test_metadata_file_contains_neither_preview_nor_password(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / 'client.json'
            self.preferences = PreferencesStore(path)
            self.activity = self.make_activity(self.state)
            self.activity.activate(('127.0.0.1', 12345), 'alice')
            self.receive(1, content='uniquely-secret-message')
            contents = path.read_text(encoding='utf-8')
            self.assertNotIn('uniquely-secret-message', contents)
            self.assertNotIn('password', contents)
            self.assertEqual(json.loads(contents)['accounts']['["127.0.0.1",12345,"alice"]']
                             ['activity']['conversations'][0]['unread_ids'], [1])


class ActivityEventTests(unittest.TestCase):
    def setUp(self):
        self.state = ClientState(username='alice')
        self.preferences = PreferencesStore(persistent=False)
        self.notices = []
        self.activity = ActivityController(self.state, self.preferences,
                                           notify=lambda *args: self.notices.append(args))
        self.activity.activate(('127.0.0.1', 12345), 'alice')
        self.connection = SimpleNamespace(session_key=b'0123456789abcdef', capabilities=('message_sync',))
        self.sync = SimpleNamespace(active=False)
        controller = SimpleNamespace(state=self.state, view=Mock(), connection=self.connection,
                                     activity=self.activity, request_group_info=Mock(), sync=self.sync)
        self.events = ServerEvents(controller)

    def message(self, mid, **extra):
        return {'type': 'private_chat', 'from': 'bob', 'to': 'alice', 'message_id': mid,
                'content': encrypt_message('secret body', self.connection.session_key), **extra}

    def test_duplicate_marked_history_is_not_counted_as_live(self):
        self.state.history_syncing = True
        self.events.chat_message(self.message(10, history=True))
        self.activity.history_complete()
        self.state.history_syncing = False
        self.events.chat_message(self.message(11))
        self.events.chat_message(self.message(11, history=True))
        self.assertEqual(self.state.total_unread, 1)
        self.assertEqual(len(self.notices), 1)

    def test_large_catchup_frame_without_flags_uses_active_sync_batch(self):
        self.activity.history_complete()
        self.state.history_syncing = self.sync.active = True
        self.events.chat_message(self.message(11))
        self.assertEqual(self.state.total_unread, 1)
        self.assertEqual(self.notices, [])

    def test_old_server_history_fallback_does_not_create_notifications(self):
        self.connection.capabilities = ()
        self.state.history_syncing = True
        self.events.chat_message(self.message(10))
        self.assertEqual(self.state.total_unread, 0)
        self.assertEqual(self.notices, [])


if __name__ == '__main__':
    unittest.main()
