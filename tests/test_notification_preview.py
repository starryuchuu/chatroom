"""Notification policies, bounded text, old settings and desktop session scopes."""
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from chatroom_client.models import ChatKey, Message
from chatroom_client.notification_preview import message_preview
from chatroom_client.preferences import PreferencesError, PreferencesStore
from chatroom_client.rpc import CoreRuntime


class NotificationPreviewTests(unittest.TestCase):
    def test_private_and_group_preview_levels(self):
        private, group = ChatKey('private', '小林'), ChatKey('group', 'team')
        message = Message('小林', '明天下午见！\n带上电脑🙂', encryption='e2ee')
        groups = {'team': {'group_name': '项目讨论'}}
        self.assertEqual(message_preview(private, message, groups, 'sender'), ('小林', '发来一条新消息'))
        self.assertEqual(message_preview(group, message, groups, 'sender'), ('项目讨论', '小林：发来一条新消息'))
        self.assertEqual(message_preview(private, message, groups, 'message'), ('小林', '明天下午见！ 带上电脑🙂'))
        self.assertEqual(message_preview(group, message, groups, 'message'), ('项目讨论', '小林：明天下午见！ 带上电脑🙂'))
        generic = message_preview(group, message, groups, 'generic')
        self.assertNotIn('小林', ''.join(generic))
        self.assertNotIn('项目讨论', ''.join(generic))
        self.assertNotIn('明天', ''.join(generic))

    def test_unverified_content_never_enters_preview_and_long_text_is_bounded(self):
        key = ChatKey('private', 'bob')
        for mode in ('generic', 'sender', 'message'):
            title, body = message_preview(key, Message('bob', 'unverified-secret', encryption='failed'), {}, mode)
            self.assertNotIn('unverified-secret', title + body)
        title, body = message_preview(key, Message('b' * 100, '\u202e\x00' + '🙂' * 10000, encryption='e2ee'), {}, 'message')
        self.assertLessEqual(len(title), 48)
        self.assertEqual(len(body), 140)
        self.assertTrue(body.endswith('…'))
        self.assertNotIn('\u202e', body)
        self.assertNotIn('\x00', body)

    def test_preview_setting_migrates_and_preserves_concurrent_changes(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / 'client.json'
            first = PreferencesStore(path)
            first.set_notifications(enabled=True)
            legacy = json.loads(path.read_text())
            legacy['notifications'].pop('preview')
            path.write_text(json.dumps(legacy))
            before = path.read_bytes()
            first, second = PreferencesStore(path), PreferencesStore(path)
            self.assertEqual(first.notifications['preview'], 'sender')
            self.assertEqual(path.read_bytes(), before)
            first.set_notifications(preview='message')
            second.set_notifications(do_not_disturb=True)
            self.assertEqual(PreferencesStore(path).notifications,
                             {'enabled': True, 'do_not_disturb': True, 'preview': 'message'})
            for invalid in (True, [], 'all', ''):
                with self.assertRaises(PreferencesError):
                    first.set_notifications(preview=invalid)

    def test_core_emits_scoped_events_only_for_live_unread_messages(self):
        output = io.StringIO()
        runtime = CoreRuntime(preferences=PreferencesStore(persistent=False), encryption=False, output=output)
        self.addCleanup(runtime.app.close)
        app, view = runtime.app, runtime.view
        app.state.username, app.state.friends = 'alice', ['bob']
        view.build_chat()
        app.activity.activate(('localhost', 12345), 'alice')
        key = ChatKey('private', 'bob')

        def receive(mid, **options):
            item = Message('bob', '正文-secret', message_id=mid, encryption='e2ee')
            app.state.conversation(key).add(item)
            app.activity.receive(key, item, **options)

        app.preferences.set_notifications(preview='message')
        with patch('chatroom_client.rpc.time.monotonic', return_value=100):
            receive(1)
            receive(2)  # Rate limit.
        app.preferences.set_notifications(do_not_disturb=True)
        receive(3)
        app.preferences.set_notifications(do_not_disturb=False, preview='generic')
        receive(4, historical=True)
        receive(5, catchup=True)
        with patch('chatroom_client.rpc.time.monotonic', return_value=102):
            receive(6)
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        notices = [item['params'] for item in events if item.get('method') == 'desktop.notification']
        self.assertEqual(len(notices), 2)
        self.assertEqual(notices[0], {'title': 'bob', 'body': '正文-secret', 'key': {'kind': 'private', 'target': 'bob'},
                                    'session': view.session, 'preview': 'message'})
        self.assertNotIn('正文-secret', notices[1]['body'])
        self.assertNotIn('正文-secret', json.dumps(app.preferences.notifications))
        with self.assertRaises(ValueError):
            runtime.invoke('settings.notifications', {'session': view.session, 'enabled': True,
                                                      'doNotDisturb': False, 'preview': ['message']})

    def test_notification_policy_is_published_before_rpc_acknowledgement(self):
        output = io.StringIO()
        runtime = CoreRuntime(preferences=PreferencesStore(persistent=False), encryption=False, output=output)
        self.addCleanup(runtime.app.close)
        output.seek(0)
        output.truncate()
        runtime.dispatch({'jsonrpc': '2.0', 'id': 7, 'method': 'settings.notifications',
                          'params': {'session': runtime.view.session, 'enabled': True,
                                     'doNotDisturb': True, 'preview': 'generic'}})
        packets = [json.loads(line) for line in output.getvalue().splitlines()]
        snapshot = next(index for index, packet in enumerate(packets) if packet.get('method') == 'state.changed')
        reply = next(index for index, packet in enumerate(packets) if packet.get('id') == 7)
        self.assertLess(snapshot, reply)
        self.assertTrue(packets[snapshot]['params']['notifications']['do_not_disturb'])


if __name__ == '__main__':
    unittest.main()
