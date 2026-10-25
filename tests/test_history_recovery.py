"""History pagination must remain retryable after partial delivery and reconnect."""
import os
import unittest
from unittest.mock import Mock

import test_regressions as regression
from chatroom_client.models import ChatKey, Message

client = regression.client


class ClientHistoryRecoveryTests(unittest.TestCase):
    def app(self):
        app = regression.headless_client(self)
        app.state.username = 'alice'
        app.connection.session_key = os.urandom(16)
        app.state.current_chat = ChatKey('private', 'bob')
        app.state.friends = ['bob']
        return app

    def message(self, app, message_id):
        app.handle_server_message({
            'type': 'private_chat', 'from': 'bob', 'to': 'alice',
            'message_id': message_id,
            'content': client.encrypt_message(str(message_id), app.connection.session_key),
        })

    def test_partial_page_retry_does_not_skip_undelivered_messages(self):
        app = self.app()
        self.message(app, 201)
        app.load_older_history()
        app.handle_server_message({'type': 'history_begin'})
        self.message(app, 101)
        app.handle_server_message({'type': 'history_error', 'error': 'retry'})
        app.load_older_history()
        self.assertEqual(app.connection.send.call_args.args[0]['before_id'], 201)
        app.handle_server_message({'type': 'history_begin'})
        for message_id in range(101, 201):
            self.message(app, message_id)
        app.handle_server_message({
            'type': 'history_end', 'history_kind': 'private', 'history_target': 'bob',
            'before_id': 101, 'has_more': True,
        })
        conversation = app.state.conversation(ChatKey('private', 'bob'))
        self.assertEqual(conversation.message_ids, list(range(101, 202)))
        app.load_older_history()
        self.assertEqual(app.connection.send.call_args.args[0]['before_id'], 101)

    def test_correlated_stale_frames_cannot_enter_model_or_unread_state(self):
        app = self.app()
        app.connection.capabilities = ('history_request_id',)
        key = app.state.current_chat
        app.activity.activate(('synthetic-server', 12345), 'alice')
        app.activity.history_complete()
        self.message(app, 201)
        app.activity.mark_read(key)

        def deliver(mid, **flags):
            app.handle_server_message({
                'type': 'private_chat', 'from': 'bob', 'to': 'alice', 'message_id': mid,
                'content': client.encrypt_message('Synthetic frame ' + str(mid), app.connection.session_key),
                **flags,
            })

        app.load_older_history()
        old = app.connection.send.call_args.args[0]['request_id']
        app.handle_server_message({'type': 'history_begin', 'request_id': old,
                                   'history_kind': 'private', 'history_target': 'bob'})
        deliver(101, history=True, history_request_id=old)
        app.view.schedule.call_args.args[1]()
        app.load_older_history()
        fresh = app.connection.send.call_args.args[0]['request_id']
        deliver(102, history=True, history_request_id=old)
        deliver(300, history=False)
        app.handle_server_message({'type': 'history_begin', 'request_id': fresh,
                                   'history_kind': 'private', 'history_target': 'bob'})
        deliver(103, history=True, history_request_id=fresh)
        app.handle_server_message({'type': 'history_end', 'request_id': old,
                                   'history_kind': 'private', 'history_target': 'bob',
                                   'before_id': 55, 'has_more': False})
        self.assertEqual(app.state.pending_history, key)
        self.assertEqual(app.state.conversation(key).cursor, 201)
        app.handle_server_message({'type': 'history_end', 'request_id': fresh,
                                   'history_kind': 'private', 'history_target': 'bob',
                                   'before_id': 101, 'has_more': True})
        self.assertEqual(app.state.conversation(key).message_ids, [101, 103, 201, 300])
        self.assertEqual(app.state.total_unread, 1)
        self.assertEqual(app.state.conversation(key).cursor, 101)

    def test_initial_history_end_does_not_release_queued_page_request(self):
        app = self.app()
        self.message(app, 201)
        app.load_older_history()
        app.handle_server_message({'type': 'history_end'})
        self.assertEqual(app.state.pending_history, ChatKey('private', 'bob'))
        app.load_older_history()
        app.connection.send.assert_called_once()

    def test_disconnect_resets_active_history_sync(self):
        app = self.app()
        app.state.history_syncing = True
        app.state.pending_history = app.state.current_chat
        app.disconnect()
        self.assertFalse(app.state.history_syncing)
        self.assertIsNone(app.state.pending_history)

    def test_failed_enqueue_does_not_block_next_attempt(self):
        app = self.app()
        app.connection.send.side_effect = ConnectionError('disconnected')
        app.load_older_history()
        self.assertIsNone(app.state.pending_history)
        app.connection.send.side_effect = None
        app.load_older_history()
        self.assertEqual(app.state.pending_history, ChatKey('private', 'bob'))

    def test_group_removal_clears_cursor_before_rejoin(self):
        app = self.app()
        group, private = ChatKey('group', 'g'), ChatKey('private', 'bob')
        app.state.conversation(private).cursor = 301
        conversation = app.state.conversation(group)
        conversation.cursor, conversation.exhausted = 101, True
        for message_id in (101, 201):
            conversation.add(Message('bob', 'cached', message_id=message_id))
        app.state.remove_group('g')
        self.assertNotIn(group, app.state.conversations)
        self.assertEqual(app.state.conversation(private).cursor, 301)
        rejoined = app.state.conversation(group)
        self.assertIsNone(rejoined.cursor)
        self.assertFalse(rejoined.exhausted)
        self.assertEqual(rejoined.add(Message('bob', 'cached', message_id=101)), 0)

    def test_other_conversation_snapshot_keeps_page_request_pending(self):
        app = self.app()
        app.state.groups['g'] = {'members': ['alice']}
        app.load_older_history()
        app.handle_server_message({'type': 'history_begin'})
        app.handle_server_message({
            'type': 'history_end', 'history_kind': 'group', 'history_target': 'g',
            'before_id': 55, 'has_more': False,
        })
        self.assertEqual(app.state.pending_history, ChatKey('private', 'bob'))
        self.assertTrue(app.state.history_syncing)
        app.handle_server_message({
            'type': 'history_end', 'history_kind': 'private', 'history_target': 'bob',
            'before_id': 101, 'has_more': True,
        })
        self.assertIsNone(app.state.pending_history)
        self.assertEqual(app.state.conversation(ChatKey('private', 'bob')).cursor, 101)

    def test_late_group_history_end_does_not_restore_removed_conversation(self):
        for removal in ('group_leave_result', 'group_kick_notification', 'group_disband_notification'):
            for has_more in (False, True):
                with self.subTest(removal=removal, has_more=has_more):
                    app = self.app()
                    group = ChatKey('group', 'g')
                    app.state.groups['g'] = {'members': ['alice', 'bob']}
                    app.state.current_chat = group
                    app.state.conversation(group).add(Message('bob', 'cached', message_id=201))
                    app.load_older_history()
                    app.handle_server_message({'type': 'history_begin'})
                    app.handle_server_message({'type': removal, 'gid': 'g', 'success': True})
                    self.assertNotIn(group, app.state.conversations)

                    app.handle_server_message({
                        'type': 'history_end', 'history_kind': 'group', 'history_target': 'g',
                        'before_id': 101, 'has_more': has_more,
                    })
                    self.assertNotIn(group, app.state.conversations)
                    self.assertIsNone(app.state.pending_history)

                    app.handle_server_message({
                        'type': 'group_join_result', 'gid': 'g', 'success': True,
                        'members': ['alice', 'bob'],
                    })
                    app.handle_server_message({'type': 'history_begin'})
                    app.handle_server_message({
                        'type': 'group_chat', 'gid': 'g', 'from': 'bob', 'message_id': 301,
                        'content': client.encrypt_message('rejoined', app.connection.session_key),
                    })
                    app.handle_server_message({
                        'type': 'history_end', 'history_kind': 'group', 'history_target': 'g',
                        'before_id': 301, 'has_more': True,
                    })
                    app.state.current_chat = group
                    app.load_older_history()
                    self.assertEqual(app.connection.send.call_count, 2)
                    self.assertEqual(app.connection.send.call_args.args[0]['before_id'], 301)

    def test_other_conversation_error_keeps_page_request_pending(self):
        for kind, target in (('private', 'carol'), ('group', 'bob')):
            with self.subTest(kind=kind, target=target):
                app = self.app()
                app.state.groups['bob'] = {'members': ['alice']}
                self.message(app, 201)
                app.load_older_history()
                app.handle_server_message({'type': 'history_begin'})
                self.message(app, 101)
                app.handle_server_message({
                    'type': 'history_error', 'history_kind': kind, 'history_target': target,
                    'error': 'another conversation failed',
                })
                self.assertEqual(app.state.pending_history, ChatKey('private', 'bob'))
                self.assertTrue(app.state.history_syncing)
                self.assertEqual(app.state.conversation(ChatKey('private', 'bob')).cursor, 201)
                app.load_older_history()
                app.connection.send.assert_called_once()
                app.handle_server_message({
                    'type': 'history_end', 'history_kind': 'private', 'history_target': 'bob',
                    'before_id': 101, 'has_more': True,
                })
                self.assertIsNone(app.state.pending_history)
                self.assertFalse(app.state.history_syncing)

    def test_removed_group_completion_preserves_another_active_page(self):
        app = self.app()
        app.state.remove_group('g')
        app.load_older_history()
        app.handle_server_message({'type': 'history_begin'})
        app.handle_server_message({
            'type': 'history_end', 'history_kind': 'group', 'history_target': 'g',
            'before_id': 55, 'has_more': False,
        })
        self.assertNotIn(ChatKey('group', 'g'), app.state.conversations)
        self.assertEqual(app.state.pending_history, ChatKey('private', 'bob'))
        self.assertTrue(app.state.history_syncing)

    def test_matching_scoped_error_releases_pending_page_after_selection_changes(self):
        app = self.app()
        self.message(app, 201)
        app.load_older_history()
        app.handle_server_message({'type': 'history_begin'})
        self.message(app, 101)
        app.state.current_chat = ChatKey('private', 'carol')
        app.handle_server_message({
            'type': 'history_error', 'history_kind': 'private', 'history_target': 'bob',
            'error': 'retry',
        })
        self.assertIsNone(app.state.pending_history)
        self.assertFalse(app.state.history_syncing)
        app.state.current_chat = ChatKey('private', 'bob')
        app.load_older_history()
        self.assertEqual(app.connection.send.call_args.args[0]['before_id'], 201)

    def test_empty_current_group_snapshot_initializes_pagination(self):
        app = self.app()
        app.state.groups['g'] = {'members': ['alice']}
        group = ChatKey('group', 'g')
        self.assertNotIn(group, app.state.conversations)
        app.handle_server_message({
            'type': 'history_end', 'history_kind': 'group', 'history_target': 'g',
            'before_id': 55, 'has_more': False,
        })
        self.assertEqual(app.state.conversations[group].cursor, 55)
        self.assertTrue(app.state.conversations[group].exhausted)
