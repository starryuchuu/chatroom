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
        app.load_older_history()
        app.handle_server_message({
            'type': 'history_end', 'history_kind': 'group', 'history_target': 'g',
            'before_id': 55, 'has_more': False,
        })
        self.assertEqual(app.state.pending_history, ChatKey('private', 'bob'))
        app.handle_server_message({
            'type': 'history_end', 'history_kind': 'private', 'history_target': 'bob',
            'before_id': 101, 'has_more': True,
        })
        self.assertIsNone(app.state.pending_history)
        self.assertEqual(app.state.conversation(ChatKey('private', 'bob')).cursor, 101)
