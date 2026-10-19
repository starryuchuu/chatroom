"""History pagination must remain retryable after partial delivery and reconnect."""
import os
import unittest
from unittest.mock import Mock

import test_regressions as regression

client = regression.client


class ClientHistoryRecoveryTests(unittest.TestCase):
    def app(self):
        app = regression.ClientTests().app()
        app.username = 'alice'
        app.session_key = os.urandom(16)
        app.current_friend, app.current_group = 'bob', None
        app.friends = ['bob']
        app.private_chats = {}
        app.queue_send = Mock()
        app.switch_chat_frame = Mock()
        app.display_message_with_time = Mock()
        app.update_chat_target = Mock()
        app.notify = Mock()
        return app

    def message(self, app, message_id):
        app.handle_server_message({
            'type': 'private_chat', 'from': 'bob', 'to': 'alice',
            'message_id': message_id,
            'content': client.encrypt_message(str(message_id), app.session_key),
        })

    def test_partial_page_retry_does_not_skip_undelivered_messages(self):
        app = self.app()
        self.message(app, 201)
        app.load_older_history()
        app.handle_server_message({'type': 'history_begin'})
        self.message(app, 101)  # Server sends oldest first, then fails mid-page.
        app.handle_server_message({'type': 'history_error', 'error': 'retry'})
        app.load_older_history()
        self.assertEqual(app.queue_send.call_args.args[0]['before_id'], 201)
        app.handle_server_message({'type': 'history_begin'})
        for message_id in range(101, 201):
            self.message(app, message_id)
        app.handle_server_message({
            'type': 'history_end', 'history_kind': 'private', 'history_target': 'bob',
            'before_id': 101, 'has_more': True,
        })
        self.assertEqual(app.message_order['bob'], list(range(101, 202)))
        app.load_older_history()
        self.assertEqual(app.queue_send.call_args.args[0]['before_id'], 101)

    def test_initial_history_end_does_not_release_queued_page_request(self):
        app = self.app()
        self.message(app, 201)
        app.load_older_history()
        app.handle_server_message({'type': 'history_end'})
        self.assertTrue(app.history_page_pending)
        app.load_older_history()
        app.queue_send.assert_called_once()

    def test_disconnect_resets_active_history_sync(self):
        app = self.app()
        app.history_syncing = True
        app.history_page_pending = True
        app.build_login = Mock()
        app.disconnect()
        self.assertFalse(app.history_syncing)
        self.assertFalse(app.history_page_pending)

    def test_failed_enqueue_does_not_block_next_attempt(self):
        app = self.app()
        app.queue_send.side_effect = ConnectionError('disconnected')
        app.load_older_history()
        self.assertFalse(app.history_page_pending)
        app.queue_send.side_effect = None
        app.load_older_history()
        self.assertTrue(app.history_page_pending)

    def test_group_removal_clears_cursor_before_rejoin(self):
        app = self.app()
        app.history_cursors = {('group', 'g'): 101, ('private', 'bob'): 301}
        app.history_exhausted = {('group', 'g')}
        app.message_order['g'] = [101, 201]
        app.seen_message_ids.update([101, 201])
        app.group_messages_g = ['cached']
        app.clear_group_history('g')
        self.assertNotIn(('group', 'g'), app.history_cursors)
        self.assertEqual(app.history_cursors[('private', 'bob')], 301)
        self.assertFalse(app.history_exhausted)
        self.assertFalse(app.seen_message_ids)

    def test_other_conversation_snapshot_keeps_page_request_pending(self):
        app = self.app()
        app.load_older_history()
        app.handle_server_message({
            'type': 'history_end', 'history_kind': 'group', 'history_target': 'g',
            'before_id': 55, 'has_more': False,
        })
        self.assertTrue(app.history_page_pending)
        app.handle_server_message({
            'type': 'history_end', 'history_kind': 'private', 'history_target': 'bob',
            'before_id': 101, 'has_more': True,
        })
        self.assertFalse(app.history_page_pending)
        self.assertEqual(app.history_cursors[('private', 'bob')], 101)
