"""Domain state and connection ownership contracts, without a Tk root."""
import unittest
from unittest.mock import Mock

from chatroom_client.connection import AuthResult, ClientSettings, ConnectionManager
from chatroom_client.models import ChatKey, ClientState, Conversation, Message


class ConversationTests(unittest.TestCase):
    def test_live_history_overlap_keeps_original_and_server_order(self):
        conversation = Conversation()
        for mid in (9, 3, 9, 5):
            conversation.add(Message('bob', str(mid), message_id=mid))
        self.assertEqual(conversation.message_ids, [3, 5, 9])
        self.assertEqual([message.content for message in conversation.messages], ['3', '5', '9'])
        self.assertIsNone(conversation.add(Message('bob', 'duplicate changed text', message_id=5)))
        self.assertEqual(conversation.messages[1].content, '5')

    def test_private_and_group_data_and_cursors_are_independent(self):
        state = ClientState()
        private, group = ChatKey('private', 'same'), ChatKey('group', 'same')
        state.conversation(private).add(Message('same', 'private', message_id=11))
        state.conversation(group).add(Message('bob', 'group', message_id=12))
        state.conversation(private).cursor = 7
        state.conversation(group).cursor = 8
        state.current_chat = private
        state.remove_group('same')
        self.assertEqual(state.current_chat, private)
        self.assertEqual(state.conversation(private).cursor, 7)
        self.assertEqual(state.conversation(private).messages[0].content, 'private')
        self.assertEqual(state.conversation(group).messages, [])
        self.assertIsNone(state.conversation(group).cursor)

    def test_account_reset_drops_session_data_and_preserves_scoped_drafts(self):
        state = ClientState(username='alice')
        key = ChatKey('group', 'g')
        state.groups['g'] = {'group_name': 'private account data'}
        state.friends.append('bob')
        state.conversation(key).add(Message('alice', 'old message', message_id=1))
        state.current_chat = state.pending_history = key
        state.history_syncing = True
        state.pending_messages['request'] = 'unsent'
        state.drafts[('server', 12345, 'alice')] = 'Alice draft'
        state.reset_session('carol')
        self.assertEqual(state.username, 'carol')
        self.assertFalse(state.friends or state.groups or state.conversations or state.pending_messages)
        self.assertIsNone(state.current_chat)
        self.assertIsNone(state.pending_history)
        self.assertFalse(state.history_syncing)
        self.assertEqual(state.drafts, {('server', 12345, 'alice'): 'Alice draft'})

    def test_unnumbered_messages_remain_distinct(self):
        conversation = Conversation()
        conversation.add(Message('bob', 'first'))
        conversation.add(Message('bob', 'second'))
        self.assertEqual([item.content for item in conversation.messages], ['first', 'second'])


class ConnectionOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.connection = ConnectionManager(ClientSettings())
        self.addCleanup(self.connection.close)

    def test_cancelled_success_cannot_replace_current_connection(self):
        connection = self.connection
        connection.generation = 2
        current, stale = Mock(), Mock()
        connection.sock = current
        connection.running = True
        connection.session_key = b'new-session-key!'
        old = AuthResult(1, 'old-account', False, ('old-server', 12345), stale, b'old-session-key!', None)
        self.assertFalse(connection.accept_auth(old))
        self.assertIs(connection.sock, current)
        self.assertEqual(connection.session_key, b'new-session-key!')
        stale.close.assert_called_once()
        current.close.assert_not_called()

    def test_queued_old_message_never_writes_to_replacement_connection(self):
        connection = self.connection
        stale, current = Mock(), Mock()
        connection.sock, connection.running = current, True
        connection.outgoing.put((stale, {'type': 'private_chat', 'content': 'old account'}))
        connection.outgoing.put(None)
        for worker in connection.workers:
            worker.join(2)
            self.assertFalse(worker.is_alive())
        stale.sendall.assert_not_called()
        current.sendall.assert_not_called()
