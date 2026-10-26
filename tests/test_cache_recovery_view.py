"""Real Tk cache eviction, page reload and send-recovery controls."""
import unittest
from unittest.mock import Mock

import test_client_scrolling as scrolling
from chatroom_client.models import ChatKey, Message
from chatroom_client.protocol import encrypt_message


class CacheRecoveryViewTests(unittest.TestCase):
    setUp = scrolling.ClientScrollingTests.setUp
    tearDown = scrolling.ClientScrollingTests.tearDown
    wait_for_geometry = scrolling.ClientScrollingTests.wait_for_geometry
    show_history = scrolling.ClientScrollingTests.show_history
    deliver = scrolling.ClientScrollingTests.deliver
    read_earlier_messages = scrolling.ClientScrollingTests.read_earlier_messages
    visible_message = scrolling.ClientScrollingTests.visible_message
    assert_message_position = scrolling.ClientScrollingTests.assert_message_position

    def begin(self, request):
        self.app.handle_server_message({'type': 'history_begin', 'history_kind': 'private',
            'history_target': self.app.state.current_chat.target, 'request_id': request.get('request_id')})

    def page(self, request, ids):
        for mid in ids:
            self.app.handle_server_message({'type': 'private_chat', 'from': 'synthetic-peer',
                'to': self.app.state.username, 'message_id': mid, 'history': True,
                'history_request_id': request.get('request_id'),
                'content': encrypt_message('Synthetic reloaded ' + str(mid), self.app.connection.session_key)})
        self.app.handle_server_message({'type': 'history_end', 'history_kind': 'private',
            'history_target': 'synthetic-peer', 'request_id': request.get('request_id'),
            'before_id': min(ids), 'has_more': True})
        self.root.update()

    def test_older_page_can_evict_newer_rows_then_return_latest_fetches_them(self):
        key = ChatKey('private', 'synthetic-peer')
        self.app.state.friends = [key.target]
        conversation = self.app.state.conversation(key)
        conversation.MAX_MESSAGES = 200
        for mid in range(301, 501):
            conversation.add(Message(key.target, 'Synthetic old cache ' + str(mid), message_id=mid))
        self.app.select_chat(key)
        self.app.connection.send = Mock()
        self.app.connection.capabilities = ('history_request_id',)
        self.app.load_older_history()
        older = self.app.connection.send.call_args.args[0]
        self.assertEqual(older['before_id'], 301)
        self.begin(older)
        self.page(older, list(range(201, 301)))
        self.assertEqual(conversation.message_ids, list(range(201, 401)))
        self.assertTrue(conversation.newer_evicted)
        self.assertEqual(conversation.latest_message.message_id, 500)
        self.view.new_messages_button.invoke()
        latest = self.app.connection.send.call_args.args[0]
        self.assertEqual(latest['before_id'], 9223372036854775807)
        self.begin(latest)
        self.page(latest, list(range(401, 501)))
        self.assertEqual(conversation.message_ids, list(range(401, 501)))
        self.assertFalse(conversation.newer_evicted)
        self.assertEqual(self.view.current_chat_frame.pack_slaves()[-1]._chat_message.message_id, 500)

    def test_full_cache_preserves_reading_anchor_while_live_body_is_deferred(self):
        key = self.show_history()
        conversation = self.app.state.conversation(key)
        conversation.MAX_MESSAGES = 80
        content, position = self.read_earlier_messages()
        self.deliver(181)
        self.root.update()
        self.assert_message_position(content, position)
        self.assertEqual(conversation.message_ids, list(range(101, 181)))
        self.assertEqual(conversation.latest_message.message_id, 181)
        self.assertTrue(self.view.new_messages_button.winfo_ismapped())
        count = self.view._new_messages[key]
        self.deliver(181)
        self.root.update()
        self.assertEqual(self.view._new_messages[key], count)

    def test_selecting_evicted_conversation_requests_recent_page(self):
        current = self.show_history()
        other = ChatKey('private', 'evicted-peer')
        self.app.state.friends.append(other.target)
        self.app.state.conversation(other).add(Message(other.target, 'Synthetic inactive body', message_id=4))
        self.app.state.conversation(other).read_id = 3
        self.app.state.conversation(other).unread_ids = {4}
        self.app.state.MAX_CACHED_MESSAGES = 80
        evicted = self.app.state.enforce_cache_limits()
        self.view.cache_changed(current, evicted)
        self.assertEqual(evicted, [other])
        self.assertEqual(self.app.state.conversations[other].unread_ids, {4})
        self.app.connection.send = Mock()
        self.app.select_chat(other)
        request = self.app.connection.send.call_args.args[0]
        self.assertEqual((request['target'], request['before_id']), (other.target, 9223372036854775807))

    def test_recent_page_enqueue_failure_keeps_existing_readable_cache(self):
        key = self.show_history()
        conversation = self.app.state.conversation(key)
        old = list(conversation.messages)
        conversation.newer_evicted = True
        self.app.connection.send = Mock(side_effect=ConnectionError('synthetic queue failure'))
        self.app.load_latest_history()
        self.assertEqual(conversation.messages, old)
        self.assertTrue(conversation.newer_evicted)

    def test_new_self_message_at_cache_limit_fetches_latest_instead_of_disappearing(self):
        key = self.show_history()
        self.app.state.conversation(key).MAX_MESSAGES = 80
        self.read_earlier_messages()
        self.app.connection.send = Mock()
        self.deliver(181, is_self=True)
        request = self.app.connection.send.call_args.args[0]
        self.assertEqual(request['type'], 'history_request')
        self.assertEqual(request['before_id'], 9223372036854775807)

    def test_timeout_recovery_button_queries_then_retries_with_same_receipt_key(self):
        self.show_history()
        self.app.connection.capabilities = ('message_receipts',)
        self.app.connection.send = Mock()
        self.view.msg_entry.insert('1.0', 'Synthetic recovery input')
        self.view.send_button.invoke()
        record = self.app.sends.records[0]
        original = record.payload['idempotency_key']
        self.app.expire_pending(self.app.connection.sock, record.request_id)
        self.root.update()
        self.assertEqual(self.view.send_button.cget('state'), 'normal')
        self.assertTrue(self.view.recover_send_button.winfo_ismapped())
        self.app.handle_server_message({'type': 'message_status_result', 'request_id': record.query,
            'idempotency_key': original, 'chat_type': 'private', 'target': 'synthetic-peer',
            'success': True, 'status': 'not_found'})
        self.assertEqual(self.view.recover_send_button.cget('text'), '待确认消息 (1)')
        self.view.recover_send_button.invoke()
        self.assertEqual(self.view.send_recovery.recover_button.cget('text'), '重试所选消息')
        self.view.send_recovery.recover_button.invoke()
        self.assertEqual(self.app.connection.send.call_args.args[0]['idempotency_key'], original)
        self.assertEqual(self.view.input_text(), 'Synthetic recovery input')
