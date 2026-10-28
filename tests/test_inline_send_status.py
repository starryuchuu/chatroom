"""Outgoing bubbles reflect persistence evidence without claiming delivery/read."""
import io
import os
import unittest
from unittest.mock import Mock

from chatroom_client.models import ChatKey, Message
from chatroom_client.preferences import PreferencesStore
from chatroom_client.rpc import CoreRuntime


class InlineSendStatusTests(unittest.TestCase):
    def setUp(self):
        self.runtime = CoreRuntime(preferences=PreferencesStore(persistent=False), encryption=False, output=io.StringIO())
        self.addCleanup(self.runtime.app.close)
        self.app, self.view = self.runtime.app, self.runtime.view
        self.app.connection.running = True
        self.app.connection.sock = Mock()
        self.app.connection.endpoint = ('synthetic-server', 12345)
        self.app.connection.session_key = os.urandom(16)
        self.app.connection.capabilities = ('message_receipts',)
        self.app.connection.send = Mock()
        self.app.state.username, self.app.state.friends = 'alice', ['bob', 'carol']
        self.key = ChatKey('private', 'bob')
        self.app.state.current_chat = self.key
        self.view.page = 'chat'

    def send(self, text='本机发送内容'):
        self.view._input = text
        self.app.send_message()
        return self.app.sends.records[-1]

    def status(self):
        return self.view.snapshot()['outgoing'][0]['sendStatus']

    def result(self, record, **result):
        self.app.finish_pending({'type': 'private_chat_result', 'request_id': record.request_id, **result})

    def test_ack_gap_then_echo_replaces_local_bubble_without_duplicate(self):
        record = self.send()
        pending = self.view.snapshot()['outgoing'][0]
        self.assertEqual(pending['sendStatus'], 'sending')
        self.assertEqual(pending['protection'], 'local')
        self.assertTrue(pending['canRecover'])
        self.assertFalse(self.view.snapshot()['messages'])
        self.result(record, success=True, message_id=42)
        self.assertEqual(self.status(), 'saved')
        self.assertEqual(self.view.snapshot()['outgoing'][0]['serverId'], '42')
        self.app.state.conversation(self.key).add(Message('alice', record.text, message_id=42, is_self=True, encryption='e2ee'))
        snapshot = self.view.snapshot()
        self.assertEqual(snapshot['outgoing'], [])
        self.assertEqual(snapshot['messages'][0]['sendStatus'], 'saved')
        self.assertEqual(snapshot['messages'][0]['id'], '42')

    def test_uncertain_query_retry_and_failure_remain_inline_without_blind_resend(self):
        record = self.send()
        self.app.sends.expire(self.app.connection.sock, record.request_id)
        self.assertEqual(self.status(), 'checking')
        before = self.app.connection.send.call_count
        self.app.sends.handle({'type': 'message_status_result', 'request_id': record.query,
            'idempotency_key': record.payload['idempotency_key'], 'chat_type': 'private', 'target': 'bob',
            'success': True, 'status': 'not_found'})
        self.assertEqual(self.status(), 'retry')
        self.assertEqual(self.app.connection.send.call_count, before)
        original_key = record.payload['idempotency_key']
        self.app.sends.recover(record)
        self.assertEqual(self.status(), 'sending')
        self.assertEqual(record.payload['idempotency_key'], original_key)
        self.result(record, success=False, error='好友关系已失效')
        failed = self.view.snapshot()['outgoing'][0]
        self.assertEqual(failed['sendStatus'], 'failed')
        self.assertEqual(failed['sendError'], '好友关系已失效')
        self.assertEqual(self.view.input_text(), record.text)
        self.assertEqual(self.view.snapshot()['pending'], [])

    def test_saved_query_merges_into_verified_history_and_newer_draft_survives(self):
        record = self.send()
        self.view._input = '刚编辑的新草稿'
        self.app.sends.expire(self.app.connection.sock, record.request_id)
        self.app.sends.handle({'type': 'message_status_result', 'request_id': record.query,
            'idempotency_key': record.payload['idempotency_key'], 'chat_type': 'private', 'target': 'bob',
            'success': True, 'status': 'saved', 'message_id': 51, 'timestamp': '2026-10-28T08:00:00Z'})
        snapshot = self.view.snapshot()
        self.assertEqual(snapshot['outgoing'], [])
        self.assertEqual(snapshot['messages'][0]['content'], record.text)
        self.assertEqual(snapshot['messages'][0]['sendStatus'], 'saved')
        self.assertEqual(self.view.input_text(), '刚编辑的新草稿')

    def test_only_identical_verified_self_envelope_settles_lost_ack(self):
        first = self.send('相同的正文')
        first.payload['e2ee'] = {'id': 'first-envelope', 'signature': 'first-signature'}
        self.app.sends.expire(self.app.connection.sock, first.request_id)
        self.app.sends.send(dict(first.payload, request_id='second-request',
            e2ee={'id': 'second-envelope', 'signature': 'second-signature'}), first.text)
        second = self.app.sends.records[-1]
        self.view._input = '新的独立草稿'
        unverified = Message('alice', first.text, message_id=55, is_self=True, encryption='failed')
        self.app.sends.observe_echo(self.key, unverified, first.payload['e2ee'])
        self.assertEqual(len(self.app.sends.records), 2)
        item = Message('alice', first.text, message_id=55, is_self=True, encryption='e2ee')
        self.app.sends.observe_echo(ChatKey('private', 'carol'), item, first.payload['e2ee'])
        self.assertEqual(len(self.app.sends.records), 2)
        self.app.sends.observe_echo(self.key, item, first.payload['e2ee'])
        self.assertEqual(self.app.sends.records, [second])
        self.assertEqual(self.view.input_text(), '新的独立草稿')
        self.assertFalse(self.app.sends.outcomes)

    def test_outcomes_are_bounded_and_isolated_from_other_chats_accounts_and_groups(self):
        self.app.sends.MAX_RECORDS = 2
        for index in range(4):
            record = self.send(str(index))
            self.result(record, success=False)
        self.assertEqual(len(self.app.sends.outcomes), 2)
        self.app.state.current_chat = ChatKey('private', 'carol')
        self.assertEqual(self.view.snapshot()['outgoing'], [])
        self.app.state.current_chat = self.key
        self.app.state.username = 'another-user'
        self.assertEqual(self.view.snapshot()['outgoing'], [])
        self.app.state.username = 'alice'
        self.app.sends.MAX_BYTES = 130
        self.app.sends._trim_outcomes()
        self.assertLessEqual(sum(item.size for item in self.app.sends.outcomes), 130)
        self.app.sends.reset()
        self.assertFalse(self.app.sends.outcomes)

    def test_failure_budget_counts_json_escape_expansion(self):
        record = self.send('\x00' * 100)
        self.result(record, success=False)
        self.assertGreaterEqual(self.app.sends.outcomes[0].size, 600)
        self.app.sends.MAX_BYTES = 400
        self.app.sends._trim_outcomes()
        self.assertFalse(self.app.sends.outcomes)


if __name__ == '__main__':
    unittest.main()
