"""Lost acknowledgements are reconciled before any idempotent retry."""
import os
import unittest
from unittest.mock import Mock

import test_regressions as regression
from chatroom_client.models import ChatKey


class SendRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.app = regression.headless_client(self)
        self.app.state.username = 'alice'
        self.app.state.current_chat = ChatKey('private', 'bob')
        self.app.connection.endpoint = ('synthetic-server', 12345)
        self.app.connection.session_key = os.urandom(16)
        self.app.connection.capabilities = ('message_receipts',)
        self.app.view.input_text.return_value = 'Synthetic pending message'

    def send(self):
        self.app.send_message()
        return self.app.sends.records[-1]

    def expire(self, record):
        self.app.expire_pending(self.app.connection.sock, record.request_id)

    def result(self, record, status, **kwargs):
        self.app.handle_server_message({'type': 'message_status_result', 'request_id': record.query,
            'idempotency_key': record.payload['idempotency_key'], 'chat_type': 'private', 'target': 'bob',
            'success': True, 'status': status, **kwargs})

    def test_lost_ack_is_queried_and_saved_message_recovers_without_resending(self):
        record = self.send()
        self.expire(record)
        self.assertFalse(self.app.state.pending_messages)
        self.assertEqual(self.app.connection.send.call_args.args[0]['type'], 'message_status_request')
        self.result(record, 'saved', message_id=37, timestamp='synthetic timestamp')
        self.assertFalse(self.app.sends.records)
        self.assertEqual(self.app.connection.send.call_count, 2)
        self.assertEqual(self.app.state.conversation(record.context.key).message_ids, [37])
        self.app.view.clear_input_if_unchanged.assert_called_once_with(record.text)

    def test_retry_preserves_idempotency_key_but_old_ack_and_timer_cannot_finish_it(self):
        record = self.send()
        first, token = record.request_id, record.timer
        self.expire(record)
        self.result(record, 'not_found')
        self.app.sends.recover(record)
        self.assertNotEqual(record.request_id, first)
        self.assertEqual(record.payload['idempotency_key'], first)
        self.app.sends.expire(self.app.connection.sock, record.request_id, token)
        self.app.handle_server_message({'type': 'private_chat_result', 'request_id': first, 'success': True})
        self.assertIn(record.request_id, self.app.state.pending_messages)
        self.app.view.notify.reset_mock()
        self.app.handle_server_message({'type': 'private_chat_result', 'request_id': first,
                                        'success': False, 'error': 'Synthetic late failure'})
        self.app.view.notify.assert_not_called()
        self.app.handle_server_message({'type': 'private_chat_result', 'request_id': record.request_id, 'success': True})
        self.assertFalse(self.app.sends.records or self.app.state.pending_messages)

    def test_timeout_allows_other_content_but_same_input_reconciles_instead_of_duplicating(self):
        record = self.send()
        self.expire(record)
        self.app.send_message()
        self.assertEqual(len(self.app.sends.records), 1)
        self.app.view.input_text.return_value = 'Synthetic next message'
        self.app.send_message()
        self.assertEqual(len(self.app.sends.records), 2)

    def test_status_from_other_scope_is_ignored_until_correct_response(self):
        record = self.send()
        self.expire(record)
        query = record.query
        self.app.handle_server_message({'type': 'message_status_result', 'request_id': query,
            'idempotency_key': record.payload['idempotency_key'], 'chat_type': 'private', 'target': 'carol',
            'success': True, 'status': 'saved', 'message_id': 19})
        self.assertEqual(record.query, query)
        self.assertFalse(self.app.state.conversations)
        self.result(record, 'saved', message_id=19)
        self.assertFalse(self.app.sends.records)

    def test_reconnect_queries_receipt_and_does_not_automatically_resend(self):
        record = self.send()
        self.app.state.pending_messages.clear()
        self.app.sends.pause()
        self.app.connection.sock = Mock()
        self.app.sends.resume()
        self.assertEqual(self.app.connection.send.call_args.args[0]['type'], 'message_status_request')
        self.result(record, 'saved', message_id=27)
        self.assertEqual(self.app.connection.send.call_count, 2)

    def test_account_change_and_removed_group_cannot_resume_old_sends(self):
        self.send()
        self.app.state.reset_session('carol')
        self.app.sends.resume()
        self.assertFalse(self.app.sends.records)
        self.app.state.current_chat = ChatKey('group', 'g')
        self.app.state.groups['g'] = {'members': ['carol']}
        self.send()
        self.app.state.remove_group('g')
        self.app.state.groups['g'] = {'members': ['carol']}
        self.app.sends.resume()
        self.assertFalse(self.app.sends.records)

    def test_legacy_timeout_does_not_guess_or_resubmit(self):
        self.app.connection.capabilities = ()
        record = self.send()
        self.expire(record)
        self.app.send_message()
        self.assertEqual(self.app.connection.send.call_count, 1)
        self.assertFalse(self.app.state.pending_messages)
        self.assertNotIn('idempotency_key', record.payload)

    def test_wrong_chat_result_cannot_release_request(self):
        record = self.send()
        self.app.handle_server_message({'type': 'group_chat_result', 'request_id': record.request_id, 'success': True})
        self.assertIn(record.request_id, self.app.state.pending_messages)

    def test_leaving_group_releases_inflight_send_and_discards_recovery_body(self):
        self.app.state.current_chat = ChatKey('group', 'g')
        self.app.state.groups['g'] = {'members': ['alice']}
        self.send()
        self.app.events.remove_group('g')
        self.assertFalse(self.app.sends.records or self.app.state.pending_messages)

    def test_record_limit_keeps_unresolved_receipts_and_input(self):
        self.app.sends.MAX_RECORDS = 1
        record = self.send()
        self.expire(record)
        self.app.view.input_text.return_value = 'Synthetic second input'
        self.app.send_message()
        self.assertEqual(self.app.connection.send.call_count, 2)
        self.assertEqual(self.app.sends.records, [record])

    def test_manual_disconnect_releases_volatile_pending_contents(self):
        self.send()
        self.app.disconnect()
        self.assertFalse(self.app.sends.records)

    def test_dismiss_does_not_cancel_sending_or_allow_stale_actions_to_resend(self):
        record = self.send()
        self.assertFalse(self.app.sends.dismiss(record.record_id))
        self.expire(record)
        self.assertTrue(self.app.sends.dismiss(record.record_id))
        count = self.app.connection.send.call_count
        self.app.sends.recover(record)
        self.result(record, 'saved', message_id=91)
        self.assertEqual(self.app.connection.send.call_count, count)
        self.assertFalse(self.app.sends.records or self.app.state.pending_messages)
        self.assertFalse(self.app.state.conversations)

    def test_legacy_records_can_be_dismissed_to_release_capacity_without_sending(self):
        self.app.connection.capabilities = ()
        self.app.sends.MAX_RECORDS = 1
        record = self.send()
        self.expire(record)
        self.assertTrue(self.app.sends.dismiss(record.record_id))
        self.assertEqual(self.app.connection.send.call_count, 1)
        self.app.view.input_text.return_value = 'Synthetic next input'
        next_record = self.send()
        self.assertNotEqual(next_record.record_id, record.record_id)
        self.assertEqual(self.app.connection.send.call_count, 2)

    def test_dismiss_is_scoped_to_current_account_and_endpoint(self):
        record = self.send()
        self.expire(record)
        self.app.state.username = 'another-owner'
        self.assertFalse(self.app.sends.owned_records())
        self.assertFalse(self.app.sends.dismiss(record.record_id))
        self.app.state.username = 'alice'
        self.app.connection.endpoint = ('another-server', 12345)
        self.assertFalse(self.app.sends.dismiss(record.record_id))

    def test_reconnect_gap_keeps_records_visible_and_old_timer_cannot_discard_them(self):
        record = self.send()
        sock, token = self.app.connection.sock, record.timer
        self.app._session_endpoint = record.endpoint
        self.app.sends.pause()
        self.app.connection.disconnect(preserve_credentials=True)
        self.app.reconnecting = True
        self.app.sends.expire(sock, record.request_id, token)
        self.assertEqual(self.app.sends.owned_records(), [record])
        self.assertTrue(self.app.sends.dismiss(record.record_id))
        self.assertFalse(self.app.sends.records)
