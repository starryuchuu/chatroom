"""Multiple unresolved sends are selectable and removable within the chat page."""
import unittest
from unittest.mock import Mock

import client
import test_client_scrolling as scrolling
from chatroom_client.models import ChatKey, Message


class SendRecoveryViewTests(unittest.TestCase):
    setUp = scrolling.ClientScrollingTests.setUp
    tearDown = scrolling.ClientScrollingTests.tearDown
    wait_for_geometry = scrolling.ClientScrollingTests.wait_for_geometry
    assert_message_position = scrolling.ClientScrollingTests.assert_message_position

    def send(self, target, text, *, receipts=True):
        self.app.connection.capabilities = ('message_receipts',) if receipts else ()
        self.app.connection.send = Mock()
        self.app.select_chat(ChatKey('private', target))
        self.view.replace_input(text)
        self.app.send_message()
        record = self.app.sends.records[-1]
        self.app.expire_pending(self.app.connection.sock, record.request_id)
        return record

    def result(self, record, status):
        self.app.handle_server_message({'type': 'message_status_result', 'request_id': record.query,
            'idempotency_key': record.payload['idempotency_key'], 'chat_type': record.context.key.kind,
            'target': record.context.key.target, 'success': True, 'status': status})

    def open_panel(self):
        self.view.recover_send_button.invoke()
        self.root.update()
        panel = self.view.send_recovery
        self.assertTrue(panel.frame.winfo_ismapped())
        return panel

    def select(self, panel, record):
        panel.tree.selection_set(record.record_id)
        self.root.update()

    def test_list_shows_all_chats_and_retries_selected_record_without_changing_draft(self):
        first = self.send('a', 'Synthetic first input')
        second = self.send('b', 'Synthetic second input')
        self.result(first, 'not_found')
        self.result(second, 'not_found')
        panel = self.open_panel()
        self.assertEqual(len(panel.tree.get_children()), 2)
        self.select(panel, second)
        self.assertIn('Synthetic second', panel.tree.item(second.record_id, 'values')[3])
        self.assertEqual(panel.recover_button.cget('text'), '重试所选消息')
        self.view.replace_input('Synthetic unrelated edit')
        panel.recover_button.invoke()
        sent = self.app.connection.send.call_args.args[0]
        self.assertEqual(sent['idempotency_key'], second.payload['idempotency_key'])
        self.assertEqual(sent['to'], 'b')
        self.assertEqual(first.status, 'retry')
        self.assertEqual(self.view.input_text(), 'Synthetic unrelated edit')
        self.assertEqual(panel.dismiss_button.cget('state'), 'disabled')
        self.assertFalse(any(isinstance(widget, client.tk.Toplevel) for widget in self.root.winfo_children()))

    def test_legacy_record_requires_explicit_removal_and_preserves_input(self):
        record = self.send('a', 'Synthetic legacy input', receipts=False)
        panel = self.open_panel()
        self.assertEqual(panel.recover_button.cget('state'), 'disabled')
        self.assertIn('无法核对', panel.hint.cget('text'))
        count = self.app.connection.send.call_count
        panel.dismiss_button.invoke()
        self.assertIn(record, self.app.sends.records)
        self.assertIn('再次发送可能重复', panel.hint.cget('text'))
        panel.dismiss_button.invoke()
        self.assertFalse(self.app.sends.records)
        self.assertEqual(self.app.connection.send.call_count, count)
        self.assertEqual(self.view.input_text(), 'Synthetic legacy input')
        self.assertFalse(panel.frame.winfo_manager())

    def test_switching_selection_cancels_pending_removal_confirmation(self):
        first = self.send('a', 'Synthetic first', receipts=False)
        second = self.send('b', 'Synthetic second', receipts=False)
        panel = self.open_panel()
        self.select(panel, first)
        panel.dismiss_button.invoke()
        self.select(panel, second)
        self.assertIsNone(panel._confirm_id)
        panel.dismiss_button.invoke()
        self.assertEqual(len(self.app.sends.records), 2)
        panel.dismiss_button.invoke()
        self.assertEqual(self.app.sends.records, [first])

    def test_query_state_disables_repeat_query_and_hiding_keeps_records(self):
        record = self.send('a', 'Synthetic checking input')
        panel = self.open_panel()
        self.assertEqual(panel.recover_button.cget('state'), 'disabled')
        self.assertEqual(panel.tree.item(record.record_id, 'values')[2], '正在核对')
        panel.hide()
        self.assertEqual(self.app.sends.records, [record])
        self.app._session_endpoint = record.endpoint
        self.app.sends.pause()
        self.app.connection.disconnect(preserve_credentials=True)
        self.app.reconnecting = True
        self.view.refresh_controls()
        self.assertEqual(panel.tree.get_children(), (record.record_id,))
        panel.toggle()
        self.assertEqual(panel.recover_button.cget('state'), 'disabled')
        self.assertEqual(panel.dismiss_button.cget('state'), 'normal')

    def test_disconnect_destroys_list_and_removes_outgoing_previews(self):
        self.send('a', 'Synthetic volatile preview', receipts=False)
        panel = self.open_panel()
        self.app.disconnect()
        self.assertFalse(panel.tree.winfo_exists())
        self.assertIsNone(self.view.send_recovery)
        self.assertFalse(self.app.sends.records)

    def test_open_and_close_list_preserve_reading_position_and_live_follow(self):
        self.send('a', 'Synthetic pending input', receipts=False)
        key = self.app.state.current_chat
        for mid in range(1, 101):
            self.app.state.conversation(key).add(Message('a', f'Synthetic history body {mid}', message_id=mid))
        self.view.render_conversation(key)
        self.root.update()
        self.view.chat_canvas.yview_moveto(.4)
        self.root.update()
        viewport = self.view.capture_chat_scroll()
        panel = self.open_panel()
        self.assert_message_position(viewport['message'].content, viewport['offset'])
        panel.hide()
        self.root.update()
        self.assert_message_position(viewport['message'].content, viewport['offset'])
        self.view.scroll_to_bottom()
        panel.toggle()
        self.root.update()
        self.assertTrue(self.view.chat_is_at_bottom())
        panel.hide()
        self.root.update()
        self.assertTrue(self.view.chat_is_at_bottom())
