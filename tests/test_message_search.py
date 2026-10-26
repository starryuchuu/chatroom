"""Literal, account-scoped searches navigate real Tk message windows."""
import unittest
from unittest.mock import Mock

import test_client_scrolling as scrolling
from chatroom_client.models import ChatKey, Message
from chatroom_client.search import find_messages


class SearchModelTests(unittest.TestCase):
    def test_literal_unicode_case_insensitive_matches_exclude_failed_validation(self):
        messages = [Message('peer', '🙂 Needle 界 a.b', message_id=1),
                    Message('peer', 'NEEDLE axb', message_id=2),
                    Message('peer', 'Needle', message_id=3, encryption='failed')]
        hits, truncated = find_messages(messages, 'needle')
        self.assertEqual([hit.message.message_id for hit in hits], [1, 2])
        self.assertEqual(messages[0].content[hits[0].start:hits[0].end], 'Needle')
        self.assertFalse(truncated)
        self.assertEqual(len(find_messages(messages, 'a.b')[0]), 1)
        self.assertFalse(find_messages(messages, '')[0])

    def test_result_limit_bounds_repeated_substrings(self):
        messages = [Message('peer', 'x' * 10000, message_id=1)]
        hits, truncated = find_messages(messages, 'x')
        self.assertEqual(len(hits), 1000)
        self.assertTrue(truncated)


class SearchViewTests(unittest.TestCase):
    setUp = scrolling.ClientScrollingTests.setUp
    tearDown = scrolling.ClientScrollingTests.tearDown
    wait_for_geometry = scrolling.ClientScrollingTests.wait_for_geometry
    assert_message_position = scrolling.ClientScrollingTests.assert_message_position

    def history(self):
        key = ChatKey('private', 'synthetic-peer')
        self.app.state.friends = [key.target]
        conversation = self.app.state.conversation(key)
        for mid in range(1, 601):
            text = '🙂 Needle 界' if mid == 13 else ('second NEEDLE' if mid == 421 else f'Synthetic body {mid}')
            conversation.add(Message(key.target, text, message_id=mid))
        self.app.select_chat(key)
        self.root.update()
        return key

    def search_for(self, query):
        self.view.search.open()
        self.view.search.query.set(query)
        self.view.search.refresh(jump=True)
        self.root.update()

    def test_search_jumps_across_windows_highlights_emoji_prefix_and_preserves_unread(self):
        key = self.history()
        before = self.app.state.conversation(key).read_id
        self.search_for('needle')
        search = self.view.search
        self.assertEqual(len(search.hits), 2)
        row = search._highlighted
        self.assertEqual(row._chat_message.message_id, 13)
        self.assertEqual(row._search_body.get(*row._search_body.tag_ranges('search_current')), 'Needle')
        self.assertLessEqual(len(self.view.current_chat_frame.winfo_children()), 120)
        search.move(1)
        self.root.update()
        self.assertEqual(search._highlighted._chat_message.message_id, 421)
        self.assertEqual(search.count.cget('text'), '2/2')
        self.assertEqual(self.app.state.conversation(key).read_id, before)
        self.assertFalse(self.view._new_messages)
        search.close()
        self.assertFalse(search.hits or search.visible)
        self.assertFalse(any(hasattr(row, '_search_body') and row._search_body.winfo_exists()
                             for row in self.view.current_chat_frame.winfo_children()))

    def test_switch_conversation_clears_query_and_results(self):
        self.history()
        self.search_for('needle')
        self.app.select_chat(ChatKey('private', 'other-peer'))
        self.root.update()
        self.assertFalse(self.view.search.hits or self.view.search.visible)
        self.assertIsNone(self.view.search.key)

    def test_ctrl_f_from_composer_opens_search_and_preserves_input(self):
        self.history()
        self.app.connection.send = Mock()
        self.view.msg_entry.insert('1.0', 'Synthetic untouched input')
        self.view.msg_entry.focus_force()
        self.view.msg_entry.event_generate('<Control-f>')
        self.root.update()
        self.assertTrue(self.view.search.visible)
        self.assertEqual(self.view.input_text(), 'Synthetic untouched input')
        self.app.connection.send.assert_not_called()

    def test_enter_before_debounce_uses_current_query(self):
        self.history()
        self.search_for('needle')
        self.view.search.entry.focus_force()
        self.root.update()
        self.view.search.query.set('Synthetic body 200')
        self.view.search.entry.event_generate('<Return>')
        self.assertEqual(self.view.search._highlighted._chat_message.message_id, 200)
        self.root.update()
        self.assertEqual(self.view.search._highlighted._chat_message.message_id, 200)

    def test_cache_reload_discards_results_and_references_to_old_message_bodies(self):
        key = self.history()
        self.search_for('needle')
        self.app.state.conversation(key).clear_cache(reload_latest=True)
        self.view.cache_changed(key, [])
        self.view.render_conversation(key)
        self.root.update()
        self.assertFalse(self.view.search.hits)
        self.assertIsNone(self.view.search._highlighted)

    def test_account_switch_invalidates_queued_search_callback(self):
        key = self.history()
        self.view.search.open()
        self.view.search.query.set('needle')
        self.app.disconnect()
        self.app.connection.running = True
        self.app.connection.sock = Mock()
        self.app.state.username = 'second-synthetic-account'
        self.app.state.current_chat = key
        self.app.state.friends = [key.target]
        self.app.state.conversation(key).add(Message(key.target, 'Second account only', message_id=1))
        self.view.build_chat()
        self.view.render_conversation(key)
        self.root.update()
        self.assertFalse(self.view.search.hits or self.view.search.visible)
        self.assertEqual(self.app.state.conversation(key).messages[0].content, 'Second account only')

    def test_close_restores_pre_search_message_and_pixel_offset(self):
        self.history()
        self.view.chat_canvas.yview_moveto(.42)
        self.root.update()
        original = self.view.capture_chat_scroll()
        self.search_for('needle')
        self.view.search.move(1)
        self.root.update()
        self.view.search.entry.focus_force()
        self.view.search.entry.event_generate('<Escape>')
        self.root.update()
        self.assert_message_position(original['message'].content, original['offset'])
        self.assertFalse(self.view.search.visible)

    def test_close_restores_live_following_after_new_messages_during_search(self):
        self.history()
        self.assertTrue(self.view.chat_is_at_bottom())
        self.search_for('needle')
        scrolling.ClientScrollingTests.deliver(self, 601)
        self.root.update()
        self.view.search.close()
        self.root.update()
        self.assertTrue(self.view.chat_is_at_bottom())
        self.assertEqual(self.view.current_chat_frame.pack_slaves()[-1]._chat_message.message_id, 601)

    def test_highlight_stays_legible_in_both_themes_and_resizes_with_viewport(self):
        self.history()
        self.search_for('needle')

        def luminance(color):
            values = [value / 65535 for value in self.root.winfo_rgb(color)]
            values = [value / 12.92 if value <= .04045 else ((value + .055) / 1.055) ** 2.4 for value in values]
            return sum(weight * value for weight, value in zip((.2126, .7152, .0722), values))

        for mode in ('dark', 'light'):
            self.view.set_theme(mode)
            self.root.update()
            body = self.view.search._highlighted._search_body
            first = luminance(body.tag_cget('search_current', 'foreground'))
            second = luminance(body.tag_cget('search_current', 'background'))
            self.assertGreaterEqual((max(first, second) + .05) / (min(first, second) + .05), 4.5)
        self.root.geometry('1120x760')
        self.root.update()
        wider = self.view.search._highlighted._search_body.cget('width')
        self.root.geometry('900x700')
        self.root.update()
        self.assertLess(self.view.search._highlighted._search_body.cget('width'), wider)
        self.assertEqual(self.view.search._highlighted._chat_message.message_id, 13)

    def test_no_results_disable_navigation_and_keep_scope_visible(self):
        self.history()
        self.search_for('absent synthetic phrase')
        self.assertEqual(self.view.search.count.cget('text'), '无结果')
        self.assertIn('已加载消息', self.view.search.scope.cget('text'))
        self.assertTrue(all(button.cget('state') == 'disabled' for button in self.view.search.buttons[:2]))

    def test_highlight_resize_with_queued_scroll_does_not_reenter_render_or_lose_anchor(self):
        self.history()
        self.search_for('needle')
        self.view.search._highlighted._search_body.configure(width=1)
        self.view.request_scroll()
        self.view.search.resize()
        self.root.update()
        self.assertEqual(self.view.search._highlighted._chat_message.message_id, 13)
        for row in self.view.current_chat_frame.winfo_children():
            self.assertLessEqual(sum(isinstance(widget, scrolling.client.tk.Text)
                                     for widget in row.winfo_children()), 1)
