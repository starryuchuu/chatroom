"""Context actions and message presentation remain usable in actual Tk windows."""
from datetime import datetime, timedelta
import unittest
from unittest.mock import Mock

import client
import test_client_scrolling as scrolling
from tk_menu_support import nonblocking_menu_posts
from chatroom_client.models import ChatKey, Message


class ChatPresentationTests(unittest.TestCase):
    setUp = scrolling.ClientScrollingTests.setUp
    tearDown = scrolling.ClientScrollingTests.tearDown
    wait_for_geometry = scrolling.ClientScrollingTests.wait_for_geometry
    assert_message_position = scrolling.ClientScrollingTests.assert_message_position

    def show(self, messages):
        key = ChatKey('private', 'synthetic-peer')
        self.app.state.friends = [key.target]
        for message in messages:
            self.app.state.conversation(key).add(message)
        self.app.select_chat(key)
        self.root.update()
        return key

    def test_header_has_two_actions_and_more_menu_respects_chat_and_busy_state(self):
        self.show([Message('synthetic-peer', 'Synthetic message', message_id=101)])
        self.app.connection.send = Mock()
        controls = [widget.cget('text') for widget in self.view.more_button.master.winfo_children()
                    if isinstance(widget, client.tk.Button)]
        self.assertEqual(controls, ['搜索', '更多'])
        menu = self.view.conversation_menu
        self.assertEqual(menu.entrycget(self.view.group_menu_index, 'state'), 'disabled')
        with nonblocking_menu_posts() as posting:
            self.view.more_button.focus_force()
            self.view.more_button.event_generate('<Return>')
            self.root.update()
            if posting is None:
                self.assertTrue(menu.winfo_ismapped())
            else:
                posting.assert_called_once()
            menu.invoke(self.view.history_menu_index)
            menu.unpost()
            self.assertEqual(self.app.connection.send.call_args.args[0]['before_id'], 101)
            self.assertEqual(menu.entrycget(self.view.history_menu_index, 'state'), 'disabled')
            self.assertIsNone(self.root.grab_current())
        self.app.history.abort()
        self.app.state.groups['g'] = {'group_name': 'Synthetic group', 'members': ['synthetic-account']}
        self.app.select_chat(ChatKey('group', 'g'))
        self.assertEqual(menu.entrycget(self.view.group_menu_index, 'state'), 'normal')
        menu.invoke(self.view.group_menu_index)
        self.assertEqual(self.app.connection.send.call_args.args[0]['type'], 'group_info')

    def test_date_sender_and_security_boundaries_control_headers_without_losing_details(self):
        self.app.encryption = Mock(ready=True, sending=False, status='Synthetic encryption status')
        messages = [
            Message('bob', 'First verified body', '2026-10-26 09:00:00', 1, encryption='e2ee'),
            Message('bob', 'Same sender body', '2026-10-26 09:01:00', 2, encryption='e2ee'),
            Message('bob', 'After a pause', '2026-10-26 09:08:00', 3, encryption='e2ee'),
            Message('carol', 'Different sender', '2026-10-26 09:09:00', 4, encryption='e2ee'),
            Message('carol', 'Legacy next day', '2026-10-27 09:00:00', 5, encryption='legacy'),
            Message('carol', 'Failed validation placeholder', '2026-10-27 09:01:00', 6, encryption='failed'),
        ]
        self.show(messages)
        rows = self.view.current_chat_frame.pack_slaves()
        self.assertEqual([bool(row._chat_author is not None and row._chat_author.winfo_manager()) for row in rows], [True, False, True, True, True, True])
        self.assertEqual([row._chat_date.cget('text') for row in rows if row._chat_date is not None and row._chat_date.winfo_manager()],
                         ['2026年10月26日', '2026年10月27日'])
        self.assertEqual(rows[1]._chat_meta.cget('text'), '09:01  ·  已加密')
        self.assertIn('非端到端加密', rows[4]._chat_meta.cget('text'))
        self.assertEqual(rows[5]._chat_meta.cget('fg'), self.view.colors['danger'])
        rows[1]._chat_meta.event_generate('<Button-1>')
        self.root.update()
        self.assertIn('2026-10-26 09:01:00', rows[1]._chat_details.cget('text'))
        self.assertIn('端到端加密验证', rows[1]._chat_details.cget('text'))
        rows[1]._chat_meta.focus_force()
        rows[1]._chat_meta.event_generate('<space>')
        self.root.update()
        self.assertFalse(rows[1]._chat_details.winfo_manager())
        self.assertFalse(any(isinstance(widget, client.tk.Toplevel) for widget in self.root.winfo_children()))

    def test_verified_replacement_regroups_neighbors_and_reuses_their_rows(self):
        key = self.show([
            Message('bob', 'First', '2026-10-26 09:00:00', 1, encryption='e2ee'),
            Message('bob', 'Failed placeholder', '2026-10-26 09:01:00', 2, encryption='failed'),
            Message('bob', 'Third', '2026-10-26 09:02:00', 3, encryption='e2ee')])
        last = self.view.current_chat_frame.pack_slaves()[-1]
        self.assertTrue(last._chat_author.winfo_manager())
        self.app.state.conversation(key).add(Message('bob', 'Recovered body', '2026-10-26 09:01:00', 2, encryption='e2ee'))
        self.view.render_conversation(key)
        self.root.update()
        self.assertIs(self.view.current_chat_frame.pack_slaves()[-1], last)
        self.assertFalse(last._chat_author.winfo_manager())
        self.assertEqual(len(self.view.current_chat_frame.winfo_children()), 3)

    def test_window_boundary_repositions_date_header_and_preserves_body_anchor(self):
        start = datetime(2026, 10, 26, 9)
        key = self.show([Message('bob', 'Synthetic dated message ' + str(mid),
                                (start + timedelta(seconds=mid)).isoformat(' '), mid, encryption='e2ee')
                         for mid in range(1, 301)])
        self.view._restoring_scroll = True
        self.view.chat_canvas.yview_moveto(0)
        self.root.update()
        self.view._restoring_scroll = False
        viewport = self.view.capture_chat_scroll()
        message = viewport['message']
        self.view.message_list.focus(key, 180)
        self.view.render_conversation(key)
        self.root.update()
        self.assert_message_position(message.content, viewport['offset'])
        rows = self.view.current_chat_frame.pack_slaves()
        self.assertEqual(rows[0]._chat_message.message_id, 121)
        self.assertTrue(rows[0]._chat_date.winfo_manager())
        self.assertEqual(sum(bool(row._chat_date is not None and row._chat_date.winfo_manager()) for row in rows), 1)
        self.assertLessEqual(len(rows), 120)

    def test_return_latest_exists_only_as_the_bottom_navigation(self):
        key = self.show([Message('bob', 'Synthetic message ' + str(mid), message_id=mid) for mid in range(1, 301)])
        self.view.message_list.focus(key, 1)
        self.view.render_conversation(key, focus_message=self.app.state.conversation(key).messages[1])
        self.root.update()
        self.assertTrue(self.view.new_messages_button.winfo_ismapped())
        self.assertEqual(self.view.new_messages_button.cget('text'), '返回最新消息 ↓')
        self.view.new_messages_button.invoke()
        self.root.update()
        self.assertTrue(self.view.chat_is_at_bottom())
        self.assertFalse(self.view.new_messages_button.winfo_ismapped())

    def test_clearing_selection_disables_actions_and_closes_search(self):
        self.show([Message('bob', 'Synthetic message', message_id=1)])
        self.view.search.open()
        self.app.clear_chat_selection()
        self.root.update()
        self.assertFalse(self.view.search.visible)
        self.assertEqual(self.view.search_button.cget('state'), 'disabled')
        self.assertEqual(self.view.more_button.cget('state'), 'disabled')

    def test_inline_details_cancel_queued_follow_before_restoring_viewport(self):
        self.show([Message('bob', 'Synthetic timed body', '2026-10-26 09:00:00', 1, encryption='e2ee')])
        row = self.view.current_chat_frame.pack_slaves()[0]
        self.view.request_scroll()
        self.view.message_rows.toggle_details(row)
        self.root.update()
        self.assertTrue(row._chat_details.winfo_manager())
        self.assertIsNone(self.view._scroll_after_id)
