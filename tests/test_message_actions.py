"""Native read-only message selection, explicit clipboard actions and cleanup."""
import unittest
from unittest.mock import Mock
from tkinter import font as tkfont

import client
import test_client_scrolling as scrolling
from tk_menu_support import nonblocking_menu_posts
from chatroom_client.models import ChatKey, Message


class MessageActionTests(unittest.TestCase):
    setUp = scrolling.ClientScrollingTests.setUp
    tearDown = scrolling.ClientScrollingTests.tearDown
    wait_for_geometry = scrolling.ClientScrollingTests.wait_for_geometry

    def show(self, count=2):
        key = ChatKey('private', 'synthetic-peer')
        for mid in range(1, count + 1):
            self.app.state.conversation(key).add(Message(key.target, 'Synthetic 中文🙂 body ' + str(mid),
                '2026-10-26T09:00:00Z', mid, encryption='e2ee'))
        self.app.select_chat(key)
        self.root.update()
        return key, self.view.current_chat_frame.pack_slaves()

    def activate(self, row):
        self.view.message_actions.activate(row)
        self.root.update()
        return self.view.message_actions.text

    def test_drag_selection_and_keyboard_copy_use_native_text_without_editing(self):
        _, rows = self.show()
        row = rows[0]
        label = row._chat_body
        label.event_generate('<Button-1>', x=15, y=15)
        self.root.update()
        text = self.view.message_actions.text
        font = tkfont.Font(root=self.root, font=text.cget('font'))
        label.event_generate('<B1-Motion>', x=15 + font.measure('Synthetic'), y=15, state=0x100)
        label.event_generate('<ButtonRelease-1>', x=15 + font.measure('Synthetic'), y=15)
        self.root.update()
        self.assertTrue(self.view.message_actions.selected_text())
        text.focus_force()
        text.event_generate('<<Copy>>')
        self.root.update()
        self.assertEqual(self.root.clipboard_get(), self.view.message_actions.selected_text())
        original = text.get('1.0', 'end-1c')
        text.event_generate('<<Paste>>')
        text.event_generate('<<Cut>>')
        text.event_generate('<KeyPress-x>')
        self.root.update()
        self.assertEqual(text.get('1.0', 'end-1c'), original)
        self.assertEqual(row._chat_message.content, original)

    def test_full_copy_and_unicode_selection_exclude_author_time_and_security(self):
        _, rows = self.show()
        row = rows[0]
        text = self.activate(row)
        self.view.message_actions.copy_message()
        self.assertEqual(self.root.clipboard_get(), row._chat_message.content)
        text.event_generate('<Control-a>')
        self.root.update()
        text.event_generate('<<Copy>>')
        self.assertEqual(self.root.clipboard_get(), row._chat_message.content)
        self.assertIn('中文🙂', self.root.clipboard_get())

    def test_context_menu_supports_keyboard_copy_and_leaves_no_grab(self):
        with nonblocking_menu_posts():
            _, rows = self.show()
            text = self.activate(rows[0])
            text.tag_add('sel', '1.0', '1.0+9c')
            self.view.message_actions.popup(rows[0], text=text)
            menu = self.view.message_actions.menu
            self.assertEqual(menu.entrycget(0, 'state'), 'normal')
            menu.invoke(0)
            menu.unpost()
            self.assertEqual(self.root.clipboard_get(), 'Synthetic')
            self.assertIsNone(self.root.grab_current())
            text.focus_force()
            self.root.update()
            text.tag_remove('sel', '1.0', 'end')
            text.event_generate('<Shift-F10>')
            self.root.update()
            self.assertEqual(menu.entrycget(0, 'state'), 'disabled')
            menu.invoke(1)
            menu.unpost()
            self.assertEqual(self.root.clipboard_get(), rows[0]._chat_message.content)

    def test_only_one_lazy_overlay_exists_and_activation_does_not_change_geometry(self):
        _, rows = self.show()
        before = [(row.winfo_height(), row._chat_body.winfo_height()) for row in rows]
        self.assertIsNone(self.view.message_actions.text)
        first = self.activate(rows[0])
        second = self.activate(rows[1])
        self.assertFalse(first.winfo_exists())
        self.assertTrue(second.winfo_exists())
        self.assertEqual(before, [(row.winfo_height(), row._chat_body.winfo_height()) for row in rows])
        self.view.message_actions.close_selection()
        self.assertIsNone(self.view.message_actions.text)

    def test_selection_and_menu_are_discarded_when_switching_chat_or_removing_cache(self):
        key, rows = self.show()
        text = self.activate(rows[0])
        self.app.select_chat(ChatKey('private', 'another-peer'))
        self.assertFalse(text.winfo_exists())
        self.assertIsNone(self.view.message_actions.row)
        self.app.select_chat(key)
        self.activate(rows[0])
        self.view.remove_conversation(key)
        self.assertIsNone(self.view.message_actions.text)
        self.assertIsNone(self.view.message_actions.row)

    def test_search_highlight_supports_copy_and_closing_search_releases_selection(self):
        _, rows = self.show()
        self.view.search.open()
        self.view.search.query.set('body')
        self.view.search.refresh(jump=True)
        self.root.update()
        text = self.view.search._highlighted._search_body
        text.focus_force()
        self.root.update()
        text.tag_add('sel', *text.tag_ranges('search_current'))
        text.event_generate('<<Copy>>')
        self.assertEqual(self.root.clipboard_get(), 'body')
        self.view.search.close()
        self.assertIsNone(self.view.message_actions.row)
        self.assertFalse(text.winfo_exists())

    def test_clipboard_is_written_only_after_explicit_copy_and_errors_keep_input(self):
        _, rows = self.show()
        self.root.clipboard_clear()
        self.root.clipboard_append('Synthetic clipboard sentinel')
        self.view.replace_input('Synthetic untouched draft')
        self.activate(rows[0])
        self.view.message_actions.close_selection()
        self.assertEqual(self.root.clipboard_get(), 'Synthetic clipboard sentinel')
        self.activate(rows[0])
        self.view.master.clipboard_append = Mock(side_effect=client.tk.TclError('Synthetic unavailable clipboard'))
        self.view.message_actions.copy_message()
        self.assertIn('复制失败', self.view.status_label.cget('text'))
        self.assertEqual(self.view.input_text(), 'Synthetic untouched draft')

    def test_windowed_history_lazily_creates_headers_and_reuses_existing_rows(self):
        key, rows = self.show(300)
        self.assertLessEqual(len(rows), 120)
        self.assertEqual(sum(row._chat_heading is not None for row in rows), 1)
        self.view.render_conversation(key)
        self.assertEqual(self.view.current_chat_frame.pack_slaves(), rows)
        self.assertIsNone(self.view.message_actions.text)
