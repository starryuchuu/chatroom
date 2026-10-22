"""Desktop interactions introduced by the simplified client layout."""
import gc
from tkinter import font as tkfont
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import client
from chatroom_client.models import ChatKey, Message
from chatroom_client.preferences import PreferencesStore


class ClientLayoutTests(unittest.TestCase):
    def setUp(self):
        self.root = client.tk.Tk()
        self.root.withdraw()
        self.app = client.ChatClient(self.root, preferences=PreferencesStore(persistent=False), encryption=False)
        self.app.connection.running = True
        self.app.connection.sock = Mock()
        self.app.state.username = 'alice'
        self.app.view.build_chat()

    def tearDown(self):
        self.app.close()
        self.app = self.root = None
        gc.collect()

    def test_online_panel_toggle_preserves_the_latest_snapshot_and_draft(self):
        view = self.app.view
        view.msg_entry.insert('1.0', 'unsent draft')
        view.update_online_users(['alice', 'bob'])
        self.assertFalse(view.online_visible)
        view.toggle_online()
        self.assertEqual(view.online_panel.winfo_manager(), 'grid')
        view.toggle_online()
        view.update_online_users(['alice', 'carol'])
        view.toggle_online()
        self.assertEqual(view.online_listbox.get(0, client.tk.END), ('alice', 'carol'))
        self.assertEqual(view.input_text(), 'unsent draft')

    def test_shift_and_ctrl_enter_insert_newlines_without_sending(self):
        view = self.app.view
        self.app.send_message = Mock()
        for modifier in (0x1, 0x4, 0x5):
            view.msg_entry.delete('1.0', client.tk.END)
            view.msg_entry.insert('1.0', 'draft')
            view.on_message_entry_key(SimpleNamespace(state=modifier))
            self.assertEqual(view.input_text(), 'draft\n')
        self.app.send_message.assert_not_called()
        self.assertEqual(view.on_message_entry_key(SimpleNamespace(state=0)), 'break')
        self.app.send_message.assert_called_once()

    def test_primary_send_button_restores_contrast_after_state_changes(self):
        view = self.app.view
        self.assertEqual(view.send_button.cget('state'), 'disabled')
        self.assertEqual(view.send_button.cget('bg'), view.colors['selected'])
        key = ChatKey('private', 'bob')
        self.app.state.current_chat = key
        self.app.state.conversation(key).add(Message('bob', 'hello', encryption='legacy'))
        view.render_conversation(key)
        self.assertEqual(view.send_button.cget('state'), 'normal')
        self.assertEqual(view.send_button.cget('bg'), view.colors['accent'])
        self.app.state.pending_messages['pending'] = 'hello back'
        view.refresh_controls()
        self.assertEqual(view.send_button.cget('state'), 'disabled')
        self.assertEqual(view.send_button.cget('bg'), view.colors['selected'])

    def test_conversation_summaries_fit_pixel_width_and_preserve_unread_marker(self):
        view = self.app.view
        self.root.geometry('900x700')
        self.root.deiconify()
        name = '多语言会话测试名字较长的用户名称示例'
        self.app.state.friends.append(name)
        private = self.app.state.conversation(ChatKey('private', name))
        private.add(Message(name, 'Synthetic preview with 中文 and more words ' * 5, message_id=1))
        private.unread_ids.update(range(1, 124))
        self.app.state.groups['synthetic-group'] = {'group_name': '多语言群聊的完整名称用于测试省略效果'}
        group = self.app.state.conversation(ChatKey('group', 'synthetic-group'))
        group.add(Message(name, '这是完整的群聊消息摘要，仅在侧栏按可用像素省略显示。' * 3, message_id=2))
        group.unread_ids.update(range(1, 10))
        view.refresh_activity()
        self.root.update_idletasks()
        for widget, badge in ((view.friends_listbox, '[123]'), (view.group_listbox, '[9]')):
            row = widget.get(0)
            font = tkfont.Font(root=self.root, font=widget.cget('font'))
            self.assertIn(badge, row)
            self.assertIn('…', row)
            self.assertIn('·', row)
            self.assertLessEqual(font.measure(row), widget.winfo_width() - 12)
        self.assertEqual(self.app.state.friends, [name])
        self.assertEqual(private.messages[0].content, 'Synthetic preview with 中文 and more words ' * 5)

    def test_refitting_sidebar_rows_keeps_selection_and_scroll_position(self):
        view = self.app.view
        self.root.deiconify()
        self.app.state.friends[:] = [f'synthetic-peer-{number:02d}' for number in range(45)]
        for name in self.app.state.friends:
            self.app.state.conversation(ChatKey('private', name)).add(
                Message(name, 'Synthetic preview with enough text for deliberate pixel truncation', message_id=1))
        view.update_friends_listbox()
        self.root.update_idletasks()
        widget = view.friends_listbox
        old_rows = widget.get(0, client.tk.END)
        widget.configure(font=view.fonts['body'])
        widget.selection_set(20)
        widget.activate(20)
        widget.selection_anchor(20)
        widget.yview_moveto(.4)
        position = widget.yview()[0]
        view.resize_conversation_list('private', widget.winfo_width() + 1)
        self.assertEqual(widget.curselection(), (20,))
        self.assertEqual(widget.index(client.tk.ACTIVE), 20)
        self.assertEqual(widget.index(client.tk.ANCHOR), 20)
        self.assertAlmostEqual(widget.yview()[0], position, places=6)
        self.assertNotEqual(widget.get(0, client.tk.END), old_rows)
        self.assertEqual(len(self.app.state.friends), 45)

    def test_composer_focus_has_a_visible_border_in_both_themes(self):
        view = self.app.view
        shell = view.msg_entry.master
        self.root.deiconify()
        self.root.update()
        for mode in ('light', 'dark'):
            view.set_theme(mode)
            view.msg_entry.focus_force()
            self.root.update()
            self.assertIs(self.root.focus_get(), view.msg_entry)
            self.assertEqual(shell.cget('highlightbackground'), view.colors['accent'])
            view.theme_button.focus_force()
            self.root.update()
            self.assertEqual(shell.cget('highlightbackground'), view.colors['line'])

    def test_login_and_recovery_controls_fit_the_minimum_window(self):
        from chatroom_client.encryption import EncryptionController

        self.app.connection.running = False
        self.app.connection.sock = None
        self.app.encryption = EncryptionController(self.app)
        view = self.app.view
        view.build_login()
        self.root.geometry('900x700')
        self.root.deiconify()
        view.set_auth_busy(False, '暂时无法连接服务器，请检查地址和端口。\n原有输入与密钥保持完整，可以稍后重试。')
        self.root.update_idletasks()
        width, height = self.root.winfo_width(), self.root.winfo_height()
        for name in ('login_button', 'register_button', 'migrate_button', 'legacy_unlock_button',
                     'import_keys_button', 'theme_button', 'login_status'):
            widget = getattr(view, name)
            left = widget.winfo_rootx() - self.root.winfo_rootx()
            top = widget.winfo_rooty() - self.root.winfo_rooty()
            self.assertGreaterEqual(left, 0, name)
            self.assertGreaterEqual(top, 0, name)
            self.assertLessEqual(left + widget.winfo_width(), width, name)
            self.assertLessEqual(top + widget.winfo_height(), height, name)
            self.assertTrue(widget.winfo_ismapped(), name)

    def test_high_dpi_login_scrolls_to_final_actions_and_reveals_keyboard_focus(self):
        from chatroom_client.encryption import EncryptionController

        original_scaling = float(self.root.tk.call('tk', 'scaling'))
        view = self.app.view
        original_fonts = dict(view.fonts)
        try:
            self.root.tk.call('tk', 'scaling', 2.6667)
            self.app.connection.running = False
            self.app.connection.sock = None
            self.app.encryption = EncryptionController(self.app)

            def build_large_text_login():
                view.build_login()
                self.root.geometry('900x700')
                self.root.deiconify()
                view.username_entry.insert(0, 'synthetic-high-dpi-account')
                view.password_entry.insert(0, 'synthetic-high-dpi-input')
                view.set_auth_busy(False, '暂时无法连接服务器，请检查地址和端口。\n输入保持完整，可以稍后重试。')
                self.root.update()

            build_large_text_login()
            if view.login_card.winfo_reqheight() <= view.login_canvas.winfo_height():
                # Some Tk 9 X11 builds keep compact widget requests after a
                # runtime DPI change. Force equivalent large text only when
                # the rendered form does not actually overflow the viewport.
                for role, specification in original_fonts.items():
                    view.fonts[role] = (specification[0], round(specification[1] * 1.25), *specification[2:])
                view.theme.set_mode('dark')
                build_large_text_login()
            canvas = view.login_canvas
            self.assertGreater(view.login_card.winfo_reqheight(), canvas.winfo_height())
            self.assertTrue(view._login_overflow)
            canvas.yview_moveto(1)
            self.root.update()
            status_bottom = view.login_status.winfo_rooty() + view.login_status.winfo_height()
            self.assertLessEqual(status_bottom, canvas.winfo_rooty() + canvas.winfo_height())
            self.assertGreaterEqual(view.legacy_unlock_button.winfo_rooty(), canvas.winfo_rooty())
            before_wheel = canvas.yview()[0]
            view.legacy_unlock_button.event_generate('<MouseWheel>', delta=120)
            self.root.update()
            self.assertLess(canvas.yview()[0], before_wheel)
            # Follow the same focus chain used by Tab, starting after a scroll
            # to the bottom. Each newly focused input/action must be visible.
            view.username_entry.focus_force()
            self.root.update()
            current = view.username_entry
            reached_final_action = False
            for _ in range(24):
                top = current.winfo_rooty()
                bottom = top + current.winfo_height()
                self.assertGreaterEqual(top, canvas.winfo_rooty())
                self.assertLessEqual(bottom, canvas.winfo_rooty() + canvas.winfo_height())
                if current is view.legacy_unlock_button:
                    reached_final_action = True
                    break
                next_path = str(self.root.tk.call('tk_focusNext', current))
                current = self.root.nametowidget(next_path)
                current.focus_force()
                self.root.update()
            self.assertTrue(reached_final_action)
            self.assertEqual(view.username_entry.get(), 'synthetic-high-dpi-account')
            self.assertEqual(view.password_entry.get(), 'synthetic-high-dpi-input')
            view.set_theme('light' if view.theme.mode == 'dark' else 'dark')
            self.root.update()
            self.assertEqual(view.username_entry.get(), 'synthetic-high-dpi-account')
            self.assertEqual(view.password_entry.get(), 'synthetic-high-dpi-input')
        finally:
            view.fonts.clear()
            view.fonts.update(original_fonts)
            self.root.tk.call('tk', 'scaling', original_scaling)


if __name__ == '__main__':
    unittest.main()
