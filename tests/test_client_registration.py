"""Signup shares the login card and preserves asynchronous auth ownership."""
import gc
import unittest
from unittest.mock import Mock, patch

import client
from chatroom_client.connection import AuthResult
from chatroom_client.preferences import PreferencesStore


class ClientRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.root = client.tk.Tk()
        self.root.withdraw()
        self.app = client.ChatClient(self.root, preferences=PreferencesStore(persistent=False))
        self.view = self.app.view
        self.app.connection.start_worker = Mock()

    def tearDown(self):
        self.app.close()
        self.app = self.view = self.root = None
        gc.collect()

    def fill(self):
        self.view.username_entry.insert(0, '  signup-test-user  ')
        self.view.password_entry.insert(0, 'synthetic-signup-password')
        self.view.port_entry.delete(0, client.tk.END)
        self.view.port_entry.insert(0, '23456')

    def result(self, error=None):
        return AuthResult(self.app.connection.generation, 'signup-test-user', True,
                          ('127.0.0.1', 23456), None, None, error)

    def test_signup_and_back_reuse_the_form_without_opening_a_window(self):
        self.fill()
        widgets = self.view.username_entry, self.view.password_entry, self.view.port_entry
        card, selector = self.view.login_card, self.view.profile_selector
        children = self.root.winfo_children()
        with patch.object(client.tk, 'Toplevel', side_effect=AssertionError('signup opened a window')):
            self.view.register_button.invoke()
            self.assertEqual(self.view.auth_title.cget('text'), '创建账号')
            self.assertEqual(self.view.login_button.cget('text'), '创建账号')
            self.assertTrue(all(not section.winfo_manager() for section in self.view._login_only_sections))
            self.view.set_theme('dark')
            self.view.register_button.invoke()
        self.assertEqual(self.root.winfo_children(), children)
        self.assertEqual(self.view.login_button.cget('text'), '登录')
        self.assertTrue(all(section.winfo_manager() == 'grid' for section in self.view._login_only_sections))
        self.assertEqual((self.view.username_entry, self.view.password_entry, self.view.port_entry), widgets)
        self.assertIs(self.view.login_card, card)
        self.assertIs(self.view.profile_selector, selector)
        self.assertEqual([widget.get() for widget in widgets],
                         ['  signup-test-user  ', 'synthetic-signup-password', '23456'])
        self.app.connection.start_worker.assert_not_called()

    def test_signup_submission_blocks_duplicates_and_success_returns_to_login(self):
        self.fill()
        self.view.register_button.invoke()
        card = self.view.login_card
        self.view.login_button.invoke()
        self.assertTrue(self.app.connection.auth_busy)
        self.assertEqual(str(self.view.register_button.cget('state')), 'disabled')
        self.assertEqual(str(self.view.username_entry.cget('state')), 'disabled')
        args = self.app.connection.start_worker.call_args.args
        self.assertEqual(args[2:6], (('127.0.0.1', 23456), 'signup-test-user',
                                    'synthetic-signup-password', True))
        self.view.submit_auth()
        self.view.register()
        self.app.connection.start_worker.assert_called_once()
        self.assertEqual(self.view.login_button.cget('text'), '创建账号')

        self.app.finish_auth(self.result())
        self.assertIs(self.view.login_card, card)
        self.assertEqual(self.view.login_button.cget('text'), '登录')
        self.assertEqual(self.view.username_entry.get(), 'signup-test-user')
        self.assertEqual(self.view.password_entry.get(), '')
        self.assertIn('账号已创建', self.view.login_status.cget('text'))
        self.assertFalse(self.app.connection.running or self.app.connection.auth_busy)

    def test_failed_signup_preserves_inputs_and_can_retry_in_place(self):
        self.fill()
        self.view.register_button.invoke()
        self.view.submit_auth()
        self.app.finish_auth(self.result('该用户名已存在'))
        self.assertEqual(self.view.login_button.cget('text'), '创建账号')
        self.assertEqual(self.view.password_entry.get(), 'synthetic-signup-password')
        self.assertIn('该用户名已存在', self.view.login_status.cget('text'))
        self.assertEqual(str(self.view.login_button.cget('state')), 'normal')
        self.view.submit_auth()
        self.assertEqual(self.app.connection.start_worker.call_count, 2)

    def test_cancel_ignores_late_success_and_allows_return_to_login(self):
        self.fill()
        self.view.register_button.invoke()
        self.view.submit_auth()
        stale = self.result()
        self.app.cancel_auth()
        self.app.finish_auth(stale)
        self.assertEqual(self.view.login_button.cget('text'), '创建账号')
        self.assertIn('连接已取消', self.view.login_status.cget('text'))
        self.assertEqual(self.view.password_entry.get(), 'synthetic-signup-password')
        self.view.register_button.invoke()
        self.assertEqual(self.view.login_button.cget('text'), '登录')

    def test_empty_credentials_and_invalid_port_show_inline_feedback(self):
        self.view.register_button.invoke()
        with patch.object(client.messagebox, 'showerror', side_effect=AssertionError('modal validation')):
            self.view.login_button.invoke()
            self.assertIn('不能为空', self.view.login_status.cget('text'))
            self.fill()
            self.view.port_entry.delete(0, client.tk.END)
            self.view.port_entry.insert(0, 'invalid')
            self.view.submit_auth()
            self.assertIn('端口必须', self.view.login_status.cget('text'))
        self.app.connection.start_worker.assert_not_called()

    def test_enter_activates_focused_action_instead_of_submitting_the_form(self):
        self.fill()
        self.root.deiconify()
        self.root.update()

        def enter(widget):
            widget.focus_force()
            self.root.update()
            widget.event_generate('<Return>')
            self.root.update()

        enter(self.view.register_button)
        self.assertEqual(self.view.login_button.cget('text'), '创建账号')
        self.app.connection.start_worker.assert_not_called()
        original_theme = self.view.theme.mode
        enter(self.view.theme_button)
        self.assertNotEqual(self.view.theme.mode, original_theme)
        self.app.connection.start_worker.assert_not_called()

        enter(self.view.login_button)
        self.assertTrue(self.app.connection.auth_busy)
        self.app.connection.start_worker.assert_called_once()
        # The cancel action is a visible button beside the mode switch.
        cancel = next(widget for widget in self.view.register_button.master.winfo_children()
                      if widget.cget('text') == '取消连接')
        enter(cancel)
        self.assertFalse(self.app.connection.auth_busy)
        self.assertIn('连接已取消', self.view.login_status.cget('text'))
        self.app.connection.start_worker.assert_called_once()

        enter(self.view.register_button)
        self.assertEqual(self.view.login_button.cget('text'), '登录')
        self.app.connection.start_worker.assert_called_once()


if __name__ == '__main__':
    unittest.main()
