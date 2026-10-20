"""Real Tk server settings selection, validation, and busy-session protection."""
import gc
from pathlib import Path
import tempfile
from types import SimpleNamespace
import tkinter as tk
import unittest
from unittest.mock import Mock

from chatroom_client.preferences import PreferencesStore
from chatroom_client.settings_view import ServerProfileSelector, SettingsWindow


class SettingsWindowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = tk.Tk()
        self.root.withdraw()
        self.controller = SimpleNamespace(
            preferences=PreferencesStore(Path(self.tmp.name) / 'client.json'),
            connection=SimpleNamespace(running=False, auth_busy=False), reconnecting=False,
            apply_profile=Mock())
        self.selector = ServerProfileSelector(self.root, self.controller)
        self.selector.pack()

    def tearDown(self):
        self.root.destroy()
        self.controller = self.root = self.selector = None
        gc.collect()
        self.tmp.cleanup()

    def test_profile_selection_persists_and_applies_actual_endpoint(self):
        self.selector.name.set('Go 本机')
        self.selector.select()
        profile = self.controller.apply_profile.call_args.args[0]
        self.assertEqual((profile.host, profile.port), ('127.0.0.1', 12346))
        self.assertEqual(PreferencesStore(self.controller.preferences.path).selected_profile, profile)
        self.assertIn('12346', self.selector.summary.cget('text'))

    def test_add_remote_profile_validates_pin_before_saving(self):
        window = SettingsWindow(self.root, self.controller, on_change=self.selector.refresh)
        window.new()
        window.name.set('远程工作服务器')
        window.host.set('chat.example')
        window.port.set('443')
        window.save()
        self.assertIn('指纹', window.status.cget('text'))
        self.controller.apply_profile.assert_not_called()
        self.assertEqual(len(self.controller.preferences.profiles), 2)
        window.fingerprint.set('AB' * 32)
        window.save()
        self.assertEqual(self.controller.preferences.selected_profile.fingerprint, 'ab' * 32)
        self.assertEqual(self.selector.name.get(), '远程工作服务器')
        self.controller.apply_profile.assert_called_once()

    def test_open_settings_guard_rejects_active_auth_and_reconnect_mutations(self):
        window = SettingsWindow(self.root, self.controller)
        window.port.set('34567')
        for kind in ('running', 'auth_busy', 'reconnecting'):
            with self.subTest(kind=kind):
                owner = self.controller if kind == 'reconnecting' else self.controller.connection
                setattr(owner, kind, True)
                window.save()
                self.selector.name.set('Go 本机')
                self.selector.select()
                self.assertEqual(self.controller.preferences.selected_profile.port, 12345)
                self.assertIn('断开', window.status.cget('text'))
                setattr(owner, kind, False)
        self.controller.apply_profile.assert_not_called()
        self.assertFalse(self.controller.preferences.path.exists())

    def test_delete_selected_profile_refreshes_effective_server(self):
        window = SettingsWindow(self.root, self.controller, on_change=self.selector.refresh)
        window.delete()
        self.assertEqual(self.controller.preferences.selected_profile.port, 12346)
        self.assertEqual(self.selector.name.get(), 'Go 本机')
        self.controller.apply_profile.assert_called_once_with(self.controller.preferences.selected_profile)

    def test_notification_settings_save_without_server_changes(self):
        window = SettingsWindow(self.root, self.controller)
        window.enabled.set(False)
        window.dnd.set(True)
        window.save_notifications()
        reopened = PreferencesStore(self.controller.preferences.path)
        self.assertFalse(reopened.notifications_enabled)
        self.assertTrue(reopened.do_not_disturb)
        self.controller.apply_profile.assert_not_called()


if __name__ == '__main__':
    unittest.main()
