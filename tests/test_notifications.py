"""Native notifications carry literal data and never call the UI from workers."""
import base64
import json
import subprocess
import threading
import unittest
from unittest.mock import Mock, patch

from chatroom_client.notifications import DesktopNotifier, native_notify


class NativeNotificationTests(unittest.TestCase):
    def test_linux_arguments_are_literal_and_have_a_timeout(self):
        title = '$(touch unsafe); --flag'
        body = 'private text " with\nnewlines'
        with patch('chatroom_client.notifications.sys.platform', 'linux'), \
                patch('chatroom_client.notifications.shutil.which', return_value='/usr/bin/notify-send'), \
                patch('chatroom_client.notifications.subprocess.run') as run:
            self.assertTrue(native_notify(title, body))
        self.assertEqual(run.call_args.args[0][-3:], ['--', title, body])
        self.assertFalse(run.call_args.kwargs.get('shell', False))
        self.assertEqual(run.call_args.kwargs['timeout'], 3)

    def test_windows_script_is_constant_and_payload_uses_json_stdin(self):
        title, body = 'literal "$env:PATH"', '你好; Remove-Item anything'
        with patch('chatroom_client.notifications.sys.platform', 'win32'), \
                patch('chatroom_client.notifications.shutil.which', return_value='powershell.exe'), \
                patch('chatroom_client.notifications.subprocess.run') as run:
            self.assertTrue(native_notify(title, body))
        arguments = run.call_args.args[0]
        script = base64.b64decode(arguments[-1]).decode('utf-16le')
        self.assertNotIn(body, script)
        self.assertNotIn(title, script)
        self.assertEqual(json.loads(run.call_args.kwargs['input']), {'title': title, 'body': body})
        self.assertFalse(run.call_args.kwargs.get('shell', False))

    def test_macos_passes_notification_content_as_arguments(self):
        with patch('chatroom_client.notifications.sys.platform', 'darwin'), \
                patch('chatroom_client.notifications.subprocess.run') as run:
            self.assertTrue(native_notify('title', 'body'))
        self.assertEqual(run.call_args.args[0][-2:], ['title', 'body'])
        self.assertEqual(run.call_args.kwargs['timeout'], 3)

    def test_missing_utility_or_timeout_requests_ui_fallback(self):
        with patch('chatroom_client.notifications.sys.platform', 'linux'), \
                patch('chatroom_client.notifications.shutil.which', return_value=None):
            self.assertFalse(native_notify('title', 'body'))
        with patch('chatroom_client.notifications.sys.platform', 'linux'), \
                patch('chatroom_client.notifications.shutil.which', return_value='notify-send'), \
                patch('chatroom_client.notifications.subprocess.run',
                      side_effect=subprocess.TimeoutExpired('notify-send', 3)):
            self.assertFalse(native_notify('title', 'body'))


class NotificationWorkerTests(unittest.TestCase):
    def test_mute_or_logout_discards_queued_notices_and_late_fallback(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        calls = []

        def deliver(title, body):
            calls.append(title)
            entered.set()
            release.wait(2)
            finished.set()
            return False

        notifier = DesktopNotifier(deliver, minimum_interval=0)
        self.addCleanup(notifier.close)
        try:
            notifier.notify('already delivering', 'body')
            self.assertTrue(entered.wait(2))
            notifier.notify('queued account notice', 'body')
            notifier.results.put(True)
            notifier.discard_pending()
            release.set()
            self.assertTrue(finished.wait(2))
            notifier.close()
            self.assertEqual(calls, ['already delivering'])
            self.assertEqual(notifier.poll(), 0)
        finally:
            release.set()

    def test_worker_delivers_off_owner_thread_and_reports_fallback_as_data(self):
        called = threading.Event()
        owner = threading.get_ident()
        threads = []

        def deliver(title, body):
            threads.append(threading.get_ident())
            called.set()
            return False

        notifier = DesktopNotifier(deliver)
        self.addCleanup(notifier.close)
        notifier.notify('title', 'body')
        self.assertTrue(called.wait(2))
        self.assertTrue(notifier.results.get(timeout=2))
        self.assertNotEqual(threads, [owner])
        notifier.results.put(True)
        notifier.results.put(True)
        self.assertEqual(notifier.poll(), 2)
        self.assertEqual(notifier.poll(), 0)

    def test_closed_notifier_discards_new_notifications(self):
        deliver = Mock(return_value=True)
        notifier = DesktopNotifier(deliver)
        notifier.close()
        notifier.notify('title', 'body')
        deliver.assert_not_called()


if __name__ == '__main__':
    unittest.main()
