"""User-facing server profiles and isolated persistent read metadata."""
import json
import multiprocessing
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from chatroom_client.preferences import PreferencesError, PreferencesStore, ServerProfile, default_config_path


def _update_preferences_worker(path, username, ready, start):
    store = PreferencesStore(path)
    ready.send(True)
    ready.close()
    if not start.wait(10):
        raise RuntimeError('preferences worker did not receive start signal')
    for cursor in range(1, 11):
        store.update_account(('localhost', 12345), username, {'sync_cursor': cursor})


def _hold_preferences_lock(path, ready, release):
    from chatroom_client.preferences import _preferences_lock

    with _preferences_lock(Path(path)):
        ready.send(True)
        ready.close()
        if not release.wait(10):
            raise RuntimeError('preferences lock was not released')


def _stop_process(process):
    if process.is_alive():
        process.terminate()
    process.join(5)


class ServerProfileTests(unittest.TestCase):
    def test_remote_identity_is_required_and_normalized(self):
        with self.assertRaises(PreferencesError):
            ServerProfile('Remote', 'chat.example', 443)
        fingerprint = ':'.join(['AB'] * 32)
        profile = ServerProfile(' Remote ', 'CHAT.EXAMPLE', 443, fingerprint)
        self.assertEqual((profile.name, profile.host, profile.fingerprint), ('Remote', 'chat.example', 'ab' * 32))
        self.assertEqual(ServerProfile('IPv6', '[::1]', 12345).host, '::1')

    def test_invalid_addresses_ports_and_fingerprints_do_not_save(self):
        for host in ('https://chat.example', 'chat.example/path', 'chat.example:12345', '', 'local host', '-host'):
            with self.subTest(host=host), self.assertRaises(PreferencesError):
                ServerProfile('Invalid', host, 12345, 'ab' * 32)
        for port in (0, 65536, True, '12345'):
            with self.subTest(port=port), self.assertRaises(PreferencesError):
                ServerProfile('Invalid', '127.0.0.1', port)
        for fingerprint in ('a' * 63, 'g' * 64):
            with self.subTest(fingerprint=fingerprint), self.assertRaises(PreferencesError):
                ServerProfile('Invalid', 'localhost', 12345, fingerprint)


class PreferencesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'nested' / 'client.json'
        self.store = PreferencesStore(self.path)

    def test_multiple_profiles_selected_server_and_private_mode_survive_restart(self):
        self.assertEqual([profile.port for profile in self.store.profiles], [12345, 12346])
        remote = ServerProfile('远程', 'chat.example', 443, 'ab' * 32)
        self.store.save_profile(remote)
        reopened = PreferencesStore(self.path)
        self.assertEqual(reopened.selected_profile, remote)
        self.assertEqual(len(reopened.profiles), 3)
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)
        reopened.select_profile('Go 本机')
        self.assertEqual(PreferencesStore(self.path).selected_profile.port, 12346)

    def test_profile_edit_rename_delete_and_duplicate_name(self):
        changed = ServerProfile('Python 开发', 'localhost', 23456)
        self.store.save_profile(changed, replace_name='Python 本机')
        self.assertEqual(self.store.selected_profile, changed)
        with self.assertRaises(PreferencesError):
            self.store.save_profile(ServerProfile('Go 本机', 'localhost', 9999))
        self.store.delete_profile('Python 开发')
        self.assertEqual(self.store.selected_profile.port, 12346)
        with self.assertRaises(PreferencesError):
            self.store.delete_profile('Go 本机')

    def test_failed_atomic_write_preserves_disk_and_selected_state(self):
        self.store.select_profile('Python 本机')
        original = self.path.read_bytes()
        with patch('chatroom_client.preferences.os.replace', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(PreferencesError, 'disk full'):
                self.store.select_profile('Go 本机')
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(self.store.selected_profile.port, 12345)
        self.assertEqual(list(self.path.parent.glob('.client-*.tmp')), [])

    def test_malformed_file_is_visible_and_preserved_until_explicit_save(self):
        self.path.parent.mkdir()
        original = b'{broken json'
        self.path.write_bytes(original)
        store = PreferencesStore(self.path)
        self.assertIsNotNone(store.warning)
        with self.assertRaises(PreferencesError):
            store.update_account(('127.0.0.1', 12345), 'alice', {'sync_cursor': 12})
        self.assertEqual(self.path.read_bytes(), original)
        store.select_profile('Go 本机')
        self.assertIsNone(store.warning)
        self.assertEqual(PreferencesStore(self.path).selected_profile.port, 12346)

    def test_invalid_schema_or_unknown_content_is_not_loaded(self):
        self.store.select_profile('Python 本机')
        valid = json.loads(self.path.read_text())
        for key, value in [('password', 'not allowed'), ('version', 50), ('version', True), ('profiles', None)]:
            invalid = dict(valid)
            invalid[key] = value
            raw = json.dumps(invalid).encode()
            self.path.write_bytes(raw)
            store = PreferencesStore(self.path)
            self.assertIsNotNone(store.warning)
            self.assertEqual(self.path.read_bytes(), raw)

    def test_account_activity_and_sync_merges_are_scoped_and_do_not_store_text(self):
        endpoint = ('chat.example', 443)
        activity = {'initialized': True, 'conversations': [
            {'kind': 'private', 'target': 'bob', 'read_id': 8, 'unread_ids': [9, 10]}]}
        self.store.update_account(endpoint, 'alice', {'activity': activity})
        self.store.update_account(endpoint, 'alice', {'sync_cursor': 10})
        self.store.update_account(('chat.example', 444), 'alice', {'sync_cursor': 20})
        self.store.update_account(endpoint, 'carol', {'sync_cursor': 30})
        reopened = PreferencesStore(self.path)
        result = reopened.account(endpoint, 'alice')
        self.assertEqual(result, {'activity': activity, 'sync_cursor': 10})
        result['activity']['conversations'].clear()
        self.assertEqual(reopened.account(endpoint, 'alice')['activity'], activity)
        self.assertEqual(reopened.account(('other.example', 443), 'alice'), {})
        self.assertEqual(reopened.account(('chat.example', 444), 'alice'), {'sync_cursor': 20})
        self.assertEqual(reopened.account(endpoint, 'carol'), {'sync_cursor': 30})
        for forbidden in ({'password': 'secret'}, {'messages': ['body']}, {'activity': {'content': 'body'}}):
            with self.assertRaises(PreferencesError):
                reopened.update_account(endpoint, 'alice', forbidden)
        self.assertNotIn('secret', self.path.read_text())

    def test_notification_preferences_persist(self):
        self.assertEqual(self.store.set_notifications(enabled=False, do_not_disturb=True),
                         {'enabled': False, 'do_not_disturb': True})
        reopened = PreferencesStore(self.path)
        self.assertFalse(reopened.notifications_enabled)
        self.assertTrue(reopened.do_not_disturb)

    def test_stale_instances_preserve_profiles_settings_and_account_fields(self):
        second = PreferencesStore(self.path)
        remote = ServerProfile('远程', 'chat.example', 443, 'ab' * 32)
        activity = {'initialized': True, 'conversations': []}
        self.store.save_profile(remote)
        self.store.set_notifications(enabled=False)
        second.set_notifications(do_not_disturb=True)
        second.update_account(('localhost', 12345), 'alice', {'sync_cursor': 42})
        self.store.update_account(('localhost', 12345), 'alice', {'activity': activity})
        second.update_account(('localhost', 12345), 'bob', {'sync_cursor': 99})
        self.store.set_notifications(do_not_disturb=True)
        reopened = PreferencesStore(self.path)
        self.assertEqual(reopened.selected_profile, remote)
        self.assertEqual(reopened.notifications, {'enabled': False, 'do_not_disturb': True})
        self.assertEqual(reopened.account(('localhost', 12345), 'alice'),
                         {'sync_cursor': 42, 'activity': activity})
        self.assertEqual(reopened.account(('localhost', 12345), 'bob'), {'sync_cursor': 99})

    def test_stale_profile_operations_use_current_names_and_selection(self):
        second = PreferencesStore(self.path)
        added = ServerProfile('开发', 'localhost', 23456)
        self.store.save_profile(added)
        with self.assertRaises(PreferencesError):
            second.save_profile(added)
        self.assertEqual(second.select_profile(added.name), added)
        renamed = ServerProfile('开发新版', 'localhost', 23457)
        self.store.save_profile(renamed, replace_name=added.name)
        with self.assertRaises(PreferencesError):
            second.delete_profile(added.name)
        self.assertEqual(second.delete_profile(renamed.name).name, 'Python 本机')
        with self.assertRaises(PreferencesError):
            self.store.save_profile(renamed, replace_name=renamed.name)
        with self.assertRaises(PreferencesError):
            self.store.save_profile(ServerProfile('Go 本机', 'localhost', 9999))
        self.assertEqual([profile.name for profile in PreferencesStore(self.path).profiles],
                         ['Python 本机', 'Go 本机'])

    def test_external_corruption_is_preserved_and_external_repair_is_recognized(self):
        self.store.select_profile('Python 本机')
        self.path.write_bytes(b'{broken json')
        original = self.path.read_bytes()
        with self.assertRaises(PreferencesError):
            self.store.update_account(('localhost', 12345), 'alice', {'sync_cursor': 1})
        self.assertEqual(self.path.read_bytes(), original)
        blocked = PreferencesStore(self.path)
        self.assertIsNotNone(blocked.warning)
        self.store.select_profile('Go 本机')
        blocked.update_account(('localhost', 12345), 'alice', {'sync_cursor': 2})
        self.assertIsNone(blocked.warning)
        self.assertEqual(blocked.selected_profile.name, 'Go 本机')

    def test_spawned_processes_preserve_each_others_account_updates(self):
        self.store.select_profile('Go 本机')
        context = multiprocessing.get_context('spawn')
        start = context.Event()
        processes = []
        receivers = []
        for username in ('alice', 'bob'):
            receiver, sender = context.Pipe(duplex=False)
            process = context.Process(target=_update_preferences_worker,
                                      args=(str(self.path), username, sender, start))
            process.start()
            sender.close()
            self.addCleanup(receiver.close)
            self.addCleanup(_stop_process, process)
            receivers.append(receiver)
            processes.append(process)
        # Both snapshots are loaded before either process is permitted to save.
        for receiver in receivers:
            self.assertTrue(receiver.poll(10), 'preferences worker did not start')
            self.assertTrue(receiver.recv())
        start.set()
        for process in processes:
            process.join(10)
            self.assertEqual(process.exitcode, 0)
        reopened = PreferencesStore(self.path)
        self.assertEqual(reopened.selected_profile.name, 'Go 本机')
        for username in ('alice', 'bob'):
            self.assertEqual(reopened.account(('localhost', 12345), username), {'sync_cursor': 10})

    def test_other_process_lock_timeout_preserves_disk_and_live_state(self):
        self.store.select_profile('Python 本机')
        original = self.path.read_bytes()
        context = multiprocessing.get_context('spawn')
        release = context.Event()
        receiver, sender = context.Pipe(duplex=False)
        process = context.Process(target=_hold_preferences_lock, args=(str(self.path), sender, release))
        process.start()
        sender.close()
        self.addCleanup(receiver.close)
        self.addCleanup(_stop_process, process)
        self.addCleanup(release.set)
        self.assertTrue(receiver.poll(10), 'preferences lock holder did not start')
        self.assertTrue(receiver.recv())
        with patch('chatroom_client.preferences._LOCK_TIMEOUT', 0.05):
            with self.assertRaisesRegex(PreferencesError, '其他进程'):
                self.store.select_profile('Go 本机')
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(self.store.selected_profile.name, 'Python 本机')
        release.set()
        process.join(10)
        self.assertEqual(process.exitcode, 0)
        self.store.select_profile('Go 本机')
        self.assertEqual(PreferencesStore(self.path).selected_profile.name, 'Go 本机')

    def test_memory_store_never_resolves_or_reads_user_config(self):
        with patch('chatroom_client.preferences.default_config_path', side_effect=AssertionError('home lookup')):
            store = PreferencesStore(persistent=False)
            store.select_profile('Go 本机')
            store.update_account(('localhost', 12346), 'alice', {'sync_cursor': 1})
        self.assertIsNone(store.path)
        self.assertEqual(store.selected_profile.port, 12346)

    def test_config_override_is_used_for_packaged_and_source_clients(self):
        with patch.dict(os.environ, {'CHATROOM_CONFIG_DIR': self.tmp.name}):
            self.assertEqual(default_config_path(), Path(self.tmp.name) / 'client.json')


if __name__ == '__main__':
    unittest.main()
