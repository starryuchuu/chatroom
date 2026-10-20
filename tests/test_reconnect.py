"""Authentication recovery keeps the original identity and never replays sends."""
from contextlib import ExitStack
import socket
import threading
import unittest
from unittest.mock import Mock, patch

from chatroom_client.connection import AuthResult, ClientSettings, ConnectionManager, ServerEvent
from chatroom_client.reconnect import ReconnectPolicy


class ReconnectPolicyTests(unittest.TestCase):
    def test_backoff_is_capped_and_cancellation_invalidates_old_callbacks(self):
        policy = ReconnectPolicy()
        self.assertEqual(policy.start(), 1)
        token = policy.token
        self.assertEqual([policy.retry() for _ in range(8)], [2, 4, 8, 15, 30, 30, 30, 30])
        self.assertTrue(policy.is_current(token))
        policy.stop()
        self.assertFalse(policy.is_current(token))
        self.assertIsNone(policy.retry())
        self.assertEqual(policy.start(), 1)
        self.assertFalse(policy.is_current(token))

    def test_optional_finite_attempt_limit_stops_retries(self):
        policy = ReconnectPolicy(max_attempts=2)
        self.assertEqual(policy.start(), 1)
        token = policy.token
        self.assertEqual(policy.retry(), 2)
        self.assertIsNone(policy.retry())
        self.assertFalse(policy.active)
        self.assertFalse(policy.is_current(token))


class ReauthenticationTests(unittest.TestCase):
    def setUp(self):
        self.connection = ConnectionManager(ClientSettings())
        self.addCleanup(self.connection.close)

    def handshake(self, start, *, reply=None, public=None, key_error=None, network_error=None):
        """Drive the real worker/completion protocol using an isolated fake peer."""
        sock = Mock()
        public = public or {'type': 'public_key', 'capabilities': ['message_sync', 'unknown']}
        reply = reply if reply is not None else {'type': 'login_result', 'success': True}
        with ExitStack() as stack:
            stack.enter_context(patch('chatroom_client.connection.socket.socket', return_value=sock))
            stack.enter_context(patch('chatroom_client.connection.protocol.send_msg'))
            check = stack.enter_context(patch('chatroom_client.connection.protocol.check_server_public_key',
                                             return_value=(Mock(), key_error)))
            stack.enter_context(patch('chatroom_client.connection.PKCS1_OAEP.new',
                                     return_value=Mock(encrypt=Mock(return_value=b'encrypted-session'))))
            stack.enter_context(patch('chatroom_client.connection.protocol.recv_msg',
                                     side_effect=[public, reply] if network_error is None else network_error))
            stack.enter_context(patch.object(self.connection, 'start_worker',
                                            side_effect=lambda target, *args: target(*args)))
            self.assertTrue(start())
        result = self.connection.events.get_nowait()
        self.assertIsInstance(result, AuthResult)
        self.assertTrue(self.connection.accept_auth(result))
        return sock, result, check

    def login(self):
        return self.handshake(lambda: self.connection.authenticate('alice', 'secret-password'))

    def test_success_retains_memory_credentials_and_logout_forgets_them(self):
        sock, result, _ = self.login()
        self.assertIsNone(result.error)
        self.assertTrue(self.connection.can_reconnect)
        self.assertEqual(self.connection.capabilities, ('message_sync',))
        self.assertNotIn('secret-password', repr(result))
        self.connection.disconnect()
        self.assertFalse(self.connection.can_reconnect)
        self.assertFalse(self.connection.authenticate_saved())
        sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)

    def test_reconnect_reuses_original_target_and_fingerprint_after_settings_change(self):
        self.connection.settings.host = 'trusted.example'
        self.connection.settings.port = 23456
        self.connection.settings.expected_fingerprint = 'a' * 64
        self.login()
        self.connection.disconnect(preserve_credentials=True)
        self.connection.settings.host = 'different.example'
        self.connection.settings.port = 34567
        self.connection.settings.expected_fingerprint = 'b' * 64
        sock, result, check = self.handshake(self.connection.authenticate_saved)
        self.assertEqual(result.endpoint, ('trusted.example', 23456))
        sock.connect.assert_called_once_with(('trusted.example', 23456))
        self.assertEqual(check.call_args.kwargs['expected_fingerprint'], 'a' * 64)

    def test_target_snapshot_is_captured_before_the_worker_starts(self):
        self.connection.settings.expected_fingerprint = 'a' * 64
        with patch.object(self.connection, 'start_worker') as start:
            self.assertTrue(self.connection.authenticate('alice', 'secret-password'))
        target, *args = start.call_args.args
        self.connection.settings.host = 'other.example'
        self.connection.settings.expected_fingerprint = 'b' * 64
        with patch('chatroom_client.connection.socket.socket', return_value=Mock()), \
                patch('chatroom_client.connection.protocol.recv_msg', return_value={'type': 'public_key'}), \
                patch('chatroom_client.connection.protocol.check_server_public_key',
                      return_value=(None, 'untrusted key')) as check:
            target(*args)
        result = self.connection.events.get_nowait()
        self.connection.accept_auth(result)
        self.assertEqual(check.call_args.kwargs['host'], '127.0.0.1')
        self.assertEqual(check.call_args.kwargs['expected_fingerprint'], 'a' * 64)
        self.assertFalse(result.retryable)

    def test_transient_error_retains_credentials_but_identity_failure_stops_retry(self):
        self.login()
        self.connection.disconnect(preserve_credentials=True)
        _, failed, _ = self.handshake(self.connection.authenticate_saved,
                                      network_error=ConnectionResetError('network dropped'))
        self.assertTrue(failed.retryable)
        self.assertFalse(self.connection.running)
        self.assertTrue(self.connection.can_reconnect)
        _, refused, _ = self.handshake(self.connection.authenticate_saved, key_error='fingerprint mismatch')
        self.assertFalse(refused.retryable)
        self.assertFalse(self.connection.can_reconnect)
        self.assertFalse(self.connection.authenticate_saved())

    def test_bad_password_is_fatal_and_registration_does_not_enable_reconnect(self):
        _, refused, _ = self.handshake(lambda: self.connection.authenticate('alice', 'wrong'),
                                       reply={'type': 'login_result', 'success': False, 'error': 'wrong password'})
        self.assertFalse(refused.retryable)
        self.assertFalse(self.connection.can_reconnect)
        _, registered, _ = self.handshake(lambda: self.connection.authenticate('alice', 'secret', register=True),
                                          reply={'type': 'register_result', 'success': True})
        self.assertIsNone(registered.error)
        self.assertFalse(self.connection.running)
        self.assertFalse(self.connection.can_reconnect)

    def test_cancelling_saved_auth_rejects_stale_success_and_erases_credentials(self):
        self.login()
        self.connection.disconnect(preserve_credentials=True)
        with patch.object(self.connection, 'start_worker') as start:
            self.assertTrue(self.connection.authenticate_saved())
        generation = self.connection.generation
        self.connection.cancel_auth()
        stale = Mock()
        result = AuthResult(generation, 'alice', False, ('127.0.0.1', 12345), stale, b'x' * 16, None)
        self.assertFalse(self.connection.accept_auth(result))
        self.assertFalse(self.connection.can_reconnect)
        self.assertFalse(self.connection.running)
        stale.close.assert_called_once()

    def test_worker_creation_failure_completes_authentication_without_busy_lock(self):
        with patch.object(self.connection, 'start_worker', side_effect=RuntimeError('thread limit')):
            self.assertTrue(self.connection.authenticate('alice', 'secret'))
        result = self.connection.events.get_nowait()
        self.assertEqual(result.error, 'thread limit')
        self.assertTrue(result.retryable)
        self.assertTrue(self.connection.accept_auth(result))
        self.assertFalse(self.connection.auth_busy)

    def test_receive_worker_creation_failure_signals_loss_to_the_owner(self):
        self.login()
        with patch.object(self.connection, 'start_worker', side_effect=RuntimeError('thread limit')):
            self.assertFalse(self.connection.receive())
        self.assertEqual(self.connection.events.get_nowait(), ServerEvent(self.connection.sock, None))

    def test_disconnect_discards_a_congested_old_queue_before_catchup(self):
        self.login()
        entered, release, synced = threading.Event(), threading.Event(), threading.Event()
        calls = []

        def send(sock, message):
            calls.append(message['type'])
            if message['type'] == 'blocked-old-send':
                entered.set()
                release.wait(3)
            elif message['type'] == 'sync_request':
                synced.set()

        with patch('chatroom_client.connection.protocol.send_msg', side_effect=send):
            try:
                self.connection.send({'type': 'blocked-old-send'})
                self.assertTrue(entered.wait(1))
                for _ in range(100):
                    self.connection.send({'type': 'queued-old-send'})
                self.connection.disconnect(preserve_credentials=True)
                self.handshake(self.connection.authenticate_saved)
                self.connection.send({'type': 'sync_request', 'after_id': 10})
            finally:
                release.set()
            self.assertTrue(synced.wait(1))
        self.assertEqual(calls, ['blocked-old-send', 'sync_request'])

    def test_ipv6_loopback_uses_an_ipv6_socket(self):
        self.connection.settings.host = '::1'
        with (
            patch('chatroom_client.connection.socket.socket', return_value=Mock()) as create,
            patch('chatroom_client.connection.protocol.recv_msg', side_effect=ConnectionError('end')),
            patch.object(self.connection, 'start_worker', side_effect=lambda target, *args: target(*args)),
        ):
            self.assertTrue(self.connection.authenticate('alice', 'secret'))
        result = self.connection.events.get_nowait()
        self.connection.accept_auth(result)
        create.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
        self.assertTrue(result.retryable)


if __name__ == '__main__':
    unittest.main()
