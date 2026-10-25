"""Extracted handlers retain failure atomicity and shared lock ownership."""
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from server_handlers.friends import handle_friend_response
from server_handlers.groups import handle_group_join


class HandlerBoundaryTests(unittest.TestCase):
    def assert_available(self, lock):
        acquired = lock.acquire(blocking=False)
        self.assertTrue(acquired, 'handler left a shared lock acquired')
        if acquired:
            lock.release()

    def test_friend_save_failure_preserves_request_and_authorization_until_retry(self):
        ctx = SimpleNamespace(
            pending_friend_requests={('bob', 'alice'): time.time(), ('alice', 'bob'): time.time()},
            pending_friend_requests_lock=threading.Lock(), user_friends_lock=threading.Lock(),
            user_friends={'alice': set(), 'bob': set()}, PENDING_REQUEST_TIMEOUT_SECONDS=86400,
            save_friend_relationship=Mock(side_effect=[OSError('synthetic database failure'), None]),
            get_sock_by_username=Mock(return_value=None), send_msg=Mock())
        sock = object()
        request = {'to': 'bob', 'accepted': True}
        handle_friend_response(ctx, sock, 'alice', request)
        self.assertEqual(set(ctx.pending_friend_requests), {('bob', 'alice'), ('alice', 'bob')})
        self.assertEqual(ctx.user_friends, {'alice': set(), 'bob': set()})
        self.assertFalse(ctx.send_msg.call_args.args[1]['success'])
        self.assert_available(ctx.pending_friend_requests_lock)
        self.assert_available(ctx.user_friends_lock)
        handle_friend_response(ctx, sock, 'alice', request)
        self.assertEqual(ctx.pending_friend_requests, {})
        self.assertEqual(ctx.user_friends, {'alice': {'bob'}, 'bob': {'alice'}})
        self.assertEqual(ctx.save_friend_relationship.call_count, 2)

    def test_rejected_group_join_releases_operation_lock_and_sends_no_history(self):
        ctx = SimpleNamespace(group_ops_lock=threading.Lock(), get_group_db=Mock(return_value=None),
                              send_msg=Mock(), send_history=Mock())
        handle_group_join(ctx, object(), 'alice', {'gid': 'missing-group'})
        self.assertFalse(ctx.send_msg.call_args.args[1]['success'])
        ctx.send_history.assert_not_called()
        self.assert_available(ctx.group_ops_lock)
