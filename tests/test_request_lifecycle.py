"""Timeout, removal and stale-frame sequences across request generations."""
import itertools
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from chatroom_client.history import HistoryController
from chatroom_client.models import ChatKey, ClientState, Message
from chatroom_client.request_context import SessionContext


class RequestLifecycleTests(unittest.TestCase):
    def controller(self, *, modern=True, group=False):
        self.key = ChatKey('group' if group else 'private', 'bob')
        self.state = ClientState(username='alice', current_chat=self.key)
        if group:
            self.state.groups['bob'] = {'members': ['alice', 'bob']}
        self.state.conversation(self.key).add(Message('bob', 'recent', message_id=201))
        self.connection = SimpleNamespace(sock=object(), capabilities=('history_request_id',) if modern else ())
        self.sent, self.timeouts = [], []
        self.notify = Mock()
        self.history = HistoryController(self.state, self.sent.append, self.notify, Mock(), Mock(),
                                         connection=self.connection,
                                         schedule=lambda ms, callback: self.timeouts.append(callback))
        return self.history

    def reply(self, request, kind='history_end', **extra):
        return dict(type=kind, request_id=request['request_id'], history_kind=request['chat_type'],
                    history_target=request['target'], before_id=101, has_more=True, **extra)

    def test_timeout_retries_original_cursor_and_old_controls_cannot_complete_new_page(self):
        for order in itertools.permutations(('history_begin', 'history_end', 'history_error')):
            with self.subTest(order=order):
                history = self.controller()
                history.load_older()
                old, timeout = self.sent[-1], self.timeouts[-1]
                timeout()
                history.load_older()
                fresh = self.sent[-1]
                self.assertNotEqual(old['request_id'], fresh['request_id'])
                self.assertEqual(fresh['before_id'], 201)
                for kind in order:
                    history.handle(self.reply(old, kind))
                    timeout()
                    self.assertEqual(self.state.pending_history, self.key)
                    self.assertEqual(self.state.conversation(self.key).cursor, 201)
                history.handle(self.reply(fresh, 'history_begin'))
                self.assertTrue(history.accepts_message({'history_request_id': fresh['request_id']}, self.key))
                self.assertFalse(history.accepts_message({'history_request_id': old['request_id']}))
                self.assertFalse(history.accepts_message({'history_request_id': fresh['request_id']}, ChatKey('group', 'other')))
                history.handle(self.reply(fresh))
                self.assertIsNone(self.state.pending_history)
                self.assertEqual(self.state.conversation(self.key).cursor, 101)
                history.handle(self.reply(old))
                self.assertEqual(self.state.conversation(self.key).cursor, 101)

    def test_same_group_rejoin_invalidates_old_page_and_its_timeout(self):
        history = self.controller(group=True)
        history.load_older()
        old, timeout = self.sent[-1], self.timeouts[-1]
        history.handle(self.reply(old, 'history_begin'))
        self.state.remove_group('bob')
        self.state.groups['bob'] = {'members': ['alice', 'bob']}
        self.state.current_chat = self.key
        self.assertFalse(history.accepts_message({'history_request_id': old['request_id']}, self.key))
        history.handle(self.reply(old))
        self.assertNotIn(self.key, self.state.conversations)
        history.load_older()
        timeout()
        self.assertEqual(self.state.pending_history, self.key)
        self.assertEqual(self.state.conversation(self.key).cursor, 9223372036854775807)

    def test_legacy_timeout_requires_reconnect_and_does_not_accept_late_cursor(self):
        history = self.controller(modern=False)
        history.load_older()
        self.assertNotIn('request_id', self.sent[-1])
        self.timeouts[-1]()
        history.load_older()
        self.assertEqual(len(self.sent), 1)
        history.handle(dict(type='history_end', history_kind='private', history_target='bob', before_id=55))
        self.assertEqual(self.state.conversation(self.key).cursor, 201)
        history.abort()
        history.load_older()
        self.assertEqual(len(self.sent), 2)

    def test_timeout_does_not_suppress_interleaved_live_messages(self):
        history = self.controller()
        history.load_older()
        self.timeouts[-1]()
        self.assertFalse(history.accepts_message({'history': True}))
        self.assertTrue(history.accepts_message({'history': False}))
        self.assertTrue(history.accepts_message({'sync': True}))

    def test_context_rejects_replacement_connection_account_and_membership(self):
        self.controller(group=True)
        context = SessionContext.capture(self.state, self.connection, self.key)
        self.state.remove_group('unrelated')
        self.assertTrue(context.matches(self.state, self.connection))
        self.state.remove_group('bob')
        self.state.groups['bob'] = {}
        self.assertFalse(context.matches(self.state, self.connection))
        context = SessionContext.capture(self.state, self.connection)
        self.state.username = 'carol'
        self.assertFalse(context.matches(self.state, self.connection))
        self.state.username = 'alice'
        self.connection.sock = object()
        self.assertFalse(context.matches(self.state, self.connection))

    def test_stale_selection_cannot_start_a_removed_groups_page(self):
        history = self.controller(group=True)
        self.state.remove_group('bob')
        self.state.current_chat = self.key
        history.load_older()
        self.assertEqual(self.sent, [])
        self.assertIsNone(self.state.pending_history)
        self.assertNotIn(self.key, self.state.conversations)

    def test_unscoped_legacy_error_from_removed_batch_cannot_cancel_another_page(self):
        history = self.controller(modern=False, group=True)
        history.load_older()
        history.handle({'type': 'history_begin'})
        self.state.remove_group('bob')
        other = self.state.current_chat = ChatKey('private', 'carol')
        history.load_older()
        history.handle({'type': 'history_error', 'error': 'obsolete group batch'})
        self.assertEqual(self.state.pending_history, other)
        history.handle({'type': 'history_begin'})
        history.handle({'type': 'history_error', 'error': 'current page failure'})
        self.assertIsNone(self.state.pending_history)

    def test_matching_id_with_wrong_scope_cannot_change_either_conversation(self):
        for wrong in (ChatKey('private', 'carol'), ChatKey('group', 'bob')):
            with self.subTest(scope=wrong):
                history = self.controller()
                history.load_older()
                request = self.sent[-1]
                for kind in ('history_begin', 'history_error', 'history_end'):
                    reply = self.reply(request, kind) | {'history_kind': wrong.kind,
                                                         'history_target': wrong.target, 'has_more': False}
                    history.handle(reply)
                self.assertEqual(self.state.pending_history, self.key)
                self.assertNotIn(wrong, self.state.conversations)
                self.assertEqual(self.state.conversation(self.key).cursor, 201)
                history.handle(self.reply(request))
                self.assertEqual(self.state.conversation(self.key).cursor, 101)

    def test_auto_join_snapshot_cannot_complete_a_correlated_manual_page(self):
        history = self.controller(group=True)
        history.load_older()
        request = self.sent[-1]
        history.handle({'type': 'history_begin', 'history_kind': 'group', 'history_target': 'bob'})
        history.handle({'type': 'history_end', 'history_kind': 'group', 'history_target': 'bob',
                        'before_id': 55, 'has_more': False})
        history.handle({'type': 'history_error', 'error': 'uncorrelated error'})
        self.assertEqual(self.state.pending_history, self.key)
        self.assertEqual(self.state.conversation(self.key).cursor, 201)
        self.assertFalse(self.state.conversation(self.key).exhausted)
        self.notify.assert_not_called()
        history.handle(self.reply(request))
        self.assertIsNone(self.state.pending_history)

    def test_correlated_error_before_begin_releases_page_and_preserves_cursor(self):
        history = self.controller()
        history.load_older()
        failed = self.sent[-1]
        history.handle({'type': 'history_error', 'request_id': failed['request_id'], 'error': 'unavailable'})
        self.assertIsNone(self.state.pending_history)
        self.assertEqual(self.state.conversation(self.key).cursor, 201)
        history.load_older()
        retry = self.sent[-1]
        self.assertNotEqual(retry['request_id'], failed['request_id'])
        self.assertEqual(retry['before_id'], 201)

    def test_failed_enqueue_does_not_commit_request_state_or_schedule_timeout(self):
        history = self.controller()
        history.send = Mock(side_effect=ConnectionError('queue full'))
        history.load_older()
        self.assertIsNone(self.state.pending_history)
        self.assertIsNone(self.state.conversation(self.key).cursor)
        self.assertEqual(self.timeouts, [])
        history.send = self.sent.append
        history.load_older()
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]['before_id'], 201)

    def test_new_account_ignores_old_callbacks_and_responses_for_same_chat_key(self):
        history = self.controller()
        history.load_older()
        old, timeout = self.sent[-1], self.timeouts[-1]
        history.handle(self.reply(old, 'history_begin'))
        history.abort()
        self.state.reset_session('carol')
        self.connection.sock = object()
        self.state.current_chat = self.key
        self.state.conversation(self.key).add(Message('bob', 'new account message', message_id=901))
        history.load_older()
        fresh = self.sent[-1]
        timeout()
        for kind in ('history_begin', 'history_error', 'history_end'):
            history.handle(self.reply(old, kind))
        self.assertFalse(history.accepts_message({'history_request_id': old['request_id']}, self.key))
        self.assertEqual(self.state.pending_history, self.key)
        self.assertEqual(self.state.conversation(self.key).cursor, 901)
        history.handle(self.reply(fresh) | {'before_id': 801})
        self.assertEqual(self.state.conversation(self.key).cursor, 801)

    def test_near_limit_frames_without_per_message_id_use_current_batch(self):
        history = self.controller()
        history.load_older()
        old = self.sent[-1]
        history.handle(self.reply(old, 'history_begin'))
        self.timeouts[-1]()
        history.load_older()
        fresh = self.sent[-1]
        self.assertFalse(history.accepts_message({}))
        history.handle(self.reply(fresh, 'history_begin'))
        self.assertTrue(history.accepts_message({}))
        history.handle(self.reply(old))
        self.assertTrue(history.accepts_message({}))
        self.assertEqual(self.state.pending_history, self.key)

    def test_history_completion_and_timeout_preserve_active_incremental_sync(self):
        history = self.controller()
        history.sync_active = lambda: True
        for completion in ('history_end', 'history_error', 'timeout'):
            with self.subTest(completion=completion):
                history.load_older()
                request = self.sent[-1]
                history.handle(self.reply(request, 'history_begin'))
                if completion == 'timeout':
                    self.timeouts[-1]()
                else:
                    history.handle(self.reply(request, completion))
                self.assertIsNone(self.state.pending_history)
                self.assertTrue(self.state.history_syncing)
        history.abort()
        self.assertTrue(self.state.history_syncing)

    def test_duplicate_completion_cannot_rewind_a_completed_cursor_or_exhaustion(self):
        history = self.controller()
        history.load_older()
        request = self.sent[-1]
        history.handle(self.reply(request) | {'has_more': False})
        history.handle(self.reply(request) | {'before_id': 55, 'has_more': True})
        self.assertEqual(self.state.conversation(self.key).cursor, 101)
        self.assertTrue(self.state.conversation(self.key).exhausted)
