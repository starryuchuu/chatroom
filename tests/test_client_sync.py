"""Catch-up pages cannot skip gaps or advance another account's checkpoint."""
import unittest
from unittest.mock import Mock, patch

from chatroom_client.models import ClientState
from chatroom_client.preferences import PreferencesStore
from chatroom_client.sync import SyncController


class ClientSyncTests(unittest.TestCase):
    endpoint = ('127.0.0.1', 12345)

    def controller(self, *, checkpoint=10, capabilities=('message_sync',), username='alice'):
        self.state = ClientState(username=username)
        self.preferences = PreferencesStore(persistent=False)
        metadata = {'activity': {'initialized': True, 'conversations': []}}
        if checkpoint is not None:
            metadata['sync_cursor'] = checkpoint
        self.preferences.update_account(self.endpoint, username, metadata)
        self.sent, self.scheduled = [], []
        self.notify, self.refresh = Mock(), Mock()
        self.sync = SyncController(self.state, self.sent.append, self.preferences, self.notify,
                                   self.refresh, lambda ms, callback: self.scheduled.append((ms, callback)))
        self.sync.establish(self.endpoint, username, capabilities)
        return self.sync

    def initial(self, boundary=450):
        self.assertTrue(self.sync.on_initial_history_end({'type': 'history_end', 'boundary': boundary}))

    def response(self, kind, request=None, **fields):
        request = request or self.sent[-1]
        result = {'type': kind, 'request_id': request['request_id'],
                  'after_id': request['after_id'], 'boundary': request['boundary']}
        result.update(fields)
        self.assertTrue(self.sync.handle(result))

    def stored(self, username='alice'):
        return self.preferences.account(self.endpoint, username).get('sync_cursor')

    def test_first_login_baselines_recent_snapshot_without_fetching_all_history(self):
        sync = self.controller(checkpoint=None)
        self.assertTrue(sync.awaiting_initial)
        self.initial(450)
        self.assertEqual(self.sent, [])
        self.assertEqual(sync.checkpoint, 450)
        self.assertEqual(self.stored(), 450)
        self.assertFalse(sync.active or sync.failed or sync.awaiting_initial)

    def test_multiple_pages_commit_only_after_all_gaps_are_received(self):
        sync = self.controller()
        self.initial()
        self.assertEqual(self.sent[0]['after_id'], 10)
        self.assertEqual(self.sent[0]['boundary'], 450)
        self.assertTrue(sync.active and self.state.history_syncing)
        self.response('sync_begin')
        self.response('sync_end', next_after_id=110, has_more=True)
        first_timeout = self.scheduled[0][1]
        self.assertEqual(self.sent[-1]['after_id'], 110)
        self.assertEqual(sync.checkpoint, 10)
        self.assertEqual(self.stored(), 10)
        first_timeout()
        self.assertTrue(sync.active)
        self.response('sync_begin')
        self.response('sync_end', next_after_id=210, has_more=True)
        self.assertEqual(self.sent[-1]['boundary'], 450)
        self.response('sync_begin')
        self.response('sync_end', next_after_id=450, has_more=False)
        self.assertEqual(sync.checkpoint, 450)
        self.assertEqual(self.stored(), 450)
        self.assertEqual(self.preferences.account(self.endpoint, 'alice')['activity'],
                         {'initialized': True, 'conversations': []})
        self.assertFalse(sync.active or self.state.history_syncing or sync.failed)

    def test_empty_catchup_can_commit_the_same_boundary(self):
        sync = self.controller(checkpoint=10)
        self.initial(10)
        self.response('sync_begin')
        self.response('sync_end', next_after_id=10, has_more=False)
        self.assertEqual(sync.checkpoint, 10)
        self.assertFalse(sync.failed)

    def test_partial_failure_retries_from_original_committed_cursor(self):
        sync = self.controller()
        self.initial()
        self.response('sync_begin')
        self.response('sync_end', next_after_id=110, has_more=True)
        failed_request = self.sent[-1]
        self.response('sync_error', error='temporary storage failure')
        self.assertEqual(sync.checkpoint, 10)
        self.assertEqual(self.stored(), 10)
        self.assertTrue(sync.failed)
        self.assertFalse(self.state.history_syncing)
        self.assertTrue(sync.retry())
        self.assertEqual(self.sent[-1]['after_id'], 10)
        self.assertNotEqual(self.sent[-1]['request_id'], failed_request['request_id'])
        self.response('sync_end', request=failed_request, next_after_id=450, has_more=False)
        self.assertTrue(sync.active)
        self.assertEqual(self.stored(), 10)

    def test_timeout_preserves_checkpoint_and_old_timers_cannot_fail_a_retry(self):
        sync = self.controller()
        self.initial()
        milliseconds, timeout = self.scheduled[-1]
        self.assertEqual(milliseconds, 20000)
        timeout()
        self.assertTrue(sync.failed)
        self.assertEqual(self.stored(), 10)
        self.assertTrue(sync.retry())
        timeout()
        self.assertTrue(sync.active)
        self.assertFalse(sync.failed)

    def test_correlated_server_error_without_page_metadata_retains_checkpoint(self):
        sync = self.controller()
        self.initial()
        request_id = self.sent[-1]['request_id']
        self.assertTrue(sync.handle({'type': 'sync_error', 'request_id': request_id,
                                     'error': 'temporary database error'}))
        self.assertTrue(sync.failed)
        self.assertEqual(self.stored(), 10)
        self.notify.assert_called_with('消息同步', 'temporary database error')

    def test_logout_and_account_switch_ignore_old_pages_and_timeouts(self):
        sync = self.controller()
        self.initial()
        old_request = self.sent[-1]
        old_timeout = self.scheduled[-1][1]
        sync.abort()
        self.preferences.update_account(self.endpoint, 'bob', {'sync_cursor': 300})
        sync.establish(self.endpoint, 'bob', ('message_sync',))
        self.initial(450)
        self.response('sync_begin', request=old_request)
        self.response('sync_end', request=old_request, next_after_id=450, has_more=False)
        old_timeout()
        self.assertEqual(sync.checkpoint, 300)
        self.assertEqual(self.stored(), 10)
        self.assertEqual(self.stored('bob'), 300)
        self.assertTrue(sync.active)

    def test_legacy_server_never_receives_unknown_sync_request_or_advances_gap_cursor(self):
        sync = self.controller(capabilities=())
        self.initial(450)
        self.assertEqual(self.sent, [])
        self.assertEqual(sync.checkpoint, 10)
        self.assertEqual(self.stored(), 10)
        self.assertFalse(sync.active or sync.failed)
        self.notify.assert_called_once()
        sync.establish(self.endpoint, 'alice', ('message_sync',))
        self.initial(450)
        self.assertEqual(self.sent[-1]['after_id'], 10)

    def test_only_unscoped_login_history_can_start_the_catchup(self):
        sync = self.controller()
        self.assertFalse(sync.on_initial_history_end({'type': 'history_end', 'history_kind': 'group',
                                                       'history_target': 'g', 'boundary': 450}))
        self.assertTrue(sync.awaiting_initial)
        self.assertEqual(self.sent, [])
        self.initial()
        request_count = len(self.sent)
        self.assertFalse(sync.on_initial_history_end({'type': 'history_end', 'boundary': 999}))
        self.assertEqual(len(self.sent), request_count)

    def test_invalid_progress_and_changed_boundary_never_commit(self):
        cases = [
            {'next_after_id': 10, 'has_more': True},
            {'next_after_id': 450, 'has_more': True},
            {'next_after_id': 449, 'has_more': False},
            {'next_after_id': True, 'has_more': False},
            {'next_after_id': 450, 'has_more': 0},
            {'next_after_id': 450, 'has_more': False, 'boundary': 451},
            {'next_after_id': 450, 'has_more': False, 'after_id': True},
            {'next_after_id': 9007199254740992, 'has_more': False},
        ]
        for fields in cases:
            with self.subTest(fields=fields):
                sync = self.controller()
                self.initial()
                self.response('sync_begin')
                self.response('sync_end', **fields)
                self.assertTrue(sync.failed)
                self.assertFalse(sync.active)
                self.assertEqual(self.stored(), 10)
                self.assertEqual(len(self.sent), 1)

    def test_server_rollback_does_not_erase_a_previously_completed_checkpoint(self):
        sync = self.controller(checkpoint=500)
        self.initial(450)
        self.assertTrue(sync.failed)
        self.assertEqual(sync.checkpoint, 500)
        self.assertEqual(self.stored(), 500)
        self.assertEqual(self.sent, [])

    def test_persistence_failure_leaves_old_checkpoint_and_retries_whole_gap(self):
        sync = self.controller()
        self.initial()
        self.response('sync_begin')
        with patch.object(self.preferences, 'update_account', side_effect=OSError('read-only directory')):
            self.response('sync_end', next_after_id=450, has_more=False)
        self.assertTrue(sync.failed)
        self.assertEqual(sync.checkpoint, 10)
        self.assertEqual(self.stored(), 10)
        self.assertTrue(sync.retry())
        self.assertEqual(self.sent[-1]['after_id'], 10)

    def test_failed_enqueue_can_be_retried_without_advancing_the_cursor(self):
        sync = self.controller()
        with patch.object(sync, 'send', side_effect=ConnectionError('connection closed')):
            self.initial()
        self.assertTrue(sync.failed)
        self.assertEqual(self.stored(), 10)
        self.assertTrue(sync.retry())
        self.assertEqual(self.sent[-1]['after_id'], 10)

    def test_unread_metadata_must_be_saved_before_checkpoint_can_advance(self):
        sync = self.controller()
        sync.before_commit = Mock(return_value=False)
        self.initial()
        self.response('sync_begin')
        self.response('sync_end', next_after_id=450, has_more=False)
        self.assertTrue(sync.failed)
        self.assertEqual(self.stored(), 10)
        sync.before_commit.return_value = True
        self.assertTrue(sync.retry())
        self.response('sync_begin')
        self.response('sync_end', next_after_id=450, has_more=False)
        self.assertEqual(self.stored(), 450)


if __name__ == '__main__':
    unittest.main()
