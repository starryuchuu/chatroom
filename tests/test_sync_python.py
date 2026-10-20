"""Forward replay across reconnects uses bounded, authorized snapshot pages."""
from contextlib import closing
import json
import os
import unittest
from unittest.mock import Mock, patch

import test_regressions as regression


class PythonSyncTests(unittest.TestCase):
    setUpClass = classmethod(regression.ServerTests.setUpClass.__func__)
    tearDownClass = classmethod(regression.ServerTests.tearDownClass.__func__)
    setUp = regression.ServerTests.setUp
    tearDown = regression.ServerTests.tearDown
    connect = regression.ServerTests.connect
    read_type = regression.ServerTests.read_type

    def replay(self, request, username='alice', *, query=None):
        sock, key, events = Mock(), os.urandom(16), []
        self.server.session_keys[sock] = key
        with patch.object(self.server, 'send_msg', side_effect=lambda peer, event: events.append(event)):
            if query is None:
                self.server.send_sync(sock, username, request)
            else:
                with patch.object(self.server.history_store, 'sync_page', side_effect=query):
                    self.server.send_sync(sock, username, request)
        self.server.session_keys.pop(sock)
        return events, key

    def test_forward_pages_recover_more_than_login_limit_at_one_boundary(self):
        s = self.server
        s.save_friend_relationship('alice', 'bob')
        gid = s.create_group_db('alice', 'Team', ['alice', 'bob'])
        private_gid = s.create_group_db('carol', 'Other', ['carol', 'bob'])
        expected = []
        for number in range(205):
            if number % 2:
                mid = s.save_message('group', 'bob', None, gid, str(number), 'now')
            else:
                mid = s.save_message('private', 'bob', 'alice', None, str(number), 'now')
            expected.append(mid)
            if number % 5 == 0:
                s.save_message('private', 'carol', 'alice', None, 'not friends', 'now')
                s.save_message('private', 'bob', 'carol', None, 'other conversation', 'now')
                s.save_message('group', 'bob', None, private_gid, 'not a member', 'now')

        after, boundary, received = 0, None, []
        sizes = []
        for page in range(3):
            request = {'type': 'sync_request', 'request_id': 'page-' + str(page), 'after_id': after}
            if boundary is not None:
                request['boundary'] = boundary
            events, key = self.replay(request)
            begin, end = events[0], events[-1]
            self.assertEqual(begin['type'], 'sync_begin')
            self.assertEqual(end['type'], 'sync_end')
            self.assertEqual(begin['request_id'], request['request_id'])
            self.assertEqual(end['request_id'], request['request_id'])
            boundary = begin['boundary'] if boundary is None else boundary
            self.assertEqual((begin['boundary'], end['boundary']), (boundary, boundary))
            messages = events[1:-1]
            sizes.append(len(messages))
            self.assertTrue(all(message['history'] is True and message['sync'] is True
                                for message in messages))
            received += [message['message_id'] for message in messages]
            self.assertEqual([s.decrypt_message(message['content'], key) for message in messages],
                             [str(number) for number in range(page * 100, min((page + 1) * 100, 205))])
            self.assertEqual(end['after_id'], after)
            self.assertEqual(end['has_more'], page < 2)
            after = end['next_after_id']
            if page == 0:
                live_id = s.save_message('private', 'bob', 'alice', None, 'after snapshot', 'now')

        self.assertEqual(sizes, [100, 100, 5])
        self.assertEqual(received, expected)
        self.assertEqual(after, boundary)
        events, key = self.replay({'request_id': 'next-reconnect', 'after_id': after})
        self.assertEqual([event['message_id'] for event in events[1:-1]], [live_id])
        self.assertEqual(s.decrypt_message(events[1]['content'], key), 'after snapshot')
        self.assertFalse(events[-1]['has_more'])

    def test_group_membership_is_rechecked_after_page_query(self):
        s = self.server
        gid = s.create_group_db('bob', 'Team', ['alice', 'bob'])
        mid = s.save_message('group', 'bob', None, gid, 'removed member must not receive', 'now')
        original = s.history_store.sync_page

        def remove_member(*args):
            result = original(*args)
            self.assertTrue(s.update_group_members_db(gid, ['bob']))
            return result

        events, _ = self.replay({'request_id': 'removed', 'after_id': 0}, query=remove_member)
        self.assertEqual([event['type'] for event in events], ['sync_begin', 'sync_end'])
        self.assertEqual(events[-1]['next_after_id'], mid)
        self.assertFalse(events[-1]['has_more'])

    def test_bad_sync_queries_are_correlated_and_never_write_state(self):
        invalid_values = (None, True, False, -1, 0.5, '0', [], {},
                          float('nan'), float('inf'), 9007199254740992)
        requests = [{'request_id': 'bad', 'after_id': value} for value in invalid_values]
        requests += [{'request_id': 'bad', 'after_id': 0, 'boundary': value}
                     for value in invalid_values]
        requests += [{'request_id': value, 'after_id': 0} for value in (None, '', [], {}, '字' * 129)]
        requests += [{'request_id': 'bad', 'after_id': 1},
                     {'request_id': 'bad', 'after_id': 0, 'boundary': 1}]
        for request in requests:
            with self.subTest(request=request):
                events, _ = self.replay(request)
                self.assertEqual([event['type'] for event in events], ['sync_error'])
                if isinstance(request['request_id'], str) and 0 < len(request['request_id']) <= 128:
                    self.assertEqual(events[0]['request_id'], request['request_id'])
                else:
                    self.assertNotIn('request_id', events[0])
        with closing(self.server.storage.connect()) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM messages').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM friends').fetchone()[0], 0)

    def test_empty_database_and_unicode_correlation_are_supported(self):
        events, _ = self.replay({'request_id': '字' * 128, 'after_id': 0.0, 'boundary': 0.0})
        self.assertEqual([event['type'] for event in events], ['sync_begin', 'sync_end'])
        self.assertEqual(events[-1], {'type': 'sync_end', 'request_id': '字' * 128,
                                     'after_id': 0, 'boundary': 0,
                                     'next_after_id': 0, 'has_more': False})

    def test_history_replay_is_explicitly_marked_for_notification_filtering(self):
        s = self.server
        s.save_friend_relationship('alice', 'bob')
        gid = s.create_group_db('alice', 'Team', ['alice', 'bob'])
        s.save_message('private', 'bob', 'alice', None, 'private', 'now')
        s.save_message('group', 'bob', None, gid, 'group', 'now')
        sock, events = Mock(), []
        s.session_keys[sock] = os.urandom(16)
        with patch.object(s, 'send_msg', side_effect=lambda peer, event: events.append(event)):
            s.send_history(sock, 'alice')
        s.session_keys.pop(sock)
        self.assertEqual([event['type'] for event in events],
                         ['history_begin', 'private_chat', 'group_chat', 'history_end'])
        self.assertTrue(all(event['history'] is True for event in events[1:-1]))
        self.assertTrue(all('sync' not in event for event in events[1:-1]))

    def test_new_message_budget_reserves_replay_metadata(self):
        s = self.server
        payload = {'type': 'private_chat', 'from': 'bob', 'to': 'alice',
                   'content': '', 'timestamp': 'now', 'message_id': 9223372036854775807,
                   'history': True, 'sync': True}
        content = 'x' * (s.MAX_MESSAGE_LEN - len(json.dumps(payload).encode('utf-8')))
        s.validate_chat_packet('private_chat', 'bob', 'alice', None, content, 'now')
        with self.assertRaisesRegex(ValueError, '过长'):
            s.validate_chat_packet('private_chat', 'bob', 'alice', None, content + 'x', 'now')

    def test_legacy_near_limit_replay_preserves_body_with_compact_or_fallback_markers(self):
        s = self.server
        base = {'type': 'private_chat', 'from': 'bob', 'to': 'alice',
                'content': '', 'timestamp': 'now', 'message_id': s.MAX_SYNC_ID}
        for compact_only in (True, False):
            with self.subTest(compact_only=compact_only):
                payload = dict(base, history=True, sync=True)
                if compact_only:
                    size = len(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
                    payload['content'] = 'x' * (s.MAX_MESSAGE_LEN - size)
                else:
                    # Prior validation reserved a 19-digit ID. The actual ID is
                    # 16 digits, so a maximum valid old message has 3 spare bytes.
                    size = len(json.dumps(base).encode('utf-8'))
                    payload['content'] = 'x' * (s.MAX_MESSAGE_LEN - size - 3)
                with patch.object(s, 'send_msg') as send:
                    s.send_replay_message(Mock(), payload)
                encoded = send.call_args.args[1]
                self.assertIsInstance(encoded, str)
                self.assertLessEqual(len(encoded.encode('utf-8')), s.MAX_MESSAGE_LEN)
                decoded = json.loads(encoded)
                self.assertTrue(decoded['content'] == payload['content'])
                self.assertEqual(decoded['message_id'], payload['message_id'])
                self.assertEqual(decoded['timestamp'], payload['timestamp'])
                if compact_only:
                    self.assertTrue(decoded['history'] and decoded['sync'])
                else:
                    self.assertNotIn('history', decoded)
                    self.assertNotIn('sync', decoded)

    def test_capability_and_sync_error_recovery_on_authenticated_connection(self):
        s, wire, advertised = self.server, regression.client, []
        original = s.send_msg

        def record(peer, event, **kwargs):
            if event.get('type') == 'public_key':
                advertised.append(event)
            return original(peer, event, **kwargs)

        with patch.object(s, 'send_msg', side_effect=record):
            peer, key, result = self.connect('alice')
            self.assertTrue(result['success'])
            self.read_type(peer, 'online_users')
        self.assertIn('message_sync', advertised[0]['capabilities'])
        s.save_friend_relationship('alice', 'bob')
        mid = s.save_message('private', 'bob', 'alice', None, 'catchup', 'now')
        wire.send_msg(peer, {'type': 'sync_request', 'request_id': 'invalid', 'after_id': True})
        self.assertEqual(self.read_type(peer, 'sync_error')['request_id'], 'invalid')
        with patch.object(s.history_store, 'sync_page', side_effect=RuntimeError('database busy')):
            wire.send_msg(peer, {'type': 'sync_request', 'request_id': 'failed', 'after_id': 0})
            self.assertEqual(self.read_type(peer, 'sync_begin')['request_id'], 'failed')
            self.assertEqual(self.read_type(peer, 'sync_error')['request_id'], 'failed')
        wire.send_msg(peer, {'type': 'sync_request', 'request_id': 'retry', 'after_id': 0})
        self.assertEqual(self.read_type(peer, 'sync_begin')['request_id'], 'retry')
        message = wire.recv_msg(peer)
        self.assertEqual(message['message_id'], mid)
        self.assertEqual(s.decrypt_message(message['content'], key), 'catchup')
        self.assertTrue(message['history'] and message['sync'])
        self.assertEqual(self.read_type(peer, 'sync_end')['next_after_id'], mid)


if __name__ == '__main__':
    unittest.main()
