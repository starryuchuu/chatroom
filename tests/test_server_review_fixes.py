"""Python server regressions for the v1.3.2 business and privacy review.

All wire requests use a temporary service on an ephemeral loopback port. Bulk
fixtures are synthetic and are written only while that service is stopped.
"""
from contextlib import closing
import json
import socket
import time
import unittest

import client
import storage
from opaque_runtime import call
from test_single_password_interop import FIRST, Wire
from test_system_reliability import PASSWORD, Service


class ServerReviewFixTests(unittest.TestCase):
    def setUp(self):
        self.service = Service('python')
        self.addCleanup(self.service.close)
        self.service.start()

    def account(self, username):
        self.service.connect(username, register=True)

    def befriend(self, owner, friend):
        result = owner.request({'type': 'friend_request', 'to': friend.username},
                               'friend_request_result')
        self.assertTrue(result['success'])
        friend.request({'type': 'friend_response', 'to': owner.username, 'accepted': True},
                       'friend_update')
        owner.wait(lambda event: event.get('type') == 'friend_update' and
                   event.get('friend') == friend.username)

    def begin_migration(self, username):
        wire = Wire(self.service)
        self.addCleanup(wire.close)
        start = call({'op': 'registration_start', 'password': FIRST})
        wire.send({'type': 'opaque_migrate_start', 'from': username,
                   'request': start['request'],
                   'legacy_data': client.encrypt_message(
                       json.dumps({'password': PASSWORD}), wire.key)})
        challenge = wire.receive('opaque_migrate_challenge')
        return wire, start, challenge

    def test_migration_reserves_account_until_online_registration(self):
        self.account('migrating')
        wire, start, challenge = self.begin_migration('migrating')
        with Wire(self.service) as competitor:
            competitor.send({'type': 'encrypted_login', 'data': client.encrypt_message(
                json.dumps({'from': 'migrating', 'password': PASSWORD}), competitor.key)})
            self.assertFalse(competitor.receive('login_result')['success'])
        finish = call({'op': 'registration_finish', 'password': FIRST,
                       'state': start['state'], 'response': challenge['response'],
                       'username': 'migrating', 'server_id': wire.server_id})
        wire.send({'type': 'opaque_migrate_finish', 'record': finish['record'],
                   'backup': wire.backup('migrating')})
        result = wire.receive('login_result')
        self.assertTrue(result['success'])
        self.assertEqual(result['opaque_generation'], 1)
        # The competing failure must not release the migration's reservation.
        with Wire(self.service) as duplicate:
            start = call({'op': 'login_start', 'password': FIRST})
            duplicate.send({'type': 'opaque_login_start', 'from': 'migrating',
                            'request': start['request']})
            reply = client.recv_msg(duplicate.sock)
            if reply.get('type') == 'opaque_login_challenge':
                proof = call({'op': 'login_finish', 'password': FIRST,
                              'state': start['state'], 'response': reply['response'],
                              'username': 'migrating', 'server_id': duplicate.server_id})
                duplicate.send({'type': 'opaque_login_finish',
                                'finalization': proof['finalization']})
                reply = duplicate.receive('login_result')
            self.assertEqual(reply.get('type'), 'login_result')
            self.assertFalse(reply['success'])

    def test_unproven_opaque_login_does_not_reserve_account(self):
        username = 'proof_boundary'
        with Wire(self.service) as registration:
            start = call({'op': 'registration_start', 'password': FIRST})
            registration.send({'type': 'opaque_register_start', 'from': username,
                               'request': start['request']})
            challenge = registration.receive('opaque_register_challenge')
            finish = call({'op': 'registration_finish', 'password': FIRST,
                           'state': start['state'], 'response': challenge['response'],
                           'username': username, 'server_id': registration.server_id})
            registration.send({'type': 'opaque_register_finish', 'record': finish['record'],
                               'backup': registration.backup(username)})
            self.assertTrue(registration.receive('register_result')['success'])

        with Wire(self.service) as unproven:
            wrong_start = call({'op': 'login_start',
                                'password': 'synthetic incorrect account password'})
            unproven.send({'type': 'opaque_login_start', 'from': username,
                           'request': wrong_start['request']})
            unproven.receive('opaque_login_challenge')
            # Keep the first exchange open without KE3. A client that has not
            # proved the password must not prevent a legitimate second login.
            with Wire(self.service) as legitimate:
                start = call({'op': 'login_start', 'password': FIRST})
                legitimate.send({'type': 'opaque_login_start', 'from': username,
                                 'request': start['request']})
                challenge = legitimate.receive('opaque_login_challenge')
                proof = call({'op': 'login_finish', 'password': FIRST,
                              'state': start['state'], 'response': challenge['response'],
                              'username': username, 'server_id': legitimate.server_id})
                legitimate.send({'type': 'opaque_login_finish',
                                 'finalization': proof['finalization']})
                result = legitimate.receive('login_result')
                self.assertTrue(result['success'])
                self.assertEqual(result['opaque_generation'], 1)

    def test_failed_and_disconnected_migrations_release_account_reservation(self):
        for mode in ('malformed', 'disconnected'):
            with self.subTest(mode=mode):
                username = 'migration_' + mode[:5]
                self.account(username)
                wire, _, _ = self.begin_migration(username)
                if mode == 'malformed':
                    wire.send({'type': 'opaque_migrate_finish', 'record': 'invalid-record',
                               'backup': wire.backup(username)})
                    self.assertFalse(wire.receive('login_result')['success'])
                else:
                    # Half-close lets the server observe EOF while the test can
                    # still wait for its terminal failure and connection close.
                    wire.sock.shutdown(socket.SHUT_WR)
                    response = client.recv_msg(wire.sock)
                    if response is not None:
                        self.assertFalse(response['success'])
                self.assertIsNone(client.recv_msg(wire.sock))
                wire.close()
                peer = self.service.connect(username)
                peer.close()

    def test_default_logs_redact_group_fields_and_malformed_requests(self):
        for username in ('log_owner', 'log_friend'):
            self.account(username)
        owner = self.service.connect('log_owner')
        friend = self.service.connect('log_friend')
        self.befriend(owner, friend)
        markers = ['SYNTHETIC_PRIVATE_GROUP_SUBJECT',
                   'SYNTHETIC_PRIVATE_RENAMED_SUBJECT',
                   'SYNTHETIC_PRIVATE_INVALID_MEMBER',
                   'SYNTHETIC_PRIVATE_INVALID_GROUP_ID',
                   'SYNTHETIC_PRIVATE_NON_OBJECT',
                   'SYNTHETIC_PRIVATE_UNKNOWN_TYPE']
        created = owner.request({'type': 'group_create', 'group_name': markers[0],
                                 'members': ['log_friend']}, 'group_create_result')
        self.assertTrue(created['success'])
        renamed = owner.request({'type': 'group_rename', 'gid': created['gid'],
                                 'new_name': markers[1]}, 'group_rename_result')
        self.assertTrue(renamed['success'])
        invalid = owner.request({'type': 'group_create', 'group_name': 'invalid',
                                 'members': [{'private': markers[2]}]}, 'group_create_result')
        self.assertFalse(invalid['success'])
        owner.request({'type': 'group_info', 'gid': {'private': markers[3]}}, 'group_info')
        owner.send(markers[4])
        owner.send({'type': markers[5], 'private': markers[2]})
        # A later response on the same connection is a processing/log barrier.
        owner.request({'type': 'group_info', 'gid': created['gid']}, 'group_info')
        log_text = self.service.log_path.read_text(encoding='utf-8')
        for marker in markers + ['log_owner', 'log_friend']:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, log_text)

    def test_oversized_duplicate_members_need_no_database_or_global_chat_lock(self):
        for username in ('aa', 'cc'):
            self.account(username)
        owner = self.service.connect('aa')
        outsider = self.service.connect('cc')
        packet = {'type': 'group_create', 'group_name': 'valid', 'members': ['bb'] * 160000}
        self.assertLess(len(json.dumps(packet).encode()), client.transport.MAX_PAYLOAD_LEN)
        # The old handler blocks in its first per-member SQL query while
        # holding the global chat lock. The fixed preflight needs neither.
        with closing(storage.connect(self.service.path / 'chat.db')) as db:
            db.execute('BEGIN EXCLUSIVE')
            try:
                owner_after, outsider_after = len(owner.events), len(outsider.events)
                owner.send(packet)
                outsider.send({'type': 'private_chat', 'to': 'aa', 'request_id': 'unrelated'})
                reply = owner.wait(lambda event: event.get('type') == 'group_create_result',
                                   after=owner_after, timeout=3)
                self.assertFalse(reply['success'])
                reply = outsider.wait(lambda event: event.get('type') == 'private_chat_result',
                                      after=outsider_after, timeout=3)
                self.assertFalse(reply['success'])
            finally:
                db.rollback()
        # An unrelated group query remains usable after the rejected packet.
        outsider.request({'type': 'group_info', 'gid': 'missing'}, 'group_info')

    def test_group_capacity_at_create_invite_join_and_legacy_recovery(self):
        for username in ('capacity_owner', 'capacity_first', 'capacity_second'):
            self.account(username)
        self.service.stop()
        fillers = ['capacity_%03d' % index for index in range(256)]
        store = storage.Storage((self.service.path / 'chat.db.key').read_bytes())
        with closing(storage.connect(self.service.path / 'chat.db')) as db, db:
            owner = store.put_name(db, 'capacity_owner')
            for username in fillers:
                token = store.put_name(db, username)
                db.execute('INSERT INTO users(username,password) VALUES(?,?)',
                           (token, store.seal('disabled-fixture', 'users', 'password', token)))
                db.execute('INSERT INTO friends(user,friend) VALUES(?,?)', (owner, token))
            for username in ('capacity_first', 'capacity_second'):
                token = store.put_name(db, username)
                db.execute('INSERT INTO friends(user,friend) VALUES(?,?)', (owner, token))
            fixtures = {
                'capacity-last-slot': ['capacity_owner'] + fillers[:254],
                'capacity-legacy-over': ['capacity_owner'] + fillers[:255] + ['capacity_first'],
            }
            for gid, members in fixtures.items():
                db.execute('INSERT INTO groups VALUES(?,?,?,?,?)',
                           (gid, store.seal('capacity fixture', 'groups', 'group_name', gid),
                            store.seal('capacity_owner', 'groups', 'owner', gid),
                            store.seal(json.dumps(members), 'groups', 'members', gid),
                            store.seal('2026-01-01 00:00:00', 'groups', 'created_at', gid)))
            for username in ('capacity_first', 'capacity_second'):
                db.execute('INSERT INTO pending_group_invites VALUES(?,?,?,?)',
                           ('capacity-last-slot', store.token(username), owner, time.time()))
        self.service.start()
        owner = self.service.connect('capacity_owner')
        first = self.service.connect('capacity_first')
        second = self.service.connect('capacity_second')
        solo = owner.request({'type': 'group_create', 'group_name': 'solo', 'members': []},
                             'group_create_result')
        self.assertTrue(solo['success'])
        self.assertEqual(solo['members'], ['capacity_owner'])
        deduplicated = owner.request({'type': 'group_create', 'group_name': 'deduplicated',
                                      'members': ['capacity_owner', fillers[0], fillers[0]]},
                                     'group_create_result')
        self.assertTrue(deduplicated['success'])
        self.assertEqual(set(deduplicated['members']), {'capacity_owner', fillers[0]})
        self.assertEqual(len(deduplicated['members']), 2)
        raw_over_limit = owner.request({'type': 'group_create', 'group_name': 'raw member cap',
                                        'members': [fillers[0]] * 257}, 'group_create_result')
        self.assertFalse(raw_over_limit['success'])
        created = owner.request({'type': 'group_create', 'group_name': '256 members',
                                 'members': fillers[:255]}, 'group_create_result')
        self.assertTrue(created['success'])
        self.assertEqual(len(created['members']), 256)
        rejected = owner.request({'type': 'group_create', 'group_name': '257 members',
                                  'members': fillers}, 'group_create_result')
        self.assertFalse(rejected['success'])
        invite = owner.request({'type': 'group_invite', 'gid': created['gid'],
                                'to': 'capacity_second'}, 'group_invite_result')
        self.assertFalse(invite['success'])
        joined = first.request({'type': 'group_join', 'gid': 'capacity-last-slot'},
                               'group_join_result')
        self.assertTrue(joined['success'])
        self.assertEqual(len(joined['members']), 256)
        rejected = second.request({'type': 'group_join', 'gid': 'capacity-last-slot'},
                                  'group_join_result')
        self.assertFalse(rejected['success'])
        with closing(storage.connect(self.service.path / 'chat.db')) as db:
            retained = db.execute('SELECT 1 FROM pending_group_invites WHERE gid=? AND target=?',
                                  ('capacity-last-slot', store.token('capacity_second'))).fetchone()
        self.assertIsNotNone(retained, 'a full group must not consume a retryable invitation')
        self.assertTrue(first.request({'type': 'group_leave', 'gid': 'capacity-last-slot'},
                                      'group_leave_result')['success'])
        retried = second.request({'type': 'group_join', 'gid': 'capacity-last-slot'},
                                 'group_join_result')
        self.assertTrue(retried['success'])
        self.assertEqual(len(retried['members']), 256)
        legacy = owner.request({'type': 'group_info', 'gid': 'capacity-legacy-over'}, 'group_info')
        self.assertEqual(len(legacy['members']), 257)
        self.assertTrue(first.request({'type': 'group_leave', 'gid': 'capacity-legacy-over'},
                                      'group_leave_result')['success'])
        recovered = owner.request({'type': 'group_info', 'gid': 'capacity-legacy-over'}, 'group_info')
        self.assertEqual(len(recovered['members']), 256)


if __name__ == '__main__':
    unittest.main()
