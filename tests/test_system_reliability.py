"""Black-box reliability checks against real Python and Go server processes.

For a longer run set CHATROOM_STRESS_USERS=8, CHATROOM_STRESS_GROUP=100 and
CHATROOM_STRESS_PRIVATE=50. The Go cases require CHATROOM_GO_SERVER_EXE.
"""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import random
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import client
import storage

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = 'reliability-test-password'


class Peer:
    def __init__(self, sock, key, username):
        self.sock, self.key, self.username = sock, key, username
        self.events = []
        self.condition = threading.Condition()
        self.closed = False
        self.error = None
        client.authenticated_sockets.add(sock)
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        try:
            while True:
                event = client.recv_msg(self.sock)
                if event is None:
                    break
                if not isinstance(event, dict):
                    raise AssertionError('server sent a non-object response')
                with self.condition:
                    self.events.append(event)
                    self.condition.notify_all()
        except Exception as error:
            self.error = error
        finally:
            with self.condition:
                self.closed = True
                self.condition.notify_all()

    def wait(self, predicate, *, after=0, timeout=20):
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                found = next((event for event in self.events[after:] if predicate(event)), None)
                if found is not None:
                    return found
                if self.closed:
                    raise ConnectionError(f'{self.username} disconnected: {self.error}')
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    kinds = [event.get('type') for event in self.events[-8:]]
                    raise TimeoutError(f'{self.username}: expected response missing; last events: {kinds}')
                self.condition.wait(remaining)

    def send(self, event):
        client.send_msg(self.sock, event)

    def request(self, event, response_type):
        after = len(self.events)
        self.send(event)
        request_id = event.get('request_id')
        return self.wait(lambda reply: reply.get('type') == response_type and
                         (request_id is None or reply.get('request_id') == request_id), after=after)

    def wait_messages(self, expected_ids):
        deadline = time.monotonic() + 30
        with self.condition:
            while True:
                messages = [event for event in self.events if event.get('type') in ('private_chat', 'group_chat')]
                if expected_ids <= {event['message_id'] for event in messages}:
                    return messages
                if self.closed:
                    raise ConnectionError(f'{self.username} disconnected before delivery: {self.error}')
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    actual = {event['message_id'] for event in messages}
                    raise TimeoutError(f'{self.username}: missing {len(expected_ids - actual)} messages')
                self.condition.wait(remaining)

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        self.reader.join(5)
        if self.reader.is_alive():
            raise AssertionError('reader did not stop after socket shutdown')
        client.authenticated_sockets.discard(self.sock)
        client.transport.forget(self.sock)


class Service:
    def __init__(self, backend):
        self.backend = backend
        self.tmp = tempfile.TemporaryDirectory(prefix='chatroom-reliability-')
        self.path = Path(self.tmp.name)
        self.log_path = self.path / 'server.log'
        self.peers = []
        self.process = self.log = None
        self.fingerprint = None
        if backend == 'go':
            self.port = 12346
        else:
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                self.port = probe.getsockname()[1]

    def start(self):
        # Never exercise an unrelated service already using the fixed Go port.
        with socket.socket() as probe:
            if os.name != 'nt':
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(('127.0.0.1', self.port))
        self.log = self.log_path.open('a', encoding='utf-8')
        if self.backend == 'go':
            command = [str(Path(os.environ['CHATROOM_GO_SERVER_EXE']).resolve())]
        else:
            command = [sys.executable, '-c',
                       'import sys,server; server.SERVER_PORT=int(sys.argv[1]); server.main()', str(self.port)]
        env = dict(os.environ)
        env['PYTHONPATH'] = str(ROOT) + os.pathsep + env.get('PYTHONPATH', '')
        self.process = subprocess.Popen(command, cwd=self.path, env=env, stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError('server exited on startup: ' + self.log_path.read_text(encoding='utf-8')[-4000:])
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=.2):
                    return
            except OSError:
                time.sleep(.02)
        raise TimeoutError('server did not listen')

    def connect(self, username, register=False):
        sock = socket.create_connection(('127.0.0.1', self.port), timeout=6)
        try:
            public = client.recv_msg(sock)
            if not isinstance(public, dict) or public.get('type') != 'public_key':
                raise AssertionError(f'unexpected handshake response: {public}')
            rsa = client.RSA.import_key(public['key'])
            fingerprint = hashlib.sha256(rsa.export_key(format='DER')).hexdigest()
            if self.fingerprint is None:
                self.fingerprint = fingerprint
            if self.fingerprint != fingerprint:
                raise AssertionError('server identity changed across restart')
            key = os.urandom(16)
            encrypted = client.PKCS1_OAEP.new(rsa).encrypt(key)
            client.send_msg(sock, {'type': 'session_key', 'protocol': client.transport.VERSION,
                                   'key': base64.b64encode(encrypted).decode()})
            client.transport.configure(sock, key)
            credentials = client.encrypt_message(json.dumps({'from': username, 'password': PASSWORD}), key)
            client.send_msg(sock, {'type': 'encrypted_register' if register else 'encrypted_login', 'data': credentials})
            result = client.recv_msg(sock)
            if not isinstance(result, dict) or result.get('success') is not True:
                raise AssertionError(f'authentication failed for {username}: {result}')
            if register:
                sock.close()
                client.transport.forget(sock)
                return None
            peer = Peer(sock, key, username)
            self.peers.append(peer)
            peer.wait(lambda event: event.get('type') == 'history_end')
            return peer
        except BaseException:
            sock.close()
            client.transport.forget(sock)
            raise

    def stop(self, *, kill=False):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.kill() if kill else self.process.terminate()
            self.process.wait(timeout=10)
            self.process = None
        for peer in self.peers:
            peer.close()
        self.peers.clear()
        if self.log is not None:
            self.log.close()
            self.log = None

    def close(self):
        self.stop()
        self.tmp.cleanup()

    def database(self):
        previous = storage._store
        try:
            with closing(storage.connect(self.path / 'chat.db')) as db:
                storage.initialize(db, self.path / 'chat.db')
                if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise AssertionError('SQLite integrity check failed')
                records = db.execute('SELECT id,chat_type,from_user,to_user,gid,message,timestamp FROM messages ORDER BY id').fetchall()
                return {row[0]: storage.decode_message(db, row) for row in records}
        finally:
            storage._store = previous

    def history(self, peer, kind, target):
        before, received = 9223372036854775807, []
        while True:
            after = len(peer.events)
            peer.send({'type': 'history_request', 'chat_type': kind, 'target': target, 'before_id': before})
            end = peer.wait(lambda event: event.get('type') in ('history_end', 'history_error'), after=after)
            if end['type'] != 'history_end':
                raise AssertionError(f'history query failed: {end}')
            page = [event for event in peer.events[after:] if event.get('type') == kind + '_chat']
            ids = [event['message_id'] for event in page]
            if ids != sorted(ids) or len(ids) > 100:
                raise AssertionError('history page order/size invariant failed')
            received.extend(page)
            if not end.get('has_more'):
                return received
            cursor = end['before_id']
            if not isinstance(cursor, int) or not 0 < cursor < before:
                raise AssertionError('history cursor did not advance')
            before = cursor


class ReliabilityScenarios:
    def setUp(self):
        self.service = Service(self.backend)
        self.addCleanup(self.service.close)
        self.service.start()

    def cohort(self, users=4):
        names = [f'user{i:02}' for i in range(users)]
        for name in names:
            self.service.connect(name, register=True)
        peers = [self.service.connect(name) for name in names]
        owner = peers[0]
        for peer in peers[1:]:
            result = owner.request({'type': 'friend_request', 'to': peer.username}, 'friend_request_result')
            self.assertTrue(result['success'])
            peer.wait(lambda event: event.get('type') == 'friend_request')
            peer.send({'type': 'friend_response', 'to': owner.username, 'accepted': True})
            peer.wait(lambda event: event.get('type') == 'friend_update')
            owner.wait(lambda event: event.get('type') == 'friend_update' and event.get('friend') == peer.username)
        result = owner.request({'type': 'group_create', 'group_name': 'Reliability 群', 'members': names[1:]}, 'group_create_result')
        self.assertTrue(result['success'])
        gid = result['gid']
        for peer in peers[1:]:
            peer.wait(lambda event: event.get('type') == 'group_create_result' and event.get('gid') == gid)
        return peers, gid

    def check_database_record(self, record, expected):
        self.assertEqual((record[1], record[2], record[4] if record[1] == 'group' else record[3], record[5]), expected)
        self.assertTrue(record[6])

    def test_concurrent_delivery_history_and_restart(self):
        users = min(32, max(3, int(os.environ.get('CHATROOM_STRESS_USERS', '4'))))
        group_count = min(300, max(1, int(os.environ.get('CHATROOM_STRESS_GROUP', '30'))))
        private_count = min(100, max(1, int(os.environ.get('CHATROOM_STRESS_PRIVATE', '12'))))
        peers, gid = self.cohort(users)

        def send_all(index):
            peer = peers[index]
            rng = random.Random(1701 + index)
            confirmed = {}
            for kind, count in (('group', group_count), ('private', private_count)):
                for number in range(count):
                    target = gid if kind == 'group' else peers[0 if index else 1 + number % (users - 1)].username
                    request_id = f'{index}-{kind}-{number}'
                    text = request_id + ': ' + ''.join(rng.choice('中🙂abc\n"\\') for _ in range(rng.randint(1, 350)))
                    request = {'type': kind + '_chat', 'request_id': request_id,
                               'content': client.encrypt_message(text, peer.key)}
                    request['gid' if kind == 'group' else 'to'] = target
                    reply = peer.request(request, kind + '_chat_result')
                    self.assertTrue(reply['success'], reply)
                    confirmed[reply['message_id']] = (kind, peer.username, target, text)
            return confirmed

        with ThreadPoolExecutor(max_workers=users) as executor:
            batches = list(executor.map(send_all, range(users)))
        confirmed = {message_id: expected for batch in batches for message_id, expected in batch.items()}
        expected_count = users * (group_count + private_count)
        self.assertEqual(len(confirmed), expected_count)
        for peer in peers:
            wanted = {mid for mid, (kind, sender, target, _) in confirmed.items()
                      if kind == 'group' or peer.username in (sender, target)}
            messages = peer.wait_messages(wanted)
            self.assertFalse(peer.closed, 'healthy concurrent traffic disconnected a client')
            self.assertIsNone(peer.error)
            counts = Counter(event['message_id'] for event in messages)
            self.assertEqual(set(counts), wanted)
            self.assertTrue(all(count == 1 for count in counts.values()), 'duplicate live delivery')
            for event in messages:
                self.assertEqual(client.decrypt_message(event['content'], peer.key), confirmed[event['message_id']][3])
        rows = self.service.database()
        self.assertEqual(set(rows), set(confirmed))
        for message_id, expected in confirmed.items():
            self.check_database_record(rows[message_id], expected)
        self.service.stop(kill=True)
        self.service.start()
        owner = self.service.connect('user00')
        group_history = self.service.history(owner, 'group', gid)
        self.assertEqual({event['message_id'] for event in group_history},
                         {mid for mid, expected in confirmed.items() if expected[0] == 'group'})
        for target in (peer.username for peer in peers[1:]):
            history = self.service.history(owner, 'private', target)
            expected_ids = {mid for mid, (kind, sender, recipient, _) in confirmed.items()
                            if kind == 'private' and target in (sender, recipient)}
            self.assertEqual({event['message_id'] for event in history}, expected_ids)
        self.assertEqual(self.service.database(), rows)
        print(f'RELIABILITY {self.backend}: {users} clients, {expected_count} confirmed messages, exact delivery/DB/history after forced restart', flush=True)

    def test_acknowledged_messages_survive_inflight_crash(self):
        peers, gid = self.cohort()
        confirmed, attempted = {}, {}
        guard = threading.Lock()
        enough, crashing = threading.Event(), threading.Event()

        def send_until_crash(index):
            peer = peers[index]
            for number in range(150):
                if crashing.is_set():
                    return
                request_id = f'crash-{index}-{number}'
                text = request_id + ' durable 中文'
                with guard:
                    attempted[text] = ('group', peer.username, gid, text)
                try:
                    reply = peer.request({'type': 'group_chat', 'gid': gid, 'request_id': request_id,
                                          'content': client.encrypt_message(text, peer.key)}, 'group_chat_result')
                    self.assertTrue(reply['success'], reply)
                    with guard:
                        confirmed[reply['message_id']] = attempted[text]
                        if len(confirmed) >= 24:
                            enough.set()
                except (ConnectionError, OSError, TimeoutError):
                    if not crashing.is_set():
                        raise
                    return

        with ThreadPoolExecutor(max_workers=len(peers)) as executor:
            futures = [executor.submit(send_until_crash, index) for index in range(len(peers))]
            try:
                self.assertTrue(enough.wait(20), 'load did not reach crash checkpoint')
            finally:
                crashing.set()
                self.service.stop(kill=True)
            for future in futures:
                future.result(timeout=20)
        rows = self.service.database()
        self.assertGreaterEqual(len(confirmed), 24)
        self.assertTrue(set(confirmed) <= set(rows), 'a successfully acknowledged message was lost')
        for mid, expected in confirmed.items():
            self.check_database_record(rows[mid], expected)
        for row in rows.values():
            self.check_database_record(row, attempted[row[5]])
        self.service.start()
        owner = self.service.connect('user00')
        history = self.service.history(owner, 'group', gid)
        self.assertEqual({event['message_id'] for event in history}, set(rows))
        print(f'RELIABILITY {self.backend}: crash during writes; {len(confirmed)} receipts preserved, {len(rows)} committed messages recovered', flush=True)

    def test_offline_requests_survive_restart_and_are_consumed_once(self):
        peers, gid = self.cohort(3)
        owner, friend, invited = peers
        self.service.connect('offline', register=True)
        invited.close()
        owner.wait(lambda event: event.get('type') == 'online_users' and invited.username not in event['users'])
        # Remove the future invitee first, then invite them while offline.
        self.assertTrue(owner.request({'type': 'group_kick', 'gid': gid, 'kick': invited.username}, 'group_kick_result')['success'])
        self.assertTrue(owner.request({'type': 'friend_request', 'to': 'offline'}, 'friend_request_result')['success'])
        self.assertTrue(owner.request({'type': 'group_invite', 'gid': gid, 'to': invited.username}, 'group_invite_result')['success'])
        self.service.stop(kill=True)
        self.service.start()
        applicant = self.service.connect('offline')
        applicant.wait(lambda event: event.get('type') == 'friend_request' and event.get('from') == owner.username)
        applicant.send({'type': 'friend_response', 'to': owner.username, 'accepted': True})
        applicant.wait(lambda event: event.get('type') == 'friend_update')
        joined = self.service.connect(invited.username)
        joined.wait(lambda event: event.get('type') == 'group_invite' and event.get('gid') == gid)
        self.assertTrue(joined.request({'type': 'group_join', 'gid': gid}, 'group_join_result')['success'])
        self.service.stop(kill=True)
        self.service.start()
        applicant = self.service.connect('offline')
        joined = self.service.connect(invited.username)
        # A request/response round trip drains the earlier login notifications.
        joined.request({'type': 'group_info', 'gid': gid}, 'group_info')
        applicant.request({'type': 'group_info', 'gid': 'missing'}, 'group_info')
        self.assertFalse(any(event.get('type') == 'friend_request' for event in applicant.events))
        self.assertFalse(any(event.get('type') == 'group_invite' for event in joined.events))
        with closing(storage.connect(self.service.path / 'chat.db')) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pending_friend_requests').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pending_group_invites').fetchone()[0], 0)

    def test_accepting_reciprocal_friend_requests_consumes_both_directions(self):
        for username in ('alice', 'bob'):
            self.service.connect(username, register=True)
        alice = self.service.connect('alice')
        bob = self.service.connect('bob')
        for sender, recipient in ((alice, bob), (bob, alice)):
            result = sender.request({'type': 'friend_request', 'to': recipient.username},
                                    'friend_request_result')
            self.assertTrue(result['success'], result)
            recipient.wait(lambda event: event.get('type') == 'friend_request' and
                           event.get('from') == sender.username)

        bob.send({'type': 'friend_response', 'to': 'alice', 'accepted': True})
        for peer, friend in ((alice, 'bob'), (bob, 'alice')):
            peer.wait(lambda event: event.get('type') == 'friend_update' and
                      event.get('friend') == friend)

        # Once friendship exists, the reverse request must no longer be actionable
        # in the running process. A barrier also makes a missing rejection fail
        # immediately instead of waiting for a success response that has no ack.
        after = len(alice.events)
        alice.send({'type': 'friend_response', 'to': 'bob', 'accepted': True})
        alice.request({'type': 'group_info', 'gid': 'reciprocal-response-barrier'}, 'group_info')
        rejections = [event for event in alice.events[after:]
                      if event.get('type') == 'friend_response_result']
        self.assertEqual(len(rejections), 1, 'accepted friendship left a reverse request actionable')
        self.assertFalse(rejections[0]['success'], rejections[0])
        self.assertFalse(any(event.get('type') == 'friend_update' for event in alice.events[after:]))

        self.service.stop(kill=True)
        self.service.start()
        alice = self.service.connect('alice')
        bob = self.service.connect('bob')
        for peer, friend in ((alice, 'bob'), (bob, 'alice')):
            snapshot = peer.wait(lambda event: event.get('type') == 'friends_list')
            self.assertEqual(set(snapshot['friends']), {friend})
            # Pending login requests can follow history_end; wait for a response
            # sent after all login events before checking for a replay.
            peer.request({'type': 'group_info', 'gid': 'reciprocal-restart-barrier'}, 'group_info')
            self.assertFalse(any(event.get('type') == 'friend_request' for event in peer.events),
                             'accepted reciprocal request replayed after restart')

    def test_connection_churn_reclaims_resources(self):
        peers, gid = self.cohort(3)
        observer, reconnecting, _ = peers
        fd_path = Path(f'/proc/{self.service.process.pid}/fd')
        baseline_fds = len(list(fd_path.iterdir())) if fd_path.is_dir() else None
        for _ in range(12):
            after = len(observer.events)
            reconnecting.close()
            observer.wait(lambda event: event.get('type') == 'online_users' and reconnecting.username not in event['users'], after=after)
            reconnecting = self.service.connect(reconnecting.username)
            self.assertTrue(reconnecting.request({'type': 'group_info', 'gid': gid}, 'group_info')['gid'] == gid)
        raw = []
        try:
            for _ in range(48):
                raw.append(socket.create_connection(('127.0.0.1', self.service.port), timeout=3))
        finally:
            for index, sock in enumerate(raw):
                if index % 2:
                    try:
                        sock.sendall(struct.pack('!I', 100)[:1 + index % 3])
                    except OSError:
                        pass  # An authentication-limit rejection may already close it.
                sock.close()
        # A valid operation and new login must still work after the abandoned handshakes.
        self.assertEqual(observer.request({'type': 'group_info', 'gid': gid}, 'group_info')['gid'], gid)
        after = len(observer.events)
        reconnecting.close()
        observer.wait(lambda event: event.get('type') == 'online_users' and reconnecting.username not in event['users'], after=after)
        reconnecting = self.service.connect(reconnecting.username)
        self.assertEqual(reconnecting.request({'type': 'group_info', 'gid': gid}, 'group_info')['gid'], gid)
        self.assertIsNone(self.service.process.poll())

        if baseline_fds is not None:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                remaining_fds = len(list(fd_path.iterdir()))
                if remaining_fds <= baseline_fds + 2:
                    break
                time.sleep(.02)
            self.assertLessEqual(remaining_fds, baseline_fds + 2, 'connections leaked file descriptors')

    def test_database_write_failure_is_reported_and_retry_recovers(self):
        peers, gid = self.cohort(3)
        owner, recipient, _ = peers
        with closing(storage.connect(self.service.path / 'chat.db')) as db, db:
            db.execute("CREATE TRIGGER reliability_reject_message BEFORE INSERT ON messages "
                       "BEGIN SELECT RAISE(ABORT, 'injected write failure'); END")
        requests = []
        for kind, target in (('private', recipient.username), ('group', gid)):
            request = {'type': kind + '_chat', 'request_id': 'retry-' + kind,
                       'content': client.encrypt_message('recover ' + kind, owner.key)}
            request['to' if kind == 'private' else 'gid'] = target
            requests.append(request)
            result = owner.request(request, kind + '_chat_result')
            self.assertFalse(result['success'], 'failed write was acknowledged as saved')
        for peer in peers:
            peer.request({'type': 'group_info', 'gid': gid}, 'group_info')
            self.assertFalse(any(event.get('type') in ('private_chat', 'group_chat') for event in peer.events),
                             'a rejected database write was delivered')
        self.assertEqual(self.service.database(), {})
        with closing(storage.connect(self.service.path / 'chat.db')) as db, db:
            db.execute('DROP TRIGGER reliability_reject_message')
        for request in requests:
            result = owner.request(request, request['type'] + '_result')
            self.assertTrue(result['success'], result)
            recipient.wait(lambda event: event.get('type') == request['type'] and
                           event.get('message_id') == result['message_id'])
        rows = self.service.database()
        self.assertEqual(len(rows), 2)
        self.assertEqual({row[5] for row in rows.values()}, {'recover private', 'recover group'})

    def test_fragmented_authenticated_frames_are_delivered_once(self):
        peers, gid = self.cohort(3)
        owner = peers[0]
        text = 'fragmented 中文🙂 ' * 30
        body = json.dumps({'type': 'group_chat', 'gid': gid, 'request_id': 'fragmented',
                           'content': client.encrypt_message(text, owner.key)}).encode()
        state = client.transport.state_for(owner.sock)
        owner.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with state.send_lock:
            authenticated = struct.pack('!Q', state.send_seq) + body
            data = authenticated + hmac.digest(state.send_key, authenticated, 'sha256')
            packet = struct.pack('!I', len(data)) + data
            offset = 0
            # Split both the length header and the authenticated sequence, then
            # split the JSON body and MAC independently of application messages.
            for width in [1, 2, 1, 3, 5] + [23] * ((len(packet) + 22) // 23):
                fragment = packet[offset:offset + width]
                if not fragment:
                    break
                owner.sock.sendall(fragment)
                offset += len(fragment)
                time.sleep(.001)
            state.send_seq += 1
        result = owner.wait(lambda event: event.get('type') == 'group_chat_result' and
                            event.get('request_id') == 'fragmented')
        self.assertTrue(result['success'], result)
        second = owner.request({'type': 'group_chat', 'gid': gid, 'request_id': 'after-fragment',
                                'content': client.encrypt_message('next frame', owner.key)}, 'group_chat_result')
        self.assertTrue(second['success'], second)
        wanted = {result['message_id'], second['message_id']}
        for peer in peers:
            messages = peer.wait_messages(wanted)
            self.assertEqual(Counter(event['message_id'] for event in messages), Counter({mid: 1 for mid in wanted}))
        rows = self.service.database()
        self.assertEqual(set(rows), wanted)
        self.assertEqual(rows[result['message_id']][5], text)
        self.assertEqual(rows[second['message_id']][5], 'next frame')

    def test_invalid_requests_and_forged_frames_do_not_mutate_state(self):
        peers, gid = self.cohort(3)
        owner, target, fuzzer = peers
        # user02 is removed so malformed requests cannot accidentally be authorized.
        self.assertTrue(owner.request({'type': 'group_kick', 'gid': gid, 'kick': fuzzer.username}, 'group_kick_result')['success'])
        fuzzer.wait(lambda event: event.get('type') == 'group_kick_notification')
        malformed = []
        for value in (None, [], {}, True, 17, ''):
            malformed.extend([
                {'type': 'private_chat', 'to': value, 'content': 'invalid'},
                {'type': 'group_chat', 'gid': value, 'content': 'invalid'},
                {'type': 'group_info', 'gid': value},
                {'type': 'friend_response', 'to': value, 'accepted': True},
                {'type': 'group_create', 'group_name': value, 'members': []},
            ])
        for value in (None, [], {}, False, -1, 0, 1.5, 1e50, '10'):
            malformed.append({'type': 'history_request', 'chat_type': 'group', 'target': gid, 'before_id': value})
        malformed.extend({'type': kind, 'gid': gid, 'new_name': 'forbidden', 'new_owner': fuzzer.username, 'kick': owner.username}
                         for kind in ('group_disband', 'group_transfer', 'group_rename', 'group_kick', 'group_join'))
        for request in malformed:
            fuzzer.send(request)
        # Match a unique barrier response, so an earlier error still in transit
        # cannot satisfy the wait before the invalid requests have been handled.
        after = len(fuzzer.events)
        fuzzer.send({'type': 'group_info', 'gid': 'validation-barrier'})
        barrier = fuzzer.wait(lambda event: event.get('type') == 'group_info' and
                             event.get('gid') == 'validation-barrier', after=after)
        self.assertIn('error', barrier)
        current = owner.request({'type': 'group_info', 'gid': gid}, 'group_info')
        self.assertEqual(current['owner'], owner.username)
        self.assertEqual(set(current['members']), {owner.username, target.username})
        self.assertEqual(self.service.database(), {})

        def sealed(peer, body):
            state = client.transport.state_for(peer.sock)
            authenticated = struct.pack('!Q', state.send_seq) + body
            data = authenticated + hmac.digest(state.send_key, authenticated, 'sha256')
            return struct.pack('!I', len(data)) + data

        verified_frames = 0
        for corruption in ('mac', 'replay', 'oversize', 'empty', 'utf8', 'null'):
            with self.subTest(corruption=corruption):
                if not fuzzer.closed:
                    after = len(owner.events)
                    fuzzer.close()
                    owner.wait(lambda event: event.get('type') == 'online_users' and fuzzer.username not in event['users'], after=after)
                fuzzer = self.service.connect(fuzzer.username)
                packet = sealed(fuzzer, json.dumps({'type': 'group_info', 'gid': gid}).encode())
                if corruption == 'mac':
                    packet = packet[:-1] + bytes([packet[-1] ^ 1])
                elif corruption == 'replay':
                    fuzzer.sock.sendall(packet)
                    fuzzer.wait(lambda event: event.get('type') == 'group_info')
                elif corruption == 'oversize':
                    packet = struct.pack('!I', client.transport.MAX_WIRE_LEN + 1)
                elif corruption == 'empty':
                    packet = struct.pack('!I', 0)
                elif corruption == 'utf8':
                    packet = sealed(fuzzer, b'\xff')
                elif corruption == 'null':
                    packet = sealed(fuzzer, b'null')
                after = len(owner.events)
                fuzzer.sock.sendall(packet)
                deadline = time.monotonic() + 5
                while not fuzzer.closed and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(fuzzer.closed, 'bad authenticated frame was not rejected')
                owner.wait(lambda event: event.get('type') == 'online_users' and fuzzer.username not in event['users'], after=after)
                current = owner.request({'type': 'group_info', 'gid': gid}, 'group_info')
                self.assertEqual(current['owner'], owner.username)
                verified_frames += 1
        self.assertEqual(verified_frames, 6)
        self.assertEqual(self.service.database(), {})
        print(f'RELIABILITY {self.backend}: {len(malformed)} invalid business requests and 6 forged/invalid frame cases isolated', flush=True)


class PythonReliabilityTests(ReliabilityScenarios, unittest.TestCase):
    backend = 'python'


@unittest.skipUnless(os.environ.get('CHATROOM_GO_SERVER_EXE'), 'Go binary not selected')
class GoReliabilityTests(ReliabilityScenarios, unittest.TestCase):
    backend = 'go'


if __name__ == '__main__':
    unittest.main(verbosity=2)
