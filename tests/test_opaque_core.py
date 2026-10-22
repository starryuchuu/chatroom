"""The packaged RFC 9807 core authenticates both peers and binds identities."""
import base64
import unittest

from opaque_runtime import OpaqueError, call


class OpaqueCoreTests(unittest.TestCase):
    password = 'synthetic-opaque-test-password'
    username = 'opaque-test-alice'
    server_id = 'synthetic-server-fingerprint'

    @classmethod
    def setUpClass(cls):
        cls.setup = call({'op': 'server_setup'})['setup']
        start = call({'op': 'registration_start', 'password': cls.password})
        response = call({
            'op': 'registration_respond', 'setup': cls.setup,
            'username': cls.username, 'server_id': cls.server_id,
            'request': start['request'],
        })
        registered = call({
            'op': 'registration_finish', 'password': cls.password,
            'username': cls.username, 'server_id': cls.server_id,
            'state': start['state'], 'response': response['response'],
        })
        cls.record = call({'op': 'record_validate', 'record': registered['record']})['record']
        cls.export_key = registered['export_key']

    def begin_login(self, *, password=None, record=True, username=None, server_id=None):
        password = self.password if password is None else password
        start = call({'op': 'login_start', 'password': password})
        response = call({
            'op': 'login_respond', 'setup': self.setup,
            'record': self.record if record else None,
            'username': self.username if username is None else username,
            'server_id': self.server_id if server_id is None else server_id,
            'request': start['request'],
        })
        return start, response

    def finish_request(self, start, response, *, password=None, username=None, server_id=None):
        return {
            'op': 'login_finish',
            'password': self.password if password is None else password,
            'username': self.username if username is None else username,
            'server_id': self.server_id if server_id is None else server_id,
            'state': start['state'], 'response': response['response'],
        }

    def assert_authentication_failure(self, request):
        with self.assertRaises(OpaqueError) as raised:
            call(request)
        self.assertEqual(str(raised.exception), 'authentication_failed')
        self.assertNotIn(self.password, str(raised.exception))

    def test_export_key_survives_login_while_session_key_is_fresh(self):
        sessions = []
        for _ in range(2):
            start, response = self.begin_login()
            client = call(self.finish_request(start, response))
            server = call({
                'op': 'login_verify', 'state': response['state'],
                'finalization': client['finalization'],
            })
            self.assertEqual(client['export_key'], self.export_key)
            self.assertEqual(client['session_key'], server['session_key'])
            self.assertEqual(len(base64.b64decode(client['export_key'])), 64)
            sessions.append(client['session_key'])
        self.assertNotEqual(*sessions)

    def test_wrong_password_cannot_authenticate(self):
        wrong = 'synthetic-wrong-password'
        start, response = self.begin_login(password=wrong)
        self.assert_authentication_failure(self.finish_request(start, response, password=wrong))

    def test_both_client_and_server_identities_are_bound(self):
        start, response = self.begin_login()
        for fields in ({'username': 'different-account'},
                       {'server_id': 'different-server-fingerprint'}):
            with self.subTest(fields=fields):
                self.assert_authentication_failure(self.finish_request(start, response, **fields))
        # The account identifier also participates in per-account OPRF keys.
        start, response = self.begin_login(username='different-account')
        self.assert_authentication_failure(self.finish_request(start, response, username='different-account'))

    def test_unknown_account_uses_same_size_response_and_fails(self):
        start, valid = self.begin_login()
        unknown = call({
            'op': 'login_respond', 'setup': self.setup, 'record': None,
            'username': self.username, 'server_id': self.server_id,
            'request': start['request'],
        })
        self.assertEqual(len(base64.b64decode(unknown['response'])),
                         len(base64.b64decode(valid['response'])))
        self.assert_authentication_failure(self.finish_request(start, unknown))

    def test_server_rejects_modified_client_finalization(self):
        start, response = self.begin_login()
        client = call(self.finish_request(start, response))
        damaged = bytearray(base64.b64decode(client['finalization']))
        damaged[-1] ^= 1
        self.assert_authentication_failure({
            'op': 'login_verify', 'state': response['state'],
            'finalization': base64.b64encode(damaged).decode('ascii'),
        })

    def test_malformed_records_and_requests_have_fixed_failures(self):
        invalid_record = base64.b64encode(b'invalid-registration-record').decode('ascii')
        start = call({'op': 'login_start', 'password': self.password})
        requests = [
            {'op': 'record_validate', 'record': invalid_record},
            {'op': 'login_respond', 'setup': self.setup, 'record': invalid_record,
             'username': self.username, 'server_id': self.server_id,
             'request': start['request']},
            {'op': 'login_finish', 'password': self.password},
            {'op': 'unrecognized-operation', 'password': self.password},
        ]
        for request in requests:
            with self.subTest(operation=request['op']):
                self.assert_authentication_failure(request)


if __name__ == '__main__':
    unittest.main()
