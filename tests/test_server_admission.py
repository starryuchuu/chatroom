"""Credential admission ordering against the real Python socket handler."""
import hashlib
import unittest
from unittest.mock import patch

from opaque_runtime import call
from test_opaque_server import backup
import test_regressions as regressions


class ServerAdmissionTests(unittest.TestCase):
    # Reuse the isolated database/socket fixture without inheriting its tests.
    setUpClass = classmethod(regressions.ServerTests.setUpClass.__func__)
    tearDownClass = classmethod(regressions.ServerTests.tearDownClass.__func__)
    setUp = regressions.ServerTests.setUp
    tearDown = regressions.ServerTests.tearDown
    connect = regressions.ServerTests.connect

    def test_legacy_admission_rejects_migration_after_password_verification(self):
        server = self.server
        username = 'alice'
        server_id = hashlib.sha256(server.private_key.publickey().export_key(format='DER')).hexdigest()
        start = call({'op': 'registration_start', 'password': 'synthetic unified credential'})
        challenge = call({'op': 'registration_respond', 'setup': server.opaque_server.get_setup(),
                          'username': username, 'server_id': server_id, 'request': start['request']})
        finished = call({'op': 'registration_finish', 'password': 'synthetic unified credential',
                         'state': start['state'], 'response': challenge['response'],
                         'username': username, 'server_id': server_id})
        original_validate = server.validate_user

        def verify_then_migrate(candidate, password):
            valid = original_validate(candidate, password)
            if valid:
                # A migration completed and disconnected in the gap between
                # this legacy proof and its subsequent admission reservation.
                server.opaque_server.store_account(
                    candidate, finished['record'], backup(candidate, server_id), server_id,
                    legacy=server.opaque_server.legacy_snapshot(candidate))
            return valid

        with patch.object(server, 'validate_user', side_effect=verify_then_migrate) as validate:
            _, _, result = self.connect(username)
        self.assertFalse(result['success'])
        validate.assert_called_once()
        self.assertTrue(server.opaque_server.has_account(username))
        self.threads[-1].join(3)
        self.assertFalse(self.threads[-1].is_alive())
        self.assertEqual(server.auth_reservations, {})
        self.assertEqual(server.usernames, {})


if __name__ == '__main__':
    unittest.main()
