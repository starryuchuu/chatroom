"""Encrypted local identity backups, TOFU decisions and concurrent updates."""
from copy import deepcopy
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from chatroom_client.e2ee_crypto import Identity, bundle_fingerprint
from chatroom_client.key_vault import (KeyVault, PeerKeyChanged, VaultError,
                                      VaultExistsError, VaultLockedError, vault_path)


PASSPHRASE = 'a separate local key passphrase'
ENDPOINT = ('chat.example', 12345)


class KeyVaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'private' / 'alice.json'
        self.vault = KeyVault(self.path, ENDPOINT, 'alice')
        self.identity = self.vault.unlock(PASSPHRASE, create=True)
        self.bob = Identity.generate()

    def test_identity_is_encrypted_and_survives_locked_restart(self):
        blob = self.path.read_bytes()
        for secret in self.identity.export_private().values():
            if isinstance(secret, str):
                self.assertNotIn(secret.encode(), blob)
        self.assertNotIn(PASSPHRASE.encode(), blob)
        self.assertEqual(json.loads(blob)['kdf'],
                         {'name': 'argon2id', 'memory': 65536, 'time': 3, 'parallelism': 1})
        self.vault.lock()
        with self.assertRaises(VaultLockedError):
            self.vault.identity
        reopened = KeyVault(self.path, ENDPOINT, 'alice')
        self.assertEqual(reopened.unlock(PASSPHRASE).fingerprint, self.identity.fingerprint)
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)

    def test_wrong_passphrase_and_tampering_never_regenerate(self):
        original = self.path.read_bytes()
        for passphrase in ('incorrect local passphrase',):
            reopened = KeyVault(self.path, ENDPOINT, 'alice')
            with self.assertRaises(VaultError):
                reopened.unlock(passphrase, create=True)
            self.assertFalse(reopened.unlocked)
            self.assertEqual(self.path.read_bytes(), original)
        altered = json.loads(original)
        altered['data'] = ('A' if altered['data'][0] != 'A' else 'B') + altered['data'][1:]
        self.path.write_text(json.dumps(altered))
        damaged = self.path.read_bytes()
        with self.assertRaises(VaultError):
            KeyVault(self.path, ENDPOINT, 'alice').unlock(PASSPHRASE, create=True)
        self.assertEqual(self.path.read_bytes(), damaged)

    def test_scope_and_host_account_paths_are_bound(self):
        for endpoint, username in ((('elsewhere.example', 12345), 'alice'), (ENDPOINT, 'bob'),
                                   (('chat.example', 54321), 'alice')):
            with self.subTest(endpoint=endpoint, username=username), self.assertRaises(VaultError):
                KeyVault(self.path, endpoint, username).unlock(PASSPHRASE)
        config = Path(self.tmp.name) / 'client.json'
        expected = vault_path(config, ENDPOINT, 'alice')
        self.assertEqual(expected, vault_path(config, ('CHAT.EXAMPLE', 12345), 'alice'))
        self.assertNotEqual(expected, vault_path(config, ENDPOINT, 'bob'))
        self.assertEqual(expected.parent, config.parent / 'e2ee')
        self.assertIsNone(vault_path(None, ENDPOINT, 'alice'))

    def test_tofu_pin_changes_require_explicit_review_and_verified_never_downgrades(self):
        bundle = self.bob.public_bundle()
        self.vault.pin_peer('bob', bundle)
        self.assertEqual(self.vault.peer('bob'), bundle)
        self.assertFalse(self.vault.is_verified('bob'))
        self.vault.pin_peer('bob', bundle, verified=True)
        self.vault.pin_peer('bob', bundle)
        self.assertTrue(self.vault.is_verified('bob'))
        changed = Identity.generate().public_bundle()
        original = self.path.read_bytes()
        with self.assertRaises(PeerKeyChanged) as raised:
            self.vault.pin_peer('bob', changed)
        self.assertEqual(raised.exception.expected, self.bob.fingerprint)
        self.assertEqual(raised.exception.actual, bundle_fingerprint(changed))
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(self.vault.peer('bob'), bundle)
        self.vault.pin_peer('bob', changed, replace=True)
        self.assertEqual(self.vault.peer('bob'), changed)
        self.assertFalse(self.vault.is_verified('bob'))
        with self.assertRaises(PeerKeyChanged):
            self.vault.pin_peer('alice', changed, replace=True)

    def test_group_approval_pins_roster_and_changed_recipients_require_new_approval(self):
        roster = {'alice': self.identity.public_bundle(), 'bob': self.bob.public_bundle()}
        self.assertIsNone(self.vault.approved_roster('group-1'))
        expected = {name: bundle_fingerprint(bundle) for name, bundle in roster.items()}
        self.assertEqual(self.vault.approve_roster('group-1', roster), expected)
        self.assertEqual(self.vault.approved_roster('group-1'), expected)
        self.assertEqual(self.vault.peer('bob'), self.bob.public_bundle())
        carol = Identity.generate()
        changed = dict(roster, carol=carol.public_bundle())
        self.assertNotEqual(expected, {name: bundle_fingerprint(bundle) for name, bundle in changed.items()})
        # A directory update alone cannot modify the locally approved roster.
        self.vault.pin_peer('carol', carol.public_bundle())
        self.assertEqual(self.vault.approved_roster('group-1'), expected)
        self.vault.approve_roster('group-1', changed)
        self.assertEqual(len(self.vault.approved_roster('group-1')), 3)
        with self.assertRaises(VaultError):
            self.vault.approve_roster('group-2', {'bob': self.bob.public_bundle()})

    def test_batch_pin_failure_does_not_partially_trust_other_recipients(self):
        self.vault.pin_peer('bob', self.bob.public_bundle())
        carol = Identity.generate()
        original = self.path.read_bytes()
        with self.assertRaises(PeerKeyChanged):
            self.vault.pin_peers({'carol': carol.public_bundle(), 'bob': carol.public_bundle()})
        self.assertEqual(self.path.read_bytes(), original)
        self.assertIsNone(self.vault.peer('carol'))

    def test_export_and_import_keep_private_keys_encrypted_and_require_explicit_replacement(self):
        self.vault.pin_peer('bob', self.bob.public_bundle(), verified=True)
        exported = Path(self.tmp.name) / 'backup' / 'alice.e2ee.json'
        self.vault.export_to(exported)
        private = self.identity.export_private()
        self.assertNotIn(private['sign'].encode(), exported.read_bytes())
        imported = KeyVault(Path(self.tmp.name) / 'other' / 'alice.json', ENDPOINT, 'alice')
        with self.assertRaises(VaultError):
            imported.import_from(exported, 'incorrect local passphrase')
        self.assertFalse(imported.exists)
        self.assertEqual(imported.import_from(exported, PASSPHRASE).fingerprint, self.identity.fingerprint)
        self.assertTrue(imported.is_verified('bob'))
        before = imported.path.read_bytes()
        with self.assertRaises(VaultError):
            imported.import_from(exported, PASSPHRASE)
        self.assertEqual(imported.path.read_bytes(), before)
        self.assertEqual(imported.import_from(exported, PASSPHRASE, replace=True).fingerprint,
                         self.identity.fingerprint)

    def test_passphrase_change_preserves_identity_and_rejects_old_password(self):
        self.vault.pin_peer('bob', self.bob.public_bundle(), verified=True)
        new_passphrase = 'new independent vault passphrase'
        self.vault.change_passphrase(new_passphrase)
        self.assertEqual(self.vault.identity.fingerprint, self.identity.fingerprint)
        self.assertTrue(self.vault.is_verified('bob'))
        with self.assertRaises(VaultError):
            KeyVault(self.path, ENDPOINT, 'alice').unlock(PASSPHRASE)
        self.assertEqual(KeyVault(self.path, ENDPOINT, 'alice').unlock(new_passphrase).fingerprint,
                         self.identity.fingerprint)

    def test_failed_atomic_save_keeps_disk_and_live_state(self):
        original = self.path.read_bytes()
        with patch('chatroom_client.key_vault.os.replace', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(VaultError, 'disk full'):
                self.vault.pin_peer('bob', self.bob.public_bundle())
        self.assertEqual(self.path.read_bytes(), original)
        self.assertIsNone(self.vault.peer('bob'))
        self.assertEqual(list(self.path.parent.glob('.vault-*.tmp')), [])
        self.vault.pin_peer('bob', self.bob.public_bundle())
        self.assertEqual(self.vault.peer('bob'), self.bob.public_bundle())

    def test_stale_instances_preserve_unrelated_pins_and_group_approvals(self):
        second = KeyVault(self.path, ENDPOINT, 'alice')
        second.unlock(PASSPHRASE)
        carol = Identity.generate()
        self.vault.pin_peer('bob', self.bob.public_bundle(), verified=True)
        second.pin_peer('carol', carol.public_bundle())
        roster = {'alice': self.identity.public_bundle(), 'bob': self.bob.public_bundle()}
        self.vault.approve_roster('group-1', roster)
        second.pin_peer('carol', carol.public_bundle(), verified=True)
        reopened = KeyVault(self.path, ENDPOINT, 'alice')
        reopened.unlock(PASSPHRASE)
        self.assertTrue(reopened.is_verified('bob'))
        self.assertTrue(reopened.is_verified('carol'))
        self.assertEqual(len(reopened.approved_roster('group-1')), 2)

    def test_external_corruption_or_identity_replacement_cannot_change_unlocked_identity(self):
        original_fingerprint = self.identity.fingerprint
        self.path.write_bytes(b'{broken')
        with self.assertRaises(VaultError):
            self.vault.pin_peer('bob', self.bob.public_bundle())
        self.assertEqual(self.path.read_bytes(), b'{broken')
        self.assertEqual(self.vault.identity.fingerprint, original_fingerprint)
        other = KeyVault(Path(self.tmp.name) / 'replacement.json', ENDPOINT, 'alice')
        replacement = other.unlock(PASSPHRASE, create=True)
        self.assertNotEqual(replacement.fingerprint, original_fingerprint)
        self.path.write_bytes(other.path.read_bytes())
        with self.assertRaisesRegex(VaultError, '其他实例替换'):
            self.vault.pin_peer('bob', self.bob.public_bundle())
        self.assertEqual(self.vault.identity.fingerprint, original_fingerprint)

    def test_malformed_headers_are_rejected_before_expensive_kdf(self):
        original = json.loads(self.path.read_bytes())
        cases = []
        for key, value in [('v', True), ('salt', 'not base64'), ('nonce', ''), ('extra', True)]:
            document = deepcopy(original)
            document[key] = value
            cases.append(document)
        document = deepcopy(original)
        document['kdf']['memory'] = 2**40
        cases.append(document)
        for document in cases:
            self.path.write_text(json.dumps(document))
            with self.subTest(document=document.keys()), patch('chatroom_client.key_vault.hash_secret_raw',
                                                               side_effect=AssertionError('unsafe KDF')):
                with self.assertRaises(VaultError):
                    KeyVault(self.path, ENDPOINT, 'alice').unlock(PASSPHRASE)

    def test_memory_vault_never_resolves_or_creates_user_directory(self):
        with patch('chatroom_client.key_vault.Path.mkdir', side_effect=AssertionError('disk write')):
            vault = KeyVault(None, ENDPOINT, 'alice')
            identity = vault.unlock(PASSPHRASE, create=True)
            vault.pin_peer('bob', self.bob.public_bundle())
            vault.lock()
            self.assertEqual(vault.unlock(PASSPHRASE).fingerprint, identity.fingerprint)
            self.assertEqual(vault.peer('bob'), self.bob.public_bundle())

    def test_missing_files_and_short_passphrases_do_not_create_identities(self):
        missing = Path(self.tmp.name) / 'missing' / 'vault.json'
        for passphrase in ('', 'short', None, 'a' * 1025):
            with self.subTest(passphrase=str(passphrase)[:10]), self.assertRaises(VaultError):
                KeyVault(missing, ENDPOINT, 'alice').unlock(passphrase, create=True)
        self.assertFalse(missing.parent.exists())
        with self.assertRaises(VaultError):
            KeyVault(missing, ENDPOINT, 'alice').unlock(PASSPHRASE)
        self.assertFalse(missing.parent.exists())

    def test_group_approval_history_is_exact_bounded_and_survives_restart(self):
        own = self.identity.fingerprint
        rosters = [{'alice': own, 'bob': f'{number:064x}'} for number in (1, 2, 3)]
        with patch('chatroom_client.key_vault.MAX_TRUST_HISTORY', 2):
            for roster in rosters:
                self.vault.approve_roster_fingerprints('gid', roster)
            self.assertFalse(self.vault.is_roster_approved('gid', rosters[0]))
            self.assertTrue(self.vault.is_roster_approved('gid', rosters[1]))
            self.assertTrue(self.vault.is_roster_approved('gid', rosters[2]))
            self.assertEqual(self.vault.approved_roster('gid'), rosters[2])
            self.assertFalse(self.vault.is_roster_approved('gid', {'alice': own}))
            reopened = KeyVault(self.path, ENDPOINT, 'alice')
            reopened.unlock(PASSPHRASE)
            self.assertTrue(reopened.is_roster_approved('gid', rosters[1]))

    def test_explicit_peer_replacement_preserves_only_bounded_trusted_history(self):
        keys = [self.bob, Identity.generate(), Identity.generate(), Identity.generate()]
        self.vault.pin_peer('bob', keys[0].public_bundle(), verified=True)
        with patch('chatroom_client.key_vault.MAX_TRUST_HISTORY', 2):
            for key in keys[1:]:
                self.vault.pin_peer('bob', key.public_bundle(), replace=True)
            self.assertIsNone(self.vault.peer_by_fingerprint('bob', keys[0].fingerprint))
            for key in keys[1:]:
                self.assertEqual(self.vault.peer_by_fingerprint('bob', key.fingerprint), key.public_bundle())
            self.assertIsNone(self.vault.peer_by_fingerprint('bob', '0' * 64))
            self.assertFalse(self.vault.is_verified('bob'))

    def test_trust_reads_refresh_other_instances_replacements_and_group_approvals(self):
        self.vault.pin_peer('bob', self.bob.public_bundle())
        second = KeyVault(self.path, ENDPOINT, 'alice')
        second.unlock(PASSPHRASE)
        changed = Identity.generate()
        second.pin_peer('bob', changed.public_bundle(), replace=True, verified=True)
        roster = {'alice': self.identity.fingerprint, 'bob': changed.fingerprint}
        second.approve_roster_fingerprints('gid', roster)
        self.assertEqual(self.vault.peer('bob'), changed.public_bundle())
        self.assertTrue(self.vault.is_verified('bob'))
        self.assertEqual(self.vault.approved_roster('gid'), roster)
        self.assertTrue(self.vault.is_roster_approved('gid', roster))

    def test_atomic_acceptance_rechecks_retired_keys_and_exact_message_digests(self):
        original = self.bob.public_bundle()
        self.assertTrue(self.vault.accept_envelope('bob', original, 'a' * 32, 11, '1' * 64))
        self.assertEqual(self.vault.known_record(self.bob.fingerprint, 'a' * 32),
                         {'message_id': 11, 'digest': '1' * 64})
        second = KeyVault(self.path, ENDPOINT, 'alice')
        second.unlock(PASSPHRASE)
        changed = Identity.generate()
        second.pin_peer('bob', changed.public_bundle(), replace=True)
        # A stale caller cannot authenticate a new message with a retired key.
        with self.assertRaises(PeerKeyChanged):
            self.vault.accept_envelope('bob', original, 'b' * 32, 12, '2' * 64)
        self.assertTrue(self.vault.accept_envelope('bob', original, 'a' * 32, 11, '1' * 64))
        self.assertFalse(self.vault.accept_envelope('bob', original, 'a' * 32, 99, '1' * 64))
        with self.assertRaises(VaultError):
            self.vault.accept_envelope('bob', original, 'a' * 32, 11, '2' * 64)
        self.assertIsNone(self.vault.known_record(self.bob.fingerprint, 'b' * 32))

    def test_old_integer_replay_records_cannot_authorize_retired_keys(self):
        self.vault.pin_peer('bob', self.bob.public_bundle())
        self.vault.observe_envelope(self.bob.fingerprint, 'a' * 32, 11)
        self.assertEqual(self.vault.known_record(self.bob.fingerprint, 'a' * 32),
                         {'message_id': 11, 'digest': None})
        self.vault.pin_peer('bob', Identity.generate().public_bundle(), replace=True)
        with self.assertRaises(PeerKeyChanged):
            self.vault.accept_envelope('bob', self.bob.public_bundle(), 'a' * 32, 11, '1' * 64)

    def test_archived_group_roster_only_authenticates_previously_observed_exact_messages(self):
        carol = Identity.generate()
        old = {'alice': self.identity.public_bundle(), 'bob': self.bob.public_bundle(),
               'carol': carol.public_bundle()}
        self.vault.approve_roster('gid', old)
        old_roster = {name: bundle_fingerprint(bundle) for name, bundle in old.items()}
        self.assertTrue(self.vault.accept_envelope('bob', self.bob.public_bundle(), 'a' * 32, 11, '1' * 64,
                                                  gid='gid', roster=old_roster))
        second = KeyVault(self.path, ENDPOINT, 'alice')
        second.unlock(PASSPHRASE)
        second.approve_roster('gid', {name: old[name] for name in ('alice', 'carol')})
        self.assertTrue(self.vault.is_roster_approved('gid', old_roster))
        with self.assertRaises(VaultError):
            self.vault.accept_envelope('bob', self.bob.public_bundle(), 'b' * 32, 12, '2' * 64,
                                       gid='gid', roster=second.approved_roster('gid'))
        with self.assertRaises(VaultError):
            self.vault.accept_envelope('bob', self.bob.public_bundle(), 'b' * 32, 12, '2' * 64,
                                       gid='gid', roster=old_roster)
        self.assertTrue(self.vault.accept_envelope('bob', self.bob.public_bundle(), 'a' * 32, 11, '1' * 64,
                                                  gid='gid', roster=old_roster))
        with self.assertRaises(VaultError):
            self.vault.accept_envelope('bob', self.bob.public_bundle(), 'a' * 32, 11, '2' * 64,
                                       gid='gid', roster=old_roster)

    def test_group_confirmation_cannot_overwrite_another_instances_new_approval(self):
        old = {'alice': self.identity.fingerprint, 'bob': self.bob.fingerprint}
        self.vault.approve_roster_fingerprints('gid', old)
        previous = self.vault.approved_roster('gid')
        second = KeyVault(self.path, ENDPOINT, 'alice')
        second.unlock(PASSPHRASE)
        new = {'alice': self.identity.fingerprint}
        second.approve_roster_fingerprints('gid', new)
        with self.assertRaises(VaultError):
            self.vault.approve_roster_fingerprints('gid', old, expected_previous=previous)
        self.assertEqual(second.approved_roster('gid'), new)

    def test_outgoing_guard_rejects_stale_rosters_and_changed_private_peer_keys(self):
        bundles = {'alice': self.identity.public_bundle(), 'bob': self.bob.public_bundle()}
        previous = self.vault.approve_roster('gid', bundles)
        second = KeyVault(self.path, ENDPOINT, 'alice')
        second.unlock(PASSPHRASE)
        second.approve_roster_fingerprints('gid', {'alice': self.identity.fingerprint})
        queued = []
        for approved in (False, True):
            with self.assertRaises(VaultError):
                with self.vault.send_guard(bundles, gid='gid', expected_roster=previous, approve=approved):
                    queued.append('Bob received a wrapped content key')
        self.assertEqual(queued, [])
        second.pin_peer('bob', Identity.generate().public_bundle(), replace=True)
        with self.assertRaises(PeerKeyChanged):
            with self.vault.send_guard(bundles):
                queued.append('private message leaked to retired key')
        self.assertEqual(queued, [])

    def test_outgoing_guard_holds_cross_instance_lock_until_queue_insertion(self):
        bundles = {'alice': self.identity.public_bundle(), 'bob': self.bob.public_bundle()}
        second = KeyVault(self.path, ENDPOINT, 'alice')
        second.unlock(PASSPHRASE)
        queued = []
        with self.vault.send_guard(bundles, gid='gid', expected_roster=None, approve=True) as identity:
            self.assertEqual(identity.fingerprint, self.identity.fingerprint)
            with patch('chatroom_client.preferences._LOCK_TIMEOUT', 0.02):
                with self.assertRaises(VaultError):
                    second.approve_roster_fingerprints('gid', {'alice': self.identity.fingerprint})
            queued.append('encrypted and queued while approved recipients stayed stable')
        self.assertEqual(len(queued), 1)
        second.approve_roster_fingerprints('gid', {'alice': self.identity.fingerprint})
        self.assertEqual(self.vault.approved_roster('gid'), {'alice': self.identity.fingerprint})

    def test_acceptance_write_failure_does_not_pin_sender_or_store_observation(self):
        with patch('chatroom_client.key_vault.os.replace', side_effect=OSError('disk full')):
            with self.assertRaises(VaultError):
                self.vault.accept_envelope('bob', self.bob.public_bundle(), 'a' * 32, 11, '1' * 64)
        self.assertIsNone(self.vault.peer('bob'))
        self.assertIsNone(self.vault.known_record(self.bob.fingerprint, 'a' * 32))

    def test_encrypted_backup_rebind_requires_explicit_same_account_consent(self):
        backup = Path(self.tmp.name) / 'backup.json'
        self.vault.export_to(backup)
        endpoint = ('migrated.example', 12346)
        restored = KeyVault(Path(self.tmp.name) / 'new' / 'alice.json', endpoint, 'alice')
        with self.assertRaises(VaultError):
            restored.import_from(backup, PASSPHRASE)
        self.assertFalse(restored.exists)
        self.assertEqual(restored.import_from(backup, PASSPHRASE, allow_rebind=True).fingerprint,
                         self.identity.fingerprint)
        self.assertEqual(json.loads(restored.path.read_bytes())['scope']['endpoint'], list(endpoint))
        self.assertNotEqual(json.loads(backup.read_bytes())['nonce'], json.loads(restored.path.read_bytes())['nonce'])
        self.assertEqual(KeyVault(restored.path, endpoint, 'alice').unlock(PASSPHRASE).fingerprint,
                         self.identity.fingerprint)
        wrong_account = KeyVault(Path(self.tmp.name) / 'bob.json', endpoint, 'bob')
        with self.assertRaises(VaultError):
            wrong_account.import_from(backup, PASSPHRASE, allow_rebind=True)
        self.assertFalse(wrong_account.exists)
        document = json.loads(backup.read_bytes())
        document['scope']['endpoint'][1] += 1
        backup.write_text(json.dumps(document))
        damaged = KeyVault(Path(self.tmp.name) / 'damaged.json', endpoint, 'alice')
        with self.assertRaises(VaultError):
            damaged.import_from(backup, PASSPHRASE, allow_rebind=True)
        self.assertFalse(damaged.exists)

    def test_overwrite_prompt_error_is_raised_only_after_valid_backup_verification(self):
        backup = Path(self.tmp.name) / 'backup.json'
        self.vault.export_to(backup)
        self.path.write_bytes(b'{damaged current vault')
        with self.assertRaises(VaultExistsError):
            self.vault.import_from(backup, PASSPHRASE)
        self.assertEqual(self.path.read_bytes(), b'{damaged current vault')
        with self.assertRaises(VaultError) as raised:
            self.vault.import_from(backup, 'incorrect passphrase')
        self.assertNotIsInstance(raised.exception, VaultExistsError)
        restored = self.vault.import_from(backup, PASSPHRASE, replace=True)
        self.assertEqual(restored.fingerprint, self.identity.fingerprint)

    def test_observed_signed_message_ids_survive_restart_and_repeats_do_not_save(self):
        sender, identifier = self.bob.fingerprint, 'ab' * 16
        self.assertTrue(self.vault.observe_envelope(sender, identifier, 42))
        original = self.path.read_bytes()
        with patch('chatroom_client.key_vault._atomic_write', side_effect=AssertionError('unneeded save')):
            self.assertTrue(self.vault.observe_envelope(sender, identifier, 42))
            self.assertFalse(self.vault.observe_envelope(sender, identifier, 43))
        self.assertEqual(self.path.read_bytes(), original)
        reopened = KeyVault(self.path, ENDPOINT, 'alice')
        reopened.unlock(PASSPHRASE)
        self.assertFalse(reopened.observe_envelope(sender, identifier, 43))
        self.assertTrue(reopened.observe_envelope(sender, identifier, 42))

    def test_replay_observation_rereads_other_instances_and_validates_identifiers(self):
        second = KeyVault(self.path, ENDPOINT, 'alice')
        second.unlock(PASSPHRASE)
        sender, identifier = self.bob.fingerprint, 'ef' * 16
        self.assertTrue(self.vault.observe_envelope(sender, identifier, 51))
        self.assertFalse(second.observe_envelope(sender, identifier, 52))
        self.assertTrue(second.observe_envelope(sender, identifier, 51))
        original = self.path.read_bytes()
        for args in ((sender, identifier, True), (sender, identifier, 0),
                     (sender, identifier, 2**63), ('bad', identifier, 1), (sender, 'bad', 1)):
            with self.subTest(args=args), self.assertRaises(VaultError):
                self.vault.observe_envelope(*args)
        self.assertEqual(self.path.read_bytes(), original)

    def test_replay_limit_evicts_oldest_insertion_across_restart(self):
        sender = self.bob.fingerprint
        # Deliberately use reverse lexical order to detect sorted-JSON eviction.
        oldest, middle, newest = 'ff' * 16, 'bb' * 16, 'aa' * 16
        with patch('chatroom_client.key_vault.MAX_REPLAY_RECORDS', 2):
            self.assertTrue(self.vault.observe_envelope(sender, oldest, 1))
            self.assertTrue(self.vault.observe_envelope(sender, middle, 2))
            reopened = KeyVault(self.path, ENDPOINT, 'alice')
            reopened.unlock(PASSPHRASE)
            self.assertTrue(reopened.observe_envelope(sender, newest, 3))
            self.assertFalse(reopened.observe_envelope(sender, middle, 20))
            self.assertTrue(reopened.observe_envelope(sender, oldest, 10))


if __name__ == '__main__':
    unittest.main()
