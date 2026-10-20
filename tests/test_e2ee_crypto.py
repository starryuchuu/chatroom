"""Cryptographic tampering, identity trust and recipient-bound E2EE messages."""
import base64
from copy import deepcopy
import unittest

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

from chatroom_client import e2ee_crypto as crypto


def flipped(value, offset=0):
    raw = bytearray(base64.b64decode(value))
    raw[offset] ^= 1
    return base64.b64encode(raw).decode('ascii')


class IdentityTests(unittest.TestCase):
    def test_private_roundtrip_and_public_fingerprint(self):
        identity = crypto.Identity.generate()
        stored = identity.export_private()
        restored = crypto.Identity.from_private(stored)
        self.assertEqual(restored.public_bundle(), identity.public_bundle())
        self.assertEqual(restored.fingerprint, identity.fingerprint)
        self.assertRegex(identity.fingerprint, r'^[0-9a-f]{64}$')
        self.assertNotIn(stored['sign'], repr(identity))
        self.assertNotIn(stored['exchange'], repr(identity))
        stored['extra'] = True
        with self.assertRaises(crypto.E2EEError):
            crypto.Identity.from_private(stored)

    def test_publication_proves_both_keys_and_account(self):
        identity = crypto.Identity.generate()
        username = '鲤鱼😀'
        bundle = identity.public_bundle()
        proof = crypto.publish_proof(identity, username)
        self.assertTrue(crypto.verify_publication(bundle, username, proof))
        for candidate, account, signature in (
                (bundle, 'another account', proof),
                (bundle, username, flipped(proof)),
                (dict(bundle, exchange=crypto.Identity.generate().public_bundle()['exchange']), username, proof),
                (crypto.Identity.generate().public_bundle(), username, proof)):
            with self.subTest(account=account, bundle=candidate):
                with self.assertRaises(crypto.E2EEError):
                    crypto.verify_publication(candidate, account, signature)

    def test_bundle_rejects_ambiguous_or_weak_keys(self):
        bundle = crypto.Identity.generate().public_bundle()
        invalid = [dict(bundle, unknown='ignored'), dict(bundle, v=True), dict(bundle, sign='bad'),
                   dict(bundle, sign=base64.b64encode(b'\1' + b'\0' * 31).decode()),
                   dict(bundle, exchange=base64.b64encode(b'\0' * 32).decode()),
                   dict(bundle, exchange=bundle['exchange'] + '\n')]
        # Base64 with nonzero unused pad bits decodes to the same bytes, but
        # must not produce a second fingerprint for an identical public key.
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        encoded = bundle['exchange']
        alias = encoded[:-2] + alphabet[alphabet.index(encoded[-2]) | 1] + '='
        self.assertEqual(base64.b64decode(encoded), base64.b64decode(alias))
        invalid.append(dict(bundle, exchange=alias))
        for candidate in invalid:
            with self.subTest(candidate=candidate):
                with self.assertRaises(crypto.E2EEError):
                    crypto.validate_public_bundle(candidate)
        self.assertEqual(crypto.validate_public_bundle(bundle), bundle)

    def test_signing_public_key_rejects_torsion_and_mixed_order_points(self):
        # y = p - 1, x = 0 is the canonical Ed25519 point of order two.
        # Adding it to a valid prime-order public point is *not* a small-order
        # point: checking only [8]P != identity would incorrectly accept it.
        order_two = eddsa.import_public_key((2**255 - 20).to_bytes(32, 'little')).pointQ
        prime_order = ECC.construct(curve='Ed25519', seed=b'\x01' * 32).pointQ
        mixed_order = prime_order + order_two
        bundle = crypto.Identity.generate().public_bundle()
        self.assertFalse((mixed_order * 8).is_point_at_infinity())
        for point in (order_two, mixed_order):
            public = ECC.construct(curve='Ed25519', point_x=point.x, point_y=point.y)
            candidate = dict(bundle, sign=base64.b64encode(public.export_key(format='raw')).decode())
            with self.subTest(public=candidate['sign']), self.assertRaises(crypto.E2EEError):
                crypto.validate_public_bundle(candidate)


class EnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice, cls.bob, cls.carol = (crypto.Identity.generate() for _ in range(3))
        cls.bundles = {'alice': cls.alice.public_bundle(), 'bob': cls.bob.public_bundle(),
                       'carol': cls.carol.public_bundle()}

    def private(self, text='正文不能出现在服务端的记录里 🔐'):
        return crypto.encrypt_message(self.alice, 'alice', 'private', 'bob', text,
                                      {name: self.bundles[name] for name in ('alice', 'bob')})

    def decrypt_bob(self, envelope, **overrides):
        options = dict(expected_sender='alice', expected_kind='private', expected_target='bob',
                       pinned_sender_bundle=self.bundles['alice'])
        options.update(overrides)
        return crypto.decrypt_message(self.bob, 'bob', envelope, **options)

    def test_private_message_is_readable_by_both_participants_only(self):
        text = '正文不能出现在服务端的记录里 🔐'
        envelope = self.private(text)
        self.assertEqual(self.decrypt_bob(envelope), text)
        self.assertEqual(crypto.decrypt_message(self.alice, 'alice', envelope), text)
        self.assertNotIn(text.encode('utf-8'), crypto.canonical_json(envelope))
        self.assertNotIn(self.alice.export_private()['sign'], crypto.canonical_json(envelope).decode())
        with self.assertRaises(crypto.E2EEError):
            crypto.decrypt_message(self.carol, 'carol', envelope, pinned_sender_bundle=self.bundles['alice'])
        with self.assertRaises(crypto.E2EEError):
            crypto.decrypt_message(self.carol, 'bob', envelope, pinned_sender_bundle=self.bundles['alice'])

    def test_group_membership_changes_use_new_independent_recipient_keys(self):
        old = crypto.encrypt_message(self.alice, 'alice', 'group', 'group-id', 'before removal', self.bundles)
        later = crypto.encrypt_message(self.alice, 'alice', 'group', 'group-id', 'after removal',
                                       {name: self.bundles[name] for name in ('alice', 'bob')})
        self.assertEqual(crypto.decrypt_message(self.carol, 'carol', old,
                                               pinned_sender_bundle=self.bundles['alice']), 'before removal')
        with self.assertRaises(crypto.E2EEError):
            crypto.decrypt_message(self.carol, 'carol', later, pinned_sender_bundle=self.bundles['alice'])
        self.assertEqual(crypto.decrypt_message(self.bob, 'bob', later,
                                               expected_kind='group', expected_target='group-id',
                                               pinned_sender_bundle=self.bundles['alice']), 'after removal')
        self.assertNotEqual(old['ephemeral'], later['ephemeral'])
        self.assertNotEqual(old['keys']['bob'], later['keys']['bob'])
        self.assertNotEqual(old['body'], later['body'])

    def test_trust_and_wire_conversation_bindings_are_required(self):
        envelope = self.private()
        with self.assertRaises(crypto.E2EEError):
            crypto.decrypt_message(self.bob, 'bob', envelope)
        for overrides in ({'expected_target': 'alice'}, {'expected_sender': 'carol'},
                          {'expected_kind': 'group'}, {'pinned_sender_bundle': self.bundles['carol']}):
            with self.subTest(overrides=overrides):
                with self.assertRaises(crypto.E2EEError):
                    self.decrypt_bob(envelope, **overrides)

    def test_signature_rejects_each_sensitive_header_and_ciphertext_mutation(self):
        envelope = self.private()
        candidates = []
        for field in ('nonce', 'body', 'signature', 'ephemeral'):
            candidate = deepcopy(envelope)
            candidate[field] = flipped(candidate[field])
            candidates.append(candidate)
        for field, value in (('id', 'a' * 32), ('sender', 'mallory'), ('target', 'carol'), ('kind', 'group')):
            candidate = deepcopy(envelope)
            candidate[field] = value
            candidates.append(candidate)
        candidate = deepcopy(envelope)
        candidate['keys']['bob'] = flipped(candidate['keys']['bob'])
        candidates.append(candidate)
        candidate = deepcopy(envelope)
        candidate['recipients']['bob'] = self.carol.fingerprint
        candidates.append(candidate)
        for candidate in candidates:
            with self.subTest(changed=[key for key in candidate if candidate[key] != envelope[key]]):
                with self.assertRaises(crypto.E2EEError):
                    self.decrypt_bob(candidate)

    def test_valid_signatures_do_not_bypass_gcm_authentication(self):
        envelope = self.private()
        for field in ('body', 'keys'):
            candidate = deepcopy(envelope)
            if field == 'body':
                candidate['body'] = flipped(candidate['body'])
            else:
                candidate['keys']['bob'] = flipped(candidate['keys']['bob'], 12)
            signed = {key: value for key, value in candidate.items() if key != 'signature'}
            candidate['signature'] = base64.b64encode(eddsa.new(self.alice._sign, mode='rfc8032').sign(
                b'chatroom-e2ee-envelope-v1\0' + crypto.canonical_json(signed))).decode('ascii')
            self.assertTrue(crypto.verify_signature(candidate, self.bundles['alice']))
            with self.assertRaisesRegex(crypto.E2EEError, '校验或解密失败'):
                self.decrypt_bob(candidate)

    def test_sender_directory_substitution_cannot_replace_a_pin(self):
        attacker = crypto.Identity.generate()
        forged = crypto.encrypt_message(attacker, 'alice', 'private', 'bob', 'forged sender',
                                        {'alice': attacker.public_bundle(), 'bob': self.bundles['bob']})
        self.assertTrue(crypto.verify_signature(forged))
        with self.assertRaisesRegex(crypto.E2EEError, '身份已变化'):
            self.decrypt_bob(forged)

    def test_unicode_canonicalization_and_publication_are_stable(self):
        alice, bob = 'alice😀', '鲤鱼𝄞'
        target = '群聊<>&\u2028\u2029/🔐'
        envelope = crypto.encrypt_message(self.alice, alice, 'group', target, '日本語 / 🔐',
                                          {alice: self.bundles['alice'], bob: self.bundles['bob']})
        encoded = crypto.canonical_json(envelope)
        self.assertIn(b'\\ud83d\\ude00', encoded)
        self.assertIn(b'<>&\\u2028\\u2029/', encoded)
        self.assertEqual(crypto.decrypt_message(self.bob, bob, envelope, expected_target=target,
                                               pinned_sender_bundle=self.bundles['alice']), '日本語 / 🔐')

    def test_structural_validation_is_strict_and_bounded(self):
        envelope = self.private()
        candidates = [dict(envelope, ignored='extension'), dict(envelope, v=True), dict(envelope, id='A' * 32),
                      dict(envelope, signature=''), dict(envelope, body=''),
                      dict(envelope, keys={'alice': envelope['keys']['alice']}),
                      dict(envelope, sender_key=dict(self.bundles['alice'], extra=True))]
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                with self.assertRaises(crypto.E2EEError):
                    crypto.validate_envelope(candidate)
        with self.assertRaises(crypto.E2EEError):
            crypto.encrypt_message(self.alice, 'alice', 'private', 'bob', 'x', {'alice': self.bundles['alice']})
        with self.assertRaises(crypto.E2EEError):
            crypto.encrypt_message(self.alice, 'alice', 'group', 'gid', 'x',
                                   {str(number): self.bundles['alice'] for number in range(257)})

    def test_plaintext_byte_limit_and_fresh_randomness(self):
        envelope = self.private('x' * crypto.MAX_PLAINTEXT_BYTES)
        self.assertEqual(len(self.decrypt_bob(envelope)), crypto.MAX_PLAINTEXT_BYTES)
        with self.assertRaises(crypto.E2EEError):
            self.private('界' * (crypto.MAX_PLAINTEXT_BYTES // 3 + 1))
        first, second = self.private('same message'), self.private('same message')
        for field in ('id', 'ephemeral', 'nonce', 'body', 'keys', 'signature'):
            self.assertNotEqual(first[field], second[field])


if __name__ == '__main__':
    unittest.main()
