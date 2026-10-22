"""Exercise the actual encryption providers without a GUI, files, or server."""


def check_encryption_runtime():
    # Imports belong inside the check so the command-line entry point can
    # report missing frozen dependencies with a failing exit status.
    import base64
    from copy import deepcopy

    from .e2ee_crypto import (
        E2EEError, Identity, decrypt_message, encrypt_message,
        publish_proof, verify_publication,
    )
    from .key_vault import KeyVault

    sender, recipient = 'runtime-alice', 'runtime-bob'
    phrase = 'synthetic-runtime-only-vault-passphrase'
    plaintext = 'Encryption runtime self-check: 中文 🔐'
    vault = KeyVault(None, ('runtime-self-check.invalid', 443), sender)
    try:
        vault.unlock(phrase, create=True)
        fingerprint = vault.identity.fingerprint
        vault.lock()
        if vault.unlocked:
            raise RuntimeError('the in-memory vault did not lock')
        # This independently rederives Argon2id and authenticates/decrypts the
        # encrypted memory blob, rather than retaining an already-open key.
        vault.unlock(phrase)
        identity = vault.identity
        if identity.fingerprint != fingerprint:
            raise RuntimeError('vault unlock changed the local identity')

        # Exercise the bundled native OPAQUE provider and its identity envelope.
        from opaque_runtime import call
        server_id = 'e' * 64
        setup = call({'op': 'server_setup'})['setup']
        start = call({'op': 'registration_start', 'password': phrase})
        challenge = call({'op': 'registration_respond', 'setup': setup, 'request': start['request'],
                          'username': sender, 'server_id': server_id})
        registered = call({'op': 'registration_finish', 'password': phrase, 'state': start['state'],
                           'response': challenge['response'], 'username': sender, 'server_id': server_id})
        login = call({'op': 'login_start', 'password': phrase})
        challenge = call({'op': 'login_respond', 'setup': setup, 'record': registered['record'],
                          'request': login['request'], 'username': sender, 'server_id': server_id})
        finished = call({'op': 'login_finish', 'password': phrase, 'state': login['state'],
                         'response': challenge['response'], 'username': sender, 'server_id': server_id})
        verified = call({'op': 'login_verify', 'state': challenge['state'],
                         'finalization': finished['finalization']})
        if (registered['export_key'] != finished['export_key'] or
                verified['session_key'] != finished['session_key']):
            raise RuntimeError('OPAQUE authentication round trip failed')
        vault.unlock_opaque(finished['export_key'], server_id)
        backup = vault.opaque_backup(finished['export_key'], server_id)
        restored = KeyVault(None, ('runtime-self-check.invalid', 443), sender)
        try:
            restored.unlock_opaque(finished['export_key'], server_id, backup=backup,
                                   remote_identity=identity.public_bundle())
            if restored.identity.fingerprint != fingerprint:
                raise RuntimeError('OPAQUE identity backup changed identity')
        finally:
            restored.lock()

        other = Identity.generate()
        identity_bundle = identity.public_bundle()
        verify_publication(identity_bundle, sender, publish_proof(identity, sender))
        envelope = encrypt_message(identity, sender, 'private', recipient, plaintext,
                                   {sender: identity_bundle, recipient: other.public_bundle()})
        incoming = decrypt_message(other, recipient, envelope,
                                   expected_sender=sender, expected_kind='private',
                                   expected_target=recipient, pinned_sender_bundle=identity_bundle)
        outgoing = decrypt_message(identity, sender, envelope,
                                   expected_sender=sender, expected_kind='private',
                                   expected_target=recipient)
        if incoming != plaintext or outgoing != plaintext:
            raise RuntimeError('private encrypted message round trip failed')

        # Ensure the native signature verification path also rejects a changed
        # ciphertext, rather than only accepting data produced by the writer.
        damaged = deepcopy(envelope)
        body = bytearray(base64.b64decode(damaged['body']))
        body[0] ^= 1
        damaged['body'] = base64.b64encode(body).decode('ascii')
        try:
            decrypt_message(other, recipient, damaged, pinned_sender_bundle=identity_bundle)
        except E2EEError:
            pass
        else:
            raise RuntimeError('modified encrypted message was accepted')
    finally:
        vault.lock()
