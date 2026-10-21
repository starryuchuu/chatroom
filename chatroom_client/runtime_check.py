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
