"""Authenticated, client-only message envelopes.

The server routes these envelopes but never receives a private key or a content
key. Identity trust belongs to the caller: signatures authenticate a *pinned*
identity, and first-use fingerprints still need an independent comparison to
detect a malicious directory. This protocol does not provide forward secrecy
against later compromise of a recipient's long-term exchange key.
"""
import base64
import binascii
from functools import lru_cache
import json
import re
import uuid

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.DH import import_x25519_public_key, key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Signature import eddsa


MAX_PLAINTEXT_BYTES = 256 * 1024
MAX_RECIPIENTS = 256
MAX_ENVELOPE_BYTES = 1024 * 1024 - 4096
_SIGNATURE_DOMAIN = b'chatroom-e2ee-envelope-v1\0'
_PUBLICATION_DOMAIN = b'chatroom-e2ee-key-v1\0'
_WRAP_DOMAIN = b'chatroom-e2ee-wrap-v1\0'
_PUBLIC_FIELDS = {'v', 'sign', 'exchange'}
_ENVELOPE_FIELDS = {'v', 'id', 'kind', 'sender', 'target', 'sender_key',
                    'recipients', 'ephemeral', 'nonce', 'body', 'keys', 'signature'}
_ED25519_ORDER = 2**252 + 27742317777372353535851937790883648493


class E2EEError(ValueError):
    """An identity or encrypted message could not be safely used."""


def canonical_json(value):
    """The signed wire representation, including ASCII escapes for Unicode."""
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False).encode('ascii')
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise E2EEError('端到端数据格式错误') from error


def _encode(value):
    return base64.b64encode(value).decode('ascii')


def _decode(value, *, size=None, maximum=None):
    if not isinstance(value, str):
        raise E2EEError('端到端数据编码错误')
    limit = size if size is not None else maximum
    if limit is not None and len(value) > 4 * ((limit + 2) // 3):
        raise E2EEError('端到端数据长度错误')
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError, binascii.Error) as error:
        raise E2EEError('端到端数据编码错误') from error
    if (_encode(decoded) != value or (size is not None and len(decoded) != size)
            or (maximum is not None and len(decoded) > maximum)):
        raise E2EEError('端到端数据长度或编码错误')
    return decoded


def _name(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        raise E2EEError('端到端账号或会话标识错误')
    try:
        if len(value.encode('utf-8')) > 1024:
            raise E2EEError('端到端账号或会话标识过长')
    except UnicodeError as error:
        raise E2EEError('端到端账号或会话标识错误') from error
    return value


@lru_cache(maxsize=2048)
def _exchange_public(raw):
    try:
        key = import_x25519_public_key(raw)
        # Reject aliases and low-order/all-zero points. The fixed scalar here
        # only validates public input; it is never used to encrypt a message.
        if key.export_key(format='raw') != raw:
            raise E2EEError('端到端公钥编码不规范')
        validation_key = ECC.construct(curve='Curve25519', seed=b'\x42' * 32)
        key_agreement(static_priv=validation_key, static_pub=key, kdf=lambda value: value)
        return key
    except (ValueError, TypeError) as error:
        raise E2EEError('端到端交换公钥无效') from error


@lru_cache(maxsize=2048)
def _signing_public(raw):
    try:
        key = eddsa.import_public_key(raw)
        point = key.pointQ
        if (key.export_key(format='raw') != raw or point.is_point_at_infinity()
                or not (point * _ED25519_ORDER).is_point_at_infinity()):
            raise E2EEError('端到端签名公钥无效')
        return key
    except (ValueError, TypeError) as error:
        raise E2EEError('端到端签名公钥无效') from error


def validate_public_bundle(bundle):
    if (not isinstance(bundle, dict) or set(bundle) != _PUBLIC_FIELDS
            or type(bundle.get('v')) is not int or bundle['v'] != 1):
        raise E2EEError('不支持的端到端公钥格式')
    _signing_public(_decode(bundle['sign'], size=32))
    _exchange_public(_decode(bundle['exchange'], size=32))
    return {'v': 1, 'sign': bundle['sign'], 'exchange': bundle['exchange']}


def bundle_fingerprint(bundle):
    return SHA256.new(canonical_json(validate_public_bundle(bundle))).hexdigest()


class Identity:
    """Two independent private seeds; repr never includes private material."""

    __slots__ = ('_sign', '_exchange')

    def __init__(self, signing, exchange):
        if not signing.has_private() or not exchange.has_private():
            raise E2EEError('端到端私钥不可用')
        self._sign, self._exchange = signing, exchange

    @classmethod
    def generate(cls):
        return cls(ECC.generate(curve='Ed25519'), ECC.generate(curve='Curve25519'))

    @classmethod
    def from_private(cls, value):
        if (not isinstance(value, dict) or set(value) != _PUBLIC_FIELDS
                or type(value.get('v')) is not int or value['v'] != 1):
            raise E2EEError('端到端私钥格式错误')
        try:
            return cls(ECC.construct(curve='Ed25519', seed=_decode(value['sign'], size=32)),
                       ECC.construct(curve='Curve25519', seed=_decode(value['exchange'], size=32)))
        except (ValueError, TypeError) as error:
            raise E2EEError('端到端私钥格式错误') from error

    def export_private(self):
        return {'v': 1, 'sign': _encode(self._sign.seed), 'exchange': _encode(self._exchange.seed)}

    def public_bundle(self):
        return {'v': 1, 'sign': _encode(self._sign.public_key().export_key(format='raw')),
                'exchange': _encode(self._exchange.public_key().export_key(format='raw'))}

    @property
    def fingerprint(self):
        return bundle_fingerprint(self.public_bundle())

    def __repr__(self):
        return f'<Identity fingerprint={self.fingerprint}>'


def _publication_bytes(bundle, username):
    _name(username)
    bundle = validate_public_bundle(bundle)
    return (_PUBLICATION_DOMAIN + username.encode('utf-8') + b'\0'
            + _decode(bundle['sign'], size=32) + _decode(bundle['exchange'], size=32))


def publish_proof(identity, username):
    return _encode(eddsa.new(identity._sign, mode='rfc8032').sign(
        _publication_bytes(identity.public_bundle(), username)))


def verify_publication(bundle, username, proof):
    value = _publication_bytes(bundle, username)
    try:
        eddsa.new(_signing_public(_decode(bundle['sign'], size=32)), mode='rfc8032').verify(
            value, _decode(proof, size=64))
    except (ValueError, TypeError) as error:
        raise E2EEError('端到端公钥持有证明无效') from error
    return True


def _header(envelope):
    return {field: value for field, value in envelope.items() if field not in ('body', 'keys', 'signature')}


def _signing_bytes(envelope):
    return _SIGNATURE_DOMAIN + canonical_json({field: value for field, value in envelope.items()
                                              if field != 'signature'})


def validate_envelope(envelope):
    """Bounded structural validation. Use verify_signature to authenticate it."""
    if (not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_FIELDS
            or type(envelope.get('v')) is not int or envelope['v'] != 1):
        raise E2EEError('不支持的端到端消息格式')
    if not isinstance(envelope['id'], str) or re.fullmatch(r'[0-9a-f]{32}', envelope['id']) is None:
        raise E2EEError('端到端消息编号错误')
    if envelope['kind'] not in ('private', 'group'):
        raise E2EEError('端到端会话类型错误')
    sender, target = _name(envelope['sender']), _name(envelope['target'])
    sender_bundle = validate_public_bundle(envelope['sender_key'])
    recipients, keys = envelope['recipients'], envelope['keys']
    if (not isinstance(recipients, dict) or not 1 <= len(recipients) <= MAX_RECIPIENTS
            or not isinstance(keys, dict) or set(keys) != set(recipients) or sender not in recipients):
        raise E2EEError('端到端收件人列表错误')
    if envelope['kind'] == 'private' and set(recipients) != {sender, target}:
        raise E2EEError('私聊端到端收件人列表错误')
    for username, fingerprint in recipients.items():
        _name(username)
        if not isinstance(fingerprint, str) or re.fullmatch(r'[0-9a-f]{64}', fingerprint) is None:
            raise E2EEError('端到端收件人指纹错误')
        _decode(keys[username], size=60)
    if recipients[sender] != bundle_fingerprint(sender_bundle):
        raise E2EEError('端到端发送者身份不一致')
    _exchange_public(_decode(envelope['ephemeral'], size=32))
    _decode(envelope['nonce'], size=12)
    if len(_decode(envelope['body'], maximum=MAX_PLAINTEXT_BYTES + 16)) < 16:
        raise E2EEError('端到端消息正文格式错误')
    _decode(envelope['signature'], size=64)
    encoded = canonical_json(envelope)
    if len(encoded) > MAX_ENVELOPE_BYTES:
        raise E2EEError('端到端消息包过大')
    return json.loads(encoded)


def verify_signature(envelope, pinned_sender_bundle=None):
    envelope = validate_envelope(envelope)
    bundle = envelope['sender_key']
    if (pinned_sender_bundle is not None
            and bundle_fingerprint(pinned_sender_bundle) != bundle_fingerprint(bundle)):
        raise E2EEError('发送者端到端身份已变化，请先核验安全指纹')
    try:
        eddsa.new(_signing_public(_decode(bundle['sign'], size=32)), mode='rfc8032').verify(
            _signing_bytes(envelope), _decode(envelope['signature'], size=64))
    except (ValueError, TypeError) as error:
        raise E2EEError('端到端消息签名无效') from error
    return True


def encrypt_message(identity, sender, kind, target, plaintext, recipients, *, message_id=None):
    """Encrypt once and wrap its random content key for each approved recipient."""
    _name(sender)
    _name(target)
    if kind not in ('private', 'group') or not isinstance(plaintext, str):
        raise E2EEError('端到端消息或会话格式错误')
    try:
        encoded = plaintext.encode('utf-8')
    except UnicodeError as error:
        raise E2EEError('端到端消息正文编码错误') from error
    if len(encoded) > MAX_PLAINTEXT_BYTES:
        raise E2EEError('端到端消息正文超过 256 KiB')
    if not isinstance(recipients, dict) or not 1 <= len(recipients) <= MAX_RECIPIENTS:
        raise E2EEError('端到端收件人数须为 1–256')
    bundles = {_name(username): validate_public_bundle(bundle) for username, bundle in recipients.items()}
    if sender not in bundles or bundle_fingerprint(bundles[sender]) != identity.fingerprint:
        raise E2EEError('端到端发送者身份不一致')
    if kind == 'private' and set(bundles) != {sender, target}:
        raise E2EEError('私聊端到端收件人列表错误')
    identifier = message_id if message_id is not None else uuid.uuid4().hex
    if not isinstance(identifier, str) or re.fullmatch(r'[0-9a-f]{32}', identifier) is None:
        raise E2EEError('端到端消息编号错误')
    ephemeral = ECC.generate(curve='Curve25519')
    nonce = get_random_bytes(12)
    header = {'v': 1, 'id': identifier, 'kind': kind, 'sender': sender, 'target': target,
              'sender_key': identity.public_bundle(),
              'recipients': {username: bundle_fingerprint(bundle) for username, bundle in bundles.items()},
              'ephemeral': _encode(ephemeral.public_key().export_key(format='raw')), 'nonce': _encode(nonce)}
    header_bytes = canonical_json(header)
    header_hash = SHA256.new(header_bytes).digest()
    content_key = get_random_bytes(32)
    cipher = AES.new(content_key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(header_bytes)
    ciphertext, tag = cipher.encrypt_and_digest(encoded)
    wrapped = {}
    for username, bundle in bundles.items():
        try:
            shared = key_agreement(eph_priv=ephemeral,
                                   static_pub=_exchange_public(_decode(bundle['exchange'], size=32)),
                                   kdf=lambda value: value)
            context = canonical_json(username)
            wrapping_key = HKDF(shared, 32, header_hash, SHA256, context=_WRAP_DOMAIN + context)
            wrap_nonce = get_random_bytes(12)
            wrapper = AES.new(wrapping_key, AES.MODE_GCM, nonce=wrap_nonce, mac_len=16)
            wrapper.update(header_hash + context)
            wrapped_key, wrap_tag = wrapper.encrypt_and_digest(content_key)
            wrapped[username] = _encode(wrap_nonce + wrapped_key + wrap_tag)
        except (ValueError, TypeError) as error:
            raise E2EEError('无法为收件人加密消息') from error
    envelope = dict(header, body=_encode(ciphertext + tag), keys=wrapped)
    envelope['signature'] = _encode(eddsa.new(identity._sign, mode='rfc8032').sign(_signing_bytes(envelope)))
    return validate_envelope(envelope)


def decrypt_message(identity, username, envelope, *, expected_sender=None, expected_kind=None,
                    expected_target=None, pinned_sender_bundle=None):
    """Authenticate sender, routing and recipient binding before decrypting.

    The pinned sender is mandatory for other people's messages. Callers may
    establish a first-use pin only after their explicit trust policy is applied.
    """
    _name(username)
    envelope = validate_envelope(envelope)
    for field, expected in (('sender', expected_sender), ('kind', expected_kind), ('target', expected_target)):
        if expected is not None and envelope[field] != expected:
            raise E2EEError('端到端消息与当前会话不匹配')
    if username not in envelope['recipients'] or envelope['recipients'][username] != identity.fingerprint:
        raise E2EEError('此端到端消息未加密给当前本地身份')
    if envelope['sender'] == username:
        pinned_sender_bundle = identity.public_bundle()
    elif pinned_sender_bundle is None:
        raise E2EEError('发送者端到端身份尚未受信任，请先核验安全指纹')
    verify_signature(envelope, pinned_sender_bundle)
    header_bytes = canonical_json(_header(envelope))
    header_hash = SHA256.new(header_bytes).digest()
    context = canonical_json(username)
    try:
        shared = key_agreement(static_priv=identity._exchange,
                               eph_pub=_exchange_public(_decode(envelope['ephemeral'], size=32)),
                               kdf=lambda value: value)
        wrapping_key = HKDF(shared, 32, header_hash, SHA256, context=_WRAP_DOMAIN + context)
        wrapped = _decode(envelope['keys'][username], size=60)
        wrapper = AES.new(wrapping_key, AES.MODE_GCM, nonce=wrapped[:12], mac_len=16)
        wrapper.update(header_hash + context)
        content_key = wrapper.decrypt_and_verify(wrapped[12:-16], wrapped[-16:])
        cipher = AES.new(content_key, AES.MODE_GCM, nonce=_decode(envelope['nonce'], size=12), mac_len=16)
        cipher.update(header_bytes)
        body = _decode(envelope['body'], maximum=MAX_PLAINTEXT_BYTES + 16)
        return cipher.decrypt_and_verify(body[:-16], body[-16:]).decode('utf-8')
    except (ValueError, TypeError, UnicodeError) as error:
        raise E2EEError('端到端消息校验或解密失败') from error
