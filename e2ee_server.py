"""Authenticated public identities and opaque, signed chat envelopes.

Only public keys and ciphertext enter this module.  Message encryption keys and
message plaintext belong exclusively to the clients.
"""
from contextlib import closing
import hashlib
import json

from chatroom_client import e2ee_crypto
import storage


MAX_RECIPIENTS = 256


class E2EEError(ValueError):
    """A key or envelope must not be trusted, stored, or downgraded."""


def canonical(value):
    return e2ee_crypto.canonical_json(value)


def _text(value, *, limit=256):
    if not isinstance(value, str) or not 1 <= len(value) <= limit:
        raise E2EEError('端到端加密标识格式错误')
    try:
        value.encode('utf-8')
    except UnicodeError as error:
        raise E2EEError('端到端加密标识包含无效字符') from error
    return value


def validate_identity(identity):
    try:
        return e2ee_crypto.validate_public_bundle(identity)
    except e2ee_crypto.E2EEError as error:
        raise E2EEError(str(error)) from error


def fingerprint(identity):
    return hashlib.sha256(canonical(validate_identity(identity))).hexdigest()


def _get_identity(db, username):
    token = storage.token(username)
    row = db.execute('SELECT identity FROM e2ee_identities WHERE username=?', (token,)).fetchone()
    if row is None:
        return None
    identity = json.loads(storage.open_field(row[0], 'e2ee_identities', 'identity', token))
    return validate_identity(identity)


def get_identity(username):
    with closing(storage.connect()) as db:
        return _get_identity(db, username)


def identities_for(members):
    members = sorted({_text(name) for name in members})
    if not 1 <= len(members) <= MAX_RECIPIENTS:
        raise E2EEError('端到端加密会话最多支持 256 位成员')
    identities = {}
    with closing(storage.connect()) as db:
        for member in members:
            identity = _get_identity(db, member)
            if identity is not None:
                identities[member] = identity
    return identities, [member for member in members if member not in identities]


def publish_identity(username, identity, proof):
    username = _text(username)
    identity = validate_identity(identity)
    try:
        e2ee_crypto.verify_publication(identity, username, proof)
    except e2ee_crypto.E2EEError as error:
        raise E2EEError('端到端身份签名验证失败') from error
    with closing(storage.connect()) as db:
        db.execute('BEGIN IMMEDIATE')
        try:
            existing = _get_identity(db, username)
            if existing is not None:
                if existing != identity:
                    raise E2EEError('此账号已绑定其他端到端密钥，请导入原密钥备份')
            else:
                token = storage.token(username)
                db.execute('INSERT INTO e2ee_identities(username,identity) VALUES(?,?)',
                           (token, storage.seal(canonical(identity).decode('ascii'),
                                                'e2ee_identities', 'identity', token)))
            db.commit()
        except Exception:
            db.rollback()
            raise
    return identity


def reject_legacy(members):
    # Preserve messaging for historical all-legacy groups, including oversized
    # groups that must remain manageable while membership is reduced.
    with closing(storage.connect()) as db:
        for member in members:
            if _get_identity(db, member) is not None:
                raise E2EEError('此会话已启用端到端加密，请升级客户端；拒绝发送非端到端加密消息')


def validate_envelope(envelope, sender, kind, target, members):
    """Verify public signatures and routing without opening the encrypted body."""
    try:
        envelope = e2ee_crypto.validate_envelope(envelope)
    except e2ee_crypto.E2EEError as error:
        raise E2EEError(str(error)) from error
    members = sorted({_text(member) for member in members})
    identities, missing = identities_for(members)
    if missing:
        raise E2EEError('会话成员尚未配置端到端密钥，请先升级并登录客户端')
    if (envelope['sender'] != sender or envelope['kind'] != kind or
            envelope['target'] != target or sender not in identities):
        raise E2EEError('端到端加密消息的发送者或会话不匹配')
    _text(envelope['sender'])
    _text(envelope['target'])
    if validate_identity(envelope['sender_key']) != identities[sender]:
        raise E2EEError('端到端发送者身份与已绑定密钥不匹配')
    recipients, keys = envelope['recipients'], envelope['keys']
    if (not isinstance(recipients, dict) or not isinstance(keys, dict) or
            set(recipients) != set(members) or set(keys) != set(members)):
        raise E2EEError('会话成员已变化，请刷新并重新确认端到端成员')
    for member in members:
        if recipients[member] != fingerprint(identities[member]):
            raise E2EEError('会话成员端到端密钥已变化，拒绝发送消息')
    try:
        e2ee_crypto.verify_signature(envelope, identities[sender])
    except e2ee_crypto.E2EEError as error:
        raise E2EEError('端到端消息签名验证失败') from error
    # A JSON copy prevents later mutation of the object that was verified.
    return json.loads(canonical(envelope))
