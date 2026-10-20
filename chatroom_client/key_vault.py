"""Local, passphrase-encrypted E2EE identities and trust decisions.

This file is never uploaded to the chat server. Its independent passphrase is
deliberately unrelated to the password sent to the server for authentication.
Public fingerprints can be compared out of band; a first-use pin is not proof
that the directory supplied the intended person's key.
"""
from contextlib import contextmanager, nullcontext
from copy import deepcopy
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from .e2ee_crypto import Identity, bundle_fingerprint, validate_public_bundle
from .preferences import _preferences_lock


MAX_VAULT_BYTES = 8 * 1024 * 1024
MAX_TRUST_HISTORY = 64
_KDF = {'name': 'argon2id', 'memory': 65536, 'time': 3, 'parallelism': 1}
_HEX = re.compile(r'[0-9a-f]{64}')
_UNSET = object()
_REPLAY_KEY = re.compile(r'[0-9a-f]{64}:[0-9a-f]{32}')
MAX_REPLAY_RECORDS = 10000


class VaultError(ValueError):
    """A vault could not be validated, unlocked, or safely updated."""


class VaultLockedError(VaultError):
    """Private keys are unavailable until the local vault is unlocked."""


class VaultExistsError(VaultError):
    """A valid backup was decoded, but replacing a local vault needs consent."""


class PeerKeyChanged(VaultError):
    def __init__(self, username, expected, actual):
        self.username, self.expected, self.actual = username, expected, actual
        super().__init__(f'{username} 的端到端加密密钥已变化，请核验安全指纹后再继续')


class _Unchanged:
    def __init__(self, result):
        self.result = result


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _name(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        raise VaultError('密钥标识格式错误')
    try:
        value.encode('utf-8')
    except UnicodeError as error:
        raise VaultError('密钥标识格式错误') from error
    return value


def _scope(endpoint, username):
    if (not isinstance(endpoint, (tuple, list)) or len(endpoint) != 2 or
            not isinstance(endpoint[0], str) or not 1 <= len(endpoint[0]) <= 253 or
            type(endpoint[1]) is not int or not 1 <= endpoint[1] <= 65535):
        raise VaultError('密钥所属服务器格式错误')
    return {'endpoint': [endpoint[0].lower(), endpoint[1]], 'username': _name(username)}


def vault_path(config_path, endpoint, username):
    """Derive a private per-server/account path, or an entirely in-memory vault."""
    if config_path is None:
        return None
    identifier = hashlib.sha256(_canonical(_scope(endpoint, username))).hexdigest()
    return Path(config_path).parent / 'e2ee' / (identifier + '.json')


def _passphrase(value):
    if not isinstance(value, str) or not 8 <= len(value) <= 1024:
        raise VaultError('本地密钥口令须为 8–1024 个字符，建议至少 12 个字符')
    try:
        return value.encode('utf-8')
    except UnicodeError as error:
        raise VaultError('本地密钥口令格式错误') from error


def _b64(value):
    return base64.b64encode(value).decode('ascii')


def _unb64(value, *, length=None):
    if not isinstance(value, str) or len(value) > MAX_VAULT_BYTES:
        raise VaultError('本地密钥文件格式错误')
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise VaultError('本地密钥文件格式错误') from error
    if _b64(decoded) != value or (length is not None and len(decoded) != length):
        raise VaultError('本地密钥文件格式错误')
    return decoded


def _json(blob):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise VaultError('本地密钥文件包含重复字段')
            result[key] = value
        return result
    if not isinstance(blob, bytes) or len(blob) > MAX_VAULT_BYTES:
        raise VaultError('本地密钥文件超过大小限制')
    try:
        return json.loads(blob.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(VaultError('本地密钥文件格式错误')))
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise VaultError('本地密钥文件格式错误') from error


def _read_file(path):
    with Path(path).open('rb') as source:
        blob = source.read(MAX_VAULT_BYTES + 1)
    if len(blob) > MAX_VAULT_BYTES:
        raise VaultError('本地密钥文件超过大小限制')
    return blob


def _atomic_write(path, blob):
    if len(blob) > MAX_VAULT_BYTES:
        raise VaultError('本地密钥文件超过大小限制')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix='.vault-', suffix='.tmp', dir=path.parent)
        with os.fdopen(descriptor, 'wb') as destination:
            destination.write(blob)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


class KeyVault:
    """An explicitly unlocked local identity with copy-on-write trust metadata.

    Every persistent mutation rereads under the stable sibling file lock. A
    missing, changed, or damaged file never regenerates or replaces an identity
    implicitly. ``path=None`` provides the same encryption semantics in memory.
    """
    def __init__(self, path, endpoint, username):
        self.path = Path(path) if path is not None else None
        self.scope = _scope(endpoint, username)
        self._memory_blob = None
        self._data = self._identity = self._secret = self._salt = self._key = None

    @property
    def exists(self):
        return self.path.exists() if self.path is not None else self._memory_blob is not None

    @property
    def unlocked(self):
        return self._identity is not None

    @property
    def identity(self):
        if not self.unlocked:
            raise VaultLockedError('请先解锁本地端到端加密密钥')
        return self._identity

    def _guard(self, *, create=False):
        if self.path is None:
            return nullcontext()
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        return _preferences_lock(self.path)

    def _blob(self):
        if self.path is None:
            if self._memory_blob is None:
                raise FileNotFoundError('本地密钥文件不存在')
            return self._memory_blob
        return _read_file(self.path)

    @staticmethod
    def _validate_data(data):
        required = {'v', 'identity', 'peers', 'groups'}
        if (not isinstance(data, dict) or not required <= set(data) or
                set(data) - (required | {'replays', 'group_history', 'peer_history'}) or
                type(data['v']) is not int or data['v'] != 1):
            raise VaultError('本地密钥数据格式错误')
        identity = Identity.from_private(data['identity'])
        peers, groups = data['peers'], data['groups']
        if not isinstance(peers, dict) or len(peers) > 10000 or not isinstance(groups, dict) or len(groups) > 10000:
            raise VaultError('本地密钥数据格式错误')
        for name, record in peers.items():
            _name(name)
            if (not isinstance(record, dict) or set(record) != {'bundle', 'verified'} or
                    type(record['verified']) is not bool):
                raise VaultError('本地信任记录格式错误')
            validate_public_bundle(record['bundle'])
        for gid, roster in groups.items():
            _name(gid)
            if not isinstance(roster, dict) or not 1 <= len(roster) <= 256:
                raise VaultError('群收件人记录格式错误')
            for name, fingerprint in roster.items():
                _name(name)
                if not isinstance(fingerprint, str) or not _HEX.fullmatch(fingerprint):
                    raise VaultError('群收件人记录格式错误')
        group_history = data.setdefault('group_history', {})
        peer_history = data.setdefault('peer_history', {})
        if (not isinstance(group_history, dict) or len(group_history) > 10000 or
                not isinstance(peer_history, dict) or len(peer_history) > 10000):
            raise VaultError('历史信任记录格式错误')
        for gid, epochs in group_history.items():
            _name(gid)
            if not isinstance(epochs, list) or not 1 <= len(epochs) <= MAX_TRUST_HISTORY:
                raise VaultError('群历史收件人记录格式错误')
            for roster in epochs:
                if not isinstance(roster, dict) or not 1 <= len(roster) <= 256:
                    raise VaultError('群历史收件人记录格式错误')
                for name, fingerprint in roster.items():
                    _name(name)
                    if not isinstance(fingerprint, str) or not _HEX.fullmatch(fingerprint):
                        raise VaultError('群历史收件人记录格式错误')
        for name, bundles in peer_history.items():
            _name(name)
            if not isinstance(bundles, list) or not 1 <= len(bundles) <= MAX_TRUST_HISTORY:
                raise VaultError('历史公钥记录格式错误')
            for bundle in bundles:
                validate_public_bundle(bundle)
        replays = data.setdefault('replays', {})
        if not isinstance(replays, dict) or len(replays) > MAX_REPLAY_RECORDS:
            raise VaultError('消息重放记录格式错误')
        for key, record in replays.items():
            if not isinstance(key, str) or not _REPLAY_KEY.fullmatch(key):
                raise VaultError('消息重放记录格式错误')
            KeyVault._replay_record(record)
        return identity

    def _decode(self, blob, secret, *, cached=True):
        document = _json(blob)
        required = {'v', 'scope', 'kdf', 'salt', 'nonce', 'data'}
        if (not isinstance(document, dict) or set(document) != required or
                type(document['v']) is not int or document['v'] != 1 or
                document['scope'] != self.scope or document['kdf'] != _KDF or
                any(type(document['kdf'].get(key)) is not int for key in ('memory', 'time', 'parallelism'))):
            raise VaultError('本地密钥版本、服务器或账号不匹配')
        salt, nonce = _unb64(document['salt'], length=16), _unb64(document['nonce'], length=12)
        ciphertext = _unb64(document['data'])
        if len(ciphertext) < 16:
            raise VaultError('本地密钥文件格式错误')
        key = (self._key if cached and self._key is not None and salt == self._salt else
               hash_secret_raw(bytes(secret), salt, time_cost=3, memory_cost=65536,
                               parallelism=1, hash_len=32, type=Type.ID, version=19))
        header = {name: value for name, value in document.items() if name != 'data'}
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(_canonical(header))
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
            data = _json(plaintext)
            identity = self._validate_data(data)
        except (ValueError, TypeError, KeyError) as error:
            raise VaultError('本地密钥口令错误，或密钥文件已损坏；原文件未修改') from error
        return data, identity, key, salt

    def _encode(self, data, key, salt):
        self._validate_data(data)
        header = {'v': 1, 'scope': deepcopy(self.scope), 'kdf': dict(_KDF),
                  'salt': _b64(salt), 'nonce': _b64(get_random_bytes(12))}
        cipher = AES.new(key, AES.MODE_GCM, nonce=_unb64(header['nonce'], length=12))
        cipher.update(_canonical(header))
        # Insertion order determines which bounded replay record is oldest.
        # Only the authenticated header needs the sorted canonical encoding.
        plaintext = json.dumps(data, separators=(',', ':'), ensure_ascii=True,
                               allow_nan=False).encode('ascii')
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        document = dict(header, data=_b64(ciphertext + tag))
        blob = _canonical(document) + b'\n'
        if len(blob) > MAX_VAULT_BYTES:
            raise VaultError('本地密钥文件超过大小限制')
        return blob

    def _write(self, blob):
        if self.path is None:
            self._memory_blob = blob
        else:
            _atomic_write(self.path, blob)

    def _accept(self, data, identity, key, salt, secret=None):
        self._data, self._identity, self._key, self._salt = data, identity, key, salt
        if secret is not None:
            if self._secret is not None:
                self._secret[:] = b'\0' * len(self._secret)
            self._secret = bytearray(secret)

    def unlock(self, passphrase, create=False):
        secret = _passphrase(passphrase)
        try:
            if not self.exists and not create:
                raise VaultError('本地端到端加密密钥不存在；已有密钥的账号请导入备份')
            with self._guard(create=create):
                try:
                    blob = self._blob()
                except FileNotFoundError:
                    if not create:
                        raise VaultError('本地端到端加密密钥不存在，请导入备份')
                    identity = Identity.generate()
                    data = {'v': 1, 'identity': identity.export_private(), 'peers': {}, 'groups': {}, 'replays': {}}
                    salt = get_random_bytes(16)
                    key = hash_secret_raw(secret, salt, time_cost=3, memory_cost=65536,
                                          parallelism=1, hash_len=32, type=Type.ID, version=19)
                    self._write(self._encode(data, key, salt))
                else:
                    data, identity, key, salt = self._decode(blob, secret, cached=False)
                self._accept(data, identity, key, salt, secret)
            return self.identity
        except VaultError:
            raise
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
            raise VaultError(f'无法解锁本地密钥：{error}') from error

    def lock(self):
        if self._secret is not None:
            self._secret[:] = b'\0' * len(self._secret)
        self._data = self._identity = self._secret = self._salt = self._key = None

    def _current(self):
        self.identity
        data, identity, key, salt = self._decode(self._blob(), self._secret)
        if identity.fingerprint != self.identity.fingerprint:
            raise VaultError('本地身份已被其他实例替换，请关闭连接后重新解锁并核验')
        return data, identity, key, salt

    def _mutate(self, mutation):
        self.identity
        try:
            with self._guard():
                data, identity, key, salt = self._current()
                result = mutation(data)
                if isinstance(result, _Unchanged):
                    self._accept(data, identity, key, salt)
                    return result.result
                blob = self._encode(data, key, salt)
                self._write(blob)
                self._accept(data, identity, key, salt)
                return result
        except VaultError:
            raise
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
            raise VaultError(f'保存本地密钥失败：{error}') from error

    def _refresh(self):
        """Read current trust under the same lock used by other instances."""
        self.identity
        try:
            with self._guard():
                data, identity, key, salt = self._current()
                self._accept(data, identity, key, salt)
                return data
        except VaultError:
            raise
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
            raise VaultError(f'读取本地信任记录失败：{error}') from error

    def peer(self, username):
        record = self._refresh()['peers'].get(_name(username))
        return deepcopy(record['bundle']) if record is not None else None

    @property
    def peer_records(self):
        """Return detached public trust records for the safety-number UI."""
        data = self._refresh()
        return [{'username': name, 'bundle': deepcopy(record['bundle']),
                 'verified': record['verified']}
                for name, record in sorted(data['peers'].items())]

    def is_verified(self, username):
        return self._refresh()['peers'].get(_name(username), {}).get('verified', False)

    def peer_by_fingerprint(self, username, fingerprint):
        username = _name(username)
        if not isinstance(fingerprint, str) or not _HEX.fullmatch(fingerprint):
            raise VaultError('端到端指纹格式错误')
        data = self._refresh()
        current = data['peers'].get(username)
        bundles = ([current['bundle']] if current else []) + data['peer_history'].get(username, [])
        for bundle in bundles:
            if bundle_fingerprint(bundle) == fingerprint:
                return deepcopy(bundle)
        return None

    peer_for_fingerprint = peer_by_fingerprint

    def _pin(self, data, bundles, *, replace, verified):
        if type(replace) is not bool or type(verified) is not bool:
            raise VaultError('本地信任设置格式错误')
        if not isinstance(bundles, dict) or not 1 <= len(bundles) <= 256:
            raise VaultError('收件人密钥列表格式错误')
        for name, bundle in bundles.items():
            _name(name)
            bundle = validate_public_bundle(bundle)
            actual = bundle_fingerprint(bundle)
            if name == self.scope['username'] and actual != self.identity.fingerprint:
                raise PeerKeyChanged(name, self.identity.fingerprint, actual)
            previous = data['peers'].get(name)
            expected = bundle_fingerprint(previous['bundle']) if previous else None
            if expected is not None and expected != actual and not replace:
                raise PeerKeyChanged(name, expected, actual)
            if previous and expected != actual:
                history = data.setdefault('peer_history', {}).setdefault(name, [])
                history[:] = [item for item in history if bundle_fingerprint(item) != expected]
                history.append(deepcopy(previous['bundle']))
                del history[:-MAX_TRUST_HISTORY]
            retained = bool(previous and expected == actual and previous['verified'])
            data['peers'][name] = {'bundle': bundle, 'verified': retained or verified}

    def pin_peers(self, bundles, *, replace=False, verified=False):
        return self._mutate(lambda data: self._pin(data, bundles, replace=replace, verified=verified))

    def pin_peer(self, username, bundle, *, replace=False, verified=False):
        self.pin_peers({_name(username): bundle}, replace=replace, verified=verified)
        return self.peer(username)

    def approved_roster(self, gid):
        return deepcopy(self._refresh()['groups'].get(_name(gid)))

    def _roster(self, roster):
        if not isinstance(roster, dict) or not 1 <= len(roster) <= 256:
            raise VaultError('群收件人列表格式错误')
        normalized = {}
        for name, value in roster.items():
            name = _name(name)
            fingerprint = bundle_fingerprint(value) if isinstance(value, dict) else value
            if not isinstance(fingerprint, str) or not _HEX.fullmatch(fingerprint):
                raise VaultError('群收件人指纹格式错误')
            normalized[name] = fingerprint
        if normalized.get(self.scope['username']) != self.identity.fingerprint:
            raise VaultError('群收件人列表必须包含当前本地身份')
        return normalized

    @staticmethod
    def _approved(data, gid, roster):
        return (data['groups'].get(gid) == roster or
                any(previous == roster for previous in data.get('group_history', {}).get(gid, [])))

    def is_roster_approved(self, gid, roster):
        gid, roster = _name(gid), self._roster(roster)
        return self._approved(self._refresh(), gid, roster)

    @staticmethod
    def _approve(data, gid, roster):
        history = data.setdefault('group_history', {}).setdefault(gid, [])
        previous = data['groups'].get(gid)
        if previous is not None and previous not in history:
            history.append(deepcopy(previous))
        history[:] = [item for item in history if item != roster]
        history.append(deepcopy(roster))
        del history[:-MAX_TRUST_HISTORY]
        data['groups'][gid] = deepcopy(roster)
        return deepcopy(roster)

    def approve_roster_fingerprints(self, gid, roster, *, expected_previous=_UNSET):
        gid, roster = _name(gid), self._roster(roster)
        expected = (self._roster(expected_previous) if expected_previous is not _UNSET and
                    expected_previous is not None else expected_previous)

        def mutation(data):
            if expected is not _UNSET and data['groups'].get(gid) != expected:
                raise VaultError('群收件人已由另一客户端更改，请重新核验后确认')
            return self._approve(data, gid, roster)

        return self._mutate(mutation)

    def approve_roster(self, gid, bundles):
        gid = _name(gid)
        if not isinstance(bundles, dict) or self.scope['username'] not in bundles:
            raise VaultError('群收件人列表必须包含当前账号')

        def mutation(data):
            self._pin(data, bundles, replace=False, verified=False)
            return self._approve(data, gid, self._roster(bundles))

        return self._mutate(mutation)

    @contextmanager
    def send_guard(self, bundles, *, gid=None, expected_roster=None, approve=False):
        """Keep trust decisions stable through encryption and queue insertion.

        The caller obtains any approval outside this context, passes the roster
        seen before that dialog, then encrypts and queues while this lock is
        still held. Revocation by another instance therefore takes effect
        either before this send or after it, never between checking and sending.
        """
        self.identity
        if type(approve) is not bool or not isinstance(bundles, dict):
            raise VaultError('端到端发送批准格式错误')
        bundles = {_name(name): validate_public_bundle(bundle) for name, bundle in bundles.items()}
        desired = self._roster(bundles)
        if gid is not None:
            gid = _name(gid)
            expected = self._roster(expected_roster) if expected_roster is not None else None
        elif expected_roster is not None:
            raise VaultError('私聊不能附带群收件人批准')
        try:
            with self._guard():
                data, identity, key, salt = self._current()
                previous = deepcopy(data)
                if gid is not None:
                    current = data['groups'].get(gid)
                    if current != expected:
                        raise VaultError('群收件人已由另一客户端更改，请重新核验后发送')
                    if current != desired:
                        if not approve:
                            raise VaultError('请先明确批准当前群收件人列表')
                        self._approve(data, gid, desired)
                self._pin(data, bundles, replace=False, verified=False)
                if data != previous:
                    self._write(self._encode(data, key, salt))
                self._accept(data, identity, key, salt)
                yield self.identity
        except VaultError:
            raise
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
            raise VaultError(f'端到端发送未完成：{error}') from error

    @staticmethod
    def _replay_record(value):
        if type(value) is int and 0 < value <= 9223372036854775807:
            return {'message_id': value, 'digest': None}
        if (not isinstance(value, dict) or set(value) != {'message_id', 'digest'} or
                type(value['message_id']) is not int or not 0 < value['message_id'] <= 9223372036854775807 or
                not isinstance(value['digest'], str) or not _HEX.fullmatch(value['digest'])):
            raise VaultError('消息重放记录格式错误')
        return deepcopy(value)

    @staticmethod
    def _replay_key(sender_fingerprint, envelope_id):
        if (not isinstance(sender_fingerprint, str) or not _HEX.fullmatch(sender_fingerprint) or
                not isinstance(envelope_id, str) or re.fullmatch(r'[0-9a-f]{32}', envelope_id) is None):
            raise VaultError('消息重放标识格式错误')
        return sender_fingerprint + ':' + envelope_id

    def known_record(self, sender_fingerprint, envelope_id):
        key = self._replay_key(sender_fingerprint, envelope_id)
        value = self._refresh()['replays'].get(key)
        return self._replay_record(value) if value is not None else None

    def known_envelope(self, sender_fingerprint, envelope_id):
        record = self.known_record(sender_fingerprint, envelope_id)
        return record['message_id'] if record else None

    def observe_envelope(self, sender_fingerprint, envelope_id, server_message_id, *, envelope_digest=None):
        """Reject a known signed envelope reassigned to a different server ID.

        The most recent 10,000 distinct envelopes are retained across restarts.
        A repeat with its original ID is legitimate history or sync replay.
        """
        if (not isinstance(sender_fingerprint, str) or not _HEX.fullmatch(sender_fingerprint) or
                not isinstance(envelope_id, str) or re.fullmatch(r'[0-9a-f]{32}', envelope_id) is None or
                type(server_message_id) is not int or not 0 < server_message_id <= 9223372036854775807):
            raise VaultError('消息重放标识格式错误')
        replay_key = self._replay_key(sender_fingerprint, envelope_id)
        if envelope_digest is not None and (not isinstance(envelope_digest, str) or not _HEX.fullmatch(envelope_digest)):
            raise VaultError('消息内容摘要格式错误')

        def mutation(data):
            records = data.setdefault('replays', {})
            if replay_key in records:
                previous = self._replay_record(records[replay_key])
                if previous['message_id'] != server_message_id:
                    return _Unchanged(False)
                if envelope_digest is None or previous['digest'] == envelope_digest:
                    return _Unchanged(True)
                if previous['digest'] is not None:
                    return _Unchanged(False)
            records[replay_key] = ({'message_id': server_message_id, 'digest': envelope_digest}
                                   if envelope_digest is not None else server_message_id)
            while len(records) > MAX_REPLAY_RECORDS:
                records.pop(next(iter(records)))
            return True

        return self._mutate(mutation)

    def accept_envelope(self, sender, bundle, envelope_id, server_message_id, digest, *, gid=None, roster=None):
        """Commit acceptance only after the caller verifies and decrypts it.

        Identity, current membership, archived exact-message proofs and replay
        observations are checked together, closing races with another instance.
        A server-provided history flag grants no permission to use retired keys
        or an archived group roster for a previously unseen message.
        """
        sender, bundle = _name(sender), validate_public_bundle(bundle)
        fingerprint = bundle_fingerprint(bundle)
        replay_key = self._replay_key(fingerprint, envelope_id)
        self._replay_record({'message_id': server_message_id, 'digest': digest})
        if (gid is None) != (roster is None):
            raise VaultError('群收件人上下文不完整')
        if gid is not None:
            gid, roster = _name(gid), self._roster(roster)
            if roster.get(sender) != fingerprint:
                raise VaultError('端到端发送者不在该群消息的收件人列表中')

        def mutation(data):
            records = data.setdefault('replays', {})
            raw_record = records.get(replay_key)
            previous = self._replay_record(raw_record) if raw_record is not None else None
            if previous and previous['message_id'] != server_message_id:
                return _Unchanged(False)
            if previous and previous['digest'] is not None and previous['digest'] != digest:
                raise VaultError('已知端到端消息编号的签名内容发生变化')
            exact = bool(previous and previous['digest'] == digest)
            current = data['peers'].get(sender)
            if sender == self.scope['username']:
                if fingerprint != self.identity.fingerprint:
                    raise PeerKeyChanged(sender, self.identity.fingerprint, fingerprint)
            elif current is not None and bundle_fingerprint(current['bundle']) != fingerprint:
                historical = any(bundle_fingerprint(old) == fingerprint
                                 for old in data.get('peer_history', {}).get(sender, []))
                if not historical or not exact:
                    raise PeerKeyChanged(sender, bundle_fingerprint(current['bundle']), fingerprint)
            if gid is not None:
                latest = data['groups'].get(gid) == roster
                if not latest and not (exact and self._approved(data, gid, roster)):
                    raise VaultError('群收件人尚未批准，或该旧收件人列表不能授权新的消息')
            new_pin = sender != self.scope['username'] and current is None
            if new_pin:
                self._pin(data, {sender: bundle}, replace=False, verified=False)
            if exact and not new_pin:
                return _Unchanged(True)
            records[replay_key] = {'message_id': server_message_id, 'digest': digest}
            while len(records) > MAX_REPLAY_RECORDS:
                records.pop(next(iter(records)))
            return True

        return self._mutate(mutation)

    def export_to(self, path):
        self.identity
        try:
            with self._guard():
                data, identity, key, salt = self._current()
                blob = self._encode(data, key, salt)
                _atomic_write(Path(path), blob)
                self._accept(data, identity, key, salt)
            return Path(path)
        except VaultError:
            raise
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise VaultError(f'导出本地密钥失败：{error}') from error

    def import_from(self, path, passphrase, *, replace=False, allow_rebind=False):
        if type(replace) is not bool or type(allow_rebind) is not bool:
            raise VaultError('导入替换选项格式错误')
        secret = _passphrase(passphrase)
        try:
            blob = _read_file(path)
            document = _json(blob)
            source_scope = document.get('scope') if isinstance(document, dict) else None
            if allow_rebind and source_scope != self.scope:
                if (not isinstance(source_scope, dict) or set(source_scope) != {'endpoint', 'username'} or
                        source_scope.get('username') != self.scope['username']):
                    raise VaultError('只能将同一账号的加密备份迁移到其他服务器地址')
                normalized = _scope(source_scope['endpoint'], source_scope['username'])
                if normalized != source_scope:
                    raise VaultError('备份所属服务器格式错误')
                source = KeyVault(None, source_scope['endpoint'], source_scope['username'])
                data, identity, key, salt = source._decode(blob, secret, cached=False)
                blob = self._encode(data, key, salt)
            else:
                data, identity, key, salt = self._decode(blob, secret, cached=False)
            with self._guard(create=True):
                if self.exists and not replace:
                    raise VaultExistsError('本地密钥已经存在；请解锁现有密钥，或明确确认替换')
                self._write(blob)
                self._accept(data, identity, key, salt, secret)
            return self.identity
        except VaultError:
            raise
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise VaultError(f'导入本地密钥失败：{error}') from error

    def change_passphrase(self, new_passphrase):
        self.identity
        secret = _passphrase(new_passphrase)
        try:
            with self._guard():
                data, identity, _, _ = self._current()
                salt = get_random_bytes(16)
                key = hash_secret_raw(secret, salt, time_cost=3, memory_cost=65536,
                                      parallelism=1, hash_len=32, type=Type.ID, version=19)
                self._write(self._encode(data, key, salt))
                self._accept(data, identity, key, salt, secret)
        except VaultError:
            raise
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise VaultError(f'修改本地密钥口令失败：{error}') from error
