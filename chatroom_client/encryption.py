"""Client-owned E2EE keys, trust decisions, and correlated recipient lookup.

Only public bundles and encrypted envelopes leave this component. A directory
response is never permission to add an unapproved group recipient or replace a
previously pinned contact identity.
"""
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import uuid

from .e2ee_crypto import (
    E2EEError, bundle_fingerprint, canonical_json, decrypt_message, encrypt_message,
    publish_proof, validate_envelope, validate_public_bundle, verify_signature,
)
from .key_vault import KeyVault, vault_path
from .protocol import decrypt_message as decrypt_legacy


_READY = '端到端加密已就绪；请在“加密与密钥”核对联系人指纹'


@dataclass
class _VaultPreparation:
    """An authentication-worker task which has no Tk objects or callbacks."""
    path: object
    endpoint: tuple
    username: str
    passphrase: str | None = field(repr=False)
    vault: object | None = field(default=None, repr=False)

    def __call__(self, remote_identity):
        remote = (validate_public_bundle(remote_identity)
                  if remote_identity is not None else None)
        candidate = self.vault or KeyVault(self.path, self.endpoint, self.username)
        if not candidate.unlocked:
            if remote is not None and not candidate.exists:
                raise ValueError('此账号已经登记端到端加密密钥，但本机没有原密钥。'
                                 '请在登录页导入原来的加密密钥备份；不会自动替换身份。')
            try:
                candidate.unlock(self.passphrase, create=remote is None)
            except Exception:
                candidate.lock()
                raise
        if remote is not None and candidate.identity.fingerprint != bundle_fingerprint(remote):
            candidate.lock()
            raise ValueError('本机端到端身份与服务器已登记身份不一致，请导入原密钥备份并核验指纹')
        self.vault = candidate
        self.passphrase = None
        return candidate


@dataclass(frozen=True)
class _SendLookup:
    request_id: str
    sock: object
    username: str
    key: object
    text: str = field(repr=False)
    send: bool = True


class EncryptionController:
    def __init__(self, application):
        self.application = application
        self.vault = None
        self.ready = self.sending = False
        self.status = '尚未解锁本机端到端加密密钥'
        self._publication = self._lookup = None
        self._peer_changes = {}
        self._denied_groups = set()

    @property
    def fingerprint(self):
        return self.vault.identity.fingerprint if self.vault is not None and self.vault.unlocked else ''

    def peers(self):
        if self.vault is None or not self.vault.unlocked:
            return []
        return [{'username': record['username'],
                 'fingerprint': bundle_fingerprint(record['bundle']),
                 'verified': record['verified']}
                for record in self.vault.peer_records
                if record['username'] != self.application.state.username]

    def peer_change(self, username):
        return deepcopy(self._peer_changes.get(username))

    def _refresh(self):
        view = self.application.view
        callback = getattr(view, 'refresh_encryption', None)
        if callback is not None:
            callback()
        view.refresh_controls()

    def _notify(self, text):
        self.application.view.notify('端到端加密', text)

    def prepare_login(self, username, login_password, endpoint):
        passphrase = self.application.view.encryption_passphrase()
        if not isinstance(passphrase, str) or not 8 <= len(passphrase) <= 1024:
            raise ValueError('请输入 8–1024 个字符的本机密钥口令，建议至少 12 个字符')
        if passphrase == login_password:
            raise ValueError('本机密钥口令必须与账号密码不同；它只用于本机密钥，不会发送给服务器')
        path = vault_path(self.application.preferences.path, endpoint, username)
        existing = self.vault if (self.vault is not None and self.vault.scope == {
            'endpoint': [endpoint[0].lower(), endpoint[1]], 'username': username}) else None
        return _VaultPreparation(path, tuple(endpoint), username, passphrase, existing)

    def discard_result(self, result):
        vault = getattr(result, 'encryption', None)
        if vault is not None and vault is not self.vault:
            vault.lock()

    def establish(self, result):
        self.pause()
        vault = result.encryption
        if vault is None or not vault.unlocked:
            self.status = '端到端密钥未解锁；发送已停止'
            self._notify(self.status)
            self._refresh()
            return
        if self.vault is not None and self.vault is not vault:
            self.vault.lock()
            self._denied_groups.clear()
        self.vault = vault
        request_id = uuid.uuid4().hex
        self._publication = (request_id, self.application.connection.sock)
        self.status = '正在核验并登记端到端加密身份…'
        try:
            self.application.queue_send({
                'type': 'e2ee_identity_publish', 'request_id': request_id,
                'identity': vault.identity.public_bundle(),
                'proof': publish_proof(vault.identity, result.username),
            })
        except Exception as error:
            self._publication = None
            self.status = '端到端身份登记失败；发送已停止'
            self._notify(str(error))
        self.application.view.schedule(20000, lambda: self._expire_publication(request_id))
        self._refresh()

    def _expire_publication(self, request_id):
        if self._publication is not None and self._publication[0] == request_id:
            self._publication = None
            self.ready = False
            self.status = '端到端身份核验超时；请断开后重新登录'
            self._notify(self.status)
            self._refresh()

    def pause(self):
        self.ready = self.sending = False
        self._publication = self._lookup = None
        self.status = '端到端加密等待连接恢复'

    def reset(self):
        self.pause()
        if self.vault is not None:
            self.vault.lock()
        self.vault = None
        self._peer_changes.clear()
        self._denied_groups.clear()
        self.status = '尚未解锁本机端到端加密密钥'

    def handle(self, message):
        if not isinstance(message, dict):
            return False
        if message.get('type') == 'e2ee_identity_result':
            self._identity_result(message)
            return True
        if message.get('type') == 'e2ee_keys':
            self._keys_result(message)
            return True
        return False

    def _identity_result(self, message):
        expected = self._publication
        if (expected is None or message.get('request_id') != expected[0]
                or self.application.connection.sock is not expected[1]):
            return
        self._publication = None
        try:
            if message.get('success') is not True:
                raise ValueError(message.get('error') or '端到端身份登记失败')
            if bundle_fingerprint(message.get('identity')) != self.fingerprint:
                raise ValueError('服务器确认的端到端身份与本机密钥不一致')
        except (ValueError, TypeError) as error:
            self.ready = False
            self.status = '端到端身份核验失败；发送已停止'
            self._notify(str(error))
        else:
            self.ready = True
            self.status = _READY
        self._refresh()

    def send_message(self, text, key, *, send=True):
        if not self.ready or self.vault is None:
            self._notify('端到端加密尚未就绪，输入已保留')
            return False
        if self.sending:
            return False
        request_id = uuid.uuid4().hex
        self._lookup = _SendLookup(request_id, self.application.connection.sock,
                                   self.application.state.username, key, text, send)
        self.sending = True
        try:
            self.application.queue_send({'type': 'e2ee_keys_request', 'request_id': request_id,
                                         'kind': key.kind, 'target': key.target})
        except Exception as error:
            self._lookup = None
            self.sending = False
            self._notify(str(error))
            self._refresh()
            return False
        self.application.view.schedule(20000, lambda: self._expire_lookup(request_id))
        self._refresh()
        return True

    def review_group(self, key):
        if key is None or key.kind != 'group':
            raise ValueError('请先选择需要核验的群聊')
        return self.send_message(self.application.view.input_text(), key, send=False)

    def _expire_lookup(self, request_id):
        if self._lookup is not None and self._lookup.request_id == request_id:
            self._lookup = None
            self.sending = False
            self._notify('获取接收人密钥超时，输入已保留；请重试')
            self._refresh()

    def _same_context(self, lookup):
        app = self.application
        return (self.ready and app.connection.running
                and app.connection.sock is lookup.sock
                and app.state.username == lookup.username
                and app.state.current_chat == lookup.key
                and app.view.input_text() == lookup.text
                and not app.state.pending_messages)

    def _keys_result(self, message):
        lookup = self._lookup
        if (lookup is None or message.get('request_id') != lookup.request_id
                or self.application.connection.sock is not lookup.sock):
            return
        # A duplicate response cannot open another approval dialog or send again.
        self._lookup = None
        try:
            if not self._same_context(lookup):
                raise ValueError('输入、会话或连接已改变，请确认后重新发送')
            if message.get('success') is not True:
                raise ValueError(message.get('error') or '未能获取接收人密钥')
            if message.get('kind') != lookup.key.kind or message.get('target') != lookup.key.target:
                raise ValueError('端到端密钥响应与当前会话不匹配')
            members, raw = message.get('members'), message.get('identities')
            if (not isinstance(members, list) or not 1 <= len(members) <= 256
                    or any(not isinstance(name, str) or not name for name in members)
                    or len(set(members)) != len(members) or lookup.username not in members
                    or not isinstance(raw, dict)):
                raise ValueError('端到端接收人列表格式错误')
            if (lookup.key.kind == 'private'
                    and set(members) != {lookup.username, lookup.key.target}):
                raise ValueError('私聊接收人列表不匹配')
            missing = message.get('missing', [])
            if missing or set(raw) != set(members):
                raise ValueError('部分接收人尚未设置端到端加密密钥，不能发送；请先让所有接收人登录新版客户端')
            bundles = {name: validate_public_bundle(bundle) for name, bundle in raw.items()}
            if bundle_fingerprint(bundles[lookup.username]) != self.fingerprint:
                raise ValueError('目录返回的本机端到端身份不一致')
            changed = []
            # One current snapshot is sufficient for the preliminary UI check.
            # The send guard performs the authoritative locked check below.
            pins = {record['username']: record['bundle'] for record in self.vault.peer_records}
            for name, bundle in bundles.items():
                if name == lookup.username:
                    continue
                pinned = pins.get(name)
                if pinned is not None and bundle_fingerprint(pinned) != bundle_fingerprint(bundle):
                    self._peer_changes[name] = bundle
                    changed.append(name)
            if changed:
                raise ValueError('联系人端到端密钥已变化，已停止发送。请在“加密与密钥”通过其他可信渠道核验：'
                                 + '、'.join(sorted(changed)))
            previous, approved = None, False
            if lookup.key.kind == 'group':
                previous = self.vault.approved_roster(lookup.key.target)
                current = {name: bundle_fingerprint(bundle) for name, bundle in bundles.items()}
                if previous != current or not lookup.send:
                    if self.application.view.confirm_encryption_roster(lookup.key.target, bundles, previous) is not True:
                        return
                    if not self._same_context(lookup):
                        raise ValueError('确认期间输入、会话或连接已改变，请重新发送')
                    approved = True
            if not self._same_context(lookup):
                raise ValueError('输入、会话或连接已改变，请确认后重新发送')
            # Keep the shared vault lock through encryption AND enqueue. A
            # second client cannot revoke a contact/group recipient between a
            # fresh approval check and the release of their wrapped key.
            with self.vault.send_guard(bundles,
                                       gid=lookup.key.target if lookup.key.kind == 'group' else None,
                                       expected_roster=previous, approve=approved) as identity:
                if lookup.send:
                    envelope = encrypt_message(identity, lookup.username, lookup.key.kind,
                                               lookup.key.target, lookup.text, bundles)
                    data = {'type': lookup.key.kind + '_chat', 'request_id': uuid.uuid4().hex,
                            'gid' if lookup.key.kind == 'group' else 'to': lookup.key.target,
                            'e2ee': envelope}
                    self.application.send_chat_payload(data, lookup.text)
            if lookup.key.kind == 'group' and approved:
                self._denied_groups.discard(lookup.key.target)
            if not lookup.send:
                self._notify('当前群接收人已确认；重新登录可重新读取此前未能验证的消息')
        except (ValueError, TypeError, KeyError, OSError) as error:
            self._notify(str(error))
        finally:
            self.sending = False
            self._refresh()

    def decode_message(self, message):
        """Return (visible content, protection label), or None for a replay."""
        if 'e2ee' not in message:
            syncing = getattr(getattr(self.application, 'sync', None), 'active', False) is True
            historical = (message.get('history') is True or message.get('sync') is True
                          or (message.get('history') is not False
                              and (self.application.state.history_syncing or syncing)))
            if not historical:
                return '[已拒绝未经端到端加密的实时消息]', 'failed'
            try:
                return decrypt_legacy(message.get('content'), self.application.connection.session_key), 'legacy'
            except Exception:
                return '[旧消息解密失败]', 'failed'
        try:
            if self.vault is None or not self.vault.unlocked:
                raise E2EEError('本机端到端密钥未解锁')
            vault, sock = self.vault, self.application.connection.sock
            envelope = validate_envelope(message['e2ee'])
            sender = message.get('from')
            kind = 'group' if message.get('type') == 'group_chat' else 'private'
            target = message.get('gid') if kind == 'group' else message.get('to')
            if (envelope['sender'] != sender or envelope['kind'] != kind or envelope['target'] != target):
                raise E2EEError('端到端消息与发送人或会话不匹配')
            username = self.application.state.username
            bundle = envelope['sender_key']
            pinned = vault.identity.public_bundle() if sender == username else vault.peer(sender)
            # Authenticate even a changed candidate before exposing it in the
            # explicit identity-review UI. Its plaintext remains unavailable.
            verify_signature(envelope)
            if pinned is not None and bundle_fingerprint(pinned) != bundle_fingerprint(bundle):
                retired = (vault.peer_by_fingerprint(sender, bundle_fingerprint(bundle))
                           if sender != username else None)
                if retired is None:
                    if sender != username:
                        self._peer_changes[sender] = bundle
                    raise E2EEError('发送者端到端密钥已变化，请先核验安全指纹')
                # Retained keys are only candidates here. The atomic final
                # vault transaction below allows them exclusively for an
                # already-observed, byte-identical envelope and server ID.
                pinned = retired
            if kind == 'group':
                if target not in self.application.state.groups:
                    raise E2EEError('未知群聊，已停止显示消息；请先核验群聊身份')
                roster = envelope['recipients']
                if roster.get(username) != vault.identity.fingerprint:
                    raise E2EEError('此端到端消息未加密给当前本地身份')
                if not vault.is_roster_approved(target, roster):
                    if target in self._denied_groups:
                        raise E2EEError('群接收人尚未确认；重新登录可再次核验')
                    previous = vault.approved_roster(target)
                    accepted = self.application.view.confirm_encryption_roster(target, roster, previous)
                    if accepted is not True:
                        self._denied_groups.add(target)
                        raise E2EEError('群接收人尚未确认；重新登录可再次核验')
                    if (self.vault is not vault or not vault.unlocked
                            or self.application.connection.sock is not sock
                            or self.application.state.username != username
                            or getattr(self.application, 'closing', False)):
                        raise E2EEError('核验期间连接或账号已改变，请重新登录后再核验')
                    vault.approve_roster_fingerprints(target, roster, expected_previous=previous)
            content = decrypt_message(vault.identity, username, envelope,
                                      expected_sender=sender, expected_kind=kind,
                                      expected_target=target,
                                      pinned_sender_bundle=pinned or bundle)
            message_id = message.get('message_id')
            if type(message_id) is not int or message_id <= 0:
                raise E2EEError('端到端消息缺少有效的服务器编号')
            digest = hashlib.sha256(canonical_json(envelope)).hexdigest()
            if not vault.accept_envelope(sender, bundle, envelope['id'], message_id, digest,
                                         gid=target if kind == 'group' else None,
                                         roster=envelope['recipients'] if kind == 'group' else None):
                return None
            return content, 'e2ee'
        except (ValueError, TypeError, KeyError, OSError) as error:
            return '[端到端加密验证失败：' + str(error) + ']', 'failed'

    def export_keys(self, path):
        if self.vault is None or not self.vault.unlocked:
            raise ValueError('请先登录并解锁本机密钥，再导出加密备份')
        return self.vault.export_to(path)

    def change_passphrase(self, value):
        if self.vault is None or not self.vault.unlocked:
            raise ValueError('请先登录并解锁本机密钥')
        if self.application.connection.is_login_password(value):
            raise ValueError('本机密钥口令必须与账号密码不同；它只用于本机密钥，不会发送给服务器')
        self.vault.change_passphrase(value)
        self._refresh()

    def import_keys(self, path, passphrase, username, endpoint, *, replace=False, allow_rebind=False):
        app = self.application
        if app.connection.running or app.connection.auth_busy or app.reconnecting:
            raise ValueError('请先断开连接，再恢复密钥备份')
        candidate = KeyVault(vault_path(app.preferences.path, endpoint, username), endpoint, username)
        identity = candidate.import_from(path, passphrase, replace=replace, allow_rebind=allow_rebind)
        fingerprint = identity.fingerprint
        if self.vault is not None:
            self.vault.lock()
        self.vault = candidate
        # Keeping the encrypted in-memory object allows injected memory-only
        # stores to be restored too; its private material still starts locked.
        candidate.lock()
        return fingerprint

    def verify_peer(self, username):
        if self.vault is None:
            raise ValueError('请先登录并解锁本机密钥')
        bundle = self.vault.peer(username)
        if bundle is None:
            raise ValueError('尚无此联系人的固定密钥，请先收取消息或尝试发送')
        self.vault.pin_peer(username, bundle, verified=True)
        self._refresh()

    def accept_peer(self, username, bundle):
        if self.vault is None:
            raise ValueError('请先登录并解锁本机密钥')
        candidate = self._peer_changes.get(username)
        if candidate is None or bundle_fingerprint(candidate) != bundle_fingerprint(bundle):
            raise ValueError('待核验的联系人密钥已改变，请重新核对')
        self.vault.pin_peer(username, candidate, replace=True, verified=True)
        self._peer_changes.pop(username, None)
        self.status = _READY
        self._refresh()
