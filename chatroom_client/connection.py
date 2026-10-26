"""Socket and worker lifetime. Workers exchange data events and never own Tk objects."""
from dataclasses import dataclass, field, replace
import base64
import hmac
import hashlib
import time
import json
import queue
import socket
import threading

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

import transport
from . import protocol


@dataclass
class ClientSettings:
    host: str = '127.0.0.1'
    port: int = 12345
    expected_fingerprint: str | None = None


@dataclass(frozen=True)
class AuthResult:
    generation: int
    username: str
    register: bool
    endpoint: tuple[str, int]
    sock: socket.socket | None
    key: bytes | None
    error: str | None
    retryable: bool = False
    capabilities: tuple[str, ...] = ()
    encryption: object | None = field(default=None, repr=False)


@dataclass(frozen=True)
class _Authentication:
    """An immutable authentication target; the password never leaves memory."""
    username: str
    password: str = field(repr=False)
    endpoint: tuple[str, int]
    fingerprint: str | None
    prepare: object | None = field(default=None, repr=False)
    legacy_password: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class PasswordChangeResult:
    generation: int
    sock: object = field(repr=False)
    error: str | None
    warning: str | None = None


@dataclass(frozen=True)
class ServerEvent:
    sock: socket.socket
    message: dict | None


class ConnectionManager:
    def __init__(self, settings):
        self.settings = settings
        self.sock = None
        self.session_key = None
        self.endpoint = None
        self.capabilities = ()
        self.running = False
        self.auth_busy = False
        self.auth_sock = None
        self.change_busy = False
        self._change_sock = None
        self.generation = 0
        self.closing = False
        self.events = queue.Queue()
        self.outgoing = queue.Queue(maxsize=100)
        self.workers = []
        self._lock = threading.Lock()
        self._auth_contexts = {}
        self._saved_auth = None
        self.start_worker(self._send_loop)

    def start_worker(self, target, *args):
        self.workers = [worker for worker in self.workers if worker.is_alive()]
        worker = threading.Thread(target=target, args=args, daemon=True)
        worker.start()
        self.workers.append(worker)

    def authenticate(self, username, password, *, register=False, prepare=None, migration_password=None):
        authentication = _Authentication(
            username, password, (self.settings.host, self.settings.port),
            self.settings.expected_fingerprint, prepare, migration_password)
        return self._start_authentication(authentication, register=register)

    def _start_authentication(self, authentication, *, register=False, reconnect=False):
        with self._lock:
            if self.auth_busy or self.closing or self.running:
                return False
            self.generation += 1
            generation = self.generation
            self.auth_busy = True
            if not reconnect:
                self._saved_auth = None
            self._auth_contexts[generation] = authentication
        try:
            self.start_worker(self._authenticate, generation, authentication.endpoint,
                              authentication.username, authentication.password, register,
                              authentication)
        except Exception as error:
            # Deliver worker creation failures through the same owner-thread
            # completion path, so a resource limit cannot leave login disabled.
            self.events.put(AuthResult(generation, authentication.username, register,
                                       authentication.endpoint, None, None, str(error),
                                       isinstance(error, (OSError, RuntimeError))))
        return True

    @property
    def can_reconnect(self):
        with self._lock:
            return self._saved_auth is not None and not self.closing

    def authenticate_saved(self):
        with self._lock:
            authentication = self._saved_auth
        if authentication is None:
            return False
        return self._start_authentication(authentication, reconnect=True)

    def forget_credentials(self):
        with self._lock:
            self._saved_auth = None
            self._auth_contexts.clear()

    def is_login_password(self, candidate):
        """Check separation of local and account secrets without exporting one."""
        if not isinstance(candidate, str):
            return False
        with self._lock:
            authentication = self._saved_auth
            if authentication is None:
                return False
            try:
                return hmac.compare_digest(candidate.encode('utf-8'),
                                           authentication.password.encode('utf-8'))
            except UnicodeError:
                return False

    def _authenticate(self, generation, endpoint, username, password, register, authentication=None):
        sock = None
        key, error, keep = None, None, False
        retryable, capabilities, prepared = False, (), None
        context = authentication
        # The fallback supports direct protocol tests. Normal authentication
        # always has a snapshot captured before its worker starts.
        fingerprint = context.fingerprint if context is not None else self.settings.expected_fingerprint
        try:
            family = socket.AF_INET6 if ':' in endpoint[0] else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            with self._lock:
                if generation != self.generation or self.closing:
                    return
                self.auth_sock = sock
            sock.settimeout(10)
            sock.connect(endpoint)
            public_packet = protocol.recv_msg(sock)
            if public_packet is None:
                raise ConnectionError('服务器在认证期间关闭了连接')
            public_key, key_error = protocol.check_server_public_key(
                public_packet, host=endpoint[0], expected_fingerprint=fingerprint)
            if key_error:
                raise ValueError(key_error)
            advertised = public_packet.get('capabilities', ())
            if (isinstance(advertised, (list, tuple))
                    and all(isinstance(item, str) for item in advertised)):
                capabilities = tuple(item for item in ('message_sync', 'e2ee_v1', 'opaque_v1', 'history_request_id', 'message_receipts') if item in advertised)
            if context is not None and context.prepare is not None and 'e2ee_v1' not in capabilities:
                raise ValueError('服务器尚不支持端到端加密，请升级服务端；不会降级发送明文消息')
            modern = context is not None and getattr(context.prepare, 'single_password', False) is True
            if modern and 'opaque_v1' not in capabilities:
                raise ValueError('服务器尚不支持统一密码认证，请升级服务端；不会发送账号密码')
            key = get_random_bytes(16)
            encrypted = PKCS1_OAEP.new(public_key).encrypt(key)
            protocol.send_msg(sock, {'type': 'session_key', 'protocol': transport.VERSION,
                                     'key': base64.b64encode(encrypted).decode('utf-8')})
            transport.configure(sock, key)
            if modern:
                server_id = hashlib.sha256(public_key.export_key(format='DER')).hexdigest()
                response, prepared = self._opaque_authenticate(
                    sock, key, username, password, server_id, register, context)
            else:
                protocol.send_msg(sock, {
                    'type': 'encrypted_register' if register else 'encrypted_login',
                    'data': protocol.encrypt_message(json.dumps({'from': username, 'password': password}), key),
                })
                response = protocol.recv_msg(sock)
                expected = 'register_result' if register else 'login_result'
                if response is None:
                    raise ConnectionError('服务器未响应或连接已关闭')
                if not isinstance(response, dict) or response.get('type') != expected or not response.get('success'):
                    raise ValueError(response.get('error', '认证失败') if isinstance(response, dict) else '服务器未响应')
                if not register and context is not None and context.prepare is not None:
                    if 'e2ee_identity' not in response:
                        raise ValueError('服务器未提供已登记的端到端身份，连接已停止')
                    prepared = context.prepare(response['e2ee_identity'])
            with self._lock:
                keep = not register and generation == self.generation and not self.closing
        except Exception as exc:
            error = str(exc)
            retryable = isinstance(exc, OSError)
        finally:
            if not keep:
                self._close_socket(sock)
                if prepared is not None:
                    prepared.lock()
                    prepared = None
            if not keep and context is not None and hasattr(context.prepare, 'abort'):
                context.prepare.abort()
            self.events.put(AuthResult(generation, username, register, endpoint, sock, key, error,
                                       retryable, capabilities, prepared))

    @staticmethod
    def _password(value):
        if not isinstance(value, str) or not 8 <= len(value) <= 128:
            raise ValueError('统一密码须为 8–128 个字符')
        try:
            value.encode('utf-8')
        except UnicodeError as error:
            raise ValueError('统一密码格式错误') from error

    @staticmethod
    def _opaque_call(op, **arguments):
        from opaque_runtime import call
        try:
            return call(dict(op=op, **arguments))
        except Exception as error:
            raise ValueError('账号认证失败，请检查密码或使用“迁移旧账号”') from error

    @staticmethod
    def _auth_reply(sock, expected, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('账号认证超时，请重试')
        sock.settimeout(remaining)
        response = protocol.recv_msg(sock)
        if not isinstance(response, dict):
            raise ValueError('服务器认证响应无效')
        if response.get('migration_required') is True:
            raise ValueError('此账号尚未升级，请使用“迁移旧账号”并准备旧密码和原本机密钥口令')
        if response.get('type') != expected or response.get('success') is False:
            raise ValueError('账号认证失败，请检查密码或账号状态')
        return response

    def _opaque_authenticate(self, sock, key, username, password, server_id, register, context):
        self._password(password)
        deadline = time.monotonic() + 30
        migrate = context.legacy_password is not None
        if register or migrate:
            phase = 'opaque_migrate' if migrate else 'opaque_register'
            request = self._opaque_call('registration_start', password=password)
            packet = {'type': phase + '_start', 'from': username, 'request': request['request']}
            if migrate:
                packet['legacy_data'] = protocol.encrypt_message(
                    json.dumps({'password': context.legacy_password}), key)
            protocol.send_msg(sock, packet)
            challenge = self._auth_reply(sock, phase + '_challenge', deadline)
            result = self._opaque_call('registration_finish', password=password, state=request['state'],
                                       response=challenge['response'], username=username, server_id=server_id)
            remote_identity = challenge.get('e2ee_identity') if migrate else None
            prepared = context.prepare(remote_identity, export_key=result['export_key'],
                                       server_id=server_id, registration=True)
            protocol.send_msg(sock, {'type': phase + '_finish', 'record': result['record'],
                                     'backup': prepared.opaque_backup(result['export_key'], server_id)})
            response = self._auth_reply(sock, 'login_result' if migrate else 'register_result', deadline)
            if response.get('success') is not True:
                raise ValueError('账号认证失败')
            context.prepare.commit()
            return response, prepared
        request = self._opaque_call('login_start', password=password)
        protocol.send_msg(sock, {'type': 'opaque_login_start', 'from': username, 'request': request['request']})
        challenge = self._auth_reply(sock, 'opaque_login_challenge', deadline)
        result = self._opaque_call('login_finish', password=password, state=request['state'],
                                   response=challenge['response'], username=username, server_id=server_id)
        protocol.send_msg(sock, {'type': 'opaque_login_finish', 'finalization': result['finalization']})
        response = self._auth_reply(sock, 'login_result', deadline)
        if (response.get('success') is not True or 'e2ee_identity' not in response or
                not isinstance(response.get('opaque_backup'), dict) or
                type(response.get('opaque_generation')) is not int or response['opaque_generation'] < 1):
            raise ValueError('服务器未提供完整的账号加密身份')
        prepared = context.prepare(response['e2ee_identity'], export_key=result['export_key'],
                                   backup=response['opaque_backup'], server_id=server_id)
        return response, prepared

    def change_password(self, current_password, new_password, vault):
        self._password(current_password)
        self._password(new_password)
        with self._lock:
            if (not self.running or self.closing or self.change_busy or self._saved_auth is None or
                    'opaque_v1' not in self.capabilities):
                return False
            authentication, sock, generation = self._saved_auth, self.sock, self.generation
            self.change_busy = True
        try:
            self.start_worker(self._change_password, authentication, sock, generation,
                              current_password, new_password, vault)
        except Exception:
            self.change_busy = False
            raise ValueError('无法启动密码更新，请重试')
        return True

    def _change_password(self, authentication, session_sock, generation, current, new, vault):
        sock, error, warning = None, None, None
        try:
            endpoint = authentication.endpoint
            family = socket.AF_INET6 if ':' in endpoint[0] else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            with self._lock:
                if self.closing or generation != self.generation or self.sock is not session_sock:
                    raise ValueError('连接已改变，请重新登录后修改密码')
                self._change_sock = sock
            deadline = time.monotonic() + 30
            sock.settimeout(10)
            sock.connect(endpoint)
            packet = self._auth_reply(sock, 'public_key', deadline)
            public_key, key_error = protocol.check_server_public_key(
                packet, host=endpoint[0], expected_fingerprint=authentication.fingerprint)
            if key_error or 'opaque_v1' not in packet.get('capabilities', []):
                raise ValueError('服务器身份或统一密码能力无法验证')
            server_id = hashlib.sha256(public_key.export_key(format='DER')).hexdigest()
            key = get_random_bytes(16)
            encrypted = PKCS1_OAEP.new(public_key).encrypt(key)
            protocol.send_msg(sock, {'type': 'session_key', 'protocol': transport.VERSION,
                                     'key': base64.b64encode(encrypted).decode('ascii')})
            transport.configure(sock, key)
            login = self._opaque_call('login_start', password=current)
            protocol.send_msg(sock, {'type': 'opaque_change_start', 'from': authentication.username,
                                     'request': login['request']})
            challenge = self._auth_reply(sock, 'opaque_change_challenge', deadline)
            finished = self._opaque_call('login_finish', password=current, state=login['state'],
                                         response=challenge['response'], username=authentication.username,
                                         server_id=server_id)
            protocol.send_msg(sock, {'type': 'opaque_change_finish', 'finalization': finished['finalization']})
            verified = self._auth_reply(sock, 'opaque_change_verified', deadline)
            remote = verified.get('e2ee_identity')
            from .e2ee_crypto import bundle_fingerprint
            if remote is None or bundle_fingerprint(remote) != vault.identity.fingerprint:
                raise ValueError('服务器加密身份不一致，未修改密码')
            registration = self._opaque_call('registration_start', password=new)
            protocol.send_msg(sock, {'type': 'opaque_change_register_start', 'request': registration['request']})
            challenge = self._auth_reply(sock, 'opaque_change_register_challenge', deadline)
            finished = self._opaque_call('registration_finish', password=new, state=registration['state'],
                                         response=challenge['response'], username=authentication.username,
                                         server_id=server_id)
            backup = vault.opaque_backup(finished['export_key'], server_id)
            protocol.send_msg(sock, {'type': 'opaque_change_register_finish', 'record': finished['record'],
                                     'backup': backup, 'generation': verified['generation']})
            result = self._auth_reply(sock, 'opaque_change_result', deadline)
            if result.get('success') is not True:
                raise ValueError('密码修改未完成，请重试')
            with self._lock:
                if self._saved_auth is authentication:
                    self._saved_auth = replace(authentication, password=new, legacy_password=None)
            try:
                vault.rewrap_opaque(finished['export_key'], server_id)
            except Exception:
                warning = '账号密码已更新，但本机保存失败；请用新密码重新登录恢复原身份和本机信任记录'
        except Exception:
            error = '密码更新失败或结果未确认；请检查连接。若新密码可登录请使用新密码，否则使用原密码重试'
        finally:
            self._close_socket(sock)
            with self._lock:
                self._change_sock = None
                self.change_busy = False
            self.events.put(PasswordChangeResult(generation, session_sock, error, warning))

    def accept_auth(self, result):
        """Called by the controller on its owner thread, before starting reception."""
        with self._lock:
            authentication = self._auth_contexts.pop(result.generation, None)
            if result.generation != self.generation or self.closing:
                self._close_socket(result.sock)
                return False
            self.auth_sock = None
            self.auth_busy = False
            if result.error is not None and not result.retryable:
                self._saved_auth = None
            if result.error is None and not result.register:
                self.sock, self.session_key, self.endpoint = result.sock, result.key, result.endpoint
                self.capabilities = result.capabilities
                self._saved_auth = (replace(authentication, legacy_password=None)
                                    if authentication is not None else None)
                protocol.authenticated_sockets.add(result.sock)
                self.running = True
        return True

    def receive(self):
        if not self.running or self.sock is None:
            return False
        try:
            self.start_worker(self._receive_loop, self.sock)
        except Exception:
            self.events.put(ServerEvent(self.sock, None))
            return False
        return True

    def _receive_loop(self, sock):
        while self.running and self.sock is sock:
            try:
                message = protocol.recv_msg(sock)
            except Exception:
                message = None
            self.events.put(ServerEvent(sock, message))
            if message is None:
                return

    def send(self, data):
        if not self.running or self.sock is None:
            raise ConnectionError('连接已断开')
        if len(json.dumps(data).encode('utf-8')) > protocol.MAX_RECV_MSG_LEN - 256:
            raise ValueError('消息包超过 1 MiB，请缩短内容')
        self.outgoing.put_nowait((self.sock, data))

    def _send_loop(self):
        while True:
            item = self.outgoing.get()
            if item is None:
                return
            sock, data = item
            if sock is not self.sock:
                continue
            try:
                protocol.send_msg(sock, data)
            except Exception as error:
                self.events.put(ServerEvent(sock, {'type': 'send_failed',
                                                   'request_id': data.get('request_id'), 'error': str(error)}))
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    @staticmethod
    def _close_socket(sock):
        if sock is None:
            return
        protocol.authenticated_sockets.discard(sock)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        transport.forget(sock)

    def cancel_auth(self, *, forget_credentials=True):
        with self._lock:
            self.generation += 1
            sock, self.auth_sock = self.auth_sock, None
            self.auth_busy = False
            self._auth_contexts.clear()
            if forget_credentials:
                self._saved_auth = None
        if sock is not None:
            self._close_socket(sock)

    def disconnect(self, *, preserve_credentials=False):
        change_sock, self._change_sock = self._change_sock, None
        if change_sock is not None:
            self._close_socket(change_sock)
        self.running = False
        sock, self.sock = self.sock, None
        self.session_key = self.endpoint = None
        self.capabilities = ()
        if not preserve_credentials:
            self.forget_credentials()
        if sock is not None:
            self._close_socket(sock)
        # A congested previous session must not fill the queue when a restored
        # connection requests its catch-up page. None is the close sentinel.
        while True:
            try:
                item = self.outgoing.get_nowait()
            except queue.Empty:
                break
            if item is None:
                self.outgoing.put_nowait(None)
                break

    def close(self):
        if self.closing:
            return
        self.closing = True
        self.cancel_auth()
        self.disconnect()
        while True:
            try:
                self.outgoing.get_nowait()
            except queue.Empty:
                break
        self.outgoing.put_nowait(None)
        for worker in self.workers:
            worker.join(timeout=.1)

    def workers_alive(self):
        return any(worker.is_alive() for worker in self.workers)

    def clear_events(self):
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                return
            if isinstance(event, AuthResult):
                self._close_socket(event.sock)
                if event.encryption is not None:
                    event.encryption.lock()
