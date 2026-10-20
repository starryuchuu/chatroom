"""Socket and worker lifetime. Workers exchange data events and never own Tk objects."""
from dataclasses import dataclass, field
import base64
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


@dataclass(frozen=True)
class _Authentication:
    """An immutable authentication target; the password never leaves memory."""
    username: str
    password: str = field(repr=False)
    endpoint: tuple[str, int]
    fingerprint: str | None


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

    def authenticate(self, username, password, *, register=False):
        authentication = _Authentication(
            username, password, (self.settings.host, self.settings.port),
            self.settings.expected_fingerprint)
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

    def _authenticate(self, generation, endpoint, username, password, register, authentication=None):
        sock = None
        key, error, keep = None, None, False
        retryable, capabilities = False, ()
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
                    and all(isinstance(item, str) for item in advertised)
                    and 'message_sync' in advertised):
                capabilities = ('message_sync',)
            key = get_random_bytes(16)
            encrypted = PKCS1_OAEP.new(public_key).encrypt(key)
            protocol.send_msg(sock, {'type': 'session_key', 'protocol': transport.VERSION,
                                     'key': base64.b64encode(encrypted).decode('utf-8')})
            transport.configure(sock, key)
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
            with self._lock:
                keep = not register and generation == self.generation and not self.closing
        except Exception as exc:
            error = str(exc)
            retryable = isinstance(exc, OSError)
        finally:
            if not keep:
                self._close_socket(sock)
            self.events.put(AuthResult(generation, username, register, endpoint, sock, key, error,
                                       retryable, capabilities))

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
                self._saved_auth = authentication
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
