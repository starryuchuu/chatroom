"""Socket and worker lifetime. Workers exchange data events and never own Tk objects."""
from dataclasses import dataclass
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
    sock: socket.socket
    key: bytes | None
    error: str | None


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
        self.running = False
        self.auth_busy = False
        self.auth_sock = None
        self.generation = 0
        self.closing = False
        self.events = queue.Queue()
        self.outgoing = queue.Queue(maxsize=100)
        self.workers = []
        self._lock = threading.Lock()
        self.start_worker(self._send_loop)

    def start_worker(self, target, *args):
        self.workers = [worker for worker in self.workers if worker.is_alive()]
        worker = threading.Thread(target=target, args=args, daemon=True)
        self.workers.append(worker)
        worker.start()

    def authenticate(self, username, password, *, register=False):
        with self._lock:
            if self.auth_busy or self.closing or self.running:
                return False
            self.generation += 1
            generation = self.generation
            self.auth_busy = True
        endpoint = (self.settings.host, self.settings.port)
        self.start_worker(self._authenticate, generation, endpoint, username, password, register)
        return True

    def _authenticate(self, generation, endpoint, username, password, register):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        key, error, keep = None, None, False
        try:
            with self._lock:
                if generation != self.generation or self.closing:
                    return
                self.auth_sock = sock
            sock.settimeout(10)
            sock.connect(endpoint)
            public_key, key_error = protocol.check_server_public_key(
                protocol.recv_msg(sock), host=endpoint[0],
                expected_fingerprint=self.settings.expected_fingerprint)
            if key_error:
                raise ValueError(key_error)
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
            if not isinstance(response, dict) or response.get('type') != expected or not response.get('success'):
                raise ValueError(response.get('error', '认证失败') if isinstance(response, dict) else '服务器未响应')
            with self._lock:
                keep = not register and generation == self.generation and not self.closing
        except Exception as exc:
            error = str(exc)
        finally:
            if not keep:
                self._close_socket(sock)
            self.events.put(AuthResult(generation, username, register, endpoint, sock, key, error))

    def accept_auth(self, result):
        """Called by the controller on its owner thread, before starting reception."""
        with self._lock:
            if result.generation != self.generation or self.closing:
                self._close_socket(result.sock)
                return False
            self.auth_sock = None
            self.auth_busy = False
            if result.error is None and not result.register:
                self.sock, self.session_key, self.endpoint = result.sock, result.key, result.endpoint
                protocol.authenticated_sockets.add(result.sock)
                self.running = True
        return True

    def receive(self):
        self.start_worker(self._receive_loop, self.sock)

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
        protocol.authenticated_sockets.discard(sock)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        transport.forget(sock)

    def cancel_auth(self):
        with self._lock:
            self.generation += 1
            sock, self.auth_sock = self.auth_sock, None
            self.auth_busy = False
        if sock is not None:
            self._close_socket(sock)

    def disconnect(self):
        self.running = False
        sock, self.sock = self.sock, None
        self.session_key = self.endpoint = None
        if sock is not None:
            self._close_socket(sock)

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
