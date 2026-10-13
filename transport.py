"""Protocol v2: authenticate every frame, its direction and a replay counter.

RSA establishes the session key. Existing AES-GCM payload encryption protects
message bodies and credentials; HMAC-SHA256 also authenticates routing/control
fields. This is client/server encryption, not end-to-end encryption.
"""
import hmac
import struct
import threading
import weakref

VERSION = 2
MAX_WIRE_LEN = 1024 * 1024
FRAME_OVERHEAD = 40  # uint64 sequence + SHA-256 MAC
MAX_PAYLOAD_LEN = MAX_WIRE_LEN - FRAME_OVERHEAD
_states = weakref.WeakKeyDictionary()
_guard = threading.Lock()


class State:
    def __init__(self, key, server):
        client_key = hmac.digest(key, b'chatroom/frame/v2/client', 'sha256')
        server_key = hmac.digest(key, b'chatroom/frame/v2/server', 'sha256')
        self.send_key, self.recv_key = (server_key, client_key) if server else (client_key, server_key)
        self.send_seq = self.recv_seq = 0
        self.send_lock = threading.Lock()


def configure(sock, key, *, server=False):
    if len(key) not in (16, 24, 32):
        raise ValueError('Invalid session key length')
    with _guard:
        _states[sock] = State(key, server)


def state_for(sock):
    with _guard:
        try:
            return _states.get(sock)
        except TypeError:  # Non-weakrefable test doubles have no session.
            return None


def forget(sock):
    with _guard:
        _states.pop(sock, None)


def send_packet(sock, packet):
    state = state_for(sock)
    if state is None:
        sock.sendall(packet)
        return
    body = packet[4:]
    if len(body) > MAX_PAYLOAD_LEN:
        raise ValueError('Message exceeds authenticated frame size limit')
    with state.send_lock:
        sequence = struct.pack('!Q', state.send_seq)
        authenticated = sequence + body
        data = authenticated + hmac.digest(state.send_key, authenticated, 'sha256')
        sock.sendall(struct.pack('!I', len(data)) + data)
        state.send_seq += 1


def decode(sock, data):
    state = state_for(sock)
    if state is None:
        return data
    if len(data) < FRAME_OVERHEAD:
        raise ValueError('Unauthenticated frame rejected')
    authenticated, signature = data[:-32], data[-32:]
    if not hmac.compare_digest(signature, hmac.digest(state.recv_key, authenticated, 'sha256')):
        raise ValueError('Frame authentication failed')
    sequence = struct.unpack('!Q', authenticated[:8])[0]
    if sequence != state.recv_seq:
        raise ValueError('Replayed or out-of-order frame rejected')
    state.recv_seq += 1
    return authenticated[8:]
