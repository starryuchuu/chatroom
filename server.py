from server_handlers import HandlerServices, dispatch
import socket
import transport
import pending_store
import history_store
import send_receipts
import storage
import e2ee_server
import opaque_server
import threading
import time
import datetime
import sqlite3
from contextlib import closing
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import os
import base64
import struct
import logging
import json
import uuid # 用于生成群组ID
import stat
import queue

# 安全配置常量
RSA_KEY_SIZE = 3072  # 使用更强的 RSA 密钥长度
SERVER_BIND_HOST = '127.0.0.1'  # 仅监听本地回环地址，防止外部访问
SERVER_PORT = 12345
SESSION_TIMEOUT_MINUTES = 30  # 会话过期时间（分钟）
RATE_LIMIT_MAX_ATTEMPTS = 5  # 最大尝试次数
RATE_LIMIT_WINDOW_SECONDS = 60  # 速率限制时间窗口（秒）
PENDING_REQUEST_TIMEOUT_SECONDS = 24 * 3600  # 好友请求过期时间，防止对方不响应时请求者永远无法再次申请
LOG_SENSITIVE_DATA = False  # 是否记录敏感数据
PRIVATE_KEY_PERMISSIONS = stat.S_IRUSR | stat.S_IWUSR  # 仅所有者可读写 (600)
DB_FILE_PERMISSIONS = stat.S_IRUSR | stat.S_IWUSR  # 仅所有者可读写 (600)

# 安全加固配置
MAX_MESSAGE_LEN = transport.MAX_PAYLOAD_LEN  # 单条消息最大长度（字节），防止内存耗尽攻击
AUTH_TIMEOUT_SECONDS = 30  # 认证阶段套接字超时（秒）
GROUP_NAME_MAX_LEN = 128
MAX_GROUP_MEMBERS = e2ee_server.MAX_RECIPIENTS
# Bound the original JSON list before hashing, deduplication or database work.
MAX_RAW_GROUP_MEMBERS = MAX_GROUP_MEMBERS
GROUP_CAPACITY_ERROR = '群聊最多支持256位成员'
USERNAME_MIN_LEN = 2  # 用户名最小长度
USERNAME_MAX_LEN = 20  # 用户名最大长度
PASSWORD_MIN_LEN = 6  # 密码最小长度
PASSWORD_MAX_LEN = 64  # 密码最大长度
MAX_SYNC_ID = 9007199254740991  # Exact JSON integer range shared with Go clients.


# 配置日志记录，设置日志级别为INFO，格式为时间-级别-消息
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 全局变量，存储客户端连接、用户名和好友关系
clients = []
usernames = {} # {socket: username}
session_keys = {} # {socket: session_key}
session_timestamps = {} # {socket: login_timestamp} 用于会话过期检查
user_friends = {} # {username: set(friends)}
groups_data = {} # {gid: {group_name, owner, members}}

# 速率限制跟踪：{ip_address: [(timestamp, attempt_count)]}
rate_limit_tracker = {}
rate_limit_lock = threading.Lock()

# 待处理的好友请求：{(requester, target): 创建时间戳}，仅真实收到请求者可响应，防止伪造好友关系。
# 带过期时间，避免目标用户永远不响应时请求者无法再次申请、集合无限增长。
pending_friend_requests = {}
pending_friend_requests_lock = threading.Lock()
# 待加入群组的用户：{gid: {username: (inviter, created_at)}}，仅收到过邀请的用户可加入，防止越权加入群组
group_pending_joins = {}
group_pending_joins_lock = threading.Lock()

# 线程锁，用于保护共享数据
clients_lock = threading.Lock()
usernames_lock = threading.Lock()
# Owned by a connection from the beginning of login/migration until online
# publication or failure. The online map and reservations share the same lock.
auth_reservations = {}
session_keys_lock = threading.Lock()
user_friends_lock = threading.Lock()
groups_data_lock = threading.Lock()
authentication_slots = threading.BoundedSemaphore(4)
connection_slots = threading.BoundedSemaphore(128)
# 群成员读-改-写串行化锁：并发 join/leave/kick 同一群组时防止互相覆盖
class GroupOperationLock:
    """Stage immutable notifications in commit order; no network I/O in the lock."""
    def __init__(self):
        self.lock = threading.Lock()
        self.local = threading.local()

    def acquire(self):
        self.lock.acquire()
        self.local.notifications = []

    def release(self):
        ready = threading.Event()
        try:
            for sock, data in self.local.notifications:
                enqueue_packet(sock, data, ready=ready)
        finally:
            del self.local.notifications
            self.lock.release()
            ready.set()

group_ops_lock = GroupOperationLock()


# 检查并生成/加载RSA密钥
def ensure_rsa_keys():
    """
    加载服务器身份；仅首次启动生成私钥，公钥可从现有私钥恢复。
    返回: (private_key, public_key_pem)
    """
    if not os.path.exists("private_key.pem"):
        if os.path.exists("public_key.pem"):
            raise RuntimeError("私钥文件丢失；请恢复原私钥，拒绝自动更换服务器身份")
        generated = RSA.generate(RSA_KEY_SIZE)
        # 独占创建，避免并发启动覆盖另一进程刚生成的服务器身份。
        fd = os.open("private_key.pem", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                     PRIVATE_KEY_PERMISSIONS)
        with os.fdopen(fd, "wb") as f:
            f.write(generated.export_key())
        logging.info("RSA private key 'private_key.pem' generated.")

    try:
        with open("private_key.pem", "rb") as f:
            private_key = RSA.import_key(f.read())
        if not private_key.has_private():
            raise ValueError("文件不包含RSA私钥")
    except (OSError, ValueError, IndexError, TypeError) as exc:
        raise RuntimeError("无法加载RSA私钥；保留原文件，请恢复有效私钥") from exc

    try:
        with open("public_key.pem", "rb") as f:
            public_key_pem = f.read()
    except FileNotFoundError:
        public_key_pem = b""
    try:
        public_key = RSA.import_key(public_key_pem)
        matches = (not public_key.has_private() and
                   public_key.n == private_key.n and public_key.e == private_key.e)
    except (ValueError, IndexError, TypeError):
        matches = False
    if not matches:
        public_key_pem = private_key.publickey().export_key()
        with open("public_key.pem", "wb") as f:
            f.write(public_key_pem)
        logging.info("RSA public key repaired from the existing private key.")
    return private_key, public_key_pem

# 速率限制检查函数（只统计"认证失败"次数，连接数与成功登录不计入，
# 否则同一 IP/NAT 后的多个用户正常使用也会被误封）
def is_rate_limited(ip_address):
    """
    检查 IP 地址的失败尝试是否超出速率限制。
    返回：True 如果应该拒绝，False 如果允许
    """
    current_time = datetime.datetime.now().timestamp()
    with rate_limit_lock:
        # 定期清理无活动 IP 的记录，防止字典无限增长（内存泄漏）
        if len(rate_limit_tracker) > 1000:
            stale_ips = [ip for ip, records in rate_limit_tracker.items()
                         if not records or current_time - records[-1] >= RATE_LIMIT_WINDOW_SECONDS]
            for ip in stale_ips:
                del rate_limit_tracker[ip]

        records = rate_limit_tracker.get(ip_address)
        if not records:
            return False
        recent = [t for t in records if current_time - t < RATE_LIMIT_WINDOW_SECONDS]
        rate_limit_tracker[ip_address] = recent
        return len(recent) >= RATE_LIMIT_MAX_ATTEMPTS

def record_auth_failure(ip_address):
    """
    记录一次认证失败（登录/注册失败）。
    """
    current_time = datetime.datetime.now().timestamp()
    with rate_limit_lock:
        records = rate_limit_tracker.get(ip_address, [])
        records.append(current_time)
        rate_limit_tracker[ip_address] = records

def clear_rate_limit(ip_address):
    """
    显式重置该 IP 的失败记录；成功认证不得调用此函数。
    """
    with rate_limit_lock:
        rate_limit_tracker.pop(ip_address, None)

# 会话过期检查函数
def is_session_expired(client_sock):
    """
    检查会话是否已过期。
    返回：True 如果会话已过期，False 如果仍然有效
    """
    if client_sock not in session_timestamps:
        return True
    
    current_time = datetime.datetime.now().timestamp()
    session_start = session_timestamps[client_sock]
    
    return (current_time - session_start) > (SESSION_TIMEOUT_MINUTES * 60)

# 安全日志函数 - 避免记录敏感信息
def log_message(level, message, sensitive_data=None):
    """
    安全地记录日志，可选择性地过滤敏感数据。
    """
    if LOG_SENSITIVE_DATA and sensitive_data:
        logging.log(level, f"{message}: {sensitive_data}")
    else:
        # 移除或脱敏敏感信息
        safe_message = message
        if sensitive_data:
            safe_message += ": [REDACTED]"
        logging.log(level, safe_message)


private_key, public_key_pem = ensure_rsa_keys()
cipher_rsa_decrypt = PKCS1_OAEP.new(private_key)


# 接收指定字节数的数据
def recvall(sock, n, deadline=None):
    """
    从套接字接收指定字节数的数据。
    参数:
        sock: 套接字对象
        n: 需要接收的字节数
    返回:
        接收到的数据，如果连接关闭则返回None
    """
    data = b''
    while len(data) < n:
        try:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                sock.settimeout(remaining)
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        except socket.timeout:
            if sock in session_timestamps and not is_session_expired(sock):
                continue
            logging.warning("Socket recvall timeout")
            return None
        except Exception as e:
            logging.error('Socket receive failed')
            return None
    return data

# 每个连接一把发送锁：多线程并发向同一 socket sendall 时，
# 长度头与消息体可能交错导致协议流失步，必须串行化整个发送
send_locks = {}
send_locks_guard = threading.Lock()

def get_send_lock(sock):
    with send_locks_guard:
        if sock not in send_locks:
            send_locks[sock] = threading.Lock()
        return send_locks[sock]

def remove_send_lock(sock):
    with send_locks_guard:
        send_locks.pop(sock, None)
    with send_queues_guard:
        outbox = send_queues.pop(sock, None)
    if outbox is not None:
        try:
            outbox.put_nowait(None)
        except queue.Full:
            pass

# 发送消息，包含消息长度头部
SEND_TIMEOUT_SECONDS = 5
send_queues = {}
send_queues_guard = threading.Lock()

def close_connection(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass

def send_worker(sock, outbox):
    try:
        while True:
            item = outbox.get()
            if item is None:
                return
            packet, ready = item
            if ready is not None:
                ready.wait()
            with get_send_lock(sock):
                transport.send_packet(sock, packet)
    except Exception:
        logging.error("发送超时或连接关闭")
        close_connection(sock)
    finally:
        with send_queues_guard:
            if send_queues.get(sock) is outbox:
                send_queues.pop(sock, None)
        with send_locks_guard:
            send_locks.pop(sock, None)

def enqueue_packet(sock, packet, ready=None):
    with send_queues_guard:
        outbox = send_queues.get(sock)
        if outbox is None:
            outbox = queue.Queue(maxsize=256)
            send_queues[sock] = outbox
            threading.Thread(target=send_worker, args=(sock, outbox), daemon=True).start()
    try:
        if ready is not None or getattr(group_ops_lock.local, 'notifications', None) is not None:
            outbox.put_nowait((packet, ready))
        else:
            outbox.put((packet, ready), timeout=SEND_TIMEOUT_SECONDS)
    except queue.Full:
        close_connection(sock)

def validate_chat_packet(kind, sender, recipient, gid, content, timestamp, *, e2ee=False):
    # Saved messages must fit both live delivery and later replay metadata.
    payload = {'type': kind, 'from': sender,
               'timestamp': timestamp, 'message_id': 9223372036854775807,
               'history': True, 'sync': True}
    payload.update(chat_content(content, None, e2ee=e2ee, already_encrypted=True))
    payload['gid' if kind == 'group_chat' else 'to'] = gid if kind == 'group_chat' else recipient
    if len(json.dumps(payload).encode('utf-8')) > MAX_MESSAGE_LEN:
        raise ValueError('消息内容过长，无法转发')

def send_msg(sock, msg, *, ready=None):
    data = json.dumps(msg).encode('utf-8') if isinstance(msg, dict) else str(msg).encode('utf-8')
    if len(data) > MAX_MESSAGE_LEN:
        raise ValueError("消息包超过大小限制")
    packet = struct.pack('!I', len(data)) + data
    staged = getattr(group_ops_lock.local, 'notifications', None)
    if staged is not None:
        staged.append((sock, packet))
    elif ready is not None or sock in session_timestamps:
        enqueue_packet(sock, packet, ready=ready)
    else:
        with get_send_lock(sock):
            transport.send_packet(sock, packet)

# 接收消息，读取消息长度头部并接收完整消息
def recv_msg(sock, deadline=None):
    """
    从套接字接收消息，首先读取长度头部，然后接收完整消息。
    参数:
        sock: 套接字对象
    返回:
        接收到的消息 dict 或 str，如果连接关闭则返回None
    """
    try:
        header = recvall(sock, 4, deadline)
        if not header:
            return None
        msg_len = struct.unpack('!I', header)[0]
        if msg_len > transport.MAX_WIRE_LEN:
            logging.warning('Oversized packet rejected')
            return None
        data = recvall(sock, msg_len, deadline)
        if data is None:
            return None
        data = transport.decode(sock, data)
        try:
            return json.loads(data.decode('utf-8'))
        except json.JSONDecodeError:
            return data.decode('utf-8')
    except Exception as e:
        logging.error('Packet decoding failed')
        return None

# 使用AES-GCM模式加密消息
def encrypt_message(message, key):
    """
    使用AES-GCM模式加密消息。
    参数:
        message: 要加密的消息字符串
        key: 会话密钥
    返回:
        加密后的消息 (nonce, ciphertext, tag)，base64编码
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(cipher.nonce + ciphertext + tag).decode('utf-8')

# 使用AES-GCM模式解密消息
def decrypt_message(encrypted_message, key):
    """
    使用AES-GCM模式解密消息。
    参数:
        encrypted_message: 加密的消息，base64编码
        key: 会话密钥
    返回:
        解密后的消息字符串
    """
    data = base64.b64decode(encrypted_message)
    nonce = data[:16]
    ciphertext = data[16:-16]
    tag = data[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# 初始化数据库，创建用户、消息和好友关系表
def init_db():
    """
    初始化数据库，创建必要的表结构。
    """
    conn = storage.connect("chat.db")
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_type TEXT NOT NULL,
                from_user TEXT NOT NULL,
                to_user TEXT,
                gid TEXT,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        if 'e2ee' not in {row[1] for row in cursor.execute('PRAGMA table_info(messages)')}:
            cursor.execute('ALTER TABLE messages ADD COLUMN e2ee INTEGER NOT NULL DEFAULT 0')
        cursor.execute('CREATE TABLE IF NOT EXISTS e2ee_identities (username TEXT PRIMARY KEY,identity TEXT NOT NULL)')
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS friends (
                user TEXT NOT NULL,
                friend TEXT NOT NULL,
                UNIQUE(user, friend)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                gid TEXT PRIMARY KEY,
                group_name TEXT NOT NULL,
                owner TEXT NOT NULL,
                members TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        cursor.executescript(pending_store.SCHEMA)
        cursor.execute(send_receipts.SCHEMA)
        cursor.execute("CREATE INDEX IF NOT EXISTS messages_private_from ON messages(chat_type,from_user,id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS messages_private_to ON messages(chat_type,to_user,id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS messages_group ON messages(chat_type,gid,id)")
        conn.commit()
        storage.initialize(conn)
    finally:
        conn.close()
    opaque_server.initialize()
    restore_pending_requests()
    # 设置数据库文件权限为仅所有者可读写 (600)
    if os.path.exists("chat.db"):
        os.chmod("chat.db", DB_FILE_PERMISSIONS)

def restore_pending_requests():
    friends, invites = pending_store.load()
    with pending_friend_requests_lock:
        pending_friend_requests.clear()
        pending_friend_requests.update({(sender, target): created for sender, target, created in friends})
    with group_pending_joins_lock:
        group_pending_joins.clear()
        for gid, target, inviter, created in invites:
            group_pending_joins.setdefault(gid, {})[target] = (inviter, created)

# 加载用户的好友列表
def load_friends(username):
    """
    从数据库加载用户的好友列表。
    参数:
        username: 用户名
    返回:
        好友列表集合
    """
    conn = storage.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT friend FROM friends WHERE user=?", (storage.token(username),))
    rows = cursor.fetchall()
    conn.close()
    with closing(storage.connect()) as db:
        return {storage.name(db, row[0]) for row in rows}

# 保存好友关系到数据库
def save_friend_relationship(user1, user2):
    """
    保存两个用户之间的好友关系到数据库。
    参数:
        user1: 用户1
        user2: 用户2
    """
    conn = storage.connect("chat.db")
    cursor = conn.cursor()
    try:
        user1 = storage.put_name(conn, user1)
        user2 = storage.put_name(conn, user2)
        cursor.execute("INSERT OR IGNORE INTO friends (user, friend) VALUES (?, ?)", (user1, user2))
        cursor.execute("INSERT OR IGNORE INTO friends (user, friend) VALUES (?, ?)", (user2, user1))
        cursor.execute("DELETE FROM pending_friend_requests WHERE (requester=? AND target=?) OR (requester=? AND target=?)",
                       (user1, user2, user2, user1))
        conn.commit()
    except Exception as e:
        conn.rollback()
        logging.error('Friend relationship persistence failed')
        raise
    finally:
        conn.close()

# 对密码进行哈希处理
def hash_password(password):
    """
    对密码进行Argon2哈希处理。
    参数:
        password: 明文密码
    返回:
        哈希后的密码字符串（带盐，安全）
    """
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    return ph.hash(password)

# 注册新用户
def register_user(username, password):
    """
    注册新用户，将用户名和哈希后的密码保存到数据库。
    参数:
        username: 用户名
        password: 密码
    返回:
        (成功与否, 错误信息)；成功时错误信息为空字符串
    """
    # 输入校验：限制长度，防止超大字段撑爆数据库
    if not isinstance(username, str) or not isinstance(password, str):
        return False, "用户名和密码格式错误"
    if not (USERNAME_MIN_LEN <= len(username) <= USERNAME_MAX_LEN):
        return False, "用户名长度必须在 %d-%d 个字符之间" % (USERNAME_MIN_LEN, USERNAME_MAX_LEN)
    if not (PASSWORD_MIN_LEN <= len(password) <= PASSWORD_MAX_LEN):
        return False, "密码长度必须在 %d-%d 个字符之间" % (PASSWORD_MIN_LEN, PASSWORD_MAX_LEN)

    password_hash = hash_password(password)
    conn = storage.connect("chat.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                      (storage.put_name(conn, username), storage.seal(password_hash, "users", "password", storage.token(username))))
        conn.commit()
        return True, ""
    except sqlite3.IntegrityError:
        conn.rollback()
        return False, "用户名已存在"
    finally:
        conn.close()

# 验证用户登录信息
def validate_user(username, password):
    """
    验证用户的用户名和密码是否正确。
    参数:
        username: 用户名
        password: 密码
        验证成功返回True，否则返回False
    """
    if opaque_server.has_account(username):
        return False
    conn = storage.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username=?", (storage.token(username),))
    row = cursor.fetchone()
    conn.close()
    if row:
        from argon2 import PasswordHasher, exceptions
        ph = PasswordHasher()
        try:
            encoded = storage.open_field(row[0], "users", "password", storage.token(username))
            if encoded == opaque_server.LEGACY_DISABLED:
                return False
            valid = ph.verify(encoded, password)
            return valid and not opaque_server.has_account(username)
        except exceptions.VerifyMismatchError:
            return False
        except (exceptions.InvalidHashError, exceptions.VerificationError, exceptions.InvalidHash) as e:
            # 哈希损坏/格式无效等异常也应视为验证失败，而不是导致线程崩溃
            logging.error("Stored legacy credential verification failed")
            return False
    return False

# 保存消息到数据库
def save_message(chat_type, from_user, to_user, gid, message, timestamp, *, e2ee=False):
    """
    保存聊天消息到数据库。
    参数:
        chat_type: 聊天类型（group或private）
        from_user: 发送者
        to_user: 接收者（私聊时使用）
        gid: 群组ID（群聊时使用）
        message: 消息内容
        timestamp: 时间戳
    """
    conn = storage.connect("chat.db")
    cursor = conn.cursor()
    try:
        message_id = storage.save_message(conn, chat_type, from_user, to_user, gid, message, timestamp, e2ee=e2ee)
        conn.commit()
        return message_id
    except Exception as e:
        conn.rollback()
        logging.error('Message persistence failed')
        raise
    finally:
        conn.close()

# 发送用户所属的群组列表
def save_message_once(chat_type, from_user, to_user, gid, message, timestamp, *, e2ee, key):
    with closing(storage.connect('chat.db')) as conn:
        with conn:
            return send_receipts.save(conn, chat_type, from_user, to_user, gid, message,
                                      timestamp, e2ee=e2ee, key=key)


def lookup_send_receipt(username, key, kind, target):
    with closing(storage.connect('chat.db')) as conn:
        return send_receipts.lookup(conn, username, key, kind, target)


def send_user_groups(client_sock, username):
    """
    查找用户所属的所有群组并发送给客户端。
    """
    group_ops_lock.acquire()
    try:
        conn = storage.connect("chat.db")
        cursor = conn.cursor()
        cursor.execute("SELECT gid, group_name, owner, members FROM groups")
        rows = cursor.fetchall()

        user_groups = []
        for row in rows:
            gid, group_name, owner, members_json = storage.decode_group(row)
            members = json.loads(members_json)
            if username in members:
                user_groups.append({
                    "gid": gid,
                    "group_name": group_name,
                    "owner": owner,
                    "members": members
                })

        conn.close()

        payload = {"type": "user_groups_list", "groups": user_groups}
        serialized = json.dumps(payload)
        if len(serialized.encode('utf-8')) <= MAX_MESSAGE_LEN:
            send_msg(client_sock, payload)
        else:
            # ensure_ascii JSON is ASCII; wrapping doubles quotes and backslashes at most.
            chunk_size = max(1, (MAX_MESSAGE_LEN - 256) // 2)
            for offset in range(0, len(serialized), chunk_size):
                send_msg(client_sock, {"type": "user_groups_chunk",
                                      "data": serialized[offset:offset + chunk_size],
                                      "first": offset == 0,
                                      "last": offset + chunk_size >= len(serialized)})
    finally:
        group_ops_lock.release()


def send_replay_message(client_sock, payload):
    """Keep previously accepted near-limit records readable with new markers."""
    if len(json.dumps(payload).encode('utf-8')) <= MAX_MESSAGE_LEN:
        send_msg(client_sock, payload)
        return
    # Older versions budgeted only live fields. Compact encoding often leaves
    # enough room for replay markers without changing any message contents.
    compact = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
    if len(compact.encode('utf-8')) <= MAX_MESSAGE_LEN:
        send_msg(client_sock, compact)
        return
    legacy = dict(payload)
    for marker in ('history_request_id', 'sync', 'history', 'encryption'):
        legacy.pop(marker, None)
        compact = json.dumps(legacy, ensure_ascii=False, separators=(',', ':'))
        if len(compact.encode('utf-8')) <= MAX_MESSAGE_LEN:
            send_msg(client_sock, compact)
            return
    # The framing layer rejects an already-invalid legacy record rather than
    # silently changing its text or timestamp.
    send_msg(client_sock, compact)


# 发送聊天历史记录给客户端
def chat_content(content, key, *, e2ee=False, already_encrypted=False):
    if e2ee:
        envelope = content if isinstance(content, dict) else json.loads(content)
        return {'e2ee': envelope, 'encryption': 'e2ee_v1'}
    return {'content': content if already_encrypted else encrypt_message(content, key),
            'encryption': 'legacy'}


def valid_history_request_id(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        return False
    try:
        value.encode('utf-8')
        return True
    except UnicodeError:
        return False


def send_history_error(client_sock, error, *, kind=None, target=None, request_id=None):
    payload = {'type': 'history_error', 'error': error}
    if valid_history_request_id(request_id):
        payload['request_id'] = request_id
    if kind in ('private', 'group') and isinstance(target, str) and target:
        payload.update(history_kind=kind, history_target=target)
    send_msg(client_sock, payload)


def send_history(client_sock, username, only_gid=None, *, kind=None, target=None, before=None, request_id=None):
    session_key = session_keys.get(client_sock)
    if not session_key:
        return
    if only_gid is not None:
        kind, target = 'group', only_gid
    correlation = {'request_id': request_id} if valid_history_request_id(request_id) else {}
    scope = {'history_kind': kind, 'history_target': target} if kind is not None else {}
    try:
        with closing(storage.connect("chat.db")) as conn:
            boundary = conn.execute("SELECT COALESCE(MAX(id),0) FROM messages").fetchone()[0]
        send_msg(client_sock, dict(type='history_begin', **scope, **correlation))
        rows, has_more = history_store.page(username, boundary, before=before, kind=kind, target=target)
        for message_id, chat_type, sender, recipient, gid, message, timestamp, *encryption in rows:
            payload = {"type":chat_type+"_chat", "from":sender,
                       "timestamp":timestamp, "message_id":message_id, "history": True}
            payload.update(chat_content(message, session_key, e2ee=bool(encryption and encryption[0])))
            if correlation:
                payload['history_request_id'] = request_id
            payload['gid' if chat_type=='group' else 'to'] = gid if chat_type=='group' else recipient
            if chat_type == 'group':
                group_ops_lock.acquire()
                try:
                    group = get_group_db(gid)
                    if group and username in group['members']:
                        send_replay_message(client_sock, payload)
                finally:
                    group_ops_lock.release()
            else:
                send_replay_message(client_sock, payload)
        end = dict(type='history_end', boundary=boundary, **correlation)
        if kind is not None:
            end.update(history_kind=kind, history_target=target, has_more=has_more,
                       before_id=rows[0][0] if rows else before or boundary)
        elif has_more:
            end['has_more'] = True
        send_msg(client_sock,end)
    except Exception:
        logging.error("历史同步失败")
        if kind is not None:
            send_history_error(client_sock, '历史加载失败，请重试', kind=kind, target=target, request_id=request_id)
        else:
            send_msg(client_sock, {"type": "error", "message": "历史同步失败，请重新登录"})


def send_sync(client_sock, username, request):
    """Replay one authorized, forward-only page for an interrupted session."""
    request_id = request.get('request_id')
    valid_request_id = isinstance(request_id, str) and 0 < len(request_id) <= 128
    correlation = {'request_id': request_id} if valid_request_id else {}

    def error(text):
        send_msg(client_sock, dict(type='sync_error', error=text, **correlation))

    def valid_cursor(value):
        return (type(value) in (int, float) and 0 <= value <= MAX_SYNC_ID
                and int(value) == value)

    after = request.get('after_id')
    boundary = request.get('boundary')
    if (not valid_request_id or not valid_cursor(after)
            or ('boundary' in request and not valid_cursor(boundary))):
        error('同步查询参数错误')
        return
    after = int(after)
    try:
        with closing(storage.connect("chat.db")) as conn:
            current = conn.execute("SELECT COALESCE(MAX(id),0) FROM messages").fetchone()[0]
        boundary = int(boundary) if 'boundary' in request else current
        if not after <= boundary <= current or boundary > MAX_SYNC_ID:
            error('同步游标已失效，请重新登录')
            return
        session_key = session_keys.get(client_sock)
        if not session_key:
            error('会话密钥未建立')
            return
        send_msg(client_sock, dict(type='sync_begin', after_id=after, boundary=boundary,
                                  **correlation))
        rows, has_more = history_store.sync_page(username, after, boundary)
        for message_id, chat_type, sender, recipient, gid, content, timestamp, *encryption in rows:
            payload = {'type': chat_type + '_chat', 'from': sender,
                       'timestamp': timestamp, 'message_id': message_id,
                       'history': True, 'sync': True}
            payload.update(chat_content(content, session_key, e2ee=bool(encryption and encryption[0])))
            payload['gid' if chat_type == 'group' else 'to'] = gid if chat_type == 'group' else recipient
            if chat_type == 'group':
                # Removal/disband and this enqueue use the same operation lock;
                # an obsolete query result must not disclose a removed group's text.
                group_ops_lock.acquire()
                try:
                    group = get_group_db(gid)
                    if group and username in group['members']:
                        send_replay_message(client_sock, payload)
                finally:
                    group_ops_lock.release()
            else:
                send_replay_message(client_sock, payload)
        next_after = rows[-1][0] if has_more else boundary
        send_msg(client_sock, dict(type='sync_end', after_id=after, boundary=boundary,
                                  next_after_id=next_after, has_more=has_more, **correlation))
    except Exception:
        logging.error('断线消息同步失败')
        error('消息同步失败，请重试')

# 检查用户是否存在
def _e2ee_request_id(request):
    value = request.get('request_id')
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise e2ee_server.E2EEError('端到端加密请求编号无效')
    try:
        value.encode('utf-8')
    except UnicodeError as error:
        raise e2ee_server.E2EEError('端到端加密请求编号无效') from error
    return value


def handle_e2ee_identity(client_sock, username, request):
    reply = {'type': 'e2ee_identity_result', 'success': False}
    # Enrollment and message commits use the same lock: a successful identity
    # binding can never be followed by a racing plaintext message commit.
    group_ops_lock.acquire()
    try:
        reply['request_id'] = _e2ee_request_id(request)
        reply['identity'] = e2ee_server.publish_identity(
            username, request.get('identity'), request.get('proof'))
        reply['success'] = True
    except (ValueError, TypeError, KeyError) as error:
        reply['error'] = str(error) if isinstance(error, e2ee_server.E2EEError) else '端到端身份保存失败，请重试'
        try:
            reply['identity'] = e2ee_server.get_identity(username)
        except Exception:
            pass
    except Exception:
        logging.error('端到端身份保存失败')
        reply['error'] = '端到端身份保存失败，请重试'
    finally:
        group_ops_lock.release()
    send_msg(client_sock, reply)


def handle_e2ee_keys(client_sock, username, request):
    reply = {'type': 'e2ee_keys', 'success': False}
    group_ops_lock.acquire()
    try:
        reply['request_id'] = _e2ee_request_id(request)
        kind, target = request.get('kind'), request.get('target')
        if kind not in ('private', 'group') or not isinstance(target, str) or not 1 <= len(target) <= 256:
            raise e2ee_server.E2EEError('端到端会话参数错误')
        reply.update(kind=kind, target=target)
        if kind == 'private':
            with user_friends_lock:
                allowed = target != username and target in user_friends.get(username, set())
            if not allowed:
                raise e2ee_server.E2EEError('无权读取该会话的端到端密钥')
            members = sorted({username, target})
        else:
            group = get_group_db(target)
            if group is None or username not in group['members']:
                raise e2ee_server.E2EEError('无权读取该会话的端到端密钥')
            members = sorted(set(group['members']))
        identities, missing = e2ee_server.identities_for(members)
        reply.update(success=True, members=members, identities=identities, missing=missing)
    except e2ee_server.E2EEError as error:
        reply['error'] = str(error)
    except Exception:
        logging.error('读取端到端会话密钥失败')
        reply['error'] = '读取端到端会话密钥失败，请重试'
    finally:
        group_ops_lock.release()
    send_msg(client_sock, reply)


def prepare_chat_content(request, sender, kind, target, members, session_key, timestamp):
    if 'e2ee' in request:
        if 'content' in request:
            raise e2ee_server.E2EEError('端到端消息不能同时携带旧版消息内容')
        envelope = e2ee_server.validate_envelope(request['e2ee'], sender, kind, target, members)
        validate_chat_packet(kind + '_chat', sender, target if kind == 'private' else None,
                             target if kind == 'group' else None, envelope, timestamp, e2ee=True)
        return e2ee_server.canonical(envelope).decode('ascii'), True
    e2ee_server.reject_legacy(members)
    encrypted_content = request.get('content')
    message = decrypt_message(encrypted_content, session_key)
    validate_chat_packet(kind + '_chat', sender, target if kind == 'private' else None,
                         target if kind == 'group' else None, encrypted_content, timestamp)
    return message, False


def user_exists(username):
    """
    检查用户名是否存在于数据库中。
    参数:
        username: 用户名
    返回:
        存在返回True，否则返回False
    """
    conn = storage.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username=?", (storage.token(username),))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

# 根据用户名获取对应的套接字
def get_sock_by_username(username):
    """
    根据用户名查找对应的客户端套接字。
    参数:
        username: 用户名
    返回:
        对应的套接字对象，如果不存在则返回None
    """
    with usernames_lock:
        for sock, uname in usernames.items():
            if uname == username:
                return sock
    return None


def reserve_auth_username(client_sock, username):
    with usernames_lock:
        if username in auth_reservations or username in usernames.values():
            return False
        auth_reservations[username] = client_sock
        return True


def validate_group_creation(owner, group_name, members):
    """Bound untrusted work before entering the shared group-operation lock."""
    if not isinstance(group_name, str) or not 1 <= len(group_name) <= GROUP_NAME_MAX_LEN:
        raise ValueError('群聊名称须为1至128个字符')
    if not isinstance(members, list):
        raise ValueError('成员格式错误')
    if len(members) > MAX_RAW_GROUP_MEMBERS:
        raise ValueError(GROUP_CAPACITY_ERROR)
    if not all(isinstance(member, str) and USERNAME_MIN_LEN <= len(member) <= USERNAME_MAX_LEN
               for member in members):
        raise ValueError('成员格式错误')
    try:
        group_name.encode('utf-8')
        for member in members:
            member.encode('utf-8')
    except UnicodeError as error:
        raise ValueError('群聊名称或成员包含无效字符') from error
    unique = list(dict.fromkeys(members))
    if owner not in unique:
        unique.append(owner)
    if len(unique) > MAX_GROUP_MEMBERS:
        raise ValueError(GROUP_CAPACITY_ERROR)
    return group_name, unique


def group_members_are_friends(owner, members):
    """Validate at most 255 peers with one indexed, bounded query."""
    peers = [storage.token(member) for member in members if member != owner]
    if not peers:
        return True
    with closing(storage.connect()) as db:
        found = db.execute('SELECT friend FROM friends WHERE user=? AND friend IN (' +
                           ','.join('?' for _ in peers) + ')', [storage.token(owner), *peers]).fetchall()
    return len({row[0] for row in found}) == len(peers)

# 用户上线时补发针对该用户的待处理好友请求（修复：离线请求"上线后可见"现在真正可见）
def send_pending_friend_requests(client_sock, username):
    """
    用户登录成功后，将此前离线期间收到的好友请求补发给该用户。
    参数：
        client_sock: 新登录用户的套接字
        username: 新登录用户名
    """
    now = time.time()
    with pending_friend_requests_lock:
        # 顺便清理已过期的请求
        expired = [k for k, ts in pending_friend_requests.items() if now - ts > PENDING_REQUEST_TIMEOUT_SECONDS]
        for k in expired:
            del pending_friend_requests[k]
        pending = [sender for (sender, target) in pending_friend_requests if target == username]
    for sender in pending:
        send_msg(client_sock, {"type": "friend_request", "from": sender})
        logging.info('Pending friend request delivered')

# 用户上线时补发针对该用户的待处理群邀请（修复：离线邀请"上线后可申请加入"现在真正可见）
def send_pending_group_invites(client_sock, username):
    """
    用户登录成功后，将此前离线期间收到的群邀请补发给该用户。
    参数:
        client_sock: 新登录用户的套接字
        username: 新登录用户名
    """
    with group_pending_joins_lock:
        pending = []
        for gid, joins in group_pending_joins.items():
            if username in joins:
                pending.append((gid, joins[username]))
    for gid, invitation in pending:
        inviter, created = invitation if isinstance(invitation, tuple) else (invitation, time.time())
        if time.time() - created > PENDING_REQUEST_TIMEOUT_SECONDS:
            with group_pending_joins_lock:
                group_pending_joins.get(gid, {}).pop(username, None)
            continue
        group = get_group_db(gid)
        if group:
            send_msg(client_sock, {"type": "group_invite", "from": inviter, "gid": gid, "group_name": group["group_name"]})
            logging.info('Pending group invitation delivered')

# 群组相关辅助函数
def create_group_db(owner, group_name, members):
    gid = str(uuid.uuid4())
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = storage.connect("chat.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO groups (gid, group_name, owner, members, created_at) VALUES (?, ?, ?, ?, ?)",
                       (gid, storage.seal(group_name, "groups", "group_name", gid), storage.seal(owner, "groups", "owner", gid), storage.seal(json.dumps(members), "groups", "members", gid), storage.seal(now, "groups", "created_at", gid)))
        conn.commit()
        return gid
    except Exception as e:
        conn.rollback()
        logging.error('Group creation persistence failed')
        return None
    finally:
        conn.close()

def get_group_db(gid):
    with closing(storage.connect("chat.db")) as conn:
        row = conn.execute("SELECT gid, group_name, owner, members, created_at FROM groups WHERE gid=?", (gid,)).fetchone()
    if row:
        row = storage.decode_group(row)
        return {
            "gid": row[0],
            "group_name": row[1],
            "owner": row[2],
            "members": json.loads(row[3]),
            "created_at": row[4]
        }
    return None

def update_group_members_db(gid, members, joined_user=None):
    conn = storage.connect("chat.db")
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE groups SET members=? WHERE gid=?", (storage.seal(json.dumps(members), "groups", "members", gid), gid))
        if joined_user is not None:
            cursor.execute("DELETE FROM pending_group_invites WHERE gid=? AND target=?", (gid,storage.token(joined_user)))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        logging.error('Group membership persistence failed')
        return False
    finally:
        conn.close()

def delete_group_db(gid):
    conn = storage.connect("chat.db")
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM groups WHERE gid=?", (gid,))
        cursor.execute("DELETE FROM pending_group_invites WHERE gid=?", (gid,))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        logging.error('Group deletion persistence failed')
        return False
    finally:
        conn.close()

def update_group_name_db(gid, new_name):
    conn = storage.connect("chat.db")
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE groups SET group_name=? WHERE gid=?", (storage.seal(new_name, "groups", "group_name", gid), gid))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        logging.error('Group rename persistence failed')
        return False
    finally:
        conn.close()

def transfer_group_ownership_db(gid, new_owner):
    conn = storage.connect("chat.db")
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE groups SET owner=? WHERE gid=?", (storage.seal(new_owner, "groups", "owner", gid), gid))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        logging.error('Group ownership persistence failed')
        return False
    finally:
        conn.close()

# 处理客户端连接


def handler_services():
    """Compose live dependencies here so protocol tests can inject failures."""
    return HandlerServices(
        GROUP_CAPACITY_ERROR=GROUP_CAPACITY_ERROR,
        GROUP_NAME_MAX_LEN=GROUP_NAME_MAX_LEN,
        MAX_GROUP_MEMBERS=MAX_GROUP_MEMBERS,
        PENDING_REQUEST_TIMEOUT_SECONDS=PENDING_REQUEST_TIMEOUT_SECONDS,
        chat_content=chat_content,
        create_group_db=create_group_db,
        delete_group_db=delete_group_db,
        get_group_db=get_group_db,
        get_sock_by_username=get_sock_by_username,
        group_members_are_friends=group_members_are_friends,
        group_ops_lock=group_ops_lock,
        group_pending_joins=group_pending_joins,
        group_pending_joins_lock=group_pending_joins_lock,
        groups_data=groups_data,
        groups_data_lock=groups_data_lock,
        handle_e2ee_identity=handle_e2ee_identity,
        handle_e2ee_keys=handle_e2ee_keys,
        pending_friend_requests=pending_friend_requests,
        pending_friend_requests_lock=pending_friend_requests_lock,
        prepare_chat_content=prepare_chat_content,
        save_friend_relationship=save_friend_relationship,
        save_message=save_message,
        save_message_once=save_message_once,
        lookup_send_receipt=lookup_send_receipt,
        send_history=send_history,
        send_history_error=send_history_error,
        send_msg=send_msg,
        send_sync=send_sync,
        session_keys=session_keys,
        transfer_group_ownership_db=transfer_group_ownership_db,
        update_group_members_db=update_group_members_db,
        update_group_name_db=update_group_name_db,
        user_exists=user_exists,
        user_friends=user_friends,
        user_friends_lock=user_friends_lock,
        valid_history_request_id=valid_history_request_id,
        validate_group_creation=validate_group_creation,
    )

def handle_client(client_sock, addr):
    logging.info("Client connection opened")
    
    # 速率限制检查（仅统计认证失败次数，见 is_rate_limited）
    ip_address = addr[0]
    if is_rate_limited(ip_address):
        logging.warning("Authentication rate limit exceeded")
        send_msg(client_sock, {"type": "error", "message": "请求过于频繁，请稍后再试"})
        client_sock.close()
        remove_send_lock(client_sock)
        # 此分支在认证 try/finally 之前退出，也需清理 main() 登记的连接。
        with clients_lock:
            if client_sock in clients:
                clients.remove(client_sock)
        return
    
    current_username = None
    reserved_username = None
    auth_reserved = authentication_slots.acquire(blocking=False)
    if not auth_reserved:
        send_msg(client_sock,{"type":"error","message":"认证繁忙，请稍后再试"})
        client_sock.close()
        remove_send_lock(client_sock)
        with clients_lock:
            if client_sock in clients:clients.remove(client_sock)
        return
    try:
        # 认证阶段设置套接字超时，防止未认证连接无限挂起线程（DoS）
        auth_deadline = time.monotonic() + AUTH_TIMEOUT_SECONDS
        client_sock.settimeout(AUTH_TIMEOUT_SECONDS)

        # 1. 发送公钥
        send_msg(client_sock, {"type": "public_key", "protocol": transport.VERSION,
                               "capabilities": ["message_sync", "e2ee_v1", "opaque_v1", "history_request_id", "message_receipts"], "key": public_key_pem.decode('utf-8')})

        # 2. 接收加密的会话密钥
        encrypted_session_key_data = recv_msg(client_sock, auth_deadline)
        if not isinstance(encrypted_session_key_data, dict) or encrypted_session_key_data.get("type") != "session_key":
            logging.error("Session key exchange rejected")
            return
        
        if encrypted_session_key_data.get("protocol") != transport.VERSION:
            send_msg(client_sock, {"type": "error", "message": "请升级客户端以使用受保护的协议"})
            return
        encrypted_session_key = base64.b64decode(encrypted_session_key_data["key"])
        session_key = cipher_rsa_decrypt.decrypt(encrypted_session_key)
        # 会话密钥必须是合法的 AES 密钥长度，防止畸形密钥导致后续解密行为混乱
        if len(session_key) not in (16, 24, 32):
            send_msg(client_sock, {"type": "error", "message": "无效的会话密钥"})
            logging.error("Invalid session key length")
            return
        transport.configure(client_sock, session_key, server=True)
        with session_keys_lock:
            session_keys[client_sock] = session_key
        logging.info("Session key established")

        auth_data = recv_msg(client_sock, auth_deadline)
        if not isinstance(auth_data, dict):
            record_auth_failure(ip_address)
            send_msg(client_sock, {"type": "login_result", "success": False, "error": "协议错误"})
            logging.error("Authentication protocol rejected")
            return

        if is_rate_limited(ip_address):
            send_msg(client_sock, {"type": "error", "message": "请求过于频繁，请稍后再试"})
            return

        opaque_fields = {}
        if auth_data.get('type') in opaque_server.START_TYPES:
            def admit_account(candidate):
                nonlocal reserved_username
                if reserve_auth_username(client_sock, candidate):
                    reserved_username = candidate
                    return True
                logging.warning('Account admission rejected')
                return False

            outcome = opaque_server.authenticate(
                auth_data, receive=lambda: recv_msg(client_sock, auth_deadline),
                send=lambda packet: send_msg(client_sock, packet),
                server_id=hashlib.sha256(private_key.publickey().export_key(format='DER')).hexdigest(),
                decrypt_legacy=lambda encoded: decrypt_message(encoded, session_key),
                verify_legacy=validate_user, get_identity=e2ee_server.get_identity,
                deadline=auth_deadline, admit=admit_account)
            if outcome.failed:
                record_auth_failure(ip_address)
                logging.warning("OPAQUE authentication rejected")
                return
            if outcome.username is None:
                return
            username = outcome.username
            opaque_fields = outcome.fields
        elif auth_data.get("type") == "encrypted_register":
            try:
                encrypted_data = auth_data.get("data")
                decrypted_data = decrypt_message(encrypted_data, session_key)
                reg_info = json.loads(decrypted_data)
                
                username = reg_info.get("from")
                password = reg_info.get("password")

                reg_ok, reg_err = register_user(username, password)
                if reg_ok:
                    send_msg(client_sock, {"type": "register_result", "success": True})
                    logging.info("Account registration completed")
                else:
                    record_auth_failure(ip_address)
                    send_msg(client_sock, {"type": "register_result", "success": False, "error": reg_err})
                    logging.warning("Account registration rejected")
            except Exception as e:
                logging.error("Legacy account registration failed")
                record_auth_failure(ip_address)
                send_msg(client_sock, {"type": "register_result", "success": False, "error": "注册处理失败"})
            return

        elif auth_data.get("type") == "encrypted_login":
            try:
                decrypted_login = decrypt_message(auth_data.get("data"), session_key)
                login_info = json.loads(decrypted_login)
                username = login_info.get("from")
                password = login_info.get("password")
            except Exception as e:
                logging.error("Legacy credential decoding failed")
                record_auth_failure(ip_address)
                send_msg(client_sock, {"type": "login_result", "success": False, "error": "登录数据处理失败"})
                return

            if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
                record_auth_failure(ip_address)
                send_msg(client_sock, {"type": "login_result", "success": False, "error": "用户名或密码错误"})
                logging.warning("Legacy credential format rejected")
                return

            if not validate_user(username, password):
                record_auth_failure(ip_address)
                send_msg(client_sock, {"type": "login_result", "success": False, "error": "用户名或密码错误"})
                logging.warning("Legacy authentication rejected")
                return
            if not reserve_auth_username(client_sock, username):
                send_msg(client_sock, {'type': 'login_result', 'success': False,
                                       'error': '该用户已登录或正在登录、迁移，请稍后重试'})
                logging.warning('Account admission rejected')
                return
            reserved_username = username
            # A completed migration can occur after the password hash check
            # and before admission. No migration can start while we own this
            # reservation; recheck its atomic credential marker without hashing.
            if opaque_server.has_account(username):
                record_auth_failure(ip_address)
                send_msg(client_sock, {'type': 'login_result', 'success': False,
                                       'error': '用户名或密码错误'})
                logging.warning('Legacy authentication superseded by migration')
                return

        else:
            record_auth_failure(ip_address)
            send_msg(client_sock, {"type": "login_result", "success": False, "error": "协议错误"})
            logging.error("Authentication protocol rejected")
            return

        # 登录成功后设置空闲超时，防止空闲连接无限期占用资源
        client_sock.settimeout(SEND_TIMEOUT_SECONDS)
        # 接受好友的数据库提交也持有 pending_friend_requests_lock。
        # 先加载并入队好友快照，再发布在线连接，增量通知必定排在快照后。
        # ready 在全局锁释放后才放行发送线程，锁内只做有界队列的非阻塞入队。
        ready = threading.Event()
        duplicate_login = False
        try:
            with pending_friend_requests_lock:
                with usernames_lock:
                    if username in usernames.values():
                        duplicate_login = True
                    else:
                        if auth_reservations.get(username) is not client_sock:
                            raise RuntimeError('Account admission reservation missing')
                        friends = load_friends(username)
                        session_timestamps[client_sock] = datetime.datetime.now().timestamp()
                        send_msg(client_sock, {"type": "login_result", "success": True,
                                               "e2ee_identity": e2ee_server.get_identity(username),
                                               **opaque_fields}, ready=ready)
                        send_msg(client_sock, {"type": "friends_list", "friends": list(friends)}, ready=ready)
                        with user_friends_lock:
                            user_friends[username] = friends
                        current_username = username
                        usernames[client_sock] = username
                        del auth_reservations[username]
                        reserved_username = None
        finally:
            ready.set()
        if duplicate_login:
            send_msg(client_sock, {"type": "login_result", "success": False, "error": "该用户已登录"})
            logging.warning("Duplicate login rejected")
            return
        authentication_slots.release()
        auth_reserved = False
        logging.info("Account login completed")

        # 发送用户所属的群组列表
        send_user_groups(client_sock, username)

        send_history(client_sock, username)
        # 补发离线期间收到的好友请求与群邀请（对方离线时积压的请求）
        send_pending_friend_requests(client_sock, username)
        send_pending_group_invites(client_sock, username)
        broadcast_online_users()
        while True:
            # 检查会话是否过期（时间戳在每次收到消息时刷新，属滑动过期：活跃会话不会被强制踢出）
            if is_session_expired(client_sock):
                logging.warning('Account session expired')
                send_msg(client_sock, {"type": "error", "message": "会话已过期，请重新登录"})
                # 短暂等待，确保客户端能读到"会话已过期"消息后再关闭连接
                time.sleep(0.5)
                break
            
            msg = recv_msg(client_sock)
            if msg is None:
                logging.info('Client connection lost')
                break
            # 收到消息视为活跃，刷新会话时间戳（滑动过期）
            session_timestamps[client_sock] = datetime.datetime.now().timestamp()
            if not isinstance(msg, dict):
                logging.warning('Non-object client message rejected')
                continue
            
            logging.debug('Client message received')
            mtype = msg.get("type")
            
            dispatch(handler_services(), client_sock, current_username, msg)

    except ConnectionResetError:
        logging.info('Client connection reset')
    except Exception as e:
        logging.error('Client handler failed')
    finally:
        if auth_reserved:
            authentication_slots.release()
        with clients_lock:
            if client_sock in clients:
                clients.remove(client_sock)
        with session_keys_lock:
            if client_sock in session_keys:
                del session_keys[client_sock]
        with usernames_lock:
            if reserved_username is not None and auth_reservations.get(reserved_username) is client_sock:
                del auth_reservations[reserved_username]
            if current_username and client_sock in usernames and usernames[client_sock] == current_username:
                del usernames[client_sock]
                logging.info('Account disconnected')
                # 若该用户没有其他在线连接，清理其内存中的好友列表，防止泄漏
                if current_username not in usernames.values():
                    with user_friends_lock:
                        user_friends.pop(current_username, None)
        # 清理会话时间戳，防止内存泄漏
        if client_sock in session_timestamps:
            del session_timestamps[client_sock]
        remove_send_lock(client_sock)
        broadcast_online_users()
        client_sock.close()
        transport.forget(client_sock)

def broadcast_online_users():
    """
    广播在线用户列表给所有客户端。
    """
    # 在锁内做快照：避免并发登录/断开时读到半修改状态的 usernames，
    # 同时避免在持有锁的情况下向慢速客户端发送消息导致阻塞。
    with usernames_lock:
        socks = list(usernames.keys())
        user_list = list(usernames.values())
    message = {"type": "online_users", "users": user_list}
    for sock in socks:
        try:
            send_msg(sock, message)
        except Exception as e:
            logging.error('Online status broadcast failed')

# 主函数，启动服务器
def main():
    """
    主函数，初始化数据库并启动服务器监听客户端连接。
    """
    init_db()
    # 加载所有群组到内存
    conn = storage.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT gid, group_name, owner, members FROM groups")
    for row in cursor.fetchall():
        gid, group_name, owner, members_json = storage.decode_group(row)
        groups_data[gid] = {"group_name": group_name, "owner": owner, "members": json.loads(members_json)}
    conn.close()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # 允许端口重用
    server.bind((SERVER_BIND_HOST, SERVER_PORT))
    server.listen(5)
    logging.info("Server started, waiting for connections...")
    while True:
        try:
            client_sock, addr = server.accept()
            if not connection_slots.acquire(blocking=False):
                client_sock.close()
                continue
            with clients_lock:
                clients.append(client_sock)
            logging.info('Client connection accepted')
            def run_connection(sock, address):
                try:
                    handle_client(sock,address)
                finally:
                    connection_slots.release()
            threading.Thread(target=run_connection, args=(client_sock, addr), daemon=True).start()
        except Exception as e:
            logging.error('Connection acceptance failed')

# 程序入口
if __name__ == '__main__':
    main()

