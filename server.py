import socket
import threading
import datetime
import sqlite3
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

# 配置日志记录，设置日志级别为INFO，格式为时间-级别-消息
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 全局变量，存储客户端连接、用户名和好友关系
clients = []
usernames = {} # {socket: username}
session_keys = {} # {socket: session_key}
user_friends = {} # {username: set(friends)}
groups_data = {} # {gid: {group_name, owner, members}}

# 加载RSA密钥
with open("private_key.pem", "rb") as f:
    private_key = RSA.import_key(f.read())
with open("public_key.pem", "rb") as f:
    public_key_pem = f.read()

cipher_rsa_decrypt = PKCS1_OAEP.new(private_key)

def ensure_rsa_keys():
    """
    检查并生成RSA密钥对文件。
    """
    if not (os.path.exists("private_key.pem") and os.path.exists("public_key.pem")):
        key = RSA.generate(2048)
        private_key = key.export_key()
        with open('private_key.pem', 'wb') as f:
            f.write(private_key)
        public_key = key.publickey().export_key()
        with open('public_key.pem', 'wb') as f:
            f.write(public_key)
        print("RSA密钥对 'private_key.pem' 和 'public_key.pem' 已成功生成。")
    with open("private_key.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    with open("public_key.pem", "rb") as f:
        public_key_pem = f.read()
    return private_key, public_key_pem

private_key, public_key_pem = ensure_rsa_keys()
cipher_rsa_decrypt = PKCS1_OAEP.new(private_key)

# 接收指定字节数的数据
def recvall(sock, n):
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
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        except socket.timeout:
            logging.warning("Socket recvall timeout")
            return None
        except Exception as e:
            logging.error(f"recvall error: {e}")
            return None
    return data

# 发送消息，包含消息长度头部
def send_msg(sock, msg):
    """
    向套接字发送消息，消息前附加长度头部。
    参数:
        sock: 套接字对象
        msg: 要发送的消息字符串或字典
    """
    try:
        if isinstance(msg, dict):
            data = json.dumps(msg).encode('utf-8')
        else:
            data = str(msg).encode('utf-8')
        header = struct.pack('!I', len(data))
        sock.sendall(header + data)
    except Exception as e:
        logging.error(f"send_msg error: {e}")

# 接收消息，读取消息长度头部并接收完整消息
def recv_msg(sock):
    """
    从套接字接收消息，首先读取长度头部，然后接收完整消息。
    参数:
        sock: 套接字对象
    返回:
        接收到的消息 dict 或 str，如果连接关闭则返回None
    """
    try:
        header = recvall(sock, 4)
        if not header:
            return None
        msg_len = struct.unpack('!I', header)[0]
        data = recvall(sock, msg_len)
        if not data:
            return None
        try:
            return json.loads(data.decode('utf-8'))
        except json.JSONDecodeError:
            return data.decode('utf-8')
    except Exception as e:
        logging.error(f"recv_msg error: {e}")
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
    conn = sqlite3.connect("chat.db")
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
    conn.commit()
    conn.close()

# 加载用户的好友列表
def load_friends(username):
    """
    从数据库加载用户的好友列表。
    参数:
        username: 用户名
    返回:
        好友列表集合
    """
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT friend FROM friends WHERE user=?", (username,))
    rows = cursor.fetchall()
    conn.close()
    return set([row[0] for row in rows])

# 保存好友关系到数据库
def save_friend_relationship(user1, user2):
    """
    保存两个用户之间的好友关系到数据库。
    参数:
        user1: 用户1
        user2: 用户2
    """
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT OR IGNORE INTO friends (user, friend) VALUES (?, ?)", (user1, user2))
        cursor.execute("INSERT OR IGNORE INTO friends (user, friend) VALUES (?, ?)", (user2, user1))
        conn.commit()
    except Exception as e:
        conn.rollback()
        logging.error(f"保存好友关系失败: {e}")
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
        注册成功返回True，否则返回False
    """
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                      (username, hash_password(password)))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        conn.rollback()
        return False
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
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        from argon2 import PasswordHasher, exceptions
        ph = PasswordHasher()
        try:
            return ph.verify(row[0], password)
        except exceptions.VerifyMismatchError:
            return False
    return False
    return bool(result)

# 保存消息到数据库
def save_message(chat_type, from_user, to_user, gid, message, timestamp):
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
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    try:
        if chat_type == 'group':
            cursor.execute("""
                INSERT INTO messages (chat_type, from_user, gid, message, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (chat_type, from_user, gid, message, timestamp))
        else:
            cursor.execute("""
                INSERT INTO messages (chat_type, from_user, to_user, message, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (chat_type, from_user, to_user, message, timestamp))
        conn.commit()
    except Exception as e:
        conn.rollback()
        logging.error(f"保存消息失败: {e}")
    finally:
        conn.close()

# 发送用户所属的群组列表
def send_user_groups(client_sock, username):
    """
    查找用户所属的所有群组并发送给客户端。
    """
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT gid, group_name, owner, members FROM groups")
    rows = cursor.fetchall()
    
    user_groups = []
    for row in rows:
        gid, group_name, owner, members_json = row
        members = json.loads(members_json)
        if username in members:
            user_groups.append({
                "gid": gid,
                "group_name": group_name,
                "owner": owner,
                "members": members
            })
    
    conn.close()
    
    if user_groups:
        send_msg(client_sock, {"type": "user_groups_list", "groups": user_groups})
        logging.info(f"Sent {len(user_groups)} groups to user '{username}'.")


# 发送聊天历史记录给客户端
def send_history(client_sock, username):
    """
    发送群聊和私聊历史记录给客户端。
    参数:
        client_sock: 客户端套接字
        username: 用户名
    """
    session_key = session_keys.get(client_sock)
    if not session_key:
        return

    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    
    # 发送群聊历史 - 只发送用户所在群组的
    cursor.execute("SELECT gid, members FROM groups")
    all_groups = cursor.fetchall()
    user_gids = [gid for gid, members_json in all_groups if username in json.loads(members_json)]
    
    if user_gids:
        # 使用参数化查询来避免SQL注入
        placeholders = ','.join('?' for _ in user_gids)
        query = f"SELECT from_user, gid, message, timestamp FROM messages WHERE chat_type='group' AND gid IN ({placeholders}) ORDER BY id ASC"
        cursor.execute(query, user_gids)
        rows = cursor.fetchall()
        for row in rows:
            from_user, gid, message, timestamp = row
            encrypted_msg = encrypt_message(message, session_key)
            hist_msg = {
                "type": "group_chat",
                "from": from_user,
                "gid": gid,
                "content": encrypted_msg,
                "timestamp": timestamp
            }
            send_msg(client_sock, hist_msg)
    
    # 发送私聊历史
    cursor.execute("""
        SELECT from_user, to_user, message, timestamp FROM messages 
        WHERE chat_type='private' AND (from_user=? OR to_user=?) 
        ORDER BY id ASC
    """, (username, username))
    rows = cursor.fetchall()
    for row in rows:
        from_user, to_user, message, timestamp = row
        encrypted_msg = encrypt_message(message, session_key)
        hist_msg = {
            "type": "private_chat", # 使用private_chat类型，客户端可以统一处理
            "from": from_user,
            "to": to_user,
            "content": encrypted_msg,
            "timestamp": timestamp
        }
        send_msg(client_sock, hist_msg)
    conn.close()

# 检查用户是否存在
def user_exists(username):
    """
    检查用户名是否存在于数据库中。
    参数:
        username: 用户名
    返回:
        存在返回True，否则返回False
    """
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username=?", (username,))
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
    for sock, uname in usernames.items():
        if uname == username:
            return sock
    return None

# 群组相关辅助函数
def create_group_db(owner, group_name, members):
    gid = str(uuid.uuid4())
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO groups (gid, group_name, owner, members, created_at) VALUES (?, ?, ?, ?, ?)",
                       (gid, group_name, owner, json.dumps(members), now))
        conn.commit()
        return gid
    except Exception as e:
        conn.rollback()
        logging.error(f"创建群组失败: {e}")
        return None
    finally:
        conn.close()

def get_group_db(gid):
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT gid, group_name, owner, members, created_at FROM groups WHERE gid=?", (gid,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "gid": row[0],
            "group_name": row[1],
            "owner": row[2],
            "members": json.loads(row[3]),
            "created_at": row[4]
        }
    return None

def update_group_members_db(gid, members):
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE groups SET members=? WHERE gid=?", (json.dumps(members), gid))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        logging.error(f"更新群组成员失败: {e}")
        return False
    finally:
        conn.close()

def delete_group_db(gid):
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM groups WHERE gid=?", (gid,))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        logging.error(f"删除群组失败: {e}")
        return False
    finally:
        conn.close()

# 处理客户端连接
def handle_client(client_sock, addr):
    logging.info(f"Client connected from {addr}")
    current_username = None
    try:
        # 1. 发送公钥
        send_msg(client_sock, {"type": "public_key", "key": public_key_pem.decode('utf-8')})

        # 2. 接收加密的会话密钥
        encrypted_session_key_data = recv_msg(client_sock)
        if not isinstance(encrypted_session_key_data, dict) or encrypted_session_key_data.get("type") != "session_key":
            logging.error(f"Failed to receive session key from {addr}")
            return
        
        encrypted_session_key = base64.b64decode(encrypted_session_key_data["key"])
        session_key = cipher_rsa_decrypt.decrypt(encrypted_session_key)
        session_keys[client_sock] = session_key
        logging.info(f"Session key established with {addr}")

        auth_data = recv_msg(client_sock)
        if not isinstance(auth_data, dict):
            send_msg(client_sock, {"type": "login_result", "success": False, "error": "协议错误"})
            logging.error(f"Protocol error during authentication from {addr}")
            return

        if auth_data.get("type") == "encrypted_register":
            try:
                encrypted_data = auth_data.get("data")
                decrypted_data = decrypt_message(encrypted_data, session_key)
                reg_info = json.loads(decrypted_data)
                
                username = reg_info.get("from")
                password = reg_info.get("password")

                if register_user(username, password):
                    send_msg(client_sock, {"type": "register_result", "success": True})
                    logging.info(f"User {username} registered successfully from {addr}")
                else:
                    send_msg(client_sock, {"type": "register_result", "success": False, "error": "用户名已存在"})
                    logging.warning(f"Registration failed for {username} from {addr}: 用户名已存在")
            except Exception as e:
                logging.error(f"Error processing encrypted_register from {addr}: {e}")
                send_msg(client_sock, {"type": "register_result", "success": False, "error": "注册处理失败"})
            return

        elif auth_data.get("type") == "login":
            username = auth_data.get("from")
            password = auth_data.get("password")
            
            # 检查是否已登录
            if username in usernames.values():
                send_msg(client_sock, {"type": "login_result", "success": False, "error": "该用户已登录"})
                logging.warning(f"Login failed for {username} from {addr}: 用户已登录")
                return

            if validate_user(username, password):
                usernames[client_sock] = username
                current_username = username # 记录当前连接的用户名
                user_friends[username] = load_friends(username)
                send_msg(client_sock, {"type": "login_result", "success": True})
                logging.info(f"User {username} logged in from {addr}")
                
                # 发送用户所属的群组列表
                send_user_groups(client_sock, username)
                
                send_history(client_sock, username)
                broadcast_online_users()
            else:
                send_msg(client_sock, {"type": "login_result", "success": False, "error": "用户名或密码错误"})
                logging.error(f"Login failed for {username} from {addr}: 用户名或密码错误")
                return
        else:
            send_msg(client_sock, {"type": "login_result", "success": False, "error": "协议错误"})
            logging.error(f"Protocol error during authentication from {addr}")
            return

        while True:
            msg = recv_msg(client_sock)
            if msg is None:
                logging.info(f"Connection lost from {addr} (User: {current_username})")
                break
            if not isinstance(msg, dict):
                logging.warning(f"Received non-dict message from {current_username}: {msg}")
                continue
            
            logging.debug(f"Message from {current_username}: {msg}")
            mtype = msg.get("type")
            
            if mtype == "friend_request":
                try:
                    to_user = msg.get("to")
                    sender = current_username
                    logging.info(f"Processing friend request from '{sender}' to '{to_user}'")
                    if not user_exists(to_user):
                        send_msg(client_sock, {"type": "friend_request_result", "success": False, "error": f"用户 {to_user} 不存在"})
                        logging.warning(f"Friend request from '{sender}' failed: User '{to_user}' does not exist.")
                        continue
                    to_sock = get_sock_by_username(to_user)
                    if to_sock and sender:
                        send_msg(to_sock, {"type": "friend_request", "from": sender})
                        logging.info(f"Friend request from '{sender}' forwarded to '{to_user}'.")
                    else:
                        send_msg(client_sock, {"type": "friend_request_result", "success": False, "error": f"用户 {to_user} 不在线"})
                        logging.warning(f"Friend request from '{sender}' to '{to_user}' failed: User not online.")
                except Exception as e:
                    logging.error(f"Error processing friend_request from {current_username}: {e}")
                
            elif mtype == "friend_response":
                try:
                    from_user = msg.get("to") # 这里的to是请求发起者
                    accepted = msg.get("accepted")
                    responder = current_username # 响应者
                    logging.info(f"Processing friend response from '{responder}' to '{from_user}'. Accepted: {accepted}")
                    
                    from_sock = get_sock_by_username(from_user)
                    if from_sock:
                        send_msg(from_sock, {"type": "friend_response", "from": responder, "accepted": accepted})
                        logging.info(f"Friend response from '{responder}' sent to '{from_user}'.")
                    
                    if accepted:
                        # 确保两个用户的好友列表都更新
                        if responder not in user_friends:
                            user_friends[responder] = set()
                        user_friends[responder].add(from_user)
                        
                        if from_user not in user_friends:
                            user_friends[from_user] = set()
                        user_friends[from_user].add(responder)
                        
                        save_friend_relationship(responder, from_user)
                        logging.info(f"Friend relationship between '{responder}' and '{from_user}' saved.")

                        # 通知双方更新好友列表
                        responder_sock = get_sock_by_username(responder)
                        if responder_sock:
                            send_msg(responder_sock, {"type": "friend_update", "friend": from_user})
                        if from_sock: # from_sock 在前面已经获取
                            send_msg(from_sock, {"type": "friend_update", "friend": responder})
                except Exception as e:
                    logging.error(f"Error processing friend_response from {current_username}: {e}")
                
            elif mtype == "private_chat":
                try:
                    to_user = msg.get("to")
                    encrypted_content = msg.get("content")
                    now = msg.get("timestamp") or datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    
                    if to_user == current_username: # 不能给自己发私聊
                        logging.warning(f"User '{current_username}' tried to send a private message to themselves.")
                        continue
                    
                    # 检查是否是好友关系
                    if to_user not in user_friends.get(current_username, set()):
                        send_msg(client_sock, {"type": "private_chat_result", "success": False, "error": f"您和 {to_user} 不是好友关系"})
                        logging.warning(f"Private chat from '{current_username}' to '{to_user}' blocked: not friends.")
                        continue

                    sender_session_key = session_keys.get(client_sock)
                    if not sender_session_key:
                        logging.error(f"No session key found for '{current_username}' to send private chat.")
                        continue
                    
                    try:
                        plaintext = decrypt_message(encrypted_content, sender_session_key)
                    except Exception as e:
                        logging.error(f"解密来自 {current_username} 的私聊消息失败: {e}")
                        continue
                    
                    save_message('private', current_username, to_user, None, plaintext, now)
                    logging.info(f"Private message from '{current_username}' to '{to_user}' saved to database.")

                    # 为接收者准备消息
                    to_sock = get_sock_by_username(to_user)
                    if to_sock:
                        recipient_session_key = session_keys.get(to_sock)
                        if recipient_session_key:
                            message_for_recipient = {
                                "type": "private_chat",
                                "from": current_username,
                                "to": to_user,
                                "content": encrypt_message(plaintext, recipient_session_key),
                                "timestamp": now
                            }
                            send_msg(to_sock, message_for_recipient)
                            logging.info(f"Private message from '{current_username}' forwarded to '{to_user}'.")
                        else:
                            logging.warning(f"Could not find session key for recipient '{to_user}'.")

                    # 为发送者准备消息（用于客户端显示）
                    message_for_sender = {
                        "type": "private_chat",
                        "from": current_username,
                        "to": to_user,
                        "content": encrypt_message(plaintext, sender_session_key),
                        "timestamp": now
                    }
                    send_msg(client_sock, message_for_sender)
                except Exception as e:
                    logging.error(f"Error processing private_chat from {current_username}: {e}")

            elif mtype == "group_create":
                try:
                    group_name = msg.get("group_name")
                    owner = current_username
                    members = msg.get("members", [])
                    logging.info(f"Processing group_create request from '{owner}' for group '{group_name}' with members {members}.")
                    
                    if not group_name or not owner or not members:
                        send_msg(client_sock, {"type": "group_create_result", "success": False, "error": "参数错误"})
                        logging.warning(f"Group create failed for '{owner}': invalid parameters.")
                        continue
                    
                    # 确保群主也在成员列表中
                    if owner not in members:
                        members.append(owner)

                    gid = create_group_db(owner, group_name, members)
                    if gid:
                        groups_data[gid] = {"group_name": group_name, "owner": owner, "members": members}
                        # 创建一个包含所有必要信息的消息负载
                        payload = {
                            "type": "group_create_result", 
                            "success": True, 
                            "gid": gid, 
                            "group_name": group_name, 
                            "owner": owner,  # 添加群主信息
                            "members": members
                        }
                        send_msg(client_sock, payload)
                        logging.info(f"Group '{group_name}' (gid: {gid}) created successfully by '{owner}'.")
                        # 通知所有成员群组已创建
                        for member in members:
                            sock = get_sock_by_username(member)
                            if sock and sock != client_sock:
                                send_msg(sock, payload) # 发送包含群主信息的完整负载
                                logging.info(f"Notified member '{member}' about creation of group '{group_name}'.")
                    else:
                        send_msg(client_sock, {"type": "group_create_result", "success": False, "error": "创建群聊失败"})
                        logging.error(f"Failed to create group '{group_name}' for '{owner}' in database.")
                except Exception as e:
                    logging.error(f"Error processing group_create from {current_username}: {e}")

            elif mtype == "group_chat":
                try:
                    gid = msg.get("gid")
                    encrypted_content = msg.get("content")
                    now = msg.get("timestamp") or datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    from_user = current_username
                    
                    if gid == "all":
                        send_msg(client_sock, {"type": "group_chat_result", "success": False, "error": "全体群组功能已禁用"})
                        continue

                    group = get_group_db(gid)
                    if not group:
                        send_msg(client_sock, {"type": "group_chat_result", "success": False, "error": "群组不存在"})
                        logging.warning(f"Group chat from '{from_user}' failed: Group '{gid}' does not exist.")
                        continue
                    
                    # 检查用户是否是群成员
                    if from_user not in group["members"]:
                        send_msg(client_sock, {"type": "group_chat_result", "success": False, "error": "您不是该群成员"})
                        logging.warning(f"Group chat from '{from_user}' to group '{gid}' blocked: not a member.")
                        continue

                    sender_session_key = session_keys.get(client_sock)
                    if not sender_session_key:
                        logging.error(f"No session key for '{from_user}' to send group chat.")
                        continue
                    
                    try:
                        plaintext = decrypt_message(encrypted_content, sender_session_key)
                    except Exception as e:
                        logging.error(f"解密来自 {from_user} 的群聊消息失败 (群组: {gid}): {e}")
                        continue

                    save_message('group', from_user, None, gid, plaintext, now)
                    logging.info(f"Group message from '{from_user}' in group '{gid}' saved to database.")

                    # 为每个群成员单独加密并发送消息
                    for member in group["members"]:
                        sock = get_sock_by_username(member)
                        if sock:
                            member_session_key = session_keys.get(sock)
                            if member_session_key:
                                message_to_send = {
                                    "type": "group_chat",
                                    "from": from_user,
                                    "gid": gid,
                                    "content": encrypt_message(plaintext, member_session_key),
                                    "timestamp": now
                                }
                                try:
                                    send_msg(sock, message_to_send)
                                except Exception as e:
                                    logging.error(f"群聊消息发送失败给 {member}: {e}")
                            else:
                                logging.warning(f"Could not find session key for group member '{member}'.")
                except Exception as e:
                    logging.error(f"Error processing group_chat from {current_username}: {e}")

            elif mtype == "group_invite":
                try:
                    to_user = msg.get("to")
                    gid = msg.get("gid")
                    inviter = current_username
                    logging.info(f"Processing group invite from '{inviter}' to '{to_user}' for group '{gid}'.")
                    
                    group = get_group_db(gid)
                    if not group:
                        send_msg(client_sock, {"type": "group_invite_result", "success": False, "error": "群组不存在"})
                        logging.warning(f"Group invite from '{inviter}' failed: Group '{gid}' does not exist.")
                        continue
                    if inviter not in group["members"]:
                        send_msg(client_sock, {"type": "group_invite_result", "success": False, "error": "您不是该群成员，无法邀请"})
                        logging.warning(f"Group invite from '{inviter}' blocked: not a member of group '{gid}'.")
                        continue
                    if to_user in group["members"]:
                        send_msg(client_sock, {"type": "group_invite_result", "success": False, "error": f"用户 {to_user} 已是群成员"})
                        logging.warning(f"Group invite from '{inviter}' failed: User '{to_user}' is already in group '{gid}'.")
                        continue
                    if not user_exists(to_user):
                        send_msg(client_sock, {"type": "group_invite_result", "success": False, "error": f"用户 {to_user} 不存在"})
                        logging.warning(f"Group invite from '{inviter}' failed: User '{to_user}' does not exist.")
                        continue

                    to_sock = get_sock_by_username(to_user)
                    if to_sock:
                        send_msg(to_sock, {"type": "group_invite", "from": inviter, "gid": gid, "group_name": group["group_name"]})
                        send_msg(client_sock, {"type": "group_invite_result", "success": True, "message": f"已向 {to_user} 发送邀请"})
                        logging.info(f"Group invite from '{inviter}' sent to '{to_user}' for group '{gid}'.")
                    else:
                        send_msg(client_sock, {"type": "group_invite_result", "success": False, "error": f"用户 {to_user} 不在线"})
                        logging.warning(f"Group invite from '{inviter}' failed: User '{to_user}' is not online.")
                except Exception as e:
                    logging.error(f"Error processing group_invite from {current_username}: {e}")

            elif mtype == "group_join":
                try:
                    gid = msg.get("gid")
                    user_to_join = current_username
                    logging.info(f"Processing group join request from '{user_to_join}' for group '{gid}'.")
                    
                    group = get_group_db(gid)
                    if not group:
                        send_msg(client_sock, {"type": "group_join_result", "success": False, "error": "群组不存在"})
                        logging.warning(f"Group join by '{user_to_join}' failed: Group '{gid}' does not exist.")
                        continue
                    if user_to_join in group["members"]:
                        send_msg(client_sock, {"type": "group_join_result", "success": False, "error": "您已是该群成员"})
                        logging.warning(f"Group join by '{user_to_join}' failed: Already a member of group '{gid}'.")
                        continue
                    
                    group["members"].append(user_to_join)
                    if update_group_members_db(gid, group["members"]):
                        groups_data[gid] = group # 更新内存中的群组数据
                        payload = {
                            "type": "group_join_result",
                            "success": True,
                            "gid": gid,
                            "group_name": group["group_name"],
                            "owner": group["owner"],
                            "members": group["members"]
                        }
                        send_msg(client_sock, payload)
                        logging.info(f"User '{user_to_join}' successfully joined group '{gid}'.")
                        # 通知所有群成员有新成员加入
                        for member in group["members"]:
                            sock = get_sock_by_username(member)
                            if sock:
                                member_session_key = session_keys.get(sock)
                                if member_session_key:
                                    join_notification = {
                                        "type": "group_chat",
                                        "from": "系统消息",
                                        "gid": gid,
                                        "content": encrypt_message(f"{user_to_join} 加入了群聊。", member_session_key),
                                        "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                    }
                                    send_msg(sock, join_notification)
                    else:
                        send_msg(client_sock, {"type": "group_join_result", "success": False, "error": "加入失败"})
                        logging.error(f"Failed to update group members in DB for group '{gid}' after join attempt by '{user_to_join}'.")
                except Exception as e:
                    logging.error(f"Error processing group_join from {current_username}: {e}")

            elif mtype == "group_leave":
                try:
                    gid = msg.get("gid")
                    user_to_leave = current_username
                    logging.info(f"Processing group leave request from '{user_to_leave}' for group '{gid}'.")
                    
                    group = get_group_db(gid)
                    if not group:
                        send_msg(client_sock, {"type": "group_leave_result", "success": False, "error": "群组不存在"})
                        logging.warning(f"Group leave by '{user_to_leave}' failed: Group '{gid}' does not exist.")
                        continue
                    if user_to_leave not in group["members"]:
                        send_msg(client_sock, {"type": "group_leave_result", "success": False, "error": "您不是该群成员"})
                        logging.warning(f"Group leave by '{user_to_leave}' failed: Not a member of group '{gid}'.")
                        continue
                    
                    if user_to_leave == group["owner"]:
                        send_msg(client_sock, {"type": "group_leave_result", "success": False, "error": "群主不能直接退出群聊，请先解散群聊或转让群主"})
                        logging.warning(f"Group leave by '{user_to_leave}' failed: Owner cannot leave group '{gid}'.")
                        continue

                    group["members"].remove(user_to_leave)
                    if update_group_members_db(gid, group["members"]):
                        groups_data[gid] = group # 更新内存中的群组数据
                        send_msg(client_sock, {"type": "group_leave_result", "success": True, "gid": gid})
                        logging.info(f"User '{user_to_leave}' successfully left group '{gid}'.")
                        
                        # 向所有剩余成员广播群组更新信息
                        update_payload = {"type": "group_update", "gid": gid, "group_name": group["group_name"], "owner": group["owner"], "members": group["members"]}
                        for member in group["members"]:
                            sock = get_sock_by_username(member)
                            if sock:
                                send_msg(sock, update_payload)
                    else:
                        send_msg(client_sock, {"type": "group_leave_result", "success": False, "error": "退出失败"})
                        logging.error(f"Failed to update group members in DB for group '{gid}' after leave attempt by '{user_to_leave}'.")
                except Exception as e:
                    logging.error(f"Error processing group_leave from {current_username}: {e}")

            elif mtype == "group_kick":
                try:
                    gid = msg.get("gid")
                    kick_user = msg.get("kick")
                    requester = current_username
                    logging.info(f"Processing group kick request from '{requester}' to kick '{kick_user}' from group '{gid}'.")
                    
                    group = get_group_db(gid)
                    if not group:
                        send_msg(client_sock, {"type": "group_kick_result", "success": False, "error": "群组不存在"})
                        logging.warning(f"Group kick by '{requester}' failed: Group '{gid}' does not exist.")
                        continue
                    if requester != group["owner"]:
                        send_msg(client_sock, {"type": "group_kick_result", "success": False, "error": "只有群主才能踢人"})
                        logging.warning(f"Group kick by '{requester}' blocked: Not the owner of group '{gid}'.")
                        continue
                    if kick_user not in group["members"]:
                        send_msg(client_sock, {"type": "group_kick_result", "success": False, "error": "该用户不是群成员"})
                        logging.warning(f"Group kick by '{requester}' failed: User '{kick_user}' not in group '{gid}'.")
                        continue
                    if kick_user == requester:
                        send_msg(client_sock, {"type": "group_kick_result", "success": False, "error": "不能踢自己"})
                        logging.warning(f"Group kick by '{requester}' failed: Cannot kick self.")
                        continue

                    group["members"].remove(kick_user)
                    if update_group_members_db(gid, group["members"]):
                        groups_data[gid] = group # 更新内存中的群组数据
                        
                        # 通知被踢者
                        kicked_sock = get_sock_by_username(kick_user)
                        if kicked_sock:
                            send_msg(kicked_sock, {"type": "group_kick_notification", "gid": gid, "group_name": group["group_name"]})
                        
                        # 向群主确认
                        send_msg(client_sock, {"type": "group_kick_result", "success": True, "gid": gid, "kick": kick_user})
                        logging.info(f"User '{kick_user}' was kicked from group '{gid}' by '{requester}'.")

                        # 向所有剩余成员广播群组更新信息
                        update_payload = {"type": "group_update", "gid": gid, "group_name": group["group_name"], "owner": group["owner"], "members": group["members"]}
                        for member in group["members"]:
                            sock = get_sock_by_username(member)
                            if sock:
                                send_msg(sock, update_payload)
                    else:
                        send_msg(client_sock, {"type": "group_kick_result", "success": False, "error": "踢人失败"})
                        logging.error(f"Failed to update group members in DB for group '{gid}' after kick attempt by '{requester}'.")
                except Exception as e:
                    logging.error(f"Error processing group_kick from {current_username}: {e}")

            elif mtype == "group_info":
                try:
                    gid = msg.get("gid")
                    logging.info(f"Processing group_info request for gid '{gid}' from '{current_username}'.")
                    group = get_group_db(gid)
                    if group:
                        send_msg(client_sock, {"type": "group_info", **group})
                        logging.info(f"Sent group_info for gid '{gid}' to '{current_username}'.")
                    else:
                        send_msg(client_sock, {"type": "group_info", "gid": gid, "error": "群组不存在"})
                        logging.warning(f"Group_info request failed: gid '{gid}' not found.")
                except Exception as e:
                    logging.error(f"Error processing group_info from {current_username}: {e}")
            
            else:
                logging.warning(f"Unknown message type received: {mtype} from {current_username}")

    except ConnectionResetError:
        logging.info(f"Client {addr} (User: {current_username}) disconnected unexpectedly.")
    except Exception as e:
        logging.exception(f"Exception in handle_client for {addr} (User: {current_username})")
    finally:
        if client_sock in clients:
            clients.remove(client_sock)
        if client_sock in session_keys:
            del session_keys[client_sock]
        if current_username and client_sock in usernames and usernames[client_sock] == current_username:
            del usernames[client_sock]
            logging.info(f"User {current_username} disconnected.")
        broadcast_online_users()
        client_sock.close()

def broadcast_online_users():
    """
    广播在线用户列表给所有客户端。
    """
    user_list = list(usernames.values())
    message = {"type": "online_users", "users": user_list}
    for sock in list(usernames.keys()):
        try:
            send_msg(sock, message)
        except Exception as e:
            logging.error(f"Error broadcasting online users to {usernames.get(sock, 'Unknown')}: {e}")

# 主函数，启动服务器
def main():
    """
    主函数，初始化数据库并启动服务器监听客户端连接。
    """
    init_db()
    # 加载所有群组到内存
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT gid, group_name, owner, members FROM groups")
    for row in cursor.fetchall():
        gid, group_name, owner, members_json = row
        groups_data[gid] = {"group_name": group_name, "owner": owner, "members": json.loads(members_json)}
    conn.close()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # 允许端口重用
    server.bind(('0.0.0.0', 12345))
    server.listen(5)
    logging.info("Server started, waiting for connections...")
    while True:
        try:
            client_sock, addr = server.accept()
            clients.append(client_sock)
            logging.info(f"Accepted connection from {addr}")
            threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True).start()
        except Exception as e:
            logging.exception(f"Error accepting new connection: {e}")

# 程序入口
if __name__ == '__main__':
    main()
