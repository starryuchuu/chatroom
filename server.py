import socket
import threading
import datetime
import sqlite3
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import struct
import logging

# 配置日志记录，设置日志级别为INFO，格式为时间-级别-消息
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 全局变量，存储客户端连接、用户名和好友关系
clients = []
usernames = {}
user_friends = {}

# 加密密钥，用于AES加密
KEY = b'\xe5\xc6\xba\xd9?x\\f(\x9f\x02B6\x9e\xdd\xd9'
# AES加密块大小
BLOCK_SIZE = 16

# AI好友名称
AI_FRIEND_NAME = "AI_Bot"
# 存储AI对话记录
ai_conversations = {}

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
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# 发送消息，包含消息长度头部
def send_msg(sock, msg):
    """
    向套接字发送消息，消息前附加长度头部。
    参数:
        sock: 套接字对象
        msg: 要发送的消息字符串
    """
    data = msg.encode('utf-8')
    header = struct.pack('!I', len(data))
    sock.sendall(header + data)

# 接收消息，读取消息长度头部并接收完整消息
def recv_msg(sock):
    """
    从套接字接收消息，首先读取长度头部，然后接收完整消息。
    参数:
        sock: 套接字对象
    返回:
        接收到的消息字符串，如果连接关闭则返回None
    """
    header = recvall(sock, 4)
    if not header:
        return None
    msg_len = struct.unpack('!I', header)[0]
    data = recvall(sock, msg_len)
    return data.decode('utf-8') if data else None

# 加密消息，使用AES-ECB模式
def encrypt_message(message):
    """
    使用AES-ECB模式加密消息。
    参数:
        message: 要加密的消息字符串
    返回:
        加密后的消息，base64编码的字符串
    """
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(message.encode(), BLOCK_SIZE))
    return base64.b64encode(encrypted).decode()

# 解密消息，使用AES-ECB模式
def decrypt_message(encrypted_message):
    """
    使用AES-ECB模式解密消息。
    参数:
        encrypted_message: 加密的消息，base64编码的字符串
    返回:
        解密后的消息字符串
    """
    cipher = AES.new(KEY, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_message)), BLOCK_SIZE)
    return decrypted.decode()

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
    finally:
        conn.close()

# 对密码进行哈希处理
def hash_password(password):
    """
    对密码进行SHA-256哈希处理。
    参数:
        password: 明文密码
    返回:
        哈希后的密码字符串
    """
    return hashlib.sha256(password.encode()).hexdigest()

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
    try:
        conn = sqlite3.connect("chat.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                      (username, hash_password(password)))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
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
    返回:
        验证成功返回True，否则返回False
    """
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", 
                  (username, hash_password(password)))
    result = cursor.fetchone()
    conn.close()
    return bool(result)

# 保存消息到数据库
def save_message(chat_type, from_user, to_user, message, timestamp):
    """
    保存聊天消息到数据库。
    参数:
        chat_type: 聊天类型（group或private）
        from_user: 发送者
        to_user: 接收者（群聊时为None）
        message: 消息内容
        timestamp: 时间戳
    """
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO messages (chat_type, from_user, to_user, message, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (chat_type, from_user, to_user, message, timestamp))
    conn.commit()
    conn.close()

# 发送聊天历史记录给客户端
def send_history(client_sock, username):
    """
    发送群聊和私聊历史记录给客户端。
    参数:
        client_sock: 客户端套接字
        username: 用户名
    """
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT from_user, message, timestamp FROM messages WHERE chat_type='group' ORDER BY id ASC")
    rows = cursor.fetchall()
    for row in rows:
        from_user, message, timestamp = row
        encrypted_msg = encrypt_message(message)
        hist_msg = f'__GROUP_HISTORY__:{from_user}:{encrypted_msg}:__TIME__:{timestamp}'
        send_msg(client_sock, hist_msg)
    cursor.execute("""
        SELECT from_user, to_user, message, timestamp FROM messages 
        WHERE chat_type='private' AND (from_user=? OR to_user=?) 
        ORDER BY id ASC
    """, (username, username))
    rows = cursor.fetchall()
    for row in rows:
        from_user, to_user, message, timestamp = row
        encrypted_msg = encrypt_message(message)
        hist_msg = f'__PRIVATE_HISTORY__:{from_user}:{to_user}:{encrypted_msg}:__TIME__:{timestamp}'
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

# 获取AI回复
def get_ai_response(username, user_message):
    """
    获取AI对用户消息的回复。
    参数:
        username: 用户名
        user_message: 用户消息
    返回:
        AI的回复内容
    """
    if username not in ai_conversations:
        ai_conversations[username] = [{"role": "system", "content": "You are a helpful assistant."}]
    ai_conversations[username].append({"role": "user", "content": user_message})
    max_retries = 3
    for attempt in range(max_retries):
        try:
            from openai import OpenAI
            client = OpenAI(
                base_url="your_api_url",
                api_key="your_api_key",
            )
            completion = client.chat.completions.create(
                model="",
                messages=ai_conversations[username],
            )
            reply = completion.choices[0].message.content
            break
        except Exception as e:
            logging.info(f"Retrying request to /chat/completions in {attempt + 1} attempt(s)")
            if attempt == max_retries - 1:
                reply = "抱歉，AI服务暂时不可用。"
    ai_conversations[username].append({"role": "assistant", "content": reply})
    return reply

# 处理客户端连接
def handle_client(client_sock, addr):
    """
    处理客户端连接，包含注册、登录、消息处理等逻辑。
    参数:
        client_sock: 客户端套接字
        addr: 客户端地址
    """
    logging.info(f"Client connected from {addr}")
    try:
        auth_data = recv_msg(client_sock)
        if auth_data.startswith('__REGISTER__'):
            _, username, password = auth_data.split(':', 2)
            if register_user(username, password):
                send_msg(client_sock, '__REGISTER_SUCCESS__')
                logging.info(f"User {username} registered successfully")
            else:
                send_msg(client_sock, '__REGISTER_FAIL__:用户名已存在')
                logging.warning(f"Registration failed for {username}: 用户名已存在")
            return
        elif auth_data.startswith('__LOGIN__'):
            _, username, password = auth_data.split(':', 2)
            for sock, uname in usernames.items():
                if uname == username:
                    send_msg(client_sock, '__LOGIN_FAIL__:该用户已登录')
                    return
            if validate_user(username, password):
                usernames[client_sock] = username
                user_friends[username] = load_friends(username)
                if AI_FRIEND_NAME not in user_friends[username]:
                    user_friends[username].add(AI_FRIEND_NAME)
                send_msg(client_sock, '__LOGIN_SUCCESS__')
                logging.info(f"User {username} logged in")
                send_history(client_sock, username)
                send_msg(client_sock, f'__ADD_AI_FRIEND__:{AI_FRIEND_NAME}')
            else:
                send_msg(client_sock, '__LOGIN_FAIL__:用户名或密码错误')
                logging.error(f"Login failed for {username}: 用户名或密码错误")
                return
        else:
            send_msg(client_sock, '__LOGIN_FAIL__:协议错误')
            logging.error("Protocol error during authentication")
            return

        def broadcast_online_users():
            """
            广播在线用户列表给所有客户端。
            """
            user_list = ','.join(usernames.values())
            message = f'__ONLINE_USERS__:{user_list}'
            for sock in list(usernames.keys()):
                try:
                    send_msg(sock, message)
                except Exception as e:
                    logging.exception("Error broadcasting online users")

        broadcast_online_users()

        while True:
            msg = recv_msg(client_sock)
            if msg is None:
                logging.info(f"Connection lost from {addr}")
                break
            logging.debug(f"Message from {usernames.get(client_sock, 'Unknown')}: {msg}")
            if msg.startswith('__FRIEND_REQUEST__'):
                _, to_user = msg.split(':', 1)
                to_user = to_user.strip()
                sender = usernames.get(client_sock, '')
                if not user_exists(to_user):
                    send_msg(client_sock, f'__FRIEND_REQUEST_FAIL__:用户 {to_user} 不存在')
                    continue
                to_sock = get_sock_by_username(to_user)
                if to_sock and sender:
                    send_msg(to_sock, f'__FRIEND_REQUEST__:{sender}')
                continue
            if msg.startswith('__FRIEND_RESPONSE__'):
                _, from_user, result = msg.split(':')
                from_sock = get_sock_by_username(from_user)
                if from_sock:
                    send_msg(from_sock, f'__FRIEND_RESPONSE__:{usernames[client_sock]}:{result}')
                if result == 'ACCEPT':
                    user_friends[usernames[client_sock]].add(from_user)
                    if from_user in user_friends:
                        user_friends[from_user].add(usernames[client_sock])
                    save_friend_relationship(usernames[client_sock], from_user)
                    if from_sock:
                        send_msg(from_sock, f'__FRIEND_RESPONSE__:{usernames[client_sock]}:ACCEPT')
                    this_sock = get_sock_by_username(usernames[client_sock])
                    if this_sock:
                        send_msg(this_sock, f'__FRIEND_RESPONSE__:{from_user}:ACCEPT')
                continue
            if msg.startswith('__PRIVATE__'):
                _, to_user, encrypted_content = msg.split(':', 2)
                if to_user == usernames[client_sock]:
                    continue
                now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                if to_user == AI_FRIEND_NAME:
                    plaintext = decrypt_message(encrypted_content)
                    user_echo = f'__PRIVATE__:{usernames[client_sock]}:{encrypt_message(plaintext)}:__TIME__:{now}'
                    send_msg(client_sock, user_echo)
                    ai_reply = get_ai_response(usernames[client_sock], plaintext)
                    encrypted_reply = encrypt_message(ai_reply)
                    ai_msg = f'__PRIVATE__:{AI_FRIEND_NAME}:{encrypted_reply}:__TIME__:{now}'
                    send_msg(client_sock, ai_msg)
                    save_message('private', usernames[client_sock], AI_FRIEND_NAME, plaintext, now)
                    save_message('private', AI_FRIEND_NAME, usernames[client_sock], ai_reply, now)
                else:
                    if to_user in user_friends[usernames[client_sock]]:
                        to_sock = get_sock_by_username(to_user)
                        plaintext = decrypt_message(encrypted_content)
                        encrypted_msg = encrypt_message(plaintext)
                        message_to_send = f'__PRIVATE__:{usernames[client_sock]}:{encrypted_msg}:__TIME__:{now}'
                        if to_sock:
                            send_msg(to_sock, message_to_send)
                        from_sock = get_sock_by_username(usernames[client_sock])
                        if from_sock:
                            send_msg(from_sock, message_to_send)
                        save_message('private', usernames[client_sock], to_user, plaintext, now)
            if msg.startswith('__GROUP__'):
                _, encrypted_content = msg.split(':', 1)
                now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                from_user = usernames[client_sock]
                plaintext = decrypt_message(encrypted_content)
                encrypted_msg = encrypt_message(plaintext)
                message_to_send = f'__GROUP__:{from_user}:{encrypted_msg}:__TIME__:{now}'
                for sock in list(usernames.keys()):
                    try:
                        send_msg(sock, message_to_send)
                    except:
                        pass
                save_message('group', from_user, None, plaintext, now)
                continue
    except Exception as e:
        logging.exception("Exception in client handler")
    finally:
        if client_sock in clients:
            clients.remove(client_sock)
        uname = usernames.get(client_sock, None)
        if uname:
            del usernames[client_sock]
            logging.info(f"User {uname} disconnected")
        user_list = ','.join(usernames.values())
        message = f'__ONLINE_USERS__:{user_list}'
        for sock in list(usernames.keys()):
            try:
                send_msg(sock, message)
            except:
                pass
        client_sock.close()

# 主函数，启动服务器
def main():
    """
    主函数，初始化数据库并启动服务器监听客户端连接。
    """
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 12345))
    server.listen(5)
    logging.info("Server started, waiting for connections...")
    while True:
        client_sock, addr = server.accept()
        clients.append(client_sock)
        logging.info(f"Accepted connection from {addr}")
        threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True).start()

# 程序入口
if __name__ == '__main__':
    main()
