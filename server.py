import socket                # 导入socket模块，进行网络通信
import threading             # 导入threading模块，实现多线程
import datetime              # 导入datetime模块，获取当前日期与时间
import sqlite3               # 导入sqlite3模块，操作本地数据库
import hashlib               # 导入hashlib模块，用于密码加密散列处理
from Crypto.Cipher import AES                      # 导入AES加密算法模块
from Crypto.Util.Padding import pad, unpad         # 导入填充函数，确保数据块长度正确
import base64                # 导入base64模块，将二进制数据转化为字符串
import struct                # 导入struct模块，用于构造定长的数据包
import logging               # 导入logging模块，用于记录日志输出

# 设置日志配置，显示时间、日志级别和消息内容，方便调试和运行监控
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 全局变量：管理所有在线客户端和用户信息
clients = []                 # 存储所有连接的客户端socket
usernames = {}               # 建立socket和用户名的映射字典：{socket: username}
user_friends = {}            # 储存每个用户的好友集合：{username: set(好友名)}

# AES加密相关常量：设置密钥和块大小
KEY = b'\xe5\xc6\xba\xd9?x\\f(\x9f\x02B6\x9e\xdd\xd9'  # 16字节AES密钥，保证加密安全
BLOCK_SIZE = 16              # AES算法要求的数据块大小为16字节

# 辅助函数：从socket中接收n个字节数据
def recvall(sock, n):
    """
    反复调用socket的recv直到接收n个字节数据。
    参数:
        sock: 要操作的socket连接对象。
        n: 需要接收的总字节数。
    返回:
        如果成功接收n字节，则返回数据；若连接中断则返回None。
    """
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None  # 若接收数据为空，说明连接中断
        data += packet
    return data

def send_msg(sock, msg):
    """
    发送消息给指定的socket连接。
    参数:
        sock: 用于通信的socket对象。
        msg: 要发送的消息字符串（未加密的明文）。
    实现:
        先将消息编码为UTF-8字节，然后打包头部（消息长度为4字节），最终发送。
    """
    data = msg.encode('utf-8')                   # 将字符串编码为字节
    header = struct.pack('!I', len(data))          # 使用网络字节序打包消息长度（4字节）
    sock.sendall(header + data)                    # 发送头部和消息数据

def recv_msg(sock):
    """
    从socket接收一条完整的消息。
    参数:
        sock: 用于通信的socket对象。
    返回:
        接收到的消息字符串；如果接收失败则返回None。
    实现:
        首先接收4字节消息头，再根据长度接收消息体数据，最后解码得到字符串。
    """
    header = recvall(sock, 4)
    if not header:
        return None
    msg_len = struct.unpack('!I', header)[0]   # 解包得到消息长度
    data = recvall(sock, msg_len)
    return data.decode('utf-8') if data else None

def encrypt_message(message):
    """
    用AES算法加密明文消息，并返回Base64编码后的字符串。
    参数:
        message: 待加密的明文字符串。
    实现:
        对消息先进行UTF-8编码和填充，然后使用ECB模式加密，最后通过Base64编码便于传输。
    """
    cipher = AES.new(KEY, AES.MODE_ECB)                      # 创建AES加密对象（ECB模式）
    encrypted = cipher.encrypt(pad(message.encode(), BLOCK_SIZE))  # 填充并加密
    return base64.b64encode(encrypted).decode()              # Base64编码后返回字符串

def decrypt_message(encrypted_message):
    """
    解密以Base64编码格式传输的AES加密消息。
    参数:
        encrypted_message: Base64编码后的加密字符串。
    实现:
        先将字符串解码为字节，再用AES解密和去填充，最后还原为明文字符串。
    """
    cipher = AES.new(KEY, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_message)), BLOCK_SIZE)
    return decrypted.decode()

def init_db():
    """
    初始化SQLite数据库和所需的表结构。
    创建:
        - users表：存放用户注册信息。
        - messages表：保存群聊与私聊的聊天记录。
        - friends表：保存双向好友关系。
    """
    conn = sqlite3.connect("chat.db")           # 连接或创建数据库文件chat.db
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)  # 创建存储用户数据的表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_type TEXT NOT NULL,
            from_user TEXT NOT NULL,
            to_user TEXT,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)  # 创建记录聊天消息的表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS friends (
            user TEXT NOT NULL,
            friend TEXT NOT NULL,
            UNIQUE(user, friend)
        )
    """)  # 创建存储好友关系的表（双向记录）
    conn.commit()   # 提交所有数据库更改
    conn.close()    # 关闭数据库连接

def load_friends(username):
    """
    从数据库中加载指定用户名对应的好友列表。
    参数:
        username: 需要查询好友的用户名。
    返回:
        该用户好友用户名组成的集合。
    """
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT friend FROM friends WHERE user=?", (username,))
    rows = cursor.fetchall()    # 获取所有好友记录
    conn.close()
    return set([row[0] for row in rows])

def save_friend_relationship(user1, user2):
    """
    将两个用户之间的好友关系保存到数据库中（双向保存）。
    参数:
        user1: 用户1的用户名。
        user2: 用户2的用户名。
    实现:
        使用INSERT OR IGNORE，避免重复添加。
    """
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT OR IGNORE INTO friends (user, friend) VALUES (?, ?)", (user1, user2))
        cursor.execute("INSERT OR IGNORE INTO friends (user, friend) VALUES (?, ?)", (user2, user1))
        conn.commit()
    finally:
        conn.close()

def hash_password(password):
    """
    对用户密码进行SHA-256加密散列处理。
    参数:
        password: 明文密码。
    返回:
        加密后的十六进制字符串散列值。
    """
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    """
    注册新用户，将用户名和加密后的密码存入数据库。
    参数:
        username: 用户的注册名称。
        password: 用户的明文密码。
    返回:
        注册成功返回True，否则（例如用户名重复）返回False。
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

def validate_user(username, password):
    """
    验证用户登录时输入的用户名和密码。
    参数:
        username: 用户输入的用户名。
        password: 用户输入的明文密码。
    返回:
        若验证成功则返回True，否则返回False。
    """
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", 
                  (username, hash_password(password)))
    result = cursor.fetchone()  # 查询是否存在符合条件的用户
    conn.close()
    return bool(result)

def save_message(chat_type, from_user, to_user, message, timestamp):
    """
    保存聊天记录到数据库中。
    参数:
        chat_type: 消息类型，'private'或'group'。
        from_user: 发送消息的用户名。
        to_user: 接收消息的用户名；若为群聊则为None。
        message: 消息内容（明文）。
        timestamp: 消息发送的时间字符串。
    """
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO messages (chat_type, from_user, to_user, message, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (chat_type, from_user, to_user, message, timestamp))
    conn.commit()
    conn.close()

def send_history(client_sock, username):
    """
    向新登录的客户端发送历史聊天记录（包括群聊与私聊）。
    参数:
        client_sock: 客户端的socket对象。
        username: 当前登录的用户名。
    说明:
        依次查询群聊记录和与该用户相关的私聊记录，然后发送给客户端。
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

def user_exists(username):
    """
    检查指定用户名是否存在于数据库中。
    参数:
        username: 待查询的用户名。
    返回:
        存在则返回True，否则返回False。
    """
    conn = sqlite3.connect("chat.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username=?", (username,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

def get_sock_by_username(username):
    """
    根据用户名查找对应的socket对象。
    参数:
        username: 用户名。
    返回:
        如果找到，返回对应的socket；否则返回None。
    """
    for sock, uname in usernames.items():
        if uname == username:
            return sock
    return None

def handle_client(client_sock, addr):
    """
    处理单个客户端连接，负责认证、消息收发及协议处理。
    参数:
        client_sock: 与客户端通信的socket对象。
        addr: 客户端的地址元组。
    说明:
        根据收到的消息前缀判断不同操作：注册、登录、好友请求、私聊、群聊等；
        同时处理异常，确保资源最终释放。
    """
    logging.info(f"Client connected from {addr}")
    try:
        auth_data = recv_msg(client_sock)  # 接收客户端发来的注册或登录信息
        if auth_data.startswith('__REGISTER__'):
            # 处理注册请求
            _, username, password = auth_data.split(':', 2)
            if register_user(username, password):
                send_msg(client_sock, '__REGISTER_SUCCESS__')
                logging.info(f"User {username} registered successfully")
            else:
                send_msg(client_sock, '__REGISTER_FAIL__:用户名已存在')
                logging.warning(f"Registration failed for {username}: 用户名已存在")
            return
        elif auth_data.startswith('__LOGIN__'):
            # 处理登录请求
            _, username, password = auth_data.split(':', 2)
            # 检查是否该用户已经在线
            for sock, uname in usernames.items():
                if uname == username:
                    send_msg(client_sock, '__LOGIN_FAIL__:该用户已登录')
                    return
            if validate_user(username, password):
                usernames[client_sock] = username   # 记录socket对应的用户名
                user_friends[username] = load_friends(username)  # 从数据库加载好友列表
                send_msg(client_sock, '__LOGIN_SUCCESS__')
                logging.info(f"User {username} logged in")
                send_history(client_sock, username)  # 登录后发送历史消息记录
            else:
                send_msg(client_sock, '__LOGIN_FAIL__:用户名或密码错误')
                logging.error(f"Login failed for {username}: 用户名或密码错误")
                return
        else:
            send_msg(client_sock, '__LOGIN_FAIL__:协议错误')
            logging.error("Protocol error during authentication")
            return

        # 广播当前所有在线用户，将列表发送给每个连接的客户端
        def broadcast_online_users():
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
            # 修改好友申请协议处理：判断目标用户是否存在
            if msg.startswith('__FRIEND_REQUEST__'):
                _, to_user = msg.split(':', 1)
                to_user = to_user.strip()  # 去除字符串两端空格
                sender = usernames.get(client_sock, '')
                if not user_exists(to_user):
                    # 返回错误提示给发送者
                    send_msg(client_sock, f'__FRIEND_REQUEST_FAIL__:用户 {to_user} 不存在')
                    continue
                to_sock = get_sock_by_username(to_user)
                if to_sock and sender:
                    send_msg(to_sock, f'__FRIEND_REQUEST__:{sender}')
                continue
            # 处理好友申请响应协议
            if msg.startswith('__FRIEND_RESPONSE__'):
                _, from_user, result = msg.split(':')
                from_sock = get_sock_by_username(from_user)
                if from_sock:
                    send_msg(from_sock, f'__FRIEND_RESPONSE__:{usernames[client_sock]}:{result}')
                if result == 'ACCEPT':
                    # 双方互加好友到内存中
                    user_friends[usernames[client_sock]].add(from_user)
                    # 也更新对方好友列表（若存在）
                    if from_user in user_friends:
                        user_friends[from_user].add(usernames[client_sock])
                    # 保存到数据库实现持久化好友关系
                    save_friend_relationship(usernames[client_sock], from_user)
                    # 主动通知双方更新好友列表
                    if from_sock:
                        send_msg(from_sock, f'__FRIEND_RESPONSE__:{usernames[client_sock]}:ACCEPT')
                    this_sock = get_sock_by_username(usernames[client_sock])
                    if this_sock:
                        send_msg(this_sock, f'__FRIEND_RESPONSE__:{from_user}:ACCEPT')
                continue
            # 处理私聊消息协议
            if msg.startswith('__PRIVATE__'):
                _, to_user, encrypted_content = msg.split(':', 2)
                if to_user == usernames[client_sock]:
                    continue  # 不允许发送给自己
                if to_user in user_friends[usernames[client_sock]]:
                    to_sock = get_sock_by_username(to_user)
                    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    # 解密、再加密，以便发送
                    plaintext = decrypt_message(encrypted_content)
                    encrypted_msg = encrypt_message(plaintext)
                    message_to_send = f'__PRIVATE__:{usernames[client_sock]}:{encrypted_msg}:__TIME__:{now}'
                    # 发送给接收方
                    if to_sock:
                        send_msg(to_sock, message_to_send)
                    # 也回显给自己
                    from_sock = get_sock_by_username(usernames[client_sock])
                    if from_sock:
                        send_msg(from_sock, message_to_send)
                    # 保存私聊历史消息
                    save_message('private', usernames[client_sock], to_user, plaintext, now)
                continue
            # 处理群聊消息协议，广播给所有在线用户
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
                        pass  # 某些socket可能已断开，忽略异常
                # 保存群聊历史消息
                save_message('group', from_user, None, plaintext, now)
                continue
            # ...existing code...
    except Exception as e:
        logging.exception("Exception in client handler")
    finally:
        # 客户端断开连接，清理资源
        if client_sock in clients:
            clients.remove(client_sock)
        uname = usernames.get(client_sock, None)
        if uname:
            del usernames[client_sock]
            logging.info(f"User {uname} disconnected")
        # 用户下线后广播最新在线用户列表
        user_list = ','.join(usernames.values())
        message = f'__ONLINE_USERS__:{user_list}'
        for sock in list(usernames.keys()):
            try:
                send_msg(sock, message)
            except:
                pass
        client_sock.close()  # 关闭socket释放资源

def main():
    """
    主程序入口，负责启动服务器并监听客户端连接。
    实现:
        - 初始化数据库结构。
        - 创建TCP socket，绑定IP和端口后进入监听模式。
        - 循环接收每个新连接，并为其启动独立线程处理。
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

if __name__ == '__main__':
    main()
