import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
import socket
import threading
import queue
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import struct
import logging
import json
import time
import hashlib
import uuid

# 配置日志记录，设置日志级别为INFO，格式为时间-级别-消息
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# 用于保护 friend_request_result 的锁
friend_request_lock = threading.Lock()
# 服务器地址
SERVER_HOST = '127.0.0.1'
# 服务器端口
SERVER_PORT = 12345
# 服务器公钥指纹（用于防止中间人攻击）
# 首次运行时注释掉下面的 EXPECTED_SERVER_KEY_FINGERPRINT，运行后从日志中获取实际指纹并填入
# 安全提示：生产环境中必须设置此值以防止中间人攻击
EXPECTED_SERVER_KEY_FINGERPRINT = None  # 示例：'a1b2c3d4...' 填入实际的 SHA-256 指纹
# TODO: 首次连接后从日志获取服务器公钥指纹并设置 above，然后取消注释下一行进行验证
# EXPECTED_SERVER_KEY_FINGERPRINT = '<从日志中获取的实际指纹>'

# 单条消息最大长度（字节），防止恶意服务器声明超大长度导致客户端阻塞/内存耗尽
MAX_RECV_MSG_LEN = 1 * 1024 * 1024
authenticated_sockets = set()

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
        except socket.timeout:
            if sock in authenticated_sockets:
                continue
            raise
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
        msg: 要发送的消息字符串或字典
    """
    if isinstance(msg, dict):
        data = json.dumps(msg).encode('utf-8')
    else:
        data = str(msg).encode('utf-8')  # 修复：原来是'极-8'
    if len(data) > MAX_RECV_MSG_LEN:
        raise ValueError('消息包超过 1 MiB，请缩短内容')
    header = struct.pack('!I', len(data))
    sock.sendall(header + data)

# 接收消息，读取消息长度头部并接收完整消息
def recv_msg(sock):
    """
    从套接字接收消息，首先读取长度头部，然后接收完整消息。
    参数:
        sock: 套接字对象
    返回:
        接收到的消息字符串或字典，如果连接关闭则返回None
    """
    header = recvall(sock, 4)
    if not header:
        return None
    msg_len = struct.unpack('!I', header)[0]
    if msg_len > MAX_RECV_MSG_LEN:
        logging.warning(f"收到超大消息长度 {msg_len} 字节（上限 {MAX_RECV_MSG_LEN}），视为异常连接")
        return None
    data = recvall(sock, msg_len)
    if not data:
        return None
    try:
        return json.loads(data.decode('utf-8'))
    except Exception:
        return data.decode('utf-8')

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

# 校验服务器公钥（指纹验证 + 回环限制），登录与注册流程共用，防止中间人攻击
def check_server_public_key(public_key_data):
    """
    校验服务器下发的公钥消息。
    参数:
        public_key_data: recv_msg 收到的公钥消息
    返回:
        (public_key, None) 校验通过；或 (None, 错误消息) 校验失败
    """
    if not isinstance(public_key_data, dict) or public_key_data.get("type") != "public_key":
        return None, "未能从服务器获取公钥"

    public_key = RSA.import_key(public_key_data["key"])

    # 验证服务器公钥指纹（防止中间人攻击）
    public_key_bytes = public_key.export_key(format='DER')
    key_fingerprint = hashlib.sha256(public_key_bytes).hexdigest()
    logging.info(f"Server public key fingerprint: {key_fingerprint}")

    if EXPECTED_SERVER_KEY_FINGERPRINT is None:
        # 未配置指纹时：仅允许本机回环连接，连接非本机服务器则拒绝（防止中间人攻击）
        if SERVER_HOST not in ('127.0.0.1', 'localhost', '::1'):
            return None, ("未配置服务器公钥指纹（EXPECTED_SERVER_KEY_FINGERPRINT），\n"
                          "连接非本机服务器时无法防止中间人攻击，连接已终止。\n\n"
                          "请在 client.py 中设置 EXPECTED_SERVER_KEY_FINGERPRINT 为服务器公钥指纹。")
        logging.warning("警告: EXPECTED_SERVER_KEY_FINGERPRINT 未设置，仅本机回环连接放行（无法防中间人攻击）。")
    else:
        if key_fingerprint != EXPECTED_SERVER_KEY_FINGERPRINT:
            return None, (f"服务器公钥指纹不匹配！\n\n预期：{EXPECTED_SERVER_KEY_FINGERPRINT}\n"
                          f"实际：{key_fingerprint}\n\n可能遭受中间人攻击，连接已终止。")
        logging.info("Server public key fingerprint verified successfully.")

    return public_key, None

# 聊天客户端类
class ChatClient:
    def __init__(self, master):
        """
        初始化聊天客户端。
        参数:
            master: Tkinter窗口对象
        """
        self.master = master
        self.master.title("简易聊天客户端")
        self.sock = None
        self.session_key = None
        self.username = None
        self.friend_request_result = None
        self.chat_frames = {}  # 用于存储每个好友或群组的聊天框架
        self.current_chat_frame = None  # 当前显示的聊天框架
        self.is_loading_messages = False  # 标记是否正在加载消息
        self.running = False  # 控制接收线程
        self.incoming = queue.Queue()
        self.ui_tasks = queue.Queue()
        self.outgoing = queue.Queue(maxsize=100)
        self.auth_generation = 0
        self.auth_busy = False
        self.auth_sock = None
        self.auth_lock = threading.Lock()
        self.pending_messages = {}
        self.seen_message_ids = set()
        self.message_order = {}
        self.group_windows = {}
        self.request_windows = {}
        self.group_info_requests = set()
        self.history_syncing = False
        threading.Thread(target=self.send_worker, daemon=True).start()
        self.server_port = int(SERVER_PORT)  # 连接端口（可在登录界面修改）
        self.build_login()
        self.master.protocol('WM_DELETE_WINDOW', self.close)
        self.master.after(50, self.drain_incoming)

    def build_login(self):
        """
        构建登录界面，包含用户名和密码输入框，以及登录和注册按钮。
        """
        self.clear_window()
        self.master.geometry('950x530')
        self.master.configure(bg="#ffffff")
        login_frame = tk.Frame(self.master, bg="#ffffff", bd=0, highlightthickness=0)
        login_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        tk.Label(login_frame, text="简易聊天室登录", font=("微软雅黑", 20, "bold"), bg="#ffffff", fg="#3a7bd5").pack(pady=(0, 25))
        tk.Label(login_frame, text="用户名:", font=("微软雅黑", 12), bg="#ffffff").pack(pady=(0, 8))
        entry_style = {"font": ("微软雅黑", 12), "relief": tk.FLAT, "highlightthickness": 2, "highlightbackground": "#aee1f9", "highlightcolor": "#3a7bd5", "bd": 0, "width": 22}
        self.username_entry = tk.Entry(login_frame, **entry_style, bg="#f5faff")
        self.username_entry.pack(pady=(0, 18), ipady=6)
        tk.Label(login_frame, text="密码:", font=("微软雅黑", 12), bg="#ffffff").pack(pady=(10, 5))
        self.password_entry = tk.Entry(login_frame, **entry_style, bg="#f5faff", show="*")
        self.password_entry.pack(ipady=6)
        tk.Label(login_frame, text="端口:", font=("微软雅黑", 12), bg="#ffffff").pack(pady=(10, 5))
        self.port_entry = tk.Entry(login_frame, **entry_style, bg="#f5faff")
        self.port_entry.insert(0, str(self.server_port))
        self.port_entry.pack(ipady=6)
        login_btn = tk.Button(login_frame, text="登录", font=("微软雅黑", 12, "bold"), bg="#3a7bd5", fg="#fff", activebackground="#5596e6", activeforeground="#fff", bd=0, relief=tk.FLAT, width=16, height=1, cursor="hand2", command=self.login)
        self.login_button = login_btn
        login_btn.pack(pady=(20, 10))
        register_btn = tk.Button(login_frame, text="注册", font=("微软雅黑", 12), bg="#f0f0f0", fg="#3a7bd5", activebackground="#dcdcdc", bd=0, relief=tk.FLAT, width=16, height=1, cursor="hand2", command=self.register)
        self.register_button = register_btn
        register_btn.pack(pady=(0, 10))
        self.login_status = tk.Label(login_frame, text="", bg="#ffffff")
        self.login_status.pack()
        tk.Button(login_frame, text="取消连接", command=self.cancel_auth).pack()
        self.username_entry.focus_set()
        self.master.bind('<Return>', lambda e: self.login())

    def build_chat(self):
        """
        构建聊天界面，包含好友列表、在线用户列表、聊天显示区域和消息输入框。
        """
        self.clear_window()
        # 解除登录界面的回车登录绑定，否则聊天界面中在输入框外按 Enter
        # 会再次触发 login() 并访问已销毁的输入框
        self.master.unbind('<Return>')
        top_frame = tk.Frame(self.master)
        top_frame.pack(side=tk.TOP, fill=tk.X)
        tk.Label(top_frame, text=f"当前用户：{self.username}", fg="green").pack(side=tk.LEFT, padx=10, pady=5)
        
        # 添加断开连接按钮
        tk.Button(top_frame, text="断开连接", command=self.disconnect).pack(side=tk.RIGHT, padx=10, pady=5)
        
        left_frame = tk.Frame(self.master)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        tk.Label(left_frame, text="好友列表").pack(pady=5)
        self.friends_listbox = tk.Listbox(left_frame, width=18, exportselection=False)
        self.friends_listbox.pack(fill=tk.Y, expand=True)
        self.friends_listbox.bind('<<ListboxSelect>>', self.select_friend)
        tk.Button(left_frame, text="添加好友", command=self.add_friend).pack(pady=5)
        tk.Button(left_frame, text="创建群聊", command=self.create_group).pack(pady=5)
        
        # 群组列表
        tk.Label(left_frame, text="群组列表").pack(pady=(10, 5))
        self.group_listbox = tk.Listbox(left_frame, width=18, exportselection=False)
        self.group_listbox.pack(fill=tk.Y, expand=True)
        self.group_listbox.bind('<<ListboxSelect>>', self.select_group)
        self.group_listbox.bind('<Double-1>', self.show_group_info_on_double_click)
        
        online_frame = tk.Frame(self.master)
        online_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)
        tk.Label(online_frame, text="在线用户").pack(pady=5)
        self.online_listbox = tk.Listbox(online_frame, width=18)
        self.online_listbox.pack(fill=tk.Y, expand=True)

        right_frame = tk.Frame(self.master)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.chat_title = tk.Label(right_frame, text="请选择好友或群组")
        self.chat_title.pack(fill=tk.X)
        self.status_label = tk.Label(right_frame, text="", anchor="w", wraplength=450)
        self.status_label.pack(fill=tk.X)
        chat_display_frame = tk.Frame(right_frame)
        chat_display_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.chat_canvas = tk.Canvas(chat_display_frame, bg="#f5f5f5", highlightthickness=0)
        self.chat_canvas.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.chat_scrollbar = tk.Scrollbar(chat_display_frame, orient="vertical", command=self.chat_canvas.yview)
        self.chat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_canvas.configure(yscrollcommand=self.chat_scrollbar.set)
        self.chat_container = tk.Frame(self.chat_canvas, bg="#f5f5f5")
        self.chat_window = self.chat_canvas.create_window((0, 0), window=self.chat_container, anchor="nw")
        self.chat_container.bind("<Configure>", lambda e: self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all")))
        self.chat_canvas.bind("<Configure>", lambda e: self.chat_canvas.itemconfig(self.chat_window, width=e.width))
        self.chat_canvas.bind("<MouseWheel>", self.on_chat_wheel)
        self.chat_container.bind("<MouseWheel>", self.on_chat_wheel)
        input_frame = tk.Frame(right_frame)
        input_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
        self.msg_entry = tk.Text(input_frame, height=2)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        draft = getattr(self, 'saved_draft', None)
        if draft and draft[0] == self.username:
            self.msg_entry.insert('1.0', draft[1])
            self.saved_draft = None
        self.send_button = tk.Button(input_frame, text="发送", command=self.send_msg, state=tk.DISABLED)
        self.send_button.pack(side=tk.LEFT, padx=5)
        self.msg_entry.bind("<Return>", self.on_message_entry_key)
        
        # 初始化变量
        self.current_friend = None
        self.current_group = None
        self.friends = []
        self.private_chats = {}
        self.group_chat = []
        self.groups = {}  # gid: {group_name, members}

    def disconnect(self):
        """断开连接并返回登录界面"""
        if not self.running: # 防止重复调用
            return
        if hasattr(self, 'msg_entry') and self.msg_entry.winfo_exists():
            self.saved_draft = (self.username, self.msg_entry.get('1.0', 'end-1c'))
        self.running = False
        self.pending_messages = {}
        self.seen_message_ids = set()
        self.message_order = {}
        if self.sock:
            authenticated_sockets.discard(self.sock)
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
            
        self.session_key = None
        self.username = None
        for name in list(vars(self)):
            if name.startswith("group_messages_"):
                delattr(self, name)
        # 清理所有聊天相关的状态
        self.chat_frames = {}
        self.current_chat_frame = None
        self.is_loading_messages = False
        self.current_friend = None
        self.current_group = None
        self.friends = []
        self.private_chats = {}
        self.group_chat = []
        self.groups = {}
        self.group_sync_chunks = []
        
        self.build_login()

    def add_friend(self):
        """
        添加好友功能，弹出输入框让用户输入好友用户名，并发送好友请求。
        """
        friend = (simpledialog.askstring("添加好友", "请输入好友用户名：") or "").strip()
        if not friend:
            messagebox.showerror("错误", "请输入好友用户名！")
            return
        if friend == self.username:
            messagebox.showerror("错误", "不能添加自己为好友！")
            return
        if friend in self.friends:
            messagebox.showerror("错误", f"{friend} 已经是你的好友")
            return
        
        with friend_request_lock:
            self.friend_request_result = None
        req = {
            "type": "friend_request",
            "from": self.username,
            "to": friend
        }
        try:
            logging.info(f"Sending friend request to '{friend}'.")
            self.queue_send(req)
        except Exception as e:
            logging.error(f"发送好友请求失败: {e}")
            messagebox.showerror("发送失败", "好友申请发送失败")

    def handle_friend_request(self, from_user):
        """
        处理收到的好友请求，弹出对话框询问是否同意。
        参数:
            from_user: 请求添加好友的用户名
        """
        def answer(accepted):
            try:
                self.queue_send({"type": "friend_response", "to": from_user, "accepted": accepted})
            except Exception as error:
                self.notify("发送失败", str(error))
        self.ask_request(('friend', from_user), "好友申请", f"{from_user} 请求添加你为好友", answer)

    def handle_friend_response(self, from_user, accepted):
        """
        处理好友请求的响应，显示是否被接受的信息。
        参数:
            from_user: 响应好友请求的用户名
            accepted: 是否接受好友请求
        """
        if accepted:
            if from_user not in self.friends:
                self.friends.append(from_user)
                self.friends_listbox.insert(tk.END, from_user)
                self.private_chats[from_user] = []
            self.notify("好友申请", f"{from_user} 已同意你的好友申请！")
        else:
            self.notify("好友申请", f"{from_user} 拒绝了你的好友申请")

    def clear_chat_bubbles(self, friend=None):
        """
        清除聊天区域中的所有消息气泡。
        参数:
            friend: 好友或群组名称，用于确定使用哪个聊天框架
        """
        if friend is None:
            friend = self.current_friend or self.current_group
        if friend and friend in self.chat_frames:
            chat_frame = self.chat_frames[friend]
        else:
            chat_frame = self.chat_container
        for widget in chat_frame.winfo_children():
            widget.destroy()

    def display_message_with_time(self, msg, time_str, is_self=False, friend=None):
        """
        在聊天区域显示带有时间戳的消息。
        参数:
            msg: 要显示的消息
            time_str: 消息的时间戳
            is_self: 是否是自己发送的消息，影响显示位置
            friend: 好友或群组名称，用于确定使用哪个聊天框架
        """
        # 检查组件是否仍然存在
        try:
            if not self.master.winfo_exists():
                return
        except:
            return
            
        if friend is None:
            friend = self.current_friend or self.current_group
        if friend and friend in self.chat_frames:
            chat_frame = self.chat_frames[friend]
        else:
            chat_frame = self.chat_container
            
        # 检查聊天框架是否存在
        try:
            if not chat_frame.winfo_exists():
                return
        except:
            return
            
        try:
            bubble_frame = tk.Frame(chat_frame, bg="#f5f5f5")
            if is_self:
                bubble = tk.Label(bubble_frame, text=msg, bg="#aee1f9", fg="black", wraplength=350, justify="left", padx=10, pady=6, font=("微软雅黑", 11), anchor="e")
                bubble.pack(side=tk.RIGHT, padx=8, pady=2)
            else:
                bubble = tk.Label(bubble_frame, text=msg, bg="#ffffff", fg="black", wraplength=350, justify="left", padx=10, pady=6, font=("微软雅黑", 11), anchor="w", relief="solid", bd=1)
                bubble.pack(side=tk.LEFT, padx=8, pady=2)
            
            if time_str:
                time_label = tk.Label(bubble_frame, text=time_str, bg="#f5f5f5", fg="#888888", font=("微软雅黑", 8))
                time_label.pack(side=tk.BOTTOM, anchor="e" if is_self else "w", padx=8)
            
            bubble_frame.pack(fill=tk.X, anchor="e" if is_self else "w")
            bubble_frame.bind('<MouseWheel>', self.on_chat_wheel)
            for child in bubble_frame.winfo_children():
                child.bind('<MouseWheel>', self.on_chat_wheel)
            
            # 强制更新UI并滚动到底部
            if not self.is_loading_messages:
                self.master.after_idle(self.scroll_to_bottom)
        except tk.TclError:
            # Widget可能已被销毁，忽略错误
            logging.warning("尝试在已销毁的widget上显示消息")
            pass

    def scroll_to_bottom(self):
        """滚动到聊天区域底部"""
        self.chat_canvas.update_idletasks()
        self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))
        self.chat_canvas.yview_moveto(1.0)

    def select_friend(self, event):
        """
        选择好友，显示对应的聊天记录。
        参数:
            event: 列表框选择事件
        """
        if not self.running or self.is_loading_messages:
            return
        try:
            selection = self.friends_listbox.curselection()
            if selection:
                friend = self.friends_listbox.get(selection[0])
                self.current_friend = friend
                self.current_group = None
                self.group_listbox.selection_clear(0, tk.END)
                self.switch_chat_frame(friend)
        except tk.TclError:
            # Widget may have been destroyed during disconnect
            logging.warning("select_friend called on a destroyed widget.")
            return

    def clear_chat_selection(self):
        """清空当前选中的聊天对象（退出群聊/被踢/群解散等场景），回到无选中状态"""
        try:
            # 隐藏当前聊天框即可。清空选择后调用 clear_chat_bubbles 会
            # 销毁 chat_container 的所有子框架，让缓存指向已销毁的控件。
            if self.current_chat_frame is not None:
                self.current_chat_frame.pack_forget()
            self.current_chat_frame = None
            self.current_friend = None
            self.current_group = None
            self.update_chat_target()
            self.master.after_idle(self.scroll_to_bottom)
        except tk.TclError:
            logging.warning("clear_chat_selection called on a destroyed widget.")


    def switch_chat_frame(self, chat_id):
        """切换聊天框架"""
        if self.current_chat_frame:
            self.current_chat_frame.pack_forget()
        
        if chat_id not in self.chat_frames:
            self.chat_frames[chat_id] = tk.Frame(self.chat_container, bg="#f5f5f5")
        
        self.chat_frames[chat_id].bind("<MouseWheel>", self.on_chat_wheel)
        self.chat_frames[chat_id].pack(fill=tk.BOTH, expand=True)
        self.current_chat_frame = self.chat_frames[chat_id]
        
        # 清除当前框架中的消息
        self.clear_chat_bubbles(chat_id)
        
        self.update_chat_target()
        self.is_loading_messages = True
        # 重新显示历史消息
        if chat_id in self.groups:
            # 群组聊天记录
            group_messages = getattr(self, f'group_messages_{chat_id}', [])
            for (msg, time_str), is_self in group_messages:
                self.display_message_with_time(msg, time_str, is_self, friend=chat_id)
        else:
            # 私聊记录
            for (msg, time_str), is_self in self.private_chats.get(chat_id, []):
                self.display_message_with_time(msg, time_str, is_self, friend=chat_id)
        
        self.is_loading_messages = False
        self.scroll_to_bottom()

    def login(self):
        """
        处理登录逻辑，验证用户名和密码，并连接到服务器。
        """
        if self.auth_busy:
            return
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showerror("错误", "用户名和密码不能为空！")
            return
        # 读取并校验端口
        try:
            port = int(self.port_entry.get().strip())
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("错误", "端口必须是 1-65535 之间的整数！")
            return
        self.server_port = port
        self.username = username
        logging.info(f"Login attempt for user: {username}")
        self.connect_server(username, password)

    def notify(self, title, text):
        """Nonmodal feedback keeps the incoming event pump running."""
        label = getattr(self, 'status_label', None) if self.running else getattr(self, 'login_status', None)
        if label is not None and label.winfo_exists():
            label.configure(text=f"{title}：{text}")
        else:
            logging.info("%s: %s", title, text)

    def ask_request(self, key, title, text, callback):
        existing = self.request_windows.get(key)
        if existing is not None and existing.winfo_exists():
            existing.lift()
            return
        window = tk.Toplevel(self.master)
        self.request_windows[key] = window
        window.title(title)
        tk.Label(window, text=text, wraplength=400).pack(padx=20, pady=20)
        def answer(accepted):
            self.request_windows.pop(key, None)
            window.destroy()
            callback(accepted)
        tk.Button(window, text="接受", command=lambda: answer(True)).pack(side=tk.LEFT, padx=20, pady=10)
        tk.Button(window, text="拒绝", command=lambda: answer(False)).pack(side=tk.RIGHT, padx=20, pady=10)
        window.protocol('WM_DELETE_WINDOW', lambda: answer(False))

    def queue_send(self, data):
        if not self.running or self.sock is None:
            raise ConnectionError("连接已断开")
        if len(json.dumps(data).encode('utf-8')) > MAX_RECV_MSG_LEN - 256:
            raise ValueError("消息包超过 1 MiB，请缩短内容")
        self.outgoing.put_nowait((self.sock, data))

    def send_worker(self):
        while True:
            item = self.outgoing.get()
            if item is None:
                return
            sock, data = item
            if sock is not self.sock:
                continue
            try:
                send_msg(sock, data)
            except Exception as error:
                self.incoming.put((sock, {'type': 'send_failed', 'request_id': data.get('request_id'), 'error': str(error)}))
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def close(self):
        if self.auth_busy:
            self.cancel_auth()
        if self.running:
            self.disconnect()
        while True:
            try:
                self.outgoing.get_nowait()
            except queue.Empty:
                break
        self.outgoing.put_nowait(None)
        self.master.destroy()

    def set_auth_busy(self, busy, text=""):
        self.auth_busy = busy
        for button in (self.login_button, self.register_button):
            button.configure(state=tk.DISABLED if busy else tk.NORMAL)
        self.login_status.configure(text=text)

    def cancel_auth(self):
        with self.auth_lock:
            self.auth_generation += 1
            sock = self.auth_sock
            self.auth_sock = None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        self.set_auth_busy(False, "连接已取消")

    def start_auth(self, username, password, register=False, window=None):
        if self.auth_busy:
            return
        self.auth_generation += 1
        generation = self.auth_generation
        port = self.server_port
        self.set_auth_busy(True, "正在注册…" if register else "正在连接…")
        def worker():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            key = None
            keep = False
            error = None
            try:
                with self.auth_lock:
                    if generation != self.auth_generation:
                        return
                    self.auth_sock = sock
                sock.settimeout(10)
                sock.connect((SERVER_HOST, port))
                public_key, key_error = check_server_public_key(recv_msg(sock))
                if key_error:
                    raise ValueError(key_error)
                key = get_random_bytes(16)
                encrypted_key = PKCS1_OAEP.new(public_key).encrypt(key)
                send_msg(sock, {"type": "session_key", "key": base64.b64encode(encrypted_key).decode('utf-8')})
                send_msg(sock, {"type": "encrypted_register" if register else "encrypted_login",
                                "data": encrypt_message(json.dumps({"from": username, "password": password}), key)})
                response = recv_msg(sock)
                expected = "register_result" if register else "login_result"
                if not isinstance(response, dict) or response.get('type') != expected or not response.get('success'):
                    raise ValueError(response.get('error', '认证失败') if isinstance(response, dict) else '服务器未响应')
                keep = not register and generation == self.auth_generation
            except Exception as exc:
                error = str(exc)
            finally:
                if not keep:
                    sock.close()
                def finish():
                    if generation != self.auth_generation:
                        sock.close()
                        return
                    self.auth_sock = None
                    self.set_auth_busy(False)
                    if error is not None:
                        self.notify("注册失败" if register else "登录失败", error)
                    elif register:
                        self.notify("注册成功", "注册成功，请登录")
                        if window is not None and window.winfo_exists():
                            window.destroy()
                    else:
                        self.sock, self.session_key, self.username = sock, key, username
                        authenticated_sockets.add(sock)
                        self.running = True
                        self.seen_message_ids = set()
                        self.message_order = {}
                        self.pending_messages = {}
                        self.build_chat()
                        threading.Thread(target=self.receive_msg, args=(sock,), daemon=True).start()
                self.ui_tasks.put(finish)
        threading.Thread(target=worker, daemon=True).start()

    def connect_server(self, username, password):
        self.start_auth(username, password)

    def send_msg(self):
        text = self.msg_entry.get("1.0", "end-1c")
        if not text.strip() or self.pending_messages:
            return
        if not self.session_key:
            self.notify("发送失败", "会话密钥未建立")
            return
        gid, friend = self.current_group, self.current_friend
        if not gid and not friend:
            self.notify("提示", "请选择好友或群组进行聊天")
            return
        request_id = uuid.uuid4().hex
        data = {'type': 'group_chat' if gid else 'private_chat', 'request_id': request_id,
                'content': encrypt_message(text, self.session_key)}
        data['gid' if gid else 'to'] = gid or friend
        try:
            self.queue_send(data)
        except Exception as error:
            self.notify("发送失败", str(error))
            return
        self.pending_messages[request_id] = text
        self.send_button.configure(state=tk.DISABLED)
        self.notify("消息", "发送中，等待服务器保存确认…")
        sock = self.sock
        self.master.after(15000, lambda: self.expire_pending(sock, request_id))

    def expire_pending(self, sock, request_id):
        if self.sock is sock and request_id in self.pending_messages:
            # Keep correlation until an ACK or disconnect; avoid duplicate retries
            # when the outcome is unknown.
            self.notify("消息", "尚未收到确认，输入已保留；可断开后查看历史确认结果")

    def finish_pending(self, msg):
        request_id = msg.get('request_id')
        text = self.pending_messages.pop(request_id, None)
        if text is None:
            return
        if msg.get('success'):
            if self.msg_entry.get('1.0', 'end-1c') == text:
                self.msg_entry.delete('1.0', tk.END)
            self.notify("消息", "服务器已保存")
        else:
            self.notify("发送失败", msg.get('error', '请重试，输入已保留'))
        self.update_chat_target()

    def register(self):
        """
        打开注册窗口，允许用户输入用户名和密码进行注册。
        """
        register_window = tk.Toplevel(self.master)
        register_window.title("注册")
        register_window.geometry("400x300")
        register_window.configure(bg="#ffffff")
        entry_style = {"font": ("微软雅黑", 12), "relief": tk.FLAT, "highlightthickness": 2,
                       "highlightbackground": "#aee1f9", "highlightcolor": "#3a7bd5", "bd": 0, "width": 22}
        tk.Label(register_window, text="用户名:", font=("微软雅黑", 12), bg="#ffffff").pack(pady=(20, 5))
        username_entry = tk.Entry(register_window, **entry_style, bg="#f5faff")
        username_entry.pack(ipady=6)
        tk.Label(register_window, text="密码:", font=("微软雅黑", 12), bg="#ffffff").pack(pady=(10, 5))
        password_entry = tk.Entry(register_window, **entry_style, bg="#f5faff", show="*")
        password_entry.pack(ipady=6)
        
        def do_register():
            username = username_entry.get().strip()
            password = password_entry.get()
            if not username or not password:
                messagebox.showerror("错误", "用户名和密码不能为空！")
                return
            # 读取并校验端口（与登录逻辑保持一致，确保注册时端口选择生效）
            try:
                port = int(self.port_entry.get().strip())
                if not (1 <= port <= 65535):
                    raise ValueError
            except ValueError:
                messagebox.showerror("错误", "端口必须是 1-65535 之间的整数！")
                return
            self.server_port = port
            
            self.start_auth(username, password, register=True, window=register_window)

        tk.Button(register_window, text="提交注册", font=("微软雅黑", 12, "bold"), bg="#3a7bd5", fg="#fff", command=do_register).pack(pady=20)

    def on_message_entry_key(self, event):
        """
        处理消息输入框的按键事件，Enter键发送消息，Ctrl+Enter换行。
        参数:
            event: 按键事件
        """
        if event.state & 0x4:  # Ctrl键被按下
            self.msg_entry.insert(tk.INSERT, "\n")
        else:
            self.send_msg()
        return "break"

    def update_online_users(self, user_list):
        """
        更新在线用户列表。
        参数:
            user_list: 在线用户列表
        """
        self.online_listbox.delete(0, tk.END)
        for user in user_list:
            self.online_listbox.insert(tk.END, user)

    def receive_msg(self, sock):
        """Read only from this connection; never call Tk from the worker."""
        while self.running and self.sock is sock:
            try:
                msg = recv_msg(sock)
            except Exception:
                msg = None
            self.incoming.put((sock, msg))
            if msg is None:
                return

    def drain_incoming(self):
        """Apply network events on Tk's thread, discarding old connection events."""
        try:
            for _ in range(100):
                try:
                    callback = self.ui_tasks.get_nowait()
                except queue.Empty:
                    break
                callback()
            # Bound work so a busy server cannot starve keyboard/window events.
            for _ in range(100):
                try:
                    sock, msg = self.incoming.get_nowait()
                except queue.Empty:
                    break
                if not self.running or self.sock is not sock:
                    continue
                if msg is None:
                    self.disconnect()
                    self.notify("连接断开", "与服务器的连接已断开；输入将在重新登录后恢复")
                    continue
                try:
                    self.handle_server_message(msg)
                except Exception:
                    logging.exception("忽略格式异常的服务器消息")
        finally:
            self.master.after(50, self.drain_incoming)

    @staticmethod
    def run_ui(callback):
        callback()

    def handle_server_message(self, msg):
        """Handle a server event on the main thread."""
        # 畸形消息过滤：非 dict 或 type 非字符串的消息直接忽略，避免接收线程崩溃
        if not isinstance(msg, dict) or not isinstance(msg.get("type"), str):
            logging.warning(f"收到格式异常的消息，已忽略: {str(msg)[:100]}")
            return

        if msg['type'] in ('private_chat_result', 'group_chat_result', 'send_failed'):
            self.finish_pending(msg)
        if msg['type'] in ('private_chat', 'group_chat') and isinstance(msg.get('message_id'), int):
            message_id = msg['message_id']
            if message_id in self.seen_message_ids:
                return
            self.seen_message_ids.add(message_id)

        if isinstance(msg, dict):
            mtype = msg.get("type")
            if mtype == "online_users":
                user_list = msg.get("users", [])
                logging.info(f"Received online users list: {user_list}")
                self.run_ui(lambda ul=user_list: self.update_online_users(ul))

            elif mtype == "user_groups_chunk":
                if msg.get("first"):
                    self.group_sync_chunks = []
                self.group_sync_chunks.append(msg["data"])
                if msg.get("last"):
                    snapshot = json.loads("".join(self.group_sync_chunks))
                    del self.group_sync_chunks
                    self.handle_server_message(snapshot)

            elif mtype == "user_groups_list":
                group_list = msg.get("groups", [])
                logging.info("Received initial group list (%s groups)", len(group_list) if isinstance(group_list, list) else "invalid")
                self.groups = {g["gid"]: g for g in group_list}
                self.run_ui(self.refresh_group_listbox)

            elif mtype == "friends_list":
                friends_list = msg.get("friends", [])
                logging.info(f"Received friends list: {friends_list}")
                self.friends = friends_list
                # 更新好友列表框
                self.run_ui(self.update_friends_listbox)

            elif mtype == "private_chat":
                logging.info(f"Received private chat message: {msg}")
                from_user = msg.get("from")
                to_user = msg.get("to")
                encrypted_content = msg.get("content")
                time_str = msg.get("timestamp", "")
                if not self.session_key:
                    return
                try:
                    content = decrypt_message(encrypted_content, self.session_key)
                except Exception as e:
                    logging.error(f"解密来自 {from_user} 的私聊消息失败: {e}")
                    content = "[消息解密失败]"

                show = f'{from_user}: {content}'
                is_self = (from_user == self.username)

                # 确定聊天对象
                chat_partner = to_user if is_self else from_user

                # 如果聊天对象不在好友列表中，则添加（处理接收新好友消息的情况）
                if chat_partner not in self.friends:
                    self.friends.append(chat_partner)
                    # 使用lambda的默认参数来捕获当前的chat_partner值
                    self.run_ui(lambda p=chat_partner: self.friends_listbox.insert(tk.END, p))
                    self.private_chats[chat_partner] = []

                # 将消息存储在聊天对象的名下
                if chat_partner not in self.private_chats:
                    self.private_chats[chat_partner] = []
                appended = self.store_chat_message(chat_partner, self.private_chats[chat_partner], ((show, time_str), is_self), msg.get("message_id"))

                # 如果当前聊天窗口是该对象，则显示消息
                if self.current_friend == chat_partner and not self.history_syncing:
                    # 使用lambda的默认参数来捕获当前值
                    if appended:
                        self.display_message_with_time(show, time_str, is_self, friend=chat_partner)
                    else:
                        self.switch_chat_frame(chat_partner)

            elif mtype == "group_chat":
                logging.info(f"Received group chat message: {msg}")
                gid = msg.get("gid")
                from_user = msg.get("from")
                encrypted_content = msg.get("content")
                time_str = msg.get("timestamp", "")
                if not self.session_key:
                    return
                try:
                    content = decrypt_message(encrypted_content, self.session_key)
                except Exception as e:
                    logging.error(f"解密来自 {from_user} 的群聊消息失败 (群组: {gid}): {e}")
                    content = "[消息解密失败]"

                show = f'{from_user}(群聊): {content}'
                is_self = (from_user == self.username)

                # 如果客户端不知道这个群组，请求信息
                if gid not in self.groups:
                    self.run_ui(lambda g=gid: self.request_group_info(g))

                # 确保该群组的消息列表存在
                if not hasattr(self, f'group_messages_{gid}'):
                    setattr(self, f'group_messages_{gid}', [])

                # 存储消息
                appended = self.store_chat_message(gid, getattr(self, f'group_messages_{gid}'), ((show, time_str), is_self), msg.get('message_id'))

                # 如果当前聊天窗口是该群组，则显示消息
                if self.current_group == gid and not self.history_syncing:
                    if appended:
                        self.display_message_with_time(show, time_str, is_self, friend=gid)
                    else:
                        self.switch_chat_frame(gid)

            elif mtype == "group_create_result":
                logging.info(f"Received group create result: {msg}")
                if msg.get("success"):
                    gid = msg.get("gid")
                    group_name = msg.get("group_name", "新群聊")
                    owner = msg.get("owner") # 从消息中获取群主
                    members = msg.get("members", [])
                    self.groups[gid] = {"group_name": group_name, "owner": owner, "members": members}
                    self.run_ui(self.refresh_group_listbox) # 刷新整个列表以保持一致性
                    if owner == self.username: # 只有创建者会看到这个弹窗
                        self.run_ui(lambda gn=group_name, g=gid: self.notify("群聊创建", f"群聊 '{gn}' 创建成功！ID: {g}"))
                else:
                    error_msg = msg.get("error", "创建群聊失败")
                    self.run_ui(lambda em=error_msg: self.notify("群聊创建失败", em))

            elif mtype == "group_info":
                logging.info(f"Received group info: {msg}")
                gid = msg.get("gid")
                if gid and "error" not in msg:
                    self.groups[gid] = msg
                    self.refresh_group_listbox()
                    if gid in self.group_info_requests:
                        self.group_info_requests.discard(gid)
                        if gid not in self.group_windows:
                            self.show_group_info_after_update(gid)
                else:
                    err = msg.get("error", "获取群组信息失败")
                    self.run_ui(lambda em=err: self.notify("群组信息", em))

            elif mtype == "group_invite":
                logging.info(f"Received group invite: {msg}")
                from_user = msg.get("from")
                gid = msg.get("gid")
                self.run_ui(lambda fu=from_user, g=gid: self.handle_group_invite(fu, g))

            elif mtype == "group_join_result":
                logging.info(f"Received group join result: {msg}")
                if msg.get("success"):
                    gid = msg.get("gid")
                    group_name = msg.get("group_name", "未知群聊")
                    owner = msg.get("owner")
                    members = msg.get("members", [])
                    self.groups[gid] = {"group_name": group_name, "owner": owner, "members": members}
                    self.run_ui(self.refresh_group_listbox)
                    self.run_ui(lambda gn=group_name: self.notify("加入群聊", f"成功加入群聊: {gn}"))
                else:
                    error_msg = msg.get("error", "加入群聊失败")
                    self.run_ui(lambda em=error_msg: self.notify("加入群聊失败", em))

            elif mtype == "group_update":
                logging.info(f"Received group update: {msg}")
                gid = msg.get("gid")
                group_name = msg.get("group_name")
                owner = msg.get("owner")
                members = msg.get("members")
                self.groups[gid] = {"group_name": group_name, "owner": owner, "members": members}
                self.run_ui(self.refresh_group_listbox)

            elif mtype == "group_leave_result":
                logging.info(f"Received group leave result: {msg}")
                if msg.get("success"):
                    gid = msg.get("gid")
                    if gid in self.groups:
                        del self.groups[gid]
                    if hasattr(self, f'group_messages_{gid}'):
                        delattr(self, f'group_messages_{gid}')
                    self.run_ui(lambda: self.refresh_group_listbox())
                    self.run_ui(lambda g=gid: self.notify("退出群聊", f"成功退出群聊: {g}"))
                    if self.current_group == gid and not self.history_syncing:
                        self.run_ui(self.clear_chat_selection) # 清空当前选中聊天
                else:
                    error_msg = msg.get("error", "退出群聊失败")
                    self.run_ui(lambda em=error_msg: self.notify("退出群聊失败", em))

            elif mtype == "group_kick_result":
                logging.info(f"Received group kick result: {msg}")
                if msg.get("success"):
                    gid = msg.get("gid")
                    kicked_user = msg.get("kick")
                    if gid in self.groups and kicked_user in self.groups[gid]["members"]:
                        self.groups[gid]["members"].remove(kicked_user)
                    self.run_ui(lambda k=kicked_user, g=gid: self.notify("踢出成员", f"已将 {k} 从群聊 {g} 踢出"))
                    if kicked_user == self.username: # 自己被踢出：移除群组并清空选中聊天
                        if gid in self.groups:
                            del self.groups[gid]
                        if hasattr(self, f'group_messages_{gid}'):
                            delattr(self, f'group_messages_{gid}')
                        if self.current_group == gid and not self.history_syncing:
                            self.run_ui(self.clear_chat_selection)
                    self.run_ui(lambda: self.refresh_group_listbox())
                else:
                    error_msg = msg.get("error", "踢出成员失败")
                    self.run_ui(lambda em=error_msg: self.notify("踢出成员失败", em))

            elif mtype == "group_kick_notification":
                logging.info(f"Received group kick notification: {msg}")
                gid = msg.get("gid")
                group_name = msg.get("group_name")
                self.run_ui(lambda gn=group_name: self.notify("群聊通知", f"您已被从群聊 {gn} 移除"))
                if gid in self.groups:
                    del self.groups[gid]
                if hasattr(self, f'group_messages_{gid}'):
                    delattr(self, f'group_messages_{gid}')
                self.run_ui(lambda: self.refresh_group_listbox())
                if self.current_group == gid and not self.history_syncing:
                    self.run_ui(self.clear_chat_selection) # 清空当前选中聊天

            elif mtype == "friend_request":
                logging.info(f"Received friend request: {msg}")
                from_user = msg.get("from")
                self.run_ui(lambda fu=from_user: self.handle_friend_request(fu))

            elif mtype == "friend_response":
                logging.info(f"Received friend response: {msg}")
                from_user = msg.get("from")
                accepted = msg.get("accepted")
                self.run_ui(lambda fu=from_user, ac=accepted: self.handle_friend_response(fu, ac))

            elif mtype == "friend_update":
                logging.info(f"Received friend update: {msg}")
                new_friend = msg.get("friend")
                if new_friend and new_friend not in self.friends:
                    self.friends.append(new_friend)
                    self.private_chats[new_friend] = []
                    self.run_ui(lambda f=new_friend: self.friends_listbox.insert(tk.END, f))

            elif mtype == "friend_request_result":
                logging.info(f"Received friend request result: {msg}")
                with friend_request_lock:
                    self.friend_request_result = msg.get("success")
                if msg.get("success"):
                    self.notify("好友申请", msg.get("message", "好友申请发送成功"))
                else:
                    error_msg = msg.get("error", "好友申请失败")
                    self.run_ui(lambda em=error_msg: self.notify("好友申请失败", em))

            elif mtype == "group_invite_result":
                logging.info(f"Received group invite result: {msg}")
                if not msg.get("success"):
                    error_msg = msg.get("error", "群邀请失败")
                    self.run_ui(lambda em=error_msg: self.notify("群邀请失败", em))

            elif mtype == "group_disband_result":
                logging.info(f"Received group disband result: {msg}")
                if msg.get("success"):
                    gid = msg.get("gid")
                    if gid in self.groups:
                        del self.groups[gid]
                    if hasattr(self, f'group_messages_{gid}'):
                        delattr(self, f'group_messages_{gid}')
                    self.run_ui(lambda: self.refresh_group_listbox())
                    self.run_ui(lambda: self.notify("解散群聊", "群聊已成功解散"))
                    if self.current_group == gid and not self.history_syncing:
                        self.run_ui(self.clear_chat_selection) # 清空当前选中聊天
                else:
                    error_msg = msg.get("error", "解散群聊失败")
                    self.run_ui(lambda em=error_msg: self.notify("解散群聊失败", em))

            elif mtype == "group_disband_notification":
                logging.info(f"Received group disband notification: {msg}")
                gid = msg.get("gid")
                group_name = msg.get("group_name")
                self.run_ui(lambda gn=group_name: self.notify("群聊通知", f"群聊 {gn} 已被解散"))
                if gid in self.groups:
                    del self.groups[gid]
                if hasattr(self, f'group_messages_{gid}'):
                    delattr(self, f'group_messages_{gid}')
                self.run_ui(lambda: self.refresh_group_listbox())
                if self.current_group == gid and not self.history_syncing:
                    self.run_ui(self.clear_chat_selection) # 清空当前选中聊天

            elif mtype == "group_transfer_result":
                logging.info(f"Received group transfer result: {msg}")
                if msg.get("success"):
                    gid = msg.get("gid")
                    new_owner = msg.get("new_owner")
                    if gid in self.groups:
                        self.groups[gid]["owner"] = new_owner
                    self.run_ui(lambda: self.refresh_group_listbox())
                    self.run_ui(lambda no=new_owner: self.notify("转让群主", f"群主已成功转让给 {no}"))
                else:
                    error_msg = msg.get("error", "转让群主失败")
                    self.run_ui(lambda em=error_msg: self.notify("转让群主失败", em))

            elif mtype == "group_transfer_notification":
                logging.info(f"Received group transfer notification: {msg}")
                gid = msg.get("gid")
                old_owner = msg.get("old_owner")
                new_owner = msg.get("new_owner")
                group_name = msg.get("group_name")
                if gid in self.groups:
                    self.groups[gid]["owner"] = new_owner
                self.run_ui(lambda: self.refresh_group_listbox())
                self.run_ui(lambda gn=group_name, oo=old_owner, no=new_owner: self.notify("群聊通知", f"群聊 {gn} 的群主已由 {oo} 转让给 {no}"))

            elif mtype == "group_rename_result":
                logging.info(f"Received group rename result: {msg}")
                if msg.get("success"):
                    gid = msg.get("gid")
                    new_name = msg.get("new_name")
                    # 群组不在本地时 old_name 无法得知，回退为 gid，避免未绑定变量
                    old_name = msg.get("old_name", gid)
                    if gid in self.groups:
                        self.groups[gid]["group_name"] = new_name
                    self.run_ui(lambda: self.refresh_group_listbox())
                    self.run_ui(lambda on=old_name, nn=new_name: self.notify("修改群聊名称", f"群聊名称已从 '{on}' 修改为 '{nn}'"))
                else:
                    error_msg = msg.get("error", "修改群聊名称失败")
                    self.run_ui(lambda em=error_msg: self.notify("修改群聊名称失败", em))

            elif mtype == "group_rename_notification":
                logging.info(f"Received group rename notification: {msg}")
                gid = msg.get("gid")
                old_name = msg.get("old_name")
                new_name = msg.get("new_name")
                if gid in self.groups:
                    self.groups[gid]["group_name"] = new_name
                self.run_ui(lambda: self.refresh_group_listbox())
                self.run_ui(lambda on=old_name, nn=new_name, owner=msg.get("owner"): self.notify("群聊通知", f"群聊名称已由群主 {owner} 从 '{on}' 修改为 '{nn}'"))

            elif mtype == "error":
                # 服务器主动通知的错误（如会话过期、速率限制等），提示后返回登录界面
                err = msg.get("message", "服务器错误")
                logging.warning(f"服务器错误: {err}")
                def show_server_error(e=err):
                    self.disconnect()
                    self.notify("服务器通知", e)
                self.run_ui(show_server_error)
                return

            elif mtype == "private_chat_result":
                if not msg.get("success"):
                    err = msg.get("error", "私聊消息发送失败")
                    self.run_ui(lambda e=err: self.notify("私聊失败", e))

            elif mtype == "group_chat_result":
                if not msg.get("success"):
                    err = msg.get("error", "群聊消息发送失败")
                    self.run_ui(lambda e=err: self.notify("群聊失败", e))

            elif mtype == "friend_response_result":
                if not msg.get("success"):
                    err = msg.get("error", "好友响应失败")
                    self.run_ui(lambda e=err: self.notify("好友响应失败", e))

            elif mtype == 'history_begin':
                self.history_syncing = True
            elif mtype == 'history_end':
                self.history_syncing = False
                target = self.current_group or self.current_friend
                if target:
                    self.switch_chat_frame(target)
            elif mtype in ("group_invite_response_result", "send_failed"):
                pass
            else:
                logging.warning(f"收到未知格式消息: {msg}")


    def clear_window(self):
        """
        清除窗口中的所有控件，用于切换界面。
        """
        self.group_windows = {}
        self.request_windows = {}
        self.group_info_requests = set()
        self.history_syncing = False
        for widget in self.master.winfo_children():
            widget.destroy()

    def create_group(self):
        # 创建群聊弹窗
        group_window = tk.Toplevel(self.master)
        group_window.title("创建群聊")
        group_window.geometry("400x400")
        tk.Label(group_window, text="群聊名称:").pack(pady=10)
        name_entry = tk.Entry(group_window)
        name_entry.pack(pady=5)
        tk.Label(group_window, text="选择成员:").pack(pady=10)
        members_listbox = tk.Listbox(group_window, selectmode=tk.MULTIPLE)
        for f in self.friends:
            members_listbox.insert(tk.END, f)
        members_listbox.pack(pady=5, fill=tk.BOTH, expand=True)
        
        def do_create():
            group_name = name_entry.get().strip()
            sel = members_listbox.curselection()
            members = [self.friends[i] for i in sel]
            if not group_name or not members:
                messagebox.showerror("错误", "群名和成员不能为空！")
                return
            req = {
                "type": "group_create",
                "from": self.username,
                "group_name": group_name,
                "members": members
            }
            self.queue_send(req)
            group_window.destroy()
        
        tk.Button(group_window, text="创建", command=do_create).pack(pady=20)

    def request_group_info(self, gid):
        """请求群组信息"""
        logging.info(f"Requesting info for group '{gid}'.")
        req = {"type": "group_info", "from": self.username, "gid": gid}
        self.queue_send(req)

    def select_group(self, event):
        if not self.running or self.is_loading_messages:
            return
        try:
            sel = self.group_listbox.curselection()
            if sel:
                # 按列表索引映射 gid（群组列表按 self.groups 的插入顺序渲染），
                # 通过群名反查在存在同名群组时会选错目标
                gid = self.get_gid_by_index(sel[0])
                if gid:
                    self.current_group = gid
                    self.friends_listbox.selection_clear(0, tk.END)
                    self.current_friend = None # 确保私聊和群聊互斥
                    self.switch_chat_frame(gid)
        except tk.TclError:
            # Widget may have been destroyed during disconnect
            logging.warning("select_group called on a destroyed widget.")
            return

    def show_group_info_on_double_click(self, event):
        if not self.running:
            return
        try:
            sel = self.group_listbox.curselection()
            if sel:
                # 按列表索引映射 gid，避免同名群组时通过群名反查选错目标
                gid = self.get_gid_by_index(sel[0])
                if gid:
                    self.show_group_info(gid)
        except tk.TclError:
            logging.warning("show_group_info_on_double_click called on a destroyed widget.")
            return

    def show_group_info(self, gid):
        # 响应到达后再打开窗口。
        self.group_info_requests.add(gid)
        self.request_group_info(gid)

    def show_group_info_after_update(self, gid):
        info = self.groups.get(gid)
        if not info:
            messagebox.showerror("错误", "无法获取群组信息")
            return

        members = info.get("members", [])
        
        group_info_window = self.group_windows.get(gid)
        if group_info_window is None or not group_info_window.winfo_exists():
            group_info_window = tk.Toplevel(self.master)
            self.group_windows[gid] = group_info_window
            group_info_window.protocol('WM_DELETE_WINDOW', lambda: self.close_group_window(gid))
        else:
            for child in group_info_window.winfo_children():
                child.destroy()
        group_info_window.title(f"群聊信息 - {info.get('group_name')}")

        # --- Top section with labels and listbox ---
        top_frame = tk.Frame(group_info_window)
        top_frame.pack(pady=5, padx=10, fill="both", expand=True)
        tk.Label(top_frame, text=f"群名: {info.get('group_name')}").pack()
        tk.Label(top_frame, text=f"群主: {info.get('owner')}").pack()
        tk.Label(top_frame, text="成员列表:").pack(pady=(10, 2))
        

        members_list = tk.Listbox(top_frame)
        for m in members:
            members_list.insert(tk.END, m)
        members_list.pack(fill="both", expand=True)

        # --- Button section ---
        button_container = tk.Frame(group_info_window)
        button_container.pack(pady=5, padx=10, fill="x")

        # --- Member Actions Frame ---
        member_actions_frame = tk.Frame(button_container)
        member_actions_frame.pack(fill="x", pady=2)

        def refresh_members():
            self.request_group_info(gid)
        
        def invite_member():
            friend = simpledialog.askstring("邀请成员", "输入好友用户名:")
            if friend:
                req = {"type": "group_invite", "from": self.username, "to": friend, "gid": gid}
                self.queue_send(req)
        
        def leave_group():
            req = {"type": "group_leave", "from": self.username, "gid": gid}
            self.queue_send(req)

        tk.Button(member_actions_frame, text="刷新成员", command=refresh_members).pack(side="left", padx=2, expand=True)
        tk.Button(member_actions_frame, text="邀请成员", command=invite_member).pack(side="left", padx=2, expand=True)
        tk.Button(member_actions_frame, text="退出群聊", command=leave_group).pack(side="left", padx=2, expand=True)
        
        # --- Owner Actions Frame ---
        if self.username == info.get("owner"):
            owner_actions_frame = tk.Frame(button_container)
            owner_actions_frame.pack(fill="x", pady=2)

            def kick_member():
                sel = members_list.curselection()
                if sel:
                    member = members_list.get(sel[0])
                    if member != self.username:
                        req = {"type": "group_kick", "from": self.username, "gid": gid, "kick": member}
                        self.queue_send(req)
            
            def disband_group():
                if messagebox.askyesno("解散群聊", "确定要解散群聊吗？此操作不可撤销。"):
                    req = {"type": "group_disband", "from": self.username, "gid": gid}
                    self.queue_send(req)

            def transfer_ownership():
                new_owner = simpledialog.askstring("转让群主", "请输入新群主用户名:")
                if new_owner:
                    req = {"type": "group_transfer", "from": self.username, "gid": gid, "new_owner": new_owner}
                    self.queue_send(req)
            
            def rename_group():
                new_name = simpledialog.askstring("修改群聊名称", "请输入新的群聊名称:")
                if new_name:
                    req = {"type": "group_rename", "from": self.username, "gid": gid, "new_name": new_name}
                    self.queue_send(req)

            tk.Button(owner_actions_frame, text="踢出成员", command=kick_member).pack(side="left", padx=2, expand=True)
            tk.Button(owner_actions_frame, text="解散群聊", command=disband_group).pack(side="left", padx=2, expand=True)
            tk.Button(owner_actions_frame, text="转让群主", command=transfer_ownership).pack(side="left", padx=2, expand=True)
            tk.Button(owner_actions_frame, text="修改群聊名称", command=rename_group).pack(side="left", padx=2, expand=True)
        
        # 自动调整窗口大小以适应内容
        group_info_window.update_idletasks()
        width = group_info_window.winfo_reqwidth()
        height = group_info_window.winfo_reqheight()
        group_info_window.geometry(f"{width+20}x{height+10}")

    def handle_group_invite(self, from_user, gid):
        def answer(accepted):
            try:
                self.queue_send({'type': 'group_join' if accepted else 'group_invite_response',
                                 'gid': gid, 'accepted': accepted})
            except Exception as error:
                self.notify("发送失败", str(error))
        self.ask_request(('group', gid), "群聊邀请", f"{from_user} 邀请你加入群聊", answer)

    def refresh_group_listbox(self):
        """刷新群组列表"""
        try:
            self.group_listbox.delete(0, tk.END)
            if self.current_group and self.current_group not in self.groups:
                self.clear_chat_selection()
            for gid in list(self.group_windows):
                if gid not in self.groups:
                    self.close_group_window(gid)
                else:
                    self.show_group_info_after_update(gid)
            for gid, info in self.groups.items():
                self.group_listbox.insert(tk.END, info.get("group_name", gid))
                if gid == self.current_group:
                    self.group_listbox.selection_set(list(self.groups).index(gid))
            self.update_chat_target()
        except tk.TclError:
            logging.warning("refresh_group_listbox called on a destroyed widget.")

    def get_gid_by_name(self, group_name):
        """通过群组名称查找GID"""
        for gid, info in self.groups.items():
            if info and info.get("group_name") == group_name:
                return gid
        return None

    def get_gid_by_index(self, index):
        """通过群组列表的显示索引查找GID（群组列表按 self.groups 的插入顺序渲染）"""
        gids = list(self.groups.keys())
        if 0 <= index < len(gids):
            return gids[index]
        return None

    def close_group_window(self, gid):
        window = self.group_windows.pop(gid, None)
        if window is not None and window.winfo_exists():
            window.destroy()

    def update_group_info_window(self, window, gid):
        if gid in self.groups and window.winfo_exists():
            self.show_group_info_after_update(gid)

    def store_chat_message(self, chat_id, messages, entry, message_id):
        import bisect
        order = self.message_order.setdefault(chat_id, [])
        key = message_id if isinstance(message_id, int) else (order[-1] + 1 if order else 0)
        index = bisect.bisect_right(order, key)
        order.insert(index, key)
        messages.insert(index, entry)
        return index == len(messages) - 1

    def update_chat_target(self):
        gid = getattr(self, 'current_group', None)
        friend = getattr(self, 'current_friend', None)
        title = self.groups.get(gid, {}).get('group_name', gid) if gid else friend
        if hasattr(self, 'chat_title'):
            self.chat_title.configure(text=f"当前会话：{title}" if title else "请选择好友或群组")
            self.send_button.configure(state=tk.NORMAL if title and not self.pending_messages else tk.DISABLED)

    def on_chat_wheel(self, event):
        if self.running and self.chat_canvas.winfo_exists():
            self.chat_canvas.yview_scroll(int(-event.delta / 120), 'units')
            return 'break'

    def update_friends_listbox(self):
        """更新好友列表框"""
        try:
            self.friends_listbox.delete(0, tk.END)
            for friend in self.friends:
                self.friends_listbox.insert(tk.END, friend)
        except tk.TclError:
            logging.warning("update_friends_listbox called on a destroyed widget.")


if __name__ == '__main__':
    import sys
    import traceback
    try:
        logging.info("Starting Chat Client")
        root = tk.Tk()
        app = ChatClient(root)
        root.mainloop()
    except Exception as e:
        print("客户端启动异常:", e)
        traceback.print_exc()
        sys.exit(1)
