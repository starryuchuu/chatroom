import tkinter as tk            # 导入tkinter，用于构建图形界面
from tkinter import simpledialog, messagebox, scrolledtext   # 导入对话框和滚动文本控件
import socket                   # 导入socket模块，实现网络通信
import threading                # 导入threading模块，处理多线程操作
from Crypto.Cipher import AES   # 导入AES模块，进行加密解密操作
from Crypto.Util.Padding import pad, unpad  # 导入填充与去填充函数
import base64                   # 导入base64模块，用于数据编码转换
import struct                   # 导入struct模块，构造定长消息包
import logging                  # 导入logging模块，记录日志信息

# 设置日志输出级别为INFO，并设置输出格式（包含时间、级别、消息）
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

KEY = b'\xe5\xc6\xba\xd9?x\\f(\x9f\x02B6\x9e\xdd\xd9'  # 16字节AES密钥，用于加密和解密
BLOCK_SIZE = 16               # AES加密块的大小：16字节
SERVER_HOST = '127.0.0.1'   # 服务器地址
SERVER_PORT = 12345           # 服务器端口号

def recvall(sock, n):
    """
    从socket中不断接收数据，直到接收指定的n个字节。
    参数:
        sock: 操作的socket对象。
        n: 需要接收的字节总数。
    返回:
        如果成功接收则返回数据，否则返回None。
    """
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def send_msg(sock, msg):
    """
    发送消息给服务器。
    参数:
        sock: 用于网络通信的socket对象。
        msg: 待发送的消息字符串。
    实现步骤:
        1. 将消息编码为UTF-8字节。
        2. 使用struct打包消息头（4字节的消息长度）。
        3. 发送打包头部和消息内容。
    """
    data = msg.encode('utf-8')
    header = struct.pack('!I', len(data))
    sock.sendall(header + data)

def recv_msg(sock):
    """
    从socket中接收一条完整消息。
    参数:
        sock: 与服务器通信的socket对象。
    返回:
        接收到的消息字符串；如果接收失败则返回None。
    实现:
        先接收4字节头，再根据消息长度接收消息体数据。
    """
    header = recvall(sock, 4)
    if not header:
        return None
    msg_len = struct.unpack('!I', header)[0]
    data = recvall(sock, msg_len)
    return data.decode('utf-8') if data else None

def encrypt_message(message):
    """
    采用AES算法对消息进行加密，并返回Base64编码后的字符串。
    参数:
        message: 待加密的明文消息。
    """
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(message.encode(), BLOCK_SIZE))
    return base64.b64encode(encrypted).decode()

def decrypt_message(encrypted_message):
    """
    解密经过AES加密且Base64编码的消息，还原为明文。
    参数:
        encrypted_message: 加密的Base64字符串。
    """
    cipher = AES.new(KEY, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_message)), BLOCK_SIZE)
    return decrypted.decode()

class ChatClient:
    def __init__(self, master):
        """
        初始化聊天客户端应用程序。
        参数:
            master: Tkinter主窗口对象。
        功能:
            - 设置窗口标题、初始化socket及当前用户名。
            - 构建登录界面以进行身份认证。
        """
        self.master = master
        self.master.title("简易聊天客户端")
        self.sock = None                 # 初始化socket为空，后续连接服务器时赋值
        self.username = None             # 当前登录用户，初始为空
        self.friend_request_result = None  # 用于保存发送好友申请后的反馈结果
        self.build_login()               # 构建并显示登录页面

    def build_login(self):
        """
        构建登录窗口界面。
        功能:
            - 清空主窗口内容。
            - 设置窗口大小及背景色。
            - 添加用户名、密码输入框，以及登录与注册按钮。
        """
        self.clear_window()             # 清除已有控件
        self.master.geometry('800x530')   # 设置窗口尺寸
        self.master.configure(bg="#ffffff")  # 背景色设为白色
        login_frame = tk.Frame(self.master, bg="#ffffff", bd=0, highlightthickness=0)
        login_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)  # 将框架居中显示
        tk.Label(login_frame, text="简易聊天室登录", font=("微软雅黑", 20, "bold"), bg="#ffffff", fg="#3a7bd5").pack(pady=(0, 25))
        tk.Label(login_frame, text="用户名:", font=("微软雅黑", 12), bg="#ffffff").pack(pady=(0, 8))
        entry_style = {"font": ("微软雅黑", 12), "relief": tk.FLAT, "highlightthickness": 2, "highlightbackground": "#aee1f9", "highlightcolor": "#3a7bd5", "bd": 0, "width": 22}
        self.username_entry = tk.Entry(login_frame, **entry_style, bg="#f5faff")
        self.username_entry.pack(pady=(0, 18), ipady=6)
        tk.Label(login_frame, text="密码:", font=("微软雅黑", 12), bg="#ffffff").pack(pady=(10, 5))
        self.password_entry = tk.Entry(login_frame, **entry_style, bg="#f5faff", show="*")
        self.password_entry.pack(ipady=6)
        login_btn = tk.Button(login_frame, text="登录", font=("微软雅黑", 12, "bold"), bg="#3a7bd5", fg="#fff", activebackground="#5596e6", activeforeground="#fff", bd=0, relief=tk.FLAT, width=16, height=1, cursor="hand2", command=self.login)
        login_btn.pack(pady=(0, 10))
        register_btn = tk.Button(login_frame, text="注册", font=("微软雅黑", 12), bg="#f0f0f0", fg="#3a7bd5", activebackground="#dcdcdc", bd=0, relief=tk.FLAT, width=16, height=1, cursor="hand2", command=self.register)
        register_btn.pack(pady=(0, 10))
        self.username_entry.focus_set()  # 使用户名输入框获得焦点，方便直接输入
        self.master.bind('<Return>', lambda e: self.login())  # 绑定回车键，便于快速登录

    def display_message(self, msg, is_self=False):
        """
        以普通文本形式显示接收到的消息。（旧方法，保留兼容性）
        参数:
            msg: 消息文本内容。
            is_self: 布尔值，指示消息是否是自己发送。
        """
        self.chat_area.config(state='normal')  # 允许修改文本框
        if is_self:
            self.chat_area.insert(tk.END, f'{msg}\n', 'right')  # 自己发送的消息右对齐
        else:
            self.chat_area.insert(tk.END, f'{msg}\n', 'left')   # 他人消息左对齐
        self.chat_area.config(state='disabled')  # 禁止手动编辑
        self.chat_area.see(tk.END)  # 自动滚动到最新消息

    def build_chat(self):
        """
        构建主聊天界面。
        功能:
            - 清空登录界面后构建显示聊天内容的各个区域，如顶部显示当前用户名、左侧好友列表、右侧在线用户及中间聊天区和输入框。
        """
        self.clear_window()             # 移除登录界面的所有控件
        top_frame = tk.Frame(self.master)
        top_frame.pack(side=tk.TOP, fill=tk.X)
        tk.Label(top_frame, text=f"当前用户：{self.username}", fg="green").pack(side=tk.LEFT, padx=10, pady=5)
        left_frame = tk.Frame(self.master)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        tk.Label(left_frame, text="好友列表").pack(pady=5)
        self.friends_listbox = tk.Listbox(left_frame, width=18)
        self.friends_listbox.pack(fill=tk.Y, expand=True)
        self.friends_listbox.bind('<<ListboxSelect>>', self.select_friend)
        tk.Button(left_frame, text="添加好友", command=self.add_friend).pack(pady=5)
        self.friends_listbox.insert(0, "[全体群组]")  # 默认显示“全体群组”
        online_frame = tk.Frame(self.master)
        online_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)
        tk.Label(online_frame, text="在线用户").pack(pady=5)
        self.online_listbox = tk.Listbox(online_frame, width=18)
        self.online_listbox.pack(fill=tk.Y, expand=True)
        right_frame = tk.Frame(self.master)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.chat_canvas = tk.Canvas(right_frame, bg="#f5f5f5", highlightthickness=0, width=520)
        self.chat_canvas.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.chat_scrollbar = tk.Scrollbar(right_frame, orient="vertical", command=self.chat_canvas.yview)
        self.chat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_canvas.configure(yscrollcommand=self.chat_scrollbar.set)
        self.chat_frame = tk.Frame(self.chat_canvas, bg="#f5f5f5")
        self.chat_canvas.create_window((0, 0), window=self.chat_frame, anchor="nw", width=500)
        self.chat_frame.bind("<Configure>", lambda e: self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all")))
        self.msg_entry = tk.Entry(right_frame, width=50)
        self.msg_entry.pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(right_frame, text="发送", command=self.send_msg).pack(side=tk.LEFT, padx=5)
        # 初始化聊天数据结构：保存当前聊天对象、好友列表、私聊及群聊记录
        self.current_friend = None
        self.friends = []
        self.private_chats = {}
        self.group_chat = []

    def add_friend(self):
        """
        添加好友操作：
        功能:
            - 弹出对话框输入想要添加的好友用户名，
            - 检查输入后向服务器发送好友申请协议。
        """
        friend = simpledialog.askstring("添加好友", "请输入好友用户名：")
        if not friend:
            messagebox.showerror("错误", "请输入好友用户名！")
            return
        if friend == self.username:
            messagebox.showerror("错误", "不能添加自己为好友！")
            return
        if friend in self.friends:
            messagebox.showerror("错误", f"{friend} 已经是你的好友")
            return
        try:
            self.friend_request_result = None  # 重置好友申请反馈状态
            send_msg(self.sock, f'__FRIEND_REQUEST__:{friend.strip()}')
            threading.Timer(0.5, self.maybe_show_friend_request_success, args=(friend.strip(),)).start()
        except Exception as e:
            messagebox.showerror("发送失败", "好友申请发送失败")

    def maybe_show_friend_request_success(self, friend):
        """
        定时器回调函数：检查好友申请反馈状态，若无反馈则弹窗提示已发送成功。
        参数:
            friend: 好友用户名。
        """
        if self.friend_request_result is None:
            messagebox.showinfo("提示", "好友申请发送成功")

    def handle_friend_request(self, from_user):
        """
        处理收到的好友申请请求。
        参数:
            from_user: 请求添加自己为好友的用户名。
        功能:
            弹出询问窗口，确认是否接受，由用户选择后发送响应给服务器。
        """
        result = messagebox.askyesno("好友申请", f"{from_user} 请求添加你为好友，是否同意？")
        if result:
            send_msg(self.sock, f'__FRIEND_RESPONSE__:{from_user}:ACCEPT')
        else:
            send_msg(self.sock, f'__FRIEND_RESPONSE__:{from_user}:REJECT')

    def handle_friend_response(self, from_user, accepted):
        """
        处理好友申请响应结果。
        参数:
            from_user: 响应好友申请的用户名。
            accepted: 布尔值，表示是否同意好友请求。
        功能:
            更新好友列表，并弹出提示告知申请结果。
        """
        if accepted:
            if from_user not in self.friends:
                self.friends.append(from_user)
                self.friends_listbox.insert(tk.END, from_user)
                self.private_chats[from_user] = []
            messagebox.showinfo("好友申请", f"{from_user} 已同意你的好友申请！")
        else:
            messagebox.showinfo("好友申请", f"{from_user} 拒绝了你的好友申请")

    def clear_chat_bubbles(self):
        """
        清空聊天区中所有已显示的消息气泡。
        在切换聊天对象时调用，保证界面清晰。
        """
        for widget in self.chat_frame.winfo_children():
            widget.destroy()

    def display_message_with_time(self, msg, time_str, is_self=False):
        """
        以气泡样式显示消息及其发送时间。
        参数:
            msg: 消息内容字符串。
            time_str: 消息发送的时间字符串。
            is_self: 布尔值，指示是否为自己发的消息。
        实现:
            根据消息来源决定气泡样式（背景颜色、对齐方式）。
        """
        bubble_frame = tk.Frame(self.chat_frame, bg="#f5f5f5")
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
        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)

    def select_friend(self, event):
        """
        处理好友列表选择事件。
        功能:
            根据用户选择的好友或群组更新聊天记录显示区域。
        """
        selection = self.friends_listbox.curselection()
        if selection:
            friend = self.friends_listbox.get(selection[0])
            self.current_friend = friend
            self.clear_chat_bubbles()
            if friend == "[全体群组]":
                for (msg, time_str), is_self in self.group_chat:
                    self.display_message_with_time(msg, time_str, is_self)
            else:
                for (msg, time_str), is_self in self.private_chats.get(friend, []):
                    self.display_message_with_time(msg, time_str, is_self)

    def login(self):
        """
        处理用户登录按钮点击事件。
        功能:
            验证用户名和密码不为空，
            保存当前用户名，
            调用连接服务器和认证操作。
        """
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("错误", "用户名和密码不能为空！")
            return
        self.username = username
        logging.info(f"Login attempt for user: {self.username_entry.get().strip()}")
        self.connect_server(username, password)

    def connect_server(self, username, password):
        """
        与服务器建立TCP连接并进行用户登录验证。
        参数:
            username: 用户名。
            password: 明文密码。
        实现:
            1. 创建socket并连接到预设的服务器地址与端口；
            2. 发送登录协议字符串；
            3. 根据服务器响应构建聊天界面或提示错误。
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((SERVER_HOST, SERVER_PORT))
            logging.info(f"Connected to server {SERVER_HOST}:{SERVER_PORT}")
            send_msg(self.sock, f'__LOGIN__:{username}:{password}')
            auth_response = recv_msg(self.sock)
            if auth_response.startswith('__LOGIN_SUCCESS__'):
                logging.info("Login successful")
                self.build_chat()
                threading.Thread(target=self.receive_msg, daemon=True).start()
                return
            elif auth_response.startswith('__LOGIN_FAIL__'):
                parts = auth_response.split(':', 1)
                error_msg = parts[1] if len(parts)>1 else auth_response
                logging.error(f"Login failed: {error_msg}")
                messagebox.showerror("登录失败", error_msg)
                self.sock.close()
                self.sock = None
                self.build_login()
                return
        except Exception as e:
            logging.exception("Failed connecting to server")
            messagebox.showerror("连接失败", str(e))
            if self.sock:
                self.sock.close()
            self.sock = None
            self.build_login()

    def register(self):
        """
        打开注册窗口，允许新用户输入注册信息。
        内部:
            弹出新窗口，包含用户名和密码输入框，
            点击提交后发送注册请求到服务器，反馈注册状态。
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
            """
            内部函数：处理注册操作逻辑。
            获取输入信息并向服务器发送注册协议，显示结果反馈。
            """
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            if not username or not password:
                messagebox.showerror("错误", "用户名和密码不能为空！")
                return
            try:
                temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                temp_sock.connect((SERVER_HOST, SERVER_PORT))
                send_msg(temp_sock, f'__REGISTER__:{username}:{password}')
                response = recv_msg(temp_sock)
                if response == '__REGISTER_SUCCESS__':
                    messagebox.showinfo("成功", "注册成功！")
                    register_window.destroy()
                    temp_sock.close()
                    return
                elif response.startswith('__REGISTER_FAIL__'):
                    messagebox.showerror("失败", response.split(':', 1)[1])
                    temp_sock.close()
                    return
            except Exception as e:
                messagebox.showerror("错误", str(e))
        tk.Button(register_window, text="提交注册", font=("微软雅黑", 12, "bold"), bg="#3a7bd5", fg="#fff",
                  command=do_register).pack(pady=20)

    def send_msg(self):
        """
        发送消息操作。
        功能:
            从消息输入框读取文本，
            判断当前聊天对象是群聊或私聊，
            加密消息后发送至服务器，并清空输入框。
        """
        msg = self.msg_entry.get().strip()
        if msg:
            if self.current_friend == "[全体群组]":
                send_text = f'__GROUP__:{encrypt_message(msg)}'
                try:
                    send_msg(self.sock, send_text)
                    self.msg_entry.delete(0, tk.END)
                except:
                    messagebox.showerror("发送失败", "群聊消息发送失败")
            elif self.current_friend:
                send_text = f'__PRIVATE__:{self.current_friend}:{encrypt_message(msg)}'
                try:
                    send_msg(self.sock, send_text)
                    self.msg_entry.delete(0, tk.END)
                except:
                    messagebox.showerror("发送失败", "消息发送失败")
            else:
                messagebox.showwarning("提示", "请选择好友或群组进行聊天")

    def update_online_users(self, user_list):
        """
        更新并显示在线用户列表。
        参数:
            user_list: 来自服务器的在线用户名列表。
        实现:
            首先清空现有列表，然后逐个插入最新用户名。
        """
        self.online_listbox.delete(0, tk.END)
        for user in user_list:
            self.online_listbox.insert(tk.END, user)

    def receive_msg(self):
        """
        后台线程函数：不断监听并处理从服务器收到的消息。
        功能:
            根据消息前缀区分不同协议，
            调用相应函数更新界面或内部数据结构。
        """
        while True:
            try:
                msg = recv_msg(self.sock)
                logging.debug(f"Received message: {msg}")
                if msg is None:
                    logging.info("Server closed connection")
                    break
                if msg.startswith('__FRIEND_REQUEST_FAIL__'):
                    self.friend_request_result = False
                    error_msg = msg.split(':', 1)[1]
                    messagebox.showerror("好友申请失败", error_msg)
                    continue
                if msg.startswith('__GROUP_HISTORY__'):
                    parts = msg.split(':', 4)
                    from_user = parts[1]
                    encrypted_content = parts[2]
                    time_str = parts[4] if len(parts) > 4 and parts[3]=='__TIME__' else ''
                    content = decrypt_message(encrypted_content)
                    show = f'{from_user}(群聊): {content}'
                    is_self = (from_user == self.username)
                    self.group_chat.append(((show, time_str), is_self))
                    if self.current_friend == "[全体群组]":
                        self.display_message_with_time(show, time_str, is_self)
                    continue
                if msg.startswith('__PRIVATE_HISTORY__'):
                    parts = msg.split(':', 5)
                    from_user = parts[1]
                    to_user = parts[2]
                    encrypted_content = parts[3]
                    time_str = parts[5] if len(parts) > 5 and parts[4]=='__TIME__' else ''
                    content = decrypt_message(encrypted_content)
                    friend = to_user if from_user == self.username else from_user
                    show = f'{from_user}: {content}'
                    if friend not in self.private_chats:
                        self.private_chats[friend] = []
                        if friend not in self.friends and friend != self.username:
                            self.friends.append(friend)
                            self.friends_listbox.insert(tk.END, friend)
                    self.private_chats[friend].append(((show, time_str), from_user==self.username))
                    if self.current_friend == friend:
                        self.display_message_with_time(show, time_str, is_self=(from_user==self.username))
                    continue
                if msg.startswith('__FRIEND_REQUEST__:'):
                    from_user = msg.split(':', 1)[1]
                    self.handle_friend_request(from_user)
                    continue
                if msg.startswith('__FRIEND_RESPONSE__:'):
                    parts = msg.split(':')
                    from_user = parts[1]
                    accepted = parts[2] == 'ACCEPT'
                    self.handle_friend_response(from_user, accepted)
                    continue
                if msg.startswith('__PRIVATE__'):
                    parts = msg.split(':', 4)
                    from_user = parts[1]
                    encrypted_content = parts[2]
                    time_str = parts[4] if len(parts)>4 and parts[3]=='__TIME__' else ''
                    content = decrypt_message(encrypted_content)
                    show = f'{from_user}: {content}'
                    if from_user == self.username:
                        if self.current_friend and self.current_friend in self.friends:
                            self.private_chats[self.current_friend].append(((show, time_str), True))
                            self.display_message_with_time(show, time_str, is_self=True)
                        continue
                    if from_user not in self.friends:
                        self.friends.append(from_user)
                        self.friends_listbox.insert(tk.END, from_user)
                        self.private_chats[from_user] = []
                    self.private_chats[from_user].append(((show, time_str), False))
                    if self.current_friend == from_user:
                        self.display_message_with_time(show, time_str, is_self=False)
                    continue
                if msg.startswith('__GROUP__'):
                    parts = msg.split(':', 4)
                    from_user = parts[1]
                    encrypted_content = parts[2]
                    time_str = parts[4] if len(parts)>4 and parts[3]=='__TIME__' else ''
                    content = decrypt_message(encrypted_content)
                    show = f'{from_user}(群聊): {content}'
                    is_self = (from_user == self.username)
                    self.group_chat.append(((show, time_str), is_self))
                    if self.current_friend == "[全体群组]":
                        self.display_message_with_time(show, time_str, is_self)
                    continue
                if msg.startswith('__ONLINE_USERS__'):
                    user_str = msg.split(':', 1)[1]
                    user_list = [u for u in user_str.split(',') if u]
                    self.update_online_users(user_list)
                    continue
                # ...existing code...
            except Exception as e:
                logging.exception("Error receiving message")
                break

    def clear_window(self):
        """
        清空当前Tkinter主窗口的所有控件，以便切换界面时重建布局。
        """
        for widget in self.master.winfo_children():
            widget.destroy()

if __name__ == '__main__':
    logging.info("Starting Chat Client")
    root = tk.Tk()              # 创建主窗口对象
    app = ChatClient(root)      # 初始化聊天客户端
    root.mainloop()             # 进入消息循环，等待用户事件
