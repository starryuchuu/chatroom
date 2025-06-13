import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import struct
import logging

# 配置日志记录，设置日志级别为INFO，格式为时间-级别-消息
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 加密密钥，用于AES加密
KEY = b'\xe5\xc6\xba\xd9?x\\f(\x9f\x02B6\x9e\xdd\xd9'
# AES加密块大小
BLOCK_SIZE = 16
# 服务器地址
SERVER_HOST = '127.0.0.1'
# 服务器端口
SERVER_PORT = 12345

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
        self.username = None
        self.friend_request_result = None
        self.chat_frames = {}  # 用于存储每个好友或群组的聊天框架
        self.current_chat_frame = None  # 当前显示的聊天框架
        self.is_loading_messages = False  # 标记是否正在加载消息
        self.build_login()

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
        login_btn = tk.Button(login_frame, text="登录", font=("微软雅黑", 12, "bold"), bg="#3a7bd5", fg="#fff", activebackground="#5596e6", activeforeground="#fff", bd=0, relief=tk.FLAT, width=16, height=1, cursor="hand2", command=self.login)
        login_btn.pack(pady=(0, 10))
        register_btn = tk.Button(login_frame, text="注册", font=("微软雅黑", 12), bg="#f0f0f0", fg="#3a7bd5", activebackground="#dcdcdc", bd=0, relief=tk.FLAT, width=16, height=1, cursor="hand2", command=self.register)
        register_btn.pack(pady=(0, 10))
        self.username_entry.focus_set()
        self.master.bind('<Return>', lambda e: self.login())

    def display_message(self, msg, is_self=False):
        """
        在聊天区域显示消息。
        参数:
            msg: 要显示的消息
            is_self: 是否是自己发送的消息，影响显示位置
        """
        self.chat_area.config(state='normal')
        if is_self:
            self.chat_area.insert(tk.END, f'{msg}\n', 'right')
        else:
            self.chat_area.insert(tk.END, f'{msg}\n', 'left')
        self.chat_area.config(state='disabled')
        self.chat_area.see(tk.END)

    def build_chat(self):
        """
        构建聊天界面，包含好友列表、在线用户列表、聊天显示区域和消息输入框。
        """
        self.clear_window()
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
        self.friends_listbox.insert(0, "[全体群组]")
        online_frame = tk.Frame(self.master)
        online_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)
        tk.Label(online_frame, text="在线用户").pack(pady=5)
        self.online_listbox = tk.Listbox(online_frame, width=18)
        self.online_listbox.pack(fill=tk.Y, expand=True)
        right_frame = tk.Frame(self.master)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
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
        self.chat_canvas.bind_all("<MouseWheel>", lambda event: self.chat_canvas.yview_scroll(int(-1*(event.delta/120)), "units"))
        input_frame = tk.Frame(right_frame)
        input_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
        self.msg_entry = tk.Text(input_frame, height=2)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(input_frame, text="发送", command=self.send_msg).pack(side=tk.LEFT, padx=5)
        self.msg_entry.bind("<Return>", self.on_message_entry_key)
        self.current_friend = None
        self.friends = []
        self.private_chats = {}
        self.group_chat = []

    def add_friend(self):
        """
        添加好友功能，弹出输入框让用户输入好友用户名，并发送好友请求。
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
            self.friend_request_result = None
            send_msg(self.sock, f'__FRIEND_REQUEST__:{friend.strip()}')
            threading.Timer(0.5, self.maybe_show_friend_request_success, args=(friend.strip(),)).start()
        except Exception as e:
            messagebox.showerror("发送失败", "好友申请发送失败")

    def maybe_show_friend_request_success(self, friend):
        """
        在发送好友请求后，延迟显示请求发送成功的提示。
        参数:
            friend: 好友用户名
        """
        if self.friend_request_result is None:
            messagebox.showinfo("提示", "好友申请发送成功")

    def handle_friend_request(self, from_user):
        """
        处理收到的好友请求，弹出对话框询问是否同意。
        参数:
            from_user: 请求添加好友的用户名
        """
        result = messagebox.askyesno("好友申请", f"{from_user} 请求添加你为好友，是否同意？")
        if result:
            send_msg(self.sock, f'__FRIEND_RESPONSE__:{from_user}:ACCEPT')
        else:
            send_msg(self.sock, f'__FRIEND_RESPONSE__:{from_user}:REJECT')

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
            messagebox.showinfo("好友申请", f"{from_user} 已同意你的好友申请！")
        else:
            messagebox.showinfo("好友申请", f"{from_user} 拒绝了你的好友申请")

    def clear_chat_bubbles(self, friend=None):
        """
        清除聊天区域中的所有消息气泡。
        参数:
            friend: 好友或群组名称，用于确定使用哪个聊天框架
        """
        if friend is None:
            friend = self.current_friend
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
        if friend is None:
            friend = self.current_friend
        if friend and friend in self.chat_frames:
            chat_frame = self.chat_frames[friend]
        else:
            chat_frame = self.chat_container
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
        # 强制更新UI并滚动到底部
        if not self.is_loading_messages:
            self.chat_canvas.update_idletasks()
            self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))
            self.chat_canvas.yview_moveto(1.0)

    def select_friend(self, event):
        """
        选择好友或群组，显示对应的聊天记录。
        参数:
            event: 列表框选择事件
        """
        if self.is_loading_messages:
            return
        selection = self.friends_listbox.curselection()
        if selection:
            friend = self.friends_listbox.get(selection[0])
            self.current_friend = friend
            if self.current_chat_frame:
                self.current_chat_frame.pack_forget()
            if friend not in self.chat_frames:
                self.chat_frames[friend] = tk.Frame(self.chat_container, bg="#f5f5f5")
                self.chat_frames[friend].pack(fill=tk.BOTH, expand=True)
            else:
                self.chat_frames[friend].pack(fill=tk.BOTH, expand=True)
                # 清除当前框架中的消息
                self.clear_chat_bubbles(friend)
            self.current_chat_frame = self.chat_frames[friend]
            self.is_loading_messages = True
            # 重新显示历史消息
            if friend == "[全体群组]":
                for (msg, time_str), is_self in self.group_chat:
                    self.display_message_with_time(msg, time_str, is_self, friend=friend)
            else:
                for (msg, time_str), is_self in self.private_chats.get(friend, []):
                    self.display_message_with_time(msg, time_str, is_self, friend=friend)
            self.is_loading_messages = False
            # 强制更新滚动区域并滚动到底部
            self.chat_canvas.update_idletasks()
            self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))
            self.chat_canvas.yview_moveto(1.0)


    def login(self):
        """
        处理登录逻辑，验证用户名和密码，并连接到服务器。
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
        连接到聊天服务器，发送登录信息。
        参数:
            username: 用户名
            password: 密码
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
        tk.Button(register_window, text="提交注册", font=("微软雅黑", 12, "bold"), bg="#3a7bd5", fg="#fff", command=do_register).pack(pady=20)

    def send_msg(self):
        """
        发送消息，根据当前选择的好友或群组发送私聊或群聊消息。
        """
        msg = self.msg_entry.get("1.0", "end-1c").strip()
        if msg:
            if self.current_friend == "[全体群组]":
                send_text = f'__GROUP__:{encrypt_message(msg)}'
                try:
                    send_msg(self.sock, send_text)
                except:
                    messagebox.showerror("发送失败", "群聊消息发送失败")
            elif self.current_friend:
                send_text = f'__PRIVATE__:{self.current_friend}:{encrypt_message(msg)}'
                try:
                    send_msg(self.sock, send_text)
                except:
                    messagebox.showerror("发送失败", "消息发送失败")
            else:
                messagebox.showwarning("提示", "请选择好友或群组进行聊天")
        self.msg_entry.delete("1.0", tk.END)

    def on_message_entry_key(self, event):
        """
        处理消息输入框的按键事件，Enter键发送消息，Ctrl+Enter换行。
        参数:
            event: 按键事件
        """
        if event.state & 0x4:
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

    def receive_msg(self):
        """
        接收服务器消息的线程函数，处理各种类型的消息，包括群聊、私聊、好友请求等。
        """
        while True:
            try:
                msg = recv_msg(self.sock)
                logging.debug(f"Received message: {msg}")
                if msg is None:
                    logging.info("Server closed connection")
                    break
                if msg.startswith('__ADD_AI_FRIEND__'):
                    _, ai_friend = msg.split(':', 1)
                    if ai_friend not in self.friends:
                        self.friends.append(ai_friend)
                        self.friends_listbox.insert(tk.END, ai_friend)
                        self.private_chats[ai_friend] = []
                    continue
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
            except Exception as e:
                logging.exception("Error receiving message")
                break

    def clear_window(self):
        """
        清除窗口中的所有控件，用于切换界面。
        """
        for widget in self.master.winfo_children():
            widget.destroy()

# 主程序入口，启动聊天客户端
if __name__ == '__main__':
    logging.info("Starting Chat Client")
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()
