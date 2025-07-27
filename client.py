import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
import socket
import threading
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import struct
import logging
import json
import time

# 配置日志记录，设置日志级别为INFO，格式为时间-级别-消息
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
        msg: 要发送的消息字符串或字典
    """
    if isinstance(msg, dict):
        data = json.dumps(msg).encode('utf-8')
    else:
        data = str(msg).encode('utf-8')  # 修复：原来是'极-8'
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
        self.running = True  # 控制接收线程
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
        login_btn.pack(pady=(20, 10))
        register_btn = tk.Button(login_frame, text="注册", font=("微软雅黑", 12), bg="#f0f0f0", fg="#3a7bd5", activebackground="#dcdcdc", bd=0, relief=tk.FLAT, width=16, height=1, cursor="hand2", command=self.register)
        register_btn.pack(pady=(0, 10))
        self.username_entry.focus_set()
        self.master.bind('<Return>', lambda e: self.login())

    def build_chat(self):
        """
        构建聊天界面，包含好友列表、在线用户列表、聊天显示区域和消息输入框。
        """
        self.clear_window()
        top_frame = tk.Frame(self.master)
        top_frame.pack(side=tk.TOP, fill=tk.X)
        tk.Label(top_frame, text=f"当前用户：{self.username}", fg="green").pack(side=tk.LEFT, padx=10, pady=5)
        
        # 添加断开连接按钮
        tk.Button(top_frame, text="断开连接", command=self.disconnect).pack(side=tk.RIGHT, padx=10, pady=5)
        
        left_frame = tk.Frame(self.master)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        tk.Label(left_frame, text="好友列表").pack(pady=5)
        self.friends_listbox = tk.Listbox(left_frame, width=18)
        self.friends_listbox.pack(fill=tk.Y, expand=True)
        self.friends_listbox.bind('<<ListboxSelect>>', self.select_friend)
        tk.Button(left_frame, text="添加好友", command=self.add_friend).pack(pady=5)
        tk.Button(left_frame, text="创建群聊", command=self.create_group).pack(pady=5)
        
        # 群组列表
        tk.Label(left_frame, text="群组列表").pack(pady=(10, 5))
        self.group_listbox = tk.Listbox(left_frame, width=18)
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
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
            
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
        
        self.build_login()

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
        
        self.friend_request_result = None
        req = {
            "type": "friend_request",
            "from": self.username,
            "to": friend.strip()
        }
        try:
            logging.info(f"Sending friend request to '{friend.strip()}'.")
            send_msg(self.sock, req)
            threading.Timer(0.5, self.maybe_show_friend_request_success, args=(friend.strip(),)).start()
        except Exception as e:
            logging.error(f"发送好友请求失败: {e}")
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
        resp = {
            "type": "friend_response",
            "from": self.username,
            "to": from_user,
            "accepted": bool(result)
        }
        try:
            logging.info(f"Sending friend response to '{from_user}'. Accepted: {result}")
            send_msg(self.sock, resp)
        except Exception as e:
            logging.error(f"发送好友响应失败: {e}")
            messagebox.showerror("发送失败", "好友响应发送失败")

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
                self.switch_chat_frame(friend)
        except tk.TclError:
            # Widget may have been destroyed during disconnect
            logging.warning("select_friend called on a destroyed widget.")
            return


    def switch_chat_frame(self, chat_id):
        """切换聊天框架"""
        if self.current_chat_frame:
            self.current_chat_frame.pack_forget()
        
        if chat_id not in self.chat_frames:
            self.chat_frames[chat_id] = tk.Frame(self.chat_container, bg="#f5f5f5")
        
        self.chat_frames[chat_id].pack(fill=tk.BOTH, expand=True)
        self.current_chat_frame = self.chat_frames[chat_id]
        
        # 清除当前框架中的消息
        self.clear_chat_bubbles(chat_id)
        
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
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("错误", "用户名和密码不能为空！")
            return
        self.username = username
        logging.info(f"Login attempt for user: {username}")
        self.connect_server(username, password)

    def connect_server(self, username, password):
        """
        连接到聊天服务器，发送登录信息。
        参数:
            username: 用户名
            password: 密码
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)  # 设置连接超时
            self.sock.connect((SERVER_HOST, SERVER_PORT))
            self.sock.settimeout(None)  # 连接后取消超时

            # 密钥交换
            # 1. 接收公钥
            public_key_data = recv_msg(self.sock)
            if not isinstance(public_key_data, dict) or public_key_data.get("type") != "public_key":
                messagebox.showerror("连接失败", "未能从服务器获取公钥")
                self.sock.close()
                self.sock = None
                return
            
            public_key = RSA.import_key(public_key_data["key"])
            cipher_rsa_encrypt = PKCS1_OAEP.new(public_key)

            # 2. 生成并发送会话密钥
            self.session_key = get_random_bytes(16) # 16 bytes for AES-128
            encrypted_session_key = cipher_rsa_encrypt.encrypt(self.session_key)
            send_msg(self.sock, {"type": "session_key", "key": base64.b64encode(encrypted_session_key).decode('utf-8')})
            logging.info("Session key sent to server.")

        except Exception as e:
            logging.error(f"Socket连接失败: {e}")
            messagebox.showerror("连接失败", f"无法连接到服务器: {e}")
            if self.sock:
                self.sock.close()
            self.sock = None
            return

        try:
            login_data = {
                "type": "login",
                "from": username,
                "password": password
            }
            send_msg(self.sock, login_data)
            logging.info(f"Connected to server {SERVER_HOST}:{SERVER_PORT}")
            
            auth_response = recv_msg(self.sock)
            if isinstance(auth_response, dict) and auth_response.get("type") == "login_result":
                if auth_response.get("success"):
                    logging.info("Login successful")
                    self.running = True
                    self.build_chat()
                    threading.Thread(target=self.receive_msg, daemon=True).start()
                    return
                else:
                    error_msg = auth_response.get("error", "登录失败")
                    logging.error(f"Login failed: {error_msg}")
                    messagebox.showerror("登录失败", error_msg)
            else:
                logging.error(f"未知登录响应: {auth_response}")
                messagebox.showerror("登录失败", f"未知响应: {auth_response}")
        except Exception as e:
            logging.exception("登录过程异常")
            messagebox.showerror("登录异常", str(e))
        
        if self.sock:
            self.sock.close()
        self.sock = None

    def send_msg(self):
        """
        发送消息，根据当前选择的好友或群组发送私聊或群聊消息。
        """
        msg = self.msg_entry.get("1.0", "end-1c").strip()
        if not msg:
            return
            
        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        
        try:
            if not self.session_key:
                messagebox.showerror("错误", "会话密钥未建立，无法发送消息")
                return

            if self.current_group:
                data = {
                    "type": "group_chat",
                    "from": self.username,
                    "gid": self.current_group,
                    "content": encrypt_message(msg, self.session_key),
                    "timestamp": ts
                }
                logging.info(f"Sending group message to GID '{self.current_group}'.")
                send_msg(self.sock, data)
            elif self.current_friend:
                data = {
                    "type": "private_chat",
                    "from": self.username,
                    "to": self.current_friend,
                    "content": encrypt_message(msg, self.session_key),
                    "timestamp": ts
                }
                logging.info(f"Sending private message to '{self.current_friend}'.")
                send_msg(self.sock, data)
            else:
                messagebox.showwarning("提示", "请选择好友或群组进行聊天")
                return
        except Exception as e:
            logging.error(f"发送消息失败: {e}")
            messagebox.showerror("发送失败", "消息发送失败")
        
        self.msg_entry.delete("1.0", tk.END)

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
            
            temp_sock = None
            try:
                # 1. 连接服务器并完成密钥交换
                temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                temp_sock.settimeout(10)
                temp_sock.connect((SERVER_HOST, SERVER_PORT))
                temp_sock.settimeout(None)

                public_key_data = recv_msg(temp_sock)
                if not isinstance(public_key_data, dict) or public_key_data.get("type") != "public_key":
                    messagebox.showerror("注册失败", "未能从服务器获取公钥")
                    temp_sock.close()
                    return
                
                public_key = RSA.import_key(public_key_data["key"])
                cipher_rsa_encrypt = PKCS1_OAEP.new(public_key)
                
                session_key = get_random_bytes(16)
                encrypted_session_key = cipher_rsa_encrypt.encrypt(session_key)
                send_msg(temp_sock, {"type": "session_key", "key": base64.b64encode(encrypted_session_key).decode('utf-8')})
                
                # 2. 加密并发送注册信息
                reg_data = {
                    "type": "register",
                    "from": username,
                    "password": password
                }
                encrypted_reg_data = encrypt_message(json.dumps(reg_data), session_key)
                send_msg(temp_sock, {"type": "encrypted_register", "data": encrypted_reg_data})
                
                logging.info(f"Attempting to register new user '{username}'.")
                
                # 3. 接收注册结果
                response = recv_msg(temp_sock)
                logging.info(f"Registration response for '{username}': {response}")
                
                if isinstance(response, dict) and response.get("type") == "register_result":
                    if response.get("success"):
                        messagebox.showinfo("注册成功", "注册成功，请登录！")
                        register_window.destroy()
                    else:
                        error_msg = response.get("error", "注册失败")
                        messagebox.showerror("注册失败", error_msg)
                else:
                    messagebox.showerror("注册失败", str(response))

            except Exception as e:
                logging.error(f"注册异常: {e}")
                messagebox.showerror("错误", f"注册失败: {e}")
            finally:
                if temp_sock:
                    temp_sock.close()
        
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

    def receive_msg(self):
        """
        接收服务器消息的线程函数，处理各种类型的消息，包括群聊、私聊、好友请求等。
        """
        while self.running:
            try:
                msg = recv_msg(self.sock)
                if not msg:
                    logging.info("服务器断开连接")
                    self.master.after(0, lambda: messagebox.showerror("连接断开", "与服务器的连接已断开"))
                    self.master.after(0, self.disconnect)
                    break
                
                if isinstance(msg, dict):
                    mtype = msg.get("type")
                    if mtype == "online_users":
                        user_list = msg.get("users", [])
                        logging.info(f"Received online users list: {user_list}")
                        self.master.after(0, lambda: self.update_online_users(user_list))
                    
                    elif mtype == "user_groups_list":
                        group_list = msg.get("groups", [])
                        logging.info(f"Received initial group list: {group_list}")
                        self.groups = {g["gid"]: g for g in group_list}
                        self.master.after(0, self.refresh_group_listbox)
                    
                    elif mtype == "friends_list":
                        friends_list = msg.get("friends", [])
                        logging.info(f"Received friends list: {friends_list}")
                        self.friends = friends_list
                        # 更新好友列表框
                        self.master.after(0, self.update_friends_listbox)
                    
                    elif mtype == "private_chat":
                        logging.info(f"Received private chat message: {msg}")
                        from_user = msg.get("from")
                        to_user = msg.get("to")
                        encrypted_content = msg.get("content")
                        time_str = msg.get("timestamp", "")
                        if not self.session_key:
                            continue
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
                            self.master.after(0, lambda p=chat_partner: self.friends_listbox.insert(tk.END, p))
                            self.private_chats[chat_partner] = []

                        # 将消息存储在聊天对象的名下
                        if chat_partner not in self.private_chats:
                            self.private_chats[chat_partner] = []
                        self.private_chats[chat_partner].append(((show, time_str), is_self))

                        # 如果当前聊天窗口是该对象，则显示消息
                        if self.current_friend == chat_partner:
                            # 使用lambda的默认参数来捕获当前值
                            self.master.after(0, lambda s=show, t=time_str, i=is_self, p=chat_partner: self.display_message_with_time(s, t, i, friend=p))
                        # 如果没有当前聊天对象但消息来自好友，则预加载消息到该好友的消息列表中
                        elif chat_partner in self.friends and chat_partner not in self.private_chats:
                            self.private_chats[chat_partner] = [((show, time_str), is_self)]
                    
                    elif mtype == "group_chat":
                        logging.info(f"Received group chat message: {msg}")
                        gid = msg.get("gid")
                        from_user = msg.get("from")
                        encrypted_content = msg.get("content")
                        time_str = msg.get("timestamp", "")
                        if not self.session_key:
                            continue
                        try:
                            content = decrypt_message(encrypted_content, self.session_key)
                        except Exception as e:
                            logging.error(f"解密来自 {from_user} 的群聊消息失败 (群组: {gid}): {e}")
                            content = "[消息解密失败]"
                        
                        show = f'{from_user}(群聊): {content}'
                        is_self = (from_user == self.username)
                        
                        # 如果客户端不知道这个群组，请求信息
                        if gid not in self.groups:
                            self.master.after(0, lambda g=gid: self.request_group_info(g))

                        # 确保该群组的消息列表存在
                        if not hasattr(self, f'group_messages_{gid}'):
                            setattr(self, f'group_messages_{gid}', [])
                        
                        # 存储消息
                        getattr(self, f'group_messages_{gid}').append(((show, time_str), is_self))
                        
                        # 如果当前聊天窗口是该群组，则显示消息
                        if self.current_group == gid:
                            self.master.after(0, lambda s=show, t=time_str, i=is_self, g=gid: self.display_message_with_time(s, t, i, friend=g))

                    elif mtype == "group_create_result":
                        logging.info(f"Received group create result: {msg}")
                        if msg.get("success"):
                            gid = msg.get("gid")
                            group_name = msg.get("group_name", "新群聊")
                            owner = msg.get("owner") # 从消息中获取群主
                            members = msg.get("members", [])
                            self.groups[gid] = {"group_name": group_name, "owner": owner, "members": members}
                            self.master.after(0, self.refresh_group_listbox) # 刷新整个列表以保持一致性
                            if owner == self.username: # 只有创建者会看到这个弹窗
                                self.master.after(0, lambda gn=group_name, g=gid: messagebox.showinfo("群聊创建", f"群聊 '{gn}' 创建成功！ID: {g}"))
                        else:
                            error_msg = msg.get("error", "创建群聊失败")
                            self.master.after(0, lambda: messagebox.showerror("群聊创建失败", error_msg))
                    
                    elif mtype == "group_info":
                        logging.info(f"Received group info: {msg}")
                        gid = msg.get("gid")
                        if gid and "error" not in msg:
                            self.groups[gid] = msg
                            self.master.after(0, lambda: self.show_group_info_after_update(gid))
                        else:
                            self.master.after(0, lambda: messagebox.showerror("群组信息", msg.get("error", "获取群组信息失败")))

                    elif mtype == "group_invite":
                        logging.info(f"Received group invite: {msg}")
                        from_user = msg.get("from")
                        gid = msg.get("gid")
                        self.master.after(0, lambda: self.handle_group_invite(from_user, gid))
                    
                    elif mtype == "group_join_result":
                        logging.info(f"Received group join result: {msg}")
                        if msg.get("success"):
                            gid = msg.get("gid")
                            group_name = msg.get("group_name", "未知群聊")
                            owner = msg.get("owner")
                            members = msg.get("members", [])
                            self.groups[gid] = {"group_name": group_name, "owner": owner, "members": members}
                            self.master.after(0, self.refresh_group_listbox)
                            self.master.after(0, lambda gn=group_name: messagebox.showinfo("加入群聊", f"成功加入群聊: {gn}"))
                        else:
                            error_msg = msg.get("error", "加入群聊失败")
                            self.master.after(0, lambda: messagebox.showerror("加入群聊失败", error_msg))
                    
                    elif mtype == "group_update":
                        logging.info(f"Received group update: {msg}")
                        gid = msg.get("gid")
                        group_name = msg.get("group_name")
                        owner = msg.get("owner")
                        members = msg.get("members")
                        self.groups[gid] = {"group_name": group_name, "owner": owner, "members": members}
                        self.master.after(0, self.refresh_group_listbox)
                    
                    elif mtype == "group_leave_result":
                        logging.info(f"Received group leave result: {msg}")
                        if msg.get("success"):
                            gid = msg.get("gid")
                            if gid in self.groups:
                                del self.groups[gid]
                            if hasattr(self, f'group_messages_{gid}'):
                                delattr(self, f'group_messages_{gid}')
                            self.master.after(0, lambda: self.refresh_group_listbox())
                            self.master.after(0, lambda: messagebox.showinfo("退出群聊", f"成功退出群聊: {gid}"))
                            if self.current_group == gid:
                                self.master.after(0, lambda: self.select_friend(None)) # 切换到全体群组
                        else:
                            error_msg = msg.get("error", "退出群聊失败")
                            self.master.after(0, lambda: messagebox.showerror("退出群聊失败", error_msg))
                    
                    elif mtype == "group_kick_result":
                        logging.info(f"Received group kick result: {msg}")
                        if msg.get("success"):
                            gid = msg.get("gid")
                            kicked_user = msg.get("kick")
                            if gid in self.groups and kicked_user in self.groups[gid]["members"]:
                                self.groups[gid]["members"].remove(kicked_user)
                            self.master.after(0, lambda: messagebox.showinfo("踢出成员", f"已将 {kicked_user} 从群聊 {gid} 踢出"))
                            if kicked_user == self.username: # 自己被踢出
                                if gid in self.groups:
                                    del self.groups[gid]
                                if hasattr(self, f'group_messages_{gid}'):
                                    delattr(self, f'group_messages_{gid}')
                            self.master.after(0, lambda: self.refresh_group_listbox())
                            self.master.after(0, lambda: self.select_friend(None)) # 切换到全体群组
                        else:
                            error_msg = msg.get("error", "踢出成员失败")
                            self.master.after(0, lambda: messagebox.showerror("踢出成员失败", error_msg))
                    
                    elif mtype == "group_kick_notification":
                        logging.info(f"Received group kick notification: {msg}")
                        gid = msg.get("gid")
                        group_name = msg.get("group_name")
                        self.master.after(0, lambda: messagebox.showinfo("群聊通知", f"您已被从群聊 {group_name} 移除"))
                        if gid in self.groups:
                            del self.groups[gid]
                        if hasattr(self, f'group_messages_{gid}'):
                            delattr(self, f'group_messages_{gid}')
                        self.master.after(0, lambda: self.refresh_group_listbox())
                        self.master.after(0, lambda: self.select_friend(None)) # 切换到全体群组
                    
                    elif mtype == "friend_request":
                        logging.info(f"Received friend request: {msg}")
                        from_user = msg.get("from")
                        self.master.after(0, lambda: self.handle_friend_request(from_user))
                    
                    elif mtype == "friend_response":
                        logging.info(f"Received friend response: {msg}")
                        from_user = msg.get("from")
                        accepted = msg.get("accepted")
                        self.master.after(0, lambda: self.handle_friend_response(from_user, accepted))
                    
                    elif mtype == "friend_update":
                        logging.info(f"Received friend update: {msg}")
                        new_friend = msg.get("friend")
                        if new_friend and new_friend not in self.friends:
                            self.friends.append(new_friend)
                            self.private_chats[new_friend] = []
                            self.master.after(0, lambda f=new_friend: self.friends_listbox.insert(tk.END, f))
                    
                    elif mtype == "friend_request_result":
                        logging.info(f"Received friend request result: {msg}")
                        self.friend_request_result = msg.get("success")
                        if not msg.get("success"):
                            error_msg = msg.get("error", "好友申请失败")
                            self.master.after(0, lambda: messagebox.showerror("好友申请失败", error_msg))
                    
                    elif mtype == "group_invite_result":
                        logging.info(f"Received group invite result: {msg}")
                        if not msg.get("success"):
                            error_msg = msg.get("error", "群邀请失败")
                            self.master.after(0, lambda: messagebox.showerror("群邀请失败", error_msg))
                    
                    elif mtype == "group_disband_result":
                        logging.info(f"Received group disband result: {msg}")
                        if msg.get("success"):
                            gid = msg.get("gid")
                            if gid in self.groups:
                                del self.groups[gid]
                            if hasattr(self, f'group_messages_{gid}'):
                                delattr(self, f'group_messages_{gid}')
                            self.master.after(0, lambda: self.refresh_group_listbox())
                            self.master.after(0, lambda: messagebox.showinfo("解散群聊", f"群聊已成功解散"))
                            if self.current_group == gid:
                                self.master.after(0, lambda: self.select_friend(None)) # 切换到全体群组
                        else:
                            error_msg = msg.get("error", "解散群聊失败")
                            self.master.after(0, lambda: messagebox.showerror("解散群聊失败", error_msg))
                    
                    elif mtype == "group_disband_notification":
                        logging.info(f"Received group disband notification: {msg}")
                        gid = msg.get("gid")
                        group_name = msg.get("group_name")
                        self.master.after(0, lambda: messagebox.showinfo("群聊通知", f"群聊 {group_name} 已被解散"))
                        if gid in self.groups:
                            del self.groups[gid]
                        if hasattr(self, f'group_messages_{gid}'):
                            delattr(self, f'group_messages_{gid}')
                        self.master.after(0, lambda: self.refresh_group_listbox())
                        self.master.after(0, lambda: self.select_friend(None)) # 切换到全体群组
                    
                    elif mtype == "group_transfer_result":
                        logging.info(f"Received group transfer result: {msg}")
                        if msg.get("success"):
                            gid = msg.get("gid")
                            new_owner = msg.get("new_owner")
                            if gid in self.groups:
                                self.groups[gid]["owner"] = new_owner
                            self.master.after(0, lambda: self.refresh_group_listbox())
                            self.master.after(0, lambda: messagebox.showinfo("转让群主", f"群主已成功转让给 {new_owner}"))
                        else:
                            error_msg = msg.get("error", "转让群主失败")
                            self.master.after(0, lambda: messagebox.showerror("转让群主失败", error_msg))
                    
                    elif mtype == "group_transfer_notification":
                        logging.info(f"Received group transfer notification: {msg}")
                        gid = msg.get("gid")
                        old_owner = msg.get("old_owner")
                        new_owner = msg.get("new_owner")
                        group_name = msg.get("group_name")
                        if gid in self.groups:
                            self.groups[gid]["owner"] = new_owner
                        self.master.after(0, lambda: self.refresh_group_listbox())
                        self.master.after(0, lambda: messagebox.showinfo("群聊通知", f"群聊 {group_name} 的群主已由 {old_owner} 转让给 {new_owner}"))
                    
                    elif mtype == "group_rename_result":
                        logging.info(f"Received group rename result: {msg}")
                        if msg.get("success"):
                            gid = msg.get("gid")
                            new_name = msg.get("new_name")
                            if gid in self.groups:
                                old_name = self.groups[gid].get("group_name", gid)
                                self.groups[gid]["group_name"] = new_name
                            self.master.after(0, lambda: self.refresh_group_listbox())
                            self.master.after(0, lambda: messagebox.showinfo("修改群聊名称", f"群聊名称已从 '{old_name}' 修改为 '{new_name}'"))
                        else:
                            error_msg = msg.get("error", "修改群聊名称失败")
                            self.master.after(0, lambda: messagebox.showerror("修改群聊名称失败", error_msg))
                    
                    elif mtype == "group_rename_notification":
                        logging.info(f"Received group rename notification: {msg}")
                        gid = msg.get("gid")
                        old_name = msg.get("old_name")
                        new_name = msg.get("new_name")
                        if gid in self.groups:
                            self.groups[gid]["group_name"] = new_name
                        self.master.after(0, lambda: self.refresh_group_listbox())
                        self.master.after(0, lambda: messagebox.showinfo("群聊通知", f"群聊名称已由群主 {msg.get('owner')} 从 '{old_name}' 修改为 '{new_name}'"))
                    
                else:
                    logging.warning(f"收到未知格式消息: {msg}")

            except (ConnectionResetError, ConnectionAbortedError):
                logging.warning("与服务器的连接已断开。")
                if self.running:
                    self.master.after(0, lambda: messagebox.showwarning("连接断开", "与服务器的连接已断开，请重新登录。"))
                    self.master.after(0, self.disconnect)
                break
            except Exception as e:
                logging.exception(f"接收消息时发生未知异常: {e}")
                if self.running:
                    self.master.after(0, self.disconnect)
                break

    def clear_window(self):
        """
        清除窗口中的所有控件，用于切换界面。
        """
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
            send_msg(self.sock, req)
            group_window.destroy()
        
        tk.Button(group_window, text="创建", command=do_create).pack(pady=20)

    def request_group_info(self, gid):
        """请求群组信息"""
        logging.info(f"Requesting info for group '{gid}'.")
        req = {"type": "group_info", "from": self.username, "gid": gid}
        send_msg(self.sock, req)

    def select_group(self, event):
        if not self.running or self.is_loading_messages:
            return
        try:
            sel = self.group_listbox.curselection()
            if sel:
                group_name = self.group_listbox.get(sel[0])
                # 通过群组名称反向查找gid
                gid = self.get_gid_by_name(group_name)
                if gid:
                    self.current_group = gid
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
                group_name = self.group_listbox.get(sel[0])
                gid = self.get_gid_by_name(group_name)
                if gid:
                    self.show_group_info(gid)
        except tk.TclError:
            logging.warning("show_group_info_on_double_click called on a destroyed widget.")
            return

    def show_group_info(self, gid):
        # 强制从服务器更新最新的群组信息
        self.request_group_info(gid)

    def show_group_info_after_update(self, gid):
        info = self.groups.get(gid)
        if not info:
            messagebox.showerror("错误", "无法获取群组信息")
            return

        members = info.get("members", [])
        
        # 检查是否已有同名窗口，避免重复打开
        for win in self.master.winfo_children():
            if isinstance(win, tk.Toplevel) and win.title() == f"群聊信息 - {info.get('group_name')}":
                win.destroy()

        group_info_window = tk.Toplevel(self.master)
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
            group_info_window.after(300, lambda: self.update_group_info_window(group_info_window, gid))
        
        def invite_member():
            friend = simpledialog.askstring("邀请成员", "输入好友用户名:")
            if friend:
                req = {"type": "group_invite", "from": self.username, "to": friend, "gid": gid}
                send_msg(self.sock, req)
        
        def leave_group():
            req = {"type": "group_leave", "from": self.username, "gid": gid}
            send_msg(self.sock, req)
            group_info_window.destroy()

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
                        send_msg(self.sock, req)
            
            def disband_group():
                if messagebox.askyesno("解散群聊", "确定要解散群聊吗？此操作不可撤销。"):
                    req = {"type": "group_disband", "from": self.username, "gid": gid}
                    send_msg(self.sock, req)
                    group_info_window.destroy()
            
            def transfer_ownership():
                new_owner = simpledialog.askstring("转让群主", "请输入新群主用户名:")
                if new_owner:
                    req = {"type": "group_transfer", "from": self.username, "gid": gid, "new_owner": new_owner}
                    send_msg(self.sock, req)
            
            def rename_group():
                new_name = simpledialog.askstring("修改群聊名称", "请输入新的群聊名称:")
                if new_name:
                    req = {"type": "group_rename", "from": self.username, "gid": gid, "new_name": new_name}
                    send_msg(self.sock, req)

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
        result = messagebox.askyesno("群聊邀请", f"{from_user} 邀请你加入群聊，是否同意？")
        if result:
            req = {"type": "group_join", "from": self.username, "gid": gid}
            send_msg(self.sock, req)

    def refresh_group_listbox(self):
        """刷新群组列表"""
        try:
            self.group_listbox.delete(0, tk.END)
            for gid, info in self.groups.items():
                self.group_listbox.insert(tk.END, info.get("group_name", gid))
        except tk.TclError:
            logging.warning("refresh_group_listbox called on a destroyed widget.")

    def get_gid_by_name(self, group_name):
        """通过群组名称查找GID"""
        for gid, info in self.groups.items():
            if info and info.get("group_name") == group_name:
                return gid
        return None

    def update_group_info_window(self, window, gid):
        """更新群组信息窗口的内容"""
        info = self.groups.get(gid)
        if not info or not window.winfo_exists():
            return

        # 更新标题和成员列表
        window.title(f"群聊信息 - {info.get('group_name')}")
        
        listbox = None
        for widget in window.winfo_children():
            if isinstance(widget, tk.Listbox):
                listbox = widget
                break
        
        if listbox:
            listbox.delete(0, tk.END)
            for member in info.get("members", []):
                listbox.insert(tk.END, member)
                
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
