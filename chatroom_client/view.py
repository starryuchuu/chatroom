"""Tk widgets and rendering. Network and domain updates belong to the controller."""
import logging
import tkinter as tk
from tkinter import messagebox, simpledialog

from .group_view import GroupWindows
from .models import ChatKey
from .settings_view import ServerProfileSelector
from .encryption_view import EncryptionWindow, confirm_roster, import_keys


class TkClientView:
    def __init__(self, master):
        self.master = master
        self.controller = None
        self.chat_frames = {}
        self.current_chat_frame = None
        self.is_loading_messages = False
        self.request_windows = {}
        self._scroll_after_id = None
        self._scheduled = set()
        self._destroyed = False
        self._friend_keys = []
        self.profile_selector = None
        self.master.title('简易聊天客户端')

    @property
    def state(self):
        return self.controller.state

    def bind_controller(self, controller):
        self.controller = controller
        self.groups_ui = GroupWindows(self.master, controller)
        self.master.protocol('WM_DELETE_WINDOW', controller.close)
        self.master.bind('<FocusIn>', lambda event: self.schedule(0, self.controller.activity.focus_changed), add='+')

    def schedule(self, milliseconds, callback):
        if self._destroyed:
            return None
        after_id = None
        def run():
            self._scheduled.discard(after_id)
            if not self._destroyed:
                callback()
        after_id = self.master.after(milliseconds, run)
        self._scheduled.add(after_id)
        return after_id

    def destroy(self):
        self._destroyed = True
        self.cancel_scroll()
        for after_id in list(self._scheduled):
            self.master.after_cancel(after_id)
        self._scheduled.clear()
        self.master.destroy()

    def clear_window(self):
        self.cancel_scroll()
        for widget in self.master.winfo_children():
            widget.destroy()
        self.request_windows.clear()
        self.groups_ui.windows.clear()
        self.chat_frames.clear()
        self.current_chat_frame = None
        self._friend_keys.clear()
        self.profile_selector = None
        self.master.title('简易聊天客户端')

    def input_text(self):
        entry = getattr(self, 'msg_entry', None)
        return entry.get('1.0', 'end-1c') if entry is not None and entry.winfo_exists() else ''

    def show_error(self, title, text):
        messagebox.showerror(title, text)

    def clear_input_if_unchanged(self, text):
        if self.input_text() == text:
            self.msg_entry.delete('1.0', tk.END)

    def credentials(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showerror('错误', '用户名和密码不能为空！')
            return None
        port = self.read_port()
        return (username, password, port) if port is not None else None

    def read_port(self):
        try:
            port = int(self.port_entry.get().strip())
            if not 1 <= port <= 65535:
                raise ValueError
            return port
        except ValueError:
            messagebox.showerror('错误', '端口必须是 1-65535 之间的整数！')
            return None

    def add_friend(self):
        friend = (simpledialog.askstring('添加好友', '请输入好友用户名：') or '').strip()
        self.controller.add_friend(friend)

    def select_friend(self, event):
        if not self.controller.connection.running or self.is_loading_messages:
            return
        selection = self.friends_listbox.curselection()
        if selection and selection[0] < len(self._friend_keys):
            self.controller.select_chat(ChatKey('private', self._friend_keys[selection[0]]))

    def select_group(self, event):
        if not self.controller.connection.running or self.is_loading_messages:
            return
        selection = self.group_listbox.curselection()
        if selection:
            gid = self.get_gid_by_index(selection[0])
            if gid is not None:
                self.controller.select_chat(ChatKey('group', gid))

    def show_group_info_on_double_click(self, event):
        if not self.controller.connection.running:
            return
        selection = self.group_listbox.curselection()
        if selection:
            gid = self.get_gid_by_index(selection[0])
            if gid is not None:
                self.controller.request_group_info(gid, open_window=True)

    def get_gid_by_index(self, index):
        gids = list(self.state.groups)
        return gids[index] if 0 <= index < len(gids) else None

    def render_conversation(self, key, scroll_top=False):
        if self.current_chat_frame is not None:
            self.current_chat_frame.pack_forget()
        if key not in self.chat_frames:
            self.chat_frames[key] = tk.Frame(self.chat_container, bg='#f5f5f5')
            self.bind_chat_wheel(self.chat_frames[key])
        frame = self.chat_frames[key]
        frame.pack(fill=tk.BOTH, expand=True)
        self.current_chat_frame = frame
        for child in frame.winfo_children():
            child.destroy()
        self.is_loading_messages = True
        try:
            for message in self.state.conversation(key).messages:
                self.append_message(key, message)
        finally:
            self.is_loading_messages = False
        if key.kind == 'group':
            self.friends_listbox.selection_clear(0, tk.END)
        else:
            self.group_listbox.selection_clear(0, tk.END)
        self.refresh_controls()
        self.scroll_to_bottom()
        if scroll_top:
            self.chat_canvas.yview_moveto(0.0)

    def append_message(self, key, message):
        label = f'{message.author}(群聊)' if key.kind == 'group' else message.author
        if self.controller.encryption is not None:
            security = getattr(message, 'encryption', 'legacy')
            label += {'e2ee': ' [端到端加密]', 'legacy': ' [旧消息 · 非端到端加密]'}.get(security, ' [安全验证失败]')
        self.display_message_with_time(f'{label}: {message.content}', message.timestamp,
                                       message.is_self, key=key)

    def clear_selection(self):
        if self.current_chat_frame is not None:
            self.current_chat_frame.pack_forget()
        self.current_chat_frame = None
        self.refresh_controls()

    def remove_conversation(self, key):
        frame = self.chat_frames.pop(key, None)
        if frame is not None:
            if self.current_chat_frame is frame:
                self.current_chat_frame = None
            frame.destroy()

    def refresh_groups(self):
        self.group_listbox.delete(0, tk.END)
        for gid in list(self.groups_ui.windows):
            if gid not in self.state.groups:
                self.groups_ui.close(gid)
            else:
                self.groups_ui.show(gid)
        for index, (gid, info) in enumerate(self.state.groups.items()):
            key = ChatKey('group', gid)
            self.group_listbox.insert(tk.END, self.conversation_label(key, info.get('group_name', gid)))
            if self.state.current_chat == ChatKey('group', gid):
                self.group_listbox.selection_set(index)
        self.refresh_controls()

    def refresh_controls(self):
        key = self.state.current_chat
        title = None
        if key is not None:
            title = self.state.groups.get(key.target, {}).get('group_name', key.target) if key.kind == 'group' else key.target
        label = getattr(self, 'chat_title', None)
        if label is not None and label.winfo_exists():
            label.configure(text=f'当前会话：{title}' if title else '请选择好友或群组')
            encryption = self.controller.encryption
            can_send = (title and self.controller.connection.running and not self.state.pending_messages
                        and (encryption is None or (encryption.ready and not encryption.sending)))
            self.send_button.configure(state=tk.NORMAL if can_send else tk.DISABLED)
            conversation = self.state.conversation(key) if key else None
            can_load = (title and self.controller.connection.running and not conversation.exhausted
                        and self.state.pending_history is None and not self.controller.sync.active
                        and not self.controller.sync.awaiting_initial)
            self.load_history_button.configure(state=tk.NORMAL if can_load else tk.DISABLED)

    def conversation_label(self, key, title):
        conversation = self.state.conversations.get(key)
        if conversation is None:
            return title
        badge = f' [{conversation.unread_count}]' if conversation.unread_count else ''
        preview = ' '.join(conversation.preview.split())[:34]
        return f'{title}{badge}' + (f' · {preview}' if preview else '')

    def refresh_activity(self):
        if getattr(self, 'friends_listbox', None) is None or not self.friends_listbox.winfo_exists():
            return
        self.update_friends_listbox()
        # Refresh rows without opening or rebuilding unrelated group dialogs.
        self.group_listbox.delete(0, tk.END)
        for index, (gid, info) in enumerate(self.state.groups.items()):
            key = ChatKey('group', gid)
            self.group_listbox.insert(tk.END, self.conversation_label(key, info.get('group_name', gid)))
            if self.state.current_chat == key:
                self.group_listbox.selection_set(index)
        count = self.state.total_unread
        self.master.title((f'({count}) ' if count else '') + '简易聊天客户端')

    def is_chat_visible(self, key):
        try:
            focused = self.master.focus_displayof()
            return (self.state.current_chat == key and self.master.state() == 'normal'
                    and self.master.winfo_viewable() == 1 and focused is not None
                    and focused.winfo_toplevel() is self.master)
        except tk.TclError:
            return False

    def bell(self):
        if (self.controller.preferences.notifications_enabled and
                not self.controller.preferences.do_not_disturb):
            self.master.bell()

    def apply_profile(self, profile):
        port = getattr(self, 'port_entry', None)
        if port is not None and port.winfo_exists():
            port.delete(0, tk.END)
            port.insert(0, str(profile.port))
        password = getattr(self, 'password_entry', None)
        if password is not None and password.winfo_exists():
            password.delete(0, tk.END)
        if self.profile_selector is not None and self.profile_selector.winfo_exists():
            self.profile_selector.refresh()

    def set_connection_status(self, text, reconnecting=False):
        label = getattr(self, 'connection_status', None)
        if label is not None and label.winfo_exists():
            label.configure(text=text, fg='#a75b00' if reconnecting else '#1e6c39')
            self.disconnect_button.configure(text='取消重连' if reconnecting else '断开连接')
            if self.controller.sync.failed:
                self.sync_retry_button.pack(side=tk.RIGHT, padx=5)
            else:
                self.sync_retry_button.pack_forget()

    def save_notification_preferences(self):
        try:
            self.controller.preferences.set_notifications(
                enabled=self.notifications_enabled.get(), do_not_disturb=self.do_not_disturb.get())
            if not self.notifications_enabled.get() or self.do_not_disturb.get():
                self.controller.notifier.discard_pending()
        except (OSError, ValueError) as error:
            self.notifications_enabled.set(self.controller.preferences.notifications_enabled)
            self.do_not_disturb.set(self.controller.preferences.do_not_disturb)
            self.notify('提醒设置保存失败', str(error))

    def build_login(self):
        """
        构建登录界面，包含用户名和密码输入框，以及登录和注册按钮。
        """
        self.clear_window()
        self.master.geometry('1020x680')
        self.master.configure(bg="#ffffff")
        login_frame = tk.Frame(self.master, bg="#ffffff", bd=0, highlightthickness=0)
        login_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        tk.Label(login_frame, text="简易聊天室登录", font=("微软雅黑", 20, "bold"), bg="#ffffff", fg="#3a7bd5").pack(pady=(0, 25))
        self.profile_selector = ServerProfileSelector(login_frame, self.controller)
        self.profile_selector.pack(fill=tk.X, pady=(0, 16))
        tk.Label(login_frame, text="用户名:", font=("微软雅黑", 12), bg="#ffffff").pack(pady=(0, 8))
        entry_style = {"font": ("微软雅黑", 12), "relief": tk.FLAT, "highlightthickness": 2, "highlightbackground": "#aee1f9", "highlightcolor": "#3a7bd5", "bd": 0, "width": 22}
        self.username_entry = tk.Entry(login_frame, **entry_style, bg="#f5faff")
        self.username_entry.pack(pady=(0, 18), ipady=6)
        tk.Label(login_frame, text="密码:", font=("微软雅黑", 12), bg="#ffffff").pack(pady=(10, 5))
        self.password_entry = tk.Entry(login_frame, **entry_style, bg="#f5faff", show="*")
        self.password_entry.pack(ipady=6)
        self.encryption_entry = None
        if self.controller.encryption is not None:
            tk.Label(login_frame, text='本机加密密钥口令:', font=('微软雅黑', 12), bg='#ffffff').pack(pady=(10, 5))
            self.encryption_entry = tk.Entry(login_frame, **entry_style, bg='#f5faff', show='*')
            self.encryption_entry.pack(ipady=6)
            tk.Label(login_frame, text='至少 8 个字符，与登录密码不同；仅在本机使用', bg='#ffffff', fg='#555').pack(pady=3)
            self.import_keys_button = tk.Button(login_frame, text='从密钥备份恢复…', command=lambda: import_keys(self))
            self.import_keys_button.pack(pady=3)
        tk.Label(login_frame, text="端口（仅本次连接）:", font=("微软雅黑", 12), bg="#ffffff").pack(pady=(10, 5))
        self.port_entry = tk.Entry(login_frame, **entry_style, bg="#f5faff")
        self.port_entry.insert(0, str(self.controller.connection.settings.port))
        self.port_entry.pack(ipady=6)
        login_btn = tk.Button(login_frame, text="登录", font=("微软雅黑", 12, "bold"), bg="#3a7bd5", fg="#fff", activebackground="#5596e6", activeforeground="#fff", bd=0, relief=tk.FLAT, width=16, height=1, cursor="hand2", command=self.controller.login)
        self.login_button = login_btn
        login_btn.pack(pady=(20, 10))
        register_btn = tk.Button(login_frame, text="注册", font=("微软雅黑", 12), bg="#f0f0f0", fg="#3a7bd5", activebackground="#dcdcdc", bd=0, relief=tk.FLAT, width=16, height=1, cursor="hand2", command=self.register)
        self.register_button = register_btn
        register_btn.pack(pady=(0, 10))
        self.login_status = tk.Label(login_frame, text="", bg="#ffffff")
        self.login_status.pack()
        tk.Button(login_frame, text="取消连接", command=self.controller.cancel_auth).pack()
        self.username_entry.focus_set()
        self.master.bind('<Return>', lambda e: self.controller.login())

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
        endpoint = self.controller.connection.endpoint or (
            self.controller.connection.settings.host, self.controller.connection.settings.port)
        host = f'[{endpoint[0]}]' if ':' in endpoint[0] else endpoint[0]
        tk.Label(top_frame, text=f"{self.state.username} · {host}:{endpoint[1]}",
                 fg="green", wraplength=260).pack(side=tk.LEFT, padx=10, pady=5)
        self.connection_status = tk.Label(top_frame, text='已连接', fg='#1e6c39')
        self.connection_status.pack(side=tk.LEFT, padx=8)

        # 添加断开连接按钮
        self.disconnect_button = tk.Button(top_frame, text="断开连接", command=self.controller.disconnect)
        self.disconnect_button.pack(side=tk.RIGHT, padx=10, pady=5)
        self.sync_retry_button = tk.Button(top_frame, text='重试补取', command=self.controller.retry_sync)
        self.notifications_enabled = tk.BooleanVar(self.master, self.controller.preferences.notifications_enabled)
        self.do_not_disturb = tk.BooleanVar(self.master, self.controller.preferences.do_not_disturb)
        tk.Checkbutton(top_frame, text='免打扰', variable=self.do_not_disturb, command=self.save_notification_preferences).pack(side=tk.RIGHT)
        tk.Checkbutton(top_frame, text='消息提醒', variable=self.notifications_enabled, command=self.save_notification_preferences).pack(side=tk.RIGHT)

        if self.controller.encryption is not None:
            security_frame = tk.Frame(self.master)
            security_frame.pack(side=tk.TOP, fill=tk.X)
            self.encryption_status = tk.Label(security_frame, text='', anchor=tk.W, wraplength=770)
            self.encryption_status.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=4)
            tk.Button(security_frame, text='端到端加密与密钥…', command=lambda: EncryptionWindow(self)).pack(side=tk.RIGHT, padx=10)
            self.refresh_encryption()

        left_frame = tk.Frame(self.master)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        tk.Label(left_frame, text="好友列表").pack(pady=5)
        self.friends_listbox = tk.Listbox(left_frame, width=32, exportselection=False)
        self.friends_listbox.pack(fill=tk.Y, expand=True)
        self.friends_listbox.bind('<<ListboxSelect>>', self.select_friend)
        tk.Button(left_frame, text="添加好友", command=self.add_friend).pack(pady=5)
        tk.Button(left_frame, text="创建群聊", command=self.groups_ui.create).pack(pady=5)

        # 群组列表
        tk.Label(left_frame, text="群组列表").pack(pady=(10, 5))
        self.group_listbox = tk.Listbox(left_frame, width=32, exportselection=False)
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
        self.load_history_button = tk.Button(right_frame, text="加载更早的消息", command=self.controller.load_older_history, state=tk.DISABLED)
        self.load_history_button.pack(fill=tk.X)
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
        self.bind_chat_wheel(self.chat_canvas)
        self.bind_chat_wheel(self.chat_container)
        input_frame = tk.Frame(right_frame)
        input_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
        self.msg_entry = tk.Text(input_frame, height=2)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        draft = self.controller.take_draft()
        if draft:
            self.msg_entry.insert('1.0', draft)
        self.send_button = tk.Button(input_frame, text="发送", command=self.controller.send_message, state=tk.DISABLED)
        self.send_button.pack(side=tk.LEFT, padx=5)
        self.msg_entry.bind("<Return>", self.on_message_entry_key)

    def display_message_with_time(self, msg, time_str, is_self=False, key=None):
        """
        在聊天区域显示带有时间戳的消息。
        参数:
            msg: 要显示的消息
            time_str: 消息的时间戳
            is_self: 是否是自己发送的消息，影响显示位置
            key: 带类型的会话键，用于确定聊天框架
        """
        # 检查组件是否仍然存在
        try:
            if not self.master.winfo_exists():
                return
        except tk.TclError:
            return

        if key is None:
            key = self.state.current_chat
        if key is not None and key in self.chat_frames:
            chat_frame = self.chat_frames[key]
        else:
            chat_frame = self.chat_container

        # 检查聊天框架是否存在
        try:
            if not chat_frame.winfo_exists():
                return
        except tk.TclError:
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
            self.bind_chat_wheel(bubble_frame)
            for child in bubble_frame.winfo_children():
                self.bind_chat_wheel(child)

            # 强制更新UI并滚动到底部
            if not self.is_loading_messages:
                self.request_scroll()
        except tk.TclError:
            # Widget可能已被销毁，忽略错误
            logging.warning("尝试在已销毁的widget上显示消息")
            pass

    def scroll_to_bottom(self):
        """滚动到聊天区域底部"""
        self.chat_canvas.update_idletasks()
        self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))
        self.chat_canvas.yview_moveto(1.0)

    def request_scroll(self):
        if self._scroll_after_id is None:
            self._scroll_after_id = self.master.after_idle(self.finish_scroll)

    def finish_scroll(self):
        self._scroll_after_id = None
        self.scroll_to_bottom()

    def cancel_scroll(self):
        if self._scroll_after_id is not None:
            self.master.after_cancel(self._scroll_after_id)
            self._scroll_after_id = None

    def notify(self, title, text):
        """Nonmodal feedback keeps the incoming event pump running."""
        label = getattr(self, 'status_label', None)
        if label is None or not label.winfo_exists():
            label = getattr(self, 'login_status', None)
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

    def set_auth_busy(self, busy, text=""):
        for button in (self.login_button, self.register_button):
            if button.winfo_exists():
                button.configure(state=tk.DISABLED if busy else tk.NORMAL)
        if self.login_status.winfo_exists():
            self.login_status.configure(text=text)
        if self.profile_selector is not None:
            self.profile_selector.set_busy(busy)
        for entry in (self.port_entry, self.username_entry, self.password_entry):
            if entry.winfo_exists():
                entry.configure(state=tk.DISABLED if busy else tk.NORMAL)
        entry = getattr(self, 'encryption_entry', None)
        if entry is not None and entry.winfo_exists():
            entry.configure(state=tk.DISABLED if busy else tk.NORMAL)
        button = getattr(self, 'import_keys_button', None)
        if button is not None and button.winfo_exists():
            button.configure(state=tk.DISABLED if busy else tk.NORMAL)

    def encryption_passphrase(self):
        entry = getattr(self, 'encryption_entry', None)
        return entry.get() if entry is not None and entry.winfo_exists() else ''

    def confirm_encryption_roster(self, gid, identities, previous):
        return confirm_roster(self.master, gid, identities, previous)

    def refresh_encryption(self):
        encryption = self.controller.encryption
        label = getattr(self, 'encryption_status', None)
        if encryption is not None and label is not None and label.winfo_exists():
            label.configure(text=encryption.status, fg='#1e6c39' if encryption.ready else '#a04b00')
        if getattr(self, 'chat_title', None) is not None and self.chat_title.winfo_exists():
            self.refresh_controls()

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
            port = self.read_port()
            if port is None:
                return
            self.controller.connection.settings.port = port

            self.controller.start_auth(username, password, register=True, window=register_window)

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
            self.controller.send_message()
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

    def bind_chat_wheel(self, widget):
        """Keep Windows/Tk wheel and standard X11 button events local to chat."""
        widget.bind('<MouseWheel>', self.on_chat_wheel)
        # Tk 9 renumbers event.num for these bindings. Use the known binding's
        # direction rather than interpreting the backend's button number.
        for sequence, units in (('<Button-4>', -1), ('<Button-5>', 1)):
            widget.bind(sequence, lambda event, units=units: self.on_chat_wheel(event, units))

    def on_chat_wheel(self, event, units=None):
        if self.controller.connection.running and self.chat_canvas.winfo_exists():
            if units is None:
                units = int(-event.delta / 120)
            self.chat_canvas.yview_scroll(units, 'units')
            return 'break'

    def update_friends_listbox(self):
        """更新好友列表框"""
        try:
            self.friends_listbox.delete(0, tk.END)
            self._friend_keys = list(self.state.friends)
            for index, friend in enumerate(self._friend_keys):
                key = ChatKey('private', friend)
                self.friends_listbox.insert(tk.END, self.conversation_label(key, friend))
                if self.state.current_chat == key:
                    self.friends_listbox.selection_set(index)
        except tk.TclError:
            logging.warning("update_friends_listbox called on a destroyed widget.")
