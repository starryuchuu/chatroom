"""Tk widgets and rendering. Network and domain updates belong to the controller."""
import logging
import tkinter as tk
from tkinter import font as tkfont, messagebox, simpledialog

from .group_view import GroupWindows
from .models import ChatKey
from .login_view import LoginCard
from .encryption_view import EncryptionWindow, confirm_roster
from .theme import AutoScrollbar, DesktopTheme
from .message_list import MessageList, message_identity as _message_identity


class TkClientView:
    def __init__(self, master):
        self.master = master
        self.controller = None
        self.chat_frames = {}
        self.message_list = MessageList(self)
        self.current_chat_frame = None
        self.is_loading_messages = False
        self.request_windows = {}
        self._scroll_after_id = None
        self._scroll_anchor = None
        self._restoring_scroll = False
        self._new_messages = {}
        self._scheduled = set()
        self._destroyed = False
        self._chat_layout_ready = False
        self._friend_keys = []
        self._group_keys = []
        self._list_widths = {}
        self._row_fonts = {}
        self.profile_selector = None
        self.theme = DesktopTheme(master)
        self.colors, self.fonts = self.theme.colors, self.theme.fonts
        self.master.title('chatroom')
        self.master.geometry('1120x760')
        self.master.minsize(900, 700)

    @property
    def state(self):
        return self.controller.state

    def bind_controller(self, controller):
        self.controller = controller
        self.theme.set_mode(controller.preferences.theme)
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
        # Native Configure events can arrive while Tk is destroying children,
        # before the old canvas itself has disappeared.
        self._chat_layout_ready = False
        self.cancel_scroll()
        for widget in self.master.winfo_children():
            widget.destroy()
        self.request_windows.clear()
        self.groups_ui.windows.clear()
        self.chat_frames.clear()
        self.message_list.reset()
        self.current_chat_frame = None
        self._friend_keys.clear()
        self._group_keys.clear()
        self._new_messages.clear()
        self._restoring_scroll = False
        self._list_widths.clear()
        self.profile_selector = None
        self.master.title('chatroom')

    def label(self, parent, text='', *, muted=False, font='body', **kwargs):
        options = dict(bg=parent.cget('bg'), fg=self.colors['muted' if muted else 'text'],
                       font=self.fonts[font], anchor=tk.W, justify=tk.LEFT)
        options.update(kwargs)
        return tk.Label(parent, text=text, **options)

    def brand(self, parent, *, large=False):
        frame = tk.Frame(parent, bg=parent.cget('bg'))
        mark = tk.Canvas(frame, width=32, height=32, bg=frame.cget('bg'),
                         highlightthickness=0, takefocus=False)
        mark.pack(side=tk.LEFT, padx=(0, 10))
        mark.create_polygon(5, 5, 27, 5, 27, 23, 14, 23, 8, 28, 8, 23, 5, 23,
                            fill=self.colors['accent'], smooth=False)
        for x in (11, 16, 21):
            mark.create_oval(x-1, 13, x+1, 15, fill=self.colors['surface'], outline='')
        self.label(frame, 'chatroom', font='title' if large else 'heading').pack(side=tk.LEFT)
        return frame

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
            self.notify('输入有误', '用户名和密码不能为空！')
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
            self.notify('输入有误', '端口必须是 1-65535 之间的整数！')
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
        return self._group_keys[index] if 0 <= index < len(self._group_keys) else None

    def render_conversation(self, key, scroll_top=False, *, preserve_scroll=True):
        frame = self.chat_frames.get(key)
        viewport = (self.capture_chat_scroll() if preserve_scroll and frame is not None
                    and frame is self.current_chat_frame else None)
        self.cancel_scroll()
        if self.current_chat_frame is not None:
            self.current_chat_frame.pack_forget()
        if key not in self.chat_frames:
            self.chat_frames[key] = tk.Frame(self.chat_container, bg=self.colors['bg'])
            self.bind_chat_wheel(self.chat_frames[key])
        frame = self.chat_frames[key]
        frame.pack(fill=tk.BOTH, expand=True)
        self.current_chat_frame = frame
        self._restoring_scroll = True
        self.is_loading_messages = True
        try:
            additions = self.message_list.reconcile(
                key, frame, self.state.conversation(key).messages, viewport, scroll_top)
        finally:
            self.is_loading_messages = False
        if key.kind == 'group':
            self.friends_listbox.selection_clear(0, tk.END)
        else:
            self.group_listbox.selection_clear(0, tk.END)
        self.refresh_controls()
        try:
            if scroll_top:
                self.update_chat_region()
                self.chat_canvas.yview_moveto(0.0)
            elif viewport is not None and not viewport['at_bottom']:
                self._new_messages[key] = self._new_messages.get(key, 0) + sum(
                    not message.is_self for message in additions)
                self.restore_chat_scroll(viewport)
            else:
                self.scroll_to_bottom()
        finally:
            self._restoring_scroll = False
        self.update_new_messages_button()

    def append_message(self, key, message):
        active = key == self.state.current_chat and not self.is_loading_messages
        if active and len(self.state.conversation(key).messages) > self.message_list.MAX_ROWS:
            self.render_conversation(key, preserve_scroll=not message.is_self)
            return None
        viewport = self.capture_chat_scroll() if active else None
        label = '你' if message.is_self else message.author
        if self.controller.encryption is not None:
            security = getattr(message, 'encryption', 'legacy')
            label += {'e2ee': ' [端到端加密]', 'legacy': ' [旧消息 · 非端到端加密]'}.get(security, ' [安全验证失败]')
        row = self.display_message_with_time(message.content, message.timestamp,
                                             message.is_self, key=key, author=label)
        if row is not None:
            row._chat_message = message
            self.message_list.observe(key, message)
        if active:
            if message.is_self or viewport['at_bottom']:
                self.request_scroll()
            else:
                self._new_messages[key] = self._new_messages.get(key, 0) + 1
                self.request_scroll(viewport)
                self.update_new_messages_button()
        return row

    def clear_selection(self):
        if self.current_chat_frame is not None:
            self.current_chat_frame.pack_forget()
        self.current_chat_frame = None
        self.cancel_scroll()
        self.update_new_messages_button()
        self.refresh_controls()

    def remove_conversation(self, key):
        self._new_messages.pop(key, None)
        self.message_list.forget(key)
        frame = self.chat_frames.pop(key, None)
        if frame is not None:
            if self.current_chat_frame is frame:
                self.current_chat_frame = None
            frame.destroy()

    def refresh_groups(self):
        for gid in list(self.groups_ui.windows):
            if gid not in self.state.groups:
                self.groups_ui.close(gid)
            else:
                self.groups_ui.show(gid)
        self.refresh_conversation_list('group')
        self.refresh_controls()

    def refresh_controls(self):
        key = self.state.current_chat
        title = None
        if key is not None:
            title = self.state.groups.get(key.target, {}).get('group_name', key.target) if key.kind == 'group' else key.target
        label = getattr(self, 'chat_title', None)
        if label is not None and label.winfo_exists():
            label.configure(text=title if title else '你的对话')
            self.chat_subtitle.configure(text=('群聊' if key.kind == 'group' else '私聊')
                                         if title else '从左侧选择好友或群聊')
            if key and key.kind == 'group':
                self.group_info_button.configure(state=tk.NORMAL)
                self.group_info_button.pack(side=tk.LEFT, before=self.load_history_button, padx=(0, 6))
            else:
                self.group_info_button.pack_forget()
            encryption = self.controller.encryption
            can_send = (title and self.controller.connection.running and not self.state.pending_messages
                        and (encryption is None or (encryption.ready and not encryption.sending)))
            self.send_button.configure(state=tk.NORMAL if can_send else tk.DISABLED)
            conversation = self.state.conversation(key) if key else None
            can_load = (title and self.controller.connection.running and not conversation.exhausted
                        and not self.controller.history.retry_requires_reconnect
                        and self.state.pending_history is None and not self.controller.sync.active
                        and not self.controller.sync.awaiting_initial)
            self.load_history_button.configure(state=tk.NORMAL if can_load else tk.DISABLED)
            empty = getattr(self, 'empty_state', None)
            if empty is not None and empty.winfo_exists():
                if conversation is None or not conversation.messages:
                    self.empty_title.configure(text='开始一段对话' if title else '给对话，一点空间')
                    self.empty_subtitle.configure(text='写下第一条消息，聊聊近况吧。' if title
                                                   else '选择一位好友或一个群聊，\n让交流从这里开始。')
                    empty.place(relx=.5, rely=.45, anchor=tk.CENTER)
                else:
                    empty.place_forget()
            self.refresh_sidebar_counts()

    def refresh_sidebar_counts(self):
        for name, text in (('friends_heading', f'好友  ·  {len(self.state.friends)}'),
                           ('groups_heading', f'群聊  ·  {len(self.state.groups)}')):
            label = getattr(self, name, None)
            if label is not None and label.winfo_exists():
                label.configure(text=text)

    @staticmethod
    def _ellipsize(text, pixels, font):
        if font.measure(text) <= pixels:
            return text
        marker = '…'
        if pixels < font.measure(marker):
            return ''
        low, high = 0, len(text)
        while low < high:
            middle = (low + high + 1) // 2
            if font.measure(text[:middle] + marker) <= pixels:
                low = middle
            else:
                high = middle - 1
        return text[:low].rstrip() + marker

    def conversation_label(self, key, title):
        widget = getattr(self, 'group_listbox' if key.kind == 'group' else 'friends_listbox', None)
        pixels = max(40, widget.winfo_width() - 12) if widget is not None and widget.winfo_width() > 2 else 232
        font_name = str(widget.cget('font')) if widget is not None else str(self.fonts['body'])
        if font_name not in self._row_fonts:
            self._row_fonts[font_name] = tkfont.Font(root=self.master,
                                                    font=widget.cget('font') if widget is not None else self.fonts['body'])
        font = self._row_fonts[font_name]
        title = ' '.join(str(title).split())
        conversation = self.state.conversations.get(key)
        badge = f' [{conversation.unread_count}]' if conversation is not None and conversation.unread_count else ''
        preview = ' '.join(conversation.preview.split()) if conversation is not None else ''
        title_space = max(0, pixels - font.measure(badge))
        if not preview:
            return self._ellipsize(title, title_space, font) + badge
        # Keep the unread count intact; share the remaining row deliberately
        # between the identity and the latest-message preview.
        separator = '  ·  '
        name_budget = min(font.measure(title), max(36, int((title_space - font.measure(separator)) * .52)))
        name = self._ellipsize(title, name_budget, font)
        preview_space = pixels - font.measure(name + badge + separator)
        summary = self._ellipsize(preview, preview_space, font)
        if not summary:
            return self._ellipsize(title, title_space, font) + badge
        return name + badge + separator + summary

    def resize_conversation_list(self, kind, width):
        if self._list_widths.get(kind) == width:
            return
        self._list_widths[kind] = width
        self.refresh_conversation_list(kind)

    def refresh_conversation_list(self, kind):
        """Refit summaries while keeping the same logical rows in view."""
        widget = self.group_listbox if kind == 'group' else self.friends_listbox
        if not widget.winfo_exists():
            return
        if kind == 'group':
            rows = [(ChatKey('group', gid), info.get('group_name', gid))
                    for gid, info in self.state.groups.items()]
            previous_keys = self._group_keys
        else:
            rows = [(ChatKey('private', name), name) for name in self.state.friends]
            previous_keys = self._friend_keys
        keys = [key.target for key, _title in rows]

        def previous_key(index):
            return previous_keys[index] if 0 <= index < len(previous_keys) else None

        selected = [previous_key(index) for index in widget.curselection()]
        active = previous_key(widget.index(tk.ACTIVE)) if widget.size() else None
        anchor = previous_key(widget.index(tk.ANCHOR)) if widget.size() else None
        top = previous_key(widget.nearest(0)) if widget.size() else None
        position = widget.yview()[0]
        if kind == 'group':
            self._group_keys = keys
        else:
            self._friend_keys = keys
        labels = [self.conversation_label(key, title) for key, title in rows]
        if keys == previous_keys and widget.size() == len(labels):
            for index, text in enumerate(labels):
                if widget.get(index) != text:
                    widget.delete(index)
                    widget.insert(index, text)
        else:
            widget.delete(0, tk.END)
            if labels:
                widget.insert(tk.END, *labels)
        indexes = {key: index for index, key in enumerate(keys)}
        current = self.state.current_chat
        if current is not None and current.kind == kind and current.target in indexes:
            selected = [current.target]
        widget.selection_clear(0, tk.END)
        for key in selected:
            if key in indexes:
                widget.selection_set(indexes[key])
        if widget.size():
            widget.activate(indexes.get(active, 0))
            widget.selection_anchor(indexes.get(anchor, 0))
        if keys != previous_keys and top in indexes:
            widget.yview(indexes[top])
        else:
            widget.yview_moveto(position)

    def refresh_activity(self):
        if getattr(self, 'friends_listbox', None) is None or not self.friends_listbox.winfo_exists():
            return
        self.update_friends_listbox()
        # Refresh rows without opening or rebuilding unrelated group dialogs.
        self.refresh_conversation_list('group')
        count = self.state.total_unread
        self.master.title((f'({count}) ' if count else '') + 'chatroom')
        self.refresh_sidebar_counts()

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
            label.configure(text=text, fg=self.colors['warning' if reconnecting else 'success'])
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

    def set_theme(self, mode):
        try:
            self.controller.preferences.set_theme(mode)
        except (OSError, ValueError) as error:
            self.notify('主题设置保存失败', str(error))
            return False
        self.theme.set_mode(mode)
        self.theme_button.configure(text='浅色模式' if mode == 'dark' else '深色模式')
        return True

    def add_theme_button(self, parent):
        self.theme_button = self.theme.button(
            parent, '浅色模式' if self.theme.mode == 'dark' else '深色模式',
            lambda: self.set_theme('light' if self.theme.mode == 'dark' else 'dark'),
            variant='quiet')
        return self.theme_button

    def build_login(self):
        LoginCard(self).build()

    def layout_login_card(self, event=None):
        canvas, card = self.login_canvas, self.login_card
        if not canvas.winfo_exists() or not card.winfo_exists():
            return
        width, height = canvas.winfo_width(), canvas.winfo_height()
        if width <= 1 or height <= 1:
            return
        card_width, card_height = min(card.winfo_reqwidth(), width), card.winfo_reqheight()
        self._login_overflow = card_height > height
        # Keep the usual centered composition, but align overflowing content at
        # the top so every action remains reachable at large text/DPI settings.
        canvas.itemconfigure(self._login_window, width=card_width, height=card_height)
        canvas.coords(self._login_window, max(0, (width-card_width)//2), max(0, (height-card_height)//2))
        canvas.configure(scrollregion=(0, 0, width, max(height, card_height)))
        if not self._login_overflow:
            canvas.yview_moveto(0)

    def bind_login_scrolling(self, widget):
        widget.bind('<MouseWheel>', self.on_login_wheel, add='+')
        widget.bind('<Button-4>', lambda event: self.on_login_wheel(event, units=-3), add='+')
        widget.bind('<Button-5>', lambda event: self.on_login_wheel(event, units=3), add='+')
        if widget.winfo_class() in ('Entry', 'Button', 'Text', 'Listbox', 'TEntry',
                                    'TCombobox', 'TButton', 'TCheckbutton'):
            widget.bind('<FocusIn>', self.reveal_login_focus, add='+')
        for child in list(widget.children.values()):
            self.bind_login_scrolling(child)

    def on_login_wheel(self, event, units=None):
        canvas = getattr(self, 'login_canvas', None)
        if canvas is None or not canvas.winfo_exists() or not self._login_overflow:
            return None
        if units is None:
            delta = getattr(event, 'delta', 0)
            if not delta:
                return None
            units = -int(delta / 120) if abs(delta) >= 120 else (-1 if delta > 0 else 1)
            units *= 3
        canvas.yview_scroll(units, 'units')
        return 'break'

    def reveal_login_focus(self, event):
        canvas = getattr(self, 'login_canvas', None)
        if canvas is None or not canvas.winfo_exists() or not self._login_overflow:
            return
        widget = event.widget
        if not widget.winfo_exists():
            return
        top = widget.winfo_rooty() - canvas.winfo_rooty()
        bottom = top + widget.winfo_height()
        height = canvas.winfo_height()
        offset = canvas.canvasy(0)
        destination = None
        if top < 12:
            destination = offset + top - 12
        elif bottom > height - 12:
            destination = offset + bottom - height + 12
        if destination is not None:
            extent = max(height, self.login_card.winfo_reqheight())
            canvas.yview_moveto(max(0, destination) / extent)

    def build_chat(self):
        """Two columns keep conversations and their contents in focus."""
        self.clear_window()
        self.master.unbind('<Return>')
        c, f = self.colors, self.fonts
        self.master.configure(bg=c['line'])
        toolbar = tk.Frame(self.master, bg=c['surface'])
        toolbar.pack(side=tk.TOP, fill=tk.X, pady=(0, 1))
        self.brand(toolbar).pack(side=tk.LEFT, padx=(22, 18), pady=13)
        connection_chip = tk.Frame(toolbar, bg=c['field'], padx=9, pady=4)
        connection_chip.pack(side=tk.LEFT)
        self.connection_status = self.label(connection_chip, '已连接', font='small', fg=c['success'],
                                            wraplength=180)
        self.connection_status.pack(side=tk.LEFT)
        toolbar_actions = tk.Frame(toolbar, bg=c['surface'])
        toolbar_actions.pack(side=tk.RIGHT, padx=(12, 16))
        self.disconnect_button = self.theme.button(
            toolbar_actions, '断开连接', self.controller.disconnect, variant='quiet',
            font=f['small'], padx=10, pady=6)
        self.disconnect_button.pack(side=tk.RIGHT, padx=(6, 0))
        theme_button = self.add_theme_button(toolbar_actions)
        theme_button.configure(font=f['small'], padx=10, pady=6)
        theme_button.pack(side=tk.RIGHT)
        self.sync_retry_button = self.theme.button(
            toolbar_actions, '重试补取', self.controller.retry_sync, variant='quiet',
            font=f['small'], padx=10, pady=6)
        self.notifications_enabled = tk.BooleanVar(self.master, self.controller.preferences.notifications_enabled)
        self.do_not_disturb = tk.BooleanVar(self.master, self.controller.preferences.do_not_disturb)
        notifications = tk.Menubutton(toolbar_actions, text='通知设置', bg=c['surface'], fg=c['muted'],
                                      font=f['small'], relief=tk.FLAT, bd=0, padx=10, pady=6,
                                      activebackground=c['selected'], takefocus=True,
                                      highlightthickness=1, highlightbackground=c['surface'],
                                      highlightcolor=c['accent'], cursor='hand2')
        menu = tk.Menu(notifications, tearoff=False, bg=c['surface'], fg=c['text'],
                       activebackground=c['selected'], activeforeground=c['text'], font=f['body'])
        menu.add_checkbutton(label='消息提醒', variable=self.notifications_enabled,
                             command=self.save_notification_preferences)
        menu.add_checkbutton(label='免打扰', variable=self.do_not_disturb,
                             command=self.save_notification_preferences)
        notifications.configure(menu=menu)
        notifications.pack(side=tk.RIGHT)
        self.online_button = self.theme.button(toolbar_actions, '在线用户 · 0', self.toggle_online, variant='quiet',
                                               font=f['small'], padx=10, pady=6)
        self.online_button.pack(side=tk.RIGHT, padx=4)

        body = tk.Frame(self.master, bg=c['line'])
        body.pack(fill=tk.BOTH, expand=True)
        sidebar = tk.Frame(body, bg=c['sidebar'], width=272)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 1))
        sidebar.pack_propagate(False)
        account = tk.Frame(sidebar, bg=c['sidebar'])
        account.pack(fill=tk.X, padx=20, pady=(20, 16))
        self.label(account, '当前账号', muted=True, font='small').pack(fill=tk.X, pady=(0, 6))
        self.label(account, self.state.username, font='heading', wraplength=232).pack(fill=tk.X)
        endpoint = self.controller.connection.endpoint or (
            self.controller.connection.settings.host, self.controller.connection.settings.port)
        host = f'[{endpoint[0]}]' if ':' in endpoint[0] else endpoint[0]
        self.label(account, f'{host}:{endpoint[1]}', muted=True, font='small', wraplength=232).pack(
            fill=tk.X, pady=(4, 0))
        actions = tk.Frame(sidebar, bg=c['sidebar'])
        actions.pack(fill=tk.X, padx=16, pady=(0, 20))
        self.theme.button(actions, '添加好友', self.add_friend, variant='secondary',
                          padx=10, font=f['small']).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        self.theme.button(actions, '创建群聊', self.groups_ui.create, variant='secondary',
                          padx=10, font=f['small']).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 0))
        lists = tk.Frame(sidebar, bg=c['sidebar'])
        lists.pack(fill=tk.BOTH, expand=True, padx=12)
        lists.columnconfigure(0, weight=1)
        lists.rowconfigure(1, weight=3)
        lists.rowconfigure(3, weight=2)

        def conversation_list(row, title):
            heading = self.label(lists, title, muted=True, font='small')
            heading.grid(row=row, column=0, sticky='w', padx=8, pady=(0, 8))
            holder = tk.Frame(lists, bg=c['sidebar'])
            holder.grid(row=row+1, column=0, sticky='nsew', pady=(0, 18))
            widget = self.theme.listbox(holder, width=23, height=4, bg=c['sidebar'],
                                       font=f['list'],
                                       highlightbackground=c['sidebar'], selectborderwidth=0)
            widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar = AutoScrollbar(holder, orient=tk.VERTICAL, command=widget.yview)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            widget.configure(yscrollcommand=scrollbar.set)
            return heading, widget

        self.friends_heading, self.friends_listbox = conversation_list(0, '好友  ·  0')
        self.groups_heading, self.group_listbox = conversation_list(2, '群聊  ·  0')
        self.friends_listbox.bind('<Configure>', lambda event: self.resize_conversation_list('private', event.width))
        self.group_listbox.bind('<Configure>', lambda event: self.resize_conversation_list('group', event.width))
        self.friends_listbox.bind('<<ListboxSelect>>', self.select_friend)
        self.group_listbox.bind('<<ListboxSelect>>', self.select_group)
        self.group_listbox.bind('<Double-1>', self.show_group_info_on_double_click)
        self.label(sidebar, '双击群聊，查看成员与设置', muted=True, font='small').pack(
            anchor=tk.W, padx=20, pady=(0, 18))

        workspace = tk.Frame(body, bg=c['bg'])
        workspace.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        workspace.rowconfigure(0, weight=1)
        workspace.columnconfigure(0, weight=1)
        right = tk.Frame(workspace, bg=c['bg'])
        right.grid(row=0, column=0, sticky='nsew')
        self.online_panel = tk.Frame(workspace, bg=c['sidebar'], width=178)
        self.online_panel.grid(row=0, column=1, sticky='nsew', padx=(1, 0))
        self.online_panel.grid_propagate(False)
        self.online_panel.rowconfigure(1, weight=1)
        self.online_panel.columnconfigure(0, weight=1)
        self.label(self.online_panel, '在线用户', font='heading').grid(
            row=0, column=0, sticky='w', padx=16, pady=22)
        self.online_listbox = self.theme.listbox(self.online_panel, width=14, bg=c['sidebar'],
                                                highlightbackground=c['sidebar'])
        self.online_listbox.grid(row=1, column=0, sticky='nsew', padx=12, pady=(0, 16))
        online_scroll = AutoScrollbar(self.online_panel, orient=tk.VERTICAL, command=self.online_listbox.yview)
        online_scroll.grid(row=1, column=1, sticky='ns', pady=(0, 16))
        self.online_listbox.configure(yscrollcommand=online_scroll.set)
        self.online_panel.grid_remove()
        self.online_visible = False

        chat_header = tk.Frame(right, bg=c['surface'])
        chat_header.pack(fill=tk.X)
        heading = tk.Frame(chat_header, bg=c['surface'])
        self.chat_title = self.label(heading, '你的对话', font='title', wraplength=400)
        self.chat_title.pack(fill=tk.X)
        self.chat_subtitle = self.label(heading, '从左侧选择好友或群聊', muted=True, font='small',
                                        wraplength=400)
        self.chat_subtitle.pack(fill=tk.X, pady=(3, 0))
        tools = tk.Frame(chat_header, bg=c['surface'])
        tools.pack(side=tk.RIGHT, padx=(0, 20))
        self.group_info_button = self.theme.button(tools, '群聊信息', self.open_current_group,
                                                   variant='quiet', state=tk.DISABLED, font=f['small'])
        self.group_info_button.pack(side=tk.LEFT, padx=(0, 6))
        self.load_history_button = self.theme.button(
            tools, '更早的消息', self.controller.load_older_history,
            variant='quiet', state=tk.DISABLED, font=f['small'])
        self.load_history_button.pack(side=tk.LEFT)
        heading.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=24, pady=(20, 16))
        tk.Frame(right, bg=c['line'], height=1).pack(fill=tk.X)

        if self.controller.encryption is not None:
            security = tk.Frame(right, bg=c['bg'])
            security.pack(fill=tk.X, padx=24, pady=(10, 0))
            self.encryption_status = self.label(security, '', muted=True, font='small', wraplength=460)
            self.encryption_status.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self.theme.button(security, '加密与密钥…', lambda: EncryptionWindow(self),
                              variant='quiet', font=f['small'], padx=6, pady=2).pack(side=tk.RIGHT)

        composer = tk.Frame(right, bg=c['surface'])
        composer.pack(side=tk.BOTTOM, fill=tk.X)
        tk.Frame(composer, bg=c['line'], height=1).pack(fill=tk.X)
        self.status_label = self.label(composer, '', muted=True, font='small', wraplength=550)
        self.status_label.pack(fill=tk.X, padx=24, pady=(8, 4))
        input_shell = tk.Frame(composer, bg=c['field'], highlightthickness=1,
                               highlightbackground=c['line'], highlightcolor=c['line'], bd=0)
        input_shell.pack(fill=tk.X, padx=24, pady=(2, 18))
        self.msg_entry = tk.Text(input_shell, height=3, wrap=tk.WORD, undo=True, font=f['body'],
                                 bg=c['field'], fg=c['text'], insertbackground=c['text'],
                                 selectbackground=c['selected'], selectforeground=c['text'],
                                 relief=tk.FLAT, bd=0, padx=12, pady=10,
                                 highlightthickness=0)
        self.msg_entry.pack(fill=tk.X)
        self.msg_entry.bind('<FocusIn>', lambda event: input_shell.configure(highlightbackground=self.colors['accent']))
        self.msg_entry.bind('<FocusOut>', lambda event: input_shell.configure(highlightbackground=self.colors['line']))
        draft = self.controller.take_draft()
        if draft:
            self.msg_entry.insert('1.0', draft)
        composer_actions = tk.Frame(input_shell, bg=c['field'])
        composer_actions.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.label(composer_actions, 'Enter 发送 · Shift / Ctrl + Enter 换行',
                   muted=True, font='small').pack(side=tk.LEFT, padx=(2, 8))
        self.send_button = self.theme.button(composer_actions, '发送', self.controller.send_message,
                                              variant='primary', state=tk.DISABLED, width=6, padx=12, pady=6)
        self.send_button.pack(side=tk.RIGHT)
        self.msg_entry.bind('<Return>', self.on_message_entry_key)

        display = tk.Frame(right, bg=c['bg'])
        display.pack(fill=tk.BOTH, expand=True)
        self.chat_canvas = tk.Canvas(display, bg=c['bg'], highlightthickness=0, yscrollincrement=20)
        self.chat_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.chat_scrollbar = AutoScrollbar(display, orient=tk.VERTICAL, command=self.chat_canvas.yview)
        self.chat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_canvas.configure(yscrollcommand=self.on_chat_scroll)
        self.chat_container = tk.Frame(self.chat_canvas, bg=c['bg'])
        self.chat_window = self.chat_canvas.create_window((0, 0), window=self.chat_container, anchor=tk.NW)
        self.chat_container.bind('<Configure>', lambda event: self.chat_canvas.configure(
            scrollregion=self.chat_canvas.bbox('all')))
        self.chat_canvas.bind('<Configure>', self.resize_chat)
        self.bind_chat_wheel(self.chat_canvas)
        self.bind_chat_wheel(self.chat_container)
        self.new_messages_button = self.theme.button(
            self.chat_canvas, '', self.scroll_to_bottom, variant='primary',
            font=f['small'], padx=12, pady=7)
        self.bind_chat_wheel(self.new_messages_button)
        self.empty_state = tk.Frame(self.chat_canvas, bg=c['bg'])
        empty_mark = tk.Canvas(self.empty_state, width=92, height=76, bg=c['bg'],
                               highlightthickness=0, takefocus=False)
        empty_mark.pack(pady=(0, 16))
        empty_mark.create_polygon(28, 8, 82, 8, 82, 45, 70, 45, 70, 56, 57, 45, 28, 45,
                                  fill=c['selected'], outline='')
        empty_mark.create_polygon(10, 25, 65, 25, 65, 62, 35, 62, 22, 72, 22, 62, 10, 62,
                                  fill=c['field'], outline=c['line'], width=1)
        for x in (27, 39, 51):
            empty_mark.create_oval(x-2, 42, x+2, 46, fill=c['muted'], outline='')
        self.empty_title = self.label(self.empty_state, '给对话，一点空间', font='title', anchor=tk.CENTER)
        self.empty_title.pack()
        self.empty_subtitle = self.label(self.empty_state, '选择一位好友或一个群聊，\n让交流从这里开始。',
                                         muted=True, justify=tk.CENTER, anchor=tk.CENTER)
        self.empty_subtitle.pack(pady=(12, 0))
        self.bind_chat_wheel(self.empty_state)
        for child in self.empty_state.winfo_children():
            self.bind_chat_wheel(child)
        self._chat_layout_ready = True
        self.refresh_controls()
        self.refresh_encryption()

    def toggle_online(self):
        self.online_visible = not self.online_visible
        if self.online_visible:
            self.online_panel.grid()
        else:
            self.online_panel.grid_remove()
        self.online_button.configure(bg=self.colors['selected' if self.online_visible else 'surface'])

    def open_current_group(self):
        key = self.state.current_chat
        if key is not None and key.kind == 'group' and self.controller.connection.running:
            self.controller.request_group_info(key.target, open_window=True)

    def resize_chat(self, event):
        canvas = getattr(self, 'chat_canvas', None)
        if (self._destroyed or not self._chat_layout_ready or event.widget is not canvas
                or canvas is None or not canvas.winfo_exists()):
            return
        if not all(widget.winfo_exists() for widget in (
                self.chat_title, self.chat_subtitle, self.status_label, self.empty_subtitle)):
            return
        canvas.itemconfigure(self.chat_window, width=event.width)
        self.chat_title.configure(wraplength=max(140, event.width-280))
        self.chat_subtitle.configure(wraplength=max(140, event.width-280))
        self.status_label.configure(wraplength=max(140, event.width-48))
        security = getattr(self, 'encryption_status', None)
        if security is not None and security.winfo_exists():
            security.configure(wraplength=max(140, event.width-180))
        width = max(100, min(520, int(event.width*.78)-48))
        for frame in self.chat_frames.values():
            for bubble in frame.winfo_children():
                for label in bubble.winfo_children():
                    if isinstance(label, tk.Label):
                        label.configure(wraplength=width)
        self.empty_subtitle.configure(wraplength=max(140, event.width-64))

    def display_message_with_time(self, msg, time_str, is_self=False, key=None, author=None):
        """Keep metadata separate from the message and adapt to the viewport."""
        try:
            if not self.master.winfo_exists():
                return
            if key is None:
                key = self.state.current_chat
            chat_frame = self.chat_frames.get(key, self.chat_container)
            if not chat_frame.winfo_exists():
                return
            c = self.colors
            anchor = tk.E if is_self else tk.W
            width = max(100, min(520, int(self.chat_canvas.winfo_width()*.78)-48))
            row = tk.Frame(chat_frame, bg=c['bg'])
            metadata = '  ·  '.join(str(value) for value in (author, time_str) if value)
            if metadata:
                self.label(row, metadata, muted=True, font='small', wraplength=width,
                           justify=tk.LEFT, anchor=anchor).pack(anchor=anchor, pady=(0, 5))
            bubble = self.label(row, msg, bg=c['self' if is_self else 'surface'],
                                wraplength=width, justify=tk.LEFT, padx=14, pady=10)
            bubble.pack(anchor=anchor)
            row.pack(fill=tk.X, padx=24, pady=(14, 4))
            self.bind_chat_wheel(row)
            for child in row.winfo_children():
                self.bind_chat_wheel(child)
            if key == self.state.current_chat:
                self.empty_state.place_forget()
            return row
        except tk.TclError:
            logging.warning('尝试在已销毁的 widget 上显示消息')

    def update_chat_region(self):
        self.chat_canvas.update_idletasks()
        self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))

    def chat_is_at_bottom(self):
        if not self.message_list.at_latest(self.state.current_chat):
            return False
        region = self.chat_canvas.bbox('all')
        if region is None:
            return True
        bottom = self.chat_canvas.canvasy(0) + self.chat_canvas.winfo_height()
        return region[3] - bottom <= 24

    def capture_chat_scroll(self):
        """Anchor a viewport to a message, rather than a changing fraction."""
        if self._scroll_after_id is not None:
            if self._scroll_anchor is not None:
                return self._scroll_anchor
            return {'at_bottom': True}
        top = self.chat_canvas.canvasy(0)
        viewport = {'at_bottom': self.chat_is_at_bottom(), 'top': top,
                    'message': None, 'offset': 0}
        frame = self.current_chat_frame
        if frame is not None:
            canvas_top = self.chat_canvas.winfo_rooty()
            for row in frame.pack_slaves():
                if hasattr(row, '_chat_message') and row.winfo_rooty() + row.winfo_height() > canvas_top:
                    viewport['message'] = row._chat_message
                    viewport['offset'] = row.winfo_rooty() - canvas_top
                    break
        return viewport

    def restore_chat_scroll(self, viewport):
        self.update_chat_region()
        target = viewport['top']
        frame = self.current_chat_frame
        if frame is not None and viewport['message'] is not None:
            for row in frame.winfo_children():
                if (hasattr(row, '_chat_message')
                        and _message_identity(row._chat_message) == _message_identity(viewport['message'])):
                    target = (self.chat_canvas.canvasy(0) + row.winfo_rooty()
                              - self.chat_canvas.winfo_rooty() - viewport['offset'])
                    break
        region = self.chat_canvas.bbox('all')
        if region is not None and region[3] > region[1]:
            self.chat_canvas.yview_moveto(max(0, target - region[1]) / (region[3] - region[1]))

    def on_chat_scroll(self, first, last):
        self.chat_scrollbar.set(first, last)
        if not self._restoring_scroll and self._scroll_after_id is None:
            self.message_list.on_scroll(self.state.current_chat, first, last)
        if (not self._restoring_scroll and self._scroll_after_id is None
                and self.message_list.at_latest(self.state.current_chat)
                and float(last) >= .999):
            self._new_messages.pop(self.state.current_chat, None)
            self.update_new_messages_button()

    def update_new_messages_button(self):
        button = getattr(self, 'new_messages_button', None)
        if button is None or not button.winfo_exists():
            return
        count = self._new_messages.get(self.state.current_chat, 0)
        if count:
            button.configure(text=f'{count} 条新消息 ↓')
            button.place(relx=1, rely=1, x=-16, y=-16, anchor=tk.SE)
            button.lift()
        else:
            button.place_forget()

    def scroll_to_bottom(self):
        """Follow the latest message after sending or an explicit request."""
        self.cancel_scroll()
        if not self.message_list.at_latest(self.state.current_chat):
            self.render_conversation(self.state.current_chat, preserve_scroll=False)
            return
        self.update_chat_region()
        self.chat_canvas.yview_moveto(1.0)
        self._new_messages.pop(self.state.current_chat, None)
        self.update_new_messages_button()

    def request_scroll(self, viewport=None):
        if self._scroll_after_id is None:
            self._scroll_anchor = viewport
            self._scroll_after_id = self.master.after_idle(self.finish_scroll)
        elif viewport is None:
            # A local send or an already-following batch keeps following even
            # when several messages arrive before Tk lays out the new rows.
            self._scroll_anchor = None

    def finish_scroll(self):
        viewport = self._scroll_anchor
        self._scroll_after_id = None
        self._scroll_anchor = None
        if viewport is None:
            self.scroll_to_bottom()
        else:
            self._restoring_scroll = True
            try:
                self.restore_chat_scroll(viewport)
            finally:
                self._restoring_scroll = False

    def cancel_scroll(self):
        if self._scroll_after_id is not None:
            self.master.after_cancel(self._scroll_after_id)
            self._scroll_after_id = None
        self._scroll_anchor = None

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
        window.transient(self.master)
        self.request_windows[key] = window
        window.title(title)
        window.configure(bg=self.colors['bg'])
        self.label(window, text, wraplength=400, justify=tk.LEFT).pack(padx=24, pady=24)
        def answer(accepted):
            self.request_windows.pop(key, None)
            window.destroy()
            callback(accepted)
        self.theme.button(window, '接受', lambda: answer(True), variant='primary').pack(side=tk.LEFT, padx=24, pady=(0, 20))
        self.theme.button(window, '拒绝', lambda: answer(False)).pack(side=tk.RIGHT, padx=24, pady=(0, 20))
        window.protocol('WM_DELETE_WINDOW', lambda: answer(False))

    def set_auth_busy(self, busy, text=""):
        self._auth_busy = busy
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
        for name in ('import_keys_button', 'migrate_button', 'legacy_unlock_button'):
            button = getattr(self, name, None)
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
            label.configure(text=encryption.status, fg=self.colors['success' if encryption.ready else 'warning'])
        if getattr(self, 'chat_title', None) is not None and self.chat_title.winfo_exists():
            self.refresh_controls()

    def unlock_legacy_keys(self):
        from .encryption_view import unlock_legacy_keys
        unlock_legacy_keys(self)

    def migrate_account(self):
        from .encryption_view import migrate_account
        migrate_account(self)

    def register(self):
        """Switch the existing authentication card between login and signup."""
        if not self._auth_busy:
            self.set_auth_mode(not self._registering)

    def set_auth_mode(self, registering):
        self._registering = registering
        self.auth_title.configure(text='创建账号' if registering else '欢迎回来')
        self.auth_subtitle.configure(text='创建你的账号，开始新的对话。' if registering else '登录账号，继续你的对话。')
        self.login_button.configure(text='创建账号' if registering else '登录')
        self.register_button.configure(text='已有账号？返回登录' if registering else '创建账号')
        for section in self._login_only_sections:
            if registering:
                section.grid_remove()
            else:
                section.grid()
        self.login_status.configure(text='')
        self.username_entry.focus_set()

    def submit_auth(self, event=None):
        if self._registering:
            self.controller.login(register=True)
        else:
            self.controller.login()
        return 'break'

    def registration_complete(self, username):
        self.set_auth_mode(False)
        self.username_entry.delete(0, tk.END)
        self.username_entry.insert(0, username)
        self.password_entry.delete(0, tk.END)
        self.password_entry.focus_set()

    def on_message_entry_key(self, event):
        """
        Enter 发送；Shift+Enter 和 Ctrl+Enter 换行。
        参数:
            event: 按键事件
        """
        if event.state & 0x5:  # Shift or Ctrl
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
        self.online_button.configure(text=f'在线用户 · {len(user_list)}')

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
                delta = getattr(event, 'delta', 0)
                if not delta:
                    return None
                units = -int(delta / 120) if abs(delta) >= 120 else (-1 if delta > 0 else 1)
            self.cancel_scroll()
            self.chat_canvas.yview_scroll(units, 'units')
            return 'break'

    def update_friends_listbox(self):
        """更新好友列表框"""
        try:
            self.refresh_conversation_list('private')
        except tk.TclError:
            logging.warning("update_friends_listbox called on a destroyed widget.")
