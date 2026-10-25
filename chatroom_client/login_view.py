"""Login/signup card layout, retaining the view's public widget interface."""
import tkinter as tk

from .encryption_view import import_keys
from .settings_view import ServerProfileSelector
from .theme import AutoScrollbar


class LoginCard:
    def __init__(self, view):
        self.view = view

    def build(self):
        """A focused login card keeps primary and recovery actions distinct."""
        view = self.view
        view.clear_window()
        view._registering = view._auth_busy = False
        view._login_only_sections = []
        c = view.colors
        view.master.configure(bg=c['bg'])
        header = tk.Frame(view.master, bg=c['bg'])
        header.pack(fill=tk.X, padx=28, pady=(18, 0))
        view.brand(header).pack(side=tk.LEFT)
        view.add_theme_button(header).pack(side=tk.RIGHT)
        view.label(header, '桌面客户端', muted=True, font='small').pack(side=tk.RIGHT, padx=12)

        stage = tk.Frame(view.master, bg=c['bg'])
        stage.pack(fill=tk.BOTH, expand=True, padx=24, pady=(12, 18))
        view.login_canvas = tk.Canvas(stage, bg=c['bg'], highlightthickness=0,
                                      yscrollincrement=20, takefocus=False)
        view.login_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        view.login_scrollbar = AutoScrollbar(stage, orient=tk.VERTICAL, command=view.login_canvas.yview)
        view.login_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        view.login_canvas.configure(yscrollcommand=view.login_scrollbar.set)
        view.login_card = tk.Frame(view.login_canvas, bg=c['surface'], highlightthickness=1,
                                   highlightbackground=c['line'], highlightcolor=c['line'], bd=0)
        view._login_window = view.login_canvas.create_window((0, 0), window=view.login_card, anchor=tk.NW)
        view._login_overflow = False
        view.login_canvas.bind('<Configure>', view.layout_login_card)
        view.login_card.bind('<Configure>', view.layout_login_card)
        form = tk.Frame(view.login_card, bg=c['surface'], padx=28, pady=18)
        form.pack(fill=tk.BOTH, expand=True)
        form.columnconfigure(0, weight=1)
        view.auth_title = view.label(form, '欢迎回来', font='title')
        view.auth_title.grid(row=0, column=0, sticky='w')
        view.auth_subtitle = view.label(form, '登录账号，继续你的对话。', muted=True, font='small')
        view.auth_subtitle.grid(
            row=1, column=0, sticky='w', pady=(4, 12))
        view.profile_selector = ServerProfileSelector(form, view.controller)
        view.profile_selector.grid(row=2, column=0, sticky='ew', pady=(0, 10))

        def field(row, title, **kwargs):
            view.label(form, title, font='small', muted=True).grid(
                row=row, column=0, sticky='w', pady=(0, 4))
            widget = view.theme.entry(form, width=38, **kwargs)
            widget.grid(row=row+1, column=0, sticky='ew', ipady=4, pady=(0, 8))
            return widget

        view.username_entry = field(3, '用户名')
        view.password_entry = field(5, '密码', show='•')
        view.encryption_entry = None
        row = 7
        if view.controller.encryption is not None:
            note = tk.Frame(form, bg=c['surface'])
            note.grid(row=row, column=0, sticky='ew', pady=(0, 6))
            view._login_only_sections.append(note)
            view.label(note, '登录即解锁加密身份', muted=True, font='small').pack(side=tk.LEFT)
            view.import_keys_button = view.theme.button(
                note, '恢复密钥…', lambda: import_keys(view), variant='quiet',
                font=view.fonts['small'], padx=5, pady=2)
            view.import_keys_button.pack(side=tk.RIGHT)
            row += 1
        view.port_entry = field(row, '连接端口 · 仅本次有效')
        view.port_entry.insert(0, str(view.controller.connection.settings.port))
        row += 2
        view.login_button = view.theme.button(form, '登录', view.submit_auth, variant='primary', pady=9)
        view.login_button.grid(row=row, column=0, sticky='ew', pady=(2, 6))
        actions = tk.Frame(form, bg=c['surface'])
        actions.grid(row=row+1, column=0, sticky='ew')
        view.register_button = view.theme.button(actions, '创建账号', view.register, variant='quiet',
                                                 font=view.fonts['small'], padx=4, pady=4)
        view.register_button.pack(side=tk.LEFT)
        view.theme.button(actions, '取消连接', view.controller.cancel_auth, variant='quiet',
                          font=view.fonts['small'], padx=4, pady=4).pack(side=tk.RIGHT)
        row += 2
        if view.controller.encryption is not None:
            recovery = tk.Frame(form, bg=c['surface'])
            recovery.grid(row=row, column=0, sticky='ew', pady=(6, 0))
            view._login_only_sections.append(recovery)
            tk.Frame(recovery, bg=c['line'], height=1).pack(fill=tk.X, pady=(0, 7))
            view.migrate_button = view.theme.button(recovery, '迁移旧账号…', view.migrate_account,
                                                    variant='quiet', font=view.fonts['small'], padx=4, pady=3)
            view.migrate_button.pack(side=tk.LEFT)
            view.legacy_unlock_button = view.theme.button(recovery, '解锁旧密钥…', view.unlock_legacy_keys,
                                                         variant='quiet', font=view.fonts['small'], padx=4, pady=3)
            view.legacy_unlock_button.pack(side=tk.RIGHT)
            row += 1
        view.login_status = view.label(form, '', muted=True, font='small', wraplength=410)
        view.login_status.grid(row=row, column=0, sticky='ew', pady=(4, 0))
        view.bind_login_scrolling(view.login_canvas)
        view.username_entry.focus_set()
        view.master.bind('<Return>', view.submit_auth)
