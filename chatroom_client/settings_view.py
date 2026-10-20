"""Server profiles and notification preference widgets for the login view."""
import tkinter as tk
from tkinter import messagebox, ttk

from .preferences import PreferencesError, ServerProfile


def settings_busy(controller):
    connection = controller.connection
    return bool(connection.running or connection.auth_busy or getattr(controller, 'reconnecting', False))


class ServerProfileSelector(ttk.Frame):
    def __init__(self, master, controller, **kwargs):
        super().__init__(master, **kwargs)
        self.controller = controller
        self.window = None
        self.name = tk.StringVar(self)
        ttk.Label(self, text='服务器').grid(row=0, column=0, sticky='w', padx=(0, 6))
        self.combobox = ttk.Combobox(self, textvariable=self.name, state='readonly', width=23)
        self.combobox.grid(row=0, column=1, sticky='ew')
        self.combobox.bind('<<ComboboxSelected>>', self.select)
        self.button = ttk.Button(self, text='连接设置…', command=self.open_settings)
        self.button.grid(row=0, column=2, padx=(6, 0))
        self.summary = ttk.Label(self, text='', wraplength=400)
        self.summary.grid(row=1, column=0, columnspan=3, sticky='w', pady=(4, 0))
        self.columnconfigure(1, weight=1)
        self.refresh()

    def refresh(self):
        profiles = self.controller.preferences.profiles
        selected = self.controller.preferences.selected_profile
        self.combobox.configure(values=[profile.name for profile in profiles])
        self.name.set(selected.name)
        host = f'[{selected.host}]' if ':' in selected.host else selected.host
        identity = '已固定公钥指纹' if selected.fingerprint else '本机连接'
        self.summary.configure(text=f'{host}:{selected.port} · {identity}')
        self.set_busy(settings_busy(self.controller))

    def set_busy(self, busy):
        self.combobox.configure(state='disabled' if busy else 'readonly')
        self.button.configure(state='disabled' if busy else 'normal')

    def select(self, event=None):
        if settings_busy(self.controller):
            self.refresh()
            return
        try:
            profile = self.controller.preferences.select_profile(self.name.get())
            self.controller.apply_profile(profile)
        except (PreferencesError, OSError) as error:
            messagebox.showerror('服务器设置', str(error), parent=self.winfo_toplevel())
        self.refresh()

    def open_settings(self):
        if settings_busy(self.controller):
            return
        if self.window is not None and self.window.winfo_exists():
            self.window.lift()
            return
        self.window = SettingsWindow(self.winfo_toplevel(), self.controller, on_change=self.refresh)


class SettingsWindow(tk.Toplevel):
    def __init__(self, master, controller, on_change=None):
        super().__init__(master)
        self.controller = controller
        self.on_change = on_change or (lambda: None)
        self.editing = None
        self.title('服务器与通知设置')
        self.transient(master)
        self.resizable(False, False)
        self.name = tk.StringVar(self)
        self.host = tk.StringVar(self)
        self.port = tk.StringVar(self)
        self.fingerprint = tk.StringVar(self)
        outer = ttk.Frame(self, padding=15)
        outer.pack(fill='both', expand=True)
        self.profile_list = tk.Listbox(outer, exportselection=False, width=22, height=8)
        self.profile_list.grid(row=0, column=0, rowspan=5, sticky='nsew', padx=(0, 14))
        self.profile_list.bind('<<ListboxSelect>>', self.select)
        fields = [('配置名称', self.name), ('地址 / 域名', self.host), ('端口', self.port), ('SHA-256 公钥指纹', self.fingerprint)]
        for row, (label, variable) in enumerate(fields):
            ttk.Label(outer, text=label).grid(row=row, column=1, sticky='w', pady=5)
            ttk.Entry(outer, textvariable=variable, width=50).grid(row=row, column=2, sticky='ew', pady=5)
        ttk.Label(outer, text='远程服务器必须填写通过可信渠道核实的公钥指纹；本机连接可留空。',
                  wraplength=440).grid(row=4, column=1, columnspan=2, sticky='w', pady=(4, 10))
        actions = ttk.Frame(outer)
        actions.grid(row=5, column=0, columnspan=3, sticky='w', pady=8)
        self.new_button = ttk.Button(actions, text='新增配置', command=self.new)
        self.new_button.pack(side='left')
        self.save_button = ttk.Button(actions, text='保存并使用', command=self.save)
        self.save_button.pack(side='left', padx=8)
        self.delete_button = ttk.Button(actions, text='删除配置', command=self.delete)
        self.delete_button.pack(side='left')
        ttk.Separator(outer).grid(row=6, column=0, columnspan=3, sticky='ew', pady=10)
        self.enabled = tk.BooleanVar(self, controller.preferences.notifications_enabled)
        self.dnd = tk.BooleanVar(self, controller.preferences.do_not_disturb)
        ttk.Checkbutton(outer, text='接收桌面消息提醒', variable=self.enabled).grid(row=7, column=0, columnspan=3, sticky='w')
        ttk.Checkbutton(outer, text='免打扰（保留未读数，关闭提醒和提示音）', variable=self.dnd).grid(row=8, column=0, columnspan=3, sticky='w', pady=5)
        self.notification_button = ttk.Button(outer, text='保存提醒设置', command=self.save_notifications)
        self.notification_button.grid(row=9, column=0, columnspan=3, sticky='w', pady=(4, 8))
        self.status = ttk.Label(outer, text=controller.preferences.warning or '', wraplength=620)
        self.status.grid(row=10, column=0, columnspan=3, sticky='w')
        self.refresh(controller.preferences.selected_profile.name)

    def guard(self):
        if settings_busy(self.controller):
            self.status.configure(text='请先断开连接或取消认证 / 重连，再修改设置。')
            return False
        return True

    def refresh(self, selected=None):
        self.names = [profile.name for profile in self.controller.preferences.profiles]
        self.profile_list.delete(0, tk.END)
        for name in self.names:
            self.profile_list.insert(tk.END, name)
        selected = selected or self.controller.preferences.selected_profile.name
        if selected in self.names:
            self.profile_list.selection_set(self.names.index(selected))
            self.load(self.controller.preferences.get_profile(selected))

    def load(self, profile):
        self.editing = profile.name
        self.name.set(profile.name)
        self.host.set(profile.host)
        self.port.set(str(profile.port))
        self.fingerprint.set(profile.fingerprint or '')

    def select(self, event=None):
        selection = self.profile_list.curselection()
        if selection:
            self.load(self.controller.preferences.get_profile(self.names[selection[0]]))

    def new(self):
        if not self.guard():
            return
        self.profile_list.selection_clear(0, tk.END)
        self.editing = None
        self.name.set('')
        self.host.set('127.0.0.1')
        self.port.set('12345')
        self.fingerprint.set('')

    def save(self):
        if not self.guard():
            return
        try:
            try:
                port = int(self.port.get().strip())
            except ValueError as error:
                raise PreferencesError('端口必须是 1–65535 之间的整数') from error
            profile = ServerProfile(self.name.get(), self.host.get(), port, self.fingerprint.get())
            self.controller.preferences.save_profile(profile, replace_name=self.editing)
            self.controller.apply_profile(profile)
        except (PreferencesError, OSError) as error:
            self.status.configure(text=str(error))
            return
        self.refresh(profile.name)
        self.status.configure(text='服务器配置已保存并选用。')
        self.on_change()

    def delete(self):
        if not self.guard() or self.editing is None:
            return
        try:
            selected = self.controller.preferences.delete_profile(self.editing)
            self.controller.apply_profile(selected)
        except (PreferencesError, OSError) as error:
            self.status.configure(text=str(error))
            return
        self.refresh(selected.name)
        self.status.configure(text='服务器配置已删除。')
        self.on_change()

    def save_notifications(self):
        if not self.guard():
            return
        try:
            self.controller.preferences.set_notifications(enabled=self.enabled.get(), do_not_disturb=self.dnd.get())
        except (PreferencesError, OSError) as error:
            self.status.configure(text=str(error))
            return
        self.status.configure(text='提醒设置已保存。')
        self.on_change()
