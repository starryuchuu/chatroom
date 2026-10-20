"""Local key management and explicit recipient verification in the Tk thread."""
import json
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk


def fingerprint_text(value):
    return ' '.join(value[index:index + 4] for index in range(0, len(value), 4))


def confirm_roster(master, gid, identities, previous):
    from .e2ee_crypto import bundle_fingerprint

    window = tk.Toplevel(master)
    window.title('确认群聊加密接收人')
    window.geometry('850x470')
    window.transient(master)
    accepted = [False]
    tk.Label(window, text=f'群聊 {gid} 的每位接收人都将能够解密新消息。请核对成员和指纹。',
             wraplength=800, justify=tk.LEFT).pack(fill=tk.X, padx=16, pady=(16, 8))
    tk.Label(window, text='首次发送及成员或密钥变化时需要重新确认。服务端提供的成员列表也可能被篡改；请通过可信渠道核对。',
             wraplength=800, justify=tk.LEFT).pack(fill=tk.X, padx=16, pady=(0, 8))
    frame = tk.Frame(window)
    frame.pack(fill=tk.BOTH, expand=True, padx=16)
    tree = ttk.Treeview(frame, columns=('name', 'change', 'fingerprint'), show='headings')
    for name, title, width in (('name', '接收人', 125), ('change', '变化', 65), ('fingerprint', '密钥指纹', 580)):
        tree.heading(name, text=title)
        tree.column(name, width=width, stretch=name == 'fingerprint')
    scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    old = previous or {}
    for name, bundle in sorted(identities.items()):
        fingerprint = bundle if isinstance(bundle, str) else bundle_fingerprint(bundle)
        change = '新增' if name not in old else ('密钥改变' if old[name] != fingerprint else '')
        tree.insert('', tk.END, values=(name, change, fingerprint_text(fingerprint)))
    removed = sorted(set(old) - set(identities))
    if removed:
        tk.Label(window, text='已移除：' + '、'.join(removed), wraplength=800, justify=tk.LEFT).pack(fill=tk.X, padx=16, pady=6)
    confirmed = tk.BooleanVar(window, False)
    button_frame = tk.Frame(window)
    button_frame.pack(fill=tk.X, padx=16, pady=12)
    button = tk.Button(button_frame, text='确认接收人', state=tk.DISABLED)
    tk.Checkbutton(button_frame, text='我确认以上所有接收人均为此群成员', variable=confirmed,
                   command=lambda: button.configure(state=tk.NORMAL if confirmed.get() else tk.DISABLED)).pack(side=tk.LEFT)

    def accept():
        if confirmed.get():
            accepted[0] = True
            window.destroy()

    button.configure(command=accept)
    button.pack(side=tk.RIGHT)
    tk.Button(button_frame, text='取消', command=window.destroy).pack(side=tk.RIGHT, padx=8)
    window.protocol('WM_DELETE_WINDOW', window.destroy)
    window.grab_set()
    master.wait_window(window)
    return accepted[0]


def import_keys(view):
    from .key_vault import VaultExistsError

    controller = view.controller
    if controller.connection.running or controller.connection.auth_busy or controller.reconnecting:
        view.show_error('恢复密钥', '请先断开连接，再恢复密钥备份。')
        return
    path = filedialog.askopenfilename(parent=view.master, title='选择加密密钥备份',
                                      filetypes=[('密钥备份', '*.json'), ('所有文件', '*')])
    if not path:
        return
    passphrase = view.encryption_passphrase()
    if not passphrase:
        passphrase = simpledialog.askstring('恢复密钥', '请输入此备份的本机密钥口令：', show='*', parent=view.master)
    if passphrase is None:
        return
    try:
        # The header is only a prompt hint. KeyVault authenticates its scope
        # together with the encrypted data before accepting the import.
        with Path(path).open('rb') as source:
            raw_header = source.read(8 * 1024 * 1024 + 1)
        if len(raw_header) > 8 * 1024 * 1024:
            raise ValueError('密钥备份超过大小限制')
        header = json.loads(raw_header)
        origin = header.get('scope', {}) if isinstance(header, dict) else {}
        if not isinstance(origin, dict):
            raise ValueError('密钥备份所属账号格式错误')
        port = view.read_port()
        if port is None:
            return
        destination = [controller.connection.settings.host.lower(), port]
        allow_rebind = origin.get('endpoint') != destination
        if allow_rebind:
            text = ('此备份属于服务器 ' + str(origin.get('endpoint')) + '。\n\n'
                    '是否将同一账号的密钥恢复到当前服务器 ' + str(destination) + '？\n'
                    '请先核实当前服务器公钥指纹；其他账号的备份不能导入。')
            if not messagebox.askyesno('确认密钥备份迁移', text, parent=view.master, default=messagebox.NO):
                return
        try:
            controller.import_encryption_keys(path, passphrase, allow_rebind=allow_rebind)
        except VaultExistsError:
            prompt = ('备份的口令与完整性已验证，但本机已有此账号的密钥文件。\n\n'
                      '替换会覆盖本机现有私钥、联系人指纹、群确认和重放记录；较旧备份也可能恢复较旧的信任状态。'
                      '尚未备份的原私钥一旦覆盖可能无法恢复。\n\n'
                      '是否明确使用所选备份替换本机文件？')
            if not messagebox.askyesno('确认替换本机密钥', prompt, parent=view.master, default=messagebox.NO):
                return
            controller.import_encryption_keys(path, passphrase, allow_rebind=allow_rebind, replace=True)
    except (OSError, ValueError, RecursionError) as error:
        view.show_error('恢复密钥失败', str(error))
        return
    entry = getattr(view, 'encryption_entry', None)
    if entry is not None and entry.winfo_exists():
        entry.delete(0, tk.END)
        entry.insert(0, passphrase)
    view.notify('恢复密钥', '备份已恢复，请使用该密钥口令登录。')


class EncryptionWindow(tk.Toplevel):
    def __init__(self, view):
        super().__init__(view.master)
        self.view, self.controller = view, view.controller
        self.title('端到端加密与密钥')
        self.geometry('850x530')
        self.transient(view.master)
        encryption = self.controller.encryption
        tk.Label(self, text=encryption.status, wraplength=810, justify=tk.LEFT).pack(fill=tk.X, padx=16, pady=(14, 8))
        tk.Label(self, text='我的指纹（请与联系人通过其他可信渠道核对）', anchor=tk.W).pack(fill=tk.X, padx=16)
        fingerprint = tk.Text(self, height=2, wrap=tk.WORD)
        fingerprint.insert('1.0', fingerprint_text(encryption.fingerprint or ''))
        fingerprint.configure(state=tk.DISABLED)
        fingerprint.pack(fill=tk.X, padx=16, pady=6)
        tk.Label(self, text='私钥仅保存在本机加密文件中。请导出并妥善保管备份；遗失密钥后无法解密历史消息。',
                 wraplength=810, justify=tk.LEFT).pack(fill=tk.X, padx=16, pady=6)
        controls = tk.Frame(self)
        controls.pack(fill=tk.X, padx=16, pady=6)
        tk.Button(controls, text='导出加密密钥备份…', command=self.export).pack(side=tk.LEFT)
        tk.Button(controls, text='更改本机密钥口令…', command=self.change_passphrase).pack(side=tk.LEFT, padx=8)
        frame = tk.Frame(self)
        frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=8)
        self.tree = ttk.Treeview(frame, columns=('name', 'verified', 'fingerprint'), show='headings')
        for name, title, width in (('name', '联系人', 130), ('verified', '身份核对', 90), ('fingerprint', '指纹', 590)):
            self.tree.heading(name, text=title)
            self.tree.column(name, width=width, stretch=name == 'fingerprint')
        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        buttons = tk.Frame(self)
        buttons.pack(fill=tk.X, padx=16, pady=(0, 12))
        tk.Button(buttons, text='核对所选联系人指纹…', command=self.verify_peer).pack(side=tk.LEFT)
        tk.Button(buttons, text='处理所选联系人密钥变化…', command=self.accept_change).pack(side=tk.LEFT, padx=8)
        tk.Button(buttons, text='确认当前群接收人…', command=lambda: self.perform(self.controller.review_encryption_group)).pack(side=tk.LEFT)
        tk.Button(buttons, text='关闭', command=self.destroy).pack(side=tk.RIGHT)
        self.reload()

    def reload(self):
        self.tree.delete(*self.tree.get_children())
        for peer in self.controller.encryption.peers():
            self.tree.insert('', tk.END, iid=peer['username'], values=(peer['username'],
                             '已核对' if peer['verified'] else '首次信任 · 未核对', fingerprint_text(peer['fingerprint'])))

    def selected_peer(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo('联系人指纹', '请先选择联系人。', parent=self)
            return None
        return selected[0]

    def verified_confirmation(self, name, fingerprint, action):
        return messagebox.askyesno('核对联系人身份',
                                  f'{name}\n\n{fingerprint_text(fingerprint)}\n\n'
                                  '你是否已经通过其他可信渠道，与联系人本人逐项核对以上指纹？\n\n' + action,
                                  parent=self, default=messagebox.NO)

    def verify_peer(self):
        name = self.selected_peer()
        if name is None:
            return
        peer = next(item for item in self.controller.encryption.peers() if item['username'] == name)
        if self.verified_confirmation(name, peer['fingerprint'], '确认后将标记为已核对。'):
            self.perform(lambda: self.controller.verify_encryption_peer(name))

    def accept_change(self):
        from .e2ee_crypto import bundle_fingerprint

        name = self.selected_peer()
        if name is None:
            return
        bundle = self.controller.encryption.peer_change(name)
        if bundle is None:
            messagebox.showinfo('联系人密钥', '没有待确认的密钥变化。', parent=self)
            return
        if self.verified_confirmation(name, bundle_fingerprint(bundle), '确认后将替换固定的联系人密钥。旧密钥仅能验证本机此前已经记录的原始消息。'):
            self.perform(lambda: self.controller.accept_encryption_peer(name, bundle))

    def perform(self, operation):
        try:
            operation()
        except (OSError, ValueError) as error:
            messagebox.showerror('密钥操作失败', str(error), parent=self)
            return False
        self.reload()
        self.view.refresh_encryption()
        return True

    def export(self):
        path = filedialog.asksaveasfilename(parent=self, title='导出加密密钥备份', defaultextension='.json',
                                           initialfile='chatroom-e2ee-keys.json', filetypes=[('密钥备份', '*.json')])
        if path and self.perform(lambda: self.controller.export_encryption_keys(path)):
            messagebox.showinfo('密钥备份', '加密备份已导出。解密时仍需要本机密钥口令，请分开妥善保管。', parent=self)

    def change_passphrase(self):
        first = simpledialog.askstring('更改本机密钥口令', '请输入新的本机密钥口令（至少 8 个字符，建议 12 个以上）：', show='*', parent=self)
        if first is None:
            return
        second = simpledialog.askstring('更改本机密钥口令', '请再次输入新的口令：', show='*', parent=self)
        if first != second:
            messagebox.showerror('口令不一致', '两次输入的口令不一致。', parent=self)
            return
        if self.perform(lambda: self.controller.change_encryption_passphrase(first)):
            messagebox.showinfo('口令已更新', '本机口令已更新。原有备份仍使用导出时的旧口令，请重新导出备份。', parent=self)
