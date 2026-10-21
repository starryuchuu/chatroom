"""Group creation and information windows, owned and updated on Tk's thread."""
import tkinter as tk
from tkinter import messagebox, simpledialog

from .theme import get_theme


class GroupWindows:
    def __init__(self, master, controller):
        self.master, self.controller = master, controller
        self.windows = {}

    @property
    def state(self):
        return self.controller.state

    def create(self):
        # 创建群聊弹窗
        theme = get_theme(self.master)
        group_window = tk.Toplevel(self.master)
        group_window.title("创建群聊")
        group_window.geometry("420x500")
        group_window.minsize(360, 420)
        group_window.transient(self.master)
        heading = tk.Label(group_window, text="新的群聊", anchor=tk.W)
        heading.pack(fill=tk.X, padx=24, pady=(24, 16))
        tk.Label(group_window, text="群聊名称", anchor=tk.W).pack(fill=tk.X, padx=24, pady=(0, 8))
        name_entry = theme.entry(group_window)
        name_entry.pack(fill=tk.X, padx=24, ipady=8)
        tk.Label(group_window, text="选择成员 · 可选择多位好友", anchor=tk.W).pack(fill=tk.X, padx=24, pady=(20, 8))
        members_listbox = theme.listbox(group_window, selectmode=tk.MULTIPLE)
        for f in self.state.friends:
            members_listbox.insert(tk.END, f)
        members_listbox.pack(padx=24, fill=tk.BOTH, expand=True)

        def do_create():
            group_name = name_entry.get().strip()
            sel = members_listbox.curselection()
            members = [members_listbox.get(i) for i in sel]
            if not group_name or not members:
                messagebox.showerror("错误", "群名和成员不能为空！")
                return
            req = {
                "type": "group_create",
                "from": self.state.username,
                "group_name": group_name,
                "members": members
            }
            if self.controller.try_send(req):
                group_window.destroy()

        create_button = theme.button(group_window, text="创建", command=do_create, variant='primary')
        create_button.pack(fill=tk.X, padx=24, pady=24)
        theme.style_window(group_window)
        heading.configure(font=theme.fonts['title'])
        create_button.configure(**theme._button_options(group_window, 'primary'))
        name_entry.focus_set()

    def show(self, gid):
        theme = get_theme(self.master)
        info = self.state.groups.get(gid)
        if not info:
            messagebox.showerror("错误", "无法获取群组信息")
            return

        members = info.get("members", [])

        group_info_window = self.windows.get(gid)
        if group_info_window is None or not group_info_window.winfo_exists():
            group_info_window = tk.Toplevel(self.master)
            self.windows[gid] = group_info_window
            group_info_window.protocol('WM_DELETE_WINDOW', lambda: self.close(gid))
        else:
            for child in group_info_window.winfo_children():
                child.destroy()
        group_info_window.title(f"群聊信息 - {info.get('group_name')}")
        group_info_window.transient(self.master)

        # --- Top section with labels and listbox ---
        top_frame = tk.Frame(group_info_window)
        top_frame.pack(pady=(24, 12), padx=24, fill="both", expand=True)
        title = tk.Label(top_frame, text=f"群名: {info.get('group_name')}", anchor=tk.W)
        title.pack(fill=tk.X)
        owner = tk.Label(top_frame, text=f"群主: {info.get('owner')}", anchor=tk.W)
        owner.pack(fill=tk.X, pady=(6, 20))
        tk.Label(top_frame, text="成员列表", anchor=tk.W).pack(fill=tk.X, pady=(0, 8))


        members_list = theme.listbox(top_frame, height=8)
        for m in members:
            members_list.insert(tk.END, m)
        members_list.pack(fill="both", expand=True)

        # --- Button section ---
        button_container = tk.Frame(group_info_window)
        button_container.pack(pady=(0, 20), padx=24, fill="x")

        # --- Member Actions Frame ---
        member_actions_frame = tk.Frame(button_container)
        member_actions_frame.pack(fill="x", pady=2)

        def refresh_members():
            self.controller.request_group_info(gid)

        def invite_member():
            friend = simpledialog.askstring("邀请成员", "输入好友用户名:")
            if friend:
                req = {"type": "group_invite", "from": self.state.username, "to": friend, "gid": gid}
                self.controller.try_send(req)

        def leave_group():
            req = {"type": "group_leave", "from": self.state.username, "gid": gid}
            self.controller.try_send(req)

        tk.Button(member_actions_frame, text="刷新成员", command=refresh_members).pack(side="left", padx=2, expand=True)
        tk.Button(member_actions_frame, text="邀请成员", command=invite_member).pack(side="left", padx=2, expand=True)
        tk.Button(member_actions_frame, text="退出群聊", command=leave_group).pack(side="left", padx=2, expand=True)

        # --- Owner Actions Frame ---
        if self.state.username == info.get("owner"):
            owner_actions_frame = tk.Frame(button_container)
            owner_actions_frame.pack(fill="x", pady=2)

            def kick_member():
                sel = members_list.curselection()
                if sel:
                    member = members_list.get(sel[0])
                    if member != self.state.username:
                        req = {"type": "group_kick", "from": self.state.username, "gid": gid, "kick": member}
                        self.controller.try_send(req)

            def disband_group():
                if messagebox.askyesno("解散群聊", "确定要解散群聊吗？此操作不可撤销。"):
                    req = {"type": "group_disband", "from": self.state.username, "gid": gid}
                    self.controller.try_send(req)

            def transfer_ownership():
                new_owner = simpledialog.askstring("转让群主", "请输入新群主用户名:")
                if new_owner:
                    req = {"type": "group_transfer", "from": self.state.username, "gid": gid, "new_owner": new_owner}
                    self.controller.try_send(req)

            def rename_group():
                new_name = simpledialog.askstring("修改群聊名称", "请输入新的群聊名称:")
                if new_name:
                    req = {"type": "group_rename", "from": self.state.username, "gid": gid, "new_name": new_name}
                    self.controller.try_send(req)

            tk.Button(owner_actions_frame, text="踢出成员", command=kick_member).pack(side="left", padx=2, expand=True)
            tk.Button(owner_actions_frame, text="解散群聊", command=disband_group).pack(side="left", padx=2, expand=True)
            tk.Button(owner_actions_frame, text="转让群主", command=transfer_ownership).pack(side="left", padx=2, expand=True)
            tk.Button(owner_actions_frame, text="修改群聊名称", command=rename_group).pack(side="left", padx=2, expand=True)

        # 自动调整窗口大小以适应内容
        theme.style_window(group_info_window)
        title.configure(font=theme.fonts['title'])
        owner.configure(fg=theme.colors['muted'], font=theme.fonts['small'])
        group_info_window.update_idletasks()
        width = group_info_window.winfo_reqwidth()
        height = group_info_window.winfo_reqheight()
        group_info_window.geometry(f"{width+20}x{height+10}")

    def close(self, gid):
        window = self.windows.pop(gid, None)
        if window is not None and window.winfo_exists():
            window.destroy()
