"""Group creation and information windows, owned and updated on Tk's thread."""
import tkinter as tk
from tkinter import messagebox, simpledialog


class GroupWindows:
    def __init__(self, master, controller):
        self.master, self.controller = master, controller
        self.windows = {}

    @property
    def state(self):
        return self.controller.state

    def create(self):
        # 创建群聊弹窗
        group_window = tk.Toplevel(self.master)
        group_window.title("创建群聊")
        group_window.geometry("400x400")
        tk.Label(group_window, text="群聊名称:").pack(pady=10)
        name_entry = tk.Entry(group_window)
        name_entry.pack(pady=5)
        tk.Label(group_window, text="选择成员:").pack(pady=10)
        members_listbox = tk.Listbox(group_window, selectmode=tk.MULTIPLE)
        for f in self.state.friends:
            members_listbox.insert(tk.END, f)
        members_listbox.pack(pady=5, fill=tk.BOTH, expand=True)

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

        tk.Button(group_window, text="创建", command=do_create).pack(pady=20)

    def show(self, gid):
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
        group_info_window.update_idletasks()
        width = group_info_window.winfo_reqwidth()
        height = group_info_window.winfo_reqheight()
        group_info_window.geometry(f"{width+20}x{height+10}")

    def close(self, gid):
        window = self.windows.pop(gid, None)
        if window is not None and window.winfo_exists():
            window.destroy()
