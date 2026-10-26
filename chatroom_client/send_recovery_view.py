"""An inline, account-scoped list of volatile outgoing save confirmations."""
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk


class SendRecoveryPanel:
    STATES = {'sending': '等待保存确认', 'checking': '正在核对',
              'uncertain': '结果待确认', 'retry': '未找到回执'}

    def __init__(self, view, parent):
        self.view = view
        self.frame = tk.Frame(parent, bg=view.colors['surface'], highlightthickness=1,
                              highlightbackground=view.colors['line'], padx=12, pady=8)
        top = tk.Frame(self.frame, bg=view.colors['surface'])
        top.pack(fill=tk.X)
        view.label(top, '待确认消息 · 仅本次运行保留', font='small').pack(side=tk.LEFT)
        view.theme.button(top, '收起', self.hide, variant='quiet', font=view.fonts['small']).pack(side=tk.RIGHT)
        listing = tk.Frame(self.frame, bg=view.colors['surface'])
        self.tree = ttk.Treeview(listing, columns=('chat', 'time', 'state', 'text'), show='headings',
                                 height=2, selectmode='browse', style='Pending.Treeview')
        self._font = tkfont.Font(root=view.master, font=view.fonts['small'])
        for name, title, width in (('chat', '会话', 110), ('time', '发送时间', 115),
                                   ('state', '状态', 100), ('text', '内容摘要', 200)):
            self.tree.heading(name, text=title)
            self.tree.column(name, width=width, minwidth=35, stretch=True)
        scrollbar = ttk.Scrollbar(listing, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind('<<TreeviewSelect>>', self.selection_changed)
        self.tree.bind('<Configure>', lambda event: self.refresh(view.controller.sends.owned_records()))
        actions = tk.Frame(self.frame, bg=view.colors['surface'])
        self.recover_button = view.theme.button(actions, '核对所选消息', self.recover, variant='quiet',
                                                font=view.fonts['small'])
        self.recover_button.pack(side=tk.LEFT)
        self.dismiss_button = view.theme.button(actions, '移除本机记录…', self.dismiss, variant='quiet',
                                                font=view.fonts['small'])
        self.dismiss_button.pack(side=tk.LEFT, padx=6)
        self.hint = view.label(self.frame, '', muted=True, font='small', wraplength=480)
        self.hint.pack(side=tk.BOTTOM, fill=tk.X, pady=(2, 0))
        self.hint.bind('<Configure>', lambda event: self.resize())
        actions.pack(side=tk.BOTTOM, fill=tk.X)
        self.details = view.label(self.frame, '', muted=True, font='small', wraplength=480)
        self.details.pack(side=tk.BOTTOM, fill=tk.X, pady=(3, 2))
        self.details.bind('<Configure>', lambda event: self.resize())
        listing.pack(fill=tk.BOTH, expand=True, pady=4)
        self.frame.bind('<Configure>', self.fit)
        self._confirm_id = None

    def hide(self):
        self._confirm_id = None
        if self.frame.winfo_manager():
            self._set_visible(False)

    def _set_visible(self, visible):
        view = self.view
        position = view.capture_reading_position()
        view.cancel_scroll()
        previous = view._restoring_scroll
        view._restoring_scroll = True
        try:
            if visible:
                self.frame.place(in_=view.chat_canvas, relx=0, rely=1, anchor=tk.SW, relwidth=1)
                self.resize()
                self.frame.lift()
            else:
                self.frame.place_forget()
            if position is not None:
                view.restore_reading_position(position)
        finally:
            view._restoring_scroll = previous

    def resize(self):
        if self.frame.winfo_manager():
            canvas = self.view.chat_canvas
            available = max(1, canvas.winfo_rooty() - self.frame.master.winfo_rooty() + canvas.winfo_height() - 8)
            height = min(self.frame.winfo_reqheight(), available)
            if int(self.frame.place_info().get('height') or 0) != height:
                self.frame.place_configure(height=height)

    def toggle(self):
        if self.frame.winfo_manager():
            self.hide()
        else:
            self._set_visible(True)
            self.refresh(self.view.controller.sends.owned_records())
            self.tree.focus_set()

    def selected(self):
        selected = self.tree.selection()
        return next((record for record in self.view.controller.sends.owned_records()
                     if selected and record.record_id == selected[0]), None)

    def fit(self, event):
        width = max(100, event.width - 28)
        for label in (self.hint, self.details):
            if label.cget('wraplength') != width:
                label.configure(wraplength=width)
        compact = width < self._font.measure('字' * 28)
        columns = ('chat', 'text') if compact else ('chat', 'time', 'state', 'text')
        if tuple(self.tree.cget('displaycolumns')) != columns:
            self.tree.configure(displaycolumns=columns)
            for column in columns:
                self.tree.column(column, width=max(50, width // len(columns)))

    def refresh(self, records):
        if not self.frame.winfo_exists():
            return
        selected = self.tree.selection()
        desired = {record.record_id for record in records}
        for iid in self.tree.get_children():
            if iid not in desired:
                self.tree.delete(iid)
        for record in records:
            key = record.context.key
            title = self.view.state.groups.get(key.target, {}).get('group_name', key.target) if key.kind == 'group' else key.target
            title = ('群聊：' if key.kind == 'group' else '私聊：') + title
            preview = ' '.join(record.text[:256].split())[:60]
            values = (title, record.created_at.astimezone().strftime('%m-%d %H:%M:%S'),
                      self.STATES.get(record.status, '结果待确认'), preview)
            shown = set(self.tree.cget('displaycolumns'))
            values = tuple(self.view._ellipsize(str(value), max(0, self.tree.column(column, 'width') - 16), self._font)
                           if column in shown or '#all' in shown else value
                           for column, value in zip(('chat', 'time', 'state', 'text'), values))
            if self.tree.exists(record.record_id):
                if tuple(self.tree.item(record.record_id, 'values')) != values:
                    self.tree.item(record.record_id, values=values)
            else:
                self.tree.insert('', tk.END, iid=record.record_id, values=values)
        if records and (not selected or selected[0] not in desired):
            self.tree.selection_set(records[0].record_id)
        if not records:
            self.hide()
        self.selection_changed()

    def selection_changed(self, event=None):
        record = self.selected()
        if record is None or record.record_id != self._confirm_id:
            self._confirm_id = None
        connection = self.view.controller.connection
        capable = record is not None and record.receipts and 'message_receipts' in connection.capabilities
        retry = record is not None and record.status == 'retry'
        can_recover = (capable and connection.running and record.status not in ('sending', 'checking')
                       and (not retry or not self.view.state.pending_messages))
        self.recover_button.configure(text='重试所选消息' if retry else '核对所选消息',
                                       state=tk.NORMAL if can_recover else tk.DISABLED)
        can_dismiss = record is not None and record.status != 'sending'
        self.dismiss_button.configure(state=tk.NORMAL if can_dismiss else tk.DISABLED,
            text='确认移除（不会撤回消息）' if self._confirm_id else '移除本机记录…')
        text = '保存确认仅表示服务器已保存，不表示对方已读。'
        if self._confirm_id:
            text = '移除不撤回消息，再次发送可能重复。再次点击确认移除。'
        elif record is not None and not capable:
            text = '此服务器无法核对，请先查看历史；移除不表示发送成功。'
        self.hint.configure(text=text)
        if record is not None:
            self.details.configure(text=f'{record.context.key.target} · '
                f'{record.created_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")} · '
                f'{self.STATES.get(record.status, "结果待确认")}')
        else:
            self.details.configure(text='')

    def recover(self):
        record = self.selected()
        if record is not None:
            self.view.controller.sends.recover(record)
            self.view.refresh_controls()

    def dismiss(self):
        record = self.selected()
        if record is None or record.status == 'sending':
            return
        if self._confirm_id != record.record_id:
            self._confirm_id = record.record_id
            self.selection_changed()
        else:
            self._confirm_id = None
            self.view.controller.sends.dismiss(record.record_id)
