"""Lazy native text selection and one shared menu for message body copying."""
import sys
import tkinter as tk


class MessageActions:
    def __init__(self, view):
        self.view = view
        self.row = self.text = self.menu = None
        self._overlay = False

    def reset(self):
        self.release()
        if self.menu is not None and self.menu.winfo_exists():
            self.menu.destroy()
        self.menu = None

    def release(self, row=None):
        if row is not None and row is not self.row:
            return
        text, owner, overlay = self.text, self.row, self._overlay
        self.text = self.row = None
        self._overlay = False
        if self.menu is not None and self.menu.winfo_exists():
            self.menu.unpost()
        if overlay and text is not None and text.winfo_exists():
            text.destroy()
        if owner is not None and owner.winfo_exists() and owner._chat_body.winfo_exists():
            owner._chat_body.configure(takefocus=True)

    def attach_label(self, row):
        label = row._chat_body
        label.configure(takefocus=True, cursor='xterm')
        label.bind('<Button-1>', lambda event: self.activate(row, event))
        label.bind('<B1-Motion>', lambda event: self.forward(row, event, '<B1-Motion>'))
        label.bind('<ButtonRelease-1>', lambda event: self.forward(row, event, '<ButtonRelease-1>'))
        label.bind('<FocusIn>', lambda event: self.activate(row))
        label.bind('<Button-3>', lambda event: self.popup(row, event))
        label.bind('<Shift-F10>', lambda event: self.popup(row))
        label.bind('<Menu>', lambda event: self.popup(row))
        row.bind('<Destroy>', lambda event: self.release(row) if event.widget is row else None, add='+')

    def attach_text(self, row, text):
        # State=disabled keeps native mouse/keyboard selection while rejecting
        # editing, paste, cut and undo, including platform class bindings.
        text.bind('<<Copy>>', lambda event: self.copy_selected())
        text.bind('<Control-a>', lambda event: self.select_all(text))
        if sys.platform == 'darwin':
            text.bind('<Command-a>', lambda event: self.select_all(text))
        text.bind('<Button-3>', lambda event: self.popup(row, event, text=text))
        text.bind('<Shift-F10>', lambda event: self.popup(row, text=text))
        text.bind('<Menu>', lambda event: self.popup(row, text=text))
        text.bind('<FocusIn>', lambda event: self._target(row, text), add='+')
        text.bind('<Button-1>', lambda event: self._target(row, text), add='+')
        text.bind('<Escape>', lambda event: self.close_selection())

    def _target(self, row, text):
        if text is not self.text:
            self.release()
            self.row, self.text = row, text
        return None

    def activate(self, row, event=None):
        if self.row is not row or self.text is None or not self.text.winfo_exists():
            self.release()
            original = row._chat_body
            text = tk.Text(row, wrap=tk.WORD, width=1, height=1, font=self.view.fonts['message'],
                           bg=original.cget('bg'), fg=self.view.colors['text'], padx=14, pady=9,
                           selectbackground=self.view.colors['accent'], selectforeground=self.view.colors['bg'],
                           borderwidth=0, highlightthickness=0, exportselection=False, undo=False)
            text.insert('1.0', row._chat_message.content)
            text.configure(state=tk.DISABLED)
            text.place(in_=original, x=0, y=0, relwidth=1, relheight=1)
            self.row, self.text, self._overlay = row, text, True
            original.configure(takefocus=False)
            self.attach_text(row, text)
            self.view.bind_chat_wheel(text)
        self.text.focus_set()
        if event is not None:
            self.text.event_generate('<Button-1>', x=event.x, y=event.y)
        return 'break'

    def forward(self, row, event, sequence):
        if self.row is row and self.text is not None and self.text.winfo_exists():
            self.text.event_generate(sequence, x=event.x, y=event.y)
        return 'break'

    def selected_text(self):
        if self.text is None or not self.text.winfo_exists():
            return ''
        try:
            return self.text.get(tk.SEL_FIRST, tk.SEL_LAST)
        except tk.TclError:
            return ''

    def _copy(self, value):
        if value:
            try:
                self.view.master.clipboard_clear()
                self.view.master.clipboard_append(value)
            except tk.TclError:
                self.view.notify('复制失败', '暂时无法访问系统剪贴板，请重试')
        return 'break'

    def copy_selected(self):
        return self._copy(self.selected_text())

    def copy_message(self):
        if self.row is not None and self.row.winfo_exists():
            return self._copy(self.row._chat_message.content)
        return 'break'

    @staticmethod
    def select_all(text):
        text.tag_add(tk.SEL, '1.0', 'end-1c')
        return 'break'

    def close_selection(self):
        row = self.row
        self.release()
        if row is not None and row.winfo_exists():
            self.view.msg_entry.focus_set()
        return 'break'

    def popup(self, row, event=None, *, text=None):
        if text is None:
            self.activate(row)
        else:
            self._target(row, text)
        if self.menu is None:
            c = self.view.colors
            self.menu = tk.Menu(self.view.master, tearoff=False, bg=c['surface'], fg=c['text'],
                                activebackground=c['selected'], activeforeground=c['text'],
                                font=self.view.fonts['body'])
            self.menu.add_command(label='复制所选文字', command=self.copy_selected)
            self.menu.add_command(label='复制整条消息', command=self.copy_message)
        self.menu.entryconfigure(0, state=tk.NORMAL if self.selected_text() else tk.DISABLED)
        x, y = ((event.x_root, event.y_root) if event is not None else
                (self.text.winfo_rootx() + 12, self.text.winfo_rooty() + 12))
        try:
            self.menu.tk_popup(x, y)
        finally:
            self.menu.grab_release()
        return 'break'
