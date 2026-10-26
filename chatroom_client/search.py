"""Literal search of the active conversation's verified in-memory messages."""
from dataclasses import dataclass
import re
import tkinter as tk
from tkinter import font as tkfont

from .message_list import message_identity


@dataclass(frozen=True, repr=False)
class SearchHit:
    message: object
    start: int
    end: int


def find_messages(messages, query, *, limit=1000):
    if not query:
        return [], False
    pattern = re.compile(re.escape(query[:256]), re.IGNORECASE)
    hits = []
    for message in messages:
        if message.encryption == 'failed':
            continue
        for match in pattern.finditer(message.content):
            if len(hits) == limit:
                return hits, True
            hits.append(SearchHit(message, match.start(), match.end()))
    return hits, False


class MessageSearch:
    def __init__(self, view):
        self.view = view
        self.frame = self.query = self.entry = None
        self.key = None
        self.hits = []
        self.index = 0
        self.truncated = False
        self._token = object()
        self._highlighted = None
        self._marker = None
        self._searched_query = None
        self._origin = None

    def build(self, parent, after):
        self.after = after
        self.frame = tk.Frame(parent, bg=self.view.colors['surface'])
        self.query = tk.StringVar()
        self.frame.columnconfigure(1, weight=1)
        self.view.label(self.frame, '查找', font='small').grid(row=0, column=0, padx=(12, 6))
        validate = self.view.master.register(lambda value: len(value) <= 256)
        self.entry = tk.Entry(self.frame, textvariable=self.query, width=18, validate='key',
                              validatecommand=(validate, '%P'), bg=self.view.colors['field'],
                              fg=self.view.colors['text'], insertbackground=self.view.colors['text'],
                              relief=tk.FLAT, font=self.view.fonts['body'])
        self.entry.grid(row=0, column=1, sticky='ew', pady=(8, 2))
        self.count = self.view.label(self.frame, '', muted=True, font='small')
        self.count.grid(row=0, column=2, padx=6)
        self.buttons = []
        for column, (text, command) in enumerate([('上一个', lambda: self.move(-1)),
                                                 ('下一个', lambda: self.move(1)), ('关闭', self.close)], 3):
            button = self.view.theme.button(self.frame, text, command, variant='quiet',
                                            font=self.view.fonts['small'], padx=6)
            button.grid(row=0, column=column, padx=(0, 4), pady=(4, 0))
            self.buttons.append(button)
        for button in self.buttons[:2]:
            button.configure(state=tk.DISABLED)
        scope = ('仅搜索本会话已加载消息' if self.view._compact_chat else
                 '仅搜索本会话已加载消息 · Enter 切换结果 · Esc 返回阅读位置')
        self.scope = self.view.label(self.frame, scope,
                                      muted=True, font='small', wraplength=520)
        self.scope.grid(row=1, column=0, columnspan=6, sticky='w', padx=12, pady=(0, 6))
        self.frame.bind('<Configure>', lambda event: self.scope.configure(wraplength=max(120, event.width - 24)))
        self.entry.bind('<Return>', lambda event: self.move(1))
        self.entry.bind('<Shift-Return>', lambda event: self.move(-1))
        self.entry.bind('<Escape>', self.close)
        self.query.trace_add('write', lambda *args: self._schedule(jump=True, delay=150))

    @property
    def visible(self):
        return self.frame is not None and self.frame.winfo_exists() and bool(self.frame.winfo_manager())

    def open(self, event=None):
        key = self.view.state.current_chat
        if self.frame is None or key is None:
            return 'break'
        if self.key != key:
            self.close(focus=False, restore=False)
            self.key = key
            self._origin = self.view.capture_reading_position()
        self.view.message_actions.release()
        if self.view._compact_chat:
            self.view.msg_entry.configure(height=1)
        was_visible = self.visible
        self.frame.pack(fill=tk.X, after=self.after)
        if not was_visible and self._origin is not None:
            self.view.restore_reading_position(self._origin)
        self.entry.focus_set()
        self.entry.selection_range(0, tk.END)
        self._schedule(jump=False, delay=0)
        return 'break'

    def close(self, event=None, *, focus=True, restore=True):
        origin, self._origin = self._origin, None
        self._token = object()
        self._clear_highlight()
        self.hits.clear()
        self._marker = self.key = None
        self._searched_query = None
        if self.frame is not None and self.frame.winfo_exists():
            self.frame.pack_forget()
        if self.query is not None:
            self.query.set('')
        if restore and origin is not None:
            self.view.restore_reading_position(origin)
        entry = getattr(self.view, 'msg_entry', None)
        if getattr(self.view, '_compact_chat', False) and entry is not None and entry.winfo_exists():
            entry.configure(height=2)
        if focus and entry is not None and entry.winfo_exists():
            entry.focus_set()
        return 'break'

    def reset(self):
        self.close(focus=False, restore=False)
        self.frame = self.entry = self.query = None

    def invalidate(self, key):
        if key != self.key or not self.visible:
            return
        if self.hits:
            hit = self.hits[min(self.index, len(self.hits) - 1)]
            self._marker = message_identity(hit.message), hit.start
        self._clear_highlight()
        self.hits.clear()
        self._schedule(jump=False, delay=0)

    def _schedule(self, *, jump, delay):
        if not self.visible or self.key != self.view.state.current_chat:
            return
        token = self._token = object()
        self.view.schedule(delay, lambda: self.refresh(jump=jump) if self._token is token else None)

    def refresh(self, *, jump=False):
        if not self.visible or self.key != self.view.state.current_chat:
            return
        self._token = object()
        self._clear_highlight()
        conversation = self.view.state.conversation(self.key)
        self._searched_query = self.query.get()
        self.hits, self.truncated = find_messages(conversation.messages, self._searched_query)
        self.index = 0
        if not jump and self._marker is not None:
            self.index = next((index for index, hit in enumerate(self.hits)
                               if (message_identity(hit.message), hit.start) == self._marker), 0)
        self._update_count()
        if self.hits and jump:
            self._jump()
        else:
            self.highlight()

    def _update_count(self):
        total = str(len(self.hits)) + ('+' if self.truncated else '')
        self.count.configure(text=f'{self.index + 1}/{total}' if self.hits else
                             ('无结果' if self.query.get() else '仅本会话'))
        for button in self.buttons[:2]:
            button.configure(state=tk.NORMAL if self.hits else tk.DISABLED)

    def move(self, direction):
        if not self.visible or self.key != self.view.state.current_chat:
            return 'break'
        if self.query.get() != self._searched_query:
            self.refresh(jump=True)
            return 'break'
        if self.hits:
            self.index = (self.index + direction) % len(self.hits)
            self._update_count()
            self._jump()
        return 'break'

    def _jump(self):
        hit = self.hits[self.index]
        messages = self.view.state.conversation(self.key).messages
        index = next((i for i, item in enumerate(messages) if item is hit.message), None)
        if index is None:
            self.invalidate(self.key)
            return
        self._marker = message_identity(hit.message), hit.start
        self.view.message_list.focus(self.key, index)
        self.view.render_conversation(self.key, focus_message=hit.message)

    def _clear_highlight(self):
        row = self._highlighted
        self._highlighted = None
        if row is not None and row.winfo_exists():
            self.view.message_actions.release(row)
            row._search_body.destroy()
            self.view.message_rows.pack_body(row, row._chat_body)

    def text_width(self):
        font = tkfont.Font(font=self.view.fonts['message'])
        return max(8, self.view.message_rows.width() // max(1, font.measure('0')))

    def resize(self):
        row = self._highlighted
        if row is None or not row.winfo_exists() or row._search_body.cget('width') == self.text_width():
            return
        viewport = self.view.capture_chat_scroll()
        self.view.cancel_scroll()
        if 'top' not in viewport:
            viewport = self.view.capture_chat_scroll()
        previous = self.view._restoring_scroll
        self.view._restoring_scroll = True
        try:
            self.highlight()
            self.view.restore_chat_scroll(viewport)
        finally:
            self.view._restoring_scroll = previous

    def highlight(self):
        self._clear_highlight()
        if not self.hits or self.key != self.view.state.current_chat:
            return
        hit = self.hits[self.index]
        frame = self.view.chat_frames.get(self.key)
        if frame is None:
            return
        row = next((row for row in frame.winfo_children() if getattr(row, '_chat_message', None) is hit.message), None)
        if row is None:
            return
        original = row._chat_body
        body = tk.Text(row, wrap=tk.WORD, width=self.text_width(), height=1,
                       font=self.view.fonts['message'], bg=original.cget('bg'), fg=self.view.colors['text'],
                       padx=14, pady=10, borderwidth=0, highlightthickness=0, takefocus=True)
        body.insert('1.0', hit.message.content)
        body.tag_configure('search_match', background=self.view.colors['selected'], foreground=self.view.colors['text'])
        body.tag_configure('search_current', background=self.view.colors['accent'], foreground=self.view.colors['bg'])

        def position(offset):
            # Text's +Nc advances Unicode characters, including on Tcl 8 where
            # string length and returned line.column indices count surrogates.
            return '1.0+%dc' % offset

        for other in self.hits:
            if other.message is hit.message:
                body.tag_add('search_match', position(other.start), position(other.end))
        body.tag_add('search_current', position(hit.start), position(hit.end))
        body.configure(state=tk.DISABLED)
        self.view.message_actions.attach_text(row, body)
        original.pack_forget()
        self.view.message_rows.pack_body(row, body)
        body.update_idletasks()
        lines = body.count('1.0', 'end-1c', 'displaylines')
        body.configure(height=min(12, (lines[0] if lines else 0) + 1))
        body.see(position(hit.start))
        self.view.bind_chat_wheel(body)
        row._search_body = body
        self._highlighted = row
