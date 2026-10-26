"""Message typography, date separators and compact consecutive-author headers."""
from datetime import datetime
import tkinter as tk


def message_time(message):
    try:
        value = datetime.fromisoformat(message.timestamp)
        # Old records have no recoverable timezone: retain their wall time.
        return value.astimezone() if value.tzinfo is not None else value
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def full_time(message):
    value = message_time(message)
    if value is None:
        return str(message.timestamp or '未提供')
    if value.tzinfo is None:
        return f'{message.timestamp}（旧记录，时区未记录）'
    return f'{value.isoformat(" ", timespec="seconds")}（本地时间）\n原始时间：{message.timestamp}'


def continues(previous, current):
    return consecutive(previous, current, message_time(previous) if previous else None, message_time(current))


def consecutive(previous, current, first, second):
    if previous is None or (previous.author, previous.is_self, previous.encryption) != (
            current.author, current.is_self, current.encryption):
        return False
    if first is None or second is None or first.date() != second.date():
        return False
    try:
        return 0 <= (second - first).total_seconds() <= 300
    except TypeError:
        return False


class MessageRows:
    def __init__(self, view):
        self.view = view

    def width(self):
        return max(100, min(560, int(self.view.chat_canvas.winfo_width() * .74) - 48))

    def create(self, frame, key, message, author):
        view, c = self.view, self.view.colors
        anchor = tk.E if message.is_self else tk.W
        row = tk.Frame(frame, bg=c['bg'])
        row._chat_message = message
        row._chat_key = key
        row._chat_heading = row._chat_date = row._chat_author = None
        row._chat_author_text = author
        row._chat_time = message_time(message)
        row._chat_width = self.width()
        row._chat_body = view.label(row, message.content, bg=c['self' if message.is_self else 'surface'],
                                    font='message', wraplength=self.width(), padx=14, pady=9)
        row._chat_body.pack(anchor=anchor)
        at = row._chat_time
        stamp = at.strftime('%H:%M') if at else str(message.timestamp or '')[:64]
        protection = ''
        if view.controller.encryption is not None:
            protection = {'e2ee': '已加密', 'legacy': '旧消息 · 非端到端加密'}.get(
                message.encryption, '安全验证失败')
        text = '  ·  '.join(value for value in (stamp, protection) if value)
        color = c['muted' if message.encryption == 'e2ee' or not protection else
                  ('warning' if message.encryption == 'legacy' else 'danger')]
        row._chat_meta = None
        if text:
            row._chat_meta = view.label(row, text, font='small', fg=color, wraplength=self.width(),
                                        cursor='hand2', takefocus=True, highlightthickness=1,
                                        highlightbackground=c['bg'], highlightcolor=c['accent'])
            row._chat_meta.pack(anchor=anchor, pady=(3, 0))
            for sequence in ('<Button-1>', '<Return>', '<space>'):
                row._chat_meta.bind(sequence, lambda event, row=row: self.toggle_details(row))
            view.bind_chat_wheel(row._chat_meta)
        row._chat_details = None
        row.pack(fill=tk.X, padx=24, pady=(12, 3))
        for widget in (row, row._chat_body):
            view.bind_chat_wheel(widget)
        view.message_actions.attach_label(row)
        return row

    def layout(self, rows):
        previous, before = None, None
        for row in rows:
            if not hasattr(row, '_chat_heading'):
                continue
            message, at = row._chat_message, row._chat_time
            date = (f'{at.year:04d}年{at.month:02d}月{at.day:02d}日'
                    if at and (before is None or before.date() != at.date()) else '')
            grouped = consecutive(previous, message, before, at)
            style = date, grouped
            if getattr(row, '_chat_style', None) != style:
                if date or not grouped:
                    if row._chat_heading is None:
                        row._chat_heading = tk.Frame(row, bg=self.view.colors['bg'])
                        self.view.bind_chat_wheel(row._chat_heading)
                    if date:
                        if row._chat_date is None:
                            row._chat_date = self.view.label(row._chat_heading, '', muted=True,
                                                              font='small', anchor=tk.CENTER)
                            self.view.bind_chat_wheel(row._chat_date)
                        row._chat_date.configure(text=date)
                        row._chat_date.pack(fill=tk.X, pady=(4, 12), before=row._chat_author
                                            if row._chat_author is not None and row._chat_author.winfo_manager() else None)
                    elif row._chat_date is not None:
                        row._chat_date.pack_forget()
                    if not grouped:
                        if row._chat_author is None:
                            row._chat_author = self.view.label(row._chat_heading, row._chat_author_text,
                                muted=True, font='small', wraplength=self.width())
                            self.view.bind_chat_wheel(row._chat_author)
                        row._chat_author.pack(anchor=tk.E if message.is_self else tk.W, pady=(0, 5))
                    elif row._chat_author is not None:
                        row._chat_author.pack_forget()
                    body = row._chat_body if row._chat_body.winfo_manager() else getattr(row, '_search_body', None)
                    options = {'before': body} if body is not None and body.winfo_manager() else {}
                    row._chat_heading.pack(fill=tk.X, **options)
                elif row._chat_heading is not None:
                    for widget in (row._chat_date, row._chat_author, row._chat_heading):
                        if widget is not None:
                            widget.pack_forget()
                row.pack_configure(pady=(3 if grouped and not date else 12, 3))
                row._chat_style = style
            previous, before = message, at

    def pack_body(self, row, widget):
        options = {'anchor': tk.E if row._chat_message.is_self else tk.W}
        if row._chat_meta is not None and row._chat_meta.winfo_manager():
            options['before'] = row._chat_meta
        widget.pack(**options)

    @staticmethod
    def anchor(row):
        body = getattr(row, '_chat_body', row)
        if not body.winfo_manager():
            other = getattr(row, '_search_body', None)
            if other is not None and other.winfo_exists():
                return other
        return body

    def toggle_details(self, row):
        view = self.view
        view.cancel_scroll()
        viewport = view.capture_chat_scroll()
        details = row._chat_details
        if details is None:
            message = row._chat_message
            security = {'e2ee': '正文已通过本机端到端加密验证。',
                        'legacy': '旧消息仅有传输保护，不是端到端加密。'}.get(
                            message.encryption, '此消息未通过完整安全验证，正文不可用。')
            text = f'发送者：{message.author}\n时间：{full_time(message)}\n{security}'
            details = row._chat_details = view.label(row, text, muted=True, font='small', wraplength=self.width())
            view.bind_chat_wheel(details)
        if details.winfo_manager():
            details.pack_forget()
        else:
            details.pack(anchor=tk.E if row._chat_message.is_self else tk.W, pady=(6, 3))
        view.restore_chat_scroll(viewport)
        return 'break'

    def resize(self):
        width = self.width()
        for frame in self.view.chat_frames.values():
            for row in frame.winfo_children():
                if getattr(row, '_chat_width', None) == width:
                    continue
                row._chat_width = width
                for name in ('_chat_body', '_chat_author', '_chat_meta', '_chat_details'):
                    widget = getattr(row, name, None)
                    if widget is not None:
                        widget.configure(wraplength=width)
