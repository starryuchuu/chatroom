"""Bounded Tk message windows, preserving rows and overlapping scroll anchors."""
from dataclasses import dataclass, field


def message_identity(message):
    if type(message.message_id) is int:
        return ('server', message.message_id)
    return ('local', id(message))


@dataclass
class _Window:
    start: int = 0
    end: int = 0
    count: int = 0
    first: object = None
    known: set = field(default_factory=set)
    forced_start: int | None = None


class MessageList:
    """Keep at most 120 rows per conversation; the model owns the body cache.

    Reaching an edge opens an overlapping window, keeping the visible message
    at the same pixel offset. The overlap also bounds native X11 window heights.
    """
    MAX_ROWS = 120

    def __init__(self, view):
        self.view = view
        self.windows = {}
        self.pending = {}

    def reset(self):
        self.windows.clear()
        self.pending.clear()

    def forget(self, key):
        self.windows.pop(key, None)
        self.pending.pop(key, None)

    def at_latest(self, key):
        window = self.windows.get(key)
        return window is None or window.end == window.count

    def observe(self, key, message):
        window = self.windows.get(key)
        if window is not None:
            window.known.add(message_identity(message))

    def focus(self, key, index):
        window = self.windows.setdefault(key, _Window())
        window.forced_start = max(0, index - self.MAX_ROWS // 2)

    def reconcile(self, key, frame, messages, viewport, scroll_top):
        window = self.windows.setdefault(key, _Window())
        identities = [message_identity(message) for message in messages]
        added = [message for message, identity in zip(messages, identities) if identity not in window.known]
        if scroll_top:
            start = 0
        elif window.forced_start is not None:
            start = window.forced_start
        elif viewport is None or viewport.get('at_bottom', False):
            start = max(0, len(messages) - self.MAX_ROWS)
        elif window.first in identities:
            start = identities.index(window.first)
        else:
            start = window.start
        start = min(max(0, start), max(0, len(messages) - self.MAX_ROWS))
        end = min(start + self.MAX_ROWS, len(messages))
        desired = messages[start:end]
        old_rows = {}
        for row in frame.winfo_children():
            if hasattr(row, '_chat_message'):
                old_rows[message_identity(row._chat_message)] = row
            else:
                row.destroy()
        rows = []
        for message in desired:
            row = old_rows.pop(message_identity(message), None)
            if row is not None and row._chat_message is not message:
                row.destroy()
                row = None
            if row is None:
                row = self.view.append_message(key, message)
            if row is not None:
                rows.append(row)
        for row in old_rows.values():
            row.destroy()
        # Creation order differs from display order after prepends/replacements.
        following = None
        for row in reversed(rows):
            if following is not None:
                row.pack_configure(before=following)
            following = row
        self.view.message_rows.layout(rows)
        window.start, window.end, window.count = start, end, len(messages)
        window.first = identities[start] if identities else None
        window.forced_start = None
        window.known = set(identities)
        return added

    def on_scroll(self, key, first, last):
        window = self.windows.get(key)
        if window is None or key in self.pending:
            return
        direction = -1 if float(first) <= .001 and window.start else (
            1 if float(last) >= .999 and window.end < window.count else 0)
        if not direction:
            return
        token = self.pending[key] = object()

        def shift():
            if self.pending.get(key) is not token:
                return
            self.pending.pop(key, None)
            if self.view.state.current_chat != key or key not in self.view.chat_frames:
                return
            current = self.windows[key]
            current.forced_start = current.start + direction * (self.MAX_ROWS // 2)
            self.view.render_conversation(key)

        self.view.schedule(0, shift)
