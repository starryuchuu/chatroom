"""Client history state and retry-safe keyset pagination.

Only a completed page advances its cursor. Partially delivered messages remain
visible and are deduplicated when the same page is retried.
"""
import bisect


class HistoryMixin:
    def reset_history(self):
        self.seen_message_ids = set()
        self.message_order = {}
        self.history_cursors = {}
        self.history_exhausted = set()
        self.history_syncing = False
        self.history_page_pending = False
        self.pending_history_target = None

    def load_older_history(self):
        target = self.current_group or self.current_friend
        if not target or self.history_page_pending:
            return
        kind = 'group' if self.current_group else 'private'
        chat = (kind, target)
        if chat in self.history_exhausted:
            return
        # Save the request cursor before any partial page can change message_order.
        ids = self.message_order.get(target, [])
        before = self.history_cursors.get(chat, min(ids) if ids else 9223372036854775807)
        try:
            self.queue_send({'type': 'history_request', 'chat_type': kind,
                             'target': target, 'before_id': before})
        except Exception as error:
            self.notify('历史记录', str(error))
            return
        self.history_cursors[chat] = before
        self.pending_history_target = chat
        self.history_page_pending = True
        self.update_chat_target()

    def handle_history_event(self, msg):
        mtype = msg['type']
        if mtype == 'history_begin':
            self.history_syncing = True
            return True
        if mtype not in ('history_end', 'history_error'):
            return False

        self.history_syncing = False
        chat = (msg.get('history_kind'), msg.get('history_target'))
        pending = self.pending_history_target
        # An unscoped login snapshot may finish while a page request is queued.
        if mtype == 'history_error' or pending is None or chat == pending:
            self.history_page_pending = False
            self.pending_history_target = None
        if mtype == 'history_end' and chat[0] in ('private', 'group') and chat[1]:
            cursor = msg.get('before_id')
            if type(cursor) is int and cursor > 0:
                self.history_cursors[chat] = cursor
            if not msg.get('has_more', False):
                self.history_exhausted.add(chat)

        target = self.current_group or self.current_friend
        if target:
            self.switch_chat_frame(target)
            kind = 'group' if self.current_group else 'private'
            if mtype == 'history_end' and chat == (kind, target) and hasattr(self, 'chat_canvas'):
                self.chat_canvas.yview_moveto(0.0)
        if mtype == 'history_error':
            self.notify('历史记录', msg.get('error', '历史加载失败'))
        self.update_chat_target()
        return True

    def clear_group_history(self, gid):
        self.seen_message_ids.difference_update(self.message_order.pop(gid, []))
        self.history_exhausted.discard(('group', gid))
        self.history_cursors.pop(('group', gid), None)
        if hasattr(self, f'group_messages_{gid}'):
            delattr(self, f'group_messages_{gid}')
        frame = self.chat_frames.pop(gid, None) if hasattr(self, 'chat_frames') else None
        if frame is not None:
            if self.current_chat_frame is frame:
                self.current_chat_frame = None
            frame.destroy()

    def store_chat_message(self, chat_id, messages, entry, message_id):
        order = self.message_order.setdefault(chat_id, [])
        key = message_id if isinstance(message_id, int) else (order[-1] + 1 if order else 0)
        index = bisect.bisect_right(order, key)
        order.insert(index, key)
        messages.insert(index, entry)
        return index == len(messages) - 1
